#include "config.h"
#include "log.h"
#include "../vendor/cJSON/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Global log level — defined here, declared extern in log.h */
int g_log_level = LOG_LEVEL_INFO;

/* ---- helpers ---- */

static int parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

static int detect_iface_mac(const char *iface_name, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("socket for ioctl"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG_PERROR("ioctl SIOCGIFHWADDR");
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int detect_iface_index(const char *iface_name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("socket for ioctl"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        LOG_PERROR("ioctl SIOCGIFINDEX");
        close(fd);
        return -1;
    }

    int idx = ifr.ifr_ifindex;
    close(fd);
    return idx;
}

/*
 * Parse a single IP or CIDR into the subnets pool.
 * Calculates exact bounds for fast matching and round-robining.
 */
static int add_entry_to_pool(source_pool_t *pool, const char *entry)
{
    if (pool->count >= MAX_SOURCE_IPS) {
        LOG_WARN("config: source pool full (%d max)", MAX_SOURCE_IPS);
        return -1;
    }

    char buf[64];
    strncpy(buf, entry, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 32;

    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) {
            LOG_ERROR("config: invalid CIDR prefix /%d in '%s'", prefix, entry);
            return -1;
        }
    }

    struct in_addr base_addr;
    if (inet_pton(AF_INET, buf, &base_addr) != 1) {
        LOG_WARN("config: skipping invalid IP entry: '%s'", entry);
        return -1;
    }

    uint32_t base = ntohl(base_addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t broadcast = network | ~mask;

    cidr_t *c = &pool->subnets[pool->count];

    /* For /32, it's a single IP */
    if (prefix == 32) {
        c->first_ip = base;
        c->last_ip = base;
        c->host_count = 1;
    } else if (prefix == 31) {
        /* /31 point-to-point, both IPs are valid hosts */
        c->first_ip = network;
        c->last_ip = broadcast;
        c->host_count = 2;
    } else {
        /* Standard CIDR: skip network (.0) and broadcast (.255) */
        c->first_ip = network + 1;
        c->last_ip = broadcast - 1;
        c->host_count = (broadcast - network) - 1;
    }

    /* Leave bounds in host order for high-speed bounds matching `ntohl(src) >= first_ip && ntohl(src) <= last_ip` */

    pool->total_hosts += c->host_count;
    pool->count++;

    if (slash) {
        struct in_addr a = { .s_addr = htonl(c->last_ip) };
        LOG_INFO("config: loaded CIDR '%s' → bounds [%s - %s] (hosts %u)",
                 entry, buf, inet_ntoa(a), c->host_count); /* Log format trick; first is in buf */
    }
    return 0;
}

/* Load IPs/CIDRs from a file (one per line) into a source_pool. */
static int load_ips_from_file(source_pool_t *pool, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_PERROR("config: open IP file");
        return -1;
    }

    char line[64];
    pool->count = 0;

    while (fgets(line, sizeof(line), f)) {
        if (pool->count >= MAX_SOURCE_IPS) {
            LOG_WARN("config: IP file exceeds max %d, truncating", MAX_SOURCE_IPS);
            break;
        }

        /* Strip newline/whitespace */
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';

        if (*p == '\0' || *p == '#') continue; /* skip blanks and comments */

        add_entry_to_pool(pool, p);
    }

    fclose(f);
    LOG_INFO("config: loaded %d IPs from '%s'", pool->count, path);
    return pool->count > 0 ? 0 : -1;
}

/*
 * Parse source.address: { "type": "static"|"file", "value": [...] | "path" }
 * and source.port: [443, 8443] or { "type":"static", "value":[443] }
 */
static int parse_source_pool(cJSON *source_obj, source_pool_t *pool)
{
    if (!source_obj) return -1;

    /* --- Address --- */
    cJSON *addr = cJSON_GetObjectItemCaseSensitive(source_obj, "address");
    if (addr) {
        cJSON *atype = cJSON_GetObjectItemCaseSensitive(addr, "type");
        cJSON *aval  = cJSON_GetObjectItemCaseSensitive(addr, "value");

        const char *type_str = cJSON_IsString(atype) ? atype->valuestring : "static";

        if (strcmp(type_str, "file") == 0) {
            pool->type = ADDR_FILE;
            if (cJSON_IsString(aval)) {
                strncpy(pool->file_path, aval->valuestring, sizeof(pool->file_path) - 1);
                pool->file_path[sizeof(pool->file_path) - 1] = '\0';
                if (load_ips_from_file(pool, pool->file_path) < 0) {
                    LOG_ERROR("config: failed to load IPs from file '%s'", pool->file_path);
                    return -1;
                }
            } else {
                LOG_ERROR("config: file type requires a string path in 'value'");
                return -1;
            }
        } else {
            /* static */
            pool->type = ADDR_STATIC;
            pool->count = 0;
            if (cJSON_IsArray(aval)) {
                cJSON *ip;
                cJSON_ArrayForEach(ip, aval) {
                    if (pool->count >= MAX_SOURCE_IPS) break;
                    if (cJSON_IsString(ip)) {
                        add_entry_to_pool(pool, ip->valuestring);
                    }
                }
            } else if (cJSON_IsString(aval)) {
                /* Single IP or CIDR string */
                add_entry_to_pool(pool, aval->valuestring);
            }
        }
    }

    /* --- Ports --- */
    cJSON *port = cJSON_GetObjectItemCaseSensitive(source_obj, "port");
    pool->port_count = 0;

    if (cJSON_IsArray(port)) {
        /* Direct array: [443, 8443] */
        cJSON *p;
        cJSON_ArrayForEach(p, port) {
            if (pool->port_count >= MAX_SOURCE_PORTS) break;
            if (cJSON_IsNumber(p)) {
                pool->ports[pool->port_count++] = (uint16_t)p->valuedouble;
            }
        }
    } else if (cJSON_IsObject(port)) {
        /* Structured: { "type":"static", "value":[443] } */
        cJSON *pval = cJSON_GetObjectItemCaseSensitive(port, "value");
        if (cJSON_IsArray(pval)) {
            cJSON *p;
            cJSON_ArrayForEach(p, pval) {
                if (pool->port_count >= MAX_SOURCE_PORTS) break;
                if (cJSON_IsNumber(p)) {
                    pool->ports[pool->port_count++] = (uint16_t)p->valuedouble;
                }
            }
        }
    } else if (cJSON_IsNumber(port)) {
        pool->ports[0] = (uint16_t)port->valuedouble;
        pool->port_count = 1;
    }

    return 0;
}

/* Parse protocol section */
static void parse_protocol(cJSON *proto_obj, protocol_t *proto)
{
    if (!proto_obj) return;

    cJSON *pmode = cJSON_GetObjectItemCaseSensitive(proto_obj, "mode");
    if (cJSON_IsString(pmode)) {
        strncpy(proto->mode, pmode->valuestring, sizeof(proto->mode) - 1);
        proto->mode[sizeof(proto->mode) - 1] = '\0';
    }

    cJSON *poption = cJSON_GetObjectItemCaseSensitive(proto_obj, "option");
    if (poption) {
        cJSON *pflag = cJSON_GetObjectItemCaseSensitive(poption, "flag");
        if (cJSON_IsString(pflag)) {
            strncpy(proto->flag, pflag->valuestring, sizeof(proto->flag) - 1);
            proto->flag[sizeof(proto->flag) - 1] = '\0';
        }
    }
}

/* ---- Public API ---- */

int config_load(config_t *cfg, const char *path, int mode)
{
    memset(cfg, 0, sizeof(config_t));
    cfg->mode = mode;
    cfg->fragment_size = DEFAULT_FRAGMENT_SIZE;
    cfg->ip_strategy = BALANCE_ROUND_ROBIN;
    cfg->log_level = LOG_LEVEL_INFO;  /* default */
    atomic_store(&cfg->rr_ip_index, 0);
    atomic_store(&cfg->rr_port_index, 0);
    strcpy(cfg->protocol.mode, "udp");  /* default */

    /* Read file */
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_PERROR("config: fopen");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0) {
        LOG_PERROR("config: ftell");
        fclose(f);
        return -1;
    }
    fseek(f, 0, SEEK_SET);

    char *data = (char *)malloc((size_t)fsize + 1);
    if (!data) {
        fclose(f);
        LOG_PERROR("config: malloc");
        return -1;
    }

    size_t nread = fread(data, 1, (size_t)fsize, f);
    data[nread] = '\0';
    fclose(f);

    /* Parse JSON */
    cJSON *root = cJSON_Parse(data);
    free(data);

    if (!root) {
        LOG_ERROR("config: JSON parse error near: %s", cJSON_GetErrorPtr());
        return -1;
    }

    int ret = 0;

    /* ============================================
     *  LOCAL ENDPOINT: listen (client) / forward (server)
     * ============================================ */
    const char *local_key = (mode == MODE_CLIENT) ? "listen" : "forward";
    cJSON *local = cJSON_GetObjectItemCaseSensitive(root, local_key);
    if (!local) {
        LOG_ERROR("config: missing '%s' section", local_key);
        ret = -1; goto cleanup;
    }

    cJSON *laddr = cJSON_GetObjectItemCaseSensitive(local, "address");
    cJSON *lport = cJSON_GetObjectItemCaseSensitive(local, "port");
    if (!cJSON_IsString(laddr) || !cJSON_IsNumber(lport)) {
        LOG_ERROR("config: invalid %s.address/port", local_key);
        ret = -1; goto cleanup;
    }
    strncpy(cfg->local_endpoint.address, laddr->valuestring, INET_ADDRSTRLEN - 1);
    cfg->local_endpoint.address[INET_ADDRSTRLEN - 1] = '\0';
    cfg->local_endpoint.port = (uint16_t)lport->valuedouble;

    /* ============================================
     *  CONNECT (client) / RESPONSE (server)
     * ============================================ */
    {
        const char *conn_key = (mode == MODE_CLIENT) ? "connect" : "response";
        cJSON *conn = cJSON_GetObjectItemCaseSensitive(root, conn_key);
        if (!conn) {
            LOG_ERROR("config: missing '%s' section", conn_key);
            ret = -1; goto cleanup;
        }

        /* .to — remote target */
        cJSON *to = cJSON_GetObjectItemCaseSensitive(conn, "to");
        if (!to) {
            LOG_ERROR("config: missing %s.to", conn_key);
            ret = -1; goto cleanup;
        }
        cJSON *taddr = cJSON_GetObjectItemCaseSensitive(to, "address");
        cJSON *tport = cJSON_GetObjectItemCaseSensitive(to, "port");
        if (!cJSON_IsString(taddr) || !cJSON_IsNumber(tport)) {
            LOG_ERROR("config: invalid %s.to.address/port", conn_key);
            ret = -1; goto cleanup;
        }
        strncpy(cfg->remote.address, taddr->valuestring, INET_ADDRSTRLEN - 1);
        cfg->remote.address[INET_ADDRSTRLEN - 1] = '\0';
        cfg->remote.port = (uint16_t)tport->valuedouble;

        /* .with.source — spoofed source pool */
        cJSON *with = cJSON_GetObjectItemCaseSensitive(conn, "with");
        if (with) {
            cJSON *src = cJSON_GetObjectItemCaseSensitive(with, "source");
            if (parse_source_pool(src, &cfg->source) < 0) {
                LOG_ERROR("config: invalid %s.with.source", conn_key);
                ret = -1; goto cleanup;
            }
        }

        /* .protocol */
        cJSON *proto = cJSON_GetObjectItemCaseSensitive(conn, "protocol");
        parse_protocol(proto, &cfg->protocol);
    }

    /* ============================================
     *  CAPTURE
     * ============================================ */
    {
        cJSON *capture = cJSON_GetObjectItemCaseSensitive(root, "capture");
        if (!capture) {
            LOG_ERROR("config: missing 'capture' section");
            ret = -1; goto cleanup;
        }

        cJSON *ciface = cJSON_GetObjectItemCaseSensitive(capture, "interface");
        if (cJSON_IsString(ciface)) {
            strncpy(cfg->capture_iface, ciface->valuestring, IFNAMSIZ - 1);
        }

        cJSON *filter = cJSON_GetObjectItemCaseSensitive(capture, "filter");
        if (filter) {
            cJSON *fsrc = cJSON_GetObjectItemCaseSensitive(filter, "source");
            if (parse_source_pool(fsrc, &cfg->capture_filter) < 0) {
                LOG_ERROR("config: invalid capture.filter.source");
                ret = -1; goto cleanup;
            }
        }
    }

    /* ============================================
     *  OUTGOING
     * ============================================ */
    {
        cJSON *outgoing = cJSON_GetObjectItemCaseSensitive(root, "outgoing");
        if (!outgoing) {
            LOG_ERROR("config: missing 'outgoing' section");
            ret = -1; goto cleanup;
        }

        cJSON *oiface = cJSON_GetObjectItemCaseSensitive(outgoing, "interface");
        if (cJSON_IsString(oiface)) {
            strncpy(cfg->outgoing_iface, oiface->valuestring, IFNAMSIZ - 1);
        }

        cJSON *ogw = cJSON_GetObjectItemCaseSensitive(outgoing, "gateway_mac");
        if (!cJSON_IsString(ogw) || parse_mac(ogw->valuestring, cfg->gateway_mac) < 0) {
            LOG_ERROR("config: invalid outgoing.gateway_mac");
            ret = -1; goto cleanup;
        }
    }

    /* ============================================
     *  TUNING
     * ============================================ */
    {
        cJSON *tuning = cJSON_GetObjectItemCaseSensitive(root, "tuning");
        if (tuning) {
            cJSON *frag = cJSON_GetObjectItemCaseSensitive(tuning, "fragment_size");
            if (cJSON_IsNumber(frag)) {
                int fval = (int)frag->valuedouble;
                if (fval < 68 || fval > 9000) {
                    LOG_WARN("config: fragment_size %d out of range [68..9000], using default %d",
                             fval, DEFAULT_FRAGMENT_SIZE);
                } else {
                    cfg->fragment_size = (uint16_t)fval;
                }
            }

            cJSON *strategy = cJSON_GetObjectItemCaseSensitive(tuning, "ip_selection_strategy");
            if (cJSON_IsString(strategy)) {
                if (strcmp(strategy->valuestring, "round_robin") == 0)
                    cfg->ip_strategy = BALANCE_ROUND_ROBIN;
                else
                    LOG_WARN("config: unknown strategy '%s', defaulting to round_robin",
                             strategy->valuestring);
            }

            cJSON *steal = cJSON_GetObjectItemCaseSensitive(tuning, "steal_client_source_ip");
            if (cJSON_IsBool(steal)) {
                cfg->steal_client_source_ip = cJSON_IsTrue(steal) ? 1 : 0;
            }

            cJSON *loglvl = cJSON_GetObjectItemCaseSensitive(tuning, "log_level");
            if (cJSON_IsString(loglvl)) {
                const char *lvl = loglvl->valuestring;
                if (strcmp(lvl, "error") == 0)       cfg->log_level = LOG_LEVEL_ERROR;
                else if (strcmp(lvl, "warn") == 0)   cfg->log_level = LOG_LEVEL_WARN;
                else if (strcmp(lvl, "info") == 0)   cfg->log_level = LOG_LEVEL_INFO;
                else if (strcmp(lvl, "debug") == 0)  cfg->log_level = LOG_LEVEL_DEBUG;
                else LOG_WARN("config: unknown log_level '%s', defaulting to 'info'", lvl);
            }
        }
    }

    /* ============================================
     *  DERIVED: detect interface MAC + index
     * ============================================ */
    if (detect_iface_mac(cfg->outgoing_iface, cfg->outgoing_mac) < 0) {
        LOG_ERROR("config: failed to detect MAC for outgoing '%s'", cfg->outgoing_iface);
        ret = -1; goto cleanup;
    }

    cfg->outgoing_index = detect_iface_index(cfg->outgoing_iface);
    if (cfg->outgoing_index < 0) {
        LOG_ERROR("config: failed to detect index for outgoing '%s'", cfg->outgoing_iface);
        ret = -1; goto cleanup;
    }

    cfg->capture_index = detect_iface_index(cfg->capture_iface);
    if (cfg->capture_index < 0) {
        LOG_ERROR("config: failed to detect index for capture '%s'", cfg->capture_iface);
        ret = -1; goto cleanup;
    }

    /* Apply log level globally */
    g_log_level = cfg->log_level;

    /* Default protocol */
    if (cfg->protocol.mode[0] == '\0')
        strcpy(cfg->protocol.mode, "udp");

cleanup:
    cJSON_Delete(root);
    return ret;
}

void config_dump(const config_t *cfg)
{
    const char *mode_str = (cfg->mode == MODE_CLIENT) ? "CLIENT" : "SERVER";

    fprintf(stderr, "=== injspoof config [%s] ===\n", mode_str);
    fprintf(stderr, "  local:        %s:%u\n", cfg->local_endpoint.address, cfg->local_endpoint.port);
    fprintf(stderr, "  remote:       %s:%u\n", cfg->remote.address, cfg->remote.port);
    fprintf(stderr, "  protocol:     %s", cfg->protocol.mode);
    if (cfg->protocol.flag[0])
        fprintf(stderr, " (flags: %s)", cfg->protocol.flag);
    fprintf(stderr, "\n");
    fprintf(stderr, "  fragment:     %u\n", cfg->fragment_size);

    fprintf(stderr, "  source_ips:   [%u hosts in %d blocks] ", cfg->source.total_hosts, cfg->source.count);
    for (int i = 0; i < cfg->source.count && i < 5; i++) {
        struct in_addr a = { .s_addr = htonl(cfg->source.subnets[i].first_ip) };
        fprintf(stderr, "%s ", inet_ntoa(a));
    }
    if (cfg->source.count > 5) fprintf(stderr, "...");
    fprintf(stderr, "\n");

    fprintf(stderr, "  source_ports: ");
    for (int i = 0; i < cfg->source.port_count; i++)
        fprintf(stderr, "%u ", cfg->source.ports[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "  capture:      %s\n", cfg->capture_iface);
    fprintf(stderr, "  filter_ips:   [%u hosts in %d blocks] ", cfg->capture_filter.total_hosts, cfg->capture_filter.count);
    for (int i = 0; i < cfg->capture_filter.count && i < 5; i++) {
        struct in_addr a = { .s_addr = htonl(cfg->capture_filter.subnets[i].first_ip) };
        fprintf(stderr, "%s ", inet_ntoa(a));
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "  filter_ports: ");
    for (int i = 0; i < cfg->capture_filter.port_count; i++)
        fprintf(stderr, "%u ", cfg->capture_filter.ports[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "  outgoing:     %s (idx=%d)\n", cfg->outgoing_iface, cfg->outgoing_index);
    fprintf(stderr, "  outgoing_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
            cfg->outgoing_mac[0], cfg->outgoing_mac[1], cfg->outgoing_mac[2],
            cfg->outgoing_mac[3], cfg->outgoing_mac[4], cfg->outgoing_mac[5]);
    fprintf(stderr, "  gateway_mac:  %02x:%02x:%02x:%02x:%02x:%02x\n",
            cfg->gateway_mac[0], cfg->gateway_mac[1], cfg->gateway_mac[2],
            cfg->gateway_mac[3], cfg->gateway_mac[4], cfg->gateway_mac[5]);

    if (cfg->mode == MODE_SERVER)
        fprintf(stderr, "  steal_src_ip: %s\n", cfg->steal_client_source_ip ? "true" : "false");

    static const char *level_names[] = { "error", "warn", "info", "debug" };
    int lvl_idx = cfg->log_level;
    if (lvl_idx < 0 || lvl_idx > 3) lvl_idx = 2;
    fprintf(stderr, "  log_level:    %s\n", level_names[lvl_idx]);

    fprintf(stderr, "================================\n");
}

uint32_t config_next_source_ip(config_t *cfg)
{
    const source_pool_t *pool = &cfg->source;
    if (pool->total_hosts == 0) return 0;
    
    if (pool->total_hosts == 1) return htonl(pool->subnets[0].first_ip);

    uint32_t idx = atomic_fetch_add(&cfg->rr_ip_index, 1) % pool->total_hosts;
    
    for (int i = 0; i < pool->count; i++) {
        if (idx < pool->subnets[i].host_count) {
            return htonl(pool->subnets[i].first_ip + idx);
        }
        idx -= pool->subnets[i].host_count;
    }
    
    /* Fallback (should never be reached) */
    return htonl(pool->subnets[0].first_ip);
}

uint16_t config_next_source_port(config_t *cfg)
{
    if (cfg->source.port_count == 0) return 0;
    if (cfg->source.port_count == 1) return cfg->source.ports[0];

    int idx = atomic_fetch_add(&cfg->rr_port_index, 1) % cfg->source.port_count;
    return cfg->source.ports[idx];
}
