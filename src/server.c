#include "server.h"
#include "config.h"
#include "packet.h"
#include "raw_socket.h"
#include "session.h"
#include "pool.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_EVENTS    256
#define EPOLL_TIMEOUT_MS 50
#define GC_INTERVAL   5
#define RECV_BATCH_SIZE  32

extern volatile sig_atomic_t g_shutdown;

/* ---- helpers ---- */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_udp_forwarder(const endpoint_t *ep)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("server: udp forwarder socket"); return -1; }

    /* Performance: large recv + send buffers for burst absorption */
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    set_nonblocking(fd);

    LOG_INFO("server: UDP forwarder target %s:%u (fd=%d)", ep->address, ep->port, fd);
    return fd;
}

/* Userspace filter (pre-compiled IPs) */
static int filter_match(const config_t *cfg, uint32_t src_ip, uint16_t src_port)
{
    const source_pool_t *flt = &cfg->capture_filter;

    int ip_match = (flt->count == 0);
    uint32_t src_ip_host = ntohl(src_ip);
    for (int i = 0; i < flt->count; i++) {
        if (src_ip_host >= flt->subnets[i].first_ip && src_ip_host <= flt->subnets[i].last_ip) {
            ip_match = 1;
            break;
        }
    }
    if (!ip_match) return 0;

    int port_match = (flt->port_count == 0);
    for (int i = 0; i < flt->port_count; i++) {
        if (src_port == flt->ports[i]) { port_match = 1; break; }
    }
    return port_match;
}

/* ---- Raw send callback ---- */

typedef struct {
    int       raw_fd;
    config_t *cfg;
} send_ctx_t;

static int raw_send_cb(const uint8_t *frame, int frame_len, void *ctx)
{
    send_ctx_t *sc = (send_ctx_t *)ctx;
    return raw_send(sc->raw_fd, sc->cfg, frame, frame_len);
}

/* ---- Main event loop ---- */

int server_run(config_t *cfg)
{
    int ret = -1;

    /* Response obfuscation mode */
    int use_tcp_resp = (strcmp(cfg->protocol.mode, "tcp") == 0);
    uint8_t tcp_flags = 0;
    if (use_tcp_resp) {
        tcp_flags = pkt_parse_tcp_flags(cfg->protocol.flag);
        LOG_INFO("server: response protocol=TCP flags=0x%02x", tcp_flags);
    } else {
        LOG_INFO("server: response protocol=UDP");
    }

    LOG_INFO("server: fragment_size=%u, steal_src_ip=%s",
             cfg->fragment_size,
             cfg->steal_client_source_ip ? "true" : "false");

    /* Resolve client address (response.to) */
    struct in_addr client_addr;
    inet_pton(AF_INET, cfg->remote.address, &client_addr);

    /* Initialize memory pool */
    pool_t pool;
    if (pool_init(&pool, POOL_DEFAULT_COUNT, POOL_DEFAULT_BUFSIZE) < 0) {
        LOG_ERROR("server: pool init failed");
        return -1;
    }

    /* Initialize session table */
    session_table_t *sessions = (session_table_t *)calloc(1, sizeof(session_table_t));
    if (!sessions) {
        LOG_PERROR("server: calloc sessions");
        pool_destroy(&pool);
        return -1;
    }
    session_init(sessions);

    /* Create sockets */
    int udp_fwd_fd = -1, raw_send_fd = -1, raw_recv_fd = -1, epoll_fd = -1;

    struct sockaddr_in udp_fwd_addr;
    memset(&udp_fwd_addr, 0, sizeof(udp_fwd_addr));

    udp_fwd_fd = create_udp_forwarder(&cfg->local_endpoint);
    if (udp_fwd_fd >= 0) {
        udp_fwd_addr.sin_family = AF_INET;
        udp_fwd_addr.sin_port   = htons(cfg->local_endpoint.port);
        inet_pton(AF_INET, cfg->local_endpoint.address, &udp_fwd_addr.sin_addr);
    }

    raw_send_fd = raw_send_init(cfg);
    if (raw_send_fd < 0) goto cleanup;

    raw_recv_fd = raw_recv_init(cfg);
    if (raw_recv_fd < 0) goto cleanup;

    set_nonblocking(raw_recv_fd);

    send_ctx_t send_ctx = { .raw_fd = raw_send_fd, .cfg = cfg };

    /* Create epoll */
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { LOG_PERROR("server: epoll_create1"); goto cleanup; }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; ev.data.fd = raw_recv_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_recv_fd, &ev);

    if (udp_fwd_fd >= 0) {
        ev.events = EPOLLIN | EPOLLET; ev.data.fd = udp_fwd_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_fwd_fd, &ev);
    }

    LOG_INFO("server: event loop starting");

    /*
     * stolen_src_ip: when steal_client_source_ip is enabled,
     * we capture the incoming packet's source IP and reuse it
     * as the spoofed source for responses.
     */
    uint32_t stolen_src_ip = 0;

    struct epoll_event events[MAX_EVENTS];
    time_t last_gc = time(NULL);

    /* ---- Event Loop ---- */
    while (!g_shutdown) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_PERROR("server: epoll_wait");
            break;
        }

        /* Update cached timestamp once per batch (avoids per-packet time() syscalls) */
        time_t now = session_update_time();
        if (now - last_gc >= GC_INTERVAL) {
            session_gc(sessions);
            last_gc = now;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            /* ---- Raw socket: incoming spoofed packet from client ---- */
            if (fd == raw_recv_fd) {
                /* Edge-triggered: drain via recvmmsg batches */
                for (;;) {
                /* Pre-allocate batch of buffers from pool */
                uint8_t *batch_bufs[RECV_BATCH_SIZE];
                struct mmsghdr batch_msgs[RECV_BATCH_SIZE];
                struct iovec batch_iovs[RECV_BATCH_SIZE];
                int batch_count = 0;

                for (int j = 0; j < RECV_BATCH_SIZE; j++) {
                    batch_bufs[j] = (uint8_t *)pool_alloc(&pool);
                    if (!batch_bufs[j]) break;
                    batch_iovs[j].iov_base = batch_bufs[j];
                    batch_iovs[j].iov_len  = POOL_DEFAULT_BUFSIZE;
                    memset(&batch_msgs[j], 0, sizeof(struct mmsghdr));
                    batch_msgs[j].msg_hdr.msg_iov    = &batch_iovs[j];
                    batch_msgs[j].msg_hdr.msg_iovlen = 1;
                    batch_count++;
                }

                if (batch_count == 0) break;

                int nrecvd = recvmmsg(raw_recv_fd, batch_msgs, (unsigned int)batch_count,
                                      MSG_DONTWAIT, NULL);
                if (nrecvd <= 0) {
                    for (int j = 0; j < batch_count; j++)
                        pool_free(&pool, batch_bufs[j]);
                    break;
                }

                /* Return unused buffers */
                for (int j = nrecvd; j < batch_count; j++)
                    pool_free(&pool, batch_bufs[j]);

                /* Process received packets */
                for (int j = 0; j < nrecvd; j++) {
                    uint8_t *buf = batch_bufs[j];
                    ssize_t n = (ssize_t)batch_msgs[j].msg_len;

                    if (n < (ssize_t)(ETH_HLEN_CONST + IP_HLEN)) {
                        pool_free(&pool, buf); continue;
                    }

                    struct iphdr *iph = (struct iphdr *)(buf + ETH_HLEN_CONST);
                    int ip_hlen = iph->ihl * 4;
                    if (n < (ssize_t)(ETH_HLEN_CONST + ip_hlen)) {
                        pool_free(&pool, buf); continue;
                    }

                    uint32_t pkt_src_ip = iph->saddr;
                    uint16_t pkt_src_port = 0;
                    int transport_offset = ETH_HLEN_CONST + ip_hlen;
                    uint8_t *transport = buf + transport_offset;
                    uint8_t *payload = NULL;
                    int payload_len = 0;
                    uint8_t pkt_proto = iph->protocol;

                    if (pkt_proto == IPPROTO_TCP) {
                        if (n < (ssize_t)(transport_offset + TCP_HLEN)) {
                            pool_free(&pool, buf); continue;
                        }
                        struct tcphdr *tcph = (struct tcphdr *)transport;
                        pkt_src_port = ntohs(tcph->source);
                        int tcp_hlen = tcph->doff * 4;
                        payload = transport + tcp_hlen;
                        payload_len = (int)n - transport_offset - tcp_hlen;
                    } else if (pkt_proto == IPPROTO_UDP) {
                        if (n < (ssize_t)(transport_offset + UDP_HLEN)) {
                            pool_free(&pool, buf); continue;
                        }
                        struct udphdr *udph = (struct udphdr *)transport;
                        pkt_src_port = ntohs(udph->source);
                        payload = transport + UDP_HLEN;
                        payload_len = (int)n - transport_offset - UDP_HLEN;
                    } else {
                        pool_free(&pool, buf); continue;
                    }

                    if (payload_len <= 0) { pool_free(&pool, buf); continue; }

                    /* Filter check (pre-compiled IPs) */
                    if (!filter_match(cfg, pkt_src_ip, pkt_src_port)) {
                        pool_free(&pool, buf); continue;
                    }

                    LOG_DEBUG("server: filter MATCHED %d bytes from port %u", payload_len, pkt_src_port);

                    if (cfg->steal_client_source_ip) {
                        stolen_src_ip = pkt_src_ip;
                    }

                    /* Session for return path */
                    session_upsert(sessions,
                                   pkt_src_ip, pkt_src_port, pkt_proto,
                                   -1, NULL, 0);

                    /* Forward payload to backend */
                    if (udp_fwd_fd >= 0) {
                        sendto(udp_fwd_fd, payload, (size_t)payload_len, MSG_DONTWAIT,
                               (struct sockaddr *)&udp_fwd_addr, sizeof(udp_fwd_addr));
                    }

                    pool_free(&pool, buf);
                }

                /* If we got fewer than requested, socket is drained */
                if (nrecvd < batch_count) break;
                } /* end drain loop */
            }

            /* ---- UDP forwarder: backend response → raw tunnel ---- */
            else if (fd == udp_fwd_fd) {
                /* Edge-triggered: drain all available packets */
                for (;;) {
                uint8_t *buf = (uint8_t *)pool_alloc(&pool);
                if (!buf) break;

                ssize_t n = recv(udp_fwd_fd, buf, POOL_DEFAULT_BUFSIZE, MSG_DONTWAIT);
                if (n <= 0) { pool_free(&pool, buf); break; }
                if (n > 65535) {
                    LOG_WARN("server: payload too large (%zd)", n);
                    pool_free(&pool, buf);
                    continue;
                }

                /*
                 * Determine response source IP:
                 *   - steal mode: use the stolen IP from the last incoming packet
                 *   - normal mode: round-robin from source pool
                 */
                uint32_t resp_src_ip;
                uint16_t resp_src_port = config_next_source_port(cfg);

                if (cfg->steal_client_source_ip && stolen_src_ip != 0) {
                    resp_src_ip = stolen_src_ip;
                } else {
                    resp_src_ip = config_next_source_ip(cfg);
                }

                if (resp_src_ip == 0 || resp_src_port == 0) {
                    LOG_ERROR("server: no source IP/port for response");
                    pool_free(&pool, buf);
                    continue;
                }

                /* Build response: spoofed src → client */
                uint8_t *pkt_buf = (uint8_t *)pool_alloc(&pool);
                if (!pkt_buf) { pool_free(&pool, buf); break; }
                uint8_t *scratch = (uint8_t *)pool_alloc(&pool);
                if (!scratch) { pool_free(&pool, pkt_buf); pool_free(&pool, buf); break; }

                int rc;
                if (use_tcp_resp) {
                    rc = pkt_send_tcp_fragmented(pkt_buf, scratch,
                                                 cfg->outgoing_mac, cfg->gateway_mac,
                                                 resp_src_ip, client_addr.s_addr,
                                                 resp_src_port, cfg->remote.port,
                                                 tcp_flags,
                                                 buf, (uint16_t)n,
                                                 cfg->fragment_size,
                                                 raw_send_cb, &send_ctx);
                } else {
                    rc = pkt_send_udp_fragmented(pkt_buf, scratch,
                                                 cfg->outgoing_mac, cfg->gateway_mac,
                                                 resp_src_ip, client_addr.s_addr,
                                                 resp_src_port, cfg->remote.port,
                                                 buf, (uint16_t)n,
                                                 cfg->fragment_size,
                                                 raw_send_cb, &send_ctx);
                }

                if (rc > 0) {
#ifdef DEBUG
                    struct in_addr sip = { .s_addr = resp_src_ip };
                    LOG_DEBUG("server: sent %d bytes src=%s:%u → %s:%u",
                              rc, inet_ntoa(sip), resp_src_port,
                              cfg->remote.address, cfg->remote.port);
#else
                    (void)rc;
#endif
                }

                pool_free(&pool, scratch);
                pool_free(&pool, pkt_buf);
                pool_free(&pool, buf);
                } /* end drain loop */
            }
        }
    }

    LOG_INFO("server: shutting down");
    ret = 0;

cleanup:
    if (epoll_fd >= 0) close(epoll_fd);
    if (udp_fwd_fd >= 0) close(udp_fwd_fd);
    if (raw_send_fd >= 0) close(raw_send_fd);
    if (raw_recv_fd >= 0) close(raw_recv_fd);
    free(sessions);
    pool_destroy(&pool);
    return ret;
}
