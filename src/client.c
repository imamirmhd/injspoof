#include "client.h"
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

#define MAX_EVENTS       256
#define EPOLL_TIMEOUT_MS 50
#define RECV_BATCH_SIZE  32

extern volatile sig_atomic_t g_shutdown;

/* ---- helpers ---- */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_udp_listener(const endpoint_t *ep)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("client: udp socket"); return -1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Performance: large recv + send buffers for burst absorption */
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ep->port);
    inet_pton(AF_INET, ep->address, &addr.sin_addr);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_PERROR("client: udp bind");
        close(fd);
        return -1;
    }

    set_nonblocking(fd);
    LOG_INFO("client: UDP listener on %s:%u (fd=%d)", ep->address, ep->port, fd);
    return fd;
}

/* ---- Userspace filter (uses pre-compiled IPs) ---- */

static int filter_match(const config_t *cfg, uint32_t src_ip, uint16_t src_port)
{
    const source_pool_t *flt = &cfg->capture_filter;

    /* IP match */
    int ip_match = (flt->count == 0);
    uint32_t src_ip_host = ntohl(src_ip);
    for (int i = 0; i < flt->count; i++) {
        if (src_ip_host >= flt->subnets[i].first_ip && src_ip_host <= flt->subnets[i].last_ip) {
            ip_match = 1;
            break;
        }
    }
    if (!ip_match) return 0;

    /* Port match */
    int port_match = (flt->port_count == 0);
    for (int i = 0; i < flt->port_count; i++) {
        if (src_port == flt->ports[i]) {
            port_match = 1;
            break;
        }
    }

    return port_match;
}

/* ---- Raw send callback for fragmented API ---- */

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

int client_run(config_t *cfg)
{
    int ret = -1;

    /* Parse TCP flags if protocol is TCP */
    uint8_t tcp_flags = 0;
    int use_tcp_obfs = (strcmp(cfg->protocol.mode, "tcp") == 0);
    if (use_tcp_obfs) {
        tcp_flags = pkt_parse_tcp_flags(cfg->protocol.flag);
        LOG_INFO("client: obfuscation protocol=TCP flags=0x%02x", tcp_flags);
    } else {
        LOG_INFO("client: obfuscation protocol=UDP");
    }

    LOG_INFO("client: fragment_size=%u, source_ips=%d, source_ports=%d",
             cfg->fragment_size, cfg->source.count, cfg->source.port_count);

    /* Resolve remote address */
    struct in_addr remote_addr;
    inet_pton(AF_INET, cfg->remote.address, &remote_addr);

    /* Initialize memory pool */
    pool_t pool;
    if (pool_init(&pool, POOL_DEFAULT_COUNT, POOL_DEFAULT_BUFSIZE) < 0) {
        LOG_ERROR("client: pool init failed");
        return -1;
    }

    /* Track last local peer for response forwarding (client has one local app) */
    struct sockaddr_in local_peer;
    memset(&local_peer, 0, sizeof(local_peer));
    int has_local_peer = 0;

    /* Create sockets */
    int udp_fd = -1, raw_send_fd = -1, raw_recv_fd = -1, epoll_fd = -1;

    udp_fd = create_udp_listener(&cfg->local_endpoint);
    if (udp_fd < 0) {
        LOG_ERROR("client: no UDP listener created");
        goto cleanup;
    }

    raw_send_fd = raw_send_init(cfg);
    if (raw_send_fd < 0) goto cleanup;

    raw_recv_fd = raw_recv_init(cfg);
    if (raw_recv_fd < 0) goto cleanup;

    set_nonblocking(raw_recv_fd);

    send_ctx_t send_ctx = { .raw_fd = raw_send_fd, .cfg = cfg };

    /* Create epoll */
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { LOG_PERROR("client: epoll_create1"); goto cleanup; }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; ev.data.fd = udp_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev);
    ev.events = EPOLLIN | EPOLLET; ev.data.fd = raw_recv_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_recv_fd, &ev);

    LOG_INFO("client: event loop starting");

    struct epoll_event events[MAX_EVENTS];

    /* ---- Event Loop ---- */
    while (!g_shutdown) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_PERROR("client: epoll_wait");
            break;
        }



        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            /* ---- UDP listener: app → raw tunnel ---- */
            if (fd == udp_fd) {
                /* Edge-triggered: drain all available packets */
                for (;;) {
                uint8_t *buf = (uint8_t *)pool_alloc(&pool);
                if (!buf) break;

                struct sockaddr_in peer;
                socklen_t peer_len = sizeof(peer);

                ssize_t n = recvfrom(udp_fd, buf, POOL_DEFAULT_BUFSIZE, MSG_DONTWAIT,
                                     (struct sockaddr *)&peer, &peer_len);
                if (n <= 0) { pool_free(&pool, buf); break; }
                if (n > 65535) {
                    LOG_WARN("client: payload too large (%zd)", n);
                    pool_free(&pool, buf);
                    continue;
                }

                LOG_DEBUG("client: UDP recv %zd bytes from %s:%u",
                          n, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

                /* Track local peer for return path */
                local_peer = peer;
                has_local_peer = 1;

                /* Round-robin source IP and port */
                uint32_t src_ip   = config_next_source_ip(cfg);
                uint16_t src_port = config_next_source_port(cfg);

                if (src_ip == 0 || src_port == 0) {
                    LOG_ERROR("client: no source IPs or ports configured");
                    pool_free(&pool, buf);
                    continue;
                }

                /* Build and send spoofed raw packet */
                uint8_t *pkt_buf = (uint8_t *)pool_alloc(&pool);
                if (!pkt_buf) { pool_free(&pool, buf); break; }
                uint8_t *scratch = (uint8_t *)pool_alloc(&pool);
                if (!scratch) { pool_free(&pool, pkt_buf); pool_free(&pool, buf); break; }

                int rc;
                if (use_tcp_obfs) {
                    rc = pkt_send_tcp_fragmented(pkt_buf, scratch,
                                                 cfg->outgoing_mac, cfg->gateway_mac,
                                                 src_ip, remote_addr.s_addr,
                                                 src_port, cfg->remote.port,
                                                 tcp_flags,
                                                 buf, (uint16_t)n,
                                                 cfg->fragment_size,
                                                 raw_send_cb, &send_ctx);
                } else {
                    rc = pkt_send_udp_fragmented(pkt_buf, scratch,
                                                 cfg->outgoing_mac, cfg->gateway_mac,
                                                 src_ip, remote_addr.s_addr,
                                                 src_port, cfg->remote.port,
                                                 buf, (uint16_t)n,
                                                 cfg->fragment_size,
                                                 raw_send_cb, &send_ctx);
                }

                if (rc > 0) {
#ifdef DEBUG
                    struct in_addr sip = { .s_addr = src_ip };
                    LOG_DEBUG("client: sent %d bytes src=%s:%u dst=%s:%u",
                              rc, inet_ntoa(sip), src_port,
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

            /* ---- Raw socket: response from tunnel → local app ---- */
            else if (fd == raw_recv_fd) {
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
                    /* Return all pre-allocated buffers */
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

                    if (iph->protocol == IPPROTO_TCP) {
                        if (n < (ssize_t)(transport_offset + TCP_HLEN)) {
                            pool_free(&pool, buf); continue;
                        }
                        struct tcphdr *tcph = (struct tcphdr *)transport;
                        pkt_src_port = ntohs(tcph->source);
                        int tcp_hlen = tcph->doff * 4;
                        payload = transport + tcp_hlen;
                        payload_len = (int)n - transport_offset - tcp_hlen;
                    } else if (iph->protocol == IPPROTO_UDP) {
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

                    /* Userspace filter (pre-compiled IPs — no inet_pton) */
                    if (!filter_match(cfg, pkt_src_ip, pkt_src_port)) {
                        pool_free(&pool, buf); continue;
                    }

                    LOG_DEBUG("client: filter MATCHED, forwarding %d bytes to local app", payload_len);

                    /* Forward to local app directly (no session lookup needed) */
                    if (has_local_peer) {
                        sendto(udp_fd, payload, (size_t)payload_len, MSG_DONTWAIT,
                               (struct sockaddr *)&local_peer,
                               sizeof(local_peer));
                    } else {
                        LOG_DEBUG("client: no local peer yet, dropping response");
                    }

                    pool_free(&pool, buf);
                }

                /* If we got fewer than requested, socket is drained */
                if (nrecvd < batch_count) break;
                } /* end drain loop */
            }
        }
    }

    LOG_INFO("client: shutting down");
    ret = 0;

cleanup:
    if (epoll_fd >= 0) close(epoll_fd);
    if (udp_fd >= 0) close(udp_fd);
    if (raw_send_fd >= 0) close(raw_send_fd);
    if (raw_recv_fd >= 0) close(raw_recv_fd);
    pool_destroy(&pool);
    return ret;
}
