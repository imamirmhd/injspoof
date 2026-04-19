#include "raw_socket.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>

/* Max IPs/ports we can fit in a BPF program (jump offsets are uint8_t) */
#define BPF_MAX_FILTER_IPS   16
#define BPF_MAX_FILTER_PORTS 16

static int attach_bpf_filter(int fd, const config_t *cfg)
{
    const source_pool_t *flt = &cfg->capture_filter;

    if (flt->count == 0 && flt->port_count == 0) {
        LOG_WARN("raw: no capture filter rules, accepting all IP packets");
        return 0;
    }

    /*
     * If the filter has too many IPs (e.g. CIDR subnets > 16 IPs total),
     * we can't fit them in BPF (jump offsets are uint8_t, max 255) and bounds 
     * checking is inefficient. Fall back to a minimal IPv4-only BPF.
     */
    int ip_count  = (flt->total_hosts > BPF_MAX_FILTER_IPS) ? 0 : flt->count;
    int port_count = (flt->port_count > BPF_MAX_FILTER_PORTS) ? 0 : flt->port_count;

    if (ip_count == 0 && port_count == 0) {
        LOG_INFO("raw: filter too large for BPF (%u IPs, %d ports), using userspace filter only",
                 flt->total_hosts, flt->port_count);
        return 0;
    }

    /*
     * BPF layout (all offsets from ethernet frame start):
     *   [0]     Load ethertype at offset 12
     *   [1]     Check IPv4 → reject if not
     *   [2]     Load IP src at offset 26
     *   [3..N]  Check src IP against each filter IP (OR chain → accept_ip)
     *   [N+1]   Reject (no IP matched)
     *   [N+2]   accept_ip: Load IHL for transport offset
     *   [N+3]   Load src port
     *   [N+4..M] Check src port against each filter port (OR chain → accept)
     *   [M+1]   Reject (no port matched)
     *   [M+2]   Accept
     */
    struct sock_filter code[256];
    int n = 0;

    /* ---- Ethertype check ---- */
    code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12);

    code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 0);
    int ethertype_jf_idx = n - 1; /* jf fixup → reject */

    /* ---- IP source check (OR chain) ---- */
    if (ip_count > 0) {
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26);

        for (int i = 0; i < ip_count; i++) {
            uint32_t ip_host = flt->subnets[i].first_ip; // Host order
            int remaining = ip_count - 1 - i;

            if (i == ip_count - 1) {
                /* Last IP: match → go to port check, no match → reject */
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                         ip_host, 0, 0);
                /* jf fixup needed → reject */
            } else {
                /* Not last: match → skip remaining IPs to port check */
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                         ip_host,
                                                         (uint8_t)remaining, 0);
            }
        }
    }

    int after_ip_idx = n; /* index right after IP checks */

    /* ---- Port check ---- */
    if (port_count > 0) {
        /* Load IHL to find transport header */
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14);
        /* Load src port (at IP header + 0) */
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14);

        for (int i = 0; i < port_count; i++) {
            int remaining = port_count - 1 - i;

            if (i == port_count - 1) {
                /* Last port: match → accept, no match → reject */
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                         flt->ports[i], 0, 0);
                /* jt → accept, jf → reject: fixup later */
            } else {
                /* Not last: match → skip remaining to accept */
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                         flt->ports[i],
                                                         (uint8_t)remaining, 0);
            }
        }
    }

    /* ---- Accept ---- */
    int accept_idx = n;
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 65535);

    /* ---- Reject ---- */
    int reject_idx = n;
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0);

    /* ---- Fix up all jump targets ---- */

    /* Ethertype check: jf → reject */
    code[ethertype_jf_idx].jf = (uint8_t)(reject_idx - ethertype_jf_idx - 1);

    /* IP checks: last IP jf → reject */
    if (ip_count > 0) {
        /* The last IP check instruction is at after_ip_idx - 1 */
        int last_ip_idx = after_ip_idx - 1;
        code[last_ip_idx].jf = (uint8_t)(reject_idx - last_ip_idx - 1);
    }

    /* Port checks */
    if (port_count > 0) {
        /* Last port check: jt → accept, jf → reject */
        int last_port_idx = accept_idx - 1;
        code[last_port_idx].jt = (uint8_t)(accept_idx - last_port_idx - 1);
        code[last_port_idx].jf = (uint8_t)(reject_idx - last_port_idx - 1);
    }

    /* If no port check, IP match should go directly to accept */
    if (port_count == 0 && ip_count > 0) {
        /* After IP match, we fall through to accept (which is right after) */
        /* The IP OR chain already jumps to after_ip_idx on match, which is accept */
    }

    struct sock_fprog bpf = { .len = (unsigned short)n, .filter = code };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        LOG_PERROR("raw: SO_ATTACH_FILTER");
        return -1;
    }

    LOG_INFO("raw: BPF filter attached (%d instructions, %d IPs, %d ports)",
             n, ip_count, port_count);
    return 0;
}

/* ---- Public API ---- */

int raw_send_init(const config_t *cfg)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        LOG_PERROR("raw_send: socket");
        return -1;
    }

    /* Bind to outgoing interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = cfg->outgoing_index;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_PERROR("raw_send: bind");
        close(fd);
        return -1;
    }

    /* Performance: increase send buffer (use FORCE to bypass wmem_max) */
    int sndbuf = 16 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0) {
        /* Fallback if not root or FORCE not available */
        sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    /* Performance: QoS priority for low-latency */
    int priority = 6;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));

    /* Performance: bypass qdisc for direct NIC injection */
    int bypass = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &bypass, sizeof(bypass)) < 0) {
        LOG_DEBUG("raw_send: PACKET_QDISC_BYPASS not available (non-critical)");
    }

    LOG_INFO("raw_send: initialized on %s (index %d)", cfg->outgoing_iface, cfg->outgoing_index);
    return fd;
}

int raw_recv_init(const config_t *cfg)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        LOG_PERROR("raw_recv: socket");
        return -1;
    }

    /* Bind to capture interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = cfg->capture_index;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_PERROR("raw_recv: bind");
        close(fd);
        return -1;
    }

    /* Performance: increase receive buffer */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* SO_BUSY_POLL intentionally NOT set — it busy-waits in kernel, wasting CPU.
     * Edge-triggered epoll with PACKET_IGNORE_OUTGOING is more efficient. */

    /* CPU Optimization: explicitly tell the kernel not to loop our own sent packets back into us */
    int ignore_outgoing = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing)) < 0) {
        LOG_DEBUG("raw_recv: PACKET_IGNORE_OUTGOING not available (Linux < 5.x), but non-critical");
    }

    /* Attach BPF filter */
    if (attach_bpf_filter(fd, cfg) < 0) {
        LOG_WARN("raw_recv: BPF filter failed, falling back to userspace filtering");
    }

    LOG_INFO("raw_recv: initialized on %s (index %d)", cfg->capture_iface, cfg->capture_index);
    return fd;
}

int raw_send(int fd, const config_t *cfg, const uint8_t *frame, int frame_len)
{
    /*
     * Static destination struct — built on first call, reused thereafter.
     * Safe because cfg->outgoing_index and cfg->gateway_mac don't change at runtime.
     */
    static struct sockaddr_ll dest;
    static int dest_initialized = 0;

    if (__builtin_expect(!dest_initialized, 0)) {
        memset(&dest, 0, sizeof(dest));
        dest.sll_family   = AF_PACKET;
        dest.sll_ifindex  = cfg->outgoing_index;
        dest.sll_halen    = 6;
        memcpy(dest.sll_addr, cfg->gateway_mac, 6);
        dest_initialized = 1;
    }

    ssize_t sent = sendto(fd, frame, (size_t)frame_len, MSG_DONTWAIT,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
            LOG_PERROR("raw_send: sendto");
        return -1;
    }

    return (int)sent;
}
