#include "packet.h"
#include "log.h"

#include <string.h>
#include <arpa/inet.h>

/* ---- Internal structures (packed for zero-copy building) ---- */

struct __attribute__((packed)) eth_header {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct __attribute__((packed)) ip_header {
    uint8_t  ihl_ver;      /* version (4 bits) + IHL (4 bits) */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct __attribute__((packed)) tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_reserved; /* data offset (4 bits) + reserved (4 bits) */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct __attribute__((packed)) udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t check;
};

/* Pseudo header for TCP/UDP checksum */
struct __attribute__((packed)) pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t length;
};

/* ---- Checksum ---- */

uint16_t pkt_checksum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)p;
        sum += last;
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

static uint16_t transport_checksum(uint32_t saddr, uint32_t daddr,
                                   uint8_t protocol,
                                   const void *transport_hdr,
                                   uint16_t transport_len)
{
    /*
     * Compute checksum incrementally: pseudo-header first, then transport data.
     * No memcpy needed — accumulate the running sum directly.
     */
    struct pseudo_header ph;
    ph.saddr    = saddr;
    ph.daddr    = daddr;
    ph.zero     = 0;
    ph.protocol = protocol;
    ph.length   = htons(transport_len);

    /*
     * Use an aligned local copy for safe uint16_t access.
     * pseudo_header is packed, so we copy to an aligned buffer.
     */
    uint16_t ph_words[sizeof(struct pseudo_header) / 2];
    memcpy(ph_words, &ph, sizeof(ph));

    /* Accumulate pseudo-header */
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(ph) / 2; i++)
        sum += ph_words[i];

    /* Accumulate transport data */
    const uint16_t *p = (const uint16_t *)transport_hdr;
    size_t len = transport_len;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)p;
        sum += last;
    }

    /* Fold */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ---- Ethernet + IP header builder ---- */

static void build_eth(uint8_t *buf, const uint8_t src[6], const uint8_t dst[6])
{
    struct eth_header *eth = (struct eth_header *)buf;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, src, 6);
    eth->ethertype = htons(ETH_P_IP_CONST);
}

/* Global IP identification counter */
static uint16_t g_ip_id = 0;

static void build_ip(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                     uint16_t total_ip_len, uint8_t protocol,
                     uint16_t ip_id, uint16_t frag_off_flags)
{
    struct ip_header *ip = (struct ip_header *)buf;
    ip->ihl_ver  = 0x45;   /* IPv4, IHL=5 (20 bytes) */
    ip->tos      = 0x00;
    ip->tot_len  = htons(total_ip_len);
    ip->id       = htons(ip_id);
    ip->frag_off = htons(frag_off_flags);
    ip->ttl      = 64;
    ip->protocol = protocol;
    ip->check    = 0;
    ip->saddr    = saddr;
    ip->daddr    = daddr;

    ip->check = pkt_checksum(ip, IP_HLEN);
}

/* ---- Public API: non-fragmented builders ---- */

int pkt_build_tcp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint8_t tcp_flags,
                  const uint8_t *payload, uint16_t payload_len)
{
    uint16_t transport_len = TCP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    if ((int)ETH_HLEN_CONST + total_ip_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: payload too large (%u)", payload_len);
        return -1;
    }

    /* Ethernet */
    build_eth(buf, src_mac, dst_mac);

    /* IP — Don't Fragment for non-fragmented packets */
    uint16_t ip_id = g_ip_id++;
    build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip, total_ip_len,
             6 /* IPPROTO_TCP */, ip_id, 0x4000);

    /* TCP */
    struct tcp_header *tcp = (struct tcp_header *)(buf + ETH_HLEN_CONST + IP_HLEN);
    memset(tcp, 0, TCP_HLEN);
    tcp->src_port     = htons(src_port);
    tcp->dst_port     = htons(dst_port);
    tcp->seq          = htonl(0x12345678);  /* Fixed seq — no real conversation */
    tcp->ack_seq      = htonl(0x87654321);  /* Fixed ack */
    tcp->doff_reserved = (TCP_HLEN / 4) << 4; /* Data offset = 5 words */
    tcp->flags        = tcp_flags;
    tcp->window       = htons(65535);

    LOG_DEBUG("packet: TCP header built — flags=0x%02x (byte13=0x%02x) doff=0x%02x",
             tcp_flags, tcp->flags, tcp->doff_reserved);
    tcp->check        = 0;
    tcp->urg_ptr      = 0;

    /* Copy payload after TCP header */
    if (payload && payload_len > 0)
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN + TCP_HLEN, payload, payload_len);

    /* TCP checksum (over pseudo header + TCP header + payload) */
    tcp->check = transport_checksum(src_ip, dst_ip, 6,
                                    tcp, transport_len);

    return ETH_HLEN_CONST + IP_HLEN + transport_len;
}

int pkt_build_udp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  const uint8_t *payload, uint16_t payload_len)
{
    uint16_t transport_len = UDP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    if ((int)ETH_HLEN_CONST + total_ip_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: payload too large (%u)", payload_len);
        return -1;
    }

    /* Ethernet */
    build_eth(buf, src_mac, dst_mac);

    /* IP */
    uint16_t ip_id = g_ip_id++;
    build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip, total_ip_len,
             17 /* IPPROTO_UDP */, ip_id, 0x4000);

    /* UDP */
    struct udp_header *udp = (struct udp_header *)(buf + ETH_HLEN_CONST + IP_HLEN);
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len      = htons(transport_len);
    udp->check    = 0;

    /* Copy payload after UDP header */
    if (payload && payload_len > 0)
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN + UDP_HLEN, payload, payload_len);

    /* UDP checksum */
    udp->check = transport_checksum(src_ip, dst_ip, 17,
                                    udp, transport_len);
    /* UDP checksum 0 means "no checksum" per RFC — use 0xFFFF instead */
    if (udp->check == 0)
        udp->check = 0xFFFF;

    return ETH_HLEN_CONST + IP_HLEN + transport_len;
}

/* ---- Fragmented builders ---- */

/*
 * IP fragmentation strategy:
 *
 * 1. Build the full transport-layer data (transport header + payload) in a
 *    temporary buffer.
 * 2. Split the transport data into fragments such that each IP packet
 *    (IP_HLEN + fragment_data) does not exceed fragment_size.
 * 3. Fragment offsets must be multiples of 8 bytes.
 * 4. First fragment contains the transport header + as much payload as fits.
 * 5. Subsequent fragments contain only payload continuation.
 * 6. All fragments share the same IP ID.
 * 7. All but the last fragment have the MF (More Fragments) flag set.
 */

static int send_fragments(uint8_t *buf,
                          const uint8_t src_mac[6], const uint8_t dst_mac[6],
                          uint32_t src_ip, uint32_t dst_ip,
                          uint8_t protocol,
                          const uint8_t *transport_data, uint16_t transport_len,
                          uint16_t fragment_size,
                          pkt_send_fn send_fn, void *send_ctx)
{
    /* Max payload per fragment (must be multiple of 8) */
    uint16_t max_frag_payload = (uint16_t)((fragment_size - IP_HLEN) & ~7u);
    if (max_frag_payload < 8) {
        LOG_ERROR("packet: fragment_size %u too small", fragment_size);
        return -1;
    }

    uint16_t ip_id = g_ip_id++;
    uint16_t offset = 0;  /* in bytes, relative to start of transport data */

    while (offset < transport_len) {
        uint16_t remaining = transport_len - offset;
        uint16_t frag_payload = (remaining > max_frag_payload) ? max_frag_payload : remaining;
        int more_frags = (offset + frag_payload < transport_len);

        /* Ensure all but last fragment are multiple of 8 */
        if (more_frags && (frag_payload & 7)) {
            frag_payload &= ~(uint16_t)7;
            if (frag_payload == 0) {
                LOG_ERROR("packet: cannot create valid fragment");
                return -1;
            }
        }

        /* Build frame: ETH + IP + fragment_payload */
        build_eth(buf, src_mac, dst_mac);

        uint16_t frag_off_flags = (uint16_t)(offset / 8);
        if (more_frags)
            frag_off_flags |= 0x2000; /* MF flag */

        build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip,
                 (uint16_t)(IP_HLEN + frag_payload), protocol,
                 ip_id, frag_off_flags);

        /* Copy fragment data */
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN, transport_data + offset, frag_payload);

        int frame_len = ETH_HLEN_CONST + IP_HLEN + frag_payload;
        if (send_fn(buf, frame_len, send_ctx) < 0) {
            LOG_ERROR("packet: fragment send failed at offset %u", offset);
            return -1;
        }

        LOG_DEBUG("packet: sent fragment offset=%u len=%u MF=%d",
                  offset, frag_payload, more_frags);

        offset += frag_payload;
    }

    return (int)transport_len;
}

int pkt_send_tcp_fragmented(uint8_t *buf,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx)
{
    uint16_t transport_len = TCP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    /* If it fits without fragmentation, use the simple path */
    if (total_ip_len <= fragment_size) {
        int frame_len = pkt_build_tcp(buf, src_mac, dst_mac,
                                       src_ip, dst_ip,
                                       src_port, dst_port,
                                       tcp_flags, payload, payload_len);
        if (frame_len < 0) return -1;
        return send_fn(buf, frame_len, send_ctx);
    }

    /* Build complete transport segment (TCP header + payload) in a temp buffer */
    uint8_t transport_buf[MAX_PACKET_SIZE];
    if (transport_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: tcp transport too large (%u)", transport_len);
        return -1;
    }

    /* TCP header */
    struct tcp_header *tcp = (struct tcp_header *)transport_buf;
    memset(tcp, 0, TCP_HLEN);
    tcp->src_port      = htons(src_port);
    tcp->dst_port      = htons(dst_port);
    tcp->seq           = htonl(0x12345678);
    tcp->ack_seq       = htonl(0x87654321);
    tcp->doff_reserved = (TCP_HLEN / 4) << 4;
    tcp->flags         = tcp_flags;
    tcp->window        = htons(65535);
    tcp->check         = 0;
    tcp->urg_ptr       = 0;

    LOG_DEBUG("packet: TCP frag header — flags=0x%02x (byte13=0x%02x)",
             tcp_flags, tcp->flags);

    /* Payload */
    if (payload && payload_len > 0)
        memcpy(transport_buf + TCP_HLEN, payload, payload_len);

    /* Compute TCP checksum over the full unfragmented segment */
    tcp->check = transport_checksum(src_ip, dst_ip, 6, tcp, transport_len);

    return send_fragments(buf, src_mac, dst_mac, src_ip, dst_ip,
                          6 /* IPPROTO_TCP */,
                          transport_buf, transport_len,
                          fragment_size, send_fn, send_ctx);
}

int pkt_send_udp_fragmented(uint8_t *buf,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx)
{
    uint16_t transport_len = UDP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    /* If it fits without fragmentation, use the simple path */
    if (total_ip_len <= fragment_size) {
        int frame_len = pkt_build_udp(buf, src_mac, dst_mac,
                                       src_ip, dst_ip,
                                       src_port, dst_port,
                                       payload, payload_len);
        if (frame_len < 0) return -1;
        return send_fn(buf, frame_len, send_ctx);
    }

    /* Build complete transport segment (UDP header + payload) in a temp buffer */
    uint8_t transport_buf[MAX_PACKET_SIZE];
    if (transport_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: udp transport too large (%u)", transport_len);
        return -1;
    }

    /* UDP header */
    struct udp_header *udp = (struct udp_header *)transport_buf;
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len      = htons(transport_len);
    udp->check    = 0;

    /* Payload */
    if (payload && payload_len > 0)
        memcpy(transport_buf + UDP_HLEN, payload, payload_len);

    /* UDP checksum over the full unfragmented datagram */
    udp->check = transport_checksum(src_ip, dst_ip, 17, udp, transport_len);
    if (udp->check == 0)
        udp->check = 0xFFFF;

    return send_fragments(buf, src_mac, dst_mac, src_ip, dst_ip,
                          17 /* IPPROTO_UDP */,
                          transport_buf, transport_len,
                          fragment_size, send_fn, send_ctx);
}

/* ---- Flag parser ---- */

uint8_t pkt_parse_tcp_flags(const char *flag_str)
{
    if (!flag_str || !flag_str[0])
        return TCP_FLAG_PSH | TCP_FLAG_ACK;  /* default */

    uint8_t flags = 0;
    char buf[64];
    strncpy(buf, flag_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Tokenize by '+' */
    char *saveptr = NULL;
    char *tok = strtok_r(buf, "+", &saveptr);

    while (tok) {
        /* Convert to lowercase in-place */
        for (char *c = tok; *c; c++) {
            if (*c >= 'A' && *c <= 'Z')
                *c += 32;
        }

        if (strcmp(tok, "fin") == 0)       flags |= TCP_FLAG_FIN;
        else if (strcmp(tok, "syn") == 0)  flags |= TCP_FLAG_SYN;
        else if (strcmp(tok, "rst") == 0)  flags |= TCP_FLAG_RST;
        else if (strcmp(tok, "psh") == 0)  flags |= TCP_FLAG_PSH;
        else if (strcmp(tok, "ack") == 0)  flags |= TCP_FLAG_ACK;
        else if (strcmp(tok, "urg") == 0)  flags |= TCP_FLAG_URG;
        else LOG_WARN("packet: unknown TCP flag '%s'", tok);

        tok = strtok_r(NULL, "+", &saveptr);
    }

    return flags ? flags : (TCP_FLAG_PSH | TCP_FLAG_ACK);
}
