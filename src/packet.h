#ifndef INJSPOOF_PACKET_H
#define INJSPOOF_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Ethernet header size */
#define ETH_HLEN_CONST  14
#define ETH_P_IP_CONST  0x0800

/* IP header size (no options) */
#define IP_HLEN  20

/* TCP header size (no options) */
#define TCP_HLEN 20

/* UDP header size */
#define UDP_HLEN 8

/* Maximum single frame size (jumbo-safe) */
#define MAX_PACKET_SIZE 9014

/* TCP flags */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/*
 * Callback for sending a single raw frame.
 * Called once per fragment. Returns bytes sent or -1 on error.
 */
typedef int (*pkt_send_fn)(const uint8_t *frame, int frame_len, void *ctx);

/*
 * Build a complete Ethernet + IP + TCP frame with payload.
 * Returns total frame length, or -1 on error.
 * `buf` must be at least MAX_PACKET_SIZE bytes.
 */
int pkt_build_tcp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint8_t tcp_flags,
                  const uint8_t *payload, uint16_t payload_len);

/*
 * Build a complete Ethernet + IP + UDP frame with payload.
 * Returns total frame length, or -1 on error.
 */
int pkt_build_udp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  const uint8_t *payload, uint16_t payload_len);

/*
 * Build and send a TCP frame, fragmenting at IP level if the total
 * IP packet (IP + TCP + payload) exceeds fragment_size.
 *
 * Each fragment is sent via the send_fn callback.
 * Returns total payload bytes processed on success, -1 on error.
 */
int pkt_send_tcp_fragmented(uint8_t *buf,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx);

/*
 * Build and send a UDP frame, fragmenting at IP level if the total
 * IP packet (IP + UDP + payload) exceeds fragment_size.
 *
 * Each fragment is sent via the send_fn callback.
 * Returns total payload bytes processed on success, -1 on error.
 */
int pkt_send_udp_fragmented(uint8_t *buf,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx);

/*
 * Parse TCP flag string like "psh+ack" or "syn" into a bitmask.
 * Returns the combined flag byte.
 */
uint8_t pkt_parse_tcp_flags(const char *flag_str);

/*
 * Compute IP checksum (RFC 1071 one's complement sum).
 */
uint16_t pkt_checksum(const void *data, size_t len);

#endif /* INJSPOOF_PACKET_H */
