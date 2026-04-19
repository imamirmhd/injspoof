#ifndef INJSPOOF_RAW_SOCKET_H
#define INJSPOOF_RAW_SOCKET_H

#include "config.h"
#include <stdint.h>

/*
 * Initialize a raw sending socket (AF_PACKET, SOCK_RAW) on
 * the outgoing interface. Includes PACKET_QDISC_BYPASS and
 * increased send buffers for performance.
 * Returns fd on success, -1 on error.
 */
int raw_send_init(const config_t *cfg);

/*
 * Initialize a raw receiving socket (AF_PACKET, SOCK_RAW) on
 * the capture interface with a BPF filter attached.
 * Includes SO_BUSY_POLL for reduced latency.
 * Returns fd on success, -1 on error.
 */
int raw_recv_init(const config_t *cfg);

/*
 * Send a pre-built raw Ethernet frame via the outgoing interface.
 * Returns bytes sent on success, -1 on error.
 */
int raw_send(int fd, const config_t *cfg, const uint8_t *frame, int frame_len);

#endif /* INJSPOOF_RAW_SOCKET_H */
