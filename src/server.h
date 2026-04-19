#ifndef INJSPOOF_SERVER_H
#define INJSPOOF_SERVER_H

#include "config.h"

/*
 * Run the server event loop.
 * - Listens on raw socket for filtered incoming packets
 * - Extracts payload and forwards to forwarder.udp backend
 * - Receives responses from backend and sends back via raw socket
 *   with spoofed source (stealth.source)
 * - Supports IP fragmentation when payload exceeds fragment_size
 *
 * Returns 0 on clean shutdown, -1 on error.
 */
int server_run(config_t *cfg);

#endif /* INJSPOOF_SERVER_H */
