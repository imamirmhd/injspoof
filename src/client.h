#ifndef INJSPOOF_CLIENT_H
#define INJSPOOF_CLIENT_H

#include "config.h"

/*
 * Run the client event loop.
 * - Listens on receiver.udp for local application traffic
 * - Crafts raw packets with spoofed source (stealth.source)
 * - Sends to remote.address:remote.port via raw socket
 * - Supports IP fragmentation when payload exceeds fragment_size
 * - Receives filtered responses and forwards back to local app via UDP
 *
 * Returns 0 on clean shutdown, -1 on error.
 */
int client_run(config_t *cfg);

#endif /* INJSPOOF_CLIENT_H */
