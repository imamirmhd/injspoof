#ifndef INJSPOOF_SESSION_H
#define INJSPOOF_SESSION_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

/*
 * Session tracking: maps raw-socket flows to local app connections.
 *
 * When the client receives data from a local app on (local_fd, local_peer),
 * it creates a session keyed by (src_port, protocol) so that when a response
 * arrives via the raw socket, we know which local_fd to forward it to.
 *
 * On the server side, the session maps incoming raw packet flows to the
 * forwarder connections so responses can be routed back.
 */

#define SESSION_TABLE_SIZE  262144 /* ~256k concurrent connections (power of 2, ~14MB) */
#define SESSION_MAX_PROBES  64     /* Wide probe distance for high load factors */
#define SESSION_TTL         30     /* 30s — aggressive GC for fast-rotating spoofed flows */

typedef struct {
    /* Key */
    uint32_t key_ip;        /* identifying IP (local app src, or remote spoofed src) */
    uint16_t key_port;      /* identifying port */
    uint8_t  key_proto;     /* IPPROTO_TCP or IPPROTO_UDP */

    /* Value */
    int      local_fd;      /* fd to forward data back to the local app */
    struct sockaddr_in local_peer;  /* local app address (for UDP sendto) */
    uint8_t  is_tcp;        /* 1 if this is a TCP session */

    /* Metadata */
    time_t   last_seen;
    uint8_t  active;
} session_entry_t;

typedef struct {
    session_entry_t entries[SESSION_TABLE_SIZE];
    int active_count;   /* Track active entries to avoid O(n) scans */
} session_table_t;

/* Update the cached timestamp (call once per event loop iteration).
 * Returns the cached time so callers can avoid a second time() syscall. */
time_t session_update_time(void);

/* Initialize (zero out) the session table */
void session_init(session_table_t *tbl);

/* Insert or update a session. Returns pointer to the entry, or NULL if full. */
session_entry_t *session_upsert(session_table_t *tbl,
                                uint32_t key_ip, uint16_t key_port, uint8_t key_proto,
                                int local_fd, struct sockaddr_in *local_peer,
                                uint8_t is_tcp);

/* Lookup a session by key. Returns pointer if found and not expired, else NULL. */
session_entry_t *session_lookup(session_table_t *tbl,
                                uint32_t key_ip, uint16_t key_port, uint8_t key_proto);

/* Expire stale sessions (call periodically). Returns number expired. */
int session_gc(session_table_t *tbl);

/* Get count of active sessions. */
int session_count(session_table_t *tbl);

#endif /* INJSPOOF_SESSION_H */
