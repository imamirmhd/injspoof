#include "session.h"
#include "log.h"

#include <string.h>
#include <time.h>

/* Cached timestamp — updated once per event loop iteration, not per-packet */
static time_t g_cached_time = 0;

void session_update_time(void)
{
    g_cached_time = time(NULL);
}

/* FNV-1a hash for session key */
static inline uint32_t session_hash(uint32_t ip, uint16_t port, uint8_t proto)
{
    uint32_t h = 2166136261u;
    h ^= ip;            h *= 16777619u;
    h ^= port;          h *= 16777619u;
    h ^= proto;         h *= 16777619u;
    return h & (SESSION_TABLE_SIZE - 1);
}

void session_init(session_table_t *tbl)
{
    memset(tbl, 0, sizeof(session_table_t));
    tbl->active_count = 0;
    g_cached_time = time(NULL);
    LOG_INFO("session: table initialized (%d slots, %zu KB)",
             SESSION_TABLE_SIZE,
             sizeof(session_table_t) / 1024);
}

session_entry_t *session_upsert(session_table_t *tbl,
                                uint32_t key_ip, uint16_t key_port, uint8_t key_proto,
                                int local_fd, struct sockaddr_in *local_peer,
                                uint8_t is_tcp)
{
    uint32_t idx = session_hash(key_ip, key_port, key_proto);
    time_t now = g_cached_time;

    /* Linear probing — search for existing or empty slot */
    for (int i = 0; i < SESSION_MAX_PROBES; i++) {
        uint32_t slot = (idx + (uint32_t)i) & (SESSION_TABLE_SIZE - 1);
        session_entry_t *e = &tbl->entries[slot];

        /* Found existing matching entry — update */
        if (e->active &&
            e->key_ip == key_ip &&
            e->key_port == key_port &&
            e->key_proto == key_proto)
        {
            e->local_fd   = local_fd;
            if (local_peer)
                e->local_peer = *local_peer;
            e->is_tcp     = is_tcp;
            e->last_seen  = now;
            return e;
        }

        /* Found empty or expired slot — insert */
        if (!e->active || (now - e->last_seen > SESSION_TTL)) {
            if (!e->active)
                tbl->active_count++;
            e->key_ip     = key_ip;
            e->key_port   = key_port;
            e->key_proto  = key_proto;
            e->local_fd   = local_fd;
            if (local_peer)
                e->local_peer = *local_peer;
            else
                memset(&e->local_peer, 0, sizeof(e->local_peer));
            e->is_tcp     = is_tcp;
            e->last_seen  = now;
            e->active     = 1;
            return e;
        }
    }

    LOG_WARN("session: table full at hash %u, probe exhausted", idx);
    return NULL;
}

session_entry_t *session_lookup(session_table_t *tbl,
                                uint32_t key_ip, uint16_t key_port, uint8_t key_proto)
{
    uint32_t idx = session_hash(key_ip, key_port, key_proto);
    time_t now = g_cached_time;

    for (int i = 0; i < SESSION_MAX_PROBES; i++) {
        uint32_t slot = (idx + (uint32_t)i) & (SESSION_TABLE_SIZE - 1);
        session_entry_t *e = &tbl->entries[slot];

        if (!e->active)
            return NULL;  /* empty slot — not found */

        if (e->key_ip == key_ip &&
            e->key_port == key_port &&
            e->key_proto == key_proto)
        {
            /* Check TTL */
            if (now - e->last_seen > SESSION_TTL) {
                e->active = 0;
                tbl->active_count--;
                return NULL;
            }
            return e;
        }
    }

    return NULL;
}

int session_gc(session_table_t *tbl)
{
    /* Skip expensive scan if table is empty */
    if (tbl->active_count == 0)
        return 0;

    time_t now = g_cached_time;
    int expired = 0;

    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        session_entry_t *e = &tbl->entries[i];
        if (e->active && (now - e->last_seen > SESSION_TTL)) {
            e->active = 0;
            expired++;
        }
    }

    tbl->active_count -= expired;

    if (expired > 0)
        LOG_DEBUG("session: GC expired %d sessions, %d remaining", expired, tbl->active_count);

    return expired;
}

int session_count(session_table_t *tbl)
{
    return tbl->active_count;
}
