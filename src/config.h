#ifndef INJSPOOF_CONFIG_H
#define INJSPOOF_CONFIG_H

#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <net/if.h>

#define MODE_CLIENT 0
#define MODE_SERVER 1

#define MAX_SOURCE_IPS   1024   /* supports up to /22 CIDR expansion */
#define MAX_SOURCE_PORTS 16

#define DEFAULT_FRAGMENT_SIZE 1400

/* Address pool type */
typedef enum {
    ADDR_STATIC = 0,
    ADDR_FILE   = 1
} addr_type_t;

/* IP selection strategy */
typedef enum {
    BALANCE_ROUND_ROBIN = 0
} balance_strategy_t;

/* Simple endpoint: address + port */
typedef struct {
    char     address[INET_ADDRSTRLEN];
    uint16_t port;
} endpoint_t;

/* Protocol obfuscation settings */
typedef struct {
    char mode[8];     /* "tcp" or "udp" */
    char flag[32];    /* "psh+ack", "syn", etc. — TCP only */
} protocol_t;

/*
 * CIDR subnet representation (inclusive bounds).
 * Stored in network-byte order for zero-cost hot-path filtering.
 */
typedef struct {
    uint32_t first_ip;    /* First usable IP (network-order) */
    uint32_t last_ip;     /* Last usable IP (network-order) */
    uint32_t host_count;  /* Number of usable IPs in this block */
} cidr_t;

/*
 * Source address pool — used for both spoofed source and capture filter.
 *
 * Supports two modes:
 *   - static: IPs listed directly in JSON array
 *   - file:   IPs loaded from a text file (one per line)
 *
 * At load time, all CIDR blocks are parsed into exact bounds [first, last].
 */
typedef struct {
    addr_type_t type;

    cidr_t      subnets[MAX_SOURCE_IPS]; /* List of CIDR blocks */
    int         count;                   /* Number of blocks */
    uint32_t    total_hosts;             /* Sum of host_count across all blocks */

    /* File path for ADDR_FILE mode */
    char        file_path[256];

    /* Ports */
    uint16_t    ports[MAX_SOURCE_PORTS];
    int         port_count;
} source_pool_t;

typedef struct {
    /* --- Local endpoint --- */
    /* Client: UDP listener (listen)  |  Server: UDP forwarder target (forward) */
    endpoint_t      local_endpoint;

    /* --- Remote target --- */
    /* Client: connect.to  |  Server: response.to */
    endpoint_t      remote;

    /* --- Spoofed source pool --- */
    /* Client: connect.with.source  |  Server: response.with.source */
    source_pool_t   source;

    /* --- Protocol obfuscation --- */
    /* Client: connect.protocol  |  Server: response.protocol */
    protocol_t      protocol;

    /* --- Capture settings --- */
    char            capture_iface[IFNAMSIZ];
    source_pool_t   capture_filter;

    /* --- Outgoing settings --- */
    char            outgoing_iface[IFNAMSIZ];
    uint8_t         gateway_mac[6];

    /* --- Tuning --- */
    uint16_t        fragment_size;
    balance_strategy_t ip_strategy;
    int             steal_client_source_ip;  /* server only */
    int             log_level;               /* 0=error, 1=warn, 2=info, 3=debug */

    /* --- Derived at runtime --- */
    uint8_t         outgoing_mac[6];     /* auto-detected from outgoing_iface */
    int             outgoing_index;      /* auto-detected interface index */
    int             capture_index;       /* auto-detected capture iface index */
    atomic_int      rr_ip_index;         /* round-robin counter for source IPs */
    atomic_int      rr_port_index;       /* round-robin counter for source ports */

    /* Operating mode */
    int             mode;
} config_t;

/* Parse a JSON config file into config_t. Returns 0 on success, -1 on error. */
int config_load(config_t *cfg, const char *path, int mode);

/* Print config summary to stderr for verification. */
void config_dump(const config_t *cfg);

/* Get the next source IP (network order) via round-robin. */
uint32_t config_next_source_ip(config_t *cfg);

/* Get the next source port via round-robin. */
uint16_t config_next_source_port(config_t *cfg);

#endif /* INJSPOOF_CONFIG_H */
