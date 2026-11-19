#ifndef JAPONDPI_CONFIG_H
#define JAPONDPI_CONFIG_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define JAPONDPI_VERSION        "1.1.0"
#define JAPONDPI_MAX_PORTS      16
#define JAPONDPI_MAX_HOST       256
#define JAPONDPI_PACKET_BUF     65536

typedef struct {
    /* Fragmentation (GoodbyeDPI-exact semantics) */
    uint16_t http_frag_size;        /* -f <N>: HTTP split offset (e.g., 2) */
    uint16_t https_frag_size;       /* -e <N>: HTTPS/TLS split offset (e.g., 2) */
    bool     frag_by_sni;           /* --frag-by-sni / --split-sni: cut at SNI */
    bool     multi_split;           /* --multi-split: 3-part TLS split */
    bool     reverse_frag;          /* --reverse-frag: send 2nd fragment before 1st (default in -5..-9) */

    /* HTTP header tricks (length-preserving) */
    bool     http_host_replace;     /* -r / --http-replace: Host: -> hoSt: */
    bool     http_host_rmspace;     /* -s / --http-rmspace: Host: x -> Host:x */
    bool     http_host_mixcase;     /* -m / --http-mixcase: example.com -> ExAmPlE.cOm */

    /* Passive DPI / TCP window */
    bool     passive_block;         /* -p / --passive-block: kernel-drop spoofed RST + drop HTTP 302 */
    uint16_t window_size;           /* -w <N>: shrink inbound SYN-ACK TCP window (0=off) */

    /* Fake packet injection (each fooling mode sends its own packet, like GoodbyeDPI) */
    uint8_t  fake_ttl;              /* --set-ttl <N>: fixed TTL (disables auto_ttl!) */
    bool     auto_ttl;              /* --auto-ttl [a1-a2-m]: dynamic hop-based TTL */
    uint8_t  auto_ttl_1;            /* default 1 */
    uint8_t  auto_ttl_2;            /* default 4 */
    uint8_t  auto_ttl_max;          /* default 10 (clamped safely on Google TTL=120) */
    uint8_t  min_ttl;               /* --min-ttl <N>: min hop distance to send fake (default 3 in auto-ttl) */
    bool     wrong_checksum;        /* --wrong-chksum / --wrong-checksum */
    bool     wrong_seq;             /* --wrong-seq: seq-10000, ack-66000 */
    uint8_t  fake_repeats;          /* --fake-resend / --fake-repeats <N> (1..10) */
    char     fake_sni[JAPONDPI_MAX_HOST];       /* --fake-sni (default www.w3.org) */
    char     fake_http_host[JAPONDPI_MAX_HOST]; /* --fake-http-host (default www.w3.org) */

    /* DNS redirection */
    bool     dns_redir_v4;
    uint32_t dns_addr_v4_net;       /* IPv4 target in network byte order */
    char     dns_addr_v4_str[64];
    uint16_t dns_port_v4;           /* host byte order */

    bool     dns_redir_v6;
    uint8_t  dns_addr_v6_net[16];   /* IPv6 target in network byte order */
    char     dns_addr_v6_str[64];
    uint16_t dns_port_v6;           /* host byte order */
    bool     block_dns_v6;          /* --block-dnsv6: drop outbound IPv6 UDP:53 */

    /* QUIC blocking (-q / --block-quic) */
    bool     block_quic;            /* OFF in -5 (keeps HTTP/3 fast!), ON in -9 */

    /* Extra TCP ports */
    uint16_t extra_ports[JAPONDPI_MAX_PORTS];
    int      extra_port_count;

    /* Filtering */
    uint16_t max_payload;           /* --max-payload <N> (0 = unlimited for TLS ClientHello) */
    char     blacklist_path[MAX_PATH];
    char     whitelist_path[MAX_PATH];

    /* Runtime flags */
    bool     verbose;               /* -v / --verbose */
    bool     quiet;                 /* -q-quiet / --quiet */
    bool     run_as_service;        /* --service */
    bool     test_filter;           /* --test-filter */
} JaponConfig;

typedef struct {
    volatile LONG64 packets_total;
    volatile LONG64 tls_bypassed;
    volatile LONG64 http_bypassed;
    volatile LONG64 fake_sent;
    volatile LONG64 dns_redirected;
    volatile LONG64 quic_blocked;
    volatile LONG64 passive_dropped;
} JaponStats;

static inline void config_set_defaults(JaponConfig *cfg) {
    ZeroMemory(cfg, sizeof(*cfg));
    cfg->auto_ttl_1   = 1;
    cfg->auto_ttl_2   = 4;
    cfg->auto_ttl_max = 10;
    cfg->min_ttl      = 0;
    cfg->fake_repeats = 1;
    cfg->dns_port_v4  = 53;
    cfg->dns_port_v6  = 53;
    lstrcpynA(cfg->fake_sni, "www.w3.org", sizeof(cfg->fake_sni));
    lstrcpynA(cfg->fake_http_host, "www.w3.org", sizeof(cfg->fake_http_host));
}

#endif /* JAPONDPI_CONFIG_H */
