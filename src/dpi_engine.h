#ifndef JAPONDPI_DPI_ENGINE_H
#define JAPONDPI_DPI_ENGINE_H

#include "config.h"
#include "wd_loader.h"
#include "fake_payloads.h"
#include "ttl_cache.h"
#include "dns_redir.h"
#include "domain_list.h"

#define IP_WL_CACHE_SIZE 1024 /* power of 2 */
#define IP_WL_CACHE_MASK (IP_WL_CACHE_SIZE - 1)

typedef struct {
    uint8_t  valid;
    uint8_t  is_v6;
    uint32_t ip[4];
    uint64_t timestamp_ms;
} IpWhitelistEntry;

typedef struct {
    IpWhitelistEntry entries[IP_WL_CACHE_SIZE];
} IpWhitelistCache;

typedef struct {
    JaponConfig      cfg;
    JaponStats       stats;
    FakePayloads     fakes;
    TtlCache         ttl_cache;
    DnsRedirector    dns_redir;
    DomainList       blacklist;
    DomainList       whitelist;
    IpWhitelistCache ip_wl;
    bool             has_blacklist;
    bool             has_whitelist;
    HANDLE           wd_handle;       /* main packet filter */
    HANDLE           wd_drop_passive; /* kernel-only WINDIVERT_FLAG_DROP for -p RSTs */
    HANDLE           wd_drop_quic;    /* kernel-only WINDIVERT_FLAG_DROP for -q QUIC */
    volatile LONG    stop_flag;
} DpiEngine;

typedef struct {
    bool   found_sni;
    size_t sni_offset;
    size_t sni_len;
    char   sni_host[JAPONDPI_MAX_HOST];
} TlsParseResult;

/* Lifecycle */
bool dpi_engine_init(DpiEngine *eng, const JaponConfig *cfg, char *err_buf, size_t err_len);
void dpi_engine_destroy(DpiEngine *eng);
void dpi_engine_request_stop(DpiEngine *eng);

/* Builds optimized WinDivert kernel filter string based on active options */
bool dpi_build_filter(const JaponConfig *cfg, char *buf, size_t buf_len);

/* Main WinDivert packet processing loop (blocking until stopped) */
int  dpi_engine_run(DpiEngine *eng);

/* Pure helper functions (also unit-tested via --self-test) */
bool dpi_parse_tls_client_hello(const uint8_t *payload, size_t len, TlsParseResult *out);
bool dpi_extract_http_host(const uint8_t *payload, size_t len, char *host_out, size_t host_cap);
bool dpi_mangle_http_payload(uint8_t *payload, size_t len, const JaponConfig *cfg);
bool dpi_is_quic_initial(const uint8_t *payload, size_t len);
void dpi_dns_learn_whitelist_ips(const uint8_t *dns_payload, size_t len,
                                 const DomainList *whitelist, IpWhitelistCache *ip_wl);
bool dpi_ip_wl_contains(const IpWhitelistCache *ip_wl, bool is_v6, const uint32_t ip[4]);

#endif /* JAPONDPI_DPI_ENGINE_H */
