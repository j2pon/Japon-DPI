#ifndef JAPONDPI_DNS_REDIR_H
#define JAPONDPI_DNS_REDIR_H

#include "config.h"
#include "wd_loader.h"
#include <stdint.h>
#include <stdbool.h>

#define DNS_TABLE_SIZE 4096 /* power of 2 */
#define DNS_TABLE_MASK (DNS_TABLE_SIZE - 1)

typedef struct {
    uint8_t  valid;
    uint8_t  is_v6;
    uint16_t client_port_net;
    uint16_t orig_dns_port_net;
    uint16_t dns_txid;
    uint32_t client_ip[4];
    uint32_t orig_dns_ip[4];
    uint64_t timestamp_ms;
} DnsNatEntry;

typedef struct {
    DnsNatEntry entries[DNS_TABLE_SIZE];
} DnsRedirector;

void dns_redir_init(DnsRedirector *dr);

/* Flushes Windows DNS resolver cache via dnsapi.dll!DnsFlushResolverCache (GoodbyeDPI style) */
bool dns_flush_system_cache(void);

/* Validates DNS query/response header flags (prevents colliding with non-DNS UDP on alt ports) */
bool dns_is_valid_packet(const uint8_t *payload, UINT payload_len, bool outbound);

/*
 * Processes a UDP DNS packet if DNS redirection applies.
 * Returns:
 *   1 = packet modified (caller should recalculate checksums & inject)
 *   0 = not applicable (pass through untouched)
 *  -1 = drop packet (e.g., --block-dnsv6)
 */
int dns_redir_process(DnsRedirector *dr, const JaponConfig *cfg, JaponStats *stats,
                      bool outbound,
                      PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ipv6_hdr,
                      PWINDIVERT_UDPHDR udp_hdr,
                      const uint8_t *payload, UINT payload_len);

#endif /* JAPONDPI_DNS_REDIR_H */
