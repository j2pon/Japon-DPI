#ifndef JAPONDPI_TTL_CACHE_H
#define JAPONDPI_TTL_CACHE_H

#include <stdint.h>
#include <stdbool.h>

#define TTL_CACHE_SIZE 4096 /* must be power of 2 */
#define TTL_CACHE_MASK (TTL_CACHE_SIZE - 1)

typedef struct {
    uint64_t key_hash;
    uint8_t  synack_ttl;
    uint8_t  valid;
    uint64_t timestamp_ms;
} TtlCacheEntry;

typedef struct {
    TtlCacheEntry entries[TTL_CACHE_SIZE];
} TtlCache;

void    ttl_cache_init(TtlCache *cache);
void    ttl_cache_record(TtlCache *cache, bool is_v6, const uint32_t remote_ip[4],
                         uint16_t remote_port_net, uint16_t local_port_net, uint8_t synack_ttl);
bool    ttl_cache_lookup(const TtlCache *cache, bool is_v6, const uint32_t remote_ip[4],
                         uint16_t remote_port_net, uint16_t local_port_net, uint8_t *out_ttl);

/* GoodbyeDPI-compatible auto-TTL calculator with Google asymmetric TTL=120 protection.
 * Returns 0 if server is too close (nhops <= a1 or nhops < min_hops). */
uint8_t ttl_compute_auto_fake(uint8_t synack_ttl, uint8_t a1, uint8_t a2,
                              uint8_t min_hops, uint8_t max_ttl);

#endif /* JAPONDPI_TTL_CACHE_H */
