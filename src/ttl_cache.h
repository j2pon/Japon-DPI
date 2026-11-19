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

/* Computes safe fake TTL strictly smaller than estimated server hop distance. Returns 0 if unsafe. */
uint8_t ttl_compute_auto_fake(uint8_t synack_ttl, uint8_t delta, uint8_t min_ttl, uint8_t max_ttl);

#endif /* JAPONDPI_TTL_CACHE_H */
