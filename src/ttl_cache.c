#include "ttl_cache.h"
#include <windows.h>
#include <string.h>

#define TTL_ENTRY_EXPIRE_MS 120000ULL /* 2 minutes */

static uint64_t flow_hash(bool is_v6, const uint32_t remote_ip[4],
                          uint16_t remote_port_net, uint16_t local_port_net) {
    uint64_t h = 14695981039346656037ULL;
    h ^= (uint64_t)(is_v6 ? 1 : 0);
    h *= 1099511628211ULL;
    int words = is_v6 ? 4 : 1;
    for (int i = 0; i < words; i++) {
        h ^= (uint64_t)remote_ip[i];
        h *= 1099511628211ULL;
    }
    h ^= ((uint64_t)remote_port_net << 16) | (uint64_t)local_port_net;
    h *= 1099511628211ULL;
    /* Mix top bits into low bits */
    h ^= (h >> 33);
    h *= 0xff51afd7ed558ccdULL;
    h ^= (h >> 33);
    return h ? h : 1;
}

void ttl_cache_init(TtlCache *cache) {
    memset(cache, 0, sizeof(*cache));
}

void ttl_cache_record(TtlCache *cache, bool is_v6, const uint32_t remote_ip[4],
                      uint16_t remote_port_net, uint16_t local_port_net, uint8_t synack_ttl) {
    if (synack_ttl == 0) return;
    uint64_t h = flow_hash(is_v6, remote_ip, remote_port_net, local_port_net);
    uint32_t idx = (uint32_t)(h & TTL_CACHE_MASK);
    uint64_t now = GetTickCount64();

    /* Direct-mapped with 4-slot linear probe for collision resilience */
    for (uint32_t i = 0; i < 4; i++) {
        TtlCacheEntry *e = &cache->entries[(idx + i) & TTL_CACHE_MASK];
        if (!e->valid || e->key_hash == h || (now - e->timestamp_ms) > TTL_ENTRY_EXPIRE_MS) {
            e->key_hash = h;
            e->synack_ttl = synack_ttl;
            e->timestamp_ms = now;
            e->valid = 1;
            return;
        }
    }
    /* Evict primary slot if all 4 full */
    TtlCacheEntry *e = &cache->entries[idx];
    e->key_hash = h;
    e->synack_ttl = synack_ttl;
    e->timestamp_ms = now;
    e->valid = 1;
}

bool ttl_cache_lookup(const TtlCache *cache, bool is_v6, const uint32_t remote_ip[4],
                      uint16_t remote_port_net, uint16_t local_port_net, uint8_t *out_ttl) {
    uint64_t h = flow_hash(is_v6, remote_ip, remote_port_net, local_port_net);
    uint32_t idx = (uint32_t)(h & TTL_CACHE_MASK);
    uint64_t now = GetTickCount64();

    for (uint32_t i = 0; i < 4; i++) {
        const TtlCacheEntry *e = &cache->entries[(idx + i) & TTL_CACHE_MASK];
        if (e->valid && e->key_hash == h && (now - e->timestamp_ms) <= TTL_ENTRY_EXPIRE_MS) {
            if (out_ttl) *out_ttl = e->synack_ttl;
            return true;
        }
    }
    return false;
}

uint8_t ttl_compute_auto_fake(uint8_t synack_ttl, uint8_t delta, uint8_t min_ttl, uint8_t max_ttl) {
    uint16_t init_ttl;
    if (synack_ttl <= 64) {
        init_ttl = 64;
    } else if (synack_ttl <= 120 && synack_ttl >= 96) {
        /* Google/GFE & some CDNs use initial TTL=120 or asymmetric 128 return paths;
         * treat conservatively as 120 so fake TTL never overshoots outbound hop count. */
        init_ttl = 120;
    } else if (synack_ttl <= 128) {
        init_ttl = 128;
    } else {
        init_ttl = 255;
    }

    uint16_t hops = init_ttl - synack_ttl;
    /* Need at least 3 hops so fake expires after ISP DPI but before server */
    if (hops <= 2) {
        return 0;
    }

    int fake = (int)hops - (int)delta;
    if (fake < (int)min_ttl) fake = (int)min_ttl;
    if (fake > (int)max_ttl) fake = (int)max_ttl;

    /* Never allow fake packet to reach destination server */
    if (fake >= (int)hops) {
        fake = (int)hops - 1;
    }
    if (fake < 1) {
        return 0;
    }
    return (uint8_t)fake;
}
