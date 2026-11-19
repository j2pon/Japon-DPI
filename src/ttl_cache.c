#include "ttl_cache.h"
#include <windows.h>
#include <string.h>

#define TTL_ENTRY_EXPIRE_MS 30000ULL /* 30 seconds (exact GoodbyeDPI conntrack TTL) */

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

uint8_t ttl_compute_auto_fake(uint8_t synack_ttl, uint8_t a1, uint8_t a2,
                              uint8_t min_hops, uint8_t max_ttl) {
    uint16_t nhops = 0;

    if (synack_ttl > 34 && synack_ttl < 64) {
        nhops = (uint16_t)(64 - synack_ttl);
    } else if (synack_ttl >= 96 && synack_ttl <= 120) {
        /* Google/GFE often sends initial TTL=120 or asymmetric 128 return paths;
         * compute conservatively against 120 so fake packets never overshoot outbound hops. */
        nhops = (uint16_t)(120 - synack_ttl);
    } else if (synack_ttl > 120 && synack_ttl < 128) {
        nhops = (uint16_t)(128 - synack_ttl);
    } else {
        return 0;
    }

    if (nhops <= a1 || nhops < min_hops) {
        return 0;
    }

    /* GoodbyeDPI weighted auto-TTL formula */
    int fake = (int)nhops - (int)a2;
    if (fake < (int)a2 && nhops <= 9) {
        fake = (int)nhops - (int)a1 - (((int)a2 - (int)a1) * (int)nhops) / 10;
    }
    if (fake < 1) {
        return 0;
    }
    if (max_ttl > 0 && fake > (int)max_ttl) {
        fake = (int)max_ttl;
    }
    /* Never allow fake packet to reach destination server */
    if (fake >= (int)nhops) {
        fake = (int)nhops - 1;
    }
    return fake >= 1 ? (uint8_t)fake : 0;
}
