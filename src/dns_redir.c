#include "dns_redir.h"
#include <string.h>

#define DNS_NAT_EXPIRE_MS 30000ULL /* 30 seconds */

bool dns_flush_system_cache(void) {
    typedef BOOL (WINAPI *pfn_DnsFlushResolverCache)(void);
    HMODULE hDns = LoadLibraryA("dnsapi.dll");
    if (!hDns) return false;
    pfn_DnsFlushResolverCache fn = (pfn_DnsFlushResolverCache)(void *)GetProcAddress(hDns, "DnsFlushResolverCache");
    bool ok = (fn != NULL && fn() != 0);
    FreeLibrary(hDns);
    return ok;
}

bool dns_is_valid_packet(const uint8_t *payload, UINT payload_len, bool outbound) {
    if (!payload || payload_len < 16) return false;
    uint16_t flags = (uint16_t)(((uint16_t)payload[2] << 8) | payload[3]);
    uint16_t qdcount = (uint16_t)(((uint16_t)payload[4] << 8) | payload[5]);
    if (qdcount == 0) return false;
    if (outbound) {
        /* Standard DNS query: QR=0, Opcode=0, TC=0, Z=0, ANCOUNT=0, NSCOUNT=0 */
        uint16_t ancount = (uint16_t)(((uint16_t)payload[6] << 8) | payload[7]);
        uint16_t nscount = (uint16_t)(((uint16_t)payload[8] << 8) | payload[9]);
        return ((flags & 0xFA00) == 0) && ancount == 0 && nscount == 0;
    } else {
        /* Standard DNS response: QR=1, Opcode=0 */
        return ((flags & 0xF800) == 0x8000);
    }
}

static uint32_t dns_slot_hash(bool is_v6, const uint32_t client_ip[4],
                              uint16_t client_port_net, uint16_t txid) {
    uint32_t h = 2166136261U;
    h ^= (uint32_t)(is_v6 ? 1 : 0);
    h *= 16777619U;
    int words = is_v6 ? 4 : 1;
    for (int i = 0; i < words; i++) {
        h ^= client_ip[i];
        h *= 16777619U;
    }
    h ^= ((uint32_t)client_port_net << 16) | (uint32_t)txid;
    h *= 16777619U;
    return h & DNS_TABLE_MASK;
}

static bool ip_equal(bool is_v6, const uint32_t a[4], const uint32_t b[4]) {
    if (!is_v6) return a[0] == b[0];
    return memcmp(a, b, 16) == 0;
}

static bool is_ipv4_loopback_or_mcast(uint32_t ip_net) {
    uint32_t host = ntohl(ip_net);
    uint8_t first = (uint8_t)(host >> 24);
    if (first == 127 || first == 0 || first >= 224) return true;
    return false;
}

static bool is_ipv6_loopback_or_mcast(const uint32_t ip_net[4]) {
    const uint8_t *b = (const uint8_t *)ip_net;
    if (b[0] == 0xFF) return true;
    for (int i = 0; i < 15; i++) {
        if (b[i] != 0) return false;
    }
    return b[15] == 1;
}

void dns_redir_init(DnsRedirector *dr) {
    memset(dr, 0, sizeof(*dr));
}

int dns_redir_process(DnsRedirector *dr, const JaponConfig *cfg, JaponStats *stats,
                      bool outbound,
                      PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ipv6_hdr,
                      PWINDIVERT_UDPHDR udp_hdr,
                      const uint8_t *payload, UINT payload_len) {
    if (!udp_hdr) return 0;

    bool is_v6 = (ipv6_hdr != NULL);
    if (!dns_is_valid_packet(payload, payload_len, outbound)) {
        return 0;
    }

    uint16_t txid = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint64_t now = GetTickCount64();

    if (outbound) {
        if (udp_hdr->DstPort != htons(53)) return 0;

        if (!is_v6) {
            if (!cfg->dns_redir_v4 || !ip_hdr) return 0;
            if (is_ipv4_loopback_or_mcast(ip_hdr->DstAddr)) return 0;

            uint32_t client_ip[4] = { ip_hdr->SrcAddr, 0, 0, 0 };
            uint32_t orig_dst[4]  = { ip_hdr->DstAddr, 0, 0, 0 };
            uint32_t idx = dns_slot_hash(false, client_ip, udp_hdr->SrcPort, txid);

            DnsNatEntry *target = &dr->entries[idx];
            for (uint32_t i = 0; i < 8; i++) {
                DnsNatEntry *e = &dr->entries[(idx + i) & DNS_TABLE_MASK];
                if (!e->valid || (now - e->timestamp_ms) > DNS_NAT_EXPIRE_MS ||
                    (!e->is_v6 && e->client_ip[0] == client_ip[0] &&
                     e->client_port_net == udp_hdr->SrcPort && e->dns_txid == txid)) {
                    target = e;
                    break;
                }
            }

            target->valid = 1;
            target->is_v6 = 0;
            target->client_port_net = udp_hdr->SrcPort;
            target->orig_dns_port_net = udp_hdr->DstPort;
            target->dns_txid = txid;
            target->client_ip[0] = client_ip[0];
            target->orig_dns_ip[0] = orig_dst[0];
            target->timestamp_ms = now;

            ip_hdr->DstAddr = cfg->dns_addr_v4_net;
            udp_hdr->DstPort = htons(cfg->dns_port_v4);
            InterlockedIncrement64(&stats->dns_redirected);
            return 1;
        } else {
            if (!cfg->dns_redir_v6) {
                if (cfg->block_dns_v6) {
                    return -1;
                }
                return 0;
            }
            if (is_ipv6_loopback_or_mcast(ipv6_hdr->DstAddr)) return 0;

            uint32_t client_ip[4];
            uint32_t orig_dst[4];
            memcpy(client_ip, ipv6_hdr->SrcAddr, 16);
            memcpy(orig_dst,  ipv6_hdr->DstAddr, 16);
            uint32_t idx = dns_slot_hash(true, client_ip, udp_hdr->SrcPort, txid);

            DnsNatEntry *target = &dr->entries[idx];
            for (uint32_t i = 0; i < 8; i++) {
                DnsNatEntry *e = &dr->entries[(idx + i) & DNS_TABLE_MASK];
                if (!e->valid || (now - e->timestamp_ms) > DNS_NAT_EXPIRE_MS ||
                    (e->is_v6 && ip_equal(true, e->client_ip, client_ip) &&
                     e->client_port_net == udp_hdr->SrcPort && e->dns_txid == txid)) {
                    target = e;
                    break;
                }
            }

            target->valid = 1;
            target->is_v6 = 1;
            target->client_port_net = udp_hdr->SrcPort;
            target->orig_dns_port_net = udp_hdr->DstPort;
            target->dns_txid = txid;
            memcpy(target->client_ip, client_ip, 16);
            memcpy(target->orig_dns_ip, orig_dst, 16);
            target->timestamp_ms = now;

            memcpy(ipv6_hdr->DstAddr, cfg->dns_addr_v6_net, 16);
            udp_hdr->DstPort = htons(cfg->dns_port_v6);
            InterlockedIncrement64(&stats->dns_redirected);
            return 1;
        }
    } else {
        if (!is_v6) {
            if (!cfg->dns_redir_v4 || !ip_hdr) return 0;
            if (ip_hdr->SrcAddr != cfg->dns_addr_v4_net ||
                udp_hdr->SrcPort != htons(cfg->dns_port_v4)) {
                return 0;
            }

            uint32_t client_ip[4] = { ip_hdr->DstAddr, 0, 0, 0 };
            uint32_t idx = dns_slot_hash(false, client_ip, udp_hdr->DstPort, txid);

            for (uint32_t i = 0; i < 8; i++) {
                DnsNatEntry *e = &dr->entries[(idx + i) & DNS_TABLE_MASK];
                if (e->valid && !e->is_v6 &&
                    e->client_ip[0] == client_ip[0] &&
                    e->client_port_net == udp_hdr->DstPort &&
                    e->dns_txid == txid &&
                    (now - e->timestamp_ms) <= DNS_NAT_EXPIRE_MS) {
                    ip_hdr->SrcAddr = e->orig_dns_ip[0];
                    udp_hdr->SrcPort = e->orig_dns_port_net;
                    return 1;
                }
            }
            return 0;
        } else {
            if (!cfg->dns_redir_v6 || !ipv6_hdr) return 0;
            if (memcmp(ipv6_hdr->SrcAddr, cfg->dns_addr_v6_net, 16) != 0 ||
                udp_hdr->SrcPort != htons(cfg->dns_port_v6)) {
                return 0;
            }

            uint32_t client_ip[4];
            memcpy(client_ip, ipv6_hdr->DstAddr, 16);
            uint32_t idx = dns_slot_hash(true, client_ip, udp_hdr->DstPort, txid);

            for (uint32_t i = 0; i < 8; i++) {
                DnsNatEntry *e = &dr->entries[(idx + i) & DNS_TABLE_MASK];
                if (e->valid && e->is_v6 &&
                    ip_equal(true, e->client_ip, client_ip) &&
                    e->client_port_net == udp_hdr->DstPort &&
                    e->dns_txid == txid &&
                    (now - e->timestamp_ms) <= DNS_NAT_EXPIRE_MS) {
                    memcpy(ipv6_hdr->SrcAddr, e->orig_dns_ip, 16);
                    udp_hdr->SrcPort = e->orig_dns_port_net;
                    return 1;
                }
            }
            return 0;
        }
    }
}
