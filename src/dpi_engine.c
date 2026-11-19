#include "dpi_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* GoodbyeDPI-style private/local network exclusions (zero LAN/router interference) */
#define NO_LOCALNETS_V4_DST \
    "((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
    "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
    "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
    "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
    "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))"

#define NO_LOCALNETS_V4_SRC \
    "((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
    "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
    "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
    "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
    "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))"

#define NO_LOCALNETS_V6_DST \
    "((ipv6.DstAddr > ::1) and " \
    "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and " \
    "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and " \
    "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0))"

#define NO_LOCALNETS_V6_SRC \
    "((ipv6.SrcAddr > ::1) and " \
    "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and " \
    "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and " \
    "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0))"

/* Kernel-only DROP filters (exact GoodbyeDPI zero-usermode architecture) */
#define FILTER_KERNEL_DROP_QUIC \
    "outbound and !impostor and !loopback and udp and udp.DstPort == 443 and " \
    "udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and " \
    "(udp.Payload32[1b] == 0x01 or udp.Payload32[1b] == 0x6b3343cf)"

#define FILTER_KERNEL_DROP_PASSIVE_RST \
    "inbound and ip and tcp and !impostor and !loopback and " \
    "(ip.Id >= 0x0 and ip.Id <= 0xF) and " \
    "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and " \
    NO_LOCALNETS_V4_SRC

/* ============================================================================
 * Pure Packet Parsers & Helpers
 * ========================================================================== */

bool dpi_parse_tls_client_hello(const uint8_t *payload, size_t len, TlsParseResult *out) {
    memset(out, 0, sizeof(*out));
    if (!payload || len < 43) return false;

    /* TLS Record Header: 0x16 (Handshake), 0x03 0x00..0x03 */
    if (payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04) {
        return false;
    }
    /* Handshake Type: 0x01 (ClientHello) */
    if (payload[5] != 0x01) {
        return false;
    }

    size_t pos = 9;
    if (pos + 2 + 32 + 1 > len) return true;

    pos += 2;  /* client_version */
    pos += 32; /* random */

    /* Session ID */
    uint8_t sid_len = payload[pos++];
    if (pos + sid_len + 2 > len) return true;
    pos += sid_len;

    /* Cipher Suites */
    uint16_t cs_len = (uint16_t)(((uint16_t)payload[pos] << 8) | payload[pos + 1]);
    pos += 2;
    if (pos + cs_len + 1 > len) return true;
    pos += cs_len;

    /* Compression Methods */
    uint8_t cm_len = payload[pos++];
    if (pos + cm_len + 2 > len) return true;
    pos += cm_len;

    /* Extensions Total Length */
    uint16_t ext_total = (uint16_t)(((uint16_t)payload[pos] << 8) | payload[pos + 1]);
    pos += 2;

    size_t ext_end = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (uint16_t)(((uint16_t)payload[pos] << 8) | payload[pos + 1]);
        uint16_t ext_len  = (uint16_t)(((uint16_t)payload[pos + 2] << 8) | payload[pos + 3]);
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t sni_pos = pos;
            uint16_t list_len = (uint16_t)(((uint16_t)payload[sni_pos] << 8) | payload[sni_pos + 1]);
            sni_pos += 2;
            size_t list_end = sni_pos + list_len;
            if (list_end > pos + ext_len) list_end = pos + ext_len;

            while (sni_pos + 3 <= list_end) {
                uint8_t  name_type = payload[sni_pos++];
                uint16_t name_len  = (uint16_t)(((uint16_t)payload[sni_pos] << 8) | payload[sni_pos + 1]);
                sni_pos += 2;
                if (sni_pos + name_len > list_end) break;

                if (name_type == 0x00 && name_len > 0) {
                    out->found_sni  = true;
                    out->sni_offset = sni_pos;
                    out->sni_len    = name_len;
                    size_t copy_len = name_len < (JAPONDPI_MAX_HOST - 1) ? name_len : (JAPONDPI_MAX_HOST - 1);
                    for (size_t i = 0; i < copy_len; i++) {
                        out->sni_host[i] = (char)tolower((unsigned char)payload[sni_pos + i]);
                    }
                    out->sni_host[copy_len] = '\0';
                    return true;
                }
                sni_pos += name_len;
            }
        }
        pos += ext_len;
    }

    return true;
}

static int find_http_method_space(const uint8_t *payload, size_t len) {
    static const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "
    };
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t mlen = strlen(methods[i]);
        if (len > mlen && memcmp(payload, methods[i], mlen) == 0) {
            return (int)(mlen - 1);
        }
    }
    return -1;
}

static bool find_http_host_header(const uint8_t *payload, size_t len,
                                  size_t *out_hdr_pos, size_t *out_val_pos, size_t *out_val_len) {
    if (len < 16) return false;
    if (find_http_method_space(payload, len) < 0) return false;

    for (size_t i = 0; i + 7 < len; i++) {
        if (payload[i] == '\r' && payload[i + 1] == '\n') {
            if (i + 3 < len && payload[i + 2] == '\r' && payload[i + 3] == '\n') {
                break;
            }
            size_t h = i + 2;
            if (h + 5 <= len &&
                tolower(payload[h])     == 'h' &&
                tolower(payload[h + 1]) == 'o' &&
                tolower(payload[h + 2]) == 's' &&
                tolower(payload[h + 3]) == 't' &&
                payload[h + 4] == ':') {
                size_t v = h + 5;
                while (v < len && (payload[v] == ' ' || payload[v] == '\t')) v++;
                size_t vend = v;
                while (vend < len && payload[vend] != '\r' && payload[vend] != '\n') vend++;
                if (vend > v) {
                    *out_hdr_pos = h;
                    *out_val_pos = v;
                    *out_val_len = vend - v;
                    return true;
                }
            }
        }
    }
    return false;
}

bool dpi_extract_http_host(const uint8_t *payload, size_t len, char *host_out, size_t host_cap) {
    if (!host_out || host_cap == 0) return false;
    host_out[0] = '\0';

    size_t hdr_pos, val_pos, val_len;
    if (!find_http_host_header(payload, len, &hdr_pos, &val_pos, &val_len)) {
        return false;
    }

    size_t n = 0;
    for (size_t i = 0; i < val_len && n + 1 < host_cap; i++) {
        unsigned char c = payload[val_pos + i];
        if (c == ':' || c == ' ' || c == '\t') break;
        host_out[n++] = (char)tolower(c);
    }
    host_out[n] = '\0';
    return n > 0;
}

bool dpi_mangle_http_payload(uint8_t *payload, size_t len, const JaponConfig *cfg) {
    size_t hdr_pos, val_pos, val_len;
    int method_sp = find_http_method_space(payload, len);
    if (method_sp < 0) return false;
    if (!find_http_host_header(payload, len, &hdr_pos, &val_pos, &val_len)) {
        return false;
    }

    bool modified = false;

    if (cfg->http_host_replace) {
        payload[hdr_pos + 0] = 'h';
        payload[hdr_pos + 1] = 'o';
        payload[hdr_pos + 2] = 'S';
        payload[hdr_pos + 3] = 't';
        modified = true;
    }

    if (cfg->http_host_mixcase) {
        for (size_t i = 0; i < val_len; i++) {
            unsigned char c = payload[val_pos + i];
            if (c == ':') break;
            if (isalpha(c)) {
                payload[val_pos + i] = (uint8_t)((i & 1) ? toupper(c) : tolower(c));
            }
        }
        modified = true;
    }

    if (cfg->http_host_rmspace) {
        size_t host_sp = hdr_pos + 5;
        if (host_sp < len && payload[host_sp] == ' ' && (size_t)method_sp < host_sp) {
            memmove(payload + method_sp + 1, payload + method_sp, host_sp - (size_t)method_sp);
            payload[method_sp] = ' ';
            modified = true;
        }
    }

    return modified;
}

bool dpi_is_quic_initial(const uint8_t *payload, size_t len) {
    if (!payload || len < 1200) return false;
    if ((payload[0] & 0xC0) != 0xC0) return false;

    uint32_t ver = ((uint32_t)payload[1] << 24) |
                   ((uint32_t)payload[2] << 16) |
                   ((uint32_t)payload[3] << 8)  |
                   ((uint32_t)payload[4]);

    if (ver == 0x00000001U) return ((payload[0] & 0x30) == 0x00);
    if (ver == 0x6b3343cfU) return ((payload[0] & 0x30) == 0x10);
    if ((ver & 0xFFFFFF00U) == 0xFF000000U) return ((payload[0] & 0x30) == 0x00);
    return false;
}

/* ============================================================================
 * Whitelisted IP Cache (for 0-RTT QUIC pass-through when -q + --whitelist used)
 * ========================================================================== */

#define IP_WL_EXPIRE_MS 600000ULL /* 10 minutes */

static uint32_t ip_wl_hash(bool is_v6, const uint32_t ip[4]) {
    uint32_t h = 2166136261U;
    h ^= (uint32_t)(is_v6 ? 1 : 0);
    h *= 16777619U;
    int words = is_v6 ? 4 : 1;
    for (int i = 0; i < words; i++) {
        h ^= ip[i];
        h *= 16777619U;
    }
    return h & IP_WL_CACHE_MASK;
}

static void ip_wl_add(IpWhitelistCache *cache, bool is_v6, const uint32_t ip[4]) {
    uint32_t idx = ip_wl_hash(is_v6, ip);
    uint64_t now = GetTickCount64();
    IpWhitelistEntry *slot = &cache->entries[idx];
    for (uint32_t i = 0; i < 4; i++) {
        IpWhitelistEntry *e = &cache->entries[(idx + i) & IP_WL_CACHE_MASK];
        if (!e->valid || (now - e->timestamp_ms) > IP_WL_EXPIRE_MS ||
            (e->is_v6 == (is_v6 ? 1 : 0) &&
             (is_v6 ? (memcmp(e->ip, ip, 16) == 0) : (e->ip[0] == ip[0])))) {
            slot = e;
            break;
        }
    }
    slot->valid = 1;
    slot->is_v6 = is_v6 ? 1 : 0;
    if (is_v6) {
        memcpy(slot->ip, ip, 16);
    } else {
        slot->ip[0] = ip[0];
        slot->ip[1] = slot->ip[2] = slot->ip[3] = 0;
    }
    slot->timestamp_ms = now;
}

bool dpi_ip_wl_contains(const IpWhitelistCache *cache, bool is_v6, const uint32_t ip[4]) {
    if (!cache) return false;
    uint32_t idx = ip_wl_hash(is_v6, ip);
    uint64_t now = GetTickCount64();
    for (uint32_t i = 0; i < 4; i++) {
        const IpWhitelistEntry *e = &cache->entries[(idx + i) & IP_WL_CACHE_MASK];
        if (e->valid && e->is_v6 == (is_v6 ? 1 : 0) &&
            (now - e->timestamp_ms) <= IP_WL_EXPIRE_MS) {
            if (is_v6 ? (memcmp(e->ip, ip, 16) == 0) : (e->ip[0] == ip[0])) {
                return true;
            }
        }
    }
    return false;
}

void dpi_dns_learn_whitelist_ips(const uint8_t *dns, size_t len,
                                 const DomainList *whitelist, IpWhitelistCache *ip_wl) {
    if (!dns || len < 17 || !whitelist || !ip_wl) return;
    if ((dns[2] & 0x80) == 0 || (dns[3] & 0x0F) != 0) return;

    uint16_t qdcount = (uint16_t)(((uint16_t)dns[4] << 8) | dns[5]);
    uint16_t ancount = (uint16_t)(((uint16_t)dns[6] << 8) | dns[7]);
    if (qdcount == 0 || ancount == 0) return;

    char qname[JAPONDPI_MAX_HOST];
    size_t qlen = 0;
    size_t pos = 12;
    while (pos < len) {
        uint8_t lab = dns[pos++];
        if (lab == 0) break;
        if ((lab & 0xC0) != 0 || pos + lab > len) return;
        if (qlen > 0 && qlen + 1 < sizeof(qname)) {
            qname[qlen++] = '.';
        }
        for (uint8_t i = 0; i < lab; i++) {
            if (qlen + 1 < sizeof(qname)) {
                qname[qlen++] = (char)tolower(dns[pos + i]);
            }
        }
        pos += lab;
    }
    qname[qlen] = '\0';
    if (qlen == 0 || pos + 4 > len) return;
    pos += 4;

    for (uint16_t q = 1; q < qdcount; q++) {
        while (pos < len) {
            uint8_t b = dns[pos++];
            if (b == 0) break;
            if ((b & 0xC0) == 0xC0) { pos++; break; }
            pos += b;
        }
        if (pos + 4 > len) return;
        pos += 4;
    }

    if (!domain_list_matches(whitelist, qname)) {
        return;
    }

    uint16_t limit = ancount > 32 ? 32 : ancount;
    for (uint16_t a = 0; a < limit && pos < len; a++) {
        while (pos < len) {
            uint8_t b = dns[pos];
            if (b == 0) { pos++; break; }
            if ((b & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + b;
        }
        if (pos + 10 > len) break;
        uint16_t rtype = (uint16_t)(((uint16_t)dns[pos] << 8) | dns[pos + 1]);
        uint16_t rdlen = (uint16_t)(((uint16_t)dns[pos + 8] << 8) | dns[pos + 9]);
        pos += 10;
        if (pos + rdlen > len) break;

        if (rtype == 1 && rdlen == 4) {
            uint32_t ip4[4] = {0};
            memcpy(&ip4[0], dns + pos, 4);
            ip_wl_add(ip_wl, false, ip4);
        } else if (rtype == 28 && rdlen == 16) {
            uint32_t ip6[4];
            memcpy(ip6, dns + pos, 16);
            ip_wl_add(ip_wl, true, ip6);
        }
        pos += rdlen;
    }
}

/* ============================================================================
 * WinDivert Kernel Filter Builder (GoodbyeDPI-grade zero-overhead filter)
 * ========================================================================== */

static bool append_str(char *buf, size_t buf_len, size_t *pos, const char *s) {
    size_t slen = strlen(s);
    if (*pos + slen >= buf_len) return false;
    memcpy(buf + *pos, s, slen);
    *pos += slen;
    buf[*pos] = '\0';
    return true;
}

bool dpi_build_filter(const JaponConfig *cfg, char *buf, size_t buf_len) {
    size_t pos = 0;
    buf[0] = '\0';

    if (!append_str(buf, buf_len, &pos, "!impostor and !loopback and (")) return false;

    char tmp[1024];

    /* 1. Outbound TLS ClientHello (port 443 + extra ports), EXCLUDING local/private networks!
     *    Kernel-level 0x16 0x03 .. 0x01 check means 100% of bulk HTTPS traffic stays in kernel! */
    char tls_ports[256];
    size_t tp = 0;
    tls_ports[0] = '\0';
    append_str(tls_ports, sizeof(tls_ports), &tp, "tcp.DstPort == 443");
    for (int i = 0; i < cfg->extra_port_count; i++) {
        char pbuf[32];
        snprintf(pbuf, sizeof(pbuf), " or tcp.DstPort == %u", (unsigned)cfg->extra_ports[i]);
        append_str(tls_ports, sizeof(tls_ports), &tp, pbuf);
    }

    if (cfg->max_payload > 0) {
        snprintf(tmp, sizeof(tmp),
            "(outbound and tcp and tcp.Ack and (%s) and "
            "tcp.PayloadLength >= 6 and tcp.PayloadLength <= %u and "
            "tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03 and tcp.Payload[5] == 0x01 and "
            "(" NO_LOCALNETS_V4_DST " or " NO_LOCALNETS_V6_DST "))",
            tls_ports, (unsigned)cfg->max_payload);
    } else {
        snprintf(tmp, sizeof(tmp),
            "(outbound and tcp and tcp.Ack and (%s) and "
            "tcp.PayloadLength >= 6 and "
            "tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03 and tcp.Payload[5] == 0x01 and "
            "(" NO_LOCALNETS_V4_DST " or " NO_LOCALNETS_V6_DST "))",
            tls_ports);
    }
    if (!append_str(buf, buf_len, &pos, tmp)) return false;

    /* 2. Outbound HTTP requests (port 80), excluding local/private networks */
    uint16_t http_max = (cfg->max_payload > 0) ? cfg->max_payload : 1500;
    snprintf(tmp, sizeof(tmp),
        " or (outbound and tcp and tcp.Ack and tcp.DstPort == 80 and "
        "tcp.PayloadLength >= 16 and tcp.PayloadLength <= %u and "
        "(" NO_LOCALNETS_V4_DST " or " NO_LOCALNETS_V6_DST "))",
        (unsigned)http_max);
    if (!append_str(buf, buf_len, &pos, tmp)) return false;

    /* 3. Inbound SYN-ACK ONLY when auto-ttl, min-ttl, or window-size requires it!
     *    With --set-ttl 5 (no auto-ttl, no min-ttl), ZERO inbound TCP packets enter user-mode! */
    if (cfg->auto_ttl || cfg->min_ttl > 0 || cfg->window_size > 0) {
        char src_ports[256];
        size_t sp = 0;
        src_ports[0] = '\0';
        append_str(src_ports, sizeof(src_ports), &sp, "tcp.SrcPort == 443 or tcp.SrcPort == 80");
        for (int i = 0; i < cfg->extra_port_count; i++) {
            char pbuf[32];
            snprintf(pbuf, sizeof(pbuf), " or tcp.SrcPort == %u", (unsigned)cfg->extra_ports[i]);
            append_str(src_ports, sizeof(src_ports), &sp, pbuf);
        }
        snprintf(tmp, sizeof(tmp),
            " or (inbound and tcp and tcp.Syn and tcp.Ack and (%s) and "
            "(" NO_LOCALNETS_V4_SRC " or " NO_LOCALNETS_V6_SRC "))",
            src_ports);
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    }

    /* 4. Inbound Passive DPI HTTP 302 redirect (only if -p; RSTs are kernel-dropped separately!) */
    if (cfg->passive_block) {
        snprintf(tmp, sizeof(tmp),
            " or (inbound and tcp and tcp.SrcPort == 80 and tcp.Ack and "
            "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF)) and "
            "tcp.PayloadLength >= 16 and tcp.Payload32[0] == 0x48545450 and "
            "(" NO_LOCALNETS_V4_SRC " or " NO_LOCALNETS_V6_SRC "))");
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    }

    /* 5. DNS Redirection IPv4 (NOTE: intentionally allows LAN DNS routers like 192.168.1.1:53!) */
    if (cfg->dns_redir_v4) {
        snprintf(tmp, sizeof(tmp),
            " or (outbound and ip and udp and udp.DstPort == 53)"
            " or (inbound and ip and udp and ip.SrcAddr == %s and udp.SrcPort == %u)",
            cfg->dns_addr_v4_str, (unsigned)cfg->dns_port_v4);
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    }

    /* 6. DNS Redirection IPv6 or IPv6 DNS block */
    if (cfg->dns_redir_v6) {
        snprintf(tmp, sizeof(tmp),
            " or (outbound and ipv6 and udp and udp.DstPort == 53)"
            " or (inbound and ipv6 and udp and ipv6.SrcAddr == %s and udp.SrcPort == %u)",
            cfg->dns_addr_v6_str, (unsigned)cfg->dns_port_v6);
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    } else if (cfg->block_dns_v6) {
        if (!append_str(buf, buf_len, &pos, " or (outbound and ipv6 and udp and udp.DstPort == 53)")) {
            return false;
        }
    }

    /* 7. Selective QUIC blocking in main handle ONLY when -q AND --whitelist are both active
     *    (Without --whitelist, -q uses a dedicated kernel-only WINDIVERT_FLAG_DROP handle!) */
    if (cfg->block_quic && cfg->whitelist_path[0] != '\0') {
        if (!append_str(buf, buf_len, &pos,
            " or (outbound and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0)")) {
            return false;
        }
    }

    if (!append_str(buf, buf_len, &pos, ")")) return false;
    return true;
}

/* ============================================================================
 * Packet Sending Primitives (Exact GoodbyeDPI Native/Reverse Frag & Fake Logic)
 * ========================================================================== */

static bool should_bypass_host(const DpiEngine *eng, const char *host) {
    if (eng->has_whitelist && host && host[0]) {
        if (domain_list_matches(&eng->whitelist, host)) {
            return false;
        }
    }
    if (eng->has_blacklist) {
        if (!host || !host[0]) return false;
        return domain_list_matches(&eng->blacklist, host);
    }
    return true;
}

static void send_tcp_segment_raw(HANDLE wd,
                                 const uint8_t *orig_pkt, size_t hdr_len, size_t tcp_offset,
                                 PWINDIVERT_IPHDR orig_ip, PWINDIVERT_IPV6HDR orig_ipv6,
                                 PWINDIVERT_TCPHDR orig_tcp,
                                 const uint8_t *seg_data, size_t seg_len,
                                 uint32_t seq_delta,
                                 const WINDIVERT_ADDRESS *orig_addr,
                                 uint8_t *scratch_buf) {
    if (hdr_len + seg_len > JAPONDPI_PACKET_BUF) return;

    memcpy(scratch_buf, orig_pkt, hdr_len);
    if (seg_len > 0) {
        memcpy(scratch_buf + hdr_len, seg_data, seg_len);
    }

    UINT new_len = (UINT)(hdr_len + seg_len);
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(scratch_buf + tcp_offset);

    if (orig_ip) {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)scratch_buf;
        ip->Length = htons((uint16_t)new_len);
    } else if (orig_ipv6) {
        PWINDIVERT_IPV6HDR ipv6 = (PWINDIVERT_IPV6HDR)scratch_buf;
        ipv6->Length = htons((uint16_t)(new_len - 40));
    }

    /* Exact GoodbyeDPI behavior: preserve original PSH flag & IP.Id so the remote TCP stack
     * immediately combines reverse-ordered fragments and delivers the intact ClientHello in 0 ms! */
    tcp->SeqNum = htonl(ntohl(orig_tcp->SeqNum) + seq_delta);

    WINDIVERT_ADDRESS addr = *orig_addr;
    addr.IPChecksum  = 0;
    addr.TCPChecksum = 0;
    g_wd.HelperCalcChecksums(scratch_buf, new_len, &addr, 0);

    g_wd.Send(wd, scratch_buf, new_len, NULL, &addr);
}

static void send_tcp_segment(HANDLE wd,
                             const uint8_t *orig_pkt, size_t hdr_len, size_t tcp_offset,
                             PWINDIVERT_IPHDR orig_ip, PWINDIVERT_IPV6HDR orig_ipv6,
                             PWINDIVERT_TCPHDR orig_tcp,
                             const uint8_t *seg_data, size_t seg_len,
                             uint32_t seq_delta,
                             const WINDIVERT_ADDRESS *orig_addr,
                             uint8_t *scratch_buf) {
    /* LSO/TSO safety: ensure injected TCP chunks never exceed standard PPPoE/Ethernet MTU */
    const size_t max_chunk = 1400;
    if (seg_len <= max_chunk) {
        send_tcp_segment_raw(wd, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             seg_data, seg_len, seq_delta, orig_addr, scratch_buf);
        return;
    }

    size_t sent = 0;
    while (sent < seg_len) {
        size_t chunk = seg_len - sent;
        if (chunk > max_chunk) chunk = max_chunk;
        send_tcp_segment_raw(wd, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             seg_data + sent, chunk,
                             seq_delta + (uint32_t)sent,
                             orig_addr, scratch_buf);
        sent += chunk;
    }
}

static void send_single_fake(DpiEngine *eng,
                             const uint8_t *orig_pkt, size_t hdr_len, size_t tcp_offset,
                             PWINDIVERT_IPHDR orig_ip, PWINDIVERT_IPV6HDR orig_ipv6,
                             PWINDIVERT_TCPHDR orig_tcp,
                             const uint8_t *fake_data, size_t fake_len,
                             uint8_t set_ttl, bool set_bad_chksum, bool set_bad_seq,
                             const WINDIVERT_ADDRESS *orig_addr,
                             uint8_t *scratch_buf) {
    if (hdr_len + fake_len > JAPONDPI_PACKET_BUF) return;

    memcpy(scratch_buf, orig_pkt, hdr_len);
    memcpy(scratch_buf + hdr_len, fake_data, fake_len);
    UINT new_len = (UINT)(hdr_len + fake_len);

    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(scratch_buf + tcp_offset);
    if (orig_ip) {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)scratch_buf;
        ip->Length = htons((uint16_t)new_len);
        if (set_ttl > 0) {
            ip->TTL = set_ttl;
        }
    } else if (orig_ipv6) {
        PWINDIVERT_IPV6HDR ipv6 = (PWINDIVERT_IPV6HDR)scratch_buf;
        ipv6->Length = htons((uint16_t)(new_len - 40));
        if (set_ttl > 0) {
            ipv6->HopLimit = set_ttl;
        }
    }

    if (set_bad_seq) {
        tcp->AckNum = htonl(ntohl(orig_tcp->AckNum) - 66000U);
        tcp->SeqNum = htonl(ntohl(orig_tcp->SeqNum) - 10000U);
    }

    WINDIVERT_ADDRESS fake_addr = *orig_addr;
    fake_addr.IPChecksum  = 0;
    fake_addr.TCPChecksum = 0;
    g_wd.HelperCalcChecksums(scratch_buf, new_len, &fake_addr, 0);

    if (set_bad_chksum) {
        /* Exact GoodbyeDPI checksum corruption (leaves fake_addr.TCPChecksum=1 so NIC won't fix it) */
        tcp->Checksum = htons((uint16_t)(ntohs(tcp->Checksum) - 1));
        fake_addr.TCPChecksum = 1;
    }

    g_wd.Send(eng->wd_handle, scratch_buf, new_len, NULL, &fake_addr);
    InterlockedIncrement64(&eng->stats.fake_sent);
}

static void send_fake_packets(DpiEngine *eng,
                              const uint8_t *orig_pkt, size_t hdr_len, size_t tcp_offset,
                              PWINDIVERT_IPHDR orig_ip, PWINDIVERT_IPV6HDR orig_ipv6,
                              PWINDIVERT_TCPHDR orig_tcp,
                              const uint8_t *fake_data, size_t fake_len,
                              const WINDIVERT_ADDRESS *orig_addr,
                              uint8_t *scratch_buf) {
    const JaponConfig *cfg = &eng->cfg;
    if (!fake_data || fake_len == 0) return;

    uint8_t eff_ttl = cfg->fake_ttl;
    bool ttl_allowed = (eff_ttl > 0);

    if (cfg->auto_ttl || cfg->min_ttl > 0) {
        uint32_t remote_ip[4] = {0};
        bool is_v6 = (orig_ipv6 != NULL);
        if (!is_v6 && orig_ip) remote_ip[0] = orig_ip->DstAddr;
        else if (orig_ipv6) memcpy(remote_ip, orig_ipv6->DstAddr, 16);

        uint8_t synack_ttl = 0;
        if (ttl_cache_lookup(&eng->ttl_cache, is_v6, remote_ip,
                             orig_tcp->DstPort, orig_tcp->SrcPort, &synack_ttl)) {
            if (cfg->auto_ttl) {
                eff_ttl = ttl_compute_auto_fake(synack_ttl,
                    cfg->auto_ttl_1, cfg->auto_ttl_2, cfg->min_ttl, cfg->auto_ttl_max);
                ttl_allowed = (eff_ttl > 0);
            } else if (cfg->min_ttl > 0) {
                if (!ttl_compute_auto_fake(synack_ttl, 0, 0, cfg->min_ttl, 0)) {
                    ttl_allowed = false;
                }
            }
        } else if (cfg->auto_ttl) {
            /* SYN-ACK not cached -> skip TTL fake safely unless fixed fallback set */
            ttl_allowed = (eff_ttl > 0);
        }
    }

    uint8_t reps = cfg->fake_repeats;
    if (reps < 1) reps = 1;
    if (reps > 10) reps = 10;

    /* Exact GoodbyeDPI fakepackets.c logic: each fooling method sends its OWN fake packet! */
    for (uint8_t r = 0; r < reps; r++) {
        if (ttl_allowed && eff_ttl > 0) {
            send_single_fake(eng, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             fake_data, fake_len, eff_ttl, false, false, orig_addr, scratch_buf);
        }
        if (cfg->wrong_checksum) {
            send_single_fake(eng, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             fake_data, fake_len, 0, true, false, orig_addr, scratch_buf);
        }
        if (cfg->wrong_seq) {
            send_single_fake(eng, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             fake_data, fake_len, 0, false, true, orig_addr, scratch_buf);
        }
    }
}

static bool is_passive_http_redirect(const uint8_t *payload, UINT payload_len) {
    if (!payload || payload_len < 32) return false;
    if (memcmp(payload, "HTTP/1.1 302 ", 13) != 0 &&
        memcmp(payload, "HTTP/1.0 302 ", 13) != 0) {
        return false;
    }
    /* Match GoodbyeDPI's exact passive DPI redirect heuristic: Location: http:// + Connection: close */
    bool has_loc = false, has_close = false;
    for (UINT i = 13; i + 19 <= payload_len; i++) {
        if (!has_loc && memcmp(payload + i, "\r\nLocation: http://", 19) == 0) has_loc = true;
        if (!has_close && memcmp(payload + i, "\r\nConnection: close", 19) == 0) has_close = true;
        if (has_loc && has_close) return true;
    }
    return false;
}

/* ============================================================================
 * Engine Lifecycle & Main Loop
 * ========================================================================== */

bool dpi_engine_init(DpiEngine *eng, const JaponConfig *cfg, char *err_buf, size_t err_len) {
    memset(eng, 0, sizeof(*eng));
    eng->cfg             = *cfg;
    eng->wd_handle       = INVALID_HANDLE_VALUE;
    eng->wd_drop_passive = INVALID_HANDLE_VALUE;
    eng->wd_drop_quic    = INVALID_HANDLE_VALUE;

    fake_payloads_init(&eng->fakes, cfg->fake_sni, cfg->fake_http_host);
    ttl_cache_init(&eng->ttl_cache);
    dns_redir_init(&eng->dns_redir);
    domain_list_init(&eng->blacklist);
    domain_list_init(&eng->whitelist);

    if (cfg->blacklist_path[0]) {
        if (!domain_list_load(&eng->blacklist, cfg->blacklist_path)) {
            snprintf(err_buf, err_len, "Blacklist dosyasi acilamadi: %s", cfg->blacklist_path);
            return false;
        }
        eng->has_blacklist = true;
    }

    if (cfg->whitelist_path[0]) {
        if (!domain_list_load(&eng->whitelist, cfg->whitelist_path)) {
            snprintf(err_buf, err_len, "Whitelist dosyasi acilamadi: %s", cfg->whitelist_path);
            dpi_engine_destroy(eng);
            return false;
        }
        eng->has_whitelist = true;
    }

    return true;
}

static void close_wd_handle(HANDLE *ph) {
    if (*ph != INVALID_HANDLE_VALUE && *ph != NULL) {
        if (g_wd.Shutdown) g_wd.Shutdown(*ph, WINDIVERT_SHUTDOWN_BOTH);
        if (g_wd.Close)    g_wd.Close(*ph);
        *ph = INVALID_HANDLE_VALUE;
    }
}

void dpi_engine_destroy(DpiEngine *eng) {
    close_wd_handle(&eng->wd_drop_passive);
    close_wd_handle(&eng->wd_drop_quic);
    close_wd_handle(&eng->wd_handle);
    domain_list_free(&eng->blacklist);
    domain_list_free(&eng->whitelist);
}

void dpi_engine_request_stop(DpiEngine *eng) {
    InterlockedExchange(&eng->stop_flag, 1);
    HANDLE h = eng->wd_handle;
    if (h != INVALID_HANDLE_VALUE && h != NULL && g_wd.Shutdown) {
        g_wd.Shutdown(h, WINDIVERT_SHUTDOWN_BOTH);
    }
}

int dpi_engine_run(DpiEngine *eng) {
    /* Flush Windows DNS cache right inside C (works in Windows Service mode too!) */
    if (eng->cfg.dns_redir_v4 || eng->cfg.dns_redir_v6) {
        dns_flush_system_cache();
    }

    /* 1. Optional kernel-only DROP handle for -p passive RSTs (zero user-mode overhead) */
    if (eng->cfg.passive_block) {
        eng->wd_drop_passive = g_wd.Open(FILTER_KERNEL_DROP_PASSIVE_RST,
                                         WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_DROP);
    }

    /* 2. Optional kernel-only DROP handle for -q QUIC when no whitelist is active */
    if (eng->cfg.block_quic && !eng->has_whitelist) {
        eng->wd_drop_quic = g_wd.Open(FILTER_KERNEL_DROP_QUIC,
                                      WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_DROP);
    }

    /* 3. Main active DPI filter */
    char filter[4096];
    if (!dpi_build_filter(&eng->cfg, filter, sizeof(filter))) {
        fprintf(stderr, "[HATA] WinDivert filtre ifadesi olusturulamadi.\n");
        return 1;
    }

    if (eng->cfg.verbose) {
        printf("[BILGI] WinDivert Filtresi:\n  %s\n\n", filter);
    }

    HANDLE wd = g_wd.Open(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (wd == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr,
                "[HATA] Yonetici (Administrator) yetkisi gerekiyor!\n"
                "Lutfen .bat dosyasina sag tiklayip 'Yonetici olarak calistir' secin.\n");
        } else if (err == ERROR_INVALID_PARAMETER) {
            const char *ferr = NULL;
            UINT fpos = 0;
            g_wd.HelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, NULL, 0, &ferr, &fpos);
            fprintf(stderr, "[HATA] Gecersiz WinDivert filtresi (konum %u): %s\nFiltre: %s\n",
                    fpos, ferr ? ferr : "bilinmiyor", filter);
        } else if (err == ERROR_INVALID_IMAGE_HASH) {
            fprintf(stderr,
                "[HATA] WinDivert64.sys dijital imzasi Windows tarafindan dogrulanamadi (Kod: %lu).\n",
                (unsigned long)err);
        } else {
            fprintf(stderr, "[HATA] WinDivertOpen basarisiz oldu (Windows Hata Kodu: %lu).\n",
                    (unsigned long)err);
        }
        return 1;
    }

    eng->wd_handle = wd;

    /* High-performance kernel queue tuning */
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_TIME,   2000);
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_SIZE,   8388608);

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    if (!eng->cfg.quiet && !eng->cfg.run_as_service) {
        printf("[AKTIF] Japon DPI v%s calisiyor! Durdurmak icin Ctrl+C tuslarina basin.\n",
               JAPONDPI_VERSION);
        fflush(stdout);
    }

    uint8_t *pkt_buf     = (uint8_t *)malloc(JAPONDPI_PACKET_BUF);
    uint8_t *scratch_buf = (uint8_t *)malloc(JAPONDPI_PACKET_BUF);
    if (!pkt_buf || !scratch_buf) {
        free(pkt_buf);
        free(scratch_buf);
        fprintf(stderr, "[HATA] Bellek ayrilamadi.\n");
        return 1;
    }

    WINDIVERT_ADDRESS addr;
    UINT pkt_len = 0;

    while (!InterlockedCompareExchange(&eng->stop_flag, 0, 0)) {
        if (!g_wd.Recv(wd, pkt_buf, JAPONDPI_PACKET_BUF, &pkt_len, &addr)) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || err == ERROR_OPERATION_ABORTED ||
                InterlockedCompareExchange(&eng->stop_flag, 0, 0)) {
                break;
            }
            continue;
        }

        InterlockedIncrement64(&eng->stats.packets_total);

        PWINDIVERT_IPHDR   ip_hdr   = NULL;
        PWINDIVERT_IPV6HDR ipv6_hdr = NULL;
        PWINDIVERT_TCPHDR  tcp_hdr  = NULL;
        PWINDIVERT_UDPHDR  udp_hdr  = NULL;
        PVOID              data_ptr = NULL;
        UINT               data_len = 0;

        if (!g_wd.HelperParsePacket(pkt_buf, pkt_len, &ip_hdr, &ipv6_hdr,
                                    NULL, NULL, NULL, &tcp_hdr, &udp_hdr,
                                    &data_ptr, &data_len, NULL, NULL)) {
            g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            continue;
        }

        const uint8_t *payload = (const uint8_t *)data_ptr;
        bool outbound = (addr.Outbound != 0);

        /* ---- 1. UDP Handling: DNS Redirection & Selective QUIC Blocking ---- */
        if (udp_hdr) {
            if (outbound && eng->cfg.block_quic && eng->has_whitelist &&
                udp_hdr->DstPort == htons(443) && dpi_is_quic_initial(payload, data_len)) {
                uint32_t dst_ip[4] = {0};
                bool is_v6 = (ipv6_hdr != NULL);
                if (!is_v6 && ip_hdr) dst_ip[0] = ip_hdr->DstAddr;
                else if (ipv6_hdr) memcpy(dst_ip, ipv6_hdr->DstAddr, 16);
                if (!dpi_ip_wl_contains(&eng->ip_wl, is_v6, dst_ip)) {
                    InterlockedIncrement64(&eng->stats.quic_blocked);
                    continue; /* drop QUIC Initial for non-whitelisted host */
                }
            }

            int dns_rc = dns_redir_process(&eng->dns_redir, &eng->cfg, &eng->stats,
                                           outbound, ip_hdr, ipv6_hdr, udp_hdr,
                                           payload, data_len);
            if (dns_rc < 0) {
                continue;
            } else if (dns_rc > 0) {
                if (!outbound && eng->has_whitelist) {
                    dpi_dns_learn_whitelist_ips(payload, data_len, &eng->whitelist, &eng->ip_wl);
                }
                addr.IPChecksum  = 0;
                addr.UDPChecksum = 0;
                g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr, 0);
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            continue;
        }

        /* ---- 2. TCP Handling ---- */
        if (!tcp_hdr) {
            g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            continue;
        }

        /* 2A. Inbound TCP: SYN-ACK TTL tracking, Window Size, Passive HTTP 302 block */
        if (!outbound) {
            if (tcp_hdr->Syn && tcp_hdr->Ack) {
                uint32_t remote_ip[4] = {0};
                bool is_v6 = (ipv6_hdr != NULL);
                uint8_t ttl = 0;
                if (!is_v6 && ip_hdr) {
                    remote_ip[0] = ip_hdr->SrcAddr;
                    ttl = ip_hdr->TTL;
                } else if (ipv6_hdr) {
                    memcpy(remote_ip, ipv6_hdr->SrcAddr, 16);
                    ttl = ipv6_hdr->HopLimit;
                }
                ttl_cache_record(&eng->ttl_cache, is_v6, remote_ip,
                                 tcp_hdr->SrcPort, tcp_hdr->DstPort, ttl);

                if (eng->cfg.window_size > 0 && ntohs(tcp_hdr->Window) > eng->cfg.window_size) {
                    tcp_hdr->Window = htons(eng->cfg.window_size);
                    addr.IPChecksum  = 0;
                    addr.TCPChecksum = 0;
                    g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr, 0);
                }
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            if (eng->cfg.passive_block && is_passive_http_redirect(payload, data_len)) {
                InterlockedIncrement64(&eng->stats.passive_dropped);
                continue;
            }

            g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            continue;
        }

        /* 2B. Outbound TCP Data */
        if (!payload || data_len == 0) {
            g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            continue;
        }

        size_t hdr_len    = (size_t)(payload - pkt_buf);
        size_t tcp_offset = (size_t)((const uint8_t *)tcp_hdr - pkt_buf);

        /* ---- Outbound HTTPS / TLS ClientHello ---- */
        if (data_len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 &&
            payload[2] <= 0x03 && payload[5] == 0x01) {
            TlsParseResult tls;
            memset(&tls, 0, sizeof(tls));
            /* Only parse SNI if blacklist, whitelist, frag_by_sni, multi_split, or verbose need it! */
            if (eng->has_blacklist || eng->has_whitelist ||
                eng->cfg.frag_by_sni || eng->cfg.multi_split || eng->cfg.verbose) {
                dpi_parse_tls_client_hello(payload, data_len, &tls);
            }

            if (!should_bypass_host(eng, tls.found_sni ? tls.sni_host : "")) {
                if (eng->has_whitelist && tls.found_sni &&
                    domain_list_matches(&eng->whitelist, tls.sni_host)) {
                    uint32_t dst_ip[4] = {0};
                    bool is_v6 = (ipv6_hdr != NULL);
                    if (!is_v6 && ip_hdr) dst_ip[0] = ip_hdr->DstAddr;
                    else if (ipv6_hdr) memcpy(dst_ip, ipv6_hdr->DstAddr, 16);
                    ip_wl_add(&eng->ip_wl, is_v6, dst_ip);
                }
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            /* Step 1: Send fake TLS ClientHello packet(s) before real fragments */
            send_fake_packets(eng, pkt_buf, hdr_len, tcp_offset,
                              ip_hdr, ipv6_hdr, tcp_hdr,
                              eng->fakes.tls_buf, eng->fakes.tls_len,
                              &addr, scratch_buf);

            /* Step 2: Determine split point(s) (exact GoodbyeDPI semantics) */
            size_t cut1 = 0, cut2 = 0;
            if (eng->cfg.multi_split && data_len > 6) {
                cut1 = (eng->cfg.https_frag_size > 0 && eng->cfg.https_frag_size < data_len - 2)
                       ? eng->cfg.https_frag_size : 2;
                if (tls.found_sni && tls.sni_offset + tls.sni_len / 2 > cut1 &&
                    tls.sni_offset + tls.sni_len / 2 < data_len) {
                    cut2 = tls.sni_offset + tls.sni_len / 2;
                } else if (data_len > cut1 + 24) {
                    cut2 = cut1 + 20;
                }
            } else if (eng->cfg.frag_by_sni && tls.found_sni &&
                       tls.sni_offset > 0 && tls.sni_offset < data_len) {
                /* Exact GoodbyeDPI --frag-by-sni: cut right before SNI (or mid-SNI) */
                cut1 = tls.sni_offset + (tls.sni_len / 2);
            } else if (eng->cfg.https_frag_size > 0 && eng->cfg.https_frag_size < data_len) {
                cut1 = eng->cfg.https_frag_size;
            } else if (eng->cfg.frag_by_sni && data_len > 2) {
                cut1 = 2;
            }

            if (cut1 > 0 && cut2 > cut1 && cut2 < data_len) {
                size_t len0 = cut1;
                size_t len1 = cut2 - cut1;
                size_t len2 = data_len - cut2;

                if (eng->cfg.reverse_frag) {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut2, len2, (uint32_t)cut2, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              &addr, scratch_buf);
                } else {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut2, len2, (uint32_t)cut2, &addr, scratch_buf);
                }
            } else if (cut1 > 0 && cut1 < data_len) {
                size_t len0 = cut1;
                size_t len1 = data_len - cut1;

                if (eng->cfg.reverse_frag) {
                    /* Exact GoodbyeDPI --reverse-frag: [cut1..end) FIRST, [0..cut1) SECOND! */
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              &addr, scratch_buf);
                } else {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, &addr, scratch_buf);
                }
            } else {
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            }

            InterlockedIncrement64(&eng->stats.tls_bypassed);
            if (eng->cfg.verbose) {
                printf("[TLS] %s (len=%u, split=%zu%s)\n",
                       tls.found_sni ? tls.sni_host : "<tls>",
                       data_len, cut1, eng->cfg.reverse_frag ? ", ters" : "");
            }
            continue;
        }

        /* ---- Outbound HTTP (port 80) ---- */
        if (tcp_hdr->DstPort == htons(80)) {
            char http_host[JAPONDPI_MAX_HOST];
            if (dpi_extract_http_host(payload, data_len, http_host, sizeof(http_host))) {
                if (!should_bypass_host(eng, http_host)) {
                    g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                    continue;
                }

                send_fake_packets(eng, pkt_buf, hdr_len, tcp_offset,
                                  ip_hdr, ipv6_hdr, tcp_hdr,
                                  eng->fakes.http_buf, eng->fakes.http_len,
                                  &addr, scratch_buf);

                bool mutated = dpi_mangle_http_payload((uint8_t *)data_ptr, data_len, &eng->cfg);

                if (eng->cfg.http_frag_size > 0 && eng->cfg.http_frag_size < data_len) {
                    size_t cut = eng->cfg.http_frag_size;
                    if (eng->cfg.reverse_frag) {
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload + cut, data_len - cut, (uint32_t)cut, &addr, scratch_buf);
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload,       cut,            0,             &addr, scratch_buf);
                    } else {
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload,       cut,            0,             &addr, scratch_buf);
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload + cut, data_len - cut, (uint32_t)cut, &addr, scratch_buf);
                    }
                } else {
                    if (mutated) {
                        addr.IPChecksum  = 0;
                        addr.TCPChecksum = 0;
                        g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr, 0);
                    }
                    g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                }

                InterlockedIncrement64(&eng->stats.http_bypassed);
                if (eng->cfg.verbose) {
                    printf("[HTTP] %s (len=%u)\n", http_host, data_len);
                }
                continue;
            }
        }

        g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
    }

    free(pkt_buf);
    free(scratch_buf);
    return 0;
}
