#include "dpi_engine.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ============================================================================
 * Pure Packet Parsers & Helpers
 * ========================================================================== */

bool dpi_parse_tls_client_hello(const uint8_t *payload, size_t len, TlsParseResult *out) {
    memset(out, 0, sizeof(*out));
    if (!payload || len < 43) return false;

    /* TLS Record Header: 0x16 (Handshake), 0x03 0x00..0x04 */
    if (payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04) {
        return false;
    }
    /* Handshake Type: 0x01 (ClientHello) */
    if (payload[5] != 0x01) {
        return false;
    }

    size_t pos = 9; /* skip 5-byte record hdr + 4-byte handshake hdr */
    if (pos + 2 + 32 + 1 > len) return true; /* valid ClientHello, truncated before SNI */

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
    if (ext_end > len) ext_end = len; /* handle multi-segment ML-KEM ClientHello cleanly */

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (uint16_t)(((uint16_t)payload[pos] << 8) | payload[pos + 1]);
        uint16_t ext_len  = (uint16_t)(((uint16_t)payload[pos + 2] << 8) | payload[pos + 3]);
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000 && ext_len >= 5) {
            /* server_name extension */
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

    return true; /* Valid TLS ClientHello even if SNI is in a subsequent TCP segment */
}

static int find_http_method_space(const uint8_t *payload, size_t len) {
    static const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "
    };
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t mlen = strlen(methods[i]);
        if (len > mlen && memcmp(payload, methods[i], mlen) == 0) {
            return (int)(mlen - 1); /* index of space right after method */
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
                break; /* end of HTTP headers */
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
        if (c == ':' || c == ' ' || c == '\t') break; /* strip :port */
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

    /* 1. Replace "Host:" with "hoSt:" (length invariant: 5 -> 5) */
    if (cfg->http_host_replace) {
        payload[hdr_pos + 0] = 'h';
        payload[hdr_pos + 1] = 'o';
        payload[hdr_pos + 2] = 'S';
        payload[hdr_pos + 3] = 't';
        modified = true;
    }

    /* 2. Mix case of hostname (length invariant) */
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

    /* 3. Remove space after "Host:" and balance by adding space after HTTP method
     *    Total payload length remains 100% identical (zero TCP sequence desync!) */
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
    /* RFC 9000: QUIC Initial datagrams MUST be at least 1200 bytes and have Long Header bit (0x80)
     * plus Fixed Bit (0x40), packet type Initial = 00 (for v1) or 01 (for v2). */
    if (!payload || len < 1200) return false;
    if ((payload[0] & 0xC0) != 0xC0) return false;

    uint32_t ver = ((uint32_t)payload[1] << 24) |
                   ((uint32_t)payload[2] << 16) |
                   ((uint32_t)payload[3] << 8)  |
                   ((uint32_t)payload[4]);

    /* QUIC v1 (0x00000001), QUIC v2 (0x6b3343cf), IETF drafts (0xff0000xx) */
    if (ver == 0x00000001U) {
        /* v1 Initial: bits 5..4 == 00 */
        return ((payload[0] & 0x30) == 0x00);
    }
    if (ver == 0x6b3343cfU) {
        /* v2 Initial: bits 5..4 == 01 */
        return ((payload[0] & 0x30) == 0x10);
    }
    if ((ver & 0xFFFFFF00U) == 0xFF000000U) {
        return ((payload[0] & 0x30) == 0x00);
    }
    return false;
}

/* ============================================================================
 * WinDivert Kernel Filter Builder
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

    bool need_or = false;
    char tmp[512];

    /* 1. Outbound TLS ClientHello (port 443 + extra ports)
     *    Kernel-level signature check (0x16 0x03 ... 0x01) means 100% of bulk HTTPS data
     *    never leaves the kernel! Supports post-quantum ML-KEM768 ClientHellos (>1400B). */
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
            "(outbound and tcp and (%s) and tcp.PayloadLength >= 6 and tcp.PayloadLength <= %u "
            "and tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[5] == 0x01)",
            tls_ports, (unsigned)cfg->max_payload);
    } else {
        snprintf(tmp, sizeof(tmp),
            "(outbound and tcp and (%s) and tcp.PayloadLength >= 6 "
            "and tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[5] == 0x01)",
            tls_ports);
    }
    if (!append_str(buf, buf_len, &pos, tmp)) return false;
    need_or = true;

    /* 2. Outbound HTTP requests (port 80) */
    uint16_t http_max = (cfg->max_payload > 0) ? cfg->max_payload : 1500;
    snprintf(tmp, sizeof(tmp),
        " or (outbound and tcp and tcp.DstPort == 80 and tcp.PayloadLength >= 16 and tcp.PayloadLength <= %u)",
        (unsigned)http_max);
    if (!append_str(buf, buf_len, &pos, tmp)) return false;

    /* 3. Inbound SYN-ACK (only when auto-ttl, passive-block, or window-size is active) */
    if (cfg->auto_ttl || cfg->passive_block || cfg->window_size > 0) {
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
            " or (inbound and tcp and tcp.Syn and tcp.Ack and (%s))", src_ports);
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    }

    /* 4. Inbound Passive DPI RST / HTTP 302 redirect (only if -p / --passive-block) */
    if (cfg->passive_block) {
        snprintf(tmp, sizeof(tmp),
            " or (inbound and tcp and (tcp.SrcPort == 443 or tcp.SrcPort == 80) and "
            "((tcp.Rst and tcp.PayloadLength == 0) or "
            "(tcp.PayloadLength >= 16 and tcp.Payload[0] == 0x48 and tcp.Payload[1] == 0x54 "
            "and tcp.Payload[2] == 0x54 and tcp.Payload[3] == 0x50)))");
        if (!append_str(buf, buf_len, &pos, tmp)) return false;
    }

    /* 5. DNS Redirection IPv4 */
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

    /* 7. QUIC Initial blocking (UDP 443 >= 1200 bytes) */
    if (cfg->block_quic) {
        if (!append_str(buf, buf_len, &pos,
            " or (outbound and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200)")) {
            return false;
        }
    }

    (void)need_or;
    if (!append_str(buf, buf_len, &pos, ")")) return false;
    return true;
}

/* ============================================================================
 * Packet Sending Primitives (Zero Malloc in Hot Path)
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
                                 uint32_t seq_delta, uint16_t id_delta, bool keep_psh,
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
        ip->Id = htons((uint16_t)(ntohs(orig_ip->Id) + id_delta));
    } else if (orig_ipv6) {
        PWINDIVERT_IPV6HDR ipv6 = (PWINDIVERT_IPV6HDR)scratch_buf;
        ipv6->Length = htons((uint16_t)(new_len - 40));
    }

    tcp->SeqNum = htonl(ntohl(orig_tcp->SeqNum) + seq_delta);
    tcp->Psh = keep_psh ? orig_tcp->Psh : 0;

    WINDIVERT_ADDRESS addr = *orig_addr;
    addr.IPChecksum  = 0;
    addr.TCPChecksum = 0;
    g_wd.HelperCalcChecksums(scratch_buf, new_len, &addr,
        WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_UDP_CHECKSUM);

    g_wd.Send(wd, scratch_buf, new_len, NULL, &addr);
}

static void send_tcp_segment(HANDLE wd,
                             const uint8_t *orig_pkt, size_t hdr_len, size_t tcp_offset,
                             PWINDIVERT_IPHDR orig_ip, PWINDIVERT_IPV6HDR orig_ipv6,
                             PWINDIVERT_TCPHDR orig_tcp,
                             const uint8_t *seg_data, size_t seg_len,
                             uint32_t seq_delta, uint16_t id_delta, bool keep_psh,
                             const WINDIVERT_ADDRESS *orig_addr,
                             uint8_t *scratch_buf) {
    /* LSO/TSO safety: ensure injected TCP chunks never exceed standard Ethernet/PPPoE MTU */
    const size_t max_chunk = 1400;
    if (seg_len <= max_chunk) {
        send_tcp_segment_raw(wd, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             seg_data, seg_len, seq_delta, id_delta, keep_psh, orig_addr, scratch_buf);
        return;
    }

    size_t sent = 0;
    uint16_t sub_id = 0;
    while (sent < seg_len) {
        size_t chunk = seg_len - sent;
        if (chunk > max_chunk) chunk = max_chunk;
        bool is_final = (sent + chunk >= seg_len);
        send_tcp_segment_raw(wd, orig_pkt, hdr_len, tcp_offset, orig_ip, orig_ipv6, orig_tcp,
                             seg_data + sent, chunk,
                             seq_delta + (uint32_t)sent,
                             (uint16_t)(id_delta + sub_id),
                             is_final ? keep_psh : false,
                             orig_addr, scratch_buf);
        sent += chunk;
        sub_id++;
    }
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
    if (hdr_len + fake_len > JAPONDPI_PACKET_BUF) return;

    /* Resolve effective fake TTL */
    uint8_t eff_ttl = cfg->fake_ttl;
    if (cfg->auto_ttl) {
        uint32_t remote_ip[4] = {0};
        bool is_v6 = (orig_ipv6 != NULL);
        if (!is_v6 && orig_ip) {
            remote_ip[0] = orig_ip->DstAddr;
        } else if (orig_ipv6) {
            memcpy(remote_ip, orig_ipv6->DstAddr, 16);
        }
        uint8_t synack_ttl = 0;
        if (ttl_cache_lookup(&eng->ttl_cache, is_v6, remote_ip,
                             orig_tcp->DstPort, orig_tcp->SrcPort, &synack_ttl)) {
            uint8_t auto_t = ttl_compute_auto_fake(synack_ttl,
                cfg->auto_ttl_delta, cfg->auto_ttl_min, cfg->auto_ttl_max);
            if (auto_t > 0) {
                eff_ttl = auto_t;
            }
        }
    }

    /* Safety guard: NEVER inject a fake packet without at least one fooling method! */
    if (eff_ttl == 0 && !cfg->wrong_checksum && !cfg->wrong_seq) {
        return;
    }

    memcpy(scratch_buf, orig_pkt, hdr_len);
    memcpy(scratch_buf + hdr_len, fake_data, fake_len);
    UINT new_len = (UINT)(hdr_len + fake_len);

    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(scratch_buf + tcp_offset);
    if (orig_ip) {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)scratch_buf;
        ip->Length = htons((uint16_t)new_len);
        ip->Id = htons((uint16_t)(ntohs(orig_ip->Id) - 1));
        if (eff_ttl > 0) {
            ip->TTL = eff_ttl;
        }
    } else if (orig_ipv6) {
        PWINDIVERT_IPV6HDR ipv6 = (PWINDIVERT_IPV6HDR)scratch_buf;
        ipv6->Length = htons((uint16_t)(new_len - 40));
        if (eff_ttl > 0) {
            ipv6->HopLimit = eff_ttl;
        }
    }

    if (cfg->wrong_seq) {
        tcp->SeqNum = htonl(ntohl(orig_tcp->SeqNum) - 10000U);
        tcp->AckNum = htonl(ntohl(orig_tcp->AckNum) - 66000U);
    }

    WINDIVERT_ADDRESS fake_addr = *orig_addr;
    fake_addr.IPChecksum  = 0;
    fake_addr.TCPChecksum = 0;
    g_wd.HelperCalcChecksums(scratch_buf, new_len, &fake_addr,
        WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_UDP_CHECKSUM);

    if (cfg->wrong_checksum) {
        /* Keep fake_addr.TCPChecksum == 1 so NDIS/NIC offload does NOT recalculate & fix it! */
        tcp->Checksum = (uint16_t)(tcp->Checksum ^ 0xA55A);
        fake_addr.TCPChecksum = 1;
    }

    uint8_t reps = cfg->fake_repeats;
    if (reps < 1) reps = 1;
    if (reps > 10) reps = 10;

    for (uint8_t r = 0; r < reps; r++) {
        g_wd.Send(eng->wd_handle, scratch_buf, new_len, NULL, &fake_addr);
        InterlockedIncrement64(&eng->stats.fake_sent);
    }
}

static bool handle_inbound_passive_dpi(DpiEngine *eng,
                                       PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ipv6_hdr,
                                       PWINDIVERT_TCPHDR tcp_hdr,
                                       const uint8_t *payload, UINT payload_len) {
    /* Return true to DROP spoofed DPI packet, false to allow */
    if (!eng->cfg.passive_block) return false;

    uint32_t remote_ip[4] = {0};
    bool is_v6 = (ipv6_hdr != NULL);
    uint8_t pkt_ttl = 0;
    if (!is_v6 && ip_hdr) {
        remote_ip[0] = ip_hdr->SrcAddr;
        pkt_ttl = ip_hdr->TTL;
    } else if (ipv6_hdr) {
        memcpy(remote_ip, ipv6_hdr->SrcAddr, 16);
        pkt_ttl = ipv6_hdr->HopLimit;
    }

    /* 1. Spoofed TCP RST check:
     *    Compare RST TTL against recorded SYN-ACK TTL for the exact same flow.
     *    A legitimate server's RST arrives with ~same TTL (+-2); ISP DPI box sits much closer (+6..+40 higher TTL)! */
    if (tcp_hdr->Rst && payload_len == 0) {
        uint8_t synack_ttl = 0;
        if (ttl_cache_lookup(&eng->ttl_cache, is_v6, remote_ip,
                             tcp_hdr->SrcPort, tcp_hdr->DstPort, &synack_ttl)) {
            int diff = (int)pkt_ttl - (int)synack_ttl;
            if (diff < 0) diff = -diff;
            if (diff >= 6) {
                InterlockedIncrement64(&eng->stats.passive_dropped);
                if (eng->cfg.verbose) {
                    printf("[PASIF-DPI] Sahte RST engellendi (SYN-ACK TTL=%u, RST TTL=%u)\n",
                           (unsigned)synack_ttl, (unsigned)pkt_ttl);
                }
                return true;
            }
        }
        /* Classic passive DPI injector signature on IPv4: DF=0 and IP.Id == 0 or 1 */
        if (ip_hdr && !WINDIVERT_IPHDR_GET_DF(ip_hdr)) {
            uint16_t id = ntohs(ip_hdr->Id);
            if (id == 0 || id == 1) {
                InterlockedIncrement64(&eng->stats.passive_dropped);
                return true;
            }
        }
    }

    /* 2. Spoofed HTTP 302/307 ISP Block Redirect check */
    if (payload && payload_len >= 16 && memcmp(payload, "HTTP/1.", 7) == 0) {
        if (memcmp(payload + 9, "302", 3) == 0 || memcmp(payload + 9, "307", 3) == 0) {
            bool suspicious = false;
            if (ip_hdr && !WINDIVERT_IPHDR_GET_DF(ip_hdr)) {
                uint16_t id = ntohs(ip_hdr->Id);
                if (id == 0 || id == 1) suspicious = true;
            }
            if (!suspicious) {
                uint8_t synack_ttl = 0;
                if (ttl_cache_lookup(&eng->ttl_cache, is_v6, remote_ip,
                                     tcp_hdr->SrcPort, tcp_hdr->DstPort, &synack_ttl)) {
                    int diff = (int)pkt_ttl - (int)synack_ttl;
                    if (diff < 0) diff = -diff;
                    if (diff >= 6) suspicious = true;
                }
            }
            if (suspicious) {
                InterlockedIncrement64(&eng->stats.passive_dropped);
                if (eng->cfg.verbose) {
                    printf("[PASIF-DPI] Sahte HTTP 302/307 yonlendirmesi engellendi.\n");
                }
                return true;
            }
        }
    }

    return false;
}

/* ============================================================================
 * Engine Lifecycle & Main Loop
 * ========================================================================== */

bool dpi_engine_init(DpiEngine *eng, const JaponConfig *cfg, char *err_buf, size_t err_len) {
    memset(eng, 0, sizeof(*eng));
    eng->cfg = *cfg;
    eng->wd_handle = INVALID_HANDLE_VALUE;

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

void dpi_engine_destroy(DpiEngine *eng) {
    if (eng->wd_handle != INVALID_HANDLE_VALUE && eng->wd_handle != NULL) {
        if (g_wd.Close) {
            g_wd.Close(eng->wd_handle);
        }
        eng->wd_handle = INVALID_HANDLE_VALUE;
    }
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
    char filter[2048];
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
                "[HATA] WinDivert64.sys dijital imzasi Windows tarafindan dogrulanamadi (Kod: %lu).\n"
                "Resmi WHQL imzali WinDivert 2.2.2-A surumunu kullandiginizdan emin olun.\n",
                (unsigned long)err);
        } else if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            fprintf(stderr,
                "[HATA] Eski WinDivert surucusu henuz kapanmamis.\n"
                "Bilgisayari yeniden baslatin veya 'sc stop WinDivert' komutunu calistirin.\n");
        } else {
            fprintf(stderr, "[HATA] WinDivertOpen basarisiz oldu (Windows Hata Kodu: %lu).\n",
                    (unsigned long)err);
        }
        return 1;
    }

    eng->wd_handle = wd;

    /* Tune WinDivert kernel queue for high throughput and zero packet drops */
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_TIME,   2000);
    g_wd.SetParam(wd, WINDIVERT_PARAM_QUEUE_SIZE,   8388608); /* 8 MB */

    /* Raise process priority slightly so handshake packets experience <0.1 ms latency */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    if (!eng->cfg.quiet && !eng->cfg.run_as_service) {
        printf("[AKTIF] Japon DPI calisiyor! Durdurmak icin Ctrl+C tuslarina basin.\n");
        fflush(stdout);
    }

    /* Pre-allocated packet buffers: ZERO malloc/free in the hot packet loop */
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
                break; /* Clean shutdown triggered */
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

        /* ---- 1. UDP Handling: DNS Redirection & QUIC Blocking ---- */
        if (udp_hdr) {
            if (outbound && eng->cfg.block_quic && udp_hdr->DstPort == htons(443)) {
                if (dpi_is_quic_initial(payload, data_len)) {
                    InterlockedIncrement64(&eng->stats.quic_blocked);
                    if (eng->cfg.verbose) {
                        printf("[QUIC] UDP:443 QUIC Initial engellendi -> TCP/443 fallback\n");
                    }
                    continue; /* drop QUIC Initial */
                }
            }

            int dns_rc = dns_redir_process(&eng->dns_redir, &eng->cfg, &eng->stats,
                                           outbound, ip_hdr, ipv6_hdr, udp_hdr,
                                           payload, data_len);
            if (dns_rc < 0) {
                continue; /* dropped (e.g., --block-dnsv6) */
            } else if (dns_rc > 0) {
                addr.IPChecksum  = 0;
                addr.UDPChecksum = 0;
                g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr,
                    WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM |
                    WINDIVERT_HELPER_NO_TCP_CHECKSUM);
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

        /* 2A. Inbound TCP: SYN-ACK TTL tracking, TCP Window shrink, Passive DPI block */
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
                    g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr,
                        WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM |
                        WINDIVERT_HELPER_NO_UDP_CHECKSUM);
                }
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            if (handle_inbound_passive_dpi(eng, ip_hdr, ipv6_hdr, tcp_hdr, payload, data_len)) {
                continue; /* dropped spoofed RST / 302 */
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
        if (data_len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01) {
            TlsParseResult tls;
            if (!dpi_parse_tls_client_hello(payload, data_len, &tls)) {
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            if (!should_bypass_host(eng, tls.found_sni ? tls.sni_host : "")) {
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
                continue;
            }

            /* Step 1: Send fake TLS ClientHello packet(s) before real fragments */
            send_fake_packets(eng, pkt_buf, hdr_len, tcp_offset,
                              ip_hdr, ipv6_hdr, tcp_hdr,
                              eng->fakes.tls_buf, eng->fakes.tls_len,
                              &addr, scratch_buf);

            /* Step 2: Determine split point(s) */
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
            } else if (eng->cfg.split_sni && tls.found_sni &&
                       tls.sni_offset + tls.sni_len / 2 > 0 &&
                       tls.sni_offset + tls.sni_len / 2 < data_len) {
                cut1 = tls.sni_offset + tls.sni_len / 2;
            } else if (eng->cfg.https_frag_size > 0 && eng->cfg.https_frag_size < data_len) {
                cut1 = eng->cfg.https_frag_size;
            } else if (eng->cfg.split_sni && data_len > 2) {
                /* Fallback when ML-KEM pushes SNI into next TCP segment */
                cut1 = 2;
            }

            if (cut1 > 0 && cut2 > cut1 && cut2 < data_len) {
                /* 3-part split */
                size_t len0 = cut1;
                size_t len1 = cut2 - cut1;
                size_t len2 = data_len - cut2;

                if (eng->cfg.reverse_frag) {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut2, len2, (uint32_t)cut2, 2, true,  &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, 1, false, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              0, false, &addr, scratch_buf);
                } else {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              0, false, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, 1, false, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut2, len2, (uint32_t)cut2, 2, true,  &addr, scratch_buf);
                }
            } else if (cut1 > 0 && cut1 < data_len) {
                /* 2-part split */
                size_t len0 = cut1;
                size_t len1 = data_len - cut1;

                if (eng->cfg.reverse_frag) {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, 1, true,  &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              0, false, &addr, scratch_buf);
                } else {
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload,        len0, 0,              0, false, &addr, scratch_buf);
                    send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                     payload + cut1, len1, (uint32_t)cut1, 1, true,  &addr, scratch_buf);
                }
            } else {
                /* No split, pass original packet after fake */
                g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
            }

            InterlockedIncrement64(&eng->stats.tls_bypassed);
            if (eng->cfg.verbose) {
                printf("[TLS] %s (len=%u, split=%zu%s)\n",
                       tls.found_sni ? tls.sni_host : "<parcali-sni>",
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

                /* Fake HTTP packet */
                send_fake_packets(eng, pkt_buf, hdr_len, tcp_offset,
                                  ip_hdr, ipv6_hdr, tcp_hdr,
                                  eng->fakes.http_buf, eng->fakes.http_len,
                                  &addr, scratch_buf);

                /* In-place length-preserving header mutations */
                bool mutated = dpi_mangle_http_payload((uint8_t *)data_ptr, data_len, &eng->cfg);

                if (eng->cfg.http_frag_size > 0 && eng->cfg.http_frag_size < data_len) {
                    size_t cut = eng->cfg.http_frag_size;
                    if (eng->cfg.reverse_frag) {
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload + cut, data_len - cut, (uint32_t)cut, 1, true,  &addr, scratch_buf);
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload,       cut,            0,             0, false, &addr, scratch_buf);
                    } else {
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload,       cut,            0,             0, false, &addr, scratch_buf);
                        send_tcp_segment(wd, pkt_buf, hdr_len, tcp_offset, ip_hdr, ipv6_hdr, tcp_hdr,
                                         payload + cut, data_len - cut, (uint32_t)cut, 1, true,  &addr, scratch_buf);
                    }
                } else {
                    if (mutated) {
                        addr.IPChecksum  = 0;
                        addr.TCPChecksum = 0;
                        g_wd.HelperCalcChecksums(pkt_buf, pkt_len, &addr,
                            WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM |
                            WINDIVERT_HELPER_NO_UDP_CHECKSUM);
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

        /* Fallback: pass through unmodified */
        g_wd.Send(wd, pkt_buf, pkt_len, NULL, &addr);
    }

    free(pkt_buf);
    free(scratch_buf);
    return 0;
}
