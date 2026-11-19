#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "wd_loader.h"
#include "dpi_engine.h"
#include "service.h"

static DpiEngine g_engine;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        dpi_engine_request_stop(&g_engine);
        return TRUE;
    default:
        return FALSE;
    }
}

static void print_banner(void) {
    printf("============================================================\n");
    printf("  Japon DPI v%s (x64 Native C / WinDivert 2.2)\n", JAPONDPI_VERSION);
    printf("  GoodbyeDPI Prensibi | Acik Kaynak | Yuksek Performans\n");
    printf("============================================================\n");
}

static void print_usage(void) {
    print_banner();
    printf(
        "\nKullanim: japondpi.exe [secenekler]\n\n"
        "Hazir Modlar (GoodbyeDPI ile birebir uyumlu):\n"
        "  -5                    -f 2 -e 2 --auto-ttl --reverse-frag\n"
        "  -6                    -f 2 -e 2 --wrong-seq --reverse-frag\n"
        "  -7                    -f 2 -e 2 --wrong-chksum --reverse-frag\n"
        "  -8                    -f 2 -e 2 --wrong-chksum --wrong-seq --reverse-frag\n"
        "  -9                    -8 + -q (QUIC engelli)\n"
        "  -1 .. -4              Klasik HTTP/HTTPS parcalama modlari\n\n"
        "Parcalama (Fragmentation):\n"
        "  -f <N>                HTTP istegini N. bayttan bol (orn: -f 2)\n"
        "  -e <N>                HTTPS (TLS ClientHello) N. bayttan bol (orn: -e 2)\n"
        "  --frag-by-sni         TLS ClientHello paketini SNI uzerinden bol (alias: --split-sni)\n"
        "  --multi-split         3 parcali TLS bolme\n"
        "  --reverse-frag        Parcalari ters sirada gonder (sunucu tek parca alir - en hizli)\n"
        "  --native-frag         Parcalari duz sirada gonder\n\n"
        "Sahte Paket (Fake Packet - Her yontem kendi paketini gonderir):\n"
        "  --set-ttl <N>         Sabit sahte paket TTL (auto-ttl'i kapatir, sifir gelen TCP yuku)\n"
        "  --auto-ttl [a1-a2-m]  SYN-ACK TTL'den otomatik hop hesapla (varsayilan: 1-4-10)\n"
        "  --min-ttl <N>         Sahte paket icin minimum hop mesafesi\n"
        "  --wrong-chksum        Bozuk TCP checksum sahte paketi (alias: --wrong-checksum)\n"
        "  --wrong-seq           Pencere disi TCP Seq/Ack sahte paketi\n"
        "  --fake-resend <N>     Sahte paket tekrar sayisi 1-10 (alias: --fake-repeats)\n"
        "  --fake-sni <alan>     Sahte TLS SNI alan adi (varsayilan: www.w3.org)\n\n"
        "HTTP, Pasif DPI & QUIC:\n"
        "  -r, --http-replace    'Host:' -> 'hoSt:'\n"
        "  -s, --http-rmspace    'Host:' boslugunu kaldir\n"
        "  -m, --http-mixcase    HTTP alan adinda harf karistir\n"
        "  -p, --passive-block   Pasif DPI RST (cekirdek DROP) ve HTTP 302 engelle\n"
        "  -q, --block-quic      QUIC (UDP:443) engelle (whitelist yoksa cekirdek DROP)\n"
        "  -w <N>                Gelen SYN-ACK TCP pencere boyutunu N yap\n\n"
        "DNS Yonlendirme:\n"
        "  --dns-addr <IP>       IPv4 UDP:53 DNS yonlendirme hedefi\n"
        "  --dns-port <PORT>     IPv4 hedef DNS portu\n"
        "  --dnsv6-addr <IPv6>   IPv6 UDP:53 DNS yonlendirme hedefi\n"
        "  --dnsv6-port <PORT>   IPv6 hedef DNS portu\n"
        "  --block-dnsv6         IPv6 UDP:53 engelle\n\n"
        "Diger:\n"
        "  --port <PORT>         Ek TCP HTTPS portu (orn: 2053, 8443)\n"
        "  --max-payload <N>     Maksimum paket boyutu siniri (0 = ML-KEM768 tam uyumlu)\n"
        "  --blacklist <dosya>   Yalnizca listedeki alan adlarina uygula\n"
        "  --whitelist <dosya>   Listedeki alan adlarina dokunma\n"
        "  -v, --verbose         Detayli canli gunluk\n"
        "  --quiet               Sessiz mod\n"
        "  --service             Windows servisi modu\n"
        "  --test-filter         WinDivert filtresini dogrula ve cik\n"
        "  --self-test           Dahili birim testlerini calistir\n"
    );
}

static void apply_preset(JaponConfig *cfg, int preset) {
    switch (preset) {
    case 1:
        cfg->passive_block = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        break;
    case 2:
        cfg->passive_block = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 40;
        break;
    case 3:
        cfg->passive_block = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        cfg->https_frag_size = 40;
        break;
    case 4:
        cfg->passive_block = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        break;
    case 5: /* Exact GoodbyeDPI -5: -f 2 -e 2 --auto-ttl --reverse-frag (NO -q, NO -p!) */
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        cfg->auto_ttl = true;
        cfg->auto_ttl_1 = 1;
        cfg->auto_ttl_2 = 4;
        cfg->auto_ttl_max = 10;
        cfg->min_ttl = 3;
        break;
    case 6: /* Exact GoodbyeDPI -6 */
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        cfg->wrong_seq = true;
        break;
    case 7: /* Exact GoodbyeDPI -7 */
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        cfg->wrong_checksum = true;
        break;
    case 8: /* Exact GoodbyeDPI -8 */
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        cfg->wrong_checksum = true;
        cfg->wrong_seq = true;
        break;
    case 9: /* Exact GoodbyeDPI -9 */
    default:
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        cfg->wrong_checksum = true;
        cfg->wrong_seq = true;
        cfg->block_quic = true;
        break;
    }
}

static void print_active_summary(const JaponConfig *cfg) {
    printf("Aktif Ayarlar:\n");
    printf("  TLS/HTTPS Bolme : ");
    if (cfg->multi_split) {
        printf("3-Parcali (Multi-Split)");
    } else if (cfg->frag_by_sni) {
        printf("SNI (fallback: %u byte)", (unsigned)(cfg->https_frag_size ? cfg->https_frag_size : 2));
    } else if (cfg->https_frag_size > 0) {
        printf("%u byte", (unsigned)cfg->https_frag_size);
    } else {
        printf("Kapali");
    }
    if (cfg->reverse_frag) printf(" [Ters Sira - Sunucu Birlestirmeli]");
    printf("\n");

    printf("  Sahte Paket     : ");
    if (cfg->fake_ttl > 0 || cfg->auto_ttl || cfg->wrong_checksum || cfg->wrong_seq) {
        if (cfg->auto_ttl) {
            printf("Auto-TTL(%u-%u-%u, min=%u) ",
                   (unsigned)cfg->auto_ttl_1, (unsigned)cfg->auto_ttl_2,
                   (unsigned)cfg->auto_ttl_max, (unsigned)cfg->min_ttl);
        }
        if (cfg->fake_ttl > 0) printf("Sabit-TTL=%u ", (unsigned)cfg->fake_ttl);
        if (cfg->wrong_checksum) printf("Bozuk-Checksum ");
        if (cfg->wrong_seq) printf("Bozuk-Seq ");
        printf("(Tekrar: %u, SNI: %s)\n", (unsigned)cfg->fake_repeats, cfg->fake_sni);
    } else {
        printf("Kapali\n");
    }

    printf("  HTTP / Pasif    : Bolme=%u | Host:%s%s%s | Pasif-RST:%s\n",
           (unsigned)cfg->http_frag_size,
           cfg->http_host_replace ? " hoSt" : "",
           cfg->http_host_rmspace ? " noSpace" : "",
           cfg->http_host_mixcase ? " mixCase" : "",
           cfg->passive_block ? "Acik (Cekirdek DROP)" : "Kapali");

    if (cfg->dns_redir_v4) {
        printf("  IPv4 DNS Yonl.  : UDP:53 -> %s:%u\n", cfg->dns_addr_v4_str, (unsigned)cfg->dns_port_v4);
    }
    if (cfg->dns_redir_v6) {
        printf("  IPv6 DNS Yonl.  : UDP:53 -> [%s]:%u\n", cfg->dns_addr_v6_str, (unsigned)cfg->dns_port_v6);
    } else if (cfg->block_dns_v6) {
        printf("  IPv6 DNS        : Engelli (IPv4 DNS zorunlu)\n");
    }
    if (cfg->block_quic) {
        printf("  QUIC (UDP:443)  : %s\n",
               cfg->whitelist_path[0] ? "Secici Engelli (Whitelist 0-RTT acik)" : "Engelli (Cekirdek DROP)");
    } else {
        printf("  QUIC (UDP:443)  : Acik (Siteler 0-RTT HTTP/3 ile hizli acilir)\n");
    }
    if (cfg->blacklist_path[0]) printf("  Blacklist       : %s\n", cfg->blacklist_path);
    if (cfg->whitelist_path[0]) printf("  Whitelist       : %s\n", cfg->whitelist_path);
    printf("------------------------------------------------------------\n");
}

static bool parse_u16(const char *s, uint16_t *out) {
    if (!s || !s[0]) return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0' || v > 65535UL) return false;
    *out = (uint16_t)v;
    return true;
}

static bool parse_auto_ttl_spec(const char *s, JaponConfig *cfg) {
    unsigned int a1 = 0, a2 = 0, am = 0;
    if (sscanf(s, "%u-%u-%u", &a1, &a2, &am) == 3 && a1 <= 255 && a2 <= 255 && am <= 255) {
        cfg->auto_ttl_1 = (uint8_t)a1;
        cfg->auto_ttl_2 = (uint8_t)a2;
        cfg->auto_ttl_max = (uint8_t)am;
        return true;
    }
    uint16_t single = 0;
    if (parse_u16(s, &single) && single <= 255) {
        cfg->auto_ttl_1 = (uint8_t)single;
        cfg->auto_ttl_2 = (uint8_t)single;
        return true;
    }
    return false;
}

/* ============================================================================
 * Built-in Self-Tests (--self-test)
 * ========================================================================== */

static int run_self_tests(void) {
    printf("[SELF-TEST] Japon DPI v%s birim testleri baslatiliyor...\n", JAPONDPI_VERSION);
    int passed = 0, failed = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("  [OK]   %s\n", name); passed++; } \
    else      { printf("  [FAIL] %s\n", name); failed++; } \
} while (0)

    FakePayloads fp;
    fake_payloads_init(&fp, "discord.com", "www.w3.org");
    TlsParseResult tls;
    bool parsed = dpi_parse_tls_client_hello(fp.tls_buf, fp.tls_len, &tls);
    CHECK("TLS ClientHello olusturma ve SNI cozumleme",
          parsed && tls.found_sni && strcmp(tls.sni_host, "discord.com") == 0 &&
          tls.sni_len == 11 && memcmp(fp.tls_buf + tls.sni_offset, "discord.com", 11) == 0);

    const char *orig_http = "GET /index.html HTTP/1.1\r\nHost: discord.com\r\nUser-Agent: Test\r\n\r\n";
    char http_buf[256];
    size_t http_len = strlen(orig_http);
    memcpy(http_buf, orig_http, http_len + 1);
    JaponConfig hcfg;
    config_set_defaults(&hcfg);
    hcfg.http_host_replace = true;
    hcfg.http_host_rmspace = true;
    hcfg.http_host_mixcase = true;
    char extracted_host[64];
    bool host_ok = dpi_extract_http_host((const uint8_t *)http_buf, http_len, extracted_host, sizeof(extracted_host));
    bool mangled = dpi_mangle_http_payload((uint8_t *)http_buf, http_len, &hcfg);
    CHECK("HTTP Host cikarma ve uzunluk korumali donusum",
          host_ok && strcmp(extracted_host, "discord.com") == 0 && mangled &&
          strlen(http_buf) == http_len &&
          strstr(http_buf, "GET  /index.html") != NULL &&
          strstr(http_buf, "hoSt:dIsCoRd.cOm") != NULL);

    uint8_t quic_v1[1200] = {0}; quic_v1[0] = 0xC3; quic_v1[4] = 0x01;
    uint8_t quic_v2[1200] = {0}; quic_v2[0] = 0xD1; quic_v2[1] = 0x6b; quic_v2[2] = 0x33; quic_v2[3] = 0x43; quic_v2[4] = 0xcf;
    uint8_t wireguard[1200] = {0}; wireguard[0] = 0x01;
    CHECK("QUIC v1/v2 Initial tespiti (WireGuard dokunulmaz)",
          dpi_is_quic_initial(quic_v1, sizeof(quic_v1)) &&
          dpi_is_quic_initial(quic_v2, sizeof(quic_v2)) &&
          !dpi_is_quic_initial(wireguard, sizeof(wireguard)));

    CHECK("GoodbyeDPI Auto-TTL (Linux TTL=54 -> 6, Google TTL=112 -> 4, LAN TTL=63 -> 0)",
          ttl_compute_auto_fake(54, 1, 4, 3, 10) == 6 &&
          ttl_compute_auto_fake(112, 1, 4, 3, 10) == 4 &&
          ttl_compute_auto_fake(118, 1, 4, 3, 10) == 0 &&
          ttl_compute_auto_fake(63, 1, 4, 3, 10) == 0);

    JaponConfig fcfg;
    config_set_defaults(&fcfg);
    apply_preset(&fcfg, 5);
    fcfg.auto_ttl = false;
    fcfg.fake_ttl = 5;
    fcfg.min_ttl  = 0;
    fcfg.dns_redir_v4 = true;
    lstrcpynA(fcfg.dns_addr_v4_str, "208.67.222.222", sizeof(fcfg.dns_addr_v4_str));
    fcfg.dns_port_v4 = 443;
    char filter[4096];
    bool flt_ok = dpi_build_filter(&fcfg, filter, sizeof(filter));
    CHECK("WinDivert -5 --set-ttl 5 filtresi (yerel ag haric + sifir gelen TCP)",
          flt_ok &&
          strstr(filter, "192.168.0.0") != NULL &&
          strstr(filter, "tcp.Syn") == NULL &&
          strstr(filter, "ip.SrcAddr == 208.67.222.222") != NULL);

    DomainList dl;
    domain_list_init(&dl);
    domain_list_add(&dl, "discord.com");
    CHECK("Domain ve alt alan adi eslestirme",
          domain_list_matches(&dl, "discord.com") &&
          domain_list_matches(&dl, "ptb.discord.com") &&
          !domain_list_matches(&dl, "notdiscord.com"));
    domain_list_free(&dl);

    DnsRedirector dr;
    dns_redir_init(&dr);
    JaponConfig dcfg;
    config_set_defaults(&dcfg);
    dcfg.dns_redir_v4 = true;
    struct in_addr dns_in, cli_ip, gw_ip;
    inet_pton(AF_INET, "208.67.222.222", &dns_in);
    inet_pton(AF_INET, "192.168.1.50", &cli_ip);
    inet_pton(AF_INET, "192.168.1.1", &gw_ip);
    dcfg.dns_addr_v4_net = dns_in.s_addr;
    dcfg.dns_port_v4 = 443;
    JaponStats dstats; ZeroMemory(&dstats, sizeof(dstats));
    WINDIVERT_IPHDR ip_pkt; ZeroMemory(&ip_pkt, sizeof(ip_pkt));
    ip_pkt.SrcAddr = cli_ip.s_addr; ip_pkt.DstAddr = gw_ip.s_addr;
    WINDIVERT_UDPHDR udp_pkt; ZeroMemory(&udp_pkt, sizeof(udp_pkt));
    udp_pkt.SrcPort = htons(54321); udp_pkt.DstPort = htons(53);
    uint8_t dns_q[24] = { 0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3,'a','b','c', 3,'c','o','m', 0, 0,1, 0 };
    uint8_t dns_r[24] = { 0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3,'a','b','c', 3,'c','o','m', 0, 0,1, 0 };
    int out_rc = dns_redir_process(&dr, &dcfg, &dstats, true, &ip_pkt, NULL, &udp_pkt, dns_q, sizeof(dns_q));
    bool out_ok = (out_rc == 1 && ip_pkt.DstAddr == dns_in.s_addr && udp_pkt.DstPort == htons(443));
    ip_pkt.SrcAddr = dns_in.s_addr; ip_pkt.DstAddr = cli_ip.s_addr;
    udp_pkt.SrcPort = htons(443); udp_pkt.DstPort = htons(54321);
    int in_rc = dns_redir_process(&dr, &dcfg, &dstats, false, &ip_pkt, NULL, &udp_pkt, dns_r, sizeof(dns_r));
    bool in_ok = (in_rc == 1 && ip_pkt.SrcAddr == gw_ip.s_addr && udp_pkt.SrcPort == htons(53));
    CHECK("DNS NAT gidis-donus + paket dogrulama (192.168.1.1:53 <-> 208.67.222.222:443)", out_ok && in_ok);

    DomainList wl; domain_list_init(&wl); domain_list_add(&wl, "googlevideo.com");
    IpWhitelistCache ip_wl; memset(&ip_wl, 0, sizeof(ip_wl));
    static const uint8_t sample_dns_resp[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 'r','r','1', 0x0b, 'g','o','o','g','l','e','v','i','d','e','o', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
        173, 194, 188, 134
    };
    dpi_dns_learn_whitelist_ips(sample_dns_resp, sizeof(sample_dns_resp), &wl, &ip_wl);
    struct in_addr yt_ip, dc_ip;
    inet_pton(AF_INET, "173.194.188.134", &yt_ip);
    inet_pton(AF_INET, "162.159.134.233", &dc_ip);
    uint32_t yt_key[4] = { yt_ip.s_addr, 0, 0, 0 };
    uint32_t dc_key[4] = { dc_ip.s_addr, 0, 0, 0 };
    CHECK("Whitelist DNS IP ogrenme (YouTube QUIC 0-RTT gecisi)",
          dpi_ip_wl_contains(&ip_wl, false, yt_key) && !dpi_ip_wl_contains(&ip_wl, false, dc_key));
    domain_list_free(&wl);

#undef CHECK
    printf("[SELF-TEST] Tamamlandi: %d basarili, %d basarisiz.\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);

    JaponConfig cfg;
    config_set_defaults(&cfg);

    if (argc == 1) {
        apply_preset(&cfg, 9); /* Default mode -9 like GoodbyeDPI 0.2.3 */
    }

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(arg, "--version") == 0) {
            printf("Japon DPI v%s\n", JAPONDPI_VERSION);
            return 0;
        } else if (strcmp(arg, "--self-test") == 0) {
            return run_self_tests();
        } else if (arg[0] == '-' && arg[1] >= '1' && arg[1] <= '9' && arg[2] == '\0') {
            apply_preset(&cfg, arg[1] - '0');
        } else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--frag-http") == 0) {
            if (++i >= argc || !parse_u16(argv[i], &cfg.http_frag_size)) {
                fprintf(stderr, "[HATA] %s icin gecerli bir sayi girin.\n", arg);
                return 1;
            }
        } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--frag-https") == 0) {
            if (++i >= argc || !parse_u16(argv[i], &cfg.https_frag_size)) {
                fprintf(stderr, "[HATA] %s icin gecerli bir sayi girin.\n", arg);
                return 1;
            }
        } else if (strcmp(arg, "--frag-by-sni") == 0 || strcmp(arg, "--split-sni") == 0) {
            cfg.frag_by_sni = true;
        } else if (strcmp(arg, "--multi-split") == 0) {
            cfg.multi_split = true;
        } else if (strcmp(arg, "--reverse-frag") == 0) {
            cfg.reverse_frag = true;
        } else if (strcmp(arg, "--native-frag") == 0) {
            cfg.reverse_frag = false;
        } else if (strcmp(arg, "-r") == 0 || strcmp(arg, "--http-replace") == 0) {
            cfg.http_host_replace = true;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--http-rmspace") == 0) {
            cfg.http_host_rmspace = true;
        } else if (strcmp(arg, "-m") == 0 || strcmp(arg, "--http-mixcase") == 0) {
            cfg.http_host_mixcase = true;
        } else if (strcmp(arg, "-p") == 0 || strcmp(arg, "--passive-block") == 0) {
            cfg.passive_block = true;
        } else if (strcmp(arg, "-q") == 0 || strcmp(arg, "--block-quic") == 0) {
            cfg.block_quic = true;
        } else if (strcmp(arg, "-w") == 0 || strcmp(arg, "--window-size") == 0) {
            if (++i >= argc || !parse_u16(argv[i], &cfg.window_size)) {
                fprintf(stderr, "[HATA] %s icin gecerli bir sayi girin.\n", arg);
                return 1;
            }
        } else if (strcmp(arg, "--set-ttl") == 0) {
            uint16_t v = 0;
            if (++i >= argc || !parse_u16(argv[i], &v) || v < 1 || v > 255) {
                fprintf(stderr, "[HATA] --set-ttl degeri 1-255 arasi olmali.\n");
                return 1;
            }
            /* Exact GoodbyeDPI behavior: --set-ttl disables auto-ttl & removes inbound SYN-ACK overhead! */
            cfg.auto_ttl = false;
            cfg.min_ttl  = 0;
            cfg.fake_ttl = (uint8_t)v;
        } else if (strcmp(arg, "--min-ttl") == 0) {
            uint16_t v = 0;
            if (++i >= argc || !parse_u16(argv[i], &v) || v > 255) {
                fprintf(stderr, "[HATA] --min-ttl degeri 0-255 arasi olmali.\n");
                return 1;
            }
            cfg.min_ttl = (uint8_t)v;
        } else if (strcmp(arg, "--auto-ttl") == 0) {
            cfg.auto_ttl = true;
            cfg.fake_ttl = 0;
            if (cfg.min_ttl == 0) cfg.min_ttl = 3;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (parse_auto_ttl_spec(argv[i + 1], &cfg)) {
                    i++;
                }
            }
        } else if (strcmp(arg, "--wrong-chksum") == 0 || strcmp(arg, "--wrong-checksum") == 0) {
            cfg.wrong_checksum = true;
        } else if (strcmp(arg, "--wrong-seq") == 0) {
            cfg.wrong_seq = true;
        } else if (strcmp(arg, "--fake-resend") == 0 || strcmp(arg, "--fake-repeats") == 0) {
            uint16_t v = 0;
            if (++i >= argc || !parse_u16(argv[i], &v) || v < 1 || v > 10) {
                fprintf(stderr, "[HATA] %s degeri 1-10 arasi olmali.\n", arg);
                return 1;
            }
            cfg.fake_repeats = (uint8_t)v;
        } else if (strcmp(arg, "--fake-sni") == 0 || strcmp(arg, "--fake-with-sni") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] %s icin alan adi girin.\n", arg);
                return 1;
            }
            lstrcpynA(cfg.fake_sni, argv[i], sizeof(cfg.fake_sni));
        } else if (strcmp(arg, "--dns-addr") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] --dns-addr icin IPv4 adresi girin.\n");
                return 1;
            }
            struct in_addr in4;
            if (inet_pton(AF_INET, argv[i], &in4) != 1) {
                fprintf(stderr, "[HATA] Gecersiz IPv4 DNS adresi: %s\n", argv[i]);
                return 1;
            }
            cfg.dns_redir_v4 = true;
            cfg.dns_addr_v4_net = in4.s_addr;
            lstrcpynA(cfg.dns_addr_v4_str, argv[i], sizeof(cfg.dns_addr_v4_str));
        } else if (strcmp(arg, "--dns-port") == 0) {
            if (++i >= argc || !parse_u16(argv[i], &cfg.dns_port_v4) || cfg.dns_port_v4 == 0) {
                fprintf(stderr, "[HATA] Gecersiz --dns-port degeri.\n");
                return 1;
            }
        } else if (strcmp(arg, "--dnsv6-addr") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] --dnsv6-addr icin IPv6 adresi girin.\n");
                return 1;
            }
            struct in6_addr in6;
            if (inet_pton(AF_INET6, argv[i], &in6) != 1) {
                fprintf(stderr, "[HATA] Gecersiz IPv6 DNS adresi: %s\n", argv[i]);
                return 1;
            }
            cfg.dns_redir_v6 = true;
            memcpy(cfg.dns_addr_v6_net, &in6, 16);
            lstrcpynA(cfg.dns_addr_v6_str, argv[i], sizeof(cfg.dns_addr_v6_str));
        } else if (strcmp(arg, "--dnsv6-port") == 0) {
            if (++i >= argc || !parse_u16(argv[i], &cfg.dns_port_v6) || cfg.dns_port_v6 == 0) {
                fprintf(stderr, "[HATA] Gecersiz --dnsv6-port degeri.\n");
                return 1;
            }
        } else if (strcmp(arg, "--block-dnsv6") == 0) {
            cfg.block_dns_v6 = true;
        } else if (strcmp(arg, "--port") == 0) {
            uint16_t p = 0;
            if (++i >= argc || !parse_u16(argv[i], &p) || p == 0) {
                fprintf(stderr, "[HATA] Gecersiz --port degeri.\n");
                return 1;
            }
            if (cfg.extra_port_count < JAPONDPI_MAX_PORTS) {
                cfg.extra_ports[cfg.extra_port_count++] = p;
            }
        } else if (strcmp(arg, "--max-payload") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (!parse_u16(argv[++i], &cfg.max_payload)) {
                    fprintf(stderr, "[HATA] Gecersiz --max-payload degeri.\n");
                    return 1;
                }
            } else {
                cfg.max_payload = 1200;
            }
        } else if (strcmp(arg, "--blacklist") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] --blacklist icin dosya yolu girin.\n");
                return 1;
            }
            lstrcpynA(cfg.blacklist_path, argv[i], sizeof(cfg.blacklist_path));
        } else if (strcmp(arg, "--whitelist") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] --whitelist icin dosya yolu girin.\n");
                return 1;
            }
            lstrcpynA(cfg.whitelist_path, argv[i], sizeof(cfg.whitelist_path));
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            cfg.verbose = true;
        } else if (strcmp(arg, "--quiet") == 0) {
            cfg.quiet = true;
        } else if (strcmp(arg, "--service") == 0) {
            cfg.run_as_service = true;
        } else if (strcmp(arg, "--test-filter") == 0) {
            cfg.test_filter = true;
        } else {
            fprintf(stderr, "[HATA] Bilinmeyen parametre: %s (Yardim icin --help)\n", arg);
            return 1;
        }
    }

    char err_buf[1024];
    if (!dpi_engine_init(&g_engine, &cfg, err_buf, sizeof(err_buf))) {
        fprintf(stderr, "[HATA] %s\n", err_buf);
        return 1;
    }

    if (cfg.test_filter) {
        char filter[4096];
        print_banner();
        print_active_summary(&cfg);
        if (dpi_build_filter(&cfg, filter, sizeof(filter))) {
            printf("WinDivert Filtresi:\n%s\n", filter);
            char wd_err[512];
            if (wd_load_library(wd_err, sizeof(wd_err))) {
                const char *ferr = NULL;
                UINT fpos = 0;
                char obj[4096];
                if (g_wd.HelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, obj, sizeof(obj), &ferr, &fpos)) {
                    printf("[OK] WinDivert.dll filtre dogrulamasi BASARILI!\n");
                } else {
                    fprintf(stderr, "[HATA] WinDivert filtre hatasi (konum %u): %s\n",
                            fpos, ferr ? ferr : "bilinmiyor");
                    wd_unload_library();
                    dpi_engine_destroy(&g_engine);
                    return 1;
                }
                wd_unload_library();
            }
        }
        dpi_engine_destroy(&g_engine);
        return 0;
    }

    if (cfg.run_as_service) {
        return japondpi_run_as_service(&g_engine);
    }

    if (!cfg.quiet) {
        print_banner();
        print_active_summary(&cfg);
    }

    if (!wd_load_library(err_buf, sizeof(err_buf))) {
        fprintf(stderr, "\n[HATA] %s\n", err_buf);
        dpi_engine_destroy(&g_engine);
        return 1;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    int rc = dpi_engine_run(&g_engine);

    if (!cfg.quiet) {
        printf("\n------------------------------------------------------------\n");
        printf("Japon DPI durduruldu. Oturum Istatistikleri:\n");
        printf("  Toplam Islenen Paket : %lld\n", (long long)g_engine.stats.packets_total);
        printf("  TLS/HTTPS Bypass     : %lld\n", (long long)g_engine.stats.tls_bypassed);
        printf("  HTTP Bypass          : %lld\n", (long long)g_engine.stats.http_bypassed);
        printf("  Sahte Paket (Fake)   : %lld\n", (long long)g_engine.stats.fake_sent);
        printf("  DNS Yonlendirme      : %lld\n", (long long)g_engine.stats.dns_redirected);
        printf("  QUIC Engellenen      : %lld\n", (long long)g_engine.stats.quic_blocked);
        printf("  Pasif DPI Engellenen : %lld\n", (long long)g_engine.stats.passive_dropped);
        printf("------------------------------------------------------------\n");
    }

    dpi_engine_destroy(&g_engine);
    wd_unload_library();
    return rc;
}
