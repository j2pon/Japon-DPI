#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
    printf("  Acik Kaynak, Sifir Paketleyici, Yuksek Performans DPI\n");
    printf("============================================================\n");
}

static void print_usage(void) {
    print_banner();
    printf(
        "\nKullanim: japondpi.exe [secenekler]\n\n"
        "Hazir Hizli Modlar (GoodbyeDPI uyumlu prensip):\n"
        "  -1 .. -9              Hazir paket parcalama/sahte paket profilleri\n"
        "                        (-5: Turk Telekom/Genel, -9: Agresif)\n\n"
        "Paket Parcalama (Fragmentation):\n"
        "  -f <N>                HTTP istegini N. bayttan bol (orn: -f 2)\n"
        "  -e <N>                HTTPS (TLS ClientHello) N. bayttan bol (orn: -e 2)\n"
        "  --split-sni           TLS ClientHello paketini SNI alan adinin ortasindan bol\n"
        "  --multi-split         3 parcali TLS bolme (kayit basligi + SNI ortasi)\n"
        "  --reverse-frag        Parcalari ters sirada gonder (son parca once)\n\n"
        "Sahte Paket (Fake Packet / Desync):\n"
        "  --set-ttl <N>         Sahte paket IP TTL degeri (orn: 3, 4, 5)\n"
        "  --auto-ttl            SYN-ACK TTL degerinden otomatik hop hesapla\n"
        "  --wrong-checksum      Sahte pakette bozuk TCP checksum kullan\n"
        "  --wrong-seq           Sahte pakette pencere disi TCP Seq/Ack kullan\n"
        "  --fake-repeats <N>    Her baglantida N adet sahte paket gonder (1-10)\n"
        "  --fake-sni <alan>     Sahte TLS SNI alan adi (varsayilan: www.google.com)\n\n"
        "HTTP & Pasif DPI:\n"
        "  -r, --http-replace    'Host:' basligini 'hoSt:' yap\n"
        "  -s, --http-rmspace    'Host:' boslugunu kaldir (TCP uzunlugunu koruyarak)\n"
        "  -m, --http-mixcase    HTTP alan adinda buyuk/kucuk harf karistir\n"
        "  -p, --passive-block   ISS sahte RST ve HTTP 302 yonlendirmelerini engelle\n"
        "  -w <N>                Gelen SYN-ACK TCP pencere boyutunu N yap\n\n"
        "DNS Yonlendirme & QUIC:\n"
        "  --dns-addr <IP>       IPv4 UDP:53 DNS sorgularini bu IP'ye yonlendir\n"
        "  --dns-port <PORT>     IPv4 hedef DNS portu (orn: 1253)\n"
        "  --dnsv6-addr <IPv6>   IPv6 UDP:53 DNS sorgularini bu IPv6'ya yonlendir\n"
        "  --dnsv6-port <PORT>   IPv6 hedef DNS portu (orn: 1253)\n"
        "  --block-dnsv6         IPv6 UDP:53 engelle (IPv4 DNS yonlendirmesi zorunlu)\n"
        "  --block-quic          QUIC (UDP:443) Initial paketlerini engelle (TCP fallback)\n\n"
        "Filtreleme & Diger:\n"
        "  --port <PORT>         Ek TCP HTTPS portu ekle (en fazla 16 adet)\n"
        "  --max-payload <N>     Maksimum paket boyutu siniri (0 = sinirsiz, ML-KEM uyumlu)\n"
        "  --blacklist <dosya>   Sadece listedeki alan adlarina uygula\n"
        "  --whitelist <dosya>   Listedeki alan adlarina DOKUNMA\n"
        "  -v, --verbose         Detayli canli alan adi gunlugu goster\n"
        "  -q, --quiet           Sessiz mod\n"
        "  --service             Windows servisi modunda calis\n"
        "  --test-filter         Olusan WinDivert filtresini yazdir ve cik\n"
        "  --self-test           Dahili paket motoru birim testlerini calistir\n"
        "  -h, --help            Bu yardim mesajini goster\n"
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
        cfg->http_frag_size = 2;
        cfg->split_sni = true;
        break;
    case 4:
        cfg->passive_block = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->reverse_frag = true;
        break;
    case 5: /* Classic Turkey / General preset */
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->split_sni = true;
        cfg->http_host_replace = true;
        cfg->http_host_mixcase = true;
        cfg->auto_ttl = true;
        cfg->fake_ttl = 5;
        cfg->reverse_frag = true;
        break;
    case 6:
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->wrong_seq = true;
        cfg->reverse_frag = true;
        break;
    case 7:
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->wrong_checksum = true;
        cfg->reverse_frag = true;
        break;
    case 8:
        cfg->http_frag_size = 2;
        cfg->multi_split = true;
        cfg->wrong_checksum = true;
        cfg->wrong_seq = true;
        cfg->reverse_frag = true;
        break;
    case 9: /* Aggressive mode */
    default:
        cfg->http_frag_size = 2;
        cfg->https_frag_size = 2;
        cfg->multi_split = true;
        cfg->reverse_frag = true;
        cfg->http_host_replace = true;
        cfg->http_host_rmspace = true;
        cfg->http_host_mixcase = true;
        cfg->passive_block = true;
        cfg->wrong_checksum = true;
        cfg->wrong_seq = true;
        cfg->fake_ttl = 5;
        cfg->fake_repeats = 2;
        break;
    }
}

static void print_active_summary(const JaponConfig *cfg) {
    printf("Aktif Ayarlar:\n");
    printf("  TLS/HTTPS Bolme : ");
    if (cfg->multi_split) {
        printf("3-Parcali (Multi-Split + SNI)");
    } else if (cfg->split_sni) {
        printf("SNI Ortasi (fallback: %u byte)", (unsigned)(cfg->https_frag_size ? cfg->https_frag_size : 2));
    } else if (cfg->https_frag_size > 0) {
        printf("%u byte", (unsigned)cfg->https_frag_size);
    } else {
        printf("Kapali");
    }
    if (cfg->reverse_frag) printf(" [Ters Sira]");
    printf("\n");

    printf("  Sahte Paket     : ");
    if (cfg->fake_ttl > 0 || cfg->auto_ttl || cfg->wrong_checksum || cfg->wrong_seq) {
        if (cfg->auto_ttl) printf("Auto-TTL ");
        if (cfg->fake_ttl > 0) printf("TTL=%u ", (unsigned)cfg->fake_ttl);
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
           cfg->passive_block ? "Acik" : "Kapali");

    if (cfg->dns_redir_v4) {
        printf("  IPv4 DNS Yonl.  : UDP:53 -> %s:%u\n", cfg->dns_addr_v4_str, (unsigned)cfg->dns_port_v4);
    }
    if (cfg->dns_redir_v6) {
        printf("  IPv6 DNS Yonl.  : UDP:53 -> [%s]:%u\n", cfg->dns_addr_v6_str, (unsigned)cfg->dns_port_v6);
    } else if (cfg->block_dns_v6) {
        printf("  IPv6 DNS        : Engelli (IPv4 DNS zorunlu)\n");
    }
    if (cfg->block_quic) {
        printf("  QUIC (UDP:443)  : Initial Engelli (Tarayici TCP'ye duser)\n");
    }
    if (cfg->blacklist_path[0]) {
        printf("  Blacklist       : %s\n", cfg->blacklist_path);
    }
    if (cfg->whitelist_path[0]) {
        printf("  Whitelist       : %s\n", cfg->whitelist_path);
    }
    printf("------------------------------------------------------------\n");
}

/* ============================================================================
 * Built-in Self-Tests (--self-test)
 * ========================================================================== */

static int run_self_tests(void) {
    printf("[SELF-TEST] Japon DPI birim testleri baslatiliyor...\n");
    int passed = 0, failed = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("  [OK]   %s\n", name); passed++; } \
    else      { printf("  [FAIL] %s\n", name); failed++; } \
} while (0)

    /* Test 1: Fake TLS ClientHello build + SNI parse round-trip */
    FakePayloads fp;
    fake_payloads_init(&fp, "discord.com", "www.w3.org");
    TlsParseResult tls;
    bool parsed = dpi_parse_tls_client_hello(fp.tls_buf, fp.tls_len, &tls);
    CHECK("TLS ClientHello olusturma ve SNI cozumleme",
          parsed && tls.found_sni && strcmp(tls.sni_host, "discord.com") == 0 &&
          tls.sni_len == 11 && memcmp(fp.tls_buf + tls.sni_offset, "discord.com", 11) == 0);

    /* Test 2: HTTP header mangling length invariance */
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

    /* Test 3: QUIC Initial detection (positive & negative cases) */
    uint8_t quic_v1[1200] = {0};
    quic_v1[0] = 0xC3; quic_v1[4] = 0x01; /* QUIC v1 Initial */
    uint8_t quic_v2[1200] = {0};
    quic_v2[0] = 0xD1; quic_v2[1] = 0x6b; quic_v2[2] = 0x33; quic_v2[3] = 0x43; quic_v2[4] = 0xcf;
    uint8_t wireguard[1200] = {0};
    wireguard[0] = 0x01; /* WireGuard handshake initiation */
    uint8_t short_udp[64] = {0};
    short_udp[0] = 0xC0; short_udp[4] = 0x01;
    CHECK("QUIC v1/v2 Initial tespiti (WireGuard/kisa UDP dokunulmaz)",
          dpi_is_quic_initial(quic_v1, sizeof(quic_v1)) &&
          dpi_is_quic_initial(quic_v2, sizeof(quic_v2)) &&
          !dpi_is_quic_initial(wireguard, sizeof(wireguard)) &&
          !dpi_is_quic_initial(short_udp, sizeof(short_udp)));

    /* Test 4: Auto-TTL hop estimation (including Google asymmetric TTL=112 safety) */
    CHECK("Auto-TTL hop hesaplama (Linux TTL=54 -> 6, Google TTL=112 -> 5, LAN TTL=63 -> 0)",
          ttl_compute_auto_fake(54, 3, 3, 6) == 6 &&
          ttl_compute_auto_fake(112, 3, 3, 6) == 5 &&
          ttl_compute_auto_fake(118, 3, 3, 6) == 0 &&
          ttl_compute_auto_fake(63, 3, 3, 6) == 0);

    /* Test 5: WinDivert filter generation */
    JaponConfig fcfg;
    config_set_defaults(&fcfg);
    apply_preset(&fcfg, 5);
    fcfg.dns_redir_v4 = true;
    lstrcpynA(fcfg.dns_addr_v4_str, "77.88.8.8", sizeof(fcfg.dns_addr_v4_str));
    fcfg.dns_port_v4 = 1253;
    fcfg.block_quic = true;
    char filter[2048];
    bool flt_ok = dpi_build_filter(&fcfg, filter, sizeof(filter));
    CHECK("WinDivert kernel filtresi olusturma",
          flt_ok &&
          strstr(filter, "tcp.Payload[0] == 0x16") != NULL &&
          strstr(filter, "ip.SrcAddr == 77.88.8.8") != NULL &&
          strstr(filter, "udp.DstPort == 443") != NULL);

    /* Test 6: Subdomain matching */
    DomainList dl;
    domain_list_init(&dl);
    domain_list_add(&dl, "discord.com");
    domain_list_add(&dl, "roblox.com");
    CHECK("Domain ve alt alan adi (subdomain) eslestirme",
          domain_list_matches(&dl, "discord.com") &&
          domain_list_matches(&dl, "cdn.discord.com") &&
          domain_list_matches(&dl, "A.B.ROBLOX.COM") &&
          !domain_list_matches(&dl, "notdiscord.com") &&
          !domain_list_matches(&dl, "google.com"));
    domain_list_free(&dl);

    /* Test 7: DNS NAT redirector round-trip (outbound rewrite + inbound restore) */
    DnsRedirector dr;
    dns_redir_init(&dr);
    JaponConfig dcfg;
    config_set_defaults(&dcfg);
    dcfg.dns_redir_v4 = true;
    struct in_addr dns_in;
    inet_pton(AF_INET, "77.88.8.8", &dns_in);
    dcfg.dns_addr_v4_net = dns_in.s_addr;
    dcfg.dns_port_v4 = 1253;
    JaponStats dstats;
    ZeroMemory(&dstats, sizeof(dstats));

    WINDIVERT_IPHDR ip_pkt;
    ZeroMemory(&ip_pkt, sizeof(ip_pkt));
    struct in_addr cli_ip, gw_ip;
    inet_pton(AF_INET, "192.168.1.50", &cli_ip);
    inet_pton(AF_INET, "192.168.1.1", &gw_ip);
    ip_pkt.SrcAddr = cli_ip.s_addr;
    ip_pkt.DstAddr = gw_ip.s_addr;

    WINDIVERT_UDPHDR udp_pkt;
    ZeroMemory(&udp_pkt, sizeof(udp_pkt));
    udp_pkt.SrcPort = htons(54321);
    udp_pkt.DstPort = htons(53);
    uint8_t dns_q[12] = { 0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };

    int out_rc = dns_redir_process(&dr, &dcfg, &dstats, true, &ip_pkt, NULL, &udp_pkt, dns_q, sizeof(dns_q));
    bool out_ok = (out_rc == 1 && ip_pkt.DstAddr == dns_in.s_addr && udp_pkt.DstPort == htons(1253));

    /* Simulate inbound response from 77.88.8.8:1253 -> 192.168.1.50:54321 */
    ip_pkt.SrcAddr = dns_in.s_addr;
    ip_pkt.DstAddr = cli_ip.s_addr;
    udp_pkt.SrcPort = htons(1253);
    udp_pkt.DstPort = htons(54321);
    int in_rc = dns_redir_process(&dr, &dcfg, &dstats, false, &ip_pkt, NULL, &udp_pkt, dns_q, sizeof(dns_q));
    bool in_ok = (in_rc == 1 && ip_pkt.SrcAddr == gw_ip.s_addr && udp_pkt.SrcPort == htons(53));
    CHECK("DNS NAT yonlendirme gidis-donus (192.168.1.1:53 <-> 77.88.8.8:1253)", out_ok && in_ok);

    /* Test 8: DNS whitelist IP learning for YouTube QUIC 0-RTT pass-through */
    DomainList wl;
    domain_list_init(&wl);
    domain_list_add(&wl, "googlevideo.com");
    IpWhitelistCache ip_wl;
    memset(&ip_wl, 0, sizeof(ip_wl));
    /* Minimal valid DNS response for rr1.googlevideo.com -> 173.194.188.134 */
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
    CHECK("YouTube/Whitelist DNS IP ogrenme (QUIC 0-RTT gecisi)",
          dpi_ip_wl_contains(&ip_wl, false, yt_key) &&
          !dpi_ip_wl_contains(&ip_wl, false, dc_key));
    domain_list_free(&wl);

#undef CHECK
    printf("[SELF-TEST] Tamamlandi: %d basarili, %d basarisiz.\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

/* ============================================================================
 * CLI Argument Parser & Entry Point
 * ========================================================================== */

static bool parse_u16(const char *s, uint16_t *out) {
    if (!s || !s[0]) return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0' || v > 65535UL) return false;
    *out = (uint16_t)v;
    return true;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);

    JaponConfig cfg;
    config_set_defaults(&cfg);

    if (argc == 1) {
        /* Default sensible profile when run with no flags */
        apply_preset(&cfg, 5);
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
        } else if (strcmp(arg, "--split-sni") == 0) {
            cfg.split_sni = true;
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
            cfg.fake_ttl = (uint8_t)v;
        } else if (strcmp(arg, "--auto-ttl") == 0) {
            cfg.auto_ttl = true;
        } else if (strcmp(arg, "--wrong-checksum") == 0) {
            cfg.wrong_checksum = true;
        } else if (strcmp(arg, "--wrong-seq") == 0) {
            cfg.wrong_seq = true;
        } else if (strcmp(arg, "--fake-repeats") == 0) {
            uint16_t v = 0;
            if (++i >= argc || !parse_u16(argv[i], &v) || v < 1 || v > 10) {
                fprintf(stderr, "[HATA] --fake-repeats degeri 1-10 arasi olmali.\n");
                return 1;
            }
            cfg.fake_repeats = (uint8_t)v;
        } else if (strcmp(arg, "--fake-sni") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[HATA] --fake-sni icin alan adi girin.\n");
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
        } else if (strcmp(arg, "--block-quic") == 0) {
            cfg.block_quic = true;
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
            if (++i >= argc || !parse_u16(argv[i], &cfg.max_payload)) {
                fprintf(stderr, "[HATA] Gecersiz --max-payload degeri.\n");
                return 1;
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
        } else if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
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
        char filter[2048];
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

    /* Windows Service mode */
    if (cfg.run_as_service) {
        return japondpi_run_as_service(&g_engine);
    }

    /* Console mode */
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
