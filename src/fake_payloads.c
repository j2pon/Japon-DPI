#include "fake_payloads.h"
#include <string.h>
#include <stdio.h>

static void put_u16(uint8_t *buf, size_t *pos, uint16_t val) {
    buf[(*pos)++] = (uint8_t)(val >> 8);
    buf[(*pos)++] = (uint8_t)(val & 0xFF);
}

static void put_u24(uint8_t *buf, size_t *pos, uint32_t val) {
    buf[(*pos)++] = (uint8_t)((val >> 16) & 0xFF);
    buf[(*pos)++] = (uint8_t)((val >> 8) & 0xFF);
    buf[(*pos)++] = (uint8_t)(val & 0xFF);
}

static void put_bytes(uint8_t *buf, size_t *pos, const void *src, size_t len) {
    memcpy(buf + *pos, src, len);
    *pos += len;
}

void fake_payloads_init(FakePayloads *fp, const char *fake_sni, const char *fake_http_host) {
    if (!fake_sni || !fake_sni[0]) {
        fake_sni = "www.google.com";
    }
    if (!fake_http_host || !fake_http_host[0]) {
        fake_http_host = "www.w3.org";
    }

    size_t sni_len = strlen(fake_sni);
    if (sni_len > 200) sni_len = 200;

    /* ---- Build Fake TLS 1.2/1.3 ClientHello ---- */
    uint8_t *b = fp->tls_buf;
    size_t pos = 0;

    /* TLS Record Header (5 bytes): Handshake (0x16), TLS 1.0 (0x03 0x01), length placeholder */
    b[pos++] = 0x16;
    b[pos++] = 0x03;
    b[pos++] = 0x01;
    size_t rec_len_pos = pos;
    pos += 2;

    /* Handshake Header (4 bytes): ClientHello (0x01), 24-bit length placeholder */
    size_t hs_start = pos;
    b[pos++] = 0x01;
    size_t hs_len_pos = pos;
    pos += 3;

    /* Client Version: TLS 1.2 (0x03 0x03) */
    put_u16(b, &pos, 0x0303);

    /* Random (32 bytes) */
    for (int i = 0; i < 32; i++) {
        b[pos++] = (uint8_t)((i * 37 + 0x5A) & 0xFF);
    }

    /* Session ID (32 bytes, TLS 1.3 compatibility mode) */
    b[pos++] = 32;
    for (int i = 0; i < 32; i++) {
        b[pos++] = (uint8_t)((i * 53 + 0xA5) & 0xFF);
    }

    /* Cipher Suites (standard modern Chrome/Firefox suite list) */
    static const uint16_t ciphers[] = {
        0x1301, /* TLS_AES_128_GCM_SHA256 */
        0x1302, /* TLS_AES_256_GCM_SHA384 */
        0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
        0xC02B, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
        0xC02F, /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
        0xC02C, /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
        0xC030, /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
        0xCCA9, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
        0xCCA8, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
        0xC013, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
        0xC014, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
        0x009C, /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
        0x009D, /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
        0x002F, /* TLS_RSA_WITH_AES_128_CBC_SHA */
        0x0035  /* TLS_RSA_WITH_AES_256_CBC_SHA */
    };
    size_t cipher_count = sizeof(ciphers) / sizeof(ciphers[0]);
    put_u16(b, &pos, (uint16_t)(cipher_count * 2));
    for (size_t i = 0; i < cipher_count; i++) {
        put_u16(b, &pos, ciphers[i]);
    }

    /* Compression methods: 1 method (null = 0x00) */
    b[pos++] = 1;
    b[pos++] = 0;

    /* Extensions length placeholder */
    size_t ext_len_pos = pos;
    pos += 2;
    size_t ext_start = pos;

    /* Extension 1: server_name (0x0000) */
    put_u16(b, &pos, 0x0000);
    put_u16(b, &pos, (uint16_t)(sni_len + 5));
    put_u16(b, &pos, (uint16_t)(sni_len + 3));
    b[pos++] = 0x00; /* host_name */
    put_u16(b, &pos, (uint16_t)sni_len);
    put_bytes(b, &pos, fake_sni, sni_len);

    /* Extension 2: extended_master_secret (0x0017) */
    put_u16(b, &pos, 0x0017);
    put_u16(b, &pos, 0x0000);

    /* Extension 3: renegotiation_info (0xff01) */
    put_u16(b, &pos, 0xFF01);
    put_u16(b, &pos, 0x0001);
    b[pos++] = 0x00;

    /* Extension 4: supported_groups (0x000a) */
    put_u16(b, &pos, 0x000A);
    put_u16(b, &pos, 0x0008);
    put_u16(b, &pos, 0x0006);
    put_u16(b, &pos, 0x001D); /* x25519 */
    put_u16(b, &pos, 0x0017); /* secp256r1 */
    put_u16(b, &pos, 0x0018); /* secp384r1 */

    /* Extension 5: ec_point_formats (0x000b) */
    put_u16(b, &pos, 0x000B);
    put_u16(b, &pos, 0x0002);
    b[pos++] = 0x01;
    b[pos++] = 0x00;

    /* Extension 6: session_ticket (0x0023) */
    put_u16(b, &pos, 0x0023);
    put_u16(b, &pos, 0x0000);

    /* Extension 7: application_layer_protocol_negotiation (0x0010): h2, http/1.1 */
    static const uint8_t alpn_data[] = {
        0x00, 0x0C,
        0x02, 'h', '2',
        0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    put_u16(b, &pos, 0x0010);
    put_u16(b, &pos, sizeof(alpn_data));
    put_bytes(b, &pos, alpn_data, sizeof(alpn_data));

    /* Extension 8: signature_algorithms (0x000d) */
    static const uint16_t sig_algs[] = {
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
    };
    size_t sig_cnt = sizeof(sig_algs) / sizeof(sig_algs[0]);
    put_u16(b, &pos, 0x000D);
    put_u16(b, &pos, (uint16_t)(2 + sig_cnt * 2));
    put_u16(b, &pos, (uint16_t)(sig_cnt * 2));
    for (size_t i = 0; i < sig_cnt; i++) {
        put_u16(b, &pos, sig_algs[i]);
    }

    /* Extension 9: supported_versions (0x002b): TLS 1.3, TLS 1.2 */
    put_u16(b, &pos, 0x002B);
    put_u16(b, &pos, 0x0005);
    b[pos++] = 0x04;
    put_u16(b, &pos, 0x0304);
    put_u16(b, &pos, 0x0303);

    /* Extension 10: key_share (0x0033): dummy 32-byte x25519 share */
    put_u16(b, &pos, 0x0033);
    put_u16(b, &pos, 0x0026);
    put_u16(b, &pos, 0x0024);
    put_u16(b, &pos, 0x001D); /* x25519 */
    put_u16(b, &pos, 0x0020); /* 32 bytes */
    for (int i = 0; i < 32; i++) {
        b[pos++] = (uint8_t)((i * 19 + 0x33) & 0xFF);
    }

    /* Extension 11: padding (0x0015) to pad total TLS packet to 517 bytes */
    const size_t target_len = 517;
    if (pos + 4 < target_len && target_len <= FAKE_TLS_MAX_LEN) {
        size_t pad_len = target_len - (pos + 4);
        put_u16(b, &pos, 0x0015);
        put_u16(b, &pos, (uint16_t)pad_len);
        memset(b + pos, 0, pad_len);
        pos += pad_len;
    }

    /* Backfill lengths */
    size_t ext_len = pos - ext_start;
    size_t hs_body_len = pos - (hs_start + 4);
    size_t rec_len = pos - 5;

    size_t tmp;
    tmp = ext_len_pos; put_u16(b, &tmp, (uint16_t)ext_len);
    tmp = hs_len_pos;  put_u24(b, &tmp, (uint32_t)hs_body_len);
    tmp = rec_len_pos; put_u16(b, &tmp, (uint16_t)rec_len);

    fp->tls_len = pos;

    /* ---- Build Fake HTTP GET Request ---- */
    int n = snprintf((char *)fp->http_buf, FAKE_HTTP_MAX_LEN,
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        "Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        fake_http_host);
    fp->http_len = (n > 0 && (size_t)n < FAKE_HTTP_MAX_LEN) ? (size_t)n : 0;
}
