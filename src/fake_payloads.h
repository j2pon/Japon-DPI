#ifndef JAPONDPI_FAKE_PAYLOADS_H
#define JAPONDPI_FAKE_PAYLOADS_H

#include <stdint.h>
#include <stddef.h>

#define FAKE_TLS_MAX_LEN  1024
#define FAKE_HTTP_MAX_LEN 512

typedef struct {
    uint8_t tls_buf[FAKE_TLS_MAX_LEN];
    size_t  tls_len;
    uint8_t http_buf[FAKE_HTTP_MAX_LEN];
    size_t  http_len;
} FakePayloads;

/* Builds realistic RFC-compliant fake TLS ClientHello & HTTP GET payloads */
void fake_payloads_init(FakePayloads *fp, const char *fake_sni, const char *fake_http_host);

#endif /* JAPONDPI_FAKE_PAYLOADS_H */
