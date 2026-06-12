#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ngx_stream_trojan_mux.h"

#define CHECK(name, expr)                                                   \
    do {                                                                    \
        if (!(expr)) {                                                       \
            fprintf(stderr, "FAIL: %s\n", name);                          \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int
check_bytes(const char *name, const uint8_t *got, const uint8_t *want,
    size_t len)
{
    if (memcmp(got, want, len) != 0) {
        fprintf(stderr, "FAIL: %s\n", name);
        return 1;
    }

    return 0;
}

int
main(void)
{
    size_t                       needed;
    uint32_t                     consumed, window;
    uint8_t                      buf[NGX_STREAM_TROJAN_MUX_HEADER_LEN];
    uint8_t                      update[NGX_STREAM_TROJAN_MUX_UPD_LEN];
    ngx_stream_trojan_addr_t     addr;
    ngx_stream_trojan_mux_frame_t frame;

    const uint8_t v1_psh[] = { 0x01, 0x02, 0x04, 0x00,
                               0x01, 0x00, 0x00, 0x00 };
    const uint8_t v2_upd[] = { 0x02, 0x04, 0x08, 0x00,
                               0x01, 0x00, 0x00, 0x00 };
    const uint8_t update_payload[] = { 0x09, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x01, 0x00 };
    const uint8_t v1_upd[] = { 0x01, 0x04, 0x08, 0x00,
                               0x01, 0x00, 0x00, 0x00 };
    const uint8_t bad_syn[] = { 0x01, 0x00, 0x01, 0x00,
                                0x01, 0x00, 0x00, 0x00 };
    const uint8_t sing_ipv4[] = { 0x00, 0x00, NGX_STREAM_TROJAN_ADDR_IPV4,
                                  127, 0, 0, 1, 0x46, 0xa0 };
    const uint8_t sing_domain[] = { 0x00, 0x00,
                                    NGX_STREAM_TROJAN_ADDR_DOMAIN, 11,
                                    'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                    '.', 'c', 'o', 'm', 0x01, 0xbb };
    const uint8_t sing_udp[] = { 0x00, 0x01, NGX_STREAM_TROJAN_ADDR_IPV4,
                                 127, 0, 0, 1, 0x46, 0xa0 };

    CHECK("v1 PSH pack",
          ngx_stream_trojan_mux_pack_header(buf, sizeof(buf),
              NGX_STREAM_TROJAN_MUX_VERSION1,
              NGX_STREAM_TROJAN_MUX_CMD_PSH, 4, 1)
          == NGX_STREAM_TROJAN_MUX_OK);
    if (check_bytes("v1 PSH bytes", buf, v1_psh, sizeof(v1_psh)) != 0) {
        return 1;
    }

    CHECK("v2 UPD parse",
          ngx_stream_trojan_mux_parse_header(v2_upd, sizeof(v2_upd), &frame)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("v2 UPD version", frame.version == NGX_STREAM_TROJAN_MUX_VERSION2);
    CHECK("v2 UPD command", frame.command == NGX_STREAM_TROJAN_MUX_CMD_UPD);
    CHECK("v2 UPD length", frame.length == NGX_STREAM_TROJAN_MUX_UPD_LEN);
    CHECK("v2 UPD stream", frame.stream_id == 1);

    CHECK("UPD payload pack",
          ngx_stream_trojan_mux_pack_update(update, sizeof(update), 9, 65536)
          == NGX_STREAM_TROJAN_MUX_OK);
    if (check_bytes("UPD payload bytes", update, update_payload,
                    sizeof(update_payload))
        != 0)
    {
        return 1;
    }
    CHECK("UPD payload parse",
          ngx_stream_trojan_mux_parse_update(update, sizeof(update),
              &consumed, &window)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("UPD consumed", consumed == 9);
    CHECK("UPD window", window == 65536);

    CHECK("v1 UPD rejected",
          ngx_stream_trojan_mux_parse_header(v1_upd, sizeof(v1_upd), &frame)
          == NGX_STREAM_TROJAN_MUX_ERROR);
    CHECK("SYN length rejected",
          ngx_stream_trojan_mux_parse_header(bad_syn, sizeof(bad_syn), &frame)
          == NGX_STREAM_TROJAN_MUX_ERROR);
    CHECK("oversized payload rejected",
          ngx_stream_trojan_mux_pack_header(buf, sizeof(buf),
              NGX_STREAM_TROJAN_MUX_VERSION2,
              NGX_STREAM_TROJAN_MUX_CMD_PSH, 32769, 1)
          == NGX_STREAM_TROJAN_MUX_ERROR);

    CHECK("sing IPv4 needed",
          ngx_stream_trojan_mux_sing_request_needed(sing_ipv4,
              sizeof(sing_ipv4), &needed)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("sing IPv4 needed length", needed == sizeof(sing_ipv4));
    CHECK("sing IPv4 parse",
          ngx_stream_trojan_mux_sing_parse_request(sing_ipv4,
              sizeof(sing_ipv4), &addr)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("sing IPv4 type", addr.type == NGX_STREAM_TROJAN_ADDR_IPV4);
    CHECK("sing IPv4 host", addr.host_len == 4
          && memcmp(addr.host, sing_ipv4 + 3, 4) == 0);
    CHECK("sing IPv4 port", addr.port == 18080);

    CHECK("sing domain needed",
          ngx_stream_trojan_mux_sing_request_needed(sing_domain,
              sizeof(sing_domain), &needed)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("sing domain needed length", needed == sizeof(sing_domain));
    CHECK("sing domain parse",
          ngx_stream_trojan_mux_sing_parse_request(sing_domain,
              sizeof(sing_domain), &addr)
          == NGX_STREAM_TROJAN_MUX_OK);
    CHECK("sing domain type", addr.type == NGX_STREAM_TROJAN_ADDR_DOMAIN);
    CHECK("sing domain host", addr.host_len == 11
          && memcmp(addr.host, sing_domain + 4, 11) == 0);
    CHECK("sing domain port", addr.port == 443);

    CHECK("sing UDP rejected",
          ngx_stream_trojan_mux_sing_request_needed(sing_udp,
              sizeof(sing_udp), &needed)
          == NGX_STREAM_TROJAN_MUX_ERROR);

    return 0;
}
