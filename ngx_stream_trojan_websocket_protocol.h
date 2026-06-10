#ifndef _NGX_STREAM_TROJAN_WEBSOCKET_PROTOCOL_H_INCLUDED_
#define _NGX_STREAM_TROJAN_WEBSOCKET_PROTOCOL_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define NGX_STREAM_TROJAN_WS_OK 0
#define NGX_STREAM_TROJAN_WS_NEED_MORE 1
#define NGX_STREAM_TROJAN_WS_ERROR -1
#define NGX_STREAM_TROJAN_WS_BAD_VERSION -2
#define NGX_STREAM_TROJAN_WS_ACCEPT_LEN 28
#define NGX_STREAM_TROJAN_WS_MAX_HEADER_LEN 14
#define NGX_STREAM_TROJAN_WS_MAX_CONTROL_PAYLOAD 125

#define NGX_STREAM_TROJAN_WS_OPCODE_CONT 0x0
#define NGX_STREAM_TROJAN_WS_OPCODE_TEXT 0x1
#define NGX_STREAM_TROJAN_WS_OPCODE_BINARY 0x2
#define NGX_STREAM_TROJAN_WS_OPCODE_CLOSE 0x8
#define NGX_STREAM_TROJAN_WS_OPCODE_PING 0x9
#define NGX_STREAM_TROJAN_WS_OPCODE_PONG 0xA

typedef struct {
    const uint8_t *path;
    size_t         path_len;
    const uint8_t *host;
    size_t         host_len;
    const uint8_t *key;
    size_t         key_len;
    size_t         header_len;
} ngx_stream_trojan_ws_handshake_t;

typedef struct {
    uint8_t  fin;
    uint8_t  opcode;
    uint8_t  masked;
    uint8_t  mask[4];
    uint64_t payload_len;
    size_t   header_len;
} ngx_stream_trojan_ws_frame_t;

int ngx_stream_trojan_ws_parse_handshake(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_trojan_ws_handshake_t *hs);
int ngx_stream_trojan_ws_build_accept(const uint8_t *key, size_t key_len,
    uint8_t out[NGX_STREAM_TROJAN_WS_ACCEPT_LEN]);
int ngx_stream_trojan_ws_build_accept_response(const uint8_t *key,
    size_t key_len, uint8_t *out, size_t out_len, size_t *written);
int ngx_stream_trojan_ws_build_error_response(uint16_t status,
    uint8_t *out, size_t out_len, size_t *written);
int ngx_stream_trojan_ws_parse_frame_header(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_trojan_ws_frame_t *frame);
int ngx_stream_trojan_ws_build_frame_header(uint8_t opcode,
    uint64_t payload_len, uint8_t *out, size_t out_len, size_t *written);
void ngx_stream_trojan_ws_apply_mask(uint8_t *data, size_t len,
    const uint8_t mask[4], uint64_t offset);

#endif
