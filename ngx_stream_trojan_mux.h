#ifndef _NGX_STREAM_TROJAN_MUX_H_INCLUDED_
#define _NGX_STREAM_TROJAN_MUX_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "ngx_stream_trojan_protocol.h"

#define NGX_STREAM_TROJAN_CMD_MUX 0x7f

#define NGX_STREAM_TROJAN_MUX_VERSION 1
#define NGX_STREAM_TROJAN_MUX_HEADER_LEN 8
#define NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE 32768
#define NGX_STREAM_TROJAN_MUX_STREAM_BUFFER_SIZE 65536
#define NGX_STREAM_TROJAN_MUX_MAX_STREAMS 128

#define NGX_STREAM_TROJAN_MUX_CMD_SYN 0x00
#define NGX_STREAM_TROJAN_MUX_CMD_FIN 0x01
#define NGX_STREAM_TROJAN_MUX_CMD_PSH 0x02
#define NGX_STREAM_TROJAN_MUX_CMD_NOP 0x03

#define NGX_STREAM_TROJAN_MUX_OK 0
#define NGX_STREAM_TROJAN_MUX_AGAIN 1
#define NGX_STREAM_TROJAN_MUX_ERROR -1

typedef struct {
    uint8_t  version;
    uint8_t  command;
    uint16_t length;
    uint32_t stream_id;
} ngx_stream_trojan_mux_frame_t;

int ngx_stream_trojan_mux_parse_header(const uint8_t *buf, size_t len,
    ngx_stream_trojan_mux_frame_t *frame);
int ngx_stream_trojan_mux_pack_header(uint8_t *buf, size_t len,
    uint8_t command, uint16_t payload_len, uint32_t stream_id);
int ngx_stream_trojan_mux_request_needed(const uint8_t *buf, size_t len,
    size_t *needed);

#endif /* _NGX_STREAM_TROJAN_MUX_H_INCLUDED_ */
