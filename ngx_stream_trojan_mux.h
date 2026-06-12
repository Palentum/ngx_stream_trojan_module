#ifndef _NGX_STREAM_TROJAN_MUX_H_INCLUDED_
#define _NGX_STREAM_TROJAN_MUX_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "ngx_stream_trojan_protocol.h"

#define NGX_STREAM_TROJAN_CMD_MUX 0x7f

#define NGX_STREAM_TROJAN_MUX_VERSION1 1
#define NGX_STREAM_TROJAN_MUX_VERSION2 2
#define NGX_STREAM_TROJAN_MUX_DEFAULT_VERSION NGX_STREAM_TROJAN_MUX_VERSION1
#define NGX_STREAM_TROJAN_MUX_HEADER_LEN 8
#define NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE 32768
#define NGX_STREAM_TROJAN_MUX_MAX_STREAM_BUFFER 65536
#define NGX_STREAM_TROJAN_MUX_MAX_RECEIVE_BUFFER 4194304
#define NGX_STREAM_TROJAN_MUX_INITIAL_PEER_WINDOW 262144
#define NGX_STREAM_TROJAN_MUX_WINDOW_UPDATE_THRESHOLD (NGX_STREAM_TROJAN_MUX_MAX_STREAM_BUFFER / 2)
#define NGX_STREAM_TROJAN_MUX_UPD_LEN 8
#define NGX_STREAM_TROJAN_MUX_MAX_STREAMS 64

#define NGX_STREAM_TROJAN_MUX_COOL_HOST "v1.mux.cool"
#define NGX_STREAM_TROJAN_MUX_COOL_HOST_LEN 11
#define NGX_STREAM_TROJAN_MUX_COOL_MAX_META_LEN 512

#define NGX_STREAM_TROJAN_MUX_SING_HOST "sp.mux.sing-box.arpa"
#define NGX_STREAM_TROJAN_MUX_SING_HOST_LEN 20
#define NGX_STREAM_TROJAN_MUX_SING_PORT 444
#define NGX_STREAM_TROJAN_MUX_SING_VERSION0 0
#define NGX_STREAM_TROJAN_MUX_SING_VERSION1 1
#define NGX_STREAM_TROJAN_MUX_SING_PROTOCOL_SMUX 0

#define NGX_STREAM_TROJAN_MUX_SING_STATUS_SUCCESS 0
#define NGX_STREAM_TROJAN_MUX_SING_FLAG_UDP 0x0001
#define NGX_STREAM_TROJAN_MUX_SING_FLAG_ADDR 0x0002

#define NGX_STREAM_TROJAN_MUX_COOL_STATUS_NEW 0x01
#define NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP 0x02
#define NGX_STREAM_TROJAN_MUX_COOL_STATUS_END 0x03
#define NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEPALIVE 0x04

#define NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA 0x01
#define NGX_STREAM_TROJAN_MUX_COOL_OPT_ERROR 0x02

#define NGX_STREAM_TROJAN_MUX_COOL_NETWORK_TCP 0x01
#define NGX_STREAM_TROJAN_MUX_COOL_NETWORK_UDP 0x02

#define NGX_STREAM_TROJAN_MUX_COOL_ADDR_IPV4 0x01
#define NGX_STREAM_TROJAN_MUX_COOL_ADDR_DOMAIN 0x02
#define NGX_STREAM_TROJAN_MUX_COOL_ADDR_IPV6 0x03

#define NGX_STREAM_TROJAN_MUX_CMD_SYN 0x00
#define NGX_STREAM_TROJAN_MUX_CMD_FIN 0x01
#define NGX_STREAM_TROJAN_MUX_CMD_PSH 0x02
#define NGX_STREAM_TROJAN_MUX_CMD_NOP 0x03
#define NGX_STREAM_TROJAN_MUX_CMD_UPD 0x04

#define NGX_STREAM_TROJAN_MUX_OK 0
#define NGX_STREAM_TROJAN_MUX_AGAIN 1
#define NGX_STREAM_TROJAN_MUX_ERROR -1

typedef struct {
    uint8_t  version;
    uint8_t  command;
    uint16_t length;
    uint32_t stream_id;
} ngx_stream_trojan_mux_frame_t;

typedef struct {
    uint16_t                  session_id;
    uint8_t                   status;
    uint8_t                   option;
    uint8_t                   network;
    ngx_stream_trojan_addr_t  target;
} ngx_stream_trojan_mux_cool_frame_t;

int ngx_stream_trojan_mux_parse_header(const uint8_t *buf, size_t len,
    ngx_stream_trojan_mux_frame_t *frame);
int ngx_stream_trojan_mux_pack_header(uint8_t *buf, size_t len,
    uint8_t version, uint8_t command, uint16_t payload_len,
    uint32_t stream_id);
int ngx_stream_trojan_mux_parse_update(const uint8_t *buf, size_t len,
    uint32_t *consumed, uint32_t *window);
int ngx_stream_trojan_mux_pack_update(uint8_t *buf, size_t len,
    uint32_t consumed, uint32_t window);
int ngx_stream_trojan_mux_request_needed(const uint8_t *buf, size_t len,
    size_t *needed);
int ngx_stream_trojan_mux_sing_request_needed(const uint8_t *buf, size_t len,
    size_t *needed);
int ngx_stream_trojan_mux_sing_parse_request(const uint8_t *buf, size_t len,
    ngx_stream_trojan_addr_t *addr);
int ngx_stream_trojan_mux_cool_parse_metadata(const uint8_t *buf, size_t len,
    ngx_stream_trojan_mux_cool_frame_t *frame);
int ngx_stream_trojan_mux_cool_pack_header(uint8_t *buf, size_t len,
    uint16_t session_id, uint8_t status, uint8_t option,
    uint16_t payload_len, size_t *written);

#endif /* _NGX_STREAM_TROJAN_MUX_H_INCLUDED_ */
