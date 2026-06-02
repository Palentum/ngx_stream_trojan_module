#include "ngx_stream_trojan_mux.h"


static uint16_t
ngx_stream_trojan_mux_get16le(const uint8_t *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}


static uint32_t
ngx_stream_trojan_mux_get32le(const uint8_t *p)
{
    return (uint32_t) p[0]
           | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16)
           | ((uint32_t) p[3] << 24);
}


static void
ngx_stream_trojan_mux_put16le(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) value;
    p[1] = (uint8_t) (value >> 8);
}


static void
ngx_stream_trojan_mux_put32le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t) value;
    p[1] = (uint8_t) (value >> 8);
    p[2] = (uint8_t) (value >> 16);
    p[3] = (uint8_t) (value >> 24);
}


int
ngx_stream_trojan_mux_parse_header(const uint8_t *buf, size_t len,
    ngx_stream_trojan_mux_frame_t *frame)
{
    if (buf == NULL || frame == NULL
        || len < NGX_STREAM_TROJAN_MUX_HEADER_LEN)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    frame->version = buf[0];
    frame->command = buf[1];
    frame->length = ngx_stream_trojan_mux_get16le(buf + 2);
    frame->stream_id = ngx_stream_trojan_mux_get32le(buf + 4);

    if (frame->version != NGX_STREAM_TROJAN_MUX_VERSION
        || frame->length > NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    switch (frame->command) {
    case NGX_STREAM_TROJAN_MUX_CMD_SYN:
    case NGX_STREAM_TROJAN_MUX_CMD_FIN:
    case NGX_STREAM_TROJAN_MUX_CMD_NOP:
        if (frame->length != 0) {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }
        break;

    case NGX_STREAM_TROJAN_MUX_CMD_PSH:
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    return NGX_STREAM_TROJAN_MUX_OK;
}


int
ngx_stream_trojan_mux_pack_header(uint8_t *buf, size_t len,
    uint8_t command, uint16_t payload_len, uint32_t stream_id)
{
    if (buf == NULL || len < NGX_STREAM_TROJAN_MUX_HEADER_LEN
        || payload_len > NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    switch (command) {
    case NGX_STREAM_TROJAN_MUX_CMD_SYN:
    case NGX_STREAM_TROJAN_MUX_CMD_FIN:
    case NGX_STREAM_TROJAN_MUX_CMD_NOP:
        if (payload_len != 0) {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }
        break;

    case NGX_STREAM_TROJAN_MUX_CMD_PSH:
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    buf[0] = NGX_STREAM_TROJAN_MUX_VERSION;
    buf[1] = command;
    ngx_stream_trojan_mux_put16le(buf + 2, payload_len);
    ngx_stream_trojan_mux_put32le(buf + 4, stream_id);

    return NGX_STREAM_TROJAN_MUX_OK;
}


int
ngx_stream_trojan_mux_request_needed(const uint8_t *buf, size_t len,
    size_t *needed)
{
    size_t addr_len;

    if (buf == NULL || needed == NULL) {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    if (len < 2) {
        *needed = 2;
        return NGX_STREAM_TROJAN_MUX_AGAIN;
    }

    if (buf[0] != NGX_STREAM_TROJAN_CMD_CONNECT
        && buf[0] != NGX_STREAM_TROJAN_CMD_ASSOCIATE)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    switch (buf[1]) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        addr_len = 1 + 4 + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 3) {
            *needed = 3;
            return NGX_STREAM_TROJAN_MUX_AGAIN;
        }
        addr_len = 1 + 1 + buf[2] + 2;
        if (buf[2] == 0) {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        addr_len = 1 + 16 + 2;
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    *needed = 1 + addr_len;

    if (len < *needed) {
        return NGX_STREAM_TROJAN_MUX_AGAIN;
    }

    return NGX_STREAM_TROJAN_MUX_OK;
}
