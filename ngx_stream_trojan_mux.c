#include "ngx_stream_trojan_mux.h"
#include <string.h>


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

static uint16_t
ngx_stream_trojan_mux_get16be(const uint8_t *p)
{
    return (uint16_t) ((p[0] << 8) | p[1]);
}


static void
ngx_stream_trojan_mux_put16be(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8);
    p[1] = (uint8_t) value;
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


int
ngx_stream_trojan_mux_sing_request_needed(const uint8_t *buf, size_t len,
    size_t *needed)
{
    size_t   addr_len;
    uint16_t flags;

    if (buf == NULL || needed == NULL) {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    if (len < 3) {
        *needed = 3;
        return NGX_STREAM_TROJAN_MUX_AGAIN;
    }

    flags = ngx_stream_trojan_mux_get16be(buf);
    if (flags & NGX_STREAM_TROJAN_MUX_SING_FLAG_UDP) {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    switch (buf[2]) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        addr_len = 1 + 4 + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 4) {
            *needed = 4;
            return NGX_STREAM_TROJAN_MUX_AGAIN;
        }
        if (buf[3] == 0) {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }
        addr_len = 1 + 1 + buf[3] + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        addr_len = 1 + 16 + 2;
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    *needed = 2 + addr_len;
    if (len < *needed) {
        return NGX_STREAM_TROJAN_MUX_AGAIN;
    }

    return NGX_STREAM_TROJAN_MUX_OK;
}


int
ngx_stream_trojan_mux_sing_parse_request(const uint8_t *buf, size_t len,
    ngx_stream_trojan_addr_t *addr)
{
    size_t  needed;

    if (addr == NULL
        || ngx_stream_trojan_mux_sing_request_needed(buf, len, &needed)
           != NGX_STREAM_TROJAN_MUX_OK
        || needed != len)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    return ngx_stream_trojan_parse_addr(buf + 2, len - 2, addr) == 0
           ? NGX_STREAM_TROJAN_MUX_OK : NGX_STREAM_TROJAN_MUX_ERROR;
}


int
ngx_stream_trojan_mux_cool_parse_metadata(const uint8_t *buf, size_t len,
    ngx_stream_trojan_mux_cool_frame_t *frame)
{
    size_t   pos, host_len;
    uint8_t  atyp;

    if (buf == NULL || frame == NULL || len < 4
        || len > NGX_STREAM_TROJAN_MUX_COOL_MAX_META_LEN)
    {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }


    frame->session_id = ngx_stream_trojan_mux_get16be(buf);
    frame->status = buf[2];
    frame->option = buf[3];
    pos = 4;

    switch (frame->status) {
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_NEW:
        memset(&frame->target, 0, sizeof(frame->target));
        if (len < pos + 4) {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }

        frame->network = buf[pos++];
        frame->target.port = ngx_stream_trojan_mux_get16be(buf + pos);
        pos += 2;
        atyp = buf[pos++];

        switch (atyp) {
        case NGX_STREAM_TROJAN_MUX_COOL_ADDR_IPV4:
            if (len < pos + 4) {
                return NGX_STREAM_TROJAN_MUX_ERROR;
            }
            frame->target.type = NGX_STREAM_TROJAN_ADDR_IPV4;
            memcpy(frame->target.host, buf + pos, 4);
            frame->target.host_len = 4;
            frame->target.wire_len = 1 + 4 + 2;
            pos += 4;
            break;

        case NGX_STREAM_TROJAN_MUX_COOL_ADDR_DOMAIN:
            if (len < pos + 1) {
                return NGX_STREAM_TROJAN_MUX_ERROR;
            }
            host_len = buf[pos++];
            if (host_len == 0 || len < pos + host_len) {
                return NGX_STREAM_TROJAN_MUX_ERROR;
            }
            frame->target.type = NGX_STREAM_TROJAN_ADDR_DOMAIN;
            memcpy(frame->target.host, buf + pos, host_len);
            frame->target.host_len = host_len;
            frame->target.wire_len = 1 + 1 + host_len + 2;
            pos += host_len;
            break;

        case NGX_STREAM_TROJAN_MUX_COOL_ADDR_IPV6:
            if (len < pos + 16) {
                return NGX_STREAM_TROJAN_MUX_ERROR;
            }
            frame->target.type = NGX_STREAM_TROJAN_ADDR_IPV6;
            memcpy(frame->target.host, buf + pos, 16);
            frame->target.host_len = 16;
            frame->target.wire_len = 1 + 16 + 2;
            pos += 16;
            break;

        default:
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }

        if (frame->network != NGX_STREAM_TROJAN_MUX_COOL_NETWORK_TCP
            && frame->network != NGX_STREAM_TROJAN_MUX_COOL_NETWORK_UDP)
        {
            return NGX_STREAM_TROJAN_MUX_ERROR;
        }
        break;

    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP:
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_END:
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEPALIVE:
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    return NGX_STREAM_TROJAN_MUX_OK;
}


int
ngx_stream_trojan_mux_cool_pack_header(uint8_t *buf, size_t len,
    uint16_t session_id, uint8_t status, uint8_t option,
    uint16_t payload_len, size_t *written)
{
    size_t  n;

    if (buf == NULL || written == NULL || len < 6) {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    if ((option & NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA) && len < 8) {
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    switch (status) {
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP:
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_END:
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEPALIVE:
        break;

    default:
        return NGX_STREAM_TROJAN_MUX_ERROR;
    }

    ngx_stream_trojan_mux_put16be(buf, 4);
    ngx_stream_trojan_mux_put16be(buf + 2, session_id);
    buf[4] = status;
    buf[5] = option;
    n = 6;

    if (option & NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA) {
        ngx_stream_trojan_mux_put16be(buf + 6, payload_len);
        n = 8;
    }

    *written = n;
    return NGX_STREAM_TROJAN_MUX_OK;
}
