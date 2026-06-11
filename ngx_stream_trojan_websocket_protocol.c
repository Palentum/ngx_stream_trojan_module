#include "ngx_stream_trojan_websocket_protocol.h"

#include <string.h>

#define NGX_STREAM_TROJAN_WS_SHA1_DIGEST_LEN 20
#define NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN 64
#define NGX_STREAM_TROJAN_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct {
    uint32_t state[5];
    uint64_t len;
    uint8_t  buffer[NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN];
    size_t   buffer_len;
} ngx_stream_trojan_ws_sha1_ctx_t;


static uint32_t
ngx_stream_trojan_ws_rotl32(uint32_t v, unsigned n)
{
    return (v << n) | (v >> (32 - n));
}


static uint32_t
ngx_stream_trojan_ws_load_be32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}


static void
ngx_stream_trojan_ws_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}


static void
ngx_stream_trojan_ws_store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t) (v >> 56);
    p[1] = (uint8_t) (v >> 48);
    p[2] = (uint8_t) (v >> 40);
    p[3] = (uint8_t) (v >> 32);
    p[4] = (uint8_t) (v >> 24);
    p[5] = (uint8_t) (v >> 16);
    p[6] = (uint8_t) (v >> 8);
    p[7] = (uint8_t) v;
}


static void
ngx_stream_trojan_ws_sha1_init(ngx_stream_trojan_ws_sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xc3d2e1f0U;
    ctx->len = 0;
    ctx->buffer_len = 0;
}


static void
ngx_stream_trojan_ws_sha1_transform(ngx_stream_trojan_ws_sha1_ctx_t *ctx,
    const uint8_t block[NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN])
{
    uint32_t  w[80], a, b, c, d, e, f, k, t;
    size_t    i;

    for (i = 0; i < 16; i++) {
        w[i] = ngx_stream_trojan_ws_load_be32(block + i * 4);
    }

    for (i = 16; i < 80; i++) {
        w[i] = ngx_stream_trojan_ws_rotl32(w[i - 3] ^ w[i - 8]
                                           ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcU;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6U;
        }

        t = ngx_stream_trojan_ws_rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ngx_stream_trojan_ws_rotl32(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}


static void
ngx_stream_trojan_ws_sha1_update(ngx_stream_trojan_ws_sha1_ctx_t *ctx,
    const uint8_t *data, size_t len)
{
    size_t n;

    ctx->len += (uint64_t) len * 8;

    while (len != 0) {
        n = NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN - ctx->buffer_len;
        if (n > len) {
            n = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, n);
        ctx->buffer_len += n;
        data += n;
        len -= n;

        if (ctx->buffer_len == NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN) {
            ngx_stream_trojan_ws_sha1_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}


static void
ngx_stream_trojan_ws_sha1_final(ngx_stream_trojan_ws_sha1_ctx_t *ctx,
    uint8_t out[NGX_STREAM_TROJAN_WS_SHA1_DIGEST_LEN])
{
    size_t   i;
    uint64_t bit_len;

    bit_len = ctx->len;

    ctx->buffer[ctx->buffer_len++] = 0x80;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < NGX_STREAM_TROJAN_WS_SHA1_BLOCK_LEN) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        ngx_stream_trojan_ws_sha1_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }

    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }

    ngx_stream_trojan_ws_store_be64(ctx->buffer + 56, bit_len);
    ngx_stream_trojan_ws_sha1_transform(ctx, ctx->buffer);

    for (i = 0; i < 5; i++) {
        ngx_stream_trojan_ws_store_be32(out + i * 4, ctx->state[i]);
    }
}


static void
ngx_stream_trojan_ws_sha1(const uint8_t *data, size_t len,
    const uint8_t *suffix, size_t suffix_len,
    uint8_t out[NGX_STREAM_TROJAN_WS_SHA1_DIGEST_LEN])
{
    ngx_stream_trojan_ws_sha1_ctx_t  ctx;

    ngx_stream_trojan_ws_sha1_init(&ctx);
    ngx_stream_trojan_ws_sha1_update(&ctx, data, len);
    ngx_stream_trojan_ws_sha1_update(&ctx, suffix, suffix_len);
    ngx_stream_trojan_ws_sha1_final(&ctx, out);
}


static int
ngx_stream_trojan_ws_ascii_lower(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }

    return c;
}


static int
ngx_stream_trojan_ws_ascii_casecmp(const uint8_t *a, size_t a_len,
    const char *b, size_t b_len)
{
    size_t i;

    if (a_len != b_len) {
        return -1;
    }

    for (i = 0; i < a_len; i++) {
        if (ngx_stream_trojan_ws_ascii_lower(a[i])
            != ngx_stream_trojan_ws_ascii_lower((uint8_t) b[i]))
        {
            return -1;
        }
    }

    return 0;
}


static const uint8_t *
ngx_stream_trojan_ws_find_header_end(const uint8_t *buf, size_t len)
{
    size_t i;

    if (len < 4) {
        return NULL;
    }

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n'
            && buf[i + 2] == '\r' && buf[i + 3] == '\n')
        {
            return buf + i + 4;
        }
    }

    return NULL;
}


static const uint8_t *
ngx_stream_trojan_ws_find_space(const uint8_t *p, const uint8_t *last)
{
    while (p < last) {
        if (*p == ' ') {
            return p;
        }

        p++;
    }

    return NULL;
}


static void
ngx_stream_trojan_ws_trim(const uint8_t **p, const uint8_t **last)
{
    while (*p < *last && ((*p)[0] == ' ' || (*p)[0] == '\t')) {
        (*p)++;
    }

    while (*last > *p && ((*last)[-1] == ' ' || (*last)[-1] == '\t')) {
        (*last)--;
    }
}


static int
ngx_stream_trojan_ws_connection_has_upgrade(const uint8_t *p,
    const uint8_t *last)
{
    const uint8_t *token, *token_last;

    while (p < last) {
        while (p < last && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }

        token = p;
        while (p < last && *p != ',') {
            p++;
        }
        token_last = p;
        ngx_stream_trojan_ws_trim(&token, &token_last);

        if (ngx_stream_trojan_ws_ascii_casecmp(token,
                                               (size_t) (token_last - token),
                                               "upgrade",
                                               sizeof("upgrade") - 1) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static int
ngx_stream_trojan_ws_base64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }

    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }

    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }

    if (c == '+') {
        return 62;
    }

    if (c == '/') {
        return 63;
    }

    return -1;
}


static int
ngx_stream_trojan_ws_base64_decode_len(const uint8_t *src, size_t len,
    size_t *decoded)
{
    uint32_t block;
    size_t   i, n;
    int      v[4];

    if (decoded == NULL || len == 0 || (len & 3) != 0) {
        return -1;
    }

    *decoded = 0;

    for (i = 0; i < len; i += 4) {
        for (n = 0; n < 4; n++) {
            if (src[i + n] == '=') {
                v[n] = -2;
            } else {
                v[n] = ngx_stream_trojan_ws_base64_value(src[i + n]);
                if (v[n] < 0) {
                    return -1;
                }
            }
        }

        if (v[0] < 0 || v[1] < 0) {
            return -1;
        }

        if (v[2] == -2 && v[3] != -2) {
            return -1;
        }

        if ((v[2] == -2 || v[3] == -2) && i + 4 != len) {
            return -1;
        }

        block = ((uint32_t) v[0] << 18) | ((uint32_t) v[1] << 12);
        if (v[2] >= 0) {
            block |= (uint32_t) v[2] << 6;
        }
        if (v[3] >= 0) {
            block |= (uint32_t) v[3];
        }
        (void) block;

        if (v[2] == -2) {
            *decoded += 1;
        } else if (v[3] == -2) {
            *decoded += 2;
        } else {
            *decoded += 3;
        }
    }

    return 0;
}


static size_t
ngx_stream_trojan_ws_base64_encode(const uint8_t *src, size_t len,
    uint8_t *out)
{
    static const uint8_t table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t   i, n;
    uint32_t v;

    n = 0;
    for (i = 0; i + 2 < len; i += 3) {
        v = ((uint32_t) src[i] << 16) | ((uint32_t) src[i + 1] << 8)
            | src[i + 2];
        out[n++] = table[(v >> 18) & 0x3f];
        out[n++] = table[(v >> 12) & 0x3f];
        out[n++] = table[(v >> 6) & 0x3f];
        out[n++] = table[v & 0x3f];
    }

    if (i < len) {
        v = (uint32_t) src[i] << 16;
        if (i + 1 < len) {
            v |= (uint32_t) src[i + 1] << 8;
        }

        out[n++] = table[(v >> 18) & 0x3f];
        out[n++] = table[(v >> 12) & 0x3f];
        if (i + 1 < len) {
            out[n++] = table[(v >> 6) & 0x3f];
            out[n++] = '=';
        } else {
            out[n++] = '=';
            out[n++] = '=';
        }
    }

    return n;
}


int
ngx_stream_trojan_ws_parse_handshake(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_trojan_ws_handshake_t *hs)
{
    const uint8_t *header_end, *line, *line_end, *target, *target_end;
    const uint8_t *version, *name, *name_end, *value, *value_end;
    size_t         decoded_len;
    int            has_upgrade, has_connection, has_key, has_version, has_host;
    int            version_bad;

    if (buf == NULL || needed == NULL || hs == NULL) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    header_end = ngx_stream_trojan_ws_find_header_end(buf, len);
    if (header_end == NULL) {
        *needed = len + 1;
        return NGX_STREAM_TROJAN_WS_NEED_MORE;
    }

    memset(hs, 0, sizeof(*hs));
    *needed = (size_t) (header_end - buf);

    line_end = buf;
    while (line_end + 1 < header_end) {
        if (line_end[0] == '\r' && line_end[1] == '\n') {
            break;
        }
        line_end++;
    }

    if (line_end + 1 >= header_end
        || (size_t) (line_end - buf) < sizeof("GET / HTTP/1.1") - 1)
    {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    if (memcmp(buf, "GET ", sizeof("GET ") - 1) != 0) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    target = buf + sizeof("GET ") - 1;
    target_end = ngx_stream_trojan_ws_find_space(target, line_end);
    if (target_end == NULL || target_end == target) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    version = target_end + 1;
    if ((size_t) (line_end - version) != sizeof("HTTP/1.1") - 1
        || memcmp(version, "HTTP/1.1", sizeof("HTTP/1.1") - 1) != 0)
    {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    hs->path = target;
    hs->path_len = (size_t) (target_end - target);
    hs->header_len = *needed;

    has_upgrade = 0;
    has_connection = 0;
    has_key = 0;
    has_version = 0;
    has_host = 0;
    version_bad = 0;

    line = line_end + 2;
    while (line + 1 < header_end && !(line[0] == '\r' && line[1] == '\n')) {
        line_end = line;
        while (line_end + 1 < header_end) {
            if (line_end[0] == '\r' && line_end[1] == '\n') {
                break;
            }
            line_end++;
        }

        if (line_end + 1 >= header_end) {
            return NGX_STREAM_TROJAN_WS_ERROR;
        }

        name = line;
        name_end = line;
        while (name_end < line_end && *name_end != ':') {
            name_end++;
        }

        if (name_end == line_end || name_end == name) {
            return NGX_STREAM_TROJAN_WS_ERROR;
        }

        value = name_end + 1;
        value_end = line_end;
        ngx_stream_trojan_ws_trim(&value, &value_end);

        if (ngx_stream_trojan_ws_ascii_casecmp(name,
                                               (size_t) (name_end - name),
                                               "upgrade",
                                               sizeof("upgrade") - 1) == 0)
        {
            if (ngx_stream_trojan_ws_ascii_casecmp(value,
                    (size_t) (value_end - value), "websocket",
                    sizeof("websocket") - 1) == 0)
            {
                has_upgrade = 1;
            }

        } else if (ngx_stream_trojan_ws_ascii_casecmp(name,
                   (size_t) (name_end - name), "connection",
                   sizeof("connection") - 1) == 0)
        {
            if (ngx_stream_trojan_ws_connection_has_upgrade(value,
                                                            value_end))
            {
                has_connection = 1;
            }

        } else if (ngx_stream_trojan_ws_ascii_casecmp(name,
                   (size_t) (name_end - name), "sec-websocket-version",
                   sizeof("sec-websocket-version") - 1) == 0)
        {
            has_version = 1;
            if ((size_t) (value_end - value) != 2
                || value[0] != '1' || value[1] != '3')
            {
                version_bad = 1;
            }

        } else if (ngx_stream_trojan_ws_ascii_casecmp(name,
                   (size_t) (name_end - name), "sec-websocket-key",
                   sizeof("sec-websocket-key") - 1) == 0)
        {
            if (ngx_stream_trojan_ws_base64_decode_len(value,
                    (size_t) (value_end - value), &decoded_len) != 0
                || decoded_len != 16)
            {
                return NGX_STREAM_TROJAN_WS_ERROR;
            }

            hs->key = value;
            hs->key_len = (size_t) (value_end - value);
            has_key = 1;

        } else if (ngx_stream_trojan_ws_ascii_casecmp(name,
                   (size_t) (name_end - name), "host",
                   sizeof("host") - 1) == 0)
        {
            hs->host = value;
            has_host = 1;
            hs->host_len = (size_t) (value_end - value);
        }

        line = line_end + 2;
    }

    if (!has_version || version_bad) {
        return NGX_STREAM_TROJAN_WS_BAD_VERSION;
    }

    if (!has_upgrade || !has_connection || !has_key || !has_host) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    return NGX_STREAM_TROJAN_WS_OK;
}


int
ngx_stream_trojan_ws_build_accept(const uint8_t *key, size_t key_len,
    uint8_t out[NGX_STREAM_TROJAN_WS_ACCEPT_LEN])
{
    uint8_t digest[NGX_STREAM_TROJAN_WS_SHA1_DIGEST_LEN];

    if (key == NULL || out == NULL) {
        return -1;
    }

    ngx_stream_trojan_ws_sha1(key, key_len,
                              (const uint8_t *) NGX_STREAM_TROJAN_WS_GUID,
                              sizeof(NGX_STREAM_TROJAN_WS_GUID) - 1,
                              digest);

    if (ngx_stream_trojan_ws_base64_encode(digest, sizeof(digest), out)
        != NGX_STREAM_TROJAN_WS_ACCEPT_LEN)
    {
        return -1;
    }

    return 0;
}


int
ngx_stream_trojan_ws_build_accept_response(const uint8_t *key,
    size_t key_len, uint8_t *out, size_t out_len, size_t *written)
{
    static const uint8_t prefix[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: ";
    static const uint8_t suffix[] = "\r\n\r\n";
    uint8_t accept[NGX_STREAM_TROJAN_WS_ACCEPT_LEN];
    size_t  len;

    if (out == NULL || written == NULL) {
        return -1;
    }

    len = sizeof(prefix) - 1 + NGX_STREAM_TROJAN_WS_ACCEPT_LEN
          + sizeof(suffix) - 1;
    if (out_len < len) {
        return -1;
    }

    if (ngx_stream_trojan_ws_build_accept(key, key_len, accept) != 0) {
        return -1;
    }

    memcpy(out, prefix, sizeof(prefix) - 1);
    memcpy(out + sizeof(prefix) - 1, accept, sizeof(accept));
    memcpy(out + sizeof(prefix) - 1 + sizeof(accept), suffix,
           sizeof(suffix) - 1);
    *written = len;

    return 0;
}


int
ngx_stream_trojan_ws_build_error_response(uint16_t status,
    uint8_t *out, size_t out_len, size_t *written)
{
    const char *response;
    size_t      len;

    if (out == NULL || written == NULL) {
        return -1;
    }

    switch (status) {
    case 403:
        response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        len = sizeof("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n") - 1;
        break;
    case 404:
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        len = sizeof("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n") - 1;
        break;
    case 426:
        response = "HTTP/1.1 426 Upgrade Required\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "Content-Length: 0\r\n\r\n";
        len = sizeof("HTTP/1.1 426 Upgrade Required\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Content-Length: 0\r\n\r\n") - 1;
        break;
    default:
        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        len = sizeof("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") - 1;
        break;
    }

    if (out_len < len) {
        return -1;
    }

    memcpy(out, response, len);
    *written = len;

    return 0;
}


int
ngx_stream_trojan_ws_parse_frame_header(const uint8_t *buf, size_t len,
    size_t *needed, ngx_stream_trojan_ws_frame_t *frame)
{
    uint8_t  opcode, len_code;
    uint64_t payload_len;
    size_t   header_len, pos;
    int      control;

    if (buf == NULL || needed == NULL || frame == NULL) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    if (len < 2) {
        *needed = 2;
        return NGX_STREAM_TROJAN_WS_NEED_MORE;
    }

    if ((buf[0] & 0x70) != 0) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    opcode = buf[0] & 0x0f;
    control = (opcode & 0x08) != 0;

    switch (opcode) {
    case NGX_STREAM_TROJAN_WS_OPCODE_CONT:
    case NGX_STREAM_TROJAN_WS_OPCODE_TEXT:
    case NGX_STREAM_TROJAN_WS_OPCODE_BINARY:
    case NGX_STREAM_TROJAN_WS_OPCODE_CLOSE:
    case NGX_STREAM_TROJAN_WS_OPCODE_PING:
    case NGX_STREAM_TROJAN_WS_OPCODE_PONG:
        break;
    default:
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    if (control && (buf[0] & 0x80) == 0) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    len_code = buf[1] & 0x7f;
    pos = 2;

    if (len_code < 126) {
        payload_len = len_code;
    } else if (len_code == 126) {
        if (len < pos + 2) {
            *needed = pos + 2;
            return NGX_STREAM_TROJAN_WS_NEED_MORE;
        }
        payload_len = ((uint64_t) buf[pos] << 8) | buf[pos + 1];
        if (payload_len < 126) {
            return NGX_STREAM_TROJAN_WS_ERROR;
        }
        pos += 2;
    } else {
        if (len < pos + 8) {
            *needed = pos + 8;
            return NGX_STREAM_TROJAN_WS_NEED_MORE;
        }
        if ((buf[pos] & 0x80) != 0) {
            return NGX_STREAM_TROJAN_WS_ERROR;
        }
        payload_len = ((uint64_t) buf[pos] << 56)
                      | ((uint64_t) buf[pos + 1] << 48)
                      | ((uint64_t) buf[pos + 2] << 40)
                      | ((uint64_t) buf[pos + 3] << 32)
                      | ((uint64_t) buf[pos + 4] << 24)
                      | ((uint64_t) buf[pos + 5] << 16)
                      | ((uint64_t) buf[pos + 6] << 8)
                      | (uint64_t) buf[pos + 7];
        if (payload_len < 65536) {
            return NGX_STREAM_TROJAN_WS_ERROR;
        }
        pos += 8;
    }

    if (control && payload_len > NGX_STREAM_TROJAN_WS_MAX_CONTROL_PAYLOAD) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    if (opcode == NGX_STREAM_TROJAN_WS_OPCODE_CLOSE && payload_len == 1) {
        return NGX_STREAM_TROJAN_WS_ERROR;
    }

    if ((buf[1] & 0x80) != 0) {
        if (len < pos + 4) {
            *needed = pos + 4;
            return NGX_STREAM_TROJAN_WS_NEED_MORE;
        }
        header_len = pos + 4;
    } else {
        header_len = pos;
    }

    memset(frame, 0, sizeof(*frame));
    frame->fin = (buf[0] & 0x80) != 0;
    frame->opcode = opcode;
    frame->masked = (buf[1] & 0x80) != 0;
    frame->payload_len = payload_len;
    frame->header_len = header_len;
    if (frame->masked) {
        memcpy(frame->mask, buf + pos, sizeof(frame->mask));
    }

    *needed = header_len;

    return NGX_STREAM_TROJAN_WS_OK;
}


int
ngx_stream_trojan_ws_build_frame_header(uint8_t opcode,
    uint64_t payload_len, uint8_t *out, size_t out_len, size_t *written)
{
    if (out == NULL || written == NULL || (payload_len >> 63) != 0) {
        return -1;
    }

    if (payload_len < 126) {
        if (out_len < 2) {
            return -1;
        }
        out[0] = 0x80 | (opcode & 0x0f);
        out[1] = (uint8_t) payload_len;
        *written = 2;
        return 0;
    }

    if (payload_len <= 65535) {
        if (out_len < 4) {
            return -1;
        }
        out[0] = 0x80 | (opcode & 0x0f);
        out[1] = 126;
        out[2] = (uint8_t) (payload_len >> 8);
        out[3] = (uint8_t) payload_len;
        *written = 4;
        return 0;
    }

    if (out_len < 10) {
        return -1;
    }

    out[0] = 0x80 | (opcode & 0x0f);
    out[1] = 127;
    ngx_stream_trojan_ws_store_be64(out + 2, payload_len);
    *written = 10;

    return 0;
}


static uint64_t
ngx_stream_trojan_ws_mask64(const uint8_t mask[4], uint64_t offset)
{
    uint8_t   bytes[8];
    uint64_t  v;
    size_t    i;

    for (i = 0; i < sizeof(bytes); i++) {
        bytes[i] = mask[(offset + i) & 3];
    }

    memcpy(&v, bytes, sizeof(v));

    return v;
}


void
ngx_stream_trojan_ws_apply_mask(uint8_t *data, size_t len,
    const uint8_t mask[4], uint64_t offset)
{
    size_t    i;
    uint64_t  m, v;

    if (data == NULL || mask == NULL) {
        return;
    }

    i = 0;
    while (i < len && ((uintptr_t) (data + i) & (sizeof(uint64_t) - 1))) {
        data[i] ^= mask[(offset + i) & 3];
        i++;
    }

    if (len - i >= sizeof(uint64_t)) {
        m = ngx_stream_trojan_ws_mask64(mask, offset + i);

        while (len - i >= sizeof(uint64_t)) {
            memcpy(&v, data + i, sizeof(v));
            v ^= m;
            memcpy(data + i, &v, sizeof(v));
            i += sizeof(uint64_t);
        }
    }

    while (i < len) {
        data[i] ^= mask[(offset + i) & 3];
        i++;
    }
}
