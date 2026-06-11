#ifndef NGX_STREAM_TROJAN_RELAY_H
#define NGX_STREAM_TROJAN_RELAY_H

#include <stddef.h>

#define NGX_STREAM_TROJAN_RELAY_MAX_LOOPS 8
#define NGX_STREAM_TROJAN_RELAY_MIN_BYTES (64 * 1024)
#define NGX_STREAM_TROJAN_RELAY_MAX_BYTES (256 * 1024)

static inline int
ngx_stream_trojan_relay_should_continue(size_t loops, size_t bytes,
    size_t limit)
{
    return loops < NGX_STREAM_TROJAN_RELAY_MAX_LOOPS
           && bytes < limit;
}

static inline size_t
ngx_stream_trojan_relay_limit(size_t buffer_size)
{
    size_t limit;

    if (buffer_size > NGX_STREAM_TROJAN_RELAY_MAX_BYTES / 4) {
        return NGX_STREAM_TROJAN_RELAY_MAX_BYTES;
    }

    limit = buffer_size * 4;

    if (limit < NGX_STREAM_TROJAN_RELAY_MIN_BYTES) {
        return NGX_STREAM_TROJAN_RELAY_MIN_BYTES;
    }

    if (limit > NGX_STREAM_TROJAN_RELAY_MAX_BYTES) {
        return NGX_STREAM_TROJAN_RELAY_MAX_BYTES;
    }

    return limit;
}

static inline size_t
ngx_stream_trojan_relay_read_size(size_t available, size_t bytes, size_t limit)
{
    size_t remaining;

    if (bytes >= limit) {
        return 0;
    }

    remaining = limit - bytes;

    return available < remaining ? available : remaining;
}

#endif
