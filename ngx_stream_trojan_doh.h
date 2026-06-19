#ifndef _NGX_STREAM_TROJAN_DOH_H_INCLUDED_
#define _NGX_STREAM_TROJAN_DOH_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


#define NGX_STREAM_TROJAN_DOH_MAX_QUERY_SIZE     512
#define NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE  4096
#define NGX_STREAM_TROJAN_DOH_DEFAULT_TIMEOUT    10000
#define NGX_STREAM_TROJAN_DOH_CACHE_ENTRIES     64
#define NGX_STREAM_TROJAN_DOH_CACHE_ADDRS       8
#define NGX_STREAM_TROJAN_DOH_CACHE_MAX_TTL     600
#define NGX_STREAM_TROJAN_DOH_CACHE_NEGATIVE_TTL 30
#define NGX_STREAM_TROJAN_DOH_MAX_ACTIVE        32
#define NGX_STREAM_TROJAN_DOH_MAX_PENDING       256
#define NGX_STREAM_TROJAN_DOH_MAX_IDLE          NGX_STREAM_TROJAN_DOH_MAX_ACTIVE

typedef struct {
    ngx_uint_t           valid;
    ngx_int_t            status;
    uint16_t             qtype;
    size_t               name_len;
    u_char               name[255];
    ngx_msec_t           expire;
    ngx_uint_t           accessed;
    ngx_uint_t           naddrs;
    ngx_resolver_addr_t  addrs[NGX_STREAM_TROJAN_DOH_CACHE_ADDRS];
    struct sockaddr_storage
                         sockaddr[NGX_STREAM_TROJAN_DOH_CACHE_ADDRS];
} ngx_stream_trojan_doh_cache_entry_t;


/* DoH per-server parsed configuration */
typedef struct {
    ngx_str_t     host;         /* hostname string (for Host header) */
    ngx_str_t     host_header;  /* "host:port" for HTTP Host header */
    ngx_str_t     path;         /* URL path, e.g. "/dns-query" */
    in_port_t     port;
    ngx_uint_t    https;        /* 1 if HTTPS */
    ngx_msec_t    timeout;

    /* pre-resolved server addresses (populated at config time) */
    ngx_addr_t   *addrs;
    ngx_uint_t    naddrs;

    ngx_stream_trojan_doh_cache_entry_t
                  cache[NGX_STREAM_TROJAN_DOH_CACHE_ENTRIES];
    ngx_uint_t    cache_generation;
    ngx_queue_t   pending;
    ngx_queue_t   idle;
    ngx_uint_t    active;
    ngx_uint_t    pending_n;
    ngx_uint_t    idle_n;

#if (NGX_SSL)
    ngx_ssl_t     ssl;          /* SSL client context */
    ngx_str_t     ssl_hostname; /* hostname for SNI + cert verification */
#endif
} ngx_stream_trojan_doh_conf_t;

/*
 * Build a DNS query in wire format (RFC 1035).
 * Returns query length on success, 0 on error.
 */
size_t ngx_stream_trojan_doh_build_query(u_char *buf, size_t buf_len,
    const u_char *name, size_t name_len, uint16_t qtype, uint16_t dns_id);

/*
 * Parse DNS wire-format response, extract A/AAAA records.
 * Allocates resolved addresses from pool.
 * Returns NGX_OK on success, NGX_DECLINED when the response is valid but
 * contains no A/AAAA answer, NGX_ERROR on malformed/error response.
 */
ngx_int_t ngx_stream_trojan_doh_parse_response(u_char *data, size_t len,
    uint16_t expected_id, ngx_resolver_addr_t **addrs_p,
    ngx_uint_t *naddrs_p, ngx_pool_t *pool, uint32_t *ttl_p);

/*
 * Parse a DoH URL string (e.g. "https://dns.google/dns-query").
 * Resolves the hostname at config time using ngx_parse_url.
 * Returns NGX_OK on success, NGX_ERROR on error.
 */
ngx_int_t ngx_stream_trojan_doh_parse_url(ngx_str_t *url,
    ngx_stream_trojan_doh_conf_t *doh_conf, ngx_pool_t *pool, ngx_log_t *log);

/*
 * Callback type for DoH resolution completion.
 */
typedef void (*ngx_stream_trojan_doh_handler_pt)(void *ctx, ngx_int_t status,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs);

typedef struct ngx_stream_trojan_doh_ctx_s ngx_stream_trojan_doh_ctx_t;

/*
 * Initiate an async DoH resolution.
 * doh_conf->addrs must contain pre-resolved server addresses.
 * On success, *ctxp receives a cancellable request handle.
 * Returns NGX_OK on success, NGX_ERROR on immediate failure.
 */
ngx_int_t ngx_stream_trojan_doh_resolve(ngx_stream_trojan_doh_conf_t *doh_conf,
    u_char *name, size_t name_len, uint16_t qtype,
    ngx_log_t *log, void *data, ngx_stream_trojan_doh_handler_pt handler,
    ngx_stream_trojan_doh_ctx_t **ctxp);

void ngx_stream_trojan_doh_cancel(ngx_stream_trojan_doh_ctx_t *doh);

#endif /* _NGX_STREAM_TROJAN_DOH_H_INCLUDED_ */
