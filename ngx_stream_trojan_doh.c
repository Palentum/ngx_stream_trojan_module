#include "ngx_stream_trojan_doh.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* ─── DNS query builder (RFC 1035) ─────────────────────────────────────── */

size_t
ngx_stream_trojan_doh_build_query(u_char *buf, size_t buf_len,
    const u_char *name, size_t name_len, uint16_t qtype, uint16_t dns_id)
{
    u_char  *p, *label_ptr;
    size_t   i, label_len;

    if (name_len == 0
        || name_len > 254
        || (name_len == 254 && name[name_len - 1] != '.')
        || buf_len < 12 + name_len + 4 + 2)
    {
        return 0;
    }

    p = buf;

    *p++ = (u_char) (dns_id >> 8);
    *p++ = (u_char) (dns_id & 0xff);
    *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x01;
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    i = 0;
    while (i < name_len) {
        label_ptr = p++;
        label_len = 0;

        while (i < name_len && name[i] != '.') {
            if (label_len == 63 || (size_t) (p - buf) >= buf_len) {
                return 0;
            }

            *p++ = name[i++];
            label_len++;
        }

        if (label_len == 0) {
            return 0;
        }

        *label_ptr = (u_char) label_len;

        if (i < name_len && name[i] == '.') {
            i++;
            if (i == name_len) {
                break;
            }
        }
    }

    if ((size_t) (p - buf) + 5 > buf_len) {
        return 0;
    }

    *p++ = 0x00;

    *p++ = (u_char) (qtype >> 8);
    *p++ = (u_char) (qtype & 0xff);
    *p++ = 0x00;
    *p++ = 0x01;

    return (size_t) (p - buf);
}


/* ─── DNS response parser ─────────────────────────────────────────────── */

static u_char *
ngx_stream_trojan_doh_skip_name(u_char *p, u_char *start, u_char *end)
{
    uint16_t  offset;

    for (;;) {
        if (p >= end) {
            return NULL;
        }

        if (*p == 0x00) {
            return p + 1;
        }

        if ((*p & 0xC0) == 0xC0) {
            if (p + 1 >= end) {
                return NULL;
            }

            offset = (uint16_t) (((*p & 0x3f) << 8) | p[1]);
            if (offset >= (size_t) (end - start)) {
                return NULL;
            }

            return p + 2;
        }

        if ((*p & 0xC0) != 0
            || (size_t) (end - p) < (size_t) (1 + *p))
        {
            return NULL;
        }

        p += 1 + *p;
    }
}


static ngx_int_t
ngx_stream_trojan_doh_extract_rdata(uint16_t rtype, u_char *rdata,
    uint16_t rdlength, struct sockaddr *sa, socklen_t *socklen)
{
    struct sockaddr_in  *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif

    if (rtype == 1 && rdlength == 4) {
        sin = (struct sockaddr_in *) sa;
        ngx_memzero(sin, sizeof(struct sockaddr_in));
        sin->sin_family = AF_INET;
        ngx_memcpy(&sin->sin_addr.s_addr, rdata, 4);
        *socklen = sizeof(struct sockaddr_in);
        return NGX_OK;
    }
#if (NGX_HAVE_INET6)
    if (rtype == 28 && rdlength == 16) {
        sin6 = (struct sockaddr_in6 *) sa;
        ngx_memzero(sin6, sizeof(struct sockaddr_in6));
        sin6->sin6_family = AF_INET6;
        ngx_memcpy(&sin6->sin6_addr.s6_addr, rdata, 16);
        *socklen = sizeof(struct sockaddr_in6);
        return NGX_OK;
    }
#endif
    return NGX_ERROR;
}


ngx_int_t
ngx_stream_trojan_doh_parse_response(u_char *data, size_t len,
    uint16_t expected_id, ngx_resolver_addr_t **addrs_p,
    ngx_uint_t *naddrs_p, ngx_pool_t *pool)
{
    u_char               *p, *end, *start;
    uint16_t              dns_id, flags, qdcount, ancount;
    uint16_t              rtype, rdlength;
    ngx_uint_t            i, n;
    ngx_resolver_addr_t  *addrs;
    struct sockaddr       sa_buf;
    socklen_t             socklen;

    *addrs_p = NULL;
    *naddrs_p = 0;

    if (len < 12) return NGX_ERROR;

    start = data;
    end = data + len;
    p = data;

    dns_id = ((uint16_t) p[0] << 8) | p[1];
    if (dns_id != expected_id) return NGX_ERROR;

    flags = ((uint16_t) p[2] << 8) | p[3];
    if ((flags & 0x8000) == 0) return NGX_ERROR;
    if ((flags & 0x000F) != 0) return NGX_ERROR;
    if ((flags & 0x0200) != 0) return NGX_ERROR;

    qdcount = ((uint16_t) p[4] << 8) | p[5];
    ancount = ((uint16_t) p[6] << 8) | p[7];
    p += 12;



    for (i = 0; i < qdcount; i++) {
        p = ngx_stream_trojan_doh_skip_name(p, start, end);
        if (p == NULL || (size_t) (end - p) < 4) return NGX_ERROR;
        p += 4;
    }

    if (ancount == 0) return NGX_DECLINED;

    /* pre-scan answers */
    {
        u_char  *scan;
        uint16_t an, rdlen;

        n = 0;
        scan = p;
        for (an = 0; an < ancount; an++) {
            scan = ngx_stream_trojan_doh_skip_name(scan, start, end);
            if (scan == NULL || (size_t) (end - scan) < 10) return NGX_ERROR;

            rtype = ((uint16_t) scan[0] << 8) | scan[1];
            rdlen = ((uint16_t) scan[8] << 8) | scan[9];
            scan += 10;

            if ((size_t) (end - scan) < rdlen) return NGX_ERROR;

            if ((rtype == 1 && rdlen == 4)
#if (NGX_HAVE_INET6)
                || (rtype == 28 && rdlen == 16)
#endif
                )
            {
                n++;
            }

            scan += rdlen;
        }
    }

    if (n == 0) return NGX_DECLINED;

    addrs = ngx_pcalloc(pool, n * sizeof(ngx_resolver_addr_t));
    if (addrs == NULL) return NGX_ERROR;

    n = 0;

    for (i = 0; i < ancount; i++) {
        p = ngx_stream_trojan_doh_skip_name(p, start, end);
        if (p == NULL || (size_t) (end - p) < 10) return NGX_ERROR;

        rtype    = ((uint16_t) p[0] << 8) | p[1];
        rdlength = ((uint16_t) p[8] << 8) | p[9];
        p += 10;

        if ((size_t) (end - p) < rdlength) return NGX_ERROR;

        if (ngx_stream_trojan_doh_extract_rdata(rtype, p, rdlength,
                                                 &sa_buf, &socklen)
            == NGX_OK)
        {
            addrs[n].sockaddr = ngx_palloc(pool, socklen);
            if (addrs[n].sockaddr == NULL) return NGX_ERROR;
            ngx_memcpy(addrs[n].sockaddr, &sa_buf, socklen);
            addrs[n].socklen = socklen;
            n++;
        }

        p += rdlength;
    }

    *addrs_p = addrs;
    *naddrs_p = n;

    return n > 0 ? NGX_OK : NGX_ERROR;
}


/* ─── URL parsing (config time, hostname pre-resolved via ngx_parse_url) ─ */

ngx_int_t
ngx_stream_trojan_doh_parse_url(ngx_str_t *url,
    ngx_stream_trojan_doh_conf_t *doh_conf, ngx_pool_t *pool, ngx_log_t *log)
{
    u_char              *p, *last, *host_start, *host_end, *path_start;
    size_t               host_len;
    ngx_uint_t           port, port_set;
    ngx_url_t            u;
#if (NGX_SSL)
    ngx_pool_cleanup_t  *cln;
#endif

    ngx_memzero(doh_conf, sizeof(ngx_stream_trojan_doh_conf_t));
    doh_conf->port = 443;
    doh_conf->https = 1;
    doh_conf->timeout = NGX_STREAM_TROJAN_DOH_DEFAULT_TIMEOUT;

    if (url->len < 8) return NGX_ERROR;

    p = url->data;
    last = url->data + url->len;

    if (ngx_strncasecmp(p, (u_char *) "https://", 8) == 0) {
        doh_conf->https = 1;
        doh_conf->port = 443;
        p += 8;
    } else if (ngx_strncasecmp(p, (u_char *) "http://", 7) == 0) {
        doh_conf->https = 0;
        doh_conf->port = 80;
        p += 7;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "DoH: unsupported URL scheme in \"%V\"", url);
        return NGX_ERROR;
    }

#if !(NGX_SSL)
    if (doh_conf->https) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "DoH: HTTPS URL requires nginx built with SSL");
        return NGX_ERROR;
    }
#endif

    host_start = p;
    path_start = last;
    port_set = 0;

    while (p < last && *p != ':' && *p != '/') {
        p++;
    }

    host_end = p;

    if (p < last && *p == ':') {
        p++;
        port = 0;
        port_set = 1;

        if (p == last || *p < '0' || *p > '9') {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "DoH: invalid port in \"%V\"", url);
            return NGX_ERROR;
        }

        while (p < last && *p >= '0' && *p <= '9') {
            port = port * 10 + (*p - '0');
            if (port > 65535) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "DoH: invalid port in \"%V\"", url);
                return NGX_ERROR;
            }
            p++;
        }

        if (p < last && *p != '/') {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "DoH: invalid URL path in \"%V\"", url);
            return NGX_ERROR;
        }

        doh_conf->port = (in_port_t) port;
    }

    if (p < last && *p == '/') {
        path_start = p;
    }

    host_len = (size_t) (host_end - host_start);
    if (host_len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "DoH: empty host in \"%V\"", url);
        return NGX_ERROR;
    }

    doh_conf->host.data = ngx_pnalloc(pool, host_len);
    if (doh_conf->host.data == NULL) return NGX_ERROR;
    ngx_memcpy(doh_conf->host.data, host_start, host_len);
    doh_conf->host.len = host_len;

    /* host_header "host:port" */
    {
        u_char   port_buf[6];
        size_t   port_len;
        u_char  *hh;

        if (port_set
            && ((doh_conf->https && doh_conf->port != 443)
                || (!doh_conf->https && doh_conf->port != 80)))
        {
            port_len = (size_t) (ngx_sprintf(port_buf, "%ui",
                                             (ngx_uint_t) doh_conf->port)
                                 - port_buf);
        } else {
            port_len = 0;
        }

        doh_conf->host_header.len = host_len + (port_len ? 1 + port_len : 0);
        hh = ngx_pnalloc(pool, doh_conf->host_header.len);
        if (hh == NULL) return NGX_ERROR;
        ngx_memcpy(hh, host_start, host_len);
        if (port_len) {
            hh[host_len] = ':';
            ngx_memcpy(hh + host_len + 1, port_buf, port_len);
        }
        doh_conf->host_header.data = hh;
    }

    /* path */
    {
        size_t path_len = (size_t) (last - path_start);
        if (path_len == 0) {
            doh_conf->path.data = ngx_pnalloc(pool, 1);
            if (doh_conf->path.data == NULL) return NGX_ERROR;
            doh_conf->path.data[0] = '/';
            doh_conf->path.len = 1;
        } else {
            doh_conf->path.data = ngx_pnalloc(pool, path_len);
            if (doh_conf->path.data == NULL) return NGX_ERROR;
            ngx_memcpy(doh_conf->path.data, path_start, path_len);
            doh_conf->path.len = path_len;
        }
    }

    /* resolve hostname at config time via ngx_parse_url */
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = doh_conf->host;
    u.default_port = doh_conf->port;
    u.no_resolve = 0;

    if (ngx_parse_url(pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "DoH: %s in \"%V\"", u.err, url);
        }
        return NGX_ERROR;
    }

    doh_conf->addrs = u.addrs;
    doh_conf->naddrs = u.naddrs;

    if (doh_conf->naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "DoH: \"%V\" could not be resolved", url);
        return NGX_ERROR;
    }

#if (NGX_SSL)
    if (doh_conf->https) {
        doh_conf->ssl.log = log;

        if (ngx_ssl_create(&doh_conf->ssl, NGX_SSL_DEFAULT_PROTOCOLS, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        cln = ngx_pool_cleanup_add(pool, 0);
        if (cln == NULL) {
            ngx_ssl_cleanup_ctx(&doh_conf->ssl);
            return NGX_ERROR;
        }
        cln->handler = ngx_ssl_cleanup_ctx;
        cln->data = &doh_conf->ssl;

        if (SSL_CTX_set_default_verify_paths(doh_conf->ssl.ctx) != 1) {
            ngx_ssl_error(NGX_LOG_ERR, log, 0,
                          "DoH: SSL_CTX_set_default_verify_paths() failed");
            return NGX_ERROR;
        }

        SSL_CTX_set_verify(doh_conf->ssl.ctx, SSL_VERIFY_PEER, NULL);
        doh_conf->ssl_hostname = doh_conf->host;
    }
#endif

    return NGX_OK;
}


/* ─── DoH async resolution engine ─────────────────────────────────────── */

struct ngx_stream_trojan_doh_ctx_s {
    ngx_stream_trojan_doh_conf_t *conf;

    u_char                       query[NGX_STREAM_TROJAN_DOH_MAX_QUERY_SIZE];
    size_t                       query_len;
    uint16_t                     dns_id;

    ngx_peer_connection_t        peer;
    ngx_stream_trojan_doh_ctx_t **owner;
    unsigned                     peer_initialized:1;
    ngx_uint_t                   addr_idx;



    u_char                      *send_ptr;
    size_t                       send_len;

    u_char                       recv_buf[NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE];
    size_t                       recv_pos;

    enum {
        DOH_READ_STATUS = 0,
        DOH_READ_HEADERS,
        DOH_READ_BODY,
        DOH_DONE
    } read_state;
    u_char                      *body_start;
    size_t                       body_len;
    size_t                       content_length;
    ngx_uint_t                   http_status;
    unsigned                     content_length_set:1;
    unsigned                     chunked:1;

    ngx_resolver_addr_t         *addrs;
    ngx_uint_t                   naddrs;
    ngx_pool_t                  *parse_pool;

    void                        *cb_data;
    ngx_stream_trojan_doh_handler_pt cb_handler;
    ngx_log_t                   *log;
    ngx_pool_t                  *pool;
};


static ngx_int_t ngx_stream_trojan_doh_get_peer(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_trojan_doh_connected(ngx_stream_trojan_doh_ctx_t *doh);
static void ngx_stream_trojan_doh_start_http(ngx_stream_trojan_doh_ctx_t *doh);
static void ngx_stream_trojan_doh_write_handler(ngx_event_t *ev);
static void ngx_stream_trojan_doh_dummy_write_handler(ngx_event_t *ev);
static void ngx_stream_trojan_doh_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_doh_event_handler(ngx_event_t *ev);
static void ngx_stream_trojan_doh_finish(ngx_stream_trojan_doh_ctx_t *doh,
    ngx_int_t status);

#if (NGX_SSL)
static void ngx_stream_trojan_doh_ssl_handshake_handler(ngx_connection_t *c);
#endif


static ngx_int_t
ngx_stream_trojan_doh_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_trojan_doh_ctx_t *doh = data;

    if (doh->addr_idx >= doh->conf->naddrs) {
        return NGX_ERROR;
    }

    pc->sockaddr = doh->conf->addrs[doh->addr_idx].sockaddr;
    pc->socklen = doh->conf->addrs[doh->addr_idx].socklen;
    doh->addr_idx++;
    pc->name = &doh->conf->host;

    return NGX_OK;
}


#if (NGX_SSL)
static ngx_int_t
ngx_stream_trojan_doh_ssl_set_name(ngx_stream_trojan_doh_ctx_t *doh,
    ngx_connection_t *c)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    u_char     *p;
    ngx_str_t  name;

    name = doh->conf->ssl_hostname;

    if (name.len == 0 || *name.data == '[') {
        return NGX_OK;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        return NGX_OK;
    }

    p = ngx_pnalloc(doh->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, name.data, name.len);
    p[name.len] = '\0';

    if (SSL_set_tlsext_host_name(c->ssl->connection, (char *) p) == 0) {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "DoH: SSL_set_tlsext_host_name(\"%s\") failed", p);
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_doh_ssl_verify_hostname(ngx_connection_t *c,
    ngx_stream_trojan_doh_conf_t *conf)
{
    X509  *cert;
    long   rc;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "DoH: no peer certificate from %V", &conf->host);
        return NGX_ERROR;
    }
    X509_free(cert);

    rc = SSL_get_verify_result(c->ssl->connection);
    if (rc != X509_V_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "DoH: certificate verify failed for %V: %s",
                      &conf->host, X509_verify_cert_error_string(rc));
        return NGX_ERROR;
    }

    if (ngx_ssl_check_host(c, &conf->ssl_hostname) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "DoH: certificate SAN/CN does not match %V",
                      &conf->ssl_hostname);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_doh_ssl_init_connection(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = doh->peer.connection;

    if (ngx_ssl_create_connection(&doh->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_doh_ssl_set_name(doh, c) != NGX_OK) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return NGX_ERROR;
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        if (!c->write->timer_set) {
            ngx_add_timer(c->write, doh->conf->timeout);
        }

        c->ssl->handler = ngx_stream_trojan_doh_ssl_handshake_handler;
        return NGX_OK;
    }

    ngx_stream_trojan_doh_ssl_handshake_handler(c);
    return NGX_OK;
}


static void
ngx_stream_trojan_doh_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_stream_trojan_doh_ctx_t *doh;

    doh = c->data;

    if (c->ssl->handshaked) {
        if (ngx_stream_trojan_doh_ssl_verify_hostname(c, doh->conf)
            != NGX_OK)
        {
            ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
            return;
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_stream_trojan_doh_start_http(doh);
        return;
    }

    ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
}
#endif


static ngx_int_t
ngx_stream_trojan_doh_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        err = c->write->kq_errno ? c->write->kq_errno : c->write->pending_eof;
        if (err) {
            c->write->kq_errno = 0;
            c->write->pending_eof = 0;
            ngx_log_error(NGX_LOG_ERR, c->log, err,
                          "DoH: connect failed");
            return NGX_ERROR;
        }
    } else
#endif
    {
        len = sizeof(int);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            ngx_log_error(NGX_LOG_ERR, c->log, err,
                          "DoH: connect failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_trojan_doh_resolve(ngx_stream_trojan_doh_conf_t *doh_conf,
    u_char *name, size_t name_len, uint16_t qtype,
    ngx_log_t *log, void *data, ngx_stream_trojan_doh_handler_pt handler,
    ngx_stream_trojan_doh_ctx_t **ctxp)
{
    ngx_stream_trojan_doh_ctx_t  *doh;
    ngx_connection_t             *c;
    ngx_pool_t                   *pool;
    ngx_int_t                     rc;
    uint16_t                      dns_id;
    size_t                        qlen;

    if (ctxp == NULL) {
        return NGX_ERROR;
    }
    *ctxp = NULL;

    pool = ngx_create_pool(4096, log);
    if (pool == NULL) return NGX_ERROR;

    doh = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_doh_ctx_t));
    if (doh == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    doh->pool = pool;
    doh->conf = doh_conf;
    doh->log = log;
    doh->cb_data = data;
    doh->cb_handler = handler;

    dns_id = (uint16_t) ngx_random();

    qlen = ngx_stream_trojan_doh_build_query(doh->query,
                                             NGX_STREAM_TROJAN_DOH_MAX_QUERY_SIZE,
                                             name, name_len, qtype, dns_id);
    if (qlen == 0) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    doh->query_len = qlen;
    doh->dns_id = dns_id;



    ngx_memzero(&doh->peer, sizeof(ngx_peer_connection_t));
    doh->peer.log = log;
    doh->peer.log_error = NGX_ERROR_ERR;
    doh->peer.get = ngx_stream_trojan_doh_get_peer;
    doh->peer.data = doh;
    doh->peer.type = SOCK_STREAM;
    doh->peer.tries = 1;
    doh->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&doh->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        goto fail;
    }

    doh->peer_initialized = 1;

    c = doh->peer.connection;
    if (c == NULL) {
        goto fail;
    }

    c->data = doh;
    c->pool = pool;
    c->log = log;
    c->read->log = log;
    c->write->log = log;

    doh->owner = ctxp;
    *ctxp = doh;

    if (rc == NGX_AGAIN) {
        c->write->handler = ngx_stream_trojan_doh_event_handler;
        c->read->handler = ngx_stream_trojan_doh_event_handler;
        ngx_add_timer(c->write, doh_conf->timeout);
        return NGX_OK;
    }

    ngx_stream_trojan_doh_connected(doh);
    return NGX_OK;

fail:
    if (doh->peer.connection) {
        ngx_close_connection(doh->peer.connection);
        doh->peer.connection = NULL;
    }
    ngx_destroy_pool(pool);
    return NGX_ERROR;
}


static void
ngx_stream_trojan_doh_event_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_stream_trojan_doh_ctx_t *doh;

    c = ev->data;
    doh = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, doh->log, NGX_ETIMEDOUT,
                      "DoH: connect to %V timed out", &doh->conf->host);
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    if (ngx_stream_trojan_doh_test_connect(c) != NGX_OK) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    ngx_stream_trojan_doh_connected(doh);
}


static void
ngx_stream_trojan_doh_connected(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_connection_t  *c;

    c = doh->peer.connection;

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

#if (NGX_SSL)
    if (doh->conf->https) {
        (void) ngx_stream_trojan_doh_ssl_init_connection(doh);
        return;
    }
#else
    if (doh->conf->https) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }
#endif

    ngx_stream_trojan_doh_start_http(doh);
}


static void
ngx_stream_trojan_doh_start_http(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_connection_t  *c;

    c = doh->peer.connection;
    c->write->handler = ngx_stream_trojan_doh_write_handler;
    c->read->handler = ngx_stream_trojan_doh_read_handler;

    ngx_stream_trojan_doh_write_handler(c->write);
}


static void
ngx_stream_trojan_doh_write_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_stream_trojan_doh_ctx_t *doh;
    ssize_t                      n;

    c = ev->data;
    doh = c->data;

    if (ev->timedout) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    if (doh->send_ptr != NULL && doh->send_len == 0) {
        return;
    }

    if (doh->send_ptr == NULL) {
        u_char   cl_buf[12];
        size_t   cl_len;
        u_char  *req, *p;
        size_t   alloc;

        cl_len = (size_t) (ngx_sprintf(cl_buf, "%uz", doh->query_len)
                           - cl_buf);
        alloc = 128 + doh->conf->host_header.len + doh->conf->path.len
                + doh->query_len + cl_len;

        req = ngx_palloc(doh->pool, alloc);
        if (req == NULL) {
            ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
            return;
        }

        p = req;
        p = ngx_cpymem(p, "POST ", 5);
        p = ngx_cpymem(p, doh->conf->path.data, doh->conf->path.len);
        p = ngx_cpymem(p, " HTTP/1.1\r\n", sizeof(" HTTP/1.1\r\n") - 1);
        p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
        p = ngx_cpymem(p, doh->conf->host_header.data,
                       doh->conf->host_header.len);
        p = ngx_cpymem(p, "\r\n", sizeof("\r\n") - 1);
        p = ngx_cpymem(p, "Content-Type: application/dns-message\r\n",
                       sizeof("Content-Type: application/dns-message\r\n") - 1);
        p = ngx_cpymem(p, "Accept: application/dns-message\r\n",
                       sizeof("Accept: application/dns-message\r\n") - 1);
        p = ngx_cpymem(p, "Content-Length: ",
                       sizeof("Content-Length: ") - 1);
        p = ngx_cpymem(p, cl_buf, cl_len);
        p = ngx_cpymem(p, "\r\n", sizeof("\r\n") - 1);
        p = ngx_cpymem(p, "Connection: close\r\n",
                       sizeof("Connection: close\r\n") - 1);
        p = ngx_cpymem(p, "\r\n", sizeof("\r\n") - 1);
        p = ngx_cpymem(p, doh->query, doh->query_len);

        doh->send_ptr = req;
        doh->send_len = (size_t) (p - req);
    }

    while (doh->send_len) {
        n = c->send(c, doh->send_ptr, doh->send_len);
        if (n == NGX_ERROR) {
            ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
            return;
        }

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                return;
            }

            if (!c->write->timer_set) {
                ngx_add_timer(c->write, doh->conf->timeout);
            }
            return;
        }

        doh->send_ptr += n;
        doh->send_len -= (size_t) n;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_stream_trojan_doh_dummy_write_handler;

    if (c->write->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(c->write, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
            return;
        }
    }

    doh->read_state = DOH_READ_STATUS;
    if (!c->read->timer_set) {
        ngx_add_timer(c->read, doh->conf->timeout);
    }
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
    }
}


static void
ngx_stream_trojan_doh_dummy_write_handler(ngx_event_t *ev)
{
    /* used as SSL saved_write_handler after the HTTP request is sent */
}


static ngx_int_t
ngx_stream_trojan_doh_header_has_token(u_char *p, u_char *end,
    u_char *token, size_t token_len)
{
    u_char  *start;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }

        start = p;
        while (p < end && *p != ',' && *p != ' ' && *p != '\t') {
            p++;
        }

        if ((size_t) (p - start) == token_len
            && ngx_strncasecmp(start, token, token_len) == 0)
        {
            return NGX_OK;
        }

        while (p < end && *p != ',') {
            p++;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_trojan_doh_decode_chunked(u_char *data, size_t len,
    size_t *decoded_len)
{
    u_char     *p, *end, *line, *dst;
    size_t      chunk_size;
    ngx_uint_t  digit, saw_digit;

    p = data;
    end = data + len;

    for (;;) {
        line = p;
        while (p + 1 < end && !(p[0] == '\r' && p[1] == '\n')) {
            p++;
        }

        if (p + 1 >= end) {
            return NGX_AGAIN;
        }

        chunk_size = 0;
        saw_digit = 0;

        while (line < p && *line != ';') {
            if (*line >= '0' && *line <= '9') {
                digit = *line - '0';
            } else if (*line >= 'A' && *line <= 'F') {
                digit = *line - 'A' + 10;
            } else if (*line >= 'a' && *line <= 'f') {
                digit = *line - 'a' + 10;
            } else {
                return NGX_ERROR;
            }

            saw_digit = 1;
            if (chunk_size
                > (NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE - digit) / 16)
            {
                return NGX_ERROR;
            }
            chunk_size = chunk_size * 16 + digit;
            line++;
        }

        if (!saw_digit) {
            return NGX_ERROR;
        }

        p += 2;

        if (chunk_size == 0) {
            for (;;) {
                line = p;
                while (p + 1 < end && !(p[0] == '\r' && p[1] == '\n')) {
                    p++;
                }

                if (p + 1 >= end) {
                    return NGX_AGAIN;
                }

                if (p == line) {
                    goto decode;
                }

                p += 2;
            }
        }

        if ((size_t) (end - p) < chunk_size + 2) {
            return NGX_AGAIN;
        }

        if (p[chunk_size] != '\r' || p[chunk_size + 1] != '\n') {
            return NGX_ERROR;
        }

        p += chunk_size + 2;
    }

decode:

    p = data;
    dst = data;

    for (;;) {
        line = p;
        while (!(p[0] == '\r' && p[1] == '\n')) {
            p++;
        }

        chunk_size = 0;
        while (line < p && *line != ';') {
            if (*line >= '0' && *line <= '9') {
                digit = *line - '0';
            } else if (*line >= 'A' && *line <= 'F') {
                digit = *line - 'A' + 10;
            } else {
                digit = *line - 'a' + 10;
            }

            if (chunk_size
                > (NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE - digit) / 16)
            {
                return NGX_ERROR;
            }
            chunk_size = chunk_size * 16 + digit;
            line++;
        }

        p += 2;

        if (chunk_size == 0) {
            *decoded_len = (size_t) (dst - data);
            return NGX_OK;
        }

        ngx_memmove(dst, p, chunk_size);
        dst += chunk_size;
        p += chunk_size + 2;
    }
}


static ngx_int_t
ngx_stream_trojan_doh_body_ready(ngx_stream_trojan_doh_ctx_t *doh,
    ngx_uint_t eof)
{
    ngx_int_t  rc;
    size_t     decoded_len;

    if (doh->chunked) {
        rc = ngx_stream_trojan_doh_decode_chunked(doh->body_start,
                                                  doh->body_len,
                                                  &decoded_len);
        if (rc == NGX_OK) {
            doh->body_len = decoded_len;
        }
        return rc;
    }

    if (doh->content_length_set) {
        if (doh->body_len < doh->content_length) {
            return NGX_AGAIN;
        }

        doh->body_len = doh->content_length;
        return NGX_OK;
    }

    if (eof && doh->body_len > 0) {
        return NGX_OK;
    }

    return NGX_AGAIN;
}


static void
ngx_stream_trojan_doh_parse_done(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_int_t   rc;
    ngx_pool_t *pp;

    pp = ngx_create_pool(512, doh->log);
    if (pp == NULL) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }
    doh->parse_pool = pp;

    rc = ngx_stream_trojan_doh_parse_response(doh->body_start,
        doh->body_len, doh->dns_id, &doh->addrs, &doh->naddrs, pp);

    if (rc != NGX_OK) {
        if (rc != NGX_DECLINED) {
            ngx_log_error(NGX_LOG_ERR, doh->log, 0,
                          "DoH: failed to parse DNS response (id=%ud)",
                          doh->dns_id);
        }

        ngx_stream_trojan_doh_finish(doh, rc);
        return;
    }

    ngx_stream_trojan_doh_finish(doh, NGX_OK);
}


static void
ngx_stream_trojan_doh_read_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_stream_trojan_doh_ctx_t *doh;
    ssize_t                      n;
    size_t                       avail;
    u_char                      *p, *end, *sp, *vp;
    ngx_int_t                    status, cl, rc;

    c = ev->data;
    doh = c->data;

    if (ev->timedout) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    avail = NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE - doh->recv_pos;
    if (avail == 0) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    n = c->recv(c, doh->recv_buf + doh->recv_pos, avail);
    if (n == NGX_ERROR) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        goto need_more;
    }

    if (n == 0) {
        if (doh->read_state == DOH_READ_BODY && doh->body_start) {
            end = doh->recv_buf + doh->recv_pos;
            doh->body_len = (size_t) (end - doh->body_start);
            rc = ngx_stream_trojan_doh_body_ready(doh, 1);
            if (rc == NGX_OK) {
                ngx_stream_trojan_doh_parse_done(doh);
                return;
            }
        }

        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
        return;
    }

    doh->recv_pos += (size_t) n;
    end = doh->recv_buf + doh->recv_pos;

    if (doh->read_state == DOH_READ_STATUS) {
        for (p = doh->recv_buf; p + 1 < end; p++) {
            if (p[0] == '\r' && p[1] == '\n') {
                if (p - doh->recv_buf < 12
                    || ngx_strncmp(doh->recv_buf, "HTTP/", 5) != 0)
                {
                    ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                    return;
                }

                sp = ngx_strlchr(doh->recv_buf + 5, p, ' ');
                if (sp == NULL || p - sp < 4) {
                    ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                    return;
                }

                status = ngx_atoi(sp + 1, 3);
                if (status == NGX_ERROR) {
                    ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                    return;
                }

                doh->http_status = (ngx_uint_t) status;

                p += 2;
                ngx_memmove(doh->recv_buf, p, end - p);
                doh->recv_pos = (size_t) (end - p);
                end = doh->recv_buf + doh->recv_pos;
                doh->read_state = DOH_READ_HEADERS;
                goto parse_headers;
            }
        }
        goto need_more;
    }

parse_headers:
    while (doh->read_state == DOH_READ_HEADERS) {
        for (p = doh->recv_buf; p + 1 < end; p++) {
            if (p[0] == '\r' && p[1] == '\n') {
                if (p == doh->recv_buf) {
                    p += 2;
                    doh->body_len = (size_t) (end - p);
                    ngx_memmove(doh->recv_buf, p, doh->body_len);
                    doh->recv_pos = doh->body_len;
                    doh->body_start = doh->recv_buf;
                    end = doh->recv_buf + doh->recv_pos;

                    if (doh->http_status < 200 || doh->http_status >= 300) {
                        ngx_log_error(NGX_LOG_ERR, doh->log, 0,
                                      "DoH: HTTP status %ui",
                                      doh->http_status);
                        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                        return;
                    }

                    doh->read_state = DOH_READ_BODY;
                    rc = ngx_stream_trojan_doh_body_ready(doh, 0);
                    if (rc == NGX_OK) {
                        ngx_stream_trojan_doh_parse_done(doh);
                        return;
                    }
                    if (rc == NGX_ERROR) {
                        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                        return;
                    }
                    goto need_more;
                }

                if ((size_t) (p - doh->recv_buf) >= 15
                    && ngx_strncasecmp(doh->recv_buf,
                                       (u_char *) "Content-Length:", 15) == 0)
                {
                    vp = doh->recv_buf + 15;
                    while (vp < p && (*vp == ' ' || *vp == '\t')) vp++;

                    cl = ngx_atoi(vp, p - vp);
                    if (cl < 0
                        || cl > NGX_STREAM_TROJAN_DOH_MAX_RESPONSE_SIZE)
                    {
                        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
                        return;
                    }

                    doh->content_length = (size_t) cl;
                    doh->content_length_set = 1;
                }

                if ((size_t) (p - doh->recv_buf) >= 18
                    && ngx_strncasecmp(doh->recv_buf,
                                       (u_char *) "Transfer-Encoding:", 18)
                       == 0)
                {
                    vp = doh->recv_buf + 18;
                    if (ngx_stream_trojan_doh_header_has_token(
                            vp, p, (u_char *) "chunked", 7)
                        == NGX_OK)
                    {
                        doh->chunked = 1;
                    }
                }

                p += 2;
                ngx_memmove(doh->recv_buf, p, end - p);
                doh->recv_pos = (size_t) (end - p);
                end = doh->recv_buf + doh->recv_pos;
                goto parse_headers;
            }
        }
        goto need_more;
    }

    if (doh->read_state == DOH_READ_BODY) {
        doh->body_len = (size_t) (end - doh->body_start);
        rc = ngx_stream_trojan_doh_body_ready(doh, 0);
        if (rc == NGX_OK) {
            ngx_stream_trojan_doh_parse_done(doh);
            return;
        }
        if (rc == NGX_ERROR) {
            ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
            return;
        }
        goto need_more;
    }

need_more:
    if (!c->read->timer_set) {
        ngx_add_timer(c->read, doh->conf->timeout);
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_stream_trojan_doh_finish(doh, NGX_ERROR);
    }
}


static void
ngx_stream_trojan_doh_close(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_connection_t  *c;

    if (doh->owner && *doh->owner == doh) {
        *doh->owner = NULL;
    }

    if (doh->peer_initialized) {
        c = doh->peer.connection;
        if (c) {
#if (NGX_SSL)
            if (c->ssl) {
                c->ssl->no_wait_shutdown = 1;
                c->ssl->no_send_shutdown = 1;
                (void) ngx_ssl_shutdown(c);
            }
#endif
            ngx_close_connection(c);
            doh->peer.connection = NULL;
        }
    }
}


void
ngx_stream_trojan_doh_cancel(ngx_stream_trojan_doh_ctx_t *doh)
{
    ngx_pool_t  *pool;

    if (doh == NULL || doh->read_state == DOH_DONE) {
        return;
    }

    doh->read_state = DOH_DONE;
    ngx_stream_trojan_doh_close(doh);

    if (doh->parse_pool) {
        ngx_destroy_pool(doh->parse_pool);
        doh->parse_pool = NULL;
    }

    pool = doh->pool;
    if (pool) {
        ngx_destroy_pool(pool);
    }
}


static void
ngx_stream_trojan_doh_finish(ngx_stream_trojan_doh_ctx_t *doh,
    ngx_int_t status)
{
    ngx_pool_t                      *pool;
    void                            *cb_data;
    ngx_stream_trojan_doh_handler_pt cb_handler;
    ngx_resolver_addr_t             *addrs;
    ngx_uint_t                       naddrs;

    if (doh->read_state == DOH_DONE) return;
    doh->read_state = DOH_DONE;

    ngx_stream_trojan_doh_close(doh);

    cb_data = doh->cb_data;
    cb_handler = doh->cb_handler;
    addrs = doh->addrs;
    naddrs = doh->naddrs;

    if (status == NGX_OK && addrs && naddrs > 0) {
        cb_handler(cb_data, NGX_OK, addrs, naddrs);
    } else {
        cb_handler(cb_data, status, NULL, 0);
    }

    if (doh->parse_pool) {
        ngx_destroy_pool(doh->parse_pool);
        doh->parse_pool = NULL;
    }

    pool = doh->pool;
    if (pool) {
        ngx_destroy_pool(pool);
    }
}