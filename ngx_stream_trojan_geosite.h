#ifndef _NGX_STREAM_TROJAN_GEOSITE_H_INCLUDED_
#define _NGX_STREAM_TROJAN_GEOSITE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_stream_trojan_geosite_s ngx_stream_trojan_geosite_t;
typedef struct ngx_stream_trojan_geosite_entry_s ngx_stream_trojan_geosite_entry_t;


char *ngx_stream_trojan_geosite_load(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_geosite_t **geosite);

ngx_stream_trojan_geosite_entry_t *ngx_stream_trojan_geosite_find(
    ngx_stream_trojan_geosite_t *geosite, ngx_str_t *code);

ngx_int_t ngx_stream_trojan_geosite_prepare_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_entry_t *entry, ngx_str_t *attr,
    ngx_uint_t attr_not);

ngx_int_t ngx_stream_trojan_geosite_match(
    ngx_stream_trojan_geosite_entry_t *entry, ngx_str_t *attr,
    ngx_uint_t attr_not, const u_char *host, size_t host_len);

#endif /* _NGX_STREAM_TROJAN_GEOSITE_H_INCLUDED_ */
