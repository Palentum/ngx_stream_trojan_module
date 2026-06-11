#ifndef _NGX_STREAM_TROJAN_GEOIP_H_INCLUDED_
#define _NGX_STREAM_TROJAN_GEOIP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_stream_trojan_geoip_s ngx_stream_trojan_geoip_t;
typedef struct ngx_stream_trojan_geoip_entry_s ngx_stream_trojan_geoip_entry_t;


char *ngx_stream_trojan_geoip_load(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_geoip_t **geoip);

ngx_stream_trojan_geoip_entry_t *ngx_stream_trojan_geoip_find(
    ngx_stream_trojan_geoip_t *geoip, ngx_str_t *code);
ngx_int_t ngx_stream_trojan_geoip_prepare_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry);

ngx_int_t ngx_stream_trojan_geoip_match(
    ngx_stream_trojan_geoip_entry_t *entry, const u_char *addr,
    size_t addr_len);

#endif /* _NGX_STREAM_TROJAN_GEOIP_H_INCLUDED_ */
