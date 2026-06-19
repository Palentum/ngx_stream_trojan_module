#ifndef _NGX_STREAM_TROJAN_DNS_RULES_H_INCLUDED_
#define _NGX_STREAM_TROJAN_DNS_RULES_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_stream_trojan_doh.h"
#include "ngx_stream_trojan_geosite.h"


typedef struct ngx_stream_trojan_dns_rules_conf_s ngx_stream_trojan_dns_rules_conf_t;
typedef struct ngx_stream_trojan_dns_rule_group_s ngx_stream_trojan_dns_rule_group_t;


struct ngx_stream_trojan_dns_rule_group_s {
    ngx_resolver_t                    *resolver;
    ngx_stream_trojan_doh_conf_t      *doh_conf;
    ngx_uint_t                         ip_prefer;
    ngx_array_t     *rules;
    ngx_array_t     *non_domain_rules;
    ngx_uint_t       strategy_set;
};


char *ngx_stream_trojan_dns_rules_parse(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_dns_rules_conf_t **rules);
ngx_int_t ngx_stream_trojan_dns_rules_prepare_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules,
    ngx_stream_trojan_geosite_t *geosite);


ngx_stream_trojan_dns_rule_group_t *ngx_stream_trojan_dns_rules_match(
    ngx_stream_trojan_dns_rules_conf_t *rules, const u_char *host,
    size_t host_len);

#endif /* _NGX_STREAM_TROJAN_DNS_RULES_H_INCLUDED_ */
