#include "ngx_stream_trojan_dns_rules.h"
#include "ngx_stream_trojan_ip_prefer.h"


#define NGX_STREAM_TROJAN_DNS_RULES_MAX_FILE_SIZE  (1024 * 1024)


typedef enum {
    ngx_stream_trojan_dns_rule_domain = 0,
    ngx_stream_trojan_dns_rule_geosite,
    ngx_stream_trojan_dns_rule_regexp
} ngx_stream_trojan_dns_rule_e;


typedef struct {
    ngx_uint_t       type;
    ngx_str_t        value;
    ngx_str_t        attr;
    ngx_uint_t       attr_not;
    ngx_stream_trojan_geosite_entry_t *geosite;
#if (NGX_PCRE)
    ngx_regex_t     *regex;
#endif
} ngx_stream_trojan_dns_rule_t;


struct ngx_stream_trojan_dns_rules_conf_s {
    ngx_array_t     *groups;
    ngx_str_t        path;
};


static ngx_int_t ngx_stream_trojan_dns_rules_read_file(ngx_conf_t *cf,
    ngx_str_t *path, u_char **data, size_t *len);
static ngx_int_t ngx_stream_trojan_dns_rules_parse_content(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_dns_rules_parse_group(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules, ngx_str_t *servers,
    ngx_uint_t line_no, ngx_stream_trojan_dns_rule_group_t **group);
static ngx_int_t ngx_stream_trojan_dns_rules_is_doh_url(ngx_str_t *value);
static ngx_stream_trojan_dns_rule_group_t *
ngx_stream_trojan_dns_rules_add_group(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules);
static ngx_int_t ngx_stream_trojan_dns_rules_parse_strategy(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_group_t *group, ngx_str_t *value,
    ngx_uint_t line_no);
static ngx_int_t ngx_stream_trojan_dns_rules_parse_rule(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_group_t *group, ngx_str_t *line,
    ngx_uint_t line_no);
static ngx_int_t ngx_stream_trojan_dns_rules_parse_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_t *rule, ngx_str_t *value, ngx_uint_t line_no);
static ngx_int_t ngx_stream_trojan_dns_rules_validate(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules);
static ngx_int_t ngx_stream_trojan_dns_rules_match_rule(
    ngx_stream_trojan_dns_rule_t *rule, const u_char *host, size_t host_len);
static ngx_int_t ngx_stream_trojan_dns_rules_match_domain(const u_char *host,
    size_t host_len, ngx_str_t *domain);
static ngx_int_t ngx_stream_trojan_dns_rules_prepare_rule_geosite(
    ngx_conf_t *cf, ngx_stream_trojan_dns_rule_t *rule,
    ngx_stream_trojan_geosite_t *geosite);


static u_char
ngx_stream_trojan_dns_rules_lc(u_char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (u_char) (ch | 0x20);
    }

    return ch;
}


static ngx_uint_t
ngx_stream_trojan_dns_rules_space(u_char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}


static ngx_str_t
ngx_stream_trojan_dns_rules_trim(ngx_str_t value)
{
    while (value.len && ngx_stream_trojan_dns_rules_space(value.data[0])) {
        value.data++;
        value.len--;
    }

    while (value.len
           && ngx_stream_trojan_dns_rules_space(value.data[value.len - 1]))
    {
        value.len--;
    }

    return value;
}


static ngx_str_t
ngx_stream_trojan_dns_rules_strip_comment(ngx_str_t value)
{
    size_t  i;

    for (i = 0; i < value.len; i++) {
        if (value.data[i] == '#'
            && (i == 0 || value.data[i - 1] == ' '
                || value.data[i - 1] == '\t'))
        {
            value.len = i;
            break;
        }
    }

    return value;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_copy(ngx_conf_t *cf, ngx_str_t *src,
    ngx_str_t *dst, ngx_uint_t lower)
{
    size_t  i;

    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < src->len; i++) {
        dst->data[i] = lower ? ngx_stream_trojan_dns_rules_lc(src->data[i])
                             : src->data[i];
    }

    dst->data[src->len] = '\0';
    dst->len = src->len;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_split_mapping(ngx_str_t *line, ngx_str_t *key,
    ngx_str_t *value)
{
    u_char  *p, *last;

    p = line->data;
    last = line->data + line->len;

    while (p < last && *p != ':') {
        p++;
    }

    if (p == last) {
        return NGX_ERROR;
    }

    key->data = line->data;
    key->len = (size_t) (p - line->data);
    *key = ngx_stream_trojan_dns_rules_trim(*key);

    value->data = p + 1;
    value->len = (size_t) (last - p - 1);
    *value = ngx_stream_trojan_dns_rules_trim(*value);

    if (key->len == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_key_eq(ngx_str_t *key, const char *literal,
    size_t len)
{
    return key->len == len && ngx_strncmp(key->data, literal, len) == 0;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_is_doh_url(ngx_str_t *value)
{
    if (value->len >= 8
        && ngx_strncasecmp(value->data, (u_char *) "https://", 8) == 0)
    {
        return 1;
    }

    if (value->len >= 7
        && ngx_strncasecmp(value->data, (u_char *) "http://", 7) == 0)
    {
        return 1;
    }

    return 0;
}


static ngx_stream_trojan_dns_rule_group_t *
ngx_stream_trojan_dns_rules_add_group(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules)
{
    ngx_stream_trojan_dns_rule_group_t  *group;

    group = ngx_array_push(rules->groups);
    if (group == NULL) {
        return NULL;
    }

    ngx_memzero(group, sizeof(ngx_stream_trojan_dns_rule_group_t));
    group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    group->rules = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_stream_trojan_dns_rule_t));
    if (group->rules == NULL) {
        return NULL;
    }

    return group;
}


char *
ngx_stream_trojan_dns_rules_parse(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_dns_rules_conf_t **rules_p)
{
    u_char                                *data;
    size_t                                 len;
    ngx_str_t                              full;
    ngx_stream_trojan_dns_rules_conf_t    *rules;

    if (rules_p == NULL) {
        return NGX_CONF_ERROR;
    }

    full = *path;
    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_dns_rules_read_file(cf, &full, &data, &len)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    rules = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_dns_rules_conf_t));
    if (rules == NULL) {
        return NGX_CONF_ERROR;
    }

    rules->groups = ngx_array_create(cf->pool, 2,
                                     sizeof(ngx_stream_trojan_dns_rule_group_t));
    if (rules->groups == NULL) {
        return NGX_CONF_ERROR;
    }

    rules->path = full;

    if (ngx_stream_trojan_dns_rules_parse_content(cf, rules, data, len)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_dns_rules_validate(cf, rules) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *rules_p = rules;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_read_file(ngx_conf_t *cf, ngx_str_t *path,
    u_char **data, size_t *len)
{
    ngx_fd_t           fd;
    ngx_file_info_t    fi;
    off_t              size;
    ssize_t            n;
    u_char            *buf;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "could not open trojan_dns_rules file \"%V\"",
                           path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "ngx_fd_info(\"%V\") failed", path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = ngx_file_size(&fi);
    if (size <= 0 || size > NGX_STREAM_TROJAN_DNS_RULES_MAX_FILE_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_dns_rules file \"%V\" has invalid size",
                           path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(cf->pool, (size_t) size + 1);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, (size_t) size);
    if (n == -1 || (size_t) n != (size_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "could not read trojan_dns_rules file \"%V\"",
                           path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "ngx_close_file(\"%V\") failed", path);
        return NGX_ERROR;
    }

    buf[(size_t) size] = '\0';
    *data = buf;
    *len = (size_t) size;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_parse_content(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules, u_char *data, size_t len)
{
    u_char                                 *p, *last, *line_start;
    ngx_str_t                              line, key, value, servers;
    ngx_uint_t                             line_no, indented;
    ngx_stream_trojan_dns_rule_group_t    *group;

    p = data;
    last = data + len;
    line_no = 1;
    group = NULL;

    while (p < last) {
        line_start = p;
        while (p < last && *p != '\n') {
            p++;
        }

        line.data = line_start;
        line.len = (size_t) (p - line_start);
        if (line.len && line.data[line.len - 1] == '\r') {
            line.len--;
        }

        if (p < last && *p == '\n') {
            p++;
        }

        line = ngx_stream_trojan_dns_rules_strip_comment(line);
        indented = line.len > 0
                   && (line.data[0] == ' ' || line.data[0] == '\t');
        line = ngx_stream_trojan_dns_rules_trim(line);

        if (line.len == 0) {
            line_no++;
            continue;
        }

        if (!indented) {
            if (line.data[line.len - 1] != ':') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trojan_dns_rules line %ui: "
                                   "expected DNS server group", line_no);
                return NGX_ERROR;
            }

            servers.data = line.data;
            servers.len = line.len - 1;
            servers = ngx_stream_trojan_dns_rules_trim(servers);

            if (servers.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trojan_dns_rules line %ui: "
                                   "empty DNS server group", line_no);
                return NGX_ERROR;
            }

            if (ngx_stream_trojan_dns_rules_parse_group(cf, rules, &servers,
                                                        line_no, &group)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            line_no++;
            continue;
        }

        if (group == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules line %ui: "
                               "directive without DNS server group", line_no);
            return NGX_ERROR;
        }

        if (line.data[0] == '-') {
            line.data++;
            line.len--;
            line = ngx_stream_trojan_dns_rules_trim(line);

            if (ngx_stream_trojan_dns_rules_parse_rule(cf, group, &line,
                                                       line_no)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            line_no++;
            continue;
        }

        if (ngx_stream_trojan_dns_rules_split_mapping(&line, &key, &value)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules line %ui", line_no);
            return NGX_ERROR;
        }

        if (ngx_stream_trojan_dns_rules_key_eq(&key, "strategy", 8)) {
            if (ngx_stream_trojan_dns_rules_parse_strategy(cf, group, &value,
                                                           line_no)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_dns_rules_key_eq(&key, "rules", 5)) {
            if (value.len != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trojan_dns_rules line %ui: "
                                   "rules must be a list", line_no);
                return NGX_ERROR;
            }

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown trojan_dns_rules key \"%V\" "
                               "on line %ui", &key, line_no);
            return NGX_ERROR;
        }

        line_no++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_parse_group(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules, ngx_str_t *servers,
    ngx_uint_t line_no, ngx_stream_trojan_dns_rule_group_t **group_p)
{
    u_char                                *p, *last, *start;
    ngx_uint_t                             n, i, doh;
    ngx_str_t                             *names, token, doh_url;
    ngx_stream_trojan_dns_rule_group_t    *group;

    n = 0;
    doh = 0;
    doh_url.data = NULL;
    doh_url.len = 0;

    p = servers->data;
    last = servers->data + servers->len;

    while (p <= last) {
        start = p;
        while (p < last && *p != ',') {
            p++;
        }

        token.data = start;
        token.len = (size_t) (p - start);
        token = ngx_stream_trojan_dns_rules_trim(token);

        if (token.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules line %ui: "
                               "empty DNS server", line_no);
            return NGX_ERROR;
        }

        n++;

        if (ngx_stream_trojan_dns_rules_is_doh_url(&token)) {
            doh = 1;
            doh_url = token;
        }

        if (p == last) {
            break;
        }
        p++;
    }

    if (doh) {
        if (n != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules line %ui: DoH URL "
                               "cannot be mixed with DNS servers", line_no);
            return NGX_ERROR;
        }

        group = ngx_stream_trojan_dns_rules_add_group(cf, rules);
        if (group == NULL) {
            return NGX_ERROR;
        }

        group->doh_conf = ngx_pcalloc(cf->pool,
                                      sizeof(ngx_stream_trojan_doh_conf_t));
        if (group->doh_conf == NULL) {
            return NGX_ERROR;
        }

        if (ngx_stream_trojan_doh_parse_url(&doh_url, group->doh_conf,
                                            cf->pool, cf->log)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules DoH URL on line %ui",
                               line_no);
            return NGX_ERROR;
        }

        *group_p = group;

        return NGX_OK;
    }

    names = ngx_pcalloc(cf->pool, n * sizeof(ngx_str_t));
    if (names == NULL) {
        return NGX_ERROR;
    }

    i = 0;
    p = servers->data;

    while (p <= last) {
        start = p;
        while (p < last && *p != ',') {
            p++;
        }

        token.data = start;
        token.len = (size_t) (p - start);
        token = ngx_stream_trojan_dns_rules_trim(token);

        if (ngx_stream_trojan_dns_rules_copy(cf, &token, &names[i], 0)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        i++;

        if (p == last) {
            break;
        }
        p++;
    }

    group = ngx_stream_trojan_dns_rules_add_group(cf, rules);
    if (group == NULL) {
        return NGX_ERROR;
    }

    group->resolver = ngx_resolver_create(cf, names, i);
    if (group->resolver == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "could not create trojan_dns_rules resolver "
                           "on line %ui", line_no);
        return NGX_ERROR;
    }

    *group_p = group;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_parse_strategy(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_group_t *group, ngx_str_t *value,
    ngx_uint_t line_no)
{
    if (group->strategy_set) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate trojan_dns_rules strategy "
                           "on line %ui", line_no);
        return NGX_ERROR;
    }

    if (value->len == 10
        && ngx_strncmp(value->data, "ipv4_first", 10) == 0)
    {
        group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV4;

    } else if (value->len == 10
               && ngx_strncmp(value->data, "ipv6_first", 10) == 0)
    {
        group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV6;

    } else if (value->len == 4
               && ngx_strncmp(value->data, "auto", 4) == 0)
    {
        group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;

    } else if (value->len == 4
               && ngx_strncmp(value->data, "ipv4", 4) == 0)
    {
        group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV4;

    } else if (value->len == 4
               && ngx_strncmp(value->data, "ipv6", 4) == 0)
    {
        group->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV6;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_dns_rules strategy \"%V\" "
                           "on line %ui", value, line_no);
        return NGX_ERROR;
    }

    group->strategy_set = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_parse_rule(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_group_t *group, ngx_str_t *line,
    ngx_uint_t line_no)
{
    ngx_str_t                       key, value;
    ngx_stream_trojan_dns_rule_t   *rule;
#if (NGX_PCRE)
    ngx_regex_compile_t             rc;
    u_char                          errstr[NGX_MAX_CONF_ERRSTR];
#endif

    if (ngx_stream_trojan_dns_rules_split_mapping(line, &key, &value)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_dns_rules rule on line %ui",
                           line_no);
        return NGX_ERROR;
    }

    if (value.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty trojan_dns_rules rule value on line %ui",
                           line_no);
        return NGX_ERROR;
    }

    rule = ngx_array_push(group->rules);
    if (rule == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_stream_trojan_dns_rule_t));

    if (ngx_stream_trojan_dns_rules_key_eq(&key, "domain", 6)) {
        rule->type = ngx_stream_trojan_dns_rule_domain;
        if (value.len > 255
            || ngx_stream_trojan_dns_rules_copy(cf, &value, &rule->value, 1)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (ngx_stream_trojan_dns_rules_key_eq(&key, "geosite", 7)) {
        rule->type = ngx_stream_trojan_dns_rule_geosite;
        if (ngx_stream_trojan_dns_rules_parse_geosite(cf, rule, &value,
                                                      line_no)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (ngx_stream_trojan_dns_rules_key_eq(&key, "regexp", 6)) {
        rule->type = ngx_stream_trojan_dns_rule_regexp;
        if (ngx_stream_trojan_dns_rules_copy(cf, &value, &rule->value, 0)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

#if (NGX_PCRE)
        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = rule->value;
        rc.pool = cf->pool;
        rc.options = NGX_REGEX_CASELESS;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_dns_rules regexp \"%V\" "
                               "on line %ui: %V", &rule->value, line_no,
                               &rc.err);
            return NGX_ERROR;
        }

        rule->regex = rc.regex;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_dns_rules regexp on line %ui requires "
                           "nginx built with PCRE", line_no);
        return NGX_ERROR;
#endif

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown trojan_dns_rules rule \"%V\" "
                           "on line %ui", &key, line_no);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_parse_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_t *rule, ngx_str_t *value, ngx_uint_t line_no)
{
    u_char     *p, *last;
    ngx_str_t   name, attr;

    name = *value;
    ngx_memzero(&attr, sizeof(ngx_str_t));

    p = value->data;
    last = value->data + value->len;

    while (p < last && *p != '@') {
        p++;
    }

    if (p < last) {
        name.len = (size_t) (p - value->data);
        attr.data = p + 1;
        attr.len = (size_t) (last - p - 1);

        if (attr.len && attr.data[0] == '!') {
            rule->attr_not = 1;
            attr.data++;
            attr.len--;
        }
    }

    if (name.len == 0 || name.len > 128 || attr.len > 128
        || (p < last && attr.len == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_dns_rules geosite value on line %ui",
                           line_no);
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_dns_rules_copy(cf, &name, &rule->value, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (attr.len
        && ngx_stream_trojan_dns_rules_copy(cf, &attr, &rule->attr, 1)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_trojan_dns_rules_validate(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules)
{
    ngx_uint_t                             i;
    ngx_stream_trojan_dns_rule_group_t    *groups;

    if (rules->groups->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_dns_rules file \"%V\" has no groups",
                           &rules->path);
        return NGX_ERROR;
    }

    groups = rules->groups->elts;
    for (i = 0; i < rules->groups->nelts; i++) {
        if (groups[i].rules == NULL || groups[i].rules->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_dns_rules file \"%V\" has a group "
                               "without rules", &rules->path);
            return NGX_ERROR;
        }

        if ((groups[i].resolver == NULL) == (groups[i].doh_conf == NULL)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_dns_rules file \"%V\" has an invalid "
                               "resolver group", &rules->path);
            return NGX_ERROR;
        }
    }


    return NGX_OK;
}


ngx_int_t
ngx_stream_trojan_dns_rules_prepare_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rules_conf_t *rules,
    ngx_stream_trojan_geosite_t *geosite)
{
    ngx_uint_t                             i, j;
    ngx_stream_trojan_dns_rule_group_t    *groups;
    ngx_stream_trojan_dns_rule_t          *rule;

    if (rules == NULL || rules->groups == NULL) {
        return NGX_OK;
    }

    groups = rules->groups->elts;
    for (i = 0; i < rules->groups->nelts; i++) {
        rule = groups[i].rules->elts;

        for (j = 0; j < groups[i].rules->nelts; j++) {
            if (rule[j].type != ngx_stream_trojan_dns_rule_geosite) {
                continue;
            }

            if (ngx_stream_trojan_dns_rules_prepare_rule_geosite(cf,
                                                                 &rule[j],
                                                                 geosite)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_prepare_rule_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_dns_rule_t *rule, ngx_stream_trojan_geosite_t *geosite)
{
    if (geosite == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_dns_rules uses geosite \"%V\" but "
                           "trojan_geosite is not configured", &rule->value);
        return NGX_ERROR;
    }

    rule->geosite = ngx_stream_trojan_geosite_find(geosite, &rule->value);
    if (rule->geosite == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geosite \"%V\" was not found in trojan_geosite",
                           &rule->value);
        return NGX_ERROR;
    }

    return ngx_stream_trojan_geosite_prepare_entry(cf, rule->geosite,
                                                   &rule->attr,
                                                   rule->attr_not);
}


ngx_stream_trojan_dns_rule_group_t *
ngx_stream_trojan_dns_rules_match(ngx_stream_trojan_dns_rules_conf_t *rules,
    const u_char *host, size_t host_len)
{
    ngx_uint_t                             i, j;
    ngx_stream_trojan_dns_rule_group_t    *groups;
    ngx_stream_trojan_dns_rule_t          *rule;

    if (rules == NULL || rules->groups == NULL
        || host == NULL || host_len == 0)
    {
        return NULL;
    }

    if (host_len > 1 && host[host_len - 1] == '.') {
        host_len--;
    }

    groups = rules->groups->elts;

    for (i = 0; i < rules->groups->nelts; i++) {
        rule = groups[i].rules->elts;

        for (j = 0; j < groups[i].rules->nelts; j++) {
            if (ngx_stream_trojan_dns_rules_match_rule(&rule[j], host,
                                                       host_len))
            {
                return &groups[i];
            }
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_match_rule(ngx_stream_trojan_dns_rule_t *rule,
    const u_char *host, size_t host_len)
{
#if (NGX_PCRE)
    ngx_str_t  name;
#endif

    switch (rule->type) {
    case ngx_stream_trojan_dns_rule_domain:
        return ngx_stream_trojan_dns_rules_match_domain(host, host_len,
                                                        &rule->value);

    case ngx_stream_trojan_dns_rule_geosite:
        return ngx_stream_trojan_geosite_match(rule->geosite, &rule->attr,
                                               rule->attr_not, host,
                                               host_len);

    case ngx_stream_trojan_dns_rule_regexp:
#if (NGX_PCRE)
        name.data = (u_char *) host;
        name.len = host_len;
        return ngx_regex_exec(rule->regex, &name, NULL, 0) >= 0;
#else
        return 0;
#endif
    }

    return 0;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_equal_ci(const u_char *host, ngx_str_t *value)
{
    size_t  i;

    for (i = 0; i < value->len; i++) {
        if (ngx_stream_trojan_dns_rules_lc(host[i]) != value->data[i]) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_stream_trojan_dns_rules_match_domain(const u_char *host, size_t host_len,
    ngx_str_t *domain)
{
    const u_char  *suffix;

    if (host_len < domain->len) {
        return 0;
    }

    suffix = host + host_len - domain->len;

    if (!ngx_stream_trojan_dns_rules_equal_ci(suffix, domain)) {
        return 0;
    }

    if (host_len == domain->len) {
        return 1;
    }

    return suffix > host && suffix[-1] == '.';
}


