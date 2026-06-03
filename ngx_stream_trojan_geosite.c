#include "ngx_stream_trojan_geosite.h"


#define NGX_STREAM_TROJAN_GEOSITE_MAX_FILE_SIZE   (64 * 1024 * 1024)
#define NGX_STREAM_TROJAN_GEOSITE_MAX_VALUE_LEN   4096


typedef enum {
    ngx_stream_trojan_geosite_plain = 0,
    ngx_stream_trojan_geosite_regex = 1,
    ngx_stream_trojan_geosite_domain = 2,
    ngx_stream_trojan_geosite_full = 3
} ngx_stream_trojan_geosite_domain_type_e;


typedef struct {
    u_char      *pos;
    u_char      *last;
} ngx_stream_trojan_geosite_reader_t;


typedef struct {
    ngx_uint_t   type;
    ngx_str_t    value;
    ngx_array_t *attrs;
#if (NGX_PCRE)
    ngx_regex_t *regex;
#endif
} ngx_stream_trojan_geosite_domain_t;


struct ngx_stream_trojan_geosite_entry_s {
    ngx_str_t    code;
    ngx_array_t *domains;
};


struct ngx_stream_trojan_geosite_s {
    ngx_array_t *entries;
    ngx_str_t    path;
};


static ngx_int_t ngx_stream_trojan_geosite_read_file(ngx_conf_t *cf,
    ngx_str_t *path, u_char **data, size_t *len);
static ngx_int_t ngx_stream_trojan_geosite_parse(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geosite_parse_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geosite_parse_domain(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_entry_t *entry, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geosite_parse_attr(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_domain_t *domain, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geosite_validate(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite);
static ngx_int_t ngx_stream_trojan_geosite_read_varint(
    ngx_stream_trojan_geosite_reader_t *r, uint64_t *value);
static ngx_int_t ngx_stream_trojan_geosite_read_bytes(
    ngx_stream_trojan_geosite_reader_t *r, u_char **data, size_t *len);
static ngx_int_t ngx_stream_trojan_geosite_skip(
    ngx_stream_trojan_geosite_reader_t *r, ngx_uint_t wire);
static ngx_int_t ngx_stream_trojan_geosite_copy(ngx_conf_t *cf,
    u_char *data, size_t len, ngx_str_t *dst, ngx_uint_t lower);
static ngx_int_t ngx_stream_trojan_geosite_domain_attr_match(
    ngx_stream_trojan_geosite_domain_t *domain, ngx_str_t *attr,
    ngx_uint_t attr_not);
static ngx_int_t ngx_stream_trojan_geosite_match_domain(const u_char *host,
    size_t host_len, ngx_str_t *domain);
static ngx_int_t ngx_stream_trojan_geosite_match_plain(const u_char *host,
    size_t host_len, ngx_str_t *keyword);
static ngx_int_t ngx_stream_trojan_geosite_equal_ci(const u_char *host,
    ngx_str_t *value);


static u_char
ngx_stream_trojan_geosite_lc(u_char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (u_char) (ch | 0x20);
    }

    return ch;
}


char *
ngx_stream_trojan_geosite_load(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_geosite_t **geosite_p)
{
    u_char                       *data;
    size_t                        len;
    ngx_str_t                     full;
    ngx_stream_trojan_geosite_t  *geosite;

    if (geosite_p == NULL) {
        return NGX_CONF_ERROR;
    }

    full = *path;
    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_geosite_read_file(cf, &full, &data, &len)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    geosite = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_geosite_t));
    if (geosite == NULL) {
        return NGX_CONF_ERROR;
    }

    geosite->entries = ngx_array_create(cf->pool, 128,
                                        sizeof(ngx_stream_trojan_geosite_entry_t));
    if (geosite->entries == NULL) {
        return NGX_CONF_ERROR;
    }

    geosite->path = full;

    if (ngx_stream_trojan_geosite_parse(cf, geosite, data, len) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_geosite_validate(cf, geosite) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *geosite_p = geosite;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_read_file(ngx_conf_t *cf, ngx_str_t *path,
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
                           "could not open trojan_geosite file \"%V\"",
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
    if (size <= 0 || size > NGX_STREAM_TROJAN_GEOSITE_MAX_FILE_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_geosite file \"%V\" has invalid size",
                           path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(cf->pool, (size_t) size);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, (size_t) size);
    if (n == -1 || (size_t) n != (size_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "could not read trojan_geosite file \"%V\"",
                           path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "ngx_close_file(\"%V\") failed", path);
        return NGX_ERROR;
    }

    *data = buf;
    *len = (size_t) size;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_parse(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite, u_char *data, size_t len)
{
    uint64_t                              tag;
    ngx_uint_t                            field, wire;
    u_char                               *value;
    size_t                                value_len;
    ngx_stream_trojan_geosite_reader_t    r;

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geosite_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_geosite file \"%V\"",
                               &geosite->path);
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || ngx_stream_trojan_geosite_parse_entry(cf, geosite, value,
                                                         value_len)
                   != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trojan_geosite entry in \"%V\"",
                                   &geosite->path);
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geosite_skip(&r, wire) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_geosite field in \"%V\"",
                               &geosite->path);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_parse_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite, u_char *data, size_t len)
{
    uint64_t                              tag;
    ngx_uint_t                            field, wire;
    u_char                               *value;
    size_t                                value_len;
    ngx_stream_trojan_geosite_entry_t    *entry;
    ngx_stream_trojan_geosite_reader_t    r;

    entry = ngx_array_push(geosite->entries);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(entry, sizeof(ngx_stream_trojan_geosite_entry_t));
    entry->domains = ngx_array_create(cf->pool, 16,
                                      sizeof(ngx_stream_trojan_geosite_domain_t));
    if (entry->domains == NULL) {
        return NGX_ERROR;
    }

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geosite_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (entry->code.len != 0
                || ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                   != NGX_OK
                || value_len == 0 || value_len > 128
                || ngx_stream_trojan_geosite_copy(cf, value, value_len,
                                                  &entry->code, 1)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (field == 2 && wire == 2) {
            if (ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || ngx_stream_trojan_geosite_parse_domain(cf, entry, value,
                                                          value_len)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geosite_skip(&r, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return entry->code.len != 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_geosite_parse_domain(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_entry_t *entry, u_char *data, size_t len)
{
    uint64_t                              tag, value64;
    ngx_uint_t                            field, wire;
    u_char                               *value;
    size_t                                value_len, i;
    ngx_stream_trojan_geosite_domain_t    temp, *domain;
    ngx_stream_trojan_geosite_reader_t    r;

    ngx_memzero(&temp, sizeof(ngx_stream_trojan_geosite_domain_t));
    temp.type = ngx_stream_trojan_geosite_plain;

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geosite_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 0) {
            if (ngx_stream_trojan_geosite_read_varint(&r, &value64) != NGX_OK
                || value64 > ngx_stream_trojan_geosite_full)
            {
                return NGX_ERROR;
            }
            temp.type = (ngx_uint_t) value64;

        } else if (field == 2 && wire == 2) {
            if (ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || value_len == 0
                || value_len > NGX_STREAM_TROJAN_GEOSITE_MAX_VALUE_LEN
                || ngx_stream_trojan_geosite_copy(cf, value, value_len,
                                                  &temp.value, 0)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (field == 3 && wire == 2) {
            if (ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || ngx_stream_trojan_geosite_parse_attr(cf, &temp, value,
                                                        value_len)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geosite_skip(&r, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (temp.value.len == 0) {
        return NGX_ERROR;
    }

    if (temp.type != ngx_stream_trojan_geosite_regex) {
        for (i = 0; i < temp.value.len; i++) {
            temp.value.data[i] = ngx_stream_trojan_geosite_lc(temp.value.data[i]);
        }
    }

    domain = ngx_array_push(entry->domains);
    if (domain == NULL) {
        return NGX_ERROR;
    }

    *domain = temp;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_parse_attr(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_domain_t *domain, u_char *data, size_t len)
{
    uint64_t                              tag;
    ngx_uint_t                            field, wire;
    u_char                               *value;
    size_t                                value_len;
    ngx_str_t                             key, *slot;
    ngx_stream_trojan_geosite_reader_t    r;

    ngx_memzero(&key, sizeof(ngx_str_t));
    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geosite_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (ngx_stream_trojan_geosite_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || value_len == 0 || value_len > 128
                || ngx_stream_trojan_geosite_copy(cf, value, value_len,
                                                  &key, 1)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geosite_skip(&r, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (key.len == 0) {
        return NGX_OK;
    }

    if (domain->attrs == NULL) {
        domain->attrs = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (domain->attrs == NULL) {
            return NGX_ERROR;
        }
    }

    slot = ngx_array_push(domain->attrs);
    if (slot == NULL) {
        return NGX_ERROR;
    }

    *slot = key;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_validate(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_t *geosite)
{
    ngx_uint_t                          i, j;
    ngx_stream_trojan_geosite_entry_t  *entries;

    if (geosite->entries->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_geosite file \"%V\" has no entries",
                           &geosite->path);
        return NGX_ERROR;
    }

    entries = geosite->entries->elts;
    for (i = 0; i < geosite->entries->nelts; i++) {
        if (entries[i].domains == NULL) {
            return NGX_ERROR;
        }

        for (j = i + 1; j < geosite->entries->nelts; j++) {
            if (entries[i].code.len == entries[j].code.len
                && ngx_strncmp(entries[i].code.data, entries[j].code.data,
                               entries[i].code.len)
                   == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate geosite entry \"%V\" in \"%V\"",
                                   &entries[i].code, &geosite->path);
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


ngx_stream_trojan_geosite_entry_t *
ngx_stream_trojan_geosite_find(ngx_stream_trojan_geosite_t *geosite,
    ngx_str_t *code)
{
    ngx_uint_t                          i;
    ngx_stream_trojan_geosite_entry_t  *entries;

    if (geosite == NULL || geosite->entries == NULL || code->len == 0) {
        return NULL;
    }

    entries = geosite->entries->elts;
    for (i = 0; i < geosite->entries->nelts; i++) {
        if (entries[i].code.len == code->len
            && ngx_strncmp(entries[i].code.data, code->data, code->len) == 0)
        {
            return &entries[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_stream_trojan_geosite_prepare_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_entry_t *entry, ngx_str_t *attr,
    ngx_uint_t attr_not)
{
    ngx_uint_t                           i;
    ngx_stream_trojan_geosite_domain_t  *domains;
#if (NGX_PCRE)
    ngx_regex_compile_t                  rc;
    u_char                               errstr[NGX_MAX_CONF_ERRSTR];
#endif

    if (entry == NULL || entry->domains == NULL) {
        return NGX_ERROR;
    }

    domains = entry->domains->elts;
    for (i = 0; i < entry->domains->nelts; i++) {
        if (domains[i].type != ngx_stream_trojan_geosite_regex
            || !ngx_stream_trojan_geosite_domain_attr_match(&domains[i], attr,
                                                            attr_not))
        {
            continue;
        }

#if (NGX_PCRE)
        if (domains[i].regex != NULL) {
            continue;
        }

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = domains[i].value;
        rc.pool = cf->pool;
        rc.options = NGX_REGEX_CASELESS;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid regexp in geosite \"%V\": %V",
                               &entry->code, &rc.err);
            return NGX_ERROR;
        }

        domains[i].regex = rc.regex;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geosite \"%V\" contains regexp rules but nginx "
                           "was built without PCRE", &entry->code);
        return NGX_ERROR;
#endif
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_trojan_geosite_match(ngx_stream_trojan_geosite_entry_t *entry,
    ngx_str_t *attr, ngx_uint_t attr_not, const u_char *host, size_t host_len)
{
    ngx_uint_t                           i;
    ngx_stream_trojan_geosite_domain_t  *domains;
#if (NGX_PCRE)
    ngx_str_t                            name;
#endif

    if (entry == NULL || entry->domains == NULL
        || host == NULL || host_len == 0)
    {
        return 0;
    }

    domains = entry->domains->elts;
    for (i = 0; i < entry->domains->nelts; i++) {
        if (!ngx_stream_trojan_geosite_domain_attr_match(&domains[i], attr,
                                                         attr_not))
        {
            continue;
        }

        switch (domains[i].type) {
        case ngx_stream_trojan_geosite_plain:
            if (ngx_stream_trojan_geosite_match_plain(host, host_len,
                                                      &domains[i].value))
            {
                return 1;
            }
            break;

        case ngx_stream_trojan_geosite_regex:
#if (NGX_PCRE)
            if (domains[i].regex == NULL) {
                break;
            }

            name.data = (u_char *) host;
            name.len = host_len;
            if (ngx_regex_exec(domains[i].regex, &name, NULL, 0) >= 0) {
                return 1;
            }
#endif
            break;

        case ngx_stream_trojan_geosite_domain:
            if (ngx_stream_trojan_geosite_match_domain(host, host_len,
                                                       &domains[i].value))
            {
                return 1;
            }
            break;

        case ngx_stream_trojan_geosite_full:
            if (host_len == domains[i].value.len
                && ngx_stream_trojan_geosite_equal_ci(host, &domains[i].value))
            {
                return 1;
            }
            break;
        }
    }

    return 0;
}


static ngx_int_t
ngx_stream_trojan_geosite_domain_attr_match(
    ngx_stream_trojan_geosite_domain_t *domain, ngx_str_t *attr,
    ngx_uint_t attr_not)
{
    ngx_uint_t  i;
    ngx_str_t  *attrs;
    ngx_uint_t  found;

    if (attr == NULL || attr->len == 0) {
        return 1;
    }

    found = 0;

    if (domain->attrs != NULL) {
        attrs = domain->attrs->elts;
        for (i = 0; i < domain->attrs->nelts; i++) {
            if (attrs[i].len == attr->len
                && ngx_strncmp(attrs[i].data, attr->data, attr->len) == 0)
            {
                found = 1;
                break;
            }
        }
    }

    return attr_not ? !found : found;
}


static ngx_int_t
ngx_stream_trojan_geosite_match_domain(const u_char *host, size_t host_len,
    ngx_str_t *domain)
{
    const u_char  *suffix;

    if (host_len < domain->len) {
        return 0;
    }

    suffix = host + host_len - domain->len;

    if (!ngx_stream_trojan_geosite_equal_ci(suffix, domain)) {
        return 0;
    }

    if (host_len == domain->len) {
        return 1;
    }

    return suffix > host && suffix[-1] == '.';
}


static ngx_int_t
ngx_stream_trojan_geosite_match_plain(const u_char *host, size_t host_len,
    ngx_str_t *keyword)
{
    size_t  i, j;

    if (keyword->len == 0 || host_len < keyword->len) {
        return 0;
    }

    for (i = 0; i <= host_len - keyword->len; i++) {
        for (j = 0; j < keyword->len; j++) {
            if (ngx_stream_trojan_geosite_lc(host[i + j])
                != keyword->data[j])
            {
                break;
            }
        }

        if (j == keyword->len) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_stream_trojan_geosite_equal_ci(const u_char *host, ngx_str_t *value)
{
    size_t  i;

    for (i = 0; i < value->len; i++) {
        if (ngx_stream_trojan_geosite_lc(host[i]) != value->data[i]) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_stream_trojan_geosite_read_varint(
    ngx_stream_trojan_geosite_reader_t *r, uint64_t *value)
{
    uint64_t    result;
    ngx_uint_t  shift, i;
    u_char      ch;

    result = 0;
    shift = 0;

    for (i = 0; i < 10; i++) {
        if (r->pos == r->last) {
            return NGX_ERROR;
        }

        ch = *r->pos++;
        result |= ((uint64_t) (ch & 0x7f)) << shift;

        if ((ch & 0x80) == 0) {
            *value = result;
            return NGX_OK;
        }

        shift += 7;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_geosite_read_bytes(ngx_stream_trojan_geosite_reader_t *r,
    u_char **data, size_t *len)
{
    uint64_t  n;

    if (ngx_stream_trojan_geosite_read_varint(r, &n) != NGX_OK
        || n > (uint64_t) (r->last - r->pos))
    {
        return NGX_ERROR;
    }

    *data = r->pos;
    *len = (size_t) n;
    r->pos += (size_t) n;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geosite_skip(ngx_stream_trojan_geosite_reader_t *r,
    ngx_uint_t wire)
{
    uint64_t  n;

    switch (wire) {
    case 0:
        return ngx_stream_trojan_geosite_read_varint(r, &n);

    case 1:
        if ((size_t) (r->last - r->pos) < 8) {
            return NGX_ERROR;
        }
        r->pos += 8;
        return NGX_OK;

    case 2:
        if (ngx_stream_trojan_geosite_read_varint(r, &n) != NGX_OK
            || n > (uint64_t) (r->last - r->pos))
        {
            return NGX_ERROR;
        }
        r->pos += (size_t) n;
        return NGX_OK;

    case 5:
        if ((size_t) (r->last - r->pos) < 4) {
            return NGX_ERROR;
        }
        r->pos += 4;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_geosite_copy(ngx_conf_t *cf, u_char *data, size_t len,
    ngx_str_t *dst, ngx_uint_t lower)
{
    size_t  i;

    dst->data = ngx_pnalloc(cf->pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        dst->data[i] = lower ? ngx_stream_trojan_geosite_lc(data[i]) : data[i];
    }

    dst->data[len] = '\0';
    dst->len = len;

    return NGX_OK;
}
