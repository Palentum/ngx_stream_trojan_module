#include "ngx_stream_trojan_geosite.h"


#define NGX_STREAM_TROJAN_GEOSITE_MAX_FILE_SIZE   (64 * 1024 * 1024)
#define NGX_STREAM_TROJAN_GEOSITE_MAX_VALUE_LEN   4096
#define NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES 64



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


typedef struct ngx_stream_trojan_geosite_domain_s
    ngx_stream_trojan_geosite_domain_t;

struct ngx_stream_trojan_geosite_domain_s {
    ngx_uint_t   type;
    ngx_str_t    value;
    ngx_array_t *attrs;
    ngx_uint_t   order;
    ngx_stream_trojan_geosite_domain_t *next;
#if (NGX_PCRE)
    ngx_regex_t *regex;
#endif
};


typedef struct {
    ngx_uint_t   valid;
    ngx_uint_t   hash;
    ngx_str_t    value;
    ngx_stream_trojan_geosite_domain_t *domains;
    ngx_stream_trojan_geosite_domain_t *tail;
} ngx_stream_trojan_geosite_domain_index_t;


typedef struct {
    ngx_uint_t   valid;
    ngx_uint_t   accessed;
    size_t       host_len;
    u_char       host[256];
    ngx_uint_t   result;
} ngx_stream_trojan_geosite_cache_entry_t;


struct ngx_stream_trojan_geosite_entry_s {
    ngx_str_t    code;
    ngx_array_t *domains;
    ngx_stream_trojan_geosite_domain_index_t *full_index;
    ngx_uint_t   full_index_slots;
    ngx_stream_trojan_geosite_domain_index_t *domain_index;
    ngx_uint_t   domain_index_slots;
    ngx_stream_trojan_geosite_domain_t *plain_index[256];
    ngx_stream_trojan_geosite_domain_t **regex_domains;
    ngx_uint_t   regex_domains_n;
    ngx_uint_t   indexes_ready;
    ngx_stream_trojan_geosite_cache_entry_t
                 cache[NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES];
    ngx_uint_t   cache_generation;
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

static ngx_int_t
ngx_stream_trojan_geosite_cache_lookup(
    ngx_stream_trojan_geosite_entry_t *entry, const u_char *host,
    size_t host_len, ngx_uint_t *result)
{
    ngx_uint_t                                i;
    ngx_stream_trojan_geosite_cache_entry_t *e;

    if (host_len > 256) {
        return 0;
    }

    e = entry->cache;
    for (i = 0; i < NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES; i++) {
        if (!e[i].valid || e[i].host_len != host_len) {
            continue;
        }

        if (ngx_strncasecmp(e[i].host, (u_char *) host, host_len) == 0) {
            e[i].accessed = ++entry->cache_generation;
            *result = e[i].result;
            return 1;
        }
    }

    return 0;
}


static void
ngx_stream_trojan_geosite_cache_store(
    ngx_stream_trojan_geosite_entry_t *entry, const u_char *host,
    size_t host_len, ngx_uint_t result)
{
    ngx_uint_t                                i, oldest;
    ngx_stream_trojan_geosite_cache_entry_t *e, *slot;

    if (host_len > 256) {
        return;
    }

    e = entry->cache;
    slot = NULL;
    oldest = 0;

    for (i = 0; i < NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES; i++) {
        if (e[i].valid && e[i].host_len == host_len
            && ngx_strncasecmp(e[i].host, (u_char *) host, host_len) == 0)
        {
            slot = &e[i];
            break;
        }

        if (!e[i].valid) {
            slot = &e[i];
            break;
        }

        if (e[i].accessed < e[oldest].accessed) {
            oldest = i;
        }
    }

    if (slot == NULL) {
        slot = &e[oldest];
    }

    slot->valid = 0;
    slot->host_len = host_len;
    ngx_memcpy(slot->host, host, host_len);
    slot->result = result;
    slot->accessed = ++entry->cache_generation;
    slot->valid = 1;
}

static ngx_uint_t
ngx_stream_trojan_geosite_value_hash(const u_char *data, size_t len)
{
    size_t      i;
    ngx_uint_t hash;

    hash = 2166136261u;

    for (i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619;
    }

    return hash ? hash : 1;
}


static ngx_uint_t
ngx_stream_trojan_geosite_index_slots(ngx_uint_t count)
{
    ngx_uint_t  slots;

    slots = 16;
    while (slots < count * 4) {
        slots <<= 1;
    }

    return slots;
}


static ngx_stream_trojan_geosite_domain_index_t *
ngx_stream_trojan_geosite_index_find(
    ngx_stream_trojan_geosite_domain_index_t *index, ngx_uint_t slots,
    const u_char *value, size_t value_len, ngx_uint_t hash)
{
    ngx_uint_t                                i, idx;
    ngx_stream_trojan_geosite_domain_index_t *entry;

    if (index == NULL || slots == 0) {
        return NULL;
    }

    idx = hash % slots;

    for (i = 0; i < slots; i++) {
        entry = &index[(idx + i) % slots];

        if (!entry->valid) {
            return NULL;
        }

        if (entry->hash == hash
            && entry->value.len == value_len
            && ngx_memcmp(entry->value.data, value, value_len) == 0)
        {
            return entry;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_geosite_index_insert(
    ngx_stream_trojan_geosite_domain_index_t *index, ngx_uint_t slots,
    ngx_stream_trojan_geosite_domain_t *domain)
{
    ngx_uint_t                                i, idx, hash;
    ngx_stream_trojan_geosite_domain_index_t *entry;

    hash = ngx_stream_trojan_geosite_value_hash(domain->value.data,
                                                domain->value.len);
    idx = hash % slots;

    for (i = 0; i < slots; i++) {
        entry = &index[(idx + i) % slots];

        if (!entry->valid) {
            entry->valid = 1;
            entry->hash = hash;
            entry->value = domain->value;
            entry->domains = domain;
            entry->tail = domain;
            domain->next = NULL;
            return NGX_OK;
        }

        if (entry->hash == hash
            && entry->value.len == domain->value.len
            && ngx_memcmp(entry->value.data, domain->value.data,
                          domain->value.len)
               == 0)
        {
            entry->tail->next = domain;
            entry->tail = domain;
            domain->next = NULL;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
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
static ngx_int_t
ngx_stream_trojan_geosite_build_indexes(ngx_conf_t *cf,
    ngx_stream_trojan_geosite_entry_t *entry)
{
    ngx_uint_t                           i, full_count, domain_count;
    ngx_uint_t                           regex_count;
    ngx_stream_trojan_geosite_domain_t  *domains, *tail[256];
    u_char                               ch;

    if (entry->indexes_ready) {
        return NGX_OK;
    }

    full_count = 0;
    domain_count = 0;
    regex_count = 0;
    ngx_memzero(tail, sizeof(tail));

    domains = entry->domains->elts;
    for (i = 0; i < entry->domains->nelts; i++) {
        domains[i].order = i;
        domains[i].next = NULL;

        switch (domains[i].type) {
        case ngx_stream_trojan_geosite_full:
            full_count++;
            break;

        case ngx_stream_trojan_geosite_domain:
            domain_count++;
            break;

        case ngx_stream_trojan_geosite_regex:
            regex_count++;
            break;

        case ngx_stream_trojan_geosite_plain:
            if (domains[i].value.len != 0) {
                ch = ngx_stream_trojan_geosite_lc(domains[i].value.data[0]);
                if (tail[ch] == NULL) {
                    entry->plain_index[ch] = &domains[i];
                } else {
                    tail[ch]->next = &domains[i];
                }
                tail[ch] = &domains[i];
            }
            break;
        }
    }

    if (full_count != 0) {
        entry->full_index_slots =
            ngx_stream_trojan_geosite_index_slots(full_count);
        entry->full_index = ngx_pcalloc(cf->pool,
            entry->full_index_slots
            * sizeof(ngx_stream_trojan_geosite_domain_index_t));
        if (entry->full_index == NULL) {
            return NGX_ERROR;
        }
    }

    if (domain_count != 0) {
        entry->domain_index_slots =
            ngx_stream_trojan_geosite_index_slots(domain_count);
        entry->domain_index = ngx_pcalloc(cf->pool,
            entry->domain_index_slots
            * sizeof(ngx_stream_trojan_geosite_domain_index_t));
        if (entry->domain_index == NULL) {
            return NGX_ERROR;
        }
    }

    if (regex_count != 0) {
        entry->regex_domains = ngx_pcalloc(cf->pool,
            regex_count * sizeof(ngx_stream_trojan_geosite_domain_t *));
        if (entry->regex_domains == NULL) {
            return NGX_ERROR;
        }
    }

    for (i = 0; i < entry->domains->nelts; i++) {
        switch (domains[i].type) {
        case ngx_stream_trojan_geosite_full:
            if (ngx_stream_trojan_geosite_index_insert(entry->full_index,
                                                       entry->full_index_slots,
                                                       &domains[i])
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            break;

        case ngx_stream_trojan_geosite_domain:
            if (ngx_stream_trojan_geosite_index_insert(
                    entry->domain_index, entry->domain_index_slots,
                    &domains[i])
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            break;

        case ngx_stream_trojan_geosite_regex:
            entry->regex_domains[entry->regex_domains_n++] = &domains[i];
            break;
        }
    }

    entry->indexes_ready = 1;
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

    if (ngx_stream_trojan_geosite_build_indexes(cf, entry) != NGX_OK) {
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
static void
ngx_stream_trojan_geosite_consider_match(
    ngx_stream_trojan_geosite_domain_t *domain, ngx_str_t *attr,
    ngx_uint_t attr_not, ngx_uint_t *best_order)
{
    for (; domain != NULL; domain = domain->next) {
        if (domain->order >= *best_order) {
            continue;
        }

        if (ngx_stream_trojan_geosite_domain_attr_match(domain, attr,
                                                        attr_not))
        {
            *best_order = domain->order;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_geosite_match_indexed(
    ngx_stream_trojan_geosite_entry_t *entry, ngx_str_t *attr,
    ngx_uint_t attr_not, const u_char *host, size_t host_len,
    ngx_uint_t *order)
{
    u_char                                      seen[256];
    const u_char                              *suffix, *end, *p;
    size_t                                     suffix_len, i;
    ngx_uint_t                                 hash, best_order;
    ngx_stream_trojan_geosite_domain_index_t  *idx;
    ngx_stream_trojan_geosite_domain_t        *domain;
    u_char                                     ch;

    best_order = (ngx_uint_t) -1;

    hash = ngx_stream_trojan_geosite_value_hash(host, host_len);
    idx = ngx_stream_trojan_geosite_index_find(entry->full_index,
                                               entry->full_index_slots,
                                               host, host_len, hash);
    if (idx != NULL) {
        ngx_stream_trojan_geosite_consider_match(idx->domains, attr,
                                                 attr_not, &best_order);
    }

    suffix = host;
    end = host + host_len;

    for (;;) {
        suffix_len = (size_t) (end - suffix);
        hash = ngx_stream_trojan_geosite_value_hash(suffix, suffix_len);
        idx = ngx_stream_trojan_geosite_index_find(entry->domain_index,
                                                   entry->domain_index_slots,
                                                   suffix, suffix_len, hash);
        if (idx != NULL) {
            ngx_stream_trojan_geosite_consider_match(idx->domains, attr,
                                                     attr_not, &best_order);
        }

        p = ngx_strlchr((u_char *) suffix, (u_char *) end, '.');
        if (p == NULL) {
            break;
        }

        suffix = p + 1;
        if (suffix >= end) {
            break;
        }
    }

    ngx_memzero(seen, sizeof(seen));

    for (i = 0; i < host_len; i++) {
        ch = ngx_stream_trojan_geosite_lc(host[i]);
        if (seen[ch]) {
            continue;
        }
        seen[ch] = 1;

        for (domain = entry->plain_index[ch]; domain != NULL;
             domain = domain->next)
        {
            if (domain->order >= best_order
                || !ngx_stream_trojan_geosite_domain_attr_match(domain, attr,
                                                                attr_not))
            {
                continue;
            }

            if (ngx_stream_trojan_geosite_match_plain(host, host_len,
                                                      &domain->value))
            {
                best_order = domain->order;
            }
        }
    }

    *order = best_order;
    return best_order != (ngx_uint_t) -1;
}


ngx_int_t
ngx_stream_trojan_geosite_match(ngx_stream_trojan_geosite_entry_t *entry,
    ngx_str_t *attr, ngx_uint_t attr_not, const u_char *host, size_t host_len)
{
    u_char                              key[256];
    size_t                              key_len, i;
    ngx_uint_t                          indexed_order, indexed_match;
    ngx_uint_t                          cacheable, cached;
    ngx_stream_trojan_geosite_domain_t *domains;
#if (NGX_PCRE)
    ngx_stream_trojan_geosite_domain_t *domain;
    ngx_str_t                           name;
#endif

    if (entry == NULL || entry->domains == NULL
        || host == NULL || host_len == 0)
    {
        return 0;
    }

    cacheable = (attr == NULL || attr->len == 0) && !attr_not;
    if (cacheable
        && ngx_stream_trojan_geosite_cache_lookup(entry, host, host_len,
                                                  &cached))
    {
        return cached;
    }

    indexed_match = 0;
    indexed_order = (ngx_uint_t) -1;
    key_len = 0;

    if (host_len <= sizeof(key)) {
        for (i = 0; i < host_len; i++) {
            key[i] = ngx_stream_trojan_geosite_lc(host[i]);
        }
        key_len = host_len;

        if (entry->indexes_ready) {
            indexed_match = ngx_stream_trojan_geosite_match_indexed(
                entry, attr, attr_not, key, key_len, &indexed_order);
        }
    }

    if (key_len != 0 && entry->indexes_ready) {
#if (NGX_PCRE)
        name.data = key;
        name.len = key_len;

        for (i = 0; i < entry->regex_domains_n; i++) {
            domain = entry->regex_domains[i];

            if (indexed_match && domain->order > indexed_order) {
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }

            if (domain->regex == NULL
                || !ngx_stream_trojan_geosite_domain_attr_match(domain, attr,
                                                                attr_not))
            {
                continue;
            }

            if (ngx_regex_exec(domain->regex, &name, NULL, 0) >= 0) {
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }
        }
#endif

        if (indexed_match) {
            if (cacheable) {
                ngx_stream_trojan_geosite_cache_store(entry, host, host_len,
                                                      1);
            }
            return 1;
        }

        if (cacheable) {
            ngx_stream_trojan_geosite_cache_store(entry, host, host_len, 0);
        }
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
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }
            break;

        case ngx_stream_trojan_geosite_regex:
#if (NGX_PCRE)
            if (domains[i].regex == NULL) {
                break;
            }

            name.data = key_len != 0 ? key : (u_char *) host;
            name.len = key_len != 0 ? key_len : host_len;
            if (ngx_regex_exec(domains[i].regex, &name, NULL, 0) >= 0) {
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }
#endif
            break;

        case ngx_stream_trojan_geosite_domain:
            if (ngx_stream_trojan_geosite_match_domain(host, host_len,
                                                       &domains[i].value))
            {
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }
            break;

        case ngx_stream_trojan_geosite_full:
            if (host_len == domains[i].value.len
                && ngx_stream_trojan_geosite_equal_ci(host, &domains[i].value))
            {
                if (cacheable) {
                    ngx_stream_trojan_geosite_cache_store(entry, host,
                                                          host_len, 1);
                }
                return 1;
            }
            break;
        }
    }

    if (cacheable) {
        ngx_stream_trojan_geosite_cache_store(entry, host, host_len, 0);
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
