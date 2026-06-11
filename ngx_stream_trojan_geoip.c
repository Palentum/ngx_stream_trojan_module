#include "ngx_stream_trojan_geoip.h"


#define NGX_STREAM_TROJAN_GEOIP_MAX_FILE_SIZE  (64 * 1024 * 1024)


typedef struct {
    u_char      *pos;
    u_char      *last;
} ngx_stream_trojan_geoip_reader_t;


typedef struct {
    u_char       addr[16];
    size_t       addr_len;
    ngx_uint_t   prefix;
} ngx_stream_trojan_geoip_cidr_t;


struct ngx_stream_trojan_geoip_entry_s {
    ngx_str_t    code;
    ngx_array_t *cidrs;
    ngx_radix_tree_t *tree4;
#if (NGX_HAVE_INET6)
    ngx_radix_tree_t *tree6;
#endif
    ngx_uint_t   prepared;
};


struct ngx_stream_trojan_geoip_s {
    ngx_array_t *entries;
    ngx_str_t    path;
};


static ngx_int_t ngx_stream_trojan_geoip_read_file(ngx_conf_t *cf,
    ngx_str_t *path, u_char **data, size_t *len);
static ngx_int_t ngx_stream_trojan_geoip_parse(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geoip_parse_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geoip_parse_cidr(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_geoip_validate(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip);
static ngx_int_t ngx_stream_trojan_geoip_read_varint(
    ngx_stream_trojan_geoip_reader_t *r, uint64_t *value);
static ngx_int_t ngx_stream_trojan_geoip_read_bytes(
    ngx_stream_trojan_geoip_reader_t *r, u_char **data, size_t *len);
static ngx_int_t ngx_stream_trojan_geoip_skip(
    ngx_stream_trojan_geoip_reader_t *r, ngx_uint_t wire);
static ngx_int_t ngx_stream_trojan_geoip_copy(ngx_conf_t *cf,
    u_char *data, size_t len, ngx_str_t *dst, ngx_uint_t lower);
static ngx_int_t ngx_stream_trojan_geoip_build_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry);
static ngx_int_t ngx_stream_trojan_geoip_insert_cidr(
    ngx_stream_trojan_geoip_entry_t *entry,
    ngx_stream_trojan_geoip_cidr_t *cidr);


static u_char
ngx_stream_trojan_geoip_lc(u_char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (u_char) (ch | 0x20);
    }

    return ch;
}


char *
ngx_stream_trojan_geoip_load(ngx_conf_t *cf, ngx_str_t *path,
    ngx_stream_trojan_geoip_t **geoip_p)
{
    u_char                     *data;
    size_t                      len;
    ngx_str_t                   full;
    ngx_stream_trojan_geoip_t  *geoip;

    if (geoip_p == NULL) {
        return NGX_CONF_ERROR;
    }

    full = *path;
    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_geoip_read_file(cf, &full, &data, &len) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    geoip = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_geoip_t));
    if (geoip == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip->entries = ngx_array_create(cf->pool, 128,
                                      sizeof(ngx_stream_trojan_geoip_entry_t));
    if (geoip->entries == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip->path = full;

    if (ngx_stream_trojan_geoip_parse(cf, geoip, data, len) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_geoip_validate(cf, geoip) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *geoip_p = geoip;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_read_file(ngx_conf_t *cf, ngx_str_t *path,
    u_char **data, size_t *len)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;
    off_t            size;
    ssize_t          n;
    u_char          *buf;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "could not open trojan_geoip file \"%V\"", path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "ngx_fd_info(\"%V\") failed", path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = ngx_file_size(&fi);
    if (size <= 0 || size > NGX_STREAM_TROJAN_GEOIP_MAX_FILE_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_geoip file \"%V\" has invalid size %O",
                           path, size);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(cf->pool, (size_t) size);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, (size_t) size);
    ngx_close_file(fd);

    if (n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "could not read trojan_geoip file \"%V\"", path);
        return NGX_ERROR;
    }

    *data = buf;
    *len = (size_t) size;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_parse(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip, u_char *data, size_t len)
{
    uint64_t                         tag;
    ngx_uint_t                       field, wire;
    u_char                          *value;
    size_t                           value_len;
    ngx_stream_trojan_geoip_reader_t r;

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geoip_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (ngx_stream_trojan_geoip_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || ngx_stream_trojan_geoip_parse_entry(cf, geoip, value,
                                                       value_len)
                   != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trojan_geoip entry in \"%V\"",
                                   &geoip->path);
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geoip_skip(&r, wire) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_geoip field in \"%V\"",
                               &geoip->path);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_parse_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip, u_char *data, size_t len)
{
    uint64_t                         tag;
    ngx_uint_t                       field, wire;
    u_char                          *value;
    size_t                           value_len;
    ngx_stream_trojan_geoip_entry_t *entry;
    ngx_stream_trojan_geoip_reader_t r;

    entry = ngx_array_push(geoip->entries);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(entry, sizeof(ngx_stream_trojan_geoip_entry_t));
    entry->cidrs = ngx_array_create(cf->pool, 16,
                                    sizeof(ngx_stream_trojan_geoip_cidr_t));
    if (entry->cidrs == NULL) {
        return NGX_ERROR;
    }

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geoip_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (entry->code.len != 0
                || ngx_stream_trojan_geoip_read_bytes(&r, &value, &value_len)
                   != NGX_OK
                || value_len == 0 || value_len > 128
                || ngx_stream_trojan_geoip_copy(cf, value, value_len,
                                                &entry->code, 1)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (field == 2 && wire == 2) {
            if (ngx_stream_trojan_geoip_read_bytes(&r, &value, &value_len)
                != NGX_OK
                || ngx_stream_trojan_geoip_parse_cidr(cf, entry, value,
                                                      value_len)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_stream_trojan_geoip_skip(&r, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return entry->code.len != 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_geoip_parse_cidr(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry, u_char *data, size_t len)
{
    uint64_t                           tag, value64;
    ngx_uint_t                         field, wire, prefix_set;
    u_char                            *value;
    size_t                             value_len;
    ngx_stream_trojan_geoip_cidr_t     temp, *cidr;
    ngx_stream_trojan_geoip_reader_t   r;

    ngx_memzero(&temp, sizeof(ngx_stream_trojan_geoip_cidr_t));
    prefix_set = 0;

    r.pos = data;
    r.last = data + len;

    while (r.pos < r.last) {
        if (ngx_stream_trojan_geoip_read_varint(&r, &tag) != NGX_OK
            || tag == 0)
        {
            return NGX_ERROR;
        }

        field = (ngx_uint_t) (tag >> 3);
        wire = (ngx_uint_t) (tag & 7);

        if (field == 1 && wire == 2) {
            if (temp.addr_len != 0
                || ngx_stream_trojan_geoip_read_bytes(&r, &value, &value_len)
                   != NGX_OK
                || (value_len != 4 && value_len != 16))
            {
                return NGX_ERROR;
            }

            ngx_memcpy(temp.addr, value, value_len);
            temp.addr_len = value_len;

        } else if (field == 2 && wire == 0) {
            if (ngx_stream_trojan_geoip_read_varint(&r, &value64) != NGX_OK
                || value64 > 128)
            {
                return NGX_ERROR;
            }

            temp.prefix = (ngx_uint_t) value64;
            prefix_set = 1;

        } else if (ngx_stream_trojan_geoip_skip(&r, wire) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (temp.addr_len == 0 || !prefix_set) {
        return NGX_ERROR;
    }

    if ((temp.addr_len == 4 && temp.prefix > 32)
        || (temp.addr_len == 16 && temp.prefix > 128))
    {
        return NGX_ERROR;
    }

    cidr = ngx_array_push(entry->cidrs);
    if (cidr == NULL) {
        return NGX_ERROR;
    }

    *cidr = temp;

    (void) cf;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_validate(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_t *geoip)
{
    ngx_uint_t                         i, j;
    ngx_stream_trojan_geoip_entry_t   *entries;

    if (geoip->entries->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_geoip file \"%V\" has no entries",
                           &geoip->path);
        return NGX_ERROR;
    }

    entries = geoip->entries->elts;
    for (i = 0; i < geoip->entries->nelts; i++) {
        if (entries[i].cidrs == NULL || entries[i].cidrs->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_geoip file \"%V\" has entry \"%V\" "
                               "without CIDR ranges", &geoip->path,
                               &entries[i].code);
            return NGX_ERROR;
        }

        for (j = i + 1; j < geoip->entries->nelts; j++) {
            if (entries[i].code.len == entries[j].code.len
                && ngx_strncmp(entries[i].code.data, entries[j].code.data,
                               entries[i].code.len)
                   == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate geoip entry \"%V\" in \"%V\"",
                                   &entries[i].code, &geoip->path);
                return NGX_ERROR;
            }
        }

    }

    return NGX_OK;
}


ngx_stream_trojan_geoip_entry_t *
ngx_stream_trojan_geoip_find(ngx_stream_trojan_geoip_t *geoip,
    ngx_str_t *code)
{
    ngx_uint_t                         i;
    ngx_stream_trojan_geoip_entry_t   *entries;

    if (geoip == NULL || geoip->entries == NULL || code->len == 0) {
        return NULL;
    }

    entries = geoip->entries->elts;
    for (i = 0; i < geoip->entries->nelts; i++) {
        if (entries[i].code.len == code->len
            && ngx_strncmp(entries[i].code.data, code->data, code->len) == 0)
        {
            return &entries[i];
        }
    }

    return NULL;
}


static uint32_t
ngx_stream_trojan_geoip_ipv4_key(const u_char *addr)
{
    return ((uint32_t) addr[0] << 24)
           | ((uint32_t) addr[1] << 16)
           | ((uint32_t) addr[2] << 8)
           | (uint32_t) addr[3];
}


static uint32_t
ngx_stream_trojan_geoip_ipv4_mask(ngx_uint_t prefix)
{
    return prefix == 0 ? 0 : (uint32_t) (0xffffffffu << (32 - prefix));
}


#if (NGX_HAVE_INET6)
static void
ngx_stream_trojan_geoip_ipv6_mask(u_char *mask, ngx_uint_t prefix)
{
    ngx_uint_t  i, full, rest;

    ngx_memzero(mask, 16);

    full = prefix / 8;
    rest = prefix % 8;

    for (i = 0; i < full; i++) {
        mask[i] = 0xff;
    }

    if (rest) {
        mask[full] = (u_char) (0xff << (8 - rest));
    }
}
#endif


ngx_int_t
ngx_stream_trojan_geoip_prepare_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry)
{
    if (entry == NULL) {
        return NGX_ERROR;
    }

    if (entry->prepared) {
        return NGX_OK;
    }

    if (ngx_stream_trojan_geoip_build_entry(cf, entry) != NGX_OK) {
        return NGX_ERROR;
    }

    entry->prepared = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_build_entry(ngx_conf_t *cf,
    ngx_stream_trojan_geoip_entry_t *entry)
{
    ngx_uint_t                       i;
    ngx_stream_trojan_geoip_cidr_t  *cidrs;

    entry->tree4 = ngx_radix_tree_create(cf->pool, -1);
    if (entry->tree4 == NULL) {
        return NGX_ERROR;
    }

#if (NGX_HAVE_INET6)
    entry->tree6 = ngx_radix_tree_create(cf->pool, -1);
    if (entry->tree6 == NULL) {
        return NGX_ERROR;
    }
#endif

    cidrs = entry->cidrs->elts;
    for (i = 0; i < entry->cidrs->nelts; i++) {
        if (ngx_stream_trojan_geoip_insert_cidr(entry, &cidrs[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_insert_cidr(ngx_stream_trojan_geoip_entry_t *entry,
    ngx_stream_trojan_geoip_cidr_t *cidr)
{
    ngx_int_t  rc;
    uint32_t   key, mask4;
#if (NGX_HAVE_INET6)
    ngx_uint_t i;
    u_char     key6[16], mask6[16];
#endif

    if (cidr->addr_len == 4) {
        mask4 = ngx_stream_trojan_geoip_ipv4_mask(cidr->prefix);
        key = ngx_stream_trojan_geoip_ipv4_key(cidr->addr) & mask4;

        rc = ngx_radix32tree_insert(entry->tree4, key, mask4, 1);
        return rc == NGX_OK || rc == NGX_BUSY ? NGX_OK : NGX_ERROR;
    }

#if (NGX_HAVE_INET6)
    ngx_stream_trojan_geoip_ipv6_mask(mask6, cidr->prefix);
    ngx_memcpy(key6, cidr->addr, 16);

    for (i = 0; i < 16; i++) {
        key6[i] &= mask6[i];
    }

    rc = ngx_radix128tree_insert(entry->tree6, key6, mask6, 1);
    return rc == NGX_OK || rc == NGX_BUSY ? NGX_OK : NGX_ERROR;
#else
    return NGX_OK;
#endif
}


ngx_int_t
ngx_stream_trojan_geoip_match(ngx_stream_trojan_geoip_entry_t *entry,
    const u_char *addr, size_t addr_len)
{
    uint32_t  key;

    if (entry == NULL || addr == NULL || (addr_len != 4 && addr_len != 16)) {
        return 0;
    }

    if (addr_len == 4) {
        if (entry->tree4 == NULL) {
            return 0;
        }

        key = ngx_stream_trojan_geoip_ipv4_key(addr);
        return ngx_radix32tree_find(entry->tree4, key) != NGX_RADIX_NO_VALUE;
    }

#if (NGX_HAVE_INET6)
    if (entry->tree6 != NULL) {
        return ngx_radix128tree_find(entry->tree6, (u_char *) addr)
               != NGX_RADIX_NO_VALUE;
    }
#endif

    return 0;
}


static ngx_int_t
ngx_stream_trojan_geoip_read_varint(ngx_stream_trojan_geoip_reader_t *r,
    uint64_t *value)
{
    uint64_t  result, shift;
    u_char    ch;

    result = 0;
    shift = 0;

    while (r->pos < r->last && shift < 64) {
        ch = *r->pos++;
        result |= (uint64_t) (ch & 0x7f) << shift;

        if ((ch & 0x80) == 0) {
            *value = result;
            return NGX_OK;
        }

        shift += 7;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_geoip_read_bytes(ngx_stream_trojan_geoip_reader_t *r,
    u_char **data, size_t *len)
{
    uint64_t  value;

    if (ngx_stream_trojan_geoip_read_varint(r, &value) != NGX_OK
        || value > (uint64_t) (r->last - r->pos))
    {
        return NGX_ERROR;
    }

    *data = r->pos;
    *len = (size_t) value;
    r->pos += value;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_geoip_skip(ngx_stream_trojan_geoip_reader_t *r,
    ngx_uint_t wire)
{
    uint64_t  value;

    switch (wire) {
    case 0:
        return ngx_stream_trojan_geoip_read_varint(r, &value);

    case 1:
        if ((size_t) (r->last - r->pos) < 8) {
            return NGX_ERROR;
        }
        r->pos += 8;
        return NGX_OK;

    case 2:
        if (ngx_stream_trojan_geoip_read_varint(r, &value) != NGX_OK
            || value > (uint64_t) (r->last - r->pos))
        {
            return NGX_ERROR;
        }
        r->pos += value;
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
ngx_stream_trojan_geoip_copy(ngx_conf_t *cf, u_char *data, size_t len,
    ngx_str_t *dst, ngx_uint_t lower)
{
    size_t  i;

    dst->data = ngx_pnalloc(cf->pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    dst->len = len;
    for (i = 0; i < len; i++) {
        dst->data[i] = lower ? ngx_stream_trojan_geoip_lc(data[i]) : data[i];
    }
    dst->data[len] = '\0';

    return NGX_OK;
}
