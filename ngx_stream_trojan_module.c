#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "ngx_stream_trojan_protocol.h"
#include "ngx_stream_trojan_http_proxy_protocol.h"
#include "ngx_stream_trojan_ip_prefer.h"
#include "ngx_stream_trojan_relay.h"
#include "ngx_stream_trojan_socks5_protocol.h"
#include "ngx_stream_trojan_mux.h"
#include "ngx_stream_trojan_doh.h"
#include "ngx_stream_trojan_dns_rules.h"
#include "ngx_stream_trojan_geosite.h"
#include "ngx_stream_trojan_geoip.h"
#include "ngx_stream_trojan_websocket_protocol.h"


#define NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE 32768
#define NGX_STREAM_TROJAN_MIN_BUFFER_SIZE 4096
#define NGX_STREAM_TROJAN_MAX_BUFFER_SIZE (1024 * 1024)
#define NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE 1024
#define NGX_STREAM_TROJAN_UDP_MAX_PACKETS_PER_EVENT 32
#define NGX_STREAM_TROJAN_UDP_MAX_BYTES_PER_EVENT (256 * 1024)
#define NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE 16384
#define NGX_STREAM_TROJAN_UDP_BUFFER_SIZE \
    (NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE \
     + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4)
#define NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE \
    (NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE \
     + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 3)
#define NGX_STREAM_TROJAN_SOCKS5_UDP_SESSION_BUCKETS 64
#define NGX_STREAM_TROJAN_WS_HANDSHAKE_BUFFER_SIZE 4096
#define NGX_STREAM_TROJAN_WS_MIN_RAW_BUFFER_SIZE 4096
#define NGX_STREAM_TROJAN_WS_MAX_FRAMES_PER_RECV 32
#define NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE \
    (NGX_STREAM_TROJAN_MUX_MAX_STREAMS * 2)
#define NGX_STREAM_TROJAN_MUX_STREAM_POOL_SIZE 2048
#define NGX_STREAM_TROJAN_ROUTE_CACHE_ENTRIES 64



typedef enum {
    ngx_stream_trojan_outbound_direct = 0,
    ngx_stream_trojan_outbound_socks5
} ngx_stream_trojan_outbound_e;

typedef enum {
    ngx_stream_trojan_block_none = 0,
    ngx_stream_trojan_block_h3,
    ngx_stream_trojan_block_udp,
    ngx_stream_trojan_block_all
} ngx_stream_trojan_block_e;



typedef enum {
    ngx_stream_trojan_socks5_mode_tcp = 0,
    ngx_stream_trojan_socks5_mode_udp
} ngx_stream_trojan_socks5_mode_e;


typedef enum {
    ngx_stream_trojan_local_proxy_none = 0,
    ngx_stream_trojan_local_proxy_socks5,
    ngx_stream_trojan_local_proxy_http_proxy
} ngx_stream_trojan_local_proxy_e;

typedef enum {
    ngx_stream_trojan_route_rule_all = 0,
    ngx_stream_trojan_route_rule_domain,
    ngx_stream_trojan_route_rule_geosite,
    ngx_stream_trojan_route_rule_geoip,
    ngx_stream_trojan_route_rule_ip,
    ngx_stream_trojan_route_rule_port
} ngx_stream_trojan_route_rule_e;


typedef struct {
    u_char       addr[16];
    size_t       addr_len;
    ngx_uint_t   prefix;
} ngx_stream_trojan_route_cidr_t;


typedef struct {
    ngx_uint_t   type;
    ngx_str_t    value;
    ngx_str_t    attr;
    ngx_uint_t   attr_not;
    ngx_stream_trojan_geosite_entry_t *geosite;
    ngx_stream_trojan_geoip_entry_t   *geoip;
    ngx_stream_trojan_route_cidr_t     cidr;
    uint16_t     port_start;
    uint16_t     port_end;
} ngx_stream_trojan_route_rule_t;


typedef struct {
    ngx_array_t *rules;
    ngx_array_t *outbounds;
} ngx_stream_trojan_route_t;
typedef struct {
    ngx_uint_t                  valid;
    ngx_uint_t                  accessed;
    ngx_stream_trojan_addr_t    target;
    ngx_stream_trojan_route_t  *route;
} ngx_stream_trojan_route_cache_entry_t;





typedef enum {
    ngx_stream_trojan_socks5_step_greeting_write = 0,
    ngx_stream_trojan_socks5_step_method_read,
    ngx_stream_trojan_socks5_step_auth_write,
    ngx_stream_trojan_socks5_step_auth_read,
    ngx_stream_trojan_socks5_step_request_write,
    ngx_stream_trojan_socks5_step_response_read
} ngx_stream_trojan_socks5_step_e;


typedef enum {
    ngx_stream_trojan_in_socks5_step_greeting = 0,
    ngx_stream_trojan_in_socks5_step_method_write,
    ngx_stream_trojan_in_socks5_step_request,
    ngx_stream_trojan_in_socks5_step_response_write
} ngx_stream_trojan_in_socks5_step_e;


typedef enum {
    ngx_stream_trojan_in_http_step_request = 0,
    ngx_stream_trojan_in_http_step_response_write
} ngx_stream_trojan_in_http_step_e;


typedef struct {
    u_char data[NGX_STREAM_TROJAN_KEY_LEN];
} ngx_stream_trojan_key_t;


typedef struct {
    ngx_str_t    host;
    in_port_t    port;
    ngx_uint_t   set;
    ngx_uint_t   localhost;
} ngx_stream_trojan_server_ref_t;


typedef struct ngx_stream_trojan_srv_conf_s ngx_stream_trojan_srv_conf_t;


typedef struct {
    ngx_uint_t   type;
    ngx_uint_t   ip_prefer;
    ngx_uint_t   ip_prefer_set;
    ngx_uint_t   block;
    ngx_uint_t   block_set;
    ngx_addr_t  *socks5_server;
    ngx_uint_t   socks5_naddrs;
    ngx_str_t    socks5_username;
    ngx_str_t    socks5_password;
} ngx_stream_trojan_outbound_t;


struct ngx_stream_trojan_srv_conf_s {
    ngx_flag_t   enable;
    ngx_flag_t   websocket_enable;
    ngx_str_t    websocket_path;
    ngx_str_t    websocket_host;
    ngx_flag_t   route_enable;
    ngx_flag_t   socks5_enable;
    ngx_flag_t   http_proxy_enable;
    ngx_flag_t   socks5_udp_enable;
    ngx_uint_t   local_proxy_type;
    ngx_uint_t   socks5_ref_set;
    ngx_array_t *keys;
    ngx_addr_t  *fallback;
    ngx_uint_t   fallback_naddrs;
    ngx_msec_t   connect_timeout;
    ngx_msec_t   timeout;
    ngx_msec_t   udp_timeout;
    size_t       buffer_size;
    ngx_array_t *outbounds;
    ngx_array_t *routes;
    ngx_stream_trojan_route_cache_entry_t *route_cache;
    ngx_uint_t   route_cache_generation;
    ngx_stream_trojan_doh_conf_t *doh_conf;
    ngx_stream_trojan_dns_rules_conf_t *dns_rules;
    ngx_stream_trojan_geosite_t *geosite;
    ngx_stream_trojan_geoip_t *geoip;
    ngx_stream_trojan_srv_conf_t *effective;
    ngx_stream_trojan_server_ref_t socks5_ref;
};


typedef struct ngx_stream_trojan_ctx_s ngx_stream_trojan_ctx_t;


typedef enum {
    ngx_stream_trojan_state_prefix = 0,
    ngx_stream_trojan_state_socks5_in_greeting,
    ngx_stream_trojan_state_socks5_in_request,
    ngx_stream_trojan_state_socks5_in_response,
    ngx_stream_trojan_state_socks5_in_udp_control,
    ngx_stream_trojan_state_http_in_request,
    ngx_stream_trojan_state_http_in_response,
    ngx_stream_trojan_state_ws_handshake,
    ngx_stream_trojan_state_ws_response,
    ngx_stream_trojan_state_ws_closing,
    ngx_stream_trojan_state_request,
    ngx_stream_trojan_state_default_fallback,
    ngx_stream_trojan_state_resolving,
    ngx_stream_trojan_state_connecting,
    ngx_stream_trojan_state_socks5_tcp,
    ngx_stream_trojan_state_socks5_udp,
    ngx_stream_trojan_state_proxy,
    ngx_stream_trojan_state_udp,
    ngx_stream_trojan_state_mux
} ngx_stream_trojan_state_e;


typedef enum {
    ngx_stream_trojan_resolve_tcp = 0,
    ngx_stream_trojan_resolve_udp
} ngx_stream_trojan_resolve_e;


typedef struct {
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_resolve_e     type;
    ngx_uint_t                      ip_prefer;
    ngx_stream_trojan_doh_conf_t   *doh_conf;
    u_char                         *name;
    size_t                          name_len;
    uint16_t                        qtype;
    uint16_t                        fallback_qtype;
    uint16_t                        port;
    uint16_t                        payload_len;
    u_char                         *payload;
} ngx_stream_trojan_resolve_data_t;


typedef enum {
    ngx_stream_trojan_peer_none = 0,
    ngx_stream_trojan_peer_fallback,
    ngx_stream_trojan_peer_tcp
} ngx_stream_trojan_peer_e;

typedef struct ngx_stream_trojan_mux_stream_s ngx_stream_trojan_mux_stream_t;
#define NGX_STREAM_TROJAN_MUX_TOMBSTONE \
    ((ngx_stream_trojan_mux_stream_t *) (uintptr_t) 1)



typedef enum {
    ngx_stream_trojan_mux_stream_request = 0,
    ngx_stream_trojan_mux_stream_resolving,
    ngx_stream_trojan_mux_stream_connecting,
    ngx_stream_trojan_mux_stream_socks5,
    ngx_stream_trojan_mux_stream_proxy,
    ngx_stream_trojan_mux_stream_closing
} ngx_stream_trojan_mux_stream_state_e;


typedef struct {
    ngx_stream_trojan_mux_stream_t  *stream;
    ngx_uint_t                       ip_prefer;
    ngx_stream_trojan_doh_conf_t    *doh_conf;
    u_char                          *name;
    size_t                           name_len;
    uint16_t                         qtype;
    uint16_t                         fallback_qtype;
    uint16_t                         port;
} ngx_stream_trojan_mux_resolve_data_t;


struct ngx_stream_trojan_mux_stream_s {
    ngx_queue_t                         queue;
    ngx_queue_t                         process_queue;
    ngx_queue_t                         flush_queue;
    ngx_stream_trojan_ctx_t            *ctx;
    ngx_pool_t                         *pool;
    uint32_t                            id;
    ngx_stream_trojan_mux_stream_state_e state;

    u_char                              command;
    ngx_stream_trojan_addr_t            target;
    ngx_stream_trojan_outbound_t       *outbound;

    u_char                              request[2 + NGX_STREAM_TROJAN_MAX_ADDR_LEN];
    size_t                              request_len;

    ngx_peer_connection_t               peer;
    ngx_str_t                           peer_name;
    ngx_connection_t                   *upstream;
    ngx_resolver_ctx_t                 *resolver_ctx;
    ngx_stream_trojan_doh_ctx_t        *doh_ctx;

    ngx_buf_t                          *client_buffer;
    ngx_buf_t                          *upstream_buffer;
    ngx_buf_t                          *socks5_buffer;
    ngx_stream_trojan_socks5_step_e     socks5_step;
    ngx_uint_t                          socks5_connected;

    ngx_uint_t                          client_fin;
    ngx_uint_t                          upstream_eof;
    ngx_uint_t                          upstream_write_shutdown;
    ngx_uint_t                          close_after_send;
    ngx_uint_t                          fin_to_client;
    ngx_uint_t                          fin_sent;
    ngx_uint_t                          sing_response_sent;
    ngx_uint_t                          process_queued;
    ngx_uint_t                          flush_queued;

    u_char                              frame_header[NGX_STREAM_TROJAN_MUX_HEADER_LEN];
    size_t                              frame_header_pos;
    size_t                              frame_header_len;
    u_char                              fin_header[NGX_STREAM_TROJAN_MUX_HEADER_LEN];
    size_t                              fin_header_pos;
    size_t                              fin_header_len;
};


struct ngx_stream_trojan_ctx_s {
    ngx_stream_session_t       *session;
    ngx_stream_trojan_srv_conf_t *conf;

    ngx_stream_trojan_state_e   state;
    ngx_uint_t                  finalized;
    ngx_stream_trojan_peer_e    peer_kind;
    ngx_stream_trojan_outbound_t *outbound;

    u_char                      prefix[NGX_STREAM_TROJAN_PREFIX_LEN];
    size_t                      prefix_len;

    u_char                      request[1 + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 2];
    size_t                      request_len;
    u_char                      command;
    ngx_stream_trojan_addr_t    target;
    ngx_stream_trojan_addr_t    route_cache_target;
    ngx_uint_t                  route_cache_command;
    ngx_uint_t                  route_cache_valid;
    ngx_stream_trojan_outbound_t *route_cache_outbound;

    ngx_peer_connection_t       peer;
    ngx_str_t                   peer_name;
    ngx_addr_t                  *connect_addrs;
    ngx_uint_t                   connect_naddrs;
    ngx_uint_t                   connect_index;
    ngx_connection_t           *upstream;

    ngx_buf_t                  *client_buffer;
    ngx_buf_t                  *upstream_buffer;
    ngx_buf_t                  *pending_to_upstream;
    ngx_buf_t                  *pending_to_client;
    ngx_uint_t                  upstream_write_shutdown;

    ngx_connection_t           *udp4;
#if (NGX_HAVE_INET6)
    ngx_connection_t           *udp6;
#endif
    ngx_connection_t           *socks5_udp;
    ngx_stream_trojan_outbound_t *socks5_udp_outbound;
    ngx_connection_t           *socks5_in_udp;
    ngx_addr_t                  socks5_udp_relay;
    ngx_uint_t                  socks5_server_index;
    struct sockaddr_storage     socks5_udp_client;
    socklen_t                   socks5_udp_client_socklen;
    ngx_uint_t                  socks5_udp_client_set;
    ngx_resolver_ctx_t         *resolver_ctx;
    ngx_stream_trojan_doh_ctx_t *doh_ctx;
    u_char                     *udp_in;
    size_t                      udp_in_pos;
    size_t                      udp_in_len;
    u_char                     *udp_out;
    u_char                     *udp_payload;
    ngx_buf_t                  *udp_pending_to_client;
    const u_char              *udp_pending_payload;
    size_t                      udp_pending_payload_len;
    size_t                      udp_pending_payload_sent;
    ngx_buf_t                  *udp_pending_to_upstream;

    ngx_buf_t                  *socks5_buffer;
    ngx_buf_t                  *http_buffer;
    size_t                      http_header_scan;
    ngx_stream_trojan_socks5_mode_e  socks5_mode;
    ngx_stream_trojan_socks5_step_e  socks5_step;
    ngx_uint_t                  socks5_connected;
    ngx_stream_trojan_in_socks5_step_e  in_socks5_step;
    ngx_stream_trojan_in_http_step_e  in_http_step;
    uint8_t                     socks5_in_status;
    uint16_t                    http_in_status;
    ngx_uint_t                  inbound_socks5;
    ngx_uint_t                  inbound_http_proxy;
    ngx_uint_t                  websocket;
    ngx_buf_t                  *ws_buffer;
    size_t                      ws_header_scan;
    ngx_buf_t                  *ws_raw;
    ngx_buf_t                  *ws_out;
    u_char                      ws_header[NGX_STREAM_TROJAN_WS_MAX_HEADER_LEN];
    size_t                      ws_header_len;
    ngx_stream_trojan_ws_frame_t ws_frame;
    ngx_uint_t                  ws_frame_active;
    uint64_t                    ws_payload_remaining;
    uint64_t                    ws_mask_offset;
    ngx_uint_t                  ws_fragmented;
    uint8_t                     ws_fragment_opcode;
    u_char                      ws_control[NGX_STREAM_TROJAN_WS_MAX_CONTROL_PAYLOAD];
    size_t                      ws_control_len;
    u_char                      ws_send_header[10];
    size_t                      ws_send_header_len;
    size_t                      ws_send_header_pos;
    size_t                      ws_send_payload_remaining;
    ngx_uint_t                  ws_close_code;
    ngx_uint_t                  ws_finalize_rc;
    uint16_t                    ws_response_status;
    ngx_uint_t                  ws_response_is_accept;

    ngx_queue_t                 mux_streams;
    ngx_stream_trojan_mux_stream_t  *mux_stream_table[
        NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE];
    ngx_queue_t                 mux_process_queue;
    ngx_queue_t                 mux_flush_queue;
    ngx_uint_t                  mux_cool;
    ngx_uint_t                  mux_sing;
    ngx_uint_t                  mux_nstreams;
    ngx_uint_t                  mux_tombstones;
    u_char                      mux_header[NGX_STREAM_TROJAN_MUX_HEADER_LEN];
    size_t                      mux_header_len;
    ngx_stream_trojan_mux_frame_t mux_frame;
    ngx_uint_t                  mux_frame_parsed;
    u_char                     *mux_payload;
    size_t                      mux_payload_len;
    size_t                      mux_payload_read;
    ngx_stream_trojan_mux_stream_t *mux_payload_stream;
    ngx_uint_t                  mux_payload_direct;
    ngx_uint_t                  mux_payload_accept_checked;
    ngx_uint_t                  mux_payload_blocked;
    u_char                      mux_nop_header[NGX_STREAM_TROJAN_MUX_HEADER_LEN];
    size_t                      mux_nop_header_pos;
    ngx_uint_t                  mux_nop_pending;
    u_char                      mux_cool_meta[NGX_STREAM_TROJAN_MUX_COOL_MAX_META_LEN];
    size_t                      mux_cool_meta_len;
    size_t                      mux_cool_meta_read;
    u_char                      mux_cool_data_len[2];
    size_t                      mux_cool_data_len_read;
    ngx_stream_trojan_mux_cool_frame_t mux_cool_frame;
    u_char                      mux_sing_handshake[5];
    size_t                      mux_sing_handshake_len;
    ngx_uint_t                  mux_sing_handshake_done;
};


static void ngx_stream_trojan_handler(ngx_stream_session_t *s);
static void ngx_stream_trojan_read_client(ngx_event_t *ev);
static void ngx_stream_trojan_peer_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_in_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_udp_control_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_in_udp_control_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev);
static void ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_socks5_in(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_http_in(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_flush(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_http_in_flush(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_read(
    ngx_stream_trojan_ctx_t *ctx, size_t needed);
static ngx_int_t ngx_stream_trojan_http_in_read(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_prepare_method(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_prepare_response(
    ngx_stream_trojan_ctx_t *ctx, uint8_t status);
static ngx_int_t ngx_stream_trojan_http_in_prepare_response(
    ngx_stream_trojan_ctx_t *ctx, uint16_t status);
static void ngx_stream_trojan_inbound_connect_success(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_inbound_connect_failure(
    ngx_stream_trojan_ctx_t *ctx, ngx_uint_t rc);
static ngx_int_t ngx_stream_trojan_init_udp_buffers(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_refresh_udp_timeout(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_websocket_handshake(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_flush_websocket_response(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_websocket_start_handshake(
    ngx_stream_trojan_ctx_t *ctx, u_char *data, size_t len);
static ssize_t ngx_stream_trojan_client_recv(ngx_stream_trojan_ctx_t *ctx,
    u_char *dst, size_t size);
static ssize_t ngx_stream_trojan_client_send(ngx_stream_trojan_ctx_t *ctx,
    u_char *src, size_t size);
static ngx_uint_t ngx_stream_trojan_client_read_ready(
    ngx_stream_trojan_ctx_t *ctx, ngx_connection_t *src);
static ngx_int_t ngx_stream_trojan_websocket_flush_out(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_websocket_queue_control(
    ngx_stream_trojan_ctx_t *ctx, uint8_t opcode, const u_char *payload,
    size_t payload_len);
static void ngx_stream_trojan_websocket_fail(ngx_stream_trojan_ctx_t *ctx,
    uint16_t code, ngx_uint_t rc);
static void ngx_stream_trojan_websocket_process_closing(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len);
static void ngx_stream_trojan_start_default_fallback(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_default_fallback_write_handler(
    ngx_event_t *ev);
static ngx_int_t ngx_stream_trojan_flush_default_fallback(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx);
static ngx_buf_t *ngx_stream_trojan_create_temp_buf(ngx_pool_t *pool,
    size_t size);
static ngx_int_t ngx_stream_trojan_set_pending(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_ensure_pending(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_socks5_tcp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_socks5_udp(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_start_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_stream_trojan_resolve_e type,
    const u_char *payload, uint16_t payload_len, size_t wire_len,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout,
    ngx_uint_t ip_prefer);
static ngx_int_t ngx_stream_trojan_socks5_connect_next(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_resolve_handler(ngx_resolver_ctx_t *rctx);
static void ngx_stream_trojan_resolve_complete(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_resolve_data_t *data,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs);
static ngx_int_t ngx_stream_trojan_start_doh_resolver(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_resolve_data_t *data);
static void ngx_stream_trojan_doh_resolve_handler(void *cb_data,
    ngx_int_t status, ngx_resolver_addr_t *addrs, ngx_uint_t naddrs);
static ngx_int_t ngx_stream_trojan_connect_next(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_addr_t *addr);
static void ngx_stream_trojan_socks5_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_socks5_mode_e mode);
static void ngx_stream_trojan_socks5_handler(ngx_event_t *ev);
static void ngx_stream_trojan_process_socks5(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_flush(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_read(ngx_stream_trojan_ctx_t *ctx,
    size_t needed);
static ngx_int_t ngx_stream_trojan_socks5_prepare_greeting(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_prepare_auth(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_prepare_request(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_response_to_ngx_addr(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *addr,
    ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_send_socks5_udp_frame(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_forward_socks5_udp_packet(
    ngx_stream_trojan_ctx_t *ctx, u_char *packet, size_t packet_len);
static ngx_int_t ngx_stream_trojan_queue_udp_client(
    ngx_stream_trojan_ctx_t *ctx, u_char *header, size_t header_len,
    const u_char *payload, size_t payload_len);
static ngx_int_t ngx_stream_trojan_queue_socks5_udp_packet(
    ngx_stream_trojan_ctx_t *ctx, u_char *packet, size_t packet_len);
static ngx_int_t ngx_stream_trojan_flush_socks5_udp_packet(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_post_socks5_in_udp_read(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_prepare_udp_outbound(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target);
static void ngx_stream_trojan_reset_socks5_udp(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_stream_trojan_outbound_t *ngx_stream_trojan_select_outbound(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_uint_t command);
static ngx_stream_trojan_outbound_t *ngx_stream_trojan_select_route_outbound(
    ngx_stream_trojan_route_t *route, ngx_stream_trojan_outbound_t *current,
    ngx_uint_t command, ngx_stream_trojan_addr_t *target);
static ngx_uint_t ngx_stream_trojan_route_missed(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_outbound_t *outbound);
static ngx_int_t ngx_stream_trojan_route_match(
    ngx_stream_trojan_route_t *route, ngx_stream_trojan_addr_t *target);
static ngx_int_t ngx_stream_trojan_route_rule_match(
    ngx_stream_trojan_route_rule_t *rule, ngx_stream_trojan_addr_t *target);
static u_char ngx_stream_trojan_route_lc(u_char ch);
static ngx_int_t ngx_stream_trojan_route_prepare(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *conf);
static ngx_int_t ngx_stream_trojan_route_validate(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *conf);
static ngx_int_t ngx_stream_trojan_route_parse_rule(ngx_conf_t *cf,
    ngx_stream_trojan_route_t *route, ngx_str_t *value);
static ngx_int_t ngx_stream_trojan_route_parse_cidr(ngx_conf_t *cf,
    ngx_str_t *value, ngx_stream_trojan_route_cidr_t *cidr);
static ngx_int_t ngx_stream_trojan_route_parse_port(ngx_str_t *value,
    uint16_t *start, uint16_t *end);
static ngx_int_t ngx_stream_trojan_route_copy(ngx_conf_t *cf,
    ngx_str_t *src, ngx_str_t *dst, ngx_uint_t lower);
static ngx_uint_t ngx_stream_trojan_outbound_type(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_outbound_request_blocked(
    ngx_stream_trojan_outbound_t *outbound, ngx_uint_t command,
    ngx_stream_trojan_addr_t *target);
static ngx_uint_t ngx_stream_trojan_request_blocked(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_test_connect(ngx_connection_t *c);
static void ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_update_read_event(ngx_connection_t *c,
    ngx_uint_t blocked);
static ngx_int_t ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof, ngx_uint_t *progress);
static void ngx_stream_trojan_start_mux(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_is_mux_cool_target(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_is_mux_sing_target(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_sing_read_client(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_sing_read_handshake(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_cool_read_client(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_cool_handle_frame(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_mux(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_read_client(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_flush_client(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_handle_frame(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_insert_stream(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_remove_stream(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_maybe_rebuild_stream_table(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_stream_trojan_mux_stream_t *ngx_stream_trojan_mux_find_stream(
    ngx_stream_trojan_ctx_t *ctx, uint32_t id);
static ngx_stream_trojan_mux_stream_t *ngx_stream_trojan_mux_create_stream(
    ngx_stream_trojan_ctx_t *ctx, uint32_t id);
static ngx_int_t ngx_stream_trojan_mux_ensure_client_buffer(
    ngx_stream_trojan_mux_stream_t *stream, size_t len);
static ngx_int_t ngx_stream_trojan_mux_ensure_upstream_buffer(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_stream_can_accept(
    ngx_stream_trojan_mux_stream_t *stream, size_t len);
static void ngx_stream_trojan_mux_refresh_read_timeout(
    ngx_stream_trojan_ctx_t *ctx, ngx_connection_t *c);
static void ngx_stream_trojan_mux_queue_process(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_process_queued_streams(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_mux_queue_flush(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_read_client_payload(
    ngx_stream_trojan_ctx_t *ctx, ngx_connection_t *c);
static ngx_uint_t ngx_stream_trojan_mux_client_blocked_on(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_post_client_read(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_mux_post_client_read_next(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_mux_append_client_data(
    ngx_stream_trojan_mux_stream_t *stream, u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_mux_feed_stream(
    ngx_stream_trojan_mux_stream_t *stream, u_char *data, size_t len);
static void ngx_stream_trojan_mux_start_stream(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_start_tcp(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_connect(
    ngx_stream_trojan_mux_stream_t *stream, ngx_addr_t *addr);
static void ngx_stream_trojan_mux_peer_handler(ngx_event_t *ev);
static void ngx_stream_trojan_mux_init_proxy(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_process_stream(
    ngx_stream_trojan_mux_stream_t *stream, size_t *send_budget);
static ngx_int_t ngx_stream_trojan_mux_flush_to_upstream(
    ngx_stream_trojan_mux_stream_t *stream, size_t *send_budget);
static ngx_int_t ngx_stream_trojan_mux_read_upstream(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_close_stream(
    ngx_stream_trojan_mux_stream_t *stream, ngx_uint_t send_fin);
static void ngx_stream_trojan_mux_cleanup_stream(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_close_streams(ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_mux_stream_outbound_type(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_uint_t ngx_stream_trojan_mux_stream_ip_prefer(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_uint_t ngx_stream_trojan_mux_stream_request_blocked(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_start_resolver(
    ngx_stream_trojan_mux_stream_t *stream,
    ngx_stream_trojan_dns_rule_group_t *dns_rule);
static void ngx_stream_trojan_mux_resolve_handler(ngx_resolver_ctx_t *rctx);
static ngx_int_t ngx_stream_trojan_mux_start_doh_resolver(
    ngx_stream_trojan_mux_stream_t *stream,
    ngx_stream_trojan_mux_resolve_data_t *data);
static void ngx_stream_trojan_mux_doh_resolve_handler(void *cb_data,
    ngx_int_t status, ngx_resolver_addr_t *addrs, ngx_uint_t naddrs);
static void ngx_stream_trojan_mux_start_socks5_tcp(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_socks5_connect(
    ngx_stream_trojan_mux_stream_t *stream);
static void ngx_stream_trojan_mux_socks5_handler(ngx_event_t *ev);
static void ngx_stream_trojan_mux_process_socks5(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_socks5_flush(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_socks5_read(
    ngx_stream_trojan_mux_stream_t *stream, size_t needed);
static ngx_int_t ngx_stream_trojan_mux_socks5_prepare_greeting(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_mux_socks5_prepare_auth(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_resolver_addrs_to_ngx_addrs(
    ngx_pool_t *pool, ngx_resolver_addr_t *addrs, ngx_uint_t naddrs,
    uint16_t port, ngx_uint_t ip_prefer, ngx_addr_t **out,
    ngx_uint_t *nout);
static ngx_int_t ngx_stream_trojan_mux_socks5_prepare_request(
    ngx_stream_trojan_mux_stream_t *stream);
static ngx_int_t ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_resolve_addr(ngx_pool_t *pool,
    ngx_log_t *log, ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_resolve_addr_prefer(ngx_pool_t *pool,
    ngx_log_t *log, ngx_stream_trojan_addr_t *addr, ngx_uint_t ip_prefer,
    ngx_addr_t *out);
static ngx_uint_t ngx_stream_trojan_resolver_configured(
    ngx_stream_session_t *s);
static ngx_resolver_addr_t *ngx_stream_trojan_resolver_pick_addr(
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, ngx_uint_t ip_prefer);
static ngx_int_t ngx_stream_trojan_resolver_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_resolver_addr_t *resolved, uint16_t port, ngx_addr_t *out);
static ngx_uint_t ngx_stream_trojan_current_ip_prefer(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_header_end_seen(u_char *buf, size_t len,
    size_t *scan);
static ngx_stream_trojan_dns_rule_group_t *ngx_stream_trojan_match_dns_rule(
    ngx_stream_trojan_srv_conf_t *conf, ngx_stream_trojan_addr_t *addr);
static ngx_int_t ngx_stream_trojan_parse_ip_prefer(ngx_str_t *value,
    ngx_uint_t *prefer);
static ngx_int_t ngx_stream_trojan_parse_block(ngx_str_t *value,
    ngx_uint_t *block);
static ngx_int_t ngx_stream_trojan_parse_server_ref(ngx_conf_t *cf,
    ngx_str_t *value, ngx_stream_trojan_server_ref_t *ref);
static ngx_int_t ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa,
    socklen_t socklen, ngx_stream_trojan_addr_t *addr);
static ngx_int_t ngx_stream_trojan_loopback_sockaddr(struct sockaddr *sa);
static ngx_int_t ngx_stream_trojan_local_proxy_check_listens(ngx_conf_t *cf,
    ngx_stream_core_srv_conf_t *cscf, ngx_stream_trojan_srv_conf_t *tscf);
static const char *ngx_stream_trojan_local_proxy_name(
    ngx_stream_trojan_srv_conf_t *tscf);
static ngx_stream_trojan_srv_conf_t *ngx_stream_trojan_local_proxy_conflict(
    ngx_stream_conf_addr_t *addr, ngx_stream_core_srv_conf_t *current);
static ngx_int_t ngx_stream_trojan_default_server_name(
    ngx_stream_core_srv_conf_t *cscf);
static ngx_stream_trojan_srv_conf_t *ngx_stream_trojan_find_trojan_server(
    ngx_conf_t *cf, ngx_stream_trojan_server_ref_t *ref, ngx_uint_t log_level);
static ngx_int_t ngx_stream_trojan_postconfiguration(ngx_conf_t *cf);
static ngx_connection_t *ngx_stream_trojan_create_udp_connection(
    ngx_stream_trojan_ctx_t *ctx, int family, ngx_event_handler_pt handler);
static ngx_connection_t *ngx_stream_trojan_create_bound_udp_connection(
    ngx_stream_trojan_ctx_t *ctx, int family,
    ngx_event_handler_pt handler);
static ngx_int_t ngx_stream_trojan_socks5_udp_bind_addr(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *addr);
static ngx_int_t ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_send_udp_resolved(
    ngx_stream_trojan_ctx_t *ctx, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs, uint16_t port, const u_char *payload,
    uint16_t payload_len, ngx_uint_t ip_prefer);
static ngx_int_t ngx_stream_trojan_send_udp_sockaddr(
    ngx_stream_trojan_ctx_t *ctx, struct sockaddr *sa, socklen_t socklen,
    const u_char *payload, uint16_t payload_len);
static ngx_int_t ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx,
    ngx_uint_t rc);

static void *ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_websocket_on(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_websocket_path(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_socks5_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_http_proxy_on(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_socks5_udp_on(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_trojan_server(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_outbounds(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_outbound_direct_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_outbound_socks5_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_outbounds_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_doh_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_geosite_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_geoip_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_dns_rules_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_routes_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_routes_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_trojan_validate_socks5_outbound(
    ngx_conf_t *cf, ngx_stream_trojan_outbound_t *outbound,
    const char *name);
static ngx_int_t ngx_stream_trojan_route_outbound_options(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *value,
    ngx_uint_t start, ngx_uint_t nelts);
static ngx_int_t ngx_stream_trojan_set_socks5_server(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *server);


static ngx_command_t ngx_stream_trojan_commands[] = {

    { ngx_string("trojan"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, enable),
      NULL },

    { ngx_string("trojan_route"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, route_enable),
      NULL },

    { ngx_string("socks5"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_socks5_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, socks5_enable),
      NULL },

    { ngx_string("http_proxy"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_http_proxy_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, http_proxy_enable),
      NULL },

    { ngx_string("socks5_udp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_socks5_udp_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, socks5_udp_enable),
      NULL },

    { ngx_string("trojan_server"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_trojan_server,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_password"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_trojan_password,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_fallback"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_fallback,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("trojan_websocket"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_websocket_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, websocket_enable),
      NULL },

    { ngx_string("trojan_websocket_path"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_websocket_path,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_websocket_host"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, websocket_host),
      NULL },


    { ngx_string("trojan_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("trojan_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, timeout),
      NULL },

    { ngx_string("trojan_udp_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, udp_timeout),
      NULL },

    { ngx_string("trojan_buffer_size"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("outbounds"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_trojan_outbounds,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_routes"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_trojan_routes_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_doh"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_doh_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_geosite"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_geosite_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_geoip"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_geoip_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_dns_rules"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_dns_rules_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("outbounds_direct"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_trojan_outbound_direct_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("outbounds_socks5"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_trojan_outbound_socks5_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t ngx_stream_trojan_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_trojan_postconfiguration,   /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_stream_trojan_create_srv_conf,     /* create server configuration */
    ngx_stream_trojan_merge_srv_conf       /* merge server configuration */
};


ngx_module_t ngx_stream_trojan_module = {
    NGX_MODULE_V1,
    &ngx_stream_trojan_module_ctx,
    ngx_stream_trojan_commands,
    NGX_STREAM_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_trojan_handler(ngx_stream_session_t *s)
{
    ngx_connection_t              *c;
    ngx_stream_trojan_ctx_t       *ctx;
    ngx_stream_trojan_srv_conf_t  *tscf;

    c = s->connection;
    tscf = ngx_stream_get_module_srv_conf(s, ngx_stream_trojan_module);

    if (!tscf->enable && !tscf->socks5_enable && !tscf->http_proxy_enable) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_trojan_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->conf = tscf;
    ctx->state = ngx_stream_trojan_state_prefix;
    ngx_queue_init(&ctx->mux_streams);
    ngx_queue_init(&ctx->mux_process_queue);
    ngx_queue_init(&ctx->mux_flush_queue);

    ngx_stream_set_ctx(s, ctx, ngx_stream_trojan_module);

    c->read->handler = ngx_stream_trojan_read_client;
    ngx_add_timer(c->read, tscf->timeout);
    c->write->handler = ngx_stream_trojan_read_client;

    if ((tscf->socks5_enable || tscf->http_proxy_enable) && !tscf->enable) {
        ctx->inbound_socks5 = tscf->socks5_enable ? 1 : 0;
        ctx->inbound_http_proxy = tscf->http_proxy_enable ? 1 : 0;
        if (ctx->inbound_socks5) {
            ctx->state = ngx_stream_trojan_state_socks5_in_greeting;
            ngx_stream_trojan_process_socks5_in(ctx);
            return;
        }

        ctx->state = ngx_stream_trojan_state_http_in_request;
        ngx_stream_trojan_process_http_in(ctx);
        return;
    }

    ngx_stream_trojan_process_prefix(ctx);
}


static void
ngx_stream_trojan_read_client(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "trojan client timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }
    if ((ctx->state == ngx_stream_trojan_state_resolving
         || ctx->state == ngx_stream_trojan_state_connecting
         || ctx->state == ngx_stream_trojan_state_socks5_tcp
         || ctx->state == ngx_stream_trojan_state_socks5_udp)
        && (c->read->eof || c->read->error))
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (ctx->websocket) {
        switch (ngx_stream_trojan_websocket_flush_out(ctx)) {
        case NGX_OK:
            break;
        case NGX_AGAIN:
            return;
        default:
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }
    }


    switch (ctx->state) {
    case ngx_stream_trojan_state_socks5_in_greeting:
    case ngx_stream_trojan_state_socks5_in_request:
    case ngx_stream_trojan_state_socks5_in_response:
        ngx_stream_trojan_process_socks5_in(ctx);
        break;

    case ngx_stream_trojan_state_http_in_request:
    case ngx_stream_trojan_state_http_in_response:
        ngx_stream_trojan_process_http_in(ctx);
        break;

    case ngx_stream_trojan_state_ws_handshake:
        ngx_stream_trojan_process_websocket_handshake(ctx);
        break;

    case ngx_stream_trojan_state_ws_response:
        ngx_stream_trojan_flush_websocket_response(ctx);
        break;

    case ngx_stream_trojan_state_ws_closing:
        ngx_stream_trojan_websocket_process_closing(ctx);
        break;

    case ngx_stream_trojan_state_prefix:
        ngx_stream_trojan_process_prefix(ctx);
        break;

    case ngx_stream_trojan_state_request:
        ngx_stream_trojan_process_request(ctx);
        break;

    case ngx_stream_trojan_state_default_fallback:
        ngx_stream_trojan_default_fallback_write_handler(c->write);
        break;

    case ngx_stream_trojan_state_resolving:
    case ngx_stream_trojan_state_connecting:
    case ngx_stream_trojan_state_socks5_tcp:
    case ngx_stream_trojan_state_socks5_udp:
        if (ngx_stream_trojan_update_read_event(c, 1) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        break;

    case ngx_stream_trojan_state_proxy:
        ngx_stream_trojan_process_proxy(ctx);
        break;

    case ngx_stream_trojan_state_udp:
        ngx_stream_trojan_process_udp_client(ctx);
        break;

    case ngx_stream_trojan_state_mux:
        ngx_stream_trojan_process_mux(ctx);
        break;

    default:
        break;
    }
}


static ngx_int_t
ngx_stream_trojan_key_valid(ngx_stream_trojan_srv_conf_t *tscf, u_char *key)
{
    ngx_uint_t                i;
    ngx_stream_trojan_key_t  *keys;

    keys = tscf->keys->elts;

    for (i = 0; i < tscf->keys->nelts; i++) {
        if (ngx_stream_trojan_key_equal(key, keys[i].data)) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_stream_trojan_process_socks5_in(ngx_stream_trojan_ctx_t *ctx)
{
    int                         rc;
    size_t                      needed;
    uint8_t                     method, command;
    ngx_stream_trojan_srv_conf_t *effective, *socks5_conf;

    if (ctx->socks5_buffer == NULL) {
        ctx->socks5_buffer = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
        if (ctx->socks5_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    for ( ;; ) {
        switch (ctx->state) {

        case ngx_stream_trojan_state_socks5_in_greeting:
            rc = ngx_stream_trojan_socks5_greeting_len(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                &needed);

            if (rc != 0
                && ctx->inbound_http_proxy
                && ctx->socks5_buffer->last > ctx->socks5_buffer->pos
                && ctx->socks5_buffer->pos[0]
                   != NGX_STREAM_TROJAN_SOCKS5_VERSION)
            {
                if (!ngx_stream_trojan_http_proxy_looks_like_http(
                        ctx->socks5_buffer->pos,
                        ctx->socks5_buffer->last - ctx->socks5_buffer->pos))
                {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                ctx->http_buffer = ctx->socks5_buffer;
                ctx->socks5_buffer = NULL;
                ctx->state = ngx_stream_trojan_state_http_in_request;
                ngx_stream_trojan_process_http_in(ctx);
                return;
            }

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_in_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != 0) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                return;
            }

            method = ngx_stream_trojan_socks5_select_method(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos);

            if (ngx_stream_trojan_socks5_in_prepare_method(ctx)
                != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (method != NGX_STREAM_TROJAN_SOCKS5_METHOD_NO_AUTH) {
                ctx->socks5_buffer->start[1] =
                    NGX_STREAM_TROJAN_SOCKS5_METHOD_NONE;
                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                continue;
            }

            ctx->state = ngx_stream_trojan_state_socks5_in_response;
            ctx->in_socks5_step = ngx_stream_trojan_in_socks5_step_method_write;
            continue;

        case ngx_stream_trojan_state_socks5_in_response:
            rc = ngx_stream_trojan_socks5_in_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ctx->in_socks5_step
                == ngx_stream_trojan_in_socks5_step_response_write)
            {
                if (ctx->socks5_in_status
                    != NGX_STREAM_TROJAN_SOCKS5_STATUS_OK)
                {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
                    return;
                }

                if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
                    ngx_stream_trojan_init_proxy(ctx);
                    return;
                }

                if (ngx_stream_trojan_outbound_type(ctx)
                    == ngx_stream_trojan_outbound_socks5)
                {
                    ngx_stream_trojan_start_socks5_udp(ctx);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
                ctx->session->connection->read->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ctx->session->connection->write->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ngx_add_timer(ctx->session->connection->read,
                              ctx->conf->udp_timeout);
                if (ngx_handle_read_event(ctx->session->connection->read, 0)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                return;
            }

            if (ctx->socks5_buffer->start[1]
                == NGX_STREAM_TROJAN_SOCKS5_METHOD_NONE)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            ctx->state = ngx_stream_trojan_state_socks5_in_request;
            continue;

        case ngx_stream_trojan_state_socks5_in_request:
            rc = ngx_stream_trojan_socks5_request_len(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                &needed);

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_in_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != 0
                || ngx_stream_trojan_socks5_parse_request(
                       ctx->socks5_buffer->pos,
                       ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                       &command, &ctx->target)
                   != 0)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                return;
            }

            socks5_conf = ctx->conf;
            effective = socks5_conf->effective;
            if (effective == NULL) {
                if (ngx_stream_trojan_socks5_in_prepare_response(
                        ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_GENERAL_FAILURE)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                ctx->in_socks5_step =
                    ngx_stream_trojan_in_socks5_step_response_write;
                continue;
            }
            ctx->conf = effective;
            ctx->command = command == NGX_STREAM_TROJAN_SOCKS5_CMD_CONNECT
                           ? NGX_STREAM_TROJAN_CMD_CONNECT
                           : NGX_STREAM_TROJAN_CMD_ASSOCIATE;

            if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
                && ctx->conf->route_enable)
            {
                ctx->outbound = NULL;

            } else {
                ctx->outbound = ngx_stream_trojan_select_outbound(
                    ctx, &ctx->target, ctx->command);
            }

            if (!(ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
                  && ctx->conf->route_enable)
                && ngx_stream_trojan_route_missed(ctx, ctx->outbound))
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
                && !socks5_conf->socks5_udp_enable)
            {
                if (ngx_stream_trojan_socks5_in_prepare_response(
                        ctx, 0x07)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                ctx->in_socks5_step =
                    ngx_stream_trojan_in_socks5_step_response_write;
                continue;
            }

            if (ngx_stream_trojan_request_blocked(ctx)) {
                if (ngx_stream_trojan_socks5_in_prepare_response(ctx, 0x02)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                ctx->in_socks5_step =
                    ngx_stream_trojan_in_socks5_step_response_write;
                continue;
            }

            if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
                && ngx_stream_trojan_init_udp_buffers(ctx) != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
                ngx_stream_trojan_start_tcp(ctx);
                return;
            }

            if (ngx_stream_trojan_socks5_in_prepare_response(
                    ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_OK)
                != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            ctx->state = ngx_stream_trojan_state_socks5_in_response;
            ctx->in_socks5_step =
                ngx_stream_trojan_in_socks5_step_response_write;
            continue;

        default:
            return;
        }
    }
}


static void
ngx_stream_trojan_process_http_in(ngx_stream_trojan_ctx_t *ctx)
{
    int                          rc;
    size_t                       needed = 0, len;
    ngx_stream_trojan_srv_conf_t *effective, *proxy_conf;

    if (ctx->http_buffer == NULL) {
        ctx->http_buffer = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
        if (ctx->http_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    for ( ;; ) {
        switch (ctx->state) {

        case ngx_stream_trojan_state_http_in_request:
            len = (size_t) (ctx->http_buffer->last - ctx->http_buffer->pos);
            if (!ngx_stream_trojan_header_end_seen(ctx->http_buffer->pos, len,
                                                   &ctx->http_header_scan))
            {
                rc = NGX_STREAM_TROJAN_HTTP_PROXY_NEED_MORE;
            } else {
                rc = ngx_stream_trojan_http_proxy_parse_connect(
                    ctx->http_buffer->pos, len, &needed, &ctx->target);
            }
            if (rc == NGX_STREAM_TROJAN_HTTP_PROXY_NEED_MORE) {
                rc = ngx_stream_trojan_http_in_read(ctx);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != NGX_STREAM_TROJAN_HTTP_PROXY_OK) {
                if (ngx_stream_trojan_http_in_prepare_response(
                        ctx,
                        rc == NGX_STREAM_TROJAN_HTTP_PROXY_METHOD_NOT_ALLOWED
                        ? 405 : 400)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_http_in_response;
                ctx->in_http_step =
                    ngx_stream_trojan_in_http_step_response_write;
                continue;
            }

            proxy_conf = ctx->conf;
            effective = proxy_conf->effective;
            if (effective == NULL) {
                if (ngx_stream_trojan_http_in_prepare_response(ctx, 502)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_http_in_response;
                ctx->in_http_step =
                    ngx_stream_trojan_in_http_step_response_write;
                continue;
            }

            ctx->conf = effective;
            ctx->command = NGX_STREAM_TROJAN_CMD_CONNECT;
            ctx->outbound = ngx_stream_trojan_select_outbound(
                ctx, &ctx->target, ctx->command);

            if (ngx_stream_trojan_route_missed(ctx, ctx->outbound)) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            if (ctx->http_buffer->last > ctx->http_buffer->pos + needed
                && ngx_stream_trojan_set_pending(
                       ctx, ctx->http_buffer->pos + needed,
                       ctx->http_buffer->last - (ctx->http_buffer->pos + needed))
                   != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_stream_trojan_request_blocked(ctx)) {
                if (ngx_stream_trojan_http_in_prepare_response(ctx, 403)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_http_in_response;
                ctx->in_http_step =
                    ngx_stream_trojan_in_http_step_response_write;
                continue;
            }

            ngx_stream_trojan_start_tcp(ctx);
            return;

        case ngx_stream_trojan_state_http_in_response:
            rc = ngx_stream_trojan_http_in_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ctx->http_in_status != 200) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
                return;
            }

            ngx_stream_trojan_init_proxy(ctx);
            return;

        default:
            return;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_http_in_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->http_buffer;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, ctx->conf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
        ngx_add_timer(c->write, ctx->conf->timeout);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_http_in_read(ngx_stream_trojan_ctx_t *ctx)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->http_buffer;

    if (b->last == b->end) {
        return NGX_ERROR;
    }

    available = b->end - b->last;
    n = c->recv(c, b->last, available);

    if (n == NGX_AGAIN) {
        ngx_add_timer(c->read, ctx->conf->timeout);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }

    if (n == 0 || n == NGX_ERROR) {
        return NGX_ERROR;
    }

    b->last += n;
    ngx_add_timer(c->read, ctx->conf->timeout);
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_http_in_prepare_response(ngx_stream_trojan_ctx_t *ctx,
    uint16_t status)
{
    size_t      written;
    ngx_buf_t  *b;

    ctx->http_in_status = status;

    b = ctx->http_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_http_proxy_build_response(
            status, b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->socks5_buffer;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, ctx->conf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
        ngx_add_timer(c->write, ctx->conf->timeout);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_read(ngx_stream_trojan_ctx_t *ctx, size_t needed)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->socks5_buffer;

    if (needed > (size_t) (b->end - b->start)) {
        return NGX_ERROR;
    }

    while ((size_t) (b->last - b->pos) < needed) {
        available = needed - (size_t) (b->last - b->pos);
        n = c->recv(c, b->last, available);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->read, ctx->conf->timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->last += n;
        ngx_add_timer(c->read, ctx->conf->timeout);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_prepare_method(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start + 2;

    return ngx_stream_trojan_socks5_build_method_response(
        NGX_STREAM_TROJAN_SOCKS5_METHOD_NO_AUTH, b->pos, 2)
        == 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_prepare_response(ngx_stream_trojan_ctx_t *ctx,
    uint8_t status)
{
    size_t                      written;
    ngx_buf_t                  *b;
    ngx_stream_trojan_addr_t    bind_addr;
    u_char                      zero[4] = { 0, 0, 0, 0 };

    ctx->socks5_in_status = status;

    ngx_memzero(&bind_addr, sizeof(bind_addr));
    if (status == NGX_STREAM_TROJAN_SOCKS5_STATUS_OK
        && ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE)
    {
        if (ngx_stream_trojan_socks5_udp_bind_addr(ctx, &bind_addr)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        bind_addr.type = NGX_STREAM_TROJAN_ADDR_IPV4;
        bind_addr.host_len = 4;
        ngx_memcpy(bind_addr.host, zero, 4);
        bind_addr.port = 0;
        bind_addr.wire_len = 1 + 4 + 2;
    }

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_response(status, &bind_addr,
                                                b->last, b->end - b->last,
                                                &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_uint_t
ngx_stream_trojan_inbound_connect_pending(ngx_stream_trojan_ctx_t *ctx)
{
    return ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT
           && (ctx->inbound_socks5 || ctx->inbound_http_proxy)
           && ctx->state != ngx_stream_trojan_state_proxy;
}


static void
ngx_stream_trojan_inbound_connect_success(ngx_stream_trojan_ctx_t *ctx)
{
    if (!ngx_stream_trojan_inbound_connect_pending(ctx)) {
        ngx_stream_trojan_init_proxy(ctx);
        return;
    }

    if (ctx->inbound_socks5) {
        if (ngx_stream_trojan_socks5_in_prepare_response(
                ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_OK)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->state = ngx_stream_trojan_state_socks5_in_response;
        ctx->in_socks5_step =
            ngx_stream_trojan_in_socks5_step_response_write;
        ngx_stream_trojan_process_socks5_in(ctx);
        return;
    }

    if (ngx_stream_trojan_http_in_prepare_response(ctx, 200) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_stream_trojan_state_http_in_response;
    ctx->in_http_step = ngx_stream_trojan_in_http_step_response_write;
    ngx_stream_trojan_process_http_in(ctx);
}


static void
ngx_stream_trojan_inbound_connect_failure(ngx_stream_trojan_ctx_t *ctx,
    ngx_uint_t rc)
{
    if (!ngx_stream_trojan_inbound_connect_pending(ctx)) {
        ngx_stream_trojan_finalize(ctx, rc);
        return;
    }

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    if (ctx->inbound_socks5) {
        if (ngx_stream_trojan_socks5_in_prepare_response(
                ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_GENERAL_FAILURE)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->state = ngx_stream_trojan_state_socks5_in_response;
        ctx->in_socks5_step =
            ngx_stream_trojan_in_socks5_step_response_write;
        ngx_stream_trojan_process_socks5_in(ctx);
        return;
    }

    if (ngx_stream_trojan_http_in_prepare_response(ctx, 502) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_stream_trojan_state_http_in_response;
    ctx->in_http_step = ngx_stream_trojan_in_http_step_response_write;
    ngx_stream_trojan_process_http_in(ctx);
}


static ngx_int_t
ngx_stream_trojan_init_udp_buffers(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_pool_t  *pool;

    pool = ctx->session->connection->pool;

    if (ctx->udp_in == NULL) {
        ctx->udp_in = ngx_pnalloc(pool, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE);
        if (ctx->udp_in == NULL) {
            return NGX_ERROR;
        }
    }

    if (ctx->udp_out == NULL) {
        ctx->udp_out = ngx_pnalloc(pool, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE);
        if (ctx->udp_out == NULL) {
            return NGX_ERROR;
        }
    }

    if (ctx->udp_payload == NULL) {
        ctx->udp_payload = ngx_pnalloc(
            pool, NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE);
        if (ctx->udp_payload == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_stream_trojan_refresh_udp_timeout(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    ngx_add_timer(c->read, ctx->conf->udp_timeout);

    if (pc && pc->read) {
        ngx_add_timer(pc->read, ctx->conf->udp_timeout);
    }
}


static void
ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             i, need;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        if (ctx->conf->websocket_enable && !ctx->websocket) {
            if (ctx->prefix_len >= 4) {
                if (ngx_memcmp(ctx->prefix, "GET ", 4) == 0) {
                    ngx_stream_trojan_websocket_start_handshake(ctx,
                                                               ctx->prefix,
                                                               ctx->prefix_len);
                } else {
                    ngx_stream_trojan_start_fallback(ctx, ctx->prefix,
                                                     ctx->prefix_len);
                }
                return;
            }

            need = 4 - ctx->prefix_len;

        } else {
            if (ctx->prefix_len == NGX_STREAM_TROJAN_PREFIX_LEN) {
                break;
            }

            need = NGX_STREAM_TROJAN_PREFIX_LEN - ctx->prefix_len;
        }

        n = ngx_stream_trojan_client_recv(ctx, ctx->prefix + ctx->prefix_len,
                                          need);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ngx_add_timer(c->read, ctx->conf->timeout);
        for (i = ctx->prefix_len; i < ctx->prefix_len + (size_t) n; i++) {
            if (ctx->prefix[i] == LF && i < NGX_STREAM_TROJAN_KEY_LEN + 1) {
                ctx->prefix_len += (size_t) n;
                if (ctx->websocket) {
                    ngx_stream_trojan_websocket_fail(ctx, 1008,
                                                     NGX_STREAM_FORBIDDEN);
                } else {
                    ngx_stream_trojan_start_fallback(ctx, ctx->prefix,
                                                     ctx->prefix_len);
                }
                return;
            }
        }

        ctx->prefix_len += (size_t) n;
    }

    if (ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN] != CR
        || ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN + 1] != LF
        || ngx_stream_trojan_key_valid(ctx->conf, ctx->prefix) != NGX_OK)
    {
        if (ctx->websocket) {
            ngx_stream_trojan_websocket_fail(ctx, 1008, NGX_STREAM_FORBIDDEN);
        } else {
            ngx_stream_trojan_start_fallback(ctx, ctx->prefix, ctx->prefix_len);
        }
        return;
    }

    ctx->state = ngx_stream_trojan_state_request;
    ngx_stream_trojan_process_request(ctx);
}


static ngx_int_t
ngx_stream_trojan_request_needed(u_char *buf, size_t len, size_t *needed)
{
    size_t addr_len;

    if (len < 2) {
        *needed = 2;
        return NGX_AGAIN;
    }

    if (buf[0] != NGX_STREAM_TROJAN_CMD_CONNECT
        && buf[0] != NGX_STREAM_TROJAN_CMD_ASSOCIATE
        && buf[0] != NGX_STREAM_TROJAN_CMD_MUX)
    {
        return NGX_ERROR;
    }

    switch (buf[1]) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        addr_len = 1 + 4 + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 3) {
            *needed = 3;
            return NGX_AGAIN;
        }
        addr_len = 1 + 1 + buf[2] + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        addr_len = 1 + 16 + 2;
        break;

    default:
        return NGX_ERROR;
    }

    *needed = 1 + addr_len + 2;

    if (len < *needed) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             needed;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        rc = ngx_stream_trojan_request_needed(ctx->request, ctx->request_len,
                                              &needed);

        if (rc == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        if (rc == NGX_OK) {
            break;
        }

        if (needed > sizeof(ctx->request)) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = ngx_stream_trojan_client_recv(ctx,
                                          ctx->request + ctx->request_len,
                                          needed - ctx->request_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->request_len += (size_t) n;
        ngx_add_timer(c->read, ctx->conf->timeout);
    }

    if (ctx->request[needed - 2] != CR || ctx->request[needed - 1] != LF) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    if (ngx_stream_trojan_parse_addr(ctx->request + 1, needed - 3,
                                     &ctx->target)
        != 0)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    ctx->command = ctx->request[0];

    if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT
        && ngx_stream_trojan_is_mux_cool_target(ctx))
    {
        ctx->mux_cool = 1;
        ngx_stream_trojan_start_mux(ctx);
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT
        && ngx_stream_trojan_is_mux_sing_target(ctx))
    {
        ctx->mux_sing = 1;
        ngx_stream_trojan_start_mux(ctx);
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_MUX) {
        ctx->mux_cool = 0;
        ctx->mux_sing = 0;
        ngx_stream_trojan_start_mux(ctx);
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
        && ctx->conf->route_enable)
    {
        ctx->outbound = NULL;
        ngx_stream_trojan_start_udp(ctx);
        return;
    }

    ctx->outbound = ngx_stream_trojan_select_outbound(ctx, &ctx->target,
                                                      ctx->command);

    if (ngx_stream_trojan_route_missed(ctx, ctx->outbound)) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
        return;
    }

    if (ngx_stream_trojan_request_blocked(ctx)) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
        ngx_stream_trojan_start_tcp(ctx);
        return;
    }

    ngx_stream_trojan_start_udp(ctx);
}


static ngx_buf_t *
ngx_stream_trojan_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t  *b;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NULL;
    }

    b->tag = (ngx_buf_tag_t) &ngx_stream_trojan_module;
    return b;
}
static ngx_uint_t
ngx_stream_trojan_websocket_host_match(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_ws_handshake_t *hs)
{
    ngx_str_t  *host;

    host = &ctx->conf->websocket_host;
    if (host->len == 0) {
        return 1;
    }

    return hs->host_len == host->len
           && ngx_strncasecmp((u_char *) hs->host, host->data, host->len)
              == 0;
}


static void
ngx_stream_trojan_websocket_prepare_response(ngx_stream_trojan_ctx_t *ctx,
    uint16_t status, ngx_uint_t accept, const uint8_t *key, size_t key_len)
{
    size_t     written;
    ngx_buf_t *b;

    b = ctx->ws_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (accept) {
        if (ngx_stream_trojan_ws_build_accept_response(key, key_len, b->last,
                (size_t) (b->end - b->last), &written)
            != 0)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        if (ngx_stream_trojan_ws_build_error_response(status, b->last,
                (size_t) (b->end - b->last), &written)
            != 0)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    b->last += written;
    ctx->ws_response_status = status;
    ctx->ws_response_is_accept = accept;
    ctx->state = ngx_stream_trojan_state_ws_response;

    ngx_stream_trojan_flush_websocket_response(ctx);
}


static void
ngx_stream_trojan_websocket_fallback_or_error(ngx_stream_trojan_ctx_t *ctx,
    uint16_t status)
{
    ngx_buf_t  *b;

    b = ctx->ws_buffer;

    if (ctx->conf->fallback != NULL) {
        ngx_stream_trojan_start_fallback(ctx, b->pos, (size_t) (b->last - b->pos));
        return;
    }

    ngx_stream_trojan_websocket_prepare_response(ctx, status, 0, NULL, 0);
}


static ngx_int_t
ngx_stream_trojan_websocket_ensure_raw(ngx_stream_trojan_ctx_t *ctx)
{
    size_t  raw_size;

    if (ctx->ws_raw != NULL) {
        return NGX_OK;
    }

    raw_size = NGX_STREAM_TROJAN_WS_MIN_RAW_BUFFER_SIZE;

    ctx->ws_raw = ngx_stream_trojan_create_temp_buf(
        ctx->session->connection->pool, raw_size);
    if (ctx->ws_raw == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_websocket_start_handshake(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len)
{

    if (ctx->ws_buffer == NULL) {
        ctx->ws_buffer = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool,
            NGX_STREAM_TROJAN_WS_HANDSHAKE_BUFFER_SIZE);
        if (ctx->ws_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }


    if (len > (size_t) (ctx->ws_buffer->end - ctx->ws_buffer->start)) {
        ngx_stream_trojan_websocket_fallback_or_error(ctx, 400);
        return;
    }

    ctx->ws_buffer->pos = ctx->ws_buffer->start;
    ctx->ws_buffer->last = ctx->ws_buffer->start;
    ngx_memcpy(ctx->ws_buffer->last, data, len);
    ctx->ws_buffer->last += len;
    ctx->prefix_len = 0;
    ctx->state = ngx_stream_trojan_state_ws_handshake;

    ngx_stream_trojan_process_websocket_handshake(ctx);
}


static void
ngx_stream_trojan_process_websocket_handshake(ngx_stream_trojan_ctx_t *ctx)
{
    int                                rc;
    ssize_t                            n;
    size_t                             needed, len, extra;
    ngx_buf_t                         *b, *raw;
    ngx_connection_t                  *c;
    ngx_stream_trojan_ws_handshake_t   hs;

    c = ctx->session->connection;
    b = ctx->ws_buffer;
    raw = NULL;

    for ( ;; ) {
        len = (size_t) (b->last - b->pos);
        if (!ngx_stream_trojan_header_end_seen(b->pos, len,
                                               &ctx->ws_header_scan))
        {
            rc = NGX_STREAM_TROJAN_WS_NEED_MORE;
        } else {
            rc = ngx_stream_trojan_ws_parse_handshake(b->pos, len, &needed,
                                                      &hs);
        }

        if (rc == NGX_STREAM_TROJAN_WS_OK) {
            if (hs.path_len != ctx->conf->websocket_path.len
                || ngx_memcmp(hs.path, ctx->conf->websocket_path.data,
                              hs.path_len)
                   != 0)
            {
                ngx_stream_trojan_websocket_fallback_or_error(ctx, 404);
                return;
            }

            if (!ngx_stream_trojan_websocket_host_match(ctx, &hs)) {
                ngx_stream_trojan_websocket_fallback_or_error(ctx, 403);
                return;
            }

            extra = len - hs.header_len;
            if (extra) {
                if (ngx_stream_trojan_websocket_ensure_raw(ctx) != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx,
                                                NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                raw = ctx->ws_raw;
                raw->pos = raw->start;
                raw->last = raw->start;
                ngx_memcpy(raw->last, b->pos + hs.header_len, extra);
                raw->last += extra;
            }

            ngx_stream_trojan_websocket_prepare_response(ctx, 101, 1,
                                                         hs.key, hs.key_len);
            return;
        }

        if (rc == NGX_STREAM_TROJAN_WS_BAD_VERSION) {
            ngx_stream_trojan_websocket_fallback_or_error(ctx, 426);
            return;
        }

        if (rc == NGX_STREAM_TROJAN_WS_ERROR) {
            ngx_stream_trojan_websocket_fallback_or_error(ctx, 400);
            return;
        }

        if (b->last == b->end) {
            ngx_stream_trojan_websocket_fallback_or_error(ctx, 400);
            return;
        }

        n = c->recv(c, b->last, (size_t) (b->end - b->last));
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        b->last += n;
    }
}


static void
ngx_stream_trojan_flush_websocket_response(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = ctx->session->connection;
    b = ctx->ws_buffer;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, (size_t) (b->last - b->pos));

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        b->pos += n;
    }

    b->pos = b->start;
    b->last = b->start;

    if (!ctx->ws_response_is_accept) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    ctx->ws_out = b;

    ctx->websocket = 1;
    ctx->state = ngx_stream_trojan_state_prefix;
    ngx_stream_trojan_process_prefix(ctx);
}


static size_t
ngx_stream_trojan_websocket_raw_pending(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->ws_raw == NULL || ctx->ws_raw->pos == ctx->ws_raw->last) {
        return 0;
    }

    return (size_t) (ctx->ws_raw->last - ctx->ws_raw->pos);
}


static ssize_t
ngx_stream_trojan_websocket_read_raw(ngx_stream_trojan_ctx_t *ctx,
    u_char *dst, size_t size)
{
    size_t             n;
    ssize_t            rc;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    if (size == 0) {
        return NGX_AGAIN;
    }

    if (ngx_stream_trojan_websocket_ensure_raw(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    b = ctx->ws_raw;
    c = ctx->session->connection;

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;

        rc = c->recv(c, b->last, (size_t) (b->end - b->last));
        if (rc == NGX_AGAIN || rc == 0 || rc == NGX_ERROR) {
            return rc;
        }

        b->last += rc;
    }

    n = (size_t) (b->last - b->pos);
    if (n > size) {
        n = size;
    }

    ngx_memcpy(dst, b->pos, n);
    b->pos += n;
    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
    }

    return (ssize_t) n;
}


static ssize_t
ngx_stream_trojan_websocket_read_payload(ngx_stream_trojan_ctx_t *ctx,
    u_char *dst, size_t size)
{
    size_t             n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    if (size == 0) {
        return NGX_AGAIN;
    }

    b = ctx->ws_raw;

    if (b != NULL && b->pos < b->last) {
        n = (size_t) (b->last - b->pos);
        if (n > size) {
            n = size;
        }

        ngx_memcpy(dst, b->pos, n);
        b->pos += n;
        if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;
        }

        return (ssize_t) n;
    }

    if (b != NULL) {
        b->pos = b->start;
        b->last = b->start;
    }

    c = ctx->session->connection;
    return c->recv(c, dst, size);
}


static ngx_uint_t
ngx_stream_trojan_websocket_app_frame_pending(ngx_stream_trojan_ctx_t *ctx)
{
    return ctx->ws_send_header_pos < ctx->ws_send_header_len
           || ctx->ws_send_payload_remaining != 0;
}


static ngx_int_t
ngx_stream_trojan_websocket_flush_out(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    b = ctx->ws_out;
    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    if (ngx_stream_trojan_websocket_app_frame_pending(ctx)) {
        return NGX_OK;
    }

    c = ctx->session->connection;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, (size_t) (b->last - b->pos));

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_websocket_queue_control(ngx_stream_trojan_ctx_t *ctx,
    uint8_t opcode, const u_char *payload, size_t payload_len)
{
    size_t             written;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    if (payload_len > NGX_STREAM_TROJAN_WS_MAX_CONTROL_PAYLOAD
        || (opcode != NGX_STREAM_TROJAN_WS_OPCODE_PONG
            && opcode != NGX_STREAM_TROJAN_WS_OPCODE_CLOSE))
    {
        return NGX_ERROR;
    }

    b = ctx->ws_out;
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (opcode == NGX_STREAM_TROJAN_WS_OPCODE_CLOSE) {
        if (ctx->ws_close_code) {
            return NGX_OK;
        }
        ctx->ws_close_code = 1;

    } else if (ctx->ws_close_code) {
        return NGX_OK;

    } else if (b->pos < b->last && b->pos != b->start) {
        return NGX_OK;
    }

    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_ws_build_frame_header(opcode, payload_len, b->last,
            (size_t) (b->end - b->last), &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    if (payload_len) {
        ngx_memcpy(b->last, payload, payload_len);
        b->last += payload_len;
    }

    c = ctx->session->connection;
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (c->write->ready
        && !ngx_stream_trojan_websocket_app_frame_pending(ctx)
        && ngx_stream_trojan_websocket_flush_out(ctx) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_websocket_process_closing(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (ngx_stream_trojan_websocket_app_frame_pending(ctx)) {
        ngx_stream_trojan_finalize(ctx, ctx->ws_finalize_rc);
        return;
    }

    rc = ngx_stream_trojan_websocket_flush_out(ctx);
    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    ngx_stream_trojan_finalize(ctx, ctx->ws_finalize_rc);
}


static void
ngx_stream_trojan_websocket_fail(ngx_stream_trojan_ctx_t *ctx, uint16_t code,
    ngx_uint_t rc)
{
    u_char             payload[2];
    ngx_connection_t  *c;

    if (!ctx->websocket || ctx->state == ngx_stream_trojan_state_ws_closing) {
        return;
    }

    payload[0] = (u_char) (code >> 8);
    payload[1] = (u_char) code;

    ctx->ws_finalize_rc = rc;
    ctx->state = ngx_stream_trojan_state_ws_closing;

    c = ctx->session->connection;
    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;

    if (ngx_stream_trojan_websocket_queue_control(ctx,
            NGX_STREAM_TROJAN_WS_OPCODE_CLOSE, payload, sizeof(payload))
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_post_event(c->write, &ngx_posted_events);
}


static ngx_int_t
ngx_stream_trojan_websocket_handle_frame_end(ngx_stream_trojan_ctx_t *ctx)
{
    u_char  *payload;
    size_t   payload_len;

    if (ctx->ws_frame.opcode == NGX_STREAM_TROJAN_WS_OPCODE_BINARY) {
        if (!ctx->ws_frame.fin) {
            ctx->ws_fragmented = 1;
            ctx->ws_fragment_opcode = NGX_STREAM_TROJAN_WS_OPCODE_BINARY;
        }
        return NGX_OK;
    }

    if (ctx->ws_frame.opcode == NGX_STREAM_TROJAN_WS_OPCODE_CONT) {
        if (ctx->ws_frame.fin) {
            ctx->ws_fragmented = 0;
            ctx->ws_fragment_opcode = 0;
        }
        return NGX_OK;
    }

    payload = ctx->ws_control;
    payload_len = ctx->ws_control_len;
    ctx->ws_control_len = 0;

    switch (ctx->ws_frame.opcode) {
    case NGX_STREAM_TROJAN_WS_OPCODE_PING:
        if (ngx_stream_trojan_websocket_queue_control(ctx,
                NGX_STREAM_TROJAN_WS_OPCODE_PONG, payload, payload_len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;

    case NGX_STREAM_TROJAN_WS_OPCODE_PONG:
        return NGX_OK;

    case NGX_STREAM_TROJAN_WS_OPCODE_CLOSE:
        if (payload_len == 1) {
            ngx_stream_trojan_websocket_fail(ctx, 1002,
                                             NGX_STREAM_BAD_REQUEST);
            return NGX_AGAIN;
        }

        ctx->ws_finalize_rc = NGX_STREAM_OK;
        ctx->state = ngx_stream_trojan_state_ws_closing;
        ctx->session->connection->read->handler = ngx_stream_trojan_read_client;
        ctx->session->connection->write->handler = ngx_stream_trojan_read_client;
        if (ngx_stream_trojan_websocket_queue_control(ctx,
                NGX_STREAM_TROJAN_WS_OPCODE_CLOSE, payload, payload_len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        ngx_post_event(ctx->session->connection->write, &ngx_posted_events);
        return NGX_AGAIN;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_stream_trojan_websocket_start_frame(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_stream_trojan_ws_frame_t *frame;

    frame = &ctx->ws_frame;

    if (!frame->masked) {
        ngx_stream_trojan_websocket_fail(ctx, 1002, NGX_STREAM_BAD_REQUEST);
        return NGX_AGAIN;
    }

    switch (frame->opcode) {
    case NGX_STREAM_TROJAN_WS_OPCODE_BINARY:
        if (ctx->ws_fragmented) {
            ngx_stream_trojan_websocket_fail(ctx, 1002,
                                             NGX_STREAM_BAD_REQUEST);
            return NGX_AGAIN;
        }
        break;

    case NGX_STREAM_TROJAN_WS_OPCODE_CONT:
        if (!ctx->ws_fragmented
            || ctx->ws_fragment_opcode != NGX_STREAM_TROJAN_WS_OPCODE_BINARY)
        {
            ngx_stream_trojan_websocket_fail(ctx, 1002,
                                             NGX_STREAM_BAD_REQUEST);
            return NGX_AGAIN;
        }
        break;

    case NGX_STREAM_TROJAN_WS_OPCODE_TEXT:
        ngx_stream_trojan_websocket_fail(ctx, 1003, NGX_STREAM_BAD_REQUEST);
        return NGX_AGAIN;

    case NGX_STREAM_TROJAN_WS_OPCODE_CLOSE:
    case NGX_STREAM_TROJAN_WS_OPCODE_PING:
    case NGX_STREAM_TROJAN_WS_OPCODE_PONG:
        break;

    default:
        ngx_stream_trojan_websocket_fail(ctx, 1002, NGX_STREAM_BAD_REQUEST);
        return NGX_AGAIN;
    }

    ctx->ws_frame_active = 1;
    ctx->ws_payload_remaining = frame->payload_len;
    ctx->ws_mask_offset = 0;
    ctx->ws_control_len = 0;

    if (ctx->ws_payload_remaining == 0) {
        ctx->ws_frame_active = 0;
        return ngx_stream_trojan_websocket_handle_frame_end(ctx);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_websocket_count_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_uint_t *frames)
{
    (*frames)++;
    if (*frames < NGX_STREAM_TROJAN_WS_MAX_FRAMES_PER_RECV) {
        return NGX_OK;
    }

    ngx_post_event(ctx->session->connection->read, &ngx_posted_events);
    return NGX_AGAIN;
}


static ssize_t
ngx_stream_trojan_client_recv(ngx_stream_trojan_ctx_t *ctx, u_char *dst,
    size_t size)
{
    int          prc;
    ssize_t      n;
    size_t       needed, chunk, produced;
    ngx_int_t    rc;
    ngx_uint_t   frames;

    if (!ctx->websocket) {
        return ctx->session->connection->recv(ctx->session->connection, dst,
                                              size);
    }

    if (ctx->state == ngx_stream_trojan_state_ws_closing) {
        return NGX_AGAIN;
    }

    if (size == 0) {
        return NGX_AGAIN;
    }

    produced = 0;
    frames = 0;

    for ( ;; ) {
        if (produced == size) {
            return (ssize_t) produced;
        }

        if (ctx->ws_frame_active) {
            if (ctx->ws_frame.opcode == NGX_STREAM_TROJAN_WS_OPCODE_BINARY
                || ctx->ws_frame.opcode == NGX_STREAM_TROJAN_WS_OPCODE_CONT)
            {
                chunk = size - produced;
                if (chunk > ctx->ws_payload_remaining) {
                    chunk = (size_t) ctx->ws_payload_remaining;
                }

                n = ngx_stream_trojan_websocket_read_payload(
                    ctx, dst + produced, chunk);
                if (n == NGX_AGAIN || n == 0 || n == NGX_ERROR) {
                    return produced ? (ssize_t) produced : n;
                }

                ngx_stream_trojan_ws_apply_mask(dst + produced, (size_t) n,
                                                ctx->ws_frame.mask,
                                                ctx->ws_mask_offset);
                ctx->ws_mask_offset += (uint64_t) n;
                ctx->ws_payload_remaining -= (uint64_t) n;
                produced += (size_t) n;

                if (ctx->ws_payload_remaining == 0) {
                    ctx->ws_frame_active = 0;
                    rc = ngx_stream_trojan_websocket_handle_frame_end(ctx);
                    if (rc == NGX_ERROR) {
                        return produced ? (ssize_t) produced : NGX_ERROR;
                    }
                    if (rc == NGX_AGAIN) {
                        return produced ? (ssize_t) produced : NGX_AGAIN;
                    }
                    if (ngx_stream_trojan_websocket_count_frame(ctx, &frames)
                        != NGX_OK)
                    {
                        return produced ? (ssize_t) produced : NGX_AGAIN;
                    }
                }

                continue;
            }

            chunk = ctx->ws_frame.payload_len - ctx->ws_control_len;
            n = ngx_stream_trojan_websocket_read_raw(
                ctx, ctx->ws_control + ctx->ws_control_len, chunk);
            if (n == NGX_AGAIN || n == 0 || n == NGX_ERROR) {
                return produced ? (ssize_t) produced : n;
            }

            ngx_stream_trojan_ws_apply_mask(
                ctx->ws_control + ctx->ws_control_len, (size_t) n,
                ctx->ws_frame.mask, ctx->ws_mask_offset);
            ctx->ws_mask_offset += (uint64_t) n;
            ctx->ws_control_len += (size_t) n;
            ctx->ws_payload_remaining -= (uint64_t) n;

            if (ctx->ws_payload_remaining == 0) {
                ctx->ws_frame_active = 0;
                rc = ngx_stream_trojan_websocket_handle_frame_end(ctx);
                if (rc == NGX_ERROR) {
                    return produced ? (ssize_t) produced : NGX_ERROR;
                }
                if (rc == NGX_AGAIN) {
                    return produced ? (ssize_t) produced : NGX_AGAIN;
                }
                if (ngx_stream_trojan_websocket_count_frame(ctx, &frames)
                    != NGX_OK)
                {
                    return produced ? (ssize_t) produced : NGX_AGAIN;
                }
            }

            continue;
        }

        for ( ;; ) {
            prc = ngx_stream_trojan_ws_parse_frame_header(
                ctx->ws_header, ctx->ws_header_len, &needed, &ctx->ws_frame);

            if (prc == NGX_STREAM_TROJAN_WS_OK) {
                ctx->ws_header_len = 0;
                rc = ngx_stream_trojan_websocket_start_frame(ctx);
                if (rc == NGX_ERROR) {
                    return produced ? (ssize_t) produced : NGX_ERROR;
                }
                if (rc == NGX_AGAIN) {
                    return produced ? (ssize_t) produced : NGX_AGAIN;
                }
                if (!ctx->ws_frame_active
                    && ngx_stream_trojan_websocket_count_frame(ctx, &frames)
                       != NGX_OK)
                {
                    return produced ? (ssize_t) produced : NGX_AGAIN;
                }
                break;
            }

            if (prc == NGX_STREAM_TROJAN_WS_ERROR) {
                ctx->ws_header_len = 0;
                ngx_stream_trojan_websocket_fail(ctx, 1002,
                                                 NGX_STREAM_BAD_REQUEST);
                return produced ? (ssize_t) produced : NGX_AGAIN;
            }

            n = ngx_stream_trojan_websocket_read_raw(
                ctx, ctx->ws_header + ctx->ws_header_len,
                needed - ctx->ws_header_len);
            if (n == NGX_AGAIN || n == 0 || n == NGX_ERROR) {
                return produced ? (ssize_t) produced : n;
            }

            ctx->ws_header_len += (size_t) n;
        }
    }
}


static ssize_t
ngx_stream_trojan_websocket_send_parts(ngx_stream_trojan_ctx_t *ctx,
    u_char *src, size_t size, u_char *next, size_t next_size,
    size_t frame_size, size_t *first_sent, size_t *second_sent)
{
    size_t             first_size, second_size, payload_sent;
    ngx_buf_t          hb, fb, sb;
    ngx_chain_t        hcl, fcl, scl, *cl, *tail, *out;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    if (first_sent != NULL) {
        *first_sent = 0;
    }
    if (second_sent != NULL) {
        *second_sent = 0;
    }

    rc = ngx_stream_trojan_websocket_flush_out(ctx);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (ctx->state == ngx_stream_trojan_state_ws_closing) {
        return NGX_AGAIN;
    }

    if (c->send_chain == NULL) {
        return NGX_ERROR;
    }

    if (ctx->ws_send_header_len == 0
        && ctx->ws_send_payload_remaining == 0)
    {
        if (ngx_stream_trojan_ws_build_frame_header(
                NGX_STREAM_TROJAN_WS_OPCODE_BINARY, frame_size,
                ctx->ws_send_header, sizeof(ctx->ws_send_header),
                &ctx->ws_send_header_len)
            != 0)
        {
            return NGX_ERROR;
        }

        ctx->ws_send_header_pos = 0;
        ctx->ws_send_payload_remaining = frame_size;
    }

    first_size = size;
    if (first_size > ctx->ws_send_payload_remaining) {
        first_size = ctx->ws_send_payload_remaining;
    }

    second_size = 0;
    if (first_size == size && next_size) {
        second_size = ctx->ws_send_payload_remaining - first_size;
        if (second_size > next_size) {
            second_size = next_size;
        }
    }

    ngx_memzero(&hb, sizeof(ngx_buf_t));
    ngx_memzero(&fb, sizeof(ngx_buf_t));
    ngx_memzero(&sb, sizeof(ngx_buf_t));

    hb.pos = ctx->ws_send_header + ctx->ws_send_header_pos;
    hb.last = ctx->ws_send_header + ctx->ws_send_header_len;
    hb.memory = 1;
    hcl.buf = &hb;

    fb.pos = src;
    fb.last = src + first_size;
    fb.memory = 1;
    fcl.buf = &fb;

    if (second_size) {
        sb.pos = next;
        sb.last = next + second_size;
        sb.memory = 1;
        scl.buf = &sb;
    }

    cl = NULL;
    tail = NULL;

    if (hb.pos < hb.last) {
        cl = &hcl;
        tail = &hcl;
    }

    if (first_size) {
        if (tail != NULL) {
            tail->next = &fcl;
        } else {
            cl = &fcl;
        }
        tail = &fcl;
    }

    if (second_size) {
        if (tail != NULL) {
            tail->next = &scl;
        } else {
            cl = &scl;
        }
        tail = &scl;
    }

    if (tail == NULL) {
        return NGX_AGAIN;
    }
    tail->next = NULL;

    out = c->send_chain(c, cl, 0);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx->ws_send_header_pos = (size_t) (hb.pos - ctx->ws_send_header);
    payload_sent = (size_t) (fb.pos - src);
    if (second_size) {
        payload_sent += (size_t) (sb.pos - next);
    }

    if (first_sent != NULL) {
        *first_sent = (size_t) (fb.pos - src);
    }
    if (second_sent != NULL && second_size) {
        *second_sent = (size_t) (sb.pos - next);
    }

    ctx->ws_send_payload_remaining -= payload_sent;

    if (ctx->ws_send_payload_remaining == 0
        && ctx->ws_send_header_pos == ctx->ws_send_header_len)
    {
        ctx->ws_send_header_len = 0;
        ctx->ws_send_header_pos = 0;

        if (ctx->ws_out != NULL && ctx->ws_out->pos < ctx->ws_out->last
            && c->write->ready)
        {
            rc = ngx_stream_trojan_websocket_flush_out(ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    if (out != NULL) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return payload_sent ? (ssize_t) payload_sent : NGX_AGAIN;
    }

    return (ssize_t) payload_sent;
}


static ssize_t
ngx_stream_trojan_client_send_part(ngx_stream_trojan_ctx_t *ctx, u_char *src,
    size_t size, size_t frame_size)
{
    if (!ctx->websocket) {
        return ctx->session->connection->send(ctx->session->connection, src,
                                              size);
    }

    return ngx_stream_trojan_websocket_send_parts(ctx, src, size, NULL, 0,
                                                  frame_size, NULL, NULL);
}



static ssize_t
ngx_stream_trojan_client_send_parts(ngx_stream_trojan_ctx_t *ctx, u_char *src,
    size_t size, const u_char *next, size_t next_size, size_t frame_size,
    size_t *first_sent, size_t *second_sent)
{
    size_t             payload_sent;
    ngx_buf_t          fb, sb;
    ngx_chain_t        fcl, scl, *cl, *tail, *out;
    ngx_connection_t  *c;

    if (first_sent != NULL) {
        *first_sent = 0;
    }
    if (second_sent != NULL) {
        *second_sent = 0;
    }
    c = ctx->session->connection;

    if (ctx->websocket) {
        return ngx_stream_trojan_websocket_send_parts(ctx, src, size,
                                                      (u_char *) next,
                                                      next_size, frame_size,
                                                      first_sent, second_sent);
    }

    if (c->send_chain == NULL) {
        ssize_t  n;

        if (size != 0) {
            n = c->send(c, src, size);
            if (n > 0 && first_sent != NULL) {
                *first_sent = (size_t) n;
            }
            return n;
        }

        if (next_size != 0) {
            n = c->send(c, (u_char *) next, next_size);
            if (n > 0 && second_sent != NULL) {
                *second_sent = (size_t) n;
            }
            return n;
        }

        return NGX_AGAIN;
    }

    ngx_memzero(&fb, sizeof(ngx_buf_t));
    ngx_memzero(&sb, sizeof(ngx_buf_t));

    cl = NULL;
    tail = NULL;

    if (size != 0) {
        fb.pos = src;
        fb.last = src + size;
        fb.memory = 1;
        fcl.buf = &fb;
        cl = &fcl;
        tail = &fcl;
    }

    if (next_size != 0) {
        sb.pos = (u_char *) next;
        sb.last = (u_char *) next + next_size;
        sb.memory = 1;
        scl.buf = &sb;

        if (tail != NULL) {
            tail->next = &scl;
        } else {
            cl = &scl;
        }

        tail = &scl;
    }

    if (tail == NULL) {
        return NGX_AGAIN;
    }
    tail->next = NULL;

    out = c->send_chain(c, cl, 0);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    payload_sent = 0;
    if (size != 0) {
        payload_sent += (size_t) (fb.pos - src);
        if (first_sent != NULL) {
            *first_sent = (size_t) (fb.pos - src);
        }
    }

    if (next_size != 0) {
        payload_sent += (size_t) (sb.pos - next);
        if (second_sent != NULL) {
            *second_sent = (size_t) (sb.pos - next);
        }
    }

    if (out != NULL) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return payload_sent ? (ssize_t) payload_sent : NGX_AGAIN;
    }

    return (ssize_t) payload_sent;
}


static ssize_t
ngx_stream_trojan_client_send(ngx_stream_trojan_ctx_t *ctx, u_char *src,
    size_t size)
{
    return ngx_stream_trojan_client_send_part(ctx, src, size, size);
}


static ngx_uint_t
ngx_stream_trojan_client_read_ready(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src)
{
    if (!ctx->websocket || src != ctx->session->connection) {
        return src->read->ready;
    }

    return src->read->ready
           || ngx_stream_trojan_websocket_raw_pending(ctx) != 0
           || (ctx->ws_frame_active && ctx->ws_payload_remaining > 0)
           || ctx->ws_header_len > 0;
}


static void
ngx_stream_trojan_post_read_if_ready(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c)
{
    if (c != NULL && c->read != NULL
        && ngx_stream_trojan_client_read_ready(ctx, c))
    {
        ngx_post_event(c->read, &ngx_posted_next_events);
    }
}

static void
ngx_stream_trojan_compact_udp_input(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->udp_in_pos == 0) {
        return;
    }

    if (ctx->udp_in_len != 0) {
        ngx_memmove(ctx->udp_in, ctx->udp_in + ctx->udp_in_pos,
                    ctx->udp_in_len);
    }

    ctx->udp_in_pos = 0;
}


static ngx_uint_t
ngx_stream_trojan_header_end_seen(u_char *buf, size_t len, size_t *scan)
{
    size_t  i;

    if (len < 4) {
        *scan = 0;
        return 0;
    }

    i = *scan;
    if (i > 3) {
        i -= 3;
    } else {
        i = 0;
    }

    for (; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n'
            && buf[i + 2] == '\r' && buf[i + 3] == '\n')
        {
            return 1;
        }
    }

    *scan = len - 3;
    return 0;
}


static void
ngx_stream_trojan_consume_udp_input(ngx_stream_trojan_ctx_t *ctx,
    size_t wire_len)
{
    if (wire_len >= ctx->udp_in_len) {
        ctx->udp_in_pos = 0;
        ctx->udp_in_len = 0;
        return;
    }

    ctx->udp_in_pos += wire_len;
    ctx->udp_in_len -= wire_len;
}




static void
ngx_stream_trojan_post_udp_read_if_ready(ngx_connection_t *c)
{
    if (c != NULL && c->read != NULL && c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_next_events);
    }
}
static void
ngx_stream_trojan_post_udp_client_read(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c;

    if (ctx == NULL || ctx->session == NULL) {
        return;
    }

    c = ctx->session->connection;
    if (c != NULL && c->read != NULL
        && (ctx->udp_in_len != 0
            || ngx_stream_trojan_client_read_ready(ctx, c)))
    {
        ngx_post_event(c->read, &ngx_posted_next_events);
    }
}



static void
ngx_stream_trojan_post_write_if_ready(ngx_connection_t *c)
{
    if (c != NULL && c->write != NULL && c->write->ready) {
        ngx_post_event(c->write, &ngx_posted_next_events);
    }
}


static ngx_int_t
ngx_stream_trojan_set_pending(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    ctx->pending_to_upstream = ngx_stream_trojan_create_temp_buf(
        ctx->session->connection->pool, len ? len : 1);

    if (ctx->pending_to_upstream == NULL) {
        return NGX_ERROR;
    }

    if (len) {
        ngx_memcpy(ctx->pending_to_upstream->last, data, len);
        ctx->pending_to_upstream->last += len;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_ensure_pending(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->pending_to_upstream != NULL) {
        return NGX_OK;
    }

    return ngx_stream_trojan_set_pending(ctx, NULL, 0);
}


static void
ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    if (ctx->conf->fallback == NULL) {
        ngx_stream_trojan_start_default_fallback(ctx);
        return;
    }

    if (ngx_stream_trojan_set_pending(ctx, data, len) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->connect_addrs = ctx->conf->fallback;
    ctx->connect_naddrs = ctx->conf->fallback_naddrs;
    ctx->connect_index = 0;
    ctx->peer_kind = ngx_stream_trojan_peer_fallback;
    ngx_stream_trojan_connect(ctx, ctx->conf->fallback);
}


static void
ngx_stream_trojan_start_default_fallback(ngx_stream_trojan_ctx_t *ctx)
{
    size_t         len;
    const u_char  *response;
    ngx_connection_t *c;

    c = ctx->session->connection;
    response = ngx_stream_trojan_default_fallback_response(&len);

    ctx->pending_to_client = ngx_stream_trojan_create_temp_buf(c->pool, len);
    if (ctx->pending_to_client == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memcpy(ctx->pending_to_client->last, response, len);
    ctx->pending_to_client->last += len;

    ctx->state = ngx_stream_trojan_state_default_fallback;
    c->write->handler = ngx_stream_trojan_default_fallback_write_handler;
    c->read->handler = ngx_stream_trojan_default_fallback_write_handler;

    ngx_add_timer(c->write, ctx->conf->timeout);
    ngx_stream_trojan_default_fallback_write_handler(c->write);
}


static void
ngx_stream_trojan_default_fallback_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL || ev->timedout) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    switch (ngx_stream_trojan_flush_default_fallback(ctx)) {
    case NGX_OK:
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;

    case NGX_AGAIN:
        return;

    default:
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }
}


static ngx_int_t
ngx_stream_trojan_flush_default_fallback(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->pending_to_client;

    while (b != NULL && b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, ctx->conf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
        ngx_add_timer(c->write, ctx->conf->timeout);
    }

    return NGX_OK;
}



static uint16_t
ngx_stream_trojan_doh_first_qtype(ngx_uint_t ip_prefer)
{
#if (NGX_HAVE_INET6)
    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6) {
        return 28; /* AAAA */
    }
#else
    (void) ip_prefer;
#endif

    return 1; /* A */
}


static uint16_t
ngx_stream_trojan_doh_fallback_qtype(ngx_uint_t ip_prefer)
{
#if (NGX_HAVE_INET6)
    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6) {
        return 1; /* A */
    }

    return 28; /* AAAA */
#else
    (void) ip_prefer;
    return 0;
#endif
}



static ngx_stream_trojan_resolve_data_t *
ngx_stream_trojan_create_doh_resolve_data(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_stream_trojan_resolve_e type,
    const u_char *payload, uint16_t payload_len, size_t wire_len,
    ngx_uint_t ip_prefer, ngx_stream_trojan_doh_conf_t *doh_conf)
{
    ngx_pool_t                       *pool;
    ngx_stream_trojan_resolve_data_t *data;

    if (doh_conf == NULL
        || addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || addr->host_len == 0 || addr->host_len > 255)
    {
        return NULL;
    }

    if (payload_len != 0 && payload == NULL) {
        return NULL;
    }

    pool = ctx->session->connection->pool;

    data = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_resolve_data_t));
    if (data == NULL) {
        return NULL;
    }

    data->name = ngx_pnalloc(pool, addr->host_len);
    if (data->name == NULL) {
        return NULL;
    }
    ngx_memcpy(data->name, addr->host, addr->host_len);

    if (payload_len != 0) {
        data->payload = ngx_pnalloc(pool, payload_len);
        if (data->payload == NULL) {
            return NULL;
        }
        ngx_memcpy(data->payload, payload, payload_len);
    }

    data->ctx = ctx;
    data->type = type;
    data->ip_prefer = ip_prefer;
    data->doh_conf = doh_conf;
    data->name_len = addr->host_len;
    data->qtype = ngx_stream_trojan_doh_first_qtype(ip_prefer);
    data->fallback_qtype = ngx_stream_trojan_doh_fallback_qtype(ip_prefer);
    data->port = addr->port;
    data->payload_len = payload_len;

    if (type == ngx_stream_trojan_resolve_udp
        && wire_len <= ctx->udp_in_len)
    {
        ngx_stream_trojan_consume_udp_input(ctx, wire_len);
    }

    return data;
}


static ngx_stream_trojan_mux_resolve_data_t *
ngx_stream_trojan_mux_create_doh_resolve_data(
    ngx_stream_trojan_mux_stream_t *stream, ngx_uint_t ip_prefer,
    ngx_stream_trojan_doh_conf_t *doh_conf)
{
    ngx_pool_t                           *pool;
    ngx_stream_trojan_mux_resolve_data_t *data;

    if (doh_conf == NULL
        || stream->target.type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || stream->target.host_len == 0 || stream->target.host_len > 255)
    {
        return NULL;
    }

    pool = stream->pool;

    data = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_mux_resolve_data_t));
    if (data == NULL) {
        return NULL;
    }

    data->name = ngx_pnalloc(pool, stream->target.host_len);
    if (data->name == NULL) {
        return NULL;
    }
    ngx_memcpy(data->name, stream->target.host, stream->target.host_len);

    data->stream = stream;
    data->ip_prefer = ip_prefer;
    data->doh_conf = doh_conf;
    data->name_len = stream->target.host_len;
    data->qtype = ngx_stream_trojan_doh_first_qtype(ip_prefer);
    data->fallback_qtype = ngx_stream_trojan_doh_fallback_qtype(ip_prefer);
    data->port = stream->target.port;

    return data;
}


static ngx_int_t
ngx_stream_trojan_start_doh_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_resolve_data_t *data)
{
    if (data->doh_conf == NULL
        || data->name == NULL || data->name_len == 0)
    {
        return NGX_ERROR;
    }
    if (ctx->doh_ctx != NULL) {
        return NGX_BUSY;
    }

    ctx->state = ngx_stream_trojan_state_resolving;

    return ngx_stream_trojan_doh_resolve(data->doh_conf,
        data->name, data->name_len, data->qtype,
        ctx->session->connection->log, data,
        ngx_stream_trojan_doh_resolve_handler, &ctx->doh_ctx);
}


static void
ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_addr_t                          addr;
    ngx_stream_trojan_resolve_data_t   *data;
    ngx_stream_trojan_srv_conf_t       *conf;
    ngx_stream_trojan_dns_rule_group_t *dns_rule;

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        ngx_stream_trojan_start_socks5_tcp(ctx);
        return;
    }

    conf = ctx->conf;
    dns_rule = ngx_stream_trojan_match_dns_rule(conf, &ctx->target);

    if (dns_rule != NULL) {
        if (ngx_stream_trojan_set_pending(ctx, NULL, 0) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->peer_kind = ngx_stream_trojan_peer_tcp;

        if (dns_rule->doh_conf != NULL) {
            data = ngx_stream_trojan_create_doh_resolve_data(ctx, &ctx->target,
                       ngx_stream_trojan_resolve_tcp, NULL, 0, 0,
                       dns_rule->ip_prefer, dns_rule->doh_conf);
            if (data == NULL) {
                ngx_stream_trojan_finalize(ctx,
                                           NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_stream_trojan_start_doh_resolver(ctx, data) != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
            }
            return;
        }

        if (ngx_stream_trojan_start_resolver(ctx, &ctx->target,
                                             ngx_stream_trojan_resolve_tcp,
                                             NULL, 0, 0, dns_rule->resolver,
                                             0, dns_rule->ip_prefer)
            != NGX_OK)
        {
            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
        }
        return;
    }

    /* try DoH first if configured and target is a domain */
    if (conf->doh_conf != NULL
        && ctx->target.type == NGX_STREAM_TROJAN_ADDR_DOMAIN
        && ctx->target.host_len > 0 && ctx->target.host_len <= 255)
    {
        data = ngx_stream_trojan_create_doh_resolve_data(ctx, &ctx->target,
                   ngx_stream_trojan_resolve_tcp, NULL, 0, 0,
                   ngx_stream_trojan_current_ip_prefer(ctx), conf->doh_conf);
        if (data == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->peer_kind = ngx_stream_trojan_peer_tcp;

        if (ngx_stream_trojan_start_doh_resolver(ctx, data) != NGX_OK)
        {
            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
        }
        return;
    }

    /* fallback to nginx resolver */
    if (ngx_stream_trojan_use_nginx_resolver(
            ctx->target.type,
            ngx_stream_trojan_resolver_configured(ctx->session)))
    {
        if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->peer_kind = ngx_stream_trojan_peer_tcp;
        if (ngx_stream_trojan_start_resolver(ctx, &ctx->target,
                                             ngx_stream_trojan_resolve_tcp,
                                             NULL, 0, 0, NULL, 0,
                                             ngx_stream_trojan_current_ip_prefer(ctx))
            != NGX_OK)
        {
            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
        }
        return;
    }

    /* synchronous fallback */
    if (ngx_stream_trojan_resolve_addr_prefer(ctx->session->connection->pool,
                                              ctx->session->connection->log,
                                              &ctx->target,
                                              ngx_stream_trojan_current_ip_prefer(ctx),
                                              &addr)
        != NGX_OK)
    {
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_tcp;
    ngx_stream_trojan_connect(ctx, &addr);
}

static void
ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_init_udp_buffers(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        ngx_stream_trojan_start_socks5_udp(ctx);
        return;
    }

    ctx->state = ngx_stream_trojan_state_udp;
    ctx->session->connection->write->handler =
        ngx_stream_trojan_udp_client_write_handler;
    ngx_add_timer(ctx->session->connection->read, ctx->conf->udp_timeout);
    ngx_stream_trojan_process_udp_client(ctx);
}


static ngx_int_t
ngx_stream_trojan_start_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_stream_trojan_resolve_e type,
    const u_char *payload, uint16_t payload_len, size_t wire_len,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout,
    ngx_uint_t ip_prefer)
{
    ngx_str_t                         name;
    ngx_pool_t                       *pool;
    ngx_resolver_ctx_t               *rctx, temp;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_trojan_resolve_data_t *data;

    if (addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || addr->host_len == 0 || addr->host_len > 255)
    {
        return NGX_ERROR;
    }

    pool = ctx->session->connection->pool;

    data = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_resolve_data_t));
    if (data == NULL) {
        return NGX_ERROR;
    }

    name.data = ngx_pnalloc(pool, addr->host_len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(name.data, addr->host, addr->host_len);
    name.len = addr->host_len;

    if (payload_len) {
        data->payload = ngx_pnalloc(pool, payload_len);
        if (data->payload == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(data->payload, payload, payload_len);
    }

    data->ctx = ctx;
    data->type = type;
    data->ip_prefer = ip_prefer;
    data->port = addr->port;
    data->payload_len = payload_len;

    ngx_memzero(&temp, sizeof(ngx_resolver_ctx_t));
    temp.name = name;

    cscf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_core_module);
    if (resolver == NULL) {
        resolver = cscf->resolver;
    }
    if (resolver_timeout == 0) {
        resolver_timeout = cscf->resolver_timeout;
    }

    rctx = ngx_resolve_start(resolver, &temp);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        return NGX_ERROR;
    }

    rctx->name = name;
    rctx->handler = ngx_stream_trojan_resolve_handler;
    rctx->data = data;
    rctx->timeout = resolver_timeout;

    ctx->resolver_ctx = rctx;
    ctx->state = ngx_stream_trojan_state_resolving;

    if (type == ngx_stream_trojan_resolve_udp && wire_len <= ctx->udp_in_len) {
        ngx_stream_trojan_consume_udp_input(ctx, wire_len);
    }

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ctx->resolver_ctx = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}



static void
ngx_stream_trojan_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_stream_trojan_ctx_t           *ctx;
    ngx_stream_trojan_resolve_data_t  *data;

    data = rctx->data;
    ctx = data->ctx;

    if (ctx == NULL) {
        ngx_resolve_name_done(rctx);
        return;
    }

    ctx->resolver_ctx = NULL;

    if (rctx->state) {
        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &rctx->name, rctx->state,
                      ngx_resolver_strerror(rctx->state));
        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_stream_trojan_resolve_complete(ctx, data, rctx->addrs, rctx->naddrs);
    ngx_resolve_name_done(rctx);
}


static void
ngx_stream_trojan_resolve_complete(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_resolve_data_t *data,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs)
{
    ngx_addr_t   *tcp_addrs;
    ngx_uint_t    ntcp_addrs;

    if (data->type == ngx_stream_trojan_resolve_tcp) {
        if (naddrs == 0
            || ngx_stream_trojan_resolver_addrs_to_ngx_addrs(
                   ctx->session->connection->pool, addrs, naddrs,
                   data->port, data->ip_prefer, &tcp_addrs, &ntcp_addrs)
               != NGX_OK)
        {
            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ctx->connect_addrs = tcp_addrs;
        ctx->connect_naddrs = ntcp_addrs;
        ctx->connect_index = 0;
        ngx_stream_trojan_connect(ctx, &ctx->connect_addrs[0]);
        return;
    }

    if (ngx_stream_trojan_send_udp_resolved(ctx, addrs, naddrs,
                                            data->port, data->payload,
                                            data->payload_len,
                                            data->ip_prefer)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ctx->inbound_socks5) {
        ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
        ngx_stream_trojan_post_socks5_in_udp_read(ctx);
        return;
    }
    ctx->state = ngx_stream_trojan_state_udp;
    ngx_stream_trojan_post_udp_client_read(ctx);
}


static void
ngx_stream_trojan_doh_resolve_handler(void *cb_data, ngx_int_t status,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs)
{
    ngx_stream_trojan_resolve_data_t  *data;
    ngx_stream_trojan_ctx_t           *ctx;

    data = cb_data;
    ctx = data->ctx;

    if (ctx == NULL) {
        return;
    }
    ctx->doh_ctx = NULL;

    if (status != NGX_OK || naddrs == 0) {
        if (status == NGX_DECLINED && data->fallback_qtype != 0) {
            data->qtype = data->fallback_qtype;
            data->fallback_qtype = 0;

            if (ngx_stream_trojan_start_doh_resolver(ctx, data) == NGX_OK) {
                return;
            }
        }

        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log, 0,
                      "DoH: resolution failed");
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_stream_trojan_resolve_complete(ctx, data, addrs, naddrs);
}

static ngx_int_t
ngx_stream_trojan_connect_next(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->connect_addrs == NULL
        || ctx->connect_index + 1 >= ctx->connect_naddrs)
    {
        return NGX_DECLINED;
    }

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    ctx->connect_index++;
    ngx_stream_trojan_connect(ctx, &ctx->connect_addrs[ctx->connect_index]);

    return NGX_OK;
}


static void
ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx, ngx_addr_t *addr)
{
    ngx_int_t          rc;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    ctx->state = ngx_stream_trojan_state_connecting;

    ngx_memzero(&ctx->peer, sizeof(ngx_peer_connection_t));
    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer_name = addr->name;
    ctx->peer.name = &ctx->peer_name;
    ctx->peer.type = SOCK_STREAM;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.tries = 1;
    ctx->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (ngx_stream_trojan_connect_next(ctx) == NGX_OK) {
            return;
        }

        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    pc = ctx->peer.connection;
    ctx->upstream = pc;

    pc->data = ctx;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc == NGX_AGAIN) {
        pc->read->handler = ngx_stream_trojan_peer_handler;
        pc->write->handler = ngx_stream_trojan_peer_handler;
        ngx_add_timer(pc->write, ctx->conf->connect_timeout);
        return;
    }

    ngx_stream_trojan_inbound_connect_success(ctx);
}


static void
ngx_stream_trojan_start_socks5_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_tcp;
    ctx->socks5_server_index = 0;
    ngx_stream_trojan_socks5_connect(ctx, ngx_stream_trojan_socks5_mode_tcp);
}


static void
ngx_stream_trojan_start_socks5_udp(ngx_stream_trojan_ctx_t *ctx)
{
    ctx->session->connection->write->handler =
        ngx_stream_trojan_udp_client_write_handler;
    ctx->socks5_udp_outbound = ctx->outbound;
    ctx->socks5_server_index = 0;

    ngx_stream_trojan_socks5_connect(ctx, ngx_stream_trojan_socks5_mode_udp);
}


static ngx_int_t
ngx_stream_trojan_socks5_connect_next(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL || ctx->outbound->socks5_server == NULL
        || ctx->socks5_server_index + 1 >= ctx->outbound->socks5_naddrs)
    {
        return NGX_DECLINED;
    }

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    ctx->socks5_connected = 0;
    ctx->socks5_server_index++;
    ngx_stream_trojan_socks5_connect(ctx, ctx->socks5_mode);

    return NGX_OK;
}


static void
ngx_stream_trojan_socks5_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_socks5_mode_e mode)
{
    ngx_int_t          rc;
    ngx_connection_t  *c, *pc;

    if (ctx->outbound == NULL || ctx->outbound->socks5_server == NULL
        || ctx->outbound->socks5_naddrs == 0
        || ctx->socks5_server_index >= ctx->outbound->socks5_naddrs)
    {
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    c = ctx->session->connection;

    if (ctx->socks5_buffer == NULL) {
        ctx->socks5_buffer = ngx_stream_trojan_create_temp_buf(
            c->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
        if (ctx->socks5_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    ctx->socks5_mode = mode;
    ctx->socks5_step = ngx_stream_trojan_socks5_step_greeting_write;
    ctx->state = mode == ngx_stream_trojan_socks5_mode_tcp
                 ? ngx_stream_trojan_state_socks5_tcp
                 : ngx_stream_trojan_state_socks5_udp;

    if (ngx_stream_trojan_socks5_prepare_greeting(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(&ctx->peer, sizeof(ngx_peer_connection_t));
    ctx->peer.sockaddr =
        ctx->outbound->socks5_server[ctx->socks5_server_index].sockaddr;
    ctx->peer.socklen =
        ctx->outbound->socks5_server[ctx->socks5_server_index].socklen;
    ctx->peer_name =
        ctx->outbound->socks5_server[ctx->socks5_server_index].name;
    ctx->peer.name = &ctx->peer_name;
    ctx->peer.type = SOCK_STREAM;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.tries = 1;
    ctx->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (ngx_stream_trojan_socks5_connect_next(ctx) == NGX_OK) {
            return;
        }

        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    pc = ctx->peer.connection;
    ctx->upstream = pc;

    pc->data = ctx;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;
    pc->read->handler = ngx_stream_trojan_socks5_handler;
    pc->write->handler = ngx_stream_trojan_socks5_handler;

    ngx_add_timer(pc->write, ctx->conf->connect_timeout);

    if (rc == NGX_AGAIN) {
        return;
    }

    ctx->socks5_connected = 1;
    ngx_stream_trojan_process_socks5(ctx);
}


static void
ngx_stream_trojan_socks5_handler(ngx_event_t *ev)
{
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan socks5 timed out");
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (!ctx->socks5_connected) {
        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            if (ngx_stream_trojan_socks5_connect_next(ctx) == NGX_OK) {
                return;
            }

            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ctx->socks5_connected = 1;
    }

    ngx_stream_trojan_process_socks5(ctx);
}


static void
ngx_stream_trojan_process_socks5(ngx_stream_trojan_ctx_t *ctx)
{
    int                         rc;
    size_t                      needed, len;
    ngx_connection_t           *pc;
    ngx_stream_trojan_addr_t    bind_addr;

    pc = ctx->upstream;

    if (pc == NULL) {
        ngx_stream_trojan_inbound_connect_failure(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    for ( ;; ) {
        switch (ctx->socks5_step) {

        case ngx_stream_trojan_socks5_step_greeting_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_method_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_method_read:
            rc = ngx_stream_trojan_socks5_read(ctx, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            rc = ngx_stream_trojan_socks5_parse_method_response(
                ctx->socks5_buffer->pos, 2,
                ctx->outbound->socks5_username.len != 0);

            if (rc == 1) {
                if (ngx_stream_trojan_socks5_prepare_auth(ctx) != NGX_OK) {
                    ngx_stream_trojan_finalize(
                        ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->socks5_step = ngx_stream_trojan_socks5_step_auth_write;
                continue;
            }

            if (rc != 0) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ngx_stream_trojan_socks5_prepare_request(ctx) != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_auth_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_auth_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_auth_read:
            rc = ngx_stream_trojan_socks5_read(ctx, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK
                || ngx_stream_trojan_socks5_parse_auth_response(
                       ctx->socks5_buffer->pos, 2)
                   != 0)
            {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ngx_stream_trojan_socks5_prepare_request(ctx) != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_request_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_response_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_response_read:
            len = ctx->socks5_buffer->last - ctx->socks5_buffer->pos;
            rc = ngx_stream_trojan_socks5_response_len(
                ctx->socks5_buffer->pos, len, &needed);

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_inbound_connect_failure(
                        ctx, NGX_STREAM_BAD_GATEWAY);
                    return;
                }

                continue;
            }

            if (rc != 0
                || ngx_stream_trojan_socks5_parse_response(
                       ctx->socks5_buffer->pos, len, &bind_addr)
                   != 0)
            {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (pc->write->timer_set) {
                ngx_del_timer(pc->write);
            }

            if (ctx->socks5_mode == ngx_stream_trojan_socks5_mode_tcp) {
                ngx_stream_trojan_inbound_connect_success(ctx);
                return;
            }

            if (ngx_stream_trojan_socks5_response_to_ngx_addr(
                    ctx, &bind_addr, &ctx->socks5_udp_relay)
                != NGX_OK)
            {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_udp = ngx_stream_trojan_create_udp_connection(
                ctx, ctx->socks5_udp_relay.sockaddr->sa_family,
                ngx_stream_trojan_socks5_udp_read_handler);
            if (ctx->socks5_udp == NULL) {
                ngx_stream_trojan_inbound_connect_failure(
                    ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            pc->read->handler = ngx_stream_trojan_socks5_udp_control_handler;
            pc->write->handler = ngx_stream_trojan_socks5_udp_control_handler;
            ngx_add_timer(pc->read, ctx->conf->udp_timeout);
            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx,
                                           NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ctx->inbound_socks5) {
                ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
                ctx->session->connection->read->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ctx->session->connection->write->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ngx_add_timer(ctx->session->connection->read,
                              ctx->conf->udp_timeout);
                if (ngx_handle_read_event(ctx->session->connection->read, 0)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (ngx_stream_trojan_flush_socks5_udp_packet(ctx)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                    return;
                }
                ngx_stream_trojan_post_socks5_in_udp_read(ctx);

                return;
            }

            ctx->state = ngx_stream_trojan_state_udp;
            ngx_add_timer(ctx->session->connection->read,
                          ctx->conf->udp_timeout);
            ngx_stream_trojan_process_udp_client(ctx);
            return;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_socks5_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *pc;
    ngx_buf_t         *b;

    pc = ctx->upstream;
    b = ctx->socks5_buffer;

    while (b->pos < b->last) {
        n = pc->send(pc, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_read(ngx_stream_trojan_ctx_t *ctx, size_t needed)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *pc;
    ngx_buf_t         *b;

    pc = ctx->upstream;
    b = ctx->socks5_buffer;

    if (needed > (size_t) (b->end - b->start)) {
        return NGX_ERROR;
    }

    while ((size_t) (b->last - b->pos) < needed) {
        available = needed - (size_t) (b->last - b->pos);
        n = pc->recv(pc, b->last, available);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->last += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_greeting(ngx_stream_trojan_ctx_t *ctx)
{
    size_t      written;
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_greeting(
            b->last, b->end - b->last, ctx->outbound->socks5_username.len != 0,
            &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_auth(ngx_stream_trojan_ctx_t *ctx)
{
    size_t      written;
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_auth(
            ctx->outbound->socks5_username.data,
            ctx->outbound->socks5_username.len,
            ctx->outbound->socks5_password.data,
            ctx->outbound->socks5_password.len,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_request(ngx_stream_trojan_ctx_t *ctx)
{
    size_t                      written;
    ngx_buf_t                  *b;
    ngx_stream_trojan_addr_t    bind_addr;
    u_char                      zero[4] = { 0, 0, 0, 0 };

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ctx->socks5_mode == ngx_stream_trojan_socks5_mode_tcp) {
        if (ngx_stream_trojan_socks5_build_request(
                NGX_STREAM_TROJAN_SOCKS5_CMD_CONNECT, &ctx->target,
                b->last, b->end - b->last, &written)
            != 0)
        {
            return NGX_ERROR;
        }

        b->last += written;
        return NGX_OK;
    }

    ngx_memzero(&bind_addr, sizeof(bind_addr));
    bind_addr.type = NGX_STREAM_TROJAN_ADDR_IPV4;
    bind_addr.host_len = 4;
    ngx_memcpy(bind_addr.host, zero, 4);
    bind_addr.port = 0;
    bind_addr.wire_len = 1 + 4 + 2;

    if (ngx_stream_trojan_socks5_build_request(
            NGX_STREAM_TROJAN_SOCKS5_CMD_UDP_ASSOCIATE, &bind_addr,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_response_to_ngx_addr(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    ngx_int_t              rc;
    struct sockaddr        *sa;
    struct sockaddr_in     *sin, *server_sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6, *server_sin6;
#endif

    rc = ngx_stream_trojan_addr_to_ngx_addr(ctx->session->connection->pool,
                                            addr, out);
    if (rc == NGX_DECLINED) {
        rc = ngx_stream_trojan_resolve_addr(ctx->session->connection->pool,
                                            ctx->session->connection->log,
                                            addr, out);
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    sa = out->sockaddr;

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        if (sin->sin_addr.s_addr == INADDR_ANY
            && ctx->outbound->socks5_server->sockaddr->sa_family == AF_INET)
        {
            server_sin = (struct sockaddr_in *)
                         ctx->outbound->socks5_server->sockaddr;
            sin->sin_addr = server_sin->sin_addr;
        }
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)
            && ctx->outbound->socks5_server->sockaddr->sa_family == AF_INET6)
        {
            server_sin6 = (struct sockaddr_in6 *)
                          ctx->outbound->socks5_server->sockaddr;
            sin6->sin6_addr = server_sin6->sin6_addr;
        }
    }
#endif

    out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                  out->name.data, NGX_SOCKADDR_STRLEN, 1);

    return NGX_OK;
}


static ngx_stream_trojan_outbound_t *
ngx_stream_trojan_select_route_outbound(ngx_stream_trojan_route_t *route,
    ngx_stream_trojan_outbound_t *current, ngx_uint_t command,
    ngx_stream_trojan_addr_t *target)
{
    ngx_uint_t                    i, n, selected;
    ngx_stream_trojan_outbound_t *outbound;

    outbound = route->outbounds->elts;
    n = 0;

    if (current != NULL) {
        for (i = 0; i < route->outbounds->nelts; i++) {
            if (&outbound[i] == current
                && !ngx_stream_trojan_outbound_request_blocked(current,
                                                               command,
                                                               target))
            {
                return current;
            }
        }
    }

    for (i = 0; i < route->outbounds->nelts; i++) {
        if (!ngx_stream_trojan_outbound_request_blocked(&outbound[i],
                                                        command, target))
        {
            n++;
        }
    }

    if (n == 0) {
        return NULL;
    }

    selected = n == 1 ? 0 : ngx_random() % n;

    for (i = 0; i < route->outbounds->nelts; i++) {
        if (ngx_stream_trojan_outbound_request_blocked(&outbound[i],
                                                       command, target))


        {
            continue;
        }

        if (selected-- == 0) {
            return &outbound[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_route_target_equal(ngx_stream_trojan_addr_t *a,
    ngx_stream_trojan_addr_t *b)
{
    size_t  i;

    if (a->type != b->type || a->port != b->port
        || a->host_len != b->host_len)
    {
        return 0;
    }

    if (a->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        for (i = 0; i < a->host_len; i++) {
            if (ngx_stream_trojan_route_lc(a->host[i])
                != ngx_stream_trojan_route_lc(b->host[i]))
            {
                return 0;
            }
        }

        return 1;
    }

    return ngx_memcmp(a->host, b->host, a->host_len) == 0;
}


static void
ngx_stream_trojan_route_cache_copy_target(ngx_stream_trojan_addr_t *dst,
    ngx_stream_trojan_addr_t *src)
{
    size_t  i;

    *dst = *src;

    if (src->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        for (i = 0; i < src->host_len; i++) {
            dst->host[i] = ngx_stream_trojan_route_lc(src->host[i]);
        }
    }
}


static ngx_stream_trojan_route_t *
ngx_stream_trojan_route_cache_lookup(ngx_stream_trojan_srv_conf_t *conf,
    ngx_stream_trojan_addr_t *target, ngx_uint_t *found)
{
    ngx_uint_t                             i;
    ngx_stream_trojan_route_cache_entry_t *e;

    *found = 0;

    if (conf->route_cache == NULL) {
        return NULL;
    }

    e = conf->route_cache;
    for (i = 0; i < NGX_STREAM_TROJAN_ROUTE_CACHE_ENTRIES; i++) {
        if (!e[i].valid) {
            continue;
        }

        if (ngx_stream_trojan_route_target_equal(&e[i].target, target)) {
            e[i].accessed = ++conf->route_cache_generation;
            *found = 1;
            return e[i].route;
        }
    }

    return NULL;
}


static void
ngx_stream_trojan_route_cache_store(ngx_stream_trojan_srv_conf_t *conf,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_route_t *route)
{
    ngx_uint_t                             i, oldest;
    ngx_stream_trojan_route_cache_entry_t *e, *slot;

    if (conf->route_cache == NULL) {
        return;
    }

    e = conf->route_cache;
    slot = NULL;
    oldest = 0;

    for (i = 0; i < NGX_STREAM_TROJAN_ROUTE_CACHE_ENTRIES; i++) {
        if (e[i].valid
            && ngx_stream_trojan_route_target_equal(&e[i].target, target))
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
    ngx_stream_trojan_route_cache_copy_target(&slot->target, target);
    slot->route = route;
    slot->accessed = ++conf->route_cache_generation;
    slot->valid = 1;
}


static ngx_stream_trojan_outbound_t *
ngx_stream_trojan_select_outbound(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_uint_t command)
{
    ngx_uint_t                    i, cache_found;
    ngx_stream_trojan_route_t    *route, *cached_route;
    ngx_stream_trojan_outbound_t *outbound;

    if (ctx->conf->route_enable) {
        if (ctx->route_cache_valid
            && ctx->route_cache_command == command
            && ngx_stream_trojan_route_target_equal(&ctx->route_cache_target,
                                                    target))
        {
            return ctx->route_cache_outbound;
        }

        if (ctx->conf->routes == NULL || ctx->conf->routes->nelts == 0) {
            return NULL;
        }

        cached_route = ngx_stream_trojan_route_cache_lookup(ctx->conf, target,
                                                            &cache_found);
        if (cache_found) {
            if (cached_route == NULL) {
                ctx->route_cache_target = *target;
                ctx->route_cache_command = command;
                ctx->route_cache_outbound = NULL;
                ctx->route_cache_valid = 1;
                return NULL;
            }

            outbound = ngx_stream_trojan_select_route_outbound(cached_route,
                                                               ctx->outbound,
                                                               command, target);
            ctx->route_cache_target = *target;
            ctx->route_cache_command = command;
            ctx->route_cache_outbound = outbound;
            ctx->route_cache_valid = 1;
            return outbound;
        }

        route = ctx->conf->routes->elts;
        for (i = 0; i < ctx->conf->routes->nelts; i++) {
            if (!ngx_stream_trojan_route_match(&route[i], target)) {
                continue;
            }

            ngx_stream_trojan_route_cache_store(ctx->conf, target, &route[i]);
            outbound = ngx_stream_trojan_select_route_outbound(&route[i],
                                                               ctx->outbound,
                                                               command, target);
            ctx->route_cache_target = *target;
            ctx->route_cache_command = command;
            ctx->route_cache_outbound = outbound;
            ctx->route_cache_valid = 1;
            return outbound;
        }

        ngx_stream_trojan_route_cache_store(ctx->conf, target, NULL);
        ctx->route_cache_target = *target;
        ctx->route_cache_command = command;
        ctx->route_cache_outbound = NULL;
        ctx->route_cache_valid = 1;

        return NULL;
    }
    if (ctx->conf->outbounds == NULL
        || ctx->conf->outbounds->nelts == 0)
    {
        return NULL;
    }

    outbound = ctx->conf->outbounds->elts;

    return &outbound[0];
}


static void
ngx_stream_trojan_reset_socks5_udp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->socks5_udp) {
        ngx_close_connection(ctx->socks5_udp);
        ctx->socks5_udp = NULL;
    }

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    ngx_memzero(&ctx->socks5_udp_relay, sizeof(ngx_addr_t));
    ctx->socks5_udp_outbound = NULL;
    ctx->socks5_connected = 0;
}


static ngx_int_t
ngx_stream_trojan_prepare_udp_outbound(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target)
{
    ngx_stream_trojan_outbound_t *outbound;

    if (!ctx->conf->route_enable) {
        return NGX_OK;
    }

    outbound = ngx_stream_trojan_select_outbound(
        ctx, target, NGX_STREAM_TROJAN_CMD_ASSOCIATE);

    if (ngx_stream_trojan_route_missed(ctx, outbound)) {
        return NGX_DECLINED;
    }

    if (outbound != NULL
        && outbound->type == ngx_stream_trojan_outbound_socks5
        && ctx->socks5_udp_outbound != NULL
        && ctx->socks5_udp_outbound != outbound)
    {
        ngx_stream_trojan_reset_socks5_udp(ctx);
    }

    ctx->outbound = outbound;

    return NGX_OK;
}


static ngx_uint_t
ngx_stream_trojan_route_missed(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_outbound_t *outbound)
{
    return ctx->conf->route_enable && outbound == NULL;
}


static ngx_int_t
ngx_stream_trojan_route_match(ngx_stream_trojan_route_t *route,
    ngx_stream_trojan_addr_t *target)
{
    ngx_uint_t                       i;
    ngx_stream_trojan_route_rule_t  *rule;

    if (route->rules == NULL || route->rules->nelts == 0
        || route->outbounds == NULL || route->outbounds->nelts == 0)
    {
        return 0;
    }

    rule = route->rules->elts;
    for (i = 0; i < route->rules->nelts; i++) {
        if (ngx_stream_trojan_route_rule_match(&rule[i], target)) {
            return 1;
        }
    }

    return 0;
}


static u_char
ngx_stream_trojan_route_lc(u_char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (u_char) (ch | 0x20);
    }

    return ch;
}


static ngx_int_t
ngx_stream_trojan_route_equal_ci(const u_char *host, ngx_str_t *value)
{
    size_t  i;

    for (i = 0; i < value->len; i++) {
        if (ngx_stream_trojan_route_lc(host[i]) != value->data[i]) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_stream_trojan_route_domain_match(const u_char *host, size_t host_len,
    ngx_str_t *domain)
{
    const u_char  *suffix;

    if (host_len > 1 && host[host_len - 1] == '.') {
        host_len--;
    }

    if (host_len < domain->len) {
        return 0;
    }

    suffix = host + host_len - domain->len;

    if (!ngx_stream_trojan_route_equal_ci(suffix, domain)) {
        return 0;
    }

    if (host_len == domain->len) {
        return 1;
    }

    return suffix > host && suffix[-1] == '.';
}


static ngx_int_t
ngx_stream_trojan_route_cidr_match(ngx_stream_trojan_route_cidr_t *cidr,
    const u_char *addr, size_t addr_len)
{
    ngx_uint_t  full, rest;
    u_char      mask;

    if (cidr->addr_len != addr_len) {
        return 0;
    }

    full = cidr->prefix / 8;
    rest = cidr->prefix % 8;

    if (full && ngx_memcmp(addr, cidr->addr, full) != 0) {
        return 0;
    }

    if (rest) {
        mask = (u_char) (0xff << (8 - rest));
        if ((addr[full] & mask) != (cidr->addr[full] & mask)) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_stream_trojan_route_rule_match(ngx_stream_trojan_route_rule_t *rule,
    ngx_stream_trojan_addr_t *target)
{
    switch (rule->type) {
    case ngx_stream_trojan_route_rule_all:
        return 1;

    case ngx_stream_trojan_route_rule_domain:
        if (target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
            return 0;
        }
        return ngx_stream_trojan_route_domain_match(target->host,
                                                    target->host_len,
                                                    &rule->value);

    case ngx_stream_trojan_route_rule_geosite:
        if (target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
            return 0;
        }
        return ngx_stream_trojan_geosite_match(rule->geosite, &rule->attr,
                                               rule->attr_not, target->host,
                                               target->host_len);

    case ngx_stream_trojan_route_rule_geoip:
        if (target->type != NGX_STREAM_TROJAN_ADDR_IPV4
            && target->type != NGX_STREAM_TROJAN_ADDR_IPV6)
        {
            return 0;
        }
        return ngx_stream_trojan_geoip_match(rule->geoip, target->host,
                                             target->host_len);

    case ngx_stream_trojan_route_rule_ip:
        if (target->type != NGX_STREAM_TROJAN_ADDR_IPV4
            && target->type != NGX_STREAM_TROJAN_ADDR_IPV6)
        {
            return 0;
        }
        return ngx_stream_trojan_route_cidr_match(&rule->cidr, target->host,
                                                  target->host_len);

    case ngx_stream_trojan_route_rule_port:
        return target->port >= rule->port_start
               && target->port <= rule->port_end;
    }

    return 0;
}


static ngx_uint_t
ngx_stream_trojan_outbound_type(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL) {
        return ngx_stream_trojan_outbound_direct;
    }

    return ctx->outbound->type;
}

static ngx_uint_t
ngx_stream_trojan_outbound_request_blocked(
    ngx_stream_trojan_outbound_t *outbound, ngx_uint_t command,
    ngx_stream_trojan_addr_t *target)
{
    ngx_uint_t block;

    if (outbound == NULL) {
        return 0;
    }

    block = outbound->block;

    if (block == ngx_stream_trojan_block_none) {
        return 0;
    }

    if (block == ngx_stream_trojan_block_all) {
        return 1;
    }

    if (command != NGX_STREAM_TROJAN_CMD_ASSOCIATE) {
        return 0;
    }

    if (block == ngx_stream_trojan_block_udp) {
        return 1;
    }

    if (block == ngx_stream_trojan_block_h3 && target->port == 443) {
        return 1;
    }

    return 0;
}


static ngx_uint_t
ngx_stream_trojan_request_blocked(ngx_stream_trojan_ctx_t *ctx)
{
    return ngx_stream_trojan_outbound_request_blocked(ctx->outbound,
                                                      ctx->command,
                                                      &ctx->target);
}



static ngx_int_t
ngx_stream_trojan_parse_ip_prefer(ngx_str_t *value, ngx_uint_t *prefer)
{
    if (value->len == 4 && ngx_strncmp(value->data, "auto", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
        return NGX_OK;
    }

    if (value->len == 4 && ngx_strncmp(value->data, "ipv4", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV4;
        return NGX_OK;
    }

    if (value->len == 4 && ngx_strncmp(value->data, "ipv6", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV6;
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_stream_trojan_parse_block(ngx_str_t *value, ngx_uint_t *block)
{
    if (value->len == 4 && ngx_strncmp(value->data, "none", 4) == 0) {
        *block = ngx_stream_trojan_block_none;
        return NGX_OK;
    }

    if (value->len == 2 && ngx_strncmp(value->data, "h3", 2) == 0) {
        *block = ngx_stream_trojan_block_h3;
        return NGX_OK;
    }

    if (value->len == 3 && ngx_strncmp(value->data, "udp", 3) == 0) {
        *block = ngx_stream_trojan_block_udp;
        return NGX_OK;
    }

    if (value->len == 3 && ngx_strncmp(value->data, "all", 3) == 0) {
        *block = ngx_stream_trojan_block_all;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_parse_server_ref(ngx_conf_t *cf, ngx_str_t *value,
    ngx_stream_trojan_server_ref_t *ref)
{
    u_char     *colon, *last, *p;
    ngx_int_t   port;
    ngx_str_t   port_part;
    ngx_addr_t  addr;

    if (value->len == 0) {
        goto invalid;
    }

    last = value->data + value->len;
    colon = ngx_strlchr(value->data, last, ':');
    if (colon == NULL || colon == value->data || colon + 1 == last) {
        goto invalid;
    }

    for (p = colon + 1; p < last; p++) {
        if (*p < '0' || *p > '9') {
            goto invalid;
        }
    }

    port_part.data = colon + 1;
    port_part.len = last - (colon + 1);
    port = ngx_atoi(port_part.data, port_part.len);
    if (port <= 0 || port > 65535) {
        goto invalid;
    }

    ref->host.data = value->data;
    ref->host.len = colon - value->data;
    ngx_strlow(ref->host.data, ref->host.data, ref->host.len);
    ref->port = (in_port_t) port;
    ref->set = 1;

    if (ref->host.len == sizeof("localhost") - 1
        && ngx_strncmp(ref->host.data, "localhost", ref->host.len) == 0)
    {
        ref->localhost = 1;
        return NGX_OK;
    }

    if (ngx_parse_addr(cf->pool, &addr, ref->host.data, ref->host.len)
        == NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_server \"%V\" does not support IP address; "
                           "use localhost:port or server_name:port",
                           value);
        return NGX_ERROR;
    }

    return NGX_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid trojan_server \"%V\", expected name:port",
                       value);
    return NGX_ERROR;
}

static ngx_uint_t
ngx_stream_trojan_current_ip_prefer(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL
        || ctx->outbound->type != ngx_stream_trojan_outbound_direct)
    {
        return NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    }

    return ctx->outbound->ip_prefer;
}


static ngx_stream_trojan_dns_rule_group_t *
ngx_stream_trojan_match_dns_rule(ngx_stream_trojan_srv_conf_t *conf,
    ngx_stream_trojan_addr_t *addr)
{
    if (conf->dns_rules == NULL
        || addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || addr->host_len == 0)
    {
        return NULL;
    }

    return ngx_stream_trojan_dns_rules_match(conf->dns_rules, addr->host,
                                             addr->host_len);
}


static void
ngx_stream_trojan_peer_handler(ngx_event_t *ev)
{
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (ev->timedout) {
            ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream timed out");
            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
            return;
        }
    } else if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream idle timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_socks5_in_response
        || ctx->state == ngx_stream_trojan_state_http_in_response)
    {
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            if (ngx_stream_trojan_connect_next(ctx) == NGX_OK) {
                return;
            }

            ngx_stream_trojan_inbound_connect_failure(ctx,
                                                      NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ngx_stream_trojan_inbound_connect_success(ctx);
        return;
    }

    ngx_stream_trojan_process_proxy(ctx);
}


static ngx_int_t
ngx_stream_trojan_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                        "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    ctx->client_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                           ctx->conf->buffer_size);
    ctx->upstream_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                             ctx->conf->buffer_size);

    if (ctx->client_buffer == NULL || ctx->upstream_buffer == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;
    pc->read->handler = ngx_stream_trojan_peer_handler;
    pc->write->handler = ngx_stream_trojan_peer_handler;

    ctx->state = ngx_stream_trojan_state_proxy;
    ngx_stream_trojan_set_proxy_timeout(ctx);
    ngx_stream_trojan_process_proxy(ctx);
}


static void
ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    ngx_add_timer(c->read, ctx->conf->timeout);

    if (pc) {
        ngx_add_timer(pc->read, ctx->conf->timeout);
    }
}

static ngx_int_t
ngx_stream_trojan_update_read_event(ngx_connection_t *c, ngx_uint_t blocked)
{
    if (!blocked) {
        return ngx_handle_read_event(c->read, 0);
    }

    if (c->read->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        return ngx_del_event(c->read, NGX_READ_EVENT, 0);
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_uint_t         client_eof, upstream_eof;
    ngx_uint_t         client_read_blocked, upstream_read_blocked;
    ngx_uint_t         proxy_active;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;
    client_eof = c->read->eof || c->read->error;
    upstream_eof = pc->read->eof || pc->read->error;
    proxy_active = 0;

    if (ctx->pending_to_upstream
        && ctx->pending_to_upstream->pos < ctx->pending_to_upstream->last)
    {
        if (ngx_stream_trojan_process_direction(ctx, NULL, pc,
                                                ctx->pending_to_upstream,
                                                &client_eof, &proxy_active)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_stream_trojan_process_direction(ctx, c, pc, ctx->client_buffer,
                                            &client_eof, &proxy_active)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_process_direction(ctx, pc, c, ctx->upstream_buffer,
                                            &upstream_eof, &proxy_active)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (client_eof && !ctx->upstream_write_shutdown
        && (ctx->pending_to_upstream == NULL
            || ctx->pending_to_upstream->pos == ctx->pending_to_upstream->last)
        && ctx->client_buffer->pos == ctx->client_buffer->last)
    {
        (void) shutdown(pc->fd, SHUT_WR);
        ctx->upstream_write_shutdown = 1;
    }

    if (client_eof && upstream_eof
        && ctx->client_buffer->pos == ctx->client_buffer->last
        && ctx->upstream_buffer->pos == ctx->upstream_buffer->last)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    client_read_blocked = ctx->client_buffer->pos < ctx->client_buffer->last
                          || (ctx->pending_to_upstream != NULL
                              && ctx->pending_to_upstream->pos
                                 < ctx->pending_to_upstream->last);
    upstream_read_blocked = ctx->upstream_buffer->pos
                            < ctx->upstream_buffer->last;

    if (ngx_stream_trojan_update_read_event(c, client_read_blocked) != NGX_OK
        || ngx_handle_write_event(c->write, 0) != NGX_OK
        || ngx_stream_trojan_update_read_event(pc, upstream_read_blocked)
           != NGX_OK
        || ngx_handle_write_event(pc->write, 0) != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (proxy_active) {
        ngx_stream_trojan_set_proxy_timeout(ctx);
    }
}


static ngx_int_t
ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof, ngx_uint_t *progress)
{
    size_t        available, bytes, limit, loops;
    ssize_t       n;
    ngx_event_t  *rev;

    if (buf == NULL || dst == NULL) {
        return NGX_OK;
    }

    bytes = 0;
    limit = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    loops = 0;

    for ( ;; ) {
        while (buf->pos < buf->last) {
            if (dst == ctx->session->connection) {
                n = ngx_stream_trojan_client_send(ctx, buf->pos,
                                                  buf->last - buf->pos);
            } else {
                n = dst->send(dst, buf->pos, buf->last - buf->pos);
            }

            if (n == NGX_AGAIN) {
                return NGX_OK;
            }

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            buf->pos += n;
            if (progress) {
                *progress = 1;
            }
        }

        buf->pos = buf->start;
        buf->last = buf->start;

        if (src == NULL || *src_eof) {
            return NGX_OK;
        }

        rev = src->read;

        if (!ngx_stream_trojan_client_read_ready(ctx, src)) {
            return NGX_OK;
        }

        if (!ngx_stream_trojan_relay_should_continue(loops, bytes, limit)) {
            ngx_stream_trojan_post_read_if_ready(ctx, src);
            return NGX_OK;
        }

        available = ngx_stream_trojan_relay_read_size(buf->end - buf->last,
                                                      bytes, limit);
        if (available == 0) {
            return NGX_OK;
        }

        if (src == ctx->session->connection) {
            n = ngx_stream_trojan_client_recv(ctx, buf->last, available);
        } else {
            n = src->recv(src, buf->last, available);
        }

        if (n == NGX_AGAIN) {
            return NGX_OK;
        }

        if (n == 0) {
            *src_eof = 1;
            rev->eof = 1;
            return NGX_OK;
        }

        if (n == NGX_ERROR) {
            *src_eof = 1;
            rev->error = 1;
            return NGX_OK;
        }

        buf->last += n;
        if (progress) {
            *progress = 1;
        }
        bytes += (size_t) n;
        loops++;
    }
}



static void
ngx_stream_trojan_mux_reset_buf(ngx_buf_t *b)
{
    if (b) {
        b->pos = b->start;
        b->last = b->start;
    }
}


static void
ngx_stream_trojan_mux_compact_buf(ngx_buf_t *b)
{
    size_t  len;

    if (b == NULL || b->pos == b->start) {
        return;
    }

    if (b->pos == b->last) {
        ngx_stream_trojan_mux_reset_buf(b);
        return;
    }

    len = b->last - b->pos;
    ngx_memmove(b->start, b->pos, len);
    b->pos = b->start;
    b->last = b->start + len;
}


static ngx_int_t
ngx_stream_trojan_mux_ensure_payload_buffer(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->mux_payload != NULL) {
        return NGX_OK;
    }

    ctx->mux_payload = ngx_pnalloc(ctx->session->connection->pool,
                                   NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE);

    return ctx->mux_payload == NULL ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_read_client_payload(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c)
{
    ssize_t                          n;
    size_t                           available, remaining;
    ngx_buf_t                       *b;
    ngx_stream_trojan_mux_stream_t  *stream;

    while (ctx->mux_payload_read < ctx->mux_payload_len) {
        b = NULL;
        stream = NULL;

        remaining = ctx->mux_payload_len - ctx->mux_payload_read;

        if (ctx->mux_payload_direct && ctx->mux_payload_stream != NULL
            && ctx->mux_payload_stream->state
               != ngx_stream_trojan_mux_stream_closing)
        {
            stream = ctx->mux_payload_stream;

            if (ngx_stream_trojan_mux_ensure_client_buffer(stream, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            b = stream->client_buffer;
            if (b->last == b->end) {
                ngx_stream_trojan_mux_compact_buf(b);
                if (b->last == b->end) {
                    ctx->mux_payload_blocked = 1;
                    return NGX_AGAIN;
                }
            }

            available = b->end - b->last;
            if (available > remaining) {
                available = remaining;
            }

            ctx->mux_payload_blocked = 0;
            n = ngx_stream_trojan_client_recv(ctx, b->last, available);

        } else {
            ctx->mux_payload_direct = 0;

            if (ngx_stream_trojan_mux_ensure_payload_buffer(ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            ctx->mux_payload_blocked = 0;
            n = ngx_stream_trojan_client_recv(ctx,
                    ctx->mux_payload + ctx->mux_payload_read, remaining);
        }

        if (n == NGX_AGAIN) {
            ctx->mux_payload_blocked = 0;
            return NGX_OK;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_DONE;
        }

        if (b != NULL) {
            b->last += n;
            ngx_stream_trojan_mux_queue_process(stream);
        }

        ctx->mux_payload_read += (size_t) n;
        ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
    }
    return NGX_OK;
}


static void
ngx_stream_trojan_mux_refresh_read_timeout(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c)
{
    ngx_msec_int_t  remaining;

    if (ctx == NULL || c == NULL || c->read == NULL) {
        return;
    }

    if (c->read->timer_set) {
        remaining = (ngx_msec_int_t) (c->read->timer.key - ngx_current_msec);
        if (remaining > (ngx_msec_int_t) (ctx->conf->timeout / 2)) {
            return;
        }
    }

    ngx_add_timer(c->read, ctx->conf->timeout);
}


static ngx_int_t
ngx_stream_trojan_mux_send_bytes(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c, u_char *data, size_t *pos, size_t len,
    size_t *sent)
{
    ssize_t  n;

    while (*pos < len) {
        if (c == ctx->session->connection) {
            n = ngx_stream_trojan_client_send(ctx, data + *pos, len - *pos);
        } else {
            n = c->send(c, data + *pos, len - *pos);
        }

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        *pos += (size_t) n;
        if (sent != NULL) {
            *sent += (size_t) n;
        }
        ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_pack_data_header(
    ngx_stream_trojan_mux_stream_t *stream, size_t len)
{
    ngx_stream_trojan_ctx_t  *ctx;

    ctx = stream->ctx;

    if (ctx->mux_cool) {
        if (ngx_stream_trojan_mux_cool_pack_header(
                stream->frame_header, sizeof(stream->frame_header),
                (uint16_t) stream->id,
                NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP,
                NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA, (uint16_t) len,
                &stream->frame_header_len)
            != NGX_STREAM_TROJAN_MUX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        if (ngx_stream_trojan_mux_pack_header(
                stream->frame_header, sizeof(stream->frame_header),
                NGX_STREAM_TROJAN_MUX_CMD_PSH, (uint16_t) len, stream->id)
            != NGX_STREAM_TROJAN_MUX_OK)
        {
            return NGX_ERROR;
        }

        stream->frame_header_len = NGX_STREAM_TROJAN_MUX_HEADER_LEN;
    }

    stream->frame_header_pos = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_pack_fin_header(ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_stream_trojan_ctx_t  *ctx;

    ctx = stream->ctx;

    if (ctx->mux_cool) {
        if (ngx_stream_trojan_mux_cool_pack_header(
                stream->fin_header, sizeof(stream->fin_header),
                (uint16_t) stream->id,
                NGX_STREAM_TROJAN_MUX_COOL_STATUS_END, 0, 0,
                &stream->fin_header_len)
            != NGX_STREAM_TROJAN_MUX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        if (ngx_stream_trojan_mux_pack_header(
                stream->fin_header, sizeof(stream->fin_header),
                NGX_STREAM_TROJAN_MUX_CMD_FIN, 0, stream->id)
            != NGX_STREAM_TROJAN_MUX_OK)
        {
            return NGX_ERROR;
        }

        stream->fin_header_len = NGX_STREAM_TROJAN_MUX_HEADER_LEN;
    }

    stream->fin_header_pos = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_send_frame_payload(
    ngx_stream_trojan_mux_stream_t *stream, ngx_buf_t *b, size_t *sent,
    size_t limit)
{
    ssize_t                   n;
    size_t                    available, frame_size, header_available;
    size_t                    header_before, header_sent, payload_sent;
    u_char                   *payload_before;
    ngx_buf_t                 hb, pb;
    ngx_chain_t               hcl, pcl, *cl, *out;
    ngx_connection_t         *c;
    ngx_stream_trojan_ctx_t  *ctx;

    ctx = stream->ctx;
    c = ctx->session->connection;
    if (!ctx->websocket && c->send_chain == NULL) {
        return NGX_ERROR;
    }


    while (stream->frame_header_pos < stream->frame_header_len
           || b->pos < b->last)
    {
        if (ctx->websocket) {
            if (stream->frame_header_pos == stream->frame_header_len
                && limit && sent != NULL && *sent >= limit)
            {
                return NGX_AGAIN;
            }

            header_available = stream->frame_header_len
                               - stream->frame_header_pos;
            available = b->last - b->pos;

            if (limit && sent != NULL) {
                if (*sent + header_available >= limit) {
                    available = 0;
                } else if (*sent + header_available + available > limit) {
                    available = limit - *sent - header_available;
                }
            }

            if (header_available == 0 && available == 0) {
                return NGX_AGAIN;
            }

            frame_size = header_available + available;
            n = ngx_stream_trojan_websocket_send_parts(ctx,
                stream->frame_header + stream->frame_header_pos,
                header_available, b->pos, available, frame_size,
                &header_sent, &payload_sent);

            if (n == NGX_AGAIN || n == 0) {
                return NGX_AGAIN;
            }

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            stream->frame_header_pos += header_sent;
            b->pos += payload_sent;
            if (sent != NULL) {
                *sent += header_sent + payload_sent;
            }

            ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
            continue;
        }

        if (stream->frame_header_pos == stream->frame_header_len
            && limit && sent != NULL && *sent >= limit)
        {
            return NGX_AGAIN;
        }

        available = b->last - b->pos;
        if (limit && sent != NULL) {
            frame_size = stream->frame_header_len - stream->frame_header_pos;
            if (*sent + frame_size >= limit) {
                available = 0;
            } else if (*sent + frame_size + available > limit) {
                available = limit - *sent - frame_size;
            }
        }

        ngx_memzero(&hb, sizeof(ngx_buf_t));
        ngx_memzero(&pb, sizeof(ngx_buf_t));

        hb.pos = stream->frame_header + stream->frame_header_pos;
        hb.last = stream->frame_header + stream->frame_header_len;
        hb.memory = 1;
        hcl.buf = &hb;

        pb.pos = b->pos;
        pb.last = b->pos + available;
        pb.memory = 1;
        pcl.buf = &pb;
        pcl.next = NULL;

        if (hb.pos < hb.last) {
            cl = &hcl;
            hcl.next = available ? &pcl : NULL;
        } else if (available) {
            cl = &pcl;
        } else {
            return NGX_AGAIN;
        }

        header_before = stream->frame_header_pos;
        payload_before = b->pos;

        out = c->send_chain(c, cl, 0);
        if (out == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        stream->frame_header_pos = (size_t) (hb.pos - stream->frame_header);
        b->pos = pb.pos;

        if (sent != NULL) {
            *sent += stream->frame_header_pos - header_before
                     + (size_t) (b->pos - payload_before);
        }

        if (stream->frame_header_pos != header_before
            || b->pos != payload_before)
        {
            ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
        }

        if (out != NULL) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_flush_stream_to_client(
    ngx_stream_trojan_mux_stream_t *stream, size_t *sent, size_t limit)
{
    size_t                    len;
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_stream_trojan_ctx_t  *ctx;
    ngx_buf_t                *b;

    ctx = stream->ctx;
    c = ctx->session->connection;
    b = stream->upstream_buffer;

    if (b && b->pos < b->last) {
        if (stream->frame_header_len == 0) {
            len = b->last - b->pos;
            if (ngx_stream_trojan_mux_pack_data_header(stream, len) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        rc = ngx_stream_trojan_mux_send_frame_payload(stream, b, sent, limit);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_stream_trojan_mux_reset_buf(b);
        if (!stream->upstream_eof) {
            ngx_stream_trojan_post_read_if_ready(ctx, stream->upstream);
        }
        stream->frame_header_len = 0;
        stream->frame_header_pos = 0;
    }

    if (stream->upstream_eof && !stream->fin_sent) {
        stream->fin_to_client = 1;
    }

    if (limit && sent != NULL && *sent >= limit) {
        return NGX_AGAIN;
    }

    if (stream->fin_to_client && !stream->fin_sent
        && (b == NULL || b->pos == b->last))
    {
        if (stream->fin_header_len == 0) {
            if (ngx_stream_trojan_mux_pack_fin_header(stream) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        rc = ngx_stream_trojan_mux_send_bytes(ctx, c, stream->fin_header,
                                              &stream->fin_header_pos,
                                              stream->fin_header_len, sent);
        if (rc != NGX_OK) {
            return rc;
        }

        stream->fin_to_client = 0;
        stream->fin_sent = 1;
        stream->fin_header_len = 0;
        stream->fin_header_pos = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_is_mux_cool_target(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->target.type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || ctx->target.host_len != NGX_STREAM_TROJAN_MUX_COOL_HOST_LEN)
    {
        return 0;
    }

    return ngx_strncasecmp(ctx->target.host,
                           (u_char *) NGX_STREAM_TROJAN_MUX_COOL_HOST,
                           NGX_STREAM_TROJAN_MUX_COOL_HOST_LEN)
           == 0;
}


static ngx_int_t
ngx_stream_trojan_is_mux_sing_target(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->target.type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || ctx->target.port != NGX_STREAM_TROJAN_MUX_SING_PORT
        || ctx->target.host_len != NGX_STREAM_TROJAN_MUX_SING_HOST_LEN)
    {
        return 0;
    }

    return ngx_strncasecmp(ctx->target.host,
                           (u_char *) NGX_STREAM_TROJAN_MUX_SING_HOST,
                           NGX_STREAM_TROJAN_MUX_SING_HOST_LEN)
           == 0;
}


static void
ngx_stream_trojan_start_mux(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->session->connection;

    ctx->state = ngx_stream_trojan_state_mux;
    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;

    ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);

    ngx_stream_trojan_process_mux(ctx);
}


static void
ngx_stream_trojan_process_mux(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    rc = ngx_stream_trojan_mux_flush_client(ctx);
    if (rc == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_stream_trojan_mux_process_queued_streams(ctx);

    if (ctx->mux_cool) {
        rc = ngx_stream_trojan_mux_cool_read_client(ctx);
    } else if (ctx->mux_sing) {
        rc = ngx_stream_trojan_mux_sing_read_client(ctx);
    } else {
        rc = ngx_stream_trojan_mux_read_client(ctx);
    }
    if (rc == NGX_DONE) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    ngx_stream_trojan_mux_process_queued_streams(ctx);

    rc = ngx_stream_trojan_mux_flush_client(ctx);
    if (rc == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_update_read_event(c,
            ngx_stream_trojan_mux_client_blocked_on(ctx,
                                                    ctx->mux_payload_stream))
        != NGX_OK
        || ngx_handle_write_event(c->write, 0) != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static ngx_int_t
ngx_stream_trojan_mux_read_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t                          n;
    ngx_int_t                        rc;
    size_t                           bytes, frame_bytes, limit, loops;
    ngx_connection_t                *c;
    ngx_stream_trojan_mux_stream_t  *stream;

    c = ctx->session->connection;
    bytes = 0;
    limit = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    loops = 0;


    for ( ;; ) {
        while (ctx->mux_header_len < NGX_STREAM_TROJAN_MUX_HEADER_LEN) {
            n = ngx_stream_trojan_client_recv(ctx,
                    ctx->mux_header + ctx->mux_header_len,
                    NGX_STREAM_TROJAN_MUX_HEADER_LEN
                    - ctx->mux_header_len);

            if (n == NGX_AGAIN) {
                return NGX_OK;
            }

            if (n == 0 || n == NGX_ERROR) {
                return NGX_DONE;
            }

            ctx->mux_header_len += (size_t) n;
            ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
        }

        if (!ctx->mux_frame_parsed) {
            if (ngx_stream_trojan_mux_parse_header(ctx->mux_header,
                    ctx->mux_header_len, &ctx->mux_frame)
                != NGX_STREAM_TROJAN_MUX_OK)
            {
                return NGX_ERROR;
            }

            ctx->mux_payload_len = ctx->mux_frame.length;
            ctx->mux_payload_read = 0;
            ctx->mux_payload_stream = NULL;
            ctx->mux_payload_direct = 0;
            ctx->mux_payload_accept_checked = 0;
            ctx->mux_payload_blocked = 0;
            ctx->mux_frame_parsed = 1;

            if (ctx->mux_frame.command == NGX_STREAM_TROJAN_MUX_CMD_PSH) {
                stream = ngx_stream_trojan_mux_find_stream(
                    ctx, ctx->mux_frame.stream_id);

                if (stream != NULL) {
                    if (stream->state
                        != ngx_stream_trojan_mux_stream_request
                        && stream->state
                           != ngx_stream_trojan_mux_stream_closing)
                    {
                        ctx->mux_payload_direct = 1;
                    } else {
                        rc = ngx_stream_trojan_mux_stream_can_accept(
                            stream, ctx->mux_payload_len);
                        if (rc == NGX_ERROR) {
                            return NGX_ERROR;
                        }
                        if (rc == NGX_AGAIN) {
                            ctx->mux_payload_stream = stream;
                            ctx->mux_payload_blocked = 1;
                            return NGX_AGAIN;
                        }

                        ctx->mux_payload_accept_checked = 1;
                    }
                }

                ctx->mux_payload_stream = stream;
            }
        }

        if (ctx->mux_frame.command == NGX_STREAM_TROJAN_MUX_CMD_PSH
            && ctx->mux_payload_stream != NULL
            && !ctx->mux_payload_direct
            && !ctx->mux_payload_accept_checked)
        {
            rc = ngx_stream_trojan_mux_stream_can_accept(
                ctx->mux_payload_stream, ctx->mux_payload_len);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
            if (rc == NGX_AGAIN) {
                ctx->mux_payload_blocked = 1;
                return NGX_AGAIN;
            }
            ctx->mux_payload_accept_checked = 1;
        }

        rc = ngx_stream_trojan_mux_read_client_payload(ctx, c);
        if (rc != NGX_OK) {
            return rc;
        }

        frame_bytes = NGX_STREAM_TROJAN_MUX_HEADER_LEN
                      + ctx->mux_payload_len;
        rc = ngx_stream_trojan_mux_handle_frame(ctx);
        ctx->mux_header_len = 0;
        ctx->mux_frame_parsed = 0;
        ctx->mux_payload_len = 0;
        ctx->mux_payload_read = 0;
        ctx->mux_payload_stream = NULL;
        ctx->mux_payload_direct = 0;
        ctx->mux_payload_accept_checked = 0;
        ctx->mux_payload_blocked = 0;

        loops++;
        bytes += frame_bytes;

        if (rc != NGX_OK) {
            return rc;
        }

        if (!ngx_stream_trojan_relay_should_continue(loops, bytes, limit)) {
            ngx_stream_trojan_post_read_if_ready(ctx, c);
            return NGX_OK;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_mux_sing_read_handshake(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    while (ctx->mux_sing_handshake_len < 2) {
        n = ngx_stream_trojan_client_recv(ctx,
                ctx->mux_sing_handshake + ctx->mux_sing_handshake_len,
                2 - ctx->mux_sing_handshake_len);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_DONE;
        }

        ctx->mux_sing_handshake_len += (size_t) n;
        ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
    }

    if (ctx->mux_sing_handshake[0] > NGX_STREAM_TROJAN_MUX_SING_VERSION1
        || ctx->mux_sing_handshake[1]
           != NGX_STREAM_TROJAN_MUX_SING_PROTOCOL_SMUX)
    {
        return NGX_ERROR;
    }

    if (ctx->mux_sing_handshake[0] == NGX_STREAM_TROJAN_MUX_SING_VERSION0) {
        ctx->mux_sing_handshake_done = 1;
        return NGX_OK;
    }

    while (ctx->mux_sing_handshake_len < 3) {
        n = ngx_stream_trojan_client_recv(ctx,
                ctx->mux_sing_handshake + ctx->mux_sing_handshake_len,
                3 - ctx->mux_sing_handshake_len);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_DONE;
        }

        ctx->mux_sing_handshake_len += (size_t) n;
        ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
    }

    if (ctx->mux_sing_handshake[2]) {
        return NGX_ERROR;
    }

    ctx->mux_sing_handshake_done = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_sing_read_client(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (!ctx->mux_sing_handshake_done) {
        rc = ngx_stream_trojan_mux_sing_read_handshake(ctx);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ngx_stream_trojan_mux_read_client(ctx);
}


static ngx_int_t
ngx_stream_trojan_mux_cool_read_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t                         n;
    ngx_int_t                       rc;
    size_t                          bytes, frame_bytes, limit, loops;
    uint16_t                        meta_len, data_len;
    ngx_connection_t               *c;
    ngx_stream_trojan_mux_stream_t  *stream;

    c = ctx->session->connection;
    bytes = 0;
    limit = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    loops = 0;

    for ( ;; ) {
        while (ctx->mux_header_len < 2) {
            n = ngx_stream_trojan_client_recv(ctx,
                    ctx->mux_header + ctx->mux_header_len,
                    2 - ctx->mux_header_len);

            if (n == NGX_AGAIN) {
                return NGX_OK;
            }

            if (n == 0 || n == NGX_ERROR) {
                return NGX_DONE;
            }

            ctx->mux_header_len += (size_t) n;
            ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
        }

        if (ctx->mux_cool_meta_len == 0) {
            meta_len = (uint16_t) ((ctx->mux_header[0] << 8)
                                   | ctx->mux_header[1]);
            if (meta_len < 4
                || meta_len > NGX_STREAM_TROJAN_MUX_COOL_MAX_META_LEN)
            {
                return NGX_ERROR;
            }

            ctx->mux_cool_meta_len = meta_len;
            ctx->mux_cool_meta_read = 0;
        }

        while (ctx->mux_cool_meta_read < ctx->mux_cool_meta_len) {
            n = ngx_stream_trojan_client_recv(ctx,
                    ctx->mux_cool_meta + ctx->mux_cool_meta_read,
                    ctx->mux_cool_meta_len - ctx->mux_cool_meta_read);

            if (n == NGX_AGAIN) {
                return NGX_OK;
            }

            if (n == 0 || n == NGX_ERROR) {
                return NGX_DONE;
            }

            ctx->mux_cool_meta_read += (size_t) n;
            ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
        }

        if (!ctx->mux_frame_parsed) {
            if (ngx_stream_trojan_mux_cool_parse_metadata(
                    ctx->mux_cool_meta, ctx->mux_cool_meta_len,
                    &ctx->mux_cool_frame)
                != NGX_STREAM_TROJAN_MUX_OK)
            {
                return NGX_ERROR;
            }

            ctx->mux_frame_parsed = 1;
            ctx->mux_payload_stream = NULL;
            ctx->mux_payload_direct = 0;
            ctx->mux_payload_accept_checked = 0;
            ctx->mux_payload_blocked = 0;
            ctx->mux_payload_len = 0;
            ctx->mux_payload_read = 0;
        }

        if (ctx->mux_cool_frame.option
            & NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA)
        {
            while (ctx->mux_cool_data_len_read < 2) {
                n = ngx_stream_trojan_client_recv(ctx,
                        ctx->mux_cool_data_len
                        + ctx->mux_cool_data_len_read,
                        2 - ctx->mux_cool_data_len_read);

                if (n == NGX_AGAIN) {
                    return NGX_OK;
                }

                if (n == 0 || n == NGX_ERROR) {
                    return NGX_DONE;
                }

                ctx->mux_cool_data_len_read += (size_t) n;
                ngx_stream_trojan_mux_refresh_read_timeout(ctx, c);
            }

            if (ctx->mux_payload_len == 0) {
                data_len = (uint16_t) ((ctx->mux_cool_data_len[0] << 8)
                                       | ctx->mux_cool_data_len[1]);
                if (data_len > NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE) {
                    return NGX_ERROR;
                }
                ctx->mux_payload_len = data_len;
            }

            if (ctx->mux_payload_len && ctx->mux_payload_read == 0
                && (ctx->mux_cool_frame.status
                    == NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP
                    || ctx->mux_cool_frame.status
                       == NGX_STREAM_TROJAN_MUX_COOL_STATUS_END))
            {
                stream = ngx_stream_trojan_mux_find_stream(
                    ctx, ctx->mux_cool_frame.session_id);
                if (stream != NULL) {
                    ctx->mux_payload_stream = stream;
                    if (stream->state
                        != ngx_stream_trojan_mux_stream_request
                        && stream->state
                           != ngx_stream_trojan_mux_stream_closing)
                    {
                        ctx->mux_payload_direct = 1;
                    } else {
                        rc = ngx_stream_trojan_mux_stream_can_accept(
                            stream, ctx->mux_payload_len);
                        if (rc != NGX_OK) {
                            if (rc == NGX_AGAIN) {
                                ctx->mux_payload_blocked = 1;
                            }
                            return rc;
                        }

                        ctx->mux_payload_accept_checked = 1;
                    }
                }
            }

            rc = ngx_stream_trojan_mux_read_client_payload(ctx, c);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        frame_bytes = 2 + ctx->mux_cool_meta_len
                      + ((ctx->mux_cool_frame.option
                          & NGX_STREAM_TROJAN_MUX_COOL_OPT_DATA)
                         ? 2 + ctx->mux_payload_len : 0);

        rc = ngx_stream_trojan_mux_cool_handle_frame(ctx);

        ctx->mux_header_len = 0;
        ctx->mux_cool_meta_len = 0;
        ctx->mux_cool_meta_read = 0;
        ctx->mux_cool_data_len_read = 0;
        ctx->mux_frame_parsed = 0;
        ctx->mux_payload_len = 0;
        ctx->mux_payload_read = 0;
        ctx->mux_payload_stream = NULL;
        ctx->mux_payload_direct = 0;
        ctx->mux_payload_accept_checked = 0;
        ctx->mux_payload_blocked = 0;

        loops++;
        bytes += frame_bytes;

        if (rc != NGX_OK) {
            return rc;
        }

        if (!ngx_stream_trojan_relay_should_continue(loops, bytes, limit)) {
            ngx_stream_trojan_post_read_if_ready(ctx, c);
            return NGX_OK;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_mux_flush_client(ngx_stream_trojan_ctx_t *ctx)
{
    size_t                          limit, sent;
    ngx_int_t                       rc;
    ngx_queue_t                    *q;
    ngx_connection_t               *c;
    ngx_stream_trojan_mux_stream_t *stream;

    c = ctx->session->connection;
    limit = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    sent = 0;

    if (ctx->mux_nop_pending) {
        if (ctx->mux_nop_header_pos == 0) {
            if (ngx_stream_trojan_mux_pack_header(
                    ctx->mux_nop_header, sizeof(ctx->mux_nop_header),
                    NGX_STREAM_TROJAN_MUX_CMD_NOP, 0, 0)
                != NGX_STREAM_TROJAN_MUX_OK)
            {
                return NGX_ERROR;
            }
        }

        rc = ngx_stream_trojan_mux_send_bytes(ctx, c, ctx->mux_nop_header,
                                              &ctx->mux_nop_header_pos,
                                              sizeof(ctx->mux_nop_header),
                                              &sent);
        if (rc != NGX_OK) {
            return rc;
        }

        ctx->mux_nop_pending = 0;
        ctx->mux_nop_header_pos = 0;
    }

    while (!ngx_queue_empty(&ctx->mux_flush_queue)) {
        q = ngx_queue_head(&ctx->mux_flush_queue);
        ngx_queue_remove(q);
        stream = ngx_queue_data(q, ngx_stream_trojan_mux_stream_t,
                                flush_queue);
        stream->flush_queued = 0;

        rc = ngx_stream_trojan_mux_flush_stream_to_client(stream, &sent,
                                                          limit);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_AGAIN) {
            ngx_stream_trojan_mux_queue_flush(stream);
            ngx_stream_trojan_post_write_if_ready(c);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        ngx_stream_trojan_mux_cleanup_stream(stream);

        if (limit && sent >= limit) {
            ngx_stream_trojan_post_write_if_ready(c);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_handle_frame(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_stream_trojan_mux_stream_t  *stream;

    switch (ctx->mux_frame.command) {
    case NGX_STREAM_TROJAN_MUX_CMD_SYN:
        if (ctx->mux_frame.stream_id == 0
            || (ctx->mux_frame.stream_id & 1) == 0)
        {
            return NGX_ERROR;
        }

        if (ngx_stream_trojan_mux_find_stream(
                ctx, ctx->mux_frame.stream_id)
            == NULL)
        {
            if (ngx_stream_trojan_mux_create_stream(
                    ctx, ctx->mux_frame.stream_id)
                == NULL)
            {
                return NGX_ERROR;
            }
        }
        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_CMD_FIN:
        stream = ngx_stream_trojan_mux_find_stream(ctx,
                                                   ctx->mux_frame.stream_id);
        if (stream != NULL) {
            stream->client_fin = 1;
            if (stream->state == ngx_stream_trojan_mux_stream_request) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
            } else {
                ngx_stream_trojan_mux_queue_process(stream);
            }
        }
        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_CMD_PSH:
        stream = ctx->mux_payload_stream;
        if (stream != NULL) {
            if (ctx->mux_payload_direct) {
                ngx_stream_trojan_mux_queue_process(stream);
                return NGX_OK;
            }

            return ngx_stream_trojan_mux_feed_stream(
                stream, ctx->mux_payload, ctx->mux_payload_len);
        }
        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_CMD_NOP:
        ctx->mux_nop_pending = 1;
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_stream_trojan_mux_cool_handle_frame(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_stream_trojan_mux_stream_t       *stream;
    ngx_stream_trojan_mux_cool_frame_t   *frame;

    frame = &ctx->mux_cool_frame;

    switch (frame->status) {
    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_NEW:
        if (frame->session_id == 0
            || frame->network != NGX_STREAM_TROJAN_MUX_COOL_NETWORK_TCP)
        {
            return NGX_ERROR;
        }

        stream = ngx_stream_trojan_mux_find_stream(ctx, frame->session_id);
        if (stream != NULL) {
            return NGX_ERROR;
        }

        stream = ngx_stream_trojan_mux_create_stream(ctx, frame->session_id);
        if (stream == NULL) {
            return NGX_ERROR;
        }

        stream->command = NGX_STREAM_TROJAN_CMD_CONNECT;
        stream->target = frame->target;
        stream->outbound = ngx_stream_trojan_select_outbound(
            ctx, &stream->target, stream->command);
        ngx_stream_trojan_mux_start_stream(stream);

        if (ctx->mux_payload_len) {
            return ngx_stream_trojan_mux_append_client_data(
                stream, ctx->mux_payload, ctx->mux_payload_len);
        }

        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEP:
        stream = ngx_stream_trojan_mux_find_stream(ctx, frame->session_id);
        if (stream == NULL) {
            return NGX_OK;
        }

        if (ctx->mux_payload_len && !ctx->mux_payload_direct) {
            return ngx_stream_trojan_mux_append_client_data(
                stream, ctx->mux_payload, ctx->mux_payload_len);
        }

        if (ctx->mux_payload_direct) {
            ngx_stream_trojan_mux_queue_process(stream);
        }

        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_END:
        stream = ngx_stream_trojan_mux_find_stream(ctx, frame->session_id);
        if (stream != NULL) {
            if (ctx->mux_payload_len && !ctx->mux_payload_direct
                && ngx_stream_trojan_mux_append_client_data(
                       stream, ctx->mux_payload, ctx->mux_payload_len)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

            stream->client_fin = 1;
            ngx_stream_trojan_mux_queue_process(stream);
        }

        return NGX_OK;

    case NGX_STREAM_TROJAN_MUX_COOL_STATUS_KEEPALIVE:
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}


static ngx_uint_t
ngx_stream_trojan_mux_stream_slot(uint32_t id)
{
    return (ngx_uint_t) ((id * 2654435761u)
                         % NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE);
}


static ngx_int_t
ngx_stream_trojan_mux_insert_stream(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_uint_t                       i, n, tombstone, slot;
    ngx_stream_trojan_mux_stream_t  *entry;

    i = ngx_stream_trojan_mux_stream_slot(stream->id);
    tombstone = NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE;

    for (n = 0; n < NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE; n++) {
        entry = ctx->mux_stream_table[i];

        if (entry == NULL) {
            slot = tombstone == NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE
                   ? i : tombstone;
            ctx->mux_stream_table[slot] = stream;
            if (slot == tombstone && ctx->mux_tombstones) {
                ctx->mux_tombstones--;
            }
            return NGX_OK;
        }

        if (entry == NGX_STREAM_TROJAN_MUX_TOMBSTONE) {
            if (tombstone == NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE) {
                tombstone = i;
            }

        } else if (entry->id == stream->id) {
            return NGX_ERROR;
        }

        if (++i == NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE) {
            i = 0;
        }
    }

    if (tombstone != NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE) {
        ctx->mux_stream_table[tombstone] = stream;
        if (ctx->mux_tombstones) {
            ctx->mux_tombstones--;
        }
        return NGX_OK;
    }

    return NGX_ERROR;
}


static void
ngx_stream_trojan_mux_remove_stream(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_uint_t                       i, n;
    ngx_stream_trojan_mux_stream_t  *entry;

    i = ngx_stream_trojan_mux_stream_slot(stream->id);

    for (n = 0; n < NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE; n++) {
        entry = ctx->mux_stream_table[i];

        if (entry == NULL) {
            return;
        }

        if (entry == stream) {
            ctx->mux_stream_table[i] = NGX_STREAM_TROJAN_MUX_TOMBSTONE;
            ctx->mux_tombstones++;
            return;
        }

        if (++i == NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE) {
            i = 0;
        }
    }
}


static ngx_stream_trojan_mux_stream_t *
ngx_stream_trojan_mux_find_stream(ngx_stream_trojan_ctx_t *ctx, uint32_t id)
{
    ngx_uint_t                       i, n;
    ngx_stream_trojan_mux_stream_t  *stream;

    i = ngx_stream_trojan_mux_stream_slot(id);

    for (n = 0; n < NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE; n++) {
        stream = ctx->mux_stream_table[i];

        if (stream == NULL) {
            return NULL;
        }

        if (stream != NGX_STREAM_TROJAN_MUX_TOMBSTONE
            && stream->id == id)
        {
            return stream;
        }

        if (++i == NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE) {
            i = 0;
        }
    }

    return NULL;
}
static void
ngx_stream_trojan_mux_rebuild_stream_table(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_queue_t                    *q;
    ngx_stream_trojan_mux_stream_t *stream;

    ngx_memzero(ctx->mux_stream_table, sizeof(ctx->mux_stream_table));
    ctx->mux_tombstones = 0;

    for (q = ngx_queue_head(&ctx->mux_streams);
         q != ngx_queue_sentinel(&ctx->mux_streams);
         q = ngx_queue_next(q))
    {
        stream = ngx_queue_data(q, ngx_stream_trojan_mux_stream_t, queue);
        (void) ngx_stream_trojan_mux_insert_stream(ctx, stream);
    }
}


static void
ngx_stream_trojan_mux_maybe_rebuild_stream_table(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->mux_tombstones == 0) {
        return;
    }

    if (ctx->mux_nstreams == 0) {
        ngx_memzero(ctx->mux_stream_table, sizeof(ctx->mux_stream_table));
        ctx->mux_tombstones = 0;
        return;
    }

    if (ctx->mux_tombstones < NGX_STREAM_TROJAN_MUX_STREAM_TABLE_SIZE / 4
        && ctx->mux_tombstones < ctx->mux_nstreams)
    {
        return;
    }

    ngx_stream_trojan_mux_rebuild_stream_table(ctx);
}



static ngx_stream_trojan_mux_stream_t *
ngx_stream_trojan_mux_create_stream(ngx_stream_trojan_ctx_t *ctx, uint32_t id)
{
    ngx_pool_t                     *pool;
    ngx_stream_trojan_mux_stream_t *stream;

    if (ctx->mux_nstreams >= NGX_STREAM_TROJAN_MUX_MAX_STREAMS) {
        return NULL;
    }

    pool = ngx_create_pool(NGX_STREAM_TROJAN_MUX_STREAM_POOL_SIZE,
                           ctx->session->connection->log);
    if (pool == NULL) {
        return NULL;
    }

    stream = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_mux_stream_t));
    if (stream == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    stream->ctx = ctx;
    stream->pool = pool;
    stream->id = id;
    stream->state = ngx_stream_trojan_mux_stream_request;
    ngx_queue_init(&stream->process_queue);
    ngx_queue_init(&stream->flush_queue);

    if (ngx_stream_trojan_mux_insert_stream(ctx, stream) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_queue_insert_tail(&ctx->mux_streams, &stream->queue);
    ctx->mux_nstreams++;

    return stream;
}

static void
ngx_stream_trojan_mux_queue_process(ngx_stream_trojan_mux_stream_t *stream)
{
    if (stream->process_queued
        || stream->state == ngx_stream_trojan_mux_stream_closing)
    {
        return;
    }

    ngx_queue_insert_tail(&stream->ctx->mux_process_queue,
                          &stream->process_queue);
    stream->process_queued = 1;
}


static void
ngx_stream_trojan_mux_process_queued_streams(ngx_stream_trojan_ctx_t *ctx)
{
    size_t                         budget;
    ngx_int_t                      rc;
    ngx_queue_t                   *q;
    ngx_stream_trojan_mux_stream_t *stream;

    budget = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);

    while (budget && !ngx_queue_empty(&ctx->mux_process_queue)) {
        q = ngx_queue_head(&ctx->mux_process_queue);
        ngx_queue_remove(q);
        stream = ngx_queue_data(q, ngx_stream_trojan_mux_stream_t,
                                process_queue);
        stream->process_queued = 0;

        rc = ngx_stream_trojan_mux_process_stream(stream, &budget);
        if (rc == NGX_BUSY) {
            ngx_stream_trojan_mux_queue_process(stream);
            break;
        }
    }

    if (budget == 0 && !ngx_queue_empty(&ctx->mux_process_queue)) {
        ngx_stream_trojan_mux_post_client_read_next(ctx);
    }
}


static void
ngx_stream_trojan_mux_queue_flush(ngx_stream_trojan_mux_stream_t *stream)
{
    if (stream->flush_queued) {
        return;
    }

    ngx_queue_insert_tail(&stream->ctx->mux_flush_queue,
                          &stream->flush_queue);
    stream->flush_queued = 1;
}


static ngx_int_t
ngx_stream_trojan_mux_ensure_client_buffer(
    ngx_stream_trojan_mux_stream_t *stream, size_t len)
{
    size_t      size, capacity, buffered;
    ngx_buf_t  *b, *nb;

    b = stream->client_buffer;
    buffered = b == NULL ? 0 : (size_t) (b->last - b->pos);

    size = stream->ctx->conf->buffer_size;
    if (size > NGX_STREAM_TROJAN_MUX_STREAM_BUFFER_SIZE) {
        size = NGX_STREAM_TROJAN_MUX_STREAM_BUFFER_SIZE;
    }
    if (size < len) {
        size = len;
    }
    if (size < buffered + len) {
        size = buffered + len;
    }
    if (size > NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE) {
        size = NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE;
    }

    if (b != NULL) {
        capacity = b->end - b->start;
        if (capacity >= size) {
            return NGX_OK;
        }
    }

    nb = ngx_stream_trojan_create_temp_buf(stream->pool, size);
    if (nb == NULL) {
        return NGX_ERROR;
    }

    if (buffered) {
        ngx_memcpy(nb->last, b->pos, buffered);
        nb->last += buffered;
    }

    stream->client_buffer = nb;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_ensure_upstream_buffer(
    ngx_stream_trojan_mux_stream_t *stream)
{
    size_t  size;

    if (stream->upstream_buffer != NULL) {
        return NGX_OK;
    }

    size = stream->ctx->conf->buffer_size;
    if (size > NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE) {
        size = NGX_STREAM_TROJAN_MUX_MAX_FRAME_SIZE;
    }

    stream->upstream_buffer = ngx_stream_trojan_create_temp_buf(stream->pool,
                                                               size);

    return stream->upstream_buffer == NULL ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_stream_can_accept(
    ngx_stream_trojan_mux_stream_t *stream, size_t len)
{
    ngx_buf_t  *b;

    if (stream == NULL || len == 0
        || stream->state == ngx_stream_trojan_mux_stream_closing)
    {
        return NGX_OK;
    }

    if (ngx_stream_trojan_mux_ensure_client_buffer(stream, len) != NGX_OK) {
        return NGX_ERROR;
    }

    b = stream->client_buffer;

    if ((size_t) (b->end - b->last) >= len) {
        return NGX_OK;
    }

    ngx_stream_trojan_mux_compact_buf(b);

    if ((size_t) (b->end - b->last) < len) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}

static ngx_uint_t
ngx_stream_trojan_mux_client_blocked_on(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_mux_stream_t *stream)
{
    return ctx != NULL && stream != NULL
           && ctx->mux_payload_stream == stream
           && ctx->mux_frame_parsed
           && ctx->mux_payload_len != 0
           && ctx->mux_payload_blocked;
}


static void
ngx_stream_trojan_mux_post_client_read(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c;

    if (ctx == NULL || ctx->finalized || ctx->session == NULL) {
        return;
    }

    c = ctx->session->connection;
    if (c == NULL || c->read == NULL) {
        return;
    }

    ngx_post_event(c->read, &ngx_posted_events);
}


static void
ngx_stream_trojan_mux_post_client_read_next(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c;

    if (ctx == NULL || ctx->finalized || ctx->session == NULL) {
        return;
    }

    c = ctx->session->connection;
    if (c == NULL || c->read == NULL) {
        return;
    }

    ngx_post_event(c->read, &ngx_posted_next_events);
}


static ngx_int_t
ngx_stream_trojan_mux_append_client_data(
    ngx_stream_trojan_mux_stream_t *stream, u_char *data, size_t len)
{
    ngx_int_t  rc;
    ngx_buf_t *b;

    if (len == 0 || stream->state == ngx_stream_trojan_mux_stream_closing) {
        return NGX_OK;
    }

    rc = ngx_stream_trojan_mux_stream_can_accept(stream, len);
    if (rc != NGX_OK) {
        return rc;
    }

    b = stream->client_buffer;
    ngx_memcpy(b->last, data, len);
    b->last += len;

    ngx_stream_trojan_mux_queue_process(stream);
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_feed_stream(ngx_stream_trojan_mux_stream_t *stream,
    u_char *data, size_t len)
{
    size_t     needed, n;
    ngx_int_t  rc;

    while (len) {
        if (stream->state == ngx_stream_trojan_mux_stream_closing) {
            return NGX_OK;
        }

        if (stream->state == ngx_stream_trojan_mux_stream_request) {
            for ( ;; ) {
                if (stream->ctx->mux_sing) {
                    rc = ngx_stream_trojan_mux_sing_request_needed(
                        stream->request, stream->request_len, &needed);
                } else {
                    rc = ngx_stream_trojan_mux_request_needed(
                        stream->request, stream->request_len, &needed);
                }

                if (rc == NGX_STREAM_TROJAN_MUX_ERROR) {
                    ngx_stream_trojan_mux_close_stream(stream, 1);
                    return NGX_OK;
                }

                if (rc == NGX_STREAM_TROJAN_MUX_OK) {
                    break;
                }

                n = needed - stream->request_len;
                if (n > len) {
                    n = len;
                }

                ngx_memcpy(stream->request + stream->request_len, data, n);
                stream->request_len += n;
                data += n;
                len -= n;

                if (stream->request_len < needed) {
                    return NGX_OK;
                }
            }

            if (stream->ctx->mux_sing) {
                if (ngx_stream_trojan_mux_sing_parse_request(
                        stream->request, needed, &stream->target)
                    != NGX_STREAM_TROJAN_MUX_OK)
                {
                    ngx_stream_trojan_mux_close_stream(stream, 1);
                    return NGX_OK;
                }

                stream->command = NGX_STREAM_TROJAN_CMD_CONNECT;

            } else {
                if (ngx_stream_trojan_parse_addr(stream->request + 1,
                                                 needed - 1, &stream->target)
                    != 0)
                {
                    ngx_stream_trojan_mux_close_stream(stream, 1);
                    return NGX_OK;
                }

                stream->command = stream->request[0];
            }

            stream->outbound = ngx_stream_trojan_select_outbound(
                stream->ctx, &stream->target, stream->command);
            ngx_stream_trojan_mux_start_stream(stream);
            continue;
        }

        rc = ngx_stream_trojan_mux_append_client_data(stream, data, len);
        if (rc != NGX_OK) {
            return rc;
        }
        len = 0;
    }

    return NGX_OK;
}



static void
ngx_stream_trojan_mux_start_stream(ngx_stream_trojan_mux_stream_t *stream)
{
    if (stream->command != NGX_STREAM_TROJAN_CMD_CONNECT) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    if (ngx_stream_trojan_route_missed(stream->ctx, stream->outbound)) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    if (ngx_stream_trojan_mux_stream_request_blocked(stream)) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_stream_trojan_mux_start_tcp(stream);
}


static ngx_uint_t
ngx_stream_trojan_mux_stream_outbound_type(
    ngx_stream_trojan_mux_stream_t *stream)
{
    if (stream->outbound == NULL) {
        return ngx_stream_trojan_outbound_direct;
    }

    return stream->outbound->type;
}


static ngx_uint_t
ngx_stream_trojan_mux_stream_ip_prefer(
    ngx_stream_trojan_mux_stream_t *stream)
{
    if (stream->outbound == NULL
        || stream->outbound->type != ngx_stream_trojan_outbound_direct)
    {
        return NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    }

    return stream->outbound->ip_prefer;
}

static ngx_uint_t
ngx_stream_trojan_mux_stream_request_blocked(
    ngx_stream_trojan_mux_stream_t *stream)
{
    return ngx_stream_trojan_outbound_request_blocked(stream->outbound,
                                                      stream->command,
                                                      &stream->target);
}



static void
ngx_stream_trojan_mux_start_tcp(ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_addr_t                         addr;
    ngx_pool_t                        *pool;
    ngx_stream_trojan_ctx_t           *ctx;
    ngx_stream_trojan_mux_resolve_data_t *data;
    ngx_stream_trojan_dns_rule_group_t *dns_rule;

    ctx = stream->ctx;

    if (ngx_stream_trojan_mux_stream_outbound_type(stream)
        == ngx_stream_trojan_outbound_socks5)
    {
        ngx_stream_trojan_mux_start_socks5_tcp(stream);
        return;
    }

    pool = stream->pool;
    dns_rule = ngx_stream_trojan_match_dns_rule(ctx->conf, &stream->target);

    if (dns_rule != NULL) {
        if (dns_rule->doh_conf != NULL) {
            data = ngx_stream_trojan_mux_create_doh_resolve_data(stream,
                       dns_rule->ip_prefer, dns_rule->doh_conf);
            if (data == NULL) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            if (ngx_stream_trojan_mux_start_doh_resolver(stream, data)
                != NGX_OK)
            {
                ngx_stream_trojan_mux_close_stream(stream, 1);
            }
            return;
        }

        if (ngx_stream_trojan_mux_start_resolver(stream, dns_rule) != NGX_OK) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
        }
        return;
    }

    if (ctx->conf->doh_conf != NULL
        && stream->target.type == NGX_STREAM_TROJAN_ADDR_DOMAIN
        && stream->target.host_len > 0 && stream->target.host_len <= 255)
    {
        data = ngx_stream_trojan_mux_create_doh_resolve_data(stream,
                   ngx_stream_trojan_mux_stream_ip_prefer(stream),
                   ctx->conf->doh_conf);
        if (data == NULL) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
            return;
        }

        if (ngx_stream_trojan_mux_start_doh_resolver(stream, data) != NGX_OK)
        {
            ngx_stream_trojan_mux_close_stream(stream, 1);
        }
        return;
    }

    if (ngx_stream_trojan_use_nginx_resolver(
            stream->target.type,
            ngx_stream_trojan_resolver_configured(ctx->session)))
    {
        if (ngx_stream_trojan_mux_start_resolver(stream, NULL) != NGX_OK) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
        }
        return;
    }

    if (ngx_stream_trojan_resolve_addr_prefer(pool,
            ctx->session->connection->log, &stream->target,
            ngx_stream_trojan_mux_stream_ip_prefer(stream), &addr)
        != NGX_OK)
    {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_stream_trojan_mux_connect(stream, &addr);
}


static ngx_int_t
ngx_stream_trojan_mux_start_resolver(ngx_stream_trojan_mux_stream_t *stream,
    ngx_stream_trojan_dns_rule_group_t *dns_rule)
{
    ngx_str_t                           name;
    ngx_pool_t                         *pool;
    ngx_resolver_ctx_t                 *rctx, temp;
    ngx_stream_core_srv_conf_t         *cscf;
    ngx_stream_trojan_mux_resolve_data_t *data;

    if (stream->target.type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || stream->target.host_len == 0 || stream->target.host_len > 255)
    {
        return NGX_ERROR;
    }

    pool = stream->pool;
    data = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_mux_resolve_data_t));
    if (data == NULL) {
        return NGX_ERROR;
    }

    name.data = ngx_pnalloc(pool, stream->target.host_len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(name.data, stream->target.host, stream->target.host_len);
    name.len = stream->target.host_len;

    data->stream = stream;
    data->ip_prefer = dns_rule != NULL ? dns_rule->ip_prefer
                                       : ngx_stream_trojan_mux_stream_ip_prefer(stream);
    data->port = stream->target.port;

    ngx_memzero(&temp, sizeof(ngx_resolver_ctx_t));
    temp.name = name;

    cscf = ngx_stream_get_module_srv_conf(stream->ctx->session,
                                          ngx_stream_core_module);
    rctx = ngx_resolve_start(dns_rule != NULL ? dns_rule->resolver
                                              : cscf->resolver,
                             &temp);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        return NGX_ERROR;
    }

    rctx->name = name;
    rctx->handler = ngx_stream_trojan_mux_resolve_handler;
    rctx->data = data;
    rctx->timeout = cscf->resolver_timeout;

    stream->resolver_ctx = rctx;
    stream->state = ngx_stream_trojan_mux_stream_resolving;

    if (ngx_resolve_name(rctx) != NGX_OK) {
        stream->resolver_ctx = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_mux_resolve_complete(
    ngx_stream_trojan_mux_stream_t *stream,
    ngx_stream_trojan_mux_resolve_data_t *data,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs)
{
    ngx_addr_t  addr;

    if (stream == NULL || stream->state == ngx_stream_trojan_mux_stream_closing)
    {
        return;
    }

    if (naddrs == 0
        || ngx_stream_trojan_resolver_addr_to_ngx_addr(
               stream->pool,
               ngx_stream_trojan_resolver_pick_addr(
                   addrs, naddrs, data->ip_prefer),
               data->port, &addr)
           != NGX_OK)
    {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_stream_trojan_mux_connect(stream, &addr);
}


static void
ngx_stream_trojan_mux_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_stream_trojan_mux_stream_t       *stream;
    ngx_stream_trojan_mux_resolve_data_t *data;

    data = rctx->data;
    stream = data->stream;

    if (stream == NULL) {
        ngx_resolve_name_done(rctx);
        return;
    }

    stream->resolver_ctx = NULL;

    if (rctx->state) {
        ngx_log_error(NGX_LOG_INFO, stream->ctx->session->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &rctx->name, rctx->state,
                      ngx_resolver_strerror(rctx->state));
        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_stream_trojan_mux_resolve_complete(stream, data,
                                           rctx->addrs, rctx->naddrs);
    ngx_resolve_name_done(rctx);
}


static ngx_int_t
ngx_stream_trojan_mux_start_doh_resolver(
    ngx_stream_trojan_mux_stream_t *stream,
    ngx_stream_trojan_mux_resolve_data_t *data)
{
    if (data->doh_conf == NULL
        || data->name == NULL || data->name_len == 0)
    {
        return NGX_ERROR;
    }

    stream->state = ngx_stream_trojan_mux_stream_resolving;

    return ngx_stream_trojan_doh_resolve(data->doh_conf,
        data->name, data->name_len, data->qtype,
        stream->ctx->session->connection->log, data,
        ngx_stream_trojan_mux_doh_resolve_handler, &stream->doh_ctx);
}


static void
ngx_stream_trojan_mux_doh_resolve_handler(void *cb_data, ngx_int_t status,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs)
{
    ngx_stream_trojan_mux_stream_t       *stream;
    ngx_stream_trojan_mux_resolve_data_t *data;

    data = cb_data;
    stream = data->stream;

    if (stream == NULL
        || stream->state == ngx_stream_trojan_mux_stream_closing)
    {
        return;
    }

    stream->doh_ctx = NULL;

    if (status != NGX_OK || naddrs == 0) {
        if (status == NGX_DECLINED && data->fallback_qtype != 0) {
            data->qtype = data->fallback_qtype;
            data->fallback_qtype = 0;

            if (ngx_stream_trojan_mux_start_doh_resolver(stream, data)
                == NGX_OK)
            {
                return;
            }
        }

        ngx_log_error(NGX_LOG_INFO, stream->ctx->session->connection->log, 0,
                      "DoH: mux resolution failed");
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_stream_trojan_mux_resolve_complete(stream, data, addrs, naddrs);
}


static void
ngx_stream_trojan_mux_connect(ngx_stream_trojan_mux_stream_t *stream,
    ngx_addr_t *addr)
{
    ngx_int_t                  rc;
    ngx_uint_t                 resume;
    ngx_connection_t          *c, *pc;
    ngx_stream_trojan_ctx_t   *ctx;

    ctx = stream->ctx;
    c = ctx->session->connection;
    stream->state = ngx_stream_trojan_mux_stream_connecting;

    ngx_memzero(&stream->peer, sizeof(ngx_peer_connection_t));
    stream->peer.sockaddr = addr->sockaddr;
    stream->peer.socklen = addr->socklen;
    stream->peer_name = addr->name;
    stream->peer.name = &stream->peer_name;
    stream->peer.type = SOCK_STREAM;
    stream->peer.get = ngx_event_get_peer;
    stream->peer.log = c->log;
    stream->peer.log_error = NGX_ERROR_ERR;
    stream->peer.tries = 1;
    stream->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&stream->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    pc = stream->peer.connection;
    stream->upstream = pc;

    pc->data = stream;
    pc->log = c->log;
    pc->pool = stream->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;
    pc->read->handler = ngx_stream_trojan_mux_peer_handler;
    pc->write->handler = ngx_stream_trojan_mux_peer_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(pc->write, ctx->conf->connect_timeout);
        return;
    }

    resume = ngx_stream_trojan_mux_client_blocked_on(ctx, stream);
    ngx_stream_trojan_mux_init_proxy(stream);
    if (resume) {
        ngx_stream_trojan_mux_post_client_read(ctx);
    }
}


static void
ngx_stream_trojan_mux_peer_handler(ngx_event_t *ev)
{
    size_t                            budget;
    ngx_int_t                         rc;
    ngx_connection_t                 *pc;
    ngx_uint_t                        resume;
    ngx_stream_trojan_ctx_t          *ctx;
    ngx_stream_trojan_mux_stream_t   *stream;

    pc = ev->data;
    stream = pc->data;

    if (stream == NULL) {
        ngx_close_connection(pc);
        return;
    }

    ctx = stream->ctx;

    if (ev->timedout) {
        if (stream->state == ngx_stream_trojan_mux_stream_connecting) {
            ngx_connection_error(pc, NGX_ETIMEDOUT,
                                 "trojan mux upstream timed out");

        } else {
            ngx_connection_error(pc, NGX_ETIMEDOUT,
                                 "trojan mux upstream idle timed out");
        }

        ngx_stream_trojan_mux_close_stream(stream, 1);
        (void) ngx_stream_trojan_mux_flush_client(ctx);
        return;
    }

    if (stream->state == ngx_stream_trojan_mux_stream_connecting) {
        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
            (void) ngx_stream_trojan_mux_flush_client(ctx);
            return;
        }

        resume = ngx_stream_trojan_mux_client_blocked_on(ctx, stream);
        ngx_stream_trojan_mux_init_proxy(stream);
        if (resume) {
            ngx_stream_trojan_mux_post_client_read(ctx);
        }
        return;
    }

    resume = ngx_stream_trojan_mux_client_blocked_on(ctx, stream);
    budget = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    rc = ngx_stream_trojan_mux_process_stream(stream, &budget);
    if (rc == NGX_BUSY) {
        ngx_stream_trojan_mux_queue_process(stream);
        ngx_stream_trojan_mux_post_client_read_next(ctx);
    }
    if (resume) {
        ngx_stream_trojan_mux_post_client_read(ctx);
    }

    if (ngx_stream_trojan_mux_flush_client(ctx) == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
    }
}


static void
ngx_stream_trojan_mux_init_proxy(ngx_stream_trojan_mux_stream_t *stream)
{
    size_t                  budget;
    ngx_int_t               rc;
    ngx_connection_t        *pc;
    ngx_stream_trojan_ctx_t *ctx;

    ctx = stream->ctx;
    pc = stream->upstream;

    if (pc == NULL) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_stream_trojan_mux_ensure_upstream_buffer(stream) != NGX_OK) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    if (ctx->mux_sing && !stream->sing_response_sent) {
        if (stream->upstream_buffer->last == stream->upstream_buffer->end) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
            return;
        }

        *stream->upstream_buffer->last++ =
            NGX_STREAM_TROJAN_MUX_SING_STATUS_SUCCESS;
        stream->sing_response_sent = 1;
        ngx_stream_trojan_mux_queue_flush(stream);
    }

    pc->read->handler = ngx_stream_trojan_mux_peer_handler;
    pc->write->handler = ngx_stream_trojan_mux_peer_handler;

    ngx_stream_trojan_mux_refresh_read_timeout(ctx, pc);

    stream->state = ngx_stream_trojan_mux_stream_proxy;
    budget = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    rc = ngx_stream_trojan_mux_process_stream(stream, &budget);
    if (rc == NGX_BUSY) {
        ngx_stream_trojan_mux_queue_process(stream);
        ngx_stream_trojan_mux_post_client_read_next(ctx);
    }
}


static ngx_int_t
ngx_stream_trojan_mux_flush_to_upstream(
    ngx_stream_trojan_mux_stream_t *stream, size_t *send_budget)
{
    size_t              size;
    ssize_t             n;
    ngx_uint_t          refreshed;
    ngx_connection_t   *pc;
    ngx_buf_t          *b;

    pc = stream->upstream;
    b = stream->client_buffer;

    if (pc == NULL || b == NULL) {
        return NGX_OK;
    }

    refreshed = 0;

    while (b->pos < b->last) {
        if (send_budget != NULL && *send_budget == 0) {
            if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            if (refreshed) {
                ngx_stream_trojan_mux_refresh_read_timeout(stream->ctx, pc);
            }
            return NGX_BUSY;
        }

        size = b->last - b->pos;
        if (send_budget != NULL && size > *send_budget) {
            size = *send_budget;
        }

        n = pc->send(pc, b->pos, size);

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            if (refreshed) {
                ngx_stream_trojan_mux_refresh_read_timeout(stream->ctx, pc);
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
        refreshed = 1;
        if (send_budget != NULL) {
            *send_budget -= (size_t) n;
        }
    }

    ngx_stream_trojan_mux_reset_buf(b);

    if (stream->client_fin && !stream->upstream_write_shutdown) {
        (void) shutdown(pc->fd, SHUT_WR);
        stream->upstream_write_shutdown = 1;
    }

    if (refreshed) {
        ngx_stream_trojan_mux_refresh_read_timeout(stream->ctx, pc);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_read_upstream(ngx_stream_trojan_mux_stream_t *stream)
{
    ssize_t             n;
    ngx_connection_t   *pc;
    ngx_buf_t          *b;

    pc = stream->upstream;
    b = stream->upstream_buffer;

    if (pc == NULL || b == NULL || stream->upstream_eof
        || b->pos < b->last)
    {
        return NGX_OK;
    }

    if (!pc->read->ready) {
        return NGX_OK;
    }

    n = pc->recv(pc, b->last, b->end - b->last);

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    if (n == 0) {
        stream->upstream_eof = 1;
        pc->read->eof = 1;
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        stream->upstream_eof = 1;
        pc->read->error = 1;
        return NGX_OK;
    }

    b->last += n;
    ngx_stream_trojan_mux_queue_flush(stream);
    ngx_stream_trojan_mux_refresh_read_timeout(stream->ctx, pc);
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_process_stream(ngx_stream_trojan_mux_stream_t *stream,
    size_t *send_budget)
{
    ngx_int_t  rc;

    if (stream->state != ngx_stream_trojan_mux_stream_proxy) {
        return NGX_OK;
    }

    rc = ngx_stream_trojan_mux_flush_to_upstream(stream, send_budget);
    if (rc == NGX_ERROR) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return NGX_ERROR;
    }

    if (rc == NGX_BUSY) {
        return NGX_BUSY;
    }

    if (ngx_stream_trojan_mux_client_blocked_on(stream->ctx, stream)
        && (stream->client_buffer == NULL
            || stream->client_buffer->last < stream->client_buffer->end
            || stream->client_buffer->pos > stream->client_buffer->start))
    {
        ngx_stream_trojan_mux_post_client_read(stream->ctx);
    }

    if (ngx_stream_trojan_mux_read_upstream(stream) != NGX_OK) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return NGX_ERROR;
    }

    if (stream->upstream_eof
        && stream->upstream_buffer->pos == stream->upstream_buffer->last
        && !stream->fin_sent)
    {
        stream->fin_to_client = 1;
        ngx_stream_trojan_mux_queue_flush(stream);
    }

    if (stream->upstream_buffer
        && stream->upstream_buffer->pos < stream->upstream_buffer->last)
    {
        ngx_stream_trojan_mux_queue_flush(stream);
    }

    if (stream->client_fin && stream->upstream_write_shutdown
        && stream->upstream_eof && stream->fin_sent)
    {
        ngx_stream_trojan_mux_close_stream(stream, 0);
        return NGX_OK;
    }

    if (stream->upstream && ngx_handle_read_event(stream->upstream->read, 0)
        != NGX_OK)
    {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return NGX_ERROR;
    }

    if (stream->upstream && ngx_handle_write_event(stream->upstream->write, 0)
        != NGX_OK)
    {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_mux_close_stream(ngx_stream_trojan_mux_stream_t *stream,
    ngx_uint_t send_fin)
{
    if (stream->resolver_ctx) {
        ngx_resolve_name_done(stream->resolver_ctx);
        stream->resolver_ctx = NULL;
    }

    if (stream->doh_ctx) {
        ngx_stream_trojan_doh_cancel(stream->doh_ctx);
        stream->doh_ctx = NULL;
    }

    if (stream->upstream) {
        ngx_close_connection(stream->upstream);
        stream->upstream = NULL;
    }

    stream->state = ngx_stream_trojan_mux_stream_closing;
    stream->upstream_eof = 1;
    stream->client_fin = 1;
    stream->close_after_send = 1;

    if (send_fin && !stream->fin_sent) {
        stream->fin_to_client = 1;
        ngx_stream_trojan_mux_queue_flush(stream);
    }

    ngx_stream_trojan_mux_cleanup_stream(stream);
}


static void
ngx_stream_trojan_mux_cleanup_stream(ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_stream_trojan_ctx_t  *ctx;
    ngx_pool_t               *pool;

    if (!stream->close_after_send) {
        return;
    }

    if (stream->fin_to_client && !stream->fin_sent) {
        return;
    }

    if (stream->upstream_buffer
        && stream->upstream_buffer->pos < stream->upstream_buffer->last)
    {
        return;
    }

    if (stream->resolver_ctx) {
        ngx_resolve_name_done(stream->resolver_ctx);
        stream->resolver_ctx = NULL;
    }

    if (stream->doh_ctx) {
        ngx_stream_trojan_doh_cancel(stream->doh_ctx);
        stream->doh_ctx = NULL;
    }

    if (stream->upstream) {
        ngx_close_connection(stream->upstream);
        stream->upstream = NULL;
    }

    ctx = stream->ctx;
    pool = stream->pool;
    if (stream->process_queued) {
        ngx_queue_remove(&stream->process_queue);
        stream->process_queued = 0;
    }

    if (stream->flush_queued) {
        ngx_queue_remove(&stream->flush_queue);
        stream->flush_queued = 0;
    }

    if (ctx->mux_payload_stream == stream) {
        ctx->mux_payload_stream = NULL;
        ctx->mux_payload_direct = 0;
        ctx->mux_payload_accept_checked = 0;
        ctx->mux_payload_blocked = 0;
        ngx_stream_trojan_mux_post_client_read(ctx);
    }
    ngx_stream_trojan_mux_remove_stream(ctx, stream);
    ngx_queue_remove(&stream->queue);
    if (ctx->mux_nstreams) {
        ctx->mux_nstreams--;
    }
    ngx_stream_trojan_mux_maybe_rebuild_stream_table(ctx);
    ngx_destroy_pool(pool);
}


static void
ngx_stream_trojan_mux_close_streams(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_queue_t                    *q;
    ngx_pool_t                     *pool;
    ngx_stream_trojan_mux_stream_t *stream;

    while (!ngx_queue_empty(&ctx->mux_streams)) {
        q = ngx_queue_head(&ctx->mux_streams);
        stream = ngx_queue_data(q, ngx_stream_trojan_mux_stream_t, queue);

        if (stream->resolver_ctx) {
            ngx_resolve_name_done(stream->resolver_ctx);
            stream->resolver_ctx = NULL;
        }

        if (stream->doh_ctx) {
            ngx_stream_trojan_doh_cancel(stream->doh_ctx);
            stream->doh_ctx = NULL;
        }

        if (stream->upstream) {
            ngx_close_connection(stream->upstream);
            stream->upstream = NULL;
        }

        pool = stream->pool;
        ngx_queue_remove(&stream->queue);
        ngx_destroy_pool(pool);
    }

    ngx_queue_init(&ctx->mux_process_queue);
    ngx_queue_init(&ctx->mux_flush_queue);
    ngx_memzero(ctx->mux_stream_table, sizeof(ctx->mux_stream_table));
    ctx->mux_nstreams = 0;
    ctx->mux_tombstones = 0;
}


static void
ngx_stream_trojan_mux_start_socks5_tcp(ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_stream_trojan_mux_socks5_connect(stream);
}


static void
ngx_stream_trojan_mux_socks5_connect(
    ngx_stream_trojan_mux_stream_t *stream)
{
    ngx_int_t                rc;
    ngx_connection_t        *c, *pc;
    ngx_stream_trojan_ctx_t *ctx;

    ctx = stream->ctx;

    if (stream->outbound == NULL || stream->outbound->socks5_server == NULL) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    c = ctx->session->connection;
    stream->socks5_buffer = ngx_stream_trojan_create_temp_buf(
        stream->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
    if (stream->socks5_buffer == NULL) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    stream->socks5_step = ngx_stream_trojan_socks5_step_greeting_write;
    stream->state = ngx_stream_trojan_mux_stream_socks5;

    if (ngx_stream_trojan_mux_socks5_prepare_greeting(stream) != NGX_OK) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    ngx_memzero(&stream->peer, sizeof(ngx_peer_connection_t));
    stream->peer.sockaddr = stream->outbound->socks5_server->sockaddr;
    stream->peer.socklen = stream->outbound->socks5_server->socklen;
    stream->peer_name = stream->outbound->socks5_server->name;
    stream->peer.name = &stream->peer_name;
    stream->peer.type = SOCK_STREAM;
    stream->peer.get = ngx_event_get_peer;
    stream->peer.log = c->log;
    stream->peer.log_error = NGX_ERROR_ERR;
    stream->peer.tries = 1;
    stream->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&stream->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    pc = stream->peer.connection;
    stream->upstream = pc;

    pc->data = stream;
    pc->log = c->log;
    pc->pool = stream->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;
    pc->read->handler = ngx_stream_trojan_mux_socks5_handler;
    pc->write->handler = ngx_stream_trojan_mux_socks5_handler;

    ngx_add_timer(pc->write, ctx->conf->connect_timeout);

    if (rc == NGX_AGAIN) {
        return;
    }

    stream->socks5_connected = 1;
    ngx_stream_trojan_mux_process_socks5(stream);
}


static void
ngx_stream_trojan_mux_socks5_handler(ngx_event_t *ev)
{
    ngx_connection_t               *pc;
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_mux_stream_t *stream;

    pc = ev->data;
    stream = pc->data;

    if (stream == NULL) {
        ngx_close_connection(pc);
        return;
    }

    ctx = stream->ctx;

    if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan mux socks5 timed out");
        ngx_stream_trojan_mux_close_stream(stream, 1);
        (void) ngx_stream_trojan_mux_flush_client(ctx);
        return;
    }

    if (!stream->socks5_connected) {
        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            ngx_stream_trojan_mux_close_stream(stream, 1);
            (void) ngx_stream_trojan_mux_flush_client(ctx);
            return;
        }

        stream->socks5_connected = 1;
    }

    ngx_stream_trojan_mux_process_socks5(stream);

    if (ngx_stream_trojan_mux_flush_client(ctx) == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
    }
}


static ngx_int_t
ngx_stream_trojan_mux_socks5_flush(ngx_stream_trojan_mux_stream_t *stream)
{
    ssize_t           n;
    ngx_connection_t *pc;
    ngx_buf_t        *b;

    pc = stream->upstream;
    b = stream->socks5_buffer;

    while (b->pos < b->last) {
        n = pc->send(pc, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN || n == 0) {
            if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_socks5_read(ngx_stream_trojan_mux_stream_t *stream,
    size_t needed)
{
    size_t            available;
    ssize_t           n;
    ngx_connection_t *pc;
    ngx_buf_t        *b;

    pc = stream->upstream;
    b = stream->socks5_buffer;

    if (needed > (size_t) (b->end - b->start)) {
        return NGX_ERROR;
    }

    while ((size_t) (b->last - b->pos) < needed) {
        available = needed - (size_t) (b->last - b->pos);
        n = pc->recv(pc, b->last, available);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->last += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_socks5_prepare_greeting(
    ngx_stream_trojan_mux_stream_t *stream)
{
    size_t      written;
    ngx_buf_t  *b;

    b = stream->socks5_buffer;
    ngx_stream_trojan_mux_reset_buf(b);

    if (ngx_stream_trojan_socks5_build_greeting(
            b->last, b->end - b->last,
            stream->outbound->socks5_username.len != 0, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_socks5_prepare_auth(
    ngx_stream_trojan_mux_stream_t *stream)
{
    size_t      written;
    ngx_buf_t  *b;

    b = stream->socks5_buffer;
    ngx_stream_trojan_mux_reset_buf(b);

    if (ngx_stream_trojan_socks5_build_auth(
            stream->outbound->socks5_username.data,
            stream->outbound->socks5_username.len,
            stream->outbound->socks5_password.data,
            stream->outbound->socks5_password.len,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_mux_socks5_prepare_request(
    ngx_stream_trojan_mux_stream_t *stream)
{
    size_t      written;
    ngx_buf_t  *b;

    b = stream->socks5_buffer;
    ngx_stream_trojan_mux_reset_buf(b);

    if (ngx_stream_trojan_socks5_build_request(
            NGX_STREAM_TROJAN_SOCKS5_CMD_CONNECT, &stream->target,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static void
ngx_stream_trojan_mux_process_socks5(
    ngx_stream_trojan_mux_stream_t *stream)
{
    int                         rc;
    ngx_uint_t                  resume;
    size_t                      needed, len;
    ngx_connection_t           *pc;
    ngx_stream_trojan_ctx_t    *ctx;
    ngx_stream_trojan_addr_t    bind_addr;

    ctx = stream->ctx;
    pc = stream->upstream;

    if (pc == NULL) {
        ngx_stream_trojan_mux_close_stream(stream, 1);
        return;
    }

    for ( ;; ) {
        switch (stream->socks5_step) {

        case ngx_stream_trojan_socks5_step_greeting_write:
            rc = ngx_stream_trojan_mux_socks5_flush(stream);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            stream->socks5_step = ngx_stream_trojan_socks5_step_method_read;
            ngx_stream_trojan_mux_reset_buf(stream->socks5_buffer);
            continue;

        case ngx_stream_trojan_socks5_step_method_read:
            rc = ngx_stream_trojan_mux_socks5_read(stream, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            rc = ngx_stream_trojan_socks5_parse_method_response(
                stream->socks5_buffer->pos, 2,
                stream->outbound->socks5_username.len != 0);

            if (rc == 1) {
                if (ngx_stream_trojan_mux_socks5_prepare_auth(stream)
                    != NGX_OK)
                {
                    ngx_stream_trojan_mux_close_stream(stream, 1);
                    return;
                }

                stream->socks5_step = ngx_stream_trojan_socks5_step_auth_write;
                continue;
            }

            if (rc != 0) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            if (ngx_stream_trojan_mux_socks5_prepare_request(stream) != NGX_OK)
            {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            stream->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_auth_write:
            rc = ngx_stream_trojan_mux_socks5_flush(stream);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            stream->socks5_step = ngx_stream_trojan_socks5_step_auth_read;
            ngx_stream_trojan_mux_reset_buf(stream->socks5_buffer);
            continue;

        case ngx_stream_trojan_socks5_step_auth_read:
            rc = ngx_stream_trojan_mux_socks5_read(stream, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK
                || ngx_stream_trojan_socks5_parse_auth_response(
                       stream->socks5_buffer->pos, 2)
                   != 0)
            {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            if (ngx_stream_trojan_mux_socks5_prepare_request(stream) != NGX_OK)
            {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            stream->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_request_write:
            rc = ngx_stream_trojan_mux_socks5_flush(stream);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            stream->socks5_step = ngx_stream_trojan_socks5_step_response_read;
            ngx_stream_trojan_mux_reset_buf(stream->socks5_buffer);
            continue;

        case ngx_stream_trojan_socks5_step_response_read:
            len = stream->socks5_buffer->last - stream->socks5_buffer->pos;
            rc = ngx_stream_trojan_socks5_response_len(
                stream->socks5_buffer->pos, len, &needed);

            if (rc == 1) {
                rc = ngx_stream_trojan_mux_socks5_read(stream, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_mux_close_stream(stream, 1);
                    return;
                }

                continue;
            }

            if (rc != 0
                || ngx_stream_trojan_socks5_parse_response(
                       stream->socks5_buffer->pos, len, &bind_addr)
                   != 0)
            {
                ngx_stream_trojan_mux_close_stream(stream, 1);
                return;
            }

            if (pc->write->timer_set) {
                ngx_del_timer(pc->write);
            }

            resume = ngx_stream_trojan_mux_client_blocked_on(ctx, stream);
            ngx_stream_trojan_mux_init_proxy(stream);
            if (resume) {
                ngx_stream_trojan_mux_post_client_read(ctx);
            }
            return;
        }
    }
}

static ngx_int_t
ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    u_char               *p;

    ngx_memzero(out, sizeof(ngx_addr_t));

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        ngx_memcpy(&sin->sin_addr, addr->host, 4);

        out->sockaddr = (struct sockaddr *) sin;
        out->socklen = sizeof(struct sockaddr_in);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        sin6 = ngx_pcalloc(pool, sizeof(struct sockaddr_in6));
        if (sin6 == NULL) {
            return NGX_ERROR;
        }

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        ngx_memcpy(&sin6->sin6_addr, addr->host, 16);

        out->sockaddr = (struct sockaddr *) sin6;
        out->socklen = sizeof(struct sockaddr_in6);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        p = ngx_pnalloc(pool, addr->host_len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(p, addr->host, addr->host_len);
        p[addr->host_len] = '\0';
        (void) p;
        return NGX_DECLINED;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_stream_trojan_resolve_addr(ngx_pool_t *pool, ngx_log_t *log,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    return ngx_stream_trojan_resolve_addr_prefer(
        pool, log, addr, NGX_STREAM_TROJAN_IP_PREFER_AUTO, out);
}


static ngx_int_t
ngx_stream_trojan_resolve_addr_prefer(ngx_pool_t *pool, ngx_log_t *log,
    ngx_stream_trojan_addr_t *addr, ngx_uint_t ip_prefer, ngx_addr_t *out)
{
    (void) log;
    (void) ip_prefer;

    if (addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        return ngx_stream_trojan_addr_to_ngx_addr(pool, addr, out);
    }

    return NGX_DECLINED;
}


static ngx_uint_t
ngx_stream_trojan_resolver_configured(ngx_stream_session_t *s)
{
    ngx_stream_core_srv_conf_t *cscf;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    return cscf->resolver != NULL && cscf->resolver->connections.nelts != 0;
}


static ngx_resolver_addr_t *
ngx_stream_trojan_resolver_pick_addr(ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs, ngx_uint_t ip_prefer)
{
    ngx_uint_t i;

    if (addrs == NULL || naddrs == 0) {
        return NULL;
    }

    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV4) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET) {
                return &addrs[i];
            }
        }
    }

#if (NGX_HAVE_INET6)
    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET6) {
                return &addrs[i];
            }
        }
    }
#endif

    return &addrs[0];
}

static ngx_int_t
ngx_stream_trojan_resolver_addrs_to_ngx_addrs(ngx_pool_t *pool,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, uint16_t port,
    ngx_uint_t ip_prefer, ngx_addr_t **out, ngx_uint_t *nout)
{
    ngx_uint_t   i, n;
    ngx_addr_t  *dst;

    if (addrs == NULL || naddrs == 0 || out == NULL || nout == NULL) {
        return NGX_ERROR;
    }

    dst = ngx_pcalloc(pool, naddrs * sizeof(ngx_addr_t));
    if (dst == NULL) {
        return NGX_ERROR;
    }

    n = 0;

    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV4) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET
                && ngx_stream_trojan_resolver_addr_to_ngx_addr(
                       pool, &addrs[i], port, &dst[n])
                   == NGX_OK)
            {
                n++;
            }
        }
    }

#if (NGX_HAVE_INET6)
    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET6
                && ngx_stream_trojan_resolver_addr_to_ngx_addr(
                       pool, &addrs[i], port, &dst[n])
                   == NGX_OK)
            {
                n++;
            }
        }
    }
#endif

    for (i = 0; i < naddrs; i++) {
        if ((ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV4
             && addrs[i].sockaddr->sa_family == AF_INET)
#if (NGX_HAVE_INET6)
            || (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6
                && addrs[i].sockaddr->sa_family == AF_INET6)
#endif
           )
        {
            continue;
        }

        if (ngx_stream_trojan_resolver_addr_to_ngx_addr(pool, &addrs[i],
                                                        port, &dst[n])
            == NGX_OK)
        {
            n++;
        }
    }

    if (n == 0) {
        return NGX_ERROR;
    }

    *out = dst;
    *nout = n;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_resolver_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_resolver_addr_t *resolved, uint16_t port, ngx_addr_t *out)
{
    struct sockaddr  *sa;

    if (resolved == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_addr_t));

    sa = ngx_pnalloc(pool, resolved->socklen);
    if (sa == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sa, resolved->sockaddr, resolved->socklen);
    ngx_inet_set_port(sa, port);

    out->sockaddr = sa;
    out->socklen = resolved->socklen;
    out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
    if (out->name.data == NULL) {
        return NGX_ERROR;
    }
    out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                  out->name.data, NGX_SOCKADDR_STRLEN, 1);

    return NGX_OK;
}


static ngx_connection_t *
ngx_stream_trojan_create_udp_connection(ngx_stream_trojan_ctx_t *ctx,
    int family, ngx_event_handler_pt handler)
{
    ngx_socket_t       fd;
    ngx_connection_t  *uc;

    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_socket_n " failed");
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_nonblocking_n " failed");
        ngx_close_socket(fd);
        return NULL;
    }

    uc = ngx_get_connection(fd, ctx->session->connection->log);
    if (uc == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uc->data = ctx;
    uc->log = ctx->session->connection->log;
    uc->read->handler = handler;
    uc->write->handler = handler;

    if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(uc);
        return NULL;
    }

    return uc;
}


static ngx_connection_t *
ngx_stream_trojan_create_bound_udp_connection(ngx_stream_trojan_ctx_t *ctx,
    int family, ngx_event_handler_pt handler)
{
    ngx_socket_t          fd;
    ngx_connection_t     *uc;
    struct sockaddr_in    sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   sin6;
#endif
    struct sockaddr      *sa;
    socklen_t             socklen;

    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_socket_n " failed");
        return NULL;
    }

    if (family == AF_INET) {
        ngx_memzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        sa = (struct sockaddr *) &sin;
        socklen = sizeof(sin);

#if (NGX_HAVE_INET6)
    } else if (family == AF_INET6) {
        ngx_memzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_loopback;
        sin6.sin6_port = 0;
        sa = (struct sockaddr *) &sin6;
        socklen = sizeof(sin6);
#endif

    } else {
        ngx_close_socket(fd);
        return NULL;
    }

    if (bind(fd, sa, socklen) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, "bind() socks5 udp relay failed");
        ngx_close_socket(fd);
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_nonblocking_n " failed");
        ngx_close_socket(fd);
        return NULL;
    }

    uc = ngx_get_connection(fd, ctx->session->connection->log);
    if (uc == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uc->data = ctx;
    uc->log = ctx->session->connection->log;
    uc->read->handler = handler;
    uc->write->handler = handler;

    if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(uc);
        return NULL;
    }

    return uc;
}


static ngx_int_t
ngx_stream_trojan_socks5_udp_bind_addr(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr)
{
    ngx_connection_t      *c, *relay;
    struct sockaddr_in    *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif
    struct sockaddr_storage ss;
    socklen_t             socklen;

    c = ctx->session->connection;

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (c->local_sockaddr->sa_family == AF_INET) {
        if (ctx->socks5_in_udp == NULL) {
            ctx->socks5_in_udp = ngx_stream_trojan_create_bound_udp_connection(
                ctx, AF_INET, ngx_stream_trojan_socks5_in_udp_read_handler);
        }
        relay = ctx->socks5_in_udp;
        if (relay == NULL) {
            return NGX_ERROR;
        }

        socklen = sizeof(ss);
        if (getsockname(relay->fd, (struct sockaddr *) &ss, &socklen) == -1) {
            return NGX_ERROR;
        }

        sin = (struct sockaddr_in *) &ss;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        addr->port = ntohs(sin->sin_port);
        ngx_memcpy(addr->host, &sin->sin_addr, 4);
        addr->wire_len = 1 + 4 + 2;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (c->local_sockaddr->sa_family == AF_INET6) {
        if (ctx->socks5_in_udp == NULL) {
            ctx->socks5_in_udp = ngx_stream_trojan_create_bound_udp_connection(
                ctx, AF_INET6, ngx_stream_trojan_socks5_in_udp_read_handler);
        }
        relay = ctx->socks5_in_udp;
        if (relay == NULL) {
            return NGX_ERROR;
        }

        socklen = sizeof(ss);
        if (getsockname(relay->fd, (struct sockaddr *) &ss, &socklen) == -1) {
            return NGX_ERROR;
        }

        sin6 = (struct sockaddr_in6 *) &ss;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        addr->port = ntohs(sin6->sin6_port);
        ngx_memcpy(addr->host, &sin6->sin6_addr, 16);
        addr->wire_len = 1 + 16 + 2;
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static void
ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t                         n;
    ngx_int_t                       rc;
    size_t                          packets, bytes;
    ngx_connection_t               *c;
    ngx_stream_trojan_udp_frame_t   frame;

    c = ctx->session->connection;
    packets = 0;
    bytes = 0;

    rc = ngx_stream_trojan_flush_udp_client(ctx);
    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    for ( ;; ) {
        if (packets >= NGX_STREAM_TROJAN_UDP_MAX_PACKETS_PER_EVENT
            || bytes >= NGX_STREAM_TROJAN_UDP_MAX_BYTES_PER_EVENT)
        {
            if (ctx->udp_in_len != 0
                || ngx_stream_trojan_client_read_ready(ctx, c))
            {
                ngx_post_event(c->read, &ngx_posted_next_events);
            }
            return;
        }

        rc = ngx_stream_trojan_parse_udp_frame(
            ctx->udp_in + ctx->udp_in_pos, ctx->udp_in_len, &frame);

        if (rc == NGX_STREAM_TROJAN_PARSE_OK) {
            rc = ngx_stream_trojan_prepare_udp_outbound(ctx, &frame.addr);
            if (rc == NGX_DECLINED) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            rc = ngx_stream_trojan_send_udp_frame(ctx, &frame);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            packets++;
            bytes += frame.wire_len;
            ngx_stream_trojan_consume_udp_input(ctx, frame.wire_len);
            continue;
        }

        if (rc == NGX_STREAM_TROJAN_PARSE_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        if (ctx->udp_in_pos + ctx->udp_in_len
            == NGX_STREAM_TROJAN_UDP_BUFFER_SIZE)
        {
            if (ctx->udp_in_pos == 0) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                return;
            }

            ngx_stream_trojan_compact_udp_input(ctx);
        }

        n = ngx_stream_trojan_client_recv(
            ctx, ctx->udp_in + ctx->udp_in_pos + ctx->udp_in_len,
            NGX_STREAM_TROJAN_UDP_BUFFER_SIZE - ctx->udp_in_pos
            - ctx->udp_in_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->udp_in_len += (size_t) n;
        ngx_stream_trojan_refresh_udp_timeout(ctx);
    }
}


static ngx_int_t
ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    struct sockaddr_in   sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  sin6;
#endif
    struct sockaddr     *sa;
    socklen_t            socklen;
    ngx_int_t           rc;
    ngx_stream_trojan_dns_rule_group_t *dns_rule;

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        if (ctx->socks5_udp == NULL
            || ctx->socks5_udp_relay.sockaddr == NULL)
        {
            ngx_stream_trojan_start_socks5_udp(ctx);
            return NGX_AGAIN;
        }

        return ngx_stream_trojan_send_socks5_udp_frame(ctx, frame);
    }


    switch (frame->addr.type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        ngx_memzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(frame->addr.port);
        ngx_memcpy(&sin.sin_addr, frame->addr.host, 4);
        sa = (struct sockaddr *) &sin;
        socklen = sizeof(sin);
        break;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        ngx_memzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(frame->addr.port);
        ngx_memcpy(&sin6.sin6_addr, frame->addr.host, 16);
        sa = (struct sockaddr *) &sin6;
        socklen = sizeof(sin6);
        break;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        dns_rule = ngx_stream_trojan_match_dns_rule(ctx->conf, &frame->addr);
        if (dns_rule != NULL) {
            if (dns_rule->doh_conf != NULL) {
                ngx_stream_trojan_resolve_data_t  *udata;

                udata = ngx_stream_trojan_create_doh_resolve_data(ctx,
                            &frame->addr, ngx_stream_trojan_resolve_udp,
                            frame->payload, frame->payload_len,
                            frame->wire_len, dns_rule->ip_prefer,
                            dns_rule->doh_conf);
                if (udata == NULL) {
                    return NGX_ERROR;
                }

                rc = ngx_stream_trojan_start_doh_resolver(ctx, udata);
                if (rc == NGX_BUSY || rc == NGX_AGAIN) {
                    return NGX_AGAIN;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                return NGX_AGAIN;
            }

            if (ngx_stream_trojan_start_resolver(ctx, &frame->addr,
                                                 ngx_stream_trojan_resolve_udp,
                                                 frame->payload,
                                                 frame->payload_len,
                                                 frame->wire_len,
                                                 dns_rule->resolver, 0,
                                                 dns_rule->ip_prefer)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        /* try DoH first */
        if (ctx->conf->doh_conf != NULL
            && frame->addr.host_len > 0 && frame->addr.host_len <= 255)
        {
            ngx_stream_trojan_resolve_data_t  *udata;

            udata = ngx_stream_trojan_create_doh_resolve_data(ctx,
                        &frame->addr, ngx_stream_trojan_resolve_udp,
                        frame->payload, frame->payload_len, frame->wire_len,
                        ngx_stream_trojan_current_ip_prefer(ctx),
                        ctx->conf->doh_conf);
            if (udata == NULL) {
                return NGX_ERROR;
            }

            rc = ngx_stream_trojan_start_doh_resolver(ctx, udata);
            if (rc == NGX_BUSY || rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        if (ngx_stream_trojan_use_nginx_resolver(
                frame->addr.type,
                ngx_stream_trojan_resolver_configured(ctx->session)))
        {
            if (ngx_stream_trojan_start_resolver(ctx, &frame->addr,
                                                 ngx_stream_trojan_resolve_udp,
                                                 frame->payload,
                                                 frame->payload_len,
                                                 frame->wire_len, NULL, 0,
                                                 ngx_stream_trojan_current_ip_prefer(ctx))
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        return NGX_ERROR;

    default:
        return NGX_ERROR;
    }

    return ngx_stream_trojan_send_udp_sockaddr(ctx, sa, socklen,
                                               frame->payload,
                                               frame->payload_len);
}


static ngx_int_t
ngx_stream_trojan_send_udp_iov(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *uc, u_char *header, size_t header_len,
    const u_char *payload, size_t payload_len, struct sockaddr *sockaddr,
    socklen_t socklen, const char *message)
{
    ssize_t        n;
    struct iovec   iov[2];
    struct msghdr  msg;

    iov[0].iov_base = header;
    iov[0].iov_len = header_len;
    iov[1].iov_base = (void *) payload;
    iov[1].iov_len = payload_len;

    ngx_memzero(&msg, sizeof(struct msghdr));
    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;
    msg.msg_iov = iov;
    msg.msg_iovlen = payload_len == 0 ? 1 : 2;

    n = sendmsg(uc->fd, &msg, 0);

    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log,
                      err, "%s", message);
        return NGX_ERROR;
    }

    if ((size_t) n != header_len + payload_len) {
        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log, 0,
                      "short UDP sendmsg() while sending %s", message);
        return NGX_ERROR;
    }

    ngx_stream_trojan_refresh_udp_timeout(ctx);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_send_socks5_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    size_t            header_len;

    if (ngx_stream_trojan_socks5_build_udp_header(
            &frame->addr, ctx->udp_out,
            NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE, &header_len)
        != 0)
    {
        return NGX_ERROR;
    }

    return ngx_stream_trojan_send_udp_iov(
        ctx, ctx->socks5_udp, ctx->udp_out, header_len, frame->payload,
        frame->payload_len, ctx->socks5_udp_relay.sockaddr,
        ctx->socks5_udp_relay.socklen, "sendmsg() to socks5 udp relay failed");
}


static ngx_int_t
ngx_stream_trojan_forward_socks5_udp_packet(ngx_stream_trojan_ctx_t *ctx,
    u_char *packet, size_t packet_len)
{
    ssize_t           n;
    ngx_connection_t *uc;

    uc = ctx->socks5_udp;
    if (uc == NULL || ctx->socks5_udp_relay.sockaddr == NULL) {
        return NGX_ERROR;
    }

    n = sendto(uc->fd, packet, packet_len, 0,
               ctx->socks5_udp_relay.sockaddr,
               ctx->socks5_udp_relay.socklen);

    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log,
                      err, "sendto() to socks5 udp relay failed");
        return NGX_ERROR;
    }
    ngx_stream_trojan_refresh_udp_timeout(ctx);

    return NGX_OK;
}


static ngx_uint_t
ngx_stream_trojan_socks5_in_udp_pending_blocked(
    ngx_stream_trojan_ctx_t *ctx)
{
    return (ctx->socks5_udp == NULL
            || ctx->socks5_udp_relay.sockaddr == NULL)
           && ctx->udp_pending_to_upstream != NULL
           && ctx->udp_pending_to_upstream->pos
              < ctx->udp_pending_to_upstream->last;
}


static void
ngx_stream_trojan_post_socks5_in_udp_read(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->socks5_in_udp == NULL || ctx->socks5_in_udp->read == NULL) {
        return;
    }

    ngx_post_event(ctx->socks5_in_udp->read, &ngx_posted_events);
}

static ngx_int_t
ngx_stream_trojan_queue_socks5_udp_packet(ngx_stream_trojan_ctx_t *ctx,
    u_char *packet, size_t packet_len)
{
    ngx_buf_t  *b;

    if (packet_len > NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE) {
        return NGX_ERROR;
    }

    if (ctx->udp_pending_to_upstream == NULL) {
        ctx->udp_pending_to_upstream = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool,
            NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE);
        if (ctx->udp_pending_to_upstream == NULL) {
            return NGX_ERROR;
        }
    }

    b = ctx->udp_pending_to_upstream;
    if (b->pos < b->last) {
        return NGX_BUSY;
    }

    b->pos = b->start;
    b->last = b->start;
    ngx_memcpy(b->last, packet, packet_len);
    b->last += packet_len;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_flush_socks5_udp_packet(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_int_t  rc;
    ngx_buf_t *b;

    b = ctx->udp_pending_to_upstream;
    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    rc = ngx_stream_trojan_forward_socks5_udp_packet(ctx, b->pos,
                                                     b->last - b->pos);
    if (rc != NGX_OK) {
        return rc;
    }

    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_send_udp_resolved(ngx_stream_trojan_ctx_t *ctx,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, uint16_t port,
    const u_char *payload, uint16_t payload_len, ngx_uint_t ip_prefer)
{
    ngx_resolver_addr_t     *resolved;
    struct sockaddr_storage  ss;

    resolved = ngx_stream_trojan_resolver_pick_addr(addrs, naddrs, ip_prefer);
    if (resolved == NULL || resolved->socklen > sizeof(ss)) {
        return NGX_ERROR;
    }

    ngx_memcpy(&ss, resolved->sockaddr, resolved->socklen);
    ngx_inet_set_port((struct sockaddr *) &ss, port);

    return ngx_stream_trojan_send_udp_sockaddr(ctx, (struct sockaddr *) &ss,
                                               resolved->socklen, payload,
                                               payload_len);
}


static ngx_int_t
ngx_stream_trojan_send_udp_sockaddr(ngx_stream_trojan_ctx_t *ctx,
    struct sockaddr *sa, socklen_t socklen, const u_char *payload,
    uint16_t payload_len)
{
    ssize_t            n;
    ngx_connection_t  *uc;

    if (sa->sa_family == AF_INET) {
        if (ctx->udp4 == NULL) {
            ctx->udp4 = ngx_stream_trojan_create_udp_connection(
                ctx, AF_INET, ngx_stream_trojan_udp_read_handler);
            if (ctx->udp4 == NULL) {
                return NGX_ERROR;
            }
        }
        uc = ctx->udp4;

#if (NGX_HAVE_INET6)
    } else if (sa->sa_family == AF_INET6) {
        if (ctx->udp6 == NULL) {
            ctx->udp6 = ngx_stream_trojan_create_udp_connection(
                ctx, AF_INET6, ngx_stream_trojan_udp_read_handler);
            if (ctx->udp6 == NULL) {
                return NGX_ERROR;
            }
        }
        uc = ctx->udp6;
#endif

    } else {
        return NGX_ERROR;
    }

    n = sendto(uc->fd, payload, payload_len, 0, sa, socklen);
    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->session->connection->log,
                      err, "sendto() failed");
        return NGX_ERROR;
    }

    ngx_stream_trojan_refresh_udp_timeout(ctx);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_queue_udp_client(ngx_stream_trojan_ctx_t *ctx, u_char *header,
    size_t header_len, const u_char *payload, size_t payload_len)
{
    ngx_buf_t  *b;

    if (header_len + payload_len > NGX_STREAM_TROJAN_UDP_BUFFER_SIZE
        || (payload_len != 0 && payload == NULL))
    {
        return NGX_ERROR;
    }

    if (ctx->udp_pending_to_client == NULL) {
        ctx->udp_pending_to_client = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE);
        if (ctx->udp_pending_to_client == NULL) {
            return NGX_ERROR;
        }
    }

    b = ctx->udp_pending_to_client;
    b->pos = b->start;
    b->last = b->start;
    ngx_memcpy(b->last, header, header_len);
    b->last += header_len;

    ctx->udp_pending_payload = payload;
    ctx->udp_pending_payload_len = payload_len;
    ctx->udp_pending_payload_sent = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_buf_t         *b;

    b = ctx->udp_pending_to_client;

    if (b == NULL) {
        return NGX_OK;
    }

    while (b->pos < b->last
           || ctx->udp_pending_payload_sent < ctx->udp_pending_payload_len)
    {
        size_t         header_sent, payload_sent, frame_size;
        const u_char  *payload;

        payload = ctx->udp_pending_payload_len == ctx->udp_pending_payload_sent
                  ? NULL
                  : ctx->udp_pending_payload + ctx->udp_pending_payload_sent;
        frame_size = (size_t) (b->last - b->start)
                     + ctx->udp_pending_payload_len;
        n = ngx_stream_trojan_client_send_parts(
            ctx, b->pos, b->last - b->pos, payload,
            ctx->udp_pending_payload_len - ctx->udp_pending_payload_sent,
            frame_size, &header_sent, &payload_sent);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += header_sent;
        ctx->udp_pending_payload_sent += payload_sent;
        ngx_stream_trojan_refresh_udp_timeout(ctx);
    }

    b->pos = b->start;
    b->last = b->start;
    ctx->udp_pending_payload = NULL;
    ctx->udp_pending_payload_len = 0;
    ctx->udp_pending_payload_sent = 0;

    return NGX_OK;
}


static void
ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ctx->websocket) {
        switch (ngx_stream_trojan_websocket_flush_out(ctx)) {
        case NGX_OK:
            break;
        case NGX_AGAIN:
            return;
        default:
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }
    }

    if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
    }
}


static ngx_int_t
ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa, socklen_t socklen,
    ngx_stream_trojan_addr_t *addr)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_memzero(addr, sizeof(*addr));

    if (sa->sa_family == AF_INET && socklen >= (socklen_t) sizeof(struct sockaddr_in)) {
        sin = (struct sockaddr_in *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        ngx_memcpy(addr->host, &sin->sin_addr, 4);
        addr->port = ntohs(sin->sin_port);
        addr->wire_len = 1 + 4 + 2;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6 && socklen >= (socklen_t) sizeof(struct sockaddr_in6)) {
        sin6 = (struct sockaddr_in6 *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        ngx_memcpy(addr->host, &sin6->sin6_addr, 16);
        addr->port = ntohs(sin6->sin6_port);
        addr->wire_len = 1 + 16 + 2;
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_loopback_sockaddr(struct sockaddr *sa)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        return sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }
#endif

    return 0;
}


static const char *
ngx_stream_trojan_local_proxy_name(ngx_stream_trojan_srv_conf_t *tscf)
{
    switch (tscf->local_proxy_type) {
    case ngx_stream_trojan_local_proxy_socks5:
        return "socks5";
    case ngx_stream_trojan_local_proxy_http_proxy:
        return "http_proxy";
    default:
        return tscf->socks5_enable ? "socks5" : "http_proxy";
    }
}


static ngx_stream_trojan_srv_conf_t *
ngx_stream_trojan_local_proxy_conflict(ngx_stream_conf_addr_t *addr,
    ngx_stream_core_srv_conf_t *current)
{
    ngx_uint_t                    s;
    ngx_stream_core_srv_conf_t  **servers;
    ngx_stream_trojan_srv_conf_t *tscf;

    servers = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {
        if (servers[s] == current) {
            continue;
        }

        tscf = servers[s]->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
        if (tscf != NULL
            && (tscf->socks5_enable || tscf->http_proxy_enable))
        {
            return tscf;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_local_proxy_check_listens(ngx_conf_t *cf,
    ngx_stream_core_srv_conf_t *cscf, ngx_stream_trojan_srv_conf_t *tscf)
{
    const char                   *name;
    ngx_uint_t                    p, a, s, found;
    ngx_stream_conf_port_t       *port;
    ngx_stream_conf_addr_t       *addr;
    ngx_stream_core_srv_conf_t  **servers;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_trojan_srv_conf_t *conflict;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf->ports == NULL) {
        return NGX_ERROR;
    }

    found = 0;
    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {
            servers = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                if (servers[s] != cscf) {
                    continue;
                }

                found = 1;
                name = ngx_stream_trojan_local_proxy_name(tscf);

                if (addr[a].servers.nelts != 1) {
                    conflict = ngx_stream_trojan_local_proxy_conflict(&addr[a],
                                                                      cscf);
                    name = ngx_stream_trojan_local_proxy_name(
                        conflict != NULL ? conflict : tscf);
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound listen %V conflicts "
                                       "with another stream server",
                                       name,
                                       &addr[a].opt.addr_text);
                    return NGX_ERROR;
                }

                if (port[p].type != SOCK_STREAM) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound requires TCP listen", name);
                    return NGX_ERROR;
                }

#if (NGX_STREAM_SSL)
                if (addr[a].opt.ssl) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound does not allow listen ssl",
                                       name);
                    return NGX_ERROR;
                }
#endif

                if (!ngx_stream_trojan_loopback_sockaddr(
                        addr[a].opt.sockaddr))
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound only allows listen "
                                       "127.0.0.1 or [::1]", name);
                    return NGX_ERROR;
                }
            }
        }
    }

    return found ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_default_server_name(ngx_stream_core_srv_conf_t *cscf)
{
    ngx_stream_server_name_t  *name;

    if (cscf->server_names.nelts == 0) {
        return 1;
    }

    if (cscf->server_names.nelts != 1) {
        return 0;
    }

    name = cscf->server_names.elts;
    return name[0].name.len == 0;
}


static ngx_stream_trojan_srv_conf_t *
ngx_stream_trojan_find_trojan_server(ngx_conf_t *cf,
    ngx_stream_trojan_server_ref_t *ref, ngx_uint_t log_level)
{
    ngx_uint_t                    p, a, s, n, matches;
    ngx_stream_conf_port_t       *port;
    ngx_stream_conf_addr_t       *addr;
    ngx_stream_core_srv_conf_t  **servers, *cscf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_server_name_t     *name;
    ngx_stream_trojan_srv_conf_t *tscf, *matched;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf->ports == NULL) {
        return NULL;
    }

    matches = 0;
    matched = NULL;
    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        if (port[p].port != ref->port || port[p].type != SOCK_STREAM) {
            continue;
        }

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {
            servers = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                cscf = servers[s];
                tscf = cscf->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
                if (tscf == NULL || !tscf->enable) {
                    continue;
                }

                if (ref->localhost) {
                    if (ngx_stream_trojan_default_server_name(cscf)) {
                        matches++;
                        matched = tscf;
                    }

                    continue;
                }

                name = cscf->server_names.elts;
                for (n = 0; n < cscf->server_names.nelts; n++) {
                    if (name[n].name.len == ref->host.len
                        && ngx_strncmp(name[n].name.data, ref->host.data,
                                       ref->host.len)
                           == 0)
                    {
                        matches++;
                        matched = tscf;
                        break;
                    }
                }
            }
        }
    }

    if (matches == 1) {
        return matched;
    }

    if (matches > 1) {
        if (ref->localhost) {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server localhost:%ui matches multiple "
                               "trojan servers without server_name",
                               (ngx_uint_t) ref->port);
        } else {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server \"%V:%ui\" matches multiple "
                               "trojan servers", &ref->host,
                               (ngx_uint_t) ref->port);
        }
    } else {
        if (ref->localhost) {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server localhost:%ui not found",
                               (ngx_uint_t) ref->port);
        } else {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server \"%V:%ui\" not found",
                               &ref->host, (ngx_uint_t) ref->port);
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_postconfiguration(ngx_conf_t *cf)
{
    ngx_uint_t                    s, trojan_count;
    ngx_stream_core_srv_conf_t  **servers, *cscf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_trojan_srv_conf_t *tscf, *default_trojan, *target;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL || cmcf->servers.nelts == 0) {
        return NGX_OK;
    }

    trojan_count = 0;
    default_trojan = NULL;
    servers = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        tscf = servers[s]->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
        if (tscf != NULL && tscf->enable) {
            trojan_count++;
            default_trojan = tscf;
        }
    }

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = servers[s];
        tscf = cscf->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];

        if (tscf == NULL
            || (!tscf->socks5_enable && !tscf->http_proxy_enable))
        {
            continue;
        }

        if (ngx_stream_trojan_local_proxy_check_listens(cf, cscf, tscf)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (tscf->enable) {
            tscf->effective = tscf;
            continue;
        }

        if (tscf->socks5_ref_set) {
            target = ngx_stream_trojan_find_trojan_server(cf,
                                                          &tscf->socks5_ref,
                                                          NGX_LOG_EMERG);
            if (target == NULL) {
                return NGX_ERROR;
            }

            tscf->effective = target;
            continue;
        }

        if (trojan_count == 1) {
            tscf->effective = default_trojan;
            continue;
        }

        if (trojan_count == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "local proxy inbound requires a trojan server");
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "local proxy inbound requires trojan_server when multiple "
                               "trojan servers are configured");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                    n;
    size_t                     written, packets, bytes;
    ngx_connection_t          *uc, *c;
    ngx_stream_trojan_ctx_t   *ctx;
    ngx_stream_trojan_addr_t   addr;
    struct sockaddr_storage    ss;
    socklen_t                  socklen;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    c = ctx->session->connection;

    packets = 0;
    bytes = 0;

    for ( ;; ) {
        if (ngx_stream_trojan_flush_udp_client(ctx) != NGX_OK) {
            return;
        }
        if (packets >= NGX_STREAM_TROJAN_UDP_MAX_PACKETS_PER_EVENT
            || bytes >= NGX_STREAM_TROJAN_UDP_MAX_BYTES_PER_EVENT)
        {
            ngx_stream_trojan_post_udp_read_if_ready(uc);
            return;
        }


        socklen = sizeof(ss);
        n = recvfrom(uc->fd,
                     ctx->udp_payload,
                     NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE, 0,
                     (struct sockaddr *) &ss, &socklen);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_INFO, c->log, err, "recvfrom() failed");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
        packets++;
        bytes += (size_t) n;
        ngx_stream_trojan_refresh_udp_timeout(ctx);

        if (ngx_stream_trojan_sockaddr_to_addr((struct sockaddr *) &ss,
                                               socklen, &addr)
            != NGX_OK)
        {
            continue;
        }

        if (ngx_stream_trojan_build_udp_header(&addr, (uint16_t) n,
                                               ctx->udp_out,
                                               NGX_STREAM_TROJAN_UDP_BUFFER_SIZE,
                                               &written)
            != 0)
        {
            continue;
        }

        if (ctx->inbound_socks5) {
            if (!ctx->socks5_udp_client_set) {
                continue;
            }

            if (ctx->socks5_in_udp == NULL) {
                continue;
            }

            if (ngx_stream_trojan_socks5_build_udp_header(
                    &addr, ctx->udp_out,
                    NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE, &written)
                != 0)
            {
                continue;
            }

            if (ngx_stream_trojan_send_udp_iov(
                    ctx, ctx->socks5_in_udp, ctx->udp_out, written,
                    ctx->udp_payload, (size_t) n,
                    (struct sockaddr *) &ctx->socks5_udp_client,
                    ctx->socks5_udp_client_socklen,
                    "sendmsg() socks5 udp client failed")
                != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            continue;
        }

        if (ngx_stream_trojan_queue_udp_client(ctx, ctx->udp_out, written,
                                               ctx->udp_payload, (size_t) n)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }


    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_socks5_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                         n;
    size_t                          written, packets, bytes;
    ngx_connection_t               *uc, *c;
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_udp_frame_t   frame;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    c = ctx->session->connection;

    packets = 0;
    bytes = 0;

    for ( ;; ) {
        if (ngx_stream_trojan_flush_udp_client(ctx) != NGX_OK) {
            return;
        }
        if (packets >= NGX_STREAM_TROJAN_UDP_MAX_PACKETS_PER_EVENT
            || bytes >= NGX_STREAM_TROJAN_UDP_MAX_BYTES_PER_EVENT)
        {
            ngx_stream_trojan_post_udp_read_if_ready(uc);
            return;
        }


        n = recvfrom(uc->fd, ctx->udp_out,
                     NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE, 0, NULL, NULL);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_INFO, c->log, err,
                          "recvfrom() from socks5 udp relay failed");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
        packets++;
        bytes += (size_t) n;
        ngx_stream_trojan_refresh_udp_timeout(ctx);

        if (ngx_stream_trojan_socks5_parse_udp_packet(ctx->udp_out,
                                                      (size_t) n, &frame)
            != 0)
        {
            continue;
        }

        if (ctx->inbound_socks5) {
            if (!ctx->socks5_udp_client_set || ctx->socks5_in_udp == NULL) {
                continue;
            }

            n = sendto(ctx->socks5_in_udp->fd, ctx->udp_out, (size_t) n, 0,
                       (struct sockaddr *) &ctx->socks5_udp_client,
                       ctx->socks5_udp_client_socklen);
            if (n == -1 && ngx_socket_errno != NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                              "sendto() socks5 udp client failed");
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            continue;
        }

        if (ngx_stream_trojan_build_udp_header(
                &frame.addr, frame.payload_len, ctx->udp_payload,
                NGX_STREAM_TROJAN_DEFAULT_UDP_PAYLOAD_SIZE, &written)
            != 0)
        {
            continue;
        }

        if (ngx_stream_trojan_queue_udp_client(ctx, ctx->udp_payload, written,
                                               frame.payload,
                                               frame.payload_len)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }


    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_socks5_in_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                         n;
    size_t                          packets, bytes;
    ngx_int_t                       rc;
    ngx_connection_t               *uc;
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_udp_frame_t   frame;
    ngx_stream_trojan_addr_t        original;
    struct sockaddr_storage         ss;
    socklen_t                       socklen;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }


    packets = 0;
    bytes = 0;

    for ( ;; ) {
        if (ctx->resolver_ctx != NULL || ctx->doh_ctx != NULL
            || ngx_stream_trojan_socks5_in_udp_pending_blocked(ctx))
        {
            break;
        }
        if (packets >= NGX_STREAM_TROJAN_UDP_MAX_PACKETS_PER_EVENT
            || bytes >= NGX_STREAM_TROJAN_UDP_MAX_BYTES_PER_EVENT)
        {
            ngx_stream_trojan_post_udp_read_if_ready(uc);
            return;
        }


        socklen = sizeof(ss);
        n = recvfrom(uc->fd, ctx->udp_out,
                     NGX_STREAM_TROJAN_SOCKS5_UDP_BUFFER_SIZE, 0,
                     (struct sockaddr *) &ss, &socklen);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_INFO, uc->log, err,
                          "recvfrom() socks5 udp relay failed");
            break;
        }
        packets++;
        bytes += (size_t) n;
        ngx_stream_trojan_refresh_udp_timeout(ctx);

        if (ngx_stream_trojan_socks5_parse_udp_packet(ctx->udp_out,
                                                      (size_t) n, &frame)
            != 0)
        {
            continue;
        }

        if (ctx->resolver_ctx != NULL || ctx->doh_ctx != NULL) {
            continue;
        }

        if (!ctx->socks5_udp_client_set) {
            ngx_memcpy(&ctx->socks5_udp_client, &ss, socklen);
            ctx->socks5_udp_client_socklen = socklen;
            ctx->socks5_udp_client_set = 1;
        } else if (ctx->socks5_udp_client_socklen != socklen
                   || ngx_memcmp(&ctx->socks5_udp_client, &ss, socklen) != 0)
        {
            continue;
        }

        original = ctx->target;
        ctx->target = frame.addr;

        if (ctx->conf->route_enable) {
            rc = ngx_stream_trojan_prepare_udp_outbound(ctx, &frame.addr);
            if (rc == NGX_DECLINED) {
                ctx->target = original;
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            if (rc != NGX_OK) {
                ctx->target = original;
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

        } else if (ngx_stream_trojan_request_blocked(ctx)) {
            ctx->target = original;
            continue;
        }

        ctx->target = original;

        if (ngx_stream_trojan_outbound_type(ctx)
            == ngx_stream_trojan_outbound_socks5)
        {
            if (ctx->socks5_udp == NULL
                || ctx->socks5_udp_relay.sockaddr == NULL)
            {
                rc = ngx_stream_trojan_queue_socks5_udp_packet(
                    ctx, ctx->udp_out, (size_t) n);
                if (rc == NGX_BUSY) {
                    break;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (ctx->upstream == NULL) {
                    ngx_stream_trojan_start_socks5_udp(ctx);
                }

                return;
            }

            (void) ngx_stream_trojan_forward_socks5_udp_packet(
                ctx, ctx->udp_out, (size_t) n);
            continue;
        }

        rc = ngx_stream_trojan_send_udp_frame(ctx, &frame);
        if (rc == NGX_AGAIN) {
            break;
        }

        if (rc != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }



    if (ngx_stream_trojan_socks5_in_udp_pending_blocked(ctx)) {
        if (ngx_stream_trojan_update_read_event(uc, 1) != NGX_OK) {
            ngx_log_error(NGX_LOG_INFO, uc->log, 0,
                          "ngx_del_event() socks5 udp relay failed");
        }

        return;
    }

    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, uc->log, 0,
                      "ngx_handle_read_event() socks5 udp relay failed");
    }
}


static void
ngx_stream_trojan_socks5_udp_control_handler(ngx_event_t *ev)
{
    u_char                    buf[1];
    ssize_t                   n;
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT,
                             "trojan socks5 udp control timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (pc->read->eof || pc->read->error || pc->write->error) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    n = pc->recv(pc, buf, sizeof(buf));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (n == 0) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
    return;
}


static void
ngx_stream_trojan_socks5_in_udp_control_handler(ngx_event_t *ev)
{
    u_char                    buf[1];
    ssize_t                   n;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT,
                             "socks5 udp control timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (c->read->eof || c->read->error || c->write->error) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    n = c->recv(c, buf, sizeof(buf));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
    return;
}


static void
ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx, ngx_uint_t rc)
{
    if (ctx->finalized) {
        return;
    }

    ctx->finalized = 1;
    if (ctx->resolver_ctx) {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
    }

    if (ctx->doh_ctx) {
        ngx_stream_trojan_doh_cancel(ctx->doh_ctx);
        ctx->doh_ctx = NULL;
    }

    ngx_stream_trojan_mux_close_streams(ctx);

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    if (ctx->udp4) {
        ngx_close_connection(ctx->udp4);
        ctx->udp4 = NULL;
    }

    if (ctx->socks5_udp) {
        ngx_close_connection(ctx->socks5_udp);
        ctx->socks5_udp = NULL;
    }

    if (ctx->socks5_in_udp) {
        ngx_close_connection(ctx->socks5_in_udp);
        ctx->socks5_in_udp = NULL;
    }

#if (NGX_HAVE_INET6)
    if (ctx->udp6) {
        ngx_close_connection(ctx->udp6);
        ctx->udp6 = NULL;
    }
#endif

    ngx_stream_finalize_session(ctx->session, rc);
}


static void *
ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_trojan_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->websocket_enable = NGX_CONF_UNSET;
    conf->route_enable = NGX_CONF_UNSET;
    conf->socks5_enable = NGX_CONF_UNSET;
    conf->http_proxy_enable = NGX_CONF_UNSET;
    conf->socks5_udp_enable = NGX_CONF_UNSET;
    conf->local_proxy_type = NGX_CONF_UNSET_UINT;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->udp_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_trojan_srv_conf_t *prev = parent;
    ngx_stream_trojan_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->websocket_enable, prev->websocket_enable, 0);
    ngx_conf_merge_value(conf->route_enable, prev->route_enable, 0);
    ngx_conf_merge_value(conf->socks5_enable, prev->socks5_enable, 0);
    ngx_conf_merge_value(conf->http_proxy_enable, prev->http_proxy_enable, 0);
    ngx_conf_merge_value(conf->socks5_udp_enable, prev->socks5_udp_enable, 0);
    ngx_conf_merge_uint_value(conf->local_proxy_type, prev->local_proxy_type,
                              ngx_stream_trojan_local_proxy_none);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 600000);
    ngx_conf_merge_msec_value(conf->udp_timeout, prev->udp_timeout, 600000);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE);

    if (conf->buffer_size < NGX_STREAM_TROJAN_MIN_BUFFER_SIZE
        || conf->buffer_size > NGX_STREAM_TROJAN_MAX_BUFFER_SIZE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_buffer_size must be between %uz and %uz",
                           (size_t) NGX_STREAM_TROJAN_MIN_BUFFER_SIZE,
                           (size_t) NGX_STREAM_TROJAN_MAX_BUFFER_SIZE);
        return NGX_CONF_ERROR;
    }

    if (conf->keys == NULL) {
        conf->keys = prev->keys;
    }

    if (conf->fallback == NULL) {
        conf->fallback = prev->fallback;
        conf->fallback_naddrs = prev->fallback_naddrs;
    }
    if (conf->websocket_path.len == 0) {
        conf->websocket_path = prev->websocket_path;
    }

    if (conf->websocket_host.len == 0) {
        conf->websocket_host = prev->websocket_host;
    }


    if (conf->outbounds == NULL) {
        conf->outbounds = prev->outbounds;
    }

    if (conf->routes == NULL) {
        conf->routes = prev->routes;
    }

    if (conf->doh_conf == NULL) {
        conf->doh_conf = prev->doh_conf;
    }

    if (conf->geosite == NULL) {
        conf->geosite = prev->geosite;
    }

    if (conf->geoip == NULL) {
        conf->geoip = prev->geoip;
    }

    if (conf->dns_rules == NULL) {
        conf->dns_rules = prev->dns_rules;
    }

    if (ngx_stream_trojan_dns_rules_prepare_geosite(cf, conf->dns_rules,
                                                    conf->geosite)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_route_validate(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_route_prepare(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    if (conf->route_enable && conf->routes != NULL
        && conf->route_cache == NULL)
    {
        conf->route_cache = ngx_pcalloc(cf->pool,
            NGX_STREAM_TROJAN_ROUTE_CACHE_ENTRIES
            * sizeof(ngx_stream_trojan_route_cache_entry_t));
        if (conf->route_cache == NULL) {
            return NGX_CONF_ERROR;
        }
    }


    conf->effective = conf->enable ? conf : NULL;

    if (conf->enable && (conf->keys == NULL || conf->keys->nelts == 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan is on but no trojan_password is configured");
        return NGX_CONF_ERROR;
    }

    if (conf->websocket_enable && !conf->enable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_websocket requires trojan on");
        return NGX_CONF_ERROR;
    }

    if (conf->websocket_enable && conf->websocket_path.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_websocket is on but no "
                           "trojan_websocket_path is configured");
        return NGX_CONF_ERROR;
    }

    if (conf->websocket_path.len != 0
        && conf->websocket_path.data[0] != '/')
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_websocket_path must start with \"/\"");
        return NGX_CONF_ERROR;
    }

    if (conf->socks5_udp_enable && !conf->socks5_enable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "socks5_udp requires socks5 on");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_websocket_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_websocket_path(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                   *value;

    if (tscf->websocket_path.len != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;
    if (value[1].len == 0 || value[1].data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_websocket_path must start with \"/\"");
        return NGX_CONF_ERROR;
    }

    tscf->websocket_path = value[1];

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_socks5_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (tscf->socks5_enable
        && tscf->local_proxy_type == NGX_CONF_UNSET_UINT)
    {
        tscf->local_proxy_type = ngx_stream_trojan_local_proxy_socks5;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_http_proxy_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (tscf->http_proxy_enable
        && tscf->local_proxy_type == NGX_CONF_UNSET_UINT)
    {
        tscf->local_proxy_type = ngx_stream_trojan_local_proxy_http_proxy;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_socks5_udp_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    return ngx_conf_set_flag_slot(cf, cmd, conf);
}


static char *
ngx_stream_trojan_trojan_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                   *value;

    if (tscf->socks5_ref_set) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_stream_trojan_parse_server_ref(cf, &value[1], &tscf->socks5_ref)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    tscf->socks5_ref_set = 1;

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_uint_t                i;
    ngx_str_t                *value;
    ngx_stream_trojan_key_t  *key;

    if (tscf->keys == NULL) {
        tscf->keys = ngx_array_create(cf->pool, 2, sizeof(ngx_stream_trojan_key_t));
        if (tscf->keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_password must not be empty");
            return NGX_CONF_ERROR;
        }

        key = ngx_array_push(tscf->keys);
        if (key == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_stream_trojan_make_key_len(value[i].data, value[i].len,
                                           key->data)
            != 0)
        {
            return NGX_CONF_ERROR;
        }
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_url_t    u;
    ngx_str_t   *value;

    if (tscf->fallback != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 80;
    u.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in trojan_fallback \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }

    if (u.naddrs < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_fallback \"%V\" resolved to no addresses",
                           &u.url);
        return NGX_CONF_ERROR;
    }

    tscf->fallback = ngx_pcalloc(cf->pool, u.naddrs * sizeof(ngx_addr_t));
    if (tscf->fallback == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(tscf->fallback, u.addrs, u.naddrs * sizeof(ngx_addr_t));
    tscf->fallback_naddrs = u.naddrs;

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_doh_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_stream_trojan_doh_conf_t *doh;
    ngx_str_t                    *value;

    if (tscf->doh_conf != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    doh = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_doh_conf_t));
    if (doh == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_doh_parse_url(&value[1], doh, cf->pool, cf->log)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    tscf->doh_conf = doh;

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_geosite_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                    *value;

    if (tscf->geosite != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    (void) cmd;
    return ngx_stream_trojan_geosite_load(cf, &value[1], &tscf->geosite);
}


static char *
ngx_stream_trojan_geoip_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                    *value;

    if (tscf->geoip != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    (void) cmd;
    return ngx_stream_trojan_geoip_load(cf, &value[1], &tscf->geoip);
}


static char *
ngx_stream_trojan_dns_rules_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                    *value;

    if (tscf->dns_rules != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    (void) cmd;
    return ngx_stream_trojan_dns_rules_parse(cf, &value[1],
                                             &tscf->dns_rules);
}


static char *
ngx_stream_trojan_routes_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t  *tscf = conf;
    ngx_stream_trojan_route_t     *route;

    char       *rv;
    ngx_conf_t  save;

    if (tscf->routes == NULL) {
        tscf->routes = ngx_array_create(cf->pool, 2,
                                        sizeof(ngx_stream_trojan_route_t));
        if (tscf->routes == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    route = ngx_array_push(tscf->routes);
    if (route == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(route, sizeof(*route));
    route->rules = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_stream_trojan_route_rule_t));
    if (route->rules == NULL) {
        return NGX_CONF_ERROR;
    }

    route->outbounds = ngx_array_create(cf->pool, 2,
                                        sizeof(ngx_stream_trojan_outbound_t));
    if (route->outbounds == NULL) {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_stream_trojan_routes_block;
    cf->handler_conf = route;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (route->rules->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_routes requires at least one rule");
        return NGX_CONF_ERROR;
    }

    if (route->outbounds->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_routes requires at least one outbound");
        return NGX_CONF_ERROR;
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_routes_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_route_t     *route = conf;
    ngx_stream_trojan_outbound_t  *outbound;

    ngx_uint_t  i, start;
    ngx_str_t  *value;

    value = cf->args->elts;

    if ((ngx_strcmp(value[0].data, "rule") == 0 && cf->args->nelts == 2)
        || (ngx_strcmp(value[0].data, "rules") == 0
            && cf->args->nelts >= 2))
    {
        for (i = 1; i < cf->args->nelts; i++) {
            if (ngx_stream_trojan_route_parse_rule(cf, route, &value[i])
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        return NGX_CONF_OK;
    }

    if (cf->args->nelts >= 1
        && ngx_strcmp(value[0].data, "outbounds_direct") == 0)
    {
        outbound = ngx_array_push(route->outbounds);
        if (outbound == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(outbound, sizeof(*outbound));
        outbound->type = ngx_stream_trojan_outbound_direct;
        outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
        outbound->block = ngx_stream_trojan_block_none;

        if (ngx_stream_trojan_route_outbound_options(cf, outbound, value, 1,
                                                     cf->args->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "outbounds_socks5") == 0) {
        start = 1;

    } else if (cf->args->nelts >= 2
               && ngx_strcmp(value[0].data, "outbounds") == 0
               && ngx_strcmp(value[1].data, "socks5") == 0)
    {
        start = 2;

    } else {
        goto unknown;
    }

    if (cf->args->nelts <= start) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V requires a socks5 server", &value[0]);
        return NGX_CONF_ERROR;
    }

    outbound = ngx_array_push(route->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(outbound, sizeof(*outbound));
    outbound->type = ngx_stream_trojan_outbound_socks5;
    outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    outbound->block = ngx_stream_trojan_block_none;

    if (ngx_stream_trojan_set_socks5_server(cf, outbound, &value[start])
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_route_outbound_options(cf, outbound, value,
                                                 start + 1, cf->args->nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_validate_socks5_outbound(cf, outbound,
                                                   "trojan_routes")
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

unknown:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in trojan_routes block",
                       &value[0]);

    (void) cmd;
    return NGX_CONF_ERROR;
}

static char *
ngx_stream_trojan_outbounds(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t   *tscf = conf;
    ngx_stream_trojan_outbound_t   *outbound;

    char         *rv;
    ngx_str_t    *value;
    ngx_conf_t    save;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "socks5") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unsupported outbounds type \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(outbound, sizeof(*outbound));
    outbound->type = ngx_stream_trojan_outbound_socks5;
    outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    outbound->block = ngx_stream_trojan_block_none;

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (outbound->socks5_server == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 requires server");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.data != NULL
        && outbound->socks5_password.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 password length must be 1..255");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.len != 0
        && outbound->socks5_username.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 password requires username");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_username.len != 0
        && outbound->socks5_password.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 username requires password");
        return NGX_CONF_ERROR;
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_outbound_direct_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    char                         *rv;
    ngx_conf_t                    save;
    ngx_stream_trojan_outbound_t *outbound;

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(outbound, sizeof(*outbound));
    outbound->type = ngx_stream_trojan_outbound_direct;
    outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    outbound->block = ngx_stream_trojan_block_none;

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    (void) cmd;
    return rv;
}


static char *
ngx_stream_trojan_outbound_socks5_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    char                         *rv;
    ngx_conf_t                    save;
    ngx_stream_trojan_outbound_t *outbound;

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(outbound, sizeof(*outbound));
    outbound->type = ngx_stream_trojan_outbound_socks5;
    outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    outbound->block = ngx_stream_trojan_block_none;

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (outbound->socks5_server == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 requires server");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.data != NULL
        && outbound->socks5_password.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 password length must be 1..255");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.len != 0
        && outbound->socks5_username.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 password requires username");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_username.len != 0
        && outbound->socks5_password.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 username requires password");
        return NGX_CONF_ERROR;
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_outbounds_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_outbound_t *outbound = conf;

    ngx_url_t   u;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "server") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_server != NULL) {
            return "duplicate socks5 server";
        }

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.default_port = 1080;
        u.no_resolve = 0;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in outbounds socks5 server \"%V\"",
                                   u.err, &u.url);
            }
            return NGX_CONF_ERROR;
        }

        if (u.naddrs < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "outbounds socks5 server \"%V\" resolved "
                               "to no addresses", &u.url);
            return NGX_CONF_ERROR;
        }

        outbound->socks5_server = ngx_pcalloc(cf->pool,
                                              u.naddrs * sizeof(ngx_addr_t));
        if (outbound->socks5_server == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(outbound->socks5_server, u.addrs,
                   u.naddrs * sizeof(ngx_addr_t));
        outbound->socks5_naddrs = u.naddrs;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "username") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "username is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_username.data != NULL) {
            return "duplicate socks5 username";
        }

        if (value[1].len == 0 || value[1].len > 255) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "socks5 username length must be 1..255");
            return NGX_CONF_ERROR;
        }

        outbound->socks5_username = value[1];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "password") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "password is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_password.data != NULL) {
            return "duplicate socks5 password";
        }

        if (value[1].len == 0 || value[1].len > 255) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "socks5 password length must be 1..255");
            return NGX_CONF_ERROR;
        }

        outbound->socks5_password = value[1];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "ip_prefer") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_direct) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ip_prefer is only allowed in outbounds_direct");
            return NGX_CONF_ERROR;
        }

        if (outbound->ip_prefer_set) {
            return "duplicate ip_prefer";
        }

        if (ngx_stream_trojan_parse_ip_prefer(&value[1],
                                              &outbound->ip_prefer)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid ip_prefer value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        outbound->ip_prefer_set = 1;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "block") == 0) {
        if (outbound->block_set) {
            return "duplicate block";
        }

        if (ngx_stream_trojan_parse_block(&value[1], &outbound->block)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid block value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (outbound->type == ngx_stream_trojan_outbound_socks5
            && outbound->block == ngx_stream_trojan_block_all)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "block all is only allowed for outbounds_direct");
            return NGX_CONF_ERROR;
        }

        outbound->block_set = 1;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in outbounds block",
                       &value[0]);

    (void) cmd;
    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_stream_trojan_validate_socks5_outbound(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, const char *name)
{
    if (outbound->socks5_server == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s socks5 requires server", name);
        return NGX_ERROR;
    }

    if (outbound->socks5_password.data != NULL
        && outbound->socks5_password.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s socks5 password length must be 1..255", name);
        return NGX_ERROR;
    }

    if (outbound->socks5_password.data != NULL
        && outbound->socks5_username.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s socks5 password requires username", name);
        return NGX_ERROR;
    }

    if (outbound->socks5_username.len != 0
        && outbound->socks5_password.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s socks5 username requires password", name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_set_socks5_server(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *server)
{
    ngx_url_t  u;

    if (outbound->socks5_server != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate socks5 server");
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = *server;
    u.default_port = 1080;
    u.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in socks5 server \"%V\"", u.err, &u.url);
        }
        return NGX_ERROR;
    }

    if (u.naddrs < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "socks5 server \"%V\" resolved to no addresses",
                           &u.url);
        return NGX_ERROR;
    }

    outbound->socks5_server = ngx_pcalloc(cf->pool,
                                          u.naddrs * sizeof(ngx_addr_t));
    if (outbound->socks5_server == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(outbound->socks5_server, u.addrs,
               u.naddrs * sizeof(ngx_addr_t));
    outbound->socks5_naddrs = u.naddrs;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_key_eq(ngx_str_t *key, const char *name, size_t len)
{
    return key->len == len && ngx_strncmp(key->data, name, len) == 0;
}


static ngx_int_t
ngx_stream_trojan_route_next_option(ngx_str_t *value, ngx_uint_t nelts,
    ngx_uint_t *i, ngx_str_t *key, ngx_str_t *val)
{
    u_char  *p, *last;

    p = value[*i].data;
    last = value[*i].data + value[*i].len;

    while (p < last && *p != '=') {
        p++;
    }

    if (p < last) {
        key->data = value[*i].data;
        key->len = (size_t) (p - value[*i].data);
        val->data = p + 1;
        val->len = (size_t) (last - p - 1);
        (*i)++;
        return key->len != 0 ? NGX_OK : NGX_ERROR;
    }

    if (*i + 1 >= nelts) {
        return NGX_ERROR;
    }

    *key = value[*i];
    *val = value[*i + 1];
    *i += 2;

    return key->len != 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_route_outbound_options(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *value,
    ngx_uint_t start, ngx_uint_t nelts)
{
    ngx_uint_t  i, bad;
    ngx_str_t   key, val;

    i = start;

    while (i < nelts) {
        bad = i;
        if (ngx_stream_trojan_route_next_option(value, nelts, &i, &key, &val)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_routes outbound option \"%V\"",
                               &value[bad]);
            return NGX_ERROR;
        }

        if (ngx_stream_trojan_route_key_eq(&key, "ip_prefer", 9)) {
            if (outbound->type != ngx_stream_trojan_outbound_direct) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ip_prefer is only allowed for direct "
                                   "route outbounds");
                return NGX_ERROR;
            }

            if (outbound->ip_prefer_set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate ip_prefer");
                return NGX_ERROR;
            }

            if (ngx_stream_trojan_parse_ip_prefer(&val, &outbound->ip_prefer)
                != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid ip_prefer value \"%V\"", &val);
                return NGX_ERROR;
            }

            outbound->ip_prefer_set = 1;
            continue;
        }

        if (ngx_stream_trojan_route_key_eq(&key, "username", 8)) {
            if (outbound->type != ngx_stream_trojan_outbound_socks5) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "username is only allowed for socks5 "
                                   "route outbounds");
                return NGX_ERROR;
            }

            if (outbound->socks5_username.data != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate socks5 username");
                return NGX_ERROR;
            }

            if (val.len == 0 || val.len > 255) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "socks5 username length must be 1..255");
                return NGX_ERROR;
            }

            outbound->socks5_username = val;
            continue;
        }

        if (ngx_stream_trojan_route_key_eq(&key, "password", 8)) {
            if (outbound->type != ngx_stream_trojan_outbound_socks5) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "password is only allowed for socks5 "
                                   "route outbounds");
                return NGX_ERROR;
            }

            if (outbound->socks5_password.data != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate socks5 password");
                return NGX_ERROR;
            }

            if (val.len == 0 || val.len > 255) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "socks5 password length must be 1..255");
                return NGX_ERROR;
            }

            outbound->socks5_password = val;
            continue;
        }

        if (ngx_stream_trojan_route_key_eq(&key, "block", 5)) {
            if (outbound->block_set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate block");
                return NGX_ERROR;
            }

            if (ngx_stream_trojan_parse_block(&val, &outbound->block)
                != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid block value \"%V\"", &val);
                return NGX_ERROR;
            }

            if (outbound->type == ngx_stream_trojan_outbound_socks5
                && outbound->block == ngx_stream_trojan_block_all)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "block all is only allowed for direct "
                                   "route outbounds");
                return NGX_ERROR;
            }

            outbound->block_set = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown trojan_routes outbound option \"%V\"",
                           &key);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_validate(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *conf)
{
    ngx_uint_t                    i, j;
    ngx_stream_trojan_route_t    *route;
    ngx_stream_trojan_outbound_t *outbound;

    if (!conf->route_enable) {
        return NGX_OK;
    }

    if (conf->routes == NULL || conf->routes->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_route is on but no trojan_routes "
                           "is configured");
        return NGX_ERROR;
    }

    route = conf->routes->elts;
    for (i = 0; i < conf->routes->nelts; i++) {
        if (route[i].rules == NULL || route[i].rules->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_routes route %ui has no rules", i + 1);
            return NGX_ERROR;
        }

        if (route[i].outbounds == NULL || route[i].outbounds->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "trojan_routes route %ui has no outbounds",
                               i + 1);
            return NGX_ERROR;
        }

        outbound = route[i].outbounds->elts;
        for (j = 0; j < route[i].outbounds->nelts; j++) {
            if (outbound[j].type == ngx_stream_trojan_outbound_socks5
                && ngx_stream_trojan_validate_socks5_outbound(cf,
                                                              &outbound[j],
                                                              "trojan_routes")
                   != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_prepare(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *conf)
{
    ngx_uint_t                       i, j;
    ngx_stream_trojan_route_t       *route;
    ngx_stream_trojan_route_rule_t  *rule;

    if (!conf->route_enable || conf->routes == NULL) {
        return NGX_OK;
    }

    route = conf->routes->elts;
    for (i = 0; i < conf->routes->nelts; i++) {
        rule = route[i].rules->elts;

        for (j = 0; j < route[i].rules->nelts; j++) {
            if (rule[j].type == ngx_stream_trojan_route_rule_geosite) {
                if (conf->geosite == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "trojan_routes uses geosite \"%V\" "
                                       "but trojan_geosite is not configured",
                                       &rule[j].value);
                    return NGX_ERROR;
                }

                rule[j].geosite = ngx_stream_trojan_geosite_find(conf->geosite,
                                                                 &rule[j].value);
                if (rule[j].geosite == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "geosite \"%V\" was not found in "
                                       "trojan_geosite", &rule[j].value);
                    return NGX_ERROR;
                }

                if (ngx_stream_trojan_geosite_prepare_entry(cf,
                                                            rule[j].geosite,
                                                            &rule[j].attr,
                                                            rule[j].attr_not)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            if (rule[j].type == ngx_stream_trojan_route_rule_geoip) {
                if (conf->geoip == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "trojan_routes uses geoip \"%V\" but "
                                       "trojan_geoip is not configured",
                                       &rule[j].value);
                    return NGX_ERROR;
                }

                rule[j].geoip = ngx_stream_trojan_geoip_find(conf->geoip,
                                                             &rule[j].value);
                if (rule[j].geoip == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "geoip \"%V\" was not found in "
                                       "trojan_geoip", &rule[j].value);
                    return NGX_ERROR;
                }

                if (ngx_stream_trojan_geoip_prepare_entry(cf, rule[j].geoip)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "could not index geoip \"%V\" in "
                                       "trojan_geoip", &rule[j].value);
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_parse_geosite(ngx_conf_t *cf,
    ngx_stream_trojan_route_rule_t *rule, ngx_str_t *value)
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
                           "invalid trojan_routes geosite rule \"%V\"",
                           value);
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_route_copy(cf, &name, &rule->value, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (attr.len
        && ngx_stream_trojan_route_copy(cf, &attr, &rule->attr, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_parse_rule(ngx_conf_t *cf,
    ngx_stream_trojan_route_t *route, ngx_str_t *value)
{
    u_char                           *p, *last;
    ngx_str_t                         key, val;
    ngx_stream_trojan_route_rule_t    temp, *rule;

    ngx_memzero(&temp, sizeof(ngx_stream_trojan_route_rule_t));

    if (value->len == 1 && value->data[0] == '*') {
        temp.type = ngx_stream_trojan_route_rule_all;
        goto done;
    }

    p = value->data;
    last = value->data + value->len;

    while (p < last && *p != ':') {
        p++;
    }

    if (p == last || p == value->data || p + 1 == last) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_routes rule \"%V\"", value);
        return NGX_ERROR;
    }

    key.data = value->data;
    key.len = (size_t) (p - value->data);
    val.data = p + 1;
    val.len = (size_t) (last - p - 1);

    if (key.len == 6 && ngx_strncmp(key.data, "domain", 6) == 0) {
        temp.type = ngx_stream_trojan_route_rule_domain;

        if (val.len == 0 || val.len > 255
            || ngx_stream_trojan_route_copy(cf, &val, &temp.value, 1)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (key.len == 7 && ngx_strncmp(key.data, "geosite", 7) == 0) {
        temp.type = ngx_stream_trojan_route_rule_geosite;
        if (ngx_stream_trojan_route_parse_geosite(cf, &temp, &val) != NGX_OK) {
            return NGX_ERROR;
        }

    } else if (key.len == 5 && ngx_strncmp(key.data, "geoip", 5) == 0) {
        temp.type = ngx_stream_trojan_route_rule_geoip;

        if (val.len == 0 || val.len > 128
            || ngx_stream_trojan_route_copy(cf, &val, &temp.value, 1)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (key.len == 2 && ngx_strncmp(key.data, "ip", 2) == 0) {
        temp.type = ngx_stream_trojan_route_rule_ip;
        if (ngx_stream_trojan_route_parse_cidr(cf, &val, &temp.cidr)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (key.len == 4 && ngx_strncmp(key.data, "port", 4) == 0) {
        temp.type = ngx_stream_trojan_route_rule_port;
        if (ngx_stream_trojan_route_parse_port(&val, &temp.port_start,
                                               &temp.port_end)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_routes port rule \"%V\"",
                               value);
            return NGX_ERROR;
        }

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown trojan_routes rule \"%V\"", &key);
        return NGX_ERROR;
    }

done:

    rule = ngx_array_push(route->rules);
    if (rule == NULL) {
        return NGX_ERROR;
    }

    *rule = temp;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_parse_cidr(ngx_conf_t *cf, ngx_str_t *value,
    ngx_stream_trojan_route_cidr_t *cidr)
{
    int        rc;
    u_char    *p, *last, *text;
    size_t     ip_len;
    ngx_int_t  prefix;
    ngx_uint_t max_prefix;

    p = value->data;
    last = value->data + value->len;

    while (p < last && *p != '/') {
        p++;
    }

    ip_len = (size_t) (p - value->data);
    if (ip_len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_routes ip rule \"%V\"", value);
        return NGX_ERROR;
    }

    text = ngx_pnalloc(cf->pool, ip_len + 1);
    if (text == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(text, value->data, ip_len);
    text[ip_len] = '\0';

    rc = inet_pton(AF_INET, (char *) text, cidr->addr);
    if (rc == 1) {
        cidr->addr_len = 4;
        max_prefix = 32;

    } else {
#if (NGX_HAVE_INET6)
        rc = inet_pton(AF_INET6, (char *) text, cidr->addr);
        if (rc == 1) {
            cidr->addr_len = 16;
            max_prefix = 128;
        } else
#endif
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid trojan_routes ip rule \"%V\"", value);
            return NGX_ERROR;
        }
    }

    if (p == last) {
        cidr->prefix = max_prefix;
        return NGX_OK;
    }

    p++;
    if (p == last) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_routes ip prefix \"%V\"", value);
        return NGX_ERROR;
    }

    prefix = ngx_atoi(p, last - p);
    if (prefix == NGX_ERROR || (ngx_uint_t) prefix > max_prefix) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid trojan_routes ip prefix \"%V\"", value);
        return NGX_ERROR;
    }

    cidr->prefix = (ngx_uint_t) prefix;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_parse_port(ngx_str_t *value, uint16_t *start,
    uint16_t *end)
{
    u_char     *p, *last;
    ngx_int_t   a, b;

    p = value->data;
    last = value->data + value->len;

    while (p < last && *p != '-') {
        p++;
    }

    if (p == value->data || (p < last && p + 1 == last)) {
        return NGX_ERROR;
    }

    a = ngx_atoi(value->data, p - value->data);
    if (a == NGX_ERROR || a > 65535) {
        return NGX_ERROR;
    }

    if (p == last) {
        b = a;

    } else {
        b = ngx_atoi(p + 1, last - p - 1);
        if (b == NGX_ERROR || b > 65535) {
            return NGX_ERROR;
        }
    }

    if (a > b) {
        return NGX_ERROR;
    }

    *start = (uint16_t) a;
    *end = (uint16_t) b;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_copy(ngx_conf_t *cf, ngx_str_t *src, ngx_str_t *dst,
    ngx_uint_t lower)
{
    size_t  i;

    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    dst->len = src->len;
    for (i = 0; i < src->len; i++) {
        dst->data[i] = lower ? ngx_stream_trojan_route_lc(src->data[i])
                             : src->data[i];
    }
    dst->data[src->len] = '\0';

    return NGX_OK;
}
