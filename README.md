# ngx_stream_trojan_module

`ngx_stream_trojan_module` 是一个 NGINX `stream` 模块，在 NGINX 终结 TLS 后直接处理 Trojan 应用层协议。模块当前实现 Trojan TCP/UDP 中继、Trojan-Go WebSocket transport、Mux TCP 多路复用、fallback、DNS-over-HTTPS、DNS 规则、geosite/geoip 路由、SOCKS5/HTTP CONNECT 本地入站，以及直连或 SOCKS5 出站。

完整 NGINX 配置示例见 [`example.conf`](./example.conf)。

## 当前能力

- **Trojan over TLS**：在 `stream server` 中解析 Trojan 密码头和 CONNECT/UDP ASSOCIATE 请求。
- **多密码认证**：`trojan_password` 可配置多个明文密码；模块内部派生 SHA-224 十六进制 key，并使用常量时间比较。
- **TCP 中继**：非阻塞连接目标地址，并在 NGINX 事件循环内双向转发。
- **UDP ASSOCIATE**：支持 Trojan UDP 包格式，直连 UDP 和 SOCKS5 UDP 出站。
- **Mux TCP 多路复用**：支持 Trojan-Go `0x7f` mux、Xray/V2Ray `v1.mux.cool`、sing-box/mihomo `sp.mux.sing-box.arpa:444` smux。当前 mux 子流只接受 TCP CONNECT；Mux.Cool UDP 和 sing-mux padding/yamux/h2mux 不支持。
- **Fallback**：非 Trojan 流量可转发到 `trojan_fallback`；未配置时返回内置 HTTP 503。
- **本地 SOCKS5 入站**：`socks5 on;` 提供无认证 SOCKS5 CONNECT；配合 `socks5_udp on;` 支持 UDP ASSOCIATE。
- **本地 HTTP CONNECT 入站**：`http_proxy on;` 提供 HTTP/1.x CONNECT；其他 HTTP 方法返回 405。
- **出站选择**：支持直连出站、SOCKS5 出站、阻断 UDP/HTTP3/全部请求、IPv4/IPv6 偏好。
- **路由**：`trojan_route on;` 后按 `trojan_routes` 顺序匹配域名、geosite、geoip、IP/CIDR、端口，并在命中路由的可用出站中随机选择一个。
- **DNS 解析链路**：直连域名命中 `trojan_dns_rules` 后使用该组配置的普通 resolver 或 DoH；未命中规则才按 `trojan_doh` → NGINX `resolver` 推进。未配置异步解析器时，域名直连请求失败；IP 目标无需解析。
- **Trojan-Go WebSocket**：`trojan_websocket on;` 使该 TLS server 进入 WebSocket-only Trojan 入站模式；WebSocket binary payload 承载现有 Trojan TCP/UDP/mux 字节。若需要同时提供裸 Trojan over TLS，必须配置另一个未开启 `trojan_websocket` 的 `stream server`。

## 构建要求

- NGINX 需要启用 `--with-stream`。
- Trojan TLS 入站需要 `--with-stream_ssl_module`，并在 `stream server` 中配置 `ssl_certificate` / `ssl_certificate_key`。
- `trojan_dns_rules` 的 `regexp` 规则需要 NGINX 编译时启用 PCRE。
- HTTPS DoH 依赖 NGINX/OpenSSL SSL 支持，并使用 OpenSSL 默认 CA 路径校验证书。

## 构建

从 NGINX 源码目录执行，路径指向本仓库：

```sh
./configure \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=/path/to/ngx_stream_trojan_module
make
```

动态模块构建使用：

```sh
./configure \
  --with-stream \
  --with-stream_ssl_module \
  --add-dynamic-module=/path/to/ngx_stream_trojan_module
make modules
```

动态模块需要在 `nginx.conf` 顶层加载：

```nginx
load_module modules/ngx_stream_trojan_module.so;
```

## 处理流程

1. NGINX `stream` 监听 TLS 连接并完成 TLS 终结。
2. 若当前 server 开启 `trojan_websocket`，模块先要求 `GET ... Upgrade: websocket` 握手；成功返回 101 后，对 WebSocket binary payload 解帧，再进入 Trojan key/request 解析。非 `GET ... Upgrade: websocket` 首包走 `trojan_fallback`，未配置时返回内置 503。
3. 未开启 `trojan_websocket` 时，模块直接读取 Trojan 56 字节 key 和 CRLF。
4. key 匹配成功后解析请求命令：TCP CONNECT、UDP ASSOCIATE 或 mux。
5. 选择出站：未启用路由时使用 server 级第一个出站；未配置出站则直连。启用路由时按 `trojan_routes` 顺序匹配。
6. 直连域名命中 DNS 规则时使用该规则组的普通 resolver 或 DoH；未命中规则再按 server 级 DoH、NGINX resolver 推进；未配置异步解析器时域名请求失败。
7. 所有连接、解析、UDP socket 和 relay 都走 NGINX 非阻塞事件模型。

## 指令总览

所有指令均在 `stream server` 上下文中使用。

### 入站指令

| 指令 | 默认 | 说明 |
|:---|:---|:---|
| `trojan on \| off;` | `off` | 启用 Trojan 协议处理；启用后必须至少配置一个 `trojan_password`。 |
| `trojan_password <password> [...];` | — | 配置一个或多个 Trojan 密码。 |
| `trojan_fallback <address>;` | — | 非 Trojan 流量转发目标；默认端口 80。未配置时返回内置 503。 |
| `trojan_websocket on \| off;` | `off` | 启用 Trojan-Go WebSocket-only transport；要求 `trojan on;` 和 `trojan_websocket_path`，同一 server 不再接受裸 Trojan over TLS。 |
| `trojan_websocket_path <path>;` | — | WebSocket request-target 必须与该值逐字节完全一致；值必须以 `/` 开头，不做 URL decode。 |
| `trojan_websocket_host <host>;` | — | 可选 Host 校验；未配置时接受任意 Host。配置后对完整 `Host` header 做 ASCII 大小写不敏感比较，不自动剥离端口。 |
| `socks5 on \| off;` | `off` | 启用本地无认证 SOCKS5 入站。 |
| `socks5_udp on \| off;` | `off` | 启用本地 SOCKS5 UDP ASSOCIATE；要求 `socks5 on;`。 |
| `http_proxy on \| off;` | `off` | 启用本地 HTTP CONNECT 入站。 |
| `trojan_server <server_name:port \| localhost:port>;` | 自动 | 本地 SOCKS5/HTTP 入站复用哪个 Trojan server 的路由、DNS、出站和超时配置。 |

本地 `socks5` / `http_proxy` 入站只允许监听 `127.0.0.1` 或 `[::1]`，不允许 `listen ssl`，且同一 listen 地址不能与其他 `stream server` 共享。若配置中只有一个 `trojan on;` server，本地入站会自动复用它；存在多个 Trojan server 时必须用 `trojan_server` 指明目标。`trojan_server` 接受 `localhost:port` 或 `server_name:port`，不接受 IP 字面量。

### 超时和缓冲区

| 指令 | 默认 | 说明 |
|:---|:---|:---|
| `trojan_connect_timeout <time>;` | `60s` | 与目标或出站代理建立 TCP 连接的超时。 |
| `trojan_timeout <time>;` | `10m` | TCP relay 空闲超时。 |
| `trojan_udp_timeout <time>;` | `10m` | UDP ASSOCIATE 空闲超时。 |
| `trojan_buffer_size <size>;` | `32k` | TCP relay 每方向缓冲区大小。 |

### DNS 和数据文件

| 指令 | 默认 | 说明 |
|:---|:---|:---|
| `trojan_doh <url>;` | — | 配置 DoH 端点，支持 `https://host[:port]/path` 和 `http://host[:port]/path`。 |
| `trojan_dns_rules <path>;` | — | 加载 DNS 规则文件，按目标域名选择 resolver/DoH 和 IPv4/IPv6 策略。 |
| `trojan_geosite <path>;` | — | 加载 `geosite.dat` / `dlc.dat`，供 DNS 规则和路由的 `geosite:` 使用。 |
| `trojan_geoip <path>;` | — | 加载 `geoip.dat`，供路由的 `geoip:` 使用。 |

DoH 使用 `POST` + `application/dns-message`。按 IP 偏好先查 A 或 AAAA；当响应有效但没有对应记录时尝试另一种类型。端点主机在加载配置时解析，HTTPS 请求启用 SNI 和证书校验。

`trojan_dns_rules` 是类 YAML 文本格式：

```yaml
https://dns.google/dns-query:
  strategy: ipv4_first
  rules:
    - geosite:google
    - domain:example.com

8.8.8.8:53,8.8.4.4,1.1.1.1:53:
  strategy: auto
  rules:
    - regexp:.*\.example\.net

[2001:4860:4860::8888]:53:
  strategy: ipv6_first
  rules:
    - domain:ipv6.example.org
```

- 普通 DNS 组行以 `:` 结尾，多个服务器用逗号分隔，交给 NGINX resolver 创建。
- DoH 组行必须是单个 `http(s)://...` URL，复用 `trojan_doh` 的 `POST application/dns-message`、SNI、证书校验和 A/AAAA fallback 行为。
- DoH URL 不能和普通 DNS server 写在同一个组头；命中 DoH 规则组后，DoH 失败不会回退到 server 级 `trojan_doh` 或 NGINX resolver。
- 每个组必须至少包含一条规则。
- `strategy` 支持 `auto`、`ipv4_first`、`ipv6_first`，并兼容 `ipv4` / `ipv6`。
- `domain` 按大小写不敏感的精确或子域后缀匹配。
- `regexp` 使用大小写不敏感正则。
- `geosite` 支持 `geosite:name`、`geosite:name@attr`、`geosite:name@!attr`。

### Server 级出站

```nginx
outbounds_direct {
    ip_prefer auto;
    block none;
}

outbounds_socks5 {
    server 127.0.0.1:1080;
    username user;
    password pass;
    block h3;
}

outbounds socks5 {
    server 127.0.0.1:1080;
}
```

| 子指令 | 适用 | 说明 |
|:---|:---|:---|
| `server <address>;` | `outbounds_socks5` | SOCKS5 出站地址，默认端口 1080。 |
| `username <string>;` | `outbounds_socks5` | SOCKS5 用户名，长度 1..255；必须和 `password` 同时配置或同时省略。 |
| `password <string>;` | `outbounds_socks5` | SOCKS5 密码，长度 ≤255；必须和 `username` 同时配置或同时省略。 |
| `ip_prefer auto \| ipv4 \| ipv6;` | `outbounds_direct` | 直连域名解析的 IP 地址族偏好。 |
| `block none \| h3 \| udp \| all;` | 两者 | `h3` 阻断 UDP/443，`udp` 阻断所有 UDP ASSOCIATE，`all` 阻断该出站全部请求。`all` 只允许用于直连出站。 |

未启用 `trojan_route` 时，模块选择第一个 server 级出站；未配置任何出站时按直连处理。

### 路由出站

```nginx
trojan_route on;

trojan_routes {
    rules geosite:netflix domain:google.com geoip:cn ip:10.0.0.0/8 port:443;
    outbounds_socks5 127.0.0.1:1080 username=user password=pass block=h3;
    outbounds_direct ip_prefer=ipv4 block=none;
}

trojan_routes {
    rule *;
    outbounds_direct ip_prefer auto;
}
```

| 指令 | 默认 | 说明 |
|:---|:---|:---|
| `trojan_route on \| off;` | `off` | 启用路由模式。 |
| `trojan_routes { ... }` | — | 定义一个路由块；可重复配置。 |

路由块内支持：

| 子指令 | 说明 |
|:---|:---|
| `rule <expr>;` | 添加一条规则。 |
| `rules <expr> [...];` | 一次添加多条规则。 |
| `outbounds_direct [ip_prefer=<auto\|ipv4\|ipv6>] [block=<none\|h3\|udp\|all>];` | 添加直连出站。 |
| `outbounds_socks5 <server> [username=<string>] [password=<string>] [block=<none\|h3\|udp>];` | 添加 SOCKS5 出站。 |
| `outbounds socks5 <server> ...;` | `outbounds_socks5` 的别名形式。 |

路由规则是“路由块内任一规则命中即命中该路由块”。模块按路由块配置顺序匹配，第一个命中的路由块生效，并从该路由块中未被 `block` 阻断的出站里随机选择一个。启用 `trojan_route` 后，如果没有路由命中或命中路由没有可用出站，请求会被拒绝；不会回退到 server 级出站或隐式直连。

规则表达式：

| 规则 | 说明 |
|:---|:---|
| `*` | 匹配任意目标。 |
| `domain:example.com` | 匹配域名本身或子域名后缀，大小写不敏感。 |
| `geosite:netflix` | 匹配 `trojan_geosite` 中的 geosite 分组；支持 `@attr` 和 `@!attr`。 |
| `geoip:cn` | 匹配 `trojan_geoip` 中的 IPv4/IPv6 CIDR 分组。 |
| `ip:1.2.3.4` / `ip:1.2.3.0/24` | 匹配客户端请求中的 IP 字面量或 CIDR。 |
| `port:443` / `port:1000-2000` | 匹配目标端口或端口范围。 |

`geoip` 和 `ip` 只匹配客户端请求里的 IP 字面量；域名请求不会先解析成 IP 再参与路由匹配。

## 客户端兼容提示

- Trojan 客户端必须使用 TLS 连接到 NGINX 的 `listen ... ssl` server。
- mihomo/sing-box 的 sing-mux 需要使用 `smux`，且关闭 padding；`yamux`、`h2mux` 和 padding 当前不支持。
- SOCKS5 本地入站只支持无认证方法。
- HTTP 本地入站只支持 CONNECT，不实现普通 HTTP 正向代理请求转发。
- Trojan-Go WebSocket 客户端的 `path` 必须与 `trojan_websocket_path` 完全一致；开启 `trojan_websocket` 的 server 不接受普通 Trojan 客户端。
- WebSocket server→client frame 不掩码，client→server frame 必须掩码；当前不实现 Trojan-Go 可选 Shadowsocks AEAD 层。

## 注意事项

- Trojan 密码头位于 TLS 应用数据内，`ssl_preread` 不能替代 TLS 终结。
- `trojan_fallback` 会转发已读到的非 Trojan 前缀数据；未配置 fallback 时发送内置 HTTP 503 后关闭连接。
- WebSocket 握手前的非 WebSocket 首包或无效 HTTP/WebSocket 请求仍可交给 `trojan_fallback`；未配置 fallback 时返回内置 503 或对应 WebSocket HTTP 错误响应。
- 101 WebSocket 握手完成后的 Trojan 鉴权失败会关闭 WebSocket，不再 fallback。
- server 级 `trojan_doh` 或命中的 DoH 规则组查询失败都会结束本次请求，不回退到其他解析层。
- `trojan_geosite` / `trojan_geoip` 文件只在加载或 reload NGINX 配置时读取；替换文件后需要 reload。
- 本仓库没有自带 Makefile、测试框架、lint、formatter 或 CI。非平凡代码改动应在 NGINX 源码树中完成 `./configure ... --add-module=/path/to/ngx_stream_trojan_module && make` 验证。

## 文件结构

| 文件 | 说明 |
|:---|:---|
| `ngx_stream_trojan_module.c` | 模块主体：配置解析、状态机、TCP/UDP relay、SOCKS5/HTTP 入站、出站、路由、生命周期。 |
| `ngx_stream_trojan_protocol.c/h` | Trojan 协议辅助：key 派生、地址解析、UDP frame、默认 fallback 响应。 |
| `ngx_stream_trojan_socks5_protocol.c/h` | SOCKS5 编解码：握手、认证、请求、响应、UDP 包。 |
| `ngx_stream_trojan_http_proxy_protocol.c/h` | HTTP CONNECT 入站解析和响应生成。 |
| `ngx_stream_trojan_websocket_protocol.c/h` | Trojan-Go WebSocket 握手、Accept、错误响应和 frame header/mask 辅助。 |
| `ngx_stream_trojan_mux.c/h` | Trojan-Go mux、Mux.Cool、sing-mux smux 帧解析/打包。 |
| `ngx_stream_trojan_doh.c/h` | 异步 DoH client。 |
| `ngx_stream_trojan_dns_rules.c/h` | DNS 规则文件解析和域名匹配。 |
| `ngx_stream_trojan_geosite.c/h` | `geosite.dat` / `dlc.dat` 解析和匹配。 |
| `ngx_stream_trojan_geoip.c/h` | `geoip.dat` 解析和 CIDR 匹配。 |
| `ngx_stream_trojan_relay.h` | relay 循环次数和字节预算限制。 |
| `ngx_stream_trojan_ip_prefer.h` | IPv4/IPv6 偏好常量。 |
| `config` | NGINX addon 构建配置。 |
| `example.conf` | 独立 NGINX 配置示例。 |
