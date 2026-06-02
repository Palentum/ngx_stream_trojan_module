# ngx_stream_trojan_module

Nginx stream 模块，在 Nginx 流式子系统中原生实现 Trojan 代理协议，支持 TLS 终结、TCP/UDP 中继、fallback 转发以及 SOCKS5 出站链式代理。

## 特性

- **Trojan over TLS** — 在 Nginx stream 子系统中直接解析 Trojan 协议，无需外部代理进程
- **多密码认证** — 支持配置一个或多个明文密码（内部使用 SHA-224 派生 56 字节十六进制密钥）
- **TCP 流量中继** — 协议层透明转发 TCP 连接到目标地址
- **UDP 流量中继** — 完整的 UDP ASSOCIATE 支持，含双向数据包转发
- **Fallback 转发** — 非 Trojan 流量可转发至指定后端（如 HTTP/HTTPS 服务）；未配置时返回 HTTP 503
- **SOCKS5 出站代理** — 支持将 Trojan 流量通过上游 SOCKS5 服务器链式转发，支持用户名/密码认证
- **IP 地址族偏好** — `outbounds_direct` 内可按出站规则指定 IPv4/IPv6 优先
- **出站规则选择** — 按顺序匹配第一个可用出站，未匹配则回退到直连
- **Nginx 异步解析器** — 配置 `resolver` 后使用 Nginx 内置异步 DNS，支持 IPv4/IPv6 偏好选择
- **可配置超时与缓冲区** — 连接超时、会话超时、UDP 超时、缓冲区大小均可独立配置

## 依赖

- Nginx 编译时需启用 `--with-stream` 和 `--with-stream_ssl_module`
- 运行时不依赖外部进程

## 构建

### 静态模块

```sh
./configure \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=/path/to/ngx_stream_trojan_module
make
```

### 动态模块

将 `--add-module` 替换为 `--add-dynamic-module`，然后在 `nginx.conf` 中用 `load_module` 加载。

## 配置指令

### `trojan`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan on \| off;` | `off` | `stream` / `server` |

启用 Trojan 协议处理。启用时要求至少配置一个 `trojan_password`。

---

### `trojan_password`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_password <password> [...];` | — | `stream` / `server` |

设置一个或多个认证密码。客户端 Trojan 请求中携带的密码哈希必须与其中一个匹配。密码为明文，模块内部自动派生为 56 字节十六进制密钥。

---

### `trojan_fallback`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_fallback <address>;` | — | `stream` / `server` |

非 Trojan 协议流量的转发目标地址（默认端口 80）。未配置时，模块返回 HTTP 503 Service Unavailable 响应后关闭连接。

---

### `trojan_connect_timeout`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_connect_timeout <time>;` | `60s` | `stream` / `server` |

与上游目标建立 TCP 连接的超时时间。

---

### `trojan_timeout`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_timeout <time>;` | `10m` | `stream` / `server` |

TCP 会话在两次数据传输之间的空闲超时时间。

---

### `trojan_udp_timeout`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_udp_timeout <time>;` | `10m` | `stream` / `server` |

UDP ASSOCIATE 会话的空闲超时时间。

---

### `trojan_buffer_size`

| 语法 | 默认 | 上下文 |
|:---|:---|:---|
| `trojan_buffer_size <size>;` | `32k` | `stream` / `server` |

TCP 数据中继的缓冲区大小。影响每次事件循环中单方向转发的最大数据量。

---

### `outbounds_direct`

| 语法 | 上下文 |
|:---|:---|
| `outbounds_direct { ... }` | `stream` / `server` |

定义一个直接出站（不走代理）。在块内可配置：

| 子指令 | 说明 |
|:---|:---|
| `ip_prefer auto \| ipv4 \| ipv6;` | 解析域名时的 IP 地址族偏好，默认 `auto` |

---

### `outbounds_socks5`

| 语法 | 上下文 |
|:---|:---|
| `outbounds_socks5 { ... }` | `stream` / `server` |

定义一个 SOCKS5 出站。在块内可配置：

| 子指令 | 说明 |
|:---|:---|
| `server <address>;` | **必填**。SOCKS5 代理服务器地址（默认端口 1080） |
| `username <string>;` | 可选。SOCKS5 认证用户名（1-255 字符） |
| `password <string>;` | 可选。SOCKS5 认证密码（≤255 字符） |

> 用户名和密码必须同时配置或同时不配置。

---

### `outbounds`

| 语法 | 上下文 |
|:---|:---|
| `outbounds socks5 { ... }` | `stream` / `server` |

`outbounds_socks5` 的别名语法，功能相同。

---

### 出站选择规则

`outbounds_direct` 和 `outbounds_socks5` 按配置顺序组成出站列表。处理 Trojan 请求时：

1. 按顺序遍历出站列表
2. 对 `outbounds_direct` 直接放行
3. 对 `outbounds_socks5` 检查 `has_rules` 标记（当前为保留字段）
4. 首个匹配的出站被选中；若所有出站均不匹配，回退到直连

> 当前版本中出站规则匹配逻辑为保留能力，实际行为是首个出站即被选中。

## 配置示例

### 基本 TLS Trojan 服务

```nginx
stream {
    server {
        listen 443 ssl;
        server_name example.com;

        resolver 1.1.1.1 8.8.8.8 valid=60s;
        resolver_timeout 5s;

        ssl_certificate     /path/to/fullchain.pem;
        ssl_certificate_key /path/to/private.key;

        trojan on;
        trojan_password pass1234 word5678;
        trojan_fallback 127.0.0.1:8080;
        trojan_connect_timeout 60s;
        trojan_timeout 10m;
        trojan_udp_timeout 10m;
        trojan_buffer_size 32k;
    }
}

http {
    server {
        listen 127.0.0.1:8080;
        root /var/www/html;
    }
}
```

### 使用 SOCKS5 出站链式代理

```nginx
stream {
    server {
        listen 443 ssl;
        server_name example.com;

        resolver 1.1.1.1 valid=60s;

        ssl_certificate     /path/to/fullchain.pem;
        ssl_certificate_key /path/to/private.key;

        trojan on;
        trojan_password mypassword;

        # 将 Trojan 流量通过上游 SOCKS5 转发
        outbounds_socks5 {
            server 10.0.0.1:1080;
            username proxyuser;
            password proxypass;
        }
    }
}
```

### 出站直连 + IP 偏好

```nginx
stream {
    server {
        listen 443 ssl;
        server_name example.com;

        ssl_certificate     /path/to/fullchain.pem;
        ssl_certificate_key /path/to/private.key;

        trojan on;
        trojan_password mypassword;

        # 直连出站，优先 IPv4
        outbounds_direct {
            ip_prefer ipv4;
        }

        # 备选：通过 SOCKS5 出站
        outbounds_socks5 {
            server 192.168.1.1:1080;
        }
    }
}
```

## 注意事项

- stream server 必须终结 TLS（`ssl_certificate` / `ssl_certificate_key`），因为 Trojan 密码头部在 TLS 应用数据内部。仅用 `ssl_preread` 不够。
- 未配置 `resolver` 时，域名目标使用系统 DNS（`getaddrinfo` 同步解析），可能阻塞 worker 进程。
- 当前版本中 `outbounds` 出站规则的 GeoIP/域名匹配尚未实现，出站选择取首个条目。

## 文件结构

| 文件 | 说明 |
|:---|:---|
| `ngx_stream_trojan_module.c` | 模块主体：协议处理、配置解析、TCP/UDP 中继、出站选择 |
| `ngx_stream_trojan_protocol.c/h` | Trojan 协议编解码：密钥派生、地址解析、UDP 帧打包/解包 |
| `ngx_stream_trojan_socks5_protocol.c/h` | SOCKS5 协议编解码：握手、认证、请求/响应、UDP 包 |
| `ngx_stream_trojan_relay.h` | TCP 中继流控：循环上限与字节预算 |
| `ngx_stream_trojan_ip_prefer.h` | IP 地址族偏好选择 |
| `config` | Nginx 动态/静态模块构建配置 |
