# Banner Fingerprint System

一个用 Go 编写的 **Banner 指纹识别系统**：接收一批网络扫描原始数据（`ip`、`port`、`banner`），
识别出对应的 **协议 / 软件 / 版本 / 操作系统提示 / 置信度**，以 **client + server** 架构交付，
支持 **Docker Compose 一键启动**。

## 特性

- **规则与代码解耦**：所有识别规则集中在 `rules/rules.json`，以正则 + 捕获组描述，运行时加载；
  新增 / 调整指纹**无需重新编译**，只需改 JSON 并重启服务。
- **client + server**：
  - `server` 暴露 `POST /fingerprint`（批量识别）与 `GET /health`（健康检查）。
  - `client` 是独立程序：读取本地 JSON 文件 → 发送 server → 表格 / JSON 展示结果。
- **鲁棒性**：认不出统一返回 `protocol: "unknown"`，**绝不会因单条数据崩溃**；
  宽容解析扫描器常见的 `\xNN` 十六进制转义 banner（如 `\x00`、`\x16\x03\x01`）。
- **生产级部署**：多阶段镜像、非 root 运行、只读根文件系统、`cap_drop: ALL`、`no-new-privileges`、
  真实健康检测（`depends_on: service_healthy`）、请求体 / 条数 / 并发三重限制 + **按客户端 IP 的速率限流**、
  优雅退出、结构化日志。
- **零第三方依赖**：仅用 Go 标准库，缩小供应链攻击面，构建更快。

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

- `server` 启动并通过 `/health` 自检通过后，`client` 自动运行：读取 `data/input.json`、
  调用 `server`，并把识别结果打印到标准输出。
- 查看识别结果：

```bash
docker compose logs client
```

- 停止：

```bash
docker compose down
```

> 设计说明：server 端口**只暴露在 compose 内部网络**（`server:8080`），不对宿主机映射，
> 容器间访问通过服务名收敛；如需从宿主机调试，见下方「本地开发」。

## 本地开发（不使用 Docker）

```bash
# 终端 1：启动 server（默认 :8080，规则自动从 rules/rules.json 加载）
go run ./cmd/server

# 终端 2：运行 client
go run ./cmd/client -file data/input.json -server http://localhost:8080
```

client 也支持 `-json` 输出原始 JSON：

```bash
go run ./cmd/client -file data/input.json -server http://localhost:8080 -json
```

client 支持 `-version` 打印版本号后退出（版本号同样通过 `-ldflags -X main.version=...` 注入）：

```bash
go run ./cmd/client -version
```

## API 说明

### `POST /fingerprint`

请求体为记录数组：

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
]
```

响应为结果数组（字段：`ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`）：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}
]
```

- 认不出 → `{"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}`。
- 限制：请求体 ≤ 8 MiB、单次记录数 ≤ 10000、并发 ≤ 64、**每客户端 IP 20 请求/秒（突发 40）**，
  分别可用 `MAX_BODY_BYTES`、`MAX_RECORDS`、`MAX_CONCURRENT`、`RATE_LIMIT_PER_SEC`、
  `RATE_LIMIT_BURST` 调整；超限返回 4xx（限流为 `429` + `Retry-After`）或 `503`，不崩溃。

#### 速率上限（按客户端 IP）

`POST /fingerprint` 使用**令牌桶**按客户端 IP 独立计数，超出预算立即返回：

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 1
Content-Type: application/json; charset=utf-8

{"error":"rate limit exceeded"}
```

- 默认 **20 请求/秒，突发 40**（`RATE_LIMIT_PER_SEC=20`、`RATE_LIMIT_BURST=40`）。
  `RATE_LIMIT_PER_SEC` 支持小数，例如 `0.5` 表示每 2 秒放行 1 个请求。
- 客户端身份取自 TCP 连接的 `RemoteAddr`，**不读取 `X-Forwarded-For` / `X-Real-IP`**：
  这些头是客户端可任意伪造的，若信任它们，攻击者只要轮换头部就能完全绕过限流。
  因此若部署在反向代理之后，请在**代理层**统一限流，或者由代理把 `RemoteAddr` 归一化
  （保证服务只能被代理访问），而不是让本服务去解析 XFF。
- 空闲客户端（超过 `3 × burst ÷ 速率`，且不低于 10 分钟未活动）会被**惰性清理**，
  因此 `map` 不会随源 IP 变化无限增长；清理由请求触发，空闲进程不做任何后台工作。
- `GET /health` **不受限流影响**，否则过载时编排器会误判进程不健康并重启它。

### `GET /health`

```json
{"status":"ok","version":"dev"}
```

## 如何新增 / 调整指纹

编辑 `rules/rules.json`，每一条规则包含：

| 字段 | 含义 |
| --- | --- |
| `id` | 规则唯一标识 |
| `priority` | 匹配优先级，越大越先尝试 |
| `match` | RE2 正则，作用于原始 banner |
| `protocol` | 命中后的协议名 |
| `product` / `product_group` | 静态产品名，或从捕获组取值 |
| `version_group` | 从第 N 个捕获组取版本号 |
| `confidence` | 基础置信度（0~1） |
| `confidence_by_product` | 按产品覆盖置信度 |
| `os_hint_keywords` | 按关键字（大小写不敏感）推断操作系统 |

Docker 部署下规则文件被挂载为只读，改完 `docker compose restart server` 即生效。

## 项目结构

```
.
├── cmd/
│   ├── server/main.go        # HTTP 服务入口（信号处理、优雅退出、配置）
│   └── client/main.go        # 独立 CLI 入口（flag/env 解析）
├── internal/
│   ├── fingerprint/          # 规则引擎（规则加载、正则编译、识别）
│   ├── jsonx/                # 宽容 JSON 解码（\xNN 转义）
│   ├── server/               # HTTP handler + 中间件 + 限流（ratelimit.go / ratelimit_test.go）
│   └── client/               # 客户端逻辑（读文件→POST→展示）
├── .github/workflows/ci.yml  # CI：gofmt / vet / build / test -race -cover / golangci-lint / gosec
├── rules/rules.json          # 识别规则（与代码解耦）
├── data/input.json           # 示例原始数据
├── Dockerfile                # 多阶段构建
├── docker-compose.yml        # 一键启动编排
├── Makefile                  # build / vet / test / run 快捷命令
├── .gitattributes            # 统一 LF 换行（避免 CRLF 导致的 gofmt 假阳性）
└── LICENSE                   # MIT
```

## 环境变量

| 变量 | 作用 | 默认 |
| --- | --- | --- |
| `PORT` | server 监听端口 | `8080` |
| `RULES_PATH` | 规则文件路径 | `rules/rules.json` |
| `LOG_LEVEL` | 日志级别（debug/info/warn/error） | `info` |
| `MAX_BODY_BYTES` | 请求体上限 | `8388608` |
| `MAX_RECORDS` | 单次记录数上限 | `10000` |
| `MAX_CONCURRENT` | 并发识别上限 | `64` |
| `RATE_LIMIT_PER_SEC` | 每客户端 IP 速率上限（请求/秒，支持小数） | `20` |
| `RATE_LIMIT_BURST` | 每客户端 IP 突发额度（令牌桶深度） | `40` |
| `SERVER_URL` | client 目标地址 | `http://localhost:8080` |
| `INPUT_FILE` | client 输入文件 | `data/input.json` |

异常值处理：`RATE_LIMIT_PER_SEC` / `RATE_LIMIT_BURST` 缺失、无法解析或非正数时回落到默认值，
`LOG_LEVEL` 无法识别时按 `info` 处理。

## 自测与自检

```bash
gofmt -l .                        # 应为空
go vet ./...
go build ./...
go test -race -cover ./...
golangci-lint run --no-config ./...
gosec -quiet ./...
```

本仓库实测结果（Go 1.26.1 windows/amd64，全部通过）：

| 检查项 | 结果 |
| --- | --- |
| `gofmt -l .` | 无输出（全部已格式化） |
| `go vet ./...` | 退出码 0 |
| `go build ./...` | 退出码 0 |
| `go test -race -cover ./...` | 全部 `ok`，无 data race |
| `golangci-lint run --no-config ./...` | 退出码 0（0 issue） |
| `gosec -quiet ./...` | 退出码 0（0 issue） |

`go test -race -cover ./...` 的分包覆盖率：

| 包 | 覆盖率 |
| --- | --- |
| `internal/server` | 87.5% |
| `internal/jsonx` | 100.0% |
| `internal/fingerprint` | 78.0% |
| `internal/client`、`cmd/*` | 0.0%（无测试文件） |
| 合计 | 52.9% |

其中 `internal/server/ratelimit.go` 各函数覆盖率为 `Allow` 95.2%、`sweepLocked` 87.5%，
`cleanupInterval` / `shardFor` / `len` / `clientIP` / `retryAfterSeconds` / `rateLimitMiddleware` 均 100%。

测试覆盖：规则引擎（20 条示例数据全量断言）、宽容 JSON 解码（`\xNN` 转义）、HTTP 接口与
限流器（放行 / 超限 429 + `Retry-After` / 多 IP 互不影响 / 令牌随时间恢复 / 空闲条目淘汰 /
并发安全）。限流测试使用**可注入时钟**，不依赖 `sleep`，整个测试套件在 1 秒内跑完。

CI（`.github/workflows/ci.yml`）在 push / PR 上执行同一组检查，并额外校验 `go.mod` 中
不存在 `require` 块、仓库中不存在 `go.sum`，以守住"零第三方依赖"这一约束。

> 关于换行符：仓库历史文件曾以 CRLF 提交，这会让 `gofmt -l` 把**所有**文件误报为未格式化。
> 现已通过 `.gitattributes`（`* text=auto eol=lf`）固定为 LF，工作区也已归一化，因此
> `gofmt -l` 在干净检出后应为空；CI 中的 `gofmt -l` 校验依赖这一点。

## 已识别协议

SSH（OpenSSH）、HTTP（nginx / Apache / Jetty / Microsoft-IIS 等，按 `Server` 头泛化）、MySQL、Redis、
FTP（ProFTPD / vsFTPd / Pure-FTPd / 通用 220）、TLS（ClientHello 前缀）。其余一律 `unknown`。

## 合规声明

本系统仅处理**已授权**目标 / 数据；不采集、不存储敏感明文；内置请求体 / 条数 / 并发限制，
以及按客户端 IP 的速率上限（默认 20 请求/秒、突发 40，见上文「速率上限」）。
