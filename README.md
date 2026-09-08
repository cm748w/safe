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
  真实健康检测（`depends_on: service_healthy`）、请求体 / 条数 / 并发三重限流、优雅退出、结构化日志。
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
- 限制：请求体 ≤ 8 MiB、单次记录数 ≤ 10000、并发 ≤ 64（均可用环境变量调整），超限返回 4xx/503，不崩溃。

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
│   ├── server/               # HTTP handler + 中间件 + 限流
│   └── client/               # 客户端逻辑（读文件→POST→展示）
├── rules/rules.json          # 识别规则（与代码解耦）
├── data/input.json           # 示例原始数据
├── Dockerfile                # 多阶段构建
├── docker-compose.yml        # 一键启动编排
└── Makefile                  # build / vet / test / run 快捷命令
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
| `SERVER_URL` | client 目标地址 | `http://localhost:8080` |
| `INPUT_FILE` | client 输入文件 | `data/input.json` |

## 自测与自检

```bash
go vet ./...
go test ./...
```

`go test ./...` 包含对规则引擎（20 条示例数据全量断言）、宽容 JSON 解码、HTTP 接口的单元测试。

## 已识别协议

SSH（OpenSSH）、HTTP（nginx / Apache / Jetty / Microsoft-IIS 等，按 `Server` 头泛化）、MySQL、Redis、
FTP（ProFTPD / vsFTPd / Pure-FTPd / 通用 220）、TLS（ClientHello 前缀）。其余一律 `unknown`。

## 合规声明

本系统仅处理**已授权**目标 / 数据；不采集、不存储敏感明文；内置请求体 / 条数 / 并发限流与速率上限。
