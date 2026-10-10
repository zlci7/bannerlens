# BannerLens

Go 批量 Banner 指纹识别系统，包含独立客户端、HTTP 服务端和外置 JSON 规则。输入网络扫描记录，输出协议、软件、版本、操作系统线索及置信度。

## 快速启动

需要 Docker Engine 和 Docker Compose v2，使用 Linux 容器。

```sh
docker compose up --build
```

server 健康检查通过后，client 读取 `testdata/banners.json` 中的 20 条样例并打印识别结果。client 成功处理后退出，server 持续运行。结果可通过以下命令查看：

```sh
docker compose logs client
docker compose exec server /app/server -healthcheck
```

将自己的 JSON 文件放入 `testdata`，然后运行：

```sh
docker compose run --rm client -input /data/my-banners.json -server http://server:8080
```

停止服务：

```sh
docker compose down
```

## 本地运行

需要 Go 1.22 或更新版本。在项目根目录执行：

```sh
go run ./cmd/server -listen 127.0.0.1:8080 -rules rules/fingerprints.json
```

另一个终端运行独立客户端：

```sh
go run ./cmd/client -input testdata/banners.json -server http://127.0.0.1:8080 -timeout 15s
```

客户端将结果 JSON 写入标准输出，错误写入标准错误并返回非零退出码。

## API

### POST /fingerprint

请求头为 `Content-Type: application/json`，请求体为数组：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
]
```

成功响应 HTTP 200：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}
]
```

结果保持输入数量和顺序，固定包含上述七个字段。置信度为 `0` 至 `1` 的规则评分。无法识别时，`protocol` 为 `unknown`，`product`、`version`、`os_hint` 为空字符串，`confidence` 为 `0`；已识别服务中缺少的版本和系统线索也返回空字符串。空数组返回 `[]`。

每条输入必须包含有效 IPv4 或 IPv6 地址、`1` 至 `65535` 的端口和字符串 Banner；空 Banner 合法。默认限制为每批 10000 条、请求体 8 MiB。格式或字段错误返回 400，超大请求返回 413，明确指定的非 JSON 媒体类型返回 415，错误方法返回 405。错误响应使用 `{"error":"..."}`。

输入使用标准 JSON：换行写为 `\r\n`，NUL 字节写为 `\u0000`；JSON 不接受 `\x00` 转义。MySQL 握手的二进制字节可按 `\u00XX` 表达。

### GET /health

服务就绪时返回 HTTP 200 和 `{"status":"ok"}`。服务端在规则成功校验、加载后启动；容器探针执行真实 HTTP 请求。

## 识别规则

支持 SSH / OpenSSH、HTTP / nginx / Apache / Jetty / Microsoft-IIS、MySQL / MariaDB、Redis、FTP / ProFTPD / vsFTPd / Pure-FTPd。识别依据 Banner 内容，支持非标准端口。HTTP 产品信息取自响应头，MySQL 版本取自协议握手，操作系统线索取自明确文本。TLS 字节和其他未支持的内容返回 `unknown`。

规则位于 `rules/fingerprints.json`，启动时加载并编译；修改后执行 `docker compose restart server`。

| 规则字段 | 含义 |
| --- | --- |
| `id` | 唯一规则标识 |
| `priority` | 数值越大越先匹配，同优先级保持文件顺序 |
| `source` | `banner`、`http_headers` 或 `mysql_version` |
| `pattern` | Go 正则表达式 |
| `protocol`、`product` | 协议和产品名称 |
| `version_group`、`product_group` | 提取信息的捕获组序号，0 表示不提取 |
| `confidence` | 匹配置信度 |

`os_rules` 定义操作系统匹配表达式和对应提示。非法表达式、重复标识、越界捕获组及非法置信度会导致启动失败。

## 部署

Compose 内部网络连接 server 和 client，默认不向宿主机发布端口；容器中的服务地址为 `http://server:8080`。客户端通过 `service_healthy` 等待服务就绪。

Dockerfile 采用多阶段构建，在构建阶段执行测试，分别生成 server 和 client 静态二进制镜像。运行镜像基于 scratch，以 UID/GID 65532 运行。Compose 配置只读根文件系统、只读规则与输入挂载、移除 capabilities、禁止提权、资源上限和日志轮转。服务端配置 HTTP 读写超时，并支持 SIGTERM 优雅退出。

## 测试与结构

```sh
go test ./...
go vet ./...
```

测试覆盖协议与版本提取、非标准端口、误匹配、未知及截断数据、非法规则、HTTP 请求边界、并发请求、健康探针和客户端错误处理。`testdata/expected.json` 为 20 条样例的预期结果。

```text
cmd/server/               服务端与健康探针
cmd/client/               独立客户端
internal/model/           输入输出结构
internal/fingerprint/     规则加载和识别引擎
internal/api/             HTTP 接口
rules/                    外置识别规则
testdata/                 自测输入和预期结果
docs/technical-design.md  技术方案
```
