# BannerLens 技术方案

## 最小闭环

独立 Go 客户端读取 JSON 数组，通过 `POST /fingerprint` 调用服务端，输出格式化 JSON 结果。Docker Compose 启动服务端，在健康检查通过后运行客户端；客户端完成批次后退出，服务端持续提供 API。

## 模块与契约

| 模块 | 文件范围 | 职责 |
| --- | --- | --- |
| 数据模型 | `internal/model` | 输入 `Record` 与输出 `Result` 的 JSON 字段 |
| 识别引擎 | `internal/fingerprint`、`rules` | 加载并校验外置规则，匹配文本与解析 MySQL 握手 |
| 服务端 | `internal/api`、`cmd/server` | HTTP 接口、批次校验、超时、健康检查与优雅退出 |
| 客户端 | `cmd/client`、`testdata` | 文件读取、请求发送、结果展示与错误退出 |
| 部署 | `Dockerfile`、`compose.yaml` | 多阶段构建、内部网络、健康依赖与容器权限 |

引擎公开 `Load(path string) (*Engine, error)`、`Identify(model.Record) model.Result`、`IdentifyBatch([]model.Record) []model.Result`。HTTP 层使用 `api.NewHandler(engine *fingerprint.Engine, maxBodyBytes int64, maxBatch int) http.Handler`。

输入为包含 `ip`、`port`、`banner` 的数组；输出保持数量和顺序，固定包含 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`。未知 Banner 返回 `unknown`、空产品信息和零置信度；空数组返回空数组。格式错误和非法地址、端口返回 HTTP 400，超大请求返回 413，超出批次数量返回 400。

## 识别规则

JSON 文件定义规则优先级、协议、产品、匹配表达式、版本捕获组和置信度；启动时编译规则，失败则阻止服务就绪。匹配以内容为依据，支持非标准端口，具体产品规则优先于协议通用规则。SSH、HTTP、Redis、FTP 使用文本匹配；MySQL 提取握手中的 NUL 结尾版本串。操作系统线索仅来自显式文本。

## 接口与命令

- `POST /fingerprint`：`application/json` 数组，成功返回 HTTP 200。
- `GET /health`：规则加载成功且服务可接受请求时返回 HTTP 200。
- 服务端：`server -listen :8080 -rules rules/fingerprints.json`。
- 健康探针：`server -healthcheck -health-url http://127.0.0.1:8080/health`。
- 客户端：`client -input testdata/banners.json -server http://localhost:8080 -timeout 15s`。

服务端默认最大请求 8 MiB、批次 10000 条，设置 HTTP 读写超时并支持 SIGTERM 优雅退出。客户端为单次请求配置超时，HTTP 错误与文件错误通过标准错误输出并返回非零退出码。

## 部署与验证

标准库实现，无第三方 Go 运行依赖。多阶段构建生成静态二进制，分别提供 server、client 镜像目标。运行容器使用非 root 用户、只读根文件系统、移除 capabilities、禁止提权并设置资源限制。server 仅通过内部网络供 client 访问；健康探针执行真实 HTTP 请求，Compose 用 `service_healthy` 控制启动顺序。

验证覆盖示例、未见过的版本、非标准端口、误匹配防护、未知及截断数据、请求边界和客户端错误处理。联调通过本地真实 HTTP 请求检查完整闭环；Docker 可用时执行 Compose 联调。
