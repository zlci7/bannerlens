# BannerLens

基于 Go 的批量 Banner 指纹识别系统。

## 项目目标

接收网络扫描产生的 `ip`、`port`、`banner`，识别协议、软件、版本及操作系统线索，输出识别置信度。

采用独立 client + server 架构：server 提供 HTTP API，client 读取本地 JSON 文件、发送批量请求并展示结果。

## 识别范围

- SSH：识别 OpenSSH、版本及 Ubuntu、Debian 等系统线索。
- HTTP：识别 nginx、Apache、Jetty 及其版本。
- MySQL：识别握手 Banner 中的软件版本。
- Redis：识别常见响应及认证提示。
- FTP：识别 ProFTPD、vsFTPd、Pure-FTPd 等服务。

识别以 Banner 内容为依据，端口作为辅助线索。无法识别的记录返回 `protocol: "unknown"`，保持批量处理正常运行。Banner 未提供的软件版本或系统信息返回空字符串。

## 接口约定

### `POST /fingerprint`

请求类型为 `application/json`，请求体是扫描记录数组：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
  }
]
```

响应是识别结果数组：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

结果固定包含 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`，置信度范围为 `0` 至 `1`。

### `GET /health`

返回服务健康状态，供部署环境判断 server 是否就绪。

## 部署目标

交付包含 Go 源码、独立客户端、识别规则、Dockerfile、Compose 配置及自测数据，目标启动命令为：

```sh
docker compose up --build
```

容器通过 Compose 内部网络访问 server，client 在 server 健康检查通过后启动。镜像采用多阶段构建，以非 root 用户运行并收紧运行权限。识别规则独立于 Go 程序代码，便于维护和扩展。

自测覆盖示例协议、版本提取、未知 Banner 和批量处理；验收以独立测试数据为准。
