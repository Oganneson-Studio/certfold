[English](README.md) | 简体中文

# Certfold

Certfold 是面向服务器集群的集中式 ACME 证书签发与分发工具。服务端（`certfolds`）通过 DNS-01 验证自动获取和续期证书；各主机上的客户端（`certfoldc`）通过 mTLS 拉取已订阅的证书，将其写为 PEM、DER 或 PKCS#12 格式，并可在证书变更时运行配置好的程序。

```
                        ACME CA
                           |
               order, DNS-01 challenge
                    certificate
                           |
  DNS provider <----> certfolds
    (TXT record)           |
                     mTLS long poll
                    _______|_______
                   |       |       |
              certfoldc certfoldc certfoldc
              (host 1)  (host 2)  (host N)
                  |
             write outputs
             run on_change
```

## 主要特性

- 自动 ACME 签发与续期，支持 ARI（RFC 9773）
- 长轮询交付：服务端在已订阅的证书签发后立即应答
- 一次性注册令牌；已注册的客户端使用 mTLS 认证
- 声明式输出对账：输出文件会自动恢复
- `on_change` 钩子：证书更新后重新加载服务
- 支持 Linux、macOS 和 Windows 的一键安装
- 服务端与客户端 TUI
- 结构化日志，最近 500 条事件保存在内存中

## 快速开始

先构建 `certfolds` 和 `certfoldc`（参阅[构建与测试](docs/zh-CN/development.md)）。编写一个最小的 `/etc/certfold/server.yaml`：

```yaml
server:
  listen: ":8443"
  public_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfolds"

acme:
  email: "ops@example.com"
  default_ca: letsencrypt
  cas:
    letsencrypt:
      directory: "https://acme-v02.api.letsencrypt.org/directory"

dns_providers:
  cloudflare:
    type: cloudflare
    api_token: "${CF_API_TOKEN}"

certificates:
  - name: api-prod
    domains: ["api.example.com"]
    ca: letsencrypt
    dns_provider: cloudflare
    subscribers: [web-1]
```

在服务端的环境中设置 `CF_API_TOKEN`，然后启动服务端（在 Linux 上以 root 身份运行）：

```bash
certfolds --config /etc/certfold/server.yaml serve
```

创建一个短期注册令牌：

```bash
certfolds --config /etc/certfold/server.yaml token create --name web-1 --expires 10m
```

在 web-1 上注册并启动客户端：

```bash
certfoldc --config /etc/certfold/client.yaml enroll --token <token>
certfoldc --config /etc/certfold/client.yaml serve
```

参阅[客户端配置](docs/zh-CN/configuration.md#客户端配置)了解如何配置输出和 `on_change`。[一键安装](docs/zh-CN/installation.md#一键安装)可自动完成注册和服务配置，但需要 `<data_dir>/binaries/` 中有对应平台的二进制文件，并且服务端证书必须已被操作系统信任（参阅[生产环境 TLS](docs/zh-CN/installation.md#生产环境-tls)）。

查看或触发正在运行的客户端：

```bash
certfoldc status
certfoldc fetch --cert api-prod
certfoldc reload
```

## 文档

| 主题 | 说明 |
|---|---|
| [安装](docs/zh-CN/installation.md) | 一键安装、重装、升级、卸载、生产环境 TLS |
| [配置](docs/zh-CN/configuration.md) | server.yaml、client.yaml、命名规则、环境变量、DNS-01 提供商 |
| [运维](docs/zh-CN/operations.md) | 令牌、交付、on_change、续期、事件、TUI、热重载、系统服务 |
| [安全](docs/zh-CN/security.md) | 信任模型、Windows 上的私钥输出、目录要求 |
| [故障排查](docs/zh-CN/troubleshooting.md) | 注册错误、目录错误、服务状态 |
| [构建与测试](docs/zh-CN/development.md) | 从源码构建及运行测试套件 |
| [已知限制](docs/zh-CN/limitations.md) | 已知限制 |

## 项目状态

处于持续开发阶段。注册、证书分发、管理命令、运行时热重载、客户端身份续签、长轮询交付、并行签发、ARI 驱动的续期、HTTPS 证书热更新、服务端与客户端 TUI 以及结构化日志与事件功能均已实现。安全关键的注册和拉取路径由单元测试和 WSLC 原生端到端测试覆盖，后者包含经由 Pebble 的真实 ACME 签发和 ARI。投入生产前请先查阅[已知限制](docs/zh-CN/limitations.md)。

## 许可证

本项目采用 [Apache License, Version 2.0](LICENSE) 许可。
