# AGENTS.md

项目：**Sigil**，面向服务器集群的 ACME 证书签发与分发工具。

## 当前状态

项目处于持续开发阶段，不要把它描述为“v1 已全部完成”。核心注册、mTLS 鉴权、证书拉取、客户端吊销、管理命令、服务端热重载、客户端身份续签和 push 调度均已可用，并有 WSLC 黑盒测试；真实 DNS provider 的 ACME 容器 E2E 与部分 TUI 操作仍未完成。

## 项目快览

- Go 1.25，模块：`github.com/Oganneson-Studio/sigil`
- 两个二进制：`sigils`（server）与 `sigilc`（client）
- 服务端用 SQLite 保存证书、客户端、token 和 ACME 账户
- 客户端使用 mTLS 拉取证书并输出 PEM、DER、PKCS#12
- CLI 使用 Cobra，TUI 使用 Bubble Tea，本地控制使用 Unix socket / Windows named pipe
- Windows 容器开发和 E2E 使用 WSLC，不使用 Docker Desktop

## 仓库布局

```text
cmd/sigils/commands/       服务端 CLI 与启动逻辑
cmd/sigilc/commands/       客户端 CLI、注册和 IPC 控制
internal/acme/             lego ACME 封装
internal/api/              HTTPS API、安装脚本和 mTLS 中间件
internal/ca/               内部 mini-CA
internal/client/           拉取循环、push receiver、状态
internal/config/           严格 YAML schema 与校验
internal/enroll/           一次性 token、CSR 和身份保存
internal/ipc/              服务端与客户端本地控制 API
internal/output/           证书格式化与原子写入
internal/scheduler/        签发、续期和退避
internal/securefile/       私钥配置的原子写入和 Windows DACL
internal/service/          系统服务封装
internal/store/            SQLite repositories
internal/tui/              server/client TUI
pkg/proto/                 HTTP DTO
test/e2e/                  WSLC 优先的原生容器编排测试
```

## 构建和验证

```powershell
go build ./cmd/sigils
go build ./cmd/sigilc
go test ./... -count=1
go vet ./...

# Windows：自动使用 C:\Program Files\WSL\wslc.exe
go test -v -tags e2e -timeout 10m ./test/e2e
```

E2E 不依赖 Compose 或固定 IP。它构建临时镜像、创建随机命名网络、通过网络别名连接、执行注册/拉取/吊销/token 测试，并按精确名称清理资源。Linux CI 可显式设置 `SIGIL_CONTAINER_CLI=docker` 使用 Docker Engine；Windows 必须使用 WSLC。

竞态测试需要 CGO：

```powershell
go test -race ./internal/client ./internal/ipc
```

如果当前 Go 环境 `CGO_ENABLED=0`，应明确报告无法运行，不能把它写成已通过。

## 安全约束

1. `server.yaml` 的 `certificates[].subscribers` 是订阅授权的唯一来源；客户端输出配置不能扩大授权。
2. 注册 token 是一次性的，并绑定 secret、server URL、客户端名和 mini-CA 证书。客户端发送 token 前必须验证 TLS，禁止恢复 `InsecureSkipVerify`。
3. 已注册客户端每次访问都必须同时通过 mTLS、数据库存在性和证书指纹匹配。删除客户端即撤销访问，heartbeat 不得重新创建它。
4. `client.yaml` 包含客户端私钥。写入必须经过 `internal/securefile`：Unix 使用私有模式，Windows 使用受保护 DACL，且采用临时文件加原子替换。
5. 私钥输出默认权限为 `0600`；公开证书可为 `0644`。不要对所有输出格式使用同一默认权限。
6. 安装下载端点的 `os/arch` 必须保持字符白名单和目录 containment 双重检查。
7. PowerShell 安装脚本只能反射 canonical base64url 字符，响应必须 `Cache-Control: no-store`，不得再次把任意查询值拼入可执行脚本。
8. 生产一键安装要求公网端点使用操作系统信任的 TLS 证书。通过 `server.tls_cert_file` 与 `server.tls_key_file` 配置；内部 mini-CA 默认证书不能让首次系统 `curl` 自动信任。
9. 服务端 push 只能向不含 userinfo、query 或 fragment 的 HTTPS endpoint 发送 bearer 鉴权请求，且不得跟随重定向或在错误日志中泄漏完整 endpoint。客户端 push listener 是明文 HTTP，只能监听字面量回环 IP；远程接入必须先由本机反向代理或隧道终止 TLS。listener 必须配置至少 32 字符 bearer token，使用常量时间比较，并合并并发通知，避免并发写证书和状态文件。
10. 配置解析使用 `yaml.KnownFields(true)`。增加字段时必须同步 schema、验证和测试。
11. 服务端只读 IPC 必须使用显式 DTO，不能在线路上返回证书私钥、push token 或 enrollment-token secret hash。
12. 数据库证书记录必须绑定有效配置指纹；CA directory、domains 或 key type 变化后，旧材料不得继续分发。

## 运行时约束

- `sigils` 与 `sigilc` 使用不同的 IPC 端点。客户端命令解析顺序为：显式 `--ipc`、`client.ipc_socket`、平台默认客户端 socket。
- `sigils reload` 必须通过本地服务端 IPC 完整解析并应用新配置。可热更新 `acme`、`dns_providers`、`certificates` 和 `clients` push routing；若 `server.listen`、`server.public_url`、`server.data_dir`、`server.ipc_socket`、`server.tls_cert_file` 或 `server.tls_key_file` 变化，必须拒绝 reload、保留旧运行配置并明确要求重启。
- 服务端 reload 与 periodic/manual issuance 必须共用同步点：旧 generation 的签发和 push 完成后才能发布新 generation；发布时清理旧 backoff，并立即唤醒 scheduler。
- `sigilc fetch` 必须调用真实 IPC 拉取；`--cert` 只强制目标证书。`reload` 必须先完整解析新配置，失败时保留旧配置。
- 客户端 mTLS 身份必须在到期前自动续签；`client.identity_renew_before` 默认 30 天，允许范围为 1 小时到 89 天。
- periodic、push 和 IPC 拉取必须由同一把锁串行化。
- 客户端 socket 在 Unix 上固定为 `/var/run/sigil/sigilc.sock`，不能依赖启动用户的 `$HOME`。
- 服务端外部 HTTPS 可使用公网证书，但客户端证书仍由内部 mini-CA 验证。
- SQLite 和 WAL 包含私钥材料，创建与重开时都必须保持私有权限。

## 平台约束

- 平台差异使用 build tag 文件，例如 `_windows.go` 与 `_unix.go`。
- Windows 的 `os.Chmod(0600)` 不能替代 DACL。
- Windows 安装脚本必须区分 AMD64、ARM64 和 x86。
- WSLC 2.9.4 每个会话存在挂载数量限制；E2E 当前每轮只挂载统一临时根目录，避免 Compose 风格的大量独立挂载。
- 不运行或依赖 Docker Desktop。需要容器验证时直接调用 `wslc`。

## 已知未完成项

- ACME 真实 DNS provider 的容器 E2E 尚未建立；现有 E2E 用生成证书验证注册和分发安全链。
- TUI 仍有部分管理操作未接线。

## 修改原则

- 先读现有实现和测试，再做局部改动；不要把未实现功能写成已完成。
- 安全边界、跨模块契约和用户工作流必须增加回归测试。
- 手工文件修改使用 `apply_patch`。
- 仓库已于 2026-09-27 初始化 Git（基线提交 `d0151bf`，`.gitattributes` 固定 LF）；变更可用 `git diff` 审阅，验证仍以格式化、单元测试、静态检查和 WSLC E2E 为准。
- 容器测试结束后确认 WSLC 容器与网络为空，并移除本轮生成的镜像。
