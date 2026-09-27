# AGENTS.md

项目：**Sigil**，面向服务器集群的 ACME 证书签发与分发工具。

## 当前状态

项目处于持续开发阶段，不要把它描述为“v1 已全部完成”。核心注册、mTLS 鉴权、证书拉取、客户端吊销、管理命令、服务端热重载、客户端身份续签和 push 调度均已可用，并有 WSLC 黑盒测试；真实 DNS provider 的 ACME 容器 E2E 与部分 TUI 操作仍未完成。2026-09-27 完成现状审阅并拍板重构方向（见下一节），按 `TODO.md` 分阶段执行。

## 重构方向（2026-09-27 拍板）

审阅文档未公开（缺陷编号 A1–A13、决定编号 B1–B4、C1 均出自该文档）。以下决定已接受；**对应 Phase 落地之前，现有代码和下文各条约束继续有效**。

- B1（Phase 3）：服务端推送改为客户端长轮询。mTLS 上的 `GET /v1/sync` 带 etag 挂起等待，证书落库或 reload 时唤醒，默认最长 55 秒。落地后删除推送通知器、客户端 push 监听、server.yaml 的 `clients:` 和 client.yaml 的 `push_listen` / `push_token`，安全约束 9 随之作废。
- B2（Phase 2）：取消全局签发锁，改为每张证书一把锁、有上限的并行签发。落库时比对下单时的 spec 指纹与当前配置，不一致则丢弃；reload 不再等待在途签发。
- B3（Phase 4）：PowerShell 安装改为 `& ([scriptblock]::Create((irm <url>/install.ps1))) -Token '<token>'`，服务端不再把请求参数写进脚本，安全约束 7 随之作废。
- B4（Phase 3）：删除 `/v1/heartbeat`，由 mTLS 鉴权中间件用条件 UPDATE 刷新 `last_seen`（每个客户端每分钟最多写一次）。
- C1（Phase 3）：客户端每张证书可配置 `on_change` 钩子，argv 形式，带超时，只能在客户端配置。
- 每一项删除都排在替代品落地之后：删除 IPC `POST /ipc/v1/certs` 要等 Pebble E2E；删除 heartbeat 和 push 要等 `/v1/sync`。
- 保留不动：mTLS + 数据库指纹鉴权、一次性令牌绑定、`subscribers` 唯一授权来源、客户端本地输出配置、spec 指纹绑定、`securefile`、严格 YAML。

## 项目快览

- Go 1.25，模块：`github.com/Oganneson-Studio/sigil`
- 两个二进制：`sigils`（server）与 `sigilc`（client）
- 服务端用 SQLite 保存证书、客户端、token 和 ACME 账户
- 客户端使用 mTLS 拉取证书并输出 PEM、DER、PKCS#12
- CLI 使用 Cobra，TUI 使用 Bubble Tea，本地控制使用 Unix socket / Windows named pipe
- Windows 容器开发和 E2E 使用 WSLC，不使用 Docker Desktop

## 仓库布局

```text
cmd/sigils/commands/       服务端 Cobra 命令与输出格式（装配在 internal/server）
cmd/sigilc/commands/       客户端 Cobra 命令、注册流程（装配在 internal/agent）
internal/acme/             lego ACME 封装
internal/agent/            sigilc daemon 组合根：客户端运行时、身份保存、IPC 控制
internal/api/              HTTPS API、安装脚本和 mTLS 中间件
internal/ca/               内部 mini-CA
internal/client/           拉取循环、push receiver、状态
internal/config/           严格 YAML schema 与校验
internal/enroll/           一次性 token、CSR 和身份保存
internal/ipc/              服务端与客户端本地控制 API
internal/output/           证书格式化与原子写入
internal/scheduler/        签发、续期和退避
internal/server/           sigils daemon 组合根：配置运行时、API、IPC、调度与有序关停
internal/securefile/       私钥配置的原子写入和 Windows DACL
internal/service/          系统服务安装与运行（非交互时经 kardianos 服务管理器）
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
3. 已注册客户端每次访问都必须同时通过 mTLS、数据库存在性和证书指纹匹配。删除客户端即撤销访问；除注册外，任何写路径（包括 heartbeat）都不得创建客户端记录。
4. `client.yaml` 包含客户端私钥。写入必须经过 `internal/securefile`：Unix 使用私有模式，Windows 使用受保护 DACL，且采用临时文件加原子替换。私有临时文件一律用 `securefile.CreateTemp` 创建：Windows 上在 `CreateFile` 时就带受保护 DACL，不能先建文件再收紧，因为收紧之前别的账户打开的句柄仍能读到之后写入的内容。
5. 私钥输出默认权限为 `0600`；公开证书可为 `0644`。不要对所有输出格式使用同一默认权限。Windows 上的私钥类输出（`pem-key`、`pem-bundle`、`pkcs12`）有几条额外规则：
   - 临时文件在 `CreateFile` 时就带受保护 DACL：SYSTEM、Administrators 和运行 sigilc 的账户完全控制，配置的 `owner` 只读。
   - `mode` 在 Windows 上不应用，不能放宽这个 DACL；只读属性还会让之后的替换失败。
   - `owner` 只有以 `S-`（不分大小写）开头且能解析时才按 SID 处理，否则按账户名查找。`BU`、`WD` 这类 SDDL 别名不能当成 SID。
6. 安装下载端点的 `os/arch` 必须保持字符白名单和目录 containment 双重检查。
7. PowerShell 安装脚本只能反射 canonical base64url 字符，响应必须 `Cache-Control: no-store`，不得再次把任意查询值拼入可执行脚本。（Phase 4 按 B3 改造后本条作废。）
8. 生产一键安装要求公网端点使用操作系统信任的 TLS 证书。通过 `server.tls_cert_file` 与 `server.tls_key_file` 配置；内部 mini-CA 默认证书不能让首次系统 `curl` 自动信任。
9. 服务端 push 只能向不含 userinfo、query 或 fragment 的 HTTPS endpoint 发送 bearer 鉴权请求，且不得跟随重定向或在错误日志中泄漏完整 endpoint。客户端 push listener 是明文 HTTP，只能监听字面量回环 IP；远程接入必须先由本机反向代理或隧道终止 TLS。listener 必须配置至少 32 字符 bearer token，使用常量时间比较，并合并并发通知，避免并发写证书和状态文件。（Phase 3 按 B1 改造后本条作废。）
10. 配置解析使用 `yaml.KnownFields(true)`。增加字段时必须同步 schema、验证和测试。`config.ReadServerPaths` 是只给 CLI 定位 IPC、给安装器找 data_dir 用的宽松读取函数，daemon 不得用它加载配置。`${VAR}` 和 `${VAR:-default}` 在 YAML 解析后逐个标量值展开：值原样插入、不 trim；键不展开；`$$` 表示字面 `$`；变量未设置且没有默认值时报错。三个解析入口（`ParseServer`、`ParseClient`、`ReadServerPaths`）必须得到一致结果。
11. 服务端只读 IPC 必须使用显式 DTO，不能在线路上返回证书私钥、push token 或 enrollment-token secret hash。
12. 数据库证书记录必须绑定有效配置指纹；CA directory、domains 或 key type 变化后，旧材料不得继续分发。

## 运行时约束

- `sigils` 与 `sigilc` 使用不同的 IPC 端点。客户端命令解析顺序为：显式 `--ipc`、`client.ipc_socket`、平台默认客户端 socket。
- `sigils reload` 必须通过本地服务端 IPC 完整解析并应用新配置。可热更新 `acme`、`dns_providers`、`certificates` 和 `clients` push routing；若 `server.listen`、`server.public_url`、`server.data_dir`、`server.ipc_socket`、`server.tls_cert_file` 或 `server.tls_key_file` 变化，必须拒绝 reload、保留旧运行配置并明确要求重启。
- 服务端 reload 与 periodic/manual issuance 必须共用同步点：旧 generation 的签发和 push 完成后才能发布新 generation；发布时清理旧 backoff，并立即唤醒 scheduler。（Phase 2 按 B2 改为每证书锁加落库时比对 spec 指纹。）
- `sigils token create` 由运行中的 daemon 经服务端 IPC 签发，daemon 未运行时报错，不再在 CLI 进程里直接写库；CLI 拒绝不支持新协议的旧 daemon 的应答。`cert add`/`cert remove` 改完 `server.yaml` 后通知 daemon reload。
- `sigilc fetch` 必须调用真实 IPC 拉取；`--cert` 只强制目标证书。`reload` 必须先完整解析新配置，失败时保留旧配置。
- sigilc 启动后和 reload 后，第一次完整拉取会重写全部订阅证书的输出；写失败的证书在后续拉取中重试，带名的 fetch 不会消耗这个重写标记。
- 客户端 mTLS 身份必须在到期前自动续签；`client.identity_renew_before` 默认 30 天，允许范围为 1 小时到 89 天。
- periodic、push 和 IPC 拉取必须由同一把锁串行化。
- 客户端 socket 在 Unix 上固定为 `/var/run/sigil/sigilc.sock`，不能依赖启动用户的 `$HOME`。
- 服务端外部 HTTPS 可使用公网证书，但客户端证书仍由内部 mini-CA 验证。客户端验证服务端时同时信任系统根和 mini-CA。
- SQLite 和 WAL 包含私钥材料，创建与重开时都必须保持私有权限。

## 平台约束

- 平台差异使用 build tag 文件，例如 `_windows.go` 与 `_unix.go`。
- Windows 的 `os.Chmod(0600)` 不能替代 DACL。
- Windows 安装脚本必须区分 AMD64、ARM64 和 x86。
- Windows 上 daemon 必须以 LocalSystem 或提权管理员身份运行。IPC 客户端只信任属主为 SYSTEM 或 Administrators 的命名管道，校验在发出请求之前完成。有管理员权限的 `Listen` 会显式把属主设为 Administrators；不指定属主时，属主取令牌的默认属主，Git Bash 下会变成用户 SID。
- Windows 服务（2026-09-27 真机实测）：
  - 正常启停退出码为 0，不会触发恢复动作。
  - 启动即失败时 `ExitCode=1067`，失败原因写在 Application 日志，来源为服务名 `sigils`/`sigilc`。
  - `service install` 会写入恢复动作：失败后 10 秒重启，失败计数 24 小时清零。这种情况下 System 日志记 7031，服务会以新进程重新拉起；没有恢复动作的旧安装只记 7034、停在 Stopped，要重新安装服务才会带上恢复动作。
  - 事件写入后有时要过几秒才查得到，脚本不能查一次为空就下结论。
  - 未握手的旧版本会等到 SCM 超时（本机 90 秒）后报 1053。
  - `service uninstall` 会一并删除事件日志源。
- WSLC 2.9.4 每个会话最多挂载 15 个**不同的主机路径**（2026-09-27 实测）：
  - 按会话存活期间出现过的不同路径计数，与容器数无关，同一路径重复挂载不另计。
  - 其中 3 个被 WSL 自身的 virtiofs 共享占用，用户可用 12 个；`wslc build` 的构建上下文目录也占一个。
  - E2E 每轮都把固定目录 `%TEMP%\sigil-wslc-e2e` 挂到 `/e2e`，本轮文件放在其下的 `run-*` 子目录，结束时只删子目录。所以跑多少轮都只占 2 个名额：挂载根和构建上下文。
  - 新增挂载或镜像构建时，主机路径必须在各轮之间保持不变。
  - 满额时报 `装入的卷太多 (限制： 15)`；确认没有容器和网络后，可以用 `wslc system session terminate` 重置空闲会话。
  - 每个 worktree 根作为构建上下文时路径都不同，在同一会话里各占一个名额。
- WSLC 容器网络与构建（2026-09-27 实测，WSLC 2.9.4）：
  - 同一网络内，网络别名在所有容器里都能解析，容器之间 DNS 的 UDP 和 TCP 都通。
  - 需要容器 IP 时，从 `wslc inspect <容器>` 的 `NetworkSettings.Networks.<网络名>.IPAddress` 取。
  - `wslc build` 走 BuildKit：构建时拉取的基础镜像只在 BuildKit 存储里，`wslc images` 看不到；构建缓存在 `rmi` 之后仍然有效；没有 builder prune 命令。
  - 构建上下文的大小不影响耗时，开销在 `COPY . .` 的缓存失效：上下文里任何文件变了，sigils 和 sigilc 各要重编约 12–15 秒。
- 本机 Git for Windows 的 curl（Schannel）校验私有根时会报 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`，要加 `--ssl-no-revoke`；Go 写的 harness 不受影响。
- 不运行或依赖 Docker Desktop。需要容器验证时直接调用 `wslc`。

## 已知未完成项

- ACME 真实 DNS provider 的容器 E2E 尚未建立；现有 E2E 用生成证书验证注册和分发安全链。
- TUI 仍有部分管理操作未接线。
- 2026-09-27 审阅发现的缺陷 A1–A13 见审阅文档，修复进度见 `TODO.md`。
- go-winio v0.6.2 的管道 listener `Close` 有竞态，可能永久阻塞。ipc 测试里用限时关闭绕开；生产上 `sigils` 停机时，如果恰好有 IPC 客户端连入，服务可能停不下来。修复要等升级到 Go 1.26，见 `TODO.md`。

## 修改原则

- 先读现有实现和测试，再做局部改动；不要把未实现功能写成已完成。
- 安全边界、跨模块契约和用户工作流必须增加回归测试。
- 手工文件修改使用 `apply_patch`。
- 仓库已于 2026-09-27 初始化 Git（基线提交 `d0151bf`，`.gitattributes` 固定 LF）；变更可用 `git diff` 审阅，验证仍以格式化、单元测试、静态检查和 WSLC E2E 为准。
- 容器测试结束后确认 WSLC 容器与网络为空，并移除本轮生成的镜像。
