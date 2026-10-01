# AGENTS.md

项目：**Sigil**，面向服务器集群的 ACME 证书签发与分发工具。

## 当前状态

项目处于持续开发阶段。核心注册、mTLS 鉴权、长轮询交付与每轮对账、`on_change` 钩子、并行签发引擎、exec DNS provider、ARI 驱动的续期、HTTPS 证书热更新、服务端与客户端 TUI、slog 日志与事件环形缓冲、两个二进制的 `events` 命令均已可用，并有 WSLC 黑盒测试（含从 Pebble 真实签发并覆盖 ARI）。各家云 DNS provider 的 E2E 仍未完成。

部署前审查各路修复（S、A、C、D、L、P、W、I、Z）及 TUI 迁到 Charm v2（T 路）已全部合入，正在做最终验证（两套 E2E 和实机验证）。余项按 `TODO.md` 跟踪。

## 重构方向（2026-09-27 拍板）

审阅文档未公开（缺陷编号 A1–A13、决定编号 B1–B4、C1 均出自该文档）。以下决定均已落地。

- B1（Phase 3）：服务端推送改为客户端长轮询 `/v1/sync`。
- B2（Phase 2）：取消全局签发锁，改为每张证书一把锁、有上限的并行签发。
- B3（Phase 4）：PowerShell 安装改为静态脚本，服务端不再把请求参数写进脚本。安装命令为 `[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm '<url>/install.ps1'))) -Token '<token>'`，`-bor 3072` 使 PowerShell 5.1 协商 TLS 1.2，服务端最低接受 TLS 1.2。安全约束 7 随之作废。
- B4（Phase 3）：删除 `/v1/heartbeat`，由 mTLS 鉴权中间件刷新 `last_seen`。
- C1（Phase 3）：客户端每张证书可配置 `on_change` 钩子。
- C2（Phase 4）：续期时点改为比例规则，并接入 ARI（RFC 9773）。删除 `renew_days_before`。
- D1–D8（Phase 4 新发现缺陷）：D1 HTTPS 证书热更新、D2 服务端 TLS 下限降到 1.2、D3 删除不存在的对象返回 404、D4 install.ps1 修复、D5 slog 接管所有日志、D6 到货即到期防护（极短寿命证书不支持，见已知未完成项）、D7 `public_url` 缺失时拒绝签发令牌、D8 `token list` 列宽修正。均已修复。
- 保留不动：mTLS + 数据库指纹鉴权、一次性令牌绑定、`subscribers` 唯一授权来源、客户端本地输出配置、spec 指纹绑定、`securefile`、严格 YAML。

### 部署前审查（2026-09-29 启动）

用户拍板 4 项：令牌经环境变量和交互输入传递，不再只能走命令行；令牌长度保持现状；安装脚本幂等（已安装时重装，另加 `--upgrade`）；同名令牌必须显式 `--replace`。

主会话已定：`cert add`/`cert remove` 改走 IPC；Windows `owner` 只加只读 ACE 不改属主；关停上界 30 秒；mini-CA 根证书不足 1 年时记 WARN；`acme.email` 变化只更新联系人不换 key；签发结果校验叶子公钥和 DNSNames；非 systemd 的 Linux 和 macOS 的部分行为标注为未验证。

各项细节见安全约束、运行时约束和已知未完成项。

## 项目快览

- Go 1.26.8，模块：`github.com/Oganneson-Studio/sigil`。go.mod 是 Go 版本的唯一来源：CI 用 `go-version-file: go.mod`，E2E 镜像用 `golang:1.26-alpine`。
- go-winio 用的是未发版的 main 快照 `7e8af9b`（修复了管道 listener `Close` 的竞态：v0.6.2 下 `sigils` 停机时，如果恰好有 IPC 客户端连入，可能永久阻塞）。上游发版后换成正式 tag，见 TODO。
- 两个二进制：`sigils`（server）与 `sigilc`（client）。
- 服务端用 SQLite 保存证书、客户端、token 和 ACME 账户。
- 客户端使用 mTLS 拉取证书并输出 PEM、DER、PKCS#12。
- CLI 使用 Cobra，TUI 使用 Charm v2（`charm.land/bubbletea/v2`、`lipgloss/v2`、`bubbles/v2`，基于 `Backend` 接口），本地控制使用 Unix socket / Windows named pipe。v1 与 termenv 已删除；非 TUI 命令不再向终端发查询序列（v1 的 init 会发 OSC 11 和 CSI 6n，经 sudo 时应答成乱码）。
- 日志使用 slog，最近 500 条事件保存在环形缓冲（`logging.Ring`），经 IPC 和 `events` 命令读取。`internal/renewal` 是叶子包，scheduler、`server/tls.go` 和 client（sigilc）用它，不引入 lego，新增依赖时注意二进制体积。`internal/proc` 也是叶子包，钩子和 exec DNS 共用（有界尾部输出、结束进程树、WaitDelay），只依赖标准库和 `x/sys`。
- kardianos v1.3.0。systemd 单元用 `SystemdScript` 选项替换 kardianos 的默认模板，含 `KillMode=mixed`。
- Windows 容器开发和 E2E 使用 WSLC，不使用 Docker Desktop。

## 仓库布局

```text
cmd/sigils/commands/       服务端 Cobra 命令与输出格式（装配在 internal/server）
cmd/sigilc/commands/       客户端 Cobra 命令、注册流程（装配在 internal/agent）
internal/acme/             lego ACME 封装与 ARI 查询
internal/agent/            sigilc daemon 组合根：客户端运行时、身份保存、IPC 控制
internal/api/              HTTPS API（含 `/v1/sync` 长轮询）、安装脚本和 mTLS 中间件（含 last_seen 节流）
internal/ca/               内部 mini-CA
internal/client/           sync 长轮询循环（每轮对账）、私有本地存储、on_change 钩子、状态
internal/config/           严格 YAML schema 与校验
internal/enroll/           一次性 token、CSR 和身份保存
internal/ipc/              服务端与客户端本地控制 API
internal/logging/          slog handler、环形缓冲、Private 标记、Recoverer、终端安全
internal/output/           证书格式化、输出比对与按证书成组的原子替换
internal/proc/             叶子包：钩子与 exec DNS 共用的进程管理（尾部 4 KiB 输出、结束进程树、WaitDelay）
internal/renewal/          叶子包：比例续期规则（sigilc 和 ipc 也用，不引入 lego）
internal/scheduler/        签发、续期、ARI 和退避
internal/server/           sigils daemon 组合根：配置运行时、API、IPC、调度与有序关停
internal/securefile/       私钥配置的原子写入和 Windows DACL
internal/service/          系统服务安装与运行（非交互时经 kardianos 服务管理器）
internal/store/            SQLite repositories
internal/tui/              server/client TUI（Charm v2，基于 Backend 接口）
internal/version/          构建版本（ReadBuildInfo + ldflags 覆盖）
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
go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

E2E 命令必须加 `-count=1`。E2E 经 `wslc build` 读取仓库文件，Go 的测试缓存看不到这些读取，改完代码再跑会命中缓存报告 `(cached)` 通过。

E2E 不依赖 Compose 或固定 IP。它构建临时镜像、创建随机命名网络、通过网络别名连接，用 Pebble + challtestsrv + exec DNS hook 真实签发证书，执行注册/拉取/renew/吊销/token 测试，并测 sync 交付延迟、输出对账与自动恢复、on_change 和 reload 唤醒、ARI 窗口跟随与 ARI 驱动的续期，并按精确名称清理资源。其中"自动恢复"一步固定约 55 秒。WSLC 热跑约 132–140 秒（2026-10-01 实测）；Linux Docker 约 171 秒，首次拉基础镜像时约 189 秒。WSLC 构建不走宿主代理，依赖变动后首次构建可能因网络超时失败，重试即可。

Linux Docker（以 docker 组里的普通用户运行，不加 sudo）：

```bash
SIGIL_CONTAINER_CLI=docker SIGIL_E2E_REQUIRED=1 go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

不设 `SIGIL_E2E_REQUIRED=1` 时，在 Linux 上找不到容器运行时会直接以 0 退出，成了假通过。Windows 必须使用 WSLC。

竞态测试需要 CGO：

```powershell
go test -race ./...
```

如果当前 Go 环境 `CGO_ENABLED=0`，应明确报告无法运行，不能把它写成已通过。Windows 上全量验证要在提权 shell 里跑；提权 PowerShell 和提权 Git Bash 下都 skip 2 个（POSIX 权限位测试，Linux 上会运行）。IPC 相关的 skip 必须为 0，出现就说明 shell 没提权。

在 `.claude/worktrees/*` 里构建的二进制，`vcs.revision` 是主工作区的提交，不是 worktree 自己的 HEAD。发版构建要在普通 clone 里做，或用 `-ldflags -X` 显式设置版本。

CI：`.github/workflows/test.yml` 跑 Linux 全量测试、race、vet（含 `GOOS=windows`）、e2e tag vet、govulncheck v1.8.0，以及 Windows 全量测试（要求提权 shell，非提权即失败）。`.github/workflows/e2e.yml` 跑 E2E（已加 `-count=1`）。仓库没有 remote，workflow 只经 actionlint v1.7.12 校验过。

## 安全约束

1. `server.yaml` 的 `certificates[].subscribers` 是订阅授权的唯一来源；客户端输出配置不能扩大授权。
2. 注册 token 是一次性的，并绑定 secret、server URL、客户端名和 mini-CA 证书。客户端发送 token 前必须验证 TLS，禁止恢复 `InsecureSkipVerify`。注册请求不跟随重定向（`CheckRedirect` 返回 `ErrUseLastResponse`）。`EnrollResponse` 不再带 `ca_cert`，sigilc 保存令牌里的 CA 证书，并校验返回的客户端证书（CN、链到令牌 CA、ClientAuth EKU、公钥等于 CSR）。CSR 格式有问题回 400、不消耗令牌。服务端回 200 后 sigilc 用不了应答（`ErrUnusableAnswer`：解码失败或证书校验失败）或写 client.yaml 失败时，报错写明令牌已被消耗并给出 `sigils token create --name <name> --replace`。注册和身份续签校验返回证书时按 NotBefore 校验链，不按本机时钟判断有效期，不许改回按本机时钟校验（证书必须持有本次 CSR 的公钥，旧证书无法重放）。
3. 已注册客户端每次访问都必须同时通过 mTLS、数据库存在性和证书指纹匹配；挂起的 `/v1/sync` 被唤醒后、返回新清单前要再校验一次。删除客户端即撤销访问；除注册外，任何写路径（包括鉴权中间件刷新 `last_seen` 的条件 UPDATE）都不得创建客户端记录。续签期间同名客户端被重新注册时，旧身份的续签回 401（`StagePendingIdentity` 带出示证书指纹条件）。
4. `client.yaml` 和客户端本地存储 `<data_dir>/certs.json` 都包含私钥。写入必须经过 `internal/securefile`：Unix 使用私有模式，Windows 使用受保护 DACL，且采用临时文件加原子替换。私有临时文件一律用 `securefile.CreateTemp` 创建：Windows 上在 `CreateFile` 时就带受保护 DACL，不能先建文件再收紧，因为收紧之前别的账户打开的句柄仍能读到之后写入的内容。certs.json 加载时若已存在，先用 `securefile.ProtectFile` 收紧；它的路径不能由服务端下发的证书名派生。`client.data_dir` 和私钥类输出必须放在能存住 Unix 权限位的文件系统上，否则私有模式形同虚设；WSL drvfs/9p（没开 metadata）、没有 unix extensions 的 CIFS、vfat/exfat 和 WSLC 的 bind mount 都存不住。
   - 目录检查在启动时做，reload 不复查。Windows 上配置目录和 sigilc `data_dir` 的属主须为 SYSTEM、Administrators（或非提权时的当前用户），其他主体不得有写入、删除、删子项、改 DACL、改属主权限。sigils `data_dir` 在 Windows 上须完全私有（继承项也算），Unix 上 `mode&077==0` 且属主为运行用户。不合规拒绝启动，报错点名目录并给出 `icacls`/`chmod`/`chown` 命令。`ca\` 子目录的检查在 `ca.Bootstrap` 中。
   - data_dir 不存在时由 `EnsurePrivateDirectory` 私有创建；已存在的 data_dir 只检查不收紧。`ca\` 是例外：`ca.Bootstrap` 先 `CheckDirectory` 再 `EnsurePrivateDirectory`，每次启动都重设受保护 DACL。经 `privateDescriptor` 创建的对象（`securefile.CreateTemp` 的文件和 `EnsurePrivateDirectory` 新建的目录）在提权时属主为 Administrators，不带操作者本人 SID。`ProtectFile` 只换 DACL，保留属主。sigils.db 和 -wal/-shm 的属主取进程默认属主：以服务运行时是 SYSTEM，在提权 PowerShell 下通常是 Administrators，在 Git Bash 里提权交互运行时是本人 SID（MSYS 会改变令牌的默认属主）。
   - 配置目录和 data_dir 的每一级上级目录都不得归其他账户所有，也不得让其他账户删改子项；检查只看最后一级，默认布局满足。输出文件所在目录及其上级也不能让低权限账户可写（`O_NOFOLLOW` 只保护最后一段路径）。
5. 私钥输出默认权限为 `0600`；公开证书可为 `0644`。不要对所有输出格式使用同一默认权限。对账重写输出时按证书成组暂存：内容、权限位和属主先在临时文件上就位，全部暂存成功才依次改名替换，不能先改名再 chown。Windows 上的私钥类输出（`pem-key`、`pem-bundle`、`pkcs12`）有几条额外规则：
   - 临时文件在 `CreateFile` 时就带受保护 DACL：SYSTEM、Administrators 完全控制（非提权时另加当前用户），配置的 `owner` 只读。`owner` 不改属主，只加只读 ACE。
   - `mode` 在 Windows 上不应用，不能放宽这个 DACL；只读属性还会让之后的替换失败。
   - `owner` 只有以 `S-`（不分大小写）开头且能解析时才按 SID 处理，否则按账户名查找。`BU`、`WD` 这类 SDDL 别名不能当成 SID。`owner` 只对私钥类输出生效，其他格式忽略且不报错。
6. 安装下载端点的 `os/arch` 必须保持字符白名单和目录 containment 双重检查。下载使用 `ServeContent`（提供 Content-Length 和 Range），单次响应写截止 10 分钟（`downloadWriteTimeout`）；未鉴权慢读者最多占一条连接 10 分钟。
7. （已作废：Phase 4 按 B3 将 install.ps1 改为静态脚本。保留编号，避免引用错位。）
8. 生产一键安装要求公网端点使用操作系统信任的 TLS 证书。通过 `server.tls_cert_file` 与 `server.tls_key_file` 配置；内部 mini-CA 默认证书不能让首次系统 `curl` 自动信任。
9. （已作废：Phase 3 按 B1 删除了服务端 push 和客户端 push listener。保留编号，避免引用错位。）
10. 配置解析使用 `yaml.KnownFields(true)`。增加字段时必须同步 schema、验证和测试。所有路径字段（`server.data_dir`、`tls_cert_file`、`tls_key_file`、`ipc_socket`、gcloud 的 `service_account_file`；`client.data_dir`、`ipc_socket`、`outputs[].path`；`on_change` 和 exec 的 `argv[0]` 原本就要求）必须是绝对路径，`${VAR}` 展开后校验，报错 `<字段>: must be an absolute path, got "<值>"`。Windows 上 `\dir`、`C:dir` 不算绝对；命名管道和 UNC 算绝对，ipc_socket 要写完整的 `\\.\pipe\...`。`config.ReadServerField(path, key)` 和 `config.ReadClientField(path, key)` 是逐字段宽松读取函数，共用 `readField` 逐字段展开和校验；CLI 定位 IPC 和安装器找 data_dir 使用，daemon 不得用它们加载配置。`sigilc enroll` 也用 `ReadClientField` 比对 name/server_url。`${VAR}` 和 `${VAR:-default}` 在 YAML 解析后逐个标量值展开：值原样插入、不 trim；键不展开；`$$` 表示字面 `$`；变量未设置且没有默认值时报错；嵌套默认值 `${A:-${B}}` 报错。四个解析入口（`ParseServer`、`ParseClient`、`ReadServerField`、`ReadClientField`）必须得到一致结果。client.yaml 的 `client.name` 和 `certificates` 键按同一命名规则校验。
11. 服务端只读 IPC 必须使用显式 DTO，不能在线路上返回证书私钥或 enrollment-token secret hash。IPC 上没有写证书的路由，证书只能经签发进入数据库。事件环里不含令牌字符串（只记令牌 ID）、私钥、配置结构体或 panic 栈（Recoverer 记 method、path 和 panic 值，栈以 `Private` 标记）；钩子和 DNS 程序的输出以 `Private` 标记，在事件和 Windows 事件日志中显示为 `(withheld)`，只有服务日志（stderr / journald / launchd 的 `/var/log/<name>.err.log`）保留最后 4 KiB。
12. 数据库证书记录必须绑定有效配置指纹；CA directory、domains 或 key type 变化后，旧材料不得继续分发。
13. `exec` DNS provider 只能在 server.yaml 中配置。它以 sigils 服务账户运行、继承其全部环境变量（包括 `${VAR}` 引用的凭据），单次运行 2 分钟超时。
    - 记录名在运行前校验：每个 label 只能是 `[A-Za-z0-9_-]`、非空、不以 `-` 开头，否则报错 `exec: <action>: record name %q is not a host name`，程序不启动。
    - 超时或 ctx 结束时连同它启动的进程一起结束（Unix 进程组，Windows Job Object）；正常退出后留下的进程在两个平台上都继续运行。
    - 错误信息只含动作、记录名和退出状态或超时，启动失败时另带 argv[0]。
    - argv[1:] 和脚本输出永远不进入错误。输出被占按失败处理，完整错误格式为 `exec: <action> <record>: exit status 0, but a process it started still holds its output`。
    - 脚本输出只在失败时写服务日志（尾部 4 KiB），不进事件。
    - exec DNS 程序用 `acme.NewIssuer` 收到的 programs ctx（`server.Run` 里由 `context.WithoutCancel` 派生），`server.Run` 返回时才取消；它既不是 daemon 的 ctx，也不是 `Issue` 的 ctx。
14. 来自 ACME CA 和 DNS provider 的错误文本，写入 `issuance_status.last_error` 或经 IPC 返回之前，必须先经 `logging.OneLine` 替换控制字符和非法 UTF-8，再经 `logging.RedactURLQueries` 将 URL 的 query 替换为 `?REDACTED`，最后截断到 1 KiB。事件渲染路径（Ring 和 Windows 事件日志的 Message 与 Attrs）同样做 URL query 脱敏；journald sink 保留原文。ARI 查询的错误文本进事件和 `last_error` 前走同一净化流程。
15. `on_change` 只能在 client.yaml 配置，argv 形式、argv[0] 为绝对路径、不经 shell。服务端下发的内容（包括证书名）不能影响执行什么、写到哪里。
    - 它以 sigilc 服务账户运行、继承其全部环境，stdin 为空，单次运行 2 分钟超时；超时或 daemon 停止时连同孙进程一起结束（Unix 进程组，Windows Job Object）；正常退出后留下的进程在两个平台上都继续运行。IPC 调用方断开不影响它。
    - 错误信息只含证书名和退出状态或超时，启动失败时另带 argv[0]；argv[1:] 和钩子输出永远不进入错误。钩子输出是 `on_change failed` 事件的 `Private` 属性，事件和 Windows 事件日志中显示为 `(withheld)`，只有服务日志（stderr / journald / launchd 的 `/var/log/<name>.err.log`）保留最后 4 KiB。Windows 服务下服务日志就是事件日志，`Private` 同样显示为 `(withheld)`，所以哪里都不记录钩子输出，钩子脚本必须自己记日志。
    - 以 0 退出但输出仍被占用时，最多再等 5 秒关闭管道、按成功处理并记 WARN `on_change output held open`（exec DNS provider 在这种情况下按失败处理）。钩子留在后台的进程必须自己重定向 stdout、stderr。
    - 钩子持续失败时，sync 循环退避（5 秒起翻倍、封顶 5 分钟），稳定在约每 5 分钟重试一次。Windows 上每次失败都写一条 Application 事件日志。
16. sigilc 打印或经 IPC 交出的文本不得携带来自网络的控制字符（与第 14 条对称）。`Printable`/`OneLine` 同时替换 Cf（零宽字符等）、Zl（行分隔符）、Zp（段分隔符）。TLS 握手错误会原样引用对端证书的 DNS 名（`crypto/x509` 先校验主机名后建链，中间人不需要可信证书），服务端的响应和下发的证书名同样不可信。处理方式：
    - `LastError` 与 Fetch、Reload 经 IPC 返回的错误离开 client 包前经 `client.printable`：`errors.Join` 的每个子错误各自 `logging.OneLine`（DEL 和 C1 换成空格，非法 UTF-8 换成 U+FFFD），再用 `\n` 拼接，网络文本里的 `\n` 也会被替换，从而无法伪造整行。不要改成直接调 `logging.Printable`，否则 `\n` 会保留。`sigilc enroll` 的网络错误整体经 `logging.OneLine`。错误仍能 `Unwrap` 到原错误。
    - 两个 CLI 的 main 打印错误时经 `logging.Printable`。
    - 视图里不合规的证书名计为本轮错误、按未列出处理、已存材料一并删掉。
    - 注册 token 在解码时校验 name（`config.ValidateClientName`）和 server_url（`config.ValidatePublicURL`），在写 client.yaml 之前完成。
    - 客户端拒绝格式不是 `sha256:` 加 64 位 hex 的 bundle fingerprint。
17. 命名规则与 `server.public_url`：
    - server.yaml 里所有名字（证书名、`acme.cas` 的键、`dns_providers` 的键）与客户端名同一规则：小写 DNS label，1 到 63 个 `a-z0-9-`，不以 `-` 开头或结尾。`config.ValidateClientName`、`config.ValidateCertificateName` 和 `validateName` 共用实现。
    - `server.public_url` 只能是纯 ASCII 的 https URL，必须有 host，不能含 userinfo、query、fragment，有端口时必须 1–65535，不能含单引号、双引号、反引号、`$`、`\`、空白和控制字符（`config.ValidatePublicURL`）。PowerShell 把 U+2018–U+201B 当作单引号、U+201C–U+201E 当作双引号，只拒绝 ASCII 引号不够。`public_url` 未设置时，`token create` 对由 listen 推出的 URL 做同一检查，不通过则提示设置 `server.public_url`。
    - `server.listen` 必须是 `host:port` 格式，端口 1–65535，主机部分可以为空（`:8443` 合法）。
18. 安装脚本是静态的，不读请求参数。install.ps1 只含 ASCII，不调用 `exit`（在 `& ([scriptblock]::Create(...))` 调用方式下 `exit` 会关掉操作者的 PowerShell 会话），每次调用 native 程序后检查 `$LASTEXITCODE`，下载用 `-UseBasicParsing`。install.sh 的 curl 带 `-q --proto '=https' --proto-redir '=https'`；令牌经 `SIGILC_TOKEN` 环境变量传给 sigilc（ps1 同样经 `$env:SIGILC_TOKEN`，用完 `Remove-Item`），不进 argv；下载先写临时文件再 `mv -f` 替换。安装脚本的静态反向断言（`install_script_test.go`）守住这些不变量，但只防无意回归，不能穷尽各种写法。
19. 服务端 HTTPS 的最低 TLS 版本为 1.2（`tls.VersionTLS12`），只是为了 PowerShell 5.1 的安装脚本和老系统。sigilc 的注册（`internal/enroll`）和所有 mTLS 请求（`internal/client`）钉死 TLS 1.3，不许放宽，由 `tls13_test.go` 守住。
20. `acme.RenewalInfo` 用临时密钥拉取 ACME 目录和 renewalInfo，不用账户、不碰数据库；查询期间不持任何锁。只有 ARI 到货即到期防护会写库（`storeGuard`）：在 genMu 读锁下开事务，先比对库里的证书指纹，还是同一张证书才写 `issuance_status`，已经被新证书替换就不写。`replaces` 只在纯续期（存储的材料与当前 spec 匹配）且最近一次尝试没有失败（`Failures == 0`）时带给 lego，lego 遇到 409 `alreadyReplaced` 会自动去掉重发。

## 运行时约束

- `sigils` 与 `sigilc` 使用不同的 IPC 端点。CLI 定位 IPC 端点的规则（`serverIPCSocket` / `clientIPCSocket`，sigils 和 sigilc 一致）：有 `--ipc` 就用它；配置文件不存在、没有读权限、或 ipc_socket 为空时用平台默认端点；ipc_socket 读不出来（相对路径、变量未设置、YAML 解析失败）直接报错，格式为 `read the IPC endpoint from <文件>: <内层错误> (pass --ipc to give it instead)`，内层错误来自 `readField`，例如 `parse <文件>: ...` 或 `<section>.ipc_socket: ...`。
- `sigils reload` 必须通过本地服务端 IPC 完整解析并应用新配置。可热更新 `acme`、`dns_providers` 和 `certificates`（含 subscribers）；若 `server.listen`、`server.public_url`、`server.data_dir`、`server.ipc_socket`、`server.tls_cert_file`、`server.tls_key_file` 或 `acme.dns_resolvers` 变化，必须拒绝 reload、保留旧运行配置并明确要求重启（TLS 文件路径和 listen 地址在启动时固定，文件内容的更新由 `tlsSource` 在每次握手时自动处理）。`acme.dns_resolvers` 需要重启，是因为 lego 把它存在进程级全局变量里。
- 服务端 HTTPS 证书热更新（`tlsSource`）：
  - 配置了 `tls_cert_file` 时，每次握手都 stat 证书与私钥文件，一旦修改时间或大小变化就重新加载。加载失败（例如替换到一半）则继续用旧证书。每次文件变化只尝试加载一次、只记一次日志（成功记 INFO `server TLS certificate reloaded`，失败记 WARN `server TLS certificate not reloaded`，stat 失败同理）。证书与私钥文件要放在本地盘；网络文件系统上 stat 一旦卡住，`tlsSource` 的 mutex 会拖住所有握手。
  - mini-CA 模式下，在 `renewal.RenewAt` 到点时重新签发。签发失败后至少隔 1 分钟（`reissueRetry`）再试，连续失败只记一次 WARN `server TLS certificate not reissued`。
- 服务端签发按证书加锁：
  - 同一张证书同一时刻最多一个签发：周期 tick 遇到在途签发即跳过；`sigils cert renew` 等它结束后再强制签发。全局并行上限为 `maxConcurrentIssuance`（4）。
  - 签发结果落库前，在 generation 读锁下按名字从当前运行配置重新取 spec 计算指纹，与下单前捕获的指纹比对。不一致或证书已删除，就丢弃结果（记 WARN `issued certificate discarded`）并立即唤醒 scheduler。
  - generation 读锁内只允许 `current()`、指纹计算和毫秒级的 DB 写；唤醒 `/v1/sync` 的通知和一切网络调用必须在锁外。
  - 旧 generation 的失败、ctx 取消导致的失败都不计入退避。
  - reload 不等待在途签发：只在 generation 写锁下清零所有证书的持久化退避（保留最近错误 `LastError`）、原子发布新配置并立即唤醒 scheduler。
  - 每证书退避（5 分钟起、翻倍、封顶 24 小时）与最近错误存 `issuance_status` 表，重启不清零；调度定时器按最早的下次尝试时间唤醒。
  - 失败记入退避后立即唤醒 scheduler 重算定时器；退避写库失败则不唤醒，以免立即重试。
  - 因为退避持久化，改配置加重启不会清零退避；修好原因后用 `sigils reload` 或 `sigils cert renew`。
  - 传给 `Issue` 的 ctx 必须可取消，`WithoutCancel` 只用于收尾的 DB 写入。
  - `save` 使用 `BeginTx` 事务，两次 Upsert 都传 tx 后 Commit。事务内不能有任何其他调用（`SetMaxOpenConns(1)` 下，传 `tx == nil` 的调用会死锁）。
- 续期时点：
  - 有有效的 ARI 窗口时，在窗口内均匀随机取一个时点续期（来源 `ari`）；窗口不变则时点不变。没有 ARI 时，用比例规则 `renewal.RenewAt`：剩 1/3 寿命时续期，寿命不足 10 天的剩 1/2 时续期（来源 `ratio`）。续期时点已经过去就立即续期。
  - `renew_days_before` 已删除。
- ARI 状态只存内存，重启后每张证书重查一次、`pick` 重新随机：
  - 只查材料匹配、未过期、不在签发中、`nextCheck` 已到的证书。新证书落库后立即查（`nextCheck` 为零）。
  - 单 goroutine 逐张查询，不持任何锁（genMu、ariMu 和证书锁都不持），不计入 `wg`（关停时不等）。ctx 结束后不再发起新的查询。
  - Retry-After 夹在 [1 分钟, 24 小时]，CA 没给时按 6 小时；超时按 1 小时后重查；其他错误（含 5xx，lego 拿不到 HTTP 状态码）按 6 小时后重查，保留原窗口。`ErrNoRenewalInfo`（目录没有 `renewalInfo` 或证书没有 AKI）按 24 小时后再查一次并回到 ratio。
  - lego 不检查 `renewalInfo` 响应的状态码，窗口由 `acme.RenewalInfo` 自己校验（`End > Start` 且 `Start < NotAfter`）。
  - reload 让所有证书立即重查 ARI。一轮查询结束后唤醒调度。
  - `ariMu` 是叶子锁，`RenewalPlan` 只拿 `ariMu`。
  - 到货即到期的 ARI 防护：某个 fingerprint 第一次查到窗口且 End 已不晚于 now 时，按失败退避（`errWindowPassed`），`pick` 设为退避结束时刻；只对本进程签出的证书（`IssuedAt >= started`）生效；`ariTrips` 内存计数按证书名翻倍退避，查到 End 晚于 now 的窗口、或以 ratio/manual/new 落库时清零；重启清零。防护写库经 `storeGuard`：在 genMu 读锁下开事务，先比对库里的证书指纹，已被新证书替换就不写（见安全约束 20）。reload 清掉库里的退避，但窗口不变时内存里的 `pick` 仍挡住续期；要立即续期用 `sigils cert renew`。
- wakeAt 取以下时间里将来最早的一个，再与"每小时 ± 抖动"比较取较早者：退避中的 `NextAttemptAt`、各证书的 `RenewalPlan` 时点、需要查询的证书的 `nextCheck`。显式唤醒点：ARI 查询 goroutine 结束时、签发落库成功后、reload 之后、记录失败并退避之后。
- 到货即到期防护：`renewal.RenewAt(result.Certificate)` 出错或 `≤ now` 时，证书照常落库，然后在同一事务里写失败状态（`failures = prev+1`，翻倍退避），错误信息为 `issued certificate was stored, but is already due for renewal (lifetime ..., renewal due ...)`。`sigils cert renew` 此时以非零退出码返回（IPC 422），但证书已交付。
- ACME 账户初始化按 CA 名加锁（账户记录以 CA 名为主键），从取或建 key 一直锁到 register 完成，下单前释放。读账户库出错时原样返回，不新建 key、不覆盖记录；只有库里的 registration JSON 损坏时，才用同一把 key 重新注册来修复。`acme.email` 变化只用 `UpdateRegistration` 更新联系人，不换 key；只有 directory 变化才换 key，key 在注册成功后才落库。注册或 `UpdateRegistration` 成功后落库不受取消影响（`WithoutCancel`），关停或 Ctrl-C 不会丢新 key。
- `GET /ipc/v1/certs`（即 `sigils cert list/show`）按运行配置顺序列出配置中的证书：
  - `not_after`、`fingerprint`、`renew_at`、`renew_source` 等材料字段，只在库中记录的 spec 指纹与当前配置一致时才填写。
  - 已从配置删除的证书，库里残留的记录不列出。
  - state 优先级为 issuing > backoff > valid > pending。
- `sigils token create` 由运行中的 daemon 经服务端 IPC 签发，daemon 未运行时报错，不再在 CLI 进程里直接写库；CLI 拒绝不支持新协议的旧 daemon 的应答（缺 `token_id`）。`public_url` 为空且 `listen` 的主机部分为空或是 `0.0.0.0`、`::` 时，拒绝签发并提示设置 `server.public_url`。名字已注册或有未用未过期令牌时要 `--replace`（IPC 409）；`--replace` 先吊销同名所有未用令牌，`--json` 字段为 `token`/`token_id`/`expires_at`/`revoked`（0 时省略）/`install_sh`/`install_ps1`；人读输出多 `Token ID:` 和 `Expires:` 两行。寿命上限 168 小时由 daemon 执行。
- `cert add`/`cert remove` 由 daemon 经服务端 IPC 修改 server.yaml 并立即应用（与 reload 语义一致），daemon 未运行时报错。应用失败时把 server.yaml 写回原字节。文件里已有需要重启的手工改动时拒绝、文件不动。IPC 状态码：`cert add` 成功 201、请求体解析失败 400、其他失败（名字重复、校验不通过、需要重启的改动、应用失败）422；`cert remove` 成功 200、配置里没有这个名字 404、其他失败 422。回写 server.yaml 时 Unix 保留模式和属主、写到符号链接目标；Windows 不保留属主，文件改为私有 DACL；空行丢失已接受（yaml.v3 的限制）。
- 删除不存在的客户端返回 404（body `client "x" is not enrolled`），删除不存在的令牌返回 404（body `enrollment token "x" does not exist`），CLI 退出码 1。
- `sigilc status` 的 IPC 调用有 10 秒超时（`statusTimeout`）。`status --json` 任何失败都输出 `{"error": "..."}`。`sigilc status --json` 返回 `ClientState`，其中 `certs` 数组的字段为 `name`、`fingerprint`、`not_after`、`renew_at`、`outputs`、`on_change`、`hook_pending`。`renew_at` 按客户端的比例规则算，sigils 有 ARI 时可能更晚续期。`last_pull_at` 在第一次 sync 前不存在（`omitzero`）。`token list --json` 里未用令牌没有 `used_at`（`omitzero`）。
- sigilc 启动时清扫上次崩溃可能留下的临时文件：data_dir 里的 `.sigil-private-*` 和各输出目录里的 `.sigil-tmp-*`，client.yaml 所在目录不碰。
- `sigilc enroll`：失败时删掉本次新建的 client.yaml（已有的不动）；提前写入保留，作为不消耗 token 的可写性预检；mismatch 错误带上配置文件路径。拒绝 name 或 URL 不合规的 token。覆盖已有身份后提示运行中的 daemon 需 `sigilc reload` 或重启服务。没有 `--token` 时读 `SIGILC_TOKEN` 环境变量。
- `sigilc fetch` 必须调用真实 IPC 拉取，返回前完成对账和钩子；`--cert` 只强制重新下载目标证书，不强制重写未变化的输出。`reload` 必须先完整解析新配置，失败时保留旧配置；成功后在返回前按新配置从存储对账并运行钩子，同时取消在途 sync，让循环立即做一次完整拉取。reload 的本地对账成功时不清空 `LastError`，由 reload 触发的下一轮用自己的结果覆盖。`client.ipc_socket` 和 `client.data_dir` 变化要求重启。
- 客户端对账：
  - client.yaml 按证书分组，写成 `certificates.<名字>.outputs` 和 `certificates.<名字>.on_change`；所有输出路径经 `filepath.Clean` 后不得重复，Windows 上不分大小写。
  - 私有存储保存最近一次 sync 视图里全部证书的材料和 `hook_pending`。视图里消失的证书从存储删除，输出文件不动、不跑钩子。不合规的证书名按安全约束 16 处理。bundle 入库前必须通过 key 与证书配对校验，链证书逐个 `x509.ParseCertificate`、任一张失败就整包拒收，坏包不能覆盖输出。存储写盘失败时下次对账补写。
  - 客户端只有一个 sync 循环，没有周期拉取。每一轮（收到 304、收到 200 并应用之后、出错之后），以及启动、reload、IPC fetch 时，都要逐个输出对账，只用本地存储、不联网。
  - 内容不一致（文件缺失、不是普通文件、读不出或内容不同）的输出按证书成组替换。PKCS#12 按解码后的证书链和私钥比较，不按字节比较（编码带随机盐）。
  - 内容一致只差元数据的：Unix 在原文件上先 chmod 再 chown，不再 stat 验证；Windows 只比较内容，不比 DACL、不比 mode、不比 owner。只修元数据不算变化、不触发钩子，因为有的文件系统存不住权限位（drvfs/9p 没开 metadata、CIFS 没有 unix extensions、WSLC bind mount 一律报告 0777），算作变化会每轮重写、每轮跑钩子。
  - 输出只写 CERTIFICATE 块和私钥块，重新编码后写出。升级到当前版本后，CA 的 PEM 不是 Go 标准格式时每张证书重写一次、on_change 跑一次。
  - 视图、bundle 和续签响应都限 1 MiB（`maxResponseBytes`，约 5000 张证书）。超过时报 JSON 解码错误。
- `on_change`：
  - 下载到的材料指纹变化（存储里原本没有也算），或者该证书任一输出的内容被重新写入后，置位 `hook_pending` 并持久化；只修权限位、属主不置位。
  - 对账之后在 pullMu 内按名字串行运行；该证书本次对账出错则不跑。
  - 失败时保留 `hook_pending` 并计为本轮错误，之后每轮重跑，失败期间循环退避。写 `hook_pending` 失败的那一轮不跑钩子。成功的 `sigilc fetch` 会叫醒退避中的循环。钩子的 ctx 来自 Run 的生命周期：Run 启动前用 Background，Run 返回后仍用它已取消的 ctx。certs.json 持续写不进去（磁盘满、只读挂载）时所有钩子暂停，`LastError` 以 `save store: ` 开头。
- `round failed` / `round succeeded again` 只在 LastError 文本变化时各记一次。
- `/v1/sync`：
  - 不带 `If-None-Match` 时立即返回该客户端的清单；带且相同时最长挂起 `proto.SyncMaxWait`（55 秒）后回 304。每客户端最多 4 个在途请求（`maxSyncsPerClient`），第 5 个回 429 `too many sync requests in progress`。If-None-Match 只做整串精确比较，弱 ETag、`*`、列表（包括分成多行发送的）一律不匹配。ETag 只由该客户端过滤后的清单计算，私钥只经 bundle 端点。
  - 证书落库（scheduler 的 stored 回调）和 reload 成功发布后，唤醒全部挂起请求。handler 必须先取唤醒 channel，再读配置和库：配置这一侧有确定性测试，库这一侧只能靠 review。stored 回调的接线只有 E2E 的 renew 交付一步能守住。
  - handler 必须用 `ResponseController.SetWriteDeadline` 越过 30 秒的 WriteTimeout，否则 HTTP/1.1 的响应会被截断、HTTP/2 的流会被重置。daemon 关停时，挂起的请求立即回 304。
  - 客户端挂起的 sync 请求不能用 30 秒超时的 HTTP client。本轮任何一步出错（身份续签、请求、应用、对账、钩子）都要退避：5 秒起翻倍，封顶 5 分钟。续签失败时仍用当前身份照发 sync。
  - 客户端与 sigils 之间若有四层代理，空闲超时必须大于 60 秒。
- 事件环（`logging.Ring`，500 条）：
  - `Started` 记录 Ring 创建时刻。调用方（如 TUI）发现 `Started` 变了，就清空已有记录、用 `after=0` 重拉。
  - 事件的 Message 中的控制字符被替换，Attrs 截断到 2 KiB，Message 截断到 1 KiB。`Private` 属性在 Ring 和 Windows 事件日志中显示为 `(withheld)`，在 stderr / journald sink 中保留全文。
  - lego 的日志行进入事件（按前缀判定 INFO / WARN，带 `component=lego`）。
  - 公网 HTTPS 的 `http.Server.ErrorLog`（握手错误等）只进服务日志，并限速：每分钟最多 10 行（`maxErrorLinesPerMinute`），超出的丢弃计数，下一行放行时附上被丢弃的行数。IPC 的 ErrorLog 不限速。
- 鉴权中间件刷新 `last_seen`：内存节流，每个客户端每分钟最多一次条件 UPDATE，节流不能写进 SQL 条件；UPDATE 影响 0 行按 401 处理，其他写库错误只记日志、照常放行（库不可写时仍要能分发已有证书）；无论写库结果如何，节流占位都不释放。并发首次使用同一 pending 身份时，提升失败后重读一次，active 指纹已等于出示指纹就放行。
- 客户端 mTLS 身份必须在到期前自动续签；`client.identity_renew_before` 默认 30 天，允许范围为 1 小时到 89 天。`/v1/identity/renew` 每客户端每分钟一次，超出回 429 `identity renewed less than a minute ago`，占位不论成败都不释放。
- sync 循环、reload 和 IPC fetch 的应用阶段（身份续签、取包、写存储、对账、钩子）由同一把锁 pullMu 串行化；sync 的挂起等待不持锁。Reload、IPC fetch 和身份切换通过同一把锁里登记的 cancel 取消在途 sync，循环拿到锁后发现请求已被取消就作废本轮。
- 客户端 socket 在 Unix 上固定为 `/var/run/sigil/sigilc.sock`，不能依赖启动用户的 `$HOME`。Unix IPC Dial 只信任属主为 root 或当前 euid 的 socket（与 Windows 管道信任 SYSTEM/Administrators 对称），Listen 替换无人应答的旧 socket 不看属主。
- 服务端外部 HTTPS 可使用公网证书，但客户端证书仍由内部 mini-CA 验证。客户端验证服务端时同时信任系统根和 mini-CA。
- 关停上界：从取消起算 30 秒（`issuanceStopTimeout`），超时放弃 scheduler 发起的在途签发，证书和 DNS TXT 清理会丢；WARN `certificate issuance abandoned at shutdown certs=...` 列出名字。`cert renew` 经 IPC 发起的手动续期不在此等待之列，IPC 只有 10 秒排水（`shutdownTimeout`）。
- 签发结果校验：叶子公钥必须等于订单私钥，叶子 DNSNames 必须覆盖 spec 的全部域名；不符按签发失败处理。
- 鉴权读库出错回 500（不再 401）。所有 500 记 ERROR 事件（`look up client failed`、`promote client identity failed`、`read certificate failed`、`read certificate view failed`、`encode certificate view failed`、`client identity renewal failed`、`enrollment failed`、`open sigilc binary failed`、`panic serving request`）。注册被拒时，已用、过期回 401 并写明原因，记 WARN `enrollment refused client=... token=<ID> error=...`；secret 不符仍是 401 `invalid token`，不记事件。
- mini-CA 只剩一半文件时拒绝启动，报错写明两条路径。mini-CA 根证书剩余不足 1 年时，在启动时和每次服务端证书重签时记 WARN `mini-CA root certificate expires within a year`。
- `SaveIdentity` 用 `yaml.Node` 只替换或追加 `identity`，保留注释、键序和原文本，空行会丢。
- SQLite 和 WAL 包含私钥材料，创建与重开时都必须保持私有权限。schema 迁移只进不退：v5 删除了 clients 表的 push 两列，升级后的数据库不能再用旧版 sigils 打开。库版本比程序新时拒绝打开并写明两个版本。`store.Open` 只接受路径（可带 `?` 参数）或 `:memory:`。
- TUI 刷新的每次 IPC 调用使用 10 秒超时（`shared.Within`），daemon 冻结时状态行最迟约 12 秒出现错误，下一个 tick 照常刷新。操作类调用（sigilc 的 `f`/`R`，sigils TUI 的 `R`/`d`/`n`）不套 10 秒超时，只受 IPC 客户端 5 分钟总超时限制。

## 平台约束

- 平台差异使用 build tag 文件，例如 `_windows.go` 与 `_unix.go`。
- Windows 的 `os.Chmod(0600)` 不能替代 DACL。
- Windows 安装脚本必须区分 AMD64、ARM64 和 x86。
- Windows 上 daemon 必须以 LocalSystem 或提权管理员身份运行。IPC 客户端只信任属主为 SYSTEM 或 Administrators 的命名管道，校验在发出请求之前完成。有管理员权限的 `Listen` 会显式把属主设为 Administrators；不指定属主时，属主取令牌的默认属主，Git Bash 下会变成用户 SID。
- Windows 服务与事件日志（2026-10-01 sigils 实测）：
  - install / start / stop / uninstall 退出码都为 0，以 LocalSystem 运行。安装时 System 日志记 7045。
  - 运行期间的 INFO、WARN、ERROR 分别写入 Application 日志，事件 ID 为 1、2、3，来源为服务名（`sigils`/`sigilc`），消息按 slog 的 TextHandler 格式正常渲染，与 `sigils events` 一致。
  - 启动即失败时 `ExitCode=1067`，失败原因写在 Application 日志 ID 3（`daemon failed`）。`service install` 会写入恢复动作：失败后 10 秒重启，失败计数 24 小时清零；System 日志记 7031。
  - `service uninstall` 会一并删除事件日志源。之后 `Get-WinEvent -FilterHashtable @{ProviderName='sigils'}` 会报参数错误，要改用 LogName 过滤再 `Where-Object ProviderName`。
  - 事件写入后有时要过几秒才查得到，脚本不能查一次为空就下结论。
  - 带引号的属性值里 Windows 路径的反斜杠会显示成双写（slog 的引号转义）。
- Windows 管道名被抢注时 daemon 启动失败。属主能读出时错误写明属主 SID；读不出时报 `another process holds the pipe name, and its owner cannot be read`。
- systemd：
  - `service install` 生成的单元包含 `Restart=on-failure`、`RestartSec=5`、`KillMode=mixed`、`EnvironmentFile=-/etc/sysconfig/<name>`。`KillMode=mixed` 使 stop 先只给主进程 SIGTERM，主进程退出后剩余进程 SIGKILL，exec DNS 程序才能用满关停宽限。持续失败时每 5 秒重启一次、永不放弃（systemd 默认 `StartLimitBurst=5/10s` 碰不到）。已装好的旧单元要先 `service uninstall` 再 `service install`（kardianos 遇到已存在的服务会报错）。
  - 环境变量放 `/etc/sysconfig/<name>`（Ubuntu 上没有这个目录，放凭据前先建）。
  - stderr 在 systemd 下进 journald。
- Linux 一键安装（2026-10-01 Ubuntu 25.04 / systemd 257 实测）写入的路径：`/usr/local/bin/sigilc`、`/etc/sigil/client.yaml`（文件 0600、目录 0700）、`/var/lib/sigilc`（sigilc 首次启动时私有创建，安装时就已存在，0700，属主 root:root — 2026-10-01 实测）、`/var/run/sigil/sigilc.sock`（0660、属主 root，`sigilc status` 要加 sudo）、`/etc/systemd/system/sigilc.service` 及 multi-user.target.wants 链接。Ubuntu 上撤临时测试根要 `update-ca-certificates --fresh` 再 `keytool -delete -cacerts`，否则留悬空链接和 Java 库条目。
- launchd：系统级 LaunchDaemon 的 stderr 日志写到 `/var/log/<name>.err.log`。
- PowerShell 5.1 的已知问题：
  - `ServerCertificateValidationCallback = {$true}` 这种 scriptblock 回调不可用，要用 C# 的 `ICertificatePolicy`。
  - 下载必须加 `-UseBasicParsing`，否则在没有 IE 引擎的 Server Core 上失败。
  - `exit` 在 `& ([scriptblock]::Create(...))` 调用方式下会关掉调用者的会话。
  - `SecurityProtocol` 为 `SystemDefault` 时，`-bor 3072` 的结果只剩 TLS 1.2，所以安装命令的前缀和服务端 TLS 下限必须一起决定。
- 东亚系统区域的经典 conhost 把 `\u00B7 \u2026 \u2191 \u2193 \u25CF \u2014 \u00D7` 等字符画成两格宽，lipgloss 按一格算，Charm v2 渲染器截断超宽行，不换行。TUI 只能画 `shared.WideGlyph` 放行的字符（`\u2500 \u2502 \u256D \u256E \u2570 \u256F \u2022 \u203A` 实测为一格宽；2026-10-01 Charm v2 + cp936 新宋体复查通过）。数据本身带宽字符的行仍会错位。
- WSLC 2.9.4 每个会话最多挂载 15 个不同的主机路径（2026-09-27 实测）：
  - 按会话存活期间出现过的不同路径计数，与容器数无关，同一路径重复挂载不另计。
  - 同一会话里，多个 agent 可以同时跑 E2E（资源名互不相同）；核对残留时只看本轮自己的资源名。
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
- WSLC bind mount（2026-09-28 实测）：
  - 挂载里的文件一律报告为 0777，chmod 静默无效。E2E 因此把客户端输出和 sigils 的 data_dir 都放在容器自己的文件系统里。
  - 宿主进程打开着挂载里的某个文件时（Go 的 os.Open/ReadFile 不带 FILE_SHARE_DELETE），容器里 rename 覆盖这个文件会报 Permission denied。容器可能替换某个文件时，宿主不要打开它。
  - 宿主改写挂载里的文件，容器里立即可见（变长、变短、等长都实测过），所以 E2E 可以在容器运行期间从宿主改 server.yaml。
- E2E 在 Linux Docker（rootful）下给 sigils、sigilc 两个容器加 `--user <uid>:<gid>`。sigils 镜像把 `/var/run/sigil` 和 `/var/lib/sigils` 设为 1777，data_dir 是容器内的 `/var/lib/sigils/data`；sigilc 镜像把 `/var/run/sigil` 和 `/cert-output` 设为 1777。WSLC 不需要加：容器写进挂载目录的文件属主本来就是 Windows 用户。rootless Docker 没有验证过。
- Pebble v2.10.1 的 ARI 特性：
  - 目录公布 `renewalInfo`，窗口默认为 NotAfter - 有效期/3 前后各 24 小时，`Retry-After` 固定为 6 小时。已吊销的证书返回已过去的窗口。
  - 管理端口提供 `POST /set-renewal-info/`，可以按 serial 覆盖返回内容。
  - 新订单带 `replaces` 通过时打印日志 `ARI: order ... is a replacement of ...`，E2E 据此断言。
- 本机 Git for Windows 的 curl（Schannel）校验私有根时会报 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`，要加 `--ssl-no-revoke`；Go 写的 harness 不受影响。
- 不运行或依赖 Docker Desktop。需要容器验证时直接调用 `wslc`。

## 已知未完成项

已知限制：
- 输出路径去重只比较 `filepath.Clean` 后的文本（Windows 上转小写）。查不出的情况包括：符号链接和硬链接（两个平台都查不出）；macOS APFS 不区分大小写（去重只在 Windows 上转小写）；Windows 上 `\\?\C:\`、`\\.\C:\`、8.3 短名、结尾的点和空格、映射盘符与 UNC 路径。
- mini-CA 根证书 10 年后到期，没有轮换机制。剩余不足 1 年时会记 WARN `mini-CA root certificate expires within a year`。
- 非 systemd 的 Linux 上，重启语义不同（未验证）。
- modernc sqlite 在 ctx 取消后连接 `IsValid()=false`，`store.Open` 用 Exec 设的 `PRAGMA foreign_keys=ON` 按连接生效、换连接就丢；schema 目前没有外键。以后要加按连接生效的 pragma 一律写进 DSN。
- `sh -s -- --token` 形式令牌仍在 sh 的命令行里，`-Token '...'` 会进 PowerShell 历史文件。Windows 自动化只能用 `-Token`。交互输入（不带 `--token`/`-Token`）不进命令行。macOS 终端单行输入上限 1024 字符（令牌约 1.05K）。
- Windows 上 sigils 正在响应下载时，替换 `data_dir/binaries` 里的文件会失败（Go 的 `os.Open` 不带 `FILE_SHARE_DELETE`），换二进制要等下载结束或停服务。
- setsid 另开会话的进程、由计划任务或服务管理器代为启动的进程不会被结束进程树杀死。非 systemd 的 Unix 和 macOS（launchd 按进程组清理，`Setpgid` 后钩子脱离该组）上，放弃签发时 exec 程序可能残留（未验证）。Windows 容器（server silo）未验证。Windows 上每次运行多约 100 ms（线程快照）。`.bat` 超时时 cmd.exe 和子进程一并被杀。
- 持有已用完整令牌的人可以反复请求注册刷 WARN（同 lego INFO 挤占事件环那条）。
- client.yaml 有未知字段时重装先消耗令牌、到服务启动才报错（改好后重启服务即可）。
- Windows 服务崩溃循环时 SCM 可能在停止与卸载之间拉起它。
- Windows 上 Stop-Service 之后 `[IO.File]::Replace` 失败（如杀软占住文件）时服务会停着，重跑安装即可。
- install.ps1 不自己建 `C:\ProgramData\Sigil`（由 enroll 私有创建）。
- bubbletea v2 在 TUI 第一次渲染时发 `ESC[?u`（kitty 键盘协议查询，无法单独关闭），支持该协议的终端若在启动后立即按 q，应答可能落到提示符上；DECRQM 2026/2027 在无 `SSH_TTY` 时也会发。
- Windows 上第一次 `cert add`/`cert remove` 之后 server.yaml 变成私有 DACL（SYSTEM、Administrators），原先授给其他账户的访问会被去掉。
ARI 简化：
- ARI 对 5xx 不做短间隔指数退避，按 6 小时后重查（lego 拿不到 HTTP 状态码）。
- ARI 的 `pick` 不持久化，重启后时点在同一窗口内重新随机。
- 到货即到期防护只覆盖整体已过去的首个窗口，跨越 now 的窗口仍会立即续期。
- 寿命不超过 CA 回拨 NotBefore 时长约两倍的证书（LE 回拨 1 小时，约 2 小时以内）不受支持：一到手就已过续期时点，会被到货即到期防护按失败退避。

对账与显示：
- 对账不比较 Windows 私钥文件的 DACL：DACL 被放宽或从目录继承的，要等内容变化（续期）才复原。从配置删掉 `owner`/`group` 时，Unix 旧 uid/gid、Windows 旧 owner 账户的读权限 ACE 同样保留到内容变化。要立即生效就删掉输出文件，下一轮对账会重建。
- 80x24 终端下，Certificates 详情里很长的 Last Error 会被截掉末尾，全文用 `sigils cert show`。
- lego 的 INFO 行进入 500 条的事件环：批量续期时可能挤掉 sigils 自己的事件。
- reload 被拒时，yaml.v3 的类型错误会带出最多约 10 个字符的配置值（例如把凭据误写进数字字段），会进服务日志和事件。
- TUI 里的 `(ari)` 显示只有单测覆盖；E2E 只在 `cert list --json` 的 `renew_source` 这一层覆盖到。
- 注册令牌内嵌整张 mini-CA 证书，长约 1.05K 字符，TUI 里无法整段复制；可以考虑改成携带 CA 指纹。
- 视图或 bundle 超过 1 MiB 时报的是 JSON 解码错误，看不出是超限。

升级期间：
- 升级二进制后没重启服务时，daemon 没有 `/ipc/v1/events`，TUI 只显示 404 和空列表，重启服务即可。
- 二进制升级但 daemon 没重启时，新 CLI/TUI 会打印旧 daemon 没净化的 LastError。新 CLI 拒绝旧 daemon 的 token 应答（无 `token_id`），但令牌已入库、到期作废；先重启 sigils 再签。旧 daemon 对 `cert add`/`cert remove` 的新路由回 `404 page not found`，重启 sigils 即可。
- 终端注入加固（`3212e5e`）之前写下的 certs.json 若含不合规的证书名，要到第一次收到 200 后才清掉。
- 输出改为重新编码写出，CA 的 PEM 不是 Go 标准格式时，升级后每张证书重写一次、on_change 跑一次。
- 审查前在 Windows 上 enroll 过的主机，`C:\ProgramData\Sigil` 带安装者 SID，升级后服务和重装 enroll 都会被拒，按报错的 `icacls` 修。

各家云 DNS provider 仍然没有 E2E。`skip_propagation_check` 的接线只有 E2E 的"签发成功"能守住，`acme.dns_resolvers` 的生效只有 `TestIssuanceUsesDNSResolvers` 能守住。改这两处时必须跑 E2E。

## 改 TUI 时注意

- 空格键名是 `"space"`。
- lipgloss v2 的 `Width` 包含边框。
- bubbles 表格要显式设宽度。
- lipgloss v2 在非终端下也输出 SGR，测试要经 `ansi.Strip` 读视图。
- 在 `%TEMP%` 下起 sigils 冒烟前，要先按报错收紧配置目录（W 路目录检查）。

## 修改原则

- 先读现有实现和测试，再做局部改动；不要把未实现功能写成已完成。
- 安全边界、跨模块契约和用户工作流必须增加回归测试。
- 手工文件修改：Codex 用 `apply_patch`；Claude Code 没有这个工具，用 Edit/Write。
- 仓库已于 2026-09-27 初始化 Git（基线提交 `d0151bf`，`.gitattributes` 固定 LF）；变更可用 `git diff` 审阅，验证仍以格式化、单元测试、静态检查和 WSLC E2E 为准。
- 容器测试结束后确认 WSLC 容器与网络为空，并移除本轮生成的镜像。
