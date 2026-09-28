# AGENTS.md

项目：**Sigil**，面向服务器集群的 ACME 证书签发与分发工具。

## 当前状态

项目处于持续开发阶段，不要把它描述为“v1 已全部完成”。核心注册、mTLS 鉴权、证书拉取、客户端吊销、管理命令、服务端热重载、客户端身份续签、Phase 2 的并行签发引擎和 exec DNS provider，以及 Phase 3 的 `/v1/sync` 长轮询交付、客户端私有存储与每轮输出对账、`on_change` 钩子均已可用，并有 WSLC 黑盒测试（含从 Pebble 真实签发、sync 交付延迟、输出自动恢复和钩子）；各家云 DNS provider 的 E2E 与部分 TUI 操作仍未完成。2026-09-27 完成现状审阅并拍板重构方向（见下一节），按 `TODO.md` 分阶段执行。

## 重构方向（2026-09-27 拍板）

审阅文档未公开（缺陷编号 A1–A13、决定编号 B1–B4、C1 均出自该文档）。以下决定已接受；**对应 Phase 落地之前，现有代码和下文各条约束继续有效**。

- B1（Phase 3，2026-09-28 已落地，规则见运行时约束）：服务端推送改为客户端长轮询。mTLS 上的 `GET /v1/sync` 带 etag 挂起等待，证书落库或 reload 时唤醒，默认最长 55 秒。落地后删除推送通知器、客户端 push 监听、server.yaml 的 `clients:` 和 client.yaml 的 `push_listen` / `push_token`，安全约束 9 随之作废。
- B2（Phase 2，2026-09-28 已落地，规则见运行时约束）：取消全局签发锁，改为每张证书一把锁、有上限的并行签发。落库时比对下单时的 spec 指纹与当前配置，不一致则丢弃；reload 不再等待在途签发。
- B3（Phase 4）：PowerShell 安装改为 `& ([scriptblock]::Create((irm <url>/install.ps1))) -Token '<token>'`，服务端不再把请求参数写进脚本，安全约束 7 随之作废。
- B4（Phase 3，2026-09-28 已落地，规则见运行时约束）：删除 `/v1/heartbeat`，由 mTLS 鉴权中间件用条件 UPDATE 刷新 `last_seen`（每个客户端每分钟最多写一次）。
- C1（Phase 3，2026-09-28 已落地，规则见安全约束 15 和运行时约束）：客户端每张证书可配置 `on_change` 钩子，argv 形式，带超时，只能在客户端配置。
- 每一项删除都排在替代品落地之后：删除 IPC `POST /ipc/v1/certs`（A13）已随 Pebble E2E 于 2026-09-28 完成；删除 heartbeat、push、`GET /v1/certificates` 列表端点和客户端的 `pull_interval` 已随 `/v1/sync` 于 2026-09-28 完成。
- 保留不动：mTLS + 数据库指纹鉴权、一次性令牌绑定、`subscribers` 唯一授权来源、客户端本地输出配置、spec 指纹绑定、`securefile`、严格 YAML。

## 项目快览

- Go 1.26，模块：`github.com/Oganneson-Studio/sigil`。go.mod 是 Go 版本的唯一来源：CI 用 `go-version-file: go.mod`，E2E 镜像用 `golang:1.26-alpine`。
- go-winio 用的是未发版的 main 快照 `7e8af9b`（修复了管道 listener `Close` 的竞态：v0.6.2 下 `sigils` 停机时，如果恰好有 IPC 客户端连入，可能永久阻塞）。上游发版后换成正式 tag，见 TODO。
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
internal/api/              HTTPS API（含 `/v1/sync` 长轮询）、安装脚本和 mTLS 中间件（含 last_seen 节流）
internal/ca/               内部 mini-CA
internal/client/           sync 长轮询循环（每轮对账）、私有本地存储、on_change 钩子、状态
internal/config/           严格 YAML schema 与校验
internal/enroll/           一次性 token、CSR 和身份保存
internal/ipc/              服务端与客户端本地控制 API
internal/output/           证书格式化、输出比对与按证书成组的原子替换
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

E2E 不依赖 Compose 或固定 IP。它构建临时镜像、创建随机命名网络、通过网络别名连接，用 Pebble + challtestsrv + exec DNS hook 真实签发证书，执行注册/拉取/renew/吊销/token 测试，并测 sync 交付延迟、输出对账与自动恢复、on_change 和 reload 唤醒，并按精确名称清理资源。WSLC 热跑一轮约 2 分钟（2026-09-28 实测 go test 121–127 秒），其中不调 fetch 的自动恢复一步固定约 55 秒：要等循环挂起的 sync 满 55 秒返回，前一步的 fetch 会让这次等待重新计时。Linux Docker 的耗时在 Phase 3 之后没有重测。Linux CI 可显式设置 `SIGIL_CONTAINER_CLI=docker` 使用 Docker Engine；Windows 必须使用 WSLC。

竞态测试需要 CGO：

```powershell
go test -race ./internal/api ./internal/client ./internal/ipc ./internal/scheduler ./internal/server ./internal/acme ./internal/store ./internal/config ./internal/output
```

如果当前 Go 环境 `CGO_ENABLED=0`，应明确报告无法运行，不能把它写成已通过。

## 安全约束

1. `server.yaml` 的 `certificates[].subscribers` 是订阅授权的唯一来源；客户端输出配置不能扩大授权。
2. 注册 token 是一次性的，并绑定 secret、server URL、客户端名和 mini-CA 证书。客户端发送 token 前必须验证 TLS，禁止恢复 `InsecureSkipVerify`。
3. 已注册客户端每次访问都必须同时通过 mTLS、数据库存在性和证书指纹匹配；挂起的 `/v1/sync` 被唤醒后、返回新清单前要再校验一次。删除客户端即撤销访问；除注册外，任何写路径（包括鉴权中间件刷新 `last_seen` 的条件 UPDATE）都不得创建客户端记录。
4. `client.yaml` 和客户端本地存储 `<data_dir>/certs.json` 都包含私钥。写入必须经过 `internal/securefile`：Unix 使用私有模式，Windows 使用受保护 DACL，且采用临时文件加原子替换。私有临时文件一律用 `securefile.CreateTemp` 创建：Windows 上在 `CreateFile` 时就带受保护 DACL，不能先建文件再收紧，因为收紧之前别的账户打开的句柄仍能读到之后写入的内容。certs.json 加载时若已存在，先用 `securefile.ProtectFile` 收紧；它的路径不能由服务端下发的证书名派生。`client.data_dir` 和私钥类输出必须放在能存住 Unix 权限位的文件系统上，否则私有模式形同虚设；WSL drvfs/9p（没开 metadata）、没有 unix extensions 的 CIFS、vfat/exfat 和 WSLC 的 bind mount 都存不住。
5. 私钥输出默认权限为 `0600`；公开证书可为 `0644`。不要对所有输出格式使用同一默认权限。对账重写输出时按证书成组暂存：内容、权限位和属主先在临时文件上就位，全部暂存成功才依次改名替换，不能先改名再 chown。Windows 上的私钥类输出（`pem-key`、`pem-bundle`、`pkcs12`）有几条额外规则：
   - 临时文件在 `CreateFile` 时就带受保护 DACL：SYSTEM、Administrators 和运行 sigilc 的账户完全控制，配置的 `owner` 只读。
   - `mode` 在 Windows 上不应用，不能放宽这个 DACL；只读属性还会让之后的替换失败。
   - `owner` 只有以 `S-`（不分大小写）开头且能解析时才按 SID 处理，否则按账户名查找。`BU`、`WD` 这类 SDDL 别名不能当成 SID。
6. 安装下载端点的 `os/arch` 必须保持字符白名单和目录 containment 双重检查。
7. PowerShell 安装脚本只能反射 canonical base64url 字符，响应必须 `Cache-Control: no-store`，不得再次把任意查询值拼入可执行脚本。（Phase 4 按 B3 改造后本条作废。）
8. 生产一键安装要求公网端点使用操作系统信任的 TLS 证书。通过 `server.tls_cert_file` 与 `server.tls_key_file` 配置；内部 mini-CA 默认证书不能让首次系统 `curl` 自动信任。
9. （已作废：Phase 3 按 B1 删除了服务端 push 和客户端 push listener。保留编号，避免引用错位。）
10. 配置解析使用 `yaml.KnownFields(true)`。增加字段时必须同步 schema、验证和测试。`config.ReadServerPaths` 是只给 CLI 定位 IPC、给安装器找 data_dir 用的宽松读取函数，daemon 不得用它加载配置。`${VAR}` 和 `${VAR:-default}` 在 YAML 解析后逐个标量值展开：值原样插入、不 trim；键不展开；`$$` 表示字面 `$`；变量未设置且没有默认值时报错。三个解析入口（`ParseServer`、`ParseClient`、`ReadServerPaths`）必须得到一致结果。
11. 服务端只读 IPC 必须使用显式 DTO，不能在线路上返回证书私钥或 enrollment-token secret hash。IPC 上没有写证书的路由，证书只能经签发进入数据库（A13）。
12. 数据库证书记录必须绑定有效配置指纹；CA directory、domains 或 key type 变化后，旧材料不得继续分发。
13. `exec` DNS provider 只能在 server.yaml 中配置。它以 sigils 服务账户运行、继承其全部环境变量（包括 `${VAR}` 引用的凭据），单次运行 2 分钟超时。
   - 错误信息只含动作、记录名和退出状态或超时，启动失败时另带 argv[0]。
   - argv[1:] 和脚本输出永远不进入错误。
   - 脚本输出只在失败时截尾写日志。
14. 来自 ACME CA 和 DNS provider 的错误文本，写入 `issuance_status.last_error` 或经 IPC 返回（手动 renew）之前，必须替换控制字符和非法 UTF-8，并截断到 1 KiB，因为 CLI 会把它原样打印到终端。
15. `on_change` 只能在 client.yaml 配置，argv 形式、argv[0] 为绝对路径、不经 shell。服务端下发的内容（包括证书名）不能影响执行什么、写到哪里。
   - 它以 sigilc 服务账户运行、继承其全部环境，stdin 为空，单次运行 2 分钟超时；daemon 停止时终止，IPC 调用方断开不影响它。
   - 错误信息只含证书名和退出状态或超时，启动失败时另带 argv[0]；argv[1:] 和钩子输出永远不进入错误，输出只保留末尾 4 KiB、只在失败时写日志。
   - 钩子以 0 退出、但它启动的进程还占着输出时，最多再等 5 秒就关闭管道、按成功处理并记一行日志（exec DNS provider 在这种情况下按失败处理）。钩子留在后台的进程必须自己重定向 stdout、stderr。

## 运行时约束

- `sigils` 与 `sigilc` 使用不同的 IPC 端点。客户端命令解析顺序为：显式 `--ipc`、`client.ipc_socket`、平台默认客户端 socket。
- `sigils reload` 必须通过本地服务端 IPC 完整解析并应用新配置。可热更新 `acme`、`dns_providers` 和 `certificates`（含 subscribers）；若 `server.listen`、`server.public_url`、`server.data_dir`、`server.ipc_socket`、`server.tls_cert_file`、`server.tls_key_file` 或 `acme.dns_resolvers` 变化，必须拒绝 reload、保留旧运行配置并明确要求重启。`acme.dns_resolvers` 需要重启，是因为 lego 把它存在进程级全局变量里。
- 服务端签发按证书加锁：
  - 同一张证书同一时刻最多一个签发：周期 tick 遇到在途签发即跳过；`sigils cert renew` 等它结束后再强制签发。全局并行上限为 `scheduler.maxConcurrentIssuance`（4）。
  - 签发结果落库前，在 generation 读锁下按名字从当前运行配置重新取 spec 计算指纹，与下单前捕获的指纹比对。不一致或证书已删除，就丢弃结果并立即唤醒 scheduler。
  - generation 读锁内只允许 `current()`、指纹计算和毫秒级的 DB 写；唤醒 `/v1/sync` 的通知和一切网络调用必须在锁外。
  - 旧 generation 的失败、ctx 取消导致的失败都不计入退避。
  - reload 不等待在途签发：只在 generation 写锁下清零所有证书的持久化退避（保留最近错误）、原子发布新配置并立即唤醒 scheduler。
  - 每证书退避（5 分钟起、翻倍、封顶 24 小时）与最近错误存 `issuance_status` 表，重启不清零；调度定时器按最早的下次尝试时间唤醒。
  - 失败记入退避后立即唤醒 scheduler 重算定时器；退避写库失败则不唤醒，以免立即重试。
  - 因为退避持久化，改配置加重启不会清零退避；修好原因后用 `sigils reload` 或 `sigils cert renew`。
  - 传给 `Issue` 的 ctx 必须可取消，`WithoutCancel` 只用于收尾的 DB 写入。
- ACME 账户初始化按 CA 名加锁（账户记录以 CA 名为主键），从取或建 key 一直锁到 register 完成，下单前释放。读账户库出错时原样返回，不新建 key、不覆盖记录；只有库里的 registration JSON 损坏时，才用同一把 key 重新注册来修复。
- `GET /ipc/v1/certs`（即 `sigils cert list/show`）按运行配置顺序列出配置中的证书：
  - `not_after`、`fingerprint` 等材料字段，只在库中记录的 spec 指纹与当前配置一致时才填写；
  - 已从配置删除的证书，库里残留的记录不列出；
  - state 优先级为 issuing > backoff > valid > pending。
- `sigils token create` 由运行中的 daemon 经服务端 IPC 签发，daemon 未运行时报错，不再在 CLI 进程里直接写库；CLI 拒绝不支持新协议的旧 daemon 的应答。`cert add`/`cert remove` 改完 `server.yaml` 后通知 daemon reload。
- `sigilc fetch` 必须调用真实 IPC 拉取，返回前完成对账和钩子；`--cert` 只强制重新下载目标证书，不强制重写未变化的输出。`reload` 必须先完整解析新配置，失败时保留旧配置；成功后在返回前按新配置从存储对账并运行钩子，同时取消在途 sync，让循环立即做一次完整拉取。`client.ipc_socket` 和 `client.data_dir` 变化要求重启。
- 客户端对账：
  - client.yaml 按证书分组，写成 `certificates.<名字>.outputs` 和 `certificates.<名字>.on_change`；所有输出路径经 `filepath.Clean` 后不得重复，Windows 上不分大小写。
  - 私有存储保存最近一次 sync 视图里全部证书的材料和 `hook_pending`。视图里消失的证书从存储删除，输出文件不动、不跑钩子。bundle 入库前必须通过 key 与证书配对校验，坏包不能覆盖输出。存储写盘失败时下次对账补写。
  - 客户端只有一个 sync 循环，没有周期拉取。每一轮（收到 304、收到 200 并应用之后、出错之后），以及启动、reload、IPC fetch 时，都要逐个输出对账，只用本地存储、不联网。
  - 内容不一致（文件缺失、不是普通文件、读不出或内容不同）的输出按证书成组替换。PKCS#12 按解码后的证书链和私钥比较，不按字节比较（编码带随机盐）。
  - 内容一致只差元数据的：Unix 在原文件上先 chmod 再 chown，不再 stat 验证；Windows 只在配置了 owner 且属主不符时重新暂存（私钥输出 DACL 里 owner 的读权限 ACE 要跟着重建），不比 DACL、不比 mode。只修元数据不算变化、不触发钩子，因为有的文件系统存不住权限位（drvfs/9p 没开 metadata、CIFS 没有 unix extensions、WSLC bind mount 一律报告 0777），算作变化会每轮重写、每轮跑钩子。
- `on_change`：
  - 下载到的材料指纹变化（存储里原本没有也算），或者该证书任一输出的内容被重新写入后，置位 `hook_pending` 并持久化；只修权限位、属主不置位。
  - 对账之后在 pullMu 内按名字串行运行；该证书本次对账出错则不跑。
  - 失败时保留 `hook_pending` 并计为本轮错误，之后每轮重跑，失败期间循环退避。钩子的 ctx 来自 Run 的生命周期：Run 启动前用 Background，Run 返回后仍用它已取消的 ctx。
- `/v1/sync`：
  - 不带 `If-None-Match` 时立即返回该客户端的清单；带且相同时最长挂起 `proto.SyncMaxWait`（55 秒）后回 304。If-None-Match 只做整串精确比较，弱 ETag、`*`、列表（包括分成多行发送的）一律不匹配。ETag 只由该客户端过滤后的清单计算，私钥只经 bundle 端点。
  - 证书落库（scheduler 的 stored 回调）和 reload 成功发布后，唤醒全部挂起请求。handler 必须先取唤醒 channel，再读配置和库：配置这一侧有确定性测试，库这一侧只能靠 review。stored 回调的接线只有 E2E 的 renew 交付一步能守住。
  - handler 必须用 `ResponseController.SetWriteDeadline` 越过 30 秒的 WriteTimeout，否则 HTTP/1.1 的响应会被截断、HTTP/2 的流会被重置。daemon 关停时，挂起的请求立即回 304。
  - 客户端挂起的 sync 请求不能用 30 秒超时的 HTTP client。本轮任何一步出错（身份续签、请求、应用、对账、钩子）都要退避：5 秒起翻倍，封顶 5 分钟。续签失败时仍用当前身份照发 sync。
  - 客户端与 sigils 之间若有四层代理，空闲超时必须大于 60 秒。
- 鉴权中间件刷新 `last_seen`：内存节流，每个客户端每分钟最多一次条件 UPDATE，节流不能写进 SQL 条件；UPDATE 影响 0 行按 401 处理，其他写库错误只记日志、照常放行（库不可写时仍要能分发已有证书）；无论写库结果如何，节流占位都不释放。并发首次使用同一 pending 身份时，提升失败后重读一次，active 指纹已等于出示指纹就放行。
- 客户端 mTLS 身份必须在到期前自动续签；`client.identity_renew_before` 默认 30 天，允许范围为 1 小时到 89 天。
- sync 循环、reload 和 IPC fetch 的应用阶段（身份续签、取包、写存储、对账、钩子）由同一把锁 pullMu 串行化；sync 的挂起等待不持锁。Reload、IPC fetch 和身份切换通过同一把锁里登记的 cancel 取消在途 sync，循环拿到锁后发现请求已被取消就作废本轮。
- 客户端 socket 在 Unix 上固定为 `/var/run/sigil/sigilc.sock`，不能依赖启动用户的 `$HOME`。
- 服务端外部 HTTPS 可使用公网证书，但客户端证书仍由内部 mini-CA 验证。客户端验证服务端时同时信任系统根和 mini-CA。
- SQLite 和 WAL 包含私钥材料，创建与重开时都必须保持私有权限。schema 迁移只进不退：v5 删除了 clients 表的 push 两列，升级后的数据库不能再用旧版 sigils 打开。

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
  - 挂载里的文件一律报告为 0777，chmod 静默无效。E2E 因此把客户端输出放在客户端容器自己的文件系统里。
  - 宿主进程打开着挂载里的某个文件时（Go 的 os.Open/ReadFile 不带 FILE_SHARE_DELETE），容器里 rename 覆盖这个文件会报 Permission denied。容器可能替换某个文件时，宿主不要打开它。
  - 宿主改写挂载里的文件，容器里立即可见（变长、变短、等长都实测过），所以 E2E 可以在容器运行期间从宿主改 server.yaml。
- 本机 Git for Windows 的 curl（Schannel）校验私有根时会报 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`，要加 `--ssl-no-revoke`；Go 写的 harness 不受影响。
- 不运行或依赖 Docker Desktop。需要容器验证时直接调用 `wslc`。

## 已知未完成项

- E2E 已用 Pebble + challtestsrv + exec DNS hook 覆盖真实 ACME 签发（`LEGO_CA_CERTIFICATES`、`acme.dns_resolvers`、`skip_propagation_check`、首启两张证书并行签发、手动 renew 后客户端拿到新证书）；各家云 DNS provider 仍然没有 E2E。
- `skip_propagation_check` 的接线只有 E2E 的“签发成功”能守住，`acme.dns_resolvers` 的生效只有 `TestIssuanceUsesDNSResolvers` 能守住（开了 skip 时签发照样成功）。改这两处时必须跑 E2E。
- TUI 仍有部分管理操作未接线。
- 对账不比较 Windows 私钥文件的 DACL：DACL 被放宽或从目录继承的，要等内容变化（续期）才复原。从配置删掉 `owner`/`group` 时，Unix 旧 uid/gid、Windows 旧属主和它的读权限 ACE 同样保留到内容变化。要立即生效就删掉输出文件，下一轮对账会重建。
- 输出路径去重只比较 `filepath.Clean` 后的文本（Windows 上不分大小写），相对与绝对两种写法指向同一文件的情况查不出来。
- 2026-09-27 审阅发现的缺陷 A1–A13 见审阅文档，修复进度见 `TODO.md`。
## 修改原则

- 先读现有实现和测试，再做局部改动；不要把未实现功能写成已完成。
- 安全边界、跨模块契约和用户工作流必须增加回归测试。
- 手工文件修改使用 `apply_patch`。
- 仓库已于 2026-09-27 初始化 Git（基线提交 `d0151bf`，`.gitattributes` 固定 LF）；变更可用 `git diff` 审阅，验证仍以格式化、单元测试、静态检查和 WSLC E2E 为准。
- 容器测试结束后确认 WSLC 容器与网络为空，并移除本轮生成的镜像。
