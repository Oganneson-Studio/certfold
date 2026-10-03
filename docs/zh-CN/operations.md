[English](../en/operations.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 运维

## 基本流程

```bash
# 启动服务端
certfolds --config /etc/certfold/server.yaml serve

# 创建短期注册令牌（--expires 最大 168h，默认 1h）
certfolds --config /etc/certfold/server.yaml token create --name web-1 --expires 10m

# 注册并运行客户端
certfoldc --config /etc/certfold/client.yaml enroll --token <token>
certfoldc --config /etc/certfold/client.yaml serve

# 通过本地 IPC 查看或触发正在运行的客户端
certfoldc status
certfoldc fetch --cert api-prod
certfoldc reload

# 通过本地 IPC 校验并应用 server.yaml 的受支持变更
certfolds --config /etc/certfold/server.yaml reload
```

在 Linux 上，`certfolds` 和 `certfoldc` 的管理命令需要 root 权限，因为 IPC socket 的属主是 root。当配置文件不存在或用户没有读取权限时，CLI 使用平台默认的 IPC 端点。当文件可读但 `ipc_socket` 无法使用（文件不是有效 YAML、`ipc_socket` 中的 `${VAR}` 未设置或路径是相对路径）时，CLI 会报告错误并建议使用 `--ipc`。如果设置了自定义 `ipc_socket`，请以 root（或提权）身份运行 CLI，或传递 `--ipc`。

`token create`、`reload`、`cert add` 和 `cert remove` 由运行中的守护进程通过本地 IPC 处理，守护进程未运行时会失败。`token create` 还会在 `server.public_url` 未设置且 `server.listen` 未指定客户端可达的主机名时拒绝运行。当名称属于已注册的客户端或未过期的未使用令牌时，`token create` 需要 `--replace`；使用 `--replace` 时，它还会吊销该名称的所有未使用令牌。`cert add` 和 `cert remove` 编辑 `server.yaml` 并原子地应用新配置；如果应用失败，文件会被写回原始内容。文件中已有的其他可热重载变更会同时生效；如果文件中包含需要重启的变更，命令会被拒绝且文件不会被修改。在 Windows 上，第一次 `cert add` 或 `cert remove` 会将 `server.yaml` 变为私有 DACL（仅 SYSTEM 和 Administrators）。

`certfoldc enroll` 在发送令牌前先写入 `client.yaml`；如果注册失败，它创建的文件会被删除（已有的文件不受影响）。名称或服务端 URL 不符合命名规则的令牌会在发起网络请求前被拒绝。不带 `--token` 时，`certfoldc enroll` 会读取 `CERTFOLDC_TOKEN` 环境变量。当 `enroll` 覆盖已有的身份时，正在运行的 `certfoldc` 守护进程会继续使用旧身份（服务端已不再接受该身份），直到执行 `certfoldc reload` 或重启服务。

`client remove` 和 `token revoke` 在名称或 ID 不存在时会报告错误（退出码 1），而不是静默地声称成功。删除客户端后，`client remove` 会列出该客户端订阅的证书，并建议对每张证书执行 `certfolds cert renew`。客户端持有的旧证书和私钥在过期前仍然有效；续期会签发新证书，但不会吊销旧证书。

### 作为服务运行

在 Linux 上将 `certfolds` 安装为 systemd 服务：

```bash
sudo install -m 0755 certfolds-linux-amd64 /usr/local/bin/certfolds
sudo install -d -m 0700 /etc/certfold
sudo install -m 0600 server.yaml /etc/certfold/server.yaml
sudo certfolds --config /etc/certfold/server.yaml service install
sudo certfolds service start
```

发布的文件名带有 `-<os>-<arch>` 后缀；`install -m 0755` 一步完成重命名和添加可执行权限。如果 `server.yaml` 引用了 `${VAR}`，请在启动服务之前写好[服务环境变量文件](#linux-服务环境变量)。在无法使用[一键安装](installation.md#一键安装)的主机上，按同样方式安装 `certfoldc` 并完成注册，然后运行 `sudo certfoldc --config /etc/certfold/client.yaml service install` 和 `sudo certfoldc service start`。

在 Windows 上，以服务（LocalSystem）或提权命令行运行守护进程。关于 IPC 端点的安全保障，参阅[信任模型](security.md#信任模型)。

要将 `certfolds` 注册为 Windows 服务：

```powershell
certfolds --config <path> service install    # 以 LocalSystem 注册 "serve --config <path>"
certfolds service start
```

事件写入 Application 事件日志，来源为 `certfolds`。`service uninstall` 会删除事件日志源。

`service install` 将守护进程注册到系统服务管理器，服务管理器在守护进程失败后会重启它；详见[系统服务](#系统服务)。

## 交付与对账

`certfoldc` 保持一个到 `GET /v1/sync` 的请求处于打开状态。服务端会在客户端订阅的证书签发或热重载改变了客户端接收的内容后立即应答，否则在 55 秒后应答；然后客户端再次发起请求。`certfoldc` 与 `certfolds` 之间的四层代理需要空闲超时大于 60 秒，否则每次请求都会失败，交付退化为按重试间隔进行。

每一轮之后——无论服务端报告了变更、报告无变更还是无法访问——`certfoldc` 都会将每个已配置的输出与本地存储进行对账：

- 缺失或内容不同的输出会被重写。同一张证书的所有输出先暂存，再一起替换。
- 内容正确但权限位或属主不对的输出会原地修正。在 Windows 上，对账只比较内容；权限和属主的变更在下次内容变更（续期）时或文件被删除后才生效。修正权限或属主不算变更，不会运行 `on_change`。
- 在无法存储 Unix 权限位的文件系统上，配置的 `mode` 不会生效；请通过其他方式保护此类目录。
- 空闲的客户端约每 55 秒对账一次。在错误持续期间（包括 `on_change` 程序失败），轮次间隔从 5 秒退避到 5 分钟。

这是声明式模型：对输出的手动编辑会在一轮之内被还原。`certfoldc fetch` 会立即拉取并对账；`--cert NAME` 还会重新下载该证书。`certfoldc reload` 在按新配置完成对账后才返回；它不会清除 `certfoldc status` 显示的最近错误，最近错误会在下一轮更新。修改 `client.data_dir` 或 `client.ipc_socket` 需要重启。

## on_change 程序

`on_change` 在证书有新材料存入或其任何输出的内容被重写后运行程序，包括被删除或被修改的输出被恢复时。仅修正权限或属主不会触发运行。

- 它是一个参数列表，第一项必须是绝对路径。不经过 shell 运行。
- 所有输出对账完成后，程序按证书名称顺序逐个运行。输出未能全部写入的证书不会运行其程序。
- 每次运行的超时时间为 2 分钟。程序以 `certfoldc` 的服务账户运行，继承其完整环境，stdin 为空。工作目录是服务的工作目录（systemd 下为 `/`，Windows 服务为 `System32`），因此请使用绝对路径。
- 运行失败后每轮重试，直到成功。期间客户端会退避，新证书的到达可能延迟最多约 5 分钟。`certfoldc status` 会显示错误，错误信息只包含证书名称和退出状态或超时；程序输出的最后 4 KiB 仅写入服务日志（参阅[事件与日志](#事件与日志)），不会出现在 `certfoldc events` 中。
- 程序启动的后台进程必须重定向自己的 stdout 和 stderr。否则 `certfoldc` 会在程序退出后等待 5 秒，然后关闭管道、记录日志并将本次运行计为成功；在 Unix 上，该进程在下次写入时可能被 `SIGPIPE` 终止。`nohup` 不会重定向已经是管道的输出。
- `client.yaml` 中的值经过 `${VAR}` 展开，因此参数中的字面量 `$` 需要写成 `$$`。
- 当 `certs.json` 初始为空时，每张配置了 `on_change` 程序的证书都会运行一次，即使其输出已经是最新的。

在 Windows 上，通过完整路径运行 PowerShell 脚本，不要使用 `.bat` 或 `.cmd` 文件：`cmd.exe` 会重新解析参数，包含特殊字符的值会被破坏。请使用 `powershell.exe -File`：

```yaml
certificates:
  web-iis:
    outputs:
      - format: pkcs12
        path: 'C:\certfold\web.pfx'
        password: "${PFX_PASSWORD}"
    on_change: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\certfold\reload-iis.ps1']
```

## 续期

`certfolds` 自动续期每张证书。当 ACME CA 发布续期窗口（ARI，RFC 9773）时，`certfolds` 在窗口内随机选取一个时点进行续期；该时点在窗口不变时保持固定。当 CA 未提供 ARI 时，`certfolds` 使用与 Let's Encrypt 指导一致的比例规则：在证书剩余三分之一寿命时续期，寿命不足 10 天的证书在剩余一半寿命时续期。

`certfolds cert list` 和 `certfolds cert show` 显示续期时点及其来源；参阅[运行时热重载与签发](#运行时热重载与签发)。

续期是自动的，无需配置。

**当 CA 宣布大规模吊销时**，运行 `certfolds reload` 使所有证书立即重新查询 ARI。否则下一次查询可能要等最多 24 小时。

证书到手时就已到续期时点的情况下，有两道防护避免陷入密集重试：

- **比例规则**：错误信息为 `issued certificate was stored, but is already due for renewal (lifetime ..., renewal due ...)`。证书会被存储并交付，但此次签发计为失败。修复原因后使用 `certfolds cert renew <name>` 或 `certfolds reload` 清除退避。
- **ARI**：错误信息为 `renewal window of a newly issued certificate has already passed`。CA 返回了一个完全在过去的 ARI 窗口。`certfolds reload` 会清除数据库中的退避，但内存中的防护仍然阻止续期，直到退避到期；要立即续期，请使用 `certfolds cert renew <name>`。

## 事件与日志

两个守护进程都将结构化日志行写入 stderr，在 systemd 下进入 journald。在 Windows 上作为服务运行时，事件写入 Application 事件日志，来源为服务名（`certfolds` 或 `certfoldc`），事件 ID 分别为 1（INFO）、2（WARN）和 3（ERROR）。

每个守护进程还在内存中保留最近 500 条事件。通过 `events` 命令读取：

```bash
certfolds events           # 文本格式
certfolds events --json    # JSON 数组
certfoldc events           # 文本格式
certfoldc events --json    # JSON 数组
```

`certfolds events` 使用全局 `--json` 标志；`certfoldc events` 有自己的局部 `--json` 标志。

事件包括证书签发、注册、热重载结果、身份续签、客户端和令牌管理以及 ARI 窗口更新。`on_change` 和 `exec` DNS 程序的输出是敏感信息，从不出现在事件中；它只写入服务日志（stderr 或 journald）。在 Windows 上，服务日志就是事件日志，输出显示为 `(withheld)`，因此没有任何地方记录；钩子脚本应自行记录输出。

对外 HTTPS 监听端口的 TLS 握手错误仅写入服务日志，且限速为每分钟 10 条。它们不会出现在 `certfolds events` 中。

## TUI

### 服务端 TUI（certfolds）

不带子命令运行 `certfolds` 会打开服务端 TUI，每 2 秒从守护进程刷新一次。

五个标签页：

| 标签页 | 内容 |
|---|---|
| Overview | 证书状态计数、令牌计数（unused / used / expired）、最近 10 条事件 |
| Certificates | Name、State、Not After、Renew At（含 `ari`/`ratio`）、Domains、Subs；选中行查看详情 |
| Clients | Name、Last Seen、Enrolled、Certificates（订阅证书的反向查找） |
| Tokens | ID、Name、Status、Expires |
| Events | 自动换行，自动跟踪最新事件 |

按键：

| 按键 | 操作 |
|---|---|
| `1`-`5` | 切换标签页 |
| `tab` / `shift+tab` | 下一个 / 上一个标签页 |
| `k`/`up`、`j`/`down` | 在表格和事件中移动 |
| `pgup`、`pgdn` | 在事件中翻页 |
| `g`、`G` | 最旧 / 最新事件 |
| `R` | 续期选中的证书（按 `y` 确认） |
| `d` | 删除选中的客户端或吊销选中的令牌（按 `y` 确认） |
| `n` | 创建新令牌（输入名称和 TTL，然后按 `enter`） |
| `r` | 立即刷新 |
| `?` | 显示所有按键 |
| `q` / `ctrl+c` | 退出（ctrl+c 在对话框中也有效） |

令牌创建后会和安装命令一起显示在结果对话框中。关闭对话框后令牌被丢弃；要获取完整的单行命令，请吊销它并在命令行使用 `certfolds token create`。选中行以 `›` 标记，即使没有颜色也能看到。

### 客户端 TUI（certfoldc）

不带子命令运行 `certfoldc` 会打开客户端 TUI，每 2 秒刷新一次。守护进程未运行时会报错退出。

标题栏显示客户端名称、服务端 URL、在线/离线状态、最近拉取时间和最近错误。下方是证书表格，包含 Name、Not After（日期加剩余天数；过期时显示 `expired`）、Outputs、on_change 和 Pending 列。黄色的 Not After 表示证书已过比例规则的续期时点；当 CA 通过 ARI 建议更晚的窗口时，`certfolds` 可能更晚续期。Pending 表示自证书或其某个输出变更以来 `on_change` 程序尚未成功执行。表格下方是最近的事件。

按键：

| 按键 | 操作 |
|---|---|
| `f` | 立即拉取（等待完成，包括钩子） |
| `R` | 热重载 client.yaml |
| `r` | 刷新显示 |
| `e` | 全屏事件（跟踪最新事件） |
| `?` | 完整帮助和颜色图例 |
| `q` / `ctrl+c` | 退出 |

在事件视图中：`k`/`up`、`j`/`down`、`pgup`/`b`、`pgdn`/`space`、`u`（半页上翻）、`d`（半页下翻）。

当守护进程重启时，事件会清空并从头重新获取。如果证书数量超出终端可显示的行数，最后一行显示 `+N more; certfoldc status --json lists them all`。

## 运行时热重载与签发

`certfolds reload` 校验 `server.yaml` 并通过本地服务端 IPC 端点应用受支持的变更。ACME 设置、DNS 提供商和证书定义（包括其订阅者）可以在不重启守护进程的情况下更新。修改 `server.listen`、`server.public_url`、`server.data_dir`、`server.ipc_socket`、`server.tls_cert_file`、`server.tls_key_file` 或 `acme.dns_resolvers` 会被拒绝，并提示重启。TLS 文件路径和监听地址在启动时固定；文件内容会在每次握手时自动热更新（参阅[生产环境 TLS](installation.md#生产环境-tls)）。

`certfolds` 并行签发证书，同时最多 4 张，每张证书同一时刻最多一个签发：

- 热重载不等待在途签发。它会清除重试退避（但保留最近错误信息），发布新配置并立即检查证书定义。
- 热重载之前开始的签发，如果该证书的 CA directory、域名或密钥类型在此期间发生了变化，其结果会被丢弃，并按新配置重新签发。存储的证书材料与这些设置绑定，因此绝不会分发同名的旧材料。
- 签发失败 5 分钟后重试，之后间隔逐次翻倍，最长 24 小时。退避存储在数据库中，重启后不会清零，因此在修复原因（例如 DNS 凭据）后，请运行 `certfolds reload` 或 `certfolds cert renew <name>` 而不是重启。
- `certfolds cert list` 显示每张已配置证书的状态（`issuing`、`backoff`、`valid` 或 `pending`），以及 RENEW AT 列，包含续期时点及其来源（`ari` 或 `ratio`）。`certfolds cert show <name>` 额外显示订阅者、失败次数、最近错误和下次尝试时间。

`certfoldc` 在到期前自动续签其 mTLS 身份。`client.identity_renew_before` 默认为 30 天，允许值为 1 小时到 89 天。续签失败不会中断交付：客户端继续使用当前身份，每轮重试续签。

数据库 schema 只向前迁移。遇到更新的 schema 时，`certfolds` 会拒绝打开数据库并写明两个版本号。

## 系统服务

在 Windows 上，`service install` 注册守护进程并写入恢复动作（10 秒后重启，24 小时后重置失败计数）。事件写入 Application 事件日志。`service uninstall` 会删除事件日志源。

在 systemd 下，`service install` 写入一个包含 `Restart=on-failure`、`RestartSec=5` 和 `KillMode=mixed` 的单元。`KillMode=mixed` 在停止时仅向守护进程发送 SIGTERM；它启动的进程（exec DNS 程序）会继续运行直到守护进程退出，然后收到 SIGKILL。持续失败的守护进程每 5 秒重启一次，无限循环。要更新已有的单元，先运行 `service uninstall` 再运行 `service install`；kardianos 在服务已存在时会报错。服务的环境变量放在 `/etc/sysconfig` 下的文件中；参阅 [Linux 服务环境变量](#linux-服务环境变量)。

`service install` 会将配置路径解析为绝对路径。查找顺序依次为 `--config`、`CERTFOLDS_CONFIG` / `CERTFOLDC_CONFIG`、平台默认值。

作为服务运行时，守护进程检查的目录必须属于服务账户。在 Linux 上，`certfolds` 以 root 运行，因此其数据目录必须属于 root（uid 0）；`certfoldc` 在 Unix 上不检查目录。在 Windows 上，两个守护进程的配置目录和数据目录必须属于 SYSTEM 或 Administrators。如果属主不匹配，守护进程拒绝启动，错误信息会打印修复命令（参阅[目录要求](security.md#目录要求)）。systemd 每 5 秒重启一次守护进程，直到属主被修正；Windows 上恢复动作每 10 秒重启一次，`sc query <name>` 报告退出码 1067。手动创建的目录（例如在提权 Git Bash 会话中使用 `mkdir`）属主为用户自己的 SID 而非 Administrators，会被拒绝；`certfolds` 和 `certfoldc` 自行创建的目录属主为 Administrators。

关于如何解读 `service status` 的输出，参阅[服务状态](troubleshooting.md#服务状态)。

### Linux 服务环境变量

在 systemd 下，DNS 凭据、`LEGO_CA_CERTIFICATES` 以及服务的其他环境变量放在 `/etc/sysconfig/<name>` 中，即 `/etc/sysconfig/certfolds` 或 `/etc/sysconfig/certfoldc`。文件每行一个 `KEY=value`，属主应为 root，权限 `0600`。在没有 `/etc/sysconfig` 的发行版上，先用 `sudo install -d -m 0755 /etc/sysconfig` 创建该目录。变更仅在服务重启后生效。

为了不让凭据出现在命令行和 shell 历史记录中，让 root shell 创建文件，再把各行粘贴进去并以 Ctrl-D 结束（也可以通过管道输入）：

```bash
sudo sh -c 'umask 077; cat > /etc/sysconfig/certfolds'
```

`certfolds config validate` 同样会展开 `${VAR}` 引用，因此运行时需要先加载该文件；否则会报 `environment variable "X" is not set`：

```bash
sudo sh -c 'set -a; . /etc/sysconfig/certfolds; certfolds --config /etc/certfold/server.yaml config validate'
```

### Windows 服务环境变量

DNS 凭据、`LEGO_CA_CERTIFICATES` 以及 Windows 服务的其他环境变量放在注册表中。`certfoldc` 服务使用相同机制；将下文路径中的 `certfolds` 替换为 `certfoldc` 即可。变更仅在服务重启后生效；`certfolds reload` 不会重新读取环境变量。

`service install` 将服务的注册表键限制为仅 SYSTEM 和 Administrators 可访问，因此存放在其中的值不会被其他本地用户读取。

PowerShell（提权）：

```powershell
[Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\certfolds', 'Environment', [string[]]@('NAME=value'), 'MultiString')
Restart-Service certfolds
```

在命令中输入的值可能被 PowerShell 脚本块日志（事件 4104）记录，下方的 `reg add` 形式可能被进程命令行审计记录。在启用了上述任一审计且值为凭据时，请改用 `regedit` 输入。

cmd（提权；`&&` 在 Windows PowerShell 5.1 中不可用）：

```bat
reg add HKLM\SYSTEM\CurrentControlSet\Services\certfolds /v Environment /t REG_MULTI_SZ /d "NAME=value\0OTHER=2" /f
net stop certfolds && net start certfolds
```

多个变量在 `reg add` 形式中用 `\0` 分隔；在 PowerShell 中传入数组：`@('NAME=value', 'OTHER=2')`。

两种形式都会替换整个列表而非追加。写入一个变量会删除已设置的所有其他变量（如 DNS 凭据），仍引用这些变量的配置会导致服务启动失败。请先读取当前列表，再写回完整列表：

```powershell
[Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\certfolds', 'Environment', $null)
```

要删除变量：`Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\certfolds' -Name Environment`。`service uninstall` 会删除整个服务键，包括此值：在 `service uninstall` 和 `service install` 之后，需要在启动服务前重新设置变量。安装脚本在重新安装 `certfoldc` 服务时会保留 `Environment` 值，并且仅通过 .NET 方法调用处理这些值，PowerShell 模块日志不会记录这些调用。

当配置中通过 `${VAR}` 引用的变量未设置时，服务启动失败（`ExitCode=1067`），Application 事件日志（事件 ID 3）显示 `load config: expand env: <field>: environment variable "X" is not set`。
