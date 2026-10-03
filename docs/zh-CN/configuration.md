[English](../en/configuration.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 配置

## 服务端配置

`server.yaml` 包含四个顶级段：`server`、`acme`、`dns_providers` 和 `certificates`。所有字段均接受 `${VAR}` 引用（参阅[配置中的环境变量](#配置中的环境变量)）。所有路径字段必须是绝对路径（详见[客户端配置](#客户端配置)）。证书名、`acme.cas` 的键和 `dns_providers` 的键遵循[命名规则](#命名规则)。

### server

| 字段 | 必填 | 默认值 | 可热重载 | 说明 |
|---|---|---|---|---|
| `listen` | 否 | `:8443` | 否（需重启） | 监听地址，格式为 `host:port`。端口必须在 1 到 65535 之间；主机部分可以为空。 |
| `data_dir` | 是 | | 否（需重启） | 数据目录的绝对路径。 |
| `public_url` | 否 | 从 `listen` 推导 | 否（需重启） | 外部可达的 `https` URL，注册令牌和安装脚本会将此地址提供给客户端；内部 mini-CA 的服务端证书也会覆盖该 URL 的主机名。未设置时，URL 从 `listen` 推导，且当 `listen` 未指定客户端可达的主机名（主机部分为空、`0.0.0.0` 或 `::`）时，`token create` 会拒绝运行。关于取值限制，参阅[生产环境 TLS](installation.md#生产环境-tls)。 |
| `tls_cert_file` | 否 | | 否（需重启） | TLS 证书链文件的路径。必须与 `tls_key_file` 同时设置。文件内容会在每次 TLS 握手时自动热更新；参阅[生产环境 TLS](installation.md#生产环境-tls)。 |
| `tls_key_file` | 否 | | 否（需重启） | TLS 私钥文件的路径。必须与 `tls_cert_file` 同时设置。 |
| `ipc_socket` | 否 | 平台默认值 | 否（需重启） | 覆盖默认的 IPC 端点（Unix socket 路径或 Windows 命名管道）。 |

### acme

| 字段 | 必填 | 默认值 | 可热重载 | 说明 |
|---|---|---|---|---|
| `email` | 是 | | 是 | ACME 账户的联系邮箱。必须包含 `@`。修改邮箱会更新 CA 上的联系信息，但不会替换账户密钥。 |
| `default_ca` | 是 | | 是 | `certfolds cert add` 未指定 `--ca` 时使用的 CA。必须是 `cas` 中的某个键。`server.yaml` 中 `certificates` 下的条目仍必须设置 `ca`。 |
| `cas` | 是（至少一个） | | 是 | CA 定义的映射，以名称为键。 |
| `cas.<name>.directory` | 是 | | 是 | ACME directory URL。必须是 `https` URL。修改 directory 会注册新账户，并重新签发使用该 CA 的所有证书。 |
| `cas.<name>.eab_kid` | 否 | | 是 | External Account Binding 的 key ID。必须与 `eab_hmac` 同时设置。 |
| `cas.<name>.eab_hmac` | 否 | | 是 | External Account Binding 的 HMAC 密钥。必须与 `eab_kid` 同时设置。 |
| `dns_resolvers` | 否 | 系统解析器 | 否（需重启） | DNS 解析器列表（`host` 或 `host:port`，默认端口 53），用于 lego 的区域查找、CNAME 跟踪和传播检查。此设置作用于整个进程，修改后需要重启。在 Windows 上为空时，lego 会回退到 Google Public DNS。 |

### dns_providers

每个键是一个提供商名称。关于 `exec` 类型及各类型的完整字段列表，参阅 [DNS-01 验证](#dns-01-验证)。

| 字段 | 必填 | 默认值 | 可热重载 | 说明 |
|---|---|---|---|---|
| `type` | 是 | | 是 | 提供商类型：`cloudflare`、`aliyun`、`tencentcloud`、`route53`、`gcloud` 或 `exec`。 |
| `command` | `exec` 类型必填；其他类型不允许 | | 是 | `exec` 的参数列表；第一项必须是绝对路径。 |
| `skip_propagation_check` | 否 | `false` | 是 | 跳过 lego 对 TXT 记录是否已到达权威 DNS 服务器的检查。仅用于无法响应该检查的 DNS 服务器。 |
| *（特定类型的字段）* | 视类型而定 | | 是 | 参阅 [DNS-01 验证](#dns-01-验证)中的表格。各类型的必填字段：`cloudflare` 需要 `api_token` 或同时设置 `auth_email` 和 `auth_key`；`aliyun` 需要 `access_key` 和 `access_secret`；`tencentcloud` 需要 `secret_id` 和 `secret_key`；`route53` 需要同时设置 `access_key` 和 `secret_key`，或两者都不设置（使用 IAM 角色）；`gcloud` 需要 `project` 或 `service_account_file`。 |

### certificates

证书定义列表。每个元素包含以下字段：

| 字段 | 必填 | 默认值 | 可热重载 | 说明 |
|---|---|---|---|---|
| `name` | 是 | | 是 | 唯一的证书名称。修改名称会触发新的签发；旧的数据库记录变为孤立记录。 |
| `domains` | 是（至少一个） | | 是 | 证书包含的域名。允许使用通配符（`*.example.com`）。每个标签由 1 到 63 个 `a-z`、`A-Z`、`0-9` 和 `-` 字符组成，不能以 `-` 开头或结尾；`*.` 只能作为第一个标签；总长度不超过 253 个字符。 |
| `ca` | 是 | | 是 | `acme.cas` 中定义的 CA 名称。修改 CA 会触发重新签发。 |
| `dns_provider` | 是 | | 是 | `dns_providers` 中定义的提供商名称。 |
| `key_type` | 否 | `ec256` | 是 | 密钥算法：`rsa2048`、`rsa4096`、`ec256` 或 `ec384`。修改密钥类型会触发重新签发。 |
| `subscribers` | 否 | | 是 | 接收该证书的客户端名称。名称遵循[命名规则](#命名规则)，无需事先注册。 |

修改证书的 `ca`、`domains`、`key_type` 或其 CA 的 `directory` 会按新配置触发重新签发。存储的材料与这些设置绑定，因此旧材料绝不会被分发。完整的热重载规则参阅[运行时热重载与签发](operations.md#运行时热重载与签发)。

## 客户端配置

`client.yaml` 指定服务端地址、客户端的数据目录，以及对每张证书的处理方式：

```yaml
client:
  name: web-1
  server_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfoldc"
certificates:
  api-prod:
    outputs:
      - format: pem-fullchain
        path: /etc/nginx/certs/api.pem
      - format: pem-key
        path: /etc/nginx/certs/api.key
    on_change: ["/usr/sbin/nginx", "-s", "reload"]
```

- 客户端接收哪些证书只由 `server.yaml` 中的 `subscribers` 决定。`client.yaml` 中 `certificates` 下的条目只说明把客户端已接收的证书写到哪里。
- 输出格式包括 `pem-cert`、`pem-key`、`pem-fullchain`、`pem-bundle`、`pkcs12`（需要 `password`）和 `der`。`mode`、`owner` 和 `group` 为可选项。私钥类输出的默认权限为 `0600`，其他输出为 `0644`。`mode` 按八进制解析：`640` 表示 `0640`；也接受 `0o640`。包含 `8` 或 `9` 的值（例如 `384`，即 `0600` 的十进制形式）会被拒绝，`certfoldc` 因此拒绝启动。
- `server.yaml`（`data_dir`、`ipc_socket`、`tls_cert_file`、`tls_key_file`、gcloud 的 `service_account_file`）和 `client.yaml`（`data_dir`、`ipc_socket`、输出的 `path`）中的所有路径字段必须是绝对路径。在 Windows 上，`\dir` 和 `C:dir` 不算绝对路径；命名管道必须写成 `\\.\pipe\...`。`${VAR}` 引用在检查前展开。相对路径会被拒绝，错误信息为 `<field>: must be an absolute path, got "<value>"`。
- 两个输出不能共享同一路径。路径经规范化后比较，在 Windows 上不区分大小写。
- `enroll` 会将客户端的 mTLS 身份写入此文件。
- `server.yaml` 和 `client.yaml` 中的未知字段都会被拒绝。`client.yaml` 没有顶级 `outputs` 映射；`server.yaml` 没有 `clients` 段（这一功能由 `subscribers` 承担）。

`client.data_dir` 存放 `certs.json`，其中包含所有已订阅证书及其私钥的副本，写入时使用与 `client.yaml` 相同的私有权限。请将其放在能存储 Unix 权限位的文件系统上（参阅[信任模型](security.md#信任模型)）。

## 命名规则

`server.yaml` 中的所有名称——证书名、`acme.cas` 的键、`dns_providers` 的键——以及客户端名称遵循同一规则：小写 DNS 标签，由 1 到 63 个 `a-z`、`0-9` 和 `-` 字符组成，不能以 `-` 开头或结尾。

证书名同时出现在 `server.yaml` 和每个订阅者的 `client.yaml` 的 `certificates.<name>` 下；重命名时需要同时修改两处。CA 或提供商的名称作为 `acme.cas` 或 `dns_providers` 中的键出现，同时被引用它的字段使用；重命名时需要同时修改键和引用。不符合规则的名称在启动和热重载时被拒绝。

重命名 CA 会以新名称注册新的 ACME 账户。重命名证书会触发新的签发；旧的数据库记录变为孤立记录。当服务端下发的证书被重命名但 `client.yaml` 中的键未更新时，`certfoldc status` 会显示该证书的 Outputs 为 0。如果服务端下发的证书名不符合命名规则，`certfoldc` 会报告错误，停止交付该证书并删除存储的材料；输出文件不受影响。

## 配置中的环境变量

`server.yaml` 和 `client.yaml` 中的值可以通过 `${VAR}` 或 `${VAR:-default}` 引用环境变量。`$$` 表示字面量 `$`，未设置且没有默认值的变量会报错。引用在 YAML 解析之后、在每个标量值内展开：

- 值按原样插入。前后的空格和换行符会保留，值中的引号、`#` 或 `: ` 不会被重新解析为 YAML 结构。但展开后的标量会被重新推断类型：展开为裸数字、`true` 或 `null` 的 `${VAR}` 会变成对应类型，除非在 YAML 中给引用加了引号（参阅 [DNS-01 验证](#dns-01-验证)）。
- 映射的键不会被展开。
- 在流式集合中，需要给引用加引号，例如 `["${HOST}"]`，因为 `{` 在那里是流指示符。

## DNS-01 验证

每张证书从 `dns_providers` 中指定一个 DNS 提供商。除了 lego 的内置提供商外，`exec` 类型可以运行你自己的程序来创建和删除验证记录：

```yaml
acme:
  dns_resolvers: ["10.0.0.53"]   # 可选；见下文
dns_providers:
  internal:
    type: exec
    command: ["/usr/local/bin/certfold-dns-hook", "--zone", "example.com"]
certificates:
  - name: api-prod
    dns_provider: internal
    # ...
```

`command` 是一个参数列表；第一项必须是绝对路径。`certfolds` 在验证前以 `command... present <fqdn> <value>` 运行它，验证后以 `command... cleanup <fqdn> <value>` 运行：

- `<fqdn>` 是 TXT 记录名（已跟随 CNAME），末尾带点。`<value>` 是 TXT 值。退出状态 0 表示成功。
- 值可能以 `-` 开头，因此请按位置读取最后三个参数。不要使用 getopt、argparse 或 PowerShell 的 `param()` 块来解析它们：以 `-` 开头的值会被当作选项，PowerShell 会静默绑定空字符串。在 PowerShell 中，请使用 `$action, $fqdn, $value = $args[-3..-1]`。
- 每次运行的超时时间为 2 分钟。钩子以 `certfolds` 的服务账户运行，继承其完整环境，包括从 `server.yaml` 引用的所有凭据。工作目录是服务的工作目录（Windows 服务为 `System32`，systemd 下为 `/`），因此请使用绝对路径。
- 不同证书可以同时运行钩子。同一证书的多个域名在处理时彼此不等待。
- 钩子启动的后台进程必须重定向其输出；否则钩子会在退出 5 秒后失败。
- 失败时，错误信息只包含动作、记录和退出状态或超时。钩子的输出会截断后写入服务日志，不会出现在 `certfolds events` 中。

在 Windows 上，通过完整路径运行 PowerShell 脚本，例如 `command: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\certfold\hook.ps1']`。

在 Windows 上，不要使用 `.bat` 或 `.cmd` 文件：`cmd.exe` 会重新解析参数，包含特殊字符的值会被破坏。请将钩子写成 `.ps1` 脚本并通过 `powershell.exe -File` 运行。不使用 CNAME 委派时，可在服务环境中设置 `LEGO_DISABLE_CNAME_SUPPORT=true` 关闭 lego 的 CNAME 查找（设置方法参阅 [Windows 服务环境变量](operations.md#windows-服务环境变量)）。

每种内置提供商类型除 `type` 和 `skip_propagation_check` 外只接受以下字段（未知字段或非字符串值会报错）：

| 类型 | 字段 |
|---|---|
| `cloudflare` | `api_token`, `zone_api_token`, `auth_email`, `auth_key` |
| `aliyun` | `access_key`, `access_secret` |
| `tencentcloud` | `secret_id`, `secret_key` |
| `route53` | `access_key`, `secret_key`, `region` |
| `gcloud` | `project`, `service_account_file` |
| `exec` | *（无；使用 `command`）* |

值必须是字符串。像 `12345` 这样的裸数字会被 YAML 解析为整数；请将其写成 `"12345"`。如果 `${VAR}` 的值是裸数字、`true` 或 `null`，在 YAML 中也必须加引号写成 `"${VAR}"`，否则展开后的值会被重新推断类型。`${VAR:-}` 展开为空字符串，对于必填字段视为未设置。

对于 `gcloud`，`project` 会覆盖 `service_account_file` 密钥文件中的项目，因此服务账户可以管理另一个项目中的 Cloud DNS 区域；未设置 `project` 时，使用密钥文件中的项目。

其他 DNS-01 设置：

- 在提供商上设置 `skip_propagation_check: true` 会跳过 lego 对 TXT 记录是否在区域的权威 DNS 服务器上可见的检查。仅适用于无法响应该检查的 DNS 服务器；跳过后 lego 只等待一个 4 秒的轮询间隔。如果提供商的权威 DNS 服务器能够响应该检查（例如 Cloudflare），跳过检查会导致签发间歇性失败：CA 可能在记录尚未到达该提供商全部权威 DNS 服务器时就发起查询，订单因 `No TXT record found` 而失败。
- `acme.dns_resolvers` 设置 lego 用于区域查找、CNAME 跟踪和传播检查的解析器。此设置作用于整个进程，修改后需要重启。为空时，lego 使用系统解析器，在 Windows 上会回退到 Google Public DNS。
- 共享同一域名的多张证书会并行签发，使用同一条 `_acme-challenge` 记录。提供商可能拒绝第二条记录，且一张证书的清理会同时删除另一张的记录，导致其中一张失败并在退避后重试。请避免不同证书之间的域名重叠。
- 要使用私有 ACME CA，请将 `certfolds` 的 `LEGO_CA_CERTIFICATES` 设置为该 CA 根证书的路径。如果该文件无法读取，lego 会 panic。
