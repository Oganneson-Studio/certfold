[English](../en/installation.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 安装

## 一键安装

从 [Releases 页面](https://github.com/Oganneson-Studio/certfold/releases)下载二进制文件，并用 `sha256sum -c SHA256SUMS` 校验；`gh attestation verify <file> --repo Oganneson-Studio/certfold` 还可以额外校验其构建来源证明。将 `certfoldc-*` 文件原样复制到服务端的 `<data_dir>/binaries/`：它们的文件名（如 `certfoldc-linux-amd64`、`certfoldc-windows-amd64.exe`）正是 `certfolds` 向安装脚本提供的文件名。该目录在 `certfolds` 首次启动后才存在；在此之前，请用 `sudo install -d -m 0755 /var/lib/certfolds/binaries` 创建。复制进去的文件立即可供下载，无需重启。要将 `certfolds` 本身安装为服务，参阅[作为服务运行](operations.md#作为服务运行)。创建注册令牌后，`certfolds token create` 会打印包含令牌的安装命令。

**Linux / macOS**（以可以 sudo 的用户身份运行）：

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh -s -- --token '<token>'
```

不带 `--token` 时，脚本会在终端上提示输入令牌（不回显），令牌不会出现在命令行中。在多人共用的主机上推荐此方式。在 macOS 上，终端的单行输入限制（1024 字符）可能截断令牌（约 1100 字符）；此时请改用 `--token`：

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh
```

**Windows**（提权 PowerShell，5.1 或 7）：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1'))) -Token '<token>'
```

不带 `-Token` 时，脚本会通过 `Read-Host -AsSecureString` 提示输入令牌（屏幕上只显示星号）：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1')))
```

`-bor 3072` 前缀为 Windows PowerShell 5.1 提供的协议列表添加 TLS 1.2。Certfold 服务端对外的 HTTPS 监听端口接受 TLS 1.2 及以上版本，而 `certfoldc` 自身的连接（注册和 mTLS）要求 TLS 1.3。

使用 `--token` / `-Token` 时，令牌会出现在进程命令行中：`sh -s -- --token` 对其他用户可见且会保存到 shell 历史记录；`-Token '...'` 留在 PowerShell 会话历史（`Get-History`）中，旧版 PSReadLine 可能将其写入历史文件。要避免令牌出现在命令行中，请省略该标志让脚本交互提示输入。`certfoldc enroll` 不带 `--token` 时会读取 `CERTFOLDC_TOKEN` 环境变量；两个安装脚本都通过此变量将令牌传递给 `certfoldc`。在没有终端的自动化环境中，需要传递 `--token` 或 `-Token`（Linux 会报告 “No terminal to read the token from”；Windows 的 `Read-Host` 在非交互会话中不可用）。

### 重装

在已安装 `certfoldc` 的主机上：使用新令牌（通过 `certfolds token create --name <name> --replace` 创建）运行相同的安装命令。脚本会停止服务、替换二进制文件、使用新令牌注册、重新安装服务并启动。如果注册失败，服务会使用先前的 `client.yaml` 重新启动；如果错误提示服务端已消耗令牌，先前的身份将不再有效，需要使用新的 `--replace` 令牌。如果 `client.yaml` 已存在且名称或服务端 URL 不同，脚本会报告文件路径并提示你删除它。服务启动后，脚本会轮询 `certfoldc status` 最多 15 秒，如果守护进程未应答则报告日志位置。

### 升级二进制文件

仅升级二进制文件而不重新注册：

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh -s -- --upgrade
```

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1'))) -Upgrade
```

`--upgrade` / `-Upgrade` 会停止服务、替换二进制文件并重新启动；如果 `certfoldc` 从未安装过则会失败。不能同时使用 `--upgrade` 和 `--token`。

### 安装写入的文件

在 Linux 上，安装脚本会写入以下文件：

- `/usr/local/bin/certfoldc`
- `/etc/certfold/client.yaml`（文件权限 `0600`，目录权限 `0700`）
- `/var/lib/certfoldc`（由 `certfoldc` 首次启动时创建；安装后即存在，权限 `0700`，属主 root）
- `/var/run/certfold/certfoldc.sock`（权限 `0660`，属主 root；需用 `sudo certfoldc status` 查询）
- `/etc/systemd/system/certfoldc.service`，包含 `Restart=on-failure`、`RestartSec=5` 和 `KillMode=mixed`

### 卸载

在 Linux 上卸载（不要删除 `/var/run/certfold`；`certfolds` 也使用它）：

```bash
sudo certfoldc service stop
sudo certfoldc service uninstall
sudo rm -f /usr/local/bin/certfoldc /etc/certfold/client.yaml
sudo rm -rf /var/lib/certfoldc
# 在服务端上吊销访问权限：
sudo certfolds client remove <name>
```

在 Windows 上卸载（提权 PowerShell）：

```powershell
& 'C:\Program Files\Certfold\certfoldc.exe' service stop
& 'C:\Program Files\Certfold\certfoldc.exe' service uninstall
Remove-Item -Recurse -Force 'C:\Program Files\Certfold'
Remove-Item -Force 'C:\ProgramData\Certfold\client.yaml'
Remove-Item -Recurse -Force 'C:\ProgramData\Certfold\client'
# 在服务端上吊销访问权限：
certfolds client remove <name>
```

如果同一主机上 `certfolds` 也使用 `C:\ProgramData\Certfold`，不要完全删除该目录。

## 生产环境 TLS

一键安装在注册之前先下载 `certfoldc`，因此对外的 Certfold 端点必须提供操作系统已信任的证书。当端点的主机名属于 Certfold 能够签发的域名时，推荐由 Certfold 自己签发该证书；参阅[使用 Certfold 签发的证书](#使用-certfold-签发的证书)。否则，直接配置公网证书：

```yaml
server:
  listen: ":8443"
  public_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfolds"
  tls_cert_file: "/etc/certfold/tls/fullchain.pem"
  tls_key_file: "/etc/certfold/tls/key.pem"
```

原地替换证书和私钥文件；`certfolds` 会在下一次 TLS 握手时自动热更新，无需重启。与私钥不配对的证书会被跳过并记录警告，继续使用先前的证书。请将文件放在本地磁盘上：网络挂载上的 `stat` 如果阻塞，会阻塞所有 TLS 握手。

不设置这些字段时，`certfolds` 使用内部 mini-CA 证书，并在到期前自动重新签发。重新签发失败后会在一分钟后重试。

`server.public_url` 必须是纯 ASCII 的 `https` URL。不能包含引号、反引号、`$`、`\`、空白或控制字符：`install.sh` 将其放在双引号中（`SERVER_URL="..."`），因此 `$`、反引号、`\` 和 `"` 会被插值；`install.ps1` 和注册令牌将其放在 PowerShell 的单引号中，其中弯引号（U+2018-U+201E）也充当引号字符。

关于 `certfoldc` 如何验证服务端以及为何两种服务端证书都可用，参阅[信任模型](security.md#信任模型)。

### 使用 Certfold 签发的证书

服务端主机上的 `certfoldc` 可以把端点证书写入 `certfolds` 读取的文件：

1. 不设置 `tls_cert_file` 和 `tls_key_file` 启动 `certfolds`，此时它使用 mini-CA 证书。在 `server.yaml` 中定义一张覆盖 `public_url` 主机名的证书（已有的通配符证书也可以），并让同一主机上的客户端订阅它。
2. 在同一主机上，用 `certfolds token create --name <client>` 创建令牌，并在 `CERTFOLDC_TOKEN` 中提供令牌运行 `certfoldc enroll`。此时还不能使用一键安装，因为操作系统不信任 mini-CA 证书；注册则通过令牌信任服务端。
3. 在 `client.yaml` 中，将该证书以 `pem-fullchain` 格式写到 `/etc/certfold/tls/fullchain.pem`，以 `pem-key` 格式写到 `/etc/certfold/tls/key.pem`，然后运行 `certfoldc service install` 和 `certfoldc service start`。`certfoldc` 会创建该目录，两个文件的属主均为 root，私钥权限为 `0600`，证书链为 `0644`；`certfolds` 以 root 运行，无需额外调整即可读取。
4. 将 `server.tls_cert_file` 和 `server.tls_key_file` 设为这两个路径，然后重启 `certfolds`。`certfolds reload` 会拒绝对这两个字段的修改。

续期无需任何操作：`certfoldc` 重写文件，`certfolds` 在下一次握手时提供新证书。切换之前注册的客户端继续正常工作。如果 `certfolds` 启动时文件不存在，它会退出并由服务管理器重启；即使服务端停止，`certfoldc` 也会从本地副本恢复这些文件，因此之后的某次重启会成功。两个服务之间不需要设置启动顺序。
