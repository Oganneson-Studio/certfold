[English](../en/security.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 安全

## 信任模型

客户端接收哪些证书只由 `server.yaml` 中的 `subscribers` 决定。`client.yaml` 中 `certificates` 下的条目只说明把客户端已接收的证书写到哪里。输出设置参阅[客户端配置](configuration.md#客户端配置)。

注册令牌携带预期的客户端名称、服务端 URL 和 mini-CA 证书。`certfoldc` 在发送令牌或 CSR 之前先验证 TLS，然后将其 mTLS 身份存储在私有的、原子替换的配置文件中。`certfoldc` 同时信任操作系统的根证书和 Certfold mini-CA 来验证服务端，因此两种服务端证书均可使用。客户端证书始终由 mini-CA 签发和验证。

在 Windows 上，CLI 只与属主为 SYSTEM 或 Administrators 的命名管道通信，因此低权限进程无法冒充守护进程。

服务端的只读 IPC 应答仅暴露元数据，从不包含证书私钥或注册令牌的哈希。

`client.data_dir` 存放 `certs.json`，其中包含所有已订阅证书及其私钥的副本，写入时使用与 `client.yaml` 相同的私有权限。请将其放在能存储 Unix 权限位的文件系统上：WSL drvfs 挂载和没有 Unix 扩展的 CIFS 都无法存储。

## Windows 上的私钥输出

包含私钥的输出（`pem-key`、`pem-bundle`、`pkcs12`）在创建时使用受保护的 ACL，授予 SYSTEM 和 Administrators 完全访问权限（未提权运行时还包括当前用户）。`mode` 在 Windows 上不生效，无法放宽该 ACL。要允许 IIS 或 nginx 等服务读取密钥，请将该输出的 `owner` 设置为服务的账户名或 SID；该账户获得读取权限，但不会成为文件的属主。`owner` 仅对私钥类输出生效；对其他格式静默忽略。

在 Windows 上，对账只比较每个输出的内容，不比较其 ACL 或属主。ACL 被放宽的密钥文件，或因其他工具写入而继承了目录 ACL 的密钥文件，会保持该 ACL 直到下次续期时内容变更。从配置中删除 `owner` 同样会保留先前账户及其读取权限，在 Unix 上也是如此。要立即应用配置，请删除该文件；下一轮对账会重新创建它。

## 目录要求

`certfolds` 和 `certfoldc` 在启动时检查特定目录，检查不通过时拒绝运行。在 Unix 上，只有 `certfolds` 检查其数据目录（`CheckPrivateDirectory`）；`certfoldc` 在 Unix 上不检查目录。在 Windows 上，两个守护进程都检查配置目录和数据目录。`certfoldc enroll` 在写入前检查配置目录。检查因平台而异：

- **certfolds data_dir**（Unix）：权限 `0700`，属主为运行用户。（Windows）：完全私有——只有 SYSTEM、Administrators 以及未提权时的运行用户可以访问；属主必须是其中之一。
- **配置目录和 certfoldc data_dir**（Windows）：属主为 SYSTEM、Administrators 或（未提权时）当前用户；其他账户不能写入、删除或修改权限。
- **ca/ 子目录**：每次启动时由 `ca.Bootstrap` 检查并收紧。在 Unix 上只执行收紧（Unix 上的检查是空操作）。

当数据目录不存在时，守护进程会以私有权限创建它。配置目录不会自动创建；`certfoldc enroll` 会创建客户端配置目录。当目录存在但检查不通过时，错误信息会指明目录并打印修复命令：

```
configuration directory: C:\ProgramData\Certfold is owned by DESKTOP\Alice, and only NT AUTHORITY\SYSTEM and BUILTIN\Administrators may own it. Its owner may have put files in it and may change who can write to it: remove it, so that it is created again. To keep it instead, check every file in it, then run:
  icacls "C:\ProgramData\Certfold" /setowner *S-1-5-32-544
```

在 Linux 上，如果数据目录的权限为 `0755`：

```
/var/lib/certfolds has mode 0755, and only its owner may have access to it. Check the files in it, then run:
  chmod 700 "/var/lib/certfolds"
```

当错误未提及属主不受信任（Unix 上模式不对，或 Windows 上有多余的 ACL 条目）时，运行它打印的命令即可。当错误提示属主不受信任时，建议是删除该目录让守护进程重新创建；仅在目录内容可以重建时才这样做。不要删除 certfolds 数据目录，除非你接受丢失 mini-CA（所有已注册的客户端都必须重新注册）和证书数据库。

配置目录和 data_dir 的每一级上级目录不能属于不受信任的账户，也不能允许不受信任的账户删除或替换其中的条目。检查只查看目录本身，不查看其上级目录；默认布局（`/etc/certfold`、`/var/lib`、`C:\ProgramData`）满足此要求。

输出文件所在目录及其上级目录也不应允许低权限账户写入：`O_NOFOLLOW` 只保护路径的最后一段，可写的上级目录允许攻击者将前面的组件替换为符号链接。
