[English](../en/limitations.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 已知限制

- 使用 `--token` / `-Token` 时，令牌会出现在进程命令行中；如何避免此问题参阅[一键安装](installation.md#一键安装)。
- 容器端到端测试通过 `exec` DNS 提供商签发证书。lego 的内置云 DNS 提供商中只有 `cloudflare` 有覆盖，由另一套端到端测试从 Let's Encrypt staging 环境真实签发证书；`aliyun`、`tencentcloud`、`route53` 和 `gcloud` 未被端到端测试覆盖。
- 对账不比较 Windows ACL；参阅 [Windows 上的私钥输出](security.md#windows-上的私钥输出)。
- 输出路径去重在 `filepath.Clean` 后比较路径（Windows 上不区分大小写）。无法检测通过符号链接或硬链接产生的重复；macOS APFS 上仅大小写不同的路径；以及在 Windows 上，`\\?\` 和 `\\.\` 前缀、8.3 短名、尾随点和空格、映射盘符与 UNC 路径之间的差异。
- 寿命不超过约两倍 CA NotBefore 回拨时长的证书（Let's Encrypt 回拨 1 小时，即约 2 小时以内的证书）不受支持：它们到达时已过续期时点，会被到货即到期防护捕获，防护会退避而非立即重试。
- mini-CA 根证书在 10 年后过期，没有轮换机制。剩余不足一年时，服务端会在启动和每次重新签发服务端证书时记录警告。
- ARI 不对 5xx 响应做短间隔指数退避（lego 不暴露 HTTP 状态码）；会在 6 小时后重新查询。
- ARI 窗口内随机选取的续期时点不持久化；重启后会在同一窗口内重新随机选取。
- 热重载被拒绝时，YAML 类型错误可能在事件和服务日志中包含最多约 10 个字符的配置值。
- macOS 服务（launchd LaunchDaemon）、macOS 安装路径以及不使用 systemd 的 Linux 发行版上的重启行为未在真实机器上测试。
