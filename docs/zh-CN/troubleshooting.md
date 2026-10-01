[English](../en/troubleshooting.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 故障排查

## 注册错误

当 `certfoldc enroll` 因网络错误失败时，使用同一个令牌重试。如果重试时收到 `server returned 401: enrollment token was already used`，说明服务端在响应到达之前已消耗了该令牌。该名称的旧身份已在服务端上被替换。使用 `certfolds token create --name <name> --replace` 创建新令牌并重新注册。

当服务端返回 200 但 `certfoldc` 无法使用响应（证书校验失败、响应无法解码）或无法写入 `client.yaml` 时，错误信息会说明服务端已消耗令牌并打印 `--replace` 命令。旧身份在服务端上已不可用。

`server returned 500: internal error` 表示服务端回滚了整个操作；令牌未被消耗，可以使用同一个令牌重试。

## 目录错误

当 `certfolds` 或 `certfoldc` 因目录错误拒绝启动时，参阅[目录要求](security.md#目录要求)了解完整的检查列表和修复方法。

## 服务状态

`service status` 查询服务管理器并通过 IPC socket 探测守护进程：

- **Running**——服务管理器报告正在运行，守护进程已应答。
- **Running (not answering on ...: ...; see ...)**——服务正在运行，但 IPC 端点不存在、拒绝连接或超时。消息中包含日志位置（`journalctl -u <name>`、Application 事件日志或 `/var/log/<name>.err.log`）。
- **Running (cannot check the daemon on ...: ...)**——打开 socket 时遇到权限错误或其他非网络错误。权限错误会附加 “checking it needs root or an elevated administrator”。
- **Stopped**——服务管理器报告服务未运行。
- **query status: ...**（退出码 1）——服务未安装，或服务管理器报告了错误（例如 systemd 的 `failed` 状态）。
