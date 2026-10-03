[English](../en/troubleshooting.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 故障排查

## 注册错误

当 `certfoldc enroll` 因网络错误失败时，使用同一个令牌重试。如果重试时收到 `server returned 401: enrollment token was already used`，说明服务端在响应到达之前已消耗了该令牌。该名称的旧身份已在服务端上被替换。使用 `certfolds token create --name <name> --replace` 创建新令牌并重新注册。

当服务端返回 200 但 `certfoldc` 无法使用响应（证书校验失败、响应无法解码）或无法写入 `client.yaml` 时，错误信息会说明服务端已消耗令牌并打印 `--replace` 命令。旧身份在服务端上已不可用。

`server returned 500: internal error` 表示服务端回滚了整个操作；令牌未被消耗，可以使用同一个令牌重试。

## 目录错误

当 `certfolds` 或 `certfoldc` 因目录错误拒绝启动时，参阅[目录要求](security.md#目录要求)了解完整的检查列表和修复方法。

## 服务端重启后客户端显示离线

`certfolds` 恢复后的约一分钟内，`certfoldc status` 可能仍显示 `offline` 和之前的连接错误。状态只在当前一轮长轮询结束时更新，之后会自行恢复。

## 服务状态

`service status` 查询服务管理器并通过 IPC socket 探测守护进程：

- **Running**——服务管理器报告正在运行，守护进程已应答。
- **Running (not answering on ...: ...; see ...)**——服务管理器报告守护进程处于运行状态，但其 IPC 端点不存在、拒绝连接或超时。守护进程仍在启动中或启动失败，因此服务并不健康；请查看消息中给出的日志（`journalctl -u <name>`、Application 事件日志或 `/var/log/<name>.err.log`）。在 systemd 下，持续失败的守护进程每次重启后也可能短暂显示此状态。
- **Running (cannot check the daemon on ...: ...)**——打开 socket 时遇到权限错误或其他非网络错误。权限错误会附加 “checking it needs root or an elevated administrator”。
- **Restarting (the daemon failed and systemd starts it again; see journalctl -u <name>)**——仅限 systemd。守护进程出错退出，systemd 正在等待再次启动它（`activating (auto-restart)`）。一直处于此状态的单元每次启动都会失败；原因见 journal。
- **Stopped**——服务管理器报告服务未运行。在 Windows 和 macOS 上，每次启动都失败的服务在两次重启之间大多显示 `Stopped`：服务控制管理器会等待 10 秒，launchd 会限制重新拉起的频率，两者都不提供“正在重启”状态。如果没有人运行过 `service stop` 而服务显示 `Stopped`，请查看 Application 事件日志（Windows）或 `/var/log/<name>.err.log`（macOS）。
- **query status: ...**（退出码 1）——服务未安装，或服务管理器报告了错误（例如 systemd 的 `failed` 状态）。
