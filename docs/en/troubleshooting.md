English | [简体中文](../zh-CN/troubleshooting.md)

[Back to README](../../README.md)

# Troubleshooting

## Enrollment errors

When `certfoldc enroll` fails with a network error, retry with the same token. If the retry gets `server returned 401: enrollment token was already used`, the server consumed the token before the response arrived. The old identity of that name was replaced on the server. Create a new token with `certfolds token create --name <name> --replace` and enroll again.

When the server answers 200 but `certfoldc` cannot use the response (certificate validation fails, response cannot be decoded) or cannot write `client.yaml`, the error says the server took the token and prints the `--replace` command. The old identity no longer works on the server.

A `server returned 500: internal error` means the server rolled back the entire operation; the token is not consumed, and you can retry with the same token.

## Directory errors

When `certfolds` or `certfoldc` refuses to start with a directory error, see [Directory requirements](security.md#directory-requirements) for the full list of checks and how to fix each one.

## Client offline after a server restart

For up to about a minute after `certfolds` is back, `certfoldc status` can still show `offline` with the old connection error. The status updates only when the current long-poll round ends, and it recovers by itself.

## Service status

`service status` queries the service manager and probes the daemon over its IPC socket:

- **Running** --- the service manager reports running and the daemon answered.
- **Running (not answering on ...: ...; see ...)** --- the service manager reports the daemon process as up, but its IPC endpoint does not exist, refuses connections, or times out. The daemon is still starting or is failing at startup, so the service is not healthy; check the log the message names (`journalctl -u <name>`, the Application event log, or `/var/log/<name>.err.log`). Under systemd, this can also appear briefly right after each restart of a failing daemon.
- **Running (cannot check the daemon on ...: ...)** --- a permission error or another non-network error when opening the socket. Permission errors add "checking it needs root or an elevated administrator".
- **Restarting (the daemon failed and systemd starts it again; see journalctl -u <name>)** --- systemd only. The daemon exited with an error, and systemd is waiting to start it again (`activating (auto-restart)`). A unit that stays in this state fails at every start; the journal says why.
- **Stopped** --- the service manager reports the service is not running. On Windows and macOS, a service that fails at every start mostly shows `Stopped` between restarts: the Service Control Manager waits 10 seconds and launchd throttles respawns, and neither reports a restarting state. If the service shows `Stopped` although nobody ran `service stop`, check the Application event log (Windows) or `/var/log/<name>.err.log` (macOS).
- **query status: ...** (exit code 1) --- the service is not installed, or the service manager reported an error (such as systemd's `failed` state).
