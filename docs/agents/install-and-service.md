# Install scripts and service management

Read this doc before changing paths under `internal/service/**`, `internal/api/install_script*.go`,
or `internal/api/install_script_test.go`.

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## Windows service and event log (INS-1)

- Environment variables are stored in the registry value `HKLM\SYSTEM\CurrentControlSet\Services\<name>` as `REG_MULTI_SZ` `Environment` (verified on certfolds, 2026-10-01). Writing replaces the entire value. Changing it requires a service restart; `reload` does not re-read environment. `service uninstall` deletes the entire service key, including this value.
- `service install` sets a protected DACL on the service key: `D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)` (`internal/service/servicekey_windows.go`). Without this, the key inherits Users read access from the `Services` parent, exposing credentials in `Environment`. On failure, `service install` exits with an error and prints a manual `Set-Acl` command. The event-source key (`Services\EventLog\...`) keeps its default access. Non-elevated `Get-Service`, `sc query`, and `sc qfailure` still work (they go through SCM); direct registry reads are denied (verified 2026-10-01). `-Upgrade` replaces the binary only and does not reset the service key DACL.
- install.ps1 reinstall flow: before uninstall, read `Environment`; after install and before start, write it back. After stopping the service, `WaitForExit(30000)` on the service PID, then `[IO.File]::Replace` (otherwise `certfoldc.exe~RF*.TMP` is left behind). Credentials are handled only through .NET method calls (`[Microsoft.Win32.Registry]::GetValue/SetValue`) and `foreach` statements -- never through cmdlet parameters or pipelines, because PowerShell module logging (event 4103) records parameter bindings. `install_script_test.go` has two static assertions: no `New-ItemProperty`/`Set-ItemProperty`, and lines containing `$Environment` must not use a pipeline. Failure prompts list only variable names.
- install / start / stop / uninstall all exit 0 (verified 2026-10-01). Runs as LocalSystem. Install logs System event 7045.
- INFO, WARN, ERROR events are written to the Application log with event IDs 1, 2, 3 respectively (verified 2026-10-01). Source: the service name (`certfolds` or `certfoldc`). Messages render in slog TextHandler format, consistent with `certfolds events`.
- Startup failure: `ExitCode=1067`, reason in Application log ID 3 (`daemon failed`) (verified 2026-10-01). `service install` writes recovery actions: restart after 10 s, failure counter resets after 24 h; System log records 7031 (verified 2026-10-01).
- `service uninstall` also removes the event log source. After that, `Get-WinEvent -FilterHashtable @{ProviderName='certfolds'}` errors; use LogName filtering with `Where-Object ProviderName` instead.
- Events may take a few seconds to become queryable. Scripts must not conclude from a single empty result.
- slog's quoting escapes backslashes in Windows paths, so they appear doubled in quoted attribute values.

## Windows install script (INS-2)

- install.ps1 must distinguish AMD64, ARM64, and x86.

## systemd (INS-3)

- `service install` generates a unit with `Restart=on-failure`, `RestartSec=5`, `KillMode=mixed`, `EnvironmentFile=-/etc/sysconfig/<name>`. `KillMode=mixed` sends SIGTERM to the main process only; remaining processes get SIGKILL after the main exits, so exec DNS programs can use the full shutdown grace period.
- Persistent failures restart every 5 s indefinitely (systemd's default `StartLimitBurst=5/10s` never triggers).
- To replace an existing unit: `service uninstall` first, then `service install` (kardianos errors on an existing service).
- Environment variables go in `/etc/sysconfig/<name>` (Ubuntu does not have this directory; create it before storing credentials).
- stderr goes to journald under systemd.
- `service status`: kardianos maps systemd's `activating` to running (and `deactivating` to not installed), so a unit waiting in `auto-restart` after a failed start looked running. `StatusText` reads the unit's `SubState` and reports `auto-restart` as `Restarting (...)`; other sub-states still go through the IPC probe. Windows (SCM waits 10 s, no restarting state) and launchd show such a service mostly as `Stopped`.

## Linux one-click install paths (INS-4)

- Verified on Ubuntu 25.04 / systemd 257, 2026-10-01.
- `/usr/local/bin/certfoldc`, `/etc/certfold/client.yaml` (file 0600, directory 0700), `/var/lib/certfoldc` (private-created by certfoldc on first start, exists at install time, 0700, root:root), `/var/run/certfold/certfoldc.sock` (0660, owned by root; `certfoldc status` requires sudo), `/etc/systemd/system/certfoldc.service` and `multi-user.target.wants` symlink.
- Removing a temporary test root on Ubuntu: `update-ca-certificates --fresh` then `keytool -delete -cacerts`; otherwise stale symlinks and Java truststore entries remain.

## launchd (INS-5)

- System-level LaunchDaemon stderr logs to `/var/log/<name>.err.log`.

## install.ps1 specifics (INS-6)

- install.ps1 does not create `C:\ProgramData\Certfold` (created privately by `certfoldc enroll`).

## Install script invariants (INS-7)

- All install script invariants (curl flags, `CERTFOLDC_TOKEN`, temp-file download, `$LASTEXITCODE` checking, `-UseBasicParsing`, no `exit`): see S18.
