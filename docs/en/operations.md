English | [简体中文](../zh-CN/operations.md)

[Back to README](../../README.md)

# Operations

## Basic flow

```bash
# Start the server
certfolds --config /etc/certfold/server.yaml serve

# Create a short-lived enrollment token (--expires up to 168h, default 1h)
certfolds --config /etc/certfold/server.yaml token create --name web-1 --expires 10m

# Enroll and run a client
certfoldc --config /etc/certfold/client.yaml enroll --token <token>
certfoldc --config /etc/certfold/client.yaml serve

# Inspect or trigger the running client through local IPC
certfoldc status
certfoldc fetch --cert api-prod
certfoldc reload

# Validate and apply supported server.yaml changes through local IPC
certfolds --config /etc/certfold/server.yaml reload
```

On Linux, `certfolds` and `certfoldc` management commands need root because the IPC sockets are owned by root. When the configuration file does not exist or the user may not read it, the CLI uses the platform default IPC endpoint. When the file can be read but `ipc_socket` cannot be used (the file is not valid YAML, a `${VAR}` in `ipc_socket` is not set, or the path is relative), the CLI reports an error and suggests `--ipc`. If you set a custom `ipc_socket`, run the CLI as root (or elevated) or pass `--ipc`.

`token create`, `reload`, `cert add`, and `cert remove` are served by the running daemon over local IPC and fail when it is not running. `token create` also refuses to run when `server.public_url` is unset and `server.listen` names no host clients can reach. When the name belongs to an enrolled client or to an unused token that has not expired, `token create` requires `--replace`; with `--replace`, it also revokes all unused tokens of that name. `cert add` and `cert remove` edit `server.yaml` and apply the new configuration atomically; if the apply fails, the file is written back to its original contents. Other hotloadable changes already in the file take effect at the same time; if the file contains a change that requires a restart, the command is refused and the file is not modified. On Windows, the first `cert add` or `cert remove` changes `server.yaml` to a private DACL (SYSTEM and Administrators only).

`certfoldc enroll` writes `client.yaml` before sending the token; if enrollment fails, the file it created is removed (an existing file is not touched). A token whose name or server URL does not pass the naming rules is rejected before any network request. Without `--token`, `certfoldc enroll` reads the `CERTFOLDC_TOKEN` environment variable. When `enroll` overwrites an existing identity, a running `certfoldc` daemon keeps the old one (which the server no longer accepts) until `certfoldc reload` or a service restart.

`client remove` and `token revoke` report an error (exit code 1) when the name or ID does not exist, instead of silently claiming success. After removing a client, `client remove` lists the certificates it subscribed to and suggests `certfolds cert renew` for each. The old certificates and private keys the client holds remain valid until they expire; renewing issues new ones but does not revoke the old.

### Running as a service

To install `certfolds` as a systemd service on Linux:

```bash
sudo install -m 0755 certfolds-linux-amd64 /usr/local/bin/certfolds
sudo install -d -m 0700 /etc/certfold
sudo install -m 0600 server.yaml /etc/certfold/server.yaml
sudo certfolds --config /etc/certfold/server.yaml service install
sudo certfolds service start
```

Release files carry a `-<os>-<arch>` suffix; `install -m 0755` renames the file and makes it executable in one step. If `server.yaml` references `${VAR}`, write the [service environment file](#linux-service-environment-variables) before starting the service. On a host that cannot use the [one-line installer](installation.md#one-line-installation), install `certfoldc` the same way, enroll it, and then run `sudo certfoldc --config /etc/certfold/client.yaml service install` and `sudo certfoldc service start`.

On Windows, run the daemons as services (LocalSystem) or from an elevated prompt. For how the IPC endpoint is secured, see [Trust model](security.md#trust-model).

To register `certfolds` as a Windows service:

```powershell
certfolds --config <path> service install    # registers "serve --config <path>" as LocalSystem
certfolds service start
```

Events go to the Application event log with `certfolds` as the source. `service uninstall` removes the event log source.

`service install` registers a daemon with the system service manager, which restarts it after a failure; see [Services](#services) for details.

## Delivery and reconciliation

`certfoldc` keeps one request to `GET /v1/sync` open. The server answers as soon as a certificate the client subscribes to is issued or a reload changes what the client receives, and otherwise after 55 seconds; the client then asks again. A layer-4 proxy between `certfoldc` and `certfolds` needs an idle timeout above 60 seconds, or every request fails and delivery slows to the retry interval.

After every round, whether the server reported a change, reported none, or could not be reached, `certfoldc` reconciles each configured output with its local store:

- An output that is missing or whose content differs is rewritten. All outputs of one certificate are staged first and then replaced together.
- An output with the right content but the wrong permission bits or ownership is corrected in place. On Windows, reconciliation compares content only; permission and ownership changes take effect on the next content change (renewal) or when the file is deleted. This does not count as a change and does not run `on_change`.
- On filesystems that cannot store Unix permission bits, the configured `mode` has no effect; protect such directories by other means.
- An idle client reconciles about every 55 seconds. While errors persist, including a failing `on_change` program, rounds back off from 5 seconds to 5 minutes.

This is a declarative model: manual edits to outputs are undone within a round. `certfoldc fetch` pulls and reconciles at once; `--cert NAME` also downloads that certificate again. `certfoldc reload` returns after reconciling with the new configuration; it does not clear the last error shown by `certfoldc status`, which updates on the next round. Changes to `client.data_dir` or `client.ipc_socket` require a restart.

## on_change programs

`on_change` runs a program after new material for the certificate is stored or the content of any of its outputs is rewritten, including when a deleted or modified output is restored. Correcting permissions or ownership alone does not run it.

- It is an argument list whose first item must be an absolute path. It is not run through a shell.
- Programs run one at a time in certificate-name order, after all outputs are reconciled. A certificate whose outputs could not all be written does not run its program.
- Each run times out after 2 minutes. The program runs as the `certfoldc` service account with its full environment and an empty stdin. Its working directory is the service's (`/` under systemd, `System32` for a Windows service), so use absolute paths.
- A failed run is retried every round until it succeeds. Meanwhile the client backs off, so new certificates can arrive up to about 5 minutes late. `certfoldc status` shows the error, which names only the certificate and the exit status or timeout; the last 4 KiB of the program's output goes to the service log only (see [Events and logging](#events-and-logging)), not to the events shown by `certfoldc events`.
- A background process the program starts must redirect its own stdout and stderr. Otherwise `certfoldc` waits 5 seconds after the program exits, then closes the pipe, logs it, and counts the run as successful; on Unix the process may be killed by `SIGPIPE` on its next write. `nohup` does not redirect output that is a pipe.
- Values in `client.yaml` go through `${VAR}` expansion, so a literal `$` in an argument is written `$$`.
- When `certs.json` starts empty, each certificate with an `on_change` program runs it once, even if its outputs were already up to date.

On Windows, run a PowerShell script through its full path, not a `.bat` or `.cmd` file: `cmd.exe` re-parses the arguments, and values that contain special characters are mangled. Use `powershell.exe -File`:

```yaml
certificates:
  web-iis:
    outputs:
      - format: pkcs12
        path: 'C:\certfold\web.pfx'
        password: "${PFX_PASSWORD}"
    on_change: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\certfold\reload-iis.ps1']
```

## Renewal

`certfolds` renews each certificate automatically. When the ACME CA publishes a renewal window (ARI, RFC 9773), `certfolds` picks a random moment within that window and renews there; the moment stays fixed until the window changes. When the CA offers no ARI, `certfolds` uses a ratio rule aligned with Let's Encrypt's guidance: renew when a third of the certificate's lifetime remains, or when half remains for certificates with a lifetime under 10 days.

`certfolds cert list` and `certfolds cert show` display the renewal moment and its source; see [Runtime reload and issuance](#runtime-reload-and-issuance).

Renewal is automatic; there is nothing to configure.

**When a CA announces a mass revocation**, run `certfolds reload` to make every certificate re-query ARI immediately. Without this, the next query may be up to 24 hours away.

Two guards prevent tight retry loops when a certificate arrives already due for renewal:

- **Ratio rule**: the error reads `issued certificate was stored, but is already due for renewal (lifetime ..., renewal due ...)`. The certificate is stored and delivered, but the issuance counts as a failure. Fix the cause and clear the backoff with `certfolds cert renew <name>` or `certfolds reload`.
- **ARI**: the error reads `renewal window of a newly issued certificate has already passed`. The CA returned an ARI window that is entirely in the past. A `certfolds reload` clears the database backoff, but the in-memory guard still blocks renewal until the backoff expires; to renew immediately, use `certfolds cert renew <name>`.

## Events and logging

Both daemons write structured log lines to stderr, which under systemd goes to journald. On Windows, when running as a service, events go to the Application event log with the service name (`certfolds` or `certfoldc`) as the source and event IDs 1 (INFO), 2 (WARN) and 3 (ERROR).

Each daemon also keeps the last 500 events in memory. Read them with the `events` command:

```bash
certfolds events           # text
certfolds events --json    # JSON array
certfoldc events           # text
certfoldc events --json    # JSON array
```

`certfolds events` uses the global `--json` flag; `certfoldc events` has its own local `--json` flag.

Events include certificate issuance, enrollment, reload results, identity renewal, client and token management, and ARI window updates. The output of `on_change` and `exec` DNS programs is sensitive and never appears in events; it goes only to the service log (stderr or journald). On Windows, the service log is the event log, and the output is shown as `(withheld)` there too, so it is not recorded anywhere; hook scripts should log their own output.

TLS handshake errors from the public HTTPS listener go only to the service log and are rate-limited to 10 per minute. They do not appear in `certfolds events`.

## TUI

### Server TUI (certfolds)

`certfolds` without a subcommand opens the server TUI, which refreshes from the daemon every 2 seconds.

Five tabs:

| Tab | Content |
|---|---|
| Overview | Certificate state counts, token counts (unused / used / expired), last 10 events |
| Certificates | Name, State, Not After, Renew At (with `ari`/`ratio`), Domains, Subs; select a row for details |
| Clients | Name, Last Seen, Enrolled, Certificates (reverse lookup of subscribed certificates) |
| Tokens | ID, Name, Status, Expires |
| Events | Auto-wrapping, follows the bottom automatically |

Keys:

| Key | Action |
|---|---|
| `1`-`5` | Switch tab |
| `tab` / `shift+tab` | Next / previous tab |
| `k`/`up`, `j`/`down` | Move in tables and events |
| `pgup`, `pgdn` | Page in events |
| `g`, `G` | Oldest / newest event |
| `R` | Renew selected certificate (confirm with `y`) |
| `d` | Delete selected client or revoke selected token (confirm with `y`) |
| `n` | Create a new token (enter name and TTL, then `enter`) |
| `r` | Refresh now |
| `?` | Show all keys |
| `q` / `ctrl+c` | Quit (ctrl+c works inside dialogs too) |

The token is shown in the result dialog after creation, together with the install commands. Closing the dialog discards the token; for a complete command on one line, revoke it and use `certfolds token create` on the command line. The selected row is marked with `›` so it is visible without color.

### Client TUI (certfoldc)

`certfoldc` without a subcommand opens the client TUI, which refreshes every 2 seconds. It fails with an error when the daemon is not running.

The header shows the client name, server URL, online/offline status, last pull time, and last error. Below it is a certificate table with columns Name, Not After (date plus remaining days; `expired` when past), Outputs, on_change, and Pending. A yellow Not After means the certificate has passed its ratio-rule renewal point; `certfolds` may renew later when its CA suggests a later ARI window. Pending means the `on_change` program has not yet succeeded since the certificate or one of its outputs changed. Below the table are the most recent events.

Keys:

| Key | Action |
|---|---|
| `f` | Fetch now (runs until done, including hooks) |
| `R` | Reload client.yaml |
| `r` | Refresh display |
| `e` | Full-screen events (follows the bottom) |
| `?` | Full help and color legend |
| `q` / `ctrl+c` | Quit |

In the events view: `k`/`up`, `j`/`down`, `pgup`/`b`, `pgdn`/`space`, `u` (half page up), `d` (half page down).

When the daemon restarts, events are cleared and fetched again from the beginning. If more certificates exist than the terminal can show, the last line reads `+N more; certfoldc status --json lists them all`.

## Runtime reload and issuance

`certfolds reload` validates `server.yaml` and applies supported changes through the local server IPC endpoint. ACME settings, DNS providers, and certificate definitions, including their subscribers, can be updated without restarting the daemon. Changes to `server.listen`, `server.public_url`, `server.data_dir`, `server.ipc_socket`, `server.tls_cert_file`, `server.tls_key_file`, or `acme.dns_resolvers` are rejected with restart guidance. The TLS file paths and listen address are fixed at startup; file content is reloaded automatically on each handshake (see [Production TLS](installation.md#production-tls)).

`certfolds` issues certificates in parallel, at most four at a time and at most one issuance per certificate at a time:

- Reload does not wait for in-flight issuance. It clears retry backoff (but keeps the last error message), publishes the new configuration, and immediately checks the certificate definitions.
- An issuance that started before a reload is discarded if the certificate's CA directory, domains, or key type changed meanwhile, and the certificate is issued again under the new configuration. Stored certificate material is tied to those same settings, so stale same-name material is never distributed.
- A failed issuance is retried after 5 minutes, doubling up to 24 hours. The backoff is stored in the database and survives a restart, so after fixing the cause (for example DNS credentials) run `certfolds reload` or `certfolds cert renew <name>` instead of restarting.
- `certfolds cert list` shows each configured certificate's state (`issuing`, `backoff`, `valid`, or `pending`), and a RENEW AT column with the renewal moment and its source (`ari` or `ratio`). `certfolds cert show <name>` adds the subscribers, the failure count, the last error, and the next attempt.

`certfoldc` automatically renews its mTLS identity before expiry. `client.identity_renew_before` defaults to 30 days and accepts values from 1 hour through 89 days. A failed renewal does not stop delivery: the client keeps using its current identity and retries the renewal each round.

The database schema only migrates forward. A `certfolds` that encounters a newer schema refuses to open the database and names both versions.

## Services

On Windows, `service install` registers the daemon and writes a recovery action (restart after 10 seconds, reset the failure count after 24 hours). Events go to the Application event log. `service uninstall` removes the event log source.

Under systemd, `service install` writes a unit with `Restart=on-failure`, `RestartSec=5`, and `KillMode=mixed`. `KillMode=mixed` sends SIGTERM to the daemon alone on stop; processes it started (exec DNS programs) keep running until the daemon exits, then receive SIGKILL. A daemon that keeps failing restarts every 5 seconds indefinitely. To update an existing unit, run `service uninstall` then `service install`; kardianos reports an error when the service already exists. Environment variables for the service go in a file under `/etc/sysconfig`; see [Linux service environment variables](#linux-service-environment-variables).

`service install` resolves the configuration path to an absolute path. The search order is `--config`, then `CERTFOLDS_CONFIG` / `CERTFOLDC_CONFIG`, then the platform default.

When running as a service, the directories the daemon checks must be owned by the service account. On Linux, `certfolds` runs as root, so its data directory must be owned by root (uid 0); `certfoldc` does not check directories on Unix. On Windows, the configuration directory and the data directory of either daemon must be owned by SYSTEM or Administrators. If the owner does not match, the daemon refuses to start and the error prints the fix command (see [Directory requirements](security.md#directory-requirements)). systemd restarts the daemon every 5 seconds until the owner is corrected; on Windows the recovery action restarts it every 10 seconds, and `sc query <name>` reports exit code 1067. A directory created by hand (for example with `mkdir`) in an elevated Git Bash session is owned by the user's own SID rather than Administrators, and is rejected; directories that `certfolds` and `certfoldc` create themselves are owned by Administrators.

For how to interpret `service status` output, see [Service status](troubleshooting.md#service-status).

### Linux service environment variables

Under systemd, DNS credentials, `LEGO_CA_CERTIFICATES`, and other environment variables for a service go in `/etc/sysconfig/<name>`, that is `/etc/sysconfig/certfolds` or `/etc/sysconfig/certfoldc`. The file holds one `KEY=value` per line and should be owned by root with mode `0600`. On distributions without `/etc/sysconfig`, create it first with `sudo install -d -m 0755 /etc/sysconfig`. Changes take effect only after a service restart.

To keep a credential off the command line and out of shell history, let a root shell create the file and paste the lines into it, ending with Ctrl-D (or pipe them in):

```bash
sudo sh -c 'umask 077; cat > /etc/sysconfig/certfolds'
```

`certfolds config validate` also expands `${VAR}` references, so run it with the file loaded; otherwise it fails with `environment variable "X" is not set`:

```bash
sudo sh -c 'set -a; . /etc/sysconfig/certfolds; certfolds --config /etc/certfold/server.yaml config validate'
```

### Windows service environment variables

DNS credentials, `LEGO_CA_CERTIFICATES`, and other environment variables for a Windows service go in the registry. The `certfoldc` service uses the same mechanism; replace `certfolds` with `certfoldc` in the paths below. Changes take effect only after a service restart; `certfolds reload` does not re-read environment variables.

`service install` leaves the service's registry key to SYSTEM and Administrators, so values kept there are not readable by other local users.

PowerShell (elevated):

```powershell
[Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\certfolds', 'Environment', [string[]]@('NAME=value'), 'MultiString')
Restart-Service certfolds
```

A value typed into a command can be recorded by PowerShell script block logging (event 4104), and the `reg add` form below by process command-line auditing. Where either is enabled and the value is a credential, enter it with `regedit` instead.

cmd (elevated; `&&` does not work in Windows PowerShell 5.1):

```bat
reg add HKLM\SYSTEM\CurrentControlSet\Services\certfolds /v Environment /t REG_MULTI_SZ /d "NAME=value\0OTHER=2" /f
net stop certfolds && net start certfolds
```

Multiple variables are separated by `\0` in the `reg add` form; in PowerShell, pass an array: `@('NAME=value', 'OTHER=2')`.

Both forms replace the whole list; they do not add to it. Writing one variable removes every other variable already set, such as DNS credentials, and a configuration that still references them then fails to start. Read the current list first and write it back complete:

```powershell
[Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\certfolds', 'Environment', $null)
```

To remove the variables: `Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\certfolds' -Name Environment`. `service uninstall` deletes the entire service key, including this value: after `service uninstall` and `service install`, set the variables again before you start the service. The install script keeps the `Environment` value of the `certfoldc` service when it installs the service again, and handles the values only through .NET method calls, which PowerShell module logging does not record.

When a variable referenced by `${VAR}` in the configuration is not set, the service fails to start (`ExitCode=1067`), and the Application event log (event ID 3) shows `load config: expand env: <field>: environment variable "X" is not set`.
