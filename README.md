# Sigil

Sigil is a central certificate issuer and distributor for server fleets.

- `sigils` manages ACME certificates, enrollment, subscriptions, and distribution.
- `sigilc` enrolls with mTLS, pulls subscribed certificates, and writes them in PEM, DER, or PKCS#12 formats.

## Project status

Active development. Enrollment, certificate distribution, management commands, runtime reload, client identity renewal, long-poll delivery, parallel issuance, ARI-directed renewal, HTTPS certificate hot-reload, server and client TUIs, and structured logging with events are implemented. The security-critical enrollment and pull path is covered by unit tests and a WSLC-native end-to-end test that includes real ACME issuance through Pebble and ARI. Review the limitations below before production use.

## Build and test

```bash
go build ./cmd/sigils
go build ./cmd/sigilc
go test ./... -count=1
go vet ./...
```

On Windows, the end-to-end suite uses WSLC directly and does not require Docker Desktop or Compose:

```powershell
go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

The `-count=1` flag is required. The test builds temporary OCI images through `wslc build`, and Go's test cache cannot see those reads; without the flag a second run reports `(cached)` even when the code changed.

The test builds temporary OCI images, creates an isolated WSLC network, and issues real certificates from a Pebble ACME server through the `exec` DNS hook and a challenge test DNS server. It verifies enrollment, certificate fetch, delivery of a renewed certificate over the long poll, restoring deleted and modified outputs, `on_change` runs, reload wake-ups, client revocation, token expiry/revocation, ARI renewal-window tracking and ARI-directed renewal with `replaces`, HTTPS certificate hot-reload, static install.ps1, deletion of non-existent objects returning 404, and renewal events, then removes its containers, network, and images.

Linux CI can run the same orchestration with Docker Engine. Set `SIGIL_CONTAINER_CLI=docker` and `SIGIL_E2E_REQUIRED=1` (without the latter, a missing container runtime silently exits 0). Run as a regular user in the `docker` group, without `sudo`; cleanup does not need `sudo` either.

## One-line installation

Place platform binaries in `<data_dir>/binaries/` using names such as `sigilc-linux-amd64` and `sigilc-windows-amd64.exe`. After creating an enrollment token, `sigils token create` prints the install commands with the token filled in.

**Linux / macOS** (as a user who may sudo):

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://sigil.example.com:8443/install.sh' | sudo sh -s -- --token '<token>'
```

Without `--token`, the script asks for the token on the terminal (not echoed), which keeps it off the command line. Prefer this on a host that others use. On macOS, the terminal's single-line input limit (1024 characters) may truncate the token (about 1050 characters); use `--token` there instead:

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://sigil.example.com:8443/install.sh' | sudo sh
```

**Windows** (elevated PowerShell, 5.1 or 7):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://sigil.example.com:8443/install.ps1'))) -Token '<token>'
```

Without `-Token`, the script prompts for the token with `Read-Host -AsSecureString` (only asterisks on screen):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://sigil.example.com:8443/install.ps1')))
```

The `-bor 3072` prefix adds TLS 1.2 to the protocols Windows PowerShell 5.1 offers. The Sigil server accepts TLS 1.2 and above on its public HTTPS listener, while `sigilc`'s own connections (enrollment and mTLS) require TLS 1.3.

With `--token` / `-Token`, the token appears in the process command line: `sh -s -- --token` is visible to other users and saved to the shell history; `-Token '...'` stays in the PowerShell session history (`Get-History`) and may be written to the history file by older PSReadLine versions. To keep the token off the command line, omit the flag so that the script prompts for it interactively. `sigilc enroll` without `--token` reads the `SIGILC_TOKEN` environment variable; both scripts use this to pass the token to `sigilc`. In automated environments without a terminal, pass `--token` or `-Token` (Linux reports "No terminal to read the token from"; Windows `Read-Host` is not available in non-interactive sessions).

**Reinstalling** on a host where `sigilc` is already installed: run the same command with a new token (created with `sigils token create --name <name> --replace`). The script stops the service, replaces the binary, enrolls with the new token, reinstalls the service, and starts it. If enrollment fails, the service is restarted with the earlier `client.yaml`; if the error says the server took the token, the earlier identity no longer works and you need a new `--replace` token. If `client.yaml` already exists with a different name or server URL, the script reports the path and asks you to remove it. After the service starts, the script polls `sigilc status` for up to 15 seconds and reports the log location if the daemon does not answer.

**Upgrading** the binary without re-enrolling:

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://sigil.example.com:8443/install.sh' | sudo sh -s -- --upgrade
```

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://sigil.example.com:8443/install.ps1'))) -Upgrade
```

`--upgrade` / `-Upgrade` stops the service, replaces the binary, and restarts; it fails if `sigilc` was never installed. You cannot combine `--upgrade` with `--token`.

## Production TLS

The one-line installer downloads `sigilc` before enrollment, so the public Sigil endpoint must present a certificate already trusted by the operating system. Configure a public certificate directly:

```yaml
server:
  listen: ":8443"
  public_url: "https://sigil.example.com:8443"
  data_dir: "/var/lib/sigils"
  tls_cert_file: "/etc/sigil/tls/fullchain.pem"
  tls_key_file: "/etc/sigil/tls/key.pem"
```

Replace the certificate and key files in place; `sigils` reloads them on the next TLS handshake without a restart. A certificate that does not pair with its key is skipped with a warning, and the previous certificate remains in use. Keep the files on a local filesystem: a network mount where `stat` stalls will block all handshakes.

When these fields are omitted, `sigils` uses its internal mini-CA certificate and reissues it automatically before it expires. A failed reissue retries after one minute.

`server.public_url` must be a pure-ASCII `https` URL. It may not contain quotes, backticks, `$`, `\`, whitespace or control characters: `install.sh` puts it in double quotes (`SERVER_URL="..."`), so `$`, backtick, `\` and `"` would be interpolated; `install.ps1` and the enrollment token put it in single quotes for PowerShell, where curly quotes (U+2018-U+201E) also act as quote characters.

Enrollment tokens carry the expected client name, server URL, and mini-CA certificate. `sigilc` validates TLS before sending the token or CSR, then stores its mTLS identity in a private, atomically replaced configuration file. `sigilc` verifies the server against the operating system's roots plus the Sigil mini-CA, so either kind of server certificate works. Client certificates are always issued and verified by the mini-CA.

## Basic flow

```bash
# Start the server
sigils --config /etc/sigil/server.yaml serve

# Create a short-lived enrollment token (--expires up to 168h, default 1h)
sigils --config /etc/sigil/server.yaml token create --name web-1 --expires 10m

# Enroll and run a client
sigilc --config /etc/sigil/client.yaml enroll --token <token>
sigilc --config /etc/sigil/client.yaml serve

# Inspect or trigger the running client through local IPC
sigilc status
sigilc fetch --cert api-prod
sigilc reload

# Validate and apply supported server.yaml changes through local IPC
sigils --config /etc/sigil/server.yaml reload
```

On Linux, `sigils` and `sigilc` management commands need root because the IPC sockets are owned by root. When the configuration file does not exist or cannot be read, the CLI uses the platform default IPC endpoint; if `ipc_socket` is set but cannot be read, the CLI reports an error and suggests `--ipc`.

`token create`, `reload`, `cert add`, and `cert remove` are served by the running daemon over local IPC and fail when it is not running. `token create` also refuses to run when `server.public_url` is unset and `server.listen` names no host clients can reach. When the name belongs to an enrolled client or to an unused token that has not expired, `token create` requires `--replace`; with `--replace`, it also revokes all unused tokens of that name. `cert add` and `cert remove` edit `server.yaml` and apply the new configuration atomically; if the apply fails, the file is written back to its original contents. Other hotloadable changes already in the file take effect at the same time; if the file contains a change that requires a restart, the command is refused and the file is not modified. On Windows, the first `cert add` or `cert remove` changes `server.yaml` to a private DACL (SYSTEM and Administrators only).

`sigilc enroll` writes `client.yaml` before sending the token; if enrollment fails, the file it created is removed (an existing file is not touched). A token whose name or server URL does not pass the naming rules is rejected before any network request. Without `--token`, `sigilc enroll` reads the `SIGILC_TOKEN` environment variable. When `enroll` overwrites an existing identity, a running `sigilc` daemon keeps the old one (which the server no longer accepts) until `sigilc reload` or a service restart.

`client remove` and `token revoke` report an error (exit code 1) when the name or ID does not exist, instead of silently claiming success. After removing a client, `client remove` lists the certificates it subscribed to and suggests `sigils cert renew` for each. The old certificates and private keys the client holds remain valid until they expire; renewing issues new ones but does not revoke the old.

On Linux, the install script writes:

- `/usr/local/bin/sigilc`
- `/etc/sigil/client.yaml` (file `0600`, directory `0700`)
- `/var/lib/sigilc` (created by `sigilc` at first startup; already present after installation, mode `0700`, owned by root --- 2026-10-01 verified)
- `/var/run/sigil/sigilc.sock` (`0660`, owned by root; `sudo sigilc status` to query)
- `/etc/systemd/system/sigilc.service` with `Restart=on-failure`, `RestartSec=5`, and `KillMode=mixed`

To uninstall (do not remove `/var/run/sigil`; `sigils` uses it too):

```bash
sudo sigilc service stop
sudo sigilc service uninstall
sudo rm -f /usr/local/bin/sigilc /etc/sigil/client.yaml
sudo rm -rf /var/lib/sigilc
# on the server, to revoke access:
sudo sigils client remove <name>
```

To uninstall on Windows (elevated PowerShell):

```powershell
& 'C:\Program Files\Sigil\sigilc.exe' service stop
& 'C:\Program Files\Sigil\sigilc.exe' service uninstall
Remove-Item -Recurse -Force 'C:\Program Files\Sigil'
Remove-Item -Force 'C:\ProgramData\Sigil\client.yaml'
Remove-Item -Recurse -Force 'C:\ProgramData\Sigil\client'
# on the server, to revoke access:
sigils client remove <name>
```

Do not remove `C:\ProgramData\Sigil` entirely if `sigils` shares it on the same host.

On Windows, run the daemons as services (LocalSystem) or from an elevated prompt. The CLI only talks to a named pipe owned by SYSTEM or Administrators, so a low-privilege process cannot impersonate the daemon.

To register `sigils` as a Windows service:

```powershell
sigils --config <path> service install    # registers "serve --config <path>" as LocalSystem
sigils service start
```

Events go to the Application event log with `sigils` as the source. `service uninstall` removes the event log source.

`service install` registers a daemon with the system service manager, which restarts it after a failure; see [Services](#services) for details.

## Client configuration

`client.yaml` names the server, the client's data directory, and what to do with each certificate:

```yaml
client:
  name: web-1
  server_url: "https://sigil.example.com:8443"
  data_dir: "/var/lib/sigilc"
certificates:
  api-prod:
    outputs:
      - format: pem-fullchain
        path: /etc/nginx/certs/api.pem
      - format: pem-key
        path: /etc/nginx/certs/api.key
    on_change: ["/usr/sbin/nginx", "-s", "reload"]
```

- Which certificates a client receives is decided only by `subscribers` in `server.yaml`. An entry under `certificates` in `client.yaml` only says where to write a certificate the client already receives.
- Output formats are `pem-cert`, `pem-key`, `pem-fullchain`, `pem-bundle`, `pkcs12` (requires `password`), and `der`. `mode`, `owner`, and `group` are optional. Private-key outputs default to `0600`, the others to `0644`. `mode` is read as octal: `640` means `0640`; `0o640` also works.
- All path fields in both `server.yaml` (`data_dir`, `ipc_socket`, `tls_cert_file`, `tls_key_file`, gcloud `service_account_file`) and `client.yaml` (`data_dir`, `ipc_socket`, output `path`) must be absolute paths. On Windows, `\dir` and `C:dir` are not absolute; named pipes must be written as `\\.\pipe\...`. `${VAR}` references are expanded before the check.
- Two outputs cannot share a path. Paths are compared after cleaning, and case-insensitively on Windows.
- `enroll` adds the client's mTLS identity to this file.
- The top-level `outputs` map and the `client.pull_interval`, `client.push_listen`, and `client.push_token` keys of earlier builds are rejected as unknown fields, as is the `clients` section of `server.yaml`.

`data_dir` holds `certs.json`, a copy of every subscribed certificate and its private key, written with the same private permissions as `client.yaml`. Keep `data_dir` on a filesystem that stores Unix permission bits: WSL drvfs mounts and CIFS without Unix extensions do not. Earlier builds left `state.json` and a `cache/` directory there; they are no longer read and can be deleted.

## Delivery and reconciliation

`sigilc` keeps one request to `GET /v1/sync` open. The server answers as soon as a certificate the client subscribes to is issued or a reload changes what the client receives, and otherwise after 55 seconds; the client then asks again. A layer-4 proxy between `sigilc` and `sigils` needs an idle timeout above 60 seconds, or every request fails and delivery slows to the retry interval.

After every round, whether the server reported a change, reported none, or could not be reached, `sigilc` reconciles each configured output with its local store:

- An output that is missing or whose content differs is rewritten. All outputs of one certificate are staged first and then replaced together.
- An output with the right content but the wrong permission bits or ownership is corrected in place. On Windows, reconciliation compares content only; permission and ownership changes take effect on the next content change (renewal) or when the file is deleted. This does not count as a change and does not run `on_change`.
- On filesystems that cannot store Unix permission bits, the configured `mode` has no effect; protect such directories by other means.
- An idle client reconciles about every 55 seconds. While errors persist, including a failing `on_change` program, rounds back off from 5 seconds to 5 minutes.

This is a declarative model: manual edits to outputs are undone within a round. `sigilc fetch` pulls and reconciles at once; `--cert NAME` also downloads that certificate again. `sigilc reload` returns after reconciling with the new configuration; it does not clear the last error shown by `sigilc status`, which updates on the next round. Changes to `client.data_dir` or `client.ipc_socket` require a restart.

## on_change programs

`on_change` runs a program after new material for the certificate is stored or the content of any of its outputs is rewritten, including when a deleted or modified output is restored. Correcting permissions or ownership alone does not run it.

- It is an argument list whose first item must be an absolute path. It is not run through a shell.
- Programs run one at a time in certificate-name order, after all outputs are reconciled. A certificate whose outputs could not all be written does not run its program.
- Each run times out after 2 minutes. The program runs as the `sigilc` service account with its full environment and an empty stdin. Its working directory is the service's (`/` under systemd, `System32` for a Windows service), so use absolute paths.
- A failed run is retried every round until it succeeds. Meanwhile the client backs off, so new certificates can arrive up to about 5 minutes late. `sigilc status` shows the error, which names only the certificate and the exit status or timeout; the last 4 KiB of the program's output goes to the service log only (see [Events and logging](#events-and-logging)), not to the events shown by `sigilc events`.
- A background process the program starts must redirect its own stdout and stderr. Otherwise `sigilc` waits 5 seconds after the program exits, then closes the pipe, logs it, and counts the run as successful; on Unix the process may be killed by `SIGPIPE` on its next write. `nohup` does not redirect output that is a pipe.
- Values in `client.yaml` go through `${VAR}` expansion, so a literal `$` in an argument is written `$$`.
- When `certs.json` starts empty, for example on the first start after an upgrade, each certificate with an `on_change` program runs it once, even if its outputs were already up to date.

On Windows, run a PowerShell script through its full path, not a `.bat` or `.cmd` file: `cmd.exe` re-parses the arguments, and values that contain special characters are mangled. Use `powershell.exe -File`:

```yaml
certificates:
  web-iis:
    outputs:
      - format: pkcs12
        path: 'C:\sigil\web.pfx'
        password: "${PFX_PASSWORD}"
    on_change: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\sigil\reload-iis.ps1']
```

## Renewal

`sigils` renews each certificate automatically. When the ACME CA publishes a renewal window (ARI, RFC 9773), `sigils` picks a random moment within that window and renews there; the moment stays fixed until the window changes. When the CA offers no ARI, `sigils` uses a ratio rule aligned with Let's Encrypt's guidance: renew when a third of the certificate's lifetime remains, or when half remains for certificates with a lifetime under 10 days.

`sigils cert list` and `sigils cert show` display the renewal moment and its source; see [Runtime reload and issuance](#runtime-reload-and-issuance).

Renewal is automatic; there is nothing to configure. `renew_days_before` has been removed and is now rejected as an unknown field.

**When a CA announces a mass revocation**, run `sigils reload` to make every certificate re-query ARI immediately. Without this, the next query may be up to 24 hours away.

Two guards prevent tight retry loops when a certificate arrives already due for renewal:

- **Ratio rule**: the error reads `issued certificate was stored, but is already due for renewal (lifetime ..., renewal due ...)`. The certificate is stored and delivered, but the issuance counts as a failure. Fix the cause and clear the backoff with `sigils cert renew <name>` or `sigils reload`.
- **ARI**: the error reads `renewal window of a newly issued certificate has already passed`. The CA returned an ARI window that is entirely in the past. A `sigils reload` clears the database backoff, but the in-memory guard still blocks renewal until the backoff expires; to renew immediately, use `sigils cert renew <name>`.

## Events and logging

Both daemons write structured log lines to stderr, which under systemd goes to journald. On Windows, when running as a service, events go to the Application event log with the service name (`sigils` or `sigilc`) as the source and event IDs 1 (INFO), 2 (WARN) and 3 (ERROR).

Each daemon also keeps the last 500 events in memory. Read them with the `events` command:

```bash
sigils events           # text
sigils events --json    # JSON array
sigilc events           # text
sigilc events --json    # JSON array
```

`sigils events` uses the global `--json` flag; `sigilc events` has its own local `--json` flag.

Events include certificate issuance, enrollment, reload results, identity renewal, client and token management, and ARI window updates. The output of `on_change` and `exec` DNS programs is sensitive and never appears in events; it goes only to the service log (stderr or journald). On Windows, the service log is the event log, and the output is shown as `(withheld)` there too, so it is not recorded anywhere; hook scripts should log their own output.

TLS handshake errors from the public HTTPS listener go only to the service log and are rate-limited to 10 per minute. They do not appear in `sigils events`.

## TUI

### sigils

`sigils` without a subcommand opens the server TUI, which refreshes from the daemon every 2 seconds.

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

The token is shown in the result dialog after creation, together with the install commands. Closing the dialog discards the token; for a complete command on one line, revoke it and use `sigils token create` on the command line. The selected row is marked with `›` so it is visible without color.

### sigilc

`sigilc` without a subcommand opens the client TUI, which refreshes every 2 seconds. It fails with an error when the daemon is not running.

The header shows the client name, server URL, online/offline status, last pull time, and last error. Below it is a certificate table with columns Name, Not After (date plus remaining days; `expired` when past), Outputs, on_change, and Pending. A yellow Not After means the certificate has passed its ratio-rule renewal point; `sigils` may renew later when its CA suggests a later ARI window. Pending means the `on_change` program has not yet succeeded since the certificate or one of its outputs changed. Below the table are the most recent events.

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

When the daemon restarts, events are cleared and fetched again from the beginning. If more certificates exist than the terminal can show, the last line reads `+N more; sigilc status --json lists them all`.

## Environment variables in configuration

Values in `server.yaml` and `client.yaml` can reference environment variables as `${VAR}` or `${VAR:-default}`. `$$` is a literal `$`, and an unset variable without a default is an error. References are expanded after the YAML is parsed, inside each scalar value:

- The value is inserted verbatim. Leading and trailing spaces and line breaks are kept, and quotes, `#`, or `: ` inside it are never re-parsed as YAML structure. However, the expanded scalar is re-typed: a `${VAR}` that expands to a bare number, `true`, or `null` becomes that type unless the YAML quotes the reference (see [DNS-01 validation](#dns-01-validation)).
- Mapping keys are never expanded.
- Inside a flow collection, quote the reference, as in `["${HOST}"]`, because `{` is a flow indicator there.

## Private key outputs on Windows

Outputs that contain a private key (`pem-key`, `pem-bundle`, `pkcs12`) are created with a protected ACL that grants full access to SYSTEM and Administrators (and the current user when the process runs without elevation). `mode` is not applied on Windows and cannot widen that ACL. To let a service such as IIS or nginx read a key, set `owner` on that output to the service's account name or SID; that account gets read access but does not become the file's owner. `owner` only takes effect on private-key outputs; on other formats it is silently ignored.

On Windows, reconciliation compares only the content of each output, not its ACL or ownership. A key file whose ACL was loosened, or that inherits its directory's ACL because another tool or an earlier build wrote it, keeps that ACL until its content changes at the next renewal. Removing `owner` from the configuration likewise leaves the previous account and its read access in place, on Unix as well. To apply the configuration at once, delete the file; the next round recreates it.

## DNS-01 validation

Each certificate names a DNS provider from `dns_providers`. Besides lego's built-in providers, the `exec` type runs your own program to create and remove the challenge record:

```yaml
acme:
  dns_resolvers: ["10.0.0.53"]   # optional; see below
dns_providers:
  internal:
    type: exec
    command: ["/usr/local/bin/sigil-dns-hook", "--zone", "example.com"]
certificates:
  - name: api-prod
    dns_provider: internal
    # ...
```

`command` is an argument list; its first item must be an absolute path. `sigils` runs it as `command... present <fqdn> <value>` before validation and `command... cleanup <fqdn> <value>` afterwards:

- `<fqdn>` is the TXT record name, after following CNAMEs, with a trailing dot. `<value>` is the TXT value. Exit status 0 means success.
- The value can start with `-`, so read the last three arguments by position. Do not parse them with getopt, argparse, or a PowerShell `param()` block: a value starting with `-` would be taken as an option, and PowerShell would silently bind an empty string. In PowerShell, use `$action, $fqdn, $value = $args[-3..-1]`.
- Each run times out after 2 minutes. The hook runs as the `sigils` service account with its full environment, including any credentials referenced from `server.yaml`. Its working directory is the service's (`System32` for a Windows service, `/` under systemd), so use absolute paths.
- Different certificates can run the hook at the same time. Several domains of one certificate are handled without waiting between them.
- Background processes started by the hook must redirect their output; otherwise the hook fails 5 seconds after it exits.
- On failure, the error names only the action, the record, and the exit status or timeout. The hook's output goes to the service log, truncated. It does not appear in `sigils events`.

On Windows, run a PowerShell script through its full path, for example `command: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\sigil\hook.ps1']`.

On Windows, do not use a `.bat` or `.cmd` file: `cmd.exe` re-parses the arguments, and values that contain special characters are mangled. Write the hook as a `.ps1` script and run it through `powershell.exe -File`. To suppress lego's CNAME lookups when you do not use CNAME delegation, set `LEGO_DISABLE_CNAME_SUPPORT=true` in the service environment (see [Windows service environment variables](#windows-service-environment-variables) for how).

Each built-in provider type accepts only these keys besides `type` and `skip_propagation_check` (an unknown key or a non-string value is an error):

| Type | Keys |
|---|---|
| `cloudflare` | `api_token`, `zone_api_token`, `auth_email`, `auth_key` |
| `aliyun` | `access_key`, `access_secret` |
| `tencentcloud` | `secret_id`, `secret_key` |
| `route53` | `access_key`, `secret_key`, `region` |
| `gcloud` | `project`, `service_account_file` |
| `exec` | *(none; uses `command`)* |

Values must be strings. A bare number like `12345` is parsed as an integer by YAML; quote it as `"12345"`. A `${VAR}` whose value is a bare number, `true`, or `null` must also be quoted in the YAML as `"${VAR}"`, otherwise the expanded value is re-typed. `${VAR:-}` expands to an empty string, which counts as unset for required keys.

Other DNS-01 settings:

- `skip_propagation_check: true` on a provider skips lego's check that the TXT record is visible on the zone's authoritative nameservers. Use it with DNS servers that cannot answer that check; lego still waits one 4-second polling interval.
- `acme.dns_resolvers` sets the resolvers lego uses for zone lookups, CNAME following, and the propagation check. It applies to the whole process, so changing it requires a restart. When it is empty, lego uses the system resolvers, and on Windows it falls back to Google Public DNS.
- Certificates that share a domain are issued in parallel and use the same `_acme-challenge` record. A provider may reject the second record, and one certificate's cleanup removes the record for both, so one of them fails and is retried after its backoff. Avoid overlapping domains across certificates.
- To use a private ACME CA, set `LEGO_CA_CERTIFICATES` for `sigils` to the path of the CA's root certificate. lego panics if that file cannot be read.

## Runtime reload and issuance

`sigils reload` validates `server.yaml` and applies supported changes through the local server IPC endpoint. ACME settings, DNS providers, and certificate definitions, including their subscribers, can be updated without restarting the daemon. Changes to `server.listen`, `server.public_url`, `server.data_dir`, `server.ipc_socket`, `server.tls_cert_file`, `server.tls_key_file`, or `acme.dns_resolvers` are rejected with restart guidance. The TLS file paths and listen address are fixed at startup; file content is reloaded automatically on each handshake (see [Production TLS](#production-tls)).

`sigils` issues certificates in parallel, at most four at a time and at most one issuance per certificate at a time:

- Reload does not wait for in-flight issuance. It clears retry backoff (but keeps the last error message), publishes the new configuration, and immediately checks the certificate definitions.
- An issuance that started before a reload is discarded if the certificate's CA directory, domains, or key type changed meanwhile, and the certificate is issued again under the new configuration. Stored certificate material is tied to those same settings, so stale same-name material is never distributed.
- A failed issuance is retried after 5 minutes, doubling up to 24 hours. The backoff is stored in the database and survives a restart, so after fixing the cause (for example DNS credentials) run `sigils reload` or `sigils cert renew <name>` instead of restarting.
- `sigils cert list` shows each configured certificate's state (`issuing`, `backoff`, `valid`, or `pending`), and a RENEW AT column with the renewal moment and its source (`ari` or `ratio`). `sigils cert show <name>` adds the subscribers, the failure count, the last error, and the next attempt.

Read-only IPC responses expose metadata only and never include certificate private keys or enrollment-token hashes.

`sigilc` automatically renews its mTLS identity before expiry. `client.identity_renew_before` defaults to 30 days and accepts values from 1 hour through 89 days. A failed renewal does not stop delivery: the client keeps using its current identity and retries the renewal each round.

The database schema only migrates forward. From this build on, a `sigils` that encounters a newer schema refuses to open the database and names both versions. Earlier builds do not check and may open a newer schema silently.

## Naming rules

All names in `server.yaml` --- certificate names, `acme.cas` keys, `dns_providers` keys --- and client names follow the same rule: a lowercase DNS label of 1 to 63 characters from `a-z`, `0-9` and `-`, not starting or ending with `-`.

**Upgrading from a build before these rules**: names that contain uppercase letters, dots or underscores must be renamed before upgrading. A certificate name appears in `server.yaml` and in every subscriber's `client.yaml` under `certificates.<name>`; rename both together. A CA or provider name appears as a key in `acme.cas` or `dns_providers` and in the references that use it; rename the key and its references together. After upgrading, `server.yaml` is rejected at startup and reload if any name is invalid. A new `sigilc` connected to an old `sigils` reports an error for each invalid certificate name and stops delivering those certificates; their stored material is removed, but output files are left in place.

Renaming a CA registers a new ACME account under the new name. Renaming a certificate triggers a fresh issuance; the old database record becomes an orphan. When a delivered certificate is renamed but the `client.yaml` key is not, `sigilc status` shows it with Outputs 0. Upgrade order: rename first, then upgrade the binaries.

## Services

On Windows, `service install` registers the daemon and writes a recovery action (restart after 10 seconds, reset the failure count after 24 hours). Events go to the Application event log. `service uninstall` removes the event log source.

Under systemd, `service install` writes a unit with `Restart=on-failure`, `RestartSec=5`, and `KillMode=mixed`. `KillMode=mixed` sends SIGTERM to the daemon alone on stop; processes it started (exec DNS programs) keep running until the daemon exits, then receive SIGKILL. A daemon that keeps failing restarts every 5 seconds indefinitely. To update an existing unit, run `service uninstall` then `service install`; kardianos reports an error when the service already exists. Environment variables for the service (DNS credentials, `LEGO_CA_CERTIFICATES`, etc.) go in `/etc/sysconfig/<name>`. Create the directory first on distributions that do not ship it.

`service install` resolves the configuration path to an absolute path. The search order is `--config`, then `SIGILS_CONFIG` / `SIGILC_CONFIG`, then the platform default.

When running as a service, the data directory must be owned by the service account. On Linux (systemd, running as root) the owner must be root (uid 0). On Windows the owner must be SYSTEM or Administrators. If the owner does not match, the daemon refuses to start and the error prints the fix command. Under systemd, the daemon restarts every 5 seconds until the owner is corrected; on Windows, the failure appears as `ExitCode=1067` in the service status. A directory created in an elevated Git Bash session is owned by the user's own SID rather than Administrators, and will be rejected.

### Windows service environment variables

DNS credentials, `LEGO_CA_CERTIFICATES`, and other environment variables for a Windows service go in the registry. The `sigilc` service uses the same mechanism; replace `sigils` with `sigilc` in the paths below. Changes take effect only after a service restart; `sigils reload` does not re-read environment variables (2026-10-01 verified on `sigils`; `sigilc` uses the same mechanism but was not separately tested).

PowerShell (elevated):

```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sigils' -Name Environment -PropertyType MultiString -Value @('NAME=value') -Force
Restart-Service sigils
```

cmd (elevated):

```
reg add HKLM\SYSTEM\CurrentControlSet\Services\sigils /v Environment /t REG_MULTI_SZ /d "NAME=value\0OTHER=2" /f
net stop sigils && net start sigils
```

Multiple variables are separated by `\0` in the `reg add` form; in PowerShell, pass an array: `@('NAME=value', 'OTHER=2')`.

To remove the variables: `Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sigils' -Name Environment`. Running `service uninstall` deletes the entire service key, including this value.

When a variable referenced by `${VAR}` in the configuration is not set, the service fails to start (`ExitCode=1067`), and the Application event log (event ID 3) shows `load config: expand env: <field>: environment variable "X" is not set`.

## Current limitations

- With `--token` / `-Token`, the token appears in the process command line; see [One-line installation](#one-line-installation) for how to avoid this.
- The container E2E issues certificates through the `exec` DNS provider; lego's built-in cloud DNS providers are not covered by an E2E.
- Reconciliation does not compare Windows ACLs; see [Private key outputs on Windows](#private-key-outputs-on-windows).
- Output path deduplication compares paths after `filepath.Clean` (case-insensitively on Windows). It does not detect duplicates through symbolic or hard links; paths differing only in case on macOS APFS; or, on Windows, `\\?\` and `\\.\` prefixes, 8.3 short names, trailing dots and spaces, and mapped drive letters versus UNC paths.
- Certificates whose lifetime does not exceed about twice the CA's NotBefore backdate (about 2 hours for Let's Encrypt, which backdates by 1 hour) are not supported: they arrive already past their renewal point and are caught by the arrival guard, which backs off instead of retrying immediately.
- The mini-CA root certificate expires after 10 years and has no rotation mechanism. When it has less than a year remaining, the server logs a warning at startup and on each server-certificate reissue.
- ARI does not do short-interval exponential backoff for 5xx responses (lego does not expose the HTTP status code); it retries after 6 hours.
- The random renewal moment within an ARI window is not persisted; a restart picks a new moment within the same window.
- A reload rejection caused by a YAML type error may include up to about 10 characters of the configuration value in the event and service log.

## Directory requirements

`sigils` and `sigilc` check certain directories at startup and refuse to run when the checks fail. On Unix, only `sigils` checks its data directory (`CheckPrivateDirectory`); `sigilc` does not check directories on Unix. On Windows, both daemons check their configuration directory and data directory. The `ca/` subdirectory is checked and tightened by `ca.Bootstrap` on every startup. `sigilc enroll` checks the configuration directory before writing. The checks vary by platform:

- **sigils data_dir** (Unix): mode `0700`, owned by the running user. (Windows): completely private --- only SYSTEM, Administrators, and, when not elevated, the running user may access it; the owner must be one of them.
- **Configuration directory and sigilc data_dir** (Windows): owned by SYSTEM, Administrators, or (when not elevated) the current user; no other account may write, delete, or change permissions.
- **ca/ subdirectory**: checked and tightened by `ca.Bootstrap` on every startup. On Unix, only tightened (the check is a no-op there).

When a data directory does not exist, the daemon creates it with private permissions. Configuration directories are not created automatically; `sigilc enroll` creates the client configuration directory. When it exists but does not pass the check, the error names the directory and prints the commands to fix it:

```
configuration directory: C:\ProgramData\Sigil is owned by DESKTOP\Alice, and only NT AUTHORITY\SYSTEM and BUILTIN\Administrators may own it. Its owner may have put files in it and may change who can write to it: remove it, so that it is created again. To keep it instead, check every file in it, then run:
  icacls "C:\ProgramData\Sigil" /setowner *S-1-5-32-544
```

On Linux, if the data directory was created with mode `0755`:

```
/var/lib/sigils has mode 0755, and only its owner may have access to it. Check the files in it, then run:
  chmod 700 "/var/lib/sigils"
```

When the error does not say the owner is untrusted (a wrong mode on Unix, extra ACL entries on Windows), run the commands it prints. When the error says the owner is untrusted, its advice is to remove the directory so that the daemon creates it again; do this only when the directory's contents can be recreated. Do not remove the sigils data directory unless you accept losing the mini-CA (all enrolled clients must re-enroll) and the certificate database.

Each parent directory of the configuration directory and data_dir must not be owned by an untrusted account and must not let untrusted accounts delete or replace entries in it. The check looks only at the directory itself, not its parents; the default layout (`/etc/sigil`, `/var/lib`, `C:\ProgramData`) satisfies this requirement.

Output file directories and their parents should not be writable by low-privilege accounts either: `O_NOFOLLOW` protects only the last path component, and a writable parent lets an attacker replace an earlier component with a symbolic link.

## Enrollment troubleshooting

When `sigilc enroll` fails with a network error, retry with the same token. If the retry gets `server returned 401: enrollment token was already used`, the server consumed the token before the response arrived. The old identity of that name was replaced on the server. Create a new token with `sigils token create --name <name> --replace` and enroll again.

When the server answers 200 but `sigilc` cannot use the response (certificate validation fails, response cannot be decoded) or cannot write `client.yaml`, the error says the server took the token and prints the `--replace` command. The old identity no longer works on the server.

A `server returned 500: internal error` means the server rolled back the entire operation; the token is not consumed, and you can retry with the same token.

## Service status

`service status` queries the service manager and probes the daemon over its IPC socket:

- **Running** --- the service manager reports running and the daemon answered.
- **Running (not answering on ...: ...; see ...)** --- the service is running but the IPC endpoint does not exist, refuses connections, or times out. The message includes the log location (`journalctl -u <name>`, the Application event log, or `/var/log/<name>.err.log`).
- **Running (cannot check the daemon on ...: ...)** --- a permission error or another non-network error when opening the socket. Permission errors add "checking it needs root or an elevated administrator".
- **Stopped** --- the service manager reports the service is not running.
- **query status: ...** (exit code 1) --- the service is not installed, or the service manager reported an error (such as systemd's `failed` state).

## Upgrade notes

**Old Windows installations**: builds before the directory audit created `C:\ProgramData\Sigil` with the installing user's SID in the ACL. After upgrading, the `sigilc` service and reinstall enrollment both refuse to start. Fix it with the `icacls` command the error message prints:

```powershell
icacls "C:\ProgramData\Sigil" /setowner *S-1-5-32-544
icacls "C:\ProgramData\Sigil" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /remove:g *S-1-5-21-...
```

The exact command is in the error message; copy it from there. If `sigils` is not on the same host, you can instead remove `C:\ProgramData\Sigil` and re-enroll with a `sigils token create --name <name> --replace` token.

If the `sigils` data directory was created interactively with elevation, it may have the same problem. Fix it with the `icacls` command the error prints; do not remove the sigils data directory, or you lose the mini-CA and certificate database.

**New CLI with old daemon**: after upgrading the binary but before restarting the daemon, the new CLI's `token create` rejects the old daemon's response (which lacks `token_id`), though the token is already stored in the database and will expire. Restart `sigils` before creating tokens. `cert add` and `cert remove` return `404 page not found` with the old daemon; restart `sigils` to use them.

**Systemd units**: builds before the audit did not include `KillMode=mixed`. After upgrading, run `service stop`, `service uninstall`, `service install`, then `service start` to update the unit. The install script's `--upgrade` does not rewrite the unit; only a reinstall with a token does.

**Old sigilc with new sigils**: the enrollment response no longer carries `ca_cert`. An old `sigilc` that enrolls with a new `sigils` saves an empty CA certificate in `client.yaml`; the daemon then refuses to start with `identity: ca_cert, client_cert, and client_key must all be present (or all absent)`. The enrollment already consumed the token. Fix: replace the binaries in `<data_dir>/binaries/` before enrolling, or re-enroll with a `--replace` token after replacing them.

**Absolute paths**: all path fields now require absolute paths. A `server.yaml` or `client.yaml` that uses relative paths causes the daemon to fail at startup, `reload` to be rejected, or CLI commands to report `<field>: must be an absolute path, got "<value>"`. Fix the paths before upgrading.

**Mode field**: the `mode` field in output specifications is now read as octal. A value that was written as decimal (such as `mode: 400`, which was `0620` in older builds) now means `0400`. Values that contain `8` or `9` (such as `384`, the decimal of `0600`) are rejected and `sigilc` refuses to start; fix them in `client.yaml`.

**Output re-encoding**: the current build re-encodes certificate PEM blocks before writing outputs. If a CA's PEM was not in Go's standard format, each certificate's outputs are rewritten once after the upgrade, and `on_change` runs once.
