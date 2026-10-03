English | [简体中文](../zh-CN/installation.md)

[Back to README](../../README.md)

# Installation

## One-line installation

Download the binaries from the [Releases page](https://github.com/Oganneson-Studio/certfold/releases) and verify them with `sha256sum -c SHA256SUMS`; `gh attestation verify <file> --repo Oganneson-Studio/certfold` additionally checks their build provenance. Copy the `certfoldc-*` files unchanged into `<data_dir>/binaries/` on the server: their names, such as `certfoldc-linux-amd64` and `certfoldc-windows-amd64.exe`, are the ones `certfolds` serves to the install scripts. The directory exists only after `certfolds` has started once; before that, create it with `sudo install -d -m 0755 /var/lib/certfolds/binaries`. Files copied there are served at once, without a restart. To install `certfolds` itself as a service, see [Running as a service](operations.md#running-as-a-service). After creating an enrollment token, `certfolds token create` prints the install commands with the token filled in.

**Linux / macOS** (as a user who may sudo):

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh -s -- --token '<token>'
```

Without `--token`, the script asks for the token on the terminal (not echoed), which keeps it off the command line. Prefer this on a host that others use. On macOS, the terminal's single-line input limit (1024 characters) may truncate the token (about 1,100 characters); use `--token` there instead:

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh
```

**Windows** (elevated PowerShell, 5.1 or 7):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1'))) -Token '<token>'
```

Without `-Token`, the script prompts for the token with `Read-Host -AsSecureString` (only asterisks on screen):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1')))
```

The `-bor 3072` prefix adds TLS 1.2 to the protocols Windows PowerShell 5.1 offers. The Certfold server accepts TLS 1.2 and above on its public HTTPS listener, while `certfoldc`'s own connections (enrollment and mTLS) require TLS 1.3.

With `--token` / `-Token`, the token appears in the process command line: `sh -s -- --token` is visible to other users and saved to the shell history; `-Token '...'` stays in the PowerShell session history (`Get-History`) and may be written to the history file by older PSReadLine versions. To keep the token off the command line, omit the flag so that the script prompts for it interactively. `certfoldc enroll` without `--token` reads the `CERTFOLDC_TOKEN` environment variable; both scripts use this to pass the token to `certfoldc`. In automated environments without a terminal, pass `--token` or `-Token` (Linux reports "No terminal to read the token from"; Windows `Read-Host` is not available in non-interactive sessions).

### Reinstalling

On a host where `certfoldc` is already installed: run the same command with a new token (created with `certfolds token create --name <name> --replace`). The script stops the service, replaces the binary, enrolls with the new token, reinstalls the service, and starts it. If enrollment fails, the service is restarted with the earlier `client.yaml`; if the error says the server took the token, the earlier identity no longer works and you need a new `--replace` token. If `client.yaml` already exists with a different name or server URL, the script reports the path and asks you to remove it. After the service starts, the script polls `certfoldc status` for up to 15 seconds and reports the log location if the daemon does not answer.

### Upgrading the binary

To upgrade the binary without re-enrolling:

```bash
curl -fsSL --proto '=https' --proto-redir '=https' 'https://certfold.example.com:8443/install.sh' | sudo sh -s -- --upgrade
```

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm 'https://certfold.example.com:8443/install.ps1'))) -Upgrade
```

`--upgrade` / `-Upgrade` stops the service, replaces the binary, and restarts; it fails if `certfoldc` was never installed. You cannot combine `--upgrade` with `--token`.

### Installed files

On Linux, the install script writes:

- `/usr/local/bin/certfoldc`
- `/etc/certfold/client.yaml` (file `0600`, directory `0700`)
- `/var/lib/certfoldc` (created by `certfoldc` at first startup; already present after installation, mode `0700`, owned by root)
- `/var/run/certfold/certfoldc.sock` (`0660`, owned by root; `sudo certfoldc status` to query)
- `/etc/systemd/system/certfoldc.service` with `Restart=on-failure`, `RestartSec=5`, and `KillMode=mixed`

### Uninstalling

To uninstall on Linux (do not remove `/var/run/certfold`; `certfolds` uses it too):

```bash
sudo certfoldc service stop
sudo certfoldc service uninstall
sudo rm -f /usr/local/bin/certfoldc /etc/certfold/client.yaml
sudo rm -rf /var/lib/certfoldc
# on the server, to revoke access:
sudo certfolds client remove <name>
```

To uninstall on Windows (elevated PowerShell):

```powershell
& 'C:\Program Files\Certfold\certfoldc.exe' service stop
& 'C:\Program Files\Certfold\certfoldc.exe' service uninstall
Remove-Item -Recurse -Force 'C:\Program Files\Certfold'
Remove-Item -Force 'C:\ProgramData\Certfold\client.yaml'
Remove-Item -Recurse -Force 'C:\ProgramData\Certfold\client'
# on the server, to revoke access:
certfolds client remove <name>
```

Do not remove `C:\ProgramData\Certfold` entirely if `certfolds` shares it on the same host.

## Production TLS

The one-line installer downloads `certfoldc` before enrollment, so the public Certfold endpoint must present a certificate already trusted by the operating system. When the endpoint's host name is in a domain Certfold can issue for, the recommended source is Certfold itself; see [Using a certificate Certfold issues](#using-a-certificate-certfold-issues). Otherwise, configure a public certificate directly:

```yaml
server:
  listen: ":8443"
  public_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfolds"
  tls_cert_file: "/etc/certfold/tls/fullchain.pem"
  tls_key_file: "/etc/certfold/tls/key.pem"
```

Replace the certificate and key files in place; `certfolds` reloads them on the next TLS handshake without a restart. A certificate that does not pair with its key is skipped with a warning, and the previous certificate remains in use. Keep the files on a local filesystem: a network mount where `stat` stalls will block all handshakes.

When these fields are omitted, `certfolds` uses its internal mini-CA certificate and reissues it automatically before it expires. A failed reissue retries after one minute.

`server.public_url` must be a pure-ASCII `https` URL. It may not contain quotes, backticks, `$`, `\`, whitespace or control characters: `install.sh` puts it in double quotes (`SERVER_URL="..."`), so `$`, backtick, `\` and `"` would be interpolated; `install.ps1` and the enrollment token put it in single quotes for PowerShell, where curly quotes (U+2018-U+201E) also act as quote characters.

How `certfoldc` verifies the server, and why either kind of server certificate works, is described under [Trust model](security.md#trust-model).

### Using a certificate Certfold issues

A `certfoldc` on the server host can write the endpoint certificate to the files `certfolds` reads:

1. Start `certfolds` without `tls_cert_file` and `tls_key_file`, so it uses its mini-CA certificate. In `server.yaml`, define a certificate that covers the host in `public_url` (an existing wildcard certificate works) and subscribe a client on the same host to it.
2. On the same host, create a token with `certfolds token create --name <client>` and run `certfoldc enroll` with the token in `CERTFOLDC_TOKEN`. The one-line installer cannot be used yet because the operating system does not trust the mini-CA certificate; enrollment trusts the server through the token instead.
3. In `client.yaml`, write that certificate as `pem-fullchain` to `/etc/certfold/tls/fullchain.pem` and as `pem-key` to `/etc/certfold/tls/key.pem`, then run `certfoldc service install` and `certfoldc service start`. `certfoldc` creates the directory and writes both files owned by root, the key with mode `0600` and the chain with `0644`; `certfolds` runs as root and reads them without further changes.
4. Set `server.tls_cert_file` and `server.tls_key_file` to these paths and restart `certfolds`. `certfolds reload` refuses changes to these fields.

Renewals need no action: `certfoldc` rewrites the files, and `certfolds` serves the new certificate at the next handshake. Clients enrolled before the switch keep working. If the files are missing when `certfolds` starts, it exits and the service manager restarts it; `certfoldc` restores the files from its local copy even while the server is down, so a later restart succeeds. The two services need no start ordering.
