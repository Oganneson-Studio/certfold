# Sigil

Sigil is a central certificate issuer and distributor for server fleets.

- `sigils` manages ACME certificates, enrollment, subscriptions, and distribution.
- `sigilc` enrolls with mTLS, pulls subscribed certificates, and writes them in PEM, DER, or PKCS#12 formats.

## Project status

Active development. Enrollment, certificate distribution, management commands, runtime reload, client identity renewal, and push delivery are implemented. The security-critical enrollment and pull path is covered by unit tests and a WSLC-native end-to-end test; review the remaining test and TUI limitations below before production use.

## Build and test

```bash
go build ./cmd/sigils
go build ./cmd/sigilc
go test ./... -count=1
go vet ./...
```

On Windows, the end-to-end suite uses WSLC directly and does not require Docker Desktop or Compose:

```powershell
go test -v -tags e2e -timeout 10m ./test/e2e
```

The test builds temporary OCI images, creates an isolated WSLC network, and issues real certificates from a Pebble ACME server through the `exec` DNS hook and a challenge test DNS server. It verifies enrollment, certificate fetch, renewal, client revocation, and token expiry/revocation, then removes its containers, network, and images.

Linux CI can run the same orchestration with Docker Engine by setting `SIGIL_CONTAINER_CLI=docker`.

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

When these fields are omitted, `sigils` uses its internal mini-CA certificate. That mode is suitable for development or a deliberately configured trusted environment, but a fresh `curl` or `Invoke-WebRequest` will not trust it automatically.

Enrollment tokens carry the expected client name, server URL, and mini-CA certificate. `sigilc` validates TLS before sending the token or CSR, then stores its mTLS identity in a private, atomically replaced configuration file.

`sigilc` verifies the server against the operating system's roots plus the Sigil mini-CA, so either kind of server certificate works. Client certificates are always issued and verified by the mini-CA.

## Basic flow

```bash
# Start the server
sigils --config /etc/sigil/server.yaml serve

# Create a short-lived enrollment token
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

`token create` and `reload` are served by the running daemon over local IPC and fail when it is not running. `cert add` and `cert remove` edit `server.yaml` and then tell a running daemon to reload.

On Windows, run the daemons as services (LocalSystem) or from an elevated prompt. The CLI only talks to a named pipe owned by SYSTEM or Administrators, so a low-privilege process cannot impersonate the daemon. `service install` registers a daemon with the system service manager, which restarts it after a failure: 10 seconds later on Windows, and through `Restart=on-failure` under systemd.

For one-line installation, place platform binaries in `<data_dir>/binaries/` using names such as `sigilc-linux-amd64` and `sigilc-windows-amd64.exe`.

## Environment variables in configuration

Values in `server.yaml` and `client.yaml` can reference environment variables as `${VAR}` or `${VAR:-default}`. `$$` is a literal `$`, and an unset variable without a default is an error. References are expanded after the YAML is parsed, inside each scalar value:

- The value is inserted verbatim. Leading and trailing spaces and line breaks are kept, and quotes, `#`, or `: ` inside it are never read as YAML.
- Mapping keys are never expanded.
- Inside a flow collection, quote the reference, as in `["${HOST}"]`, because `{` is a flow indicator there.

## Private key outputs on Windows

Outputs that contain a private key (`pem-key`, `pem-bundle`, `pkcs12`) are created with a protected ACL that grants access only to SYSTEM, Administrators, and the account running `sigilc`. `mode` is not applied on Windows and cannot widen that ACL. To let a service such as IIS or nginx read a key, set `owner` on that output to the service's account name or SID; that account gets read access.

When upgrading from an earlier build:

- The first start rewrites every output. A non-administrator consumer that relied on the directory's inherited ACL loses access to key files until `owner` is set for it.
- Files that an earlier build wrote with a read-only `mode` carry the read-only attribute, which makes replacing them fail. Clear it once with `attrib -r <file>`.

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
- On failure, the error names only the action, the record, and the exit status or timeout. The hook's output goes to the service log, truncated.

On Windows, run a PowerShell script through its full path, for example `command: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\sigil\hook.ps1']`.

Other DNS-01 settings:

- `skip_propagation_check: true` on a provider skips lego's check that the TXT record is visible on the zone's authoritative nameservers. Use it with DNS servers that cannot answer that check; lego still waits one 4-second polling interval.
- `acme.dns_resolvers` sets the resolvers lego uses for zone lookups, CNAME following, and the propagation check. It applies to the whole process, so changing it requires a restart. When it is empty, lego uses the system resolvers, and on Windows it falls back to Google Public DNS.
- Certificates that share a domain are issued in parallel and use the same `_acme-challenge` record. A provider may reject the second record, and one certificate's cleanup removes the record for both, so one of them fails and is retried after its backoff. Avoid overlapping domains across certificates.
- To use a private ACME CA, set `LEGO_CA_CERTIFICATES` for `sigils` to the path of the CA's root certificate. lego panics if that file cannot be read.

## Runtime reload and renewal

`sigils reload` validates `server.yaml` and applies supported changes through the local server IPC endpoint. ACME settings, DNS providers, certificate definitions, and client push routing can be updated without restarting the daemon. Changes to `server.listen`, `server.public_url`, `server.data_dir`, `server.ipc_socket`, `server.tls_cert_file`, `server.tls_key_file`, or `acme.dns_resolvers` are rejected with restart guidance: the listener and TLS identity are fixed at startup, and lego keeps the DNS resolvers in process-wide state. The active runtime configuration remains unchanged.

`sigils` issues certificates in parallel, at most four at a time and at most one issuance per certificate at a time:

- Reload does not wait for in-flight issuance. It clears retry backoff, publishes the new configuration, and immediately checks the certificate definitions.
- An issuance that started before a reload is discarded if the certificate's CA directory, domains, or key type changed meanwhile, and the certificate is issued again under the new configuration. Stored certificate material is tied to those same settings, so stale same-name material is never distributed.
- A failed issuance is retried after 5 minutes, doubling up to 24 hours. The backoff is stored in the database and survives a restart, so after fixing the cause (for example DNS credentials) run `sigils reload` or `sigils cert renew <name>` instead of restarting.
- `sigils cert list` shows each configured certificate's state: `issuing`, `backoff`, `valid`, or `pending`. `sigils cert show <name>` adds the failure count, the last error, and the next attempt.

Read-only IPC responses expose metadata only and never include certificate private keys, push tokens, or enrollment-token hashes.

`sigilc` automatically renews its mTLS identity before expiry. `client.identity_renew_before` defaults to 30 days and accepts values from 1 hour through 89 days.

After it starts and after `sigilc reload`, the client rewrites every subscribed output once. A certificate that could not be written is retried on later pulls.

After successful certificate issuance or renewal, `sigils` sends push notifications to configured subscriber routes. Outbound push uses HTTPS with a bearer token, rejects endpoint query strings, and never follows redirects. The client push receiver is plaintext HTTP, so it is restricted to a literal loopback address and requires a bearer token of at least 32 characters; remote ingress must terminate TLS locally before forwarding to it.

## Current limitations

- The container E2E issues certificates through the `exec` DNS provider; lego's built-in cloud DNS providers are not covered by an E2E.
- Some TUI management actions are not wired yet; use the corresponding CLI commands for those operations.
