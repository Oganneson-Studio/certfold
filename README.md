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

The test builds temporary OCI images, creates an isolated WSLC network, verifies enrollment, certificate fetch, client revocation, and token expiry/revocation, then removes its containers, network, and images.

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

## Runtime reload and renewal

`sigils reload` validates `server.yaml` and applies supported changes through the local server IPC endpoint. ACME settings, DNS providers, certificate definitions, and client push routing can be updated without restarting the daemon. Changes to `server.listen`, `server.public_url`, `server.data_dir`, `server.ipc_socket`, `server.tls_cert_file`, or `server.tls_key_file` are rejected with restart guidance because the listener or TLS identity was fixed at startup; the active runtime configuration remains unchanged.

Reload waits for any in-flight issuance to finish, publishes one configuration generation, clears obsolete retry backoff, and immediately checks the new certificate definitions. Stored certificate material is tied to its CA directory, domains, and key type, so stale same-name material is not distributed while a replacement is being issued. Read-only IPC responses expose metadata only and never include certificate private keys, push tokens, or enrollment-token hashes.

`sigilc` automatically renews its mTLS identity before expiry. `client.identity_renew_before` defaults to 30 days and accepts values from 1 hour through 89 days.

After it starts and after `sigilc reload`, the client rewrites every subscribed output once. A certificate that could not be written is retried on later pulls.

After successful certificate issuance or renewal, `sigils` sends push notifications to configured subscriber routes. Outbound push uses HTTPS with a bearer token, rejects endpoint query strings, and never follows redirects. The client push receiver is plaintext HTTP, so it is restricted to a literal loopback address and requires a bearer token of at least 32 characters; remote ingress must terminate TLS locally before forwarding to it.

## Current limitations

- Automated ACME issuance is unit-tested; the current container E2E focuses on the security-critical enrollment and distribution path using a generated test certificate.
- Some TUI management actions are not wired yet; use the corresponding CLI commands for those operations.
