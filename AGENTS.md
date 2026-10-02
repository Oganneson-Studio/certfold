# AGENTS.md

**Certfold** is an ACME certificate issuer and distributor for server clusters.
The server binary is `certfolds`; the client is `certfoldc`.
See [README.md](README.md) for user-facing documentation and [docs/en/](docs/en/) for extended guides.

## Current status

Active development. Core features are implemented: enrollment, mTLS auth,
long-poll delivery with per-round reconciliation, `on_change` hooks, parallel
issuance, exec DNS provider, ARI-driven renewal (RFC 9773), HTTPS certificate
hot reload, server and client TUI, slog logging with a 500-entry event ring,
and `events` commands for both binaries. E2E tests (WSLC and Linux Docker)
cover real Pebble issuance including ARI. An opt-in suite (`e2e_cloud`) issues
real certificates from Let's Encrypt staging through the Cloudflare provider;
the other cloud DNS providers have no E2E.

Pre-deploy audit completed 2026-10-01. Renamed from Sigil to Certfold on
2026-10-01 because all Sigil-related domain names were taken. For the full
history of refactoring decisions (B1--B4, C1--C2, D1--D8) and the audit, see
[docs/history.md](docs/history.md).

## Quick facts

- Go 1.26.8. Module: `github.com/Oganneson-Studio/certfold`. `go.mod` is the single source of the Go version (CI uses `go-version-file: go.mod`; E2E images use `golang:1.26-alpine`).
- go-winio: unreleased main snapshot `7e8af9b` (fixes a pipe-listener `Close` race in v0.6.2 that could block `certfolds` shutdown forever if an IPC client connects at that moment). Replace with a tagged release once upstream publishes one.
- Server uses SQLite to store certificates, clients, tokens, and ACME accounts. Client outputs PEM, DER, and PKCS#12.
- `internal/renewal` and `internal/proc` are leaf packages shared by both binaries; `internal/proc` provides bounded tail output, process-tree kill, and `WaitDelay`. Dependency rules: see Change checklists.
- CLI: Cobra. TUI: Charm v2 (`bubbletea/v2`, `lipgloss/v2`, `bubbles/v2`), based on the `Backend` interface. v1 and termenv have been removed.
- Logging: slog. Event ring: `logging.Ring` (500 entries), read via IPC and `events`.
- Service management: kardianos v1.3.0. systemd units use a custom `SystemdScript` template with `KillMode=mixed`.
- Windows container development and E2E: WSLC (not Docker Desktop).

## Build and verification

```sh
go build ./cmd/certfolds
go build ./cmd/certfoldc
go test ./... -count=1
go vet ./...
```

### E2E

```sh
# Windows (uses C:\Program Files\WSL\wslc.exe automatically):
go test -v -tags e2e -count=1 -timeout 10m ./test/e2e

# Linux Docker (run as a docker-group user, no sudo):
CERTFOLD_CONTAINER_CLI=docker CERTFOLD_E2E_REQUIRED=1 \
  go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

- Always pass `-count=1`. E2E reads repository files via `wslc build`, which Go's test cache does not track; a stale cache can report `(cached)` on a changed tree.
- Without `CERTFOLD_E2E_REQUIRED=1`, Linux silently exits 0 when no container runtime is found (false pass). Windows requires WSLC.
- Warm-run timings: WSLC ~132--140 s; Linux Docker ~171 s (~189 s on first base-image pull). WSLC builds do not go through the host proxy; the first build after a dependency change may time out -- retry.

### Cloud DNS E2E

```sh
# Load the token from a file so it stays out of shell history.
export CERTFOLD_E2E_CLOUDFLARE_TOKEN="$(tr -d '\r\n' < <token-file>)"   # bash
# $env:CERTFOLD_E2E_CLOUDFLARE_TOKEN = (Get-Content -Raw <token-file>).Trim()   # PowerShell
go test -v -tags e2e_cloud -count=1 -timeout 15m ./test/e2e
```

- Issues real certificates from Let's Encrypt staging through the `cloudflare` provider for random names under `certfold.com` and `certfold.org`, with the default propagation check and default resolvers (the `e2e` suite skips the check and pins the resolvers). Details: [PLT-13](docs/agents/platforms.md).
- The token needs DNS:Edit and Zone:Read on both zones. Without it the run fails; it never skips. Keep the token out of the repository and out of command lines that get logged.
- Not run in CI (CI only vets the tag). Warm run on WSLC: ~45--55 s.

### Race detection

```sh
go test -race ./...
```

Requires `CGO_ENABLED=1`. If CGO is disabled, report it as not run; do not record it as passed.

### Windows full verification

Run in an elevated PowerShell or an elevated Git Bash. Both skip exactly 2 tests (POSIX permission-bit tests; they run on Linux). IPC-related skips must be 0; a nonzero count means the shell is not elevated.

### Worktree builds

Binaries built in linked worktrees nested inside the main checkout get `vcs.revision` from the main worktree, not the worktree's own HEAD. Release builds should use a regular clone or set the version with `-ldflags -X`.

### CI

`.github/workflows/test.yml`: Linux full tests, race, vet (including `GOOS=windows`), `e2e` tag vet, govulncheck v1.8.0, and Windows full tests (elevated shell required). Typical CI times: Linux ~5 min, Windows ~3 min (including elevation check).
`.github/workflows/e2e.yml`: Linux Docker E2E (triggered by the `run-e2e` label or `workflow_dispatch`). Typical CI time: ~4 min.
Both workflows have run green on GitHub-hosted runners (verified 2026-10-01).

## Repository map

```text
cmd/certfolds/commands/    Server CLI and output formatting (wired in internal/server)
cmd/certfoldc/commands/    Client CLI and enrollment flow (wired in internal/agent)
internal/acme/             lego ACME wrapper and ARI queries
internal/agent/            certfoldc daemon composition root
internal/api/              HTTPS API (/v1/sync long poll), install scripts, mTLS middleware
internal/ca/               Internal mini-CA
internal/client/           Sync loop, private store, on_change hooks, reconciliation
internal/config/           Strict YAML schema and validation
internal/enroll/           One-time token, CSR, identity persistence
internal/ipc/              Server and client local-control API
internal/logging/          slog handler, event ring, Private marker, Recoverer, terminal safety
internal/output/           Certificate formatting, output comparison, grouped atomic replacement
internal/proc/             Leaf: process management for hooks and exec DNS (tail 4 KiB, kill tree)
internal/renewal/          Leaf: ratio renewal rule (scheduler, server TLS, certfoldc client; no lego)
internal/scheduler/        Issuance, renewal, ARI, backoff
internal/server/           certfolds daemon composition root
internal/securefile/       Private-key atomic write and Windows DACL
internal/service/          System service install and lifecycle (kardianos)
internal/store/            SQLite repositories
internal/tui/              Server/client TUI (Charm v2, Backend interface)
internal/version/          Build version (ReadBuildInfo + ldflags override)
pkg/proto/                 HTTP DTOs
test/e2e/                  WSLC-first container-orchestrated E2E tests
```

## Working rules

- Read the existing implementation and tests before making changes. Do not describe unimplemented features as done.
- Verify changes with gofmt, unit tests, go vet, and the E2E suite.
- Add regression tests for security boundaries, cross-module contracts, and user workflows.
- `.gitattributes` enforces LF line endings.
- Agent-facing rules live in `AGENTS.md` and `docs/agents/`. Do not add tool-specific instruction files.
- After container tests, confirm that WSLC containers and networks are empty and remove the images built for the run.

## Docs i18n rule

`README.md` and `docs/en/` are the English source of truth. `README.zh-CN.md` and `docs/zh-CN/` are Simplified Chinese translations. Any change to the English docs must update the Chinese counterpart in the same commit.

## Change checklists

When you change X, also do Y:

- **Adding a config field**: update the YAML schema, validation, and tests. Keep the four parse entry points (`ParseServer`, `ParseClient`, `ReadServerField`, `ReadClientField`) consistent. All path fields must require absolute paths after `${VAR}` expansion.
- **Touching `skip_propagation_check`, `acme.dns_resolvers`, or other DNS-01 wiring in `internal/acme`**: run both the `e2e` and `e2e_cloud` suites.
- **Changing install scripts**: keep S18 and INS-1 intact; add a static assertion to `internal/api/install_script_test.go` for any new invariant; re-run a real-machine install, reinstall and upgrade round on Linux (systemd) and Windows (PowerShell 5.1 and 7).
- **Changing a Windows ACL code path**: Windows ACL code has elevated and non-elevated branches (S4, S5); test both.
- **Schema migration**: migrations move forward only. An upgraded database cannot be opened by older binaries.
- **Adding a dependency to `internal/renewal` or `internal/proc`**: both are leaf packages shared by both binaries. `internal/renewal` must not pull in lego. `internal/proc` depends only on the standard library and `x/sys`. Check binary size impact before adding anything.
- **Adding a TUI glyph**: add it to `narrowGlyphs` in `internal/tui/shared/glyphs.go` only after confirming it renders one cell wide in conhost under cp936. The view tests fail on any glyph `shared.WideGlyph` reports. See [TUI-5](docs/agents/tui.md) and [PLT-4](docs/agents/platforms.md).
- **Changing reload-rejected fields**: `validateHotReload` in `internal/server/server_runtime.go` builds the message from its list. Update its test and [SRV-1](docs/agents/server.md). `cert add`/`cert remove` use the same check ([SRV-16](docs/agents/server.md)).

## Component contracts index

Read the linked doc before changing these paths.

| Paths | Doc | Summary |
|-------|-----|---------|
| `internal/server/**`, `internal/scheduler/**`, `internal/acme/**`, `internal/ca/**`, `internal/store/**` | [docs/agents/server.md](docs/agents/server.md) | Reload, TLS hot reload, issuance locking, ARI, backoff, accounts, SQLite |
| `internal/api/**`, `internal/enroll/**` | [docs/agents/api.md](docs/agents/api.md) | `/v1/sync`, auth middleware, identity renewal, enrollment, downloads |
| `internal/client/**`, `internal/agent/**`, `internal/output/**`, `cmd/certfoldc/**` | [docs/agents/client.md](docs/agents/client.md) | Sync loop, reconciliation, outputs, hooks, enroll, fetch, reload |
| `cmd/certfolds/**`, `internal/ipc/**` | [docs/agents/server.md](docs/agents/server.md) SRV-1, SRV-14 to SRV-18; [docs/agents/client.md](docs/agents/client.md) CLI-1 | certfolds CLI, server and client IPC, IPC endpoint resolution |
| `internal/proc/**`, `internal/renewal/**` | S13, S15 (below); Change checklists | Leaf packages: process management, ratio renewal |
| `internal/config/**` | S10 (below) | Strict YAML, env-var expansion, absolute-path enforcement |
| `internal/securefile/**` | S4, S5 (below) | Private temp files, atomic rename, Windows DACL |
| `internal/logging/**` | [docs/agents/server.md](docs/agents/server.md) SRV-19 | Event ring, Private marker, Recoverer, terminal safety |
| `internal/service/**`, `internal/api/install_script*` | [docs/agents/install-and-service.md](docs/agents/install-and-service.md) | Install scripts, service install, Windows registry, systemd, launchd |
| (platform-specific `_windows.go`, `_unix.go`, `_other.go`, `test/e2e/**`) | [docs/agents/platforms.md](docs/agents/platforms.md) | Windows, PowerShell 5.1, conhost, WSLC, Docker E2E, Pebble |
| `internal/tui/**` | [docs/agents/tui.md](docs/agents/tui.md) | TUI keys, lipgloss v2, wide glyphs, refresh timeouts |
| (all) | [docs/agents/known-gaps.md](docs/agents/known-gaps.md) | Known limitations, ARI simplifications, display issues |

## Security invariants S1--S20

Other documents, commits, and tests reference these by number. S7 and S9 are
retired but keep their numbers so existing references stay valid.

**S1** `server.yaml`'s `certificates[].subscribers` is the sole source of subscription authorization. Client output configuration must not widen it.

**S2** Enrollment tokens are one-time, binding a secret, server URL, client name, and mini-CA certificate. The client must verify TLS before sending the token; never restore `InsecureSkipVerify`. Enrollment requests do not follow redirects (`CheckRedirect` returns `ErrUseLastResponse`). `EnrollResponse` does not carry `ca_cert`; the client saves the CA certificate from the token and validates the returned client certificate (CN, chain to token CA, ClientAuth EKU, public key equals CSR). Malformed CSR returns 400 without consuming the token. `ErrUnusableAnswer` means the server's answer fails to decode or its certificate fails verification. When the server returns 200 but `ErrUnusableAnswer` occurs or writing `client.yaml` fails, the error states the token is consumed and suggests `certfolds token create --name <name> --replace`. Enrollment and identity renewal verify the returned certificate's chain as of the certificate's own `NotBefore` (`x509.VerifyOptions.CurrentTime`), not the local clock; do not change this, because the certificate must carry the current CSR's public key, so an old certificate cannot be replayed.

**S3** Every request from an enrolled client must pass mTLS, database existence, and certificate fingerprint matching. A waking `/v1/sync` must re-verify before returning a new view. Deleting a client revokes access. No write path other than enrollment may create a client record (including the auth middleware's conditional `last_seen` UPDATE). During identity renewal, if the same-named client is re-enrolled, the old identity's renewal returns 401 (`StagePendingIdentity` conditions on the presented certificate fingerprint).

**S4** `client.yaml` and `<data_dir>/certs.json` contain private keys. All writes go through `internal/securefile`: Unix private mode, Windows protected DACL, temp file + atomic rename. Always create private temp files with `securefile.CreateTemp`: Windows sets the DACL at `CreateFile` time. Never create a file and tighten it afterwards: a handle another account opened before the tightening can still read what is written afterwards. `certs.json` is tightened with `securefile.ProtectFile` on load if it already exists; its path must not be derived from server-supplied certificate names. `client.data_dir` and private-key outputs must reside on a filesystem that preserves Unix permission bits (WSL drvfs/9p without metadata, CIFS without unix extensions, vfat/exfat, and WSLC bind mounts cannot).
- Directory checks run at startup; reload does not recheck. On Windows, the config directory and `certfoldc` `data_dir` must be owned by SYSTEM, Administrators, or (when not elevated) the current user; no other principal may have write, delete, delete-child, change-DACL, or change-owner access. `certfolds` `data_dir` must be fully private on Windows (inherited entries included); on Unix `mode&077==0` and owner must be the running user. Non-compliant directories refuse startup with an error naming the directory and suggesting `icacls`/`chmod`/`chown`. The `ca\` subdirectory is checked in `ca.Bootstrap`.
- `data_dir` is created privately by `EnsurePrivateDirectory` if it does not exist; existing directories are checked but not tightened. Exception: `ca.Bootstrap` runs `CheckDirectory` then `EnsurePrivateDirectory`, resetting the protected DACL on every startup. Objects created via `privateDescriptor` (`securefile.CreateTemp` files and `EnsurePrivateDirectory` directories) are owned by Administrators when elevated, without the operator's own SID. `ProtectFile` replaces only the DACL, keeping the owner. `certfolds.db` and `-wal/-shm` inherit the process default owner: SYSTEM as a service, typically Administrators in elevated PowerShell, the user SID in elevated Git Bash (MSYS changes the token's default owner).
- The config directory and `data_dir`'s parent chain must not be owned by or writable by other accounts. The check inspects only the final component; the default layout satisfies this. Output file directories and their parents must not be writable by lower-privilege accounts (`O_NOFOLLOW` protects only the last path segment).

**S5** Private-key outputs default to mode `0600`; public certificates may use `0644`. Do not use one default for all formats. Reconciliation rewrites outputs grouped by certificate: content, permissions, and ownership are staged on temp files; renames happen only after all temp files succeed. Never rename first and chown afterwards. On Windows, private-key outputs (`pem-key`, `pem-bundle`, `pkcs12`) have additional rules:
- Temp files get a protected DACL at `CreateFile` time: SYSTEM and Administrators full control (plus the current user when not elevated), configured `owner` read-only. `owner` adds a read-only ACE; it does not change the file owner.
- `mode` is not applied on Windows and must not relax the DACL; the read-only attribute would also break the subsequent rename.
- `owner` is treated as a SID when it starts with `S-` (case-insensitive) and can be resolved; otherwise it is looked up as an account name. SDDL aliases (`BU`, `WD`, etc.) must not be treated as SIDs. `owner` applies only to private-key outputs; other formats ignore it silently.

**S6** The install download endpoint must maintain both a character whitelist and directory containment on the `os`/`arch` path. Downloads use `ServeContent` (Content-Length and Range). Per-response write deadline: 10 min (`downloadWriteTimeout`).

**S7** Retired (B3 made install.ps1 static). Number kept so references stay valid.

**S8** Production one-click install requires the public endpoint to use an OS-trusted TLS certificate. Configure via `server.tls_cert_file` and `server.tls_key_file`; the mini-CA's default certificate is not trusted by system `curl`.

**S9** Retired (B1 removed server push and client push listener). Number kept so references stay valid.

**S10** Config parsing uses `yaml.KnownFields(true)`. Adding a field requires updating the schema, validation, and tests. All path fields (`server.data_dir`, `tls_cert_file`, `tls_key_file`, `ipc_socket`, gcloud `service_account_file`; `client.data_dir`, `ipc_socket`, `outputs[].path`; `on_change` and exec `argv[0]` already required) must be absolute after `${VAR}` expansion. Error: `<field>: must be an absolute path, got "<value>"`. Windows: `\dir` and `C:dir` are not absolute; named pipes and UNC paths are; `ipc_socket` must be a full `\\.\pipe\...`. `ReadServerField` and `ReadClientField` are per-field lenient readers sharing `readField` for expansion and validation; used by CLI IPC lookup and the installer to find `data_dir`; daemons must not use them. `certfoldc enroll` uses `ReadClientField` to compare `name`/`server_url`. `${VAR}` and `${VAR:-default}` are expanded per scalar value after YAML parsing: value inserted as-is without trimming; keys are not expanded; `$$` is literal `$`; unset variable without a default is an error; nested defaults `${A:-${B}}` are an error. The four entry points (`ParseServer`, `ParseClient`, `ReadServerField`, `ReadClientField`) must produce consistent results. `client.yaml`'s `client.name` and `certificates` keys are validated with the same naming rule.

**S11** Server read-only IPC must use explicit DTOs. Never return certificate private keys or enrollment-token secret hashes over IPC. No IPC route writes certificates; certificates enter the database only through issuance. The event ring must not contain token strings (only token IDs), private keys, config structs, or panic stacks (Recoverer logs method, path, and panic value; the stack is a `Private` attribute). Hook and DNS program output is marked `Private`: `(withheld)` in the ring and Windows event log; only the service log (stderr / journald / launchd `/var/log/<name>.err.log`) keeps the last 4 KiB.

**S12** Database certificate records must bind a valid config fingerprint. After a CA directory, domains, or key-type change, old material must not be distributed.

**S13** `exec` DNS provider is configurable only in `server.yaml`. It runs as the `certfolds` service account with its full environment (including `${VAR}` credentials). Timeout: 2 min per invocation.
- Record names are validated before execution: each label `[A-Za-z0-9_-]`, non-empty, no leading `-`. Error: `exec: <action>: record name %q is not a host name`, and the program is not started.
- Timeout or ctx end kills the process tree (Unix process group, Windows Job Object). If the program exits normally, processes it left behind keep running, on both platforms.
- Error messages contain only the action, record name, and exit status or timeout; startup failures additionally name `argv[0]`. `argv[1:]` and program output never enter errors. Output held open is treated as failure: `exec: <action> <record>: exit status 0, but a process it started still holds its output`.
- Output is written to the service log (last 4 KiB) only on failure; never to events.
- The programs ctx comes from `acme.NewIssuer` (derived via `context.WithoutCancel` in `server.Run`), cancelled only when `server.Run` returns. It is neither the daemon's ctx nor `Issue`'s ctx.

**S14** Error text from the ACME CA and DNS provider must be sanitized before being written to `issuance_status.last_error` or returned via IPC: `logging.OneLine` (replace control characters and invalid UTF-8), then `logging.RedactURLQueries` (replace URL query strings with `?REDACTED`), then truncate to 1 KiB. The event rendering path (Ring and Windows event log Message and Attrs) also redacts URL queries; the stderr service-log sink (journald under systemd, `/var/log/<name>.err.log` under launchd) keeps the original text. ARI query errors undergo the same sanitization pipeline before entering events or `last_error`.

**S15** `on_change` is configurable only in `client.yaml`, as an argv (argv[0] must be an absolute path), never through a shell. Server-supplied content (including certificate names) must not influence what is executed or where files are written.
- Runs as the `certfoldc` service account with its full environment. stdin is empty. Timeout: 2 min. On timeout or daemon stop, the process tree is killed (Unix process group, Windows Job Object). If the hook exits normally, processes it left behind keep running, on both platforms. IPC caller disconnect does not affect it.
- Error messages contain only the certificate name and exit status or timeout; startup failures also name `argv[0]`. `argv[1:]` and hook output never enter errors. Hook output is the `Private` attribute of the `on_change failed` event: `(withheld)` in events and Windows event log; only the service log (stderr / journald / launchd `/var/log/<name>.err.log`) keeps the last 4 KiB. Under a Windows service, the service log *is* the event log, so `Private` shows `(withheld)` everywhere -- hook scripts must log on their own.
- Exit 0 with output still held: wait up to 5 s, treat as success, log WARN `on_change output held open` (exec DNS treats this as failure). Background processes must redirect their own stdout/stderr.
- Persistent hook failures cause sync-loop backoff (5 s initial, doubling, capped at 5 min, settling at ~5 min between retries). Each failure on Windows writes an Application event log entry.

**S16** Text printed by `certfoldc` or returned via its IPC must not carry network-sourced control characters (symmetric with S14). `Printable`/`OneLine` also replace Cf (zero-width), Zl (line separator), Zp (paragraph separator). TLS handshake errors quote the peer certificate's DNS names verbatim (`crypto/x509` checks the hostname before building the chain; a MITM does not need a trusted certificate); server responses and server-supplied certificate names are equally untrusted.
- `LastError`, Fetch, and Reload errors leaving the `client` package go through `client.printable`: each sub-error in `errors.Join` gets `logging.OneLine` (DEL and C1 become spaces, invalid UTF-8 becomes U+FFFD), then the results are joined with `\n`. Network-sourced `\n` is also replaced, preventing line spoofing. Do not replace this with `logging.Printable` (it preserves `\n`). `certfoldc enroll` network errors go through `logging.OneLine`. Errors still `Unwrap` to the original.
- Both CLIs' `main` functions print errors through `logging.Printable`.
- Non-compliant certificate names in the view count as a round error, are treated as unlisted, and their stored material is deleted.
- Token decoding validates `name` (`config.ValidateClientName`) and `server_url` (`config.ValidatePublicURL`) before writing `client.yaml`.
- The client rejects bundle fingerprints not matching `sha256:` followed by 64 hex characters.

**S17** Naming rules and `server.public_url`:
- All names in `server.yaml` (certificate names, `acme.cas` keys, `dns_providers` keys) and client names follow the same rule: lowercase DNS labels, 1--63 characters of `a-z0-9-`, no leading or trailing `-`. Shared implementation: `config.ValidateClientName`, `config.ValidateCertificateName`, `validateName`.
- `server.public_url`: ASCII-only https URL, must have a host, no userinfo / query / fragment, port 1--65535 if present, no single/double/backtick quotes, `$`, `\`, whitespace, or control characters (`config.ValidatePublicURL`). PowerShell treats U+2018--U+201B as single quotes and U+201C--U+201E as double quotes, so rejecting only ASCII quotes is insufficient. When `public_url` is unset, `token create` applies the same check to the URL inferred from `listen`; failure prompts the user to set `server.public_url`.
- `server.listen`: `host:port`, port 1--65535, host may be empty (`:8443` is valid).

**S18** Install scripts are static and do not read request parameters. install.ps1 is ASCII-only, never calls `exit` (under `& ([scriptblock]::Create(...))` it closes the caller's session), checks `$LASTEXITCODE` after every native call, downloads with `-UseBasicParsing`. install.sh uses `curl -q --proto '=https' --proto-redir '=https'`; the token is passed via `CERTFOLDC_TOKEN` (install.ps1 via `$env:CERTFOLDC_TOKEN`, removed after use), never as a command-line argument; downloads go to a temp file, then `mv -f`. Static assertions in `install_script_test.go` guard these invariants, but they only catch accidental regressions and cannot cover every way of writing a violation.

**S19** Server HTTPS minimum TLS version: 1.2 (`tls.VersionTLS12`), for PowerShell 5.1 and older systems. `certfoldc` enrollment (`internal/enroll`) and all mTLS requests (`internal/client`) require TLS 1.3; do not relax this. Guarded by `tls13_test.go`.

**S20** `acme.RenewalInfo` queries using a temporary key; no account, no database access, no locks held during the query. Only the due-on-arrival ARI guard writes to the DB (`storeGuard`): under `genMu` read lock, opens a transaction, compares the DB certificate fingerprint, writes `issuance_status` only if the certificate has not been replaced. `replaces` is sent to lego only on pure renewal (stored material matches the current spec) and when `Failures == 0`. On a 409 `alreadyReplaced`, lego strips `replaces` and resends the order.
