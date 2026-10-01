# Client component contracts

Read this doc before changing paths under `internal/client/**`, `internal/agent/**`,
`internal/output/**`, or `cmd/certfoldc/**` (rules for `internal/enroll/**` are in api.md and S2).

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## IPC endpoint resolution (CLI-1)

- `certfolds` and `certfoldc` use separate IPC endpoints.
- Resolution order (`serverIPCSocket` / `clientIPCSocket`, same logic for both): `--ipc` flag; then the config file's `ipc_socket` field; then the platform default.
- If the config file does not exist, is unreadable, or `ipc_socket` is empty: fall back to the platform default.
- If `ipc_socket` cannot be read (relative path, unset variable, YAML parse error): error immediately. Format: `read the IPC endpoint from <file>: <inner error> (pass --ipc to give it instead)`, where the inner error comes from `readField`, e.g. `parse <file>: ...` or `<section>.ipc_socket: ...`.
- Unix client socket: fixed at `/var/run/certfold/certfoldc.sock`; must not depend on `$HOME`.
- Unix IPC Dial trusts only sockets owned by root or the current euid (symmetric with Windows pipe trust of SYSTEM/Administrators). Listen replaces a stale socket without checking ownership.

## Sync loop (CLI-2)

- There is exactly one sync loop; no periodic polling.
- After every round (304 received, 200 applied, or error), and on startup, reload, and IPC fetch: reconcile every output using local storage only, without network access.
- The sync HTTP request must not use a 30-second timeout (the server may hold it for up to 55 s).
- Any error in a round (identity renewal, request, apply, reconcile, hooks) triggers backoff: 5 s initial, doubling, capped at 5 min.
- Identity renewal failure: continue the sync with the current identity.
- If a layer-4 proxy sits between the client and `certfolds`, its idle timeout must exceed 60 s.

## `pullMu` serialization (CLI-3)

- The apply phase (identity renewal, bundle fetch, store write, reconcile, hooks) of the sync loop, reload, and IPC fetch are all serialized by `pullMu`. The sync's long-poll wait does not hold the lock.
- Reload, IPC fetch, and identity rotation cancel the in-flight sync via a cancel registered under the same lock. After taking the lock, the loop aborts a round whose request was cancelled.

## Reconciliation (CLI-4)

- `client.yaml` groups outputs by certificate: `certificates.<name>.outputs` and `certificates.<name>.on_change`. All output paths must be unique after `filepath.Clean` (case-insensitive on Windows).
- Private storage keeps every certificate's material and `hook_pending` from the latest sync view. Certificates that disappear from the view are removed from storage; output files are left in place and no hooks run. Non-compliant certificate names are treated per S16.
- Bundles are validated before storage: key/certificate pairing check; each chain certificate is parsed with `x509.ParseCertificate`; a single failure rejects the entire bundle. Corrupted bundles must never overwrite outputs.
- If writing the store to disk fails, the next reconcile retries the write.

## Output comparison and replacement (CLI-5)

- Content mismatch (file missing, not a regular file, unreadable, or content differs): replace all outputs for that certificate as a group (staging rules: S5).
- PKCS#12: compare by decoded certificate chain and private key, not by raw bytes (encoding includes random salt).
- Content match with metadata difference: Unix does chmod then chown on the existing file without re-statting. Windows compares content only; DACL, mode, and owner are not compared. Metadata-only changes do not trigger hooks, because some filesystems cannot persist permission bits (drvfs/9p without metadata, CIFS without unix extensions, WSLC bind mounts always report 0777).
- Outputs re-encode only CERTIFICATE and private-key PEM blocks. After upgrading, if the CA's PEM is not in Go's canonical format, each certificate's outputs are rewritten once and on_change runs once.
- Views, bundles, and identity-renewal responses are capped at 1 MiB (`maxResponseBytes`, enough for approximately 5000 certificates). Exceeding this limit surfaces as a JSON decode error.

## `on_change` hooks (CLI-6)

- When the downloaded material fingerprint changes (including when the store had no entry for it), or when any output of that certificate is rewritten, set `hook_pending` and persist it. Fixing only permission bits or ownership does not set `hook_pending`.
- After reconciliation, hooks run inside `pullMu`, serially by certificate name. A hook is skipped for a certificate whose reconciliation had an error.
- On failure: `hook_pending` stays set, the failure counts as a round error, and the hook reruns every round with sync-loop backoff. If writing `hook_pending` fails, the hook is skipped that round.
- A successful `certfoldc fetch` wakes a backing-off loop.
- Hook ctx comes from `Run`'s lifecycle: `context.Background()` before `Run` starts, and the already-cancelled ctx after `Run` returns.
- When `certs.json` is persistently unwritable (full disk, read-only mount), all hooks are paused and `LastError` starts with `save store: `.

## Error logging (CLI-7)

- Each is logged once per change of the `LastError` text: `round failed` when it becomes a different error, `round succeeded again` when it is cleared.

## `certfoldc status` (CLI-8)

- IPC call timeout: 10 s (`statusTimeout`).
- `status --json` outputs `{"error": "..."}` on any failure.
- `status --json` returns `ClientState` with `certs` array fields: `name`, `fingerprint`, `not_after`, `renew_at`, `outputs`, `on_change`, `hook_pending`. `renew_at` uses the client's ratio rule; `certfolds` with ARI may renew later.
- `last_pull_at` is absent before the first sync (`omitzero`).

## `certfoldc enroll` (CLI-9)

- On failure: delete a newly created `client.yaml` (leave an existing one).
- The early write is kept as a writability pre-check that does not consume the token.
- Mismatch errors include the config file path.
- Reject tokens whose `name` or `server_url` fail validation.
- After overwriting an existing identity, print a reload hint only if the local daemon's IPC endpoint is reachable (install scripts stop the service before enrolling).
- Without `--token`: read the `CERTFOLDC_TOKEN` environment variable.

## Startup temp-file cleanup (CLI-10)

- On startup, `certfoldc` removes leftover temp files from a previous crash: `.certfold-private-*` in `data_dir` and `.certfold-tmp-*` in each output directory. The directory containing `client.yaml` is not touched.

## `certfoldc fetch` (CLI-11)

- Must call the real IPC to pull, completing reconcile and hooks before returning.
- `--cert` forces re-download of only the named certificate; it does not force rewriting unchanged outputs.

## `certfoldc reload` (CLI-12)

- Parse the new config fully before applying; on failure, keep the old config.
- On success: reconcile from storage under the new config and run hooks before returning. Cancel the in-flight sync so the loop does a full pull immediately.
- A successful local reconcile during reload does not clear `LastError`; the next pull's own result overwrites it.
- Changes to `client.ipc_socket` or `client.data_dir` require a restart.

## `SaveIdentity` (CLI-13)

- Uses `yaml.Node` to replace or append `identity` in client.yaml, preserving comments, key order, and original text. Blank lines are lost (yaml.v3 limitation).
