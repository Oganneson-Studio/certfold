# Server component contracts

Read this doc before changing paths under `internal/server/**`, `internal/scheduler/**`,
`internal/acme/**`, `internal/ca/**`, or `internal/store/**`.

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## Reload (SRV-1)

- `certfolds reload` must go through the local server IPC; the daemon fully parses and validates the new config before applying any of it.
- Hot-reloadable sections: `acme`, `dns_providers`, `certificates` (including `subscribers`).
- Reject the reload and keep the running config when any of these change: `server.listen`, `server.public_url`, `server.data_dir`, `server.ipc_socket`, `server.tls_cert_file`, `server.tls_key_file`, `acme.dns_resolvers`. Require a full restart instead. Reason: TLS file paths and the listen address are fixed at startup; `acme.dns_resolvers` is stored in a lego process-global variable.
- TLS file *content* is picked up automatically by `tlsSource` on every handshake (see SRV-2).

## TLS hot reload -- `tlsSource` (SRV-2)

- When `tls_cert_file` is configured, every TLS handshake stats both the certificate and key files. A change in mtime or size triggers a reload attempt.
- A failed load (e.g. mid-replacement) keeps the old certificate. Each file change triggers exactly one load attempt and one log entry: INFO `server TLS certificate reloaded` on success, WARN `server TLS certificate not reloaded` on failure. Stat failures are logged the same way.
- Place certificate and key files on a local disk. A stalled stat on a network filesystem blocks `tlsSource`'s mutex, which blocks all handshakes.
- In mini-CA mode, the server certificate is reissued when `renewal.RenewAt` says it is due. A failed attempt waits at least 1 minute (`reissueRetry`) before retrying. Consecutive failures log only one WARN `server TLS certificate not reissued`.

## Per-certificate issuance locking (SRV-3)

- At most one issuance per certificate at a time: a periodic tick skips a certificate whose issuance is already in flight; `certfolds cert renew` waits for the in-flight issuance to finish, then forces a new one.
- Global concurrency cap: `maxConcurrentIssuance` (4).

## Issuance validation (SRV-4)

- Before storing the result, under a generation read lock, re-fetch the spec by name from the running config, recompute its fingerprint, and compare with the fingerprint captured before ordering. Discard the result on mismatch or if the certificate was deleted (WARN `issued certificate discarded`), and wake the scheduler immediately.
- The generation read lock permits only `current()`, fingerprint computation, and millisecond-scale DB writes. `/v1/sync` wake notifications and all network calls must happen outside the lock.
- Leaf public key must equal the order private key; leaf DNSNames must cover every domain in the spec. Mismatches are issuance failures.

## Generation lock discipline (SRV-5)

- Failures from an old generation or from ctx cancellation do not count toward backoff.
- Reload does not wait for in-flight issuances: under a generation write lock, it zeros all certificates' persisted backoff (keeping `LastError`), atomically publishes the new config, releases the lock, then wakes the scheduler.

## Issuance backoff (SRV-6)

- Per-certificate backoff: 5 minutes initial, doubles, caps at 24 hours. Stored with the last error in the `issuance_status` table; survives restarts.
- The scheduler timer wakes at the earliest `NextAttemptAt`.
- After recording a failure and its backoff, wake the scheduler to recompute the timer. If writing the backoff to the DB fails, do not wake (to avoid an immediate retry).
- Because backoff is persisted, a config change plus restart does not clear it. Use `certfolds reload` or `certfolds cert renew` after fixing the cause.

## Issuance transaction (SRV-7)

- Pass a cancellable ctx to `Issue`; use `WithoutCancel` only for the final DB write.
- `save` uses `BeginTx`. Both `Upsert` calls receive the tx, then `Commit`. No other call may happen inside the transaction (`SetMaxOpenConns(1)` means a call with `tx == nil` would deadlock).

## Renewal timing (SRV-8)

- With a valid ARI window: pick a uniformly random point inside the window (source `ari`); the point is stable while the window is unchanged.
- Without ARI: ratio rule via `renewal.RenewAt` -- renew at 1/3 remaining lifetime, or 1/2 for lifetimes under 10 days (source `ratio`).
- A renewal point in the past triggers immediate renewal.
- `renew_days_before` has been removed.

## ARI state (SRV-9)

- ARI state is in-memory only; on restart every certificate is re-queried and `pick` re-randomized.
- Query criteria: material matches spec, not expired, not currently issuing, `nextCheck` has arrived. Newly stored certificates have `nextCheck` zero (query immediately).
- A single goroutine queries certificates sequentially, holding no locks (`genMu`, `ariMu`, certificate locks are all released). It is not counted in `wg` (shutdown does not wait for it). No new queries start after ctx ends.
- Retry-After is clamped to [1 min, 24 h]; default (CA did not send one) is 6 h. Timeout: re-query after 1 h. Other errors (including 5xx -- lego cannot expose the HTTP status code): re-query after 6 h, keep the existing window. `ErrNoRenewalInfo` (directory lacks `renewalInfo` or certificate lacks AKI): re-query after 24 h and fall back to ratio.
- lego does not check the `renewalInfo` response status code. Window validation is done by `acme.RenewalInfo`: `End > Start` and `Start < NotAfter`.
- Reload makes all certificates re-query ARI immediately. The scheduler is woken after a query round finishes.
- `ariMu` is a leaf lock; `RenewalPlan` acquires only `ariMu`.

## Due-on-arrival ARI guard (SRV-10)

- When a fingerprint's first-seen window has `End <= now`: treat as a failure (`errWindowPassed`), set `pick` to the backoff-end time. Applies only to certificates issued by this process (`IssuedAt >= started`).
- `ariTrips` (in-memory, per certificate name) doubles the backoff. Cleared when the window's `End` is after `now`, or when a certificate is stored with source `ratio`, `manual`, or `new`. Reset on restart.
- The guard writes to the DB via `storeGuard`: under a `genMu` read lock, opens a transaction, compares the DB certificate fingerprint, and writes `issuance_status` only if the certificate has not been replaced (see S20).
- Reload clears the DB backoff, but if the window is unchanged the in-memory `pick` still blocks renewal. Use `certfolds cert renew` for immediate renewal.

## Due-on-arrival at storage time (SRV-11)

- When `renewal.RenewAt(result.Certificate)` errors or returns `<= now`: the certificate is stored normally, then in the same transaction a failure status is written (`failures = prev+1`, doubled backoff). Error message: `issued certificate was stored, but is already due for renewal (lifetime ..., renewal due ...)`.
- `certfolds cert renew` returns a nonzero exit code (IPC 422) in this case, but the certificate has been delivered.

## wakeAt computation (SRV-12)

- Take the earliest future time among: backoff `NextAttemptAt` values, each certificate's `RenewalPlan` point, `nextCheck` of certificates due for ARI query. Compare with an hourly jittered wake and take the earlier.
- Explicit wake points: ARI query goroutine finishes, issuance stored successfully, reload completes, failure recorded with backoff.

## ACME accounts (SRV-13)

- Initialization is locked per CA name (the account record's primary key). The lock is held from fetching-or-creating the key through registration; released before ordering.
- On a DB read error, return the error as-is; do not create a new key or overwrite the record. Re-register with the same key only when the stored registration JSON is corrupt.
- When `acme.email` changes, call `UpdateRegistration` to update contacts; do not replace the key. Replace the key only when the directory changes. The key is persisted only after successful registration.
- Registration and `UpdateRegistration` persist via `WithoutCancel`, so shutdown or Ctrl-C does not lose a new key.

## cert list / cert show (SRV-14)

- `GET /ipc/v1/certs` lists certificates in running-config order.
- Material fields (such as `not_after`, `fingerprint`, `renew_at`, `renew_source`) are populated only when the DB record's spec fingerprint matches the current config.
- Certificates deleted from the config are not listed, even if DB records remain.
- State priority: `issuing` > `backoff` > `valid` > `pending`.

## token create (SRV-15)

- Runs via server IPC on the running daemon; errors if the daemon is not running. The CLI never writes the database itself.
- The CLI rejects answers from old daemons that lack `token_id`.
- Refuse to issue when `public_url` is empty and `listen`'s host is empty, `0.0.0.0`, or `::`. Prompt the user to set `server.public_url`.
- If the name is already enrolled or has an unused unexpired token, require `--replace` (IPC 409). `--replace` revokes all unused tokens with that name first.
- `--json` fields: `token`, `token_id`, `expires_at`, `revoked` (omitted when 0), `install_sh`, `install_ps1`. Human-readable output adds `Token ID:` and `Expires:` lines. `token list --json`: unused tokens omit `used_at` (`omitzero`).
- Lifetime cap: 168 hours, enforced by the daemon.

## cert add / cert remove (SRV-16)

- Run via server IPC; the daemon modifies `server.yaml` and applies the change immediately (reload semantics). Error if the daemon is not running.
- On apply failure, restore `server.yaml` to its original bytes. Reject, leaving the file untouched, if it already contains hand edits that need a restart.
- IPC status codes: `cert add` success 201, parse failure 400, other failures (duplicate name, validation, restart-required changes, apply failure) 422. `cert remove` success 200, name not found 404, other failures 422.
- Writing back `server.yaml`: Unix preserves mode and owner, writes through symlinks. Windows does not preserve ownership; the file gets a private DACL. Blank-line loss is accepted (yaml.v3 limitation).

## delete nonexistent objects (SRV-17)

- Deleting a nonexistent client returns 404, body `client "x" is not enrolled`.
- Deleting a nonexistent token returns 404, body `enrollment token "x" does not exist`.
- CLI exit code: 1.

## Shutdown bound (SRV-18)

- 30 seconds from cancellation (`issuanceStopTimeout`): after that, scheduler-initiated in-flight issuances are abandoned: the certificates they would have stored are lost and their DNS TXT records are not cleaned up. WARN `certificate issuance abandoned at shutdown certs=...` names the affected certificates.
- Manual renewals via `cert renew` (IPC-initiated) are not covered by this timeout. HTTPS and IPC share a 10-second drain (`shutdownTimeout`).

## Event ring -- `logging.Ring` (SRV-19)

- Capacity: 500 entries.
- `Started` records when the Ring was created. Callers (e.g. TUI) that see `Started` change must clear their state and re-fetch with `after=0`.
- Control characters in `Message` are replaced. `Attrs` are truncated to 2 KiB, `Message` to 1 KiB. `Private` attributes render as `(withheld)` in the Ring and Windows event log; stderr / journald sinks preserve the full text.
- lego log lines enter the ring (INFO / WARN determined by prefix, with `component=lego`).
- Public HTTPS `http.Server.ErrorLog` (handshake errors, etc.) goes to the service log only, rate-limited to `maxErrorLinesPerMinute` (10). Excess lines are counted; the next admitted line reports how many were dropped. IPC ErrorLog is not rate-limited.

## mini-CA (SRV-20)

- Refuses to start when only half of its files exist; the error names both paths.
- Logs WARN `mini-CA root certificate expires within a year` at startup and on each server certificate reissuance when the root has less than a year of validity.

## SQLite (SRV-21)

- The database and WAL contain private key material; creation and reopening must maintain private permissions.
- Schema migrations are forward-only: an upgraded database cannot be opened by an older `certfolds` (current schema: v5). When the schema version is newer than the binary, refuse to open and report both versions.
- `store.Open` accepts a path (optionally with `?` parameters) or `:memory:`.
