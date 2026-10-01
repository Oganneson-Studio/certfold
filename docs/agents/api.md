# API component contracts

Read this doc before changing paths under `internal/api/**` or `internal/enroll/**`.

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## `/v1/sync` endpoint (API-1)

- Without `If-None-Match`: return the client's certificate view immediately.
- With `If-None-Match` matching the current ETag: hold the request for up to `proto.SyncMaxWait` (55 s), then return 304.
- Per-client concurrency cap: `maxSyncsPerClient` (4). The 5th concurrent sync returns 429 `too many sync requests in progress`.
- `If-None-Match` is compared as one exact string. Weak ETags, `*`, and comma-separated lists (including multi-line) never match.
- The ETag is computed from the client-filtered view only. Private keys are served only through the bundle endpoint.

## `/v1/sync` wake and ordering (API-2)

- Certificate storage (the scheduler's `stored` callback) and a successful reload wake all pending sync requests.
- The handler must capture the wake channel *before* reading the config and DB. The config side has a deterministic test; the DB side relies on review. The `stored` callback wiring is guarded only by the E2E renew-delivery step.
- The handler must use `ResponseController.SetWriteDeadline` to extend past the 30-second `WriteTimeout`, or HTTP/1.1 responses are truncated and HTTP/2 streams are reset.
- On daemon shutdown, pending sync requests return 304 immediately.

## Auth middleware and `last_seen` throttling (API-3)

- In-memory throttle: one `seenClaim` per client name (stores certificate fingerprint and last write time). At most one conditional UPDATE per minute per client; the throttle condition must not be encoded in SQL.
- When the presented certificate fingerprint differs from the stored claim, write immediately and replace the record. The claim map grows to at most the number of client names that have authenticated during this process's lifetime (client deletion does not clear entries). During the brief period when pending and active identities alternate, each identity switch triggers an extra write.
- UPDATE affecting 0 rows: respond 401. Other DB write errors: log only, allow the request (the server must distribute existing certificates even when the DB is read-only). The throttle slot is never released regardless of the DB outcome.
- Concurrent first use of the same pending identity: after a failed promotion, re-read; if the active fingerprint already equals the presented one, allow.

## Identity renewal (API-4)

- Client mTLS identity must auto-renew before expiry. `client.identity_renew_before` defaults to 30 days, allowed range 1 hour to 89 days.
- `/v1/identity/renew` is rate-limited to once per client per minute. Exceeding returns 429 `identity renewed less than a minute ago`. The slot is never released regardless of success or failure.

## Enrollment (API-5)

- Enrollment binding, redirect refusal, CSR 400, `ErrUnusableAnswer`, NotBefore validation: see S2.

## Download endpoint (API-6)

- Character whitelist and directory containment: see S6.
- An unauthenticated slow reader occupies one connection for at most 10 min (`downloadWriteTimeout`).

## Error responses (API-7)

- Auth DB read errors return 500 (not 401). All 500s are logged as ERROR events: `look up client failed`, `promote client identity failed`, `read certificate failed`, `read certificate view failed`, `encode certificate view failed`, `client identity renewal failed`, `enrollment failed`, `open certfoldc binary failed`, `panic serving request`.
- Enrollment refusal: used or expired tokens return 401 with the reason, logged as WARN `enrollment refused client=... token=<ID> error=...`. Wrong secret returns 401 `invalid token` without an event.

## TLS trust (API-8)

- The server's external HTTPS endpoint can use a public certificate, but client certificates are always verified by the internal mini-CA. The client trusts both system roots and the mini-CA.
