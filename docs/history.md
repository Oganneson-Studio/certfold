# Project history

This document records major design decisions, the pre-deploy audit, and the
Sigil-to-Certfold rename. It is not loaded into agent sessions automatically;
read it only when you need the background behind a current rule.

---

## Refactoring decisions (decided 2026-09-27)

These decisions were made during a review of the original architecture
(defect IDs A1--A13 from an unpublished review, decision IDs B1--B4, C1).
All have been implemented.

- **B1** (Phase 3): Replace server push with client long-polling (`/v1/sync`).
- **B2** (Phase 2): Replace the global issuance lock with per-certificate locks and a bounded concurrency pool.
- **B3** (Phase 4): Make the PowerShell install script static. The server no longer writes request parameters into the script. Install command: `[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm '<url>/install.ps1'))) -Token '<token>'`. `-bor 3072` makes PowerShell 5.1 negotiate TLS 1.2; the server floor is TLS 1.2. Security invariant S7 was retired as a result.
- **B4** (Phase 3): Remove `/v1/heartbeat`. `last_seen` is now refreshed by the mTLS auth middleware.
- **C1** (Phase 3): Per-certificate `on_change` hooks on the client.
- **C2** (Phase 4): Ratio-based renewal timing with ARI (RFC 9773). `renew_days_before` was removed.
- **D1--D8** (Phase 4, newly discovered defects): D1 HTTPS certificate hot reload. D2 Server TLS floor lowered to 1.2. D3 404 for deleting nonexistent objects. D4 install.ps1 fixes. D5 slog takes over all logging. D6 Due-on-arrival guard (short-lived certificates are not supported; see known-gaps.md). D7 Refuse token issuance when `public_url` is missing. D8 `token list` column-width fix. All fixed.
- **Retained unchanged**: mTLS + DB fingerprint auth, one-time token binding, `subscribers` as the sole authorization source, client-side output config, spec fingerprint binding, `securefile`, strict YAML.

## Pre-deploy audit (started 2026-09-29)

Audit lanes: S, A, C, D, L, P, W, I, Z (fixes), T (TUI migration to Charm v2). All lanes completed. Final verification (two E2E suites, full unit tests and race on two platforms, Linux systemd and Windows service installs, three rounds of one-click install) passed. Issues found during verification (last_seen throttle, redundant reload prompt, Windows reinstall losing service environment variables, service key readable by local users) were fixed before closing.

### Decided during the audit

Project decisions:
- Tokens are passed via environment variables and interactive input, no longer only as command-line arguments.
- Token length stays as-is.
- Install scripts are idempotent (reinstall when already installed; `--upgrade` flag).
- Same-name tokens require explicit `--replace`.

Architecture decisions:
- `cert add`/`cert remove` go through IPC.
- Windows `owner` adds a read-only ACE; it does not change the file owner.
- Shutdown bound: 30 s (`issuanceStopTimeout`).
- WARN when mini-CA root certificate has less than 1 year of validity.
- `acme.email` change updates the contact only (no key replacement).
- Issuance result validation checks leaf public key and DNSNames.
- Some behaviors on non-systemd Linux and macOS are marked as unverified.

## Rename from Sigil to Certfold (2026-10-01)

Reason: all domain names related to the original name (Sigil) were already registered.

Scope of the rename:
- Module path: `github.com/Oganneson-Studio/certfold`.
- Binaries: `sigils` became `certfolds`, `sigilc` became `certfoldc`.
- File paths, service names, named pipes, environment variables all changed.
- New and old installations are fully incompatible in paths, service names, and environment variables. No migration path exists because the project had not been deployed.
