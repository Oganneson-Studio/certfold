# Known gaps and limitations

This file lists known limitations, simplifications, and unresolved issues.
Items stay here until fixed; remove an item in the change that fixes it.

---

## Known limitations (GAP-1 through GAP-14)

**GAP-1** Output-path deduplication compares only `filepath.Clean` text (lowercased on Windows). Cases it cannot detect: symlinks and hard links (both platforms); macOS APFS case-insensitivity (dedup lowercases only on Windows); Windows `\\?\C:\`, `\\.\C:\`, 8.3 short names, trailing dots/spaces, mapped drive letters vs. UNC paths.

**GAP-2** The mini-CA root certificate expires after 10 years. There is no rotation mechanism. When less than 1 year of validity remains, WARN `mini-CA root certificate expires within a year` is logged.

**GAP-3** Non-systemd Linux restart semantics differ (not verified).

**GAP-4** modernc SQLite: after ctx cancellation, the connection becomes `IsValid()=false`. `PRAGMA foreign_keys=ON` set via `Exec` in `store.Open` is per-connection and lost when the connection changes. The schema currently has no foreign keys. Any future per-connection pragma must go into the DSN.

**GAP-5** Token exposure in process lists: `sh -s -- --token` places the token on sh's command line; `-Token '...'` enters PowerShell history. Windows automation can only use `-Token`. Interactive input (omitting `--token`/`-Token`) does not expose the token. macOS Terminal has a single-line input limit of 1024 characters (tokens are ~1.05K).

**GAP-6** While `certfolds` is serving a download, replacing files under `data_dir/binaries` fails (Go's `os.Open` does not set `FILE_SHARE_DELETE`). Wait for the download to finish or stop the service.

**GAP-7** Process-tree termination limitations: processes that have called setsid, or that were started by a task scheduler or service manager, escape the process-tree kill. On non-systemd Unix and macOS (launchd cleans by process group; `Setpgid` makes hooks leave that group), exec programs may linger after abandoned issuance (not verified). Windows containers (server silo) not verified. Windows runs ~100 ms slower per invocation (thread snapshot). `.bat` files: on timeout, cmd.exe and its children are killed together.

**GAP-8** A holder of a consumed full token can repeatedly POST enrollment, flooding WARN events (same concern as lego INFO lines crowding the 500-entry event ring).

**GAP-9** If `client.yaml` has unknown fields, reinstall consumes the token first; the error surfaces only when the service starts. Fix the config and restart.

**GAP-10** Windows: during a service crash loop, SCM may restart the service between stop and uninstall.

**GAP-11** Windows: if `[IO.File]::Replace` fails after Stop-Service (e.g. antivirus holds the file), the service stays stopped. Re-run the install. If `certfoldc.exe` is held by another process (e.g. `certfoldc tui`), Replace leaves `certfoldc.exe~RF*.TMP`. If the service PID is reused after stop, the installer waits 30 s then errors.

**GAP-12** When `service install` fails to tighten the service key, install.ps1's closing prompt tells the operator to re-run `service install` (which would fail because the service already exists). The correct action is to follow the `Set-Acl` command printed by `certfoldc`, then write back `Environment` and start. In practice this almost never happens (the administrator has full control over a key SCM just created).

**GAP-13** Windows: the first `cert add` or `cert remove` changes `server.yaml` to a private DACL (SYSTEM, Administrators). Any access previously granted to other accounts is removed.

**GAP-14** Reconciliation does not compare Windows private-key file DACLs. If a DACL is relaxed or inherited, it is restored only when content changes (renewal). Removing `owner`/`group` from config: Unix leaves the old uid/gid, Windows leaves the old owner's read ACE until content changes. To fix immediately: delete the output file; the next reconcile recreates it.

## ARI simplifications (GAP-15 through GAP-18)

**GAP-15** ARI does not perform short-interval exponential backoff on 5xx. Re-queries after 6 h (lego cannot expose the HTTP status code).

**GAP-16** ARI `pick` is not persisted. On restart, the renewal point is re-randomized within the same window.

**GAP-17** The due-on-arrival guard covers only a window that has entirely passed. A window that straddles `now` still triggers immediate renewal.

**GAP-18** Certificates with a lifetime shorter than roughly twice the CA's NotBefore backdating (Let's Encrypt backdates 1 h, so ~2 h) are not supported: they are already past the renewal point on arrival and trigger the due-on-arrival backoff.

## Display and event limitations (GAP-19 through GAP-24)

**GAP-19** In an 80x24 terminal, long Last Error text in the Certificates detail view is truncated. Use `certfolds cert show` for the full text.

**GAP-20** lego INFO lines enter the 500-entry event ring: bulk renewal can push out Certfold's own events.

**GAP-21** When reload is rejected, yaml.v3 type errors leak up to ~10 characters of the config value (e.g. credentials put in a numeric field). This appears in the service log and events.

**GAP-22** TUI `(ari)` display is covered only by unit tests; E2E covers it only at the `cert list --json` `renew_source` level.

**GAP-23** Enrollment tokens embed the full mini-CA certificate (~1.05K characters). They cannot be fully copied from the TUI. A future change could replace the embedded certificate with a CA fingerprint.

**GAP-24** When a view or bundle exceeds the 1 MiB `maxResponseBytes` limit, the error surfaces as a JSON decode error with no indication of the size limit.

## Upgrade path (GAP-25)

**GAP-25** Certfold has never been released, so it has no upgrade path. Sigil-era installs are incompatible; uninstall and reinstall. When a future change breaks compatibility, record the upgrade notes in the user docs (`docs/en/`) and here.

## E2E coverage gaps (GAP-26)

**GAP-26** Cloud DNS providers have no E2E coverage. `skip_propagation_check` wiring is guarded only by the E2E "issuance succeeds" step. `acme.dns_resolvers` effectiveness is guarded only by `TestIssuanceUsesDNSResolvers`. Changes to either must include an E2E run.
