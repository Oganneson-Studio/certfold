# Platform constraints

Read this doc before writing platform-specific code or modifying the E2E harness.

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## General (PLT-1)

- Platform differences use build-tag files, e.g. `_windows.go`, `_unix.go`, `_other.go`.
- `os.Chmod(0600)` on Windows does not enforce access control; use DACLs.
- TLS trust model: see [API-8](api.md).

## Windows daemon (PLT-2)

- Must run as LocalSystem or an elevated administrator.
- IPC clients trust only named pipes owned by SYSTEM or Administrators; ownership is checked before sending any request. An elevated `Listen` sets the owner to Administrators explicitly. Without this, the owner defaults to the token's default owner, which under Git Bash becomes the user SID.
- When the pipe name is already held by another process, the daemon fails to start. If the owner can be read, the error includes the owner SID; otherwise: `another process holds the pipe name, and its owner cannot be read`.

## PowerShell 5.1 quirks (PLT-3)

- `ServerCertificateValidationCallback = {$true}` (scriptblock callback) does not work; use C# `ICertificatePolicy`.
- Downloads must use `-UseBasicParsing`; without it, Server Core (no IE engine) fails.
- `exit` inside `& ([scriptblock]::Create(...))` closes the caller's session.
- When `SecurityProtocol` is `SystemDefault`, `-bor 3072` leaves only TLS 1.2. The install-command prefix and the server's TLS floor must be decided together.

## East-Asian conhost glyphs (PLT-4)

- Classic conhost with an East-Asian system locale draws `·`, `…`, `↑`, `↓`, `●`, `—`, `×` and similar characters two cells wide. lipgloss counts them as one. Charm v2's renderer truncates overwide lines instead of wrapping.
- The TUI must use only characters allowed by `shared.WideGlyph`: `─`, `│`, `╭`, `╮`, `╰`, `╯`, `•`, `›` (verified one-cell-wide on cp936 NSimSun, 2026-10-01). Data that contains wide characters will still misalign.

## WSLC mount limits (PLT-5)

- WSLC 2.9.4: at most 15 distinct host paths per session (verified 2026-09-27). Counted by distinct paths seen during the session lifetime, independent of container count; remounting the same path does not use another slot.
- 3 slots are used by WSL's virtiofs shares, leaving 12. `wslc build`'s build-context directory uses one slot.
- E2E mounts a fixed directory (`%TEMP%\certfold-wslc-e2e`) to `/e2e` and puts per-run files in `run-*` subdirectories, cleaning only the subdirectory at the end. This uses 2 slots across any number of runs: the mount root and the build context.
- New mounts or image builds must use a host path that is stable across runs.
- At capacity: `装入的卷太多 (限制： 15)`. After confirming no containers or networks remain, reset an idle session with `wslc system session terminate`.
- Each worktree root used as a build context is a distinct path and uses its own slot within the same session.
- Several E2E runs can share one WSLC session concurrently (resource names are distinct); when checking for leftovers, look only at the current run's resource names.

## WSLC networking and builds (PLT-6)

- Within a network, aliases resolve in all containers; both UDP and TCP DNS work between containers (verified 2026-09-27, WSLC 2.9.4).
- To obtain a container IP: inspect `NetworkSettings.Networks.<network>.IPAddress` from `wslc inspect <container>`.
- `wslc build` uses BuildKit: pulled base images exist only in BuildKit storage (`wslc images` does not list them); build cache survives `rmi`; there is no `builder prune`.
- Build-context size does not affect build time. The cost is `COPY . .` cache invalidation: any file change in the context means ~12--15 s of recompilation for each binary.

## WSLC bind mounts (PLT-7)

- Files inside a mount always report mode 0777; chmod is silently ignored. E2E puts client outputs and `certfolds` data_dir on the container's own filesystem for this reason.
- If the host process has a file open (Go's `os.Open`/`ReadFile` does not set `FILE_SHARE_DELETE`), renaming over that file inside the container fails with Permission denied. Do not hold a host file handle when the container may replace the file.
- Host writes to a mounted file are immediately visible inside the container (verified for grow, shrink, and same-length writes). E2E uses this to modify `server.yaml` while containers are running.

## E2E Docker on Linux (PLT-8)

- Under rootful Docker, `certfolds` and `certfoldc` containers run with `--user <uid>:<gid>`.
- `certfolds` image sets `/var/run/certfold` and `/var/lib/certfolds` to 1777; data_dir is `/var/lib/certfolds/data`. `certfoldc` image sets `/var/run/certfold` and `/cert-output` to 1777.
- WSLC does not need `--user`: files written into mounts are owned by the Windows user.
- Rootless Docker has not been verified.

## E2E harness (PLT-9)

- No Compose or fixed IPs. Builds temporary images, creates randomly named networks, connects via network aliases. Uses Pebble + challtestsrv + exec DNS hook to issue real certificates. Exercises enrollment, fetch, renew, revoke, token, sync delivery latency, output reconciliation and auto-recovery, on_change and reload waking, ARI window tracking and ARI-driven renewal. Cleans up by exact resource name.
- The auto-recovery step takes a fixed ~55 s.
- Build and run commands and timings are in [AGENTS.md](../../AGENTS.md) (Build and verification).

## Pebble ARI (PLT-10)

- Pebble v2.10.1 publishes `renewalInfo`. Default window: `NotAfter - lifetime/3` plus/minus 24 h. `Retry-After` is fixed at 6 h. Revoked certificates return a window in the past.
- Management port: `POST /set-renewal-info/` overrides the response by serial.
- A new order with `replaces` logs `ARI: order ... is a replacement of ...`; E2E asserts on this.

## Git for Windows curl (PLT-11)

- Git for Windows' curl (Schannel backend) reports `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` when validating a private root. Add `--ssl-no-revoke`. Go-based tools are unaffected.

## Container runtime (PLT-12)

- Do not run or depend on Docker Desktop. Use `wslc` directly for container-based verification.

## Cloud DNS E2E (PLT-13)

- `test/e2e/cloud_test.go`, tag `e2e_cloud`, own `TestMain`. Shared helpers live in `runtime_test.go` (tag `e2e || e2e_cloud`). Passing both tags at once does not compile (two `TestMain`s).
- One `certfolds` container, no Pebble and no `certfoldc`. CA: Let's Encrypt staging. `LEGO_CA_CERTIFICATES` must stay unset: when it is set, lego trusts only those roots. `acme.email` must not be at `example.com`; Let's Encrypt refuses it.
- Each provider is a `cloudProvider`: its keys, the environment variables holding them, its zones, and a function listing the run's leftover TXT records (Cloudflare API; the Alibaba Cloud and DNSPod SDK modules lego already pulls in). Credentials reach the container as `-e NAME` (name only, value from the test's environment) and `server.yaml` reads them through `${...}`, so they are in no file and on no command line. `cloudflare` is required; `aliyun` and `tencentcloud` are skipped when none of their variables is set and fail the run when only some are.
- Cases: `cross-zone`, one certificate with names in both Cloudflare zones (zone lookup per name); `wildcard`, a base name plus its wildcard (two TXT values at one record name); `aliyun` and `tencentcloud`, a base name plus its wildcard each under its subzone. Each run uses a random `e2e-<hex>` label so runs never share a challenge record. Afterwards the test lists the run's TXT records and fails if any is left. It deletes nothing.
- Subzones: `ali.certfold.org` is hosted at Alibaba Cloud DNS (`ns1/ns2.alidns.com`) and `tc.certfold.org` at DNSPod (`f1g1ns1/f1g1ns2.dnspod.net`), both on free plans, delegated by NS records in the `certfold.org` Cloudflare zone. Adding a subdomain zone at either provider first requires an ownership TXT at the parent (`alidnscheck.certfold.org` / `_dnspodcheck.certfold.org`, removed after); a new DNSPod zone starts paused and answers NXDOMAIN until enabled.
- Each certificate takes ~20--40 s; the 3-minute deadline only bounds a broken run. A certificate still issuing at the deadline leaves its TXT records (cleanup stops the server before lego removes them); the leftover check lists them for deletion by hand.
- An interrupted run (`-timeout` panic, Ctrl-C) skips cleanup and leaves the container running with the credentials in its environment, still retrying issuance against the real zones. Remove `certfold-e2e-cloud-*` containers and images by hand.
- A host proxy that intercepts DNS from WSLC containers (TUN mode or DNS hijacking), including queries sent straight to authoritative servers, makes the propagation check flaky: it can serve a stale NXDOMAIN for minutes after the record exists. Runs then time out at the deadline. Exclude WSL from the interception or run on Linux.
- gcloud and route53 have no case: their zones cost money monthly. Both were verified once on 2026-10-03 the same way (a zone `gc.`/`r53.certfold.org` delegated from Cloudflare, real issuance of a base name plus its wildcard, no leftovers, then zone and delegation deleted); route53 took ~2.5 min because lego waits for each change to become INSYNC. The same round checked the key mapping of all four: a name the account does not host fails at zone lookup, swapped keys fail authentication.
- In a WSLC container, lego's default resolver is WSL's DNS tunnel `10.255.255.254:53`. lego logs "Checking DNS record propagation" whether or not the check is skipped, so the logs cannot show that the check ran.
- There is no skip case. With Cloudflare, `skip_propagation_check: true` lost the race in one of two runs: Let's Encrypt validated ~4 s after the record was created and found no TXT record. The skip wiring stays guarded by the `e2e` suite, whose DNS server cannot answer the check.
