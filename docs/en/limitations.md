English | [简体中文](../zh-CN/limitations.md)

[Back to README](../../README.md)

# Current limitations

- With `--token` / `-Token`, the token appears in the process command line; see [One-line installation](installation.md#one-line-installation) for how to avoid this.
- The container E2E issues certificates through the `exec` DNS provider. A separate E2E suite issues real certificates from Let's Encrypt staging through `cloudflare`, `aliyun`, and `tencentcloud`; `gcloud` and `route53` were verified once with real issuance but have no recurring E2E.
- Reconciliation does not compare Windows ACLs; see [Private key outputs on Windows](security.md#private-key-outputs-on-windows).
- Output path deduplication compares paths after `filepath.Clean` (case-insensitively on Windows). It does not detect duplicates through symbolic or hard links; paths differing only in case on macOS APFS; or, on Windows, `\\?\` and `\\.\` prefixes, 8.3 short names, trailing dots and spaces, and mapped drive letters versus UNC paths.
- Certificates whose lifetime does not exceed about twice the CA's NotBefore backdate (about 2 hours for Let's Encrypt, which backdates by 1 hour) are not supported: they arrive already past their renewal point and are caught by the arrival guard, which backs off instead of retrying immediately.
- The mini-CA root certificate expires after 10 years and has no rotation mechanism. When it has less than a year remaining, the server logs a warning at startup and on each server-certificate reissue.
- ARI does not do short-interval exponential backoff for 5xx responses (lego does not expose the HTTP status code); it retries after 6 hours.
- The random renewal moment within an ARI window is not persisted; a restart picks a new moment within the same window.
- A reload rejection caused by a YAML type error may include up to about 10 characters of the configuration value in the event and service log.
- The macOS service (launchd LaunchDaemon), the macOS install paths, and the restart behavior on Linux distributions that do not use systemd have not been tested on real machines.
