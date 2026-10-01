English | [简体中文](../zh-CN/development.md)

[Back to README](../../README.md)

# Build and test

```bash
go build ./cmd/certfolds
go build ./cmd/certfoldc
go test ./... -count=1
go vet ./...
```

On Windows, the end-to-end suite uses WSLC directly and does not require Docker Desktop or Compose:

```powershell
go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

The `-count=1` flag is required. The test builds temporary OCI images through `wslc build`, and Go's test cache cannot see those reads; without the flag a second run reports `(cached)` even when the code changed.

The test builds temporary OCI images, creates an isolated WSLC network, and issues real certificates from a Pebble ACME server through the `exec` DNS hook and a challenge test DNS server. It verifies enrollment, certificate fetch, delivery of a renewed certificate over the long poll, restoring deleted and modified outputs, `on_change` runs, reload wake-ups, client revocation, token expiry/revocation, ARI renewal-window tracking and ARI-directed renewal with `replaces`, HTTPS certificate hot-reload, static install.ps1, deletion of non-existent objects returning 404, and renewal events, then removes its containers, network, and images.

Linux CI can run the same orchestration with Docker Engine. Set `CERTFOLD_CONTAINER_CLI=docker` and `CERTFOLD_E2E_REQUIRED=1` (without the latter, a missing container runtime silently exits 0). Run as a regular user in the `docker` group, without `sudo`; cleanup does not need `sudo` either.
