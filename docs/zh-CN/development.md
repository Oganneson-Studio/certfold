[English](../en/development.md) | 简体中文

[返回 README](../../README.zh-CN.md)

# 构建与测试

```bash
go build ./cmd/certfolds
go build ./cmd/certfoldc
go test ./... -count=1
go vet ./...
```

在 Windows 上，端到端测试直接使用 WSLC，不需要 Docker Desktop 或 Compose：

```powershell
go test -v -tags e2e -count=1 -timeout 10m ./test/e2e
```

`-count=1` 是必需的。测试通过 `wslc build` 构建临时 OCI 镜像，Go 的测试缓存无法感知这些读取；不加此标志时，代码改动后第二次运行仍会报告 `(cached)`。

测试构建临时 OCI 镜像，创建隔离的 WSLC 网络，并通过 `exec` DNS 钩子和验证测试 DNS 服务器从 Pebble ACME 服务器真实签发证书。测试覆盖注册、证书拉取、通过长轮询交付续期后的证书、恢复被删除和被修改的输出、`on_change` 运行、热重载唤醒、客户端吊销、令牌过期和吊销、ARI 续期窗口跟踪和带 `replaces` 的 ARI 驱动续期、HTTPS 证书热更新、静态 install.ps1、删除不存在对象返回 404 以及续期事件，测试结束后清理容器、网络和镜像。

Linux CI 可以使用 Docker Engine 运行相同的编排。设置 `CERTFOLD_CONTAINER_CLI=docker` 和 `CERTFOLD_E2E_REQUIRED=1`（不设后者时，在找不到容器运行时的情况下会静默以 0 退出）。以 `docker` 组中的普通用户身份运行，不要加 `sudo`；清理同样不需要 `sudo`。

另有一套需要手动启用的云端测试，不在 CI 中运行（CI 只对 `e2e_cloud` 标签做 vet）；令牌从文件读取，以免留在 shell 历史中：

```bash
export CERTFOLD_E2E_CLOUDFLARE_TOKEN="$(tr -d '\r\n' < <token-file>)"
go test -v -tags e2e_cloud -count=1 -timeout 15m ./test/e2e
```

```powershell
$env:CERTFOLD_E2E_CLOUDFLARE_TOKEN = (Get-Content -Raw <token-file>).Trim()
go test -v -tags e2e_cloud -count=1 -timeout 15m ./test/e2e
```

它通过 `cloudflare` 提供商，为项目自有区域 `certfold.com` 和 `certfold.org` 下的随机名称从 Let's Encrypt staging 环境真实签发证书，因此需要一个对这两个区域具有 DNS:Edit 和 Zone:Read 权限的 Cloudflare API 令牌；实际上只有维护者能运行。未提供令牌时，测试会失败而不是跳过。容器运行时的设置与 `e2e` 测试相同：Windows 上使用 WSLC，Linux 上设置 `CERTFOLD_CONTAINER_CLI=docker`。
