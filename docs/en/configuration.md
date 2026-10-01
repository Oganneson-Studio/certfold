English | [简体中文](../zh-CN/configuration.md)

[Back to README](../../README.md)

# Configuration

## Server configuration

`server.yaml` has four top-level sections: `server`, `acme`, `dns_providers`, and `certificates`. All fields accept `${VAR}` references (see [Environment variables in configuration](#environment-variables-in-configuration)). All path fields must be absolute (see [Client configuration](#client-configuration) for details). Certificate names, `acme.cas` keys, and `dns_providers` keys follow the [naming rules](#naming-rules).

### server

| Field | Required | Default | Hot-reloadable | Description |
|---|---|---|---|---|
| `listen` | no | `:8443` | no (restart) | Listen address in `host:port` format. The port must be 1 to 65535; the host may be empty. |
| `data_dir` | yes | | no (restart) | Absolute path to the data directory. |
| `public_url` | no | derived from `listen` | no (restart) | Externally reachable `https` URL that enrollment tokens and install scripts give to clients; the internal mini-CA server certificate also covers its host. Without it, the URL is derived from `listen`, and `token create` refuses to run when `listen` names no host clients can reach (an empty host, `0.0.0.0` or `::`). See [Production TLS](installation.md#production-tls) for restrictions on its value. |
| `tls_cert_file` | no | | no (restart) | Path to the TLS certificate chain file. Must be set together with `tls_key_file`. File content is reloaded automatically on each handshake; see [Production TLS](installation.md#production-tls). |
| `tls_key_file` | no | | no (restart) | Path to the TLS private key file. Must be set together with `tls_cert_file`. |
| `ipc_socket` | no | platform default | no (restart) | Override the default IPC endpoint (Unix socket path or Windows named pipe). |

### acme

| Field | Required | Default | Hot-reloadable | Description |
|---|---|---|---|---|
| `email` | yes | | yes | Contact email for the ACME account. Must contain `@`. Changing the email updates the contact on the CA without replacing the account key. |
| `default_ca` | yes | | yes | CA that `certfolds cert add` uses when `--ca` is not given. Must name a key of `cas`. Entries under `certificates` in `server.yaml` must still set `ca`. |
| `cas` | yes (at least one) | | yes | Map of CA definitions, keyed by name. |
| `cas.<name>.directory` | yes | | yes | ACME directory URL. Must be an `https` URL. Changing the directory registers a new account and reissues every certificate that uses this CA. |
| `cas.<name>.eab_kid` | no | | yes | External Account Binding key ID. Must be set together with `eab_hmac`. |
| `cas.<name>.eab_hmac` | no | | yes | External Account Binding HMAC key. Must be set together with `eab_kid`. |
| `dns_resolvers` | no | system resolvers | no (restart) | List of DNS resolvers (`host` or `host:port`, default port 53) for lego's zone lookups, CNAME following, and propagation checks. Applies process-wide; changing it requires a restart. On Windows, when empty, lego falls back to Google Public DNS. |

### dns_providers

Each key is a provider name. See [DNS-01 validation](#dns-01-validation) for the `exec` type and the full list of per-type keys.

| Field | Required | Default | Hot-reloadable | Description |
|---|---|---|---|---|
| `type` | yes | | yes | Provider type: `cloudflare`, `aliyun`, `tencentcloud`, `route53`, `gcloud`, or `exec`. |
| `command` | yes for `exec`; rejected for other types | | yes | Argument list for `exec`; the first item must be an absolute path. |
| `skip_propagation_check` | no | `false` | yes | Skip lego's check that the TXT record has reached the authoritative nameservers. |
| *(type-specific keys)* | varies | | yes | See the table in [DNS-01 validation](#dns-01-validation). Required keys per type: `cloudflare` needs `api_token` or both `auth_email` and `auth_key`; `aliyun` needs `access_key` and `access_secret`; `tencentcloud` needs `secret_id` and `secret_key`; `route53` needs both `access_key` and `secret_key` or neither (for IAM role); `gcloud` needs `project` or `service_account_file`. |

### certificates

A list of certificate definitions. Each element:

| Field | Required | Default | Hot-reloadable | Description |
|---|---|---|---|---|
| `name` | yes | | yes | Unique certificate name. Changing the name triggers a fresh issuance; the old database record becomes an orphan. |
| `domains` | yes (at least one) | | yes | Domain names to include in the certificate. Wildcard (`*.example.com`) is allowed. Labels are 1 to 63 characters of `a-z`, `A-Z`, `0-9` and `-`, not starting or ending with `-`; `*.` is allowed only as the first label; total length at most 253. |
| `ca` | yes | | yes | Name of a CA defined in `acme.cas`. Changing the CA triggers reissuance. |
| `dns_provider` | yes | | yes | Name of a provider defined in `dns_providers`. |
| `key_type` | no | `ec256` | yes | Key algorithm: `rsa2048`, `rsa4096`, `ec256`, or `ec384`. Changing the key type triggers reissuance. |
| `subscribers` | no | | yes | Client names that receive this certificate. Names follow the [naming rules](#naming-rules) and need not be enrolled yet. |

Changing a certificate's `ca`, `domains`, or `key_type`, or the `directory` of its CA, triggers reissuance under the new configuration. Stored material is tied to those settings, so stale material is never distributed. See [Runtime reload and issuance](operations.md#runtime-reload-and-issuance) for the full reload rules.

## Client configuration

`client.yaml` names the server, the client's data directory, and what to do with each certificate:

```yaml
client:
  name: web-1
  server_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfoldc"
certificates:
  api-prod:
    outputs:
      - format: pem-fullchain
        path: /etc/nginx/certs/api.pem
      - format: pem-key
        path: /etc/nginx/certs/api.key
    on_change: ["/usr/sbin/nginx", "-s", "reload"]
```

- Which certificates a client receives is decided only by `subscribers` in `server.yaml`. An entry under `certificates` in `client.yaml` only says where to write a certificate the client already receives.
- Output formats are `pem-cert`, `pem-key`, `pem-fullchain`, `pem-bundle`, `pkcs12` (requires `password`), and `der`. `mode`, `owner`, and `group` are optional. Private-key outputs default to `0600`, the others to `0644`. `mode` is read as octal: `640` means `0640`; `0o640` also works. A value containing `8` or `9` (such as `384`, the decimal form of `0600`) is rejected, and `certfoldc` refuses to start.
- All path fields in both `server.yaml` (`data_dir`, `ipc_socket`, `tls_cert_file`, `tls_key_file`, gcloud `service_account_file`) and `client.yaml` (`data_dir`, `ipc_socket`, output `path`) must be absolute paths. On Windows, `\dir` and `C:dir` are not absolute; named pipes must be written as `\\.\pipe\...`. `${VAR}` references are expanded before the check. A relative path is rejected with `<field>: must be an absolute path, got "<value>"`.
- Two outputs cannot share a path. Paths are compared after cleaning, and case-insensitively on Windows.
- `enroll` adds the client's mTLS identity to this file.
- Unknown fields in either `server.yaml` or `client.yaml` are rejected. `client.yaml` has no top-level `outputs` map; `server.yaml` has no `clients` section (`subscribers` is the mechanism).

`client.data_dir` holds `certs.json`, a copy of every subscribed certificate and its private key, written with the same private permissions as `client.yaml`. Keep it on a filesystem that stores Unix permission bits (see [Trust model](security.md#trust-model)).

## Naming rules

All names in `server.yaml` --- certificate names, `acme.cas` keys, `dns_providers` keys --- and client names follow the same rule: a lowercase DNS label of 1 to 63 characters from `a-z`, `0-9` and `-`, not starting or ending with `-`.

A certificate name appears in `server.yaml` and in every subscriber's `client.yaml` under `certificates.<name>`; rename both together. A CA or provider name appears as a key in `acme.cas` or `dns_providers` and in the references that use it; rename the key and its references together. Names that do not pass the rule are rejected at startup and reload.

Renaming a CA registers a new ACME account under the new name. Renaming a certificate triggers a fresh issuance; the old database record becomes an orphan. When a delivered certificate is renamed but the `client.yaml` key is not, `certfoldc status` shows it with Outputs 0. If a delivered certificate's name does not pass the naming rule, `certfoldc` reports an error, stops delivering it, and removes stored material; output files are left in place.

## Environment variables in configuration

Values in `server.yaml` and `client.yaml` can reference environment variables as `${VAR}` or `${VAR:-default}`. `$$` is a literal `$`, and an unset variable without a default is an error. References are expanded after the YAML is parsed, inside each scalar value:

- The value is inserted verbatim. Leading and trailing spaces and line breaks are kept, and quotes, `#`, or `: ` inside it are never re-parsed as YAML structure. However, the expanded scalar is re-typed: a `${VAR}` that expands to a bare number, `true`, or `null` becomes that type unless the YAML quotes the reference (see [DNS-01 validation](#dns-01-validation)).
- Mapping keys are never expanded.
- Inside a flow collection, quote the reference, as in `["${HOST}"]`, because `{` is a flow indicator there.

## DNS-01 validation

Each certificate names a DNS provider from `dns_providers`. Besides lego's built-in providers, the `exec` type runs your own program to create and remove the challenge record:

```yaml
acme:
  dns_resolvers: ["10.0.0.53"]   # optional; see below
dns_providers:
  internal:
    type: exec
    command: ["/usr/local/bin/certfold-dns-hook", "--zone", "example.com"]
certificates:
  - name: api-prod
    dns_provider: internal
    # ...
```

`command` is an argument list; its first item must be an absolute path. `certfolds` runs it as `command... present <fqdn> <value>` before validation and `command... cleanup <fqdn> <value>` afterwards:

- `<fqdn>` is the TXT record name, after following CNAMEs, with a trailing dot. `<value>` is the TXT value. Exit status 0 means success.
- The value can start with `-`, so read the last three arguments by position. Do not parse them with getopt, argparse, or a PowerShell `param()` block: a value starting with `-` would be taken as an option, and PowerShell would silently bind an empty string. In PowerShell, use `$action, $fqdn, $value = $args[-3..-1]`.
- Each run times out after 2 minutes. The hook runs as the `certfolds` service account with its full environment, including any credentials referenced from `server.yaml`. Its working directory is the service's (`System32` for a Windows service, `/` under systemd), so use absolute paths.
- Different certificates can run the hook at the same time. Several domains of one certificate are handled without waiting between them.
- Background processes started by the hook must redirect their output; otherwise the hook fails 5 seconds after it exits.
- On failure, the error names only the action, the record, and the exit status or timeout. The hook's output goes to the service log, truncated. It does not appear in `certfolds events`.

On Windows, run a PowerShell script through its full path, for example `command: ['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\certfold\hook.ps1']`.

On Windows, do not use a `.bat` or `.cmd` file: `cmd.exe` re-parses the arguments, and values that contain special characters are mangled. Write the hook as a `.ps1` script and run it through `powershell.exe -File`. To suppress lego's CNAME lookups when you do not use CNAME delegation, set `LEGO_DISABLE_CNAME_SUPPORT=true` in the service environment (see [Windows service environment variables](operations.md#windows-service-environment-variables) for how).

Each built-in provider type accepts only these keys besides `type` and `skip_propagation_check` (an unknown key or a non-string value is an error):

| Type | Keys |
|---|---|
| `cloudflare` | `api_token`, `zone_api_token`, `auth_email`, `auth_key` |
| `aliyun` | `access_key`, `access_secret` |
| `tencentcloud` | `secret_id`, `secret_key` |
| `route53` | `access_key`, `secret_key`, `region` |
| `gcloud` | `project`, `service_account_file` |
| `exec` | *(none; uses `command`)* |

Values must be strings. A bare number like `12345` is parsed as an integer by YAML; quote it as `"12345"`. A `${VAR}` whose value is a bare number, `true`, or `null` must also be quoted in the YAML as `"${VAR}"`, otherwise the expanded value is re-typed. `${VAR:-}` expands to an empty string, which counts as unset for required keys.

Other DNS-01 settings:

- `skip_propagation_check: true` on a provider skips lego's check that the TXT record is visible on the zone's authoritative nameservers. Use it with DNS servers that cannot answer that check; lego still waits one 4-second polling interval.
- `acme.dns_resolvers` sets the resolvers lego uses for zone lookups, CNAME following, and the propagation check. It applies to the whole process, so changing it requires a restart. When it is empty, lego uses the system resolvers, and on Windows it falls back to Google Public DNS.
- Certificates that share a domain are issued in parallel and use the same `_acme-challenge` record. A provider may reject the second record, and one certificate's cleanup removes the record for both, so one of them fails and is retried after its backoff. Avoid overlapping domains across certificates.
- To use a private ACME CA, set `LEGO_CA_CERTIFICATES` for `certfolds` to the path of the CA's root certificate. lego panics if that file cannot be read.
