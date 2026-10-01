English | [简体中文](README.zh-CN.md)

# Certfold

Certfold is a central ACME certificate issuer and distributor for server fleets. The server (`certfolds`) obtains and renews certificates automatically through DNS-01 validation; clients (`certfoldc`) on each host pull their subscribed certificates over mTLS, write them in PEM, DER, or PKCS#12 format, and can run a configured program when a certificate changes.

```
                        ACME CA
                           |
               order, DNS-01 challenge
                    certificate
                           |
  DNS provider <----> certfolds
    (TXT record)           |
                     mTLS long poll
                    _______|_______
                   |       |       |
              certfoldc certfoldc certfoldc
              (host 1)  (host 2)  (host N)
                  |
             write outputs
             run on_change
```

## Key features

- Automatic ACME issuance and renewal with ARI (RFC 9773) support
- Long-poll delivery: the server answers as soon as a subscribed certificate is issued
- One-time enrollment tokens; enrolled clients authenticate with mTLS
- Declarative output reconciliation: outputs are restored automatically
- `on_change` hooks for reloading services after certificate updates
- One-line installation on Linux, macOS, and Windows
- Server and client TUIs
- Structured logging with the last 500 events kept in memory

## Quick start

Build `certfolds` and `certfoldc` first (see [Build and test](docs/en/development.md)). Write a minimal `/etc/certfold/server.yaml`:

```yaml
server:
  listen: ":8443"
  public_url: "https://certfold.example.com:8443"
  data_dir: "/var/lib/certfolds"

acme:
  email: "ops@example.com"
  default_ca: letsencrypt
  cas:
    letsencrypt:
      directory: "https://acme-v02.api.letsencrypt.org/directory"

dns_providers:
  cloudflare:
    type: cloudflare
    api_token: "${CF_API_TOKEN}"

certificates:
  - name: api-prod
    domains: ["api.example.com"]
    ca: letsencrypt
    dns_provider: cloudflare
    subscribers: [web-1]
```

Set `CF_API_TOKEN` in the server's environment, then start the server (on Linux, as root):

```bash
certfolds --config /etc/certfold/server.yaml serve
```

Create a short-lived enrollment token:

```bash
certfolds --config /etc/certfold/server.yaml token create --name web-1 --expires 10m
```

On web-1, enroll and start the client:

```bash
certfoldc --config /etc/certfold/client.yaml enroll --token <token>
certfoldc --config /etc/certfold/client.yaml serve
```

See [Client configuration](docs/en/configuration.md#client-configuration) for how to configure outputs and `on_change`. The [one-line installer](docs/en/installation.md#one-line-installation) automates enrollment and service setup, but requires platform binaries in `<data_dir>/binaries/` and a server certificate the operating system already trusts (see [Production TLS](docs/en/installation.md#production-tls)).

Inspect or trigger the running client:

```bash
certfoldc status
certfoldc fetch --cert api-prod
certfoldc reload
```

## Documentation

| Topic | Description |
|---|---|
| [Installation](docs/en/installation.md) | One-line install, reinstall, upgrade, uninstall, production TLS |
| [Configuration](docs/en/configuration.md) | server.yaml, client.yaml, naming rules, environment variables, DNS-01 providers |
| [Operations](docs/en/operations.md) | Tokens, delivery, on_change, renewal, events, TUI, reload, services |
| [Security](docs/en/security.md) | Trust model, private key outputs on Windows, directory requirements |
| [Troubleshooting](docs/en/troubleshooting.md) | Enrollment errors, directory errors, service status |
| [Build and test](docs/en/development.md) | Building from source and running the test suite |
| [Limitations](docs/en/limitations.md) | Known limitations |

## Project status

Active development. Enrollment, certificate distribution, management commands, runtime reload, client identity renewal, long-poll delivery, parallel issuance, ARI-directed renewal, HTTPS certificate hot-reload, server and client TUIs, and structured logging with events are implemented. The security-critical enrollment and pull path is covered by unit tests and a WSLC-native end-to-end test that includes real ACME issuance through Pebble and ARI. Review the [limitations](docs/en/limitations.md) before production use.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
