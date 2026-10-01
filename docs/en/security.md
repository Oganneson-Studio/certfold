English | [简体中文](../zh-CN/security.md)

[Back to README](../../README.md)

# Security

## Trust model

Which certificates a client receives is decided only by `subscribers` in `server.yaml`. An entry under `certificates` in `client.yaml` only says where to write a certificate the client already receives. See [Client configuration](configuration.md#client-configuration) for the output settings.

Enrollment tokens carry the expected client name, server URL, and mini-CA certificate. `certfoldc` validates TLS before sending the token or CSR, then stores its mTLS identity in a private, atomically replaced configuration file. `certfoldc` verifies the server against the operating system's roots plus the Certfold mini-CA, so either kind of server certificate works. Client certificates are always issued and verified by the mini-CA.

On Windows, the CLI only talks to a named pipe owned by SYSTEM or Administrators, so a low-privilege process cannot impersonate the daemon.

The server's read-only IPC responses expose metadata only and never include certificate private keys or enrollment-token hashes.

`client.data_dir` holds `certs.json`, a copy of every subscribed certificate and its private key, written with the same private permissions as `client.yaml`. Keep it on a filesystem that stores Unix permission bits: WSL drvfs mounts and CIFS without Unix extensions do not.

## Private key outputs on Windows

Outputs that contain a private key (`pem-key`, `pem-bundle`, `pkcs12`) are created with a protected ACL that grants full access to SYSTEM and Administrators (and the current user when the process runs without elevation). `mode` is not applied on Windows and cannot widen that ACL. To let a service such as IIS or nginx read a key, set `owner` on that output to the service's account name or SID; that account gets read access but does not become the file's owner. `owner` only takes effect on private-key outputs; on other formats it is silently ignored.

On Windows, reconciliation compares only the content of each output, not its ACL or ownership. A key file whose ACL was loosened, or that inherits its directory's ACL because another tool wrote it, keeps that ACL until its content changes at the next renewal. Removing `owner` from the configuration likewise leaves the previous account and its read access in place, on Unix as well. To apply the configuration at once, delete the file; the next round recreates it.

## Directory requirements

`certfolds` and `certfoldc` check certain directories at startup and refuse to run when the checks fail. On Unix, only `certfolds` checks its data directory (`CheckPrivateDirectory`); `certfoldc` does not check directories on Unix. On Windows, both daemons check their configuration directory and data directory. `certfoldc enroll` checks the configuration directory before writing. The checks vary by platform:

- **certfolds data_dir** (Unix): mode `0700`, owned by the running user. (Windows): completely private --- only SYSTEM, Administrators, and, when not elevated, the running user may access it; the owner must be one of them.
- **Configuration directory and certfoldc data_dir** (Windows): owned by SYSTEM, Administrators, or (when not elevated) the current user; no other account may write, delete, or change permissions.
- **ca/ subdirectory**: checked and tightened by `ca.Bootstrap` on every startup. On Unix, only tightened (the check is a no-op there).

When a data directory does not exist, the daemon creates it with private permissions. Configuration directories are not created automatically; `certfoldc enroll` creates the client configuration directory. When it exists but does not pass the check, the error names the directory and prints the commands to fix it:

```
configuration directory: C:\ProgramData\Certfold is owned by DESKTOP\Alice, and only NT AUTHORITY\SYSTEM and BUILTIN\Administrators may own it. Its owner may have put files in it and may change who can write to it: remove it, so that it is created again. To keep it instead, check every file in it, then run:
  icacls "C:\ProgramData\Certfold" /setowner *S-1-5-32-544
```

On Linux, if the data directory was created with mode `0755`:

```
/var/lib/certfolds has mode 0755, and only its owner may have access to it. Check the files in it, then run:
  chmod 700 "/var/lib/certfolds"
```

When the error does not say the owner is untrusted (a wrong mode on Unix, extra ACL entries on Windows), run the commands it prints. When the error says the owner is untrusted, its advice is to remove the directory so that the daemon creates it again; do this only when the directory's contents can be recreated. Do not remove the certfolds data directory unless you accept losing the mini-CA (all enrolled clients must re-enroll) and the certificate database.

Each parent directory of the configuration directory and data_dir must not be owned by an untrusted account and must not let untrusted accounts delete or replace entries in it. The check looks only at the directory itself, not its parents; the default layout (`/etc/certfold`, `/var/lib`, `C:\ProgramData`) satisfies this requirement.

Output file directories and their parents should not be writable by low-privilege accounts either: `O_NOFOLLOW` protects only the last path component, and a writable parent lets an attacker replace an earlier component with a symbolic link.
