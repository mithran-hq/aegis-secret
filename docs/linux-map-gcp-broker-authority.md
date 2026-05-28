# Linux MAP/GCP Broker Authority

On macOS, Aegis Secret stores local secrets in Keychain and asks the developer
for device-owner approval before a wrapped command receives credential material.

On Linux developer hosts, the broker authority is different. `aegis-broker` and
`aegis-broker-mcp` resolve broker credential refs through the developer's MAP
sign-in and GCP Secret Manager. This is the authority used by the Linux
Firecracker `aegis codex` path: the guest stays credential-starved, and the host
broker materializes only the scoped credential needed for an approved typed
action or CLI profile.

## Runtime Selection

Linux defaults to the MAP/GCP authority. It can also be selected explicitly:

```bash
export AEGIS_SECRET_AUTHORITY=map-gcp
```

Required configuration:

```bash
export AEGIS_SECRET_GCP_PROJECT=mithran-dev-secrets
```

Optional configuration:

```bash
export AEGIS_SECRET_GCP_SECRET_PREFIX=aegis-
export AEGIS_SECRET_GCLOUD=/usr/bin/gcloud
export AEGIS_SECRET_MAP_ACCOUNT=developer@mithran.ai
```

If `AEGIS_SECRET_MAP_ACCOUNT` is not set, the broker checks `gcloud auth list`
for an active account before reading Secret Manager.

## Broker Behavior

The Linux authority implements broker credential materialization only.

Supported:

- `list_remote_actions`
- `run_remote_action`
- `list_cli_profiles`
- `run_cli_profile`
- `list_commands`
- `run_command`

Not supported:

- raw secret set
- raw secret get
- raw secret list
- raw secret delete

Raw secret CRUD returns `raw_secret_crud_unavailable`. MCP does not expose raw
secret CRUD tools on any platform.

## Secret Refs

Broker requests use ordinary local refs:

```text
aegis-secret://gcp-run-token
```

With `AEGIS_SECRET_GCP_SECRET_PREFIX=aegis-`, the Linux authority reads this
GCP Secret Manager secret:

```text
aegis-gcp-run-token
```

Secret names are restricted to ASCII letters, digits, `_`, and `-`. Unsafe refs
fail closed before any GCP call.

## Failure Modes

The Linux authority fails closed and keeps provider details out of agent-visible
errors.

| State | Error |
| --- | --- |
| Missing project config | `broker_auth_lease_denied` |
| Missing MAP sign-in | `broker_auth_lease_denied` |
| Unsafe credential ref | `broker_auth_lease_denied` |
| IAM denial | `broker_credential_materialization_failed` |
| Missing or denied secret | `broker_credential_materialization_failed` |
| GCP Secret Manager or KMS unavailable | `broker_credential_materialization_failed` |

Command receipts and remote-authority evidence include hashes and metadata, not
raw credential values.
