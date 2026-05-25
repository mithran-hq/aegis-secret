# Local Broker Proof

`scripts/local-broker-proof.sh` is the hosted-infra-free proof harness for Aegis
Secret/Broker. It runs the local CI suite and writes:

```text
dist/local-broker-proof/aegis-broker-local-proof.json
```

The proof is intentionally local. It demonstrates that:

- ordinary shell commands are not brokered by default;
- protected GitHub mutations are classified for Bruno sync gating;
- privileged commands such as `terraform apply` are blocked from direct shell and
  redirected to Aegis Broker MCP;
- command environment values using `aegis-secret://<key>` are resolved through
  Aegis Secret before subprocess execution;
- the resolved secret value is not present in MCP output or receipts;
- Broker MCP does not expose raw secret CRUD tools;
- tool decision receipts include command, requester, policy decision,
  approval/cache state, exit code, truncation flags, output hashes, and
  redaction metadata.

The generated JSON has schema `aegis.local_broker_proof.v1` and points to the
unit tests and receipt examples that back each assertion. Its public fields state
`raw_credential_material_present=false` and
`broker_mcp_raw_secret_crud_available=false`.

This proof is not hosted D72 GitHub App grant proof. It does not prove Mithran
Auth, Studio, GitHub App callbacks, or a Mithran-minted GitHub App installation
token. Those claims belong to the hosted setup/control-plane lane.

## Secret References

Wrapped-command environment values may reference Aegis Secret keys:

```json
{
  "environment": {
    "GH_TOKEN": "aegis-secret://github-app-token"
  }
}
```

At execution time the broker asks the configured `SecretStore` for the key and
injects the resolved value into the subprocess environment. Receipts record the
policy decision and output hashes, not the secret key or secret value.
