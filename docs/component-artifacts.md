# Aegis Secret And Broker Component Artifacts

`Aegis.app` is the MAP 1.0 user-facing install surface. This repository still
builds standalone Aegis Secret releases for compatibility and development, but
normal users should install Aegis.

The Aegis Secret/Broker component artifact is produced by:

```bash
./scripts/package-component-artifacts.sh v0.2.0
```

The script expects the signed and notarized release app at:

```text
dist/v0.2.0/Aegis Secret.app
```

It writes:

```text
dist/v0.2.0/aegis-secret-broker-0.2.0-component.tar.gz
dist/v0.2.0/aegis-secret-broker-0.2.0-component.json
```

The archive layout is:

```text
aegis-secret-broker-0.2.0-component/
  bin/
    aegis-secret
    aegis-secret-mcp
    aegis-broker
    aegis-broker-mcp
  share/
    aegis-secret/
      commands.default.json
      codex.guidance.md
      claude.guidance.md
  manifest/
    aegis-secret-component.json
```

`aegis-secret` is the signed executable copied from the release app. The other
three files are wrappers used by Aegis packaging to preserve command names:

- `aegis-secret-mcp` runs `aegis-secret --mcp-server`;
- `aegis-broker` runs `aegis-secret`;
- `aegis-broker-mcp` runs `aegis-secret --mcp-server`.

The top-level JSON manifest uses schema `aegis.component_artifact.v1` and names
`aegis.component_manifest.v1` as the consumer manifest schema. It records:

- component set name, version, source repo, source ref, and license;
- binary and wrapper paths;
- SHA256 for every shipped file;
- code-signing and notarization state for the signed executable;
- Broker MCP and Secret MCP entrypoints;
- `ordinary_commands_brokered_by_default=false`;
- `raw_secret_mcp_crud_available=false`.

This artifact is local Aegis component proof. It does not prove Mithran-hosted
Auth, Studio, GitHub App callbacks, or Mithran-minted GitHub App credentials.

Standalone `Aegis Secret-<version>-installer.pkg` remains a compatibility and
developer artifact while `Aegis.app` consumes the component archive.
