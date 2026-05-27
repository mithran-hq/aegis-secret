# Aegis Secret And Aegis Broker Boundary

MAP 1.0 ships Aegis Broker from this repository as a compatibility alias over
the Aegis Secret package. This keeps existing installs working while making the
product boundary explicit for protected tool calls.

## Responsibilities

Aegis Secret owns:

- Keychain-backed secret storage, listing, deletion, and explicit human raw
  reads;
- biometric approval for secret access;
- persisted approval leases for wrapped command execution;
- redaction rules that keep raw secrets out of MCP responses and logs.

Aegis Broker owns:

- PreTool protected-action classification;
- synchronous Bruno invocation for protected GitHub method mutations;
- privileged MCP command execution for actions that require biometric unlock
  and scoped secret injection;
- audit records for protected-action decisions.

AgentSH remains the inline AI-safety enforcement boundary for process, file,
and network execution. Aegis Engine consumes logs asynchronously and emits
policy packages. Bruno owns method judgment, not secret access or GitHub
remediation in the local path.

## MAP 1.0 Packaging

The primary MAP 1.0 user-facing install surface is `Aegis.app` installed by
`Aegis.pkg`. Aegis Secret/Broker is consumed as a managed component artifact
inside that bundle.

This repository still builds standalone Aegis Secret packages for compatibility
and development. Component artifacts for `Aegis.app` are described in
`docs/component-artifacts.md`.

The installed package exposes these command names:

- `aegis-secret`
- `aegis-secret-mcp`
- `aegis-broker`
- `aegis-broker-mcp`

All four names currently execute the same signed app binary. The Broker names
are compatibility aliases for the protected-action broker surface. Existing
`aegis-secret` MCP registrations continue to work. New setup may also register
`aegis-broker` as an MCP server name for agents that support multiple local MCP
servers.

This alias-first split is the MAP 1.0 migration path. It avoids breaking local
installs while allowing docs, setup, hooks, and agent guidance to use the
correct names.

## Routing Rules

Ordinary commands pass through by default. Examples include `gh issue list`,
`terraform plan`, `git status`, and read-only inspection commands.

Protected GitHub method mutations run Bruno synchronously in the PreTool hook
and then allow or block the original command. They do not route through Broker
MCP unless they also need privileged credential materialization.

Privileged credentialed actions, such as `terraform apply`, are blocked from
direct shell execution and rerouted to Aegis Broker MCP. Broker requests
biometric unlock through Aegis Secret, injects only scoped credentials into the
child process, and returns redacted output.

The concrete policy schema is defined in
`docs/adr/0002-aegis-broker-privileged-action-policy.md`.

D79 brokered remote authority for credential-starved protected workers is
defined in `docs/d79-broker-remote-authority-contract.md`.
