# ADR 0001: Per-Agent Approval Leases And Shell-Bypass Guard

## Status

Accepted

## Context

Aegis Secret wraps local developer CLIs such as `gh`, `aws`, and `gcloud`
behind Touch ID approval. The current approval cache is process-local, so a
new Aegis MCP server process starts with no memory of an approval granted to a
previous process.

Agents can also bypass the MCP wrapper by invoking wrapped CLIs through a shell
tool. That routes through the agent client's shell permission system rather
than Aegis, so Aegis cannot apply its wrapped-command cache or policy.

## Decision

Aegis will persist wrapped-command approval leases per agent in a non-secret
JSON file under the Aegis config directory. A lease is valid only when all of
these values match:

- agent name
- wrapped command name
- resolved executable path
- wrapped-command policy fingerprint

The policy fingerprint includes the resolved command policy and the resolved
executable path. Policy or executable changes therefore invalidate old leases.

Aegis will also provide a hook-friendly shell guard that blocks agent shell
commands which directly invoke configured wrapped commands or
`aegis-secret run <wrapped-command>`. The guard will tell agents to use the
Aegis MCP `list_commands` and `run_command` tools instead.

## Consequences

- Separate Aegis MCP server processes for the same agent can reuse approval
  during the configured approval window.
- Claude and Codex approvals stay separate because the agent name is part of
  the lease identity.
- Leases are inspectable and testable because they contain metadata, not
  secrets.
- Hooks are a routing guardrail, not a security boundary. Security still comes
  from Aegis command policy, Touch ID, and the wrapped command execution path.
- Hooks block rather than rewrite shell commands. This keeps behavior explicit
  and avoids fragile shell-to-MCP translation.
