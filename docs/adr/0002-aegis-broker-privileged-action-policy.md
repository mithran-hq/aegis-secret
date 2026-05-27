# ADR 0002: Aegis Broker Privileged-Action Policy

## Status

Accepted

## Context

D73 in `mithran-business` splits local enforcement into three paths:

- ordinary tool calls pass through without Aegis Broker ceremony;
- protected GitHub method mutations run Bruno synchronously in the PreTool
  hook;
- privileged credentialed actions are blocked from direct shell execution and
  rerouted through Aegis Broker MCP for biometric Keychain unlock and scoped
  secret injection.

The existing Aegis Secret wrapped-command config is command-centric: it lists
commands that should be executed through MCP and can deny prefixes or flags.
MAP 1.0 needs a narrower broker policy that classifies a requested tool action
before execution. Aegis Secret remains the Keychain-backed secret boundary.
Aegis Broker owns protected tool routing, Bruno sync gates, privileged command
execution, and evidence.

For MAP 1.0, Aegis Broker ships from this repo as a compatibility alias over
the existing product package. The user-visible split is real in command names,
MCP descriptions, docs, and policy ownership, but it does not require a new
repository or installer boundary before the release.

## Decision

Aegis Broker will load a layered JSON policy:

1. bundled defaults inside the app/package;
2. managed base policy at `~/.config/aegis-broker/policy.base.json`;
3. local override policy at `~/.config/aegis-broker/policy.local.json`.

Later layers replace rules with the same `id` and append new rules. A disabled
local rule with the same `id` suppresses a bundled or managed rule. The loader
must validate `schema_version`, unique rule IDs after layering, known action
kinds, and supported match fields before enabling the policy. Invalid policy
fails closed only for protected or privileged matches; ordinary unmatched
commands still pass through unless the bundled default policy cannot be loaded.

The MAP 1.0 schema version is `aegis.broker_policy.v1`. Each rule has:

- `id`: stable policy ID;
- `enabled`: optional boolean, default `true`;
- `description`: operator-readable reason;
- `match`: predicates over `tool_kind`, `command`, `args_prefix`,
  `args_any`, `cwd_globs`, `repo`, and `env`;
- `action`: one of `allow`, `bruno_sync`, `broker_mcp_required`, or `deny`;
- `audit`: optional tags and evidence category.

Rules are evaluated in policy order after layering. The first enabled rule
whose predicates match decides the action. If no rule matches, the action is
`allow`.

`tool_kind` is the agent tool family, such as `shell`, `bash`, `exec_command`,
or `mcp`. `command` is the resolved executable basename from the shell command
segment. `args_prefix` matches the executable arguments after the command name.
`args_any` matches any argument. `cwd_globs` and `repo` are optional context
predicates; absent context does not match a rule that requires that field. `env`
predicates only test key presence or exact redacted-safe marker values. Broker
policy must not compare raw secret values.

### Example: protected GitHub method mutation

```json
{
  "schema_version": "aegis.broker_policy.v1",
  "rules": [
    {
      "id": "github.issue.close.bruno-sync",
      "description": "Require Bruno evidence before closing GitHub issues",
      "match": {
        "tool_kind": ["shell", "bash", "exec_command", "unified_exec"],
        "command": "gh",
        "args_prefix": ["issue", "close"]
      },
      "action": {
        "kind": "bruno_sync",
        "command": "bruno",
        "timeout_seconds": 5,
        "fail_on_unavailable": true,
        "fail_on_malformed_output": true
      },
      "audit": {
        "category": "github_method_mutation",
        "tags": ["bruno-method", "issue-close"]
      }
    }
  ]
}
```

For a command such as:

```text
gh issue close 138 --repo mithran-hq/mithran-business --comment "Evidence: artifact://setup/smoke-1"
```

the PreTool hook sends Bruno a metadata-only event:

```json
{
  "schema_version": "aegis.broker.bruno_event.v1",
  "action": {
    "kind": "github.issue.close",
    "command": "gh",
    "argv": ["issue", "close", "138", "--repo", "mithran-hq/mithran-business", "--comment", "[REDACTED]"]
  },
  "subject_refs": {
    "repo": "github://mithran-hq/mithran-business",
    "issue": "github://mithran-hq/mithran-business/issues/138"
  },
  "actor": {
    "agent": "Codex",
    "session_ref": "agent-session://local"
  },
  "context": {
    "cwd": "[REDACTED_PATH]",
    "tool_kind": "shell"
  },
  "evidence_refs": ["artifact://setup/smoke-1"],
  "redaction_state": "metadata_only"
}
```

The sync path must not read GitHub. Evidence must come from the hook payload or
supported mutation-intent arguments such as `--comment`, `--body`, `--notes`,
or equivalent message fields. If a protected close, merge, or release mutation
does not carry evidence refs, Bruno should deny or the broker should fail the
gate before execution.

Bruno returns `bruno.guard_decision.v1`:

```json
{
  "schema_version": "bruno.guard_decision.v1",
  "id": "guard-github-issue-close-138",
  "producer": {"name": "bruno", "version": "0.1.0"},
  "method": {"id": "bruno-method", "version": "0.1.0", "spec": "SPEC.md"},
  "produced_at": "unknown",
  "subject_refs": {
    "issue": "github://mithran-hq/mithran-business/issues/138"
  },
  "redaction_state": "metadata_only",
  "decision": "allow",
  "reasons": [],
  "required_evidence": [],
  "recommended_next_prompt": "Proceed with the supplied hook action and keep collecting evidence.",
  "evidence_refs": ["artifact://setup/smoke-1"],
  "calls_external_tools": false
}
```

`decision=deny` blocks the original tool call. Bruno exit code `1` is a method
block. Bruno timeout, missing binary, non-JSON stdout, malformed decision JSON,
or usage/input exit code `2` fail closed for protected GitHub mutations and
print a remediation message to the agent.

### Example: privileged credentialed action

```json
{
  "schema_version": "aegis.broker_policy.v1",
  "rules": [
    {
      "id": "terraform.apply.broker-mcp",
      "description": "Terraform apply requires biometric unlock and scoped credentials",
      "match": {
        "tool_kind": ["shell", "bash", "exec_command", "unified_exec"],
        "command": "terraform",
        "args_prefix": ["apply"]
      },
      "action": {
        "kind": "broker_mcp_required",
        "mcp_tool": "run_command",
        "secret_scope": "terraform"
      },
      "audit": {
        "category": "privileged_credentialed_action",
        "tags": ["terraform", "biometric-required"]
      }
    }
  ]
}
```

The initial privileged Terraform set is `apply`, `destroy`, `import`, `state`,
`force-unlock`, and `login`. Similar mutating cloud credential verbs should use
the same `broker_mcp_required` action.

When a direct shell command matches `broker_mcp_required`, the PreTool hook
blocks it and tells the agent to call the Aegis Broker MCP `list_commands` and
`run_command` path. In that path, Aegis Broker requests biometric unlock from
Aegis Secret, obtains only the scoped secret material needed for the child
process, injects it into the child environment or credential file, and returns
redacted command output. Raw secret values must never appear in MCP responses,
logs, audit records, or agent-visible errors.

## Compatibility

Existing Aegis Secret MCP clients continue to see `list_commands` and
`run_command`. MAP 1.0 guidance should describe these tools as the Aegis Broker
route for privileged credentialed actions, not as the default path for every
wrapped command.

The current wrapped-command config remains the compatibility source for command
summaries, command execution defaults, approval leases, and legacy MCP callers.
Broker policy is the PreTool classifier. In the compatibility config,
`deny_prefixes` means the command must not run through direct shell or
`run_command`, while `broker_required_prefixes` means direct shell must reroute
to Broker MCP and `run_command` may execute after approval. If both systems know
a command, the broker classifier decides whether the direct shell command may
proceed, whether Bruno must run, or whether MCP is required.

Ordinary commands pass through by default. For example, `gh issue list`,
`terraform plan`, `git status`, and read-only inspection commands must not be
brokered unless an explicit policy version protects them.

## Audit And Evidence

Every non-allow decision emits a metadata-only audit record with:

- policy schema version and policy hash;
- matched rule ID and action kind;
- redacted command argv;
- actor agent and session ref when available;
- cwd/repo context with paths redacted;
- Bruno decision ID and evidence refs for `bruno_sync`;
- broker MCP execution ID and secret scope for `broker_mcp_required`;
- result: `allowed`, `blocked`, `reroute_required`, or `error`.

Audit records are local evidence for #138 and async input for aegis-engine.
They must not include raw secrets, access tokens, full provider homes, or
unredacted local paths.

## Consequences

- Protected GitHub mutations are prevented before execution when the local
  method evidence is missing or Bruno denies the action.
- The sync Bruno path remains bounded and deterministic because it is
  metadata-only and performs no GitHub reads.
- Privileged credentialed commands pay the biometric and MCP cost only when a
  policy says they require scoped secret materialization.
- The alias-first Aegis Broker packaging lets MAP 1.0 ship the boundary without
  forcing a repository or installer split first.
- Local hooks are still guardrails, not a complete authority. Remote GitHub
  webhook/MAP remediation remains the backstop for mutations that bypass local
  controls.
