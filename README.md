# aegis-secret

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Aegis Secret allows agents to use local developer tools such as `gh`, `aws`,
`gcloud`, `kubectl`, `terraform`, and `az`, but without them freely shelling
out to those tools and asking or using raw credentials.

Aegis sits between the agent and the local CLI:

- the agent sees a small MCP surface
- Aegis prompts for Touch ID
- Aegis runs the real local command directly
- the agent gets the command result, not a raw secret

Wrapped commands are the main product surface. They matter because many useful
tools already know how to authenticate themselves through existing local state:

- `gh` may already be logged in
- `aws` may already have SSO, profile, or role-based auth
- `gcloud` may already have an active local login
- `kubectl`, `terraform`, and `az` may already be configured locally for the
  repo or machine

The product model is intentionally simple:

- humans manage raw secrets through the CLI when they need to
- agents do not get raw secret tools over MCP
- MCP exposes only wrapped local commands
- Aegis runs the real CLI directly after approval

Examples:

- let an agent use `gh api /user`
- let an agent use `aws sts get-caller-identity --output json`
- let an agent use `gcloud projects list --format=json`
- let an agent use `kubectl get pods -A -o json`
- let an agent use `terraform show -json`
- let an agent use `az account show --output json`

## What Aegis Does

Aegis has two surfaces:

- CLI for humans
- MCP for agents

### Human CLI

Humans use the CLI to:

- store, read, list, and delete Keychain secrets
- inspect wrapped-command config
- run wrapped commands manually
- repair user setup

### Agent MCP

Agents get only:

- `list_commands`
- `run_command`

That means an agent can discover which local tools Aegis allows and then ask
Aegis to run one of them. It does not get `get_secret`, `set_secret`, or
`delete_secret` over MCP.

## Quick Start

Store a secret:

```bash
aegis-secret set OPENAI_API_KEY
```

See which wrapped commands ship by default:

```bash
aegis-secret command list
aegis-secret command show gh
```

Run one yourself:

```bash
aegis-secret run gh -- api /user
aegis-secret run aws -- sts get-caller-identity --output json
```

Let an agent use the MCP server:

1. the agent calls `list_commands`
2. the agent picks a wrapped command such as `gh`
3. the agent calls `run_command`
4. you approve with Touch ID

## Install

### Binary Release

Download the installer package from the
[GitHub Releases page](https://github.com/mithran-hq/aegis-secret/releases).

1. Download `Aegis Secret-<version>-installer.pkg`
2. Open the package and finish the installer

The package installs:

- `/Applications/Aegis Secret.app`
- `/usr/local/bin/aegis-secret`
- `/usr/local/bin/aegis-secret-mcp`

The installer also makes a best-effort attempt to run:

```bash
aegis-secret install-user
```

That per-user setup step is what creates and refreshes:

- `~/.config/aegis-secret/commands.base.json`
  This is the managed base config. Aegis replaces it on install and upgrade with
  the shipped default wrapped commands such as `gh`, `aws`, `gcloud`,
  `kubectl`, `terraform`, and `az`.
- `~/.config/aegis-secret/commands.local.json`
  This is the user-owned overlay. Aegis creates it if missing, but does not
  overwrite your edits. Use it to disable shipped commands, override defaults,
  or add new wrapped commands.
- user-scoped Claude MCP registration
  Aegis registers itself as a Claude MCP server in the current user account, so
  new Claude sessions can discover `list_commands` and `run_command` in every
  project.
- user-scoped Codex MCP registration
  Aegis registers itself as a Codex MCP server in the current user account, so
  Codex can use the same wrapped-command tools without extra per-repo setup.
- user-scoped shell-bypass guard hooks, when agent config files are present
  - `~/.claude/settings.json`
    Aegis installs a `PreToolUse` hook for Claude `Bash` calls. The hook runs
    `aegis-secret guard shell` before the shell command executes.
  - `~/.codex/config.toml` and `~/.codex/hooks.json`
    Aegis enables Codex hooks and installs a `PreToolUse` hook for shell tool
    calls. Codex may ask you to review and trust a newly installed user hook.
- the managed Aegis block in:
  - `~/.claude/CLAUDE.md`
    Aegis updates only its marked block there, telling Claude to prefer
    `list_commands` and `run_command` for wrapped tools.
  - `~/.codex/AGENTS.md`
    Aegis updates only its marked block there, telling Codex to prefer
    `list_commands` and `run_command` for wrapped tools.

If that best-effort step did not run, or if you want to repair user setup at
any time, run:

```bash
aegis-secret install-user
```

## Default Wrapped Commands

Out of the box, Aegis ships wrappers for:

- `gh`
- `aws`
- `gcloud`
- `kubectl`
- `terraform`
- `az`

The shipped defaults are permissive enough to work out of the box, but include
obvious deny rules for credential and auth-management paths.

Examples:

- `gh auth ...` is blocked
- `aws sts assume-role ...` is blocked
- `aws ecr get-login-password` is blocked
- `gcloud auth ...` is blocked
- `kubectl apply ...` is blocked
- `terraform apply` is blocked
- `az login` is blocked

Wrapped command names are the top-level whitelist. If `kubectl` is not
configured, Aegis will not run `kubectl` over MCP.

## Customizing Wrapped Commands

Example custom `~/.config/aegis-secret/commands.local.json`:

```json
{
  "version": 1,
  "commands": [
    {
      "name": "gh",
      "approval_window_seconds": 0
    },
    {
      "name": "aws",
      "enabled": false
    },
    {
      "name": "kubectl",
      "command": "kubectl",
      "description": "Kubernetes CLI",
      "approval_window_seconds": 300,
      "timeout_seconds": 30,
      "max_output_bytes": 262144
    }
  ]
}
```

That example:

- makes `gh` prompt every time
- disables the shipped `aws` wrapper
- adds a new `kubectl` wrapper

Useful commands:

```bash
aegis-secret command list
aegis-secret command show gh
aegis-secret command validate
aegis-secret command validate --file examples/commands.example.json
```

## Expected Agent Behavior

After `install-user`, Claude and Codex should prefer Aegis for wrapped tools.

Expected agent flow:

1. call `list_commands`
2. see whether a tool such as `gh`, `aws`, `gcloud`, `kubectl`, `terraform`, or `az` is wrapped
3. use `run_command` instead of calling that CLI directly through Bash
4. fall back to direct shell use only when the command is not wrapped

If the agent calls a wrapped command through the shell anyway, the installed
Claude/Codex hook runs `aegis-secret guard shell`. A direct command such as
`gh issue list`, an env-prefixed command such as `FOO=1 gh api /user`, a
compound command such as `git status && gh issue list`, and
`aegis-secret run gh -- ...` are blocked with exit code `2`. The feedback tells
the agent to use the Aegis MCP `list_commands` and `run_command` tools.

Expected behavior for denied commands:

- the agent may try something blocked, such as `gh auth status`
- Aegis rejects it
- the agent should recover by trying a safe wrapped command instead, such as
  `gh api /user`

If an existing Claude or Codex session keeps behaving as if Aegis exposes old
tools or ignores the wrapped-command path, start a fresh session after install
or upgrade.

## Approval Leases and Diagnostics

Approvals are per agent, not global. The lease key is not the process name and
it is not a token passed by the agent. Aegis stores approvals by:

- agent name, such as `Codex` or `Claude`
- wrapped command name, such as `gh`
- resolved executable path for that command
- policy fingerprint for the resolved wrapped-command policy

The default lease file is:

```bash
~/.config/aegis-secret/approval-leases.json
```

That file lets a new Aegis process reuse a still-valid approval for the same
agent, command, executable path, and policy. A subprocess can also reuse the
lease when it calls Aegis with the same agent identity. A different agent name,
an expired window, a changed executable path, or a changed command policy gets a
new prompt.

Troubleshooting commands:

```bash
aegis-secret approval status gh --agent Codex
AEGIS_SECRET_DEBUG=1 aegis-secret run gh -- api /user
```

`approval status` reports whether the matching lease is active, expired,
missing, or invalidated by a policy or executable-path change. Debug mode logs
approval cache hit and miss reasons to stderr.

## CLI Reference

```bash
aegis-secret set <key> [--stdin]
aegis-secret get <key> --agent <agent-name>
aegis-secret delete <key>
aegis-secret list
aegis-secret install-user
aegis-secret command list
aegis-secret command show <name>
aegis-secret command validate [<name> | --file <path>]
aegis-secret command import <json-file>
aegis-secret approval status [<command>] [--agent <agent>]
aegis-secret guard shell [--command <shell-command>]
aegis-secret run <name> -- <args...>
```

## Security Model

- Secrets are stored in the macOS Data Protection keychain.
- Raw secret reads are CLI-only and intended for explicit human use.
- MCP never exposes secret-management tools.
- Wrapped commands are executed directly, never through a shell.
- Aegis closes stdin for wrapped commands.
- Aegis applies timeout and output-size limits.
- Aegis prompts for Touch ID before wrapped-command execution.
- Default approval caching is five minutes per agent and wrapped command,
  configurable in `commands.base.json` or `commands.local.json`.
- Approval leases are invalidated when the wrapped command policy or resolved
  executable path changes.
- Agent shell hooks are guardrails for common local shell paths, not a complete
  OS-level sandbox.

## Smoke Notes

Use these checks before a release or after changing approval or hook behavior:

```bash
swift test
./scripts/ci_local.sh
.build/debug/aegis-secret guard shell --command 'gh issue list'
```

Expected smoke results:

- `swift test` covers cross-process approval lease reuse, agent separation,
  expiry, policy changes, executable path changes, hook JSON extraction, and
  idempotent Claude/Codex hook updates.
- `./scripts/ci_local.sh` passes.
- direct shell guard smoke prints a message telling the agent to use
  `list_commands` and `run_command`, then exits `2`.
- MCP allow smoke succeeds when an agent uses Aegis MCP `list_commands` followed
  by `run_command` for an allowed wrapped command, such as `gh api /user`.

## Development

Run the main checks with:

```bash
swift build
swift test
```

If you change install or MCP behavior, also smoke test:

```bash
./scripts/install-user-mcp.sh
codex mcp list
claude mcp list
```

### Build From Source

Source installs are for development and contributors.

Store your Xcode team ID once:

```bash
mkdir -p ~/.config/aegis-secret
cat > ~/.config/aegis-secret/install.env <<'EOF'
AEGIS_SECRET_TEAM_ID=YOURTEAMID
EOF
```

If you want Xcode.app builds to work without editing the project file, create a
repo-local signing override once:

```bash
cp Config/Signing.local.xcconfig.example Config/Signing.local.xcconfig
```

Then set your team ID in `Config/Signing.local.xcconfig`. That file is
gitignored.

Then install:

```bash
git clone https://github.com/mithran-hq/aegis-secret.git
cd aegis-secret
./scripts/install-user-mcp.sh
```

The source installer builds a signed development app, installs it into
`~/Applications/Aegis Secret.app`, and then runs `install-user`.
