# Tool Decision Receipts

Aegis Secret writes broker decision receipts as JSON Lines for the Aegis daemon.
The default handoff file is:

```text
~/.config/aegis-secret/tool-decisions.jsonl
```

Set `AEGIS_SECRET_RECEIPTS_FILE` to another absolute path to redirect the
handoff file. Set it to `off`, `false`, `0`, or `none` to disable local receipt
writing.

Receipts use schema `aegis.tool_decision_receipt.v1`. Aegis Secret records MCP
`list_commands` and `run_command` decisions. Raw secret CRUD is not available
over MCP, and each receipt states `raw_secret_mcp_crud_available=false` in its
redaction metadata.

## `list_commands`

```json
{
  "approval_state": "not_required",
  "argv": [],
  "completed_at": "2026-05-25T12:00:00Z",
  "decision": "allow",
  "redaction": {
    "raw_secret_mcp_crud_available": false,
    "stderr": "not_redacted_broker_response",
    "stdout": "not_redacted_broker_response"
  },
  "receipt_id": "example-list",
  "requester": "Codex",
  "schema_version": "aegis.tool_decision_receipt.v1",
  "started_at": "2026-05-25T12:00:00Z",
  "stderr_truncated": false,
  "stdout_truncated": false,
  "surface": "mcp",
  "tool_name": "list_commands"
}
```

## Allowed `run_command`

```json
{
  "approval_state": "prompted",
  "argv": ["/opt/homebrew/bin/gh", "api", "/user"],
  "command_name": "gh",
  "completed_at": "2026-05-25T12:00:03Z",
  "decision": "allow",
  "exit_code": 0,
  "matched_policy": {
    "allow_prefixes": [],
    "broker_required_prefixes": [],
    "approval_window_seconds": 21600,
    "command": "gh",
    "command_name": "gh",
    "deny_flags": ["--hostname"],
    "deny_prefixes": [["auth"], ["alias"], ["extension"]],
    "executable_path": "/opt/homebrew/bin/gh",
    "max_output_bytes": 262144,
    "policy_fingerprint": "7a7f...",
    "timeout_seconds": 30
  },
  "output": {
    "stderr_bytes": 0,
    "stderr_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb924...",
    "stdout_bytes": 22,
    "stdout_sha256": "sha256:0fbf..."
  },
  "redaction": {
    "raw_secret_mcp_crud_available": false,
    "stderr": "not_redacted_broker_response",
    "stdout": "not_redacted_broker_response"
  },
  "receipt_id": "example-run",
  "requester": "Codex",
  "schema_version": "aegis.tool_decision_receipt.v1",
  "started_at": "2026-05-25T12:00:00Z",
  "stderr_truncated": false,
  "stdout_truncated": false,
  "surface": "mcp",
  "tool_name": "run_command"
}
```

## Denied `run_command`

```json
{
  "approval_state": "denied_by_policy",
  "argv": ["/opt/homebrew/bin/gh", "auth", "token"],
  "command_name": "gh",
  "completed_at": "2026-05-25T12:00:00Z",
  "decision": "deny",
  "error": "The `auth` subcommand is not allowed for wrapped command `gh`.",
  "matched_policy": {
    "allow_prefixes": [],
    "broker_required_prefixes": [],
    "approval_window_seconds": 21600,
    "command": "gh",
    "command_name": "gh",
    "deny_flags": ["--hostname"],
    "deny_prefixes": [["auth"], ["alias"], ["extension"]],
    "executable_path": "/opt/homebrew/bin/gh",
    "max_output_bytes": 262144,
    "policy_fingerprint": "7a7f...",
    "timeout_seconds": 30
  },
  "redaction": {
    "raw_secret_mcp_crud_available": false,
    "stderr": "not_redacted_broker_response",
    "stdout": "not_redacted_broker_response"
  },
  "receipt_id": "example-deny",
  "requester": "Codex",
  "schema_version": "aegis.tool_decision_receipt.v1",
  "started_at": "2026-05-25T12:00:00Z",
  "stderr_truncated": false,
  "stdout_truncated": false,
  "surface": "mcp",
  "tool_name": "run_command"
}
```
