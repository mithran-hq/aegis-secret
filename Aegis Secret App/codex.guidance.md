## Aegis Secret / Aegis Broker

Use ordinary shell calls for ordinary commands. Use Aegis Broker only for protected or privileged actions.

- Protected GitHub method mutations such as issue close, PR merge, or release edits are checked by the Aegis PreTool hook and Bruno before the original command runs.
- Privileged credentialed actions such as `terraform apply` must use the Aegis Broker MCP server: call `list_commands`, then `run_command`.
- Ordinary commands such as `gh issue list`, `terraform plan`, and `git status` are not brokered by default.
- Use `aegis-secret command list` and `aegis-secret command show <NAME>` only as a local fallback when MCP is unavailable.
- If a shell tool call is blocked by `aegis-secret guard shell`, follow the block message. It may ask for evidence, or it may ask you to retry through Aegis Broker MCP.
- Aegis approval leases are per agent and wrapped command. The persisted lease identity includes the agent name, command name, resolved executable path, and policy fingerprint.
- Use `aegis-secret approval status <NAME> --agent Codex` to diagnose repeated approval prompts.
- Use `aegis-secret get <KEY> --agent Codex` only for explicit human-approved debugging or when the user specifically asks for the raw value.
