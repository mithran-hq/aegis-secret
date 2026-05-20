## Aegis Secret

When a task involves local CLIs such as `gh`, `aws`, `gcloud`, `kubectl`, or similar tools, prefer the `aegis-secret` MCP server when it is available.

- Call `list_commands` first to discover which wrapped commands Aegis exposes.
- Use `run_command` for wrapped tools instead of invoking those CLIs directly through Bash.
- Treat Aegis as the default path for wrapped local tools, not as a fallback after shelling out.
- Use `aegis-secret command list` and `aegis-secret command show <NAME>` only as a local fallback when MCP is unavailable.
- If a `Bash` call is blocked by `aegis-secret guard shell`, retry through the Aegis MCP `run_command` tool instead of asking for shell approval.
- Aegis approval leases are per agent and wrapped command. The persisted lease identity includes the agent name, command name, resolved executable path, and policy fingerprint.
- Use `aegis-secret approval status <NAME> --agent Claude` to diagnose repeated approval prompts.
- Use `aegis-secret get <KEY> --agent Claude` only for explicit human-approved debugging or when the user specifically asks for the raw value.
