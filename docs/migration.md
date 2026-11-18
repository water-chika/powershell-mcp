# Migration

The standalone server uses MCP registration name `powershell` and tools:

- `list_powershell_targets`
- `powershell_status`
- `powershell_run`

Replace old `host="alias"` arguments with explicit `target="ssh:alias"`. Local execution uses `target="local"`.

Remove the previous MCP registration only after this server passes local and SSH smoke tests. Rollback by restoring the prior registration and reconnecting the MCP client.
