# Configuration

The target registry defaults to `~/.config/powershell-mcp/targets.conf` and can be overridden with `POWERSHELL_MCP_REGISTRY`.

Each non-comment line contains:

```text
alias | OpenSSH destination/options | powershell
```

Aliases may contain letters, digits, dots, underscores, and hyphens. `local` is reserved. The destination field is trusted configuration and is parsed as OpenSSH arguments, so protect this file with user-only write access.

Local PowerShell is selected from `POWERSHELL_MCP_PWSH` or `pwsh` on PATH. The configured executable is never accepted from a tool argument.
