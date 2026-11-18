# PowerShell MCP

A provider-neutral MCP server for bounded PowerShell execution on explicit local or registered SSH targets.

> This is an independent project and is not affiliated with or endorsed by Microsoft.

## Tools

- `list_powershell_targets()`
- `powershell_status(target)`
- `powershell_run(target, script, ...)`

Targets are always explicit:

```text
local
ssh:example-windows
```

There is no implicit local fallback and arbitrary SSH destinations are rejected.

## Install

Requires Python 3.11+, PowerShell (`pwsh`) for local execution, and OpenSSH for SSH targets.

```bash
pipx install .
claude mcp add --scope user --transport stdio powershell -- \
  ~/.local/bin/powershell-mcp
```

For development:

```bash
pipx install --editable .
```

## Configuration

The default target registry is `~/.config/powershell-mcp/targets.conf`. Override it with `POWERSHELL_MCP_REGISTRY`.

```text
example-windows | developer@example.invalid | powershell
forwarded       | -p 2222 developer@127.0.0.1 | powershell
```

The registry is trusted configuration because its destination field is parsed as OpenSSH arguments. Keep it private and writable only by its owner.

Configure a pinned local runtime with `POWERSHELL_MCP_PWSH`; otherwise `pwsh` is resolved from PATH.

## Examples

```json
{"target":"local","script":"$PSVersionTable.PSVersion.ToString()"}
```

```json
{"target":"ssh:example-windows","script":"Get-Process","max_lines":20}
```

Normal results contain only:

```json
{"output":"...","exit_code":0}
```

Failure, truncation, timeout, and raw protocol fields appear only when relevant. Raw records are opt-in with `include_raw_records: true`.

## Bounds and security

This tool executes arbitrary PowerShell with the selected account's authority. It is not a sandbox.

- `target` is mandatory.
- SSH targets are allowlisted.
- Line, byte, record, diagnostic, and time limits are enforced.
- Process groups receive bounded TERM/KILL cleanup.
- Exactly one terminal protocol record must be last.
- Normal OpenSSH host-key verification is retained.
- MCP approval generally applies to the tool, not individual target values.

Use least-privilege accounts and keep client-side tool approval enabled.

See [configuration](docs/configuration.md), [protocol](docs/protocol.md), [security](docs/security.md), and [migration](docs/migration.md).
