# Security Policy

Please report vulnerabilities through GitHub private vulnerability reporting when enabled for this repository. Do not include credentials, private host configuration, or sensitive command output in a public issue.

## Security model

The server executes arbitrary PowerShell with the authority of the selected local or SSH account. Output bounds and timeouts limit transport/resource use; they do not sandbox commands or reverse their side effects.

Use explicit targets, least-privilege accounts, pinned local runtimes, normal OpenSSH host-key verification, private target configuration, and MCP client approval controls.
