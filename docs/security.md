# Security Model

`powershell_run` is an arbitrary-code execution tool. `local` uses the MCP server account; `ssh:<alias>` uses the registered SSH account.

Target allowlisting prevents arbitrary destinations but does not make commands safe. Timeouts cannot undo remote side effects, and terminating the local SSH process cannot always prove that remote descendants stopped. Such cases report `cancellation_unconfirmed`.

The target registry is trusted configuration. OpenSSH host-key verification remains enabled. Raw records may expose machine names, paths, and command output and should be requested only for protocol diagnosis.
