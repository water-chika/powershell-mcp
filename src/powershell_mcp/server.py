"""Expose the structured PowerShell runner transport as a narrow stdio MCP server."""
from __future__ import annotations

import io
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import NotRequired, TypedDict, cast

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import CallToolResult, TextContent

from .runner import SequenceParser, UsageError, execute, load_registry, resolve_target

_DEFAULT_REGISTRY = Path.home() / ".config/powershell-mcp/targets.conf"
_MAX_LINES = 200
_MAX_BYTES = 1024 * 1024
_MAX_TIMEOUT_SECONDS = 600


@dataclass
class CommandResult:
    host: str
    ok: bool = False
    output: str = ""
    output_complete: bool = False
    exit_code: int | None = None
    transport_exit_code: int | None = None
    failure: str | None = None
    message: str | None = None
    timeout_seconds: int | None = None
    partial: bool = False
    cancellation_unconfirmed: bool = False
    duration_ms: int = 0
    records: list[dict[str, object]] = field(default_factory=list)
    observed_lines: int = 0
    observed_bytes: int = 0
    emitted_lines: int = 0
    emitted_bytes: int = 0
    filter_suppressed_lines: int = 0
    filter_suppressed_bytes: int = 0
    line_suppressed_lines: int = 0
    line_suppressed_bytes: int = 0
    byte_suppressed_lines: int = 0
    byte_suppressed_bytes: int = 0


class PublicCommandResult(TypedDict):
    output: str
    exit_code: NotRequired[int | None]
    host: NotRequired[str]
    ok: NotRequired[bool]
    output_complete: NotRequired[bool]
    transport_exit_code: NotRequired[int]
    failure: NotRequired[str]
    message: NotRequired[str]
    timeout_seconds: NotRequired[int]
    partial: NotRequired[bool]
    cancellation_unconfirmed: NotRequired[bool]
    observed_lines: NotRequired[int]
    observed_bytes: NotRequired[int]
    emitted_lines: NotRequired[int]
    emitted_bytes: NotRequired[int]
    filter_suppressed_lines: NotRequired[int]
    filter_suppressed_bytes: NotRequired[int]
    line_suppressed_lines: NotRequired[int]
    line_suppressed_bytes: NotRequired[int]
    byte_suppressed_lines: NotRequired[int]
    byte_suppressed_bytes: NotRequired[int]
    records: NotRequired[list[dict[str, object]]]


def registry_path() -> Path:
    return Path(os.environ.get("POWERSHELL_MCP_REGISTRY", _DEFAULT_REGISTRY)).expanduser()


def load_hosts(path: Path | None = None) -> tuple[str, ...]:
    source = path or registry_path()
    try:
        return tuple(load_registry(source))
    except (OSError, UnicodeError, UsageError) as exc:
        raise ToolError(f"cannot read wsh host registry: {exc}") from exc


def require_target(target: str) -> str:
    try:
        resolve_target(target, registry_path())
    except (OSError, UnicodeError, UsageError) as exc:
        raise ToolError(str(exc)) from exc
    return target


def parse_records(data: bytes) -> list[dict[str, object]]:
    parser = SequenceParser()
    records = list(parser.feed(data))
    records.extend(parser.finish())
    return records


def run_target(target: str, script: str, max_lines: int, max_bytes: int,
               filter: str | None, timeout_seconds: int) -> CommandResult:
    try:
        resolved = resolve_target(target, registry_path())
    except (OSError, UnicodeError, UsageError) as exc:
        raise ToolError(str(exc)) from exc
    framed = io.BytesIO()
    status = execute(resolved, script, mode="powershell", max_lines=max_lines,
                     max_bytes=max_bytes, pattern=filter, timeout=timeout_seconds,
                     output=framed)
    records = parse_records(framed.getvalue())
    return command_result_from_records(records, target, status)


def command_result_from_records(records: list[dict[str, object]], target: str,
                                backend_status: int = 0) -> CommandResult:
    terminals = [record for record in records if record.get("type") == "terminal"]
    if len(terminals) != 1:
        raise ToolError(f"invalid PowerShell runner terminal count ({len(terminals)})")
    if not records or records[-1] is not terminals[0]:
        final_type = records[-1].get("type") if records else None
        raise ToolError(f"invalid PowerShell runner terminal order (final record: {final_type!r})")
    terminal = terminals[0]
    protocol_records = [record for record in records if record.get("type") == "protocol_error"]
    structured_protocol_failures = {"timeout", "receive_budget"}
    if protocol_records and terminal.get("failure") not in structured_protocol_failures:
        raise ToolError("PowerShell runner response contains a protocol error")
    if protocol_records and not isinstance(terminal.get("message"), str):
        raise ToolError("structured failure omitted preceding protocol-error details")
    ordered = [record for record in records if record.get("type") in ("output", "diagnostic")]
    output_parts: list[str] = []
    for record in ordered:
        output_parts.append(str(record.get("text", "")))
        delimiters = record.get("trailing_delimiter_bytes", 0)
        if isinstance(delimiters, int) and not isinstance(delimiters, bool) and delimiters > 0:
            output_parts.append("\n" * delimiters)
    output_text = "".join(output_parts)
    result = CommandResult(host=target, output=output_text, records=records)
    result.output_complete = terminal.get("output_complete") is True
    exit_code = terminal.get("exit_code")
    result.exit_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None
    transport_exit_code = terminal.get("transport_exit_code")
    result.transport_exit_code = (transport_exit_code if isinstance(transport_exit_code, int) and
                                  not isinstance(transport_exit_code, bool) else None)
    failure = terminal.get("failure")
    result.failure = failure if isinstance(failure, str) else None
    message = terminal.get("message")
    result.message = message if isinstance(message, str) else None
    timeout = terminal.get("timeout_seconds")
    result.timeout_seconds = timeout if isinstance(timeout, int) and not isinstance(timeout, bool) else None
    result.partial = terminal.get("partial") is True
    result.cancellation_unconfirmed = terminal.get("cancellation_unconfirmed") is True
    for name in ("duration_ms", "observed_lines", "observed_bytes", "emitted_lines", "emitted_bytes",
                 "filter_suppressed_lines", "filter_suppressed_bytes", "line_suppressed_lines",
                 "line_suppressed_bytes", "byte_suppressed_lines", "byte_suppressed_bytes"):
        value = terminal.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            setattr(result, name, value)
    result.ok = result.failure is None and result.exit_code == 0 and backend_status == 0
    return result


def public_result(result: CommandResult, include_raw_records: bool = False) -> PublicCommandResult:
    response: dict[str, object] = {"output": result.output}
    if result.exit_code != 0:
        response["exit_code"] = result.exit_code
    if not result.output_complete:
        response["output_complete"] = False
    if result.transport_exit_code is not None:
        response["transport_exit_code"] = result.transport_exit_code
    if result.failure is not None:
        response["failure"] = result.failure
    if result.message is not None:
        response["message"] = result.message
    if result.timeout_seconds is not None:
        response["timeout_seconds"] = result.timeout_seconds
    if result.partial:
        response["partial"] = True
    if result.cancellation_unconfirmed:
        response["cancellation_unconfirmed"] = True

    suppression = {
        "filter_suppressed_lines": result.filter_suppressed_lines,
        "filter_suppressed_bytes": result.filter_suppressed_bytes,
        "line_suppressed_lines": result.line_suppressed_lines,
        "line_suppressed_bytes": result.line_suppressed_bytes,
        "byte_suppressed_lines": result.byte_suppressed_lines,
        "byte_suppressed_bytes": result.byte_suppressed_bytes,
    }
    if any(suppression.values()):
        for name, value in suppression.items():
            response[name] = value
        response["observed_lines"] = result.observed_lines
        response["observed_bytes"] = result.observed_bytes
        response["emitted_lines"] = result.emitted_lines
        response["emitted_bytes"] = result.emitted_bytes
    if include_raw_records:
        response["records"] = result.records
    return cast(PublicCommandResult, response)


def display_result(result: CommandResult, include_raw_records: bool = False) -> CallToolResult:
    structured = public_result(result, include_raw_records)
    text = result.output
    if result.exit_code not in (None, 0):
        suffix = f"Process exited with code {result.exit_code}"
        text = f"{text}{'' if not text or text.endswith(chr(10)) else chr(10)}{suffix}"
    elif result.failure is not None and result.exit_code is None:
        suffix = f"PowerShell execution failed: {result.failure}"
        text = f"{text}{'' if not text or text.endswith(chr(10)) else chr(10)}{suffix}"
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=False,
    )


mcp = MCPServer("powershell", instructions="Run bounded PowerShell on explicit local or registered SSH targets; command failures are structured results, not tool errors.")

@mcp.tool(structured_output=True)
def list_powershell_targets() -> dict[str, list[dict[str, str]]]:
    """List public-safe explicit local and registered SSH target identifiers."""
    targets = [{"id": "local", "kind": "local"}]
    targets.extend({"id": f"ssh:{alias}", "kind": "ssh"} for alias in load_hosts())
    return {"targets": targets}


@mcp.tool()
def powershell_status(target: str, include_raw_records: bool = False) -> CallToolResult:
    """Check an explicit local or registered SSH PowerShell target."""
    require_target(target)
    script = "$PSVersionTable.PSVersion.ToString(); [Environment]::MachineName"
    result = run_target(target, script, 2, 4096, None, 30)
    return display_result(result, include_raw_records)


@mcp.tool()
def powershell_run(target: str, script: str, max_lines: int = 40,
                   max_bytes: int = 65536, filter: str | None = None,
                   timeout_seconds: int = 120,
                   include_raw_records: bool = False) -> PublicCommandResult:
    """Run bounded PowerShell on target='local' or target='ssh:<registered-alias>'."""
    require_target(target)
    if not script.strip(): raise ToolError("PowerShell script must not be empty")
    if not 0 <= max_lines <= _MAX_LINES: raise ToolError(f"max_lines must be between 0 and {_MAX_LINES}")
    if not 1 <= max_bytes <= _MAX_BYTES: raise ToolError(f"max_bytes must be between 1 and {_MAX_BYTES}")
    if not 1 <= timeout_seconds <= _MAX_TIMEOUT_SECONDS: raise ToolError(f"timeout_seconds must be between 1 and {_MAX_TIMEOUT_SECONDS}")
    if filter == "": raise ToolError("filter must not be empty when provided")
    return display_result(run_target(target, script, max_lines, max_bytes, filter, timeout_seconds),
                          include_raw_records)




def main() -> None: mcp.run("stdio", show_banner=False)
if __name__ == "__main__": main()
