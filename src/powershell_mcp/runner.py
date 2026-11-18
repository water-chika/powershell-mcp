"""Structured SSH transport used by wsh-jsonseq, wsh, and the MCP adapter."""

from __future__ import annotations

import argparse
import base64
import codecs
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, cast

RS = b"\x1e"
_DEFAULT_LINES = 40
_DEFAULT_BYTES = 64 * 1024
_MAX_LINES = 100_000
_MAX_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT = 600
_BANNER = re.compile(
    r"^\*\* (?:WARNING: connection|This session may be|The server may need)"
)
_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class UsageError(ValueError):
    """Invalid local request."""


@dataclass(frozen=True)
class Host:
    alias: str
    spec: str
    mode: str = "powershell"
    transport: str = "ssh"


def registry_path() -> Path:
    return Path(os.environ.get("POWERSHELL_MCP_REGISTRY", "~/.config/powershell-mcp/targets.conf")).expanduser()


def load_registry(path: Path | None = None) -> dict[str, Host]:
    source = path or registry_path()
    if not source.is_file():
        return {}
    result: dict[str, Host] = {}
    for number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [part.strip() for part in line.split("|")]
        if len(fields) < 2 or not fields[0] or not fields[1]:
            raise UsageError(f"malformed wsh host registry line {number}")
        if len(fields) > 3:
            raise UsageError(f"too many fields in PowerShell target registry line {number}")
        alias, spec = fields[:2]
        mode = fields[2] if len(fields) > 2 and fields[2] else "powershell"
        if alias == "local":
            raise UsageError("reserved target alias 'local' cannot appear in the SSH registry")
        if not _ALIAS.fullmatch(alias):
            raise UsageError(f"invalid wsh host alias on line {number}")
        if alias in result:
            raise UsageError(f"duplicate wsh host alias '{alias}'")
        if mode != "powershell":
            raise UsageError(f"bad payload language '{mode}' for host '{alias}' (expected powershell)")
        result[alias] = Host(alias, spec, mode)
    return result


def resolve_host(alias: str, *, registered_only: bool = False) -> Host:
    hosts = load_registry()
    if alias in hosts:
        return hosts[alias]
    if registered_only:
        raise UsageError(f"unknown wsh host alias '{alias}'")
    return Host(alias, alias, "powershell")


def resolve_target(target: str, path: Path | None = None) -> Host:
    if target == "local":
        configured = os.environ.get("POWERSHELL_MCP_PWSH")
        executable = configured or shutil.which("pwsh") or str(Path.home() / ".local/bin/pwsh")
        path = Path(executable).expanduser()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise UsageError(f"local PowerShell executable is unavailable: {path}")
        return Host("local", str(path.resolve()), "powershell", "local")
    if target.startswith("ssh:"):
        alias = target[4:]
        if not _ALIAS.fullmatch(alias):
            raise UsageError(f"invalid PowerShell SSH target '{target}'")
        if alias == "local":
            raise UsageError("reserved target 'local' cannot be used as an SSH alias")
        hosts = load_registry(path)
        if alias not in hosts:
            raise UsageError(f"unknown wsh host alias '{alias}'")
        return hosts[alias]
    raise UsageError(f"invalid PowerShell target '{target}' (expected 'local' or 'ssh:<alias>')")


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode("ascii")


def _ps_encoded(value: str) -> str:
    return base64.b64encode(value.encode("utf-16le")).decode("ascii")


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_remote_script(
    script: str,
    mode: str,
    max_lines: int,
    max_bytes: int,
    pattern: str | None,
    powershell_executable: str = "pwsh.exe",
) -> str:
    """Build a streaming target program with finite target-side budgets."""
    if mode != "powershell":
        raise UsageError("mode must be powershell")
    if not 0 <= max_lines <= _MAX_LINES:
        raise UsageError(f"max_lines must be between 0 and {_MAX_LINES}")
    if not 1 <= max_bytes <= _MAX_BYTES:
        raise UsageError(f"max_bytes must be between 1 and {_MAX_BYTES}")
    if mode == "powershell":
        # Redirect the child process's two OS streams and consume whichever line
        # becomes readable first. PowerShell's pipeline merger can defer ErrorRecord
        # formatting and reorder stderr behind later stdout.
        invoke = f"""
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$psi=[Diagnostics.ProcessStartInfo]::new()
$psi.FileName={_ps_literal(powershell_executable)}
$psi.UseShellExecute=$false
$psi.RedirectStandardOutput=$true
$psi.RedirectStandardError=$true
$psi.ArgumentList.Add('-NoLogo'); $psi.ArgumentList.Add('-NoProfile'); $psi.ArgumentList.Add('-NonInteractive')
$psi.ArgumentList.Add('-OutputFormat'); $psi.ArgumentList.Add('Text')
$psi.ArgumentList.Add('-EncodedCommand'); $psi.ArgumentList.Add($encoded)
$child=[Diagnostics.Process]::new(); $child.StartInfo=$psi
if (-not $child.Start()) {{ throw 'failed to start child PowerShell' }}
$outBuffer=[char[]]::new(4096); $errBuffer=[char[]]::new(4096)
$outTask=$child.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length); $errTask=$child.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)
try {{
  while (($null -ne $outTask) -or ($null -ne $errTask)) {{
    $tasks=[Collections.Generic.List[Threading.Tasks.Task[int]]]::new()
    if ($null -ne $outTask) {{ $tasks.Add($outTask) }}; if ($null -ne $errTask) {{ $tasks.Add($errTask) }}
    $completed=[Threading.Tasks.Task]::WhenAny([Threading.Tasks.Task[int][]]$tasks.ToArray()).GetAwaiter().GetResult()
    if ([object]::ReferenceEquals($completed, $outTask)) {{
      $count=$outTask.GetAwaiter().GetResult()
      if ($count -eq 0) {{ Observe-Text '' 'stdout' $true; $outTask=$null }}
      else {{ Observe-Text ([string]::new($outBuffer,0,$count)) 'stdout' $false; $outTask=$child.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length) }}
    }} else {{
      $count=$errTask.GetAwaiter().GetResult()
      if ($count -eq 0) {{ Observe-Text '' 'stderr' $true; $errTask=$null }}
      else {{ Observe-Text ([string]::new($errBuffer,0,$count)) 'stderr' $false; $errTask=$child.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length) }}
    }}
  }}
  $child.WaitForExit(); $script:nativeRc=$child.ExitCode
}} finally {{
  if (-not $child.HasExited) {{ $child.Kill($true); $child.WaitForExit(2000) | Out-Null }}
  $child.Dispose()
}}
"""
    filter_expr = "$null" if pattern is None else _ps_literal(pattern)
    # The wire format is itself RFC 7464. Console.Write bypasses PowerShell's
    # CLIXML serializer and flushes every observed line before the next arrives.
    return f"""$ProgressPreference='SilentlyContinue'
try {{ [Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8 }} catch {{}}
$command=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{_b64(script)}'))
$pattern={filter_expr}; $lineLimit={max_lines}; $byteLimit={max_bytes}
$script:seenLines=0; $script:seenBytes=0; $script:sentLines=0; $script:sentBytes=0; $script:seq=0
$script:filterLines=0; $script:filterBytes=0; $script:lineLines=0; $script:lineBytes=0; $script:byteLines=0; $script:byteBytes=0
$script:hadError=$false; $script:nativeRc=$null
$script:pendingText=@{{stdout='';stderr=''}}
$script:droppingLine=@{{stdout=$false;stderr=$false}}; $script:droppedLineBytes=@{{stdout=0;stderr=0}}
$script:outputStream=$null; $script:outputLines=[Collections.Generic.List[string]]::new(); $script:outputBatchBytes=0; $script:outputBatchDelimiterBytes=0
function Send-Record([hashtable]$record) {{
  $script:seq++; $record.sequence=$script:seq; $record.source='remote'
  $json=$record | ConvertTo-Json -Compress -Depth 5
  [Console]::Out.Write([char]0x1e); [Console]::Out.Write($json); [Console]::Out.Write("`n"); [Console]::Out.Flush()
}}
$regex=$null
if ($null -ne $pattern) {{
  try {{ $regex=[regex]::new($pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(100)) }}
  catch {{ Send-Record @{{type='exit'; exit_code=2; message=('wsh: bad -f pattern: ' + $_.Exception.Message); observed_lines=0; observed_bytes=0; emitted_lines=0; emitted_bytes=0; filter_suppressed_lines=0; filter_suppressed_bytes=0; line_suppressed_lines=0; line_suppressed_bytes=0; byte_suppressed_lines=0; byte_suppressed_bytes=0}}; exit 2 }}
}}
function Flush-Output {{
  if ($script:outputLines.Count -gt 0) {{
    $text=$script:outputLines -join "`n"
    $internalDelimiterBytes=[Math]::Max(0,$script:outputLines.Count-1)
    $trailingDelimiterBytes=$script:outputBatchDelimiterBytes-$internalDelimiterBytes
    Send-Record @{{type='output'; stream=$script:outputStream; text=$text; line_count=$script:outputLines.Count; byte_count=$script:outputBatchBytes; trailing_delimiter_bytes=$trailingDelimiterBytes}}
    $script:outputLines.Clear(); $script:outputBatchBytes=0; $script:outputBatchDelimiterBytes=0
  }}
}}
function Observe-Text([string]$text, [string]$stream, [bool]$final) {{
  $combined=$script:pendingText[$stream] + $text
  $start=0
  for ($i=0; $i -lt $combined.Length; $i++) {{
    if ($combined[$i] -eq "`n") {{
      $length=$i-$start; if (($length -gt 0) -and ($combined[$i-1] -eq "`r")) {{ $length-- }}
      $segment=$combined.Substring($start,$length)
      if ($script:droppingLine[$stream]) {{
        $script:droppedLineBytes[$stream] += [Text.Encoding]::UTF8.GetByteCount($segment) + 1
        $script:seenLines++; $script:seenBytes += $script:droppedLineBytes[$stream]
        $script:byteLines++; $script:byteBytes += $script:droppedLineBytes[$stream]
        $script:droppingLine[$stream]=$false; $script:droppedLineBytes[$stream]=0
      }} else {{ Observe-Line $segment $stream $true }}
      $start=$i+1
    }}
  }}
  $remaining=$combined.Substring($start)
  $remainingBytes=[Text.Encoding]::UTF8.GetByteCount($remaining)
  if ($script:droppingLine[$stream]) {{
    $script:droppedLineBytes[$stream] += $remainingBytes
    $script:pendingText[$stream]=''
    if ($final) {{
      $script:seenLines++; $script:seenBytes += $script:droppedLineBytes[$stream]
      $script:byteLines++; $script:byteBytes += $script:droppedLineBytes[$stream]
      $script:droppingLine[$stream]=$false; $script:droppedLineBytes[$stream]=0
    }}
  }} elseif ($final) {{
    if ($remaining.Length -gt 0) {{ Observe-Line $remaining $stream $false }}
    $script:pendingText[$stream]=''
  }} elseif ($remainingBytes -gt $byteLimit) {{
    $script:droppingLine[$stream]=$true; $script:droppedLineBytes[$stream]=$remainingBytes
    $script:pendingText[$stream]=''
  }} else {{
    $script:pendingText[$stream]=$remaining
  }}
}}
function Observe-Line([string]$line, [string]$stream, [bool]$hadDelimiter) {{
      if ($stream -eq 'stderr') {{ $script:hadError=$true }}
      $bytes=[Text.Encoding]::UTF8.GetByteCount($line) + $(if ($hadDelimiter) {{1}} else {{0}})
      try {{ $matched=($null -eq $regex) -or $regex.IsMatch($line) }}
      catch [Text.RegularExpressions.RegexMatchTimeoutException] {{ throw 'filter regular expression timed out' }}
      $script:seenLines++; $script:seenBytes += $bytes
      $withinLines=($lineLimit -eq 0) -or ($script:sentLines -lt $lineLimit)
      $withinBytes=($script:sentBytes + $bytes -le $byteLimit)
      if (-not $matched) {{ $script:filterLines++; $script:filterBytes += $bytes }}
      elseif (-not $withinLines) {{ $script:lineLines++; $script:lineBytes += $bytes }}
      elseif (-not $withinBytes) {{ $script:byteLines++; $script:byteBytes += $bytes }}
      else {{
        if (($script:outputStream -ne $stream) -or
            ($script:outputLines.Count -ge 255) -or
            ($script:outputBatchBytes + $bytes -gt 8192)) {{ Flush-Output }}
        if ($script:outputLines.Count -eq 0) {{ $script:outputStream=$stream }}
        $script:outputLines.Add($line); $script:outputBatchBytes += $bytes
        if ($hadDelimiter) {{ $script:outputBatchDelimiterBytes++ }}
        $script:sentLines++; $script:sentBytes += $bytes
      }}
}}
try {{ {invoke}; Flush-Output }}
catch {{
  Flush-Output
  $diagnostic=$_.ToString(); $diagnosticBytes=[Text.Encoding]::UTF8.GetByteCount($diagnostic)
  Send-Record @{{type='diagnostic'; stream='stderr'; text=$diagnostic; line_count=1; byte_count=$diagnosticBytes; trailing_delimiter_bytes=0}}
  if ($script:nativeRc -eq $null) {{ $script:nativeRc=1 }}
}}
$rc=$script:nativeRc
if ($rc -eq $null) {{ $rc=if ($script:hadError) {{1}} else {{0}} }}
Send-Record @{{type='exit'; exit_code=[int64]$rc; observed_lines=$script:seenLines; observed_bytes=$script:seenBytes; emitted_lines=$script:sentLines; emitted_bytes=$script:sentBytes; filter_suppressed_lines=$script:filterLines; filter_suppressed_bytes=$script:filterBytes; line_suppressed_lines=$script:lineLines; line_suppressed_bytes=$script:lineBytes; byte_suppressed_lines=$script:byteLines; byte_suppressed_bytes=$script:byteBytes}}
exit [int]$rc
"""


def ssh_argv(host: Host, remote_script: str) -> list[str]:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / "wsh"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    import hashlib
    control = runtime / hashlib.sha256(host.spec.encode()).hexdigest()[:32]
    opts = [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto",
        "-o", f"ControlPath={control}", "-o", f"ControlPersist={os.environ.get('POWERSHELL_MCP_SSH_PERSIST', '600')}",
    ]
    # specs intentionally support the same shell-like host registry as legacy wsh.
    import shlex
    return ["ssh", *opts, *shlex.split(host.spec),
            f"pwsh.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {_ps_encoded(remote_script)}"]


def launch_argv(host: Host, remote_script: str) -> list[str]:
    if host.transport == "local":
        return [host.spec, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                _ps_encoded(remote_script)]
    return ssh_argv(host, remote_script)


def write_record(stream: BinaryIO, record: dict[str, object]) -> None:
    stream.write(RS + json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")
    stream.flush()


class SequenceParser:
    """Incremental RFC 7464 parser with bounded framing diagnostics."""

    def __init__(self, maximum_record_bytes: int = _MAX_BYTES * 6 + 65536) -> None:
        self.buffer = bytearray()
        self.maximum_record_bytes = maximum_record_bytes

    def feed(self, data: bytes) -> Iterator[dict[str, object]]:
        self.buffer.extend(data)
        while True:
            start = self.buffer.find(RS)
            if start < 0:
                if len(self.buffer) > 8192:
                    del self.buffer[:-8192]
                return
            if start:
                garbage = bytes(self.buffer[:start])
                del self.buffer[:start]
                if garbage.strip():
                    yield {"type": "protocol_error", "message": "unframed bytes before JSON sequence record"}
            end = self.buffer.find(b"\n", 1)
            if end < 0:
                if len(self.buffer) > self.maximum_record_bytes:
                    self.buffer.clear()
                    yield {"type": "protocol_error", "message": "JSON sequence record exceeds maximum size"}
                return
            if end - 1 > self.maximum_record_bytes:
                del self.buffer[: end + 1]
                yield {"type": "protocol_error", "message": "JSON sequence record exceeds maximum size"}
                continue
            raw = bytes(self.buffer[1:end])
            del self.buffer[: end + 1]
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                yield {"type": "protocol_error", "message": f"invalid JSON sequence record: {exc}"}
                continue
            if isinstance(value, dict):
                yield value
            else:
                yield {"type": "protocol_error", "message": "JSON sequence record is not an object"}

    def finish(self) -> Iterator[dict[str, object]]:
        """Report an incomplete final record instead of silently dropping it."""
        if self.buffer.strip():
            self.buffer.clear()
            yield {"type": "protocol_error", "message": "incomplete JSON sequence record at EOF"}


def execute(
    host: Host,
    script: str,
    *,
    mode: str,
    max_lines: int,
    max_bytes: int,
    pattern: str | None,
    timeout: int,
    output: BinaryIO,
) -> int:
    inner_powershell = host.spec if host.transport == "local" else "pwsh.exe"
    remote = build_remote_script(script, mode, max_lines, max_bytes, pattern, inner_powershell)
    argv = launch_argv(host, remote)
    if os.environ.get("POWERSHELL_MCP_DRYRUN"):
        write_record(output, {"type": "request", "host": host.alias, "remote_script": remote, "argv": argv})
        return 0
    started = time.monotonic()
    local_sequence = 0

    def emit(record: dict[str, object]) -> None:
        nonlocal local_sequence
        local_sequence += 1
        remote_sequence = record.get("sequence")
        if record.get("source") == "remote" and isinstance(remote_sequence, int):
            record["remote_sequence"] = remote_sequence
        record["sequence"] = local_sequence
        record.setdefault("source", "transport")
        write_record(output, record)

    emit({"type": "start", "version": 1, "host": host.alias, "mode": mode})
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        emit({"type": "terminal", "failure": "transport_start", "message": str(exc),
              "exit_code": None, "transport_exit_code": 127, "output_complete": False,
              "duration_ms": round((time.monotonic() - started) * 1000)})
        return 127

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    parser = SequenceParser(maximum_record_bytes=max(_MAX_BYTES * 6 + 65536, max_bytes * 6 + 65536))
    request_deadline = time.monotonic() + timeout
    termination_deadline: float | None = None
    drain_deadline: float | None = None
    remote_exit_count = 0
    pending_exit: dict[str, object] | None = None
    saw_remote_exit = False
    expected_remote_sequence = 1
    protocol_errors: list[str] = []
    protocol_error_overflow = 0
    stderr_decoder = codecs.getincrementaldecoder("utf-8")("replace")
    stderr_text = ""
    diagnostic_lines = 0
    diagnostic_bytes = 0
    diagnostic_suppressed = 0
    raw_stdout_bytes = 0
    maximum_output_records = min(max_lines if max_lines else max_bytes, max_bytes)
    receive_limit = max_bytes * 6 + maximum_output_records * 256 + 65536
    cancellation_reason: str | None = None

    def emit_stderr_lines(text: str, *, final: bool = False) -> str:
        nonlocal diagnostic_lines, diagnostic_bytes, diagnostic_suppressed
        lines = text.splitlines(keepends=True)
        if not final and lines and not lines[-1].endswith(("\n", "\r")):
            remainder = lines.pop()
            if len(remainder) > 4096:
                lines.append(remainder[:4096])
                remainder = ""
        else:
            remainder = ""
        for line in lines:
            clean = line.rstrip("\r\n")[:4096]
            encoded_bytes = len(clean.encode("utf-8"))
            if clean and not _BANNER.match(clean):
                if diagnostic_lines < 40 and diagnostic_bytes + encoded_bytes <= 65536:
                    emit({"type": "diagnostic", "stream": "stderr", "text": clean})
                    diagnostic_lines += 1
                    diagnostic_bytes += encoded_bytes
                else:
                    diagnostic_suppressed += 1
        return remainder

    def add_protocol_error(message: str) -> None:
        nonlocal protocol_error_overflow
        if len(protocol_errors) < 16 and sum(map(len, protocol_errors)) + len(message) <= 4096:
            protocol_errors.append(message)
        else:
            protocol_error_overflow += 1

    protocol_diagnostics_emitted = 0
    protocol_diagnostic_bytes = 0
    received_output_lines = 0
    received_output_bytes = 0

    def handle_remote_record(record: dict[str, object]) -> None:
        nonlocal remote_exit_count, pending_exit, saw_remote_exit, expected_remote_sequence
        nonlocal protocol_diagnostics_emitted, protocol_diagnostic_bytes
        nonlocal received_output_lines, received_output_bytes
        record_type = record.get("type")
        if record_type == "protocol_error":
            message = str(record.get("message", "remote protocol error"))[:1024]
            add_protocol_error(message)
            encoded_size = len(message.encode("utf-8"))
            if protocol_diagnostics_emitted < 8 and protocol_diagnostic_bytes + encoded_size <= 4096:
                emit({"type": "protocol_error", "message": message})
                protocol_diagnostics_emitted += 1
                protocol_diagnostic_bytes += encoded_size
            return
        if record_type == "diagnostic":
            stream = record.get("stream")
            text = record.get("text")
            if stream not in ("stdout", "stderr") or not isinstance(text, str):
                add_protocol_error("invalid diagnostic record fields")
                return
        elif record_type not in ("output", "exit"):
            add_protocol_error(f"unexpected remote record type {record_type!r}")
            return
        if record_type in ("output", "diagnostic"):
            stream = record.get("stream")
            text = record.get("text")
            line_count = record.get("line_count")
            byte_count = record.get("byte_count")
            trailing_delimiter_bytes = record.get("trailing_delimiter_bytes")
            fields_valid = (
                stream in ("stdout", "stderr") and isinstance(text, str) and
                isinstance(line_count, int) and not isinstance(line_count, bool) and line_count >= 1 and
                isinstance(byte_count, int) and not isinstance(byte_count, bool) and byte_count >= 0 and
                isinstance(trailing_delimiter_bytes, int) and not isinstance(trailing_delimiter_bytes, bool) and
                trailing_delimiter_bytes >= 0
            )
            if fields_valid:
                text_value = cast(str, text)
                lines_value = cast(int, line_count)
                bytes_value = cast(int, byte_count)
                delimiters_value = cast(int, trailing_delimiter_bytes)
                expected_lines = text_value.count("\n") + 1
                expected_bytes = len(text_value.encode("utf-8")) + delimiters_value
                fields_valid = (lines_value == expected_lines and
                                delimiters_value in (0, 1) and bytes_value == expected_bytes)
            if not fields_valid:
                add_protocol_error(f"invalid {record_type} record fields")
                return
        sequence = record.get("sequence")
        record_valid = True
        if (not isinstance(sequence, int) or isinstance(sequence, bool) or
                sequence != expected_remote_sequence):
            add_protocol_error(
                f"remote sequence mismatch: expected {expected_remote_sequence}, received {sequence!r}")
            record_valid = False
        else:
            expected_remote_sequence += 1
        if record.get("source") != "remote":
            add_protocol_error(f"invalid remote record source {record.get('source')!r}")
            record_valid = False
        if not record_valid:
            return
        if record_type == "exit":
            remote_exit_count += 1
            saw_remote_exit = True
            if pending_exit is None:
                pending_exit = dict(record)
            return
        if saw_remote_exit:
            add_protocol_error(f"remote {record_type!r} record followed exit")
            return
        if record_type == "output":
            received_output_lines += cast(int, record["line_count"])
            received_output_bytes += cast(int, record["byte_count"])
        emit(record)

    try:
        while selector.get_map():
            now = time.monotonic()
            if not cancellation_reason and now >= request_deadline:
                cancellation_reason = "timeout"
                if proc.poll() is None:
                    termination_deadline = now + 2.0
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                elif drain_deadline is None:
                    drain_deadline = now + 2.0
            if cancellation_reason and termination_deadline is not None and now >= termination_deadline:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                termination_deadline = None
                drain_deadline = now + 2.0
            if proc.poll() is not None and drain_deadline is None:
                drain_deadline = now + 2.0
            if drain_deadline is not None and now >= drain_deadline:
                add_protocol_error("transport pipes did not reach EOF after process exit")
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    cast(BinaryIO, key.fileobj).close()
                if stderr_text:
                    stderr_text = emit_stderr_lines(stderr_text, final=True)
                break

            wakeups = [now + 0.2]
            if not cancellation_reason:
                wakeups.append(request_deadline)
            if termination_deadline is not None:
                wakeups.append(termination_deadline)
            if drain_deadline is not None:
                wakeups.append(drain_deadline)
            events = selector.select(max(0.0, min(wakeups) - now))
            for key, _ in events:
                fileobj = cast(BinaryIO, key.fileobj)
                data = os.read(fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    fileobj.close()
                    if key.data == "stdout":
                        for record in parser.finish():
                            handle_remote_record(record)
                    else:
                        stderr_text += stderr_decoder.decode(b"", final=True)
                        stderr_text = emit_stderr_lines(stderr_text, final=True)
                    continue
                if key.data == "stdout":
                    if cancellation_reason is not None:
                        continue
                    raw_stdout_bytes += len(data)
                    if raw_stdout_bytes > receive_limit and cancellation_reason is None:
                        cancellation_reason = "receive_budget"
                        add_protocol_error(
                            f"receive-side byte budget exceeded ({raw_stdout_bytes}>{receive_limit})")
                        termination_deadline = time.monotonic() + 2.0
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        continue
                    for record in parser.feed(data):
                        handle_remote_record(record)
                else:
                    stderr_text += stderr_decoder.decode(data)
                    stderr_text = emit_stderr_lines(stderr_text)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        selector.close()

    try:
        transport_rc = proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            transport_rc = proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            transport_rc = None
        add_protocol_error("transport process did not terminate after forced cancellation")

    duration_ms = round((time.monotonic() - started) * 1000)
    if diagnostic_suppressed:
        emit({"type": "diagnostic", "stream": "stderr",
              "text": f"{diagnostic_suppressed} additional transport diagnostics suppressed"})
    if cancellation_reason:
        terminal: dict[str, object] = {
            "type": "terminal", "failure": cancellation_reason,
            "partial": True, "output_complete": False, "exit_code": None,
            "transport_exit_code": transport_rc, "cancellation_unconfirmed": True,
            "duration_ms": duration_ms,
        }
        if cancellation_reason == "timeout":
            terminal["timeout_seconds"] = timeout
        if protocol_errors or protocol_error_overflow:
            details = list(protocol_errors)
            if protocol_error_overflow:
                details.append(f"{protocol_error_overflow} additional protocol errors suppressed")
            terminal["message"] = f"transport protocol errors before {cancellation_reason}: " + "; ".join(details)
        emit(terminal)
        return 124 if cancellation_reason == "timeout" else 1

    pending_exit_code = pending_exit.get("exit_code") if pending_exit is not None else None
    if host.transport == "ssh" and transport_rc != 0 and pending_exit_code == 0:
        add_protocol_error(f"SSH transport exited with status {transport_rc!r} after remote success")

    if (remote_exit_count != 1) or protocol_errors or (pending_exit is None):
        details = list(protocol_errors)
        if protocol_error_overflow:
            details.append(f"{protocol_error_overflow} additional protocol errors suppressed")
        if remote_exit_count != 1:
            details.append(f"expected exactly one remote exit record, received {remote_exit_count}")
        emit({"type": "terminal", "failure": "protocol", "message": "; ".join(details),
              "transport_exit_code": transport_rc, "exit_code": None,
              "output_complete": False, "duration_ms": duration_ms})
        return transport_rc or 1

    terminal = dict(cast(dict[str, object], pending_exit))
    exit_code = terminal.get("exit_code")
    counter_names = ("observed_lines", "observed_bytes", "emitted_lines", "emitted_bytes",
                     "filter_suppressed_lines", "filter_suppressed_bytes", "line_suppressed_lines",
                     "line_suppressed_bytes", "byte_suppressed_lines", "byte_suppressed_bytes")
    invalid_fields = [name for name in counter_names if name not in terminal]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        invalid_fields.append("exit_code")
    for name in counter_names:
        value = terminal.get(name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            invalid_fields.append(name)
    if not invalid_fields:
        if terminal["emitted_lines"] != received_output_lines:
            invalid_fields.append("emitted_lines_mismatch")
        if terminal["emitted_bytes"] != received_output_bytes:
            invalid_fields.append("emitted_bytes_mismatch")
        if terminal["observed_lines"] != (terminal["emitted_lines"] + terminal["filter_suppressed_lines"] +
                                           terminal["line_suppressed_lines"] + terminal["byte_suppressed_lines"]):
            invalid_fields.append("observed_lines_mismatch")
        if terminal["observed_bytes"] != (terminal["emitted_bytes"] + terminal["filter_suppressed_bytes"] +
                                           terminal["line_suppressed_bytes"] + terminal["byte_suppressed_bytes"]):
            invalid_fields.append("observed_bytes_mismatch")
    if invalid_fields:
        emit({"type": "terminal", "failure": "protocol",
              "message": "invalid remote exit fields: " + ", ".join(invalid_fields),
              "transport_exit_code": transport_rc, "exit_code": None,
              "output_complete": False, "duration_ms": duration_ms})
        return transport_rc or 1
    suppressed = [terminal.get(key, 0) for key in
                  ("filter_suppressed_lines", "line_suppressed_lines", "byte_suppressed_lines")]
    terminal["type"] = "terminal"
    remote_sequence = terminal.get("sequence")
    if isinstance(remote_sequence, int) and not isinstance(remote_sequence, bool):
        terminal["remote_sequence"] = remote_sequence
    terminal["source"] = "transport"
    terminal["duration_ms"] = duration_ms
    terminal["output_complete"] = not any(value for value in suppressed if isinstance(value, int))
    terminal["failure"] = None if exit_code == 0 else "remote_exit"
    terminal["transport_exit_code"] = None
    emit(terminal)
    return 0


def backend_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wsh-jsonseq", description="Run a Windows command and emit RFC 7464 JSON text sequences")
    parser.add_argument("--mode", choices=("powershell",))
    parser.add_argument("--max-lines", type=int, default=_DEFAULT_LINES)
    parser.add_argument("--max-bytes", type=int, default=_DEFAULT_BYTES)
    parser.add_argument("--filter")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("POWERSHELL_MCP_TIMEOUT", "120")))
    parser.add_argument("--script-stdin", action="store_true")
    parser.add_argument("--registered-only", action="store_true")
    parser.add_argument("host")
    parser.add_argument("script", nargs="?")
    return parser


def backend_main(argv: list[str] | None = None) -> int:
    args = backend_parser().parse_args(argv)
    try:
        if args.script_stdin:
            if args.script is not None:
                raise UsageError("script argument conflicts with --script-stdin")
            try:
                stdin_buffer = getattr(sys.stdin, "buffer", None)
                script = (stdin_buffer.read().decode("utf-8", "strict")
                          if stdin_buffer is not None else sys.stdin.read())
            except UnicodeDecodeError as exc:
                raise UsageError(f"script stdin is not valid UTF-8: {exc}") from exc
        else:
            if args.script is None:
                raise UsageError("script is required (or use --script-stdin)")
            script = args.script
        if not script.strip():
            raise UsageError("script must not be empty")
        if "\x00" in script:
            raise UsageError("script must not contain NUL")
        if not 1 <= args.timeout <= _MAX_TIMEOUT:
            raise UsageError(f"timeout must be between 1 and {_MAX_TIMEOUT}")
        host = resolve_host(args.host, registered_only=args.registered_only)
        mode = args.mode or host.mode
        return execute(host, script, mode=mode, max_lines=args.max_lines,
                       max_bytes=args.max_bytes, pattern=args.filter,
                       timeout=args.timeout, output=sys.stdout.buffer)
    except UsageError as exc:
        write_record(sys.stdout.buffer, {"type": "request_error", "message": str(exc), "exit_code": 2})
        return 2


if __name__ == "__main__":
    raise SystemExit(backend_main())
