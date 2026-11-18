#!/usr/bin/env python3

import io
import os
import sys
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from powershell_mcp.runner import (Host, RS, SequenceParser, backend_main,
                               build_remote_script, execute, launch_argv, resolve_target)


def decode(data: bytes) -> list[dict]:
    parser = SequenceParser()
    records = list(parser.feed(data))
    records.extend(parser.finish())
    return records


class ScriptTests(unittest.TestCase):
    def test_child_stdin_is_disconnected(self) -> None:
        status, records = self.run_helper(r'''
            import json, sys
            value = sys.stdin.read()
            def record(item):
                if item.get("type") == "output":
                    item.setdefault("line_count", item.get("text", "").count("\n") + 1)
                    item.setdefault("trailing_delimiter_bytes", 1)
                    item.setdefault("byte_count", len(item.get("text", "").encode()) + item["trailing_delimiter_bytes"])
                sys.stdout.buffer.write(b"\x1e" + json.dumps(item).encode() + b"\n")
                sys.stdout.buffer.flush()
            record({"type":"process", "source":"remote", "sequence":1, "pid":1234, "started":133801632000000000})
            record({"type":"output", "source":"remote", "sequence":2,
                    "stream":"stdout", "text":"eof" if value == "" else "unexpected"})
            record({"type":"exit", "source":"remote", "sequence":3, "exit_code":0, "observed_lines":1, "observed_bytes":4, "emitted_lines":1, "emitted_bytes":4, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})
        ''')
        self.assertEqual(status, 0)
        self.assertIn("eof", [record.get("text") for record in records])

    def test_local_target_uses_direct_pwsh_without_shell(self) -> None:
        executable = Path(sys.executable)
        with patch.dict(os.environ, {"POWERSHELL_MCP_PWSH": str(executable)}):
            target = resolve_target("local")
        argv = launch_argv(target, "Write-Output ok")
        self.assertEqual(argv[0], str(executable.resolve()))
        self.assertNotIn("sh", argv[:1])
        self.assertIn("-EncodedCommand", argv)

    def test_target_budgets_and_framed_exit_are_built_in(self) -> None:
        script = build_remote_script('Write-Output "x"', "powershell", 12, 3456, "x y")
        self.assertIn("$lineLimit=12", script)
        self.assertIn("$byteLimit=3456", script)
        self.assertIn("$regex.IsMatch($line)", script)
        self.assertIn("type='exit'", script)
        self.assertIn("[Console]::Out.Write([char]0x1e)", script)

    def test_parser_accepts_fragmented_records(self) -> None:
        parser = SequenceParser()
        self.assertEqual(list(parser.feed(b"noise\x1e{\"type\":\"std"))[0]["type"], "protocol_error")
        self.assertEqual(list(parser.feed(b"out\",\"text\":\"ok\"}\n")),
                         [{"type": "stdout", "text": "ok"}])

    def run_helper(self, body: str, *, timeout: float = 5) -> tuple[int, list[dict]]:
        output = io.BytesIO()
        argv = [sys.executable, "-c", textwrap.dedent(body)]
        with patch("powershell_mcp.runner.launch_argv", return_value=argv):
            status = execute(Host("test", "unused", "powershell"), "Write-Output ignored",
                             mode="powershell", max_lines=40, max_bytes=65536,
                             pattern=None, timeout=timeout, output=output)
        return status, decode(output.getvalue())

    def test_late_stderr_precedes_single_terminal(self) -> None:
        status, records = self.run_helper(r'''
            import json, sys, time
            def record(value):
                if value.get("type") == "output":
                    value.setdefault("line_count", value.get("text", "").count("\n") + 1)
                    value.setdefault("trailing_delimiter_bytes", 1)
                    value.setdefault("byte_count", len(value.get("text", "").encode()) + value["trailing_delimiter_bytes"])
                sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n")
                sys.stdout.buffer.flush()
            record({"type":"process", "source":"remote", "sequence":1, "pid":1234, "started":133801632000000000})
            record({"type":"output", "source":"remote", "sequence":2,
                    "stream":"stdout", "text":"ok"})
            record({"type":"exit", "source":"remote", "sequence":3, "exit_code":0, "observed_lines":1, "observed_bytes":3, "emitted_lines":1, "emitted_bytes":3, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})
            time.sleep(0.05)
            sys.stderr.write("late diagnostic\n"); sys.stderr.flush()
        ''')
        self.assertEqual(status, 0)
        self.assertEqual(sum(record["type"] == "terminal" for record in records), 1)
        self.assertEqual(records[-1]["type"], "terminal")
        self.assertEqual([record["type"] for record in records],
                         ["start", "output", "diagnostic", "terminal"])
        self.assertEqual([record["sequence"] for record in records], list(range(1, 5)))

    def test_duplicate_missing_and_trailing_records_are_protocol_failures(self) -> None:
        cases = {
            "missing": 'record({"type":"output", "text":"x"})',
            "duplicate": 'record({"type":"exit", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0}); record({"type":"exit", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})',
            "trailing": 'record({"type":"exit", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0}); record({"type":"output", "text":"late"})',
            "incomplete": 'sys.stdout.buffer.write(b"\\x1e{\\\"type\\\":\\\"exit\\\""); sys.stdout.buffer.flush()',
            "bad-exit-type": 'record({"type":"exit", "exit_code":"0"})',
            "bad-counter": 'record({"type":"exit", "exit_code":0, "observed_lines":false, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})',
            "reserved-terminal": 'record({"type":"terminal", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0}); record({"type":"exit", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})',
            "unknown-type": 'record({"type":"mystery"}); record({"type":"exit", "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})',
            "bad-sequence": 'record({"type":"output", "source":"remote", "sequence":2, "text":"x"}); record({"type":"exit", "source":"remote", "sequence":1, "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})',
        }
        for name, statements in cases.items():
            with self.subTest(name=name):
                status, records = self.run_helper(f'''
                    import json, sys
                    def record(value):
                        if value.get("type") == "output":
                            value.setdefault("line_count", value.get("text", "").count("\n") + 1)
                            value.setdefault("trailing_delimiter_bytes", 1)
                            value.setdefault("byte_count", len(value.get("text", "").encode()) + value["trailing_delimiter_bytes"])
                        sys.stdout.buffer.write(b"\\x1e" + json.dumps(value).encode() + b"\\n")
                        sys.stdout.buffer.flush()
                    {statements}
                ''')
                self.assertNotEqual(status, 0)
                self.assertEqual(sum(record["type"] == "terminal" for record in records), 1)
                self.assertEqual(records[-1]["type"], "terminal")
                self.assertEqual(records[-1]["failure"], "protocol")

    def test_real_powershell_preserves_newline_free_and_blank_lines(self) -> None:
        from powershell_mcp.server import public_result, run_target
        no_newline = public_result(run_target("local", "[Console]::Out.Write('abcdefghij')", 40, 65536, None, 120))
        self.assertEqual(no_newline["output"], "abcdefghij")
        blank = public_result(run_target("local", "Write-Output ''; Write-Output x", 40, 65536, None, 120), True)
        texts = [record["text"] for record in blank["records"] if record.get("type") == "output"]
        self.assertEqual(texts, ["\nx"])

    def test_oversized_newline_free_line_is_fully_suppressed(self) -> None:
        from powershell_mcp.server import public_result, run_target
        result = public_result(run_target(
            "local", "[Console]::Out.Write('x' * 10000)", 40, 5000, None, 120
        ), True)
        self.assertEqual(result["output"], "")
        terminal = result["records"][-1]
        self.assertEqual(terminal["observed_lines"], 1)
        self.assertEqual(terminal["observed_bytes"], 10000)
        self.assertEqual(terminal["emitted_lines"], 0)
        self.assertEqual(terminal["byte_suppressed_lines"], 1)
        self.assertEqual(terminal["byte_suppressed_bytes"], 10000)

    def test_powershell_error_policy_follows_script_preferences(self) -> None:
        from powershell_mcp.server import public_result, run_target
        continued = public_result(run_target("local", "Write-Error bad; Write-Output x", 40, 65536, None, 120))
        self.assertNotIn("exit_code", continued)
        self.assertIn("x", continued["output"])
        stopped = public_result(run_target(
            "local", "$ErrorActionPreference='Stop'; Write-Error bad; Write-Output unreachable", 40, 65536, None, 120
        ))
        self.assertEqual(stopped["exit_code"], 1)
        self.assertEqual(stopped["failure"], "remote_exit")
        self.assertNotIn("unreachable", stopped["output"])

    def test_real_powershell_preserves_stderr_before_later_stdout(self) -> None:
        from powershell_mcp.server import public_result, run_target
        result = public_result(run_target(
            "local", "[Console]::Error.WriteLine('bad'); Start-Sleep -Milliseconds 50; Write-Output x",
            40, 65536, None, 120
        ), True)
        streams = [record["stream"] for record in result["records"] if record.get("type") == "output"]
        self.assertEqual(streams, ["stderr", "stdout"])
        self.assertNotIn("exit_code", result)

    def test_timeout_drains_shutdown_output_before_terminal(self) -> None:
        status, records = self.run_helper(r'''
            import json, signal, sys, time
            def record(value):
                if value.get("type") == "output":
                    value.setdefault("line_count", value.get("text", "").count("\n") + 1)
                    value.setdefault("trailing_delimiter_bytes", 1)
                    value.setdefault("byte_count", len(value.get("text", "").encode()) + value["trailing_delimiter_bytes"])
                sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n")
                sys.stdout.buffer.flush()
            def stop(signum, frame):
                record({"type":"output", "stream":"stdout", "text":"shutdown output"})
                sys.stderr.write("shutdown diagnostic\n"); sys.stderr.flush()
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop)
            while True: time.sleep(0.05)
        ''', timeout=0.1)
        self.assertEqual(status, 124)
        self.assertEqual(records[-1]["type"], "terminal")
        self.assertEqual(records[-1]["failure"], "timeout")
        self.assertEqual(sum(record["type"] == "terminal" for record in records), 1)
        self.assertNotIn("shutdown output", [record.get("text") for record in records])
        self.assertNotIn("shutdown diagnostic", [record.get("text") for record in records])

    def test_nonzero_transport_status_overrides_remote_success(self) -> None:
        status, records = self.run_helper(r'''
            import json, sys
            record = lambda value: (sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n"), sys.stdout.buffer.flush())
            record({"type":"process", "source":"remote", "sequence":1, "pid":1234, "started":133801632000000000})
            value = {"type":"exit", "source":"remote", "sequence":2, "exit_code":0, "observed_lines":0, "observed_bytes":0, "emitted_lines":0, "emitted_bytes":0, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0}
            sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n")
            sys.stdout.buffer.flush()
            raise SystemExit(255)
        ''')
        self.assertNotEqual(status, 0)
        self.assertEqual(records[-1]["failure"], "transport_exit")
        self.assertIn("ssh transport exited with status 255", records[-1]["message"])

    def test_unlimited_lines_are_bounded_only_by_bytes(self) -> None:
        body = r'''
            import json, sys
            def record(value):
                if value.get("type") == "output":
                    value.setdefault("line_count", value.get("text", "").count("\n") + 1)
                    value.setdefault("trailing_delimiter_bytes", 1)
                    value.setdefault("byte_count", len(value.get("text", "").encode()) + value["trailing_delimiter_bytes"])
                sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n")
            record({"type":"process", "source":"remote", "sequence":1, "pid":1234, "started":133801632000000000})
            for sequence in range(2, 502):
                record({"type":"output", "source":"remote", "sequence":sequence,
                        "stream":"stdout", "text":"x"})
            record({"type":"exit", "source":"remote", "sequence":502, "exit_code":0, "observed_lines":500, "observed_bytes":1000, "emitted_lines":500, "emitted_bytes":1000, "filter_suppressed_lines":0, "filter_suppressed_bytes":0, "line_suppressed_lines":0, "line_suppressed_bytes":0, "byte_suppressed_lines":0, "byte_suppressed_bytes":0})
            sys.stdout.buffer.flush()
        '''
        output = io.BytesIO()
        argv = [sys.executable, "-c", textwrap.dedent(body)]
        with patch("powershell_mcp.runner.launch_argv", return_value=argv):
            status = execute(Host("test", "unused", "powershell"), "ignored", mode="powershell",
                             max_lines=0, max_bytes=4096, pattern=None, timeout=5, output=output)
        records = decode(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(records[-1]["exit_code"], 0)
        self.assertEqual(sum(record.get("type") == "output" for record in records), 500)

    def test_timeout_discards_shutdown_stdout(self) -> None:
        output = io.BytesIO()
        body = r'''
            import json, signal, sys, time
            def stop(signum, frame):
                for sequence in range(1, 20001):
                    value = {"type":"output", "source":"remote", "sequence":sequence,
                             "stream":"stdout", "text":"x", "line_count":1,
                             "byte_count":2, "trailing_delimiter_bytes":1}
                    sys.stdout.buffer.write(b"\x1e" + json.dumps(value).encode() + b"\n")
                sys.stdout.buffer.flush()
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop)
            while True: time.sleep(0.05)
        '''
        argv = [sys.executable, "-c", textwrap.dedent(body)]
        with patch("powershell_mcp.runner.launch_argv", return_value=argv):
            status = execute(Host("test", "unused", "powershell"), "ignored", mode="powershell",
                             max_lines=0, max_bytes=1, pattern=None, timeout=0.1, output=output)
        records = decode(output.getvalue())
        self.assertEqual(status, 124)
        self.assertEqual(records[-1]["failure"], "timeout")
        self.assertFalse(any(record.get("type") == "output" for record in records))
        self.assertLess(len(output.getvalue()), 65536)

    def test_receive_budget_is_distinct_from_timeout(self) -> None:
        output = io.BytesIO()
        body = r'''
            import os, sys, time
            os.write(sys.stdout.fileno(), b"x" * 200000)
            time.sleep(5)
        '''
        argv = [sys.executable, "-c", textwrap.dedent(body)]
        with patch("powershell_mcp.runner.launch_argv", return_value=argv):
            status = execute(Host("test", "unused", "powershell"), "ignored", mode="powershell",
                             max_lines=1, max_bytes=1, pattern=None, timeout=30, output=output)
        records = decode(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(records[-1]["failure"], "receive_budget")
        self.assertNotIn("timeout_seconds", records[-1])

    def test_timeout_preserves_protocol_error_details(self) -> None:
        status, records = self.run_helper(r'''
            import signal, sys, time
            signal.signal(signal.SIGTERM, lambda signum, frame: (_ for _ in ()).throw(SystemExit(0)))
            sys.stdout.buffer.write(b"unframed bytes")
            sys.stdout.buffer.flush()
            while True: time.sleep(0.05)
        ''', timeout=0.1)
        self.assertEqual(status, 124)
        self.assertEqual(records[-1]["failure"], "timeout")
        self.assertIn("protocol errors before timeout", records[-1]["message"])
        self.assertEqual(records[-1]["type"], "terminal")

    def test_parser_bounds_and_reports_incomplete_records(self) -> None:
        parser = SequenceParser(maximum_record_bytes=8)
        errors = list(parser.feed(RS + b"123456789"))
        self.assertEqual(errors[0]["type"], "protocol_error")
        parser = SequenceParser(maximum_record_bytes=8)
        errors = list(parser.feed(RS + b"123456789\n"))
        self.assertEqual(errors[0]["type"], "protocol_error")
        parser = SequenceParser()
        list(parser.feed(RS + b'{"type":"exit"'))
        self.assertEqual(list(parser.finish())[0]["type"], "protocol_error")

    def test_stdin_script_and_structured_request_failure(self) -> None:
        output = io.BytesIO()
        fake_stdout = type("Stdout", (), {"buffer": output})()
        with patch("sys.stdout", fake_stdout), patch("sys.stdin", io.StringIO("Write-Output ok")), \
             patch.dict(os.environ, {"POWERSHELL_MCP_DRYRUN": "1", "POWERSHELL_MCP_REGISTRY": "/nonexistent"}, clear=False):
            self.assertEqual(backend_main(["--mode", "powershell", "--script-stdin", "host"]), 0)
        request = decode(output.getvalue())[0]
        self.assertEqual(request["type"], "request")
        self.assertIn("V3JpdGUtT3V0cHV0IG9r", request["remote_script"])

        output = io.BytesIO()
        fake_stdout = type("Stdout", (), {"buffer": output})()
        with patch("sys.stdout", fake_stdout), patch("sys.stdin", io.StringIO("")):
            self.assertEqual(backend_main(["--script-stdin", "host"]), 2)
        self.assertEqual(decode(output.getvalue())[0]["type"], "request_error")


if __name__ == "__main__":
    unittest.main()
