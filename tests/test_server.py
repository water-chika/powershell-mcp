#!/usr/bin/env python3

import asyncio
import anyio
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError

from powershell_mcp.server import command_result_from_records, load_hosts

RS = b"\x1e"


class RegistryTests(unittest.TestCase):
    def test_lists_aliases_and_rejects_bad_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "hosts.conf"
            registry.write_text("# x\nalpha | developer@example.invalid | powershell\nbeta|-p 2222 developer@127.0.0.1|powershell\n")
            self.assertEqual(load_hosts(registry), ("alpha", "beta"))
            registry.write_text("badmode | developer@example.invalid | cmd\n")
            with self.assertRaisesRegex(ToolError, "expected powershell"):
                load_hosts(registry)
            registry.write_text("bad row\n")
            with self.assertRaisesRegex(ToolError, "malformed"):
                load_hosts(registry)
            registry.write_bytes(b"\xff")
            with self.assertRaisesRegex(ToolError, "cannot read"):
                load_hosts(registry)

    def test_output_reconstruction_uses_declared_delimiters(self) -> None:
        records = [
            {"type": "output", "text": "a", "trailing_delimiter_bytes": 0},
            {"type": "output", "text": "b", "trailing_delimiter_bytes": 1},
            {"type": "terminal", "exit_code": 0, "output_complete": True},
        ]
        result = command_result_from_records(records, "local")
        self.assertEqual(result.output, "ab\n")


class ProtocolTests(unittest.TestCase):
    def test_stdio_tools(self) -> None:
        asyncio.run(self._run())

    async def _run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); registry = root / "hosts.conf"
            registry.write_text("alpha | ignored | powershell\n")
            env = os.environ.copy(); env.update(POWERSHELL_MCP_REGISTRY=str(registry), POWERSHELL_MCP_PWSH=str(Path.home() / ".local/bin/pwsh"))
            params = StdioServerParameters(command=sys.executable, args=["-m", "powershell_mcp.server"], env=env)
            async with stdio_client(params) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                    self.assertIn("list_powershell_targets", tools)
                    list_schema = tools["list_powershell_targets"].output_schema
                    self.assertIn("targets", list_schema["properties"])
                    self.assertIn("targets", list_schema["required"])
                    for name in ("powershell_status", "powershell_run"):
                        tool = tools[name]
                        flag = tool.input_schema["properties"]["include_raw_records"]
                        if name.startswith("powershell_"):
                            self.assertIn("target", tool.input_schema.get("required", []))
                        self.assertEqual(flag["type"], "boolean")
                        self.assertFalse(flag["default"])
                        if name == "powershell_run":
                            props = tool.input_schema["properties"]
                            self.assertEqual(props["max_lines"]["minimum"], 0)
                            self.assertEqual(props["max_lines"]["maximum"], 200)
                            self.assertEqual(props["max_bytes"]["maximum"], 1_048_576)
                            self.assertEqual(props["timeout_seconds"]["maximum"], 600)
                            self.assertIn("regular expression", props["filter"]["description"])

                    listed_targets = await session.call_tool("list_powershell_targets", {})
                    self.assertEqual(listed_targets.structured_content, {"targets": [
                        {"id": "local", "kind": "local"},
                        {"id": "ssh:alpha", "kind": "ssh"},
                    ]})
                    invalid_target = await session.call_tool(
                        "powershell_run", {"target": "alpha", "script": "ok"}
                    )
                    self.assertTrue(invalid_target.is_error)
                    local = await session.call_tool(
                        "powershell_run", {"target": "local", "script": "Write-Output local-ok"}
                    )
                    self.assertEqual(local.structured_content, {"output": "local-ok\n"})
                    self.assertEqual(local.content[0].text, "local-ok\n")
                    failed = await session.call_tool(
                        "powershell_run", {"target": "local", "script": "Write-Output bad; exit 7"}
                    )
                    self.assertEqual(failed.content[0].text, "bad\nProcess exited with code 7")
                    self.assertEqual(failed.structured_content["exit_code"], 7)

                    marker = root / "cancelled-marker"
                    started = anyio.Event()
                    scope = anyio.CancelScope()

                    async def cancelled_call() -> None:
                        with scope:
                            started.set()
                            await session.call_tool(
                                "powershell_run",
                                {"target": "local", "script": f"Start-Sleep -Seconds 2; Set-Content -LiteralPath '{marker}' -Value bad"},
                            )

                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(cancelled_call)
                        await started.wait()
                        await anyio.sleep(0.2)
                        scope.cancel()
                    await anyio.sleep(2.2)
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
