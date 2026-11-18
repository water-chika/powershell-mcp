#!/usr/bin/env python3

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError

from powershell_mcp.server import load_hosts

RS = b"\x1e"


class RegistryTests(unittest.TestCase):
    def test_lists_aliases_and_rejects_bad_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "hosts.conf"
            registry.write_text("# x\nalpha | developer@example.invalid | powershell\nbeta|-p 2222 developer@127.0.0.1|cmd\n")
            self.assertEqual(load_hosts(registry), ("alpha", "beta"))
            registry.write_text("bad row\n")
            with self.assertRaisesRegex(ToolError, "malformed"):
                load_hosts(registry)


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
                    for name in ("powershell_status", "powershell_run"):
                        tool = tools[name]
                        flag = tool.input_schema["properties"]["include_raw_records"]
                        if name.startswith("powershell_"):
                            self.assertIn("target", tool.input_schema.get("required", []))
                        self.assertEqual(flag["type"], "boolean")
                        self.assertFalse(flag["default"])
                        self.assertIn("records", tool.output_schema["properties"])
                        self.assertNotIn("records", tool.output_schema.get("required", []))

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
                    self.assertEqual(local.structured_content, {"output": "local-ok", "exit_code": 0})


if __name__ == "__main__":
    unittest.main()
