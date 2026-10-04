import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from starlette.testclient import TestClient

import mcp.types as types
from ableton_connect import bridge
from ableton_connect.tanomind import ConnectError, ConnectSession
from ableton_connect.security import confirm_edit


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.revoked = Path(self.temp.name) / "revoked"
        self.patch = patch.object(bridge, "REVOKED_PATH", self.revoked)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.gate = bridge.Gate("bootstrap", True)
        self.gate.app_id = "app"
        self.gate.connect = Mock()
        self.gate.connect.profile.return_value = {"agent": {"handle": "alice"}}
        self.gate.grant(ConnectSession("session", "session-token", 3600, "alice"))
        self.ctx = SimpleNamespace(request=SimpleNamespace(headers={"authorization": "Bearer " + self.gate.token}))
        self.upstream = SimpleNamespace(call_tool=AsyncMock(return_value=types.CallToolResult(content=[])))
        server = bridge.build_server(self.upstream, SimpleNamespace(), asyncio.Lock(), self.gate)
        self.call = server.get_request_handler("tools/call").handler

    async def invoke(self, name="get_session_info", ctx=None):
        return await self.call(ctx or self.ctx, types.CallToolRequestParams(name=name, arguments={}))

    async def test_verified_agent_can_read(self):
        result = await self.invoke()
        self.assertFalse(result.is_error)
        self.upstream.call_tool.assert_awaited_once()

    async def test_bootstrap_cannot_use_approved_agent(self):
        self.assertFalse(self.gate.allow("Bearer bootstrap"))
        ctx = SimpleNamespace(request=SimpleNamespace(headers={"authorization": "Bearer bootstrap"}))
        self.assertTrue((await self.invoke(ctx=ctx)).is_error)
        self.upstream.call_tool.assert_not_awaited()

    async def test_new_agent_invalidates_old_credential(self):
        old = self.gate.token
        self.gate.grant(ConnectSession("second", "other-session", 3600, "bob"))
        self.assertFalse(self.gate.allow("Bearer " + old))
        self.assertTrue((await self.invoke()).is_error)

    async def test_identity_mismatch_denied(self):
        self.gate.connect.profile.return_value = {"agent": {"handle": "bob"}}
        self.assertTrue((await self.invoke()).is_error)
        self.upstream.call_tool.assert_not_awaited()

    async def test_remote_revocation_or_outage_fails_closed(self):
        self.gate.connect.profile.side_effect = ConnectError("revoked")
        self.assertTrue((await self.invoke()).is_error)
        self.upstream.call_tool.assert_not_awaited()

    async def test_local_revocation_denies_existing_session(self):
        self.revoked.touch()
        self.assertTrue((await self.invoke()).is_error)
        self.assertFalse(self.gate.allow("Bearer " + self.gate.token))
        self.upstream.call_tool.assert_not_awaited()

    async def test_missing_http_identity_denied(self):
        self.assertTrue((await self.invoke(ctx=SimpleNamespace(request=None))).is_error)

    async def test_unknown_and_destructive_tools_are_read_only_by_default(self):
        for name in ["delete_track", "replace_notes", "get_and_delete_track", "new_tool"]:
            self.assertTrue((await self.invoke(name)).is_error)
        self.upstream.call_tool.assert_not_awaited()

    async def test_edit_requires_fresh_confirmation_each_time(self):
        self.gate.allow_edits = True
        with patch.object(bridge, "confirm_edit", side_effect=[True, False]) as confirm:
            self.assertFalse((await self.invoke("delete_track")).is_error)
            self.assertTrue((await self.invoke("delete_track")).is_error)
            self.assertEqual(confirm.call_count, 2)
        self.assertEqual(self.upstream.call_tool.await_count, 1)

    async def test_revocation_during_confirmation_denies_edit(self):
        self.gate.allow_edits = True
        def revoke(*_args):
            self.revoked.touch()
            return True
        with patch.object(bridge, "confirm_edit", side_effect=revoke):
            self.assertTrue((await self.invoke("delete_track")).is_error)
        self.upstream.call_tool.assert_not_awaited()

    def test_noninteractive_terminal_cannot_approve(self):
        with patch("sys.stdin.isatty", return_value=False):
            self.assertFalse(confirm_edit("delete_track", {}))

    async def test_public_bridge_requires_connect(self):
        with patch.object(bridge, "load_env_file"), patch("os.environ", {}):
            with self.assertRaisesRegex(SystemExit, "Public access requires"):
                await bridge.run(["--tunnel"])


class HttpSecurityTests(unittest.TestCase):
    def test_http_identity_and_revocation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(bridge, "REVOKED_PATH", Path(directory) / "revoked"):
            gate = bridge.Gate("bootstrap", True)
            gate.connect = Mock()
            gate.connect.profile.return_value = {"agent": {"handle": "alice"}}
            gate.grant(ConnectSession("session", "session-token", 3600, "alice"))
            upstream = SimpleNamespace(call_tool=AsyncMock(return_value=types.CallToolResult(content=[])))
            server = bridge.build_server(upstream, SimpleNamespace(), asyncio.Lock(), gate)
            app = bridge.bearer_app(server.streamable_http_app(json_response=True, host="127.0.0.1", transport_security=bridge.security_for(None)), gate)
            with TestClient(app, base_url="http://127.0.0.1:8765") as client:
                headers = {"Authorization": "Bearer " + gate.token, "Accept": "application/json, text/event-stream"}
                self.assertEqual(client.post("/mcp", json={}).status_code, 401)
                response = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "security-test", "version": "1"}}})
                self.assertEqual(response.status_code, 200, response.text)
                if response.headers.get("mcp-session-id"):
                    headers["Mcp-Session-Id"] = response.headers["mcp-session-id"]
                headers["MCP-Protocol-Version"] = "2025-11-25"
                client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_session_info", "arguments": {}}}
                response = client.post("/mcp", headers=headers, json=message)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertFalse(response.json()["result"].get("isError", False), response.text)
                self.assertEqual(upstream.call_tool.await_count, 1)
                message["params"]["name"] = "delete_track"
                response = client.post("/mcp", headers=headers, json=message)
                self.assertTrue(response.json()["result"]["isError"], response.text)
                self.assertEqual(upstream.call_tool.await_count, 1)
                (Path(directory) / "revoked").touch()
                self.assertEqual(client.post("/mcp", headers=headers, json=message).status_code, 401)


if __name__ == "__main__":
    unittest.main()
