"""HTTP MCP bridge from a remote client to the local Ableton stdio server."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import sys
import time
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
import uvicorn
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from ableton_connect.tanomind import ConnectError, ConnectSession, TanomindConnect
from ableton_connect.security import READ_ONLY_TOOLS, confirm_edit

STATE_DIR = Path.home() / ".ableton-connect"
TOKEN_PATH = STATE_DIR / "bridge-token"
SESSION_PATH = STATE_DIR / "connect-session.json"
REVOKED_PATH = STATE_DIR / "revoked"
TUNNEL_URL = re.compile(r"https://[-a-z0-9]+\.trycloudflare\.com")
CLOUDFLARED = os.environ.get("CLOUDFLARED") or shutil.which("cloudflared") or "cloudflared"


class Gate:
    def __init__(self, token: str, connect_required: bool):
        self.token = token
        self.connect_required = connect_required
        self.approved = not connect_required
        self.agent_handle: str | None = None
        self.app_id: str | None = None
        self.origin = "https://tanomind.com"
        self.attempt: dict[str, str] | None = None
        self._lock = asyncio.Lock()
        self.session: ConnectSession | None = None
        self.connect: TanomindConnect | None = None
        self.allow_edits = False
        self.revoked = False

    def is_revoked(self) -> bool:
        if REVOKED_PATH.exists():
            self.revoked = True
            self.approved = False
        return self.revoked

    def grant(self, session: ConnectSession) -> None:
        self.session = session
        self.agent_handle = session.agent_handle
        # Invalidate the bootstrap credential and all previous agent credentials.
        self.token = secrets.token_urlsafe(32)
        self.approved = True

    async def validate(self, ctx) -> bool:
        if self.is_revoked() or not self.approved:
            return False
        request = getattr(ctx, "request", None)
        if request is None or not self.allow(request.headers.get("authorization", "")):
            return False
        if not self.connect_required:
            return True
        if self.connect is None or self.session is None:
            return False
        try:
            profile = await anyio.to_thread.run_sync(self.connect.profile, self.session.session_token)
        except ConnectError:
            self.approved = False
            return False
        agent = profile.get("agent") or {}
        # Identity comes from the authenticated profile, never the join payload.
        return bool(self.agent_handle and agent.get("handle") == self.agent_handle)

    def allow(self, header: str) -> bool:
        if self.is_revoked():
            return False
        expected = f"Bearer {self.token}"
        if len(header) != len(expected):
            return False
        return secrets.compare_digest(header, expected)


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_token() -> str:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if TOKEN_PATH.exists():
        token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    write_private(TOKEN_PATH, token)
    return token


def load_saved_session() -> ConnectSession | None:
    if not SESSION_PATH.exists():
        return None
    try:
        data = json.loads(SESSION_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not data.get("session_id") or not data.get("session_token"):
        return None
    return ConnectSession(
        session_id=data["session_id"],
        session_token=data["session_token"],
        expires_in=0,
        agent_handle=data.get("agent_handle"),
    )


def save_session(session: ConnectSession, expires_at: float) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    write_private(SESSION_PATH,
        json.dumps(
            {
                "session_id": session.session_id,
                "session_token": session.session_token,
                "agent_handle": session.agent_handle,
                "expires_at": expires_at,
            }
        ),
    )


def load_env_file() -> None:
    path = Path(".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def bearer_app(app: Any, gate: Gate) -> Any:
    open_paths = {"/health", "/connect/start", "/connect/callback", "/tanomind/join", "/tanomind/connect"}

    async def wrapped(scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in open_paths:
            await app(scope, receive, send)
            return
        headers = {key.decode().lower(): value.decode() for key, value in scope.get("headers", [])}
        if not gate.allow(headers.get("authorization", "")):
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        await app(scope, receive, send)

    return wrapped


def connect_card(origin: str, app_id: str) -> dict[str, Any]:
    return {
        "app_id": app_id,
        "request": {
            "method": "POST",
            "url": f"{origin}/api/agent/connect/request",
            "headers": {
                "Authorization": "Bearer <your Tanomind agent token>",
                "Content-Type": "application/json",
            },
            "body": {"app_id": app_id},
        },
        "show_user": (
            "Show the user approve_url from that response and tell them to press Agree and connect. "
            "Check poll_url until the status changes. Send your agent token only to tanomind.com."
        ),
    }


def connect_text(origin: str, app_id: str) -> str:
    card = connect_card(origin, app_id)
    return (
        "Show the user Tanomind's connect form before using Ableton. "
        f"POST {card['request']['url']} with your Tanomind agent token and "
        f'{{"app_id":"{app_id}"}}. '
        "Send that token only to tanomind.com. "
        "Show the user the approve_url from the response and tell them to press Agree and connect. "
        "Check poll_url every 5 seconds or more until the status changes, then call the Ableton tools."
    )


def server_instructions(gate: Gate) -> str:
    base = (
        "Ableton Live on this computer. Live must be open with the AbletonMCP control surface selected. "
        "Use the tools to create tracks, write MIDI, load devices, arrange clips, and mix."
    )
    if not gate.app_id:
        return base
    if gate.approved:
        who = f" @{gate.agent_handle}" if gate.agent_handle else ""
        return base + f" Tanomind agent{who} is already connected. " + connect_text(gate.origin, gate.app_id)
    return connect_text(gate.origin, gate.app_id) + " " + base


def build_server(session: ClientSession, capabilities: Any, lock: asyncio.Lock, gate: Gate) -> Server:
    handlers: dict[str, Any] = {}

    connect_tool = types.Tool(
        name="connect_tanomind",
        description=(
            "Show the user Tanomind's Agree and connect form. "
            "Call this before any Ableton tool when the user has not connected yet. "
            "Do not ask the user for a token."
        ),
        input_schema={"type": "object", "properties": {}},
    )

    async def on_list_tools(_ctx, params):
        async with lock:
            listed = await session.list_tools(params=params)
        if gate.app_id and not gate.approved:
            listed.tools = [connect_tool]
        return listed

    def connect_result() -> types.CallToolResult:
        assert gate.app_id
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=connect_text(gate.origin, gate.app_id))],
        )

    async def on_call_tool(_ctx, params):
        if params.name == "connect_tanomind":
            if not gate.app_id:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="Tanomind Connect is not configured on this bridge.")],
                    is_error=True,
                )
            if gate.approved:
                who = gate.agent_handle or "the approved agent"
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"Already connected as {who}. Ableton tools are ready.")],
                )
            return connect_result()
        async with lock:
            if not await gate.validate(_ctx):
                return types.CallToolResult(content=[types.TextContent(type="text", text="Access denied. Use the current credential for the approved agent; reconnect if access was revoked.")], is_error=True)
            if params.name not in READ_ONLY_TOOLS:
                if not gate.allow_edits:
                    return types.CallToolResult(content=[types.TextContent(type="text", text="Read-only mode: editing requires the operator to restart with --allow-edits.")], is_error=True)
                if not await anyio.to_thread.run_sync(confirm_edit, params.name, params.arguments):
                    return types.CallToolResult(content=[types.TextContent(type="text", text="The local operator did not approve this edit.")], is_error=True)
                # A revocation while the operator was deciding must also win.
                if not await gate.validate(_ctx):
                    return types.CallToolResult(content=[types.TextContent(type="text", text="Access revoked before the edit could start.")], is_error=True)
            result = await session.call_tool(
                params.name,
                params.arguments,
                read_timeout_seconds=180,
            )
        if isinstance(result, types.CallToolResult):
            return result
        return types.CallToolResult(content=[types.TextContent(type="text", text=str(result))], is_error=True)

    handlers["on_list_tools"] = on_list_tools
    handlers["on_call_tool"] = on_call_tool

    if getattr(capabilities, "prompts", None) is not None:

        async def on_list_prompts(_ctx, params):
            async with lock:
                if not await gate.validate(_ctx):
                    raise PermissionError("Agent access denied")
                return await session.list_prompts(params=params)

        async def on_get_prompt(_ctx, params):
            async with lock:
                if not await gate.validate(_ctx):
                    raise PermissionError("Agent access denied")
                return await session.get_prompt(params.name, params.arguments)

        handlers["on_list_prompts"] = on_list_prompts
        handlers["on_get_prompt"] = on_get_prompt

    if getattr(capabilities, "resources", None) is not None:

        async def on_list_resources(_ctx, params):
            async with lock:
                if not await gate.validate(_ctx):
                    raise PermissionError("Agent access denied")
                return await session.list_resources(params=params)

        async def on_list_resource_templates(_ctx, params):
            async with lock:
                if not await gate.validate(_ctx):
                    raise PermissionError("Agent access denied")
                return await session.list_resource_templates(params=params)

        async def on_read_resource(_ctx, params):
            async with lock:
                if not await gate.validate(_ctx):
                    raise PermissionError("Agent access denied")
                return await session.read_resource(str(params.uri))

        handlers["on_list_resources"] = on_list_resources
        handlers["on_list_resource_templates"] = on_list_resource_templates
        handlers["on_read_resource"] = on_read_resource

    return Server(
        "ableton-connect",
        version="0.1.0",
        instructions=server_instructions(gate),
        **handlers,
    )


async def open_tunnel(port: int) -> tuple[str, asyncio.subprocess.Process]:
    if not Path(CLOUDFLARED).exists() and not shutil.which("cloudflared"):
        raise RuntimeError("cloudflared is not installed, so Grokbot cannot reach this PC.")
    process = await asyncio.create_subprocess_exec(
        CLOUDFLARED,
        "tunnel",
        "--url",
        f"http://127.0.0.1:{port}",
        "--no-autoupdate",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    found: asyncio.Future[str] = asyncio.get_running_loop().create_future()

    async def read_output() -> None:
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                if not found.done():
                    found.set_exception(RuntimeError("cloudflared exited before it printed a public URL."))
                return
            match = TUNNEL_URL.search(line.decode(errors="replace"))
            if match and not found.done():
                found.set_result(match.group(0))

    reader = asyncio.create_task(read_output())
    try:
        url = await asyncio.wait_for(found, timeout=30)
    except Exception:
        reader.cancel()
        process.terminate()
        raise
    return url, process


def security_for(public_url: str | None) -> TransportSecuritySettings:
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    if public_url:
        host = public_url.split("://", 1)[1].split("/", 1)[0]
        hosts.append(host)
        hosts.append(f"{host}:*")
        origins.append(public_url)
        origins.append(f"{public_url}:*")
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )


def grokbot_config(url: str, token: str) -> str:
    return json.dumps(
        {
            "mcpServers": {
                "ableton": {
                    "url": f"{url}/mcp",
                    "headers": {"Authorization": f"Bearer {token}"},
                }
            }
        },
        indent=2,
    )


def write_client_config(url: str, token: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / "mcp-config.json"
    write_private(path, grokbot_config(url, token))
    print(f"Private MCP config saved to {path}. Share it only with the approved agent.", flush=True)


async def restore_connect(connect: TanomindConnect, gate: Gate) -> None:
    saved = load_saved_session()
    if saved is None:
        return
    try:
        profile = await anyio.to_thread.run_sync(connect.profile, saved.session_token)
    except ConnectError:
        try:
            refreshed = await anyio.to_thread.run_sync(connect.refresh, saved.session_id, saved.session_token)
        except ConnectError:
            return
        save_session(refreshed, time.time() + refreshed.expires_in)
        saved = refreshed
        try:
            profile = await anyio.to_thread.run_sync(connect.profile, saved.session_token)
        except ConnectError:
            return
    agent = profile.get("agent") if isinstance(profile.get("agent"), dict) else {}
    saved.agent_handle = agent.get("handle")
    if saved.agent_handle:
        gate.grant(saved)


async def run(argv: list[str] | None = None) -> None:
    load_env_file()
    parser = argparse.ArgumentParser(description="Expose the local Ableton MCP over authenticated HTTP.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("ABLETON_CONNECT_PORT", "8765")))
    parser.add_argument("--tunnel", action="store_true", help="Publish an HTTPS URL with cloudflared.")
    parser.add_argument("--connect", action="store_true", help="Require an approved Tanomind Connect session.")
    parser.add_argument("--allow-edits", action="store_true", help="Allow edits only after local terminal confirmation for each call.")
    parser.add_argument("--revoke", action="store_true", help="Immediately deny new calls in the running bridge and remove its saved session.")
    args = parser.parse_args(argv)
    if args.revoke:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        REVOKED_PATH.write_text("revoked", encoding="utf-8")
        SESSION_PATH.unlink(missing_ok=True)
        TOKEN_PATH.unlink(missing_ok=True)
        (STATE_DIR / "mcp-config.json").unlink(missing_ok=True)
        print("Access revoked. The running bridge will close its server and tunnel. Already-running calls cannot be undone.")
        return
    # Restart is an explicit local operator action; old credentials rotate below.
    if REVOKED_PATH.exists():
        SESSION_PATH.unlink(missing_ok=True)
        REVOKED_PATH.unlink()

    app_id = os.environ.get("TANOME_APP_ID", "").strip()
    app_key = os.environ.get("TANOME_APP_KEY", "").strip()
    origin = os.environ.get("TANOME_ORIGIN", "https://tanomind.com").strip() or "https://tanomind.com"
    connect_requested = args.connect or bool(app_id or app_key)
    if connect_requested and (not app_id or not app_key):
        raise SystemExit("Set TANOME_APP_ID and TANOME_APP_KEY. Create them at https://tanomind.com/developers#tanomind-connect")

    public_url = os.environ.get("ABLETON_CONNECT_PUBLIC_URL", "").strip().rstrip("/") or None
    use_tunnel = args.tunnel or (connect_requested and not public_url)
    if (use_tunnel or public_url) and not connect_requested:
        raise SystemExit("Public access requires Tanomind Connect (--connect and app credentials).")
    token = secrets.token_urlsafe(32) if connect_requested else (os.environ.get("ABLETON_CONNECT_TOKEN", "").strip() or load_token())
    uvx = os.environ.get("UVX_PATH") or shutil.which("uvx") or "uvx"
    gate = Gate(token, connect_required=connect_requested)
    connect = TanomindConnect(app_id, app_key, origin) if connect_requested else None
    gate.connect = connect
    gate.allow_edits = args.allow_edits
    if connect_requested and not origin.startswith("https://"):
        raise SystemExit("Tanomind Connect requires an HTTPS origin.")

    params = StdioServerParameters(command=uvx, args=["mcp-server-ableton-live"])
    tunnel: asyncio.subprocess.Process | None = None
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                lock = asyncio.Lock()
                if use_tunnel:
                    public_url, tunnel = await open_tunnel(args.port)
                local_url = f"http://127.0.0.1:{args.port}"
                advertised = public_url or local_url
                gate.origin = origin
                if connect is not None:
                    if not public_url or not public_url.startswith("https://"):
                        raise SystemExit("Tanomind agent connect needs an HTTPS URL. Start with --tunnel.")
                    redirect_uri = f"{public_url}/connect/callback"
                    join_url = f"{public_url}/tanomind/join"
                    gate.app_id, join_set = await anyio.to_thread.run_sync(
                        lambda: connect.publish_agent_join(redirect_uri, join_url)
                    )
                    if not join_set:
                        print(
                            "\nSet agent_join_url in Tanomind (Settings > Developer apps) to:\n" + join_url + "\n",
                            flush=True,
                        )
                    await restore_connect(connect, gate)
                mcp_server = build_server(session, initialized.capabilities, lock, gate)

                async def grant_access(granted: ConnectSession):
                    assert connect is not None
                    profile = await anyio.to_thread.run_sync(connect.profile, granted.session_token)
                    agent = profile.get("agent") or {}
                    handle = agent.get("handle")
                    if not isinstance(handle, str) or not handle:
                        raise ConnectError("Approved session has no verified agent identity")
                    if gate.is_revoked():
                        raise ConnectError("Access revoked during approval")
                    granted.agent_handle = handle
                    save_session(granted, time.time() + granted.expires_in)
                    gate.grant(granted)
                    write_client_config(advertised, gate.token)

                async def health(_request: Request):
                    return JSONResponse(
                        {
                            "ok": True,
                            "connect_required": gate.connect_required,
                            "approved": gate.approved,
                            "agent": gate.agent_handle,
                        }
                    )

                async def callback(request: Request):
                    if connect is None or gate.attempt is None or gate.is_revoked() or gate.approved:
                        return HTMLResponse("Connect is not waiting for approval.", status_code=400)
                    if request.query_params.get("error"):
                        return HTMLResponse("Tanomind Connect was declined.", status_code=400)
                    state = request.query_params.get("state") or ""
                    code = request.query_params.get("code") or ""
                    expected = gate.attempt["state"]
                    if len(state) != len(expected) or not secrets.compare_digest(state, expected):
                        return HTMLResponse("This approval does not match the bridge that is running.", status_code=400)
                    # Consume the pending state before awaiting, preventing races/replays.
                    attempt = gate.attempt
                    gate.attempt = None
                    try:
                        granted = await anyio.to_thread.run_sync(
                            lambda: connect.exchange_code(code, attempt["redirect_uri"], attempt["verifier"])
                        )
                        async with gate._lock:
                            if gate.is_revoked() or gate.approved:
                                return HTMLResponse("Access changed; restart approval.", status_code=409)
                            await grant_access(granted)
                    except ConnectError as error:
                        return HTMLResponse("Tanomind did not accept the approval.", status_code=400)
                    who = granted.agent_handle or "your agent"
                    return HTMLResponse(f"Connected {html.escape(who)} to Ableton. Ask the operator for the new private MCP config.")

                async def start_connect(_request: Request):
                    if connect is None or not public_url:
                        return HTMLResponse("Tanomind Connect is not configured.", status_code=404)
                    if gate.approved:
                        return HTMLResponse("Already connected to Ableton.")
                    if gate.is_revoked():
                        return HTMLResponse("Access revoked. Restart the bridge locally.", status_code=403)
                    verifier, challenge = pkce()
                    state = secrets.token_urlsafe(24)
                    redirect_uri = f"{public_url}/connect/callback"
                    gate.attempt = {"state": state, "verifier": verifier, "redirect_uri": redirect_uri}
                    return RedirectResponse(connect.authorization_url(redirect_uri, state, challenge))

                async def accept_join(request: Request):
                    if connect is None or not gate.app_id or not public_url:
                        return JSONResponse({"error": "tanomind_connect_not_configured"}, status_code=404)
                    if gate.is_revoked() or gate.approved:
                        return JSONResponse({"error": "disconnect_existing_agent_first"}, status_code=409)
                    raw = await request.body()
                    if len(raw) > 8192:
                        return JSONResponse({"error": "invalid_join"}, status_code=400)
                    try:
                        body = json.loads(raw)
                    except json.JSONDecodeError:
                        return JSONResponse({"error": "invalid_join"}, status_code=400)
                    if not isinstance(body, dict):
                        return JSONResponse({"error": "invalid_join"}, status_code=400)
                    code = body.get("code")
                    verifier = body.get("code_verifier")
                    posted_redirect = body.get("redirect_uri")
                    handle = body.get("agent_handle")
                    if (
                        not isinstance(code, str)
                        or not isinstance(verifier, str)
                        or not isinstance(posted_redirect, str)
                        or not code
                        or not verifier
                        or posted_redirect != f"{public_url}/connect/callback"
                    ):
                        return JSONResponse({"error": "invalid_join"}, status_code=400)
                    if handle is not None and (not isinstance(handle, str) or len(handle) > 80):
                        return JSONResponse({"error": "invalid_join"}, status_code=400)
                    try:
                        granted = await anyio.to_thread.run_sync(
                            lambda: connect.exchange_code(code, posted_redirect, verifier)
                        )
                        async with gate._lock:
                            if gate.is_revoked() or gate.approved:
                                return JSONResponse({"error": "access_changed"}, status_code=409)
                            await grant_access(granted)
                    except ConnectError as error:
                        return JSONResponse({"error": "exchange_failed"}, status_code=400)
                    return JSONResponse({"ok": True})

                async def connect_info(_request: Request):
                    if not gate.app_id:
                        return JSONResponse({"error": "tanomind_connect_not_configured"}, status_code=503)
                    card = connect_card(gate.origin, gate.app_id)
                    card["approved"] = gate.approved
                    card["agent"] = gate.agent_handle
                    return JSONResponse(card)

                app = mcp_server.streamable_http_app(
                    json_response=True,
                    host="127.0.0.1",
                    transport_security=security_for(public_url),
                    custom_starlette_routes=[
                        Route("/health", health),
                        Route("/connect/start", start_connect),
                        Route("/connect/callback", callback),
                        Route("/tanomind/join", accept_join, methods=["POST"]),
                        Route("/tanomind/connect", connect_info),
                    ],
                )
                app = bearer_app(app, gate)

                write_client_config(advertised, gate.token)
                if gate.app_id and not gate.approved:
                    print(f"If you already agreed in Tanomind, open {public_url}/connect/start\n", flush=True)
                if gate.app_id:
                    print(
                        "Agents show the user the Agree and connect link from "
                        f"POST {origin}/api/agent/connect/request with app_id {gate.app_id}.\n",
                        flush=True,
                    )
                print("Live must be open with Control Surface AbletonMCP, Input and Output set to None.\n", flush=True)
                config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning")
                http_server = uvicorn.Server(config)

                async def watch_revocation():
                    while not http_server.should_exit:
                        if gate.is_revoked():
                            http_server.should_exit = True
                            if tunnel is not None and tunnel.returncode is None:
                                tunnel.terminate()
                            return
                        await asyncio.sleep(0.25)

                watcher = asyncio.create_task(watch_revocation())
                try:
                    await http_server.serve()
                finally:
                    watcher.cancel()
                    try:
                        await watcher
                    except asyncio.CancelledError:
                        pass
    finally:
        if tunnel is not None and tunnel.returncode is None:
            tunnel.terminate()
            try:
                await asyncio.wait_for(tunnel.wait(), timeout=5)
            except asyncio.TimeoutError:
                tunnel.kill()
                await tunnel.wait()


def main(argv: list[str] | None = None) -> None:
    try:
        anyio.run(run, argv)
    except KeyboardInterrupt:
        sys.exit(0)
