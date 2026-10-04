# ableton-connect

A bridge that lets a remote agent control Ableton Live on your own computer. It wraps the local [Ableton Live MCP Server](https://abletonmcp.com) in an HTTP MCP endpoint that needs a bearer token. It can also publish that endpoint through a Cloudflare quick tunnel and let [Tanomind Connect](https://tanomind.com/tanomind-connect.md) decide which agent gets in.

Tanomind never talks to Ableton. The bridge runs on your PC, and your agent calls it.

## How it works

1. The bridge starts `mcp-server-ableton-live` over stdio and serves the same tools, prompts and resources over streamable HTTP on `127.0.0.1:8765`.
2. MCP requests need `Authorization: Bearer <token>`. With Connect, approval creates a new credential for one verified agent and invalidates the bootstrap credential. The session is checked with Tanomind before each tool call.
3. With `--tunnel`, the bridge starts `cloudflared` and prints the public `trycloudflare.com` address.
4. With Tanomind Connect set up, Ableton calls are refused until you approve an agent. The agent asks Tanomind for a connect form, you press Agree and connect, and Tanomind sends a one-time code to the bridge. The bridge trades it for a session with PKCE and keeps the session for restarts.

## Requirements

- Ableton Live 11 or 12
- Python 3.13 or newer and [uv](https://docs.astral.sh/uv/)
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/), for remote agents
- A Tanomind account, for Tanomind Connect

## Setup

Set up the Ableton MCP first:

```bash
uvx mcp-server-ableton-live install
```

Fully restart Live. In Settings, Tempo & MIDI, pick **AbletonMCP** in an unused Control Surface row and set Input and Output to None. Then check it:

```bash
uvx mcp-server-ableton-live doctor --json
```

Install the bridge:

```bash
git clone https://github.com/fitworks-io/ableton-connect
cd ableton-connect
uv sync
cp .env.example .env
```

## Run it

Local only, for an MCP client on the same machine:

```bash
uv run ableton-connect
```

Public, for a cloud agent:

```bash
uv run ableton-connect --connect --tunnel
```

The bridge saves the MCP config in `~/.ableton-connect/mcp-config.json` instead of printing credentials into logs. Give the current file only to the approved agent. Approval and restarting the bridge rotate Connect credentials, so update the agent configuration afterward:

```json
{
  "mcpServers": {
    "ableton": {
      "url": "https://<your-tunnel>.trycloudflare.com/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Tanomind Connect

1. Create a Connect app at https://tanomind.com/developers#tanomind-connect and add its terms and privacy links.
2. Put the app ID and key in `.env` as `TANOME_APP_ID` and `TANOME_APP_KEY`.
3. Run `uv run ableton-connect`. With Connect set, the tunnel starts on its own unless `ABLETON_CONNECT_PUBLIC_URL` is set.

On start, the bridge registers `/connect/callback` as the app's redirect URL and sets `/tanomind/join` as its agent join URL. Until an agent is approved, it exposes only `connect_tanomind` and refuses Ableton calls. After approval, the operator must give the approved agent its new private MCP config. A second agent cannot replace the connected agent; revoke access and restart before approving a different agent. Public access without Connect is refused.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `TANOME_APP_ID` | | Tanomind Connect app ID |
| `TANOME_APP_KEY` | | Tanomind Connect app key |
| `TANOME_ORIGIN` | `https://tanomind.com` | Tanomind address |
| `ABLETON_CONNECT_PORT` | `8765` | Local port |
| `ABLETON_CONNECT_PUBLIC_URL` | | A fixed public HTTPS URL, such as a named tunnel |
| `ABLETON_CONNECT_TOKEN` | generated | Bearer token |
| `UVX_PATH` | `uvx` on PATH | Path to uvx |
| `CLOUDFLARED` | `cloudflared` on PATH | Path to cloudflared |

## Safety

The bridge defaults to read-only access. Only the explicit inspection tools listed in `security.py` bypass edit confirmation; unknown tools are treated as edits.

To permit editing, start in an interactive local terminal:

```bash
uv run ableton-connect --connect --allow-edits
```

Every editing call displays its tool name and arguments in that terminal and requires the operator to type `APPROVE`. This includes destructive calls and prevents an agent from approving its own request. Noninteractive runs refuse edits. Save a backup of the Live set before approving changes. An approval is for one call only.

To revoke the running bridge from a second terminal under the same OS account:

```bash
uv run ableton-connect --revoke
```

This denies subsequent calls, invalidates the saved session and removes the saved client configuration. Revocation is checked again after an operator confirmation. The running bridge polls for revocation every 250 ms, shuts down its HTTP server, and terminates its tunnel. It cannot undo or stop an Ableton call that has already started. Revoking the connection in Tanomind also blocks the next tool call. Tanomind outages fail closed; reconnect after access validation fails.

One bridge supports one approved agent at a time. Run separate bridge instances under separate OS accounts/state directories for isolation between multiple agents. Do not share an approved agent's bearer credential: anyone possessing it can impersonate that agent. The bearer model does not prove who is using a copied credential.

State files receive owner-only Unix permissions. On Windows these do not replace NTFS ACLs: keep the state directory in your private user profile and do not share it or synchronize it publicly.


- Treat the bearer token like a password. Never put tokens or app keys in public posts, source control, or logs. Rotate a leaked token by revoking access and restarting.
- The Ableton Remote Script listens on port 9877 with no authentication. Never expose that port. Only the bridge should face the internet.
- Quick tunnel addresses change on every restart. A named Cloudflare tunnel keeps a fixed address.
- Save your set first. Some Ableton tools delete tracks, replace notes or overwrite arrangement regions.

## Troubleshooting

- Every command times out: a dialog is open in Live, often the trial startup nag. Dismiss it.
- AbletonMCP is missing from the Control Surface list: Live only scans scripts at startup, so restart it.

## License

MIT. Ableton and Live are trademarks of Ableton AG. This project is not affiliated with or endorsed by Ableton AG.
