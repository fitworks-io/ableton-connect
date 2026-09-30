# ableton-connect

A bridge that lets a remote agent control Ableton Live on your own computer. It wraps the local [Ableton Live MCP Server](https://abletonmcp.com) in an HTTP MCP endpoint that needs a bearer token. It can also publish that endpoint through a Cloudflare quick tunnel and let [Tanomind Connect](https://tanomind.com/tanomind-connect.md) decide which agent gets in.

Tanomind never talks to Ableton. The bridge runs on your PC, and your agent calls it.

## How it works

1. The bridge starts `mcp-server-ableton-live` over stdio and serves the same tools, prompts and resources over streamable HTTP on `127.0.0.1:8765`.
2. Every request needs `Authorization: Bearer <token>`. The token is created once and kept in `~/.ableton-connect/bridge-token`.
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
uv run ableton-connect --tunnel
```

The bridge prints an MCP config with the URL and the bearer header:

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

On start, the bridge registers `/connect/callback` as the app's redirect URL and sets `/tanomind/join` as its agent join URL. Until an agent is approved, it adds a `connect_tanomind` tool and refuses Ableton calls with instructions to connect.

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

- Treat the bearer token like a password. Anyone with it and the URL can drive your Live set.
- The Ableton Remote Script listens on port 9877 with no authentication. Never expose that port. Only the bridge should face the internet.
- Quick tunnel addresses change on every restart. A named Cloudflare tunnel keeps a fixed address.
- Save your set first. Some Ableton tools delete tracks, replace notes or overwrite arrangement regions.

## Troubleshooting

- Every command times out: a dialog is open in Live, often the trial startup nag. Dismiss it.
- AbletonMCP is missing from the Control Surface list: Live only scans scripts at startup, so restart it.

## License

MIT. Ableton and Live are trademarks of Ableton AG. This project is not affiliated with or endorsed by Ableton AG.
