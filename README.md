# uptime-kuma-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![Uptime Kuma](https://img.shields.io/badge/Uptime%20Kuma-compatible-green.svg)](https://github.com/louislam/uptime-kuma)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple.svg)](https://modelcontextprotocol.io)

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that gives AI assistants like **Claude** full control over your [Uptime Kuma](https://github.com/louislam/uptime-kuma) monitoring — list monitors, check heartbeats, create/edit/pause/resume/delete monitors, view notifications, status pages, tags, and maintenance windows. Designed from day one for **multi-instance deployments**: manage one or many Uptime Kuma instances from a single MCP endpoint.

## Why?

Uptime Kuma's web UI is great for manual management, but scripting against its Socket.IO API is cumbersome. This MCP server turns every Uptime Kuma action into a tool that any MCP-compatible AI assistant can call directly. Instead of clicking through the dashboard or reverse-engineering WebSocket events, just ask your AI to check what's down, add a new monitor, or pause checks during maintenance.

Perfect for **homelabbers** running multiple Uptime Kuma instances, **DevOps teams** managing monitoring at scale, and anyone who wants AI-assisted uptime management.

## Features

- **Multi-instance support** — configure 1 to N Uptime Kuma instances via environment variables
- **Full Socket.IO API coverage** — monitors, heartbeats, notifications, status pages, tags, maintenance
- **Read & write operations** — list, create, edit, delete, pause, and resume monitors
- **Persistent connections** — Socket.IO connection per instance with automatic reconnection
- **Docker-ready** — multi-stage Dockerfile with non-root user, health checks, and security hardening
- **Streamable HTTP transport** — works with any MCP client that supports HTTP-based MCP
- **Docker secrets support** — passwords via env vars or `/run/secrets/` files

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/ranklancer/uptime-kuma-mcp.git
cd uptime-kuma-mcp
cp .env.example .env
# Edit .env with your Uptime Kuma URL(s), username(s), and password(s)

mkdir -p secrets
echo "your-kuma-password" > secrets/kuma_password
chmod 600 secrets/kuma_password

cp docker-compose.example.yml docker-compose.yml
docker compose up -d
```

### Node.js

```bash
npm install
npm run build
export KUMA_INSTANCES=kuma
export KUMA_BASE_URL=http://kuma.example.com:3001
export KUMA_USERNAME=admin
export KUMA_PASSWORD=your-password
npm start
```

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full reference.

### Single Instance

```env
KUMA_INSTANCES=kuma
KUMA_BASE_URL=http://192.0.2.1:3001
KUMA_USERNAME=admin
KUMA_PASSWORD=your-password
```

### Multiple Instances

```env
KUMA_INSTANCES=primary,secondary
PRIMARY_BASE_URL=http://192.0.2.10:3001
PRIMARY_USERNAME=admin
PRIMARY_PASSWORD=password1
SECONDARY_BASE_URL=https://198.51.100.1:3001
SECONDARY_USERNAME=admin
SECONDARY_PASSWORD=password2
SECONDARY_INSECURE_TLS=true
```

For each instance name in `KUMA_INSTANCES`, provide:

| Variable | Required | Description |
|---|---|---|
| `<NAME>_BASE_URL` | Yes | Uptime Kuma base URL (e.g. `http://kuma.local:3001`) |
| `<NAME>_USERNAME` | Yes | Uptime Kuma login username |
| `<NAME>_PASSWORD` | Yes | Uptime Kuma login password (or use Docker secrets) |
| `<NAME>_INSECURE_TLS` | No | Set `true` for self-signed certs (default: `false`) |

Docker secrets are supported as a fallback: `/run/secrets/<name>_password` (lowercase).

## Available MCP Tools

### Read Operations

| Tool | Description |
|---|---|
| `uptimekuma_list_monitors` | List all monitors with optional filtering by type, status, keyword, or tag |
| `uptimekuma_get_monitor` | Get detailed info about a single monitor including recent heartbeats |
| `uptimekuma_stats_summary` | Overall uptime statistics (total monitors, up/down/paused counts) |
| `uptimekuma_list_heartbeats` | Heartbeat history for a specific monitor |
| `uptimekuma_list_notifications` | List all notification channels |
| `uptimekuma_list_status_pages` | List public status pages |
| `uptimekuma_list_tags` | List all tags |
| `uptimekuma_list_maintenance` | List maintenance windows |

### Write Operations

| Tool | Description |
|---|---|
| `uptimekuma_add_monitor` | Create a new monitor (HTTP, ping, port, keyword, DNS, Docker, etc.) |
| `uptimekuma_edit_monitor` | Update an existing monitor's configuration |
| `uptimekuma_delete_monitor` | Permanently delete a monitor |
| `uptimekuma_pause_monitor` | Pause a monitor (stops checking) |
| `uptimekuma_resume_monitor` | Resume a paused monitor |
| `uptimekuma_create_tag` / `uptimekuma_add_monitor_tag` / `uptimekuma_remove_monitor_tag` | Create tags; attach/detach them on monitors (`add_monitor` / `edit_monitor` also take a `tags` array) |
| `uptimekuma_add_maintenance` | Create a maintenance window (manual, single, recurring, cron) and attach monitors |
| `uptimekuma_pause_maintenance` / `uptimekuma_resume_maintenance` / `uptimekuma_delete_maintenance` | Manage a maintenance window |
| `uptimekuma_add_status_page` / `uptimekuma_save_status_page` / `uptimekuma_delete_status_page` | Create, update (title, theme, footer, groups) or delete a status page. `save_status_page` replaces the whole group list: pass the complete `groups` array |

### Monitor add / edit semantics

- **`add_monitor`** sends the same complete payload as the Kuma UI (defaults for every NOT NULL column such as `conditions`, `kafkaProducer*`, `rabbitmqNodes`; `accepted_statuscodes` as an array; `timeout` = 80% of `interval`, 10 for ping). Supported fields include `timeout`, `parent`, `docker_host`, `docker_container`, `headers`, `body`, `authMethod`, `basic_auth_user`/`basic_auth_pass`, `maxredirects`, `upsideDown`, `invertKeyword`, `resendInterval`, `expiryNotification`, `tags`. `accepted_statuscodes` takes an array or a comma-separated string.
- **`edit_monitor`** loads the current monitor, merges your changes and emits the FULL object (Kuma's `editMonitor` overwrites every field, so partial payloads used to drop or fail to persist fields such as `keyword` and `accepted_statuscodes`). Omitted fields are preserved; `null` is only applied to nullable columns (`parent`, `docker_host`, ...). A monitor that already holds credentials cannot have its destination changed (url, host, port, docker, auth, ...).

### Secrets

All monitor and notification responses are an allowlist projection: credentials (push token, basic-auth password, headers, bodies, DSNs, notification configs) come back as `{ "value": "***REDACTED***", "present": true|false }`. Credential inputs (`basic_auth_pass`, `headers`, `body`) are accepted on write but never echoed.

**Push monitors:** `pushToken` is deliberately not a tool parameter and is never returned. `add_monitor` with `type: "push"` generates a 32-character alphanumeric token (as the UI does) and returns only the monitor id plus `pushTokenFingerprint` (first 8 hex of its sha256) so you can recognise the token without being able to use it. An MCP client therefore cannot forge heartbeats; read the push URL in the Kuma UI.

### Connection and re-authentication

Kuma binds login to the Socket.IO connection. The client clears its auth state on every `connect` and `disconnect` and logs in again (token first, then password) before the next call, so Kuma restarts and socket.io auto-reconnects no longer end in `You are not logged in.`. As a safety net, a call answered with that message triggers one re-login and one retry.

Every tool accepts an optional `instance` parameter to target a specific Uptime Kuma instance. Defaults to the first configured instance.

## Connecting to Your MCP Client

The server listens on `http://HOST:PORT/mcp` (default: `http://localhost:3000/mcp`).

### Claude Desktop / Claude Code

Add to your MCP settings:

```json
{
  "mcpServers": {
    "uptime-kuma": {
      "url": "http://localhost:3032/mcp"
    }
  }
}
```

### Supergateway (stdio wrapper)

If your MCP client only supports stdio transport, use [supergateway](https://github.com/supercorp-ai/supergateway):

```bash
npx -y supergateway --streamableHttp http://localhost:3032/mcp
```

## Health Check

```bash
curl http://localhost:3032/health
# {"ok":true,"service":"uptime-kuma-mcp","version":"0.1.0"}
```

## Development

```bash
npm install
npm run dev     # Watch mode — recompiles on save
npm start       # Run the server
```

## Requirements

- Node.js >= 20
- Uptime Kuma instance with login credentials
- Network connectivity to your Uptime Kuma instance(s)

## Related Projects

- [Uptime Kuma](https://github.com/louislam/uptime-kuma) — Self-hosted monitoring tool
- [Pi-hole MCP](https://github.com/ranklancer/pihole-mcp) — MCP server for Pi-hole DNS management
- [Model Context Protocol](https://modelcontextprotocol.io) — Open standard for AI tool integration
- [MCP Server Registry](https://github.com/modelcontextprotocol/servers) — Directory of MCP servers

## License

MIT
