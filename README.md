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

### Request-forgery guards (operator environment)

A Kuma monitor makes real requests from the Kuma host, so monitor inputs are restricted:

| Variable | Effect |
|---|---|
| `KUMA_MCP_ALLOW_WRITE_METHODS=1` | Allow HTTP methods other than GET/HEAD and request bodies (default: refused) |
| `KUMA_MCP_DENY_HOSTS` | Comma-separated extra denied targets: host, `*` glob, IPv4 CIDR, or `host:port` (IPv6 with a port needs brackets: `[2001:db8::5]:8080`; a malformed entry makes add/edit fail with an error rather than being skipped). Added to the built-ins (loopback, `0.0.0.0`, 169.254.0.0/16, IPv6 link-local/ULA/IPv4-compatible/NAT64, `0.0.0.0/8`, `host.docker.internal`, any host containing `bifrost` or `mcp`). List your gateway host:port here. |
| `KUMA_MCP_ALLOW_HOSTS` | Comma-separated hosts you vouch for (exact, `*` glob or CIDR). A monitor hostname this process cannot resolve (e.g. a Docker service name only Kuma can see) is **refused** unless listed here; listed hosts are also exempt from `KUMA_MCP_DENY_PRIVATE`. Loopback/link-local/gateway and `KUMA_MCP_DENY_HOSTS` entries still apply to them. |
| `KUMA_MCP_DENY_PRIVATE=1` | Also deny RFC1918 (10/8, 172.16/12, 192.168/16) and CGNAT (100.64/10), literal or resolved. Default off. Recommended with a complete `KUMA_MCP_ALLOW_HOSTS`: list the targets you monitor (service names and LAN IPs), then turn this on. |
| `KUMA_MCP_NOTIFICATION_TYPES` | **Notification provider types `create_notification` / `update_notification` may write** (comma list, default `ntfy`). **This narrows earlier behaviour:** apprise, webhook, gotify, smtp, slack, etc. now need operator opt-in, and changing a provider to a type not listed is refused. Recommended production value: `ntfy`. Each enabled type is still checked field by field (per-type destination table). |
| `KUMA_MCP_NOTIFICATION_HOSTS` | **Hosts the URL/host-shaped destination fields of an enabled notification type may point at.** Default empty: such a destination is refused until you list it. Entry grammar: an exact host, IPv4 or `[IPv6]`, or `*.suffix` (whole leading labels, with at least two labels after the star: `*.lan.example` matches `a.lan.example`, not `evillan.example`; `*.com` is ignored), each with an optional `:port`. **A portless entry allows only the scheme's default port (443 for https/wss, 80 for http/ws)**; a destination without a scheme (SMTP host+port, `host:port` values) needs an entry with its port. Bare `*`, CIDRs and other globs are not accepted: they are logged at startup and ignored. Recommended production value: your own ntfy host with its port, for example `ntfy.lan.example:443`. Denylist, loopback, `*bifrost*` and `KUMA_MCP_DENY_HOSTS` still win; the host must also resolve or be in `KUMA_MCP_ALLOW_HOSTS`. **What this does NOT constrain** (so only `ntfy` is recommended, see `KUMA_MCP_NOTIFICATION_TYPES`): apprise token schemes (`discord://`, `tgram://`, `slack://`, `pover://`, `pbul://`) and the SaaS types with no destination field in the table (Telegram without `telegramServerUrl`, Pushover, Pushbullet, LINE, Opsgenie, Twilio, ...) send to any account on that provider; SMTP recipients go through whatever relay you list; a redirect from a listed host is an unchecked second hop. |
| `KUMA_MCP_NTFY_TOPICS` | Optional comma list of ntfy topics `create_notification` / `update_notification` may use (unset or empty = no restriction). The ntfy topic is agent-chosen, and Kuma's default ntfy body carries the raw heartbeat text, so on a multi-tenant ntfy a topic is a destination: **running your ntfy with `auth-default-access: deny-all` (or equivalent) is a REQUIREMENT; this list is defence in depth.** `ntfyserverurl` is required for ntfy and must be the server root (`https://host[:port]` or with a single `/`; no path, dot-segment such as `/.` or `/..`, query or fragment, checked on the raw text), because an empty value makes Kuma pick a default and a POST to `/<topic>` would publish to that topic regardless of `ntfytopic`. |
| `KUMA_MCP_ALLOW_REDIRECTS=1` | Allow `maxredirects` up to 2. Default: forced to 0, because a followed redirect is a second target the denylist never sees. |

Ports in `host:port` entries are taken from the URL (including the scheme default, 80/443) or the monitor's `port`; per-type default ports are only filled in for dns (53), radius (1812) and snmp (161), as the Kuma UI does, and are NOT inferred for other hostname monitors (e.g. ssh/smtp): give those a `port` or deny the bare host. The denylist checks the literal `url`, `hostname` and `dns_resolve_server` (schemes limited to http/https/ws/wss). `hostname` / DNS-server fields must be a bare host name or IP (no scheme, `user@`, port or path). `maxredirects` is forced to 0 (see `KUMA_MCP_ALLOW_REDIRECTS`). While write methods are disabled, editing the target of an existing POST/body monitor is refused. Hostnames are also resolved at add/edit time and every address must pass the denylist; a name that cannot be resolved is refused (fail closed, see `KUMA_MCP_ALLOW_HOSTS`). Remaining gap: the check is point-in-time, so a record that changes afterwards (DNS rebinding) is not seen; only a network egress policy on the Kuma host closes that. The headers `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `X-Forwarded-Server`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded`, `X-Original-Host`, `X-Original-URL`, `X-Rewrite-URL` and `X-HTTP-Method-Override` are refused (a health check that needs `X-Forwarded-Proto` must be configured in the Kuma UI) (object, array and JSON-string shapes). IDN hostnames are accepted (validated in punycode form).

Notification providers: the provider `type` must be enabled in `KUMA_MCP_NOTIFICATION_TYPES` (default `ntfy`) and on the supported table (unknown types are refused). A listed destination field must be a plain string; `apprise` takes exactly one URL (no `,` `;` or second scheme), only http-backed schemes (`json`, `jsons`, `xml`, `xmls`, `form`, `forms`, `http`, `https`) and token schemes (`tgram`, `discord`, `slack`, `pover`, `pbul`); control and invisible characters in a destination are refused; a `webhook` must set `httpMethod` to GET; URL/host destination fields must be listed in `KUMA_MCP_NOTIFICATION_HOSTS` with their port (token-scheme apprise URLs such as `tgram://` go to a fixed service and are not constrained by it; see that row). Each type's destination fields (URL, host+port, multi-value relay lists) pass the same denylist and resolve checks, host and port judged together; apprise `json/jsons/xml/xmls/form/forms://` URLs are checked like http, other apprise schemes against the literal denylist. A field that is not a known destination for its type but holds a URL/host-like value is refused. Tab/CR/LF inside a destination are stripped before checking (URL parsers delete them), other whitespace is refused. `ntfyIcon` (an image URL that ntfy clients fetch) goes through the denylist and `KUMA_MCP_NOTIFICATION_HOSTS` like any destination, and `ntfyCall` (triggers a phone call) needs `KUMA_MCP_ALLOW_WRITE_METHODS=1`. A custom or templated body/title or additional headers (`webhookCustomBody`, `webhookAdditionalHeaders`, `ntfyUseTemplate`, `ntfyCustomTitle`, `ntfyCustomMessage`, SMTP `customSubject`/`customBody`, Telegram templates) needs `KUMA_MCP_ALLOW_WRITE_METHODS=1`; a webhook without an explicit GET `httpMethod` is refused for the same reason. `update_notification` re-checks the stored config merged with your changes, so editing a provider whose stored destination is now denied is refused. `isDefault`, `applyExisting`, `name` and `type` must be top-level parameters, not inside `config`.

**Wildcard hygiene:** `KUMA_MCP_ALLOW_HOSTS`, `KUMA_MCP_DENY_HOSTS` and `KUMA_MCP_NOTIFICATION_HOSTS` reject over-broad `*.` wildcards: a public suffix (`*.com`, `*.co.uk`, `*.com.au`, any two-letter ccTLD, common gTLDs) or a numeric suffix (`*.1.2.3`). **The server refuses to start** with such an entry and names it in the log; use specific hosts or a suffix under your own domain (`*.lan.example`). Homelab suffixes such as `*.lan` and `*.home.arpa` stay allowed. The list of public suffixes is built in and covers common ones, not the full Public Suffix List.

**Deploy note:** because unresolvable names are refused, put every Docker service name you monitor or notify (for example an `ntfy` host) in `KUMA_MCP_ALLOW_HOSTS` BEFORE deploying. `KUMA_MCP_DENY_PRIVATE` is off by default, so LAN services such as 192.168.1.54 stay reachable unless you list them in `KUMA_MCP_DENY_HOSTS`. The allow-list can never un-deny loopback, built-in names (`localhost`, `*bifrost*`, `*mcp*`, metadata) or `KUMA_MCP_DENY_HOSTS` entries; it only exempts the opt-in private ranges and unresolvable names.

Recommended production values for a Docker-service-name-heavy homelab: `KUMA_MCP_ALLOW_HOSTS=<every monitored service name and LAN IP, or *.svc-suffix globs>`, then `KUMA_MCP_DENY_PRIVATE=1`, `KUMA_MCP_DENY_HOSTS=<gateway/vault/admin host:port entries>`; leave write methods and redirects off. Known gap: the `/mcp` HTTP endpoint itself has no authentication; restrict it at the network layer.

Destructive or exposing calls need explicit confirmation: `delete_monitor` / `delete_notification` (`confirmId`), `delete_status_page` (`confirmSlug`), `delete_maintenance` (`confirmId`), `save_status_page` on a published page (`confirmPublic`), a maintenance window of any strategy covering more than 5 monitors, running all day or open-ended (`confirmOpenEnded`), `create_notification` / `update_notification` with `isDefault` or `applyExisting` (`confirmApply`), and `apply_notification_to_all_monitors` with `enabled:false` (`confirmDetach`; `dryRun` now defaults to true). The `confirm*` flags are typo guards, not an agent-proof control: a caller that can set them can set them to true. A `manual` maintenance window always needs `confirmOpenEnded`; for other strategies the rule is computed from the effective schedule (cron expressions that overlap into a permanent silence, durations of 23h or more); `resume_maintenance` is not gated. Push monitors that have no token cannot be edited (tokens are only generated on creation).

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
