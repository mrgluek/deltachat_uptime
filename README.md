# Delta Chat Uptime Bot

Delta Chat Uptime Bot is a self-hosted uptime monitoring bot (similar to Uptime Kuma) integrated directly with Delta Chat. It monitors resources (websites, APIs, TCP ports, or ping targets) and alerts you inside Delta Chat if they go offline.

Additionally, it automatically generates a secure, beautiful web status dashboard for each chat.

## Features

- 🛡️ **Secure Administration:** Claim ownership with `/initadmin` via private chat. Cryptographic fingerprint-based authentication protects administrative actions.
- 💬 **Per-Chat Isolation:** Each chat (private or group) maintains its own separate list of monitored resources.
- 🚨 **Incident-Based Alerting & In-Place Dynamic Updates:**
  - Instead of flooding the chat with dozens of separate DOWN/UP messages, outages trigger a unified **Incident** per chat.
  - As multiple monitors fail or recover, the bot edits the **same incident message in-place** with real-time status and duration metrics.
  - **Tiered Rate-Limiting:** Live duration updates adaptively back off (every 15s in the first minute, 30s during minutes 1–5, 1m up to an hour, and 5m after an hour) while status transitions edit immediately with zero delay.
  - When all services recover, the incident message is updated to **Resolved** with total downtime duration.
- 🔍 **Content & Keyword Assertion (Zero-Config + Custom Keywords):**
  - **Zero-Config Error Detection:** In the background, automatically scans HTTP responses for silent failure signatures wrapped in `200 OK` responses (e.g. database connection errors, 502/503 wrapped in HTML, Cloudflare error screens).
  - **Custom Keyword Matching:** Assert that response body contains specific text (e.g. `/add https://api.site.com Health "status:ok"` or `/keyword 1 "Welcome"`).
- ⏸️ **Smart Maintenance Windows & Alert Snoozing:**
  - Pause monitoring and mute outage alerts during planned maintenance without skewing 30-day uptime metrics: `/pause <id|url> [duration]` (e.g. `/pause 1 30m`, `/pause https://example.com 2h`).
  - Supports replying `/pause [duration]` directly to incident alerts.
  - Automatically resumes normal monitoring when the maintenance window expires, or resume early with `/resume`.
- ⚡ **Universal Latency Measurement & Response Time Tracking:**
  - Measures probe latency in milliseconds for HTTP/HTTPS, TCP sockets, and ICMP Ping.
  - Real-time latency badges displayed on the Web Status Dashboard (`⚡ 124ms`) and in `/list`.
- 📜 **Detailed Outage & Incident History:**
  - `/events` (or `/incidents`) — View the chat's historical incident log, active outages, and total downtime durations.
  - `/history [id]` — Inspect recent downtime events for a specific monitor with failure reasons, error codes, and recovery timestamps.
- 🌐 **Host Outage Protection & Circuit Breaker:**
  - Automatically verifies host internet connectivity via high-speed canary checks (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `1.0.0.1`) before declaring any resource DOWN.
  - If the bot host itself loses internet access, false mass-downtime alerts and false downtime logs are suppressed, keeping 30-day uptime metrics accurate.
- 🔒 **SSL Certificate Expiration Monitoring:** Automatically tracks SSL/TLS certificate expiration for HTTPS targets:
  - Periodic checks cached to run at most once per hour.
  - Staged proactive alerts sent to chat at **7 days**, **3 days**, and **24 hours (1 day)** before expiration, as well as upon expiration.
  - Automatic alert state reset when certificate is renewed.
  - Real-time expiration countdown displayed in `/list` and on the Web Status Dashboard.
- 🧹 **Stale Resource Notices & 30-Day Auto-Cleanup:**
  - **7-Day Notice:** Sends a notice when a resource is continuously unreachable for 7 days, suggesting removal if decommissioned.
  - **14-Day Warning:** Sends a warning at 14 days of continuous downtime, advising that 30-day unreachable monitors are automatically removed.
  - **30-Day Auto-Cleanup:** Automatically deletes resources with continuous 0% uptime for 30 days and notifies the chat of the removal.
- 🛰️ **Distributed Multi-Node Peering & Cross-Probe Verification:**
  - Link multiple bot instances across different regions/servers as remote probes via private 1:1 Delta Chat DMs (`/addpeer <email> [node_name]`).
  - **Zero Group Spam:** All protocol handshakes, background telemetry, and instant cross-checks happen in private DMs between bots.
  - **Cross-Probe Verification:** Outages are verified across remote probes in real-time before alerting, distinguishing global downtime from regional/routing reachability issues.
  - **Aggregated Web Dashboard:** Web status pages show latency and status badges for all active probe locations (`[📍 Frankfurt-DE: 18ms] [🛰️ RU-Moscow: 45ms]`).
- 🤖 **Identified User-Agent:** Sends a custom `User-Agent` header (e.g. `DeltaChat-Uptime-Bot/2.4.0 (https://git.gluek.info/gluek/deltachat_uptime)`) during HTTP checks so server administrators can easily identify monitoring requests in server logs.

- 🔄 **Failure Resiliency & Retry Logic:**
  - Checks resources once a minute.
  - If a resource check fails, the bot does not alert immediately. It retries **2 more times at 30-second intervals**.
  - Alerts are only triggered if all 3 checks fail, avoiding false positives.
  - Once a DOWN resource recovers, it is marked UP on the first successful check.
- 📊 **Uptime Dashboards:** Generates a secure, 12-character unguessable base62 URL (e.g. `https://up.example.com/k8D2x9mPqL1a`) hosting a modern dark-themed web status dashboard with active status, latency metrics, SSL countdowns, and recent incident logs for each chat.
- ✉️ **Multi-Transport & Resilient Sending:** Supports multiple SMTP servers and resilient broadcast sending across all connected relays, with automatic exponential backoff failover if a primary transport encounters errors.

---

## Commands

### User Commands (Public per-chat)
These commands are available to any member of a chat. They support suffixes (e.g. `/add@up`, `/status@uptime`) to route commands correctly if multiple bots exist in the same chat.

- `/add <target> [name] ["keyword"]` — Add a monitor. Target formats:
  • `https://google.com Google` (HTTP/HTTPS check)
  • `https://api.site.com Health "status:ok"` (HTTP with keyword assertion)
  • `google.com:443 Google TCP` (TCP port check)
  • `google.com Google Ping` (ICMP Ping check)
- `/remove <id|url>` (or `/delete`, `/rm`, `/del`) — Stop monitoring a resource by ID or target URL. You can also reply `/remove` directly to any incident or outage alert message to remove the affected monitor without knowing its ID.
- `/pause <id|url> [dur]` (or `/mute`, `/maintenance`) — Mute outage alerts during maintenance (e.g. `/pause 1 30m`, `/pause https://example.com 2h`, or reply `/pause` to an alert).
- `/resume <id|url>` (or `/unpause`) — Resume active monitoring after maintenance.
- `/keyword <id|url> [keyword|none]` — Configure or remove expected keyword assertion.
- `/list` — List monitored resources, status, latency, and SSL expiration in this chat.
- `/status` — View monthly uptime statistics and get the link to the chat's secure Web Status Page.
- `/events` — View recent incidents and active outages for this chat.
- `/history [id]` — View downtime history for monitors.
- `/sync` — Synchronize monitored resources with other bots in the same chat (rate-limited to 1/minute for non-admins).
- `/donate` — Support bot development ❤️
- `/help` — View available commands and system information.

### Admin-Only Commands
These commands are only executable by the configured administrator.

- `/url` — View current base external status URL.
- `/url <url>` — Update the base external status URL (e.g., `/url https://up.gluek.info`) to generate correct status links.
- `/nodename [name]` — View or set the local probe node identifier (e.g. `/nodename Frankfurt-DE`).
- `/invitepeer` — Generate a SecureJoin E2E encrypted invite link (`https://i.delta.chat/#...`) for pairing with other bots.
- `/peers` (or `/probes`) — List distributed monitoring peers, node names, and last seen activity.
- `/addpeer <email|link> [node_name]` — Link another Delta Chat Uptime bot as a remote probe using its email address or SecureJoin invite link (e.g. `/addpeer https://i.delta.chat/#... RU` or `/addpeer ruptimebot@chat.gluek.info RU`).
- `/rmpeer <email>` — Remove a remote peer probe.
- `/accounts` — List active bot accounts.
- `/rmaccount <id>` — Delete a bot account.
- `/transports` — Show configured mail relays, status, and stats.
- `/addtransport` — Add backup mail relays (either chatmail URIs or address/password).
- `/rmtransport <addr>` — Remove backup mail relay.
- `/setprimary <addr>` — Switch primary SMTP transport.
- `/resilient` — Toggle resilient sending mode (all relays). Outgoing messages are broadcasted across all connected transports.

---

## Deployment

### Prerequisites
- Docker and Docker Compose installed.
- A dedicated email address for the bot (e.g. `uptimebot@yourdomain.com`).
- A domain name pointing to your host for the status pages (e.g. `up.gluek.info`).

### 1. Build and Prepare
Clone the repository, enter the directory, and build the Docker container:
```bash
cd deltachat_uptime
docker compose build
```

### 2. Configure Email and Admin
Initialize the bot account with your email and password:
```bash
docker compose run --rm uptime_bot python bot.py init uptimebot@yourdomain.com "your_email_password"
```

Configure your admin email address and optionally your cryptographic fingerprint on the server:
```bash
docker compose run --rm uptime_bot python set_admin.py --email admin@yourdomain.com
docker compose run --rm uptime_bot python set_admin.py --fingerprint 1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD
```

### 3. Run the Bot
Start the bot daemon in background:
```bash
docker compose up -d
```

### 4. Claim Ownership inside Delta Chat
1. Scan the bot's secure join QR code printed in the logs (`docker compose logs uptime_bot`) or add the bot's email address in Delta Chat.
2. Send `/initadmin` to the bot in a private message.
3. The bot will automatically verify your identity and associate your cryptographic fingerprint. You are now the administrator!

### 5. Set up Base URL
Tell the bot your public status domain so that it generates correct dashboard links:
```text
/url https://up.gluek.info
```

## Configuration & Profile Customization

You can customize the bot's name, avatar, and status text by passing environment variables (e.g. in your `.env` file or `docker-compose.yml`):

- `DISPLAY_NAME` — Customize the display name of the bot (default: `Delta Chat Uptime Bot`).
- `STATUS_TEXT` — Customize the status/about text of the bot.
- `AVATAR_PATH` — Path to an image file (PNG/JPG) to use as the bot's profile avatar (default: falls back to `icon.png` or `icon.jpg` in the project root).

---

## Reverse Proxy with Caddy

If you use Caddy on your host (like for your ntfy bot), you can expose the status pages by adding the following config to your `/etc/caddy/Caddyfile`:

```caddy
up.gluek.info {
    reverse_proxy 127.0.0.1:8080
}
```

Reload Caddy to apply changes:
```bash
sudo systemctl reload caddy
```
