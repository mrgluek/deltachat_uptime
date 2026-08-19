# Delta Chat Uptime Bot

Delta Chat Uptime Bot is a self-hosted uptime monitoring bot (similar to Uptime Kuma) integrated directly with Delta Chat. It monitors resources (websites, APIs, TCP ports, or ping targets) and alerts you inside Delta Chat if they go offline.

Additionally, it automatically generates a secure, beautiful web status dashboard for each chat.

## Features

- 🛡️ **Secure Administration:** Claim ownership with `/initadmin` via private chat. Cryptographic fingerprint-based authentication protects administrative actions.
- 💬 **Per-Chat Isolation:** Each chat (private or group) maintains its own separate list of monitored resources.
- ⚙️ **Three Check Modes:**
  - **HTTP/HTTPS:** Checks status code and latency (e.g. `https://example.com`).
  - **TCP Port:** Checks port availability (e.g. `example.com:22`).
  - **Ping (ICMP):** Sends standard ICMP echo requests (e.g. `example.com`).
- 🌐 **Host Outage Protection & Circuit Breaker:**
  - Automatically verifies host internet connectivity via high-speed canary checks (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `1.0.0.1`) before declaring any resource DOWN.
  - If the bot host itself loses internet access, false mass-downtime alerts and false downtime logs are suppressed, keeping 30-day uptime metrics accurate.
- ✍️ **Smart Alert Editing on Rapid Recovery:**
  - If a resource recovers within **1 hour** of going DOWN, the bot edits the original 🔴 DOWN message into the 🟢 UP notification in-place instead of posting a new message, completely eliminating chat notification noise for flapping services.
- 🔒 **SSL Certificate Expiration Monitoring:** Automatically tracks SSL/TLS certificate expiration for HTTPS targets:
  - Periodic checks cached to run at most once per hour.
  - Staged proactive alerts sent to chat at **7 days**, **3 days**, and **24 hours (1 day)** before expiration, as well as upon expiration.
  - Automatic alert state reset when certificate is renewed.
  - Real-time expiration countdown displayed in `/list` and on the Web Status Dashboard.
- 🤖 **Identified User-Agent:** Sends a custom `User-Agent` header (e.g. `DeltaChat-Uptime-Bot/1.3.0 (https://git.gluek.info/gluek/deltachat_uptime)`) during HTTP checks so server administrators can easily identify monitoring requests in server logs.

- 🔄 **Failure Resiliency & Retry Logic:**
  - Checks resources once a minute.
  - If a resource check fails, the bot does not alert immediately. It retries **2 more times at 30-second intervals**.
  - Alerts are only triggered if all 3 checks fail, avoiding false positives.
  - Once a DOWN resource recovers, it is marked UP on the first successful check.
- 📊 **Uptime Dashboards:** Generates a secure, 12-character unguessable base62 URL (e.g. `https://up.example.com/k8D2x9mPqL1a`) hosting a modern dark-themed web status dashboard for each chat.
- ✉️ **Multi-Transport Failover:** Supports multiple SMTP servers and automatically falls back to backups if message delivery fails.

---

## Commands

### User Commands (Public per-chat)
These commands are available to any member of a chat. They support suffixes (e.g. `/add@up`, `/status@uptime`) to route commands correctly if multiple bots exist in the same chat.

- `/add <target> [name]` — Add a monitor. Target formats:
  - `https://google.com` (HTTP/HTTPS check)
  - `google.com:443` (TCP port check)
  - `google.com` (ICMP Ping check)
- `/remove <id>` — Stop monitoring a resource by ID.
- `/list` — List monitored resources and their status in this chat.
- `/status` — View monthly uptime statistics and get the link to the chat's secure Web Status Page.
- `/sync` — Synchronize monitored resources with other bots in the same chat (rate-limited to 1/minute for non-admins).
- `/help` — View available commands and system information.

### Admin-Only Commands
These commands are only executable by the configured administrator.

- `/url` — View current base external status URL.
- `/url <url>` — Update the base external status URL (e.g., `/url https://up.gluek.info`) to generate correct status links.
- `/accounts` — List active bot accounts.
- `/rmaccount <id>` — Delete a bot account.
- `/transports` — Show configured mail relays, status, and stats.
- `/addtransport` — Add backup mail relays (either chatmail URIs or address/password).
- `/rmtransport <addr>` — Remove backup mail relay.
- `/setprimary <addr>` — Switch primary SMTP transport.
- `/resilient` — Toggle resilient sending (attempts sending on backups if primary fails).

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
