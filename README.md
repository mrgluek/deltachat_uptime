# Delta Chat Uptime Bot

Delta Chat Uptime Bot is a self-hosted uptime monitoring bot (similar to Uptime Kuma) integrated directly with Delta Chat. It monitors resources (websites, APIs, TCP ports, or ping targets) and alerts you inside Delta Chat if they go offline.

Additionally, it automatically generates a secure, beautiful web status dashboard for each chat.

## Features

- 🛡️ **Secure Administration:** Claim ownership with `/initadmin` via private chat. Cryptographic fingerprint-based authentication protects administrative actions.
- 💬 **Per-Chat Isolation:** Each chat (private or group) maintains its own separate list of monitored resources.
- 🚨 **Incident-Based Alerting & In-Place Dynamic Updates:**
  - Instead of flooding the chat with dozens of separate DOWN/UP messages, outages trigger a unified **Incident** per chat.
  - As multiple monitors fail or recover, the bot edits the **same incident message in-place** with real-time status and duration metrics.
  - **Tiered Rate-Limiting:** Status transitions edit the incident message immediately; the live duration is refreshed every 5 minutes during the first day and hourly after that (every edit is a mail to the whole chat).
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
- 🌍 **IPv6:** IPv6 addresses work as targets (`2a00::1`, `[2a00::1]:443`, `https://[2a00::1]/`). A node without IPv6 (no route, or Docker without `enable_ipv6`) does not report IPv6 targets as DOWN: its checks are skipped (⚪ in `/ping`, no alert, status unchanged) and other regions answer instead. Names with both A and AAAA records are checked over IPv4 there, so an unreachable IPv6 address no longer hides the real error.
- 🔒 **SSL Certificate Expiration Monitoring:** Automatically tracks SSL/TLS certificate expiration for HTTPS targets:
  - Periodic checks cached to run at most once per hour.
  - Staged proactive alerts sent to chat at **7 days**, **3 days**, and **24 hours (1 day)** before expiration, as well as upon expiration.
  - Automatic alert state reset when certificate is renewed.
  - Real-time expiration countdown displayed in `/list` and on the Web Status Dashboard.
- 🧹 **Stale Resource Notices & 30-Day Auto-Cleanup:**
  - A resource counts as unreachable for N days when its uptime over the last N days is under 1%. A short recovery (a flap) does not restart the count.
  - **7-Day Notice:** Sends a notice after 7 days unreachable, suggesting removal if decommissioned.
  - **14-Day Warning:** Sends a warning after 14 days, advising that monitors unreachable for 30 days are automatically removed.
  - **30-Day Auto-Cleanup:** Deletes resources unreachable for 30 days and notifies the chat. Removal happens at least 3 days after the 14-day warning, so the warning always comes first.
  - Notices start over only after a resource has been up for a full day.
- 🐢 **Slower Checks for Long Outages:** A resource that stays down is checked less often: every 5 minutes after 1 day, every 15 minutes after 7 days, every hour after 14 days (never more often than its own interval). Recovery is still noticed within that time. `/list` and incident messages show it (`🐢 checked every 15 min`). Targets mirrored from peers slow down the same way and are checked once a day after 30 days, so a dead domain on one node does not keep the whole mesh busy.
- 🛰️ **Distributed Multi-Node Peering & Cross-Probe Verification:**
  - Link multiple bot instances across different regions/servers as remote probes via private 1:1 Delta Chat DMs. Run `/invitepeer` on the other bot and send the `/addpeer <link> token=<token> [node_name]` command it prints to this bot; both bots then exchange telemetry.
  - **Closed Peering:** A bot only becomes a peer if the admin added it with `/addpeer`, or if it presents a single-use `/invitepeer` token (valid 24h). Telemetry and cross-check messages are only accepted from configured peers, in a 1:1 chat, end-to-end encrypted.
  - **Peers Identified by Key:** A peer is bound to its OpenPGP key fingerprint (taken from the SecureJoin invite or the first encrypted message), not to its email address. A bot with several relays may send from any of them and stays the same peer; a message from the peer's address signed by another key is rejected.
  - **Controlled Disclosure (`/peershare`):** By default peers only see monitors from chats the administrator is a member of (`admin`); `all` shares every chat, `none` shares no local monitors. Monitor names are never sent, and targets a peer asked this node to probe are only reported back to that peer, never relayed to others.
  - **Zero Group Spam:** All protocol handshakes, background telemetry, and instant cross-checks happen in private DMs between bots.
  - **Cross-Probe Verification:** Outages are verified across remote probes in real-time before alerting, distinguishing global downtime from regional/routing reachability issues.
  - **Quorum Alerting (`/alertmode quorum`, default):** When a target fails, this node and its live peers vote. If most nodes cannot reach it, it is 🔴 DOWN (incident). If only some cannot (e.g. 1–2 of 4, or only this node), it is 🟠 DEGRADED: one grouped notice in the chat, no incident and no downtime. Alerts show which nodes can and cannot reach the target and why they failed (`🔴 DE, RU (Timeout) · 🟢 IT (196ms)`; with different reasons per node: `🔴 DE (Timeout), RU (SSL: self-signed certificate)`). Nodes that are offline, cannot check the target (IPv6) or ignore it (`/probeignore`) abstain; with fewer than two voters this node decides alone. DEGRADED is entered and left after two consecutive votes. `/alertmode local` keeps the previous behaviour (this node decides).
  - **Failures Seen Only by Peers:** If a peer reports a target DOWN in its telemetry while this node still reaches it, the target's next check asks all peers and votes too, so a target most nodes cannot reach becomes DOWN even when this node can (and DEGRADED if only some cannot).
  - **Status Page & History:** DEGRADED monitors are shown in orange with the last vote; partial outages are listed on the status page, in `/events` and in `/history <id>` (not counted as downtime).
  - **Batched Cross-Checks:** Monitors that fail within the same 5 seconds go to each peer in one message (up to 100 targets) and come back in one, instead of a message per target and peer. In a mass outage this keeps the bots far below the chatmail relays' send limit (60 messages a minute). Bots announce the feature (`caps` in telemetry and check messages); peers that have not announced it yet get the classic one-target requests, so nodes can be updated one at a time.
  - **Telemetry Changes First:** Telemetry carries up to 200 targets every 2 minutes. With more targets, the ones whose status changed go first and the rest are refreshed in turn, so peers learn about an outage within 2 minutes even with 1000+ monitors.
  - **Aggregated Web Dashboard:** Web status pages show latency and status badges for all active probe locations (`[📍 Frankfurt-DE: 18ms] [🛰️ RU-Moscow: 45ms]`).
- 🤖 **Identified User-Agent:** Sends a custom `User-Agent` header (e.g. `Delta Chat Uptime Monitor/2.12.1 (+https://git.gluek.info/gluek/deltachat_uptime)`) during HTTP checks so server administrators can easily identify monitoring requests in server logs. The name deliberately avoids the word "bot", because some services (e.g. Hiddify subscription links) answer `400 Bad Request` to bot User-Agents.
- 🚀 **High-Concurrency Scaling Architecture:**
  - **Two-Tier HTTP Probing (`HEAD` -> `GET` with Auto-Memorization):** Zero body download (0 bytes) and 0 CPU decoding for standard HTTP checks via `HEAD`, with automatic 16 KB `GET` fallback on 405 or errors (not on a timeout or connection error, which a `GET` would only repeat), and 128 KB limit for keyword assertions. When a server responds with `405 Method Not Allowed` to `HEAD` (e.g. GoToSocial, Mastodon, specialized APIs), the bot automatically memorizes `GET` for that monitor and database record so all subsequent checks use `GET` directly without generating repeated `405` log entries.
  - **Async DNS Resolution & 5m TTL Cache:** `aiodns` (`AsyncResolver`) support with 300s TTL cache prevents blocking DNS lookups and reduces repeated nameserver queries.
  - **Native Async ICMP Ping (`aioping`):** Native in-process raw socket pinging eliminates subprocess creation overhead. Without raw socket permissions (hosted containers without `CAP_NET_RAW`) it uses an unprivileged ICMP datagram socket (allowed by `net.ipv4.ping_group_range`, the Docker default), then `/bin/ping`. A node with none of these skips ping checks (⚪ in `/ping`, abstains in votes) instead of reporting them as DOWN.
  - **Deterministic Time Slot Staggering:** Uniform phase slotting (`(r_id * 11) % interval`) spreads checks across 5-second windows, preventing thundering-herd spikes on startup and interval boundaries.
  - **Lock-Free SQLite WAL Concurrent Reads & Persistent Writer:** Dedicated `_write_lock` protects write transactions with a persistent connection (`_writer_conn`) while enabling concurrent lock-free reads for web dashboards and chat status commands.
  - **Zero-Churn Disk I/O (`synchronous=NORMAL`):** Uses SQLite WAL mode with `PRAGMA synchronous = NORMAL`, eliminating fsync overhead during commits and reducing continuous disk writes by >98%.
  - **Non-Blocking Semaphore:** Concurrency semaphore slots are held exclusively for the milliseconds of network probes; retry backoffs (30s) and remote peer checks execute asynchronously without starving healthy checks.
  - **200 Checks at Once:** Checks are async, so the limit is sockets, not CPU (about 0.15 ms of CPU per check, plus 1-3 ms for a TLS handshake: 1000 monitors take a few percent of one core). Up to 200 run at once (`CHECK_CONCURRENCY`, connection pool 250, `nofile` 8192 in `docker-compose.yml`): 300 targets that accept connections but never answer finish in about 20 s instead of 130 s, so a dead data center does not delay the other checks.
  - **One Transaction per Check:** The status of every monitor of a target and the local measurement for the peers are written in one SQLite transaction.
  - **Paced Outbox (send limit):** chatmail relays accept 60 messages a minute per sender (burst 10) and answer `450 Too much mail` above that; the core's retries count too, so a mass outage could delay alerts by minutes. Every message, edit and reaction therefore goes through one queue (`outbox.py`): 50 a minute with bursts of 5, sent by priority - alerts (new / resolved incidents, status changes, SSL, stale, partial outage, admin) → command replies → duration refreshes → peer protocol → telemetry. A queued update of the same incident message (or reaction, or telemetry to the same peer) is merged into the waiting one, so it goes out once with the latest text; peer requests and answers that waited past the peer's timeout are dropped. The minute summary in the log shows a backlog (`outbox waiting 12 (alert 2, peer 10)`).
  - **Quiet Logs:** Only DOWN results, status changes and retries are logged at INFO; routine UP results are DEBUG, and one line a minute sums up all checks (`Checks in the last 60s: 148 (146 up, 2 down, 0 skipped), avg latency 87 ms, slowest …`). With Docker's 30 MB log rotation the history then covers days instead of hours.
  - **Dedicated Thread Pools:** Separate thread executors for database queries (`uptime_db`) and Delta Chat JSON-RPC / SMTP calls (`uptime_rpc`) prevent slow email delivery from stalling database operations.
  - **Single-Query Batch Metrics & In-Memory TTL Cache:** Single SQL batch queries and 60-second TTL caching eliminate N+1 queries across web status pages, `/list`, and `/status`.
  - **Optimized SQLite Indexes:** Comprehensive indexes on downtime intervals, incident states, and peer telemetry ensure sub-millisecond query execution even with tens of thousands of historical records.
- 🔄 **Failure Resiliency & Retry Logic:**
  - Checks resources once a minute.
  - If a resource check fails, the bot does not alert immediately. It retries **2 more times at 30-second intervals**.
  - Alerts are only triggered if all 3 checks fail, avoiding false positives.
  - Once a DOWN resource recovers, it is marked UP on the first successful check.
- 📊 **Uptime Dashboards:** Generates a secure, 12-character unguessable base62 URL (e.g. `https://up.example.com/k8D2x9mPqL1a`) hosting a modern dark-themed web status dashboard with active status, latency metrics, SSL countdowns, and recent incident logs for each chat.
- ✉️ **Multiple Mail Relays:** Supports multiple mail servers. Relay selection and failover are handled by the Delta Chat core (2.61+), which sends via the newest relay first and falls back to the next one if a relay is unreachable.

---

## Commands

### User Commands (Public per-chat)
These commands are available to any member of a chat. They support suffixes (e.g. `/add@up`, `/status@uptime`) to route commands correctly if multiple bots exist in the same chat.

A plain `/help` sent in a group chat is answered in a private 1:1 chat with the sender, so several bots don't flood the group with help texts. Use `/help@uptime` to show the help in the group itself.

- `/ping [-4|-6] <target> ["keyword"]` (or `/check`, `/test`) — Perform an immediate on-demand reachability and diagnostics test without adding to monitoring (rate-limited to 1 request per 15s per chat for non-admins; supports HTTP/HTTPS, SSL certificate inspection, keyword assertions, TCP port, ICMP Ping, and multi-region cross-checks). `-6` / `-4` check a name only over IPv6 / IPv4 (also on the other regions), e.g. `/ping -6 chatmail.uk`.
- `/add <target> [name] ["keyword"]` — Add a monitor. Target formats:
  • `https://google.com Google` (HTTP/HTTPS check)
  • `https://api.site.com Health "status:ok"` (HTTP with keyword assertion)
  • `google.com:443 Google TCP` (TCP port check)
  • `google.com Google Ping` (ICMP Ping check)
  • `2a00::1 Server` / `[2a00::1]:22 SSH` (IPv6 ping / TCP port; with a port the address goes in brackets, as in URLs)
- `/remove <id|url>` (or `/delete`, `/rm`, `/del`) — Stop monitoring a resource by ID or target URL. You can also reply `/remove` directly to any incident or outage alert message to remove the affected monitor without knowing its ID.
- `/pause <id|url> [dur]` (or `/mute`, `/maintenance`) — Mute outage alerts during maintenance (e.g. `/pause 1 30m`, `/pause https://example.com 2h`, or reply `/pause` to an alert).
- `/resume <id|url>` (or `/unpause`) — Resume active monitoring after maintenance.
- `/keyword <id|url> [keyword|none]` — Configure or remove expected keyword assertion.
- `/list` — List monitored resources, status, latency, and SSL expiration in this chat.
- `/status` — View monthly uptime statistics (online / degraded / offline, alert mode) and get the link to the chat's secure Web Status Page.
- `/alertmode [quorum|local]` — How this chat is alerted: `quorum` (default) — DOWN when most nodes cannot reach a target, DEGRADED notice when some cannot; `local` — this node's checks only.
- `/events` — View recent incidents and active outages for this chat.
- `/history [id]` — View downtime history for monitors.
- `/sync` — Synchronize monitored resources with other bots in the same chat (rate-limited to 1/minute for non-admins).
- `/donate` — Support bot development ❤️
- `/help` — View available commands and system information.

### Admin-Only Commands
These commands are only executable by the configured administrator.

- `/url` — View current base external status URL.
- `/url <url>` — Update the base external status URL (e.g., `/url https://up.gluek.info`) to generate correct status links.
- `/probeignore [url|host|pattern]` — On this node, stop probing targets it cannot reach (e.g. blocked in its region or by its ISP) and abstain when peers vote on them. Accepts a target as shown in alerts (`https://nine.testrun.org/`, `dnd.wb.ru:25`), a host (`nine.testrun.org`: all its targets) or a pattern with `*` matched against the target, its host and host:port (`*:25` — all SMTP port checks, `*.testrun.org`). Without arguments lists the entries; `/probeunignore <entry>` removes one.
- `/nodename [name]` — View or set the local probe node identifier (e.g. `/nodename Frankfurt-DE`). Peers (2.17.2+) pick up a new name from the next telemetry message; a name already used by another node is refused.
- `/invitepeer` — Generate a SecureJoin E2E encrypted invite link (`https://i.delta.chat/#...`) with a single-use pairing token (valid 24h) for linking another bot.
- `/peers` (or `/probes`) — List distributed monitoring peers, node names, key fingerprints, the relay address each one last used, and last seen activity.
- `/addpeer <email|link> [token=<token>] [node_name]` — Link another Delta Chat Uptime bot as a remote probe using the command printed by its `/invitepeer` (e.g. `/addpeer https://i.delta.chat/#... token=... RU`). Without a token (e.g. `/addpeer ruptimebot@chat.gluek.info RU`) the other bot's admin must add this bot too.
- `/rmpeer <email|key>` — Remove a remote peer probe by its current address or key fingerprint (the first 8+ hex digits shown by `/peers` are enough). Also stops probing targets it mirrored to this node.
- `/peershare [admin|all|none]` — Choose which local monitors are disclosed to peers (default `admin`: only chats the administrator is a member of).
- `/accounts` — List active bot accounts.
- `/rmaccount <id>` — Delete a bot account.
- `/transports` — Show mail relays: relay used for sending, send queue, incoming status and storage.
- `/addtransport` — Add backup mail relays (either chatmail URIs or address/password). Restricted to private 1:1 chat with the bot for security.
- `/rmtransport <addr>` — Remove backup mail relay.

Relay selection and failover are handled by the Delta Chat core (2.61+): it keeps sending through the relay that last worked and moves to the next one only if it cannot connect, so the relay used for sending can differ from the account's main address. `/transports` shows which relay that is, the core's send queue, and per relay the incoming status, the last received message and mailbox storage. The former `/setprimary` and `/resilient` commands are deprecated and only reply with this explanation.

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
1. Scan the bot's secure join QR code printed in the logs (`docker compose logs uptime_bot`), open the root web dashboard (`/`) to scan the high-resolution vector QR code, or copy the invite link / email address into Delta Chat.
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

## License

MIT, see [LICENSE](LICENSE).
