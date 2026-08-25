# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] - 2026-08-25

### Added
- **Keyword & Content Assertion (Zero-Config + Custom Assertions):**
  - **Zero-Config Error Detection:** In the background, automatically inspects HTTP response bodies for silent failure signatures wrapped in `200 OK` responses (such as database connection errors, 502/503 errors in title/HTML, Cloudflare error screens).
  - **Custom Keyword Matching:** Supports asserting that response body contains specific text via `/add <url> [name] ["keyword"]` or `/keyword <id|url> [keyword|none]`.
- **Smart Maintenance Windows & Alert Snoozing (`/pause`, `/resume`, `/mute`):**
  - Allows muting outage alerts and suppressing incident creation during planned maintenance: `/pause <id|url> [duration]` (supports durations like `30m`, `2h`, `1d`; default `1h`).
  - Supports replying `/pause [duration]` directly to incident alerts.
  - Automatically resumes active monitoring upon maintenance expiration, or resume manually with `/resume <id|url>`.
  - Excludes maintenance windows from skewing 30-day uptime metrics.
- **Universal Latency Measurement & Dashboard Badges:**
  - Measures probe latency in milliseconds for HTTP/HTTPS, TCP sockets, and ICMP Ping probes.
  - Displays live latency metrics on the Web Status Dashboard (`⚡ 124ms`) and in `/list`.
- **Dashboard & List UI Enhancements:**
  - Added visual badges for active maintenance state (`⏸️ Maintenance`) and expected keywords (`🔍 keyword`).

## [1.8.0] - 2026-08-25

### Added
- **Delete Monitors by Quote / Reply (`/delete`, `/remove`, `/rm`, `/del`):**
  - Replying `/delete` (without arguments) to an incident notification, downtime reminder, or outage alert message now automatically deletes the affected monitor.
  - Safely supports multiple bot instances in the same chat: if a quote belongs to another bot or mentions monitors not owned by this instance, the bot silently ignores it without error or accidental deletions.
- **Delete Monitors by Target URL / Domain:**
  - Added support for deleting monitors directly by URL or domain name (e.g. `/delete https://example.com` or `/remove example.com`), removing the need to look up internal integer monitor IDs.
- **Command Aliases:**
  - Added `/rm` and `/del` aliases alongside `/delete` and `/remove`.

## [1.7.1] - 2026-08-24

### Added
- **Reopen Resolved Incidents on Flapping (1-Hour Window):**
  - If a service recovers but fails again within **1 hour (3600s)** of its previous failure / resolution, the bot reopens the existing incident instead of spamming new incident messages.
  - The message in the chat is edited in-place from `Resolved` back to `Ongoing`, preserving the overall duration of the flapping window.
- **Robust Database Migration Order:**
  - Ensured schema migrations (`ALTER TABLE`) execute prior to index creations (`CREATE INDEX`) to prevent `no such column` startup errors on pre-existing databases.

## [1.7.0] - 2026-08-24

### Added
- **1-Hour Incident Clustering Window & Independent Incidents:**
  - Implemented an incident time-window threshold: service outages occurring within **1 hour (3600s)** of previous failure events are clustered together into the active incident and update the existing alert message.
  - Failures occurring **more than 1 hour** after previous failures now spawn a **new, independent incident** with its own alert message and lifecycle.
  - Each incident tracks its assigned monitors independently, so when monitors belonging to an incident recover, that incident resolves without affecting other ongoing incidents in the same chat.

## [1.6.1] - 2026-08-20

### Added
- **Concise Resolved Incident Messages:**
  - Upon incident resolution, the updated message now displays only the specific monitors that were affected and recovered during the incident (`Recovered Monitors:`), eliminating cluttered lists of dozens of unaffected operational services.
- **Tiered Rate-Limiting for Live Incident Message Edits:**
  - Implemented progressive time-based throttling for in-place live incident duration updates:
    - **First minute (< 60s):** updates at most once every **15 seconds**.
    - **1 to 5 minutes (60s – 300s):** updates at most once every **30 seconds**.
    - **5 minutes to 1 hour (300s – 3600s):** updates at most once every **1 minute**.
    - **1 to 24 hours (3600s – 86400s):** updates at most once every **5 minutes**.
    - **Over 24 hours (> 86400s):** updates at most once every **1 hour**.
  - Immediate updates remain active with zero delay whenever an actual monitor state change occurs (e.g. outage, partial recovery, monitor removal, or resolution).

## [1.6.0] - 2026-08-19

### Added
- **Multi-Transport Resilient Broadcast Sending (`/resilient`):**
  - Standardized resilient sending mode across all connected mail relays. When enabled via `/resilient on`, outgoing messages are broadcasted via the primary transport and all configured backup relays in background threads (`_setup_resilient_mode`).
  - Standardized confirmation and status messages for `/resilient` matching the repository-wide bot convention.
- **Enhanced `/transports` Display & Connectivity Status:**
  - Live transport status parsing from `get_connectivity_html()` (`🔄 Working`, `🟡 Connecting`, `🔴 Not connected`).
  - Active sending indicator `✔︎ Used for sending:` displayed for all connected relays when resilient mode is enabled, and for the active primary relay when disabled.
  - Detailed per-transport `Sent`, `Received`, `Last sent`, and `Last received` timestamp diagnostics.
- **Intelligent Transport Failover with Exponential Backoff (`on_msg_failed`):**
  - Standardized reactive failover mechanism when resilient mode is disabled: automatically retries failed messages across alternative transports with backoff (5s, 10s, 20s... up to 300s) and permanent E2E encryption error detection.

## [1.5.0] - 2026-08-19

### Added
- **Stale Resource Downtime Notices (7 Days & 14 Days):**
  - Sends a reminder at **7 days** of continuous downtime suggesting removal if the target was decommissioned.
  - Sends a warning at **14 days** of continuous downtime notifying that monitors with 0% uptime for **30 days** will be automatically purged.
- **30-Day Continuous Downtime Auto-Cleanup:**
  - Automatically deletes resources that remain unreachable for **30 consecutive days** (0% uptime) from monitoring and notifies the chat with an auto-cleanup message.
- **State Tracking & Recovery Reset:**
  - Persists `stale_warning_level` per resource to prevent duplicate reminder notifications per downtime streak, and automatically resets the level to `0` whenever a resource recovers (`UP`).

## [1.4.0] - 2026-08-19

### Added
- **Incident-Based Alerting & In-Place Dynamic Updates:**
  - Consolidated individual monitor down/up alerts into a single unified **Incident** per chat.
  - When the first monitor fails, an incident is created (`🚨 Incident #X — Ongoing`).
  - As subsequent monitors fail or partially recover, the existing message is edited in-place (`⚠️ Incident #X — Ongoing (Partial Recovery)`), completely eliminating chat spam.
  - Upon full recovery of all monitors, the message is edited in-place to `✅ Incident #X — Resolved` with full duration and operational status.
- **Incident Log Command (`/events` / `/incidents`):**
  - View the list of recent incidents in the chat, active ongoing outages, and historical resolution times and durations.
- **Monitor Downtime History Command (`/history [id]`):**
  - Inspect historical downtime periods for a specific monitor, including exact start/end timestamps, outage duration, and failure cause/error codes (e.g. `502 Bad Gateway`, `Timeout`).
- **Dashboard Incident Feed:**
  - Integrated a sleek "Recent Incidents" section into the Web Status Dashboard showing ongoing and resolved incidents.

## [1.3.0] - 2026-08-19

### Added
- **Host Outage Protection & Canary Connectivity Checks:**
  - Automated outbound internet check across multiple fast DNS canary endpoints (`1.1.1.1:53`, `8.8.8.8:53`, `9.9.9.9:53`, `1.0.0.1:53`) before declaring any monitored resource DOWN.
  - Suppresses false mass-downtime alerts and avoids corrupting 30-day uptime statistics during host network partitions or server internet outages.
- **Circuit Breaker for Mass Failures:**
  - Automatically pauses check execution and alerts when host network loss is detected, resuming smoothly when connectivity is restored.
- **Smart In-Place Alert Editing on Rapid Recovery:**
  - When a resource recovers within 1 hour of going DOWN, the bot edits the original 🔴 DOWN message directly in the Delta Chat chat via `send_edit_request` into the 🟢 UP status instead of sending a separate notification, eliminating chat spam from flapping services.
  - Automatically falls back to posting a new notification message if downtime exceeds 1 hour or if message editing fails.

## [1.2.0] - 2026-08-14

### Added
- **SSL/TLS Certificate Expiration Monitoring:** Automated SSL certificate expiration tracking for HTTPS resources:
  - Non-blocking peer certificate inspection cached to execute at most once per hour per HTTPS target.
  - Multi-stage warning alerts dispatched directly to the Delta Chat chat at **7 days**, **3 days**, and **24 hours (1 day)** prior to expiration, as well as on expiration.
  - Automatic alert state reset when a renewed certificate is detected.
  - Expiration remaining time and date displayed in the `/list` command response and on the Web Status Dashboard monitor cards.

## [1.1.2] - 2026-08-10

### Added
- **Identified User-Agent Header:** Configured a custom `User-Agent` HTTP header (`DeltaChat-Uptime-Bot/<version> (https://git.gluek.info/gluek/deltachat_uptime)`) for all HTTP resource checks to allow server operators to identify and whitelist monitoring requests.

## [1.1.1] - 2026-07-30


### Fixed
- **Standardized `/resilient` Command:** Refactored `/resilient` to match repository standards. Query status without arguments, or explicitly toggle with `on`/`off`/`1`/`0`/`true`/`false`. Migrated state storage to standard `"resilient"` key.

## [1.1.0] - 2026-07-20

### Added
- **Peer-to-Peer Synchronization (`/sync`):** Added resource synchronization between multiple Uptime Bot instances running in the same group chat. Bots automatically exchange and import missing targets locally.
- **Sync Rate Limiting:** Implemented a 1-minute rate limit per chat for non-admin users triggering the `/sync` command to prevent spam. Admins bypass the rate limit.
- **Profile Customization via Env:** Supported `DISPLAY_NAME`, `STATUS_TEXT`, and `AVATAR_PATH` environment variables on initialization to easily configure bot profile details.

## [1.0.2] - 2026-07-06

### Fixed
- **Fix Dependency Conflict/NameError:** Pinned `deltabot-cli==8.1.2` and `deltachat2[full]<1.0.0` in `requirements.txt` to resolve dependency conflicts and avoid the `ChatType` NameError/ImportError bugs introduced in newer, incompatible versions of `deltachat2`.

## [1.0.1] - 2026-07-03

### Fixed
- **Zombie Process Reaping:** Enabled `init: true` in Docker Compose to automatically reap zombie processes (like those from system ping checks) in the bot container, preventing PID limit exhaustion.

## [1.0.0] - 2026-06-29

### Added
- **Initial Release:** Created the Delta Chat Uptime Bot under `deltachat_uptime/` folder.
- **Per-Chat Isolation:** Allows individual chats to configure their own independent monitoring lists.
- **Three Check Modes:** Fully supports HTTP/HTTPS, TCP port, and Ping (ICMP) checks.
- **Retry Mechanism:** Configured failure-mitigation retry checking (initial + 2 retries, 30s apart) to eliminate false alerting.
- **High Concurrency checks:** Developed check scheduling using `asyncio.Semaphore` (limit 50) and SQLite Write-Ahead Logging (WAL) mode for scaling up to 1000+ monitored hosts.
- **Web Status Pages:** Built a responsive Uptime Kuma-like dashboard server on port 8080 with 12-char secure base62 unguessable URL tokens per chat.
- **Secure Administration:** Fully integrates secure setup via `/initadmin` and cryptographic fingerprint verification.
- **Multi-transport Resiliency:** Added multiple SMTP relay failover management commands (`/transports`, `/addtransport`, `/rmtransport`, `/setprimary`, `/resilient`).
- **Containerization:** Exposes Dockerfile and docker-compose.yml configurations.
- **Testing:** Unit tests verifying targets, durations, CRUD operations, database WAL, token generation, and uptime statistics.
