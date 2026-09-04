# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.3] - 2026-09-05

### Added
- **ASCII QR Code in Startup Logs:**
  - Render ASCII QR code directly into stdout on bot startup for easy terminal and container log onboarding.
  - Added line-buffering and explicit flushing for container environments (Docker, Home Assistant Add-on).

### Fixed
- **Relative Web Asset URLs for Ingress:**
  - Changed absolute `/icon.png` and `/favicon.ico` paths to relative (`icon.png`, `favicon.ico`) in both dashboard and index HTML templates so logos and favicons load correctly under Home Assistant Ingress reverse proxy paths.

## [2.7.2] - 2026-09-01

### Optimized
- **Parallel Multi-Region Cross-Check in `/ping`:**
  - Remote probe cross-checks are now dispatched immediately on millisecond 0 in parallel with local checks, SSL inspections, and HTML title parsing.
  - Increased federated probe response timeout to 6.5s to reliably accommodate full HTTP GET and TLS handshakes over E2EE email delivery.

## [2.7.1] - 2026-09-01

### Added
- **Message Reaction Feedback for `/ping`:**
  - Bot reacts with hourglass `⏳` on the user's `/ping` command message immediately upon receipt to indicate ongoing processing.
  - Automatically updates the reaction to checkmark `☑️` upon successful completion (or `❌` if the target is unreachable/errored).

## [2.7.0] - 2026-09-01

### Added
- **On-Demand Target Testing & Diagnostics (`/ping`, `/check`, `/test`):**
  - Added `/ping <target> ["keyword"]` command allowing users to quickly verify any target before adding it to permanent monitoring.
  - Tests HTTP status codes, latency, response time, HTML page titles, and SSL certificate expiration.
  - Supports keyword assertion testing for HTTP/HTTPS endpoints (e.g. `/ping https://gluek.info "and enjoy"`).
  - Automatically queries connected multi-region probes and displays a synchronized reachability breakdown (e.g. Local DE, Remote RU, US).
  - Provides a quick 1-click `/add` suggestion upon successful checks.

## [2.6.2] - 2026-08-27

### Fixed
- **Prioritized Exact URL Matching in `/keyword`:** Fixed target resolution in `get_resources_by_target` so exact URL matches (e.g. `https://dnd.wb.ru/`) take strict priority over scheme-stripped matches (e.g. `dnd.wb.ru` [PING]).
- **HTTP-Only Keyword Enforcement:** Enforced that `/keyword` exclusively targets HTTP/HTTPS monitors and rejects non-HTTP types (PING/TCP), with automatic preference for HTTP monitors when matching ambiguous domain targets.
- **Web Dashboard Keyword Badge Scope:** Ensured that content assertion keyword badges (`🔍 keyword`) render exclusively on HTTP monitors on the status dashboard.

## [2.6.1] - 2026-08-27

### Fixed
- **Bi-Directional Probe Telemetry Broadcast:** Fixed an issue where probe nodes with 0 local chat resources did not include scanned `probe_targets` in outgoing telemetry broadcasts back to primary nodes. Now all measured mirrored targets are broadcast back automatically.
- **Immediate Telemetry Sync on Resource Addition:** Adding a monitor via `/add` immediately invalidates the scheduler cache and triggers background telemetry broadcast to all connected peers.
- **Automatic Probe Target Cache Invalidation:** Incoming telemetry packets immediately invalidate the local `probe_targets` cache so new endpoints are scheduled on the very next scheduler tick without waiting for cache TTL.

## [2.6.0] - 2026-08-27

### Security & Hardening
- **Peer Protocol Authentication & Verification:** Verified all incoming peer protocol messages (`[UPTIME_PEER_*]`) against registered peers table to prevent unauthorized message spoofing.
- **SSRF & Private Network Protection:** Added `is_safe_target_url()` blocking dangerous target queries (localhost, loopback, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254, cloud metadata) during cross-checks and telemetry mirroring.
- **Verified Node Attribution:** Enforced lookup of node names from registered peers database rather than unverified JSON payloads to prevent cross-node metric spoofing.
- **Protocol Message Deduplication:** Added `msg_id` tracking cache to eliminate redundant processing from retransmitted Delta Chat messages.

### Performance & Scalability
- **Rotating Telemetry Window for >100 Targets:** Implemented rotating offset broadcast mechanism ensuring all unique targets are eventually synchronized across nodes regardless of cluster size.
- **Batch Insertion via `executemany`:** Replaced looped individual SQL executions with bulk `executemany` statements for `save_peer_measurements_batch` and `save_probe_targets_batch`.
- **Scheduler Query Caching:** Added TTL-based caching to scheduler loop reducing full-table SQLite scans by over 50% and spaced incident/peer audit intervals to 30s.
- **Thread-safe Future Resolution:** Replaced direct `Future.set_result` with `call_soon_threadsafe` for cross-check response synchronization.

## [2.5.0] - 2026-08-27

### Added
- **Distributed Probe Heartbeat & Mutual Liveness Monitoring:**
  - Automated mesh heartbeat tracking: monitors connected remote probes in the background.
  - **Probe Offline Alerts:** If a remote probe stops sending telemetry for > 6 minutes (3 missed cycles), an alert is dispatched directly to the bot administrator's private Delta Chat inbox (`🚨 Monitoring Probe Offline Alert`).
  - **Probe Recovery Notifications:** When the probe reconnects, the administrator receives an immediate recovery notification detailing the exact downtime duration (`✅ Monitoring Probe Restored`).
  - **Zero Group Noise:** All probe infrastructure alerts are isolated strictly to the administrator's private 1:1 chat without disturbing client/user monitoring groups.
  - Automatic `admin_chat_id` caching to guarantee 100% end-to-end encrypted admin message delivery.

## [2.4.0] - 2026-08-27

### Added
- **Probe Target Ignore List (`/probeignore` & `/probeunignore`):**
  - Added `/probeignore <url>` (and `/ignoreprobe`) allowing administrators on a probe node to exclude specific targets (e.g. region-blocked or geo-restricted services) from remote scanning and telemetry syncing.
  - Added `/probeunignore <url>` to remove targets from the ignore list and resume remote probing upon the next peer sync cycle.
  - Added list view for `/probeignore` (without arguments) showing all currently ignored targets on the probe node.
  - Re-entrant database operations using `threading.RLock()` for high-concurrency safety.

## [2.3.0] - 2026-08-27

### Added
- **Detailed Network & Peer Statistics in `/peers` (`/probes`):**
  - Added summary of total local unique monitored URLs and resources across all chats.
  - Added count of mirrored remote probe targets actively scanned in the background.
  - Added total cached peer telemetry measurements count and per-peer active metrics count.
- **Affected Monitors Breakdown on Web Status Dashboards:**
  - In the "Recent Incidents" section of the status page, each incident card now lists all affected services and targets along with their specific error messages (e.g. `502 Bad Gateway`, `Connection refused`).

## [2.2.0] - 2026-08-27

### Added
- **Automatic Remote Probe Mirroring & Telemetry Sync:**
  - Active monitoring targets added on one bot (in any private chat or group) are automatically mirrored to all peered remote probes in the background.
  - Remote probe bots continuously scan mirrored targets from their location and report real-time latencies back every 2 minutes.
  - **Deduplication by URL:** Scheduled checks group identical targets by URL so each unique endpoint is scanned strictly once per cycle with zero redundant network load.
  - **Universal Multi-Node Dashboards:** Web status pages now display live multi-region latencies (`[📍 DE: 18ms] [🛰️ RU: 45ms]`) across all monitored targets automatically.
  - **Instance-Isolated Dynamic Suffix Routing:** Command suffixes (`@up`, `@de`, `@ruptime`, `@ru`) dynamically match against each bot's own email local-part and configured node name, preventing cross-bot command collisions.

## [2.1.0] - 2026-08-27

### Added
- **E2E Encrypted SecureJoin Peering Support (`/invitepeer` & `/addpeer <link>`):**
  - Added `/invitepeer` (and `/peerinvite`) command to generate a 1:1 SecureJoin invite link (`https://i.delta.chat/#...`).
  - Enhanced `/addpeer` to accept both email addresses and SecureJoin invite links.
  - Automatically executes `secure_join` when adding a peer via invite link, exchanging public PGP keys and establishing strict end-to-end encryption.
  - Fixes `Permanent E2E encryption failure` on strict Chatmail and custom mail servers (e.g. `chat.gluek.info`).
  - Enriched peering handshake payloads with `sender_email` for deterministic identification across instances.

## [2.0.0] - 2026-08-27

### Added
- **Distributed Multi-Node Peering & Cross-Probe Verification via 1:1 Direct Messages:**
  - Link multiple Delta Chat Uptime bots across different datacenters/regions as remote probes (`/addpeer <email> [node_name]`, `/rmpeer <email>`, `/peers` or `/probes`).
  - **Zero Group Spam:** All peering protocol communications (handshakes, telemetry broadcasts, instant cross-checks) are isolated exclusively inside 1:1 private Delta Chat DMs.
  - **No Group Invites Needed:** Secondary bots do not need to be invited into every user group chat; the primary bot queries remote probes directly in private chats.
  - **Cross-Probe Outage Verification:** Before declaring any resource `DOWN`, bots verify availability with configured remote probes in real-time.
  - **Regional Degradation Detection:** Alerts distinguish between confirmed global outages (`DOWN [Confirmed by RU-Moscow]`) and regional connectivity/routing issues (`DEGRADED (Reachable from RU-Moscow: 42ms)`).
  - **Multi-Node Web Status Dashboard:** Status pages now display multi-region latency and availability badges per probe location (e.g. `[📍 Frankfurt-DE: 18ms] [🛰️ RU-Moscow: 45ms]`).
  - **Configurable Node Identifiers (`/nodename [name]`):** Easily name local monitoring probes (e.g. `Frankfurt-DE`, `Helsinki-DO`, `RU-Moscow`).

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
