# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.17.0] - 2026-10-17

### Added
- **Quorum Also When Only Peers See the Failure**: In 2.16.0 the vote started only when this node's own check failed, so a target this node reached but most other nodes did not (e.g. blocked in one country, broken routing) raised nothing. Now, when a peer's telemetry reports a target DOWN (a result at most 5 minutes old) that is UP here, in a `quorum` chat, the target's next regular check asks all peers and votes: most nodes cannot reach it → 🔴 DOWN; some cannot → 🟠 DEGRADED after two votes (about two telemetry rounds). Peers are asked about such a target at most once per 2 minutes, however many of them report it.
- **Status Page**: DEGRADED monitors are shown in orange with their last vote (`🔴 RU · 🟢 DE (40ms), IT (9ms)`), the header says "N Service(s) Unreachable From Some Regions" when nothing is down but something is degraded, and a "Partial Outages" section lists recent ones (ongoing and ended, with the nodes that could not reach the target).
- **`/events` and `/history <id>`** list partial outages too, marked as not counted as downtime. `/events` no longer says only "No incidents" when there were partial outages.

### Changed
- In quorum results the check error and the vote are separated by " — " instead of nested parentheses, e.g. `timeout — Unreachable from 🇩🇪 DE, 🇷🇺 RU; reachable from 🇮🇹 IT`.

## [2.16.0] - 2026-10-17

### Added
- **Quorum Alerting (`/alertmode quorum`, default for every chat)**: Whether a target is down was decided by this node alone; peers' cross-check answers were only appended to the error text. A problem on this node's own network raised a full DOWN incident even when every other node reached the target. Now, when a target fails here (after the usual two retries and the host connectivity check), this node and its live peers vote:
  - more than half of the voting nodes cannot reach it → 🔴 **DOWN**, an incident as before;
  - some, but not most, cannot reach it → 🟠 **DEGRADED**: a notice in the chat ("Partial Outage"), no incident, not counted as downtime. Entered and left only after two consecutive votes, so a single flap does not notify;
  - fewer than two voters (no live peers, no answers, monitor not shared by `/peershare`) → this node decides alone, as before.
  Votes are per node (RU and RU2 count separately). Offline peers, peers that cannot check the target (IPv6) and peers that `/probeignore` it abstain.
- **Who Can Reach It, in Every Alert**: Incident messages, `/list` and DEGRADED notices show the vote, e.g. `🔴 DE, RU, RU2 · 🟢 IT (196ms)`. The answers are also kept for monitors in `local` mode.
- **`/alertmode [quorum|local]`**: Per chat. `local` keeps the previous behaviour. Without arguments it explains the current mode, how many nodes vote and the majority needed, and warns when the chat's monitors are not shared with peers.
- **Partial outage history**: DEGRADED periods are recorded (`partial_outages`) for the status page and history in the next release.

### Changed
- **`/probeignore` Targets Abstain in Cross-Checks**: A node that ignores a target (e.g. blocked in its region) used to answer cross-checks for it with `down`. It now answers `skip`, so it does not vote.
- **Offline Peers Are Not Asked**: Cross-checks skip peers marked offline instead of waiting for them to time out.
- **DOWN/DEGRADED Targets Ask Peers Less Often**: While a target stays down or degraded and this node's own result does not change, peers are asked again at most every 2 minutes (every 10 minutes after the first hour), not on every check. Retries are no longer repeated every minute for DEGRADED targets.
- `/status` shows degraded monitors and the alert mode; `/list` shows 🟠 DEGRADED.

### Upgrade Notes
- Chats switch to `quorum` automatically. Run `/alertmode local` in a chat to keep the old behaviour.
- Quorum needs peers: with none (or none live) nothing changes. Monitors outside `/peershare` are decided locally.
- Nodes on older versions still vote (they answer cross-checks); only the `/probeignore` abstention needs this version on the ignoring node.

## [2.15.0] - 2026-10-17

Ready for 1000+ monitors. Measured on de2 (148 monitors) the bot used 1.5 % of one core, and a local benchmark put the bot's own work at about 0.15 ms of CPU per check (plus 1-3 ms for a TLS handshake), so CPU is not what limits it; the changes below address what does.

### Changed
- **Hung targets no longer block the queue**: a `HEAD` request that times out (or cannot connect: refused, DNS, certificate) is no longer repeated as `GET`, which held a check slot for a second full timeout. Up to 200 checks run at once instead of 50 (`CHECK_CONCURRENCY`; HTTP connection pool 250, since aiohttp counts the wait for a pooled connection against the timeout), and `docker-compose.yml` raises the open-file limit from 1024 to 8192. 300 targets that accept connections but never answer: 131 s before, 21 s now - before, they delayed every other check past its one-minute interval.
- **Batched peer cross-checks**: failing monitors found within 5 seconds are sent to each peer in one `[UPTIME_PEER_CHECK_BATCH_REQ]` message (up to 100 targets, identical targets once), answered with one `[UPTIME_PEER_CHECK_BATCH_RESP]`; the peer runs them 20 at a time. Before, each failing target sent a message to every peer and got one back - 600 mails per peer a minute for 300 failing targets, far over the relays' 60 messages a minute. Bots announce support with `caps: ["batch_check"]` in telemetry and check messages; until a peer has announced it, it gets the old one-target requests, so mixed versions keep working. Answers are only accepted from the chat the batch went to; URLs are taken from the request, the peer's answer only fills positions; refused targets keep their position as "Target refused".
- **Telemetry with changes first**: with more than 200 targets per peer, each message starts with the targets whose status changed since the last one and fills the rest by rotation over the whole list, so a status change reaches peers within 2 minutes even with 1000+ monitors (before: up to 10 minutes). 200 per message stays, as receivers take no more.
- **Quiet logs**: `Check result` lines are INFO only for DOWN results and status changes, routine UP results and `Triggering N target checks` are DEBUG, and a summary is logged once a minute: `Checks in the last 60s: 148 (146 up, 2 down, 0 skipped), avg latency 87 ms, slowest … ; running now: 3`. At 1000 monitors the per-check lines alone filled Docker's 30 MB log rotation in 2-3 hours.
- **One DB transaction per check**: the status of every monitor of a target and the local peer measurement are written together (`database.record_check_results`) instead of in 2+ transactions. Results are still written right away: deferring them would let the scheduler re-read an old `last_checked` and run the same check twice.

## [2.14.0] - 2026-10-17

### Added
- **IPv6 targets**: `/ping` and `/add` accept IPv6 addresses - `2a00::1` or `[2a00::1]` (ICMP ping), `[2a00::1]:443` (TCP; with a port the address goes in brackets, as in URLs, because `2a00::1:22` is itself a valid address). Addresses are stored normalized (compressed, lowercase). Private, link-local and loopback IPv6 addresses stay blocked.
- **`/ping -4` / `/ping -6`**: check a name only over IPv4 / IPv6, like `ping -4/-6`. The flag is sent to the other regions too (older peers ignore it and check either family); a name without an address of that family gets "has no IPv6 address". The `/add` hint is left out, since monitors have no family setting; `/add -6` explains to add the address itself.

### Fixed
- **IPv6 address read as host:port**: `/ping 2a00:da00:f443:e900::1` was parsed as a TCP check of `2a00:da00:f443:e900:` on port 1 and failed with "Name or service not known".
- **No IPv6 on a node is not an outage**: before connecting, the bot asks the kernel for a route to each IPv6 address (a UDP `connect()`, which sends nothing). Unroutable IPv6 addresses are dropped, so a host with A and AAAA records is checked over IPv4 instead of failing with `[Errno 101] Connect call failed ('2a00:…', 22)`. An IPv6-only target on such a node is skipped - no retries, no peer cross-check, no alert, status unchanged - and `/ping` shows ⚪ "Not checked" with the verdict of the other regions. Peers answer such requests with status `skip` (shown as ⚪). `/add` of an IPv6 target warns when this node has no IPv6.
- **TCP error of the preferred address**: when every address of a host fails, the error of the first one (IPv4 first) is reported instead of the last one.
- **Peer measurements of IPv6 targets**: check responses were classified as TCP whenever the target contained ":", so IPv6 ping targets were dropped as unsafe; the type now comes from the same parser as `/add`.

## [2.13.0] - 2026-10-16

### Changed
- **Peers Identified by Key Fingerprint, Not Address**: Since Delta Chat 2.61 a bot can have several relays and sends from whichever one is reachable. Peers were stored and matched by email address, so as soon as a peer switched relays (e.g. `ruptimebo@chat.gluek.info` → `ruptimebot@chatmail.uk`) its telemetry, cross-check requests and answers were dropped as coming from an "untrusted sender", although they arrived end-to-end encrypted, from the same key, in the same 1:1 chat. Each peer now stores its OpenPGP fingerprint:
  - taken from the invite when adding a peer with `/addpeer <link>`, from an encrypted `HELLO` when a bot pairs with an `/invitepeer` token, or from the first encrypted message for existing peers;
  - incoming peer messages are matched by fingerprint first; the stored address and 1:1 chat follow the peer, and probe targets it mirrored to this node move with it;
  - once a key is bound, a message from the peer's address signed by another key (or unencrypted) is rejected, which is stricter than the address check before.
- **Cross-Check Answers Matched by Chat**: Answers are expected from the 1:1 chats the request was sent to instead of from the addresses, so a peer answering via another relay is still counted.
- **`/peers` Shows Keys, `/rmpeer` Accepts Them**: `/peers` shows the first 16 hex digits of each peer's key (or "not bound yet"). `/rmpeer` accepts the current address, the full fingerprint or a unique prefix of at least 8 hex digits.
- **Re-adding a Known Bot**: `/addpeer <link>` for a bot whose key is already a peer updates that peer instead of creating a second entry.

### Upgrade Notes
- No action needed. Existing peers are bound to their key on their first encrypted message: in their 1:1 chat (also when they already send from a new address) or from their stored address. Peers that switched relays before this release recover on the next telemetry round (every 2 minutes).
- All nodes should run 2.13.0: an older node still drops this node's messages once this node sends from another relay.

## [2.12.1] - 2026-10-16

### Added
- **MIT License**: the project is now licensed under MIT (`LICENSE`).

### Fixed
- **Crash Risk in DNS Pinning**: 2.12.0 created and closed a new aiodns/pycares resolver for every lookup. Queries cancelled by a timeout were torn down mid-flight, and pycares destroys channels in a background thread that can crash the interpreter at shutdown (the test run on `main` ended with SIGBUS, exit code 135, after the PR run had passed). Lookups now share one long-lived resolver per event loop, which is how aiodns is meant to be used.
- **Tests Made Hermetic**: Some peer and redirect tests performed real DNS queries, which only happened in CI (where the network is reachable). All tests now stub DNS, and CI runs with `-X faulthandler` so a native crash prints a traceback.

## [2.12.0] - 2026-10-16

### Security
- **No More Automatic Peering**: Any Delta Chat user could send a `[UPTIME_PEER_HELLO]` message to the bot, be added as a peer automatically and from then on receive every monitor of every chat every 2 minutes. An unknown bot is now only accepted as a peer if it presents a single-use token from `/invitepeer` (valid 24h); the admin is notified when that happens. `HELLO_ACK` is only accepted from bots the admin added. Without a token, both admins have to run `/addpeer` for each other.
- **Peer Messages Only From Peers**: `CHECK_REQ`, `CHECK_RESP` and `METRICS` were processed from any sender, so anyone could make the bot probe arbitrary hosts, plant up to 200 probe targets per message and inject fake per-node results into public status pages. They are now accepted only from configured peers, in a 1:1 chat and end-to-end encrypted (padlock). The sender is taken from the Delta Chat contact only; `sender_email` and `node_name` in the payload are no longer trusted.
- **Cross-Check Responses Bound to Requests**: A response is only accepted for a pending `req_id`, from a peer the request was sent to, once per peer. Request IDs are now 96-bit.
- **Controlled Disclosure (`/peershare admin|all|none`)**: Telemetry and cross-check requests now include only monitors from chats the administrator is a member of (`admin`, default). `all` restores the previous behaviour, `none` shares no local monitors. Monitor names are no longer sent. `/ping` from non-admin users reaches peers only with `all`.
- **No Relaying of Mirrored Targets**: Targets one peer asked this node to probe are reported back only to that peer instead of being forwarded to every other peer (and from there further across the mesh). Each peer can make this node probe at most 200 targets; `/rmpeer` removes the targets mirrored from that peer.
- **SSRF via Redirects**: HTTP checks and `/ping` title fetches followed redirects without re-validating them, so a public URL could redirect the probe to `127.0.0.1` or cloud metadata addresses. Redirects are now followed manually (at most 10) and every hop is checked by the SSRF filter.

- **DNS Rebinding Protection**: Targets were validated with one DNS lookup and then connected to after a second, independent lookup, so a hostname could answer with a public address during validation and with `127.0.0.1` or a cloud metadata address at connect time. All probe connections (HTTP checks, redirects, TCP, ping, SSL expiry, `/ping` title fetch) now go through one resolver that checks every address and pins the validated answer for the record's TTL (clamped to 30–300 s, 60 s when the TTL is unknown). After expiry the new answer is validated again. HTTP checks use a custom aiohttp resolver; TCP, ping and SSL checks connect to the validated IP; the title fetch connects to the pinned IP with the original hostname for SNI and no longer uses environment proxies. DNS is now resolved asynchronously (aiodns, falling back to the system resolver for `/etc/hosts`) instead of blocking the event loop on every check.

### Fixed
- **TCP Targets With IPv6 Literals**: `[::1]:22` style targets were not recognised as IP literals by the SSRF filter.
- **SecureJoin Peers With Unknown Address**: A peer stored under the `peer_<chat>@securejoin` placeholder never matched incoming messages. The placeholder is now replaced with the real address on the first message in that chat.

### Upgrade Notes
- Existing peers keep working. Pairing with a new bot requires the `/addpeer ... token=...` command printed by `/invitepeer` (or `/addpeer` on both sides).
- Unencrypted peer telemetry is dropped. Bots exchange keys during the HELLO handshake, so this only affects peers on classic email providers without Autocrypt.
- If you relied on peers seeing monitors of all chats, run `/peershare all`.

## [2.11.1] - 2026-10-15
- **User-Agent No Longer Contains "Bot"**: HTTP checks now send `Delta Chat Uptime Monitor/<version> (+https://git.gluek.info/gluek/deltachat_uptime)` instead of `DeltaChat-Uptime-Bot/...`. Hiddify Manager (and other services that block crawlers) answered `400 Bad Request` to any User-Agent containing "bot", so working subscription links showed as down while they opened fine in a browser.

## [2.11.0] - 2026-10-14
- **`/transports` Shows the Relay Actually Used for Sending**: Since core 2.61 the core sends through the relay that last worked and switches only when it cannot connect, so the main address (`configured_addr`) says nothing about where mail goes out. `/transports` now lists relays in the order the core tries them, with the current sending relay first, shows the core's send queue (waiting messages and retries) and outgoing status, and per relay the incoming status, when the last message arrived, mailbox storage usage (⚠️ from 80%) and when it was added. The sending order and queue are read from the core's account database (read-only); the report is built by the shared `transports_view.py`.
- **Removed Misleading Per-Relay Sent/Received Counters**: They credited every message to `configured_addr` (or, in some places, the wrong address), so the numbers and "last sent" dates were wrong once the core sent through another relay. Counting them also cost extra RPC calls per message. The `transport_stats` table is left in place but no longer updated.

## [2.10.0] - 2026-09-28

### Removed
- **Bot-Side Relay Failover**: Removed the `MSG_FAILED` failover handler and the resilient-send `send_msg` patch. Both switched `configured_addr` and called `resend_messages`, but since Delta Chat core 2.61 the SMTP relay is no longer chosen by `configured_addr`: the core tries the newest relay first and falls back to the next one if a relay is unreachable. The old logic could no longer switch relays and only caused delayed duplicate resends.

### Changed
- **`/setprimary` and `/resilient` Deprecated**: Both commands are disabled and only reply with an explanation of how the core picks relays now. They are removed from `/help` and the README.
- **`/transports` Sending Order**: Relays are listed newest first, in the order the core tries them for sending, instead of marking `configured_addr` as "Used for sending".
- **Core Requirement**: `requirements.txt` now requires `deltachat-rpc-server>=2.62.0`.

## [2.9.7] - 2026-09-24

### Fixed
- **`update.sh` Deployed the Wrong Branch**: Branch detection took the first remote branch in alphabetical order, so a leftover PR branch such as `origin/claude/...` sorted before `origin/master` and was deployed instead (and new `master` commits were reported as "Already up to date"). It now follows the checked-out branch, falling back to `main`/`master`.

## [2.9.6] - 2026-09-24

### Changed
- **Private `/help` in Groups**: A plain `/help` sent in a group chat is now answered in a private 1:1 chat with the sender instead of the group, so several bots don't flood it with help texts (the reply ends with a note on how to show it in the group). Addressed `/help@uptime` is still answered in the group. Previously a plain `/help` was answered in the group, or silently ignored when other bots were present.

## [2.9.5] - 2026-09-22

### Fixed
- **False SSRF block for hosts with Yggdrasil IPv6 records**: Domains publishing an AAAA record in the Yggdrasil mesh range (`200::/7`, e.g. `cm1.wwire.su`) were rejected with "Target blocked: internal or private network address", because Python's `ipaddress` flags that range as reserved. Yggdrasil addresses are now treated as routable, while other reserved ranges stay blocked. IP checks are consolidated in a new `_is_blocked_ip()` helper.

## [2.9.4] - 2026-09-16

### Security
- **SSRF & DNS Rebinding Hardening (`is_safe_target_url`)**:
  - Enforced DNS resolution checks in `is_safe_target_url()` to verify that resolved IP addresses do not map to loopback (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.169.254`), multicast, or reserved ranges.
  - Added blocking for local domain name suffixes (`.local`, `.internal`, `.lan`, `.localdomain`).
  - Added SSRF checks in `/add` command, preventing users from registering internal or metadata endpoints.
  - Added SSRF checks in `fetch_html_title()`, preventing title resolution on internal addresses.
  - Added direct SSRF guard in `run_single_check()` as defense-in-depth against malicious targets.
- **Request Body Limits & Rate Limiting**:
  - Configured `client_max_size = 256 * 1024` (256 KB) on `web.Application` to protect web endpoints from unbounded payload DoS.
  - Added sliding-window rate limiting on public web endpoints (`GET /` and `GET /{token}`) with HTTP 429 `Retry-After: 60` headers.
- **Dependency Pinning**:
  - Pinned `aiohttp>=3.10.5,<4.0.0`, `qrcode[pil]>=7.4.2,<8.0.0`, `pillow>=10.4.0,<11.0.0`, `emoji>=2.12.0,<3.0.0`, `appdirs>=1.4.4,<2.0.0`, `aiodns>=3.2.0,<4.0.0`, and `aioping>=0.3.3,<1.0.0` in `requirements.txt`.

## [2.9.3] - 2026-09-14

### Added
- **Auto-Memorization of GET Method on HTTP 405 (Method Not Allowed)**:
  - When a target server responds with `405 Method Not Allowed` to a lightweight `HEAD` probe (common on GoToSocial, Mastodon, and specialized web frameworks that disallow HEAD on root or API endpoints), the bot now automatically remembers `GET` as the preferred method for that monitor and URL.
  - Persisted to database via new `http_method` column in `resources` and `probe_targets` tables, and synchronized with active in-memory scheduler caches.
  - Subsequent minute checks bypass the `HEAD` attempt and directly issue `GET` requests, eliminating redundant `405` error log entries on target servers and halving network overhead for those endpoints.

## [2.9.2] - 2026-09-10

### Fixed
- **Persistent SQLite Writer Connection & Elimination of Continuous Disk Writes**:
  - Resolved root cause of continuous disk I/O (~500 kB/s on Linux ext4 / `jbd2` journal): SQLite in WAL mode defaults to connection-scoped `synchronous = FULL`, causing `fdatasync()` on every single commit. When combined with ephemeral per-operation database connections, every monitor check caused repeated WAL header synchronizations and ext4 journal commits.
  - Implemented a dedicated persistent writer connection (`_writer_conn`) and `_writer_transaction()` context manager under `_write_lock`, eliminating per-check connection open/close churn and reusing the connection across all database writes.
  - Enforced `PRAGMA synchronous = NORMAL;` across all reader and writer connections. In WAL mode, `NORMAL` guarantees full ACID durability and WAL crash-safety while eliminating `fdatasync()` during transaction commits, reducing fsync operations by >98% (from 400+ calls per 100 commits to 0 during commits).
  - Added `close_db()` lifecycle helper for clean connection teardown and test isolation.

## [2.9.1] - 2026-09-10

### Fixed
- **Container Environment Compatibility (`socket.getprotobyname("icmp")` / `OSError: protocol not found`)**:
  - Added a defensive IANA protocol number fallback (`IPPROTO_ICMP = 1`, `IPPROTO_ICMPV6 = 58`) for `socket.getprotobyname` during `aioping` initialization, preventing startup crashes in minimal container base images lacking `/etc/protocols` (such as Debian minimal without `netbase` or minimal Alpine in Home Assistant Add-ons).
  - Widened `import aioping` and `import aiodns` exception handling to catch all `Exception`/`OSError` types, guaranteeing safe fallback to `/bin/ping` subprocesses if socket initialization fails for any reason.
  - Added `netbase` to `Dockerfile` dependencies to supply `/etc/protocols` out-of-the-box.

## [2.9.0] - 2026-09-10

### Added
- **Native Async ICMP Ping (`aioping`)**:
  - Integrated `aioping` for native in-process ICMP echo requests, avoiding OS subprocess spawning overhead on ping monitors.
  - Implemented graceful fallback: automatically falls back to system `/bin/ping` subprocess if `aioping` is unavailable or if raw socket permissions (`CAP_NET_RAW`) are restricted.
- **Asynchronous DNS Resolver & 5-Minute DNS TTL Caching (`aiodns`)**:
  - Added `aiodns` integration with `aiohttp.AsyncResolver`, eliminating blocking system `getaddrinfo` calls from thread pools during routine HTTP/HTTPS checks.
  - Configured 5-minute DNS caching (`ttl_dns_cache=300, use_dns_cache=True`) across the shared monitoring session.
- **Deterministic Time Slot Staggering**:
  - Implemented uniform deterministic phase staggering (`(r_id * 11) % interval`) to evenly distribute monitor checks across 5-second execution windows, eliminating thundering-herd CPU/network spikes on bot startup and synchronized intervals without expensive hashing.
- **Concurrent Lock-Free SQLite WAL Reads (`_write_lock`)**:
  - Separated SQLite synchronization into a dedicated `_write_lock` for database mutations (`INSERT`, `UPDATE`, `DELETE`, batch updates, and pruning).
  - Unlocked all read-only queries (`SELECT`) with `_connect()` and `PRAGMA busy_timeout = 5000`, enabling parallel non-blocking reads across web status dashboards, commands (`/status`, `/list`), and background workers.
  - Maintained `_lock = _write_lock` alias for full backwards compatibility.

### Changed
- **Two-Tier HTTP Monitoring Strategy (`HEAD` -> `GET`)**:
  - For standard HTTP/HTTPS monitors without keyword assertions, the bot now issues a lightweight `HEAD` request first (transferring 0 body bytes and 0 CPU decode overhead).
  - Automatically falls back to `GET` reading at most 16 KB (`16384` bytes) if the server returns non-2xx/3xx (e.g. `405 Method Not Allowed`) or on connection errors.
  - When custom keyword assertions are configured, direct `GET` is used with body reading capped at 128 KB (`131072` bytes, reduced from 256 KB).
  - `fetch_html_title` buffer reduced from 64 KB to 16 KB (`16384` bytes).

## [2.8.0] - 2026-09-09

### Added
- **Performance Indexes for SQLite**:
  - Added indexes on `downtime_events` (`went_up_at`, `(resource_id, went_down_at, went_up_at)`), `incidents` (`(dc_chat_id, status)`, `resolved_at`), `resources` (`(dc_chat_id, status)`, `url`, `status`), `peers` (`last_seen`), and `peer_measurements` (`last_checked`) to eliminate full table scans during checks, audits, and cleanup.
- **Dedicated Thread Pools for DB vs RPC**:
  - Introduced separate `db_executor` (for fast non-blocking SQLite operations) and `rpc_executor` (for Delta Chat JSON-RPC and SMTP network operations) via `run_db` and `run_rpc`, preventing slow email delivery from exhausting worker threads.
- **In-Memory Uptime TTL Cache & Batch Calculation**:
  - Implemented `_uptime_cache` with a 60-second TTL and `get_resources_uptime_30d` for single-query batch calculation across all monitors in a chat, eliminating N+1 query patterns on web status dashboards, `/list`, and `/status`.
  - Added cache invalidation on status transitions, resource deletions, and maintenance cleanup.
- **Batch Check Status Updates**:
  - Implemented `batch_update_resource_status` to commit grouped check results in a single transaction under the database lock.
- **Non-Blocking Check Concurrency Semaphore**:
  - Refactored `check_group_task` with `check_network_probe` to hold the concurrency semaphore only during physical network probes. Retry backoff sleeps (30s) and remote peer cross-checks now run without holding semaphore slots, preventing failing endpoints from starving healthy monitors.
- **Incident Sync Lock Pruning**:
  - Added `prune_incident_sync_locks` to automatically evict idle, unlocked chat incident synchronization locks, preventing unbounded in-memory dictionary growth over long operational periods.
- **Standardized Admin Authentication**:
  - Added standardized `get_admin_email`, `set_admin_email`, `get_admin_fingerprint`, `set_admin_fingerprint`, and `is_authorized_sender` in `database.py`.
- **New Unit Test Suite**:
  - Added `tests/test_database.py` covering schema indexes, batch uptime calculation, caching, status updates, and admin handling, bringing test coverage to 88 automated tests.

## [2.7.7] - 2026-09-09

### Security
- **Credential Protection in `/addtransport`:**
  - Restricted `/addtransport` exclusively to private 1:1 chats with the bot, protecting passwords and chatmail tokens from accidental exposure in group chats.
- **Sanitized Command Error Messages:**
  - Sanitized exception disclosures across administrative commands (`/rmaccount`, `/addtransport`, `/rmtransport`, `/setprimary`, `/resilient`, `/invite`, `/addpeer`) to prevent internal system or credential leakages in chat replies.
- **Resilient Sending Concurrency Protection:**
  - Synchronized initial message queueing inside `resilient_lock` to eliminate data races with background transport failover workers.

### Performance & Optimization
- **Single Atomic Write for Status & Latency:**
  - Merged routine check latency and status updates into a single atomic SQLite transaction, cutting database disk write operations in half.
- **Shared HTTP Connection Pooling:**
  - Transitioned routine monitoring HTTP checks to a persistent shared `aiohttp.ClientSession` with connection pooling, DNS caching, and TCP keep-alive, significantly reducing socket and SSL handshake CPU overhead.
- **Buffered Transport Stats:**
  - Introduced in-memory buffering for transport send/receive statistics with periodic flushing (and automatic flush-on-read), eliminating per-message synchronous disk writes.
- **Scheduler Cache Optimization:**
  - Preserved resource schedule cache across active checks instead of invalidating it every 5-second tick, drastically reducing full-table database scans.
- **Automated Database Maintenance:**
  - Added scheduled pruning (`database.cleanup_old_records`) of resolved downtime events, closed incidents older than 90 days, and stale peer measurements older than 7 days.
- **Rate Limiting on Diagnostic Checks:**
  - Added a 15-second per-chat anti-spam cooldown on `/ping`, `/check`, and `/test` commands with administrator bypass to prevent resource exhaustion.

## [2.7.6] - 2026-09-05

### Fixed
- **Home Assistant Display Name & Status Text Configuration:**
  - Added direct fallback reading of `/data/options.json` in `on_init` for `display_name` and `status_text`, ensuring custom display names configured in Home Assistant Add-on settings are always applied even if environment variables are not exported.

## [2.7.5] - 2026-09-05

### Added
- **Clickable SecureJoin Link & Clickable QR Code:**
  - In Step 1 of the web dashboard index page, replaced the reference to bot email address with a direct clickable `bot's SecureJoin link` (`https://i.delta.chat/#...`).
  - Made the QR code image itself clickable, seamlessly opening the Delta Chat invite link when clicked on mobile or desktop devices.
  - Added in-process invite link caching (`get_bot_invite_link`) for fast zero-cost rendering across index, SVG, and PNG endpoints.

## [2.7.4] - 2026-09-05

### Added
- **Vector SVG & PNG QR Code Web Endpoints:**
  - Added `/qr.svg` and `/qr.png` endpoints dynamically serving the bot's securejoin invite QR code.
  - Embedded vector QR code directly into Step 1 of the web dashboard index page for effortless visual onboarding from Home Assistant Ingress or any browser.
- **Inverted ASCII QR Rendering:**
  - Configured `invert=True` for ASCII QR generation in terminal logs to render high-contrast black modules on standard dark terminal and container log backgrounds.

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
