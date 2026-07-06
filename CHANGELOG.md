# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
