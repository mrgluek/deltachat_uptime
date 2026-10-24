import contextlib
import os
import re
import sqlite3
import threading
import time
import secrets
import string
from urllib.parse import urlparse

DB_PATH = os.getenv("DB_PATH", "uptime.db")
_write_lock = threading.RLock()
_lock = _write_lock  # Backwards compatibility

_writer_conn = None
_writer_conn_db_path = None

def close_db():
    """Explicitly closes the persistent writer connection (useful for tests and shutdown)."""
    global _writer_conn, _writer_conn_db_path
    with _write_lock:
        if _writer_conn is not None:
            try:
                _writer_conn.close()
            except Exception:
                pass
            _writer_conn = None
            _writer_conn_db_path = None

def _get_writer_conn() -> sqlite3.Connection:
    """Returns a shared, persistent connection for write operations guarded by _write_lock."""
    global _writer_conn, _writer_conn_db_path
    if _writer_conn is not None and _writer_conn_db_path != DB_PATH:
        try:
            _writer_conn.close()
        except Exception:
            pass
        _writer_conn = None

    if _writer_conn is None:
        _writer_conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
        _writer_conn.execute("PRAGMA busy_timeout = 5000;")
        _writer_conn.execute("PRAGMA synchronous = NORMAL;")
        _writer_conn.execute("PRAGMA journal_mode = WAL;")
        _writer_conn.execute("PRAGMA wal_autocheckpoint = 1000;")
        _writer_conn_db_path = DB_PATH
    return _writer_conn

@contextlib.contextmanager
def _writer_transaction():
    """Context manager for write transactions reusing _writer_conn under _write_lock."""
    with _write_lock:
        conn = _get_writer_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

def _connect(timeout: float = 10.0) -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=timeout)
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db():
    with _writer_transaction() as conn:
        # Enable WAL mode and concurrency PRAGMAs
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-4000;")
        cursor = conn.cursor()
        
        # Config table for admin_dc_email, admin_dc_fingerprint, etc.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Chats table mapping dc_chat_id to random secure token
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                dc_chat_id INTEGER PRIMARY KEY,
                token TEXT UNIQUE,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            )
        ''')
        
        cursor.execute("PRAGMA table_info(chats)")
        if "abandoned_at" not in [row[1] for row in cursor.fetchall()]:
            # Set while the bot cannot write to the chat (removed from the group, chat deleted,
            # contact blocked): its monitors are paused, and deleted after a grace period
            cursor.execute("ALTER TABLE chats ADD COLUMN abandoned_at INTEGER")

        # Resources table storing monitored targets per chat
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dc_chat_id INTEGER,
                name TEXT,
                url TEXT,
                type TEXT, -- 'ping', 'http', 'tcp'
                interval INTEGER DEFAULT 60, -- in seconds
                status TEXT DEFAULT 'unknown', -- 'up', 'down', 'unknown'
                last_checked INTEGER,
                last_changed INTEGER,
                consecutive_failures INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT (strftime('%s','now')),
                ssl_expiry_date INTEGER,
                ssl_last_checked INTEGER,
                ssl_alert_state INTEGER DEFAULT 0,
                last_down_msg_id INTEGER,
                expected_keyword TEXT,
                maintenance_until INTEGER DEFAULT 0,
                last_latency_ms INTEGER,
                http_method TEXT,
                UNIQUE(dc_chat_id, url)
            )
        ''')
        
        # Ensure new columns exist in resources table
        cursor.execute("PRAGMA table_info(resources)")
        columns = [row[1] for row in cursor.fetchall()]
        if "ssl_expiry_date" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN ssl_expiry_date INTEGER")
        if "ssl_last_checked" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN ssl_last_checked INTEGER")
        if "ssl_alert_state" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN ssl_alert_state INTEGER DEFAULT 0")
        if "last_down_msg_id" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN last_down_msg_id INTEGER")
        if "stale_warning_level" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN stale_warning_level INTEGER DEFAULT 0")
        if "stale_warning_at" not in columns:
            # When the last stale notice went out: auto-cleanup waits a few days after the 14-day warning
            cursor.execute("ALTER TABLE resources ADD COLUMN stale_warning_at INTEGER")
        if "expected_keyword" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN expected_keyword TEXT")
        if "maintenance_until" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN maintenance_until INTEGER DEFAULT 0")
        if "last_latency_ms" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN last_latency_ms INTEGER")
        if "http_method" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN http_method TEXT")
        # Quorum alerting: up / degraded (unreachable from a minority of nodes) / down. `status`
        # stays up/down only, so uptime and incidents are unchanged by a degraded target.
        if "alert_state" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN alert_state TEXT DEFAULT 'up'")
        if "last_votes" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN last_votes TEXT")  # JSON: per-node results
        if "degraded_since" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN degraded_since INTEGER DEFAULT 0")

        # Partial outages: periods a target was unreachable from a minority of nodes (not downtime)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS partial_outages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER,
                started_at INTEGER,
                ended_at INTEGER,
                nodes_down TEXT,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_partial_outages_resource ON partial_outages(resource_id, ended_at)')

        # Downtime events for uptime calculations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS downtime_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER,
                went_down_at INTEGER,
                went_up_at INTEGER,
                error_msg TEXT,
                incident_id INTEGER,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        ''')
        
        # Ensure columns exist in downtime_events
        cursor.execute("PRAGMA table_info(downtime_events)")
        columns_dt = [row[1] for row in cursor.fetchall()]
        if "error_msg" not in columns_dt:
            cursor.execute("ALTER TABLE downtime_events ADD COLUMN error_msg TEXT")
        if "incident_id" not in columns_dt:
            cursor.execute("ALTER TABLE downtime_events ADD COLUMN incident_id INTEGER")
            
        # Add indexes to downtime_events for fast lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_resource ON downtime_events(resource_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_went_down ON downtime_events(went_down_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_went_up ON downtime_events(went_up_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_resource_range ON downtime_events(resource_id, went_down_at, went_up_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_incident ON downtime_events(incident_id)')

        # Incidents table for tracking grouped chat outages
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dc_chat_id INTEGER,
                status TEXT DEFAULT 'ongoing', -- 'ongoing', 'resolved'
                started_at INTEGER,
                resolved_at INTEGER,
                msg_id INTEGER,
                summary TEXT,
                FOREIGN KEY(dc_chat_id) REFERENCES chats(dc_chat_id)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_chat ON incidents(dc_chat_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_chat_status ON incidents(dc_chat_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved_at)')

        # Resources indexes for high-frequency queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_resources_chat_status ON resources(dc_chat_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_resources_url ON resources(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_resources_status ON resources(status)')
        
        # Transport statistics (multi-transport failover support)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transport_stats (
                addr TEXT PRIMARY KEY,
                msgs_sent INTEGER DEFAULT 0,
                msgs_received INTEGER DEFAULT 0,
                last_sent_at INTEGER,
                last_received_at INTEGER
            )
        ''')

        # Distributed peers (multi-node bots via 1:1 Delta Chat DMs)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS peers (
                email TEXT PRIMARY KEY,
                node_name TEXT,
                chat_id INTEGER,
                last_seen INTEGER,
                created_at INTEGER DEFAULT (strftime('%s','now')),
                is_offline INTEGER DEFAULT 0,
                went_offline_at INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_chat ON peers(chat_id)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS peer_invites (
                token TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen)')

        # Ensure columns exist in peers for existing DBs
        cursor.execute("PRAGMA table_info(peers)")
        peer_cols = [c[1] for c in cursor.fetchall()]
        if "is_offline" not in peer_cols:
            cursor.execute("ALTER TABLE peers ADD COLUMN is_offline INTEGER DEFAULT 0")
        if "went_offline_at" not in peer_cols:
            cursor.execute("ALTER TABLE peers ADD COLUMN went_offline_at INTEGER DEFAULT 0")
        # A peer is identified by its OpenPGP key: bots with several relays send from different
        # addresses, so the address is only kept for display. NULL until the first encrypted message.
        if "fingerprint" not in peer_cols:
            cursor.execute("ALTER TABLE peers ADD COLUMN fingerprint TEXT")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_fingerprint ON peers(fingerprint)')

        # Telemetry metrics reported from remote peer probes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS peer_measurements (
                url TEXT,
                node_name TEXT,
                status TEXT, -- 'up', 'down', 'unknown'
                latency_ms INTEGER,
                error_msg TEXT,
                last_checked INTEGER,
                PRIMARY KEY (url, node_name)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peer_measurements_url ON peer_measurements(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peer_meas_checked ON peer_measurements(last_checked)')

        # Remote probe targets mirrored from peer bots
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS probe_targets (
                url TEXT PRIMARY KEY,
                name TEXT,
                type TEXT DEFAULT 'http',
                expected_keyword TEXT,
                http_method TEXT,
                source_peer TEXT,
                last_seen INTEGER,
                last_checked INTEGER,
                last_status TEXT,
                last_latency_ms INTEGER,
                last_error TEXT
            )
        ''')

        cursor.execute("PRAGMA table_info(probe_targets)")
        pt_columns = [row[1] for row in cursor.fetchall()]
        if "http_method" not in pt_columns:
            cursor.execute("ALTER TABLE probe_targets ADD COLUMN http_method TEXT")
        if "down_since" not in pt_columns:
            # Start of the current local outage of a peer's target: drives the check slowdown
            cursor.execute("ALTER TABLE probe_targets ADD COLUMN down_since INTEGER")

        # Ignored probe targets (excluded from remote scanning on this probe)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ignored_probe_targets (
                url TEXT PRIMARY KEY,
                reason TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            )
        ''')

        # Usual ping round trip of this node per pinged address (degraded path detection)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ping_baselines (
                ip TEXT PRIMARY KEY,
                rtt_ms REAL NOT NULL,
                updated_at INTEGER
            )
        ''')

# Config functions
def set_config(key: str, value: str):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))

def get_config(key: str) -> str:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def get_admin_email():
    db_val = get_config("admin_dc_email")
    if db_val and db_val.strip():
        return db_val.strip().lower()
    env_val = os.getenv("ADMIN_DC_EMAIL")
    return env_val.strip().lower() if env_val else None


def set_admin_email(email: str):
    if email:
        email = email.strip().lower()
    set_config("admin_dc_email", email)


def get_admin_fingerprint():
    fp = get_config("admin_dc_fingerprint")
    if not fp:
        fp = os.getenv("ADMIN_DC_FINGERPRINT", "")
    if fp:
        cleaned = fp.strip().replace(" ", "").replace(":", "").upper()
        if re.match(r"^[0-9A-F]{32,64}$", cleaned):
            return cleaned
    return None


def set_admin_fingerprint(fp: str):
    if fp:
        cleaned = fp.strip().replace(" ", "").replace(":", "").upper()
        if re.match(r"^[0-9A-F]{32,64}$", cleaned):
            set_config("admin_dc_fingerprint", cleaned)
        else:
            set_config("admin_dc_fingerprint", "")
    else:
        set_config("admin_dc_fingerprint", "")


def is_authorized_sender(sender_addr: str, fingerprint: str = None) -> bool:
    admin_email = get_admin_email()
    admin_fp = get_admin_fingerprint()

    if not admin_email and not admin_fp:
        return False

    sender_addr_clean = (sender_addr or "").strip().lower()

    if admin_email and sender_addr_clean == admin_email:
        if admin_fp:
            if fingerprint:
                fp_clean = fingerprint.strip().replace(" ", "").replace(":", "").upper()
                return admin_fp in fp_clean
            return False
        return True

    return False

# Chat token functions (12-character base62 secure tokens)
def generate_chat_token() -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(12))

def get_or_create_chat_token(dc_chat_id: int) -> str:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM chats WHERE dc_chat_id = ?", (dc_chat_id,))
        row = cursor.fetchone()
        if row:
            return row[0]
        # Generate a unique token
        while True:
            token = generate_chat_token()
            try:
                cursor.execute("INSERT INTO chats (dc_chat_id, token) VALUES (?, ?)", (dc_chat_id, token))
                return token
            except sqlite3.IntegrityError:
                # Token collision, retry
                continue

def get_chat_id_by_token(token: str) -> int:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT dc_chat_id FROM chats WHERE token = ?", (token,))
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

# Resource functions
def add_resource(dc_chat_id: int, url: str, name: str, check_type: str, interval: int = 60, expected_keyword: str = None, http_method: str = None) -> int:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        try:
            if not http_method and check_type == "http":
                # Inherit learned http_method if this URL was already known in resources or probe_targets
                cursor.execute("SELECT http_method FROM resources WHERE url = ? AND http_method IS NOT NULL LIMIT 1", (url,))
                row = cursor.fetchone()
                if row and row[0]:
                    http_method = row[0]
                else:
                    cursor.execute("SELECT http_method FROM probe_targets WHERE url = ? AND http_method IS NOT NULL LIMIT 1", (url,))
                    row_pt = cursor.fetchone()
                    if row_pt and row_pt[0]:
                        http_method = row_pt[0]

            cursor.execute('''
                INSERT INTO resources (dc_chat_id, url, name, type, interval, status, last_changed, expected_keyword, http_method) 
                VALUES (?, ?, ?, ?, ?, 'unknown', ?, ?, ?)
            ''', (dc_chat_id, url, name, check_type, interval, int(time.time()), expected_keyword, http_method))
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.rollback()
            return None

def set_resource_http_method(resource_id: int, http_method: str | None) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET http_method = ? WHERE id = ?", (http_method, resource_id))
        return cursor.rowcount > 0

def set_url_http_method(url: str, http_method: str | None) -> int:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET http_method = ? WHERE url = ?", (http_method, url))
        count = cursor.rowcount
        cursor.execute("UPDATE probe_targets SET http_method = ? WHERE url = ?", (http_method, url))
        count += cursor.rowcount
        return count

def set_resource_keyword(dc_chat_id: int, resource_id: int, keyword: str | None) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET expected_keyword = ? WHERE dc_chat_id = ? AND id = ?", (keyword, dc_chat_id, resource_id))
        return cursor.rowcount > 0

def set_resource_maintenance(dc_chat_id: int, resource_id: int, until_ts: int) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET maintenance_until = ? WHERE dc_chat_id = ? AND id = ?", (until_ts, dc_chat_id, resource_id))
        return cursor.rowcount > 0

def update_resource_latency(resource_id: int, latency_ms: int):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET last_latency_ms = ? WHERE id = ?", (latency_ms, resource_id))

def get_monitored_chats() -> dict[int, int | None]:
    """chat id -> abandoned_at (None while active) for every chat that has monitors."""
    conn = _connect()
    try:
        rows = conn.execute('''
            SELECT DISTINCT r.dc_chat_id, c.abandoned_at FROM resources r
            LEFT JOIN chats c ON c.dc_chat_id = r.dc_chat_id
        ''').fetchall()
        return {row[0]: row[1] for row in rows}
    finally:
        conn.close()


def set_chat_abandoned(dc_chat_id: int, abandoned_at: int | None):
    """Pause (abandoned_at = time) or resume (None) the monitors of a chat."""
    get_or_create_chat_token(dc_chat_id)  # the chats row may not exist yet
    with _writer_transaction() as conn:
        conn.execute("UPDATE chats SET abandoned_at = ? WHERE dc_chat_id = ?", (abandoned_at, dc_chat_id))


def delete_chat_data(dc_chat_id: int) -> int:
    """Removes a chat's monitors with their history, incidents and the chat itself. Returns how
    many monitors were deleted."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        ids = [row[0] for row in cursor.execute("SELECT id FROM resources WHERE dc_chat_id = ?", (dc_chat_id,))]
        for rid in ids:
            invalidate_uptime_cache(rid)
            cursor.execute("DELETE FROM downtime_events WHERE resource_id = ?", (rid,))
            cursor.execute("DELETE FROM partial_outages WHERE resource_id = ?", (rid,))
        cursor.execute("DELETE FROM resources WHERE dc_chat_id = ?", (dc_chat_id,))
        cursor.execute("DELETE FROM incidents WHERE dc_chat_id = ?", (dc_chat_id,))
        cursor.execute("DELETE FROM chats WHERE dc_chat_id = ?", (dc_chat_id,))
        cursor.execute("DELETE FROM config WHERE key = ?", (f"alert_mode:{dc_chat_id}",))
        return len(ids)


def delete_resource(dc_chat_id: int, resource_id: int) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM resources WHERE dc_chat_id = ? AND id = ?", (dc_chat_id, resource_id))
        deleted = cursor.rowcount > 0
        if deleted:
            invalidate_uptime_cache(resource_id)
            cursor.execute("DELETE FROM partial_outages WHERE resource_id = ?", (resource_id,))
        return deleted

def get_resources(dc_chat_id: int) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE dc_chat_id = ? ORDER BY id ASC", (dc_chat_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_resource_by_id(resource_id: int) -> dict | None:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_all_resources() -> list[dict]:
    """Monitors of all chats the bot can still write to (abandoned chats are paused)."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.* FROM resources r LEFT JOIN chats c ON c.dc_chat_id = r.dc_chat_id
            WHERE c.abandoned_at IS NULL ORDER BY r.id ASC
        ''')
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def batch_update_resource_status(updates: list[dict]):
    """
    Batch updates multiple resources' check statuses in a single transaction.
    Each item in updates is a dict with:
      {'id': int, 'status': str, 'consecutive_failures': int, 'error_msg': str, 'latency_ms': int | None}
    """
    if not updates:
        return
    with _writer_transaction() as conn:
        _apply_status_updates(conn.cursor(), updates, int(time.time()))


def record_check_results(updates: list[dict], measurement: tuple | None = None):
    """Everything one check writes, in one transaction: the status of each monitor of the target
    (as batch_update_resource_status) and, if given, the local peer measurement
    (url, node_name, status, latency_ms, error_msg) - one commit per check instead of 2+."""
    now = int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        if updates:
            _apply_status_updates(cursor, updates, now)
        if measurement:
            _upsert_peer_measurement(cursor, *measurement, now)


def _apply_status_updates(cursor, updates: list[dict], now: int):
    """batch_update_resource_status inside an open transaction."""
    for item in updates:
        resource_id = item["id"]
        status = item["status"]
        consecutive_failures = item.get("consecutive_failures", 0)
        error_msg = item.get("error_msg")
        latency_ms = item.get("latency_ms")

        cursor.execute("SELECT status, last_changed FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        if not row:
            continue

        old_status = row[0]
        if old_status != status:
            invalidate_uptime_cache(resource_id)
            cursor.execute('''
                UPDATE resources 
                SET status = ?, last_checked = ?, last_changed = ?, consecutive_failures = ?,
                    last_latency_ms = COALESCE(?, last_latency_ms)
                WHERE id = ?
            ''', (status, now, now, consecutive_failures, latency_ms, resource_id))

            if status == "down":
                cursor.execute("SELECT dc_chat_id FROM resources WHERE id = ?", (resource_id,))
                chat_row = cursor.fetchone()
                inc_id = None
                if chat_row:
                    chat_id = chat_row[0]
                    cursor.execute('''
                        SELECT i.id, i.status,
                               MAX(COALESCE(de.went_down_at, i.started_at)) as last_down_at,
                               COALESCE(i.resolved_at, MAX(COALESCE(de.went_up_at, de.went_down_at, i.started_at))) as last_event_at
                        FROM incidents i
                        LEFT JOIN downtime_events de ON de.incident_id = i.id
                        WHERE i.dc_chat_id = ?
                        GROUP BY i.id
                        HAVING (? - last_event_at) <= 3600 AND (? >= last_event_at)
                        ORDER BY (CASE WHEN i.status = 'ongoing' THEN 0 ELSE 1 END), i.id DESC LIMIT 1
                    ''', (chat_id, now, now))
                    inc_row = cursor.fetchone()
                    if inc_row:
                        inc_id = inc_row[0]
                        inc_status = inc_row[1]
                        if inc_status == 'resolved':
                            cursor.execute("UPDATE incidents SET status = 'ongoing', resolved_at = NULL, summary = NULL WHERE id = ?", (inc_id,))
                    else:
                        cursor.execute("INSERT INTO incidents (dc_chat_id, status, started_at) VALUES (?, 'ongoing', ?)", (chat_id, now))
                        inc_id = cursor.lastrowid

                cursor.execute('''
                    INSERT INTO downtime_events (resource_id, went_down_at, went_up_at, error_msg, incident_id)
                    VALUES (?, ?, NULL, ?, ?)
                ''', (resource_id, now, error_msg, inc_id))
            elif status == "up" and old_status == "down":
                cursor.execute('''
                    UPDATE downtime_events 
                    SET went_up_at = ? 
                    WHERE resource_id = ? AND went_up_at IS NULL
                ''', (now, resource_id))
        else:
            cursor.execute('''
                UPDATE resources 
                SET last_checked = ?, consecutive_failures = ?,
                    last_latency_ms = COALESCE(?, last_latency_ms)
                WHERE id = ?
            ''', (now, consecutive_failures, latency_ms, resource_id))
            if status == "up":
                # Stale notices start over only after a full day up: a target that comes up for a
                # few minutes now and then would otherwise get the 7-day notice again after each flap.
                cursor.execute('''
                    UPDATE resources SET stale_warning_level = 0, stale_warning_at = NULL
                    WHERE id = ? AND stale_warning_level > 0 AND ? - last_changed >= ?
                ''', (resource_id, now, STALE_RESET_UP_SECONDS))


def update_resource_status(resource_id: int, status: str, consecutive_failures: int, error_msg: str = None, latency_ms: int = None):
    """Updates the status, last_checked, and optionally last_latency_ms in a single transaction."""
    batch_update_resource_status([{
        "id": resource_id,
        "status": status,
        "consecutive_failures": consecutive_failures,
        "error_msg": error_msg,
        "latency_ms": latency_ms,
    }])

STALE_RESET_UP_SECONDS = 86400


def update_stale_warning_level(resource_id: int, level: int):
    """Update the highest stale downtime warning level sent for this resource (0, 7, 14)."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET stale_warning_level = ?, stale_warning_at = ? WHERE id = ?",
                       (level, int(time.time()), resource_id))

def update_resource_ssl(resource_id: int, ssl_expiry_date: int | None, ssl_last_checked: int, ssl_alert_state: int = 0):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET ssl_expiry_date = ?, ssl_last_checked = ?, ssl_alert_state = ? 
            WHERE id = ?
        ''', (ssl_expiry_date, ssl_last_checked, ssl_alert_state, resource_id))

def update_ssl_alert_state(resource_id: int, ssl_alert_state: int):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET ssl_alert_state = ? 
            WHERE id = ?
        ''', (ssl_alert_state, resource_id))

def update_resource_down_msg_id(resource_id: int, msg_id: int | None):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET last_down_msg_id = ? 
            WHERE id = ?
        ''', (msg_id, resource_id))

# Incident management functions
def create_incident(dc_chat_id: int, started_at: int = None) -> int:
    if started_at is None:
        started_at = int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (dc_chat_id, status, started_at)
            VALUES (?, 'ongoing', ?)
        ''', (dc_chat_id, started_at))
        return cursor.lastrowid

def get_active_incident(dc_chat_id: int) -> dict | None:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND status = 'ongoing' 
            ORDER BY id DESC LIMIT 1
        ''', (dc_chat_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_active_incidents_for_chat(dc_chat_id: int) -> list[dict]:
    """Returns all currently ongoing incidents for a specific chat."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND status = 'ongoing' 
            ORDER BY id ASC
        ''', (dc_chat_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_active_incident_for_outage(dc_chat_id: int, outage_time: int, max_gap_seconds: int = 3600, allow_reopen: bool = True) -> dict | None:
    """Finds an ongoing or recently resolved incident in dc_chat_id within max_gap_seconds of outage_time."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        if allow_reopen:
            cursor.execute('''
                SELECT i.*, 
                       MAX(COALESCE(de.went_down_at, i.started_at)) as last_down_at,
                       COALESCE(i.resolved_at, MAX(COALESCE(de.went_up_at, de.went_down_at, i.started_at))) as last_event_at
                FROM incidents i
                LEFT JOIN downtime_events de ON de.incident_id = i.id
                WHERE i.dc_chat_id = ?
                GROUP BY i.id
                HAVING (? - last_event_at) <= ? AND (? >= last_event_at)
                ORDER BY (CASE WHEN i.status = 'ongoing' THEN 0 ELSE 1 END), i.id DESC LIMIT 1
            ''', (dc_chat_id, outage_time, max_gap_seconds, outage_time))
        else:
            cursor.execute('''
                SELECT i.*, 
                       MAX(COALESCE(de.went_down_at, i.started_at)) as last_down_at
                FROM incidents i
                LEFT JOIN downtime_events de ON de.incident_id = i.id
                WHERE i.dc_chat_id = ? AND i.status = 'ongoing'
                GROUP BY i.id
                HAVING (? - last_down_at) <= ? AND (? >= last_down_at)
                ORDER BY i.id DESC LIMIT 1
            ''', (dc_chat_id, outage_time, max_gap_seconds, outage_time))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def reopen_incident(incident_id: int):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET status = 'ongoing', resolved_at = NULL, summary = NULL 
            WHERE id = ?
        ''', (incident_id,))

def get_all_active_incidents() -> list[dict]:
    """Ongoing incidents, except in abandoned chats (nobody can be told about them there)."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT i.* FROM incidents i LEFT JOIN chats c ON c.dc_chat_id = i.dc_chat_id
            WHERE i.status = 'ongoing' AND c.abandoned_at IS NULL ORDER BY i.id ASC
        ''')
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_incident_by_msg_id(dc_chat_id: int, msg_id: int) -> dict | None:
    """Finds incident record matching chat and message ID."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND msg_id = ?
            ORDER BY id DESC LIMIT 1
        ''', (dc_chat_id, msg_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_resources_matching_text(dc_chat_id: int, text: str) -> list[dict]:
    """Finds all resources in dc_chat_id whose url or name appears in text."""
    if not text:
        return []
    resources = get_resources(dc_chat_id)
    matched = []
    text_lower = text.lower()
    for r in resources:
        url = r.get("url", "").strip().lower()
        name = r.get("name", "").strip().lower()
        if url:
            url_no_scheme = re.sub(r'^https?://', '', url).rstrip('/')
            if url in text_lower or (url_no_scheme and url_no_scheme in text_lower):
                matched.append(r)
                continue
        if name and len(name) >= 3 and name in text_lower:
            matched.append(r)
    return matched

def get_resources_by_target(dc_chat_id: int, target: str) -> list[dict]:
    """Finds resources in dc_chat_id matching a given target string (URL, domain, or name), prioritized by match quality."""
    target_clean = target.strip().lower()
    if not target_clean:
        return []
    target_clean_slash = target_clean.rstrip('/')
    target_no_scheme = re.sub(r'^https?://', '', target_clean).rstrip('/')
    resources = get_resources(dc_chat_id)
    
    exact_url_matches = []
    exact_name_matches = []
    scheme_stripped_matches = []
    
    for r in resources:
        r_url = r.get("url", "").strip().lower()
        r_url_slash = r_url.rstrip('/')
        r_url_no_scheme = re.sub(r'^https?://', '', r_url).rstrip('/')
        r_name = r.get("name", "").strip().lower()
        
        if r_url == target_clean or r_url_slash == target_clean_slash:
            exact_url_matches.append(r)
        elif r_name == target_clean:
            exact_name_matches.append(r)
        elif r_url_no_scheme == target_no_scheme:
            scheme_stripped_matches.append(r)
            
    return exact_url_matches + exact_name_matches + scheme_stripped_matches

def update_incident_msg_id(incident_id: int, msg_id: int | None):
    if msg_id is not None and not isinstance(msg_id, int):
        return
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET msg_id = ? 
            WHERE id = ?
        ''', (msg_id, incident_id))

def resolve_incident(incident_id: int, resolved_at: int = None, summary: str = ""):
    if resolved_at is None:
        resolved_at = int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET status = 'resolved', resolved_at = ?, summary = ? 
            WHERE id = ?
        ''', (resolved_at, summary, incident_id))

def get_recent_incidents(dc_chat_id: int, limit: int = 10) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? 
            ORDER BY id DESC LIMIT ?
        ''', (dc_chat_id, limit))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_incident_by_id(dc_chat_id: int, incident_id: int) -> dict | None:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND id = ?
        ''', (dc_chat_id, incident_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_unlinked_open_downtime_events(dc_chat_id: int) -> list[dict]:
    """Returns open downtime events in this chat that are not yet linked to any incident."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT de.*, r.name, r.url, r.type, r.status as resource_status
            FROM downtime_events de
            JOIN resources r ON r.id = de.resource_id
            WHERE r.dc_chat_id = ? AND de.went_up_at IS NULL AND de.incident_id IS NULL
            ORDER BY de.went_down_at ASC
        ''', (dc_chat_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def link_downtime_event_to_incident(downtime_event_id: int, incident_id: int):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE downtime_events SET incident_id = ? WHERE id = ?", (incident_id, downtime_event_id))

def get_incident_downtime_events(incident_id: int) -> list[dict]:
    """Returns all downtime events associated with an incident."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT de.*, r.name, r.url, r.type, r.status as resource_status, r.last_changed, r.consecutive_failures, r.interval
            FROM downtime_events de
            LEFT JOIN resources r ON r.id = de.resource_id
            WHERE de.incident_id = ?
            ORDER BY de.went_down_at ASC
        ''', (incident_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def close_resource_downtime_events(resource_id: int, now: int = None):
    if now is None:
        now = int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE downtime_events SET went_up_at = ? WHERE resource_id = ? AND went_up_at IS NULL", (now, resource_id))

def get_resource_downtime_events(resource_id: int, limit: int = 10) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM downtime_events 
            WHERE resource_id = ? 
            ORDER BY went_down_at DESC LIMIT ?
        ''', (resource_id, limit))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_incident_affected_resource_ids(incident_id: int, fallback_chat_id: int = None, fallback_started_at: int = None) -> set[int]:
    """Return set of resource IDs that experienced downtime in this incident."""
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT resource_id FROM downtime_events
            WHERE incident_id = ? AND resource_id IS NOT NULL
        ''', (incident_id,))
        rows = cursor.fetchall()
        res_ids = {r[0] for r in rows if r[0] is not None}
        
        # Fallback query if legacy incident before incident_id linking
        if not res_ids and fallback_chat_id is not None and fallback_started_at is not None:
            cursor.execute('''
                SELECT DISTINCT de.resource_id 
                FROM downtime_events de
                JOIN resources r ON r.id = de.resource_id
                WHERE r.dc_chat_id = ? 
                  AND (de.went_down_at >= ? OR de.went_up_at IS NULL OR de.went_up_at >= ?)
            ''', (fallback_chat_id, fallback_started_at - 60, fallback_started_at))
            rows = cursor.fetchall()
            res_ids = {r[0] for r in rows if r[0] is not None}
            
        return res_ids
    finally:
        conn.close()

# Uptime calculation functions & TTL cache
_uptime_cache: dict[int, tuple[float, float]] = {}  # resource_id -> (timestamp, uptime_pct)
_uptime_cache_lock = threading.Lock()
UPTIME_CACHE_TTL = 60.0  # seconds


def invalidate_uptime_cache(resource_id: int = None):
    """Invalidate uptime cache for a specific resource or all resources."""
    with _uptime_cache_lock:
        if resource_id is None:
            _uptime_cache.clear()
        else:
            _uptime_cache.pop(resource_id, None)


def get_resources_uptime_30d(resource_ids: list[int]) -> dict[int, float]:
    """Batch calculates the 30-day uptime percentages for multiple resources in a single query with TTL caching."""
    if not resource_ids:
        return {}

    now_ts = time.time()
    now = int(now_ts)
    start_time = now - 30 * 24 * 3600

    res_dict: dict[int, float] = {}
    missing_ids = []

    with _uptime_cache_lock:
        for rid in resource_ids:
            cached = _uptime_cache.get(rid)
            if cached and (now_ts - cached[0] < UPTIME_CACHE_TTL):
                res_dict[rid] = cached[1]
            else:
                missing_ids.append(rid)

    if not missing_ids:
        return res_dict

    conn = _connect()
    try:
        cursor = conn.cursor()
        placeholders = ",".join("?" for _ in missing_ids)
        cursor.execute(f"SELECT id, created_at FROM resources WHERE id IN ({placeholders})", missing_ids)
        created_map = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(f'''
            SELECT resource_id, went_down_at, went_up_at FROM downtime_events 
            WHERE resource_id IN ({placeholders}) AND went_down_at < ? AND (went_up_at IS NULL OR went_up_at > ?)
        ''', (*missing_ids, now, start_time))
        events = cursor.fetchall()
    finally:
        conn.close()

    events_by_res: dict[int, list[tuple[int, int]]] = {rid: [] for rid in missing_ids}
    for r_id, went_down, went_up in events:
        events_by_res[r_id].append((went_down, went_up))

    new_cache = {}
    for rid in missing_ids:
        created_at = created_map.get(rid)
        if created_at is None:
            pct = 100.0
        else:
            tracking_start = max(created_at, start_time)
            total_time = now - tracking_start
            if total_time <= 0:
                pct = 100.0
            else:
                total_downtime = 0
                for went_down, went_up in events_by_res.get(rid, []):
                    effective_start = max(went_down, tracking_start)
                    effective_end = min(went_up if went_up else now, now)
                    duration = effective_end - effective_start
                    if duration > 0:
                        total_downtime += duration
                pct = max(0.0, min(100.0, ((total_time - total_downtime) / total_time) * 100.0))
        res_dict[rid] = pct
        new_cache[rid] = (now_ts, pct)

    with _uptime_cache_lock:
        _uptime_cache.update(new_cache)

    return res_dict


def get_resource_uptime_window(resource_id: int, window_seconds: int, now: int = None) -> float | None:
    """Uptime percentage over the last window_seconds, or None if the resource is younger than
    that (not cached: used for the rare stale checks, any window)."""
    now = int(now or time.time())
    start_time = now - window_seconds
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT created_at FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        if not row or row[0] is None or row[0] > start_time:
            return None
        cursor.execute('''
            SELECT went_down_at, went_up_at FROM downtime_events
            WHERE resource_id = ? AND went_down_at < ? AND (went_up_at IS NULL OR went_up_at > ?)
        ''', (resource_id, now, start_time))
        events = cursor.fetchall()
    finally:
        conn.close()
    downtime = 0
    for went_down, went_up in events:
        downtime += max(0, min(went_up or now, now) - max(went_down, start_time))
    return max(0.0, min(100.0, (window_seconds - downtime) / window_seconds * 100.0))


def get_resource_uptime_30d(resource_id: int) -> float:
    """Calculates the uptime percentage of a resource over the last 30 days (cached with TTL)."""
    now_ts = time.time()
    with _uptime_cache_lock:
        cached = _uptime_cache.get(resource_id)
        if cached and (now_ts - cached[0] < UPTIME_CACHE_TTL):
            return cached[1]

    results = get_resources_uptime_30d([resource_id])
    return results.get(resource_id, 100.0)


def get_chat_uptime_30d(dc_chat_id: int) -> float:
    """Calculates average uptime percentage for all resources in a chat using batch query."""
    resources = get_resources(dc_chat_id)
    if not resources:
        return 100.0

    r_ids = [r["id"] for r in resources]
    uptimes_map = get_resources_uptime_30d(r_ids)
    uptimes = [uptimes_map.get(rid, 100.0) for rid in r_ids]
    return sum(uptimes) / len(uptimes)

# Transport statistics tracking (buffered in memory)
_transport_stats_buffer: dict[str, dict[str, int]] = {}
_transport_stats_lock = threading.Lock()
_last_transport_flush = time.time()
TRANSPORT_FLUSH_INTERVAL = 30.0  # seconds

def increment_transport_sent(addr: str):
    """Increment the sent counter for a transport address (buffered in memory)."""
    if not addr or not isinstance(addr, str) or "@" not in addr:
        return
    now = int(time.time())
    should_flush = False
    with _transport_stats_lock:
        if addr not in _transport_stats_buffer:
            _transport_stats_buffer[addr] = {"sent": 0, "recv": 0, "last_sent": 0, "last_recv": 0}
        _transport_stats_buffer[addr]["sent"] += 1
        _transport_stats_buffer[addr]["last_sent"] = now
        global _last_transport_flush
        if now - _last_transport_flush >= TRANSPORT_FLUSH_INTERVAL:
            should_flush = True
    if should_flush:
        flush_transport_stats()

def increment_transport_received(addr: str):
    """Increment the received counter for a transport address (buffered in memory)."""
    if not addr or not isinstance(addr, str) or "@" not in addr:
        return
    now = int(time.time())
    should_flush = False
    with _transport_stats_lock:
        if addr not in _transport_stats_buffer:
            _transport_stats_buffer[addr] = {"sent": 0, "recv": 0, "last_sent": 0, "last_recv": 0}
        _transport_stats_buffer[addr]["recv"] += 1
        _transport_stats_buffer[addr]["last_recv"] = now
        global _last_transport_flush
        if now - _last_transport_flush >= TRANSPORT_FLUSH_INTERVAL:
            should_flush = True
    if should_flush:
        flush_transport_stats()

def flush_transport_stats():
    """Flush buffered transport stats to the database in a single transaction."""
    global _last_transport_flush
    with _transport_stats_lock:
        if not _transport_stats_buffer:
            _last_transport_flush = time.time()
            return
        pending = dict(_transport_stats_buffer)
        _transport_stats_buffer.clear()
        _last_transport_flush = time.time()

    with _writer_transaction() as conn:
        cursor = conn.cursor()
        for addr, counts in pending.items():
            if not isinstance(addr, str) or "@" not in addr:
                continue
            sent = int(counts.get("sent", 0))
            recv = int(counts.get("recv", 0))
            last_s = counts.get("last_sent") or None
            last_r = counts.get("last_recv") or None
            cursor.execute('''
                INSERT INTO transport_stats (addr, msgs_sent, msgs_received, last_sent_at, last_received_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(addr) DO UPDATE SET
                    msgs_sent = msgs_sent + excluded.msgs_sent,
                    msgs_received = msgs_received + excluded.msgs_received,
                    last_sent_at = COALESCE(excluded.last_sent_at, transport_stats.last_sent_at),
                    last_received_at = COALESCE(excluded.last_received_at, transport_stats.last_received_at)
            ''', (addr, sent, recv, last_s, last_r))

def get_all_transport_stats() -> list[dict]:
    flush_transport_stats()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transport_stats ORDER BY msgs_sent + msgs_received DESC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def cleanup_old_records(retention_days: int = 90) -> dict[str, int]:
    """Prune old downtime events, resolved incidents, and stale peer measurements."""
    now = int(time.time())
    cutoff = now - (retention_days * 86400)
    cleaned = {}
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        
        # 1. Prune resolved downtime events older than retention_days
        cursor.execute("DELETE FROM downtime_events WHERE went_up_at IS NOT NULL AND went_up_at < ?", (cutoff,))
        cleaned["downtime_events"] = cursor.rowcount
        
        # 2. Prune resolved incidents older than retention_days
        cursor.execute("DELETE FROM incidents WHERE status = 'resolved' AND resolved_at < ?", (cutoff,))
        cleaned["incidents"] = cursor.rowcount
        
        # 3. Prune old peer measurements (older than 7 days)
        meas_cutoff = now - (7 * 86400)
        cursor.execute("DELETE FROM peer_measurements WHERE last_checked < ?", (meas_cutoff,))
        cleaned["peer_measurements"] = cursor.rowcount

        cursor.execute("DELETE FROM partial_outages WHERE ended_at IS NOT NULL AND ended_at < ?", (cutoff,))
        cleaned["partial_outages"] = cursor.rowcount
    return cleaned

# Peer management functions
def get_local_node_name() -> str:
    name = get_config("node_name")
    if name:
        return name
    return os.getenv("NODE_NAME", "Node-1")

def set_local_node_name(name: str):
    set_config("node_name", name.strip())

_FINGERPRINT_RE = re.compile(r'[0-9A-F]{40}|[0-9A-F]{64}')

def normalize_fingerprint(fp) -> str | None:
    """Returns an OpenPGP fingerprint as uppercase hex without separators (v4: 40, v6: 64 chars), or None."""
    if not isinstance(fp, str):
        return None
    cleaned = re.sub(r'[\s:]', '', fp).upper()
    return cleaned if _FINGERPRINT_RE.fullmatch(cleaned) else None

def add_or_update_peer(email: str, node_name: str = None, chat_id: int = None, last_seen: int = None, fingerprint: str = None):
    email = email.lower().strip()
    fingerprint = normalize_fingerprint(fingerprint)
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT node_name, chat_id, last_seen FROM peers WHERE email = ?", (email,))
        row = cursor.fetchone()
        
        now = int(time.time())
        if row:
            curr_node, curr_chat, curr_seen = row
            new_node = node_name if node_name is not None else curr_node
            new_chat = chat_id if chat_id is not None else curr_chat
            new_seen = last_seen if last_seen is not None else (curr_seen or now)
            # A fingerprint is only filled in, never replaced: a different key means a different bot
            cursor.execute(
                "UPDATE peers SET node_name = ?, chat_id = ?, last_seen = ?, fingerprint = COALESCE(fingerprint, ?) WHERE email = ?",
                (new_node, new_chat, new_seen, fingerprint, email)
            )
        else:
            n_name = node_name or "Remote-Node"
            c_id = chat_id
            s_time = last_seen or now
            cursor.execute(
                "INSERT INTO peers (email, node_name, chat_id, last_seen, fingerprint) VALUES (?, ?, ?, ?, ?)",
                (email, n_name, c_id, s_time, fingerprint)
            )

def find_peer(identifier: str) -> dict | None:
    """Looks a peer up by address, full fingerprint or a fingerprint prefix of at least 8 hex chars."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    peer = get_peer(ident)
    if peer:
        return peer
    fp = re.sub(r'[\s:]', '', ident).upper()
    if len(fp) < 8 or not re.fullmatch(r'[0-9A-F]+', fp):
        return None
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM peers WHERE fingerprint LIKE ?", (fp + "%",)).fetchall()
        # An ambiguous prefix matches nothing rather than an arbitrary peer
        return dict(rows[0]) if len(rows) == 1 else None
    finally:
        conn.close()

def remove_peer(identifier: str) -> bool:
    peer = find_peer(identifier)
    if not peer:
        return False
    email = peer["email"]
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM peers WHERE email = ?", (email,))
        removed = cursor.rowcount > 0
        # Stop scanning targets that were mirrored from this peer
        cursor.execute("DELETE FROM probe_targets WHERE source_peer = ?", (email,))
        return removed

def get_peer(email: str) -> dict | None:
    email = email.lower().strip()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers WHERE email = ?", (email,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_peer_by_fingerprint(fingerprint: str) -> dict | None:
    fingerprint = normalize_fingerprint(fingerprint)
    if not fingerprint:
        return None
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM peers WHERE fingerprint = ?", (fingerprint,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def bind_peer_identity(email: str, fingerprint: str = None, new_email: str = None, chat_id: int = None) -> dict | None:
    """Updates what is known about a peer row identified by `email` and returns the updated row.

    - `fingerprint` is stored if the row has none yet (a row bound to another key is left alone).
    - `new_email` (the address the peer currently sends from) replaces the stored address. Mirrored
      probe targets follow the peer. A stale row of the same bot under `new_email` (no key, or the
      same key) is dropped; a row under `new_email` that belongs to another key blocks the rename.
    - `chat_id` replaces the stored 1:1 chat.
    """
    email = email.lower().strip()
    fingerprint = normalize_fingerprint(fingerprint)
    new_email = (new_email or "").lower().strip() or None
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        # Row access by name on this cursor only: the shared writer connection must keep returning tuples
        cursor.row_factory = sqlite3.Row
        row = cursor.execute("SELECT * FROM peers WHERE email = ?", (email,)).fetchone()
        if not row:
            return None
        if fingerprint and not row["fingerprint"]:
            cursor.execute("UPDATE peers SET fingerprint = ? WHERE email = ?", (fingerprint, email))
        if chat_id is not None and row["chat_id"] != chat_id:
            cursor.execute("UPDATE peers SET chat_id = ? WHERE email = ?", (chat_id, email))
        own_fp = row["fingerprint"] or fingerprint
        if new_email and new_email != email:
            other = cursor.execute("SELECT fingerprint FROM peers WHERE email = ?", (new_email,)).fetchone()
            if other and other["fingerprint"] and other["fingerprint"] != own_fp:
                new_email = None
            else:
                if other:
                    cursor.execute("DELETE FROM peers WHERE email = ?", (new_email,))
                    cursor.execute("DELETE FROM probe_targets WHERE source_peer = ?", (new_email,))
                cursor.execute("UPDATE peers SET email = ? WHERE email = ?", (new_email, email))
                cursor.execute("UPDATE probe_targets SET source_peer = ? WHERE source_peer = ?", (new_email, email))
                email = new_email
        updated = cursor.execute("SELECT * FROM peers WHERE email = ?", (email,)).fetchone()
        return dict(updated) if updated else None

def get_peer_by_chat_id(chat_id: int) -> dict | None:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers WHERE chat_id = ?", (chat_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_all_peers() -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers ORDER BY node_name ASC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def update_peer_last_seen(email: str, timestamp: int = None) -> tuple[bool, int, dict | None]:
    """
    Updates peer last_seen timestamp.
    If the peer was previously marked offline, recovers it and returns:
    (was_recovered, downtime_seconds, peer_dict).
    """
    email = email.lower().strip()
    now = timestamp if timestamp is not None else int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email, node_name, chat_id, last_seen, is_offline, went_offline_at FROM peers WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            return False, 0, None
            
        peer = {
            "email": row[0],
            "node_name": row[1],
            "chat_id": row[2],
            "last_seen": row[3],
            "is_offline": row[4],
            "went_offline_at": row[5],
        }
        was_offline = (peer.get("is_offline") == 1)
        went_offline_at = peer.get("went_offline_at") or 0
        downtime = max(1, now - went_offline_at) if was_offline and went_offline_at > 0 else 0

        cursor.execute("UPDATE peers SET last_seen = ?, is_offline = 0, went_offline_at = 0 WHERE email = ?", (now, email))
        return was_offline, downtime, peer

def audit_peers_offline(threshold_seconds: int = 360, now: int = None) -> list[dict]:
    """
    Finds active peers that have stopped responding (last_seen older than threshold)
    and marks them offline, returning list of newly offline peers.
    """
    cur_time = now if now is not None else int(time.time())
    cutoff = cur_time - threshold_seconds
    newly_offline = []
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, node_name, chat_id, last_seen, is_offline, went_offline_at FROM peers 
            WHERE last_seen > 0 AND last_seen < ? AND (is_offline IS NULL OR is_offline = 0)
        ''', (cutoff,))
        rows = cursor.fetchall()
        for r in rows:
            p = {
                "email": r[0],
                "node_name": r[1],
                "chat_id": r[2],
                "last_seen": r[3],
                "is_offline": 1,
                "went_offline_at": cur_time,
            }
            cursor.execute('''
                UPDATE peers 
                SET is_offline = 1, went_offline_at = ? 
                WHERE email = ?
            ''', (cur_time, p["email"]))
            newly_offline.append(p)
    return newly_offline

# One-time peering invite tokens (issued by /invitepeer, consumed by an incoming HELLO)
PEER_INVITE_TTL_SECONDS = 24 * 3600

def create_peer_invite_token(ttl_seconds: int = PEER_INVITE_TTL_SECONDS, now: int = None) -> str:
    cur_time = now if now is not None else int(time.time())
    token = secrets.token_urlsafe(18)
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM peer_invites WHERE expires_at < ?", (cur_time,))
        cursor.execute("INSERT INTO peer_invites (token, expires_at) VALUES (?, ?)", (token, cur_time + ttl_seconds))
    return token

def consume_peer_invite_token(token: str, now: int = None) -> bool:
    """Returns True and invalidates the token if it is known and not expired."""
    if not token or not isinstance(token, str):
        return False
    cur_time = now if now is not None else int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM peer_invites WHERE token = ? AND expires_at >= ?", (token.strip(), cur_time))
        return cursor.rowcount > 0

# Which local monitors are disclosed to peers: "admin" (chats the admin is in), "all" or "none"
PEER_SHARE_SCOPES = ("admin", "all", "none")

def get_peer_share_scope() -> str:
    scope = (get_config("peer_share_scope") or os.getenv("PEER_SHARE_SCOPE", "admin")).strip().lower()
    return scope if scope in PEER_SHARE_SCOPES else "admin"

def set_peer_share_scope(scope: str):
    scope = (scope or "").strip().lower()
    if scope not in PEER_SHARE_SCOPES:
        raise ValueError(f"Unknown peer share scope: {scope}")
    set_config("peer_share_scope", scope)

# Peer measurements (remote probe telemetry)
def save_peer_measurement(url: str, node_name: str, status: str, latency_ms: int | None = None, error_msg: str = None, last_checked: int = None):
    now = last_checked if last_checked is not None else int(time.time())
    with _writer_transaction() as conn:
        _upsert_peer_measurement(conn.cursor(), url, node_name, status, latency_ms, error_msg, now)


def _upsert_peer_measurement(cursor, url, node_name, status, latency_ms, error_msg, now):
    cursor.execute('''
        INSERT INTO peer_measurements (url, node_name, status, latency_ms, error_msg, last_checked)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(url, node_name) DO UPDATE SET
            status = excluded.status,
            latency_ms = excluded.latency_ms,
            error_msg = excluded.error_msg,
            last_checked = excluded.last_checked
    ''', (url, node_name, status, latency_ms, error_msg, now))

def save_peer_measurements_batch(node_name: str, metrics_list: list[dict]):
    if not metrics_list:
        return
    clean_node = (node_name or "Remote-Node").strip()[:64]
    now = int(time.time())
    
    rows = []
    for item in metrics_list[:200]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()[:500]
        if not url:
            continue
        status = str(item.get("status") or "unknown").strip().lower()
        if status not in ("up", "down", "unknown", "paused"):
            status = "unknown"
        raw_lat = item.get("latency_ms")
        latency_ms = None
        if raw_lat is not None:
            try:
                lat_int = int(raw_lat)
                if 0 <= lat_int <= 600000:
                    latency_ms = lat_int
            except (ValueError, TypeError):
                latency_ms = None
        err = item.get("error_msg")
        error_msg = str(err)[:500] if err else None
        ts = item.get("last_checked")
        try:
            checked_ts = int(ts) if ts is not None else now
        except (ValueError, TypeError):
            checked_ts = now
        rows.append((url, clean_node, status, latency_ms, error_msg, checked_ts))

    if not rows:
        return

    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.executemany('''
            INSERT INTO peer_measurements (url, node_name, status, latency_ms, error_msg, last_checked)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(url, node_name) DO UPDATE SET
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                error_msg = excluded.error_msg,
                last_checked = excluded.last_checked
        ''', rows)

def get_ping_baseline(ip: str) -> float | None:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT rtt_ms FROM ping_baselines WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def set_ping_baseline(ip: str, rtt_ms: float):
    with _writer_transaction() as conn:
        conn.cursor().execute(
            "INSERT OR REPLACE INTO ping_baselines (ip, rtt_ms, updated_at) VALUES (?, ?, ?)",
            (ip, rtt_ms, int(time.time())))

def get_peer_measurements_for_url(url: str) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peer_measurements WHERE url = ? ORDER BY node_name ASC", (url,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_all_peer_measurements() -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peer_measurements ORDER BY url, node_name ASC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

# Remote probe targets functions
MAX_PROBE_TARGETS_PER_PEER = 200

def save_probe_targets_batch(targets: list[dict], source_peer: str = None, max_per_source: int = MAX_PROBE_TARGETS_PER_PEER):
    if not targets:
        return
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM ignored_probe_targets")
        ignore_patterns = [row[0] for row in cursor.fetchall()]

        now = int(time.time())
        # Cap how many active probe targets a single peer can make this node scan
        known_urls = set()
        if source_peer and max_per_source:
            cursor.execute(
                "SELECT url FROM probe_targets WHERE source_peer = ? AND last_seen >= ?",
                (source_peer, now - 86400)
            )
            known_urls = set(row[0] for row in cursor.fetchall())
        new_slots = max(0, max_per_source - len(known_urls)) if (source_peer and max_per_source) else None

        rows = []
        for item in targets[:200]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()[:500]
            if not url or target_matches_ignore(url, ignore_patterns):
                continue
            if new_slots is not None and url not in known_urls:
                if new_slots <= 0:
                    continue
                new_slots -= 1
                known_urls.add(url)
            name = str(item.get("name") or url).strip()[:200]
            chk_type = str(item.get("type") or "http").strip().lower()
            if chk_type not in ("http", "tcp", "ping"):
                chk_type = "http"
            raw_kw = item.get("expected_keyword")
            kw = str(raw_kw).strip()[:200] if raw_kw else None
            raw_method = item.get("http_method")
            method = str(raw_method).strip().upper()[:10] if raw_method else None
            rows.append((url, name, chk_type, kw, method, source_peer, now))

        if rows:
            cursor.executemany('''
                INSERT INTO probe_targets (url, name, type, expected_keyword, http_method, source_peer, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name = excluded.name,
                    type = excluded.type,
                    expected_keyword = excluded.expected_keyword,
                    http_method = COALESCE(excluded.http_method, probe_targets.http_method),
                    source_peer = COALESCE(excluded.source_peer, probe_targets.source_peer),
                    last_seen = excluded.last_seen
            ''', rows)

def get_active_probe_targets(max_age_seconds: int = 86400) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        min_seen = int(time.time()) - max_age_seconds
        cursor.execute("SELECT * FROM probe_targets WHERE last_seen >= ? ORDER BY url ASC", (min_seen,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def update_probe_target_result(url: str, status: str, latency_ms: int = None, error_msg: str = None):
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        now = int(time.time())
        cursor.execute('''
            UPDATE probe_targets
            SET last_checked = ?, last_status = ?, last_latency_ms = ?, last_error = ?,
                down_since = CASE WHEN ? = 'down' THEN COALESCE(down_since, ?) ELSE NULL END
            WHERE url = ?
        ''', (now, status, latency_ms, error_msg, status, now, url))

# Ignored probe targets (excluded from remote scanning on this probe node).
# An entry is a target as written (`https://site/`, `host:25`), a host (`site.example`: every
# target on it) or a pattern with `*` (`*:25`, `*.testrun.org`). Each is compared with the
# target's address, its host and its host:port (http/https with their default port).
_TCP_TARGET_RE = re.compile(r'^\[([^\]]+)\]:(\d+)$|^([^:\[\]/]+):(\d+)$')

def _target_match_keys(url: str) -> set:
    u = (url or "").strip().lower()
    keys = {u, u.rstrip("/")}
    host, port = None, None
    if "://" in u:
        try:
            parsed = urlparse(u)
            host = parsed.hostname
            port = parsed.port or {"https": 443, "http": 80, "smtp": 25}.get(parsed.scheme)
        except ValueError:
            pass
    else:
        m = _TCP_TARGET_RE.match(u)
        if m:
            host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        else:
            host = u  # ping target (host name or IP)
    if host:
        keys.add(host)
        if port:
            keys.add(f"{host}:{port}")
    keys.discard("")
    return keys

def _ignore_pattern_regex(pattern: str):
    # Only "*" is special (any characters); everything else, IPv6 brackets included, is literal
    return re.compile("^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$")

def target_matches_ignore(url: str, patterns) -> bool:
    keys = _target_match_keys(url)
    for pattern in patterns or []:
        p = (pattern or "").strip().lower()
        if not p:
            continue
        if "*" in p:
            rx = _ignore_pattern_regex(p)
            if any(rx.match(k) for k in keys):
                return True
        elif p in keys or p.rstrip("/") in keys:
            return True
    return False

def add_ignored_probe_target(url: str, reason: str = "") -> int:
    """Adds an ignore entry; returns how many mirrored probe targets it matched (and removed)."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO ignored_probe_targets (url, reason) VALUES (?, ?)", (url, reason))
        # Immediately remove matching active probe targets and this node's results for them
        cursor.execute("SELECT url FROM probe_targets")
        matched = [row[0] for row in cursor.fetchall() if target_matches_ignore(row[0], [url])]
        local_node = get_local_node_name()
        cursor.execute("SELECT DISTINCT url FROM peer_measurements WHERE node_name = ?", (local_node,))
        measured = [row[0] for row in cursor.fetchall() if target_matches_ignore(row[0], [url])]
        for target in matched:
            cursor.execute("DELETE FROM probe_targets WHERE url = ?", (target,))
        for target in measured:
            cursor.execute("DELETE FROM peer_measurements WHERE url = ? AND node_name = ?", (target, local_node))
        return len(matched)

def remove_ignored_probe_target(url: str) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ignored_probe_targets WHERE url = ?", (url,))
        return cursor.rowcount > 0

def is_probe_target_ignored(url: str) -> bool:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM ignored_probe_targets")
        return target_matches_ignore(url, [row[0] for row in cursor.fetchall()])
    finally:
        conn.close()

def get_all_ignored_probe_targets() -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ignored_probe_targets ORDER BY url ASC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

# Initialize DB on module import
init_db()


# ---- Quorum alerting -----------------------------------------------------------

ALERT_MODES = ("quorum", "local")

def get_chat_alert_mode(dc_chat_id: int) -> str:
    """quorum (default): a target is down when most nodes cannot reach it. local: this node decides."""
    mode = get_config(f"alert_mode:{dc_chat_id}")
    return mode if mode in ALERT_MODES else "quorum"

def set_chat_alert_mode(dc_chat_id: int, mode: str):
    if mode not in ALERT_MODES:
        raise ValueError(f"alert mode must be one of {ALERT_MODES}")
    set_config(f"alert_mode:{dc_chat_id}", mode)

def update_resource_alert_state(resource_id: int, alert_state: str, last_votes: str | None, degraded_since: int = 0):
    with _writer_transaction() as conn:
        conn.execute(
            "UPDATE resources SET alert_state = ?, last_votes = ?, degraded_since = ? WHERE id = ?",
            (alert_state, last_votes, degraded_since, resource_id)
        )

def update_resource_votes(resource_id: int, last_votes: str | None):
    with _writer_transaction() as conn:
        conn.execute("UPDATE resources SET last_votes = ? WHERE id = ?", (last_votes, resource_id))

def start_partial_outage(resource_id: int, started_at: int, nodes_down: str):
    """Opens a partial outage, or updates the unreachable nodes of the one already open."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM partial_outages WHERE resource_id = ? AND ended_at IS NULL", (resource_id,))
        row = cursor.fetchone()
        if row:
            # "[]": the nodes that could not reach it abstained this time; keep the last known ones
            if nodes_down and nodes_down != "[]":
                cursor.execute("UPDATE partial_outages SET nodes_down = ? WHERE id = ?", (nodes_down, row[0]))
        else:
            cursor.execute(
                "INSERT INTO partial_outages (resource_id, started_at, nodes_down) VALUES (?, ?, ?)",
                (resource_id, started_at, nodes_down)
            )

def end_partial_outage(resource_id: int, ended_at: int) -> int | None:
    """Closes the open partial outage; returns when it started (None if none was open)."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, started_at FROM partial_outages WHERE resource_id = ? AND ended_at IS NULL", (resource_id,))
        row = cursor.fetchone()
        if not row:
            return None
        cursor.execute("UPDATE partial_outages SET ended_at = ? WHERE id = ?", (ended_at, row[0]))
        return row[1]

def get_partial_outages(resource_id: int, limit: int = 20) -> list[dict]:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM partial_outages WHERE resource_id = ? ORDER BY started_at DESC LIMIT ?",
            (resource_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_chat_partial_outages(dc_chat_id: int, limit: int = 10) -> list[dict]:
    """Recent partial outages of a chat's monitors, newest first, with the monitor's name and URL."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute('''
            SELECT po.*, r.name, r.url FROM partial_outages po
            JOIN resources r ON r.id = po.resource_id
            WHERE r.dc_chat_id = ?
            ORDER BY po.started_at DESC LIMIT ?
        ''', (dc_chat_id, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_resources_by_urls(urls) -> list[dict]:
    urls = [u for u in set(urls or []) if u]
    if not urls:
        return []
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = []
        for i in range(0, len(urls), 500):  # stay below SQLite's variable limit
            chunk = urls[i:i + 500]
            rows += conn.execute(
                f"SELECT * FROM resources WHERE url IN ({','.join('?' * len(chunk))})", chunk
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def rename_measurement_node(old_name: str, new_name: str):
    """Moves cached per-node measurements to a node's new name (a newer row under the new name wins)."""
    if not old_name or not new_name or old_name == new_name:
        return
    with _writer_transaction() as conn:
        conn.execute("UPDATE OR IGNORE peer_measurements SET node_name = ? WHERE node_name = ?", (new_name, old_name))
        conn.execute("DELETE FROM peer_measurements WHERE node_name = ?", (old_name,))

def rename_peer_node(email: str, new_name: str) -> bool:
    """Sets a peer's node name and moves its cached measurements to it."""
    email = email.lower().strip()
    with _writer_transaction() as conn:
        row = conn.execute("SELECT node_name FROM peers WHERE email = ?", (email,)).fetchone()
        if not row:
            return False
        old_name = row[0]
        conn.execute("UPDATE peers SET node_name = ? WHERE email = ?", (new_name, email))
        if old_name and old_name != new_name:
            conn.execute("UPDATE OR IGNORE peer_measurements SET node_name = ? WHERE node_name = ?", (new_name, old_name))
            conn.execute("DELETE FROM peer_measurements WHERE node_name = ?", (old_name,))
        return True
