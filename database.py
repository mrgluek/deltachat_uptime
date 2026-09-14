import contextlib
import os
import re
import sqlite3
import threading
import time
import secrets
import string

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
        if "expected_keyword" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN expected_keyword TEXT")
        if "maintenance_until" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN maintenance_until INTEGER DEFAULT 0")
        if "last_latency_ms" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN last_latency_ms INTEGER")
        if "http_method" not in columns:
            cursor.execute("ALTER TABLE resources ADD COLUMN http_method TEXT")
        
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen)')

        # Ensure columns exist in peers for existing DBs
        cursor.execute("PRAGMA table_info(peers)")
        peer_cols = [c[1] for c in cursor.fetchall()]
        if "is_offline" not in peer_cols:
            cursor.execute("ALTER TABLE peers ADD COLUMN is_offline INTEGER DEFAULT 0")
        if "went_offline_at" not in peer_cols:
            cursor.execute("ALTER TABLE peers ADD COLUMN went_offline_at INTEGER DEFAULT 0")

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

        # Ignored probe targets (excluded from remote scanning on this probe)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ignored_probe_targets (
                url TEXT PRIMARY KEY,
                reason TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now'))
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

def delete_resource(dc_chat_id: int, resource_id: int) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM resources WHERE dc_chat_id = ? AND id = ?", (dc_chat_id, resource_id))
        deleted = cursor.rowcount > 0
        if deleted:
            invalidate_uptime_cache(resource_id)
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
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources ORDER BY id ASC")
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

    now = int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
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
                    cursor.execute('''
                        UPDATE resources 
                        SET stale_warning_level = 0 
                        WHERE id = ?
                    ''', (resource_id,))
            else:
                cursor.execute('''
                    UPDATE resources 
                    SET last_checked = ?, consecutive_failures = ?,
                        last_latency_ms = COALESCE(?, last_latency_ms)
                    WHERE id = ?
                ''', (now, consecutive_failures, latency_ms, resource_id))


def update_resource_status(resource_id: int, status: str, consecutive_failures: int, error_msg: str = None, latency_ms: int = None):
    """Updates the status, last_checked, and optionally last_latency_ms in a single transaction."""
    batch_update_resource_status([{
        "id": resource_id,
        "status": status,
        "consecutive_failures": consecutive_failures,
        "error_msg": error_msg,
        "latency_ms": latency_ms,
    }])

def update_stale_warning_level(resource_id: int, level: int):
    """Update the highest stale downtime warning level sent for this resource (0, 7, 14)."""
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET stale_warning_level = ? WHERE id = ?", (level, resource_id))

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
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE status = 'ongoing' ORDER BY id ASC")
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
            SELECT de.*, r.name, r.url, r.type, r.status as resource_status, r.last_changed, r.consecutive_failures
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
    return cleaned

# Peer management functions
def get_local_node_name() -> str:
    name = get_config("node_name")
    if name:
        return name
    return os.getenv("NODE_NAME", "Node-1")

def set_local_node_name(name: str):
    set_config("node_name", name.strip())

def add_or_update_peer(email: str, node_name: str = None, chat_id: int = None, last_seen: int = None):
    email = email.lower().strip()
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
            cursor.execute(
                "UPDATE peers SET node_name = ?, chat_id = ?, last_seen = ? WHERE email = ?",
                (new_node, new_chat, new_seen, email)
            )
        else:
            n_name = node_name or "Remote-Node"
            c_id = chat_id
            s_time = last_seen or now
            cursor.execute(
                "INSERT INTO peers (email, node_name, chat_id, last_seen) VALUES (?, ?, ?, ?)",
                (email, n_name, c_id, s_time)
            )

def remove_peer(email: str) -> bool:
    email = email.lower().strip()
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM peers WHERE email = ?", (email,))
        return cursor.rowcount > 0

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

# Peer measurements (remote probe telemetry)
def save_peer_measurement(url: str, node_name: str, status: str, latency_ms: int | None = None, error_msg: str = None, last_checked: int = None):
    now = last_checked if last_checked is not None else int(time.time())
    with _writer_transaction() as conn:
        cursor = conn.cursor()
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
def save_probe_targets_batch(targets: list[dict], source_peer: str = None):
    if not targets:
        return
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM ignored_probe_targets")
        ignored_set = set(row[0] for row in cursor.fetchall())

        now = int(time.time())
        rows = []
        for item in targets[:200]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()[:500]
            if not url or url in ignored_set:
                continue
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
            SET last_checked = ?, last_status = ?, last_latency_ms = ?, last_error = ?
            WHERE url = ?
        ''', (now, status, latency_ms, error_msg, url))

# Ignored probe targets (excluded from remote scanning on this probe node)
def add_ignored_probe_target(url: str, reason: str = "") -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO ignored_probe_targets (url, reason) VALUES (?, ?)", (url, reason))
        # Immediately remove from active probe targets
        cursor.execute("DELETE FROM probe_targets WHERE url = ?", (url,))
        local_node = get_local_node_name()
        cursor.execute("DELETE FROM peer_measurements WHERE url = ? AND node_name = ?", (url, local_node))
        return True

def remove_ignored_probe_target(url: str) -> bool:
    with _writer_transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ignored_probe_targets WHERE url = ?", (url,))
        return cursor.rowcount > 0

def is_probe_target_ignored(url: str) -> bool:
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM ignored_probe_targets WHERE url = ?", (url,))
        row = cursor.fetchone()
        return row is not None
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
