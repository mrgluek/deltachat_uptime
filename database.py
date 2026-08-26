import os
import re
import sqlite3
import threading
import time
import secrets
import string

DB_PATH = os.getenv("DB_PATH", "uptime.db")
_lock = threading.RLock()

def init_db():
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
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
            
        # Add index to downtime_events for fast lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_resource ON downtime_events(resource_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_downtime_went_down ON downtime_events(went_down_at)')
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

        # Remote probe targets mirrored from peer bots
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS probe_targets (
                url TEXT PRIMARY KEY,
                name TEXT,
                type TEXT DEFAULT 'http',
                expected_keyword TEXT,
                source_peer TEXT,
                last_seen INTEGER,
                last_checked INTEGER,
                last_status TEXT,
                last_latency_ms INTEGER,
                last_error TEXT
            )
        ''')

        # Ignored probe targets (excluded from remote scanning on this probe)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ignored_probe_targets (
                url TEXT PRIMARY KEY,
                reason TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            )
        ''')
        
        conn.commit()
        conn.close()

# Config functions
def set_config(key: str, value: str):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()

def get_config(key: str) -> str:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

def get_admin_fingerprint():
    return get_config("admin_dc_fingerprint")

def set_admin_fingerprint(fp):
    set_config("admin_dc_fingerprint", fp)

# Chat token functions (12-character base62 secure tokens)
def generate_chat_token() -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(12))

def get_or_create_chat_token(dc_chat_id: int) -> str:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM chats WHERE dc_chat_id = ?", (dc_chat_id,))
        row = cursor.fetchone()
        if row:
            token = row[0]
        else:
            # Generate a unique token
            while True:
                token = generate_chat_token()
                try:
                    cursor.execute("INSERT INTO chats (dc_chat_id, token) VALUES (?, ?)", (dc_chat_id, token))
                    conn.commit()
                    break
                except sqlite3.IntegrityError:
                    # Token collision, retry
                    continue
        conn.close()
        return token

def get_chat_id_by_token(token: str) -> int:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT dc_chat_id FROM chats WHERE token = ?", (token,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

# Resource functions
def add_resource(dc_chat_id: int, url: str, name: str, check_type: str, interval: int = 60, expected_keyword: str = None) -> int:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO resources (dc_chat_id, url, name, type, interval, status, last_changed, expected_keyword) 
                VALUES (?, ?, ?, ?, ?, 'unknown', ?, ?)
            ''', (dc_chat_id, url, name, check_type, interval, int(time.time()), expected_keyword))
            resource_id = cursor.lastrowid
            conn.commit()
            return resource_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

def set_resource_keyword(dc_chat_id: int, resource_id: int, keyword: str | None) -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET expected_keyword = ? WHERE dc_chat_id = ? AND id = ?", (keyword, dc_chat_id, resource_id))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

def set_resource_maintenance(dc_chat_id: int, resource_id: int, until_ts: int) -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET maintenance_until = ? WHERE dc_chat_id = ? AND id = ?", (until_ts, dc_chat_id, resource_id))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

def update_resource_latency(resource_id: int, latency_ms: int):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET last_latency_ms = ? WHERE id = ?", (latency_ms, resource_id))
        conn.commit()
        conn.close()

def delete_resource(dc_chat_id: int, resource_id: int) -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM resources WHERE dc_chat_id = ? AND id = ?", (dc_chat_id, resource_id))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

def get_resources(dc_chat_id: int) -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE dc_chat_id = ? ORDER BY id ASC", (dc_chat_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_resource_by_id(resource_id: int) -> dict | None:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

def get_all_resources() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def update_resource_status(resource_id: int, status: str, consecutive_failures: int, error_msg: str = None):
    """Updates the status and last_checked fields. Manages downtime events for monthly statistics."""
    now = int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get current status
        cursor.execute("SELECT status, last_changed FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return
            
        old_status = row[0]
        
        if old_status != status:
            # Status transition occurred
            cursor.execute('''
                UPDATE resources 
                SET status = ?, last_checked = ?, last_changed = ?, consecutive_failures = ? 
                WHERE id = ?
            ''', (status, now, now, consecutive_failures, resource_id))
            
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

                # Opened new downtime event with error message and incident_id
                cursor.execute('''
                    INSERT INTO downtime_events (resource_id, went_down_at, went_up_at, error_msg, incident_id)
                    VALUES (?, ?, NULL, ?, ?)
                ''', (resource_id, now, error_msg, inc_id))
            elif status == "up" and old_status == "down":
                # Close existing downtime event and reset stale warning level
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
            # No status change
            cursor.execute('''
                UPDATE resources 
                SET last_checked = ?, consecutive_failures = ? 
                WHERE id = ?
            ''', (now, consecutive_failures, resource_id))
            
        conn.commit()
        conn.close()

def update_stale_warning_level(resource_id: int, level: int):
    """Update the highest stale downtime warning level sent for this resource (0, 7, 14)."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET stale_warning_level = ? WHERE id = ?", (level, resource_id))
        conn.commit()
        conn.close()

def update_resource_ssl(resource_id: int, ssl_expiry_date: int | None, ssl_last_checked: int, ssl_alert_state: int = 0):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET ssl_expiry_date = ?, ssl_last_checked = ?, ssl_alert_state = ? 
            WHERE id = ?
        ''', (ssl_expiry_date, ssl_last_checked, ssl_alert_state, resource_id))
        conn.commit()
        conn.close()

def update_ssl_alert_state(resource_id: int, ssl_alert_state: int):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET ssl_alert_state = ? 
            WHERE id = ?
        ''', (ssl_alert_state, resource_id))
        conn.commit()
        conn.close()

def update_resource_down_msg_id(resource_id: int, msg_id: int | None):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE resources 
            SET last_down_msg_id = ? 
            WHERE id = ?
        ''', (msg_id, resource_id))
        conn.commit()
        conn.close()

# Incident management functions
def create_incident(dc_chat_id: int, started_at: int = None) -> int:
    if started_at is None:
        started_at = int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (dc_chat_id, status, started_at)
            VALUES (?, 'ongoing', ?)
        ''', (dc_chat_id, started_at))
        incident_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return incident_id

def get_active_incident(dc_chat_id: int) -> dict | None:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND status = 'ongoing' 
            ORDER BY id DESC LIMIT 1
        ''', (dc_chat_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

def get_active_incidents_for_chat(dc_chat_id: int) -> list[dict]:
    """Returns all currently ongoing incidents for a specific chat."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND status = 'ongoing' 
            ORDER BY id ASC
        ''', (dc_chat_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_active_incident_for_outage(dc_chat_id: int, outage_time: int, max_gap_seconds: int = 3600, allow_reopen: bool = True) -> dict | None:
    """Finds an ongoing or recently resolved incident in dc_chat_id within max_gap_seconds of outage_time."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
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
        conn.close()
        return dict(row) if row else None

def reopen_incident(incident_id: int):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET status = 'ongoing', resolved_at = NULL, summary = NULL 
            WHERE id = ?
        ''', (incident_id,))
        conn.commit()
        conn.close()

def get_all_active_incidents() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE status = 'ongoing' ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_incident_by_msg_id(dc_chat_id: int, msg_id: int) -> dict | None:
    """Finds incident record matching chat and message ID."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND msg_id = ?
            ORDER BY id DESC LIMIT 1
        ''', (dc_chat_id, msg_id))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

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
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET msg_id = ? 
            WHERE id = ?
        ''', (msg_id, incident_id))
        conn.commit()
        conn.close()

def resolve_incident(incident_id: int, resolved_at: int = None, summary: str = ""):
    if resolved_at is None:
        resolved_at = int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE incidents 
            SET status = 'resolved', resolved_at = ?, summary = ? 
            WHERE id = ?
        ''', (resolved_at, summary, incident_id))
        conn.commit()
        conn.close()

def get_recent_incidents(dc_chat_id: int, limit: int = 10) -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? 
            ORDER BY id DESC LIMIT ?
        ''', (dc_chat_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_incident_by_id(dc_chat_id: int, incident_id: int) -> dict | None:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE dc_chat_id = ? AND id = ?
        ''', (dc_chat_id, incident_id))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

def get_unlinked_open_downtime_events(dc_chat_id: int) -> list[dict]:
    """Returns open downtime events in this chat that are not yet linked to any incident."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT de.*, r.name, r.url, r.type, r.status as resource_status
            FROM downtime_events de
            JOIN resources r ON r.id = de.resource_id
            WHERE r.dc_chat_id = ? AND de.went_up_at IS NULL AND de.incident_id IS NULL
            ORDER BY de.went_down_at ASC
        ''', (dc_chat_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def link_downtime_event_to_incident(downtime_event_id: int, incident_id: int):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE downtime_events SET incident_id = ? WHERE id = ?", (incident_id, downtime_event_id))
        conn.commit()
        conn.close()

def get_incident_downtime_events(incident_id: int) -> list[dict]:
    """Returns all downtime events associated with an incident."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT de.*, r.name, r.url, r.type, r.status as resource_status, r.last_changed, r.consecutive_failures
            FROM downtime_events de
            LEFT JOIN resources r ON r.id = de.resource_id
            WHERE de.incident_id = ?
            ORDER BY de.went_down_at ASC
        ''', (incident_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def close_resource_downtime_events(resource_id: int, now: int = None):
    if now is None:
        now = int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE downtime_events SET went_up_at = ? WHERE resource_id = ? AND went_up_at IS NULL", (now, resource_id))
        conn.commit()
        conn.close()

def get_resource_downtime_events(resource_id: int, limit: int = 10) -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM downtime_events 
            WHERE resource_id = ? 
            ORDER BY went_down_at DESC LIMIT ?
        ''', (resource_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_incident_affected_resource_ids(incident_id: int, fallback_chat_id: int = None, fallback_started_at: int = None) -> set[int]:
    """Return set of resource IDs that experienced downtime in this incident."""
    with _lock:
        conn = sqlite3.connect(DB_PATH)
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
            
        conn.close()
        return res_ids

# Uptime calculation functions
def get_resource_uptime_30d(resource_id: int) -> float:
    """Calculates the uptime percentage of a resource over the last 30 days."""
    now = int(time.time())
    start_time = now - 30 * 24 * 3600
    
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get resource creation time
        cursor.execute("SELECT created_at FROM resources WHERE id = ?", (resource_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return 100.0
            
        created_at = row[0]
        tracking_start = max(created_at, start_time)
        total_time = now - tracking_start
        if total_time <= 0:
            conn.close()
            return 100.0
            
        # Get all overlapping downtime events in the last 30 days
        cursor.execute('''
            SELECT went_down_at, went_up_at FROM downtime_events 
            WHERE resource_id = ? AND went_down_at < ? AND (went_up_at IS NULL OR went_up_at > ?)
        ''', (resource_id, now, tracking_start))
        
        events = cursor.fetchall()
        conn.close()
        
        total_downtime = 0
        for went_down, went_up in events:
            effective_start = max(went_down, tracking_start)
            effective_end = min(went_up if went_up else now, now)
            duration = effective_end - effective_start
            if duration > 0:
                total_downtime += duration
                
        uptime_pct = ((total_time - total_downtime) / total_time) * 100.0
        return max(0.0, min(100.0, uptime_pct))

def get_chat_uptime_30d(dc_chat_id: int) -> float:
    """Calculates average uptime percentage for all resources in a chat."""
    resources = get_resources(dc_chat_id)
    if not resources:
        return 100.0
        
    uptimes = [get_resource_uptime_30d(r["id"]) for r in resources]
    return sum(uptimes) / len(uptimes)

# Transport statistics tracking
def increment_transport_sent(addr: str):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transport_stats (addr, msgs_sent, msgs_received, last_sent_at)
            VALUES (?, 1, 0, CAST(strftime('%s','now') AS INTEGER))
            ON CONFLICT(addr) DO UPDATE SET
                msgs_sent = msgs_sent + 1,
                last_sent_at = CAST(strftime('%s','now') AS INTEGER)
        ''', (addr,))
        conn.commit()
        conn.close()

def increment_transport_received(addr: str):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transport_stats (addr, msgs_sent, msgs_received, last_received_at)
            VALUES (?, 0, 1, CAST(strftime('%s','now') AS INTEGER))
            ON CONFLICT(addr) DO UPDATE SET
                msgs_received = msgs_received + 1,
                last_received_at = CAST(strftime('%s','now') AS INTEGER)
        ''', (addr,))
        conn.commit()
        conn.close()

def get_all_transport_stats() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transport_stats ORDER BY msgs_sent + msgs_received DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

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
    with _lock:
        conn = sqlite3.connect(DB_PATH)
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
        conn.commit()
        conn.close()

def remove_peer(email: str) -> bool:
    email = email.lower().strip()
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM peers WHERE email = ?", (email,))
        changed = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return changed

def get_peer(email: str) -> dict | None:
    email = email.lower().strip()
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

def get_peer_by_chat_id(chat_id: int) -> dict | None:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers WHERE chat_id = ?", (chat_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

def get_all_peers() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers ORDER BY node_name ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def update_peer_last_seen(email: str, timestamp: int = None) -> tuple[bool, int, dict | None]:
    """
    Updates peer last_seen timestamp.
    If the peer was previously marked offline, recovers it and returns:
    (was_recovered, downtime_seconds, peer_dict).
    """
    email = email.lower().strip()
    now = timestamp if timestamp is not None else int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False, 0, None
            
        peer = dict(row)
        was_offline = (peer.get("is_offline") == 1)
        went_offline_at = peer.get("went_offline_at") or 0
        downtime = max(1, now - went_offline_at) if was_offline and went_offline_at > 0 else 0

        cursor.execute("UPDATE peers SET last_seen = ?, is_offline = 0, went_offline_at = 0 WHERE email = ?", (now, email))
        conn.commit()
        conn.close()
        return was_offline, downtime, peer

def audit_peers_offline(threshold_seconds: int = 360, now: int = None) -> list[dict]:
    """
    Finds active peers that have stopped responding (last_seen older than threshold)
    and marks them offline, returning list of newly offline peers.
    """
    cur_time = now if now is not None else int(time.time())
    cutoff = cur_time - threshold_seconds
    newly_offline = []
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM peers 
            WHERE last_seen > 0 AND last_seen < ? AND (is_offline IS NULL OR is_offline = 0)
        ''', (cutoff,))
        rows = cursor.fetchall()
        for r in rows:
            p = dict(r)
            cursor.execute('''
                UPDATE peers 
                SET is_offline = 1, went_offline_at = ? 
                WHERE email = ?
            ''', (cur_time, p["email"]))
            p["is_offline"] = 1
            p["went_offline_at"] = cur_time
            newly_offline.append(p)
        conn.commit()
        conn.close()
    return newly_offline

# Peer measurements (remote probe telemetry)
def save_peer_measurement(url: str, node_name: str, status: str, latency_ms: int | None = None, error_msg: str = None, last_checked: int = None):
    now = last_checked if last_checked is not None else int(time.time())
    with _lock:
        conn = sqlite3.connect(DB_PATH)
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
        conn.commit()
        conn.close()

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

    with _lock:
        conn = sqlite3.connect(DB_PATH)
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
        conn.commit()
        conn.close()

def get_peer_measurements_for_url(url: str) -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peer_measurements WHERE url = ? ORDER BY node_name ASC", (url,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def get_all_peer_measurements() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peer_measurements ORDER BY url, node_name ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

# Remote probe targets functions
def save_probe_targets_batch(targets: list[dict], source_peer: str = None):
    if not targets:
        return
    with _lock:
        conn = sqlite3.connect(DB_PATH)
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
            rows.append((url, name, chk_type, kw, source_peer, now))

        if rows:
            cursor.executemany('''
                INSERT INTO probe_targets (url, name, type, expected_keyword, source_peer, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name = excluded.name,
                    type = excluded.type,
                    expected_keyword = excluded.expected_keyword,
                    source_peer = COALESCE(excluded.source_peer, probe_targets.source_peer),
                    last_seen = excluded.last_seen
            ''', rows)
        conn.commit()
        conn.close()

def get_active_probe_targets(max_age_seconds: int = 86400) -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        min_seen = int(time.time()) - max_age_seconds
        cursor.execute("SELECT * FROM probe_targets WHERE last_seen >= ? ORDER BY url ASC", (min_seen,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def update_probe_target_result(url: str, status: str, latency_ms: int = None, error_msg: str = None):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = int(time.time())
        cursor.execute('''
            UPDATE probe_targets
            SET last_checked = ?, last_status = ?, last_latency_ms = ?, last_error = ?
            WHERE url = ?
        ''', (now, status, latency_ms, error_msg, url))
        conn.commit()
        conn.close()

# Ignored probe targets (excluded from remote scanning on this probe node)
def add_ignored_probe_target(url: str, reason: str = "") -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO ignored_probe_targets (url, reason) VALUES (?, ?)", (url, reason))
        # Immediately remove from active probe targets
        cursor.execute("DELETE FROM probe_targets WHERE url = ?", (url,))
        local_node = get_local_node_name()
        cursor.execute("DELETE FROM peer_measurements WHERE url = ? AND node_name = ?", (url, local_node))
        conn.commit()
        conn.close()
        return True

def remove_ignored_probe_target(url: str) -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ignored_probe_targets WHERE url = ?", (url,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

def is_probe_target_ignored(url: str) -> bool:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM ignored_probe_targets WHERE url = ?", (url,))
        row = cursor.fetchone()
        conn.close()
        return row is not None

def get_all_ignored_probe_targets() -> list[dict]:
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ignored_probe_targets ORDER BY url ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

# Initialize DB on module import
init_db()


