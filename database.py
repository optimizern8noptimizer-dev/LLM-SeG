import sqlite3
from datetime import datetime
from contextlib import contextmanager


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self.get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    key        TEXT UNIQUE NOT NULL,
                    name       TEXT NOT NULL,
                    status     TEXT DEFAULT 'active',
                    rpm_limit  INTEGER DEFAULT 60,
                    created_at TEXT DEFAULT (datetime('now')),
                    last_used  TEXT
                );

                CREATE TABLE IF NOT EXISTS providers (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    name       TEXT NOT NULL,
                    type       TEXT NOT NULL,
                    base_url   TEXT NOT NULL,
                    api_key    TEXT DEFAULT '',
                    status     TEXT DEFAULT 'active',
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS model_routes (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_id       TEXT NOT NULL,
                    provider_id    INTEGER NOT NULL,
                    upstream_model TEXT NOT NULL,
                    priority       INTEGER DEFAULT 0,
                    FOREIGN KEY (provider_id) REFERENCES providers(id)
                );

                CREATE TABLE IF NOT EXISTS request_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id      INTEGER,
                    model       TEXT,
                    status      INTEGER,
                    duration_ms INTEGER,
                    tokens_in   INTEGER DEFAULT 0,
                    tokens_out  INTEGER DEFAULT 0,
                    error_msg   TEXT DEFAULT '',
                    created_at  TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (key_id) REFERENCES api_keys(id)
                );

                CREATE TABLE IF NOT EXISTS rate_limit_tracker (
                    key_id INTEGER NOT NULL,
                    minute TEXT NOT NULL,
                    count  INTEGER DEFAULT 0,
                    PRIMARY KEY (key_id, minute)
                );

                CREATE TABLE IF NOT EXISTS filter_rules (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    name         TEXT NOT NULL UNIQUE,
                    category     TEXT NOT NULL,
                    pattern      TEXT NOT NULL,
                    action       TEXT DEFAULT 'block',
                    severity     TEXT DEFAULT 'high',
                    standard_ref TEXT DEFAULT '',
                    description  TEXT DEFAULT '',
                    is_builtin   INTEGER DEFAULT 0,
                    enabled      INTEGER DEFAULT 1,
                    created_at   TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS filter_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id      INTEGER,
                    model       TEXT,
                    rule_name   TEXT,
                    action      TEXT,
                    severity    TEXT,
                    matched_text TEXT DEFAULT '',
                    created_at  TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (key_id) REFERENCES api_keys(id)
                );

                CREATE INDEX IF NOT EXISTS idx_logs_created ON request_logs(created_at);
                CREATE INDEX IF NOT EXISTS idx_logs_key     ON request_logs(key_id);
                CREATE INDEX IF NOT EXISTS idx_routes_model ON model_routes(model_id);
                CREATE INDEX IF NOT EXISTS idx_flogs_created ON filter_logs(created_at);
            """)

    # ── API Keys ──────────────────────────────────────────────────────────────

    def get_api_key(self, key: str):
        with self.get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key = ?", (key,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE api_keys SET last_used = datetime('now') WHERE key = ?",
                    (key,),
                )
                return dict(row)
        return None

    def check_rate_limit(self, key_id: int, rpm_limit: int) -> bool:
        if rpm_limit <= 0:
            return True
        minute = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO rate_limit_tracker (key_id, minute, count)
                VALUES (?, ?, 1)
                ON CONFLICT(key_id, minute) DO UPDATE SET count = count + 1
                """,
                (key_id, minute),
            )
            row = conn.execute(
                "SELECT count FROM rate_limit_tracker WHERE key_id = ? AND minute = ?",
                (key_id, minute),
            ).fetchone()
            return row["count"] <= rpm_limit

    def log_request(
        self,
        key_id: int,
        model: str,
        status: int,
        duration_ms: int,
        tokens_in: int = 0,
        tokens_out: int = 0,
        error_msg: str = "",
    ):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO request_logs
                    (key_id, model, status, duration_ms, tokens_in, tokens_out, error_msg)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (key_id, model, status, duration_ms, tokens_in, tokens_out, error_msg),
            )

    def list_api_keys(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT k.*,
                    (SELECT COUNT(*) FROM request_logs l
                     WHERE l.key_id = k.id
                       AND l.created_at >= datetime('now', '-24 hours')) AS requests_today
                FROM api_keys k
                ORDER BY k.created_at DESC
                """
            ).fetchall()
            # Mask key: show only last 6 chars
            result = []
            for r in rows:
                d = dict(r)
                d["key_masked"] = "sk-gw-..." + d["key"][-6:]
                result.append(d)
            return result

    def create_api_key(self, key: str, name: str, rpm_limit: int):
        with self.get_conn() as conn:
            conn.execute(
                "INSERT INTO api_keys (key, name, rpm_limit) VALUES (?, ?, ?)",
                (key, name, rpm_limit),
            )

    def update_api_key(self, key_id: int, data: dict):
        allowed = {"name", "status", "rpm_limit"}
        fields = [f for f in data if f in allowed]
        if not fields:
            return
        sql = f"UPDATE api_keys SET {', '.join(f + ' = ?' for f in fields)} WHERE id = ?"
        values = [data[f] for f in fields] + [key_id]
        with self.get_conn() as conn:
            conn.execute(sql, values)

    def delete_api_key(self, key_id: int):
        with self.get_conn() as conn:
            conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))

    # ── Providers ─────────────────────────────────────────────────────────────

    def list_providers(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM providers ORDER BY name"
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                # Mask API key
                ak = d.get("api_key") or ""
                d["api_key_masked"] = (ak[:4] + "..." + ak[-4:]) if len(ak) > 8 else ("***" if ak else "")
                result.append(d)
            return result

    def get_provider_raw(self, provider_id: int):
        with self.get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM providers WHERE id = ?", (provider_id,)
            ).fetchone()
            return dict(row) if row else None

    def create_provider(self, data: dict):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO providers (name, type, base_url, api_key, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    data["name"],
                    data["type"],
                    data["base_url"],
                    data.get("api_key", ""),
                    data.get("status", "active"),
                ),
            )

    def update_provider(self, provider_id: int, data: dict):
        allowed = {"name", "type", "base_url", "api_key", "status"}
        fields = [f for f in data if f in allowed]
        if not fields:
            return
        sql = f"UPDATE providers SET {', '.join(f + ' = ?' for f in fields)} WHERE id = ?"
        values = [data[f] for f in fields] + [provider_id]
        with self.get_conn() as conn:
            conn.execute(sql, values)

    def delete_provider(self, provider_id: int):
        with self.get_conn() as conn:
            conn.execute(
                "DELETE FROM model_routes WHERE provider_id = ?", (provider_id,)
            )
            conn.execute("DELETE FROM providers WHERE id = ?", (provider_id,))

    # ── Routes ────────────────────────────────────────────────────────────────

    def list_routes(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT r.*, p.name AS provider_name, p.type AS provider_type
                FROM model_routes r
                JOIN providers p ON r.provider_id = p.id
                ORDER BY r.model_id
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def create_route(self, data: dict):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO model_routes (model_id, provider_id, upstream_model, priority)
                VALUES (?, ?, ?, ?)
                """,
                (
                    data["model_id"],
                    int(data["provider_id"]),
                    data["upstream_model"],
                    int(data.get("priority", 0)),
                ),
            )

    def delete_route(self, route_id: int):
        with self.get_conn() as conn:
            conn.execute("DELETE FROM model_routes WHERE id = ?", (route_id,))

    def get_provider_for_model(self, model_id: str):
        with self.get_conn() as conn:
            row = conn.execute(
                """
                SELECT r.*, p.name AS provider_name, p.type AS provider_type,
                       p.base_url, p.api_key
                FROM model_routes r
                JOIN providers p ON r.provider_id = p.id
                WHERE r.model_id = ? AND p.status = 'active'
                ORDER BY r.priority DESC
                LIMIT 1
                """,
                (model_id,),
            ).fetchone()
            return dict(row) if row else None

    def get_all_models(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT r.model_id, p.name AS provider
                FROM model_routes r
                JOIN providers p ON r.provider_id = p.id
                WHERE p.status = 'active'
                GROUP BY r.model_id
                """
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Stats & Logs ──────────────────────────────────────────────────────────

    def get_stats(self):
        with self.get_conn() as conn:
            total = conn.execute(
                """
                SELECT
                    COUNT(*)                                             AS total,
                    COALESCE(SUM(tokens_in + tokens_out), 0)            AS tokens,
                    COALESCE(AVG(duration_ms), 0)                       AS avg_lat,
                    COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) AS errors
                FROM request_logs
                WHERE created_at >= datetime('now', '-24 hours')
                """
            ).fetchone()

            by_hour = conn.execute(
                """
                SELECT strftime('%H', created_at) AS hour, COUNT(*) AS cnt
                FROM request_logs
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
                """
            ).fetchall()

            top_models = conn.execute(
                """
                SELECT model,
                       COUNT(*) AS cnt,
                       COALESCE(SUM(tokens_in + tokens_out), 0) AS tokens
                FROM request_logs
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY model
                ORDER BY cnt DESC
                LIMIT 10
                """
            ).fetchall()

            active_keys = conn.execute(
                "SELECT COUNT(*) AS cnt FROM api_keys WHERE status = 'active'"
            ).fetchone()

            req_7d = conn.execute(
                """
                SELECT strftime('%Y-%m-%d', created_at) AS day, COUNT(*) AS cnt
                FROM request_logs
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY day
                ORDER BY day
                """
            ).fetchall()

            return {
                "total_requests": total["total"],
                "total_tokens": total["tokens"],
                "avg_latency": round(total["avg_lat"]),
                "errors": total["errors"],
                "active_keys": active_keys["cnt"],
                "by_hour": [dict(r) for r in by_hour],
                "top_models": [dict(r) for r in top_models],
                "req_7d": [dict(r) for r in req_7d],
            }

    def get_logs(self, limit: int = 100, offset: int = 0):
        with self.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT l.*, k.name AS key_name
                FROM request_logs l
                LEFT JOIN api_keys k ON l.key_id = k.id
                ORDER BY l.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) AS cnt FROM request_logs"
            ).fetchone()
            return {"logs": [dict(r) for r in rows], "total": total["cnt"]}

    def cleanup_old_rate_limits(self):
        """Remove rate limit records older than 5 minutes."""
        with self.get_conn() as conn:
            conn.execute(
                "DELETE FROM rate_limit_tracker WHERE minute < strftime('%Y-%m-%d %H:%M', datetime('now', '-5 minutes'))"
            )

    # ── Filter Rules ──────────────────────────────────────────────────────────

    def get_rule_names(self) -> set:
        with self.get_conn() as conn:
            rows = conn.execute("SELECT name FROM filter_rules").fetchall()
            return {r["name"] for r in rows}

    def list_filter_rules(self, enabled_only: bool = False):
        with self.get_conn() as conn:
            if enabled_only:
                rows = conn.execute(
                    "SELECT * FROM filter_rules WHERE enabled = 1 ORDER BY severity DESC, category"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM filter_rules ORDER BY severity DESC, category"
                ).fetchall()
            return [dict(r) for r in rows]

    def create_filter_rule(self, data: dict):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO filter_rules
                    (name, category, pattern, action, severity, standard_ref, description, is_builtin, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["name"], data["category"], data["pattern"],
                    data.get("action", "block"), data.get("severity", "high"),
                    data.get("standard_ref", ""), data.get("description", ""),
                    int(data.get("is_builtin", 0)), int(data.get("enabled", 1)),
                ),
            )

    def update_filter_rule(self, rule_id: int, data: dict):
        allowed = {"name", "category", "pattern", "action", "severity",
                   "standard_ref", "description", "enabled"}
        fields = [f for f in data if f in allowed]
        if not fields:
            return
        sql = f"UPDATE filter_rules SET {', '.join(f + ' = ?' for f in fields)} WHERE id = ?"
        values = [data[f] for f in fields] + [rule_id]
        with self.get_conn() as conn:
            conn.execute(sql, values)

    def delete_filter_rule(self, rule_id: int):
        with self.get_conn() as conn:
            conn.execute("DELETE FROM filter_rules WHERE id = ?", (rule_id,))

    def toggle_filter_rule(self, rule_id: int, enabled: bool):
        with self.get_conn() as conn:
            conn.execute(
                "UPDATE filter_rules SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, rule_id),
            )

    def log_filter_event(self, key_id: int, model: str, rule_name: str,
                         action: str, severity: str, matched_text: str = ""):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO filter_logs
                    (key_id, model, rule_name, action, severity, matched_text)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, model, rule_name, action, severity, matched_text[:200]),
            )

    def get_filter_logs(self, limit: int = 100, offset: int = 0):
        with self.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT fl.*, k.name AS key_name
                FROM filter_logs fl
                LEFT JOIN api_keys k ON fl.key_id = k.id
                ORDER BY fl.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS cnt FROM filter_logs").fetchone()
            return {"logs": [dict(r) for r in rows], "total": total["cnt"]}

    def get_filter_stats(self):
        with self.get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS cnt FROM filter_logs WHERE created_at >= datetime('now', '-24 hours')"
            ).fetchone()
            by_severity = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM filter_logs
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY severity ORDER BY cnt DESC
                """
            ).fetchall()
            top_rules = conn.execute(
                """
                SELECT rule_name, action, COUNT(*) AS cnt
                FROM filter_logs
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY rule_name ORDER BY cnt DESC LIMIT 10
                """
            ).fetchall()
            enabled_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM filter_rules WHERE enabled = 1"
            ).fetchone()
            return {
                "total_blocked": total["cnt"],
                "enabled_rules": enabled_count["cnt"],
                "by_severity": [dict(r) for r in by_severity],
                "top_rules": [dict(r) for r in top_rules],
            }
