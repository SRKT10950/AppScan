"""
AppScan Database Layer
Supports PostgreSQL (Central Database) with automatic fallback to local SQLite.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3

# Try to import psycopg2 if available
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAVE_PSYCOPG2 = True
except ImportError:
    HAVE_PSYCOPG2 = False

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))

def get_pg_config():
    db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if db_url:
        # Strip asyncpg prefix if present
        cleaned_url = db_url.replace("+asyncpg", "").replace("+psycopg2", "")
        return {"url": cleaned_url}

    pg_host = os.environ.get("CENTRAL_PG_HOST")
    if pg_host:
        return {
            "host": pg_host,
            "port": int(os.environ.get("CENTRAL_PG_PORT", "5432")),
            "user": os.environ.get("CENTRAL_PG_USER", "postgres"),
            "password": os.environ.get("CENTRAL_PG_PASSWORD", "postgres_master_pass_2026"),
            "dbname": os.environ.get("CENTRAL_PG_DATABASE") or os.environ.get("CENTRAL_PG_DB", "appscan_db"),
            "connect_timeout": 5
        }
    return None


class DBWrapper:
    def __init__(self, backend_type, raw_conn, cur):
        self.backend = backend_type
        self.conn = raw_conn
        self.cur = cur

    def execute(self, sql, params=None):
        params = params or ()
        if self.backend == "postgres":
            # Convert SQLite '?' placeholders to PostgreSQL '%s'
            pg_sql = sql.replace("?", "%s")
            self.cur.execute(pg_sql, params)
        else:
            self.cur.execute(sql, params)
        return self

    def fetchone(self):
        row = self.cur.fetchone()
        if row is None:
            return None
        if self.backend == "postgres":
            return dict(row)
        return dict(row)

    def fetchall(self):
        rows = self.cur.fetchall()
        if self.backend == "postgres":
            return [dict(r) for r in rows]
        return [dict(r) for r in rows]


@contextmanager
def get_db():
    pg_conf = get_pg_config() if HAVE_PSYCOPG2 else None
    if pg_conf:
        try:
            if "url" in pg_conf:
                conn = psycopg2.connect(pg_conf["url"], cursor_factory=RealDictCursor)
            else:
                conn = psycopg2.connect(**pg_conf, cursor_factory=RealDictCursor)
            cur = conn.cursor()
            wrapper = DBWrapper("postgres", conn, cur)
            try:
                yield wrapper
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cur.close()
                conn.close()
            return
        except Exception as exc:
            # Fall back to SQLite if PostgreSQL connection fails
            print(f"[AppScan DB] PostgreSQL connection failed ({exc}). Falling back to SQLite.", flush=True)

    # SQLite fallback
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATA_DIR / "appscan.db", timeout=15)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    wrapper = DBWrapper("sqlite", conn, cur)
    try:
        yield wrapper
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def initialize_db():
    pg_conf = get_pg_config() if HAVE_PSYCOPG2 else None
    active_backend = "SQLite"

    with get_db() as db:
        if db.backend == "postgres":
            active_backend = "Central PostgreSQL"
            db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id VARCHAR(64) PRIMARY KEY,
                    project TEXT,
                    created TEXT,
                    status VARCHAR(32),
                    result TEXT
                )
            """)
        else:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    project TEXT,
                    created TEXT,
                    status TEXT,
                    result TEXT
                )
            """)

        reset_msg = json.dumps({"error": "Server restarted before completion. Submit the scan again."})
        db.execute("UPDATE scans SET status='failed', result=? WHERE status IN ('queued', 'running')", (reset_msg,))

    print(f"[AppScan DB] Database initialized using: {active_backend}", flush=True)
