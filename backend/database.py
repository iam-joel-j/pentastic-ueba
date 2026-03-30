import sqlite3

DB_NAME = "pentastic.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT UNIQUE NOT NULL,
        role            TEXT NOT NULL,
        risk_score      INTEGER DEFAULT 0,
        status          TEXT DEFAULT 'SAFE',
        failed_attempts INTEGER DEFAULT 0,
        last_updated    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT NOT NULL,
        login_time      TEXT,
        ip_address      TEXT,
        device          TEXT,
        folder_accessed TEXT,
        event_type      TEXT,
        timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL,
        risk_score INTEGER,
        reason     TEXT,
        confirmed  INTEGER DEFAULT 0,
        timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized")