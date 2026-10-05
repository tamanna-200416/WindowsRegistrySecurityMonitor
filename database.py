import sqlite3
from datetime import datetime

DATABASE_FILE = "data/registry_monitor.db"


def create_database():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registry_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            root TEXT,
            registry_path TEXT,
            name TEXT,
            value TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_event(event_type, root, registry_path, name, value=""):

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    # Prevent duplicate events generated within a short time
    cursor.execute("""
        SELECT id
        FROM registry_events
        WHERE event_type = ?
        AND root = ?
        AND registry_path = ?
        AND name = ?
        AND value = ?
        AND timestamp >= datetime('now', '-5 seconds')
        LIMIT 1
    """, (
        event_type,
        root,
        registry_path,
        name,
        value
    ))

    existing_event = cursor.fetchone()

    if existing_event:
        connection.close()
        return

    cursor.execute("""
        INSERT INTO registry_events
        (event_type, root, registry_path, name, value, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        root,
        registry_path,
        name,
        value,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()

def get_events():

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT event_type, root, registry_path, name, value, timestamp
        FROM registry_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events