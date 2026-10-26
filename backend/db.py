import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    direction TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_cidr TEXT NOT NULL,
    dst_cidr TEXT NOT NULL,
    dst_port TEXT NOT NULL DEFAULT 'any',
    interface TEXT NOT NULL DEFAULT 'any',
    enabled INTEGER NOT NULL DEFAULT 1,
    hits INTEGER NOT NULL DEFAULT 0,
    comment TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    port TEXT NOT NULL,
    proto TEXT NOT NULL,
    matched_rule_id INTEGER,
    action TEXT NOT NULL,
    FOREIGN KEY (matched_rule_id) REFERENCES rules(id) ON DELETE SET NULL
);
"""


def connect(database_path):
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_path):
    connection = connect(database_path)
    try:
        connection.executescript(SCHEMA)
    finally:
        connection.close()
