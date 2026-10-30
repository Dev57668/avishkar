import sqlite3


def by_name(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name = ?", (name,))
    return cur.fetchall()


def insert(conn, rows):
    conn.executemany("INSERT INTO t(a, b) VALUES (?, ?)", rows)


def table_exists(conn):
    return conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
