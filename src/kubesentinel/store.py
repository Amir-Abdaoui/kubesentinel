import json
import sqlite3
import threading
import time


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS windows(ts REAL, ns TEXT, pod TEXT, vec TEXT);
            CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, body TEXT);
            """)

    def add_window(self, ns, pod, vec):
        with self.lock:
            self.db.execute("INSERT INTO windows VALUES(?,?,?,?)", (time.time(), ns, pod, json.dumps(vec)))
            self.db.commit()

    def windows(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT vec FROM windows")]

    def count_windows(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM windows").fetchone()[0]

    def add_alert(self, alert):
        with self.lock:
            cur = self.db.execute("INSERT INTO alerts(ts, body) VALUES(?,?)", (alert["ts"], json.dumps(alert)))
            self.db.commit()
            alert["id"] = cur.lastrowid
        return alert

    def alerts(self, limit=200):
        with self.lock:
            rows = self.db.execute("SELECT id, body FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**json.loads(b), "id": i} for i, b in rows]
