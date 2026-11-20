import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = os.getenv("DATABASE_PATH", "./data/monitor.db")


def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT NOT NULL,
          captured_at TEXT NOT NULL, received_at TEXT NOT NULL,
          process_count INTEGER NOT NULL, service_count INTEGER NOT NULL,
          payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_endpoint ON snapshots(endpoint, id DESC);
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT NOT NULL,
          created_at TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
          title TEXT NOT NULL, details TEXT NOT NULL, fingerprint TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
        CREATE TABLE IF NOT EXISTS service_baseline (
          endpoint TEXT NOT NULL, name TEXT NOT NULL, config_hash TEXT NOT NULL,
          first_seen TEXT NOT NULL, PRIMARY KEY(endpoint, name)
        );
        """)


def save_snapshot(payload: dict):
    now = datetime.now(timezone.utc).isoformat()
    endpoint = payload["endpoint"]
    alerts = payload.get("alerts", [])
    with connect() as db:
        prior_snapshot = db.execute("SELECT 1 FROM snapshots WHERE endpoint=? LIMIT 1", (endpoint,)).fetchone() is not None
        db.execute("INSERT INTO snapshots(endpoint,captured_at,received_at,process_count,service_count,payload) VALUES(?,?,?,?,?,?)",
                   (endpoint, payload.get("captured_at", now), now, len(payload.get("processes", [])), len(payload.get("services", [])), json.dumps(payload)))
        for alert in alerts:
            db.execute("INSERT INTO alerts(endpoint,created_at,severity,category,title,details,fingerprint) VALUES(?,?,?,?,?,?,?)",
                       (endpoint, now, alert.get("severity", "medium"), alert.get("category", "behavior"), alert.get("title", "Detection"), json.dumps(alert.get("details", {})), alert.get("fingerprint", "")))
        current_services = payload.get("services", [])
        for service in current_services:
            name, config_hash = service.get("name", ""), service.get("config_hash", "")
            if not name:
                continue
            previous = db.execute("SELECT config_hash FROM service_baseline WHERE endpoint=? AND name=?", (endpoint, name)).fetchone()
            if previous and previous[0] != config_hash:
                db.execute("INSERT INTO alerts(endpoint,created_at,severity,category,title,details,fingerprint) VALUES(?,?,?,?,?,?,?)",
                           (endpoint, now, "high", "service_change", f"Service configuration changed: {name}", json.dumps(service), f"service-change:{endpoint}:{name}:{config_hash}"))
                if prior_snapshot and service.get("start_mode", "").lower() in ("auto", "automatic"):
                    db.execute("INSERT INTO alerts(endpoint,created_at,severity,category,title,details,fingerprint) VALUES(?,?,?,?,?,?,?)",
                               (endpoint, now, "medium", "new_service", f"New automatic service observed: {name}", json.dumps(service), f"new-service:{endpoint}:{name}"))
            elif not previous:
                db.execute("INSERT INTO service_baseline(endpoint,name,config_hash,first_seen) VALUES(?,?,?,?)", (endpoint, name, config_hash, now))
    retention = int(os.getenv("ALERT_RETENTION_DAYS", "30"))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention)).isoformat()
    with connect() as db:
        db.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))


def recent_alerts(limit=100):
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]


def latest_snapshots():
    with connect() as db:
        rows = db.execute("SELECT s.* FROM snapshots s JOIN (SELECT endpoint,MAX(id) id FROM snapshots GROUP BY endpoint) x ON s.id=x.id ORDER BY s.endpoint").fetchall()
        return [dict(row) for row in rows]


def summary():
    with connect() as db:
        alerts = db.execute("SELECT COUNT(*) total, SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) high FROM alerts").fetchone()
        endpoints = db.execute("SELECT COUNT(DISTINCT endpoint) FROM snapshots").fetchone()[0]
        latest = db.execute("SELECT COUNT(*) processes FROM (SELECT endpoint,MAX(id) id FROM snapshots GROUP BY endpoint) x JOIN snapshots s ON s.id=x.id").fetchone()[0]
        return {"alert_count": alerts["total"] or 0, "high_alert_count": alerts["high"] or 0, "endpoint_count": endpoints, "process_count": latest}
