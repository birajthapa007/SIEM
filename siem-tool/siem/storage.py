"""SQLite backend: events, alerts, blocklist, stats, retention."""
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source TEXT, host TEXT, ip TEXT,
  user TEXT, event_type TEXT, severity TEXT, message TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_ev_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_ev_type ON events(event_type);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, rule TEXT, severity TEXT, title TEXT,
  detail TEXT, ip TEXT, user TEXT, count INTEGER, acked INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_al_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS blocklist(
  ip TEXT PRIMARY KEY, ts REAL, reason TEXT);
"""

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Storage:
    def __init__(self, path="siem.db", retention_days=7):
        self.path = path
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        except sqlite3.OperationalError:
            # some filesystems (network mounts) don't support WAL
            self._conn.executescript("PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL;")
        self._conn.executescript(SCHEMA)
        for col in ("mitre", "geo"):     # migrate older databases
            try:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
        self._conn.commit()
        t = threading.Thread(target=self._retention_loop, daemon=True)
        t.start()

    def _exec(self, sql, params=(), fetch=False):
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()] if fetch else None
            self._conn.commit()
            return rows, cur.lastrowid

    # ---------------------------------------------------------- writes
    def insert_event(self, ev):
        _, rid = self._exec(
            "INSERT INTO events(ts,source,host,ip,user,event_type,severity,message,raw) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (ev.ts, ev.source, ev.host, ev.ip, ev.user, ev.event_type, ev.severity,
             ev.message, ev.raw))
        return rid

    def insert_alert(self, al):
        _, rid = self._exec(
            "INSERT INTO alerts(ts,rule,severity,title,detail,ip,user,count,mitre,geo) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (al.ts, al.rule, al.severity, al.title, al.detail, al.ip, al.user, al.count,
             al.mitre, al.geo))
        al.id = rid
        return rid

    def ack_alert(self, alert_id):
        self._exec("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))

    def block_ip(self, ip, reason):
        self._exec("INSERT OR REPLACE INTO blocklist(ip,ts,reason) VALUES(?,?,?)",
                   (ip, time.time(), reason))

    def unblock_ip(self, ip):
        self._exec("DELETE FROM blocklist WHERE ip=?", (ip,))

    # ---------------------------------------------------------- reads
    def query_events(self, q=None, event_type=None, severity=None, ip=None,
                     since=None, limit=200):
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if q:
            sql += " AND (message LIKE ? OR raw LIKE ? OR user LIKE ?)"
            params += [f"%{q}%"] * 3
        if event_type:
            sql += " AND event_type=?"; params.append(event_type)
        if severity:
            sql += " AND severity=?"; params.append(severity)
        if ip:
            sql += " AND ip=?"; params.append(ip)
        if since:
            sql += " AND ts>=?"; params.append(float(since))
        sql += " ORDER BY ts DESC LIMIT ?"; params.append(min(int(limit), 1000))
        rows, _ = self._exec(sql, params, fetch=True)
        return rows

    def query_alerts(self, limit=100, unacked_only=False):
        sql = "SELECT * FROM alerts"
        if unacked_only:
            sql += " WHERE acked=0"
        sql += " ORDER BY ts DESC LIMIT ?"
        rows, _ = self._exec(sql, (min(int(limit), 500),), fetch=True)
        return rows

    def get_blocklist(self):
        rows, _ = self._exec("SELECT * FROM blocklist ORDER BY ts DESC", fetch=True)
        return rows

    def stats(self):
        now = time.time()
        hour_ago = now - 3600
        out = {}
        r, _ = self._exec("SELECT COUNT(*) c FROM events", fetch=True)
        out["total_events"] = r[0]["c"]
        r, _ = self._exec("SELECT COUNT(*) c FROM events WHERE ts>=?", (hour_ago,), fetch=True)
        out["events_last_hour"] = r[0]["c"]
        r, _ = self._exec("SELECT COUNT(*) c FROM alerts WHERE acked=0", (), fetch=True)
        out["open_alerts"] = r[0]["c"]
        r, _ = self._exec("SELECT COUNT(*) c FROM blocklist", (), fetch=True)
        out["blocked_ips"] = r[0]["c"]
        r, _ = self._exec(
            "SELECT severity, COUNT(*) c FROM alerts WHERE ts>=? GROUP BY severity",
            (hour_ago,), fetch=True)
        out["alerts_by_severity"] = {x["severity"]: x["c"] for x in r}
        r, _ = self._exec(
            "SELECT event_type, COUNT(*) c FROM events WHERE ts>=? GROUP BY event_type "
            "ORDER BY c DESC LIMIT 8", (hour_ago,), fetch=True)
        out["events_by_type"] = {x["event_type"]: x["c"] for x in r}
        r, _ = self._exec(
            "SELECT ip, COUNT(*) c FROM events WHERE ts>=? AND ip!='' GROUP BY ip "
            "ORDER BY c DESC LIMIT 8", (hour_ago,), fetch=True)
        out["top_ips"] = [{"ip": x["ip"], "count": x["c"]} for x in r]
        r, _ = self._exec(
            "SELECT CAST((ts-?)/60 AS INT) m, COUNT(*) c FROM events WHERE ts>=? GROUP BY m",
            (now - 1800, now - 1800), fetch=True)
        buckets = {x["m"]: x["c"] for x in r}
        out["events_per_min"] = [buckets.get(i, 0) for i in range(30)]
        out["risk_ips"] = self.risk_ips()
        return out

    def risk_ips(self, hours=24, limit=8):
        """Per-IP risk score: weighted sum of alert severities in the last N hours."""
        rows, _ = self._exec(
            "SELECT ip, COUNT(*) alerts, "
            "SUM(CASE severity WHEN 'critical' THEN 10 WHEN 'high' THEN 6 "
            "WHEN 'medium' THEN 3 ELSE 1 END) score, "
            "MAX(geo) geo, GROUP_CONCAT(DISTINCT rule) rules "
            "FROM alerts WHERE ts>=? AND ip!='' GROUP BY ip "
            "ORDER BY score DESC LIMIT ?",
            (time.time() - hours * 3600, limit), fetch=True)
        return rows

    # ---------------------------------------------------------- retention
    def _retention_loop(self):
        while True:
            cutoff = time.time() - self.retention_days * 86400
            try:
                self._exec("DELETE FROM events WHERE ts<?", (cutoff,))
                self._exec("DELETE FROM alerts WHERE ts<?", (cutoff,))
            except Exception:
                pass
            time.sleep(3600)
