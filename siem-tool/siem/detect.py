"""Detection engine: correlation rules, threat intel, statistical anomaly detection.
Every alert is tagged with its MITRE ATT&CK technique."""
import math
import time
from collections import defaultdict, deque
from .events import Alert

MITRE = {
    "bruteforce": "T1110.001", "password_spraying": "T1110.003",
    "distributed_bruteforce": "T1110.004", "credential_compromise": "T1078",
    "portscan": "T1046", "priv_escalation": "T1548.003",
    "web_sql_injection": "T1190", "web_xss": "T1190", "web_path_traversal": "T1190",
    "web_command_injection": "T1190", "web_sensitive_probe": "T1595.003",
    "web_scanner": "T1595.002", "http_recon": "T1595.003",
    "log_cleared": "T1070.001", "service_installed": "T1543.003",
    "account_lockout": "T1110", "account_created": "T1136.001",
    "system_error": "T1499", "rate_anomaly": "T1498",
    "threat_intel": "T1071", "off_hours_login": "T1078",
    "malware_indicator": "T1105", "persistence": "T1098.004",
}


class SlidingWindow:
    """Timestamps (+ optional payload) per key inside a time window."""

    def __init__(self, window_sec):
        self.window = window_sec
        self.data = defaultdict(deque)

    def add(self, key, ts, payload=None):
        dq = self.data[key]
        dq.append((ts, payload))
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return dq

    def count(self, key):
        return len(self.data.get(key, ()))

    def payloads(self, key):
        return {p for _, p in self.data.get(key, ()) if p}


class DetectionEngine:
    def __init__(self, cfg=None, intel=None, geoip=None):
        c = cfg or {}
        self.intel = intel
        self.geoip = geoip
        self.brute_n = c.get("bruteforce_attempts", 5)
        self.brute_win = SlidingWindow(c.get("bruteforce_window", 60))
        self.recent_fails = SlidingWindow(300)            # success-after-failure
        self.spray_win = SlidingWindow(c.get("spray_window", 120))     # ip -> users
        self.spray_n = c.get("spray_users", 6)
        self.dist_win = SlidingWindow(c.get("dist_window", 120))       # user -> ips
        self.dist_n = c.get("dist_ips", 5)
        self.scan_win = SlidingWindow(c.get("portscan_window", 30))
        self.scan_ports = c.get("portscan_ports", 10)
        self.sudo_win = SlidingWindow(120)
        self.sudo_n = c.get("sudo_failures", 3)
        self.http_err_win = SlidingWindow(60)
        self.http_err_n = c.get("http_error_burst", 20)
        self.work_hours = c.get("work_hours")             # e.g. [7, 20] or null
        self.admin_users = set(c.get("admin_users", ["root", "admin", "administrator"]))
        self.cooldown_sec = c.get("alert_cooldown", 120)
        self._cooldowns = {}
        # anomaly detection: EWMA of per-source event rate (10s buckets)
        self._buckets = defaultdict(int)
        self._bucket_id = None
        self._ewma = {}
        self._ewvar = {}
        self.anomaly_z = c.get("anomaly_zscore", 3.5)
        self.anomaly_min = c.get("anomaly_min_events", 15)

    # ------------------------------------------------------------ main
    def process(self, ev):
        alerts = []
        t, et = ev.ts, ev.event_type

        # threat intel — any event from a known-bad IP
        if self.intel and ev.ip:
            reason = self.intel.check(ev.ip)
            if reason:
                alerts.append(self._alert(
                    "threat_intel", "critical", f"Threat-intel hit: {ev.ip}",
                    f"Traffic from known-malicious IP ({reason}). "
                    f"Triggering event: {ev.message}", ev))

        if et == "auth_failure" and ev.ip:
            dq = self.brute_win.add(ev.ip, t)
            self.recent_fails.add(ev.ip, t)
            if len(dq) >= self.brute_n:
                users = f"user '{ev.user}'" if ev.user else "multiple users"
                alerts.append(self._alert(
                    "bruteforce", "high", f"Brute-force attack from {ev.ip}",
                    f"{len(dq)} failed logins in {self.brute_win.window}s targeting {users}.",
                    ev, count=len(dq)))
            if ev.user:
                sprayed = self.spray_win.add(ev.ip, t, ev.user)
                users = {u for _, u in sprayed if u}
                if len(users) >= self.spray_n:
                    alerts.append(self._alert(
                        "password_spraying", "high", f"Password spraying from {ev.ip}",
                        f"{len(users)} distinct accounts probed in {self.spray_win.window}s "
                        f"({', '.join(sorted(users)[:6])}…).", ev, count=len(users)))
                self.dist_win.add(ev.user, t, ev.ip)
                ips = self.dist_win.payloads(ev.user)
                if len(ips) >= self.dist_n:
                    alerts.append(self._alert(
                        "distributed_bruteforce", "high",
                        f"Distributed brute-force on account '{ev.user}'",
                        f"Failures from {len(ips)} different IPs in "
                        f"{self.dist_win.window}s — likely a botnet.", ev, count=len(ips)))

        elif et == "auth_success" and ev.ip:
            n_fails = self.recent_fails.count(ev.ip)
            if n_fails >= 3:
                alerts.append(self._alert(
                    "credential_compromise", "critical",
                    f"Successful login after {n_fails} failures — {ev.ip}",
                    f"User '{ev.user}' logged in from {ev.ip} right after {n_fails} failed "
                    f"attempts. Possible compromised credentials.", ev, count=n_fails))
            if self.work_hours and ev.user in self.admin_users:
                hour = time.localtime(t).tm_hour
                lo, hi = self.work_hours
                if not (lo <= hour < hi):
                    alerts.append(self._alert(
                        "off_hours_login", "medium",
                        f"Off-hours admin login: '{ev.user}' at {hour:02d}h",
                        f"Privileged account '{ev.user}' logged in from {ev.ip} outside "
                        f"work hours ({lo:02d}–{hi:02d}h).", ev))

        elif et == "firewall_block" and ev.ip:
            dq = self.scan_win.add(ev.ip, t, ev.meta.get("port"))
            ports = {p for _, p in dq if p}
            if len(ports) >= self.scan_ports:
                alerts.append(self._alert(
                    "portscan", "high", f"Port scan from {ev.ip}",
                    f"{len(ports)} distinct ports probed in {self.scan_win.window}s "
                    f"(e.g. {', '.join(sorted(ports)[:8])}).", ev, count=len(ports)))

        elif et == "priv_failure":
            key = ev.user or ev.host or "unknown"
            dq = self.sudo_win.add(key, t)
            if len(dq) >= self.sudo_n:
                alerts.append(self._alert(
                    "priv_escalation", "high", f"Repeated sudo failures: '{key}'",
                    f"{len(dq)} sudo authentication failures in 120s — possible privilege "
                    f"escalation attempt.", ev, count=len(dq)))

        elif et in ("web_attack", "web_scanner"):
            attack = ev.meta.get("attack", "scanner")
            rule = f"web_{attack}" if et == "web_attack" else "web_scanner"
            alerts.append(self._alert(
                rule, "high" if et == "web_attack" else "medium",
                f"Web attack ({attack}) from {ev.ip}", ev.message, ev))

        elif et == "http_error" and ev.ip:
            dq = self.http_err_win.add(ev.ip, t)
            if len(dq) >= self.http_err_n:
                alerts.append(self._alert(
                    "http_recon", "medium", f"HTTP error burst from {ev.ip}",
                    f"{len(dq)} 4xx/5xx responses in 60s — likely forced browsing / "
                    f"directory scanning.", ev, count=len(dq)))

        elif et in ("log_cleared", "service_installed", "account_lockout",
                    "account_created", "system_error"):
            alerts.append(self._alert(
                et, "critical" if et == "log_cleared" else "high",
                ev.message[:100], ev.message, ev))

        if ev.severity in ("high", "critical") and ev.meta.get("signature"):
            alerts.append(self._alert(
                "signature:" + ev.meta["signature"], ev.severity,
                f"Signature match: {ev.meta['signature']}", ev.message, ev,
                mitre=MITRE.get(ev.event_type, "")))

        alerts.extend(self._anomaly_check(ev))
        return [a for a in alerts if a is not None]

    # ------------------------------------------------------------ anomaly
    def _anomaly_check(self, ev):
        bucket = int(ev.ts // 10)
        out = []
        if self._bucket_id is None:
            self._bucket_id = bucket
        if bucket != self._bucket_id:
            for src, n in self._buckets.items():
                mean = self._ewma.get(src, float(n))
                var = self._ewvar.get(src, 1.0)
                std = math.sqrt(max(var, 1.0))
                z = (n - mean) / std
                if n >= self.anomaly_min and z >= self.anomaly_z:
                    out.append(self._alert(
                        "rate_anomaly", "medium",
                        f"Traffic anomaly on source '{src}'",
                        f"{n} events in 10s vs baseline {mean:.1f} (z={z:.1f}). "
                        f"Sudden spike may indicate an attack or misconfiguration.",
                        ev, count=n))
                a = 0.15
                self._ewma[src] = (1 - a) * mean + a * n
                self._ewvar[src] = (1 - a) * var + a * (n - mean) ** 2
            self._buckets.clear()
            self._bucket_id = bucket
        self._buckets[ev.source] += 1
        return out

    # ------------------------------------------------------------ dedupe + build
    def _alert(self, rule, severity, title, detail, ev, count=1, mitre=None):
        key = (rule, ev.ip or ev.user or ev.source)
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self.cooldown_sec:
            return None
        self._cooldowns[key] = now
        geo = ""
        if self.geoip and ev.ip:
            g = self.geoip.lookup(ev.ip)
            if g:
                geo = g["country"]
        return Alert(ts=ev.ts, rule=rule, severity=severity, title=title,
                     detail=detail, ip=ev.ip, user=ev.user, count=count,
                     mitre=mitre if mitre is not None else MITRE.get(rule, ""),
                     geo=geo)
