"""Regex-driven log parser. Normalizes raw lines from any source into Events."""
import json
import os
import re
import time
from .events import Event

# ---------------------------------------------------------------- helpers
SYSLOG_TS = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d\d:\d\d:\d\d)\s(?P<host>\S+)\s")
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

WEB_ATTACK_PATTERNS = [
    (re.compile(r"(?i)(union\s+select|select\s.+\sfrom|or\s+1=1|'--|%27|sleep\(\d)"), "sql_injection"),
    (re.compile(r"(?i)(<script|%3Cscript|javascript:|onerror\s*=)"), "xss"),
    (re.compile(r"(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|/etc/shadow)", re.I), "path_traversal"),
    (re.compile(r"(?i)(cmd=|;wget\s|;curl\s|\|bash|`.+`|\$\(.+\))"), "command_injection"),
    (re.compile(r"(?i)(/\.env|/\.git/|/wp-login\.php|/phpmyadmin|/admin/config)"), "sensitive_probe"),
]
SCANNER_UAS = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|zgrab|nuclei|wpscan)")


def _syslog_ts(m):
    try:
        now = time.localtime()
        t = time.strptime(f"{now.tm_year} {m.group('mon')} {m.group('day')} {m.group('time')}",
                          "%Y %b %d %H:%M:%S")
        return time.mktime(t)
    except ValueError:
        return time.time()


# ---------------------------------------------------------------- built-in patterns
RE_SSH_FAIL = re.compile(r"sshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
RE_SSH_INVALID = re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
RE_SSH_OK = re.compile(r"sshd\[\d+\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
RE_SSH_DISCONNECT = re.compile(r"sshd\[\d+\]: (?:Received disconnect|Disconnected) from (?:authenticating user \S+ )?(?P<ip>[\d.]+)")
RE_SUDO_FAIL = re.compile(r"sudo(?:\[\d+\])?: .*authentication failure.*user=(?P<user>\S+)|sudo(?:\[\d+\])?:\s+(?P<user2>\S+) : (?:\d+ incorrect password attempts|command not allowed)")
RE_SUDO_CMD = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : TTY=.* ; PWD=.* ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)")
RE_FIREWALL = re.compile(r"(?:UFW BLOCK|iptables.*DROP).*SRC=(?P<ip>[\d.]+) DST=(?P<dst>[\d.]+)(?:.*\bDPT=(?P<port>\d+))?")
RE_HTTP = re.compile(r'^(?P<ip>[\d.]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
RE_WIN_CSV = re.compile(r"^(?P<ts>[\d/:\- ]+),(?P<eid>\d{4}),(?P<host>[^,]*),(?P<user>[^,]*),(?P<ip>[\d.]*),(?P<msg>.*)$")
RE_KERNEL_ERR = re.compile(r"(?i)(segfault|oom-killer|out of memory|kernel panic)")
RE_SYSLOG_PROC = re.compile(
    r"^\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d\s\S+\s(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?"
    r"(?:\s\([^)]*\))?:\s*(?P<msg>.+)$")

WIN_EVENT_MAP = {
    "4625": ("auth_failure", "medium", "Windows logon failure"),
    "4624": ("auth_success", "info", "Windows logon success"),
    "4672": ("priv_assigned", "medium", "Special privileges assigned"),
    "4720": ("account_created", "medium", "User account created"),
    "4740": ("account_lockout", "high", "Account locked out"),
    "1102": ("log_cleared", "critical", "Audit log was cleared"),
    "7045": ("service_installed", "high", "New service installed"),
}


class Parser:
    """Turns raw log lines into normalized Events. Also applies user signature rules."""

    def __init__(self, signature_path=None):
        self.signatures = []
        if signature_path and os.path.exists(signature_path):
            with open(signature_path) as f:
                for sig in json.load(f):
                    try:
                        self.signatures.append({
                            "name": sig["name"],
                            "regex": re.compile(sig["regex"]),
                            "event_type": sig.get("event_type", "signature_match"),
                            "severity": sig.get("severity", "medium"),
                        })
                    except re.error:
                        pass

    def parse(self, line, source):
        line = line.rstrip("\n")
        if not line.strip():
            return None
        ts, host = time.time(), ""
        m = SYSLOG_TS.match(line)
        if m:
            ts, host = _syslog_ts(m), m.group("host")

        ev = self._classify(line, source, ts, host)
        self._apply_signatures(ev)
        return ev

    # ------------------------------------------------------------ classify
    def _classify(self, line, source, ts, host):
        def E(**kw):
            return Event(ts=ts, source=source, host=host, raw=line, **kw)

        m = RE_SSH_FAIL.search(line) or RE_SSH_INVALID.search(line)
        if m:
            return E(event_type="auth_failure", severity="medium", ip=m.group("ip"),
                     user=m.group("user"), message=f"SSH auth failure for '{m.group('user')}' from {m.group('ip')}")
        m = RE_SSH_OK.search(line)
        if m:
            return E(event_type="auth_success", severity="info", ip=m.group("ip"),
                     user=m.group("user"), message=f"SSH login: {m.group('user')} from {m.group('ip')}")
        m = RE_SSH_DISCONNECT.search(line)
        if m:
            return E(event_type="ssh_disconnect", severity="info", ip=m.group("ip"),
                     message=f"SSH disconnect from {m.group('ip')}")
        m = RE_SUDO_CMD.search(line)
        if m:
            return E(event_type="priv_command", severity="low", user=m.group("user"),
                     message=f"sudo: {m.group('user')} ran '{m.group('cmd')}' as {m.group('target')}",
                     meta={"cmd": m.group("cmd")})
        m = RE_SUDO_FAIL.search(line)
        if m:
            user = m.group("user") or m.group("user2") or ""
            return E(event_type="priv_failure", severity="medium", user=user,
                     message=f"sudo authentication failure for '{user}'")
        m = RE_FIREWALL.search(line)
        if m:
            port = m.group("port") or "?"
            return E(event_type="firewall_block", severity="low", ip=m.group("ip"),
                     message=f"Firewall blocked {m.group('ip')} -> port {port}",
                     meta={"port": port, "dst": m.group("dst")})
        m = RE_HTTP.match(line)
        if m:
            return self._http_event(m, E)
        m = RE_WIN_CSV.match(line)
        if m and m.group("eid") in WIN_EVENT_MAP:
            etype, sev, label = WIN_EVENT_MAP[m.group("eid")]
            return Event(ts=ts, source=source, host=m.group("host"), ip=m.group("ip"),
                         user=m.group("user"), event_type=etype, severity=sev,
                         message=f"{label} (EventID {m.group('eid')}) user={m.group('user')}",
                         raw=line, meta={"event_id": m.group("eid")})
        if RE_KERNEL_ERR.search(line):
            return E(event_type="system_error", severity="high", message=line[:200])
        # generic syslog: strip the "Mon d HH:MM:SS host" prefix, surface the process
        m = RE_SYSLOG_PROC.match(line)
        if m:
            proc = m.group("proc").rsplit("/", 1)[-1].lower()[:20]
            return E(event_type=proc, severity="info",
                     message=m.group("msg")[:200], meta={"proc": proc})
        return E(event_type="generic", severity="info", message=line[:200])

    def _http_event(self, m, E):
        path, ua, status = m.group("path"), m.group("ua") or "", int(m.group("status"))
        target = path + " " + ua
        for rx, attack in WEB_ATTACK_PATTERNS:
            if rx.search(target):
                return E(event_type="web_attack", severity="high", ip=m.group("ip"),
                         message=f"Web attack ({attack}): {m.group('method')} {path[:120]} [{status}]",
                         meta={"attack": attack, "status": status, "path": path, "ua": ua})
        if SCANNER_UAS.search(ua):
            return E(event_type="web_scanner", severity="high", ip=m.group("ip"),
                     message=f"Scanner UA detected: {ua[:80]}", meta={"status": status, "ua": ua})
        sev = "info" if status < 400 else ("low" if status < 500 else "medium")
        etype = "http_request" if status < 400 else "http_error"
        return E(event_type=etype, severity=sev, ip=m.group("ip"),
                 message=f"{m.group('method')} {path[:120]} -> {status}",
                 meta={"status": status, "path": path, "ua": ua})

    def _apply_signatures(self, ev):
        for sig in self.signatures:
            if sig["regex"].search(ev.raw):
                ev.event_type = sig["event_type"]
                ev.severity = sig["severity"]
                ev.message = f"[{sig['name']}] {ev.message}"
                ev.meta["signature"] = sig["name"]
                return
