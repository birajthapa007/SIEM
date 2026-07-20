"""Alert dispatch: pretty console, alerts.log, webhook (Slack/Discord), email,
and active response (auto-block + optional firewall command)."""
import json
import logging
import os
import smtplib
import subprocess
import sys
import threading
import time
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("siem.alerts")

AUTO_BLOCK_RULES = {"bruteforce", "portscan", "credential_compromise",
                    "password_spraying", "threat_intel"}

# ---------------------------------------------------------------- console style
USE_COLOR = sys.stdout.isatty() or os.environ.get("SIEM_COLOR") == "1"
C = {
    "critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
    "low": "\033[36m", "info": "\033[90m",
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m", "cyan": "\033[96m",
}
GLYPH = {"critical": "▲", "high": "●", "medium": "◆", "low": "○", "info": "·"}


def c(code, text):
    return f"{C[code]}{text}{C['reset']}" if USE_COLOR else text


def render_alert(a):
    """Pretty multi-line console rendering of an alert."""
    sev = a.severity
    hdr = f" {GLYPH.get(sev, '·')} {sev.upper()} "
    when = time.strftime("%H:%M:%S", time.localtime(a.ts))
    tags = " · ".join(x for x in (
        a.mitre and f"MITRE {a.mitre}", a.geo and f"geo: {a.geo}",
        a.ip and f"ip: {a.ip}", a.user and f"user: {a.user}") if x)
    lines = [
        c(sev, f"┌─{hdr}─ {when} " + "─" * max(1, 46 - len(hdr) - len(when))),
        c(sev, "│ ") + c("bold", a.title),
        c(sev, "│ ") + a.detail,
    ]
    if tags:
        lines.append(c(sev, "│ ") + c("dim", tags))
    lines.append(c(sev, "└" + "─" * 58))
    return "\n".join(lines)


class AlertManager:
    def __init__(self, storage, bus, cfg=None, log_dir="logs"):
        self.storage = storage
        self.bus = bus
        c_ = cfg or {}
        self.webhook_url = c_.get("webhook_url") or ""
        self.email_cfg = c_.get("email") or {}
        self.auto_block = c_.get("auto_block", True)
        self.block_command = c_.get("block_command") or ""
        self.min_notify = c_.get("min_notify_severity", "high")
        self._sev = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        self.log_path = None
        try:
            os.makedirs(log_dir, exist_ok=True)
            self.log_path = os.path.join(log_dir, "alerts.log")
        except OSError:
            pass

    def handle(self, alert):
        self.storage.insert_alert(alert)
        self.bus.publish(alert)
        print(render_alert(alert), flush=True)
        self._file_log(alert)

        if self.auto_block and alert.rule in AUTO_BLOCK_RULES and alert.ip:
            self.storage.block_ip(alert.ip, alert.rule)
            self.bus.publish({"kind": "block", "ip": alert.ip, "reason": alert.rule})
            print(c("cyan", f"  ↳ active response: {alert.ip} added to blocklist"), flush=True)
            if self.block_command:
                threading.Thread(target=self._run_block_cmd, args=(alert.ip,),
                                 daemon=True).start()

        if self._sev.get(alert.severity, 0) >= self._sev.get(self.min_notify, 3):
            if self.webhook_url:
                threading.Thread(target=self._webhook, args=(alert,), daemon=True).start()
            if self.email_cfg.get("smtp_host"):
                threading.Thread(target=self._email, args=(alert,), daemon=True).start()

    # ------------------------------------------------------------ channels
    def _file_log(self, a):
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps({
                    "ts": round(a.ts, 3), "iso": time.strftime(
                        "%Y-%m-%dT%H:%M:%S", time.localtime(a.ts)),
                    "severity": a.severity, "rule": a.rule, "mitre": a.mitre,
                    "title": a.title, "detail": a.detail, "ip": a.ip,
                    "user": a.user, "geo": a.geo, "count": a.count}) + "\n")
        except OSError:
            pass

    def _webhook(self, alert):
        try:
            tag = f" [{alert.mitre}]" if alert.mitre else ""
            text = (f"🚨 *{alert.severity.upper()}*{tag} — {alert.title}\n"
                    f"{alert.detail}")
            body = {"text": text, "content": text}
            req = urllib.request.Request(
                self.webhook_url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            log.error("webhook failed: %s", e)

    def _email(self, alert):
        cfg = self.email_cfg
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[SIEM {alert.severity.upper()}] {alert.title}"
            msg["From"] = cfg.get("from_addr", "siem@localhost")
            msg["To"] = cfg.get("to_addr", "")
            msg.set_content(
                f"{alert.title}\n\n{alert.detail}\n\nIP: {alert.ip} ({alert.geo})\n"
                f"User: {alert.user}\nRule: {alert.rule}\nMITRE: {alert.mitre}")
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587), timeout=15) as s:
                if cfg.get("use_tls", True):
                    s.starttls()
                if cfg.get("username"):
                    s.login(cfg["username"], cfg["password"])
                s.send_message(msg)
        except Exception as e:
            log.error("email failed: %s", e)

    def _run_block_cmd(self, ip):
        try:
            cmd = self.block_command.format(ip=ip)
            subprocess.run(cmd, shell=True, timeout=15, capture_output=True)
            log.info("active response executed for %s", ip)
        except Exception as e:
            log.error("block command failed: %s", e)
