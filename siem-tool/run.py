#!/usr/bin/env python3
"""SIEM — Real-Time Security Log Analysis
Usage:
    python3 run.py --demo                 # built-in attack simulator (great for demos)
    python3 run.py -f /var/log/auth.log -f /var/log/nginx/access.log
    python3 run.py --config config.json   # full config: syslog, webhooks, email...
Dashboard: http://127.0.0.1:8787
"""
import argparse
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from siem.events import EventBus
from siem.parser import Parser
from siem.storage import Storage
from siem.detect import DetectionEngine
from siem.alerts import AlertManager, c
from siem.enrich import GeoIP, ThreatIntel
from siem.ingest import FileTailer, SyslogServer, DemoGenerator
from siem.server import DashboardServer

BANNER = r"""
   _____ _____ ______ __  __
  / ____|_   _|  ____|  \/  |   Real-Time Security Log Analysis
  \___ \  | | |  __| | |\/| |   signatures · correlation · anomaly · threat intel
  ____) |_| |_| |____| |  | |   MITRE ATT&CK tagging · GeoIP · active response
 |_____/|_____|______|_|  |_|   v2.1
"""


class ColorFormatter(logging.Formatter):
    COLORS = {"WARNING": "\033[33m", "ERROR": "\033[31m", "CRITICAL": "\033[1;31m",
              "INFO": "\033[36m", "DEBUG": "\033[90m"}

    def format(self, record):
        color = self.COLORS.get(record.levelname, "") if sys.stdout.isatty() else ""
        reset = "\033[0m" if color else ""
        record.levelname = f"{color}{record.levelname:<7}{reset}"
        return super().format(record)


def main():
    ap = argparse.ArgumentParser(description="Real-time SIEM")
    ap.add_argument("--config", "-c", default=None, help="path to config.json")
    ap.add_argument("--file", "-f", action="append", default=[], help="log file to tail (repeatable)")
    ap.add_argument("--demo", action="store_true", help="run built-in attack simulator")
    ap.add_argument("--port", type=int, default=None, help="dashboard port (default 8787)")
    ap.add_argument("--from-start", action="store_true", help="read tailed files from beginning")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    cfg_path = args.config or os.path.join(base, "config.json")
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            cfg = json.load(f)

    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    print(c("cyan", BANNER))

    bus = EventBus()
    storage = Storage(cfg.get("database", "siem.db"),
                      retention_days=cfg.get("retention_days", 7))
    parser = Parser(signature_path=os.path.join(base, "rules", "signatures.json"))
    geoip = GeoIP(enabled=cfg.get("geoip", True))
    intel = ThreatIntel(os.path.join(base, "rules", "threat_intel.json"))
    engine = DetectionEngine(cfg.get("detection"), intel=intel, geoip=geoip)
    alerts = AlertManager(storage, bus, cfg.get("alerting"),
                          log_dir=os.path.join(base, "logs"))

    def pipeline(line, source):
        ev = parser.parse(line, source)
        if ev is None:
            return
        if ev.ip:
            geoip.lookup(ev.ip)          # warm the geo cache asynchronously
        storage.insert_event(ev)
        bus.publish(ev)
        for alert in engine.process(ev):
            alerts.handle(alert)

    # ------------------------------------------------------------ sources
    sources = []
    for path in args.file + cfg.get("sources", {}).get("files", []):
        FileTailer(path, pipeline, from_start=args.from_start).start()
        sources.append(f"tail {path}")
    sy = cfg.get("sources", {}).get("syslog", {})
    if sy.get("enabled"):
        SyslogServer(pipeline, sy.get("host", "0.0.0.0"), sy.get("port", 5514))
        sources.append(f"syslog udp+tcp :{sy.get('port', 5514)}")
    if args.demo or not sources:
        DemoGenerator(pipeline).start()
        sources.append("demo attack simulator")

    dash = cfg.get("dashboard", {})
    host = dash.get("host", "127.0.0.1")
    port = args.port or dash.get("port", 8787)
    DashboardServer(storage, bus, host, port, geoip=geoip).start()

    print(c("bold", "  Sources:"))
    for s in sources:
        print(f"    • {s}")
    print(c("bold", "\n  Dashboard: ") + c("cyan", f"http://{host}:{port}"))
    print(c("dim", "  Alerts also logged to logs/alerts.log · Ctrl+C to stop\n"))

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nbye.")


if __name__ == "__main__":
    main()
