"""Enrichment: GeoIP lookups (cached, non-blocking) and threat-intelligence feed."""
import ipaddress
import json
import logging
import os
import queue
import threading
import urllib.request

log = logging.getLogger("siem.enrich")


class GeoIP:
    """Best-effort, cached, background GeoIP via ip-api.com (free, no key).
    Never blocks the pipeline: unknown IPs are queued and resolved async.
    Private / documentation ranges are labelled locally, fully offline."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.cache = {}
        self._q = queue.Queue(maxsize=500)
        self._pending = set()
        self._lock = threading.Lock()
        if enabled:
            threading.Thread(target=self._worker, daemon=True).start()

    def lookup(self, ip):
        """Returns {'country','cc'} if known, else None (and schedules a fetch)."""
        if not ip:
            return None
        hit = self.cache.get(ip)
        if hit is not None:
            return hit
        local = self._local_label(ip)
        if local:
            self.cache[ip] = local
            return local
        if self.enabled:
            with self._lock:
                if ip not in self._pending:
                    self._pending.add(ip)
                    try:
                        self._q.put_nowait(ip)
                    except queue.Full:
                        self._pending.discard(ip)
        return None

    @staticmethod
    def _local_label(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return {"country": "?", "cc": "?"}
        for net, name in (("192.0.2.0/24", "TEST-NET-1"), ("198.51.100.0/24", "TEST-NET-2"),
                          ("203.0.113.0/24", "TEST-NET-3")):
            if a in ipaddress.ip_network(net):
                return {"country": f"{name} (demo)", "cc": "DOC"}
        if a.is_private or a.is_loopback or a.is_link_local:
            return {"country": "Internal", "cc": "LAN"}
        return None

    def _worker(self):
        while True:
            ip = self._q.get()
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
                with urllib.request.urlopen(url, timeout=6) as r:
                    d = json.loads(r.read())
                if d.get("status") == "success":
                    self.cache[ip] = {"country": d.get("country", "?"),
                                      "cc": d.get("countryCode", "?")}
                else:
                    self.cache[ip] = {"country": "Unknown", "cc": "?"}
            except Exception:
                pass   # offline — retry never; stays unknown
            finally:
                with self._lock:
                    self._pending.discard(ip)

    def bulk(self, ips):
        return {ip: self.lookup(ip) for ip in ips if ip}


class ThreatIntel:
    """Local threat-intel feed: rules/threat_intel.json → {"ips": {ip: reason}}.
    Reloads automatically when the file changes."""

    def __init__(self, path):
        self.path = path
        self.ips = {}
        self._mtime = 0
        self._load()

    def _load(self):
        try:
            st = os.stat(self.path)
            if st.st_mtime == self._mtime:
                return
            self._mtime = st.st_mtime
            with open(self.path) as f:
                self.ips = json.load(f).get("ips", {})
            log.info("threat intel: %d indicators loaded", len(self.ips))
        except FileNotFoundError:
            self.ips = {}
        except Exception as e:
            log.error("threat intel load failed: %s", e)

    def check(self, ip):
        self._load()          # cheap stat() — hot-reload on edit
        return self.ips.get(ip)
