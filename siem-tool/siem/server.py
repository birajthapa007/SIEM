"""Web dashboard + REST API + SSE live stream. Pure stdlib."""
import json
import logging
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("siem.server")
DASHBOARD = os.path.join(os.path.dirname(__file__), "dashboard.html")


def make_handler(storage, bus, geoip=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence default access log
            pass

        # ------------------------------------------------------ helpers
        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _qs(self):
            return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

        # ------------------------------------------------------ GET
        def do_GET(self):
            path = urlparse(self.path).path
            try:
                if path == "/":
                    with open(DASHBOARD, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/api/stats":
                    self._json(storage.stats())
                elif path == "/api/events":
                    q = self._qs()
                    self._json(storage.query_events(
                        q=q.get("q"), event_type=q.get("type"),
                        severity=q.get("severity"), ip=q.get("ip"),
                        since=q.get("since"), limit=q.get("limit", 200)))
                elif path == "/api/alerts":
                    q = self._qs()
                    self._json(storage.query_alerts(
                        limit=q.get("limit", 100),
                        unacked_only=q.get("open") == "1"))
                elif path == "/api/blocklist":
                    self._json(storage.get_blocklist())
                elif path == "/api/risk":
                    self._json(storage.risk_ips())
                elif path == "/api/geo":
                    ips = self._qs().get("ips", "").split(",")
                    self._json(geoip.bulk(ips) if geoip else {})
                elif path == "/stream":
                    self._sse()
                else:
                    self._json({"error": "not found"}, 404)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                log.error("GET %s: %s", path, e)
                try:
                    self._json({"error": str(e)}, 500)
                except Exception:
                    pass

        # ------------------------------------------------------ POST
        def do_POST(self):
            path = urlparse(self.path).path
            try:
                n = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(n) or b"{}")
                if path == "/api/alerts/ack":
                    storage.ack_alert(int(data["id"]))
                    self._json({"ok": True})
                elif path == "/api/blocklist/remove":
                    storage.unblock_ip(data["ip"])
                    self._json({"ok": True})
                else:
                    self._json({"error": "not found"}, 404)
            except Exception as e:
                self._json({"error": str(e)}, 400)

        # ------------------------------------------------------ SSE
        def _sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = bus.subscribe()
            try:
                while True:
                    try:
                        payload = q.get(timeout=15)
                        self.wfile.write(f"data: {payload}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                bus.unsubscribe(q)

    return Handler


class DashboardServer:
    def __init__(self, storage, bus, host="127.0.0.1", port=8787, geoip=None):
        self.httpd = ThreadingHTTPServer((host, port), make_handler(storage, bus, geoip))
        self.httpd.daemon_threads = True
        self.host, self.port = host, port

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        log.info("dashboard: http://%s:%d", self.host, self.port)
