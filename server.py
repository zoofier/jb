#!/usr/bin/env python3
"""
zoof13r // PS4 13.52 Local Payload Host Server
Serves the jailbreak page to your PS4's browser over your LAN.
Handles /t telemetry POSTs so the exploit engine can log to your terminal.
"""

import http.server
import socketserver
import socket
import sys
import os
import json
import urllib.parse
from datetime import datetime

# force UTF-8 so ANSI escape codes + emoji don't die on Windows cp1252
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── config ──────────────────────────────────────────────────────────────────
PORT     = 8080          # change if something else is eating this
BIND     = "0.0.0.0"    # all interfaces so PS4 can reach it on LAN
DIR      = os.path.dirname(os.path.abspath(__file__))

# ── ansi colors because we're not animals ────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

# ── tag → color mapping (mirrors jb.js class logic) ─────────────────────────
def colorize_tag(tag: str, detail: str) -> str:
    t = tag.upper()
    if any(x in t for x in ("FAIL","ERROR","THREW","REBOOT","MISS","LOST","POISON","TIMEOUT","MISMATCH","ABORTED")):
        return f"{R}{BOLD}[{tag}]{RST}{R} {detail}{RST}"
    if any(x in t for x in ("WARN","SKIP","REFUSED","COMMITTED","DIRTY")):
        return f"{Y}[{tag}]{RST}{Y} {detail}{RST}"
    if any(x in t for x in ("OK","PASS","ACHIEVED","RUNNING","ARMED","PRIMITIVE","BASES","STUBS","FW","PAIR","JAILBREAK","KPATCH","PAYLOAD")):
        return f"{G}[{tag}]{RST}{W} {detail}{RST}"
    return f"{C}[{tag}]{RST}{DIM} {detail}{RST}"


class PS4Handler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that:
    - Serves static files from ./13.52/
    - Accepts POST /t  (exploit telemetry log)
    - Injects PS4-friendly CORS + cache headers
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    # ── shared headers every response needs ──────────────────────────────────
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")

    def end_headers(self):
        self._cors_headers()
        super().end_headers()

    # ── OPTIONS preflight (PS4 WebKit sometimes sends these) ─────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        super().end_headers()

    # ── POST /t — exploit telemetry ──────────────────────────────────────────
    def do_POST(self):
        if self.path.startswith("/t"):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(body)

            tag    = params.get("tag",    ["???"])[0]
            detail = params.get("detail", [""])[0]
            ts     = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            print(f"{DIM}{ts}{RST}  {colorize_tag(tag, detail)}")

            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    # ── suppress the default request log spam, print our own ─────────────────
    def log_message(self, fmt, *args):
        # only log non-telemetry requests
        code = args[1] if len(args) > 1 else "???"
        path = args[0].split(" ")[1] if args else "?"
        if not path.startswith("/t"):
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"{DIM}{ts}{RST}  {B}GET{RST} {path}  {DIM}{code}{RST}")


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    os.chdir(DIR)

    ip = get_local_ip()

    print(f"""
{M}{'─'*54}{RST}
{BOLD}{W}  zoof13r // PS4 13.52 Payload Host{RST}
{M}{'─'*54}{RST}
  {G}●{RST} Server ready
  {C}LAN URL  :{RST}  http://{ip}:{PORT}/
  {C}JB Page  :{RST}  http://{ip}:{PORT}/jb.html
  {C}Log Mode :{RST}  http://{ip}:{PORT}/jb.html?log=1
{M}{'─'*54}{RST}
  Point your PS4 browser at the JB Page URL above.
  Exploit telemetry will stream to this terminal.
{M}{'─'*54}{RST}
""")

    try:
        with socketserver.TCPServer((BIND, PORT), PS4Handler) as httpd:
            httpd.allow_reuse_address = True
            httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Y}  Server stopped. Later. 👋{RST}\n")
    except OSError as e:
        print(f"{R}  Port {PORT} is busy — kill whatever's on it or change PORT in server.py{RST}")
        sys.exit(1)


if __name__ == "__main__":
    main()
