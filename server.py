#!/usr/bin/env python3
"""
webkit-host — Local LAN Payload Server
by zoofier

Serves ./public/ over HTTP on your local network.
Point your PS4 browser at http://<YOUR_LAN_IP>:8080/

Usage:
    python server.py [--port 8080] [--host 0.0.0.0]
"""

import argparse
import http.server
import os
import socket
import socketserver
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"
SERVE_DIR    = os.path.join(os.path.dirname(__file__), "public")


# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    """Serves ./public/ and logs every hit with timestamp + client IP."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def log_message(self, format, *args):  # noqa: A002
        ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client = self.client_address[0]
        msg    = format % args
        print(f"[{ts}] [{client}] {msg}")

    def end_headers(self):
        # Allow cross-origin requests so inline scripts don't get blocked
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def get_lan_ip() -> str:
    """Best-effort local LAN IP detection — no external calls."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def banner(host: str, port: int) -> None:
    lan_ip = get_lan_ip()
    print("=" * 52)
    print("  webkit-host  |  zoofier  |  LAN payload server")
    print("=" * 52)
    print(f"  Serving : ./public/")
    print(f"  Local   : http://127.0.0.1:{port}/")
    print(f"  LAN     : http://{lan_ip}:{port}/")
    print(f"  PS4 URL : http://{lan_ip}:{port}/index.html")
    print("=" * 52)
    print("  CTRL+C to stop\n")


# ─────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="webkit-host local server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", type=str, default=DEFAULT_HOST)
    args = parser.parse_args()

    if not os.path.isdir(SERVE_DIR):
        os.makedirs(SERVE_DIR)
        print(f"[*] Created missing ./public/ directory.")

    banner(args.host, args.port)

    with socketserver.TCPServer((args.host, args.port), LoggingHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Server stopped. See you next time, LO.")


if __name__ == "__main__":
    main()
