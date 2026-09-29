#!/usr/bin/env python3
"""
ENI // payload_host.py
PS4 13.52 — C2 / Payload Delivery System
Queue-driven, XOR-obfuscated, retry-resilient.
Drop bins in payloads/, point at a PS4, let it rip.
"""

import os
import sys
import socket
import struct
import time
import threading
import queue
import json
import hashlib
import http.server
import urllib.parse
from datetime import datetime
from pathlib import Path

# ── config (overridden by config.json if present) ─────────────────────────────
CFG = {
    "ps4_ip":         "192.168.1.100",
    "bin_loader_port": 9090,
    "http_port":       8888,           # REST + status UI
    "payload_dir":     "../payloads",
    "xor_key":         0x42,           # single-byte XOR — lightweight obfuscation
    "send_timeout":    10.0,
    "retry_max":       3,
    "retry_backoff":   1.5,
}

# ── ANSI ─────────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"; M="\033[95m"


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log(tag: str, msg: str, color: str = DIM):
    print(f"{DIM}{ts()}{RST}  {color}{BOLD}[{tag}]{RST}{color} {msg}{RST}")


# ── XOR obfuscation layer ─────────────────────────────────────────────────────
# Not encryption. Not even close. But it stops dumb pattern matching.
# PS4-side stub should XOR the payload back before executing.
# Stub pseudocode: for(int i=0;i<size;i++) buf[i]^=0x42;

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ── payload queue item ────────────────────────────────────────────────────────

class PayloadJob:
    def __init__(self, path: str, target_ip: str, port: int, raw: bool = False):
        self.path      = path
        self.target_ip = target_ip
        self.port      = port
        self.raw       = raw           # if True, skip XOR
        self.name      = os.path.basename(path)
        self.queued_at = datetime.now()
        self.status    = "queued"
        self.attempts  = 0
        self.error     = ""


# ── delivery engine ───────────────────────────────────────────────────────────

class DeliveryEngine:
    def __init__(self, cfg: dict):
        self.cfg    = cfg
        self.q:     queue.Queue[PayloadJob] = queue.Queue()
        self.history: list[PayloadJob]      = []
        self._stop  = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="DeliveryWorker")

    def start(self):
        self._thread.start()
        log("ENGINE", "Delivery worker started", G)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)

    def enqueue(self, job: PayloadJob):
        self.q.put(job)
        log("QUEUE", f"Enqueued: {job.name} → {job.target_ip}:{job.port}", C)

    def enqueue_file(self, filepath: str, target_ip: str = None, port: int = None, raw: bool = False):
        ip   = target_ip or self.cfg["ps4_ip"]
        port = port or self.cfg["bin_loader_port"]
        job  = PayloadJob(filepath, ip, port, raw)
        self.enqueue(job)
        return job

    def _worker(self):
        while not self._stop.is_set():
            try:
                job = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            self._deliver(job)
            self.history.append(job)
            self.q.task_done()

    def _deliver(self, job: PayloadJob):
        job.status = "sending"
        backoff    = 1.0

        for attempt in range(1, self.cfg["retry_max"] + 1):
            job.attempts = attempt
            try:
                self._send_once(job)
                job.status = "delivered"
                log("SENT", f"{job.name} ({job.attempts} attempt(s))", G)
                return
            except Exception as e:
                job.error = str(e)
                if attempt < self.cfg["retry_max"]:
                    log("RETRY", f"{job.name} attempt {attempt} failed: {e} — backing off {backoff:.1f}s", Y)
                    self._stop.wait(backoff)
                    backoff *= self.cfg["retry_backoff"]
                else:
                    log("FAIL", f"{job.name} gave up after {attempt} attempts: {e}", R)
                    job.status = "failed"

    def _send_once(self, job: PayloadJob):
        with open(job.path, "rb") as f:
            data = f.read()

        if not job.raw:
            data = xor_bytes(data, self.cfg["xor_key"])

        size    = len(data)
        chksum  = hashlib.md5(data).hexdigest()
        xor_lbl = "off" if job.raw else f"0x{self.cfg['xor_key']:02X}"
        log("SEND", f"{job.name}  size={size}  md5={chksum[:8]}  xor={xor_lbl}", C)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.cfg["send_timeout"])
        try:
            sock.connect((job.target_ip, job.port))
            # bin loader protocol: send size(4LE) then raw bytes
            sock.sendall(struct.pack("<I", size))
            sock.sendall(data)
            # wait for 4-byte ACK (0x00000000 = success)
            ack = sock.recv(4)
            if len(ack) >= 4:
                code = struct.unpack("<I", ack[:4])[0]
                if code != 0:
                    raise RuntimeError(f"Loader NAK: 0x{code:08X}")
        finally:
            sock.close()


# ── REST / status HTTP handler ────────────────────────────────────────────────

class ControlHandler(http.server.BaseHTTPRequestHandler):
    engine: DeliveryEngine = None

    def do_GET(self):
        if self.path == "/" or self.path == "/status":
            self._send_status()
        elif self.path.startswith("/queue"):
            self._send_queue()
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/send":
            target = params.get("target", [self.engine.cfg["ps4_ip"]])[0]
            fname  = params.get("file",   [""])[0]
            raw    = params.get("raw",    ["0"])[0] == "1"

            payload_dir = Path(self.engine.cfg["payload_dir"]).resolve()
            fpath = payload_dir / fname

            if not fpath.exists():
                self._json({"error": f"File not found: {fname}"}, 404); return

            job = self.engine.enqueue_file(str(fpath), target_ip=target, raw=raw)
            self._json({"status": "queued", "file": fname, "target": target})
        else:
            self.send_error(404)

    def _send_status(self):
        payload_dir = Path(self.engine.cfg["payload_dir"]).resolve()
        files       = [f.name for f in payload_dir.glob("*.bin")] if payload_dir.exists() else []
        body        = {
            "ps4_ip":        self.engine.cfg["ps4_ip"],
            "loader_port":   self.engine.cfg["bin_loader_port"],
            "queue_depth":   self.engine.q.qsize(),
            "history_count": len(self.engine.history),
            "payloads":      files,
        }
        self._json(body)

    def _send_queue(self):
        items = [{"name":j.name, "status":j.status, "attempts":j.attempts, "error":j.error}
                 for j in self.engine.history[-20:]]
        self._json({"jobs": items})

    def _json(self, obj, code=200):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        code = args[1] if len(args) > 1 else "?"
        path = args[0].split(" ")[1] if args else "?"
        log("HTTP", f"{path}  {code}", DIM)


# ── payload directory watcher ─────────────────────────────────────────────────

class DirWatcher:
    """
    Watches payload_dir for new .bin files and auto-queues them.
    Processes files in mtime order — oldest first because that's polite.
    """
    def __init__(self, engine: DeliveryEngine, payload_dir: str, interval: float = 2.0):
        self.engine      = engine
        self.dir         = Path(payload_dir).resolve()
        self.interval    = interval
        self.seen: set   = set()
        self._stop       = threading.Event()
        self._thread     = threading.Thread(target=self._loop, daemon=True, name="DirWatcher")

    def start(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        self._thread.start()
        log("WATCH", f"Watching {self.dir}", C)

    def _loop(self):
        while not self._stop.is_set():
            try:
                bins = sorted(self.dir.glob("*.bin"), key=lambda f: f.stat().st_mtime)
                for f in bins:
                    if str(f) not in self.seen:
                        self.seen.add(str(f))
                        self.engine.enqueue_file(str(f))
            except Exception as e:
                log("WATCH ERR", str(e), R)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()


# ── CLI entry ─────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    cfg_path = Path(__file__).parent / "config.json"
    if cfg_path.exists():
        with open(cfg_path) as f:
            overrides = json.load(f)
        CFG.update(overrides)
        log("CFG", f"Loaded config from {cfg_path}", G)
    return CFG


def main():
    cfg = load_cfg()

    print(f"""
{M}{'─'*56}{RST}
{BOLD}{W}  ENI // PS4 Payload Delivery System{RST}
{M}{'─'*56}{RST}
  {G}●{RST} Target    {C}{cfg['ps4_ip']}:{cfg['bin_loader_port']}{RST}
  {G}●{RST} REST API  {C}http://0.0.0.0:{cfg['http_port']}/{RST}
  {G}●{RST} Watch     {C}{cfg['payload_dir']}{RST}
  {G}●{RST} XOR key   {C}0x{cfg['xor_key']:02X}{RST}
{M}{'─'*56}{RST}
  POST /send?target=<ip>&file=<name>.bin  to send manually
  GET  /status                            for queue status
{M}{'─'*56}{RST}
""")

    engine = DeliveryEngine(cfg)
    engine.start()

    watcher = DirWatcher(engine, cfg["payload_dir"])
    watcher.start()

    ControlHandler.engine = engine
    import socketserver
    with socketserver.TCPServer(("0.0.0.0", cfg["http_port"]), ControlHandler) as httpd:
        httpd.allow_reuse_address = True
        log("HTTP", f"Control server on :{cfg['http_port']}", G)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{Y}  Shutting down.{RST}\n")
            engine.stop()
            watcher.stop()


if __name__ == "__main__":
    main()
