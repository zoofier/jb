#!/usr/bin/env python3
"""
ENI // memory_scanner.py
PS4 13.52 — Memory Scanner & Pattern Engine
Speaks ps4debug TCP protocol (port 2801) directly.
No wrappers. No training wheels. Raw sockets, raw memory.
"""

import socket
import struct
import threading
import time
from typing import Optional

# ── ps4debug protocol constants ───────────────────────────────────────────────
# CMD_PROC_READ_MEM  = 0x10
# CMD_PROC_WRITE_MEM = 0x11
# CMD_PROC_LIST      = 0x09
# CMD_PROC_INFO      = 0x0A
# STATUS_SUCCESS     = 0x80000000
# All ints are little-endian unless noted.

CMD_VERSION        = 0xBD000001
CMD_PROC_LIST      = 0xBD000009
CMD_PROC_READ_MEM  = 0xBD000010
CMD_PROC_WRITE_MEM = 0xBD000011
CMD_PROC_MAP       = 0xBD000012

STATUS_SUCCESS     = 0x80000000

HEADER_FMT  = "<II"   # magic(4) + length(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)


# ── low-level transport ───────────────────────────────────────────────────────

class PS4Debug:
    """
    Raw TCP session to ps4debug.
    If this blows up, check your firewall — or that you actually loaded ps4debug.
    """

    def __init__(self, ip: str, port: int = 2801, timeout: float = 5.0):
        self.ip      = ip
        self.port    = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip, self.port))
        # ps4debug sends a 4-byte greeting — eat it
        self.sock.recv(4)

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send(self, data: bytes):
        total = 0
        while total < len(data):
            sent = self.sock.send(data[total:])
            if sent == 0:
                raise ConnectionResetError("ps4debug socket died mid-send")
            total += sent

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError(f"ps4debug dropped connection (wanted {n}, got {len(buf)})")
            buf += chunk
        return buf

    def _cmd(self, cmd: int, payload: bytes = b"") -> bytes:
        """Send a command packet, return the response payload (after status dword)."""
        # packet: cmd(4LE) + payloadlen(4LE) + payload
        pkt = struct.pack("<II", cmd, len(payload)) + payload
        self._send(pkt)

        # response: status(4LE) + length(4LE) + data
        hdr    = self._recv_exact(8)
        status, resp_len = struct.unpack("<II", hdr)

        if status != STATUS_SUCCESS:
            raise RuntimeError(f"ps4debug error: status=0x{status:08X} for cmd=0x{cmd:08X}")

        return self._recv_exact(resp_len) if resp_len else b""

    # ── public API ────────────────────────────────────────────────────────────

    def process_list(self) -> list[dict]:
        """Return list of {pid, name} dicts for all running processes."""
        raw  = self._cmd(CMD_PROC_LIST)
        # format: count(4) + [pid(4) + name(32)]*count
        count = struct.unpack_from("<I", raw, 0)[0]
        procs = []
        off   = 4
        for _ in range(count):
            pid  = struct.unpack_from("<I", raw, off)[0]; off += 4
            name = raw[off:off+32].rstrip(b"\x00").decode("utf-8", errors="replace"); off += 32
            procs.append({"pid": pid, "name": name})
        return procs

    def get_maps(self, pid: int) -> list[dict]:
        """Return memory map entries for a process: {start, end, prot, name}"""
        payload = struct.pack("<I", pid)
        raw     = self._cmd(CMD_PROC_MAP, payload)
        count   = struct.unpack_from("<I", raw, 0)[0]
        maps    = []
        off     = 4
        for _ in range(count):
            start = struct.unpack_from("<Q", raw, off)[0]; off += 8
            end   = struct.unpack_from("<Q", raw, off)[0]; off += 8
            prot  = struct.unpack_from("<I", raw, off)[0]; off += 4
            name  = raw[off:off+32].rstrip(b"\x00").decode("utf-8", errors="replace"); off += 32
            maps.append({"start": start, "end": end, "prot": prot, "name": name})
        return maps

    def read_mem(self, pid: int, addr: int, size: int) -> bytes:
        payload = struct.pack("<IQI", pid, addr, size)
        return self._cmd(CMD_PROC_READ_MEM, payload)

    def write_mem(self, pid: int, addr: int, data: bytes):
        payload = struct.pack("<IQI", pid, addr, len(data)) + data
        self._cmd(CMD_PROC_WRITE_MEM, payload)


# ── pattern scanner ───────────────────────────────────────────────────────────

def _match_pattern(buf: bytes, offset: int, pattern: bytes, mask: str) -> bool:
    """
    IDA-style mask match. mask chars: 'x' = match, '?' = wildcard.
    Pattern and mask must be same length. Obviously.
    """
    for i, (b, m) in enumerate(zip(pattern, mask)):
        if m == 'x' and buf[offset + i] != b:
            return False
    return True


def scan_pattern(
    dbg: PS4Debug,
    pid: int,
    pattern: bytes,
    mask: str,
    readable_only: bool = True,
    chunk_size: int = 0x10000,
) -> list[int]:
    """
    Walk mapped regions for pid, find all occurrences of pattern/mask.
    Returns list of absolute addresses. Can take a sec on large processes — deal with it.

    pattern: raw bytes, e.g. b"\\xDE\\xAD\\x00\\xBE\\xEF"
    mask:    string,    e.g. "xx?xx"
    """
    assert len(pattern) == len(mask), "pattern and mask must be same length, come on"

    hits    = []
    pat_len = len(pattern)
    maps    = dbg.get_maps(pid)

    for region in maps:
        # prot bit 0x04 = read permission
        if readable_only and not (region["prot"] & 0x04):
            continue

        start = region["start"]
        size  = region["end"] - start
        read  = 0

        # stream the region in chunks — ps4debug can't handle one 500MB read
        while read < size:
            to_read = min(chunk_size, size - read)
            try:
                chunk = dbg.read_mem(pid, start + read, to_read)
            except Exception:
                # unreadable sub-region — skip, don't die
                read += to_read
                continue

            # overlap by pat_len-1 so we don't miss cross-chunk matches
            search_end = len(chunk) - pat_len + 1
            for i in range(search_end):
                if _match_pattern(chunk, i, pattern, mask):
                    hits.append(start + read + i)

            read += to_read

    return hits


# ── value freeze ─────────────────────────────────────────────────────────────

class FreezeThread:
    """
    Background thread that hammers a value into an address every `interval` seconds.
    Classic god mode delivery vehicle.
    """

    def __init__(self, dbg: PS4Debug, pid: int, addr: int, data: bytes, interval: float = 0.05):
        self.dbg      = dbg
        self.pid      = pid
        self.addr     = addr
        self.data     = data
        self.interval = interval
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._stop.clear()
        self._thread.start()
        print(f"  [FREEZE] 0x{self.addr:016X} → {self.data.hex()} @ {self.interval*1000:.0f}ms")

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        print(f"  [UNFREEZE] 0x{self.addr:016X}")

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.dbg.write_mem(self.pid, self.addr, self.data)
            except Exception as e:
                print(f"  [FREEZE ERR] 0x{self.addr:016X}: {e}")
                break
            self._stop.wait(self.interval)


def freeze_int32(dbg: PS4Debug, pid: int, addr: int, value: int) -> FreezeThread:
    return FreezeThread(dbg, pid, addr, struct.pack("<i", value))

def freeze_int64(dbg: PS4Debug, pid: int, addr: int, value: int) -> FreezeThread:
    return FreezeThread(dbg, pid, addr, struct.pack("<q", value))

def freeze_float(dbg: PS4Debug, pid: int, addr: int, value: float) -> FreezeThread:
    return FreezeThread(dbg, pid, addr, struct.pack("<f", value))


# ── convenience wrappers ──────────────────────────────────────────────────────

def read_int32(dbg: PS4Debug, pid: int, addr: int) -> int:
    return struct.unpack("<i", dbg.read_mem(pid, addr, 4))[0]

def read_int64(dbg: PS4Debug, pid: int, addr: int) -> int:
    return struct.unpack("<q", dbg.read_mem(pid, addr, 8))[0]

def read_float(dbg: PS4Debug, pid: int, addr: int) -> float:
    return struct.unpack("<f", dbg.read_mem(pid, addr, 4))[0]

def write_int32(dbg: PS4Debug, pid: int, addr: int, v: int):
    dbg.write_mem(pid, addr, struct.pack("<i", v))

def write_int64(dbg: PS4Debug, pid: int, addr: int, v: int):
    dbg.write_mem(pid, addr, struct.pack("<q", v))

def write_float(dbg: PS4Debug, pid: int, addr: int, v: float):
    dbg.write_mem(pid, addr, struct.pack("<f", v))


# ── CLI quick-scan ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: memory_scanner.py <ps4_ip> <pid> <hex_pattern> [mask]")
        print("  hex_pattern: AA BB CC DD (space-separated hex bytes)")
        print("  mask:        xxxx        (x=match, ?=wildcard, defaults to all x)")
        sys.exit(1)

    ip       = sys.argv[1]
    pid      = int(sys.argv[2])
    raw_hex  = sys.argv[3]
    pat      = bytes.fromhex(raw_hex.replace(" ", ""))
    mask     = sys.argv[4] if len(sys.argv) > 4 else "x" * len(pat)

    print(f"  Connecting to {ip}:2801 ...")
    dbg = PS4Debug(ip)
    dbg.connect()
    print(f"  Scanning PID {pid} for pattern [{raw_hex}] mask [{mask}]")

    hits = scan_pattern(dbg, pid, pat, mask)
    if hits:
        print(f"\n  {len(hits)} hit(s):")
        for addr in hits:
            val = dbg.read_mem(pid, addr, len(pat)).hex()
            print(f"    0x{addr:016X}  →  {val}")
    else:
        print("  No hits. Wrong process, wrong pattern, or you're on the wrong firmware.")

    dbg.disconnect()
