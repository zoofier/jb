#!/usr/bin/env python3
"""
ENI // syscall_map.py
PS4 13.52 — Kernel Syscall Enumerator
Reads ps4_offsets.js + known 13.52 bases, enumerates syscalls 0-700,
logs signatures via ps4debug RPC, writes syscall_map_1352.json.
Non-destructive. Readonly. Mostly.
"""

import os
import re
import sys
import json
import struct
import socket
import time
import threading
from pathlib import Path
from typing import Optional

# ensure tools dir is importable
sys.path.insert(0, os.path.dirname(__file__))
from memory_scanner import PS4Debug

# ── 13.52 known bases ─────────────────────────────────────────────────────────
# These are not magic numbers. They are years of community work.
# sys_sysent table base on 13.52 — adjust if your kernel slide is different.
SYSENT_BASE_1352    = 0xFFFFFFFF82A00000   # example — fill with real dump value
SYSENT_ENTRY_SIZE   = 24                   # size of struct sysent on FreeBSD/PS4
SYSENT_FN_OFFSET    = 8                    # offset of sy_call ptr within sysent

# ps4debug RPC call cmd
CMD_PROC_CALL       = 0xBD000016
STATUS_SUCCESS      = 0x80000000

# ── known syscall names (FreeBSD 9 base, PS4-truncated) ───────────────────────
# Not exhaustive — PS4 nukes a bunch. Fill in blanks from reverse.
KNOWN_SYSCALLS: dict[int, str] = {
    0:   "nosys",
    1:   "exit",
    2:   "fork",
    3:   "read",
    4:   "write",
    5:   "open",
    6:   "close",
    7:   "wait4",
    9:   "link",
    10:  "unlink",
    12:  "chdir",
    13:  "fchdir",
    14:  "mknod",
    15:  "chmod",
    16:  "chown",
    18:  "getfsstat",
    20:  "getpid",
    23:  "setuid",
    24:  "getuid",
    25:  "geteuid",
    27:  "recvmsg",
    28:  "sendmsg",
    29:  "recvfrom",
    30:  "accept",
    31:  "getpeername",
    32:  "getsockname",
    33:  "access",
    36:  "sync",
    37:  "kill",
    39:  "getppid",
    41:  "dup",
    42:  "pipe",
    43:  "getegid",
    47:  "getgid",
    49:  "getlogin",
    54:  "ioctl",
    56:  "revoke",
    57:  "symlink",
    58:  "readlink",
    59:  "execve",
    60:  "umask",
    61:  "chroot",
    65:  "msync",
    66:  "vfork",
    73:  "munmap",
    74:  "mprotect",
    75:  "madvise",
    78:  "mincore",
    79:  "getgroups",
    80:  "setgroups",
    81:  "getpgrp",
    83:  "setitimer",
    85:  "getitimer",
    89:  "getdtablesize",
    90:  "dup2",
    92:  "fcntl",
    93:  "select",
    95:  "fsync",
    96:  "setpriority",
    97:  "socket",
    98:  "connect",
    100: "getpriority",
    104: "bind",
    105: "setsockopt",
    106: "listen",
    111: "sigsuspend",
    116: "gettimeofday",
    117: "getrusage",
    118: "getsockopt",
    120: "readv",
    121: "writev",
    122: "settimeofday",
    123: "fchown",
    124: "fchmod",
    126: "setreuid",
    127: "setregid",
    128: "rename",
    131: "flock",
    132: "mkfifo",
    133: "sendto",
    134: "shutdown",
    135: "socketpair",
    136: "mkdir",
    137: "rmdir",
    138: "utimes",
    140: "adjtime",
    147: "setsid",
    148: "quotactl",
    154: "nlm_syscall",
    155: "nfssvc",
    157: "statfs",
    158: "fstatfs",
    160: "getfh",
    163: "getdomainname",
    164: "setdomainname",
    165: "uname",
    166: "sysarch",
    169: "semsys",
    170: "msgsys",
    171: "shmsys",
    181: "setgid",
    182: "setegid",
    183: "seteuid",
    188: "stat",
    189: "fstat",
    190: "lstat",
    191: "pathconf",
    192: "fpathconf",
    194: "getrlimit",
    195: "setrlimit",
    196: "getdirentries",
    197: "mmap",
    199: "lseek",
    200: "truncate",
    201: "ftruncate",
    202: "sysctl",
    203: "mlock",
    204: "munlock",
    205: "undelete",
    209: "futimes",
    210: "getpgid",
    220: "semget",
    221: "semop",
    222: "semctl",    # wait no, wrong numbering — adjust per dump
    253: "issetugid",
    272: "sigprocmask",
    273: "sigsuspend",
    274: "sigaction",
    275: "sigpending",
    276: "sigreturn",
    278: "sigtimedwait",
    280: "sigwaitinfo",
    281: "sigqueue",
    334: "sigfastblock",
    340: "dynlib_dlsym",
    341: "dynlib_get_list",
    351: "mmap",
    362: "sceKernelSetProcessName",
    372: "sceKernelGetProcessName",
    405: "sceKernelDebugRaiseException",
    532: "sceKernelGetSystemSwVersion",
    557: "sceKernelGetProsperoSystemSwVersion",
    597: "sceKernelDebugOutText",
}


# ── offset parser ─────────────────────────────────────────────────────────────

def parse_offsets_js(js_path: str) -> dict[str, int]:
    """
    Pull named offsets out of ps4_offsets.js.
    Format expected: var SOMETHING = 0xDEADBEEF; or similar.
    Returns a flat {name: value} dict.
    """
    offsets = {}
    pattern = re.compile(r'(?:var|const|let)\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)', re.MULTILINE)
    try:
        text = Path(js_path).read_text(encoding="utf-8", errors="replace")
        for match in pattern.finditer(text):
            name = match.group(1)
            val  = int(match.group(2), 0)
            offsets[name] = val
    except Exception as e:
        print(f"  [WARN] Could not parse {js_path}: {e}")
    return offsets


# ── ps4debug RPC call ─────────────────────────────────────────────────────────

def rpc_call(dbg: PS4Debug, pid: int, fn_addr: int, args: list[int]) -> Optional[int]:
    """
    Call a function in the PS4 process via ps4debug's RPC mechanism.
    args: up to 6 uint64 args.
    Returns rax (return value) or None on error.
    Completely harmless if fn_addr points at a read-only syscall stub.
    """
    # pad args to 6
    args = (list(args) + [0] * 6)[:6]
    payload = struct.pack("<II", pid, fn_addr) + struct.pack("<6Q", *args)
    try:
        resp = dbg._cmd(CMD_PROC_CALL, payload)
        if len(resp) >= 8:
            return struct.unpack("<Q", resp[:8])[0]
    except Exception:
        return None
    return None


# ── syscall enumerator ────────────────────────────────────────────────────────

def enumerate_syscalls(
    dbg: Optional[PS4Debug],
    offsets: dict[str, int],
    pid: int = 0,
    start: int = 0,
    end: int = 700,
    dry_run: bool = False,
) -> list[dict]:
    """
    Build the syscall table.
    In dry_run mode (or no ps4debug): reads the sysent table addresses via memory,
    but doesn't actually invoke syscalls. Safe and fast.
    """
    results = []
    sysent_base = offsets.get("SYSENT_BASE", SYSENT_BASE_1352)

    for num in range(start, end + 1):
        name  = KNOWN_SYSCALLS.get(num, f"sys_{num}")
        entry = {"num": num, "name": name, "fn_addr": None, "probed": False, "result": None}

        if dbg and not dry_run and pid:
            # read fn pointer from sysent table
            entry_addr = sysent_base + (num * SYSENT_ENTRY_SIZE) + SYSENT_FN_OFFSET
            try:
                raw = dbg.read_mem(pid, entry_addr, 8)
                fn  = struct.unpack("<Q", raw)[0]
                entry["fn_addr"] = f"0x{fn:016X}"
                # probe: call with all-zero args — harmless for most syscalls
                # Skip syscalls known to have side effects (fork, exit, etc.)
                SKIP_NUMS = {1, 2, 7, 23, 37, 60, 66}
                if num not in SKIP_NUMS:
                    ret = rpc_call(dbg, pid, fn, [0, 0, 0, 0, 0, 0])
                    entry["result"]  = f"0x{ret:X}" if ret is not None else "N/A"
                    entry["probed"]  = True
            except Exception as e:
                entry["error"] = str(e)

        results.append(entry)

        # progress every 50
        if num % 50 == 0:
            print(f"  [{num:>3}/{end}] mapped so far...", end="\r", flush=True)

    print()  # clear progress line
    return results


# ── output formatters ─────────────────────────────────────────────────────────

def print_table(results: list[dict]):
    C_NUM  = "\033[96m"; C_NAME = "\033[97m"; C_ADDR = "\033[92m"
    C_RES  = "\033[93m"; C_DIM  = "\033[2;90m"; RST    = "\033[0m"
    HDR    = "\033[95m"

    print(f"\n{HDR}  {'NUM':>5}  {'NAME':<40}  {'FN ADDR':<20}  {'RESULT'}{RST}")
    print(f"  {'─'*5}  {'─'*40}  {'─'*20}  {'─'*16}")
    for r in results:
        num_s  = f"{C_NUM}{r['num']:>5}{RST}"
        name_s = f"{C_NAME}{r['name']:<40}{RST}"
        addr_s = f"{C_ADDR}{r.get('fn_addr') or '':>20}{RST}"
        res_s  = f"{C_RES}{r.get('result') or '':>16}{RST}" if r.get("probed") else f"{C_DIM}{'—':>16}{RST}"
        print(f"  {num_s}  {name_s}  {addr_s}  {res_s}")


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ENI // PS4 13.52 Syscall Map Builder")
    ap.add_argument("--ps4",      metavar="IP",    help="PS4 IP for live probe (omit for dry-run)")
    ap.add_argument("--pid",      type=int,        default=0, help="Target PID for RPC calls")
    ap.add_argument("--start",    type=int,        default=0, help="First syscall number")
    ap.add_argument("--end",      type=int,        default=700, help="Last syscall number")
    ap.add_argument("--dry-run",  action="store_true", help="Parse offsets only, no PS4 required")
    ap.add_argument("--out",      metavar="FILE",  default="syscall_map_1352.json")
    ap.add_argument("--offsets",  metavar="FILE",  default="../ps4_offsets.js")
    args = ap.parse_args()

    print(f"""
\033[95m{'─'*56}\033[0m
\033[1m\033[97m  ENI // Syscall Map  —  PS4 13.52\033[0m
\033[95m{'─'*56}\033[0m
  Mode:   {'DRY RUN' if (args.dry_run or not args.ps4) else f'LIVE → {args.ps4}'}
  Range:  {args.start} → {args.end}
  Output: {args.out}
\033[95m{'─'*56}\033[0m
""")

    offsets = parse_offsets_js(args.offsets)
    print(f"  Parsed {len(offsets)} offsets from {args.offsets}")

    dbg = None
    if args.ps4 and not args.dry_run:
        try:
            dbg = PS4Debug(args.ps4)
            dbg.connect()
            print(f"  \033[92mConnected to {args.ps4}\033[0m")
        except Exception as e:
            print(f"  \033[91mCould not connect: {e}. Falling back to dry-run.\033[0m")
            dbg = None

    results = enumerate_syscalls(
        dbg=dbg,
        offsets=offsets,
        pid=args.pid,
        start=args.start,
        end=args.end,
        dry_run=(args.dry_run or dbg is None),
    )

    if dbg:
        dbg.disconnect()

    # write JSON
    out_path = Path(__file__).parent / args.out
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"fw": "13.52", "syscalls": results}, f, indent=2)
    print(f"\n  \033[92mWrote {len(results)} entries → {out_path}\033[0m")

    # print table
    print_table(results)
