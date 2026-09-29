#!/usr/bin/env python3
"""
ENI // ps4_suite.py
PS4 13.52 Developer Suite — Unified Launcher
One entry point. All tools. No excuses.
"""

import sys
import os
import json
import subprocess
import argparse
from pathlib import Path

# Windows cp1252 dies on box-drawing chars — fix it before any print() runs
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

TOOLS_DIR = Path(__file__).parent
CFG_PATH  = TOOLS_DIR / "config.json"

# ── ANSI ─────────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; M="\033[95m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

BANNER = f"""
{M}╔══════════════════════════════════════════════════════╗{RST}
{M}║{RST}  {BOLD}{W}ENI // PS4 13.52 Developer Suite{RST}                  {M}║{RST}
{M}╠══════════════════════════════════════════════════════╣{RST}
{M}║{RST}  {C}A{RST}  Memory Scanner & Pattern Engine                {M}║{RST}
{M}║{RST}  {C}B{RST}  GSC Bytecode Disassembler                      {M}║{RST}
{M}║{RST}  {C}C{RST}  PS4 Debug GUI (Tkinter)                        {M}║{RST}
{M}║{RST}  {C}D{RST}  Payload Delivery System (C2)                   {M}║{RST}
{M}║{RST}  {C}E{RST}  Kernel Syscall Map Builder                     {M}║{RST}
{M}╚══════════════════════════════════════════════════════╝{RST}
"""


TOOLS = {
    "a": {
        "name":   "Memory Scanner",
        "script": TOOLS_DIR / "memory_scanner.py",
        "desc":   "Pattern scanner — args: <ps4_ip> <pid> <hex_bytes> [mask]",
    },
    "b": {
        "name":   "GSC Disassembler",
        "script": TOOLS_DIR / "gsc_disasm.py",
        "desc":   "Disassemble a .gsc binary — args: <file.gsc> [--json] [--fn NAME]",
    },
    "c": {
        "name":   "PS4 Debug GUI",
        "script": TOOLS_DIR / "ps4_gui.py",
        "desc":   "Dark Tkinter debug control panel — no extra args needed",
    },
    "d": {
        "name":   "Payload Delivery System",
        "script": TOOLS_DIR / "payload_host.py",
        "desc":   "C2 + REST delivery host — reads config.json automatically",
    },
    "e": {
        "name":   "Syscall Map Builder",
        "script": TOOLS_DIR / "syscall_map.py",
        "desc":   "Enumerate 13.52 syscalls — args: [--ps4 IP] [--pid N] [--dry-run]",
    },
}


def load_cfg() -> dict:
    if CFG_PATH.exists():
        with open(CFG_PATH) as f:
            return json.load(f)
    return {}


def self_test() -> bool:
    """Import-level sanity check for all modules. No PS4 required."""
    print(f"\n  {C}Self-test: checking all modules import cleanly...{RST}\n")
    passed = True
    for key, tool in TOOLS.items():
        script = tool["script"]
        if not script.exists():
            print(f"  {R}[{key.upper()}] MISSING: {script.name}{RST}")
            passed = False
            continue
        # test import via subprocess to keep each tool isolated
        r = subprocess.run(
            [sys.executable, "-c", f"import importlib.util, sys; \
             spec=importlib.util.spec_from_file_location('t',r'{script}'); \
             m=importlib.util.module_from_spec(spec)"],
            capture_output=True, text=True
        )
        status = f"{G}OK{RST}" if r.returncode == 0 else f"{R}FAIL{RST}"
        print(f"  [{key.upper()}] {tool['name']:<30} {status}")
        if r.returncode != 0 and r.stderr:
            print(f"       {DIM}{r.stderr.strip()[:120]}{RST}")
            passed = False

    cfg = load_cfg()
    print(f"\n  {C}Config:{RST}")
    for k, v in cfg.items():
        print(f"    {DIM}{k:<20}{RST} {W}{v}{RST}")

    print(f"\n  {'─'*40}")
    print(f"  {'All checks passed.' if passed else 'Some checks FAILED.'}")
    return passed


def run_tool(key: str, extra_args: list[str]):
    tool = TOOLS.get(key.lower())
    if not tool:
        print(f"  {R}Unknown tool '{key}'.{RST}")
        return

    script = tool["script"]
    if not script.exists():
        print(f"  {R}Script not found: {script}{RST}")
        return

    print(f"\n  {G}Launching:{RST} {tool['name']}")
    print(f"  {DIM}{tool['desc']}{RST}\n")

    cmd = [sys.executable, str(script)] + extra_args
    subprocess.run(cmd)


def interactive_menu():
    print(BANNER)
    cfg = load_cfg()
    ps4_ip = cfg.get("ps4_ip", "not set")
    print(f"  {DIM}Config: {CFG_PATH}{RST}")
    print(f"  {C}PS4:{RST} {ps4_ip}  |  {C}ps4debug:{RST} {cfg.get('ps4debug_port',2801)}  |  {C}loader:{RST} {cfg.get('bin_loader_port',9090)}\n")

    while True:
        print(f"\n  {W}Select tool {C}[a-e]{W}, {C}test{W} for self-test, or {C}q{W} to quit:{RST} ", end="")
        try:
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {Y}Later.{RST}\n")
            break

        if choice in ("q", "quit", "exit"):
            print(f"  {Y}Later.{RST}\n"); break
        elif choice in ("test", "self-test", "t"):
            self_test()
        elif choice in TOOLS:
            extra = []
            if choice != "c":  # GUI has no extra args
                print(f"  {DIM}Extra args (enter for none):{RST} ", end="")
                try:
                    raw = input().strip()
                    extra = raw.split() if raw else []
                except (EOFError, KeyboardInterrupt):
                    extra = []
            run_tool(choice, extra)
        else:
            print(f"  {R}Unknown: '{choice}'{RST}")


def main():
    ap = argparse.ArgumentParser(
        description="ENI // PS4 13.52 Dev Suite Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  ps4_suite.py               # interactive menu\n"
               "  ps4_suite.py --tool c      # launch GUI directly\n"
               "  ps4_suite.py --tool b script.gsc --json  # passthrough args\n"
               "  ps4_suite.py --self-test   # import check, no PS4 needed"
    )
    ap.add_argument("--tool",      metavar="LETTER", help="a=scanner b=disasm c=gui d=payload e=syscall")
    ap.add_argument("--self-test", action="store_true", help="Run import sanity checks and exit")
    args, passthrough = ap.parse_known_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)
    elif args.tool:
        run_tool(args.tool, passthrough)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
