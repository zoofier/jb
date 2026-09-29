#!/usr/bin/env python3
"""
ENI // ps4_gui.py
PS4 13.52 Debug Control Panel
Dark Tkinter. No external deps. Pure personality.
This is what happens when you refuse to use ImGui.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import struct
import sys
import os
import json

# ensure our tools dir is in path
sys.path.insert(0, os.path.dirname(__file__))
from memory_scanner import PS4Debug, scan_pattern, FreezeThread, read_int32, read_int64, write_int32, write_int64

# ── dark theme palette ────────────────────────────────────────────────────────
BG      = "#0d0d0d"
BG2     = "#141414"
BG3     = "#1c1c1c"
PANEL   = "#1a1a2e"
ACCENT  = "#7b2ff7"
ACCENT2 = "#00d4ff"
GREEN   = "#39ff14"
RED     = "#ff3355"
YELLOW  = "#ffd700"
FG      = "#e8e8e8"
FG_DIM  = "#5a5a6a"
MONO    = ("Consolas", 10)
MONO_SM = ("Consolas", 9)
BOLD    = ("Segoe UI", 10, "bold")
TITLE   = ("Segoe UI", 9)


def style_ttk():
    """Shove the dark theme into ttk so it stops looking like Windows 98."""
    s = ttk.Style()
    s.theme_use("default")
    s.configure(".",             background=BG2, foreground=FG, font=TITLE, borderwidth=0)
    s.configure("TFrame",        background=BG2)
    s.configure("TLabel",        background=BG2, foreground=FG)
    s.configure("TButton",       background=PANEL, foreground=FG, relief="flat", padding=4)
    s.map      ("TButton",       background=[("active", ACCENT)], foreground=[("active", "#fff")])
    s.configure("TEntry",        fieldbackground=BG3, foreground=FG, insertcolor=ACCENT2)
    s.configure("TNotebook",     background=BG, tabposition="nw")
    s.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM, padding=[10,4])
    s.map      ("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT2)])
    s.configure("Treeview",      background=BG3, foreground=FG, fieldbackground=BG3, rowheight=22)
    s.configure("Treeview.Heading", background=PANEL, foreground=ACCENT2, font=MONO_SM)
    s.map      ("Treeview",      background=[("selected", ACCENT)])
    s.configure("TSeparator",    background=FG_DIM)
    s.configure("TScrollbar",    background=BG3, troughcolor=BG, arrowcolor=FG_DIM)


def make_btn(parent, text, cmd, color=ACCENT, **kw):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg="#fff", activebackground=ACCENT2,
                  activeforeground=BG, relief="flat", font=MONO_SM,
                  padx=8, pady=3, cursor="hand2", **kw)
    b.bind("<Enter>", lambda e: b.config(bg=ACCENT2))
    b.bind("<Leave>", lambda e: b.config(bg=color))
    return b


def make_entry(parent, width=20, **kw):
    e = tk.Entry(parent, bg=BG3, fg=FG, insertbackground=ACCENT2,
                 relief="flat", font=MONO, width=width,
                 highlightbackground=PANEL, highlightcolor=ACCENT2,
                 highlightthickness=1, **kw)
    return e


def make_label(parent, text, color=FG, size=9, **kw):
    return tk.Label(parent, text=text, bg=BG2, fg=color,
                    font=("Consolas", size), **kw)


# ── connection state ──────────────────────────────────────────────────────────

class State:
    dbg:     PS4Debug  = None
    pid:     int       = 0
    freezes: dict      = {}   # addr → FreezeThread
    connected: bool    = False


# ── log pane ──────────────────────────────────────────────────────────────────

class LogPane(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.text = tk.Text(self, bg=BG, fg=FG_DIM, font=MONO_SM,
                            relief="flat", state="disabled",
                            wrap="word", height=6)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._tag_colors()

    def _tag_colors(self):
        self.text.tag_configure("OK",    foreground=GREEN)
        self.text.tag_configure("ERR",   foreground=RED)
        self.text.tag_configure("WARN",  foreground=YELLOW)
        self.text.tag_configure("INFO",  foreground=ACCENT2)
        self.text.tag_configure("DIM",   foreground=FG_DIM)

    def log(self, msg: str, tag: str = "DIM"):
        self.text.configure(state="normal")
        self.text.insert("end", msg + "\n", tag)
        self.text.see("end")
        self.text.configure(state="disabled")


# ── connect panel ─────────────────────────────────────────────────────────────

class ConnectPanel(tk.Frame):
    def __init__(self, parent, state: State, log: LogPane):
        super().__init__(parent, bg=BG2, padx=10, pady=8)
        self.state = state
        self.log   = log

        make_label(self, "PS4 IP:", ACCENT2).grid(row=0, column=0, sticky="w", padx=(0,6))
        self.ip_var = tk.StringVar(value="192.168.1.100")
        self.ip_e = make_entry(self, width=18, textvariable=self.ip_var)
        self.ip_e.grid(row=0, column=1, padx=(0,6))

        make_label(self, "Port:", ACCENT2).grid(row=0, column=2, sticky="w", padx=(0,4))
        self.port_var = tk.StringVar(value="2801")
        make_entry(self, width=6, textvariable=self.port_var).grid(row=0, column=3, padx=(0,10))

        self.btn_connect = make_btn(self, "● Connect", self._connect, color=GREEN)
        self.btn_connect.grid(row=0, column=4, padx=(0,4))

        self.btn_disconnect = make_btn(self, "✕ Disconnect", self._disconnect, color=RED)
        self.btn_disconnect.grid(row=0, column=5)
        self.btn_disconnect.config(state="disabled")

        self.status_lbl = make_label(self, "  ○  Disconnected", FG_DIM, 9)
        self.status_lbl.grid(row=0, column=6, padx=(12,0))

    def _connect(self):
        ip   = self.ip_var.get().strip()
        port = int(self.port_var.get().strip())
        def do():
            try:
                self.state.dbg = PS4Debug(ip, port)
                self.state.dbg.connect()
                self.state.connected = True
                self.after(0, self._on_connected)
            except Exception as e:
                self.after(0, lambda: self.log.log(f"Connect failed: {e}", "ERR"))
        threading.Thread(target=do, daemon=True).start()

    def _on_connected(self):
        self.state.connected = True
        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        self.status_lbl.config(text="  ●  Connected", fg=GREEN)
        self.log.log(f"Connected to {self.ip_var.get()}:{self.port_var.get()}", "OK")
        self.event_generate("<<Connected>>", when="tail")

    def _disconnect(self):
        if self.state.dbg:
            self.state.dbg.disconnect()
            self.state.dbg = None
        self.state.connected = False
        self.btn_connect.config(state="normal")
        self.btn_disconnect.config(state="disabled")
        self.status_lbl.config(text="  ○  Disconnected", fg=FG_DIM)
        self.log.log("Disconnected.", "WARN")


# ── process list panel ────────────────────────────────────────────────────────

class ProcessPanel(tk.Frame):
    def __init__(self, parent, state: State, log: LogPane):
        super().__init__(parent, bg=BG2)
        self.state = state
        self.log   = log

        toolbar = tk.Frame(self, bg=BG2, padx=8, pady=6)
        toolbar.pack(fill="x")
        make_label(toolbar, "PROCESSES", ACCENT2, 10).pack(side="left")
        make_btn(toolbar, "⟳ Refresh", self._refresh).pack(side="left", padx=(10,4))
        make_label(toolbar, "  Attach PID:", FG_DIM).pack(side="left", padx=(10,2))
        self.pid_var = tk.StringVar()
        make_btn(toolbar, "Attach", self._attach, color=ACCENT).pack(side="left", padx=(4,0))

        cols = ("PID","Name")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=16)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("PID",  width=80,  anchor="center")
        self.tree.column("Name", width=320, anchor="w")
        self.tree.bind("<Double-1>", self._on_dbl)

        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=(0,8))
        sb.pack(side="right", fill="y", pady=(0,8), padx=(0,8))

    def _refresh(self):
        if not self.state.connected:
            self.log.log("Not connected.", "WARN"); return
        def do():
            try:
                procs = self.state.dbg.process_list()
                self.after(0, lambda: self._populate(procs))
            except Exception as e:
                self.after(0, lambda: self.log.log(f"Process list error: {e}", "ERR"))
        threading.Thread(target=do, daemon=True).start()

    def _populate(self, procs):
        self.tree.delete(*self.tree.get_children())
        for p in procs:
            self.tree.insert("", "end", values=(p["pid"], p["name"]))
        self.log.log(f"Got {len(procs)} processes.", "INFO")

    def _on_dbl(self, _):
        sel = self.tree.selection()
        if sel:
            pid = int(self.tree.item(sel[0])["values"][0])
            name = self.tree.item(sel[0])["values"][1]
            self.state.pid = pid
            self.log.log(f"Attached → PID {pid}  ({name})", "OK")
            self.event_generate("<<PIDAttached>>", when="tail")

    def _attach(self):
        try:
            self.state.pid = int(self.pid_var.get())
            self.log.log(f"Attached → PID {self.state.pid}", "OK")
        except ValueError:
            self.log.log("Invalid PID.", "ERR")


# ── memory hex editor panel ───────────────────────────────────────────────────

class MemoryPanel(tk.Frame):
    def __init__(self, parent, state: State, log: LogPane):
        super().__init__(parent, bg=BG2)
        self.state = state
        self.log   = log
        self._build()

    def _build(self):
        # toolbar
        tb = tk.Frame(self, bg=BG2, padx=8, pady=6)
        tb.pack(fill="x")
        make_label(tb, "MEMORY", ACCENT2, 10).pack(side="left")

        make_label(tb, "  Addr (hex):", FG_DIM).pack(side="left", padx=(12,2))
        self.addr_var = tk.StringVar(value="0x00000000")
        make_entry(tb, width=18, textvariable=self.addr_var).pack(side="left")

        make_label(tb, "  Len:", FG_DIM).pack(side="left", padx=(8,2))
        self.len_var = tk.StringVar(value="256")
        make_entry(tb, width=6, textvariable=self.len_var).pack(side="left")

        make_btn(tb, "Read", self._read).pack(side="left", padx=(8,2))
        make_btn(tb, "Write Hex", self._write, color=YELLOW).pack(side="left", padx=(2,0))

        # hex view
        self.hex_view = tk.Text(self, bg=BG, fg=ACCENT2, font=MONO,
                                relief="flat", wrap="none", height=18,
                                state="disabled")
        sx = ttk.Scrollbar(self, orient="horizontal", command=self.hex_view.xview)
        sy = ttk.Scrollbar(self, orient="vertical",   command=self.hex_view.yview)
        self.hex_view.configure(xscrollcommand=sx.set, yscrollcommand=sy.set)
        self.hex_view.pack(fill="both", expand=True, padx=8, pady=(2,0))
        sx.pack(fill="x", padx=8)

        # write field
        wb = tk.Frame(self, bg=BG2, padx=8, pady=4)
        wb.pack(fill="x")
        make_label(wb, "Write bytes (hex, space-sep):", FG_DIM).pack(side="left")
        self.write_var = tk.StringVar()
        make_entry(wb, width=50, textvariable=self.write_var).pack(side="left", padx=6)

    def _read(self):
        if not self._check(): return
        try:
            addr = int(self.addr_var.get(), 16)
            size = int(self.len_var.get())
        except ValueError:
            self.log.log("Bad addr/len.", "ERR"); return

        def do():
            try:
                data = self.state.dbg.read_mem(self.state.pid, addr, size)
                self.after(0, lambda: self._show_hex(addr, data))
            except Exception as e:
                self.after(0, lambda: self.log.log(f"Read error: {e}", "ERR"))
        threading.Thread(target=do, daemon=True).start()

    def _show_hex(self, base_addr: int, data: bytes):
        self.hex_view.configure(state="normal")
        self.hex_view.delete("1.0", "end")
        # classic hex dump — 16 bytes per row
        for row in range(0, len(data), 16):
            chunk = data[row:row+16]
            addr_s  = f"0x{base_addr+row:016X}"
            hex_s   = " ".join(f"{b:02X}" for b in chunk).ljust(47)
            ascii_s = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            self.hex_view.insert("end", f"{addr_s}  {hex_s}  │{ascii_s}│\n")
        self.hex_view.configure(state="disabled")
        self.log.log(f"Read 0x{base_addr:X} +{len(data)} bytes", "OK")

    def _write(self):
        if not self._check(): return
        try:
            addr  = int(self.addr_var.get(), 16)
            patch = bytes.fromhex(self.write_var.get().replace(" ", ""))
        except ValueError:
            self.log.log("Bad addr or hex bytes.", "ERR"); return

        def do():
            try:
                self.state.dbg.write_mem(self.state.pid, addr, patch)
                self.after(0, lambda: self.log.log(f"Wrote {len(patch)} bytes → 0x{addr:016X}", "OK"))
            except Exception as e:
                self.after(0, lambda: self.log.log(f"Write error: {e}", "ERR"))
        threading.Thread(target=do, daemon=True).start()

    def _check(self) -> bool:
        if not self.state.connected:
            self.log.log("Not connected.", "WARN"); return False
        if not self.state.pid:
            self.log.log("No PID attached.", "WARN"); return False
        return True


# ── freeze watchlist panel ────────────────────────────────────────────────────

class FreezePanel(tk.Frame):
    def __init__(self, parent, state: State, log: LogPane):
        super().__init__(parent, bg=BG2)
        self.state   = state
        self.log     = log
        self.freezes: dict[str, FreezeThread] = {}
        self._build()

    def _build(self):
        tb = tk.Frame(self, bg=BG2, padx=8, pady=6)
        tb.pack(fill="x")
        make_label(tb, "FREEZE WATCHLIST", ACCENT2, 10).pack(side="left")

        # add controls
        add_f = tk.Frame(self, bg=BG3, padx=8, pady=6)
        add_f.pack(fill="x", padx=8, pady=(0,4))

        make_label(add_f, "Addr:", FG_DIM).grid(row=0, column=0, sticky="w")
        self.f_addr = make_entry(add_f, width=18); self.f_addr.grid(row=0, column=1, padx=4)

        make_label(add_f, "Value:", FG_DIM).grid(row=0, column=2, sticky="w", padx=(8,0))
        self.f_val  = make_entry(add_f, width=12); self.f_val.grid(row=0, column=3, padx=4)

        make_label(add_f, "Type:", FG_DIM).grid(row=0, column=4, sticky="w", padx=(8,0))
        self.f_type = ttk.Combobox(add_f, values=["int32","int64","float","bytes"], width=8, state="readonly")
        self.f_type.current(0); self.f_type.grid(row=0, column=5, padx=4)

        make_btn(add_f, "❄ Freeze", self._add_freeze, color=ACCENT2).grid(row=0, column=6, padx=(8,0))
        make_btn(add_f, "✕ Remove", self._remove_freeze, color=RED).grid(row=0, column=7, padx=4)

        # table
        cols = ("Addr","Value","Type","Status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        widths = [180, 120, 80, 100]
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c); self.tree.column(c, width=w, anchor="center")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=(0,8))
        sb.pack(side="right", fill="y", pady=(0,8), padx=(0,8))

    def _make_data(self, typ: str, val_str: str) -> bytes:
        if typ == "int32":  return struct.pack("<i", int(val_str, 0))
        if typ == "int64":  return struct.pack("<q", int(val_str, 0))
        if typ == "float":  return struct.pack("<f", float(val_str))
        if typ == "bytes":  return bytes.fromhex(val_str.replace(" ",""))
        raise ValueError(f"Unknown type: {typ}")

    def _add_freeze(self):
        if not self.state.connected or not self.state.pid:
            self.log.log("Connect + attach PID first.", "WARN"); return
        try:
            addr  = int(self.f_addr.get(), 16)
            typ   = self.f_type.get()
            data  = self._make_data(typ, self.f_val.get())
        except Exception as e:
            self.log.log(f"Bad freeze params: {e}", "ERR"); return

        key = f"0x{addr:016X}"
        if key in self.freezes:
            self.log.log(f"{key} already frozen.", "WARN"); return

        ft = FreezeThread(self.state.dbg, self.state.pid, addr, data)
        ft.start()
        self.freezes[key] = ft
        self.tree.insert("", "end", iid=key, values=(key, self.f_val.get(), typ, "🔒 FROZEN"))
        self.log.log(f"Freezing {key} = {self.f_val.get()} ({typ})", "OK")

    def _remove_freeze(self):
        sel = self.tree.selection()
        if not sel: return
        key = sel[0]
        if key in self.freezes:
            self.freezes[key].stop()
            del self.freezes[key]
        self.tree.delete(key)
        self.log.log(f"Unfroze {key}", "WARN")


# ── patch slot manager ────────────────────────────────────────────────────────

class PatchPanel(tk.Frame):
    def __init__(self, parent, state: State, log: LogPane):
        super().__init__(parent, bg=BG2)
        self.state   = state
        self.log     = log
        self.patches = []
        self._build()

    def _build(self):
        tb = tk.Frame(self, bg=BG2, padx=8, pady=6)
        tb.pack(fill="x")
        make_label(tb, "PATCH SLOTS", ACCENT2, 10).pack(side="left")
        make_btn(tb, "+ Add", self._add).pack(side="left", padx=(10,4))
        make_btn(tb, "▶ Apply All", self._apply_all, color=GREEN).pack(side="left", padx=4)
        make_btn(tb, "✕ Remove", self._remove, color=RED).pack(side="left", padx=4)
        make_btn(tb, "💾 Save", self._save, color=YELLOW).pack(side="left", padx=4)
        make_btn(tb, "📂 Load", self._load).pack(side="left", padx=4)

        cols = ("Name","Addr","Bytes","Status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=18)
        for c, w in zip(cols, [160, 180, 260, 100]):
            self.tree.heading(c, text=c); self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=(0,8))
        sb.pack(side="right", fill="y", pady=(0,8), padx=(0,8))

    def _add(self):
        win = tk.Toplevel(bg=BG2); win.title("Add Patch"); win.resizable(False, False)
        win.grab_set()
        entries = {}
        for i, (lbl, default) in enumerate([
            ("Name",      "UnlockAll"),
            ("Addr (hex)","0x00000000"),
            ("Bytes (hex)","90 90 90 90"),
        ]):
            make_label(win, lbl+":", FG_DIM, 9).grid(row=i, column=0, sticky="w", padx=8, pady=4)
            e = make_entry(win, width=30)
            e.insert(0, default)
            e.grid(row=i, column=1, padx=8, pady=4)
            entries[lbl] = e

        def confirm():
            try:
                name  = entries["Name"].get()
                addr  = int(entries["Addr (hex)"].get(), 16)
                b     = bytes.fromhex(entries["Bytes (hex)"].get().replace(" ",""))
                iid   = f"{name}_{addr:016X}"
                self.patches.append({"name":name, "addr":addr, "bytes":b.hex()})
                self.tree.insert("", "end", iid=iid, values=(name, f"0x{addr:016X}", b.hex().upper(), "Pending"))
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=win)

        make_btn(win, "Add", confirm, color=GREEN).grid(row=3, column=1, pady=8, sticky="e", padx=8)

    def _apply_all(self):
        if not self.state.connected or not self.state.pid:
            self.log.log("Connect + attach PID first.", "WARN"); return
        for iid in self.tree.get_children():
            vals = self.tree.item(iid)["values"]
            addr  = int(vals[1], 16)
            data  = bytes.fromhex(vals[2])
            def do(iid=iid, addr=addr, data=data, name=vals[0]):
                try:
                    self.state.dbg.write_mem(self.state.pid, addr, data)
                    self.after(0, lambda: (
                        self.tree.set(iid, "Status", "✅ Applied"),
                        self.log.log(f"Patch '{name}' → 0x{addr:016X} ✓", "OK")
                    ))
                except Exception as e:
                    self.after(0, lambda: self.log.log(f"Patch '{name}' failed: {e}", "ERR"))
            threading.Thread(target=do, daemon=True).start()

    def _remove(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)

    def _save(self):
        import tkinter.filedialog as fd
        path = fd.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            data = [{"name":self.tree.item(i)["values"][0],
                     "addr":self.tree.item(i)["values"][1],
                     "bytes":self.tree.item(i)["values"][2]} for i in self.tree.get_children()]
            with open(path, "w") as f: json.dump(data, f, indent=2)
            self.log.log(f"Saved {len(data)} patches → {path}", "OK")

    def _load(self):
        import tkinter.filedialog as fd
        path = fd.askopenfilename(filetypes=[("JSON","*.json")])
        if path:
            with open(path) as f: data = json.load(f)
            for p in data:
                iid = f"{p['name']}_{p['addr']}"
                if not self.tree.exists(iid):
                    self.tree.insert("", "end", iid=iid, values=(p["name"], p["addr"], p["bytes"], "Pending"))
            self.log.log(f"Loaded {len(data)} patches from {path}", "INFO")


# ── main window ───────────────────────────────────────────────────────────────

class PS4DebugGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ENI // PS4 13.52 Debug Suite")
        self.root.configure(bg=BG)
        self.root.geometry("1100x780")
        self.root.minsize(900, 640)

        style_ttk()
        self._build()

    def _build(self):
        state = State()

        # header
        hdr = tk.Frame(self.root, bg=PANEL, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="■ PS4 13.52  DEBUG SUITE",
                 bg=PANEL, fg=ACCENT2, font=("Consolas", 13, "bold")).pack(side="left", padx=16)
        tk.Label(hdr, text="ENI //",
                 bg=PANEL, fg=ACCENT, font=("Consolas", 10)).pack(side="right", padx=16)

        # log pane at bottom
        log_frame = tk.LabelFrame(self.root, text=" Log ", bg=BG2, fg=FG_DIM,
                                  font=MONO_SM, bd=1, relief="flat")
        log_frame.pack(fill="x", side="bottom", padx=8, pady=(0,8))
        log = LogPane(log_frame)
        log.pack(fill="both", padx=4, pady=4)

        # connect bar
        conn = ConnectPanel(self.root, state, log)
        conn.pack(fill="x", padx=8, pady=(8,4))

        # separator
        ttk.Separator(self.root).pack(fill="x", padx=8)

        # tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        proc_tab   = ProcessPanel(notebook, state, log)
        mem_tab    = MemoryPanel(notebook, state, log)
        freeze_tab = FreezePanel(notebook, state, log)
        patch_tab  = PatchPanel(notebook, state, log)

        notebook.add(proc_tab,   text="  Processes  ")
        notebook.add(mem_tab,    text="  Memory     ")
        notebook.add(freeze_tab, text="  Freeze     ")
        notebook.add(patch_tab,  text="  Patches    ")

        log.log("ENI // PS4 Debug Suite ready. Connect and attach a PID to begin.", "INFO")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    PS4DebugGUI().run()
