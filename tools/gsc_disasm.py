#!/usr/bin/env python3
"""
ENI // gsc_disasm.py
BO2 GSC Bytecode Disassembler — PS4 / 13.52 flavour
Feed it a raw .gsc binary, get back something humans can read.
If it segfaults your concepts of scripting, that's working as intended.
"""

import struct
import sys
import json
from dataclasses import dataclass, field
from typing import Optional

# ── GSC magic & header ────────────────────────────────────────────────────────
# BO2 GSC header layout (T6/treyarch):
#   magic:        8 bytes  "GSC" + version byte + padding
#   crc:          4 bytes
#   pad:          4 bytes
#   script_size:  4 bytes  (total file size)
#   exports_off:  4 bytes
#   imports_off:  4 bytes  (external function calls)
#   exports_count:2 bytes
#   imports_count:2 bytes
#   fixups_count: 2 bytes
#   profile_count:2 bytes
#   fixups_off:   4 bytes
#   profile_off:  4 bytes
#   bytecode_off: 4 bytes  ← where the actual opcodes live
#   strings_count:2 bytes
#   anim_count:   2 bytes
#   strings_off:  4 bytes

MAGIC_BYTES = b"\x1c\x00\x00\x00"   # BO2 magic variant (some tools use full 8-byte)
HEADER_FMT  = "<4sIIIIIHHHHIIIHHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


@dataclass
class GSCHeader:
    magic:          bytes
    crc:            int
    pad:            int
    script_size:    int
    exports_off:    int
    imports_off:    int
    exports_count:  int
    imports_count:  int
    fixups_count:   int
    profile_count:  int
    fixups_off:     int
    profile_off:    int
    bytecode_off:   int
    strings_count:  int
    anim_count:     int
    strings_off:    int


@dataclass
class GSCExport:
    checksum:   int
    offset:     int     # bytecode offset of this function
    name_index: int
    num_params: int
    flags:      int
    name:       str = ""


@dataclass
class Instruction:
    offset:  int
    opcode:  int
    mnemonic:str
    operands:list = field(default_factory=list)
    raw:     bytes = b""
    comment: str = ""


# ── BO2 T6 opcode table ───────────────────────────────────────────────────────
# Because Treyarch never published this, so someone had to do it.
# Operand format codes:
#   s1  = 1-byte signed
#   u1  = 1-byte unsigned
#   s2  = 2-byte signed LE
#   u2  = 2-byte unsigned LE
#   s4  = 4-byte signed LE
#   u4  = 4-byte unsigned LE
#   str = string table index (2 bytes)
#   rel = relative branch offset (2 bytes signed)
# Tuple: (mnemonic, [operand_formats])

OPCODES: dict[int, tuple[str, list]] = {
    0x00: ("End",                   []),
    0x01: ("Return",                []),
    0x02: ("GetUndefined",          []),
    0x03: ("GetZero",               []),
    0x04: ("GetByte",               ["u1"]),
    0x05: ("GetNegByte",            ["u1"]),
    0x06: ("GetUnsignedShort",      ["u2"]),
    0x07: ("GetNegUnsignedShort",   ["u2"]),
    0x08: ("GetInteger",            ["s4"]),
    0x09: ("GetFloat",              ["f4"]),
    0x0A: ("GetString",             ["str"]),
    0x0B: ("GetIString",            ["str"]),
    0x0C: ("GetVector",             ["f4","f4","f4"]),
    0x0D: ("GetLevelObject",        []),
    0x0E: ("GetAnimObject",         []),
    0x0F: ("GetSelf",               []),
    0x10: ("GetThisThread",         []),
    0x11: ("GetLastArray",          []),
    0x12: ("GetLevel",              []),
    0x13: ("GetGame",               []),
    0x14: ("GetAnim",               []),
    0x15: ("GetAnimation",          ["str","str"]),
    0x16: ("GetGameRef",            []),
    0x17: ("GetFunction",           ["u4"]),
    0x18: ("CreateLocalVariable",   ["str"]),
    0x19: ("RemoveLocalVariables",  ["u1"]),
    0x1A: ("EvalNewLocalVariableRef",["str"]),
    0x1B: ("EvalLocalVariableRef",  ["u1"]),
    0x1C: ("EvalArrayRef",          []),
    0x1D: ("EvalSelfFieldVariableRef",["str"]),
    0x1E: ("EvalFieldVariableRef",  ["str"]),
    0x1F: ("ClearFieldVariable",    ["str"]),
    0x20: ("ClearArray",            []),
    0x21: ("EmptyArray",            []),
    0x22: ("GetSelfObject",         []),
    0x23: ("GetFieldVariable",      ["str"]),
    0x24: ("SafeSetVariableFieldCached",["u1"]),
    0x25: ("SafeSetWaittillVariableFieldCached",["u1"]),
    0x26: ("GetAnimTree",           ["u1"]),
    0x27: ("GetObjectType",         ["str"]),
    0x28: ("ClearParams",           []),
    0x29: ("CheckClearParams",      []),
    0x2A: ("Push",                  ["u4"]),         # push constant
    0x2B: ("SetLocalVariableFieldCached0",["u1"]),
    0x2C: ("SetLocalVariableFieldCached",["u1"]),
    0x2D: ("CallScriptFunctionParam0",["u2"]),
    0x2E: ("EvalLocalVariableCached0",[]),
    0x2F: ("EvalLocalVariableCached1",[]),
    0x30: ("EvalLocalVariableCached2",[]),
    0x31: ("EvalLocalVariableCached3",[]),
    0x32: ("EvalLocalVariableCached4",[]),
    0x33: ("EvalLocalVariableCached5",[]),
    0x34: ("EvalLocalVariableCached", ["u1"]),
    0x35: ("EvalLocalArrayRefCached0",[]),
    0x36: ("EvalLocalArrayRefCached", ["u1"]),
    0x37: ("EvalFieldVariable",     ["str"]),
    0x38: ("EvalSelfFieldVariable", ["str"]),
    0x39: ("GetBuiltin",            ["u4"]),
    0x3A: ("GetBuiltinFunction",    ["u4"]),
    0x3B: ("GetBuiltinMethod",      ["u4"]),
    0x3C: ("CallBuiltinFunction0",  ["u4"]),
    0x3D: ("CallBuiltinFunction1",  ["u4"]),
    0x3E: ("CallBuiltinFunction2",  ["u4"]),
    0x3F: ("CallBuiltinFunction3",  ["u4"]),
    0x40: ("CallBuiltinFunction4",  ["u4"]),
    0x41: ("CallBuiltinFunction5",  ["u4"]),
    0x42: ("CallBuiltinFunction",   ["u1","u4"]),
    0x43: ("CallBuiltinMethod0",    ["u4"]),
    0x44: ("CallBuiltinMethod1",    ["u4"]),
    0x45: ("CallBuiltinMethod2",    ["u4"]),
    0x46: ("CallBuiltinMethod3",    ["u4"]),
    0x47: ("CallBuiltinMethod4",    ["u4"]),
    0x48: ("CallBuiltinMethod5",    ["u4"]),
    0x49: ("CallBuiltinMethod",     ["u1","u4"]),
    0x4A: ("Wait",                  []),
    0x4B: ("WaitTillFrameEnd",      []),
    0x4C: ("PreScriptCall",         []),
    0x4D: ("ScriptMethodCall",      []),
    0x4E: ("ScriptMethodCallPointer",[]),
    0x4F: ("ScriptFunctionCall",    ["u4"]),
    0x50: ("ScriptFunctionCallPointer",[]),
    0x51: ("ScriptThreadCall",      ["u1","u4"]),
    0x52: ("ScriptThreadCallPointer",["u1"]),
    0x53: ("ScriptMethodThreadCall",["u1","u4"]),
    0x54: ("ScriptMethodThreadCallPointer",["u1"]),
    0x55: ("JumpOnFalse",           ["rel"]),
    0x56: ("JumpOnTrue",            ["rel"]),
    0x57: ("JumpOnFalseExpr",       ["rel"]),
    0x58: ("JumpOnTrueExpr",        ["rel"]),
    0x59: ("Jump",                  ["rel"]),
    0x5A: ("JumpBack",              ["rel"]),
    0x5B: ("Inc",                   []),
    0x5C: ("Dec",                   []),
    0x5D: ("Bit_Or",                []),
    0x5E: ("Bit_Xor",               []),
    0x5F: ("Bit_And",               []),
    0x60: ("Equal",                 []),
    0x61: ("NotEqual",              []),
    0x62: ("LessThan",              []),
    0x63: ("GreaterThan",           []),
    0x64: ("LessThanOrEqualTo",     []),
    0x65: ("GreaterThanOrEqualTo",  []),
    0x66: ("ShiftLeft",             []),
    0x67: ("ShiftRight",            []),
    0x68: ("Plus",                  []),
    0x69: ("Minus",                 []),
    0x6A: ("Multiply",              []),
    0x6B: ("Divide",                []),
    0x6C: ("Modulus",               []),
    0x6D: ("SizeOf",                []),
    0x6E: ("WaitTill",              []),
    0x6F: ("Notify",                []),
    0x70: ("EndOn",                 []),
    0x71: ("VoidCodePos",           []),
    0x72: ("Switch",                ["u4"]),
    0x73: ("EndSwitch",             ["u2"]),
    0x74: ("Vector",                []),
    0x75: ("GetHash",               ["u4"]),
    0x76: ("RealWait",              []),
    0x77: ("VectorConstantOnStack", ["u1"]),
    0x78: ("IsDefined",             []),
    0x79: ("IsTrue",                []),
    0x7A: ("NativeGetLocalFunction",["u4"]),
    0x7B: ("NativeLocalCall",       ["u1","u4"]),
    0x7C: ("NativeLocalThread",     ["u1","u4"]),
    0x7D: ("NativeLocalMethod",     ["u1","u4"]),
    0x7E: ("NativeLocalMethodThread",["u1","u4"]),
    0x7F: ("NativeGetFarFunction",  ["u2","u4"]),
    0x80: ("NativeFarCall",         ["u1","u2","u4"]),
    0x81: ("NativeFarThread",       ["u1","u2","u4"]),
    0x82: ("NativeFarMethod",       ["u1","u2","u4"]),
    0x83: ("NativeFarMethodThread", ["u1","u2","u4"]),
    0x84: ("EvalNewLocalArrayRefCached0",["u1"]),
    0x85: ("SetNewLocalVariableFieldCached0",["u1"]),
    0x86: ("GetNegZero",            []),
    0x87: ("EvalLocalVariableObjectCached",["u1"]),
    0x88: ("SpecialVariable",       ["u1"]),
}

OPERAND_SIZES = {"u1":1,"s1":1,"u2":2,"s2":2,"u4":4,"s4":4,"f4":4,"str":2,"rel":2}


# ── parser ────────────────────────────────────────────────────────────────────

class GSCParser:

    def __init__(self, data: bytes):
        self.data    = data
        self.header: Optional[GSCHeader] = None
        self.exports: list[GSCExport]    = []
        self.strings: list[str]          = []

    def parse_header(self) -> GSCHeader:
        if len(self.data) < HEADER_SIZE:
            raise ValueError(f"File too small ({len(self.data)} bytes) to be a GSC binary")
        fields = struct.unpack_from(HEADER_FMT, self.data, 0)
        self.header = GSCHeader(*fields)
        return self.header

    def parse_strings(self):
        """Pull the string table — needed for operand resolution."""
        h = self.header
        off = h.strings_off
        for _ in range(h.strings_count):
            str_off = struct.unpack_from("<I", self.data, off)[0]; off += 4
            _refs   = struct.unpack_from("<H", self.data, off)[0]; off += 2
            _type   = struct.unpack_from("<B", self.data, off)[0]; off += 1
            end = self.data.index(b"\x00", str_off)
            self.strings.append(self.data[str_off:end].decode("utf-8", errors="replace"))

    def parse_exports(self) -> list[GSCExport]:
        h   = self.header
        off = h.exports_off
        # export entry: checksum(4) + offset(4) + name(2str) + params(1) + flags(1)
        for _ in range(h.exports_count):
            checksum   = struct.unpack_from("<I", self.data, off)[0]; off += 4
            fn_offset  = struct.unpack_from("<I", self.data, off)[0]; off += 4
            name_idx   = struct.unpack_from("<H", self.data, off)[0]; off += 2
            num_params = struct.unpack_from("<B", self.data, off)[0]; off += 1
            flags      = struct.unpack_from("<B", self.data, off)[0]; off += 1
            name = self.strings[name_idx] if name_idx < len(self.strings) else f"fn_{fn_offset:04X}"
            self.exports.append(GSCExport(checksum, fn_offset, name_idx, num_params, flags, name))
        return self.exports

    def disasm_function(self, export: GSCExport) -> list[Instruction]:
        """Disassemble one exported function's bytecode."""
        off   = export.offset
        instrs = []

        # find the end boundary — next export or EOF
        next_offsets = sorted(e.offset for e in self.exports if e.offset > export.offset)
        end = next_offsets[0] if next_offsets else len(self.data)

        while off < end:
            start_off = off
            opcode    = self.data[off]; off += 1

            if opcode not in OPCODES:
                # unknown opcode — emit raw byte and advance
                instrs.append(Instruction(
                    offset=start_off, opcode=opcode,
                    mnemonic=f"UNKNOWN_{opcode:02X}",
                    raw=bytes([opcode]),
                    comment="// unrecognized — may be padding or new opcode"
                ))
                continue

            mnemonic, operand_fmts = OPCODES[opcode]
            operands = []

            for fmt in operand_fmts:
                size = OPERAND_SIZES[fmt]
                raw_op = self.data[off:off+size]; off += size

                if fmt in ("u1","u2","u4"):
                    val = int.from_bytes(raw_op, "little", signed=False)
                elif fmt in ("s1","s2","s4"):
                    val = int.from_bytes(raw_op, "little", signed=True)
                elif fmt == "f4":
                    val = struct.unpack("<f", raw_op)[0]
                elif fmt == "str":
                    idx = int.from_bytes(raw_op, "little", signed=False)
                    val = f'"{self.strings[idx]}"' if idx < len(self.strings) else f"STR_{idx}"
                elif fmt == "rel":
                    delta = int.from_bytes(raw_op, "little", signed=True)
                    target = off + delta
                    val = f"0x{target:04X}  // +{delta:+d}"
                else:
                    val = raw_op.hex()

                operands.append(val)

            raw_bytes = self.data[start_off:off]
            instrs.append(Instruction(
                offset=start_off,
                opcode=opcode,
                mnemonic=mnemonic,
                operands=operands,
                raw=raw_bytes
            ))

            if opcode in (0x00, 0x01):  # End / Return
                break

        return instrs


# ── output formatters ─────────────────────────────────────────────────────────

ANSI_ADDR  = "\033[96m"
ANSI_OP    = "\033[93m"
ANSI_MNEM  = "\033[97m"
ANSI_OPER  = "\033[92m"
ANSI_CMT   = "\033[2;90m"
ANSI_FUNC  = "\033[95m"
ANSI_RST   = "\033[0m"

def format_listing(parser: GSCParser) -> str:
    lines = []
    lines.append(f"\n  GSC Disassembly — {len(parser.exports)} export(s), {len(parser.strings)} string(s)\n")

    for exp in parser.exports:
        flags_str = f"flags=0x{exp.flags:02X}" if exp.flags else ""
        lines.append(f"{ANSI_FUNC}{'─'*60}{ANSI_RST}")
        lines.append(f"{ANSI_FUNC}  function {exp.name}  (params={exp.num_params} {flags_str}){ANSI_RST}")
        lines.append(f"{ANSI_FUNC}{'─'*60}{ANSI_RST}")

        instrs = parser.disasm_function(exp)
        for ins in instrs:
            addr_s = f"{ANSI_ADDR}0x{ins.offset:04X}{ANSI_RST}"
            hex_s  = f"{ANSI_OP}{ins.raw.hex():<12}{ANSI_RST}"
            mnem_s = f"{ANSI_MNEM}{ins.mnemonic:<36}{ANSI_RST}"
            oper_s = f"{ANSI_OPER}{', '.join(str(o) for o in ins.operands)}{ANSI_RST}"
            cmt_s  = f"  {ANSI_CMT}{ins.comment}{ANSI_RST}" if ins.comment else ""
            lines.append(f"  {addr_s}  {hex_s}  {mnem_s}  {oper_s}{cmt_s}")

        lines.append("")

    return "\n".join(lines)


def format_json(parser: GSCParser) -> str:
    out = {"exports": []}
    for exp in parser.exports:
        fn = {"name": exp.name, "offset": exp.offset, "params": exp.num_params, "instructions": []}
        for ins in parser.disasm_function(exp):
            fn["instructions"].append({
                "offset":   ins.offset,
                "opcode":   f"0x{ins.opcode:02X}",
                "mnemonic": ins.mnemonic,
                "operands": [str(o) for o in ins.operands],
                "raw":      ins.raw.hex(),
            })
        out["exports"].append(fn)
    return json.dumps(out, indent=2)


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ENI // GSC Bytecode Disassembler (BO2/T6)")
    ap.add_argument("file",   help="Raw .gsc binary file")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of annotated listing")
    ap.add_argument("--fn",   metavar="NAME", help="Disassemble only a specific function by name")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    parser = GSCParser(data)
    parser.parse_header()
    parser.parse_strings()
    parser.parse_exports()

    h = parser.header
    if not args.json:
        print(f"\n  File:       {args.file}")
        print(f"  Size:       0x{h.script_size:08X} ({h.script_size} bytes)")
        print(f"  Bytecode:   0x{h.bytecode_off:08X}")
        print(f"  Exports:    {h.exports_count}")
        print(f"  Imports:    {h.imports_count}")
        print(f"  Strings:    {h.strings_count}")

    if args.fn:
        match = [e for e in parser.exports if e.name == args.fn]
        if not match:
            print(f"  Function '{args.fn}' not found. Available: {[e.name for e in parser.exports]}")
            sys.exit(1)
        parser.exports = match

    if args.json:
        print(format_json(parser))
    else:
        print(format_listing(parser))
