#!/usr/bin/env python3
"""
Disassemble key functions in libaudioproxy.so using capstone.
Outputs annotated Thumb-2 disassembly with PC-relative LDR values resolved.

Usage:
    python3 scripts/disasm_libaudioproxy.py
    python3 scripts/disasm_libaudioproxy.py --func proxy_open_capture_stream
"""

import struct, sys, argparse
from pathlib import Path

try:
    import capstone
except ImportError:
    sys.exit("pip install capstone")

BINARY = Path(__file__).parent.parent / "binaries" / "libaudioproxy.so"

# Known functions from ELF .dynsym (vaddr, size, name)
FUNCTIONS = {
    "proxy_create_capture_stream": (0x9ee8, 1332),
    "proxy_open_capture_stream":   (0xa9f0, 1024),
    "proxy_setparam_capture_stream": (0xa118, 800),
}

def parse_dynsym(data):
    """Return {name: (vaddr, size)} from ELF .dynsym."""
    e_shoff = struct.unpack_from('<I', data, 0x20)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x2e)[0]
    e_shnum = struct.unpack_from('<H', data, 0x30)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]

    sections = [struct.unpack_from('<IIIIII', data, e_shoff + i * e_shentsize)
                for i in range(e_shnum)]
    shstr_off = sections[e_shstrndx][4]

    def shname(idx):
        start = shstr_off + sections[idx][0]
        return data[start:data.index(b'\x00', start)].decode()

    dynsym = next((i for i in range(e_shnum) if shname(i) == '.dynsym'), None)
    dynstr = next((i for i in range(e_shnum) if shname(i) == '.dynstr'), None)
    if dynsym is None or dynstr is None:
        return {}

    sym_off, sym_size = sections[dynsym][4], sections[dynsym][5]
    str_off = sections[dynstr][4]
    result = {}
    for i in range(sym_size // 16):
        st_name, st_value, st_size = struct.unpack_from('<III', data, sym_off + i * 16)
        if st_value:
            start = str_off + st_name
            name = data[start:data.index(b'\x00', start)].decode()
            result[name] = (st_value & ~1, st_size)  # clear Thumb bit
    return result


def disasm(data, vaddr, size, name=""):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    # vaddr → file offset: .text starts at vaddr 0x1000, fileoff 0x0 in libaudioproxy
    # (section mapping: vaddr = fileoff + 0x1000)
    fileoff = vaddr - 0x1000
    code = data[fileoff:fileoff + size]

    print(f"\n; {'=' * 60}")
    print(f"; {name}  vaddr=0x{vaddr:06x}  size={size}")
    print(f"; {'=' * 60}")

    for insn in md.disasm(code, vaddr):
        annotation = ""
        if insn.mnemonic == 'ldr' and '[pc,' in insn.op_str:
            import re
            m = re.search(r'#(0x[\da-f]+|\d+)', insn.op_str)
            if m:
                pc = (insn.address + 4) & ~3
                pool_addr = pc + int(m.group(1), 0)
                pool_fileoff = pool_addr - 0x1000
                if 0 <= pool_fileoff + 4 <= len(data):
                    val = struct.unpack_from('<I', data, pool_fileoff)[0]
                    annotation = f"  ; *0x{pool_addr:06x}=0x{val:08x}"
        print(f"0x{insn.address:06x}  {insn.mnemonic:<12} {insn.op_str}{annotation}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--func', default=None, help="Function name to disassemble (default: all built-in)")
    p.add_argument('--list', action='store_true', help="List all exported functions")
    args = p.parse_args()

    data = BINARY.read_bytes()
    syms = parse_dynsym(data)

    if args.list:
        for name, (vaddr, size) in sorted(syms.items(), key=lambda x: x[1][0]):
            if size > 0:
                print(f"0x{vaddr:06x}  {size:6d}  {name}")
        return

    targets = FUNCTIONS.copy()
    for name, (vaddr, size) in syms.items():
        if name in targets:
            targets[name] = (vaddr, targets[name][1])

    if args.func:
        if args.func in targets:
            items = [(args.func, *targets[args.func])]
        elif args.func in syms:
            items = [(args.func, *syms[args.func])]
        else:
            sys.exit(f"Unknown function: {args.func}")
    else:
        items = [(n, v, s) for n, (v, s) in sorted(targets.items(), key=lambda x: x[1][0])]

    for name, vaddr, size in items:
        disasm(data, vaddr, size, name)


if __name__ == '__main__':
    main()
