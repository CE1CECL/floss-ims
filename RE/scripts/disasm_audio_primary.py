#!/usr/bin/env python3
"""
Manual Thumb-2 disassembler for audio.primary.universal3830.so.
Used to analyse the proxy_mode computation function at vaddr 0x089b4.

audio.primary has no exported symbols so capstone alone is not enough —
this script uses a hand-rolled decoder tuned to the instruction forms
actually present in the function, plus PC-relative LDR annotation.

Usage:
    python3 scripts/disasm_audio_primary.py
    python3 scripts/disasm_audio_primary.py --vaddr 0x089b4 --size 0x100
"""

import struct, argparse
from pathlib import Path

BINARY = Path(__file__).parent.parent / "binaries" / "audio.primary.universal3830.so"

# ELF section mapping for audio.primary.universal3830.so
TEXT_VADDR   = 0x7260
TEXT_FILEOFF = 0x6260

# Key locations confirmed by RE
KNOWN_FUNCTIONS = {
    "proxy_mode_compute":   (0x089b4, 0xE0),   # reads hw_dev->field_0x114, returns proxy_mode
    "proxy_mode_compute_2": (0x072e0, 0x120),   # second proxy_mode path (LTE/GSM flags)
}


def vaddr_to_fileoff(vaddr):
    return TEXT_FILEOFF + (vaddr - TEXT_VADDR)


def decode(data, pos, vaddr):
    """Decode one Thumb-2 instruction. Returns (size_bytes, mnemonic_string)."""
    if pos + 2 > len(data):
        return 2, "???"
    hw1 = struct.unpack_from('<H', data, pos)[0]
    is32 = (hw1 >> 11) in (0x1d, 0x1e, 0x1f)

    if is32 and pos + 4 <= len(data):
        hw2 = struct.unpack_from('<H', data, pos + 2)[0]

        # ldr.w / str.w / ldrb.w / ldrh.w [rn, #imm12]
        if (hw1 & 0xFFF0) == 0xF8D0:
            rn, rt, i12 = hw1 & 0xF, (hw2 >> 12) & 0xF, hw2 & 0xFFF
            return 4, f"ldr.w r{rt},[r{rn},#0x{i12:x}]"
        if (hw1 & 0xFFF0) == 0xF8C0:
            rn, rt, i12 = hw1 & 0xF, (hw2 >> 12) & 0xF, hw2 & 0xFFF
            return 4, f"str.w r{rt},[r{rn},#0x{i12:x}]"
        if (hw1 & 0xFFF0) == 0xF890:
            rn, rt, i12 = hw1 & 0xF, (hw2 >> 12) & 0xF, hw2 & 0xFFF
            return 4, f"ldrb.w r{rt},[r{rn},#0x{i12:x}]"
        if (hw1 & 0xFFF0) == 0xF8B0:
            rn, rt, i12 = hw1 & 0xF, (hw2 >> 12) & 0xF, hw2 & 0xFFF
            return 4, f"ldrh.w r{rt},[r{rn},#0x{i12:x}]"
        if (hw1 & 0xFFF0) == 0xF880:
            rn, rt, i12 = hw1 & 0xF, (hw2 >> 12) & 0xF, hw2 & 0xFFF
            return 4, f"strb.w r{rt},[r{rn},#0x{i12:x}]"

        # ldrd / strd [rn, #imm8*4]
        if (hw1 & 0xFFF0) == 0xE9D0:
            rn, rt, rt2, i8 = hw1 & 0xF, (hw2 >> 12) & 0xF, (hw2 >> 8) & 0xF, hw2 & 0xFF
            return 4, f"ldrd r{rt},r{rt2},[r{rn},#0x{i8*4:x}]"
        if (hw1 & 0xFFF0) == 0xE940:
            rn, rt, rt2, i8 = hw1 & 0xF, (hw2 >> 12) & 0xF, (hw2 >> 8) & 0xF, hw2 & 0xFF
            return 4, f"strd r{rt},r{rt2},[r{rn},#0x{i8*4:x}]"

        # push.w / pop.w
        if hw1 == 0xE92D:
            return 4, f"push.w {{mask=0x{hw2:04x}}}"
        if hw1 == 0xE8BD:
            return 4, f"pop.w {{mask=0x{hw2:04x}}}"

        # mov.w / movw / movt
        if (hw1 & 0xFBEF) == 0xF04F:
            rd = (hw2 >> 8) & 0xF
            ic = (hw1 >> 10) & 1
            i3 = (hw2 >> 12) & 7
            i8 = hw2 & 0xFF
            return 4, f"mov.w r{rd},#0x{(ic << 11) | (i3 << 8) | i8:x}"
        if (hw1 & 0xFBF0) == 0xF240:
            rd = (hw2 >> 8) & 0xF
            imm = ((hw1 & 0xF) << 12) | ((hw1 >> 10 & 1) << 11) | ((hw2 >> 12 & 7) << 8) | (hw2 & 0xFF)
            return 4, f"movw r{rd},#0x{imm:x}"
        if (hw1 & 0xFBF0) == 0xF2C0:
            rd = (hw2 >> 8) & 0xF
            imm = ((hw1 & 0xF) << 12) | ((hw1 >> 10 & 1) << 11) | ((hw2 >> 12 & 7) << 8) | (hw2 & 0xFF)
            return 4, f"movt r{rd},#0x{imm:x}"

        # add.w / sub.w / cmp.w
        if (hw1 & 0xFFE0) == 0xEB00:
            rd, rn, rm = (hw2 >> 8) & 0xF, hw1 & 0xF, hw2 & 0xF
            return 4, f"add.w r{rd},r{rn},r{rm}"
        if (hw1 & 0xFFE0) == 0xEBA0:
            rd, rn, rm = (hw2 >> 8) & 0xF, hw1 & 0xF, hw2 & 0xF
            return 4, f"sub.w r{rd},r{rn},r{rm}"
        if (hw1 & 0xFBE0) == 0xF100:
            rd, rn = (hw2 >> 8) & 0xF, hw1 & 0xF
            return 4, f"add.w r{rd},r{rn},#0x{hw2 & 0xFFF:x}"
        if (hw1 & 0xFBE0) == 0xF1A0:
            rd, rn = (hw2 >> 8) & 0xF, hw1 & 0xF
            return 4, f"sub.w r{rd},r{rn},#0x{hw2 & 0xFFF:x}"
        if (hw1 & 0xFBF0) == 0xF1B0:
            rn = hw1 & 0xF
            return 4, f"cmp.w r{rn},#0x{hw2 & 0xFFF:x}"

        # bl / blx (32-bit branch)
        if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xD000:
            s = (hw1 >> 10) & 1
            i1 = 1 ^ (s ^ ((hw2 >> 13) & 1))
            i2 = 1 ^ (s ^ ((hw2 >> 11) & 1))
            imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
            if s:
                imm |= (-1 << 25)
            return 4, f"bl 0x{(vaddr + 4 + imm) & 0xFFFFFFFF:05x}"

        # b.w / b<cc>.w (32-bit branch)
        if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xF000) in (0x8000, 0x9000, 0xa000, 0xb000):
            s = (hw1 >> 10) & 1
            j1 = (hw2 >> 13) & 1
            j2 = (hw2 >> 11) & 1
            imm = (s << 20) | (j2 << 19) | (j1 << 18) | ((hw1 & 0x3F) << 12) | ((hw2 & 0x7FF) << 1)
            if s:
                imm |= (-1 << 21)
            cond = (hw2 >> 10) & 0xF
            cc = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','',''][cond]
            return 4, f"b{cc}.w 0x{(vaddr + 4 + imm) & 0xFFFFFFFF:05x}"

        return 4, f".word32 0x{hw1:04x}{hw2:04x}"

    # 16-bit Thumb instructions
    if (hw1 & 0xFF00) == 0xBD00:
        return 2, f"pop {{pc,...}}"
    if (hw1 & 0xFF00) == 0xB500:
        return 2, f"push {{lr,...}}"
    if (hw1 & 0xFF87) == 0x4700:
        rm = (hw1 >> 3) & 0xF
        return 2, f"bx r{rm}"
    if (hw1 & 0xFF87) == 0x4780:
        rm = (hw1 >> 3) & 0xF
        return 2, f"blx r{rm}"
    if (hw1 & 0xF800) == 0x4800:
        rt = (hw1 >> 8) & 0x7
        imm8 = hw1 & 0xFF
        pc = (vaddr + 4) & ~3
        pool_vaddr = pc + imm8 * 4
        pool_foff = pool_vaddr - TEXT_VADDR + TEXT_FILEOFF
        val = struct.unpack_from('<I', data, pool_foff)[0] if 0 <= pool_foff + 4 <= len(data) else 0
        return 2, f"ldr r{rt},[pc,#0x{imm8*4:x}]  ; *0x{pool_vaddr:06x}=0x{val:08x}"
    if (hw1 & 0xFE00) == 0xBC00:
        return 2, f"pop {{mask=0x{hw1&0xFF:02x}}}"
    if (hw1 & 0xFE00) == 0xB400:
        return 2, f"push {{mask=0x{hw1&0xFF:02x}}}"
    if (hw1 & 0xF800) == 0x2000:
        rn = (hw1 >> 8) & 0x7
        return 2, f"movs r{rn},#0x{hw1 & 0xFF:x}"
    if (hw1 & 0xF800) == 0x2800:
        rn = (hw1 >> 8) & 0x7
        return 2, f"cmp r{rn},#0x{hw1 & 0xFF:x}"
    if (hw1 & 0xF800) == 0xD000:
        cond = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        if imm8 >= 0x80:
            imm8 -= 0x100
        cc = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','',''][cond]
        return 2, f"b{cc} 0x{(vaddr + 4 + imm8 * 2) & 0xFFFF:05x}"
    if (hw1 & 0xF800) == 0xE000:
        imm11 = hw1 & 0x7FF
        if imm11 >= 0x400:
            imm11 -= 0x800
        return 2, f"b 0x{(vaddr + 4 + imm11 * 2) & 0xFFFF:05x}"
    if (hw1 & 0xFF00) == 0xBF00:
        it_cond = (hw1 >> 4) & 0xF
        mask = hw1 & 0xF
        cc = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','',''][it_cond]
        return 2, f"IT{'' if mask & 0x8 else 'E'} {cc}"
    if (hw1 & 0xF800) == 0xB000:
        imm7 = hw1 & 0x7F
        sign = '+' if not (hw1 & 0x80) else '-'
        return 2, f"{'add' if not (hw1 & 0x80) else 'sub'} sp,sp,#0x{imm7 * 4:x}"
    if (hw1 & 0xFD00) == 0xB100:
        rn = hw1 & 0x7
        imm = ((hw1 >> 3) & 0x1F) | ((hw1 >> 7 & 1) << 5)
        return 2, f"cbz r{rn},0x{(vaddr + 4 + imm * 2) & 0xFFFF:05x}"
    if (hw1 & 0xFD00) == 0xB900:
        rn = hw1 & 0x7
        imm = ((hw1 >> 3) & 0x1F) | ((hw1 >> 7 & 1) << 5)
        return 2, f"cbnz r{rn},0x{(vaddr + 4 + imm * 2) & 0xFFFF:05x}"
    if (hw1 & 0xF800) == 0x6800:
        rt, rn, imm5 = hw1 & 0x7, (hw1 >> 3) & 0x7, (hw1 >> 6) & 0x1F
        return 2, f"ldr r{rt},[r{rn},#0x{imm5 * 4:x}]"
    if (hw1 & 0xF800) == 0x6000:
        rt, rn, imm5 = hw1 & 0x7, (hw1 >> 3) & 0x7, (hw1 >> 6) & 0x1F
        return 2, f"str r{rt},[r{rn},#0x{imm5 * 4:x}]"
    if (hw1 & 0xF800) == 0x7800:
        rt, rn, imm5 = hw1 & 0x7, (hw1 >> 3) & 0x7, (hw1 >> 6) & 0x1F
        return 2, f"ldrb r{rt},[r{rn},#0x{imm5:x}]"
    if (hw1 & 0xF800) == 0x7000:
        rt, rn, imm5 = hw1 & 0x7, (hw1 >> 3) & 0x7, (hw1 >> 6) & 0x1F
        return 2, f"strb r{rt},[r{rn},#0x{imm5:x}]"
    if (hw1 & 0xFFC0) == 0x4440:
        rdn = hw1 & 0xF
        rm = (hw1 >> 3) & 0xF
        return 2, f"add r{rdn},r{rm}"
    if (hw1 & 0xFFC0) == 0x4500:
        rn = hw1 & 0xF
        rm = (hw1 >> 3) & 0xF
        return 2, f"cmp r{rn},r{rm}"
    if (hw1 & 0xFFC0) == 0x4600:
        rd = (hw1 & 0x7) | ((hw1 >> 4) & 0x8)
        rm = (hw1 >> 3) & 0xF
        return 2, f"mov r{rd},r{rm}"

    return 2, f".hword 0x{hw1:04x}"


def disasm_range(data, vaddr, size, label=""):
    fileoff = vaddr_to_fileoff(vaddr)
    print(f"\n; {'=' * 70}")
    print(f"; {label}  vaddr=0x{vaddr:06x}  fileoff=0x{fileoff:06x}  size=0x{size:x}")
    print(f"; {'=' * 70}")
    pos = fileoff
    end = fileoff + size
    while pos < end:
        cur_vaddr = TEXT_VADDR + (pos - TEXT_FILEOFF)
        sz, mnem = decode(data, pos, cur_vaddr)
        print(f"0x{cur_vaddr:06x}:  {mnem}")
        pos += sz


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--func', default=None,
                   help=f"Function to disassemble. Known: {list(KNOWN_FUNCTIONS)}")
    p.add_argument('--vaddr', default=None, help="Start vaddr (hex)")
    p.add_argument('--size',  default=None, help="Size in bytes (hex or dec)")
    args = p.parse_args()

    data = BINARY.read_bytes()

    if args.vaddr:
        vaddr = int(args.vaddr, 0)
        size  = int(args.size, 0) if args.size else 0x80
        disasm_range(data, vaddr, size, label=f"0x{vaddr:06x}")
    elif args.func:
        if args.func not in KNOWN_FUNCTIONS:
            import sys; sys.exit(f"Unknown: {args.func}")
        vaddr, size = KNOWN_FUNCTIONS[args.func]
        disasm_range(data, vaddr, size, label=args.func)
    else:
        for name, (vaddr, size) in KNOWN_FUNCTIONS.items():
            disasm_range(data, vaddr, size, label=name)


if __name__ == '__main__':
    main()
