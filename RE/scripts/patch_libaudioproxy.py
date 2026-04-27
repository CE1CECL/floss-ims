#!/usr/bin/env python3
"""
Patch libaudioproxy.so: NOP out the proxy_mode range-gate in proxy_open_capture_stream.

The gate at vaddr 0xaa46 (file offset 0x9a46) is a `bhi 0xaae0` that skips
ALSA mixer-path arming when global_proxy->field_0x38 is outside [17..23].
For SIP calls the mode is never in that range, so the mic ADC stays disarmed.
Replacing the branch with NOP16 (0xBF00) makes the arming unconditional.

Usage:
    python3 scripts/patch_libaudioproxy.py [--apply]

Without --apply the script only validates the expected bytes and exits.
"""

import shutil, sys
from pathlib import Path

BINARY  = Path(__file__).parent.parent / "binaries" / "libaudioproxy.so"
PATCHED = Path(__file__).parent.parent / "binaries" / "libaudioproxy_patched.so"

# vaddr 0xaa46; .text vaddr 0x1000 → fileoff 0x0000  ⟹  fileoff = vaddr - 0x1000
PATCH_OFFSET   = 0x9a46
EXPECTED_BYTES = bytes([0x4B, 0xD8])   # bhi 0xaae0
NOP16          = bytes([0x00, 0xBF])   # NOP (Thumb-16, 0xBF00 little-endian)


def verify(data: bytes) -> None:
    found = data[PATCH_OFFSET : PATCH_OFFSET + 2]
    if found != EXPECTED_BYTES:
        sys.exit(
            f"Unexpected bytes at 0x{PATCH_OFFSET:x}: "
            f"got {found.hex()} expected {EXPECTED_BYTES.hex()}\n"
            "Binary may already be patched or does not match the expected version."
        )
    print(f"[OK] Verified: bytes at 0x{PATCH_OFFSET:x} = {found.hex()} (bhi 0xaae0)")


def apply_patch(data: bytearray) -> None:
    data[PATCH_OFFSET : PATCH_OFFSET + 2] = NOP16
    print(f"[OK] Patched:  bytes at 0x{PATCH_OFFSET:x} = {NOP16.hex()} (NOP16)")


def main() -> None:
    apply = "--apply" in sys.argv

    raw = BINARY.read_bytes()
    verify(raw)

    if not apply:
        print("Dry-run complete.  Pass --apply to write the patched binary.")
        return

    buf = bytearray(raw)
    apply_patch(buf)

    shutil.copy2(BINARY, BINARY.with_suffix(".so.orig"))
    print(f"[OK] Backup:   {BINARY.with_suffix('.so.orig')}")

    PATCHED.write_bytes(buf)
    print(f"[OK] Written:  {PATCHED}")
    print()
    print("Next steps:")
    print("  adb root && adb remount")
    print(f"  adb push {PATCHED} /vendor/lib/libaudioproxy.so")
    print("  adb reboot")


if __name__ == "__main__":
    main()
