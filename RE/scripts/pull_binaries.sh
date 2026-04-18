#!/bin/bash
# Pull Samsung audio HAL binaries from a connected device.
# Run from the RE/ directory: bash scripts/pull_binaries.sh
set -e
adb root
sleep 1
adb pull /vendor/lib/hw/audio.primary.universal3830.so binaries/audio.primary.universal3830.so
adb pull /vendor/lib/libaudioproxy.so binaries/libaudioproxy.so
echo "Pulled:"
ls -lh binaries/*.so
