# Reverse Engineering — Samsung Exynos3830 Audio HAL

Goal: understand why `AudioRecord` with `VOICE_COMMUNICATION` source produces silence
during a SIP/VoLTE call on Samsung A21s (SM-A217F, Exynos 850).

## Binaries

| File | Source on device | Size |
|------|-----------------|------|
| `binaries/libaudioproxy.so` | `/vendor/lib/libaudioproxy.so` | ~64 KB |
| `binaries/audio.primary.universal3830.so` | `/vendor/lib/hw/audio.primary.universal3830.so` | ~68 KB |

Refresh from a connected device: `bash scripts/pull_binaries.sh`

## Device audio topology (A21s, Exynos3830-Madera)

Three ALSA cards:

| Card | Name | Role |
|------|------|------|
| 0 | Exynos3830-Madera (Cirrus Logic CS47L92) | Main card — real mic + modem uplinks |
| 1 | aboxvdma | Abox DSP virtual DMA |
| 2 | aboxdump | Abox DSP debug |

Key capture PCMs on card 0:

| PCM | ID | What it is |
|-----|----|------------|
| pcm12c | WDMA0 | **Real microphone** via Abox DSP — 48 kHz |
| pcm13c–pcm16c | WDMA1–4 | Additional real capture paths |
| pcm110c–pcm129c | calliope_10–29 | **Modem/baseband uplink** (CP audio) — produces silence for software IMS |

During a SIP call, `AudioRecord` should open a WDMA path. If a calliope path opens instead
(visible in `/proc/asound/card0/pcm110c/sub0/status`), the hardware is routing to the
modem uplink and the captured audio will be silent.

## Root cause hypothesis

`libaudioproxy.so :: proxy_open_capture_stream` gates ALSA mixer path arming behind:

```
global_proxy->field_0x38  (proxy_mode)  ∈  [17 .. 23]
```

If `proxy_mode` is outside that range, the function skips `audio_route_apply_path` for
the primary capture path — mic ADC, amplifier, and mux controls are never written to the
ALSA mixer, so the capture stream opens but returns silence.

## proxy_mode computation — confirmed by RE of `audio.primary.universal3830.so`

Function at **vaddr 0x089b4** in `audio.primary.universal3830.so` reads
`hw_dev->field_0x114` (the Android `AudioManager` mode) and returns the Samsung internal
`proxy_mode` stored in `global_proxy->field_0x38`.

### Android mode → proxy_mode mapping

| Android mode | Value | proxy_mode | In [17..23]? | Mixer armed? |
|---|---|---|---|---|
| `MODE_IN_CALL` | 2 | **24–26** | NO | NO → mic silent |
| `MODE_IN_COMMUNICATION` | 3 | **20–23** _(conditional)_ | YES | YES → mic live |

### MODE_IN_CALL path (0x089cc–0x089e2)

```asm
0x089cc: cmp  r2, #2
0x089ce: bne  0x08a5c          ; ≠2: else branch
0x089d0: ldr.w r1,[r1,#0xa0]
0x089d4: movs r0,#0x18         ; return 24
0x089d6: cmp  r1, #3
0x089da: movs r0,#0x19         ; if r1==3: return 25
0x089de: movs r0,#0x1a         ; if r1==4: return 26
0x089e2: pop  {r4,pc}          ; → 24–26, ABOVE [17..23], guard FAILS
```

### MODE_IN_COMMUNICATION path (0x08a1e–0x08a86)

Returns a value in [17..23] only if **at least one aproxy sub-flag is set**:

```asm
0x08a1e: ldr.w r1,[r0,#0xf4]     ; r1 = aproxy ptr
0x08a22: cbz  r1,+0x1c           ; NULL → fallthrough
0x08a24: ldrb r2,[r1,#0x5]       ; aproxy->field_0x5
0x08a28: IT NE → movs r0,#0x14   ; ≠0 → return 20 ✓
0x08a2e: ldrb.w r2,[r1,#0x39]    ; aproxy->field_0x39
0x08a32: cmp  r2, #1
0x08a34: bne  0x08a70
0x08a36: ldr  r2,[r1,#0x18]      ; aproxy->field_0x18
0x08a3c: IT NE → movs r0,#0x17   ; ≠0x10 → return 23 ✓
0x08a70: ldr.w r1,[r0,#0x108]    ; hw_dev->field_0x108
0x08a74: movs r0,#0x16           ; return 22 ✓
0x08a7a: pop  {r4,pc}            ; field_0x108==0 → return 22
0x08a7c: ldr.w r1,[r1,#0xa0]
0x08a84: IT EQ → movs r0,#0x15   ; r1==1 → return 21 ✓
```

**Why the Telecom patch (`MODE_IN_COMMUNICATION`) didn't fix the mic:**
For SIP calls there is no modem involvement. The sub-flags (`field_0x5`, `field_0x39`,
`field_0x108`) are set by modem call state events and are all zero for software IMS calls.
With a NULL aproxy or all-zero sub-flags and `MODE_IN_COMMUNICATION`, the function falls
through to a default outside [17..23], so the guard still fails.

## ELF section maps

### libaudioproxy.so
| Section | vaddr | fileoff |
|---------|-------|---------|
| .text | 0x1000 | 0x0000 |
| .data | varies | vaddr − 0x3000 |

### audio.primary.universal3830.so
| Section | vaddr | fileoff |
|---------|-------|---------|
| .text | 0x7260 | 0x6260 |
| .got | 0x11704 | 0xf704 |

## Key libaudioproxy.so symbols

| Symbol | vaddr | size |
|--------|-------|------|
| `proxy_create_capture_stream` | 0x9ee8 | 1332 |
| `proxy_open_capture_stream` | 0xa9f0 | 1024 |

### pcm_config for AudioSource.VOICE_COMMUNICATION (stream_type=11)

`proxy_create_capture_stream` inner switch at 0xa0ac, indexed by `ausage_param`:

- `ausage_param=1` (VOICE_COMM / MIC) → `AUSAGE=0x6e=110` → loads GOT[0x10a48] as `pcm_config` ptr

The pcm_config at GOT[0x10a48] determines sample rate and device:
- 48 kHz → `pcm_config_primary_capture` → real ADC path
- 32 kHz → `pcm_config_voicetx_capture` → modem uplink (silence)

GOT resolution requires parsing the packed Android `.rel.dyn` format; not yet completed.

### proxy_open_capture_stream TBB switch (0xaa6e)

Executes ALSA mixer path arming only when `global_proxy->field_0x38 ∈ [17..23]`.
For SIP calls this check fails → falls through to `pcm_open` without arming any mixer path.

## AudioSource → stream parameters (confirmed)

| AudioSource | stream_type | ausage_param |
|-------------|-------------|--------------|
| MIC (1) | 11 | 1 |
| VOICE_COMMUNICATION (7) | 11 | 1 |
| CAMCORDER (5) | 11 | 2 |
| VOICE_RECOGNITION (6) | 11 | 27 |
| VOICE_UPLINK (2) | 12 | 24 |
| VOICE_DOWNLINK (3) | 12 | 25 |

`VOICE_UPLINK`/`VOICE_DOWNLINK` are the modem call sources (stream_type=12).
All other sources including `VOICE_COMMUNICATION` use stream_type=11 with the same pcm_config.
Changing AudioSource alone cannot fix the silence.

## Dumps

- `dumps/proxy_create_capture_stream.asm` — raw disassembly text from r2 (rasm2), vaddr 0x9ee8

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/pull_binaries.sh` | Pull fresh .so files from connected device |
| `scripts/disasm_libaudioproxy.py` | Capstone-based Thumb-2 disassembly of libaudioproxy functions |
| `scripts/disasm_audio_primary.py` | Manual Thumb-2 decoder for audio.primary (no exported symbols) |

```sh
pip install capstone
python3 scripts/disasm_libaudioproxy.py
python3 scripts/disasm_audio_primary.py
python3 scripts/disasm_audio_primary.py --func proxy_mode_compute
python3 scripts/disasm_audio_primary.py --vaddr 0x089b4 --size 0xe0
```

## Who writes `global_proxy->field_0x38` (the gate)

Key fact: **`libaudioproxy.so` is NOT stripped** — it exports ~85 `proxy_*`
functions. `readelf --dyn-syms binaries/libaudioproxy.so` lists them all; the
updated `scripts/disasm_libaudioproxy.py --list` prints them with sizes.

### `proxy_set_route` (vaddr 0xbb84, 996 B) — the writer

Signature reconstructed from the prologue:

```
proxy_set_route(proxy*, r1=mode, r2=type, r3=delta)
```

The `field_0x38` / `field_0x3C` pair is written by two `strd` sites:

```asm
; "clear / no-route" sentinel — written on stop / reset
0x00bd0a:  movs r0,#0x24          ; 36
0x00bd0c:  movs r1,#0x26          ; 38
0x00bd0e:  cmp.w r8,#0xf          ; r8 = type
0x00bd12:  ite  hi
0x00bd14:    strdhi r1,r0,[sl,#0x44]   ; type >= 0x10 → slot 0x44 / 0x48
0x00bd18:    strdls r1,r0,[sl,#0x38]   ; type <  0x10 → slot 0x38 / 0x3C = (38,36)

; "install route" — writes the REAL mode
0x00bd0e… path reaching 0xbee6:
0x00beea:  strd r6,r8,[sl,#0x38]       ; proxy->0x38 = arg1 (mode),
                                       ; proxy->0x3C = arg2 (type)
```

Preceded by the transition-check at 0xbe1c:

```asm
0x00be1c:  ldr.w r1,[sl,#0x38]
0x00be20:  cmp  r1,#0x26               ; cleared sentinel?
0x00be24:  ldrne.w r2,[sl,#0x3c]
0x00be28:  cmpne r2,#0x24
0x00be2a:  bne  0xbeda                  ; not cleared → transition path (→ bl 0xbf68)
0x00be2c:  mov  r0,sl ; r1=r6 ; r2=r8 ; r3=r7
0x00be34:  bl   0xc24c                  ; install_route helper
0x00be38:  b    0xbee6                  ; → strd at 0xbeea
```

**So: `proxy->field_0x38 = arg1` of `proxy_set_route`**. The gate in
`proxy_open_capture_stream` (range [17..23]) is therefore satisfied iff the
caller passes `mode ∈ [17..23]` — which is precisely the Samsung proxy_mode
computed by audio.primary at 0x089b4.

### `proxy_set_audiomode` (vaddr 0xd66c, 228 B) — NOT the gate writer

```asm
0x00d670:  mov  r4,r1                   ; r4 = arg1 = Android audio_mode
0x00d672:  movw r1,#0x1f8c
0x00d676:  movt r1,#1                   ; r1 = 0x11f8c
0x00d67a:  mov  r5,r0                   ; r5 = arg0 = proxy
0x00d67c:  ldr  r0,[r0,r1]              ; r0 = proxy->[0x11f8c] (old mode)
0x00d67e:  add.w r8,r5,r1               ; r8 = &proxy->[0x11f8c]
…
0x00d6de:  str.w r4,[r8]                ; proxy->[0x11f8c] = new Android mode
```

So `proxy_set_audiomode` stores the **raw Android `audio_mode_t`** into a
different field deep inside the giant proxy struct (`.data` range 0x11c84–0x123f4
matches — `proxy` is actually based at the library image; see note below). This
field is later READ by audio.primary's proxy_mode_compute (via
`hw_dev->field_0x114`) to decide what Samsung proxy_mode to pass to
`proxy_set_route`. Patching this path alone does not arm the gate.

Note on the `proxy[0x11f8c]` pattern: this is actually PC-relative access to a
.data global (`global_proxy` pointer slot at ~0x11f8c in .data), not a field on
the argument. The first arg is effectively used as a zero base for that specific
access. Semantically it is "save current Android mode to the global singleton".

### Observed chain of events during `set_mode`

1. Framework → `adev_set_mode(dev, MODE_IN_COMMUNICATION=3)`.
2. audio.primary sets `hw_dev->field_0x114 = 3` and calls
   `proxy_set_audiomode(global_proxy, 3)`.
3. audio.primary calls the function at **0x089b4** (proxy_mode_compute) — returns
   a Samsung proxy_mode based on `hw_dev->field_0x114` + aproxy sub-flags
   (`field_0x5`, `field_0x39`, `field_0x108`).
4. audio.primary calls `proxy_set_route(global_proxy, proxy_mode, type, delta)`
   → sets `global_proxy->field_0x38 = proxy_mode`.
5. Later, `proxy_open_capture_stream` checks `field_0x38 ∈ [17..23]` before
   arming the ALSA mixer path.

For a SIP call on stock HAL, step 3 returns a value **outside** [17..23]
because the aproxy sub-flags are zero — the `IT NE → movs r0,#0x14`
branches are never taken. Control falls through to the default
(returns 22 only if `hw_dev->field_0x108 != 0`, else… also 22, but `field_0x108`
is the "AP call active" indicator that IMS stack never toggles).

## Candidate fixes

Ordered from smallest / most targeted to most invasive.

### A — Patch `libaudioproxy.so` to remove the capture gate  (**recommended**)

In `proxy_open_capture_stream`:

```asm
0x00aa40:  ldr  r0,[r5,#0x38]
0x00aa42:  subs r0,#0x11
0x00aa44:  cmp  r0,#6
0x00aa46:  bhi  0xaae0               ; <-- 16-bit branch (2 B)
```

Overwrite the `bhi` at 0xaa46 with `BF00` (NOP16) — 2 bytes. The gate always
falls through to the mixer-arming path; whatever value `field_0x38` holds no
longer matters.

File offset: `0xaa46 - 0x1000 = 0x9a46` (libaudioproxy .text maps
vaddr 0x1000 → fileoff 0x0; but see §ELF section maps — .text is 0x7ab0 fileoff
0x6ab0, so real offset is `0xaa46 - 0x7ab0 + 0x6ab0 = 0x9a46`). Verify before
flashing.

Pros: minimal change, does not touch the much-larger audio.primary. Does not
depend on reproducing the aproxy-sub-flag setter logic.
Cons: all non-cellular capture will take the "armed" path even when the framework
thinks MODE_NORMAL — usually fine because path arming is idempotent and gated
further downstream, but needs verification.

### B — Patch `audio.primary.universal3830.so` at 0x089b4

Force proxy_mode_compute to always return 20 (0x14) for `field_0x114 ∈ {2, 3}`:

```
0x089cc: cmp  r2,#2
0x089ce: bne  0x08a5c     →  b    0x08a1e    ; fold MODE_IN_CALL into the
                                              ; MODE_IN_COMMUNICATION path
```

Then in the MODE_IN_COMMUNICATION path, replace
`ldr.w r1,[r0,#0xf4]; cbz r1,+0x1c; ldrb r2,[r1,#0x5]` with a hard
`movs r0,#0x14; pop {r4,pc}` so the return is unconditional.

Pros: fixes the root cause at the source.
Cons: larger change, must update both branches, risk of breaking other callers
that depend on the 24–26 range for CP calls.

### C — Native helper calling the exported `proxy_set_route`

Because `proxy_set_route` is an exported dynsym, a tiny JNI helper can:

```c
void* h = dlopen("/vendor/lib/libaudioproxy.so", RTLD_NOW);
void* proxy = ((void*(*)(void))dlsym(h, "proxy_init"))();
((int(*)(void*, int, int, int))dlsym(h, "proxy_set_route"))(proxy, 20, 0, 0);
```

Called once before `AudioRecord.startRecording()`, this forces `field_0x38 = 20`.
No binary patching required, but side effects of `proxy_set_route`
(`audio_route_apply_path`, mixer writes in the `bl 0xc24c` / `bl 0xbf68`
helpers) may clash with the HAL's own state machine.

## Open questions (updated)

1. ~~What sets `aproxy->field_0x5`?~~ — Deprioritized. Fix A bypasses the gate
   without reproducing the sub-flag logic. If we still need audio.primary's
   proxy_mode to be correct (e.g. for downlink routing), revisit by scanning
   audio.primary for `strb.w r?,[r?,#0x5]` / `#0x39` from functions reachable
   via `adev_set_parameters` / RIL callback hooks.
2. **What does GOT[0x10a48] resolve to?** — unchanged; needs `.rel.dyn`
   packed-relocation parsing to confirm pcm_config for stream_type=11.
3. **Are ALSA mixer controls for WDMA0 actually armed during a SIP call?** —
   unchanged; monitor `/proc/asound/card0/pcm12c/sub0/status` and the mixer
   controls `audio_diag.sh` dumps.
4. **Side effects of `proxy_set_route(proxy, 20, 0, 0)` from userspace** —
   needs rooted-device test: does `bl 0xc24c` (install_route) disturb playback
   state?
5. **Is fix A safe for playback paths?** — `proxy_open_capture_stream` is the
   only known consumer of field_0x38 in the range check. Grep playback
   equivalents (`proxy_open_playback_stream @ 0x89fd`) for similar gates before
   flashing.
