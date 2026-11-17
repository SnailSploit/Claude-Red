---
name: offensive-flipper-zero
description: "Flipper Zero as a red-team tool: sub-GHz capture/replay (fixed-code vs rolling-code/KeeLoq caveats), 125kHz RFID and iButton read/clone, NFC read/emulate, BadUSB payload delivery, and GPIO addon usage (nRF24 + sub-GHz boards). Covers direct serial-CLI control of the device from a PC session (no companion app required), DFU/FUS firmware recovery, and a hardcoded risk-tier action gate scoping all use to equipment and premises the operator is explicitly authorized to test. Use for physical-access red team engagements, access-control/badge testing, and authorized office/facility security assessments."
---

# Flipper Zero — Offensive Testing & Direct Control

## Scope Gate (read first, every session)

This device trivially captures and replays signals from equipment its operator does not own or administer. Before running ANY action below, classify it:

| Tier | Examples | Rule |
|---|---|---|
| **Low** | `device_info`, reading a signal/card to screen only, listing captured files | Always allowed |
| **Medium** | Saving a capture, cloning a card/fob **you possess and own or are the administrator of** | Allowed, confirm ownership first |
| **High** | Replaying a sub-GHz/RFID capture, running a BadUSB payload against a target machine | Allowed only against equipment confirmed in scope (your own office door, your own badge, your own test laptop) — confirm the specific target each time, not once per session |
| **Blocked** | Anything involving a third party's badge/fob/vehicle/device, a neighbor's garage door, any system you administer but haven't gotten explicit written authorization to test, or any capture made outside premises you control | Refuse, state why |

Rolling-code systems (most modern car fobs, KeeLoq rolling-code variants, many newer garage openers) cannot be meaningfully "replayed" after a single capture by design — don't present a captured rolling-code signal as clonable; say so and move on. Fixed-code systems (many older garage/gate remotes, cheap wireless doorbells, simple RF remotes) replay as-is — these are the one legitimately useful "capture → clone/replay" workflow for authorized testing of your own equipment.

---

## Quick Workflow

1. **Confirm target is in scope** (your office, your badge, your equipment) per the gate above
2. **Identify the technology**: sub-GHz remote/fob, 125kHz RFID badge, 13.56MHz NFC/Mifare badge, iButton, or a target PC (BadUSB)
3. **Read before you write/clone/replay** — always capture and inspect first
4. **Capture → save → (if authorized) clone or replay**
5. **Log what was tested** — device, frequency/protocol, timestamp, result — for the engagement report

---

## Direct Serial-CLI Control (no companion app)

The Flipper exposes a plain-text CLI over its USB CDC-ACM serial port (`VID_0483:PID_5740`, enumerates as a COM port on Windows, `/dev/ttyACM*` on Linux/macOS). This is the same interface `pyFlipper`, `AgentFlipper`, and `promptzero` all wrap — talk to it directly instead of installing a second app with its own API key.

```
baud: any (USB CDC, baud is ignored by the device but most tools set 115200)
newline: \r or \r\n
```

### Connecting (PowerShell / .NET SerialPort — verified working pattern)

```powershell
$p = New-Object System.IO.Ports.SerialPort('COM11', 115200)
$p.ReadTimeout = 2000
$p.WriteTimeout = 2000
$p.DtrEnable = $true   # required — without this, the device never prints to the port on open
$p.RtsEnable = $true
$p.Open()
Start-Sleep -Milliseconds 1200   # device reboots/re-announces CLI banner on DTR assert; let it settle
# Reads work reliably at this point: boot banner + "Firmware version: ..." + ">: " prompt
# arrives automatically without sending anything.
```

**Known open issue (unresolved as of 2026-11-17, mntm-012, Windows 11, driver `usbser.sys`):** reads from the port work fine (banner, version, prompt all arrive), but `SerialPort.Write()` calls to send a command consistently fail with `"The semaphore timeout period has expired"` — on the first write and every subsequent one, regardless of delay, DTR/RTS state, or whether qFlipper is running (confirmed it wasn't). A raw Win32 `CreateFile`/`WriteFile` handle was tried as a workaround and also returned a failed write (needs proper `OVERLAPPED` struct handling, not attempted yet — that's the next thing to try, not a plain synchronous handle). This blocks sending CLI *commands* from this PC right now; read-only telemetry (banner/version on connect) works. **Before relying on chat-driven command execution against this device, fix this write path first** — candidates, in order to try: (1) proper overlapped `WriteFile` with an `OVERLAPPED` struct and `GetOverlappedResult`, (2) `python -m serial` (pyserial) instead of .NET `SerialPort` — pyserial's Windows backend handles this device class differently and is what `pyFlipper`/`AgentFlipper` actually use, (3) a different USB cable/port (ruled out as likely cause since reads work over the same physical link), (4) check for a stale/competing handle from a previous session not fully closed.

### Command reference (once writes work)

```
help                        # list all commands
device_info                 # firmware version, hw revision, serial
power info                  # battery status
storage list /ext           # list SD card contents
storage read /ext/subghz/<file>.sub
subghz tx_from_file /ext/subghz/<file>.sub   # HIGH tier — replay, confirm target first
subghz rx <frequency>       # capture, e.g. subghz rx 433920000
nfc detect                  # LOW tier — read-only NFC probe
ibutton read                # LOW tier
badusb                      # requires .txt ducky-script payload on SD, then run via UI/CLI — HIGH tier
```

Full CLI reference: [docs.flipper.net/development/cli](https://docs.flipper.net/development/cli)

---

## Sub-GHz (433/315/868 MHz remotes, fobs, sensors)

- **Fixed-code** (most garage remotes pre-2000s, cheap doorbells, simple RF switches): capture once with `subghz rx <freq>`, save, replay with `tx_from_file`. This is a genuine clone.
- **Rolling-code / KeeLoq rolling** (most car fobs, modern garage openers): a single capture is a used code, not reusable. Flipper's "rolling code" apps generally only demo the concept (jam-and-capture classes of attack) — don't frame a casual capture as a working clone of these.
- De-Bruijn / brute-force attacks on fixed 8–12 bit codes (old garage doors) are a real and fast attack against **your own** old garage door opener — confirm it's actually yours before running.
- GPIO 4-in-1 addon extends range/frequency coverage for sub-GHz beyond the stock internal antenna — same capture/replay workflow, just better RF reach.

## 125kHz RFID (most building access badges — HID Prox, EM41xx, Indala)

```
LOW:    rfid read               # identify card type, read UID to screen
MEDIUM: rfid read → save         # clone to T5577 if you own the badge/are the admin
HIGH:   write cloned card to a physical T5577 blank, test against a reader you administer
```

HID Prox and EM41xx are unencrypted, fixed-ID — reading one you're authorized to test fully clones it. This is the single most useful "test your own office" capability on this device: read your own badge, confirm it clones, confirm whether the reader itself can tell the difference (most can't without facility-code validation on the backend — that finding is the actual deliverable for the engagement).

## NFC / 13.56MHz (Mifare Classic/DESFire badges, some newer access cards)

- `nfc detect` / read UID — low tier, always fine
- Mifare Classic key recovery (nested/darkside attacks) — only against cards you own; this takes minutes and reveals sector keys, genuinely demonstrates weak crypto if the badge system uses Classic instead of DESFire/Plus
- DESFire / Mifare Plus in secure mode: Flipper cannot break these outright — a finding that your badge system already uses them is a "no finding," not a tool limitation to work around

## iButton (older access systems, Dallas/Maxim 1-Wire)

Fixed, unencrypted ID — read and clone trivially. Same authorization rule: only your own fobs/readers.

## BadUSB

- Ducky-script `.txt` payloads on SD card, run against a **target machine you own or have written authorization to test** — this is the highest-risk tier here because it executes arbitrary keystrokes on whatever it's plugged into
- Standard payload categories: credential harvesting demo, exfil-via-clipboard, privilege-escalation chain triggers — build these to demonstrate a finding (e.g. "USB ports aren't locked down, unattended machine took a payload in 4 seconds"), not to actually exfiltrate anything
- Always test against your own test laptop first before running near production office equipment

## GPIO Addon (4-in-1: nRF24 + sub-GHz + extras)

- nRF24: 2.4GHz proprietary protocols — wireless keyboard/mouse sniffing and injection (`mousejack`-style), BLE-adjacent IoT device probing. Scope to your own peripherals/devices.
- Extended sub-GHz: same workflow as internal radio, better range/sensitivity for site survey of what's actually broadcasting around your office (garage remotes, wireless sensors, tire-pressure monitors in the parking lot — recon-only unless you own the device)

---

## DFU / Firmware Recovery (if the device bricks or a flash goes wrong)

1. **Entering DFU**: On-device `Settings → Power → Reboot → Firmware Upgrade`, or hold LEFT+BACK 5s then release BACK keeping LEFT held until blue LED. Hard-bricked (no screen): unplug, hold OK+BACK 30s, replug.
2. **Confirm DFU**: Device Manager shows `USB\VID_0483&PID_DF11` ("DFU in FS Mode"). If it shows `ConfigManagerErrorCode 28`, no WinUSB driver is bound — use Zadig against the DFU interface.
3. **Flash via qFlipper-cli** (`C:\Program Files\qFlipper\qFlipper-cli.exe`), headless, no GUI needed:
   ```
   qFlipper-cli.exe firmware <path>\firmware.dfu      # Core1 main firmware
   qFlipper-cli.exe core2radio <path>\radio.bin        # Core2 BLE/sub-GHz radio stack
   ```
   Bare `qFlipper-cli.exe` (no args) does a quick update/repair but **only against official stock Flipper firmware channels** (`-c release|rc|dev`) — it does not accept third-party packages like Momentum/Unleashed/RogueMaster. For those, always use the two explicit subcommands above with files extracted from the vendor's own `flipper-z-f7-update-<tag>.tgz`.
4. **`core2radio` "Can't start FUS: Unexpected FUS state" error**: confirmed transient on a real device (2026-11-17, mntm-012) — re-running the identical `core2radio` command once immediately after the failure succeeded clean ("All done! Thank you."). This matches ST's own forum guidance that CPU2's FUS state machine can report a false "not idle" on first contact after a Core1 flash. **Do not** attempt manual FUS stop/erase/upgrade register commands as a first response — those are the genuine brick risk on this chip (STM32WB55); a plain retry is the documented-safe first move. If a second clean retry also fails, stop and get a real ST-forum/Flipper-support confirmed procedure before going further — don't improvise against the radio coprocessor.
5. **Verify**: device leaves DFU, re-enumerates as `0483:5740` on a COM port, CLI banner reports the expected firmware tag on connect.
6. **Resources sync** (dolphin assets/bundled apps) isn't covered by the two-command flash above — either let the device's own "update resources" prompt run on next boot (clear with physical buttons), or push `resources.tar.gz` via the storage protocol once serial writes are working (see open issue above).

Firmware choice: Momentum (`Next-Flip/Momentum-Firmware` on GitHub) is the actively-maintained, broadly-compatible pick for a GPIO 4-in-1 (nRF24 + sub-GHz) setup — best balance of plugin ecosystem and upstream stability versus RogueMaster (more baked-in BadUSB payload presets, less stable upstream) or Unleashed. Always download the release fresh from the vendor's GitHub releases page rather than reusing an old local file of uncertain provenance.

---

## References

- [docs.flipper.net](https://docs.flipper.net) — official docs, CLI reference, firmware recovery procedure
- [Next-Flip/Momentum-Firmware](https://github.com/Next-Flip/Momentum-Firmware) — firmware releases
- [djsime1/awesome-flipperzero](https://github.com/djsime1/awesome-flipperzero) — curated firmware/payload/hardware-mod list (144+ resources, not vendored here — check the list directly for current payload repos)
- [elder-plinius/V3SP3R](https://github.com/elder-plinius/V3SP3R) — risk-tier action-gating concept (this skill's Scope Gate is modeled on its low/medium/high/blocked pattern)
- [mattyspangler/AgentFlipper](https://github.com/mattyspangler/AgentFlipper) — PyFlipper + local-LLM serial control reference architecture
- ST Community forums — STM32WB55 FUS state machine behavior and recovery reports (search `FUS state` on `community.st.com`)
