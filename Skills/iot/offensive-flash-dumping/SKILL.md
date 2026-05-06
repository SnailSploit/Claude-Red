---
name: offensive-flash-dumping
description: "Flash memory extraction methodology for embedded devices — SPI NOR in-circuit dumping with CH341A / Bus Pirate / flashrom, eMMC chip-off and BGA-to-SD adapter reading, NAND extraction with bit-flip and ECC handling, NOR EPROM reading, in-circuit vs desolder decision tree, post-extraction integrity verification, and conversion to mountable filesystems with binwalk. Use when device has no usable debug interface or when complete firmware extraction is required (versus runtime memory dump)."
---

# Flash Dumping

Pulling firmware off the chip directly. The most reliable extraction path when debug interfaces are locked, and the only path for some packages (eMMC, NAND).

## Quick Workflow

1. Identify flash type and package (see `offensive-iot-hardware-recon`)
2. Decide: in-circuit vs chip-off
3. Connect appropriate programmer
4. Dump full chip + verify checksum
5. Carry to firmware analysis (`offensive-firmware-analysis`)

---

## SPI NOR (Most Common — 8-pin SOIC)

### In-Circuit Dump (Easier — Try First)

The risk: SoC fights you on the bus. Solution: hold SoC in reset.

```
1. Connect CH341A test clip to flash chip
2. Connect VCC test clip to a 3.3V rail (not VCC of the chip — power flash externally only)
3. Hold SoC reset pin to GND through a wire
4. Power flash via CH341A's 3.3V output
5. Run flashrom
```

```bash
# Detect chip
flashrom -p ch341a_spi
# Identifies vendor:device:capacity from JEDEC ID

# Read
flashrom -p ch341a_spi -r firmware.bin

# Verify
file firmware.bin
binwalk firmware.bin
```

### Desolder + Read in Socket

When in-circuit fails (SoC contention):

1. Hot-air rework station at 250°C
2. Lift the 8-pin SOIC with tweezers
3. Place in CH341A socket adapter
4. Read with `flashrom -p ch341a_spi -r fw.bin`
5. Resolder to the board (or to a socket if you'll iterate)

### Common Quirks

- Some flashes need explicit chip name: `flashrom -p ch341a_spi -c W25Q64.V -r fw.bin`
- 1.8V SPI flashes (newer designs) need a 1.8V programmer — CH341A is 3.3V default
- Verify with two reads — bit-flips during in-circuit reads can occur

## eMMC

eMMC packages are BGA-153 / BGA-169. They speak MMC protocol and can be read through a BGA-to-SD adapter.

### Chip-Off (Standard Approach)

1. Hot-air rework at 250–280°C — eMMCs survive higher temperatures than SPI flash
2. Lift with vacuum tweezers; clean residual solder with braid
3. Place in BGA-to-SD reader (~$10 on AliExpress)
4. Insert reader into a USB SD card reader
5. Read with `dd`:

```bash
sudo dd if=/dev/sdX of=emmc.bin bs=4M status=progress
# Will be 4–32 GB depending on capacity
```

### eMMC Boot Partition

eMMCs have a special **boot partition** (BOOT0/BOOT1) used by some SoCs:

```bash
# Linux exposes boot partitions as /dev/sdX_boot0, /dev/sdX_boot1
sudo dd if=/dev/sdXboot0 of=emmc_boot0.bin
sudo dd if=/dev/sdXboot1 of=emmc_boot1.bin
```

These contain bootloaders / secure boot stages that the user partition doesn't.

### In-System with USB Mass Storage Mode

Some SoCs support a "USB MSC" boot mode that exposes eMMC over USB without chip-off:

```bash
# Allwinner: hold FEL pin during boot → device shows as USB device
sunxi-fel uboot u-boot-sunxi-with-spl.bin

# Rockchip: maskrom mode
rkdeveloptool ld
rkdeveloptool rd 0
rkdeveloptool er 0 1
```

Per-vendor: research the device's bootrom modes before chip-off.

## NAND Flash (TSOP-48 / BGA)

NAND is harder than NOR because:
- Bit-flips are normal — ECC required to recover
- Bad blocks are normal — wear leveling expected
- Page + spare-area structure differs by manufacturer

### Tools

```bash
# Hardware: dedicated NAND programmer (XGecu T48, FlashcatUSB)
# Or open-source via FT2232H + nandrl

# Read with proprietary programmer software (vendor-specific)
# Output: raw NAND with spare bytes per page

# Reconstruct logical filesystem
ubireader_extract_files ubi.bin -o rootfs/
jefferson jffs2.bin -d rootfs/
nanddump --noecc --omitoob -f /dev/mtd0 nand.bin   # if device exposes /dev/mtd*
```

NAND extraction typically requires desolder + dedicated programmer. Plan time and budget accordingly — NAND on consumer IoT is rarer than SPI NOR or eMMC.

## NOR Parallel Flash (TSOP-48)

Used in older industrial / automotive devices. Standard parallel-bus interface.

```bash
# Use a universal programmer like XGecu T48 with the appropriate adapter
# Configure for the chip's manufacturer + part number
# Read full chip image
```

## SoC-Internal Flash

For MCUs (STM32, ESP32, etc.) with on-chip flash, see `offensive-uart-jtag-swd` — JTAG/SWD or ROM bootloader is the path.

## Verification

Always verify flash dumps:

```bash
# Two reads should match
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin
sha256sum dump1.bin dump2.bin

# binwalk should find recognizable signatures
binwalk firmware.bin

# Entropy plot — large flat regions = encrypted/compressed; gradient = plaintext data
binwalk -E firmware.bin
```

If `binwalk` finds nothing recognizable:
- Flash may be encrypted (look for vendor-specific encryption hints in datasheet)
- Image may be wrapped in a custom header — strip first 0x100/0x200 bytes and re-binwalk
- Bad read — try again with chip-off if in-circuit, or flip Vcc rail

## Common Encrypted-Flash Vendors

| Vendor | Encryption | Recovery Path |
|---|---|---|
| Espressif ESP32 (with flash encryption enabled) | AES-256 | Recover key via fault injection on boot ROM |
| Many automotive ECUs | Vendor-specific | Reverse engineer bootloader's decryption routine |
| Cisco / Juniper | Vendor key | Out of scope without vendor cooperation |

## Engagement Cheatsheet

```bash
# 1. Identify flash chip (recon phase)

# 2. SPI NOR — in-circuit dump first
flashrom -p ch341a_spi -r fw.bin
# If contention errors: hold SoC reset, retry; or desolder

# 3. eMMC — desolder + BGA-to-SD reader
sudo dd if=/dev/sdX of=emmc.bin bs=4M status=progress
sudo dd if=/dev/sdXboot0 of=emmc_boot.bin

# 4. NAND — dedicated programmer, ECC handling, bit-flip recovery

# 5. Verify
binwalk fw.bin
binwalk -E fw.bin
sha256sum fw.bin

# 6. Hand off to offensive-firmware-analysis
```

## Anti-Tamper

| Defense | Bypass |
|---|---|
| Encrypted flash | Recover key via boot-ROM bus snooping or fault injection |
| Tamper switch (battery-backed RAM erase) | Identify and bypass before opening case |
| Conformal coating | Solvent (acetone for some) before desolder |
| Epoxy potting | Heat or solvent removal — destructive |
| BGA-only package with no test points | Chip-off required |

---

## Key References

- flashrom project: flashrom.org
- "Practical Hardware Pentesting" (Henrik Lange Petersen)
- ESP32 Flash Encryption documentation
- iCEStick / Glasgow Interface Explorer for open-source dumping
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
