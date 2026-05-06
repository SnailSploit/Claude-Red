---
name: offensive-iot-hardware-recon
description: "IoT hardware reconnaissance methodology — PCB visual inspection, SoC and chipset identification by markings, flash chip identification (SPI NOR, eMMC, NAND, NOR by package), debug header discovery (UART, JTAG, SWD test points and pads), boundary-scan via JTAG ID code, voltage rail identification with multimeter, and pre-attack power/RF profiling with logic analyzer. Use as the first step in any embedded device assessment before any firmware extraction or runtime attack."
---

# IoT Hardware Reconnaissance

The first phase of an embedded assessment. Identify the chips, the buses, and the debug interfaces — without this, every subsequent attack guesses.

## Quick Workflow

1. Photograph PCB top and bottom in good light
2. Identify SoC, flash, RAM, radios by package markings
3. Identify candidate debug interfaces (UART/JTAG/SWD pads)
4. Probe voltage rails with multimeter (don't connect anything yet)
5. Capture initial logic-analyzer trace of suspected debug pins

---

## PCB Inspection

Open the device — most consumer IoT uses 4 Phillips screws or plastic clips. ESD precautions matter for boards with unmarked passives.

### What to Photograph

- Full board top — all components visible
- Full board bottom — silkscreen often labels test points
- SoC close-up — read every line of the chip marking
- Flash close-up — read the chip identifier
- Connectors and headers — populated and unpopulated

### SoC Identification

Common consumer/SOHO chipsets and their characteristic identifiers:

| Vendor | Marking pattern | Use |
|---|---|---|
| Realtek | RTL8xxx, RTL81xx | Wi-Fi routers, IP cams |
| MediaTek | MT76xx, MT79xx | Routers, mesh nodes |
| Broadcom | BCM43xx, BCM47xx | Routers, smart speakers |
| Espressif | ESP8266, ESP32, ESP32-S3 | Smart-home devices, sensors |
| Qualcomm | IPQxxxx, QCAxxxx | High-end routers |
| Allwinner | Hxxx, Axxx | Tablets, dev boards, no-name IoT |
| Rockchip | RKxxxx | Tablets, set-tops |
| ST Microelectronics | STM32xxx | Industrial / medical / appliance MCUs |
| NXP | LPCxxxx, MK6x | Automotive, industrial |
| TI | CC25xx, CC26xx, CC13xx | Zigbee/Thread/BLE/Sub-GHz radios |
| Nordic | nRF52xxx, nRF53xxx | BLE peripherals |
| Microchip | PIC24, PIC32, ATtinyXX | Cheap embedded |

Cross-reference the chip's number with the vendor datasheet. Datasheets give:
- Pin assignments (which pin is UART TX/RX, which is JTAG TCK)
- Boot mode pins (which pin held high/low forces ROM bootloader)
- Available debug protocols
- Voltage requirements

## Flash Chip Identification

Most consumer IoT uses one of:

### SPI NOR Flash (8-pin SOIC)

| Marking | Capacity | Notes |
|---|---|---|
| W25Q xx | Winbond, 1–256MB | Most common |
| MX25L xx | Macronix | Common |
| EN25Q xx | Eon Silicon | Cheaper devices |
| GD25Q xx | GigaDevice | Cheap and ubiquitous |

Pin 1 indicator (dot or notch on top). Pinout: `CS, MISO, WP, GND, MOSI, CLK, HOLD, VCC` on most 8-pin SOICs.

### eMMC (BGA-153 or BGA-169)

Markings typically include `eMMC` and a vendor (Samsung, SK Hynix, Kingston, Micron). Capacity usually printed (4G, 8G, 16G, 32G).

Removal: hot-air rework station; reflow at 250°C, lift gently.

### NAND Flash (TSOP-48 or BGA)

Less common in consumer; common in industrial / older devices. Identifiable by larger package and vendor markings (Toshiba, Samsung, Hynix).

## Debug Interface Discovery

### UART

Look for 3-4 unpopulated through-holes near the SoC. Standard pinout:

```
TX  RX  GND  VCC (3.3V or 1.8V)
```

Sometimes labeled, sometimes not. UART pads on board often have:
- Larger pad size than nearby pads
- Through-hole even when most components are SMD
- Silkscreen markings: `J1`, `J2`, `TP1`, `CON1`, `DBG`, `SERIAL`

Verify with multimeter:
- GND continuous to chassis ground
- VCC reads 3.3V (or 1.8V) when device powered
- TX has activity (varying voltage) on boot
- RX is high-Z when device is not receiving

### JTAG

10-pin or 14-pin connector pattern. Pinout varies by SoC; common ARM Cortex JTAG:

```
1  VTRef    2  N/C
3  TRST     4  GND
5  TDI      6  GND
7  TMS      8  GND
9  TCK     10  GND
11 RTCK    12  GND
13 TDO     14  GND
15 RST     16  GND
17 N/C     18  GND
19 N/C     20  GND
```

JTAG test points are sometimes scattered across the board, not in a connector. Use a logic analyzer to probe candidate pads on power-up — JTAG idle clock at boot identifies the TCK pin.

### SWD (ARM Cortex-M)

Two pins: `SWDIO` and `SWCLK`. Plus reset and ground. Cortex-M MCUs ubiquitously expose SWD; the question is whether it's locked (RDP protection).

Probe MCU pin 50 (SWDIO) and pin 49 (SWCLK) on STM32F1, etc. — datasheet specifies.

## JTAG Boundary Scan ID

Even without datasheet:

```bash
# UrJTAG / OpenOCD JTAG enumeration
openocd -f interface/jlink.cfg -c "jtag init; scan_chain"
# Returns IDCODE for chips on chain → search vendor:device
```

JTAG IDCODE database: jtag.cdkbz.cz, openocd.org, vendor-specific tools.

## Voltage Rail ID

Before connecting anything:

```
1. Multimeter on resistance mode — verify chassis ground continuity
2. Multimeter on 20V DC — measure each candidate VCC pin while device runs
3. Identify rails: 5V (USB), 3.3V (SoC core/IO), 1.8V (some IO), 1.0V (modern SoC core)
4. Note which rails are present in standby vs running
```

Connecting 5V to a 1.8V pin destroys the chip. Always verify.

## Logic Analyzer

Cheap USB analyzers (Saleae clones at $10–20) capture 8 channels at 24 MS/s — enough for UART/SPI/I²C and slow JTAG.

```bash
# sigrok-cli with fx2lafw clone
sigrok-cli -d fx2lafw --config samplerate=12MHz --channels D0,D1,D2,D3 \
  --frames 10 --output-format csv > capture.csv

# Or use PulseView GUI to visually identify protocols
pulseview
```

Identify:
- UART by start-stop pattern at known bauds
- SPI by clock + data signals on flash chip pins
- I²C by 9-bit pattern with ACK on 9th
- JTAG by 4-clock idle + TMS-driven state machine

## Radio Identification

Look for separate radio modules near the antenna:

- Wi-Fi: shielded module with crystal, often integrated SoC
- BLE: small module (Nordic nRF, TI CC26xx, Espressif ESP32)
- Zigbee/Thread: TI CC2xxx, Silicon Labs EFR32
- LoRa: Semtech SX1276/1278/1262
- Cellular: Quectel, Sierra Wireless, Telit modems with SIM slot
- Sub-GHz: TI CC11xx, ADF7xxx

The radio module's markings tell you the protocol stack you're attacking.

## Engagement Cheatsheet

```
[ ] Photograph PCB top + bottom
[ ] Identify SoC, RAM, flash, radios
[ ] Find candidate UART pads (3-4 holes, 0.1" spaced typical)
[ ] Find candidate JTAG/SWD test points
[ ] Multimeter: GND, voltage rails, TX activity
[ ] Logic analyzer capture on power-up: identify protocols
[ ] Cross-reference SoC datasheet for exact pin assignments
[ ] Document: chip → datasheet URL → pin map → debug interface located
```

## Detection / Anti-Tamper

Some devices have:
- Tamper switches on the case (battery-backed; opens trigger erase)
- Secure boot fuses (anti-rollback)
- Conformal coating obscuring components (acetone removable on some)
- Epoxy potting (heat or solvent removal)

Document anti-tamper before opening. For high-value targets, consider X-ray imaging before destructive analysis.

---

## Key References

- IoT Hackers Handbook (Aditya Gupta)
- "Hardware Hacking: Have Fun While Voiding Your Warranty" (Joe Grand)
- Datasheets — SoC vendor sites, alldatasheet.com
- jtag.cdkbz.cz — JTAG IDCODE database
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
