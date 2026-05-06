---
name: offensive-fault-injection
description: "Fault injection (glitching) attack methodology for embedded systems — voltage glitching, clock glitching, electromagnetic fault injection (EMFI), laser fault injection (LFI), tooling with ChipWhisperer-Lite/Husky / PicoEMP / custom MOSFET crowbar, target identification (signature checks, RDP read, fuse reads), glitch parameter sweeping (delay, width, voltage), success-rate quantification, and when to apply (RDP bypass, secure-boot signature corruption, JTAG re-enable, OTP read). Use against secure boot, RDP-locked microcontrollers, anti-rollback fuses, and any target where a signature/CRC check stands between you and the firmware."
---

# Fault Injection / Glitching

When the chip refuses to give up its firmware via JTAG, ROM bootloader, or chip-off, fault injection corrupts a single instruction execution at a known time — turning a `verify_signature == OK` check into "OK regardless." Modern non-trivial; legacy and low-cost devices remain glitchable.

## Quick Workflow

1. Identify the target instruction (signature check, fuse read, RDP enforcement)
2. Find a timing reference (UART output, GPIO toggle, power signature)
3. Choose injection method (voltage / clock / EM)
4. Sweep glitch parameters (delay, width, voltage)
5. Quantify success rate; iterate until reliable

---

## Tooling

| Tool | Cost | Capability |
|---|---|---|
| **ChipWhisperer-Lite** | $250 | Voltage glitch + power analysis, education-targeted |
| **ChipWhisperer-Husky** | $1500 | Pro-grade, faster sample rate, higher-precision glitches |
| **PicoEMP** | $50 (DIY) | Cheap EM fault injection coil + capacitor bank |
| **MOSFET crowbar (custom)** | <$20 | Voltage glitch via shorting Vcc to ground briefly |
| **EM probes + arbitrary function gen** | $$$$ | Pro EMFI without packaged tooling |
| **Laser fault injection rig** | $$$$$ | Final-resort, micron-precision; requires decapsulated chip |

For a first-time glitching effort: start with ChipWhisperer-Lite + the manufacturer's tutorials. Pre-built setup, well-documented targets (XMEGA, STM32F0, etc.) save weeks of debugging.

## Voltage Glitching

Briefly drop Vcc on the target SoC during the moment a critical instruction executes. The dropped voltage causes the instruction to misexecute (often silently — wrong register written, wrong comparison result).

```
        Vcc level
           ─────────────╮  ╭──────────────
                        │  │
                        │  │
                        ╰──╯
                        ↑   ↑
                      drop  recover
                       (~50–500 ns wide)
```

```python
# ChipWhisperer Python — glitch a target STM32 RDP read
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope)
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'glitch_only'
scope.glitch.trigger_src = 'ext_single'

for delay in range(1000, 2000, 5):
    for width in range(10, 100, 2):
        scope.glitch.ext_offset = delay
        scope.glitch.repeat = width
        scope.arm()
        target.simpleserial_write('p', b'')
        scope.capture()
        response = target.simpleserial_read('r', 16)
        if response and response != EXPECTED_FAIL:
            print(f"GLITCH SUCCESS at delay={delay}, width={width}: {response.hex()}")
```

The glitch's `delay` (when relative to trigger) and `width` (how long Vcc stays low) are the primary tuning parameters. Sweep them to find the success window.

## Clock Glitching

Insert a short clock pulse (sub-cycle) that violates setup/hold timing, causing flip-flops to capture wrong data.

Suitable for chips where clock is externally driven and accessible. Less common on modern integrated SoCs with on-chip PLLs.

## Electromagnetic Fault Injection (EMFI)

Discharge a capacitor through a coil placed near the die; the magnetic pulse couples into chip internals and flips bits.

PicoEMP is the cheap entry point:

```python
# PicoEMP triggers on UART character or GPIO event,
# fires the coil with sub-microsecond precision
import picoemp
emp = picoemp.PicoEMP()
emp.charge_to(8000)
emp.fire_at_uart_char('A')   # fires when target UART emits 'A'
```

Advantages over voltage:
- Doesn't require connecting to the Vcc rail directly
- Localized to the chip area where probe is positioned
- Works through epoxy / conformal coating for most cases

## Common Targets

### RDP Bypass on STM32

The boot ROM reads the RDP byte from option bytes. Glitch the read so the RDP-enabled flag returns "disabled" → JTAG remains accessible at boot.

```
Sequence (simplified):
1. Power on → boot ROM starts
2. Boot ROM reads RDP option byte
3. (← glitch here) makes the read return 0xFF or 0xAA (RDP=disabled)
4. Boot ROM enables JTAG
5. Attacker reads firmware via JTAG

Tool: ChipWhisperer + STM32F0/F1 tutorials show full chains
```

### Secure Boot Signature Bypass

```
Sequence:
1. Bootloader computes hash of firmware
2. Bootloader compares hash to signed value
3. (← glitch here) turn the comparison into "equal" regardless
4. Unsigned firmware accepted
```

Targets: U-Boot signed-boot, ESP32 secure boot v1 (broken historically), older secure boot in industrial controllers.

### OTP / Fuse Read

ROM reads OTP fuses (containing keys, lock bits) via memory-mapped registers. Glitch the read to return zero or pre-glitch state, exposing keys.

### JTAG Re-enable

Some MCUs check a runtime flag for JTAG enablement. Glitch the check at boot to keep JTAG live for an additional N cycles → connect during the window.

## Glitch Parameter Sweeping

The glitch is reliable only within a small (delay, width) window. Build success-rate maps:

```python
results = {}
for delay in range(0, 5000, 10):
    for width in range(5, 200, 2):
        successes = 0
        for trial in range(10):
            apply_glitch(delay, width)
            if check_target_state() == 'compromised':
                successes += 1
        results[(delay, width)] = successes / 10

# Plot heatmap; bright spots = reliable glitch parameters
```

A 5–10% success rate is enough — repeat until success.

## Reliability Improvement

- **Stable temperature** (cooler chip = wider glitch window)
- **Fresh capacitors** for voltage glitchers (dielectric absorption matters)
- **Solid GND reference** (poor ground = scattered timing)
- **Timing reference from the chip itself** (UART character before target instruction is the gold standard)

## Decapsulation (Last Resort)

For laser fault injection or very precise EMFI, you decap the chip:

- **Acid decap**: nitric acid removes epoxy. Requires fume hood, hazmat handling, and skill.
- **Mechanical decap**: file or grind from the back of the package; less precise but lab-feasible.
- **Plasma etch**: cleanest, requires specialized equipment.

Decapped dies are inspected with an optical microscope to identify the security-critical regions, then targeted with focused EM probes or laser pulses.

## When NOT to Glitch

- Production timeline tight: glitching is iterative and slow
- High-value target with tamper-resistant chip (smart card secure elements): unlikely to succeed
- Easier path exists: try UART, JTAG, ROM bootloader, network, application layer first

## Engagement Cheatsheet

```
[ ] Identify target operation (RDP read, signature verify, fuse access)
[ ] Find a timing trigger (UART output, GPIO toggle, characteristic power profile)
[ ] Choose injection method (voltage cheapest; EM more flexible)
[ ] Set up tooling (ChipWhisperer for voltage/clock; PicoEMP for EM)
[ ] Sweep delay × width parameter space
[ ] Quantify success rate at best parameters
[ ] Iterate to reliable exploit (target ≥10% success rate)
[ ] Document: target chip, instruction targeted, glitch parameters, success rate
```

## Detection / Defenses

| Defense | Implication |
|---|---|
| Vcc monitor (rejects glitched values) | Pre-clear voltage stays in spec; glitch must be very fast |
| Clock monitor (similar) | Rejects out-of-spec clock events |
| Multiple-redundant signature checks | All N must be glitched simultaneously — exponentially harder |
| Tamper detection (case open / chip removal) | Erases keys before access possible |

## Reporting

Glitching findings include:
- Exact target chip + revision
- Specific operation glitched (with instruction-level reference if possible)
- Glitch tooling and parameters
- Reliability achieved (success rate, mean attempts to success)
- Practical impact (firmware extraction? key recovery? RDP bypass?)
- Mitigation feasibility for the vendor (often: chip respin, sometimes not fixable in deployed devices)

---

## Key References

- ChipWhisperer documentation: chipwhisperer.io
- "The Hardware Hacking Handbook" (Voorhoeve, van Woudenberg) — definitive book on FI
- PicoEMP: github.com/newaetech/chipshouter-picoemp
- "Glitching the KeyScrambler" research (case studies of practical FI)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
