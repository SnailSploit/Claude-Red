---
name: offensive-secure-boot-bypass
description: "Secure boot and chain-of-trust bypass methodology — anti-rollback fuse analysis, downgrade attacks to older signed images with known kernel CVEs, signature-check fault injection, key-extraction from boot ROM via bus snooping or invasive analysis, vendor-key compromise paths (PKI failures, SoC family-wide keys), and practical secure-boot weaknesses in major SoC families (ESP32 v1, NXP, TI, Allwinner). Use when the device enforces signed firmware and you need to load attacker-controlled kernel/userspace."
---

# Secure Boot Bypass

Secure boot is the modern defense against firmware tampering — at boot, each stage verifies the next stage's signature before transferring control. Defeating it requires either a key compromise, a logic flaw, or a fault-injection bypass of the verification step.

## Quick Workflow

1. Identify the secure-boot scheme (vendor-specific)
2. Check anti-rollback enforcement (fuses blown vs not)
3. Try downgrade to older signed image with exploit-eligible vulnerabilities
4. If anti-rollback prevents downgrade, fault-inject the signature check
5. Last resort: extract the OEM key via invasive analysis

---

## Anatomy of Secure Boot

```
ROM Code (in SoC silicon, signed by SoC vendor key fused at fab)
    │ verifies
    ▼
First-stage bootloader (signed by OEM via fused public key)
    │ verifies
    ▼
U-Boot / Second-stage (signed)
    │ verifies
    ▼
Linux kernel (signed)
    │ verifies (sometimes)
    ▼
Initramfs / dm-verity rootfs
```

Each stage in the chain typically:
1. Computes hash of next stage
2. Verifies signature against fused public key (or chain back to fused root)
3. Transfers control

## Anti-Rollback Fuses

Modern SoCs include monotonic counter fuses. When a new firmware version is shipped, the OEM blows additional fuses. The bootloader checks these against a version field in the firmware header — older versions are rejected.

Per-SoC fuse implementations:

| Family | Anti-Rollback |
|---|---|
| ESP32 v3 | Block 0/1 efuses |
| NXP i.MX | OCOTP MAC2/SRK_REVOKE registers |
| TI Sitara AM6x | OTP secure section |
| ARM TrustZone | OTP-based monotonic counter |

Check whether the device has all anti-rollback fuses blown:

```bash
# ESP32 (with esptool)
esptool.py --port /dev/ttyUSB0 read_flash 0xe000 0x1000 efuses.bin
xxd efuses.bin | head

# Check if ANTI_ROLLBACK_KEY_SLOT bits are set
```

## Downgrade Attack

When anti-rollback is **not** enforced (common in early product runs, IoT with infrequent updates):

1. Find a publicly-released older signed firmware
2. Identify a kernel / userspace CVE in that version
3. Flash the older firmware (via vendor update mechanism or chip-off)
4. Exploit the now-running vulnerable code

```bash
# Vendor firmware archives, archive.org, FCC ID search for FCC-deposited firmware
# Anchor finds: device model → firmware download URLs across versions

# Once you have the older signed bin, write it back via vendor tooling or SPI flash
flashrom -p ch341a_spi -w old_signed.bin
```

If the bootloader accepts it (no anti-rollback), you've bypassed the chain by using a real signed image with known bugs.

## Signature-Check Fault Injection

When anti-rollback is enforced and downgrade fails, fault-inject the verification step:

```
ROM verifies first-stage:
  hash = sha256(payload)
  if (memcmp(hash, expected_hash, 32) == 0) {   ← glitch this comparison
    transfer_control(payload);
  } else {
    halt();
  }
```

A timed voltage glitch corrupts the comparison — `memcmp` returns 0 (equal) regardless. Boot proceeds with attacker-controlled payload.

Per `offensive-fault-injection`, the parameter sweep finds the precise glitch window.

Successful targets historically:
- ESP32 v1 secure boot (broken; key extractable)
- Various Cortex-M MCUs (RDP bypass via glitch is well-documented)
- Older NXP automotive ECUs (laser fault injection in research)
- Cheap ARM TrustZone implementations on consumer IoT

## Key Extraction

If you have full physical access and time, extract the verification key:

### Bus Snooping During Boot ROM

```
Boot ROM reads OTP key from internal fuses.
Some chips load the key into RAM and use RAM-resident copy.
Probe RAM via JTAG (if accessible) or via fault-injected JTAG re-enable.
```

### Side-Channel Power Analysis

Power traces during signature verification can leak the key bit-by-bit. Tools: ChipWhisperer for educational targets; commercial pro setups for production hardware.

### Invasive Decapsulation

Decap the chip, optical-microscope-image the OTP region. Some OEMs leave OTP cells visually distinguishable (full vs empty cells). Read by inspection.

## Vendor-Key Compromise (Out-of-Band)

Sometimes the OEM signing key leaks:

- Insider threat / supply chain
- Stolen developer workstation (BIOS UEFI keys have leaked publicly)
- HSM misconfiguration
- Forgotten test keys still trusted in production builds

If you encounter a leaked key in the wild (research disclosure, prior CVE), check whether the target accepts firmware signed with it.

## ESP32 Secure Boot v1 Specifics

ESP32 secure boot v1 (early ESP32 chips, 2016–2019) is broken:

- Non-cryptographic root of trust (key burned into hardware can be read in some glitched paths)
- Cache-based key recovery via timing
- Specific glitches at boot bypass first-stage check

ESP32 v3 (newer chips and ESP32-S2/S3/C3) added v2 secure boot with proper RSA-3072 chain. v1 chips are EOL but still in deployed products.

## NXP / TI / Allwinner Targets

Each SoC family has its own secure-boot scheme:

- **NXP i.MX**: HAB (High Assurance Boot) — well-documented; some hardware revisions glitchable
- **TI Sitara**: OTP-fused root key, image-signing tooling — secure but complex; older revisions have known fault-injection paths
- **Allwinner**: SMC (Secure Boot Mode) — multiple research disclosures of bypass

OEM-modified versions of these schemes vary widely in actual deployment security.

## Engagement Cheatsheet

```
[ ] Identify SoC + secure-boot scheme version
[ ] Check anti-rollback state (fuse readout if accessible)
[ ] Search for older signed firmware (vendor site, archive.org, FCC)
[ ] Try downgrade attack first (cheapest)
[ ] If blocked, plan fault injection (see offensive-fault-injection)
[ ] Identify the exact verification instruction window
[ ] Sweep glitch parameters
[ ] Last resort: invasive analysis for key extraction
[ ] Document: scheme, attack used, success rate, specific firmware loaded
```

## Reporting

- Specific SoC + secure-boot version
- Whether anti-rollback is fused
- The bypass mechanism (downgrade / glitch / key extract)
- Reliability and time-to-exploit
- Vendor remediation feasibility (often: chip respin, sometimes patchable via OTA)

## When to Stop

Secure boot bypass is one of the highest-effort attack paths. Before committing:

- Verify the device's other surfaces are exhausted (network, application, side-channel keys)
- Confirm scope explicitly authorizes destructive analysis
- Consider whether the engagement budget supports glitching equipment + iteration
- For compliance assessments, "we couldn't bypass secure boot in 5 days" is itself a useful finding

---

## Key References

- "Bypassing Secure Boot using Fault Injection" (Riscure, NCC)
- ESP32 secure boot research (LimitedResults, Tarlogic)
- "Hardware Security in Automotive ECUs" research (multiple authors)
- Trusted Firmware-A documentation
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
