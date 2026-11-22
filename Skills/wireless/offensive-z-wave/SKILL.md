---
name: offensive-z-wave
description: "Z-Wave attack methodology — sniffing with Z-Force / EZ-Wave / RTL-SDR + ZniffMobile, S0 (legacy) network-key derivation flaw, the S0 downgrade attack (Z-Shave), S2 (modern) ECDH commissioning analysis, replay/injection on unauthenticated nodes, default-key brute-force on test deployments, and home-automation hub pivots. Pairs each technique with a defender view (what the hub/SIEM sees) and concrete hardening (force S2, remove S0 fallback, secure the hub key store). Use when assessing or defending Z-Wave smart home devices (door locks, sensors, garage controllers) — common in mid-2010s smart home deployments still in production, and when mapping Z-Wave findings to MITRE ATT&CK for ICS."
---

# Z-Wave Attacks

Z-Wave runs in the 800/900 MHz ISM band (US: 908 MHz, EU: 868 MHz). Older networks used the S0 security scheme with a fixed-derivation network key — long-known to be flawed. S2 (mandatory for Z-Wave Plus v2 since 2017) uses ECDH commissioning and is significantly stronger.

## Quick Workflow

1. Identify region (US 908 MHz / EU 868 MHz) — adapter frequency must match
2. Sniff inclusion (commissioning) traffic — that's where keys are exchanged
3. Determine S0 vs S2 from frame format
4. For S0: derive/replay; for S2: analyze ECDH and look for implementation flaws

---

## Hardware

| Adapter | Use |
|---|---|
| Z-Force (legacy, hard to find) | Original research tool |
| EZ-Wave (GNU Radio flowgraph on HackRF) | Legacy (2016, Python 2) recon/TX toolset |
| Aeotec Z-Stick | Commercial controller, useful as legitimate node |
| HackRF + open Z-Wave firmware | Multi-band SDR approach |
| RTL-SDR + ZniffMobile (passive only) | Cheap sniffer |

## Sniffing

```bash
# EZ-Wave (Hall & Ramsey, ShmooCon 2016) — Scapy-Radio + GNU Radio on HackRF.
# Legacy Python 2 toolset, largely unmaintained; GitHub release is recon-focused.
git clone https://github.com/scriptingxss/EZ-Wave

# Enumerate networks / nodes (passive, or active with a known HomeID)
python2 ezstumbler.py --passive
python2 ezstumbler.py --active --homeid=0x1a2b3c4e

# Interrogate a node: manufacturer, firmware, supported command classes
python2 ezrecon.py 0x1a2b3c4d 2

# Raw capture is driven by EZ-Wave's GNU Radio flowgraph over the HackRF;
# frames parse in Wireshark via the Z-Wave dissector (LINKTYPE_ZWAVE_R1_R2).
```

> Note: `ezwave-sniff` is **not** a real EZ-Wave command — use `ezstumbler.py` / `ezrecon.py` as above. For a modern passive sniffer, an RTL-SDR with a Z-Wave decoder or a Silicon Labs Zniffer + ZniffMobile is the practical path.

Look for the inclusion phase (controller adding new device) — that's where the network key is exchanged.

## S0 Security Flaw

S0 derives the network key from a fixed all-zero PSK during the inclusion of the first device. That fixed material is well-known — any S0 network you sniff during inclusion can be decrypted offline.

```
S0 commissioning:
  1. New node joins → controller sends key with zero-PSK encryption
  2. Attacker sniffs commissioning frame → derives session key
  3. All future S0 traffic on that network is decryptable
```

If you can:
- Trigger inclusion (factory-reset a node, or wait for legitimate inclusion)
- Sniff during the ~2-second key-exchange window

You own the network key for that mesh.

### S0 Downgrade ("Z-Shave")

Pen Test Partners (2018) showed that an S2-capable node can be **forced down to S0** during inclusion: the attacker spoofs the "S2 not supported" indication so commissioning falls back to the weak S0 exchange, re-opening the zero-PSK window on otherwise-modern hardware. This matters because many deployments leave S0 enabled "for compatibility" long after every node supports S2.

Defender takeaway: the fix is not detection-only — it is **removing the S0 fallback path** (see Mitigations / Hardening). Treat any S0 commissioning observed on an S2-capable mesh as a downgrade indicator.

## S2 (Z-Wave Plus / S2 Authenticated)

S2 fixes S0 by using ECDH for commissioning:
- Each device has a Curve25519 keypair
- Inclusion uses DSK (Device Specific Key) verified out-of-band (sticker/QR)
- Network key never traverses the air in plaintext

S2 attack surface is mostly implementation:
- Inclusion-mode-always-open (controller misconfig)
- Firmware bugs in S2 verification
- Side-channel on ECDH on resource-constrained chips
- DSK printed on a sticker → physical access yields it

## Replay / Injection on Unauthenticated Nodes

Many low-end Z-Wave devices (older sensors, basic switches) don't enforce S0 or S2 — they accept commands in cleartext.

```python
# Illustrative only — Z-Wave frame crafting via the Scapy-Radio zwave contrib.
# Class/field names (ZWave, home_id, command-class layers) vary by Scapy-Radio
# version; verify against the installed scapy/contrib/zwave module before relying
# on them. Transmission goes through EZ-Wave's GNU Radio flowgraph, not a plain iface.
from scapy.contrib.zwave import *
frame = ZWave(homeid=0x12345678)/ZWaveSwitchBin(switchcmd=0x01, val=0xFF)
```

This unlocks doors / switches lights / unarms sensors when the target lacks authentication.

## Key Brute-Force

For old test deployments using default home IDs / network keys:

```bash
# HomeID is 32-bit, so brute-forcing the full space is infeasible.
# In practice: recover the real HomeID by sniffing, then active-probe it.
python2 ezstumbler.py --active --homeid=0x1a2b3c4e
```

The 32-bit HomeID space rules out exhaustive brute-force. This is only realistic against default-config IoT lab gear with known/guessable HomeIDs — on production you recover the HomeID passively first, then probe.

## Hub Pivots

Z-Wave devices are typically controlled by a hub (SmartThings, Hubitat, Vera, Home Assistant, Z-Wave JS UI). The hub is a Linux device with the Z-Wave PSK in plaintext storage:

- SmartThings Hub: previously cloud-only credentials; modern v3 stores network key locally
- Home Assistant: `~/.homeassistant/zwave_js.json` typically contains keys
- Hubitat: web UI with default password on older versions

Compromise the hub → walk away with the Z-Wave PSK + every paired device's command authority. See `offensive-iot` for hub firmware extraction.

## Engagement Cheatsheet

```bash
# 1. Identify region + frequency
# US: 908.4 MHz; EU: 868.4 MHz; CN: 868.4 MHz

# 2. Enumerate + sniff (EZ-Wave recon tools, or RTL-SDR/Zniffer passive)
python2 ezstumbler.py --passive
wireshark cap.pcap   # filter zwave (LINKTYPE_ZWAVE_R1_R2)

# 3. Identify S0 vs S2 from frame format

# 4. For S0: capture inclusion → derive key → decrypt history + control devices

# 5. For S2: focus on hub compromise / DSK theft / implementation bugs

# 6. Test unauthenticated cleartext devices with crafted frames
```

## Detection / Defender View

What a defender can actually observe, and where the blind spots are:

| Signal | Where it shows up | Blind spot |
|---|---|---|
| Unexpected inclusion event | Hub log / UI "device added" notification | Rarely alerted on; no email/push by default on most hubs |
| S0 commissioning on an S2-capable mesh | Z-Wave JS UI security-class per node; packet capture | Interpreted as "compatibility", not as a downgrade (Z-Shave) indicator |
| Inclusion mode left open | Hub UI toggle | Ignored by inattentive admins; some hubs auto-close after a timeout, some don't |
| Cleartext Basic/Switch command bursts | Hub command log, if enabled | Most low-end nodes keep no history; hub UI does not surface per-command source |
| New/unknown Home ID in RF range | Only via an SDR sniffer the defender runs | No native IDS — Z-Wave has no Wi-Fi/Zigbee-grade monitoring ecosystem |

Practical detection posture for a blue team:
- Enable and forward hub logs (Home Assistant / Z-Wave JS UI emit inclusion + security-class events) to the SIEM; alert on any inclusion outside a change window.
- Periodically export the node list and **alert when a node's security class drops** (S2 → S0) — that is the clearest downgrade/Z-Shave signal.
- For high-value nodes (locks, garage, alarm arming), treat any cleartext Basic Set as an incident.

## Mitigations / Hardening

This is the counter — what stops each technique above:

| Technique | Mitigation |
|---|---|
| S0 key-derivation sniff | Do all inclusion in an RF-quiet area; prefer S2, which never sends the key in the clear |
| S0 downgrade (Z-Shave) | **Disable S0 fallback** where the controller allows it; require S2 for all nodes; replace any node that is S0-only |
| Cleartext replay/injection | Retire unauthenticated/legacy nodes; require S2 Authenticated for locks, garage, and alarm devices |
| Default home ID / key brute-force | Never ship lab/default configs to production; force fresh key generation at commissioning |
| Hub key-store theft | Encrypt the hub at rest; restrict OS access; rotate network keys after any hub compromise; keep hub firmware current |
| Inclusion-mode-open | Keep inclusion disabled by default; enable only during a change window; verify it auto-closes |

Defender one-liner: **S2-only mesh + hub hardening + log-forwarded inclusion events** removes the entire S0 chain and makes the remaining attack surface (hub compromise, physical DSK theft) loud.

## Reporting

- Identify chipset / firmware revision per device (ZW0500 series, ZW7000 series)
- Map S0 vs S2 per node — note any S0 left on a network with S2-capable nodes
- Document hub compromise paths separately

---

## MITRE ATT&CK for ICS Mapping

| Technique | ID | Where it appears here |
|---|---|---|
| Network Sniffing | T0842 | Sniffing inclusion / S0 key-exchange frames |
| Adversary-in-the-Middle | T0830 | S0 downgrade (Z-Shave) during commissioning |
| Wireless Compromise | T0860 | RF access to the mesh via SDR |
| Unauthorized Command Message | T0855 | Cleartext Basic/Switch command injection |
| Brute Force I/O | T0806 | Default home ID / network-key brute-force |

(Enterprise equivalents for the hub-pivot path: T1557 Adversary-in-the-Middle, T1040 Network Sniffing, T1552.001 Credentials in Files for the plaintext hub key store.)

## Key References

- Fouladi, B. & Ghanoun, S. — "Security Evaluation of the Z-Wave Wireless Protocol," Black Hat USA 2013 (foundational Z-Wave security research; key-reset / implementation flaws)
- Pen Test Partners — "Z-Shave: Exploiting Z-Wave downgrade attacks" (2018): https://www.pentestpartners.com/security-blog/z-shave-exploiting-z-wave-downgrade-attacks/
- Silicon Labs — Z-Wave S2 security whitepaper and 700-series specification
- EZ-Wave (Hall & Ramsey, ShmooCon 2016; Scapy-Radio/GNU Radio, canonical repo): https://github.com/scriptingxss/EZ-Wave
- tcpdump LINKTYPE_ZWAVE_R1_R2 (Z-Wave capture link type / frame format): https://www.tcpdump.org/linktypes/LINKTYPE_ZWAVE_R1_R2.html
- Z-Wave JS UI (defender-side node/security-class inspection and logging): https://github.com/zwave-js/zwave-js-ui
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/wireless.md
