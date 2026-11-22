---
name: offensive-krack-fragattacks
description: "KRACK (CVE-2017-13077..082) and FragAttacks (CVE-2020-24586..588 + 26139-26147) — key reinstallation, fragmentation, and aggregation attacks against WPA2 supplicants. Covers Vanhoef's test scripts, viability against modern patched stacks (mostly mitigated post-2021), residual unpatched embedded devices and IoT vendors, and the practical limitations of these attacks in modern engagements. Use when assessing legacy supplicants, embedded clients, or vendors with poor patch cadence."
---

# KRACK & FragAttacks

Two attack families against WPA2 client implementations. Both well-disclosed (KRACK 2017, FragAttacks 2021) and largely patched on modern OSes — but the embedded/IoT long tail keeps them in scope for many engagements.

## When These Apply

| Family | Target | Patch Status |
|---|---|---|
| KRACK | WPA2 supplicants in 4-way handshake / GTK / FT / TDLS | Major OSes patched 2017–2018 |
| FragAttacks | Frame fragmentation/aggregation across WPA2/3 | Most stacks patched 2021–2022 |

Probability of success today is high only against:
- Embedded OEM devices (cameras, sensors, point-of-sale)
- Old Android phones (<8 unpatched)
- Industrial / SCADA Wi-Fi clients
- Wi-Fi-enabled toys, smart bulbs, no-name IoT

Modern Win11 / iOS 16+ / Android 13+ / hostapd-2.10 are mitigated.

## KRACK — Key Reinstallation

The 4-way handshake's M3 retransmission causes the supplicant to reinstall the same PTK with reset nonce/replay counters. Frames encrypted under the reused keystream become decryptable.

```bash
# Vanhoef's official test scripts
git clone https://github.com/vanhoefm/krackattacks-scripts
cd krackattacks-scripts/krackattack
sudo ./krack-test-client.py --interface wlan0
# Tests the supplicant on a connected client
```

Output identifies which CVE variants the client is vulnerable to.

### Practical Outcomes

When successful:
- Decryption of WPA2-encrypted frames between client and AP
- TKIP downgrade enables packet injection
- Recovery of session keys for the duration of the affected key cycle

Not a PSK recovery — you don't get the wireless password from KRACK.

## FragAttacks — Frame Splicing

FragAttacks abuse 802.11 fragmentation and aggregation to inject frames that mix encrypted and plaintext fragments, or to splice attacker-controlled fragments into legitimate frames.

```bash
git clone https://github.com/vanhoefm/fragattacks
cd fragattacks && make          # builds the modified hostap/wpa_supplicant

# Run one test at a time: ./fragattack.py <iface> <test-name>
# Test names (ping, ping-frag-sep, amsdu-inject, linux-plain, ...) are in the README.
sudo ./fragattack.py wlan0 ping-frag-sep
```

> The script is `fragattack.py` (singular), invoked as `fragattack.py <iface> <test-name>` — **not** `test-fragattacks.py --interface …` (a name that only appears in copied cheatsheets). The harness needs the target network's credentials, so it tests a client/AP you control rather than attacking a blind target.

| CVE | Mechanism |
|---|---|
| CVE-2020-24588 | A-MSDU spoofing — inject crafted A-MSDU subframes |
| CVE-2020-24587 | Mixed-key fragment cache poisoning |
| CVE-2020-24586 | Decoupled fragment cache → reuse |
| CVE-2020-26139 | Forwarding plaintext frames before authentication |
| CVE-2020-26140 | Accepting plaintext frames in protected network |

### Practical Outcomes

- Inject malicious frames that the client treats as legitimate (HTTP redirect, DNS poison)
- Read decrypted fragments from cached state
- Cross-protect data exfil via crafted A-MSDU

## Targeting Workflow

1. Identify the in-scope client (MAC, OS, vendor)
2. Estimate patch likelihood — if modern OS, likely patched; if embedded, likely vulnerable
3. Run the test suite from a controlled AP setup
4. Report each vulnerable variant separately with the matching CVE

```bash
# Rogue AP that drives the test
sudo hostapd-mana /tmp/krack_test_ap.conf

# Force client to associate (deauth from real AP, or social-engineer)
sudo aireplay-ng --deauth 5 -a <real-BSSID> -c <client-MAC> wlan0mon

# Run test once associated
sudo ./krack-test-client.py --interface wlan0
```

## Detection / Defender View

- WIPS may flag the **deauth-driven roam** to the attacker AP — this is the loudest, most reliable signal, since exploitation itself is near-silent.
- Vanhoef's test scripts generate distinctive frame patterns; modern WIPS signatures recognize the tooling.
- Successful exploitation is essentially silent at the protocol level — so detection leans on the *setup* (rogue AP, forced roam), not the exploit.
- An unexpected A-MSDU / fragmented-frame mix from a client that normally doesn't fragment is an anomaly worth hunting if you have frame-level capture.

Blue-team takeaway: you will rarely catch the exploit; you catch the **rogue AP + forced association** that precedes it. Monitor for both.

## Mitigations / Defender Hardening

The counter — and for these families it is decisive, because both are patched upstream:

| Technique | Mitigation |
|---|---|
| KRACK key reinstallation | **Patch the supplicant** — every major OS has shipped fixes since 2017–2018. This closes it outright |
| FragAttacks splicing/aggregation | Patch client and AP firmware (2021–2022 fixes); ensure the stack drops plaintext frames inside a protected network (CVE-2020-26140/26139 are acceptance bugs) |
| Unpatchable embedded / IoT long tail | Inventory them; **segment onto an isolated VLAN/SSID** carrying no sensitive traffic; deny inter-VLAN routing |
| Forced-roam precondition | Enforce **PMF-Required / WPA3** so the attacker cannot deauth the client onto a rogue AP in the first place (see `offensive-deauth-disassoc`) |
| Residual injection impact (DNS poison, HTTP redirect) | Defense-in-depth: enforce HTTPS/HSTS and encrypted DNS so a spliced frame can't downgrade traffic to plaintext |

Defender one-liner: **patch + segment the unpatchable + PMF/WPA3 + TLS-everywhere** reduces KRACK/FragAttacks from a decryption-and-inject primitive to a dead end on anything that matters.

## Reporting

For each vulnerable CVE:

- Client model + firmware version (be specific)
- Variant tested + result (vulnerable / patched / partial)
- Practical impact in the engagement context (decryption only, or injection viable?)
- Remediation: vendor patch URL, mitigation (WPA3 + PMF blocks most)

---

## MITRE ATT&CK Mapping

| Technique | ID | Where it appears here |
|---|---|---|
| Adversary-in-the-Middle | T1557 | Rogue AP + frame injection (HTTP redirect, DNS poison) |
| Network Sniffing | T1040 | Decryption of WPA2 frames via key reinstallation |
| Network Denial of Service | T1498 | Deauth used to force the client onto the attacker AP |

## Key References

- KRACK: krackattacks.com (Vanhoef)
- FragAttacks: fragattacks.com (Vanhoef)
- Original papers: USENIX Security 2017 (KRACK), USENIX Security 2021 (FragAttacks)
- CISA advisories tracking embedded vendor patches
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/wireless.md
