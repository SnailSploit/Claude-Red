# Changelog

All notable changes to `claude-red` are documented here. Versions follow [Semantic Versioning](https://semver.org/) where breaking changes mean skill renames, removals, or category restructures.

## [0.3.0] — 2025-05

### Added — 67 new focused skills (45 → 112)

**Internal (`Skills/internal/`)** — renamed from `active-directory/`, +16 skills:
- internal-recon, network-poisoning, ntlm-relay, coercion, kerberoasting,
  asreproasting, acl-abuse, adcs, kerberos-delegation, pass-the-x,
  lsass-dumping, ticket-forgery, dcsync-dcshadow, gpo-abuse, trust-attacks,
  network-pivoting

**Cloud Identity (`Skills/cloud-identity/`, new)** — 10 skills:
- entra-recon, entra-privesc, aadconnect-attacks, golden-saml, pass-the-prt,
  conditional-access-bypass, device-code-phish, illicit-consent, m365-recon,
  okta-attacks

**Wireless (`Skills/wireless/`)** — +12 skills:
- wifi-recon, wpa2-psk, wpa3-sae, wpa-enterprise, wps, evil-twin,
  krack-fragattacks, deauth-disassoc, bluetooth-ble, bluetooth-classic,
  zigbee-thread-matter, z-wave, lorawan-sub-ghz

**IoT (`Skills/iot/`)** — +10 skills:
- iot-hardware-recon, uart-jtag-swd, flash-dumping, fault-injection,
  firmware-analysis, uboot-bypass, secure-boot-bypass, rtos-pwn,
  ics-ot-protocols, mqtt-coap

**Web (`Skills/web/`)** — +18 skills (8 basics + 10 advanced):
- Basics: web-recon, auth-bypass, access-control, csrf-samesite,
  header-attacks, cors-misconfig, cache-poisoning-deception, clickjacking
- Advanced: prototype-pollution, mass-assignment, saml-attacks, oidc-attacks,
  websocket, grpc, postmessage, ssi-esi, csti, dom-clobbering

### Changed

- Windows-side skills (edr-evasion, windows-mitigations, windows-boundaries,
  keylogger-arch) moved from `infrastructure/` into `internal/`
- README rewritten with full categorized navigation
- MINDMAP.md added — Mermaid mindmap + MITRE ATT&CK / OWASP cross-reference

## [0.2.0] — 2025-05

## [0.2.0] — 2025-05

### Added

- 7 new offensive skills:
  - `offensive-active-directory` — AD attack methodology (Kerberoast, ASREProast, ACL abuse, ADCS ESC1-15, delegation, persistence, hybrid AAD)
  - `offensive-wifi` — 802.11 attacks (WPA2/WPA3, EAP, KARMA/Mana, KRACK, WPS, BLE, Zigbee, Z-Wave, LoRa, sub-GHz)
  - `offensive-business-logic` — workflow bypass, price/coupon/refund abuse, race conditions, anti-fraud defeat, chain construction
  - `offensive-toctou` — time-of-check/use across binary, kernel, web, container layers with window-widening primitives
  - `offensive-iot` — hardware recon, firmware extraction, RTOS, ICS/OT, wireless protocols, MQTT/CoAP
  - `offensive-mobile` — Android+iOS pentest (Frida, pinning bypass, storage, biometric, deep links, Firebase) [category-sized]
  - `offensive-cloud` — AWS+Azure+GCP attack paths (privesc, IMDS, cross-account, persistence, CSPM evasion) [category-sized]
- `offensive-reporting` — pro pentest report writing methodology (CVSS scoring, evidence hygiene, executive summaries, finding templates, attack chain narratives, deliverable formats, retest discipline)

### Changed

- **Reorganized skills into 13 category subdirectories.** Top-level `Skills/` now contains category folders (`web/`, `auth/`, `active-directory/`, `wireless/`, `cloud/`, `mobile/`, `iot/`, `infrastructure/`, `exploit-dev/`, `fuzzing/`, `recon/`, `ai/`, `utility/`). Skill folder names unchanged.
- README rewritten with category-based navigation, badges, install snippets, and roadmap.
- SECURITY.md rewritten with intended-use scope and disclosure policy.

### Added (Documentation & Packaging)

- `LICENSE` — MIT (was claimed in README, file now present)
- `CONTRIBUTING.md` — skill format, frontmatter standard, review process
- `CHANGELOG.md` — this file
- `claude-skills.json` — machine-readable manifest of all skills
- `install.sh` — installer that copies skills into the Claude skills path

## [0.1.0] — 2024

### Added

- Initial library of 37 offensive security skills, derived from the SnailSploit / Sahar Shlichov offensive checklist collection
- Categories covered: web app, auth, infrastructure & binary, recon, fuzzing, AI security, utility
