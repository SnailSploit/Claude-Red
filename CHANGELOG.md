# Changelog

All notable changes to `codex-red` are documented here. The library follows a phased roadmap (see [README.md](README.md#roadmap)). Versions follow [Semantic Versioning](https://semver.org/) where breaking changes mean skill renames, removals, or category restructures.

## [Unreleased]

### Added

- Codex-first installation path in `install.sh` that flattens skills into `$CODEX_HOME/skills/<skill-name>`.
- `codex-skills.json` manifest generated alongside the Claude-compatible manifest.
- Root `AGENTS.md` with Codex-oriented repository operating guidance.

### Changed

- README and contributor guidance now document Codex as the optimized default while preserving Claude-compatible usage.
- Legacy platform-specific skill headings now use platform-neutral `Operational Instructions`.

### Planned

- Phase 1 — Internal AD/Windows split (16 skills)
- Phase 2 — Cloud Identity / Hybrid (10 skills)
- Phase 3 — Wireless split (12 skills) — **mandatory for v0.3.0**
- Phase 4 — IoT split (10 skills)
- Phase 5 — Web Basics (8 skills)
- Phase 6 — Web Advanced (10 skills)

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
