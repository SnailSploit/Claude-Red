# Changelog

All notable changes to `claude-red` are documented here. The library follows a phased roadmap (see [README.md](README.md#roadmap)). Versions follow [Semantic Versioning](https://semver.org/) where breaking changes mean skill renames, removals, or category restructures.

## [Unreleased]

### Added

- `offensive-active-directory` — Added Pre-Windows 2000 Compatible Access section covering legacy computer account password exploitation, detection indicators (userAccountControl 4128, logonCount=0, group membership), LDAP enumeration, automated pre2k tool usage, and post-compromise escalation paths (ReadGMSAPassword → gMSA → ACL abuse). References HTB Vintage writeups and The Hacker Recipes.

### Planned

- Phase 1 — Internal AD/Windows split (16 skills)
- Phase 2 — Cloud Identity / Hybrid (10 skills)
- Phase 4 — IoT split (10 skills)
- Phase 5 — Web Basics (8 skills)
- Phase 6 — Web Advanced (10 skills)

## [0.3.0] — 2025-08

### Added — 10 New Categories (20 skills)

- **container/** — `offensive-container-escape` (Docker/containerd/Podman breakout, runc CVEs, cgroup escape), `offensive-k8s-attacks` (RBAC abuse, etcd, kubelet API, pod escape, CRD exploitation)
- **cicd/** — `offensive-cicd-pipeline` (GitHub Actions injection, Jenkins RCE, GitLab CI, Azure DevOps), `offensive-cicd-secrets` (env var extraction, vault misconfigs, OIDC federation, runner tokens)
- **api/** — `offensive-api-security` (OWASP API Top 10, REST/gRPC/WebSocket), `offensive-api-abuse` (business logic, batching, JWT manipulation, webhook hijacking)
- **crypto/** — `offensive-crypto-attacks` (padding oracle, ECB, hash extension, RSA, PRNG), `offensive-tls-attacks` (POODLE/DROWN/Heartbleed, pinning bypass, HSTS bypass, 0-RTT)
- **privesc/** — `offensive-linux-privesc` (SUID, capabilities, sudo, cron, kernel exploits), `offensive-windows-privesc` (Potato family, service misconfigs, DLL hijacking, UAC bypass)
- **post-exploitation/** — `offensive-lateral-movement` (PTH/PTT, NTLM relay, tunneling), `offensive-persistence` (registry, scheduled tasks, Golden/Silver tickets, PAM), `offensive-data-exfiltration` (DNS/HTTPS/ICMP tunneling, cloud dead drops, steganography)
- **forensics/** — `offensive-anti-forensics` (log clearing, timestomping, ADS, anti-VM), `offensive-c2-frameworks` (Cobalt Strike, Sliver, Mythic, Havoc, redirectors)
- **supply-chain/** — `offensive-supply-chain` (dependency confusion, typosquatting, build attacks), `offensive-dependency-confusion` (npm/PyPI/NuGet/Maven namespace attacks)
- **social-engineering/** — `offensive-phishing` (GoPhish, EvilGinx2, MFA phishing), `offensive-social-engineering` (pretexting, vishing, smishing, physical SE, USB drops)
- **network/** — `offensive-network-attacks` (ARP spoofing, LLMNR/NBT-NS poisoning, VLAN hopping, IPv6 attacks, MITM)

### Changed — Deep Rewrites (4 skills)

- `offensive-deserialization` — 183 to 600+ lines; added Java/PHP/.NET/Python/Node/Ruby exploitation depth, modern vectors (K8s, message queues, serverless), WAF bypass, tool commands
- `offensive-graphql` — 207 to 567 lines; added introspection bypass, batching attacks, subscription abuse, file upload, DoS patterns, CrackQL/BatchQL tooling
- `offensive-advanced-redteam` — 146 to 640 lines; added engagement planning, infrastructure setup, C2 tradecraft, OPSEC discipline, evasion techniques, reporting, engagement scenarios
- `offensive-ssti` — 347 to 758 lines; added 10+ engine-specific exploits (Jinja2/Twig/Freemarker/Velocity/Pebble/Smarty/Mako/ERB/Thymeleaf), filter bypass, blind exploitation, chaining

### Changed — Documentation

- README updated with 10 new category sections, badge counts (58 to 78 skills, 13 to 23 categories), expanded roadmap
- CHANGELOG updated with v0.3.0 section
- `claude-skills.json` manifest regenerated

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
