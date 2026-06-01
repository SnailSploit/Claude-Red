![skills-red banner](/assets/banner.png)

<div align="center">

# skills-red

**Offensive security skills for Claude, Codex, and OpenCode — portable `SKILL.md` files that turn AI coding agents into context-aware red team operators.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-58-red.svg)](#skill-index)
[![Categories](https://img.shields.io/badge/categories-13-orange.svg)](#categories)
[![Stars](https://img.shields.io/github/stars/trewwwsec/skills-red?style=social)](https://github.com/trewwwsec/skills-red)
[![Forks](https://img.shields.io/github/forks/trewwwsec/skills-red?style=social)](https://github.com/trewwwsec/skills-red/network/members)

Built by **[SnailSploit](https://snailsploit.com)** — GenAI Security Research.

</div>

---

## Table of Contents

- [What is this](#what-is-this)
- [Quickstart](#quickstart)
- [Generated manifests](#generated-manifests)
- [Categories](#categories)
- [Skill Index](#skill-index)
  - [Web Application](#web-application)
  - [Auth & Identity](#auth--identity)
  - [Active Directory](#active-directory)
  - [Wireless](#wireless)
  - [Cloud](#cloud)
  - [Mobile](#mobile)
  - [IoT & Embedded](#iot--embedded)
  - [Infrastructure & Red Team](#infrastructure--red-team)
  - [Exploit Development](#exploit-development)
  - [Fuzzing & Vulnerability Research](#fuzzing--vulnerability-research)
  - [Reconnaissance](#reconnaissance)
  - [AI Security](#ai-security)
  - [Utility](#utility)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## What is this

`skills-red` is a curated library of offensive security skills for Claude, Codex, and OpenCode skill systems. Each skill is a structured `SKILL.md` file that primes an AI coding agent with expert-level methodology for a specific attack surface — from SQLi to shellcode, EDR evasion to ADCS abuse.

Install skills into `$CODEX_HOME/skills/skills-red` for Codex, `~/.claude/skills/skills-red` for Claude, or `~/.config/opencode/skills/skills-red` for OpenCode. The same `SKILL.md` files are portable across all supported platforms; the installer preserves the category tree under the `skills-red` namespace for each platform.

**Use it for:** authorized red team engagements, bug bounty triage, security research, CTF preparation, training operators, and exploring attack surfaces methodically.

---

## Quickstart

### Codex Skills System

```bash
# Clone this repo and install all skills into ~/.codex/skills/skills-red/<category>/<skill-name>
git clone https://github.com/trewwwsec/skills-red
cd skills-red
./install.sh --platform codex

# Or install only one category
./install.sh --platform codex --category web
```

Restart Codex after installation so the skill metadata is picked up. Current Codex releases recursively discover `SKILL.md` files under `$CODEX_HOME/skills`, so the installer keeps skills namespaced as `$CODEX_HOME/skills/skills-red/<category>/<skill-name>/SKILL.md`.

### Manual Codex install

```bash
mkdir -p ~/.codex/skills/skills-red/web
cp -R Skills/web/offensive-sqli ~/.codex/skills/skills-red/web/offensive-sqli
```

### OpenCode Agent Skills

```bash
# Install all skills into ~/.config/opencode/skills/skills-red/<category>/<skill-name>
git clone https://github.com/trewwwsec/skills-red
cd skills-red
./install.sh --platform opencode

# Or install only one category
./install.sh --platform opencode --category web
```

Start a new OpenCode session after installation so the `skill` tool refreshes its available skills. OpenCode's public docs show the simple one-folder layout, but current OpenCode releases recursively scan `SKILL.md` files under configured skill roots (`{skill,skills}/**/SKILL.md` in the upstream loader). The installer relies on that current recursive discovery behavior to keep skills namespaced as `~/.config/opencode/skills/skills-red/<category>/<skill-name>/SKILL.md`.

### Manual OpenCode install

```bash
mkdir -p ~/.config/opencode/skills/skills-red/web
cp -R Skills/web/offensive-sqli ~/.config/opencode/skills/skills-red/web/offensive-sqli
```

### Claude Skills System

```bash
# Upstream Claude Red install into a directory Claude will scan
git clone https://github.com/SnailSploit/claude-red ~/.claude/skills/claude-red
```

```bash
# Or install skills-red while preserving Claude's category tree
git clone https://github.com/trewwwsec/skills-red
cd skills-red
./install.sh --platform claude
```

Claude will auto-load matching skills based on conversational triggers (e.g. mentioning SQLi loads `offensive-sqli`).

### Claude Code

```bash
# Point Claude at a single skill before a session
cat Skills/web/offensive-sqli/SKILL.md | claude --system-file -

# Or load a whole category
cat Skills/active-directory/**/SKILL.md | claude --system-file -
```

### Install Script

```bash
./install.sh                           # Codex install (interactive target if TTY)
./install.sh --platform codex          # explicit Codex install
./install.sh --platform claude         # Claude-compatible install
./install.sh --platform opencode       # OpenCode agent-skill install
./install.sh --target ~/.codex/skills/skills-red  # explicit target
./install.sh --platform opencode --target ~/.config/opencode/skills/skills-red  # explicit OpenCode target
./install.sh --category web            # one category
./install.sh --dry-run                 # preview copy plan
```

---

## Generated manifests

The root `claude-skills.json`, `codex-skills.json`, and `opencode-skills.json`
files are generated distribution indexes, not hand-authored skill sources. They
summarize the `Skills/<category>/<skill-name>/SKILL.md` tree for platform
tooling, marketplace/index consumers, and release review while keeping each
`SKILL.md` file as the source of truth.

Manifest `install_path` values are default metadata for indexes and review. They intentionally include the `skills-red/<category>/<skill-name>` namespace so generated indexes match the default installer layout. For Codex and OpenCode this depends on current recursive skill discovery; if either platform drops recursive scanning, update `tools/platform_defaults.sh`, `install.sh`, and regenerated manifests together. Runtime installation behavior, including `--target`, `CODEX_HOME`, and `OPENCODE_CONFIG_HOME` overrides, is owned by [`install.sh`](install.sh).

Regenerate them after any skill metadata, category, or install-path change:

```bash
python3 tools/build_manifest.py
python3 tools/check_manifest_fresh.py
```

The freshness check also validates manifest `install_path` values against the
shared defaults in `tools/platform_defaults.sh`, which are consumed by both the
installer and manifest tooling.

Do not edit the root manifest JSON files by hand; update the relevant
`SKILL.md` frontmatter or `tools/build_manifest.py`, then regenerate and commit
the resulting manifest diff.

---

## Categories

| Category | Skills | Focus |
|---|---:|---|
| [Web Application](#web-application) | 16 | OWASP Top 10 + business logic + advanced web bug classes |
| [Auth & Identity](#auth--identity) | 2 | JWT, OAuth |
| [Active Directory](#active-directory) | 1 | On-prem AD attack methodology *(expanding)* |
| [Wireless](#wireless) | 13 | 802.11, WPA2/3, EAP, WPS, evil-twin, BLE, Zigbee, Z-Wave, LoRa, sub-GHz |
| [Cloud](#cloud) | 1 | AWS / Azure / GCP attack paths *(expanding)* |
| [Mobile](#mobile) | 1 | Android + iOS pentest *(expanding)* |
| [IoT & Embedded](#iot--embedded) | 1 | Hardware, firmware, RTOS, ICS *(expanding)* |
| [Infrastructure & Red Team](#infrastructure--red-team) | 7 | Initial access, EDR evasion, Windows ops |
| [Exploit Development](#exploit-development) | 6 | Stack/heap, mitigations, crash analysis, TOCTOU |
| [Fuzzing & VR](#fuzzing--vulnerability-research) | 4 | libFuzzer, AFL++, bug ID, vuln classes |
| [Reconnaissance](#reconnaissance) | 2 | OSINT tooling and methodology |
| [AI Security](#ai-security) | 1 | Prompt injection, jailbreaks, RAG poisoning |
| [Utility](#utility) | 2 | Fast-checking, professional reporting |

---

## Skill Index

### Web Application

`Skills/web/`

| Skill | Description |
|---|---|
| [`offensive-sqli`](Skills/web/offensive-sqli/SKILL.md) | SQL injection — error/blind/OOB, DB-specific, ORM CVEs, cloud paths |
| [`offensive-xss`](Skills/web/offensive-xss/SKILL.md) | Cross-site scripting — stored, reflected, DOM, mutation |
| [`offensive-ssrf`](Skills/web/offensive-ssrf/SKILL.md) | Server-side request forgery — cloud metadata, filter bypass |
| [`offensive-ssti`](Skills/web/offensive-ssti/SKILL.md) | Server-side template injection — engine ID, RCE paths |
| [`offensive-xxe`](Skills/web/offensive-xxe/SKILL.md) | XML external entity — OOB exfil, blind exploitation |
| [`offensive-idor`](Skills/web/offensive-idor/SKILL.md) | Insecure direct object references — enumeration, business logic |
| [`offensive-file-upload`](Skills/web/offensive-file-upload/SKILL.md) | File upload — extension bypass, polyglots, webshells |
| [`offensive-rce`](Skills/web/offensive-rce/SKILL.md) | Remote code execution — chaining, command injection |
| [`offensive-deserialization`](Skills/web/offensive-deserialization/SKILL.md) | Insecure deserialization — Java/PHP/.NET gadget chains |
| [`offensive-race-condition`](Skills/web/offensive-race-condition/SKILL.md) | Race conditions — TOCTOU, single-packet, limit bypass |
| [`offensive-request-smuggling`](Skills/web/offensive-request-smuggling/SKILL.md) | HTTP request smuggling — CL.TE, TE.CL, h2 desync |
| [`offensive-open-redirect`](Skills/web/offensive-open-redirect/SKILL.md) | Open redirect — OAuth abuse, phishing, SSRF pivots |
| [`offensive-parameter-pollution`](Skills/web/offensive-parameter-pollution/SKILL.md) | HTTP parameter pollution — WAF bypass, logic confusion |
| [`offensive-graphql`](Skills/web/offensive-graphql/SKILL.md) | GraphQL — introspection, batching, IDOR via aliases |
| [`offensive-waf-bypass`](Skills/web/offensive-waf-bypass/SKILL.md) | WAF bypass — encoding, chunking, case mutation |
| [`offensive-business-logic`](Skills/web/offensive-business-logic/SKILL.md) | Business logic — workflow bypass, pricing, refunds, chains |

### Auth & Identity

`Skills/auth/`

| Skill | Description |
|---|---|
| [`offensive-jwt`](Skills/auth/offensive-jwt/SKILL.md) | JWT — alg:none, key confusion, secret cracking |
| [`offensive-oauth`](Skills/auth/offensive-oauth/SKILL.md) | OAuth — open redirect abuse, token leakage, PKCE bypass |

### Active Directory

`Skills/active-directory/`

| Skill | Description |
|---|---|
| [`offensive-active-directory`](Skills/active-directory/offensive-active-directory/SKILL.md) | AD — Kerberoast, ASREProast, ACL abuse, ADCS ESC1-15, delegation, persistence, hybrid AAD |

> **Note:** This category is being expanded. The AD overview is being split into 16 focused skills (Kerberoasting, ASREProasting, ADCS, coercion, NTLM relay, BloodHound, ticket forgery, GPO abuse, etc.). See [Roadmap](#roadmap).

### Wireless

`Skills/wireless/`

| Skill | Description |
|---|---|
| [`offensive-wifi`](Skills/wireless/offensive-wifi/SKILL.md) | 802.11 overview — entrypoint into the wireless category |
| [`offensive-wifi-recon`](Skills/wireless/offensive-wifi-recon/SKILL.md) | Adapter selection, monitor mode, multi-band airspace mapping |
| [`offensive-wpa2-psk`](Skills/wireless/offensive-wpa2-psk/SKILL.md) | Handshake capture, PMKID, hashcat 22000 cracking |
| [`offensive-wpa3-sae`](Skills/wireless/offensive-wpa3-sae/SKILL.md) | Transition-mode downgrade, Dragonblood, SAE side-channels |
| [`offensive-wpa-enterprise`](Skills/wireless/offensive-wpa-enterprise/SKILL.md) | 802.1X / EAP attacks, eaphammer evil-twin RADIUS |
| [`offensive-wps`](Skills/wireless/offensive-wps/SKILL.md) | Pixie Dust, online PIN brute, vendor PIN generators |
| [`offensive-evil-twin`](Skills/wireless/offensive-evil-twin/SKILL.md) | KARMA, Mana, captive portal, post-association MITM |
| [`offensive-krack-fragattacks`](Skills/wireless/offensive-krack-fragattacks/SKILL.md) | KRACK + FragAttacks supplicant testing |
| [`offensive-deauth-disassoc`](Skills/wireless/offensive-deauth-disassoc/SKILL.md) | Targeted/broadcast deauth, PMF awareness, action frames |
| [`offensive-bluetooth-ble`](Skills/wireless/offensive-bluetooth-ble/SKILL.md) | BLE GATT enum, pairing downgrade, sniffing, MITM |
| [`offensive-bluetooth-classic`](Skills/wireless/offensive-bluetooth-classic/SKILL.md) | BR/EDR — SDP, SPP, KNOB, BlueBorne, HID spoofing |
| [`offensive-zigbee-thread-matter`](Skills/wireless/offensive-zigbee-thread-matter/SKILL.md) | 802.15.4 mesh — KillerBee, Touchlink abuse, ZCL command injection |
| [`offensive-z-wave`](Skills/wireless/offensive-z-wave/SKILL.md) | S0 key derivation flaw, S2 commissioning, hub pivots |
| [`offensive-lorawan-sub-ghz`](Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md) | LoRaWAN ABP/OTAA, KeeLoq garage doors, fixed-code, TPMS |

### Cloud

`Skills/cloud/`

| Skill | Description |
|---|---|
| [`offensive-cloud`](Skills/cloud/offensive-cloud/SKILL.md) | AWS / Azure / GCP — privesc, IMDS, cross-account, persistence, CSPM evasion |

> **Note:** Cloud-identity (Entra/AAD/Okta hybrid) skills coming separately. See [Roadmap](#roadmap).

### Mobile

`Skills/mobile/`

| Skill | Description |
|---|---|
| [`offensive-mobile`](Skills/mobile/offensive-mobile/SKILL.md) | Android + iOS — Frida, pinning, storage, biometric, deep links |

### IoT & Embedded

`Skills/iot/`

| Skill | Description |
|---|---|
| [`offensive-iot`](Skills/iot/offensive-iot/SKILL.md) | Hardware recon, firmware, RTOS, ICS/OT, MQTT/CoAP |

> **Note:** Being split into 10 focused skills (UART/JTAG, flash dump, fault injection, U-Boot, secure boot, RTOS, ICS protocols). See [Roadmap](#roadmap).

### Infrastructure & Red Team

`Skills/infrastructure/`

| Skill | Description |
|---|---|
| [`offensive-initial-access`](Skills/infrastructure/offensive-initial-access/SKILL.md) | Phishing, drive-by, supply chain — TA0001 |
| [`offensive-advanced-redteam`](Skills/infrastructure/offensive-advanced-redteam/SKILL.md) | Full kill chain, C2, OPSEC, lateral, persistence |
| [`offensive-edr-evasion`](Skills/infrastructure/offensive-edr-evasion/SKILL.md) | Unhooking, indirect syscalls, PPID spoofing |
| [`offensive-shellcode`](Skills/infrastructure/offensive-shellcode/SKILL.md) | Writing, encoding, injection techniques |
| [`offensive-keylogger-arch`](Skills/infrastructure/offensive-keylogger-arch/SKILL.md) | Keylogger architecture and input-capture techniques |
| [`offensive-windows-mitigations`](Skills/infrastructure/offensive-windows-mitigations/SKILL.md) | Windows mitigations — ACG, Arbitrary Code Guard |
| [`offensive-windows-boundaries`](Skills/infrastructure/offensive-windows-boundaries/SKILL.md) | Defeating Windows boundaries — sandbox escape, privilege |

### Exploit Development

`Skills/exploit-dev/`

| Skill | Description |
|---|---|
| [`offensive-exploit-development`](Skills/exploit-dev/offensive-exploit-development/SKILL.md) | Stack/heap, ROP chains, mitigations |
| [`offensive-exploit-dev-course`](Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md) | Structured curriculum format |
| [`offensive-basic-exploitation`](Skills/exploit-dev/offensive-basic-exploitation/SKILL.md) | Linux exploitation, mitigations disabled — beginner-to-mid |
| [`offensive-crash-analysis`](Skills/exploit-dev/offensive-crash-analysis/SKILL.md) | Crash triage, exploitability assessment, root cause |
| [`offensive-mitigations`](Skills/exploit-dev/offensive-mitigations/SKILL.md) | Modern kernel mitigations — ASLR, CFG, CET, PAC |
| [`offensive-toctou`](Skills/exploit-dev/offensive-toctou/SKILL.md) | Time-of-check/use across binary, kernel, web, container |

### Fuzzing & Vulnerability Research

`Skills/fuzzing/`

| Skill | Description |
|---|---|
| [`offensive-fuzzing`](Skills/fuzzing/offensive-fuzzing/SKILL.md) | libFuzzer, AFL++, coverage-guided, mutation strategies |
| [`offensive-fuzzing-course`](Skills/fuzzing/offensive-fuzzing-course/SKILL.md) | Curriculum — finding vulns via fuzzing |
| [`offensive-bug-identification`](Skills/fuzzing/offensive-bug-identification/SKILL.md) | Code review patterns, static analysis triggers |
| [`offensive-vuln-classes`](Skills/fuzzing/offensive-vuln-classes/SKILL.md) | Vulnerability classes — real-world examples, taxonomy |

### Reconnaissance

`Skills/recon/`

| Skill | Description |
|---|---|
| [`offensive-osint`](Skills/recon/offensive-osint/SKILL.md) | OSINT tools — recon-ng, theHarvester, Maltego pipelines |
| [`offensive-osint-methodology`](Skills/recon/offensive-osint-methodology/SKILL.md) | OSINT methodology — structured intelligence collection |

### AI Security

`Skills/ai/`

| Skill | Description |
|---|---|
| [`offensive-ai-security`](Skills/ai/offensive-ai-security/SKILL.md) | AI pentest — prompt injection, jailbreaking, RAG poisoning |

### Utility

`Skills/utility/`

| Skill | Description |
|---|---|
| [`offensive-fast-checking`](Skills/utility/offensive-fast-checking/SKILL.md) | Fast triage checklist — quick-win identification |
| [`offensive-reporting`](Skills/utility/offensive-reporting/SKILL.md) | Pro pentest reporting — CVSS, evidence, exec summary, retest |

---

## Roadmap

The library is being expanded in seven phases. Track progress in [CHANGELOG.md](CHANGELOG.md).

| Phase | Category | New Skills | Status |
|---|---|---:|---|
| 1 | Internal AD/Windows (rename `active-directory/` → `internal/`) | +16 | Planned |
| 2 | Cloud Identity (Entra/AAD, ADFS, Okta, M365) | +10 | Planned |
| 3 | Wireless split (WPA2/3, EAP, BLE, Zigbee, Z-Wave, LoRa, sub-GHz) | +12 | **Mandatory** |
| 4 | IoT split (UART/JTAG, flash, fault injection, RTOS, ICS) | +10 | Planned |
| 5 | Web Basics (recon, auth bypass, access control, CSRF, headers, CORS, cache, clickjack) | +8 | Planned |
| 6 | Web Advanced (proto pollution, SAML, OIDC, WebSocket, gRPC, postMessage, SSI/ESI, CSTI) | +10 | Planned |
| 7 | Polish (README, LICENSE, manifest, install) | — | **In progress** |

End state: ~107 skills across the same 13+ categories.

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the skill template, frontmatter standard, and review process. Focused, single-surface skills are preferred over monolithic overviews.

## License

[MIT](LICENSE) — use freely, attribution appreciated.

## Acknowledgements

- **Author:** Kai Aizen (SnailSploit) — [snailsploit.com](https://snailsploit.com)
- **Original Checklists:** [Sahar Shlichov](https://github.com/sahar042/offensive-checklist) — the offensive checklist collection many of these skills are based on.
- **Community:** PRs and feedback that keep the library current with the threat landscape.

---

<div align="center">

> *"Give the agent the right skill and it stops being a chatbot. It becomes an operator."*

</div>

<!-- snailsploit-backlink:start -->

---

## 📚 Documentation & Author

This project's full writeup, methodology, and related research lives at:

**Upstream:** [https://snailsploit.com/claude-red](https://snailsploit.com/claude-red)

Created by **Kai Aizen** — independent offensive security researcher.

[snailsploit.com](https://snailsploit.com) · [Research](https://snailsploit.com/research) · [Frameworks](https://snailsploit.com/frameworks) · [GitHub](https://github.com/SnailSploit) · [LinkedIn](https://linkedin.com/in/kaiaizen) · [ResearchGate](https://www.researchgate.net/profile/Kai-Aizen-2) · [X/Twitter](https://x.com/SnailSploit)

> *Same attack. Different substrate.*

<!-- snailsploit-backlink:end -->
