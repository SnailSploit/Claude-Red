![claude-red banner](/assets/banner.png)

<div align="center">

# claude-red

**Offensive security skills for Claude — drop-in `SKILL.md` files that turn Claude into a context-aware red team operator.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-78-red.svg)](#skill-index)
[![Categories](https://img.shields.io/badge/categories-23-orange.svg)](#categories)
[![Stars](https://img.shields.io/github/stars/SnailSploit/claude-red?style=social)](https://github.com/SnailSploit/claude-red)
[![Forks](https://img.shields.io/github/forks/SnailSploit/claude-red?style=social)](https://github.com/SnailSploit/claude-red/network/members)

Built by **[SnailSploit](https://snailsploit.com)** — GenAI Security Research.

</div>

---

## Table of Contents

- [What is this](#what-is-this)
- [Quickstart](#quickstart)
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
  - [API Security](#api-security)
  - [Container & Kubernetes](#container--kubernetes)
  - [CI/CD & Pipeline](#cicd--pipeline)
  - [Cryptography](#cryptography)
  - [Privilege Escalation](#privilege-escalation)
  - [Post-Exploitation](#post-exploitation)
  - [Forensics & C2](#forensics--c2)
  - [Supply Chain](#supply-chain)
  - [Social Engineering](#social-engineering)
  - [Network Attacks](#network-attacks)
  - [AI Security](#ai-security)
  - [Utility](#utility)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## What is this

`claude-red` is a curated library of offensive security skills for the [Claude Skills system](https://docs.claude.com). Each skill is a structured `SKILL.md` file that primes Claude with expert-level methodology for a specific attack surface — from SQLi to shellcode, EDR evasion to ADCS abuse.

Drop a skill into your Claude environment and it behaves like a specialist: it knows the techniques, the tooling, the edge cases, and the escalation paths. Skills load on demand based on conversational triggers — you don't pay context for skills you aren't using.

**Use it for:** authorized red team engagements, bug bounty triage, security research, CTF preparation, training operators, and exploring attack surfaces methodically.

---

## Quickstart

### Claude Skills System (recommended)

```bash
# Clone into a directory Claude will scan
git clone https://github.com/SnailSploit/claude-red ~/.claude/skills/claude-red

# Or install only one category
git clone --filter=blob:none --sparse https://github.com/SnailSploit/claude-red
cd claude-red && git sparse-checkout set Skills/web Skills/active-directory
```

Claude will auto-load matching skills based on conversational triggers (e.g. mentioning SQLi loads `offensive-sqli`).

### Claude Code

```bash
# Point Claude at a single skill before a session
cat Skills/web/offensive-sqli/SKILL.md | claude --system-file -

# Or load a whole category
cat Skills/active-directory/**/SKILL.md | claude --system-file -
```

### Claude.ai (Manual)

Paste the contents of a `SKILL.md` into a Project's system prompt or prepend to your conversation.

### Install Script

```bash
./install.sh                           # interactive
./install.sh --target ~/.claude/skills # explicit target
./install.sh --category web            # one category
```

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
| [Infrastructure & Red Team](#infrastructure--red-team) | 7 | Initial access, EDR evasion, advanced red team ops, Windows internals |
| [Exploit Development](#exploit-development) | 6 | Stack/heap, mitigations, crash analysis, TOCTOU |
| [Fuzzing & VR](#fuzzing--vulnerability-research) | 4 | libFuzzer, AFL++, bug ID, vuln classes |
| [Reconnaissance](#reconnaissance) | 2 | OSINT tooling and methodology |
| [API Security](#api-security) | 2 | REST/gRPC/WebSocket testing, business logic abuse |
| [Container & Kubernetes](#container--kubernetes) | 2 | Container escape, K8s cluster attacks |
| [CI/CD & Pipeline](#cicd--pipeline) | 2 | Pipeline exploitation, secrets extraction |
| [Cryptography](#cryptography) | 2 | Crypto implementation attacks, TLS/SSL |
| [Privilege Escalation](#privilege-escalation) | 2 | Linux and Windows privesc |
| [Post-Exploitation](#post-exploitation) | 3 | Lateral movement, persistence, data exfiltration |
| [Forensics & C2](#forensics--c2) | 2 | Anti-forensics, C2 framework tradecraft |
| [Supply Chain](#supply-chain) | 2 | Supply chain attacks, dependency confusion |
| [Social Engineering](#social-engineering) | 2 | Phishing campaigns, physical/vishing/smishing |
| [Network Attacks](#network-attacks) | 1 | Layer 2/3 attacks, MITM, poisoning |
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
| [`offensive-active-directory`](Skills/active-directory/offensive-active-directory/SKILL.md) | AD — Kerberoast, ASREProast, Pre-Windows 2000 computers, ACL abuse, ADCS ESC1-15, delegation, persistence, hybrid AAD |

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

### API Security

`Skills/api/`

| Skill | Description |
|---|---|
| [`offensive-api-security`](Skills/api/offensive-api-security/SKILL.md) | API testing — OWASP API Top 10, REST/gRPC/WebSocket, BOLA, BFLA, mass assignment |
| [`offensive-api-abuse`](Skills/api/offensive-api-abuse/SKILL.md) | API business logic — chaining, batching, JWT manipulation, webhook hijacking |

### Container & Kubernetes

`Skills/container/`

| Skill | Description |
|---|---|
| [`offensive-container-escape`](Skills/container/offensive-container-escape/SKILL.md) | Container breakout — privileged escape, Docker socket, capabilities, cgroup, runc CVEs |
| [`offensive-k8s-attacks`](Skills/container/offensive-k8s-attacks/SKILL.md) | Kubernetes — RBAC abuse, etcd access, kubelet API, pod escape, secrets, CRD exploitation |

### CI/CD & Pipeline

`Skills/cicd/`

| Skill | Description |
|---|---|
| [`offensive-cicd-pipeline`](Skills/cicd/offensive-cicd-pipeline/SKILL.md) | CI/CD exploitation — GitHub Actions injection, Jenkins RCE, GitLab CI, Azure DevOps |
| [`offensive-cicd-secrets`](Skills/cicd/offensive-cicd-secrets/SKILL.md) | CI/CD secrets — env var extraction, vault misconfigs, OIDC federation, runner token abuse |

### Cryptography

`Skills/crypto/`

| Skill | Description |
|---|---|
| [`offensive-crypto-attacks`](Skills/crypto/offensive-crypto-attacks/SKILL.md) | Crypto attacks — padding oracle, ECB manipulation, hash extension, RSA, weak PRNG |
| [`offensive-tls-attacks`](Skills/crypto/offensive-tls-attacks/SKILL.md) | TLS/SSL — POODLE, DROWN, Heartbleed, pinning bypass, HSTS bypass, 0-RTT replay |

### Privilege Escalation

`Skills/privesc/`

| Skill | Description |
|---|---|
| [`offensive-linux-privesc`](Skills/privesc/offensive-linux-privesc/SKILL.md) | Linux privesc — SUID, capabilities, sudo, cron, kernel exploits, Docker group |
| [`offensive-windows-privesc`](Skills/privesc/offensive-windows-privesc/SKILL.md) | Windows privesc — Potato family, service misconfigs, DLL hijacking, UAC bypass, PrintNightmare |

### Post-Exploitation

`Skills/post-exploitation/`

| Skill | Description |
|---|---|
| [`offensive-lateral-movement`](Skills/post-exploitation/offensive-lateral-movement/SKILL.md) | Lateral movement — PTH, PTT, NTLM relay, WMI/WinRM/DCOM, tunneling (chisel, ligolo-ng) |
| [`offensive-persistence`](Skills/post-exploitation/offensive-persistence/SKILL.md) | Persistence — registry, scheduled tasks, WMI subs, Golden/Silver tickets, PAM backdoors |
| [`offensive-data-exfiltration`](Skills/post-exploitation/offensive-data-exfiltration/SKILL.md) | Data exfiltration — DNS/HTTPS/ICMP tunneling, cloud dead drops, steganography |

### Forensics & C2

`Skills/forensics/`

| Skill | Description |
|---|---|
| [`offensive-anti-forensics`](Skills/forensics/offensive-anti-forensics/SKILL.md) | Anti-forensics — log clearing, timestomping, ADS hiding, memory cleanup, anti-VM |
| [`offensive-c2-frameworks`](Skills/forensics/offensive-c2-frameworks/SKILL.md) | C2 tradecraft — Cobalt Strike, Sliver, Mythic, Havoc, Metasploit, redirectors, domain fronting |

### Supply Chain

`Skills/supply-chain/`

| Skill | Description |
|---|---|
| [`offensive-supply-chain`](Skills/supply-chain/offensive-supply-chain/SKILL.md) | Supply chain — dependency confusion, typosquatting, build system attacks, image trojaning |
| [`offensive-dependency-confusion`](Skills/supply-chain/offensive-dependency-confusion/SKILL.md) | Dependency confusion — npm/PyPI/NuGet/Maven/Go namespace attacks, safe PoC methodology |

### Social Engineering

`Skills/social-engineering/`

| Skill | Description |
|---|---|
| [`offensive-phishing`](Skills/social-engineering/offensive-phishing/SKILL.md) | Phishing — GoPhish, EvilGinx2, payload delivery, email auth bypass, MFA phishing |
| [`offensive-social-engineering`](Skills/social-engineering/offensive-social-engineering/SKILL.md) | Social engineering — pretexting, vishing, smishing, physical SE, USB drops, watering holes |

### Network Attacks

`Skills/network/`

| Skill | Description |
|---|---|
| [`offensive-network-attacks`](Skills/network/offensive-network-attacks/SKILL.md) | Network L2/L3 — ARP spoofing, LLMNR/NBT-NS poisoning, VLAN hopping, IPv6 attacks, MITM |

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
| 3 | Wireless split (WPA2/3, EAP, BLE, Zigbee, Z-Wave, LoRa, sub-GHz) | +12 | **Done** |
| 4 | IoT split (UART/JTAG, flash, fault injection, RTOS, ICS) | +10 | Planned |
| 5 | Web Basics (recon, auth bypass, access control, CSRF, headers, CORS, cache, clickjack) | +8 | Planned |
| 6 | Web Advanced (proto pollution, SAML, OIDC, WebSocket, gRPC, postMessage, SSI/ESI, CSTI) | +10 | Planned |
| 7 | Polish (README, LICENSE, manifest, install) | — | **Done** |
| 8 | New categories (API, container, CI/CD, crypto, privesc, post-exploitation, forensics/C2, supply chain, social engineering, network) | +20 | **Done** |
| 9 | Deep rewrites (deserialization, GraphQL, advanced red team, SSTI) | — | **Done** |

End state: ~130 skills across 23+ categories.

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

> *"Give Claude the right skill and it stops being a chatbot. It becomes an operator."*

</div>

<!-- snailsploit-backlink:start -->

---

## 📚 Documentation & Author

This project's full writeup, methodology, and related research lives at:

**[https://snailsploit.com/claude-red](https://snailsploit.com/claude-red)**

Created by **Kai Aizen** — independent offensive security researcher.

[snailsploit.com](https://snailsploit.com) · [Research](https://snailsploit.com/research) · [Frameworks](https://snailsploit.com/frameworks) · [GitHub](https://github.com/SnailSploit) · [LinkedIn](https://linkedin.com/in/kaiaizen) · [ResearchGate](https://www.researchgate.net/profile/Kai-Aizen-2) · [X/Twitter](https://x.com/SnailSploit)

> *Same attack. Different substrate.*

<!-- snailsploit-backlink:end -->
