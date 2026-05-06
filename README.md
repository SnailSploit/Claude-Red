![claude-red banner](/assets/banner.png)

<div align="center">

# claude-red

**Offensive security skills for Claude — drop-in `SKILL.md` files that turn Claude into a context-aware red team operator.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-112-red.svg)](#skill-index)
[![Categories](https://img.shields.io/badge/categories-14-orange.svg)](#categories)
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
  - [Internal (AD / Windows)](#internal-ad--windows)
  - [Cloud Identity (Hybrid)](#cloud-identity-hybrid)
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
- [Mindmap](#mindmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## What is this

`claude-red` is a curated library of offensive security skills for the [Claude Skills system](https://docs.claude.com). Each skill is a structured `SKILL.md` file that primes Claude with expert-level methodology for a specific attack surface — from SQLi to Active Directory exploitation, ADCS abuse to cloud-identity hybrid attacks.

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
cd claude-red && git sparse-checkout set Skills/web Skills/internal
```

Claude will auto-load matching skills based on conversational triggers (e.g. mentioning Kerberoasting loads `offensive-kerberoasting`).

### Claude Code

```bash
# Point Claude at a single skill before a session
cat Skills/web/offensive-sqli/SKILL.md | claude --system-file -

# Or load a whole category
cat Skills/internal/**/SKILL.md | claude --system-file -
```

### Claude.ai (Manual)

Paste the contents of a `SKILL.md` into a Project's system prompt or prepend to your conversation.

### Install Script

```bash
./install.sh                              # interactive
./install.sh --target ~/.claude/skills    # explicit target
./install.sh --category internal          # one category
./install.sh --list                       # list available categories
```

---

## Categories

| Category | Skills | Focus |
|---|---:|---|
| [Web Application](#web-application) | 26 | OWASP Top 10, business logic, basics, advanced (SAML, OIDC, prototype pollution, CSTI, gRPC) |
| [Auth & Identity](#auth--identity) | 2 | JWT, OAuth |
| [Internal (AD / Windows)](#internal-ad--windows) | 21 | AD attack chain end-to-end + Windows-side ops |
| [Cloud Identity (Hybrid)](#cloud-identity-hybrid) | 10 | Entra ID, AAD Connect, Golden SAML, PRT, Okta, M365 |
| [Wireless](#wireless) | 14 | 802.11, EAP, WPS, evil-twin, BLE, Zigbee, Z-Wave, LoRa |
| [Cloud](#cloud) | 1 | AWS / Azure / GCP attack paths |
| [Mobile](#mobile) | 1 | Android + iOS pentest |
| [IoT & Embedded](#iot--embedded) | 11 | Hardware, firmware, RTOS, ICS, MQTT/CoAP |
| [Infrastructure & Red Team](#infrastructure--red-team) | 3 | Initial access, advanced ops, shellcode |
| [Exploit Development](#exploit-development) | 6 | Stack/heap, mitigations, crash analysis, TOCTOU |
| [Fuzzing & VR](#fuzzing--vulnerability-research) | 4 | libFuzzer, AFL++, bug ID, vuln classes |
| [Reconnaissance](#reconnaissance) | 2 | OSINT tooling and methodology |
| [AI Security](#ai-security) | 1 | Prompt injection, jailbreaks, RAG poisoning |
| [Utility](#utility) | 2 | Fast-checking, professional reporting |

---

## Skill Index

### Web Application

`Skills/web/`

**OWASP Top 10 + Business Logic (16):**

| Skill | Description |
|---|---|
| [`offensive-sqli`](Skills/web/offensive-sqli/SKILL.md) | SQL injection — error/blind/OOB, DB-specific, ORM CVEs |
| [`offensive-xss`](Skills/web/offensive-xss/SKILL.md) | Cross-site scripting — stored, reflected, DOM, mutation |
| [`offensive-ssrf`](Skills/web/offensive-ssrf/SKILL.md) | SSRF — cloud metadata, filter bypass |
| [`offensive-ssti`](Skills/web/offensive-ssti/SKILL.md) | Server-side template injection |
| [`offensive-xxe`](Skills/web/offensive-xxe/SKILL.md) | XML external entity |
| [`offensive-idor`](Skills/web/offensive-idor/SKILL.md) | Insecure direct object references |
| [`offensive-file-upload`](Skills/web/offensive-file-upload/SKILL.md) | File upload — bypass, polyglots, webshells |
| [`offensive-rce`](Skills/web/offensive-rce/SKILL.md) | Remote code execution chains |
| [`offensive-deserialization`](Skills/web/offensive-deserialization/SKILL.md) | Insecure deserialization |
| [`offensive-race-condition`](Skills/web/offensive-race-condition/SKILL.md) | Race conditions, single-packet attacks |
| [`offensive-request-smuggling`](Skills/web/offensive-request-smuggling/SKILL.md) | HTTP request smuggling |
| [`offensive-open-redirect`](Skills/web/offensive-open-redirect/SKILL.md) | Open redirect chains |
| [`offensive-parameter-pollution`](Skills/web/offensive-parameter-pollution/SKILL.md) | HPP — WAF bypass, logic confusion |
| [`offensive-graphql`](Skills/web/offensive-graphql/SKILL.md) | GraphQL — introspection, batching, IDOR |
| [`offensive-waf-bypass`](Skills/web/offensive-waf-bypass/SKILL.md) | WAF bypass techniques |
| [`offensive-business-logic`](Skills/web/offensive-business-logic/SKILL.md) | Workflow bypass, pricing, refunds, chains |

**Web Basics (8):**

| Skill | Description |
|---|---|
| [`offensive-web-recon`](Skills/web/offensive-web-recon/SKILL.md) | Content discovery, JS bundle analysis, hidden parameters |
| [`offensive-auth-bypass`](Skills/web/offensive-auth-bypass/SKILL.md) | Login bypass, password reset, MFA bypass |
| [`offensive-access-control`](Skills/web/offensive-access-control/SKILL.md) | RBAC bypass, mass assignment, method tampering |
| [`offensive-csrf-samesite`](Skills/web/offensive-csrf-samesite/SKILL.md) | CSRF, SameSite bypass, login CSRF |
| [`offensive-header-attacks`](Skills/web/offensive-header-attacks/SKILL.md) | Host injection, X-Forwarded, CRLF |
| [`offensive-cors-misconfig`](Skills/web/offensive-cors-misconfig/SKILL.md) | Origin reflection, null bypass, regex flaws |
| [`offensive-cache-poisoning-deception`](Skills/web/offensive-cache-poisoning-deception/SKILL.md) | Unkeyed input, cache deception |
| [`offensive-clickjacking`](Skills/web/offensive-clickjacking/SKILL.md) | iframe overlay, OAuth consent hijack, tapjacking |

**Web Advanced (10):**

| Skill | Description |
|---|---|
| [`offensive-prototype-pollution`](Skills/web/offensive-prototype-pollution/SKILL.md) | __proto__ injection, Node.js gadgets |
| [`offensive-mass-assignment`](Skills/web/offensive-mass-assignment/SKILL.md) | Privileged field over-posting |
| [`offensive-saml-attacks`](Skills/web/offensive-saml-attacks/SKILL.md) | XSW, comment injection, KeyInfo, Golden SAML |
| [`offensive-oidc-attacks`](Skills/web/offensive-oidc-attacks/SKILL.md) | ID token validation, alg confusion, JWKS override |
| [`offensive-websocket`](Skills/web/offensive-websocket/SKILL.md) | CSWSH, post-handshake authz, message injection |
| [`offensive-grpc`](Skills/web/offensive-grpc/SKILL.md) | Reflection enum, schema recovery, interceptor bypass |
| [`offensive-postmessage`](Skills/web/offensive-postmessage/SKILL.md) | Origin check flaws, OAuth callback hijack |
| [`offensive-ssi-esi`](Skills/web/offensive-ssi-esi/SKILL.md) | SSI exec, ESI to SSRF, cache poisoning chain |
| [`offensive-csti`](Skills/web/offensive-csti/SKILL.md) | Client-side template injection, AngularJS sandbox |
| [`offensive-dom-clobbering`](Skills/web/offensive-dom-clobbering/SKILL.md) | Named element global override, DOMPurify bypass |

### Auth & Identity

`Skills/auth/`

| Skill | Description |
|---|---|
| [`offensive-jwt`](Skills/auth/offensive-jwt/SKILL.md) | JWT — alg:none, key confusion, secret cracking |
| [`offensive-oauth`](Skills/auth/offensive-oauth/SKILL.md) | OAuth — open redirect, token leakage, PKCE bypass |

### Internal (AD / Windows)

`Skills/internal/`

| Skill | Description |
|---|---|
| [`offensive-active-directory`](Skills/internal/offensive-active-directory/SKILL.md) | AD attack overview / category index |
| [`offensive-internal-recon`](Skills/internal/offensive-internal-recon/SKILL.md) | BloodHound, PowerView, ADExplorer |
| [`offensive-network-poisoning`](Skills/internal/offensive-network-poisoning/SKILL.md) | LLMNR/NBT-NS/mDNS/IPv6, Responder, mitm6 |
| [`offensive-ntlm-relay`](Skills/internal/offensive-ntlm-relay/SKILL.md) | impacket-ntlmrelayx chains, EPA awareness |
| [`offensive-coercion`](Skills/internal/offensive-coercion/SKILL.md) | PetitPotam, PrinterBug, DFSCoerce, Coercer |
| [`offensive-kerberoasting`](Skills/internal/offensive-kerberoasting/SKILL.md) | SPN enum, TGS roast, targeted via WriteSPN |
| [`offensive-asreproasting`](Skills/internal/offensive-asreproasting/SKILL.md) | DONT_REQUIRE_PREAUTH abuse |
| [`offensive-acl-abuse`](Skills/internal/offensive-acl-abuse/SKILL.md) | GenericAll/Write/WriteDacl/WriteOwner cookbook |
| [`offensive-adcs`](Skills/internal/offensive-adcs/SKILL.md) | ESC1-ESC15, certipy, Shadow Credentials, UnPAC |
| [`offensive-kerberos-delegation`](Skills/internal/offensive-kerberos-delegation/SKILL.md) | Unconstrained, S4U, RBCD chains |
| [`offensive-pass-the-x`](Skills/internal/offensive-pass-the-x/SKILL.md) | PtH/PtT/OPth/PtC variants |
| [`offensive-lsass-dumping`](Skills/internal/offensive-lsass-dumping/SKILL.md) | comsvcs, nanodump, pypykatz, PPL awareness |
| [`offensive-ticket-forgery`](Skills/internal/offensive-ticket-forgery/SKILL.md) | Golden, Silver, Diamond, Sapphire |
| [`offensive-dcsync-dcshadow`](Skills/internal/offensive-dcsync-dcshadow/SKILL.md) | Replication abuse, AdminSDHolder persistence |
| [`offensive-gpo-abuse`](Skills/internal/offensive-gpo-abuse/SKILL.md) | SharpGPOAbuse, GPP cpassword |
| [`offensive-trust-attacks`](Skills/internal/offensive-trust-attacks/SKILL.md) | SID History, trust ticket forging |
| [`offensive-network-pivoting`](Skills/internal/offensive-network-pivoting/SKILL.md) | Chisel, Ligolo-ng, sshuttle, proxychains |
| [`offensive-edr-evasion`](Skills/internal/offensive-edr-evasion/SKILL.md) | Unhooking, indirect syscalls, PPID spoofing |
| [`offensive-windows-mitigations`](Skills/internal/offensive-windows-mitigations/SKILL.md) | ACG, Arbitrary Code Guard, exploit guard |
| [`offensive-windows-boundaries`](Skills/internal/offensive-windows-boundaries/SKILL.md) | Sandbox escape, privilege boundaries |
| [`offensive-keylogger-arch`](Skills/internal/offensive-keylogger-arch/SKILL.md) | Keylogger architecture, input capture |

### Cloud Identity (Hybrid)

`Skills/cloud-identity/`

| Skill | Description |
|---|---|
| [`offensive-entra-recon`](Skills/cloud-identity/offensive-entra-recon/SKILL.md) | ROADtools, AzureHound, MS Graph enum |
| [`offensive-entra-privesc`](Skills/cloud-identity/offensive-entra-privesc/SKILL.md) | App Admin abuse, PIM activation, custom role escalate |
| [`offensive-aadconnect-attacks`](Skills/cloud-identity/offensive-aadconnect-attacks/SKILL.md) | MSOL_ DCSync, PHS, PTA hook, Seamless SSO ticket |
| [`offensive-golden-saml`](Skills/cloud-identity/offensive-golden-saml/SKILL.md) | ADFS token-signing cert theft, SAML forgery |
| [`offensive-pass-the-prt`](Skills/cloud-identity/offensive-pass-the-prt/SKILL.md) | PRT extraction, cloud session hijack |
| [`offensive-conditional-access-bypass`](Skills/cloud-identity/offensive-conditional-access-bypass/SKILL.md) | Excluded apps/users, trusted location, break-glass |
| [`offensive-device-code-phish`](Skills/cloud-identity/offensive-device-code-phish/SKILL.md) | OAuth device code flow phishing |
| [`offensive-illicit-consent`](Skills/cloud-identity/offensive-illicit-consent/SKILL.md) | Attacker app + scope phishing |
| [`offensive-m365-recon`](Skills/cloud-identity/offensive-m365-recon/SKILL.md) | Mailbox, SharePoint, Teams, Power Platform |
| [`offensive-okta-attacks`](Skills/cloud-identity/offensive-okta-attacks/SKILL.md) | Push fatigue, session theft, SSO chain pivots |

### Wireless

`Skills/wireless/`

| Skill | Description |
|---|---|
| [`offensive-wifi`](Skills/wireless/offensive-wifi/SKILL.md) | Wireless overview / category index |
| [`offensive-wifi-recon`](Skills/wireless/offensive-wifi-recon/SKILL.md) | Adapter, monitor mode, multi-band recon |
| [`offensive-wpa2-psk`](Skills/wireless/offensive-wpa2-psk/SKILL.md) | Handshake, PMKID, hashcat 22000 |
| [`offensive-wpa3-sae`](Skills/wireless/offensive-wpa3-sae/SKILL.md) | Transition downgrade, Dragonblood, SAE |
| [`offensive-wpa-enterprise`](Skills/wireless/offensive-wpa-enterprise/SKILL.md) | 802.1X / EAP, eaphammer evil-twin RADIUS |
| [`offensive-wps`](Skills/wireless/offensive-wps/SKILL.md) | Pixie Dust, online brute, vendor PIN |
| [`offensive-evil-twin`](Skills/wireless/offensive-evil-twin/SKILL.md) | KARMA/Mana, captive portal, MITM |
| [`offensive-krack-fragattacks`](Skills/wireless/offensive-krack-fragattacks/SKILL.md) | KRACK + FragAttacks supplicant testing |
| [`offensive-deauth-disassoc`](Skills/wireless/offensive-deauth-disassoc/SKILL.md) | Deauth tactics, PMF, action frames |
| [`offensive-bluetooth-ble`](Skills/wireless/offensive-bluetooth-ble/SKILL.md) | BLE GATT, pairing, MITM |
| [`offensive-bluetooth-classic`](Skills/wireless/offensive-bluetooth-classic/SKILL.md) | BR/EDR — SDP, SPP, KNOB, BlueBorne |
| [`offensive-zigbee-thread-matter`](Skills/wireless/offensive-zigbee-thread-matter/SKILL.md) | KillerBee, Touchlink, ZCL commands |
| [`offensive-z-wave`](Skills/wireless/offensive-z-wave/SKILL.md) | S0/S2, hub pivots |
| [`offensive-lorawan-sub-ghz`](Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md) | LoRaWAN ABP/OTAA, KeeLoq, TPMS |

### Cloud

`Skills/cloud/`

| Skill | Description |
|---|---|
| [`offensive-cloud`](Skills/cloud/offensive-cloud/SKILL.md) | AWS/Azure/GCP — privesc, IMDS, persistence, CSPM evasion |

### Mobile

`Skills/mobile/`

| Skill | Description |
|---|---|
| [`offensive-mobile`](Skills/mobile/offensive-mobile/SKILL.md) | Android + iOS — Frida, pinning, biometric, deep links |

### IoT & Embedded

`Skills/iot/`

| Skill | Description |
|---|---|
| [`offensive-iot`](Skills/iot/offensive-iot/SKILL.md) | IoT/embedded overview |
| [`offensive-iot-hardware-recon`](Skills/iot/offensive-iot-hardware-recon/SKILL.md) | PCB inspection, SoC ID, debug-pad discovery |
| [`offensive-uart-jtag-swd`](Skills/iot/offensive-uart-jtag-swd/SKILL.md) | UART console, JTAG/SWD, RDP bypass |
| [`offensive-flash-dumping`](Skills/iot/offensive-flash-dumping/SKILL.md) | SPI NOR / eMMC / NAND extraction |
| [`offensive-fault-injection`](Skills/iot/offensive-fault-injection/SKILL.md) | Voltage/clock/EM glitching |
| [`offensive-firmware-analysis`](Skills/iot/offensive-firmware-analysis/SKILL.md) | binwalk, fs extraction, CGI auditing |
| [`offensive-uboot-bypass`](Skills/iot/offensive-uboot-bypass/SKILL.md) | U-Boot console drop, env injection |
| [`offensive-secure-boot-bypass`](Skills/iot/offensive-secure-boot-bypass/SKILL.md) | Anti-rollback, downgrade, signature glitch |
| [`offensive-rtos-pwn`](Skills/iot/offensive-rtos-pwn/SKILL.md) | FreeRTOS / Zephyr / ThreadX |
| [`offensive-ics-ot-protocols`](Skills/iot/offensive-ics-ot-protocols/SKILL.md) | Modbus, BACnet, OPC-UA, S7, DNP3 |
| [`offensive-mqtt-coap`](Skills/iot/offensive-mqtt-coap/SKILL.md) | MQTT broker abuse, retained, CoAP DTLS |

### Infrastructure & Red Team

`Skills/infrastructure/`

| Skill | Description |
|---|---|
| [`offensive-initial-access`](Skills/infrastructure/offensive-initial-access/SKILL.md) | Phishing, drive-by, supply chain |
| [`offensive-advanced-redteam`](Skills/infrastructure/offensive-advanced-redteam/SKILL.md) | Full kill chain, C2, OPSEC |
| [`offensive-shellcode`](Skills/infrastructure/offensive-shellcode/SKILL.md) | Writing, encoding, injection |

### Exploit Development

`Skills/exploit-dev/`

| Skill | Description |
|---|---|
| [`offensive-exploit-development`](Skills/exploit-dev/offensive-exploit-development/SKILL.md) | Stack/heap, ROP, mitigations |
| [`offensive-exploit-dev-course`](Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md) | Structured curriculum format |
| [`offensive-basic-exploitation`](Skills/exploit-dev/offensive-basic-exploitation/SKILL.md) | Linux, mitigations disabled |
| [`offensive-crash-analysis`](Skills/exploit-dev/offensive-crash-analysis/SKILL.md) | Crash triage, exploitability |
| [`offensive-mitigations`](Skills/exploit-dev/offensive-mitigations/SKILL.md) | Modern kernel mitigations |
| [`offensive-toctou`](Skills/exploit-dev/offensive-toctou/SKILL.md) | Time-of-check/use across layers |

### Fuzzing & Vulnerability Research

`Skills/fuzzing/`

| Skill | Description |
|---|---|
| [`offensive-fuzzing`](Skills/fuzzing/offensive-fuzzing/SKILL.md) | libFuzzer, AFL++, coverage-guided |
| [`offensive-fuzzing-course`](Skills/fuzzing/offensive-fuzzing-course/SKILL.md) | Curriculum format |
| [`offensive-bug-identification`](Skills/fuzzing/offensive-bug-identification/SKILL.md) | Code review, static analysis triggers |
| [`offensive-vuln-classes`](Skills/fuzzing/offensive-vuln-classes/SKILL.md) | Vulnerability classes, taxonomy |

### Reconnaissance

`Skills/recon/`

| Skill | Description |
|---|---|
| [`offensive-osint`](Skills/recon/offensive-osint/SKILL.md) | OSINT tools — recon-ng, theHarvester, Maltego |
| [`offensive-osint-methodology`](Skills/recon/offensive-osint-methodology/SKILL.md) | OSINT methodology |

### AI Security

`Skills/ai/`

| Skill | Description |
|---|---|
| [`offensive-ai-security`](Skills/ai/offensive-ai-security/SKILL.md) | Prompt injection, jailbreaking, RAG poisoning |

### Utility

`Skills/utility/`

| Skill | Description |
|---|---|
| [`offensive-fast-checking`](Skills/utility/offensive-fast-checking/SKILL.md) | Fast triage checklist |
| [`offensive-reporting`](Skills/utility/offensive-reporting/SKILL.md) | Pro pentest reporting — CVSS, evidence, exec summary |

---

## Mindmap

A visual map of the entire library — see [MINDMAP.md](MINDMAP.md) for the full Mermaid render and a coverage cross-reference against MITRE ATT&CK / OWASP WSTG.

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
