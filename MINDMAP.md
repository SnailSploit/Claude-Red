# claude-red — Library Mindmap

A visual map of every skill in the library, by category. Use it to navigate, to discover skills you didn't know existed, and to spot coverage gaps before an engagement.

References for completeness checking: [MITRE ATT&CK](https://attack.mitre.org/), [HackTricks](https://book.hacktricks.xyz/), [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/), [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).

---

## Library Map

```mermaid
mindmap
  root((claude-red))
    Web
      sqli
      xss
      ssrf
      ssti
      xxe
      idor
      file-upload
      rce
      deserialization
      race-condition
      request-smuggling
      open-redirect
      parameter-pollution
      graphql
      waf-bypass
      business-logic
      web-recon
      auth-bypass
      access-control
      csrf-samesite
      header-attacks
      cors-misconfig
      cache-poisoning-deception
      clickjacking
      prototype-pollution
      mass-assignment
      saml-attacks
      oidc-attacks
      websocket
      grpc
      postmessage
      ssi-esi
      csti
      dom-clobbering
    Auth
      jwt
      oauth
    Internal
      active-directory
      internal-recon
      network-poisoning
      ntlm-relay
      coercion
      kerberoasting
      asreproasting
      acl-abuse
      adcs
      kerberos-delegation
      pass-the-x
      lsass-dumping
      ticket-forgery
      dcsync-dcshadow
      gpo-abuse
      trust-attacks
      network-pivoting
      edr-evasion
      windows-mitigations
      windows-boundaries
      keylogger-arch
    Cloud-Identity
      entra-recon
      entra-privesc
      aadconnect-attacks
      golden-saml
      pass-the-prt
      conditional-access-bypass
      device-code-phish
      illicit-consent
      m365-recon
      okta-attacks
    Wireless
      wifi
      wifi-recon
      wpa2-psk
      wpa3-sae
      wpa-enterprise
      wps
      evil-twin
      krack-fragattacks
      deauth-disassoc
      bluetooth-ble
      bluetooth-classic
      zigbee-thread-matter
      z-wave
      lorawan-sub-ghz
    Cloud
      cloud
    Mobile
      mobile
    IoT
      iot
      iot-hardware-recon
      uart-jtag-swd
      flash-dumping
      fault-injection
      firmware-analysis
      uboot-bypass
      secure-boot-bypass
      rtos-pwn
      ics-ot-protocols
      mqtt-coap
    Infrastructure
      initial-access
      advanced-redteam
      shellcode
    Exploit-Dev
      exploit-development
      exploit-dev-course
      basic-exploitation
      crash-analysis
      mitigations
      toctou
    Fuzzing
      fuzzing
      fuzzing-course
      bug-identification
      vuln-classes
    Recon
      osint
      osint-methodology
    AI
      ai-security
    Utility
      fast-checking
      reporting
```

---

## Coverage Cross-Reference

Use this table to confirm coverage of common offensive surfaces. Every row maps to one or more skills.

### Web Application (OWASP WSTG)

| Surface | Skill |
|---|---|
| Information gathering | `web/offensive-web-recon`, `recon/*` |
| Configuration / deployment | `web/offensive-waf-bypass`, `web/offensive-header-attacks` |
| Identity management | `auth/offensive-jwt`, `auth/offensive-oauth`, `web/offensive-saml-attacks`, `web/offensive-oidc-attacks` |
| Authentication | `web/offensive-auth-bypass` |
| Authorization | `web/offensive-idor`, `web/offensive-access-control`, `web/offensive-mass-assignment` |
| Session management | `web/offensive-csrf-samesite`, `auth/*` |
| Input validation | `web/offensive-sqli`, `web/offensive-xss`, `web/offensive-xxe`, `web/offensive-ssti`, `web/offensive-ssrf`, `web/offensive-deserialization`, `web/offensive-file-upload`, `web/offensive-rce` |
| Cryptography | _(handled implicitly across skills)_ |
| Business logic | `web/offensive-business-logic` |
| Client-side | `web/offensive-xss`, `web/offensive-csti`, `web/offensive-dom-clobbering`, `web/offensive-postmessage`, `web/offensive-clickjacking` |
| API testing | `web/offensive-graphql`, `web/offensive-grpc`, `web/offensive-websocket` |
| Cache / CDN | `web/offensive-cache-poisoning-deception`, `web/offensive-ssi-esi` |
| Server-side prototype | `web/offensive-prototype-pollution` |
| CORS / cross-origin | `web/offensive-cors-misconfig` |

### Internal / Active Directory (MITRE ATT&CK Enterprise)

| Tactic | Skill |
|---|---|
| Reconnaissance | `internal/offensive-internal-recon`, `recon/*` |
| Initial Access | `infrastructure/offensive-initial-access` |
| Execution | `infrastructure/offensive-advanced-redteam` |
| Persistence | `internal/offensive-ticket-forgery`, `internal/offensive-dcsync-dcshadow`, `internal/offensive-gpo-abuse` |
| Privilege Escalation | `internal/offensive-acl-abuse`, `internal/offensive-adcs`, `internal/offensive-kerberos-delegation`, `internal/offensive-kerberoasting`, `internal/offensive-asreproasting` |
| Defense Evasion | `internal/offensive-edr-evasion`, `internal/offensive-windows-mitigations`, `internal/offensive-windows-boundaries` |
| Credential Access | `internal/offensive-network-poisoning`, `internal/offensive-ntlm-relay`, `internal/offensive-coercion`, `internal/offensive-lsass-dumping`, `internal/offensive-pass-the-x` |
| Discovery | `internal/offensive-internal-recon` |
| Lateral Movement | `internal/offensive-pass-the-x`, `internal/offensive-network-pivoting`, `internal/offensive-kerberos-delegation` |
| Collection | `infrastructure/offensive-advanced-redteam` |
| Command and Control | `infrastructure/offensive-advanced-redteam` |
| Exfiltration | `infrastructure/offensive-advanced-redteam` |
| Trust Attacks | `internal/offensive-trust-attacks` |

### Cloud Identity (Hybrid)

| Surface | Skill |
|---|---|
| Entra ID recon | `cloud-identity/offensive-entra-recon` |
| Entra ID privesc | `cloud-identity/offensive-entra-privesc` |
| AAD Connect / hybrid | `cloud-identity/offensive-aadconnect-attacks` |
| ADFS / federation | `cloud-identity/offensive-golden-saml` |
| Device PRT theft | `cloud-identity/offensive-pass-the-prt` |
| Conditional Access | `cloud-identity/offensive-conditional-access-bypass` |
| OAuth flow phishing | `cloud-identity/offensive-device-code-phish`, `cloud-identity/offensive-illicit-consent` |
| Microsoft 365 surface | `cloud-identity/offensive-m365-recon` |
| Okta IdP | `cloud-identity/offensive-okta-attacks` |

### Wireless

| Surface | Skill |
|---|---|
| Recon / war-driving | `wireless/offensive-wifi-recon` |
| WPA2-PSK | `wireless/offensive-wpa2-psk` |
| WPA3-SAE | `wireless/offensive-wpa3-sae` |
| WPA-Enterprise | `wireless/offensive-wpa-enterprise` |
| WPS | `wireless/offensive-wps` |
| Evil twin / KARMA / Mana | `wireless/offensive-evil-twin` |
| KRACK / FragAttacks | `wireless/offensive-krack-fragattacks` |
| Deauth / disassoc | `wireless/offensive-deauth-disassoc` |
| BLE | `wireless/offensive-bluetooth-ble` |
| Bluetooth Classic | `wireless/offensive-bluetooth-classic` |
| Zigbee / Thread / Matter | `wireless/offensive-zigbee-thread-matter` |
| Z-Wave | `wireless/offensive-z-wave` |
| LoRa / sub-GHz | `wireless/offensive-lorawan-sub-ghz` |

### Cloud (Infrastructure)

| Provider / Surface | Skill |
|---|---|
| AWS / Azure / GCP — IAM, IMDS, persistence | `cloud/offensive-cloud` |

### Mobile

| Platform | Skill |
|---|---|
| Android + iOS | `mobile/offensive-mobile` |

### IoT / Embedded

| Layer | Skill |
|---|---|
| Hardware recon | `iot/offensive-iot-hardware-recon` |
| UART / JTAG / SWD | `iot/offensive-uart-jtag-swd` |
| Flash extraction | `iot/offensive-flash-dumping` |
| Fault injection | `iot/offensive-fault-injection` |
| Firmware analysis | `iot/offensive-firmware-analysis` |
| Bootloader | `iot/offensive-uboot-bypass` |
| Secure boot bypass | `iot/offensive-secure-boot-bypass` |
| RTOS exploitation | `iot/offensive-rtos-pwn` |
| ICS / OT protocols | `iot/offensive-ics-ot-protocols` |
| MQTT / CoAP | `iot/offensive-mqtt-coap` |

### Exploit Development

| Topic | Skill |
|---|---|
| Beginner / mitigations off | `exploit-dev/offensive-basic-exploitation` |
| Course curriculum | `exploit-dev/offensive-exploit-dev-course` |
| Stack / heap / ROP | `exploit-dev/offensive-exploit-development` |
| Modern mitigations | `exploit-dev/offensive-mitigations` |
| Crash triage | `exploit-dev/offensive-crash-analysis` |
| TOCTOU / race | `exploit-dev/offensive-toctou`, `web/offensive-race-condition` |

### Fuzzing & Vulnerability Research

| Topic | Skill |
|---|---|
| Coverage-guided fuzzing | `fuzzing/offensive-fuzzing` |
| Fuzzing curriculum | `fuzzing/offensive-fuzzing-course` |
| Static review patterns | `fuzzing/offensive-bug-identification` |
| Vuln class taxonomy | `fuzzing/offensive-vuln-classes` |

### AI Security

| Topic | Skill |
|---|---|
| Prompt injection / jailbreak / RAG | `ai/offensive-ai-security` |

### Utility

| Topic | Skill |
|---|---|
| Fast triage checklist | `utility/offensive-fast-checking` |
| Pro pentest reporting | `utility/offensive-reporting` |

---

## How to Use the Mindmap

- **Pre-engagement:** Walk the relevant category branch and confirm a skill exists per surface in scope. Gaps you spot here are gaps in the engagement plan.
- **During engagement:** Click into the category for the surface you're testing; load only those skills into Claude.
- **Post-engagement:** Cross-check findings against the relevant Mindmap branches to ensure no surface was skipped.
