# skillmd-lint findings — baseline

Baseline captured on 2026-09-20 with [skillmd-lint](https://github.com/Mine-FNL/skillmd-lint) v1.4.0 (`--format json`) across 79 `SKILL.md` files under `Skills/`.

**Total: 130 errors, 295 warnings.**

## Summary

| Rule | Severity | Findings | Meaning |
|------|----------|----------|---------|
| `E002` | error | 28 | frontmatter is missing or invalid YAML |
| `E003` | error | 28 | `name` is missing or empty |
| `E005` | error | 28 | `name` collides with a reserved word |
| `E007` | error | 28 | `description` is missing or empty |
| `E008` | error | 18 | `description` exceeds 1024 characters |
| `W001` | warning | 1 |  |
| `W002` | warning | 51 | description missing negative trigger |
| `W004` | warning | 67 | body exceeds 200 lines |
| `W005` | warning | 75 | no `## When to use` section in body |
| `W006` | warning | 22 | no concrete examples in body |
| `W012` | warning | 78 | no `## Pitfalls to avoid` section in body |
| `W015` | warning | 1 | description contains placeholder text |

## Errors

### `E002` — frontmatter is missing or invalid YAML (28)

- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`

### `E003` — `name` is missing or empty (28)

- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`

### `E005` — `name` collides with a reserved word (28)

- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`

### `E007` — `description` is missing or empty (28)

- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`

### `E008` — `description` exceeds 1024 characters (18)

- `Skills/api/offensive-api-abuse/SKILL.md`
- `Skills/cicd/offensive-cicd-pipeline/SKILL.md`
- `Skills/cicd/offensive-cicd-secrets/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/container/offensive-k8s-attacks/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/forensics/offensive-anti-forensics/SKILL.md`
- `Skills/forensics/offensive-c2-frameworks/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/post-exploitation/offensive-persistence/SKILL.md`
- `Skills/privesc/offensive-linux-privesc/SKILL.md`
- `Skills/privesc/offensive-windows-privesc/SKILL.md`
- `Skills/social-engineering/offensive-phishing/SKILL.md`
- `Skills/social-engineering/offensive-social-engineering/SKILL.md`
- `Skills/supply-chain/offensive-dependency-confusion/SKILL.md`
- `Skills/supply-chain/offensive-supply-chain/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`

## Warnings

### `W001` —  (1)

- `Skills/infrastructure/offensive-advanced-redteam/SKILL.md`

### `W002` — description missing negative trigger (51)

- `Skills/active-directory/offensive-active-directory/SKILL.md`
- `Skills/active-directory/offensive-netexec/SKILL.md`
- `Skills/api/offensive-api-abuse/SKILL.md`
- `Skills/api/offensive-api-security/SKILL.md`
- `Skills/auth/offensive-jwt/SKILL.md`
- `Skills/cicd/offensive-cicd-pipeline/SKILL.md`
- `Skills/cicd/offensive-cicd-secrets/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/container/offensive-container-escape/SKILL.md`
- `Skills/container/offensive-k8s-attacks/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/exploit-dev/offensive-toctou/SKILL.md`
- `Skills/forensics/offensive-anti-forensics/SKILL.md`
- `Skills/forensics/offensive-c2-frameworks/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing/SKILL.md`
- `Skills/infrastructure/offensive-advanced-redteam/SKILL.md`
- `Skills/infrastructure/offensive-shellcode/SKILL.md`
- `Skills/iot/offensive-iot/SKILL.md`
- `Skills/mobile/offensive-mobile/SKILL.md`
- `Skills/network/offensive-network-attacks/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/post-exploitation/offensive-lateral-movement/SKILL.md`
- `Skills/post-exploitation/offensive-persistence/SKILL.md`
- `Skills/privesc/offensive-linux-privesc/SKILL.md`
- `Skills/privesc/offensive-windows-privesc/SKILL.md`
- `Skills/recon/offensive-osint/SKILL.md`
- `Skills/social-engineering/offensive-phishing/SKILL.md`
- `Skills/social-engineering/offensive-social-engineering/SKILL.md`
- `Skills/supply-chain/offensive-dependency-confusion/SKILL.md`
- `Skills/supply-chain/offensive-supply-chain/SKILL.md`
- `Skills/utility/offensive-reporting/SKILL.md`
- `Skills/web/offensive-business-logic/SKILL.md`
- `Skills/web/offensive-deserialization/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`
- `Skills/web/offensive-sqli/SKILL.md`
- `Skills/web/offensive-ssti/SKILL.md`
- `Skills/wireless/offensive-bluetooth-ble/SKILL.md`
- `Skills/wireless/offensive-bluetooth-classic/SKILL.md`
- `Skills/wireless/offensive-deauth-disassoc/SKILL.md`
- `Skills/wireless/offensive-evil-twin/SKILL.md`
- `Skills/wireless/offensive-krack-fragattacks/SKILL.md`
- `Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md`
- `Skills/wireless/offensive-wifi-recon/SKILL.md`
- `Skills/wireless/offensive-wifi/SKILL.md`
- `Skills/wireless/offensive-wpa-enterprise/SKILL.md`
- `Skills/wireless/offensive-wpa2-psk/SKILL.md`
- `Skills/wireless/offensive-wpa3-sae/SKILL.md`
- `Skills/wireless/offensive-wps/SKILL.md`
- `Skills/wireless/offensive-z-wave/SKILL.md`
- `Skills/wireless/offensive-zigbee-thread-matter/SKILL.md`

### `W004` — body exceeds 200 lines (67)

- `Skills/active-directory/offensive-active-directory/SKILL.md`
- `Skills/active-directory/offensive-netexec/SKILL.md`
- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/api/offensive-api-abuse/SKILL.md`
- `Skills/api/offensive-api-security/SKILL.md`
- `Skills/auth/offensive-jwt/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/cicd/offensive-cicd-pipeline/SKILL.md`
- `Skills/cicd/offensive-cicd-secrets/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/container/offensive-container-escape/SKILL.md`
- `Skills/container/offensive-k8s-attacks/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/exploit-dev/offensive-toctou/SKILL.md`
- `Skills/forensics/offensive-anti-forensics/SKILL.md`
- `Skills/forensics/offensive-c2-frameworks/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-advanced-redteam/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-shellcode/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/iot/offensive-iot/SKILL.md`
- `Skills/mobile/offensive-mobile/SKILL.md`
- `Skills/network/offensive-network-attacks/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/post-exploitation/offensive-lateral-movement/SKILL.md`
- `Skills/post-exploitation/offensive-persistence/SKILL.md`
- `Skills/privesc/offensive-linux-privesc/SKILL.md`
- `Skills/privesc/offensive-windows-privesc/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/recon/offensive-osint/SKILL.md`
- `Skills/social-engineering/offensive-phishing/SKILL.md`
- `Skills/social-engineering/offensive-social-engineering/SKILL.md`
- `Skills/supply-chain/offensive-dependency-confusion/SKILL.md`
- `Skills/supply-chain/offensive-supply-chain/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/utility/offensive-reporting/SKILL.md`
- `Skills/web/offensive-business-logic/SKILL.md`
- `Skills/web/offensive-deserialization/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-sqli/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-ssti/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`
- `Skills/wireless/offensive-evil-twin/SKILL.md`
- `Skills/wireless/offensive-wifi/SKILL.md`
- `Skills/wireless/offensive-wpa-enterprise/SKILL.md`

### `W005` — no `## When to use` section in body (75)

- `Skills/active-directory/offensive-active-directory/SKILL.md`
- `Skills/active-directory/offensive-netexec/SKILL.md`
- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/api/offensive-api-abuse/SKILL.md`
- `Skills/api/offensive-api-security/SKILL.md`
- `Skills/auth/offensive-jwt/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/cicd/offensive-cicd-pipeline/SKILL.md`
- `Skills/cicd/offensive-cicd-secrets/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/container/offensive-container-escape/SKILL.md`
- `Skills/container/offensive-k8s-attacks/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/exploit-dev/offensive-basic-exploitation/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/exploit-dev/offensive-toctou/SKILL.md`
- `Skills/forensics/offensive-anti-forensics/SKILL.md`
- `Skills/forensics/offensive-c2-frameworks/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-advanced-redteam/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-shellcode/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/iot/offensive-iot/SKILL.md`
- `Skills/mobile/offensive-mobile/SKILL.md`
- `Skills/network/offensive-network-attacks/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/post-exploitation/offensive-lateral-movement/SKILL.md`
- `Skills/post-exploitation/offensive-persistence/SKILL.md`
- `Skills/privesc/offensive-linux-privesc/SKILL.md`
- `Skills/privesc/offensive-windows-privesc/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/recon/offensive-osint/SKILL.md`
- `Skills/social-engineering/offensive-phishing/SKILL.md`
- `Skills/social-engineering/offensive-social-engineering/SKILL.md`
- `Skills/supply-chain/offensive-dependency-confusion/SKILL.md`
- `Skills/supply-chain/offensive-supply-chain/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/web/offensive-business-logic/SKILL.md`
- `Skills/web/offensive-deserialization/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-sqli/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-ssti/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`
- `Skills/wireless/offensive-bluetooth-ble/SKILL.md`
- `Skills/wireless/offensive-bluetooth-classic/SKILL.md`
- `Skills/wireless/offensive-deauth-disassoc/SKILL.md`
- `Skills/wireless/offensive-evil-twin/SKILL.md`
- `Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md`
- `Skills/wireless/offensive-wifi-recon/SKILL.md`
- `Skills/wireless/offensive-wifi/SKILL.md`
- `Skills/wireless/offensive-wpa-enterprise/SKILL.md`
- `Skills/wireless/offensive-wpa2-psk/SKILL.md`
- `Skills/wireless/offensive-wpa3-sae/SKILL.md`
- `Skills/wireless/offensive-wps/SKILL.md`
- `Skills/wireless/offensive-z-wave/SKILL.md`
- `Skills/wireless/offensive-zigbee-thread-matter/SKILL.md`

### `W006` — no concrete examples in body (22)

- `Skills/active-directory/offensive-active-directory/SKILL.md`
- `Skills/auth/offensive-jwt/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/iot/offensive-iot/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`
- `Skills/wireless/offensive-bluetooth-ble/SKILL.md`
- `Skills/wireless/offensive-deauth-disassoc/SKILL.md`
- `Skills/wireless/offensive-evil-twin/SKILL.md`
- `Skills/wireless/offensive-krack-fragattacks/SKILL.md`
- `Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md`
- `Skills/wireless/offensive-wifi-recon/SKILL.md`
- `Skills/wireless/offensive-wpa-enterprise/SKILL.md`
- `Skills/wireless/offensive-wpa2-psk/SKILL.md`
- `Skills/wireless/offensive-wpa3-sae/SKILL.md`
- `Skills/wireless/offensive-wps/SKILL.md`
- `Skills/wireless/offensive-z-wave/SKILL.md`
- `Skills/wireless/offensive-zigbee-thread-matter/SKILL.md`

### `W012` — no `## Pitfalls to avoid` section in body (78)

- `Skills/active-directory/offensive-active-directory/SKILL.md`
- `Skills/active-directory/offensive-netexec/SKILL.md`
- `Skills/ai/offensive-ai-security/SKILL.md`
- `Skills/api/offensive-api-abuse/SKILL.md`
- `Skills/api/offensive-api-security/SKILL.md`
- `Skills/auth/offensive-jwt/SKILL.md`
- `Skills/auth/offensive-oauth/SKILL.md`
- `Skills/cicd/offensive-cicd-pipeline/SKILL.md`
- `Skills/cicd/offensive-cicd-secrets/SKILL.md`
- `Skills/cloud/offensive-cloud/SKILL.md`
- `Skills/container/offensive-container-escape/SKILL.md`
- `Skills/container/offensive-k8s-attacks/SKILL.md`
- `Skills/crypto/offensive-crypto-attacks/SKILL.md`
- `Skills/crypto/offensive-tls-attacks/SKILL.md`
- `Skills/exploit-dev/offensive-crash-analysis/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-dev-course/SKILL.md`
- `Skills/exploit-dev/offensive-exploit-development/SKILL.md`
- `Skills/exploit-dev/offensive-mitigations/SKILL.md`
- `Skills/exploit-dev/offensive-toctou/SKILL.md`
- `Skills/forensics/offensive-anti-forensics/SKILL.md`
- `Skills/forensics/offensive-c2-frameworks/SKILL.md`
- `Skills/fuzzing/offensive-bug-identification/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing-course/SKILL.md`
- `Skills/fuzzing/offensive-fuzzing/SKILL.md`
- `Skills/fuzzing/offensive-vuln-classes/SKILL.md`
- `Skills/infrastructure/offensive-advanced-redteam/SKILL.md`
- `Skills/infrastructure/offensive-edr-evasion/SKILL.md`
- `Skills/infrastructure/offensive-initial-access/SKILL.md`
- `Skills/infrastructure/offensive-keylogger-arch/SKILL.md`
- `Skills/infrastructure/offensive-shellcode/SKILL.md`
- `Skills/infrastructure/offensive-windows-boundaries/SKILL.md`
- `Skills/infrastructure/offensive-windows-mitigations/SKILL.md`
- `Skills/iot/offensive-iot/SKILL.md`
- `Skills/mobile/offensive-mobile/SKILL.md`
- `Skills/network/offensive-network-attacks/SKILL.md`
- `Skills/post-exploitation/offensive-data-exfiltration/SKILL.md`
- `Skills/post-exploitation/offensive-lateral-movement/SKILL.md`
- `Skills/post-exploitation/offensive-persistence/SKILL.md`
- `Skills/privesc/offensive-linux-privesc/SKILL.md`
- `Skills/privesc/offensive-windows-privesc/SKILL.md`
- `Skills/recon/offensive-osint-methodology/SKILL.md`
- `Skills/recon/offensive-osint/SKILL.md`
- `Skills/social-engineering/offensive-phishing/SKILL.md`
- `Skills/social-engineering/offensive-social-engineering/SKILL.md`
- `Skills/supply-chain/offensive-dependency-confusion/SKILL.md`
- `Skills/supply-chain/offensive-supply-chain/SKILL.md`
- `Skills/utility/offensive-fast-checking/SKILL.md`
- `Skills/utility/offensive-reporting/SKILL.md`
- `Skills/web/offensive-business-logic/SKILL.md`
- `Skills/web/offensive-deserialization/SKILL.md`
- `Skills/web/offensive-file-upload/SKILL.md`
- `Skills/web/offensive-graphql/SKILL.md`
- `Skills/web/offensive-idor/SKILL.md`
- `Skills/web/offensive-open-redirect/SKILL.md`
- `Skills/web/offensive-parameter-pollution/SKILL.md`
- `Skills/web/offensive-race-condition/SKILL.md`
- `Skills/web/offensive-rce/SKILL.md`
- `Skills/web/offensive-request-smuggling/SKILL.md`
- `Skills/web/offensive-sqli/SKILL.md`
- `Skills/web/offensive-ssrf/SKILL.md`
- `Skills/web/offensive-ssti/SKILL.md`
- `Skills/web/offensive-waf-bypass/SKILL.md`
- `Skills/web/offensive-xss/SKILL.md`
- `Skills/web/offensive-xxe/SKILL.md`
- `Skills/wireless/offensive-bluetooth-ble/SKILL.md`
- `Skills/wireless/offensive-bluetooth-classic/SKILL.md`
- `Skills/wireless/offensive-deauth-disassoc/SKILL.md`
- `Skills/wireless/offensive-evil-twin/SKILL.md`
- `Skills/wireless/offensive-krack-fragattacks/SKILL.md`
- `Skills/wireless/offensive-lorawan-sub-ghz/SKILL.md`
- `Skills/wireless/offensive-wifi-recon/SKILL.md`
- `Skills/wireless/offensive-wifi/SKILL.md`
- `Skills/wireless/offensive-wpa-enterprise/SKILL.md`
- `Skills/wireless/offensive-wpa2-psk/SKILL.md`
- `Skills/wireless/offensive-wpa3-sae/SKILL.md`
- `Skills/wireless/offensive-wps/SKILL.md`
- `Skills/wireless/offensive-z-wave/SKILL.md`
- `Skills/wireless/offensive-zigbee-thread-matter/SKILL.md`

### `W015` — description contains placeholder text (1)

- `Skills/crypto/offensive-crypto-attacks/SKILL.md`

