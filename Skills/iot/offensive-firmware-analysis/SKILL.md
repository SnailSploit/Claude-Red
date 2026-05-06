---
name: offensive-firmware-analysis
description: "Firmware analysis methodology — initial triage with binwalk and entropy plots, filesystem extraction (SquashFS, JFFS2, UBIFS, CPIO, ROMFS), credential and key hunting (etc/passwd, etc/shadow, hardcoded secrets in binaries), CGI / web admin auditing, vulnerable component identification (BusyBox, Dropbear, OpenSSL, lighttpd versions), reverse engineering ELF binaries with Ghidra / Binary Ninja, and structured walkthrough for finding RCE bugs in CGI / API handlers. Use after firmware extraction to map the device's attack surface and find vulnerabilities offline before runtime testing."
---

# Firmware Analysis

You have the firmware; now find the bugs. Embedded firmware compresses years of legacy code into one image — old BusyBox, ancient SSL, vendor-modified kernels, CGI binaries written before security hardening was a thing.

## Quick Workflow

1. Initial triage with `binwalk` and entropy plot
2. Extract filesystem(s); mount or browse
3. Quick wins: hardcoded creds, default passwords, key files
4. Identify vulnerable components by version
5. Reverse-engineer custom CGI / daemon binaries

---

## Initial Triage

```bash
# Identify embedded structures
binwalk firmware.bin
# Output: offsets and types of recognized blobs (Linux kernel, SquashFS, U-Boot images, etc.)

# Entropy plot
binwalk -E firmware.bin
# Flat regions = encrypted or compressed blobs
# Gradient regions = plaintext data
# Spike at start = header

# Recursive extraction
binwalk -Me firmware.bin
# Creates _firmware.bin.extracted/ with decompressed/extracted contents
```

Modern binwalk extracts most common firmware layouts automatically. For unusual formats, manually carve at offsets binwalk identified.

## Filesystem Extraction

### SquashFS (most common)

```bash
unsquashfs -d rootfs squashfs.bin
# Browses to rootfs/ with full Linux filesystem layout
```

### JFFS2 / UBIFS (NAND-backed)

```bash
jefferson jffs2.bin -d rootfs/
ubireader_extract_files ubi.bin -o rootfs/
ubidump.py ubi.bin
```

### CramFS

```bash
cramfsck -x rootfs cramfs.bin
```

### CPIO (initramfs)

```bash
mkdir initramfs && cd initramfs
zcat ../initramfs.cpio.gz | cpio -i -d -H newc --no-absolute-filenames
```

### Custom / Encrypted Containers

Many vendors wrap firmware with a custom header. Identify by:
- Magic bytes at start
- Vendor-specific tools (`fwextract` from vendor support pages)
- Reverse-engineering the bootloader's parsing routine

For encrypted firmware: extraction key may be in plain in:
- Bootloader (also dumpable)
- Companion app (see `offensive-mobile`)
- Cloud API responses (if device fetches keyed downloads)

## Quick Wins (5-Minute Audit)

```bash
# Credentials and shadows
cat rootfs/etc/passwd rootfs/etc/shadow

# Hardcoded creds across all files
grep -RIE "(BEGIN (RSA |DSA |EC )?PRIVATE KEY|api[_-]?key|secret|token|passwd|root:[^*])" rootfs/

# Keys / certificates
find rootfs -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.crt"

# WPA-Enterprise / Wi-Fi creds
find rootfs -name "wpa_supplicant.conf" -exec cat {} \;

# Default service configs
ls -la rootfs/etc/init.d/
cat rootfs/etc/inetd.conf rootfs/etc/services 2>/dev/null

# Setuid binaries
find rootfs -perm -4000 -type f 2>/dev/null

# All scripts (high custom-code signal)
find rootfs -name "*.sh" -o -name "*.py" -o -name "*.lua" | head -30
```

## Vulnerable Component Identification

```bash
# BusyBox (often very old, with CVEs)
rootfs/bin/busybox 2>&1 | head -1

# SSH / Telnet daemons
strings rootfs/sbin/dropbear 2>/dev/null | grep "Dropbear v"
strings rootfs/usr/sbin/sshd 2>/dev/null | grep "OpenSSH"

# OpenSSL version (huge attack surface)
strings rootfs/usr/lib/libssl* 2>/dev/null | grep "OpenSSL "
strings rootfs/usr/lib/libcrypto* 2>/dev/null | grep "OpenSSL "

# Web server identification
find rootfs -name "lighttpd*" -o -name "boa" -o -name "goahead" -o -name "mini_httpd" -o -name "thttpd"

# Kernel version (for kernel CVE applicability)
strings rootfs/boot/vmlinuz* 2>/dev/null | grep "Linux version"
strings rootfs/lib/modules/* 2>/dev/null | grep "vermagic"
```

Cross-reference each version against:
- nuclei templates: `nuclei -t cves/ -l ...`
- CVE database: cve.mitre.org / nvd.nist.gov
- Specific advisory feeds (BusyBox CVEs, OpenSSL advisories)

## CGI / Web Admin Auditing

GoAhead, Boa, mini_httpd — these embedded web servers' CGI handlers are notorious for command injection.

```bash
# Find CGI binaries
find rootfs/www -type f -executable
find rootfs -name "*.cgi" -o -name "*.lua"

# Identify file format
file rootfs/www/cgi-bin/setup.cgi
# Often: ELF MIPS, ARM, or x86

# Strings for quick wins
strings rootfs/www/cgi-bin/setup.cgi | grep -E "system|popen|exec|sprintf"
```

### Disassemble in Ghidra

```bash
ghidra-headlessAnalyzer ./project_dir test_project \
  -import rootfs/www/cgi-bin/setup.cgi \
  -postScript ListSymbols.java
```

Look for:
- `system()`, `popen()`, `execve()` calls with concatenated user input
- `sprintf()` builds command strings, then `system()`
- Authentication checks based on plaintext file compare
- Path traversal via unsanitized parameters

### Common CGI Bug Pattern

```c
// Vulnerable
char cmd[256];
sprintf(cmd, "ping -c 1 %s", get_query_param("host"));
system(cmd);
// Inject via host=8.8.8.8;cat /etc/passwd;
```

Once you find this in the CGI, test:
- Web admin → command injection on parameter X
- Auth required? Often yes — check default creds first
- Reachable pre-auth? Some CGIs have auth bypass paths

## Custom Daemon Reverse Engineering

Vendor-specific daemons (telnet replacement, configuration daemon, vendor cloud connector):

```bash
# Find non-stock binaries
find rootfs/usr/sbin rootfs/usr/bin -type f -newer rootfs/etc/passwd

# Identify what listens on the network
grep -r "bind\|listen\|socket" rootfs/etc/ rootfs/usr/sbin/ 2>/dev/null
```

For each custom binary:

1. Identify network listeners (`bind` syscall references in disassembly)
2. Map the protocol (custom TLV? JSON? text-based?)
3. Identify input handlers and look for buffer overflows / format strings
4. Check authentication/authorization on each command

## Cross-Compile a Test Harness

For runtime fuzzing of CGI binaries from your own host:

```bash
# QEMU emulation of MIPS / ARM binaries
qemu-mips-static -L rootfs/ rootfs/www/cgi-bin/setup.cgi

# AFL++ over QEMU
afl-fuzz -Q -i corpus/ -o findings/ -- qemu-mips-static -L rootfs rootfs/www/cgi-bin/setup.cgi
```

## Configuration File Inspection

Many vulns hide in config files:

```bash
# Web server configs
find rootfs/etc -name "*.conf" | xargs grep -l "auth\|password\|secret" 2>/dev/null

# Boot scripts / startup
cat rootfs/etc/inittab rootfs/etc/init.d/rcS rootfs/etc/rc.d/* 2>/dev/null

# Cron / scheduled
cat rootfs/etc/crontab rootfs/var/spool/cron/* 2>/dev/null
```

## Engagement Cheatsheet

```bash
# 1. Triage
binwalk firmware.bin
binwalk -Me firmware.bin

# 2. Identify rootfs and mount
ls _firmware.bin.extracted/squashfs-root/

# 3. Quick wins
cat etc/passwd etc/shadow
grep -RIE "key|secret|password" etc/

# 4. Vulnerable components
bin/busybox 2>&1 | head -1
strings sbin/dropbear | grep Dropbear
strings usr/lib/libssl* | grep OpenSSL

# 5. CGI audit
find www -type f -executable | xargs file
ghidra-headlessAnalyzer . project -import www/cgi-bin/setup.cgi

# 6. Document each finding: file, line/offset, nature, exploitation steps
```

## Reporting

For each finding:
- File path within firmware
- Specific function / offset (for binary issues)
- Reproduction steps (URL + curl for CGI, console steps for service)
- Pre-conditions (auth required? specific config?)
- Remediation (vendor patch, config disable, replace component)

---

## Key References

- binwalk: github.com/ReFirmLabs/binwalk
- Ghidra: ghidra-sre.org
- "Practical IoT Hacking" (Heres, Forshaw)
- FACT (Firmware Analysis and Comparison Tool): github.com/fkie-cad/FACT_core
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
