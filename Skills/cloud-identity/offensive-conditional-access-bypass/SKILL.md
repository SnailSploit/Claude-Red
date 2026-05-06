---
name: offensive-conditional-access-bypass
description: "Conditional Access bypass methodology — legacy authentication paths exempt from MFA, trusted location IP spoofing, named locations gap analysis, app-specific policy gaps, device compliance via fake compliant device, MFA exclusion lists, break-glass account enumeration, and CA misconfiguration patterns. Use to bypass MFA / location / device-state requirements when targeting an Entra ID tenant."
---

# Conditional Access Bypass

Conditional Access policies gate sign-ins on conditions: user, app, location, device, risk. Bypasses come from policy gaps — not from breaking the policy mechanism.

## Discover CA Policies

```bash
# As any user with Conditional Access reader (often broader than expected)
az rest --method GET \
  --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

# Or via ROADtools — preferred for offline analysis
roadrecon gui  # → ConditionalAccess
```

For each policy, identify:
- Users / groups in scope
- Excluded users / groups (often "break-glass" accounts!)
- Apps in scope
- Conditions (location, device, sign-in risk)
- Grant controls (MFA, compliant device, etc.)

## Common Bypass Categories

### Excluded Apps

```bash
# Look for apps NOT in any CA policy that requires MFA
# Examples: legacy POP/IMAP, ActiveSync, certain admin endpoints
# If app X has no CA policy, sign-in to X needs only password
```

If you have user/pass and the user's MFA is enforced for primary apps, find an app without MFA enforcement. Common gaps: ADConnect's connector, Exchange ActiveSync, Microsoft Authenticator endpoint itself.

### Legacy Auth (Where Still Enabled)

```bash
# POP3 / IMAP / SMTP basic auth bypasses MFA on the protocol
# Microsoft disabled these by default in 2022+, but custom-tenant exemptions exist

# Test
curl -u user:pass "https://outlook.office365.com/EWS/Exchange.asmx"
```

### Trusted Location

```
CA: "If outside named locations, require MFA"
Bypass: spoof source IP to a named location
```

```bash
# Use a VPN that egresses from the office IP range
# Or a corporate VDI / cloud workstation in the trusted range
# Or compromise a host within trusted IPs and pivot
```

### Device Compliance

```
CA: "Require compliant device"
Compliance check: Intune-reported "compliant"
```

Bypasses:
- Compromise an Intune-managed device
- Forge compliance via Intune connector compromise
- Exclude scoped to admin override

### Sign-in Risk Exclusions

Some policies exclude "low risk" sign-ins from MFA. If your sign-in pattern matches (known IP, known UA), you skip MFA.

### Break-Glass Accounts

Most tenants have 2 emergency / break-glass accounts excluded from all CA. Often:
- Names like `bg.admin@tenant.onmicrosoft.com`
- Stored credentials in vault (target the vault)
- Long static passwords (target via spray after pattern recognition)

```bash
# Look for excluded users in CA policies
roadrecon gui → ConditionalAccess → for each policy, "excludeUsers"
# Names ending in -emergency, bg.*, breakglass.*, root, admin-no-mfa
```

## App-Specific Bypass

| App | Common Gap |
|---|---|
| Azure AD PowerShell | App ID 1b730954-xxx — sometimes excluded |
| MS Graph PowerShell | App ID 14d82eec-xxx — often excluded for admin scripting |
| Exchange Online PowerShell | If excluded, mailbox access without MFA |
| AAD Connect | Service identity, no MFA inherently |
| Custom apps | Per-app policies often missing |

## Authentication Method Strength

```bash
# Weaker methods exempt from "strong auth" requirement
# - SMS / voice OTP (deprecated but still allowed in some tenants)
# - Email OTP — bypassable if email account is also takeable
# - Hardware token if not piwned-policy-required

# Some CA policies require "MFA" without specifying strength → SMS suffices
```

## Engagement Cheatsheet

```bash
# 1. Pull CA policies
roadrecon gui → ConditionalAccess

# 2. For each gap:
#    - Excluded users → spray these
#    - Excluded apps → use these for foothold
#    - Trusted locations → spoof / pivot via internal host
#    - Device compliance → exclude policies / Intune compromise

# 3. Test bypass via login attempts (with explicit authorization)
# 4. Document: policy gap, bypass method, demonstrated access
```

## Detection

CA bypass attempts log as standard sign-ins; the absence of MFA prompt is the indicator. Mature programs review:

- Sign-ins from break-glass accounts
- Sign-ins to legacy-auth endpoints
- Sign-ins from new locations after CA policy change

## Key References

- Microsoft CA documentation
- "Conditional Access Bypasses" (various BB writeups)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/conditional-access.md
