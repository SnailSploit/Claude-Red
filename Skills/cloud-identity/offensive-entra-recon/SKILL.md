---
name: offensive-entra-recon
description: "Microsoft Entra ID (formerly Azure AD) reconnaissance — ROADtools authentication and offline analysis, AzureHound for BloodHound integration, Microsoft Graph API enumeration, tenant fingerprinting (federation provider, sign-in name format), user / group / app registration enumeration, Conditional Access policy discovery, and identifying high-value targets (Global Admins, Privileged Identity Management roles). Use as the first step in any cloud-identity engagement to map the tenant before active credential attacks."
---

# Entra ID Reconnaissance

The cloud-identity equivalent of `offensive-internal-recon`. Map the tenant, identities, and roles before active attacks.

## Tenant Fingerprinting

```bash
# Domain → Tenant ID
curl https://login.microsoftonline.com/<domain>/.well-known/openid-configuration

# Or via UserRealm endpoint
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@domain.com"
# Reveals: federated/managed, tenant ID, federation URL (ADFS)
```

## ROADtools

```bash
# Authenticate
roadrecon auth -u user@tenant.onmicrosoft.com -p pass
# Or with refresh token from device-code phish
roadrecon auth --refresh-token <token>

# Pull full directory
roadrecon gather

# Browse offline
roadrecon gui
# Opens local web UI for the gathered data
```

ROADtools dumps to a SQLite DB you can query offline — the Entra equivalent of an ADExplorer snapshot.

## AzureHound (BloodHound Integration)

```bash
azurehound list \
  -u user@tenant.onmicrosoft.com -p pass \
  --tenant tenant.onmicrosoft.com \
  -o azurehound.json

# Import into BloodHound (CE has Azure support)
```

BloodHound's Azure edge types include:
- Owner, Contributor, User Access Administrator
- AAD role assignments (GA, AppAdmin, etc.)
- Service principal owner / member
- Application Administrator → service principal control

## Microsoft Graph API Direct

```bash
# Token from previous auth
TOKEN=$(roadrecon auth -u user -p pass --token-only)

# User listing
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users"

# Roles
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/directoryRoles?\$expand=members"

# Apps
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications"

# Conditional Access policies (requires Conditional Access reader)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

## Anonymous / Unauthenticated Recon

```bash
# Tenant exists?
curl -I https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize

# UserRealm — federated vs managed
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com"

# Tenant subdomain enumeration via DNS
host tenant.onmicrosoft.com
dig tenant.onmicrosoft.com MX

# AAD-related domains: outlook.office365.com, autodiscover.target.com
```

## Service Principal Enumeration

```bash
# All service principals
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals"

# App permissions
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-id>/oauth2PermissionGrants"
```

High-priv service principals (Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory) are escalation targets — see `offensive-entra-privesc`.

## Privileged Identity Management (PIM)

```bash
# Eligible / active role assignments
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances"
```

Eligible (PIM-elevated) roles aren't always active — but they're activatable. Targets include eligible Global Admins not currently active.

## Conditional Access Discovery

```bash
# CA policies (often readable to all users by default — varies)
roadrecon gui → ConditionalAccess

# Or via az CLI
az rest --method GET \
  --uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
```

Key CA findings to map:
- "Block legacy auth" policy presence
- MFA exclusion lists (specific users / groups / apps)
- "Trusted location" IPs
- Device compliance requirements

## Engagement Cheatsheet

```bash
# 1. Tenant fingerprint
curl https://login.microsoftonline.com/<domain>/.well-known/openid-configuration

# 2. Get a foothold token (phish, leaked, etc.)

# 3. ROADtools full gather
roadrecon auth -u user -p pass
roadrecon gather

# 4. AzureHound for path analysis
azurehound list -u user -p pass --tenant <tenant>

# 5. Map: users, roles, apps, service principals, CA, PIM
# 6. Identify privesc paths (Application Admin → app → app role; etc.)
```

## Detection

| Signal | Defender View |
|---|---|
| Bulk Graph API calls | Sign-in audit / Azure AD Audit |
| ROADrecon HTTP pattern | Anomaly detection |
| AzureHound user-agent (default) | Easy fingerprint; can be customized |
| Foreign-IP token use | Sign-in risk (Azure AD Identity Protection) |

Mature Azure AD Identity Protection flags some patterns. Stealthy approach: pace queries, use known good IP, randomize user-agent.

## Key References

- ROADtools: github.com/dirkjanm/ROADtools
- AzureHound: github.com/BloodHoundAD/AzureHound
- Microsoft Graph reference: docs.microsoft.com/graph
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/entra-recon.md
