---
name: offensive-grpc
description: "gRPC and Protocol Buffers attack methodology — service / method enumeration via reflection, .proto file recovery, schema-driven fuzzing, authentication / interceptor bypass, gRPC-Web bridge attacks, message replay, oversized message DoS, transcoded REST gateway abuse, and gRPC-specific tooling (grpcurl, evans, ghz, BloodHound for gRPC). Use when targets expose gRPC endpoints (typically port 50051 or behind grpc-web on standard HTTPS) — common in modern microservices, Kubernetes intra-cluster traffic, and mobile / IoT app backends."
---

# gRPC / Protocol Buffers Attacks

gRPC is HTTP/2 + protobuf. Without the `.proto` schema, messages look like opaque binary. With it (often discoverable via reflection), the surface looks much like REST.

## Quick Workflow

1. Enumerate services and methods via gRPC reflection
2. Recover .proto schemas if reflection disabled
3. Test authentication / interceptor enforcement
4. Send crafted messages to each method
5. Test gRPC-Web / REST transcoded gateways for the same endpoints

---

## Identification

| Indicator | Implies |
|---|---|
| Port 50051 | gRPC (standard) |
| `Content-Type: application/grpc` | gRPC |
| `Content-Type: application/grpc-web` | gRPC-Web (browser-friendly) |
| HTTP/2 only | Likely gRPC |
| `grpc-status` header in response | gRPC server confirmed |

```bash
# Probe for gRPC reflection
grpcurl -plaintext target:50051 list
# If reflection enabled, returns service list
```

## Service Enumeration via Reflection

```bash
# List all services
grpcurl -plaintext target:50051 list

# List methods of a service
grpcurl -plaintext target:50051 list mypackage.MyService

# Describe a method (input / output proto)
grpcurl -plaintext target:50051 describe mypackage.MyService.GetUser
```

Output gives you the full service surface — every method, parameter, return type.

## Recovery Without Reflection

When server has reflection disabled:

### Client App Reverse Engineering

Mobile / desktop apps using gRPC ship the .proto schemas (as compiled descriptor sets):

```bash
# Android: pull the APK, look for *.proto, *.pb, descriptor.binarypb
unzip app.apk
find . -name "*.proto" -o -name "*.binarypb"

# Compile descriptor.binarypb back to .proto with protoc
protoc --decode_raw < descriptor.binarypb
```

### Network Capture

```bash
# Capture gRPC traffic with Wireshark
# Use HTTP/2 dissector + protobuf dissector
# Without schema, you see field numbers + wire types — partial recovery

# Or use Burp's gRPC extension (Protobuf-To-OpenAPI)
```

## Sending Crafted Requests

```bash
# Once you have schema (via reflection or recovery)
grpcurl -plaintext -d '{"id": 1}' target:50051 mypackage.MyService.GetUser

# With auth
grpcurl -plaintext -H "authorization: Bearer $TOKEN" target:50051 \
  -d '{"id": 1}' mypackage.MyService.GetUser

# evans — interactive REPL
evans --host target --port 50051 -r repl
```

## Authentication Bypass Tests

### No Auth on Some Methods

Like REST, gRPC services often have inconsistent auth: most methods require a valid token, but admin / debug methods might not.

```bash
# Send no auth header
grpcurl -plaintext -d '{}' target:50051 admin.AdminService.WipeDatabase
```

### Interceptor Bypass

Some servers gate auth on a per-method whitelist. If a method name has a typo or isn't in the whitelist, it's unprotected.

### Token Validation Flaws

Same JWT/OAuth issues as REST APIs (see `offensive-jwt`). gRPC tokens are usually JWTs.

## Mass Assignment in gRPC

Protobuf has all-fields-optional design. Send fields the server forgot to validate:

```bash
grpcurl -d '{"username": "user", "isAdmin": true}' \
  -plaintext target:50051 mypackage.UserService.CreateUser
```

If the server doesn't strip extraneous fields before persistence, isAdmin lands.

## Authorization Bypass Per Object

gRPC methods take object IDs:

```bash
# Try fetching another user's data
grpcurl -plaintext -d '{"id": 1}' target:50051 svc.UserService.Get
grpcurl -plaintext -d '{"id": 2}' target:50051 svc.UserService.Get
```

IDOR works the same as REST (see `offensive-idor`).

## Streaming Methods

gRPC supports unary, server-streaming, client-streaming, and bidirectional. Test each:

```bash
# Server-streaming (server sends multiple responses)
grpcurl -plaintext -d '{"query": "*"}' target:50051 svc.SearchService.Stream

# Client-streaming and bidi tested via custom clients
```

Streaming methods are sometimes more permissive in error handling — server may keep streaming even when authz fails partway.

## Message Replay

Captured gRPC messages can be replayed:

```bash
# Capture a valid request, save the body
# Replay with grpcurl --rpc-header for any auth
grpcurl -plaintext -import-path . -proto schema.proto -H "authorization: Bearer $T" \
  -d @ < captured_body.json target:50051 mypackage.MyService.MyMethod
```

If sequence numbers / nonces are not enforced, replay works.

## Oversize Message DoS

```python
import grpc
# Send an enormous message — gRPC default max is 4MB on most stacks
# but configurable; test the actual limit
```

If the server doesn't enforce, OOM. Modern Go / Java / Node gRPC defaults are reasonable; custom configs may be permissive.

## gRPC-Web Bridge

`grpc-web` lets browsers talk to gRPC servers via a translation proxy. Attack surface:

- Translation proxy (Envoy, grpcwebproxy) parses and forwards — possible parsing differences
- WS-style cross-origin issues if not properly Origin-locked
- HTTP/1.1 ↔ HTTP/2 translation occasionally yields request smuggling

```bash
# Identify grpc-web
curl -i https://app.com/api/svc.Method \
  -H "Content-Type: application/grpc-web-text"
```

## REST/HTTP Transcoded Gateway

Many gRPC services expose a REST gateway via grpc-gateway. The same auth/authz bugs may exist on either side; test both.

```bash
# REST side — typically /v1/users/{id} or similar
curl https://api.target.com/v1/users/1

# gRPC side — same data via protobuf
grpcurl -plaintext target:50051 -d '{"id": 1}' svc.UserService.GetUser
```

If transcoded gateway uses different auth than direct gRPC, attack the weaker side.

## Engagement Cheatsheet

```bash
# 1. Identify gRPC port
nmap -sV -p- target | grep -i grpc
# Typical: 50051, sometimes behind 443

# 2. Reflection enum
grpcurl -plaintext target:50051 list

# 3. If reflection disabled, recover proto from client app

# 4. For each service.Method, test:
#    - No auth
#    - Wrong-tenant ID
#    - Mass assignment (extra fields)
#    - Crafted edge values

# 5. Streaming methods — test partial-auth scenarios

# 6. gRPC-Web / REST gateway parity — same bugs on either side?

# 7. Document: service.Method, missing check, exact request, impact
```

## Detection

| Signal | Defender View |
|---|---|
| Reflection list calls | Server logs (typically not enabled by default) |
| High volume of unauth method calls | Application metrics on auth failure rate |
| Schema mismatch in fields | Validation error logs (if logged) |
| Streaming abuse | Connection-level metrics |

Most gRPC stacks have less mature security observability than HTTP REST. App-level instrumentation varies widely.

## Reporting

- Server + version (Go, Java, Node, etc.) — affects available attacks
- Schema discovery method (reflection / recovered)
- Per-method bugs (one per finding)
- Request crafted to demonstrate bug
- Impact (privilege, data, RCE if reached)

---

## Key References

- gRPC documentation: grpc.io
- grpcurl: github.com/fullstorydev/grpcurl
- Protobuf-to-OpenAPI Burp extension
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/grpc.md
