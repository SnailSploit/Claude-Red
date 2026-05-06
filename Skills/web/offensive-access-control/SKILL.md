---
name: offensive-access-control
description: "Authorization / access control testing methodology — RBAC and ABAC bypass beyond IDOR, vertical privilege escalation (low-priv → admin), horizontal privilege escalation (one user → another), tenant boundary violations in multi-tenant SaaS, role parameter mass assignment, function-level missing authorization (admin endpoint reachable by user), method-based ACL gaps (GET vs POST/PATCH), HTTP verb tampering, path traversal in authorization (//admin//, .. encoding), and post-token-introspection authorization gaps. Use after authentication is established to test what the user is and isn't allowed to do."
---

# Access Control / Authorization

Authentication says who you are; authorization says what you can do. Authorization bugs are second only to injection in OWASP statistics — and they're easier to find than injection if you methodically map every privileged action.

## Quick Workflow

1. Map every endpoint by role: who *should* be able to call it
2. As a low-priv user, try every endpoint a higher-priv user can call
3. As one user, try every endpoint another user can call
4. Test method tampering (GET → POST, etc.) on every endpoint
5. Test parameter pollution / mass assignment on role/tenant fields

---

## Role Discovery

```bash
# Compare authenticated JS bundles for different roles
diff <(curl -H 'Cookie: user_session' https://app/main.js) \
     <(curl -H 'Cookie: admin_session' https://app/main.js)
```

Differences reveal admin-only routes the regular user shouldn't see — and often shouldn't be able to call.

## Vertical Privilege Escalation

A low-priv user calling admin endpoints. The most common bug class in modern SPAs because RBAC is enforced *only* in the UI.

```bash
# Enumerate verbs on every discovered admin path with low-priv token
for path in $(cat admin_paths.txt); do
  for v in GET POST PUT PATCH DELETE; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $v -H "Authorization: Bearer $LOW_TOKEN" "https://app$path")
    [[ "$code" =~ ^(2|3) ]] && echo "WIN: $v $path → $code"
  done
done
```

### Mass Assignment of Role Field

```http
PUT /api/users/me
Cookie: user_session
{ "email": "x@y.com", "name": "X", "role": "admin", "isAdmin": true, "permissions": ["*"] }
```

Test every plausible role-field name: `role`, `roles`, `userRole`, `isAdmin`, `is_admin`, `admin`, `permissions`, `scope`, `groups`, `claims`, `tier`, `plan`, `accountType`.

### Role Confusion via Parameter Pollution

```http
POST /api/users/create
Cookie: user_session
role=user&role=admin
```

Last-wins parsers (PHP, some Java) take `admin`.

```http
POST /api/users/create
Cookie: user_session
Content-Type: application/json
{"role": "user", "role": "admin"}
```

JSON parsers usually take last value.

## Horizontal Privilege Escalation

Same role, different user — accessing user B's data as user A. This is IDOR; see `offensive-idor` for object-ID enumeration. Authorization-specific patterns:

### Tenant Boundary Violation

```http
GET /api/orders/123
Cookie: tenantA_user_session
→ 200 { "order": {...} }   # but this order belongs to tenant B
```

In multi-tenant SaaS, the tenant filter is often missing on individual record lookups but present on list endpoints.

### Hidden Field Tenant Override

```http
POST /api/invoices
Cookie: tenantA_user_session
{ "amount": 100, "tenantId": "tenantB" }   # Charge tenant B
```

## Method Tampering / Verb Confusion

If `GET /api/admin/users` is forbidden, try:
- `POST /api/admin/users` (some frameworks check verb-by-verb)
- `OPTIONS /api/admin/users` (might leak schema)
- `HEAD /api/admin/users` (might bypass auth check that only runs on GET)
- `X-HTTP-Method-Override: PUT` header
- `_method=PUT` query parameter
- Trailing slash variant: `/api/admin/users/`
- Casing: `/Api/Admin/Users`

## Path Confusion / Traversal

```http
GET /api/user
GET /api/admin/../user        # Resolves to /api/user but bypasses prefix-based ACL
GET /api//admin/users         # Double-slash — some proxies normalize, some don't
GET /api/admin%2fusers        # URL-encoded slash — same idea
GET /api/.;/admin/users       # JSP-specific: dot-semicolon path-parameter trick
GET /;jsessionid=X/api/admin  # Path parameter injection
```

Test against the auth proxy / API gateway — it may differ from the backend's parsing.

## API Gateway / Backend Authorization Mismatch

Common pattern: gateway authenticates JWT, forwards `X-User-Id` to backend. If backend trusts the header without re-verifying against the JWT signature:

```http
GET /api/admin
Authorization: Bearer <low-priv-jwt>
X-User-Id: 1                  # If we can inject this header at the gateway-bypassing entrypoint
X-User-Roles: admin
```

Some gateways pass through unknown headers; some rewrite them. Test by setting them yourself.

## Function-Level Missing Auth

Endpoint exists, requires authentication, but doesn't check the role:

```http
GET /api/admin/users         # Required: admin role
Cookie: user_session         # Has any session
→ 200 [{...all users...}]
```

This is the most common missing-auth bug. Map every admin endpoint and test as a regular user.

## Direct Object Action Without Permission

Operations that modify state often skip the per-object permission check:

```http
POST /api/projects/SOMEONE_ELSES_PROJECT/delete
Cookie: user_session
→ 200 { "deleted": true }
```

Test mutating actions (delete, transfer, share, change-owner) per object across the user-object boundary.

## SSO / Token-Bound Authorization Drift

If JWT has `roles: ["user"]` but server reads roles from DB by user ID at request time, modifying the JWT's roles claim doesn't help — but modifying the user ID does.

Conversely, if the server trusts JWT roles without re-fetching, signing your own JWT (alg:none, key confusion) gives admin. See `offensive-jwt`.

## Stale Permission

User gets demoted; their existing session continues with old permissions. Test:

1. Authenticate as admin → get session
2. Demote that account to user (out of band)
3. Continue using the original session for admin actions

If the server caches the role in the session without re-checking, you have post-demotion access.

## File / Resource Access

```bash
# Direct file URL leak
curl https://app/api/files/123
# Try: 124, 122, increment

# Predictable file URLs
curl https://app/uploads/2024/05/document.pdf

# Cloud-signed URLs:
curl 'https://s3.amazonaws.com/bucket/key?X-Amz-Signature=...&X-Amz-Expires=86400'
# Long-lived signed URLs are equivalent to a public URL until expiry
```

## Test Matrix (per Endpoint)

For every discovered endpoint, create a row in:

| Endpoint | Verb | Auth State | Expected | Actual | Notes |
|---|---|---|---|---|---|
| `/api/admin/users` | GET | unauth | 401 | ? | |
| `/api/admin/users` | GET | low-user | 403 | ? | |
| `/api/admin/users` | GET | other-tenant-admin | 403 | ? | |
| `/api/admin/users` | POST | low-user | 403 | ? | |
| `/api/admin/users` | OPTIONS | unauth | varies | ? | |

A spreadsheet with one row per (endpoint, verb, auth state) makes findings systematic instead of accidental.

## Engagement Cheatsheet

```
[ ] Map endpoints by role (compare bundles, OpenAPI specs)
[ ] Brute every (path, verb) with low-priv token
[ ] Test mass assignment on every PUT/PATCH for role/tenant fields
[ ] Test parameter pollution for role
[ ] Test horizontal access per object across user boundary
[ ] Test mutation actions across object boundary
[ ] Test stale permissions after role change
[ ] Test method tampering (X-HTTP-Method-Override, _method)
[ ] Test path confusion (.., %2f, ;, double-slash)
[ ] Test gateway header injection
[ ] Verify JWT-vs-DB role drift
```

---

## Key References

- OWASP API Security Top 10 — API1 (Broken Object Level Authorization), API5 (Broken Function Level)
- OWASP WSTG-AUTHZ
- "Mass Assignment Cheat Sheet" (OWASP)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/access-control.md
