---
name: offensive-mass-assignment
description: "Use this skill during an authorized application or API security assessment to identify and validate mass assignment, auto-binding, or over-posting. You map fields accepted from JSON and form requests, test whether sensitive properties such as role, isAdmin, ownerId, and price are bindable, and independently confirm whether the server persists or acts on them. Keep all testing within approved scope, using only authorized accounts and disposable records. This skill distinguishes unsafe binding from object-level authorization and workflow defects, and provides safe request patterns, evidence criteria, defensive controls, and concise reporting guidance for reproducible findings."
---

# Mass Assignment

Mass assignment occurs when an application binds client input to an object with
more writable properties than the endpoint intends to expose.

You test whether an endpoint accepts an unexpected property.

You then confirm whether the server persists or uses that property.

Use only systems, accounts, data, and environments explicitly in scope.

Use a test account and a disposable record whenever possible.

Do not change another user's privileges, ownership, billing, or production data.

Mass assignment is also called auto-binding, over-posting, or unsafe object
binding.

The central question is:

> Can you send a field that the server did not intend the client to control?

Impact depends on the field.

A writable display preference may have little security impact.

A writable `role`, `isAdmin`, `ownerId`, `price`, `balance`, or `status` can
create a material integrity or authorization issue.

This differs from `offensive-idor`.

Use `offensive-idor` when the principal issue is access to an object belonging
to another user or tenant.

A writable `ownerId` may be mass assignment; access to the reassigned object
may also require IDOR analysis.

This also differs from `offensive-business-logic`.

Use `offensive-business-logic` when valid operations can be sequenced or
combined to defeat a workflow rule.

A client-controlled `price` directly bound into an order is mass assignment.

A discount workflow that calculates a negative order total is business logic.

State the primary root cause accurately and avoid duplicating those skills.

## Quick Workflow

1. Identify an authorized create or update endpoint.
2. Capture a normal baseline request and response.
3. Inventory candidate sensitive or server-managed fields.
4. Add one unexpected field to the baseline request.
5. Submit a safe, reversible test value.
6. Retrieve the resource through an independent authorized read path.
7. Confirm persistence or a safe behavior change.
8. Record the request, response, read-back, and impact.
9. Restore or delete disposable data when permitted.

Do not treat `200 OK` as proof.

Do not treat an echoed request body as proof.

Do not submit every candidate field in one request.

One field per request produces clear evidence and clear remediation.

Prefer harmless, distinctive values.

For strings, use an assessment marker such as `"assessment-marker"`.

For booleans, use the opposite baseline value only when safe.

For identifiers, use only a secondary test principal you control.

## Framing the Assessment

Treat every create and update route as a separate binding surface.

An endpoint can safely bind some fields and unsafely bind others.

A profile route may allow `displayName` but must not allow `role`.

An order route may allow `shippingAddress` but must not allow `price`.

An administration route can intentionally accept privileged fields, but it must
apply the correct authorization before persisting them.

Compare these field sets:

- Fields documented as editable.
- Fields rendered in the normal user interface.
- Fields present in API responses.
- Fields accepted by the request parser.
- Fields persisted by service code.

Do not assume a response field is writable.

Do not assume a hidden HTML field is protected.

Do not assume an ignored field is persisted.

## Scope and Safety

Before testing, verify the endpoint is in the approved target list.

Verify the account belongs to the engagement.

Verify the resource is disposable or safely reversible.

Verify that you have a normal authorized way to read the resulting state.

Record the environment, API version, role, and timestamp.

Respect tenant, notification, rate, and data-handling restrictions.

Do not create a real charge without explicit approval.

Do not reassign another customer's resource.

Do not publish customer-facing content unless the engagement permits it.

If you cannot safely verify persistence, report suspected binding behavior only.

## Finding the Bindable Schema

Start with legitimate application behavior.

Capture requests the browser or mobile client makes when it creates or edits a
resource.

Compare that request with the corresponding response object.

Also inspect:

- OpenAPI schemas and API reference material.
- Client-side type definitions.
- GraphQL input types, when allowed.
- HTML forms and hidden fields.
- JavaScript request builders.
- Validation errors.
- Existing test fixtures.

Create a field inventory.

Classify each field as user-editable, server-managed, privilege-related,
ownership-related, financial, workflow-related, or unknown.

Use the application's existing naming conventions.

### Compare Request and Response Shapes

A normal request may contain:

```json
{
  "displayName": "Avery",
  "timezone": "UTC"
}
```

The response may reveal additional candidates:

```json
{
  "id": "p_test",
  "displayName": "Avery",
  "timezone": "UTC",
  "role": "member",
  "isAdmin": false,
  "ownerId": "u_test",
  "createdAt": "2026-10-25T12:00:00Z"
}
```

The additional fields are candidates, not proof of writability.

Test each field separately.

Review request DTOs, generated input types, `Partial<Model>` usage, hidden
inputs, and form serialization helpers.

A persistence-shaped type or hidden field is a candidate, not proof.

### Use Validation Errors Carefully

Send one unknown field to an authorized test endpoint.

```http
PATCH /v1/profile HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "displayName": "Avery",
  "assessmentProbe": "test"
}
```

A validation error can indicate strict schema handling.

A successful response can indicate permissive parsing.

Neither outcome alone proves persistence.

Use error messages as schema hints, not as authorization to fuzz aggressively.

## Candidate Fields

Prioritize fields with a plausible security consequence.

```json
{
  "role": "admin",
  "isAdmin": true,
  "permissions": ["manage_users"],
  "ownerId": "u_test_owner",
  "accountId": "a_test",
  "price": 1,
  "discount": 100,
  "status": "approved",
  "approved": true,
  "published": true,
  "createdAt": "2026-10-25T12:00:00Z"
}
```

Test privilege changes only on isolated accounts.

Use ownership identifiers belonging to authorized test principals only.

Use a draft or sandbox for financial values and workflow states.

An ignored server-managed field is not a vulnerability.

Coordinate any cross-object access analysis through `offensive-idor`.

## Technique: JSON Over-Posting

Start with a known-good request.

Baseline:

```http
PATCH /v1/profiles/p_test HTTP/1.1
Host: api.example.com
Authorization: Bearer test-token
Content-Type: application/json

{
  "displayName": "Avery",
  "timezone": "UTC"
}
```

Controlled test:

```http
PATCH /v1/profiles/p_test HTTP/1.1
Host: api.example.com
Authorization: Bearer test-token
Content-Type: application/json

{
  "displayName": "Avery",
  "timezone": "UTC",
  "role": "viewer"
}
```

Use a distinctive, safe value when possible.

Then read the resource separately:

```http
GET /v1/profiles/p_test HTTP/1.1
Host: api.example.com
Authorization: Bearer test-token
```

Wait for the documented consistency window before reading an asynchronous
system.

Do not rely on a request echo or frontend state before refresh.

## Technique: Form Over-Posting

Test form binding when the endpoint normally accepts a form.

```http
POST /profile HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

displayName=Avery&timezone=UTC&isAdmin=false
```

Use multipart only where the application normally accepts multipart data.

Test form fields one at a time and independently read the saved resource.

## Technique: Nested Binding

Nested structures can expose writable properties below a controlled root.

```json
{
  "displayName": "Avery",
  "settings": {
    "timezone": "UTC",
    "isAdmin": false
  }
}
```

Also test application-used relationship objects and collection members.

Record the complete persisted path, such as `settings.isAdmin`.

## Technique: PATCH and GraphQL

Test `PATCH` and `PUT` independently when both exist.

JSON Merge Patch can bind every supplied property unless a DTO filters it.

JSON Patch requires an allowlist of operations and paths.

```json
[
  {
    "op": "replace",
    "path": "/price",
    "value": 1
  }
]
```

GraphQL input types can enumerate accepted fields.

If a generic JSON scalar accepts arbitrary input, apply the same one-field
testing approach.

## Confirming Persistence

Independent confirmation is required.

Use one or more of these methods:

- A subsequent authorized `GET` response.
- A normal UI page reload.
- A documented audit event visible to your test role.
- A permitted list or search response.
- A harmless behavior change tied to the field.
- A database read, only when database access is in scope.

Example write:

```json
{
  "displayName": "Avery",
  "ownerId": "u_test_owner"
}
```

Example independent response:

```json
{
  "id": "p_test",
  "displayName": "Avery",
  "ownerId": "u_test_owner"
}
```

This strongly supports persistence of `ownerId`.

You must still describe the actual impact.

If the secondary test account cannot access or act on the object, impact may be
limited despite persistence.

Weak evidence includes:

- HTTP `200`.
- A generic saved message.
- Immediate frontend state.
- An echoed request body.
- An unverified debug log.

## Interpreting Outcomes

An explicit unknown-field rejection is generally a good sign.

```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "role",
      "message": "Unknown field"
    }
  ]
}
```

Do not report a vulnerability based on that result.

A server can accept and silently discard an unknown property.

Confirm with a follow-up read before concluding it is ignored.

A server can normalize a sensitive value safely.

For example, self-service registration may always force `role` to `"member"`.

If an unexpected property is stored or acted upon, you have confirmed the
technical condition for mass assignment.

Then assess impact using the smallest safe proof.

## Detection / Defender View

Treat request binding as an explicit security boundary.

Use allowlists of bindable fields for every endpoint and action.

Never bind the persistence model directly from JSON or form bodies.

Never rely on hidden fields or client-side validation.

### Allowlists

Define only the fields that the action supports.

```typescript
const profileUpdateFields = ["displayName", "timezone"] as const;

type ProfileUpdateField = (typeof profileUpdateFields)[number];
```

Reject or ignore fields outside the deliberate contract.

Prefer clear rejection when clients need early feedback.

Apply allowlists recursively to nested objects.

### DTOs and Explicit Mapping

Use request-specific DTOs.

```typescript
interface UpdateProfileDto {
  displayName?: string;
  timezone?: string;
}

function applyProfileUpdate(profile: Profile, input: UpdateProfileDto): void {
  if (input.displayName !== undefined) {
    profile.displayName = input.displayName;
  }

  if (input.timezone !== undefined) {
    profile.timezone = input.timezone;
  }
}
```

Do not use broad assignment on untrusted data.

```typescript
Object.assign(profile, request.body);
```

Do not expose `Partial<Profile>` as a public request contract.

Keep separate DTOs for self-service, administrative, registration, import, and
internal integration actions.

### Authorization and Patches

Validation does not replace authorization.

Put sensitive changes behind dedicated, authorized operations.

```typescript
function changeRole(actor: User, target: User, role: Role): void {
  if (!actor.permissions.includes("manage_users")) {
    throw new Error("Forbidden");
  }

  target.role = role;
}
```

For JSON Patch, allowlist operations and paths.

For Merge Patch, map approved fields into a DTO.

Do not send arbitrary patch documents directly to an ORM or document store.

### Testing and Monitoring

Write negative tests for fields that must remain non-bindable.

```typescript
it("rejects a self-service role update", async () => {
  const response = await request(app)
    .patch("/v1/profile")
    .send({ displayName: "Avery", role: "admin" });

  expect(response.status).toBe(400);
});
```

Verify that rejected or ignored data does not persist after a follow-up read.

Test create, update, bulk, import, and patch routes separately.

Monitor validation failures and suspicious sensitive property names.

Avoid logging raw tokens, secrets, or unnecessary personal data.

## Engagement Cheatsheet

### Fast Triage

```text
Capture a normal write request.
Compare request fields with the response model.
Choose one sensitive or server-managed candidate.
Add it to the request with a safe value.
Read the resource through an independent path.
Record only confirmed persistence.
```

### Candidate Names

```text
role
isAdmin
permissions
ownerId
accountId
organizationId
tenantId
price
discount
balance
status
approved
published
```

### Evidence Checklist

```text
[ ] Baseline request
[ ] Modified request
[ ] Immediate response
[ ] Independent read-back
[ ] Test role and environment
[ ] Safe impact verification
[ ] Secrets and identifiers redacted
[ ] Cleanup recorded
```

### Remediation Checklist

```text
[ ] DTO per action
[ ] Bindable field allowlists
[ ] No direct persistence-model binding
[ ] Sensitive changes use authorization
[ ] Nested schemas constrained
[ ] Patch paths allowlisted
[ ] Regression tests added
```

## Key References

- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes.
- OWASP API Security Top 10: API3 Mass Assignment guidance.
- OWASP API Top 10: use the current edition and terminology adopted by the engagement.
- OWASP Mass Assignment Cheat Sheet and framework-specific secure-binding guidance.

Map confirmed uncontrolled modification of object attributes to CWE-915.

Keep findings scoped to verified behavior.

Recommend allowlists of bindable fields, dedicated DTOs, explicit mapping, and
authorization checks for sensitive state transitions.
