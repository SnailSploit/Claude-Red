---
name: offensive-nosql-injection
description: "Use this skill during explicitly authorized security assessments to identify, validate, and clearly report NoSQL injection risks without broadening scope or treating document stores like relational databases. You map every untrusted input that reaches a query, distinguish JSON bodies from URL-encoded parameters, and safely test whether an application accepts MongoDB operators or executable JavaScript where it expects scalar data. The workflow emphasizes reproducible evidence against controlled example.com targets or documentation-address space only, minimal-impact authentication-bypass validation, and remediation guidance that developers can implement. It covers common MongoDB operator injection, JavaScript-capable $where behavior, regex abuse, and nearby CouchDB and Redis command-injection concerns while keeping those distinct. Pair it with offensive-sqli for a complete input-to-query assessment, but do not duplicate SQL payloads or SQL-specific tactics."
---

# NoSQL Injection

NoSQL injection occurs when an application turns untrusted input into part of a
document, key-value, graph, or search query without enforcing the expected type
and structure.

## Framing

MongoDB queries are documents.

That is convenient when the application constructs every query field itself.

It is dangerous when a request value intended to be a string, number, or Boolean
can instead become an object containing an operator.

Consider an intended lookup:

```javascript
db.users.findOne({ email: suppliedEmail, password: suppliedPassword })
```

If `suppliedEmail` is always a string, the query remains a scalar comparison.

If the server accepts a request object unchanged, an attacker may supply an
operator document instead.

```javascript
db.users.findOne({ email: { $ne: "" }, password: { $ne: "" } })
```

The security issue is not the database product by itself.

The issue is a type and structure boundary between untrusted input and the query
language.

Document stores have different query languages and driver behaviors.

Verify the actual backend, framework, serialization path, and query API before
claiming impact.

MongoDB examples are the central focus because its operators commonly surface in
web applications.

Adjacent systems require different validation:

- CouchDB commonly exposes selector, map/reduce, and design-document concerns.
- Redis commonly presents command construction or protocol-framing concerns.
- Elasticsearch and OpenSearch have query-DSL injection and resource-abuse cases.
- Graph databases use their own query languages and should receive separate tests.

Do not call all of these “MongoDB injection.”

Report the actual query boundary and affected technology precisely.

## Quick Workflow

1. Confirm written authorization and the permitted application paths.
2. Identify endpoints that filter, search, authenticate, update, or delete data.
3. Capture a normal request and establish a baseline response.
4. Determine whether input arrives as JSON, form data, query parameters, or path
   values.
5. Determine whether the expected server-side type is scalar, array, or object.
6. Test one benign type-confusion probe at a time.
7. Compare status, body shape, redirect, timing, and authenticated state.
8. Confirm a positive result with a minimal alternate probe.
9. Stop once the agreed proof threshold is met.
10. Record the exact request format, response evidence, affected field, and
    remediation.

Start with low-impact operators that change comparison semantics.

Prefer a known nonexistent test value to a real user identifier.

Use a scoped test account when authentication behavior must be validated.

Keep a request log with timestamps and correlation IDs.

Do not rely on a single response difference.

False positives can result from validation middleware, caching, WAF behavior,
generic error handling, or a completely different downstream service.

## Establish a Baseline

Send an ordinary request with controlled data first.

For a fictional login endpoint:

```http
POST /api/session HTTP/1.1
Host: example.com
Content-Type: application/json

{"email":"nobody@example.com","password":"not-the-password"}
```

Record the normal response.

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"Invalid credentials"}
```

Then send malformed scalar values to understand validation.

```http
POST /api/session HTTP/1.1
Host: example.com
Content-Type: application/json

{"email":true,"password":false}
```

If the endpoint rejects Booleans with a type-validation error, it may also reject
operator objects.

That is useful evidence of a defensive boundary.

Do not equate validation errors with security by itself.

Test whether nested objects are rejected consistently for every query-relevant
field.

## JSON Bodies Versus URL Parameters

JSON allows nested objects directly.

That makes operator injection probes easy to express and easy to identify in
captured traffic.

```json
{
  "email": {
    "$ne": ""
  },
  "password": {
    "$ne": ""
  }
}
```

Some frameworks bind URL-encoded bracket notation into nested objects.

For example, a request might express the same shape as:

```http
POST /session HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email%5B%24ne%5D=&password%5B%24ne%5D=
```

Decoded, that becomes:

```text
email[$ne]=&password[$ne]=
```

Whether this becomes a nested server object depends on the framework and parser.

Never assume PHP-like bracket handling in every environment.

Some parsers keep the brackets in the key name.

Some parsers reject nested keys.

Some parsers allow prototype-pollution-adjacent keys that deserve separate
assessment under a separate finding category.

Query-string variants may look like:

```http
GET /api/users?status%5B%24ne%5D=disabled HTTP/1.1
Host: example.com
```

JSON versus URL syntax is a transport distinction, not a different vulnerability.

The decisive question is what typed value reaches the database driver.

Use the application’s normal content type whenever possible.

Changing both content type and payload structure at once makes results ambiguous.

## MongoDB Operator Injection

MongoDB operators alter how a field is compared or evaluated.

Operator injection arises when a server permits a client-controlled operator in a
position that should contain a scalar value.

Test one operator and one field at a time.

Keep values benign and limited to the authorized data set.

### `$ne`: Not Equal

`$ne` matches values that are not equal to the supplied value.

In an unsafe authentication query, it can turn an intended equality check into a
broad match.

```json
{
  "email": {
    "$ne": ""
  },
  "password": {
    "$ne": ""
  }
}
```

This is a conceptual example for `example.com`.

It is not a substitute for a controlled validation plan.

An application may still resist bypass because it hashes a password before query
construction, adds account-state constraints, or performs post-query checks.

Validate the actual outcome.

For search filters, a lower-risk probe may be:

```json
{
  "status": {
    "$ne": "disabled"
  }
}
```

Compare the result set only within your approved test records.

Do not enumerate unrelated records to demonstrate that an operator works.

### `$gt`: Greater Than

`$gt` compares values greater than the supplied value.

It can expose a type boundary when a field expected to be a numeric scalar accepts
an operator object.

```json
{
  "priority": {
    "$gt": 0
  }
}
```

Use it against an authorized filter where a response difference is expected and
safe.

For a date-like field, use a documentation-safe value:

```json
{
  "createdAt": {
    "$gt": "2026-01-01T00:00:00.000Z"
  }
}
```

Do not infer MongoDB type coercion from client-side strings.

The driver, ORM, schema, and database field type control comparison behavior.

### `$regex`: Pattern Matching

`$regex` can change exact matching into pattern matching.

It can also create a performance concern if the server accepts expensive patterns.

Start with a simple anchored pattern.

```json
{
  "username": {
    "$regex": "^test-user$"
  }
}
```

Use a non-sensitive, scoped test identifier.

Avoid catastrophic or intentionally expensive regular expressions.

Regex resource exhaustion is a separate availability assessment and needs explicit
authorization.

For an authentication field, a regex probe can show operator acceptance but may
not prove bypass:

```json
{
  "email": {
    "$regex": "^nobody@example\\.com$"
  }
}
```

Record whether the application rejects the object, sanitizes the operator, or
passes it into a query.

### `$where`: Server-Side JavaScript

`$where` historically allows JavaScript evaluation in MongoDB query contexts.

Its availability depends on MongoDB configuration, version, hosting mode, and
application query construction.

Treat it as high risk because it may cross from comparison manipulation into
server-side code evaluation within the database process.

Do not use it by default.

Use it only when the engagement explicitly permits testing server-side JavaScript
execution and when a safe proof is agreed.

A harmless conceptual shape is:

```json
{
  "$where": "return false;"
}
```

This example demonstrates the syntax without attempting data access, delay, file
interaction, network interaction, or command execution.

If the application accepts this key where it should accept a normal filter, stop
and assess with the engagement lead before proceeding.

Do not use timing loops, sleep-like constructs, or data-dependent predicates as a
default validation technique.

Those techniques can affect availability and may disclose more than necessary.

Server-side JavaScript should be disabled unless there is a documented,
reviewed business requirement.

### Operators in Nested Fields

Applications often construct nested documents from request bodies.

That makes deep validation important.

For example:

```json
{
  "profile": {
    "age": {
      "$gt": 18
    }
  }
}
```

If the API expects `profile.age` to be a number, the object should fail schema
validation before query construction.

Do not confuse a legitimate, documented filter DSL with injection.

An API may intentionally support operators in a dedicated filter object.

In that case, assess authorization, operator allowlists, field allowlists,
resource limits, and tenant scoping rather than calling all operator use an
injection flaw.

## Authentication Bypass Patterns

Authentication is a high-impact path.

Use a dedicated assessment account and a pre-agreed proof requirement.

Never attempt to access other users’ accounts merely to strengthen the finding.

An unsafe pattern resembles:

```javascript
const user = await users.findOne({
  email: req.body.email,
  password: req.body.password,
});
```

The flaw exists if `req.body.email` and `req.body.password` can be objects rather
than strings.

For a controlled `example.com` illustration, an object-shaped request is:

```http
POST /api/session HTTP/1.1
Host: example.com
Content-Type: application/json

{"email":{"$ne":""},"password":{"$ne":""}}
```

Success indicators may include:

- a session cookie created for the test account;
- a documented success redirect;
- an authenticated response that identifies only the controlled test account;
- a token with expected low-privilege claims;
- a server audit event that confirms the scoped account session.

Do not treat a changed error message as successful authentication.

Do not retain authentication tokens beyond the assessment rules.

Log out and revoke the controlled session after validation.

Safer application logic loads a user by a validated scalar identity, then checks
the password using a dedicated password-verification function.

```javascript
const email = requireEmailString(req.body.email);
const password = requirePasswordString(req.body.password);
const user = await users.findOne({ email });

if (!user || !(await verifyPassword(password, user.passwordHash))) {
  throw new UnauthorizedError("Invalid credentials");
}
```

This pattern prevents password values from becoming query operators and preserves
appropriate password-hash verification.

## Detection / Defender View

Defenders prevent NoSQL injection by preserving type boundaries.

Validate request shape before business logic.

Use typed query APIs that construct field names and operators in server code.

Treat user input as a scalar value unless a documented filter DSL explicitly
requires structured input.

Reject objects where a string, number, Boolean, or identifier is expected.

Reject arrays where a scalar is expected.

Reject unknown keys at every nested level.

Allowlist filterable fields.

Allowlist permitted operators per field.

Do not use a denylist of `$`-prefixed names as the only control.

Denylists are easy to miss during serialization, nesting, and library upgrades.

Use JSON Schema, Zod, Joi, Pydantic, class-validator, or an equivalent
server-side schema system correctly and consistently.

Ensure the validator runs before any query construction.

Configure parsers so form and query parameters cannot silently become arbitrary
objects where scalars are expected.

Avoid directly spreading untrusted objects into a query:

```javascript
// Unsafe: client controls query structure.
const users = await db.collection("users").find(req.body.filter).toArray();
```

Use explicit construction instead:

```javascript
const status = requireAllowedStatus(req.body.status);
const users = await db.collection("users").find({ status }).toArray();
```

For supported filter DSLs, translate an application-level grammar into a new,
server-created query document.

```javascript
const allowedComparisons = new Set(["equals", "after"]);
const filter = parseApplicationFilter(req.body.filter, allowedComparisons);
const query = buildSafeQuery(filter);
```

Do not pass the client filter directly to MongoDB.

Disable server-side JavaScript and `$where` where feasible.

Review whether `$expr`, map-reduce, aggregation expressions, and user-supplied
pipeline stages are necessary in the exposed API.

Apply least privilege to the database account.

The application account should not have administrative roles.

Separate read-only reporting roles from write-capable application roles.

Enforce tenant and ownership constraints server-side, independent of filters.

Add query timeouts and result limits.

Monitor rejected operator-shaped input.

Log validation failures without logging secrets or full sensitive request bodies.

Alert on repeated keys such as `$ne`, `$gt`, `$regex`, `$where`, and unusual
bracket-notation parameters.

Treat detection telemetry as a supplement to validation, not a replacement.

## CouchDB: Adjacent but Distinct

CouchDB is document-oriented but does not use MongoDB operators.

Its security concerns can include overly permissive selectors, design-document
exposure, map/reduce logic, authorization gaps, and query-resource abuse.

Do not send MongoDB `$ne` payloads and call the result a CouchDB test.

Instead, determine whether the application accepts a CouchDB Mango selector or
other structured query object.

If a selector DSL is intentionally exposed, verify field restrictions, tenant
constraints, authorization, result limits, and index expectations.

Keep any test selector limited to authorized data.

```json
{
  "selector": {
    "owner": "assessment-user"
  },
  "limit": 1
}
```

Do not create, alter, or execute design documents without explicit permission.

## Redis Command Injection: Adjacent but Distinct

Redis command injection is not NoSQL operator injection.

It usually arises when application code constructs Redis commands, Lua scripts,
or protocol messages from untrusted strings unsafely.

Use the driver’s argument-array API rather than concatenating command text.

```javascript
// Safer: arguments remain distinct values.
await redis.set(`session:${sessionId}`, serializedSession);
```

Avoid APIs that interpret a user-controlled string as an entire Redis command.

Do not send destructive Redis commands during a normal assessment.

Do not use `FLUSHALL`, `CONFIG`, replication, module, or script-management
commands as probes.

For a suspected Redis boundary, document the code path and validate only with a
non-destructive, pre-approved test fixture.

## Engagement Cheatsheet

### Before Testing

```text
[ ] Authorization confirms NoSQL testing.
[ ] Scope names only approved hosts and routes.
[ ] Test accounts and fixtures are ready.
[ ] Stop condition is agreed.
[ ] Logging and redaction plan is ready.
```

### Baseline

```text
[ ] Send a normal scalar request.
[ ] Send a wrong scalar request.
[ ] Record status, response shape, and session state.
[ ] Identify JSON, form, and query-string parsing paths.
```

### Operator Probes

```text
[ ] Test a single $ne object in a non-sensitive filter.
[ ] Test $gt only for authorized numeric/date filters.
[ ] Test an anchored $regex only against scoped fixture data.
[ ] Test $where only with explicit approval and a harmless false predicate.
[ ] Stop after minimal proof.
```

### Confirm

```text
[ ] Reproduce once with a controlled alternate input.
[ ] Rule out caching and generic errors.
[ ] Limit proof to the dedicated assessment account.
[ ] Log out and revoke issued sessions.
```

### Report

```text
[ ] Include request transport and decoded structure.
[ ] Include baseline and differential evidence.
[ ] State demonstrated impact, not assumed impact.
[ ] Recommend scalar validation and operator allowlists.
[ ] Recommend disabling server-side JavaScript where feasible.
[ ] Map to CWE-943.
```

## Key References

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic.
  https://cwe.mitre.org/data/definitions/943.html
- OWASP NoSQL Injection Prevention Cheat Sheet.
  https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Testing Guide: Testing for NoSQL Injection.
  https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: NoSQL injection.
  https://portswigger.net/web-security/nosql-injection
- MongoDB documentation: Query and projection operators.
  https://www.mongodb.com/docs/manual/reference/operator/query/
- MongoDB documentation: Server-side JavaScript.
  https://www.mongodb.com/docs/manual/core/server-side-javascript/

Use current vendor documentation when behavior depends on database version,
driver, framework parser, or managed-service configuration.

When in doubt, validate in an isolated environment that mirrors the authorized
application’s relevant request parsing and query construction.
