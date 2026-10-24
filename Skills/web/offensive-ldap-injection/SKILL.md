---
name: offensive-ldap-injection
description: "Use this skill only during an explicitly authorized security assessment of an application that queries an LDAP directory. It provides a controlled methodology for identifying LDAP filter and bind injection, validating impact with fictional targets, and documenting reproducible evidence without accessing unnecessary records. You test only approved hosts and accounts, begin with low-impact syntax probes, and stop if a result exposes data beyond the agreed scope. The examples use example.com and 192.0.2.0/24 exclusively. Pair each finding with practical remediation: parameterized directory APIs, RFC 4515 escaping, schema-aware validation, least-privilege service binds, and audit telemetry. Do not use this skill for unapproved systems, credential collection, persistence, denial of service, or data exfiltration."
---

# LDAP Injection

LDAP injection occurs when application-controlled text becomes LDAP query
syntax instead of literal data.

You assess the boundary where an application constructs a directory search
filter, distinguished name (DN), or bind operation from user input.

This is an authorized assessment methodology.

You work only inside the written scope, rate limits, and data-handling rules.

You use `example.com` and `192.0.2.0/24` in examples and evidence templates.

You do not substitute a real domain, address, username, or credential.

You do not collect directory data that is not necessary to prove impact.

LDAP injection is commonly mapped to CWE-90: Improper Neutralization of
Special Elements used in an LDAP Query.

The primary technical reference for LDAP search-filter escaping is RFC 4515.

The OWASP LDAP Injection Prevention Cheat Sheet provides implementation
guidance and testing context.

## Framing

An LDAP client often creates a filter similar to this:

```text
(&(objectClass=person)(uid=<user-input>))
```

If `<user-input>` is concatenated directly, LDAP filter metacharacters can
change the filter's structure.

This differs from a lookup that passes user input as a typed filter value.

The core question is simple:

> Does the application treat your input as a value, or as LDAP syntax?

You validate that question with the least invasive probe that gives a clear
answer.

You distinguish three related injection surfaces:

1. Search filters, such as `(&(uid=value)(memberOf=group))`.
2. DN construction, such as `uid=value,ou=people,dc=example,dc=com`.
3. Bind or authentication flow, where a lookup result controls a bind.

Search-filter injection is usually the most visible form.

DN construction has different escaping requirements from filter construction.

Do not assume that RFC 4515 filter escaping makes DN construction safe.

Record the endpoint, parameter, request method, apparent directory operation,
and expected normal behavior before testing.

Use an approved test identity when the engagement provides one.

If the engagement does not provide a test identity, prefer public search,
registration, password-reset, or error-message paths over authentication.

Treat an unexpected directory response as sensitive evidence.

Capture only the minimum response fields needed to establish the issue.

Do not enumerate users, groups, organizational units, or attributes unless
the rules of engagement explicitly require it.

## Quick Workflow

1. Confirm the target is in scope and record the authorization reference.
2. Identify inputs that may reach a directory search, DN, or bind.
3. Baseline valid, invalid, empty, and long-but-benign input behavior.
4. Send one metacharacter probe at a time.
5. Compare response status, body length, timing, redirect, and session state.
6. Validate filter structure changes with a harmless true/false pair.
7. Demonstrate impact using the smallest allowed proof.
8. Stop expanding once the finding is reproducible.
9. Preserve sanitized request/response evidence.
10. Map root cause to remediation and detection guidance.

Start with server-side observation when available.

Application logs, safe staging telemetry, and code review can answer the
question with less production interaction.

If you have source access, trace each value from HTTP input to the LDAP API.

Flag string interpolation, concatenation, templating, and custom escaping.

Prefer library functions that bind values into a filter rather than manually
assembling filter strings.

If black-box testing is necessary, use a narrow request cadence.

Avoid concurrent fuzzing against authentication or directory-backed endpoints.

Use a correlation header or other approved request marker when the application
supports it.

## LDAP Filter Fundamentals

LDAP search filters are prefix expressions.

An equality filter uses this shape:

```text
(uid=alice)
```

An AND filter uses an ampersand:

```text
(&(objectClass=person)(uid=alice))
```

An OR filter uses a vertical bar:

```text
(|(uid=alice)(uid=bob))
```

Negation uses an exclamation mark:

```text
(!(accountStatus=disabled))
```

Presence is commonly expressed with an asterisk:

```text
(mail=*)
```

Substring filters also use the asterisk:

```text
(cn=ali*)
```

An attacker-controlled parenthesis can prematurely close an equality filter.

An attacker-controlled asterisk can broaden an equality or substring match.

An attacker-controlled ampersand, vertical bar, or exclamation mark can add
boolean logic.

Backslash is meaningful because it begins hexadecimal escaping.

NUL is not valid raw filter text and must be handled carefully at API
boundaries.

The key filter metacharacters are:

```text
* ( ) \ NUL
```

RFC 4515 defines escaping for those characters when they are literal values.

The escaped octets are:

```text
*    -> \2a
(    -> \28
)    -> \29
\    -> \5c
NUL  -> \00
```

This escaping must occur exactly once at the boundary where an untrusted value
becomes an LDAP assertion value.

Escaping too early can produce a value that later gets decoded or concatenated
unsafely.

Escaping too late means the parser has already interpreted the metacharacter.

## Identify Candidate Inputs

Review inputs with directory-shaped names first:

- `username`
- `user`
- `login`
- `email`
- `mail`
- `uid`
- `cn`
- `group`
- `role`
- `department`
- `search`
- `q`

Also review values that appear unrelated but can select a user:

- password-reset identifiers
- invite recipient fields
- account lookup fields
- profile search terms
- SSO mapping claims
- API query parameters
- JSON request properties
- form hidden fields

Record the normal request exactly as sent.

Example fictional request:

```http
POST /api/auth/lookup HTTP/1.1
Host: app.example.com
Content-Type: application/json

{"username":"test.user"}
```

Do not infer LDAP from an error alone.

Look for consistent clues such as LDAP exception text, DN fragments,
object-class names, or directory-specific result codes.

Treat verbose error output as a separate information-disclosure observation.

## Filter Metacharacter Probes

Begin with individual characters.

The purpose is to detect parsing or escaping behavior, not to retrieve data.

Test one of these values in a field expected to be literal:

```text
*
(
)
\
```

Interpretation examples:

- A validation error can indicate safe input validation or an incomplete parser.
- An LDAP syntax error can indicate unescaped concatenation.
- A normal literal lookup can indicate correct escaping.
- A broader result can indicate wildcard interpretation.

Do not conclude vulnerability merely because the application rejects input.

Rejection can be a valid defensive control.

Do not conclude safety merely because the application hides errors.

Use behavior comparison, code review, or approved server-side telemetry.

### Wildcard Semantics

For a lookup that normally expects an exact username, compare an ordinary
unknown literal with a literal asterisk.

Use this fictional request only in an authorized test environment:

```http
GET /directory/search?uid=%2A HTTP/1.1
Host: app.example.com
```

If the endpoint returns a result set only for the asterisk, the application
may be allowing the wildcard into the LDAP filter.

Do not retain result records.

Record only that the result count or response class changed.

If the application is supposed to support substring search, a wildcard may be
intentional.

In that case, assess whether authorization, result limits, and attribute
controls prevent excessive disclosure.

### Parenthesis Semantics

Parentheses delimit LDAP filter expressions.

An unmatched parenthesis probe can reveal whether the backend parses raw input.

Example:

```http
GET /directory/search?uid=%28 HTTP/1.1
Host: app.example.com
```

Compare its result with a URL-encoded literal backslash or ordinary punctuation.

Do not rely on an exception message that includes implementation internals.

Use it only as a hypothesis that you confirm safely.

### Backslash Semantics

Backslash begins an RFC 4515 hexadecimal escape sequence.

Test it as a literal character to verify whether the application escapes it.

```http
GET /directory/search?uid=%5C HTTP/1.1
Host: app.example.com
```

Malformed escaping must be rejected or treated as literal input.

It must not be silently repaired into a filter fragment.

## AND and OR Logic Abuse

When user input is concatenated into a filter, injected parentheses can
terminate the intended assertion and add a second assertion.

Consider this unsafe pseudocode:

```python
filter_text = "(&(objectClass=person)(uid=" + request.args["uid"] + "))"
connection.search(base_dn, filter_text)
```

Your goal is to demonstrate structural control with an approved true/false
comparison, not to extract entries.

Use a known-false predicate against a fictional attribute value:

```text
)(uid=nonexistent-test-value)
```

Use an explicitly true predicate only when the test directory defines one:

```text
)(objectClass=person)
```

Wrap and encode probes according to the application transport.

For example, the raw input field may receive:

```text
test.user)(objectClass=person
```

Do not copy a payload blindly.

First reconstruct the expected filter shape and count its parentheses.

Then predict the intended parsed filter before sending the request.

If you cannot predict the resulting structure, use source review or a local
test harness instead of trial-and-error against a live service.

An OR injection can change a restrictive filter into one that admits either
the intended value or another condition.

Illustrative unsafe filter construction:

```text
(&(objectClass=person)(uid=<input>)(accountStatus=active))
```

An assessment validates whether injected boolean structure changes the outcome
between a known true and known false condition.

It does not need to name or return another directory entry.

## Authentication-Bypass Patterns

LDAP authentication flows frequently have two stages:

1. Search for the account DN using a supplied identifier.
2. Bind as that DN using the supplied password.

A secure flow must require both stages to succeed.

Filter injection can be dangerous when a lookup chooses an unintended account,
or when code treats “any search result” as authentication success.

Use this fictional vulnerable pattern only for code-review recognition:

```python
search_filter = f"(&(uid={username})(userPassword={password}))"
connection.search("ou=people,dc=example,dc=com", search_filter)
authenticated = len(connection.entries) > 0
```

This design combines identity lookup and password verification in a search
filter, which is unsafe and difficult to reason about.

It may also expose password values to application or directory logs.

The preferred design is:

1. Escape and validate the user identifier as a filter value.
2. Search only for the account DN with a least-privilege service bind.
3. Enforce an exact single-account result.
4. Perform an LDAP bind as that exact DN with the supplied password.
5. Treat bind success as authentication success.

Do not attempt to authenticate as a real user during validation.

Use an authorized synthetic account in a lab or staging system.

For black-box testing at `app.example.com`, measure only whether an invalid
password can produce the same authenticated state as a valid test password.

Use a session-state comparison:

```text
Control A: valid test identity + invalid password
Control B: malformed LDAP syntax + invalid password
Control C: true-condition candidate + invalid password
```

All three controls should remain unauthenticated.

If Control C creates a session, redirect to a protected test-only page, or
changes an authentication flag, stop immediately after preserving minimal
evidence and notify the engagement lead.

Do not navigate to customer data, administrative features, or other users'
profiles.

## Blind True/False Checks

Blind LDAP injection exists when the response does not show directory records
but differs based on whether an injected condition is true.

Use a pair of conditions that you can justify as true and false in the
approved test directory.

For example, compare a known-present object class with a deliberately absent
fictional value:

```text
True candidate:  objectClass=person
False candidate: objectClass=never-defined-example-value
```

Embed these only after you understand the application’s filter template.

Observe a single stable indicator:

```text
indicator = status + redirect + response_length + session_state
```

Do not perform character-by-character extraction.

Do not infer usernames, group names, attribute values, or directory schema
through repeated blind queries.

The goal is to establish that application input changes LDAP boolean logic.

A safe test sequence is:

1. Send the baseline unknown literal.
2. Send the structurally equivalent false-condition candidate.
3. Send the structurally equivalent true-condition candidate.
4. Repeat each once at a low rate to rule out transient behavior.
5. Compare only the approved indicator fields.

Example analysis pseudocode:

```python
def fingerprint(response):
    return (
        response.status_code,
        response.headers.get("Location"),
        len(response.content),
        "session" in response.headers.get("Set-Cookie", "").lower(),
    )
```

If true and false fingerprints differ consistently, preserve redacted
evidence and stop.

If they do not differ, record the test as inconclusive rather than safe.

## Detection / Defender View

Defenders should treat LDAP query construction as a data-boundary problem.

The primary control is parameterized or value-bound filter construction using
the directory library's safest supported API.

If a library requires a string filter, escape each untrusted assertion value
per RFC 4515 immediately before composing the filter.

Do not use generic HTML, SQL, shell, JSON, or URL encoding as an LDAP
escaping substitute.

Validate expected format before escaping.

For a username, allow a narrow expected character set and length where product
requirements permit it.

For email, validate an email-shaped value but still apply LDAP filter escaping.

Use allowlists for selectable attributes and directory bases.

Never let a client provide a raw filter, raw base DN, or arbitrary attribute
list.

Use least-privilege service binds for account lookup.

The lookup identity should have access only to the attributes and subtree
needed for the application function.

Do not grant the application service account directory write permission unless
the feature explicitly needs it.

Prefer direct user binds for password verification after an exact account DN
lookup.

Require exactly one matching account before attempting authentication.

Reject zero results and multiple results with the same generic login response.

Do not compare submitted passwords through directory searches.

Do not log passwords, raw authorization headers, or full unredacted filters.

Log structured metadata instead:

```json
{
  "event": "ldap_search",
  "request_id": "approved-correlation-id",
  "filter_template": "person_by_uid",
  "input_length": 12,
  "escape_applied": true,
  "result_count_bucket": "one",
  "outcome": "success"
}
```

Alert on repeated parse failures, escaped-metacharacter rejections, sudden
search-result expansion, and anomalous authentication-state transitions.

Correlate application request IDs with directory server audit logs.

Rate-limit unauthenticated search and login endpoints.

Use uniform error messages for unknown users, invalid passwords, malformed
inputs, and backend errors where feasible.

Uniform messaging alone is not a security control.

It reduces oracle quality while parameterization and least privilege address
the root cause.

## Engagement Cheatsheet

Use this checklist during an authorized engagement.

```text
[ ] Confirm scope, rate limits, and stop conditions.
[ ] Identify LDAP-backed inputs and authenticate flows.
[ ] Capture normal valid/invalid/empty baselines.
[ ] Send individual metacharacter probes.
[ ] Compare stable response indicators.
[ ] Model the target filter before boolean-logic testing.
[ ] Use one true/false pair with fictional values.
[ ] Avoid enumeration and blind data extraction.
[ ] Stop once structural control or auth impact is proven.
[ ] Capture only minimal, redacted evidence.
[ ] Recommend parameterized filters and RFC 4515 escaping.
[ ] Recommend least-privilege binds and exact-result checks.
[ ] Retest the fix and record the outcome.
```

Factors that reduce impact include:

- strict value binding
- narrow attribute and base allowlists
- least-privilege service account
- no meaningful response oracle
- strong authorization after authentication
- test-only or isolated directory data

Do not label a finding critical solely because an LDAP error is visible.

Base severity on demonstrated, scoped impact and realistic exploitability.

## Key References

- CWE-90, Improper Neutralization of Special Elements used in an LDAP Query:
  <https://cwe.mitre.org/data/definitions/90.html>
- OWASP LDAP Injection Prevention Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
- RFC 4515, Lightweight Directory Access Protocol (LDAP): String Representation
  of Search Filters:
  <https://www.rfc-editor.org/rfc/rfc4515>
- RFC 4514, LDAP: String Representation of Distinguished Names:
  <https://www.rfc-editor.org/rfc/rfc4514>

Use RFC 4515 for filter-value escaping.

Use RFC 4514 and your LDAP library documentation for DN construction.

Keep the assessment focused on authorized proof, minimal impact, and useful
remediation evidence.
