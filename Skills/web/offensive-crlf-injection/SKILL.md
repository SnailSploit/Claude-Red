---
name: offensive-crlf-injection
description: "Use this skill during authorized security assessments to identify, validate, and document CRLF injection and HTTP response-splitting weaknesses. It provides a disciplined workflow for testing header injection, response splitting, log injection, and encoded newline bypasses without affecting real users or production data. You scope every test to explicitly approved systems, use harmless markers and non-routable documentation addresses, preserve evidence, and stop when behavior is ambiguous. The skill distinguishes CRLF injection from request smuggling and cache poisoning, which require separate assessment methods. It also translates findings into practical remediation advice: reject carriage return and line feed characters in header values, encode logs safely, and never reflect raw request data into response headers."
---

# CRLF Injection

CRLF injection occurs when an application accepts attacker-controlled carriage return
(`\r`) and line feed (`\n`) characters in a context interpreted as an HTTP header,
log record, or other line-oriented protocol.

In HTTP, the byte sequence `\r\n` terminates a header line.

If untrusted input reaches a response header without strict validation, you can
attempt to add a header, terminate the response headers, or influence downstream
components that parse the resulting response.

This skill is for explicitly authorized testing only.

You obtain written scope before testing.

You use harmless markers, avoid persistent state changes, and do not target systems
outside the approved engagement.

Use `example.com` for illustrative hostnames.

Use addresses in `192.0.2.0/24` for illustrative IP-based examples.

Do not substitute real third-party services, production domains, or public resolver
addresses in examples or test notes.

CRLF injection is not synonymous with HTTP request smuggling.

Request smuggling concerns ambiguity between front-end and back-end request framing.

Assess request smuggling with its dedicated skill rather than duplicating that
methodology here.

CRLF injection is also not cache poisoning.

Cache poisoning concerns attacker-controlled cacheable representations and cache-key
behavior.

Assess cache poisoning with its dedicated skill rather than treating a CRLF symptom
as proof of cache impact.

A successful newline reflection does not automatically establish response splitting.

You validate the exact parsing boundary, the affected response, and whether the
server, framework, proxy, or client rejects or normalizes the input.

You do not claim impact based only on URL-encoded characters appearing in an error
page or access log.

Treat observed behavior as a hypothesis until you reproduce it with controlled,
minimal requests and independent evidence.

## Quick Workflow

1. Confirm written authorization, target scope, test window, and rate limits.

2. Map inputs that may influence response headers or line-oriented logs.

3. Establish a clean baseline response for each input.

4. Use a unique harmless marker for every test case.

5. Test literal and encoded CRLF representations incrementally.

6. Observe raw response headers, status line behavior, redirects, and logs when
   access is authorized.

7. Determine whether the application rejects, decodes, normalizes, strips, or
   reflects the candidate newline sequence.

8. Validate any apparent header injection with a single benign header name and
   marker value.

9. Stop before attempting content injection unless the rules of engagement
   explicitly permit response-splitting validation.

10. Record the full request, raw response, component path, and observed impact.

11. Test fixed behavior after remediation using the same harmless markers.

12. Report the root cause and the exact encoding/canonicalization mismatch.

Start with the smallest possible request.

Change one variable at a time.

Do not combine newline payloads with unrelated attack techniques.

Keep each test attributable to one hypothesis.

Use a marker that is unique to the request and easy to search.

For example, `crlf-skill-marker-001` is safer and clearer than a generic value.

Record timestamps in UTC if the engagement requires correlation with server logs.

Prefer a capture tool that preserves raw response bytes and headers.

Browser developer tools may normalize or hide malformed headers.

Command-line clients may also reject malformed responses differently from browsers.

Use more than one client only when it is allowed and materially helps interpretation.

## Baseline Capture

Capture a normal response before you test a candidate newline sequence.

Record status code, response version, headers, body length, and redirect behavior.

Record which client generated the request.

Record whether the target is reached through a proxy or test gateway.

Use a non-sensitive baseline value that exercises the suspected code path.

For a redirect, a baseline might be `/account`.

For a download filename, a baseline might be `report.txt`.

For a diagnostic header, a baseline might be `test-client`.

The following command is illustrative only.

```bash
curl --http1.1 --include --silent --show-error \
  'https://example.com/redirect?next=%2Faccount'
```

You inspect the complete response before creating a CRLF test.

You save raw headers where the engagement evidence process permits it.

You verify that any observed `Location` header is generated by the target rather
than by your client following redirects.

Disable automatic redirect following during baseline collection.

```bash
curl --http1.1 --include --max-redirs 0 --silent --show-error \
  'https://example.com/redirect?next=%2Faccount'
```

You use `--max-redirs 0` to preserve the initial response.

You do not include credentials unless the authorized test case requires them.

## Header Injection Validation

Header injection exists when untrusted input can introduce or alter a response
header field.

You begin with a benign, unique header name and value.

Use a marker that cannot be confused with a real control or security header.

For example, `X-Assessment-Marker: crlf-skill-marker-002` is appropriate for a
controlled validation.

You test one likely header-construction sink at a time.

You compare the baseline response with the candidate response byte for byte when
possible.

An illustrative encoded candidate looks like this:

```text
%0D%0AX-Assessment-Marker%3A%20crlf-skill-marker-002
```

You append it only to an input confirmed or suspected to reach a response header.

You do not test arbitrary URL parameters merely to generate malformed traffic.

An illustrative request is:

```bash
curl --http1.1 --include --max-redirs 0 --silent --show-error \
  'https://example.com/redirect?next=%2Faccount%0D%0AX-Assessment-Marker%3A%20crlf-skill-marker-002'
```

You treat a `400`, `403`, or validation error as an expected defensive result.

You distinguish rejection by a WAF from rejection by the application.

You record the response component when response headers reveal it.

If the marker appears only URL-encoded in an HTML error body, header injection is
not demonstrated.

If the marker appears as a new response header in a raw capture, you have evidence
of a header injection condition.

You then repeat the request once to establish reproducibility.

You do not repeat it excessively.

You test an alternate harmless marker to rule out response caching artifacts.

You test whether the application accepts the same value through another encoding
only when that encoding follows a documented decode path.

You avoid test headers named `Set-Cookie`, `Location`, `Content-Length`, or
security-policy headers unless the rules of engagement explicitly authorize the
impact demonstration.

## Redirect and Location Header Cases

Redirect handlers are a common CRLF sink because they turn an input into a
`Location` value.

You confirm that the application controls the redirect rather than a reverse proxy.

You test local, valid redirect values before testing malformed candidates.

You keep the requested path within `example.com` in examples.

```bash
curl --http1.1 --include --max-redirs 0 --silent --show-error \
  'https://example.com/continue?return_to=%2Fdashboard'
```

You then test whether a decoded CRLF reaches the `Location` construction.

```bash
curl --http1.1 --include --max-redirs 0 --silent --show-error \
  'https://example.com/continue?return_to=%2Fdashboard%0D%0AX-Assessment-Marker%3A%20crlf-skill-marker-003'
```

You check the raw `Location` value and the presence of the marker header.

You do not follow a redirect generated by a malformed response automatically.

You note whether the framework converts the candidate to a safe encoded value.

Safe re-encoding is not equivalent to acceptance.

It may be a valid mitigation if no later decode restores the control characters.

You validate the final emitted bytes before concluding that the issue is fixed.

## Response Splitting Validation

Response splitting is a higher-impact form of CRLF injection.

It may occur when an attacker-controlled CRLF sequence terminates the header
section and begins a separate or attacker-influenced response segment.

Modern servers and frameworks often prevent this.

You do not assume response splitting from successful single-header injection.

You only validate response splitting if the rules of engagement explicitly permit
it and the test environment is isolated or otherwise approved.

You use a harmless body marker.

You do not inject scripts, redirects, cookies, or cache-control directives.

You do not create a payload intended to affect another user.

A conceptual HTTP/1.1 layout is:

```http
HTTP/1.1 302 Found
Location: /dashboard
X-Assessment-Marker: crlf-skill-marker-005

assessment-body-marker
```

The layout above explains the parsing boundary.

It is not a recommendation to deploy or replay an exploit payload.

You validate whether the server emits an unexpected second header block, altered
content length, or an attacker-controlled body segment.

You distinguish a malformed response rejected by your client from a response
actually split by the origin.

You capture traffic at the closest authorized observation point.

You test once with HTTP/1.1 if the target supports it.

You document protocol negotiation and intermediary behavior.

You do not transpose an HTTP/1.1 result onto HTTP/2 or HTTP/3 without direct
validation.

You stop immediately if the behavior could affect shared clients or cached content.

Potential cache interactions belong in the cache poisoning assessment, not this
skill.

Potential desynchronization interactions belong in the request smuggling
assessment, not this skill.

## Encoded Newline Bypasses

Encoded newline testing examines whether different components canonicalize input
inconsistently.

You begin with standard percent encoding.

```text
%0D%0A
```

You test individual characters separately when useful.

```text
%0D
%0A
```

You test lowercase percent escapes only if the input parser is expected to accept
them.

```text
%0d%0a
```

You test double encoding only where a documented or observed multi-stage decoding
path exists.

```text
%250D%250A
```

You do not treat double encoding as a universal bypass.

You identify each decode stage before interpreting the result.

You test plus signs as spaces only in form-style query decoding contexts.

You do not confuse `%0A` with the literal characters percent, zero, and A after
the value has been encoded for display.

You check whether the application validates before decoding.

You check whether an upstream proxy decodes before the application validates.

You check whether a framework decodes a route or query parameter automatically.

You check whether a downstream header library rejects actual control characters.

You record the exact representation observed at every accessible stage.

An illustrative table in plain text:

```text
Representation      Intended observation
%0D%0A              Standard URL decoding path
%0d%0a              Case-insensitive percent decoding path
%250D%250A          Two-stage decoding path
\r\n                Language-string parsing path only
\u000d\u000a        JSON parsing path only
```

Do not send literal raw CRLF characters in a request target through tools that may
serialize or normalize them unexpectedly.

Use an approved interception proxy or purpose-built test harness when literal-byte
testing is necessary.

You document the tool behavior as part of the evidence.

## Log Injection

Log injection occurs when an attacker-controlled newline makes one log event appear
as multiple records or changes the apparent meaning of a record.

It can mislead analysts, hide activity, or corrupt ingestion pipelines.

Log injection does not require an HTTP response header sink.

You identify logs that record request paths, query strings, headers, user IDs,
user-agent values, forwarding headers, and error messages.

You coordinate with the log owner before testing production-like systems.

You use a unique inert marker.

You avoid strings that resemble genuine alerts, credentials, or administrative
activity.

An illustrative request target is:

```text
/search?q=crlf-skill-marker-007%0Alog-record-marker
```

You verify the raw ingress value when authorized.

You verify the application log output when authorized.

You verify any downstream structured-log or SIEM representation when authorized.

You distinguish a visual line wrap from a real record boundary.

You inspect raw log events or event IDs, not only a dashboard display.

You check whether a logging library serializes values as structured JSON.

Structured JSON logging reduces some risks but still requires correct escaping.

You check whether values are embedded as raw text inside JSON or another format.

You check whether log shippers, parsers, and dashboards preserve escape sequences.

You record the affected field and the exact parser behavior.

## Detection / Defender View

You reject CR and LF characters in all response header values.

You apply this validation after decoding and normalization.

You use framework APIs that reject invalid header values.

You do not build raw HTTP header lines with string concatenation.

You do not reflect raw request data into response headers.

You allowlist expected formats for redirect targets, filenames, locales, and custom
metadata.

You validate redirect destinations as URLs or application-relative paths, not merely
as strings without CRLF.

You validate filenames against a narrow character set and a length limit.

You use standard library content-disposition builders where available.

You ensure every proxy and gateway rejects invalid response headers consistently.

You audit any code that translates HTTP/2 or HTTP/3 traffic to HTTP/1.1.

You configure error handlers not to place raw request values in response headers.

You encode logs using structured logging.

You ensure logs preserve attacker-controlled strings as escaped values within one
event.

You do not interpolate raw request data into line-oriented logs.

You protect log viewers from interpreting newline-containing fields as independent
records.

You add detections for escaped and decoded CRLF patterns in suspicious inputs.

You tune detection so normal encoded data does not generate excessive noise.

You correlate rejected requests with endpoint and source information.

You monitor for validation errors involving header setting APIs.

You test headers at integration boundaries, not just unit-test helper functions.

You test redirect, download, and proxy behavior under the deployed server stack.

You maintain regression tests for encoded, lowercase-encoded, and double-encoded
values where multi-stage decoding is supported.

You do not rely on a WAF as the primary mitigation.

A WAF can be a compensating control but cannot correct unsafe header construction.

You ensure application validation protects every deployment path.

## Evidence Collection

Your evidence includes the authorized target identifier.

Your evidence includes the date and time of the test.

Your evidence includes the tool and protocol version used.

Your evidence includes the exact encoded input and a harmless marker.

Your evidence includes the baseline response.

Your evidence includes the candidate response.

Your evidence includes a raw capture when permitted.

Your evidence includes the observed effect and confidence level.

Your evidence includes the affected component when known.

Your evidence includes the rollback or cleanup status.

You redact session identifiers, credentials, customer information, and private
infrastructure details before broader distribution.

You store sensitive raw captures only in the approved evidence repository.

You do not include exploit-ready payloads in an executive summary.

You use minimal reproduction steps in the technical appendix.

## Reporting Guidance

State the vulnerable input and response or log sink.

State the representation that bypasses validation.

State the decode or canonicalization sequence when known.

State whether the result is header injection, response splitting, log injection, or
only suspicious reflection.

State the client and protocol used to reproduce the behavior.

State the tested scope and whether the issue was reproduced.

State a remediation that removes the unsafe boundary behavior.

Do not recommend blacklisting only `%0D%0A`.

Recommend rejecting actual CR and LF after decoding and validating the expected
format of the value.

For logs, recommend escaping control characters and preserving event structure.

For response headers, recommend framework-managed setters and defense in depth.

## Engagement Cheatsheet

| Goal | Safe action | Evidence to collect |
| --- | --- | --- |
| Identify candidate sinks | Map header and log-bound inputs | Endpoint and input matrix |
| Establish normal behavior | Capture a clean baseline | Raw status and headers |
| Test encoded newline handling | Use one inert marker | Request and raw response |
| Confirm header injection | Observe a new benign header | Reproduction capture |
| Assess response splitting | Proceed only with explicit approval | Parsing evidence and scope notes |
| Assess log injection | Review event boundaries with log owner | Raw log event and renderer view |
| Verify remediation | Repeat baseline and candidate tests | Fixed response and regression test |

Use this minimal sequence for a suspected header sink:

```text
1. Send a valid baseline value.
2. Record status and raw response headers.
3. Send one percent-encoded CRLF plus a benign marker header.
4. Verify whether the marker is a separate response header.
5. Repeat once with a new marker.
6. Stop and document the result.
```

Use this minimal sequence for a suspected log sink:

```text
1. Send a baseline marker.
2. Confirm one log event exists.
3. Send an encoded newline plus a second inert marker.
4. Inspect raw event boundaries.
5. Confirm whether rendering merely wraps text or creates a new record.
6. Stop and document the result.
```

Keep scope notes with every test.

```text
Target: example.com
Test environment: authorized staging
Source address example: 192.0.2.10
Assessment marker prefix: crlf-skill-marker
Prohibited impact: user-facing redirects, cookies, cache manipulation, content injection
```

## Key References

- CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection').

- CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP
  Request/Response Splitting').

- OWASP: HTTP Response Splitting guidance and related injection-prevention
  recommendations.

- OWASP Web Security Testing Guide: input validation, HTTP testing, and logging
  considerations.

- RFC 9110: HTTP Semantics.

- RFC 9112: HTTP/1.1 message syntax and routing.

Use the current CWE entries and OWASP guidance when drafting a formal report.

Prefer the normative protocol RFCs when explaining actual header and message syntax.

Keep this skill focused on CRLF injection.

Use the dedicated request smuggling skill for message-framing ambiguity.

Use the dedicated cache poisoning skill for cache-key and cacheable-response impact.

Document only the behavior you directly observe in the authorized environment.
