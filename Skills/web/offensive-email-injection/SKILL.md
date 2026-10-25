---
name: offensive-email-injection
description: "Use this skill only during an explicitly authorized security assessment to evaluate SMTP and email-header injection in contact forms, account workflows, API endpoints, and mail integrations. It covers safely identifying untrusted values that reach To, Cc, Bcc, Subject, Reply-To, and other message headers; validating newline handling without sending mail to real recipients; documenting impact; and recommending durable fixes. Keep all testing scoped to systems and domains you are authorized to assess, use example.com and 192.0.2.0/24 in examples, and prefer sink mailboxes or local capture services. This skill addresses email header injection under CWE-93, not HTTP response splitting."
---
# Email Header Injection
## Framing
Use this skill for an authorized assessment of email-generation paths.
Confirm the written scope before entering any payload.
Record the target application, assessment window, and authorized test accounts.
Do not test production recipients unless the authorization explicitly permits them.
Use an approved mail sink whenever one is available.
Use only `example.com` and `192.0.2.0/24` in examples and test data.
Treat outbound mail as potentially persistent and externally visible.
Avoid credentials, customer data, and real addresses in test messages.
Keep proof-of-concept messages identifiable and harmless.
Prefer a single controlled recipient to broad distribution.
Stop if the test could create an uncontrolled delivery path.
This issue occurs when untrusted input is concatenated into an email header.
The dangerous characters are carriage return and line feed.
In protocol notation, these are `\r` and `\n`.
A newline can terminate one header and begin another.
An attacker may then add `Bcc`, `Cc`, `Reply-To`, or other headers.
The result can be spam relay, recipient disclosure, phishing support, or message tampering.
This is email header injection and maps to CWE-93.
CWE-93 covers improper neutralization of CRLF sequences in headers.
Do not classify this as CWE-77.
CWE-77 concerns command injection and is not the right primary mapping here.
Do not confuse this issue with HTTP response splitting.
The separate `offensive-crlf-injection` skill covers HTTP response splitting.
Use that skill for HTTP response headers and bodies.
Use this skill for SMTP and application-generated email headers.
Avoid duplicating HTTP response-splitting procedures in this document.
An application may be vulnerable before it reaches an SMTP server.
Mail transfer agents can reject malformed messages after application code accepts them.
That rejection does not prove the application is safe.
The relevant question is whether user-controlled newlines reach message construction.
Assess the full path from request field to mail library call.
Include templates, helpers, queue workers, and notification services.
Focus on fields that conceptually become headers.
Typical examples include recipient, subject, sender display name, and reply-to.
Contact forms are common because they often concatenate values into a raw message.
Password-reset workflows can be affected by recipient construction.
Support-ticket integrations can be affected by subject construction.
Bulk mail and CRM integrations can expose secondary header paths.
Webhook-to-email bridges often deserve special attention.
Legacy PHP mail wrappers are a recurring risk area.
Raw SMTP clients and custom MIME builders also need review.
Use a mail library that accepts structured recipients where possible.
Structured APIs reduce the need to build RFC 5322 header strings manually.
They do not remove the need to validate untrusted values.
An assessment seeks evidence, not unnecessary message delivery.
Demonstrate parsing behavior with a harmless sentinel header when permitted.
Do not add headers that impersonate real organizations.
Do not alter authentication-related headers in a way that could trigger abuse controls.
Do not send marketing, promotional, or deceptive content.
Use local capture when validating the final rendered message.
Capture the raw message source, not just the UI rendering.
Preserve timestamps and request identifiers in evidence.
Redact sensitive values before sharing findings.
State clearly whether mail was captured, queued, rejected, or delivered.
Distinguish application acceptance from successful transport.
Document any egress control that limits practical impact.
Do not assume rate limiting prevents exploitation.
Do not assume an allowlist prevents exploitation without testing newline handling.
## Quick Workflow
1. Confirm scope, authorization, and the approved mail-capture endpoint.
2. Inventory every field that can influence an email header.
3. Trace each field to the message construction API or raw SMTP builder.
4. Establish baseline behavior with ordinary, syntactically valid input.
5. Test whether carriage return or line feed is rejected before mail construction.
6. Use a harmless controlled marker to check whether a new header is parsed.
7. Inspect the raw captured message and relevant application logs.
8. Verify whether validation is consistent across UI, API, and background jobs.
9. Assess exploitability, blast radius, and mitigations.
10. Report the issue with a minimal safe reproduction and a code-level fix.
Start with passive code review when source access is available.
Search for string concatenation around message headers.
Search for raw uses of `mail`, `sendmail`, SMTP commands, and MIME builders.
Search for helpers that accept a recipient as a single string.
Search for template variables used in subject or sender configuration.
Review validation at every trust boundary.
Do not rely on frontend validation as a security control.
Exercise server-side endpoints directly when authorized.
Use the smallest payload that distinguishes safe rejection from unsafe parsing.
Prefer a sentinel header such as `X-Assessment-Token`.
Use an opaque token that identifies the test run.
Do not use a production secret as the token.
Choose a unique token for each endpoint and field.
Keep a test ledger containing request, response, timestamp, and capture ID.
If the request is rejected, record the status and normalized error message.
If it is accepted, inspect the generated message before escalating testing.
If mail capture is unavailable, test only the validation boundary.
State that transport-level confirmation was not obtained.
Do not substitute public email providers for a controlled mail sink.
Do not test recipient injection against third-party mailboxes.
If the application has a staging environment, use it first.
Treat staging as in scope only when the engagement says it is.
Verify that a staging sink cannot forward to live recipients.
Confirm whether queues retain failed messages for later retry.
Prevent delayed delivery by disabling or isolating the test queue if authorized.
Coordinate with operations before testing a high-volume notification path.
Keep testing serialized when a sink has limited observability.
Use one variable at a time.
First test `\r`.
Then test `\n`.
Then test the CRLF sequence.
Compare server responses and captured output.
Some frameworks normalize one newline but not the other.
Some libraries reject recipient fields but allow subject fields.
Some validation occurs only after a message is queued.
Some alternate endpoints bypass the primary validator.
Assess equivalent mobile, API, and administrative flows.
Check CSV imports and integrations that create email notifications.
Check support workflows that convert user text into a message subject.
Check localization templates that compose a subject from request values.
Check error-notification systems that include request metadata in headers.
Check password-reset aliases and invite workflows.
Check user-configurable notification routing.
Check reply-to and display-name customization.
Check contact form “email” and “name” fields separately.
Check subject fields separately from recipient fields.
Check any field documented as free text but used in a mail header.
## Assessment Preconditions
Obtain explicit authorization for the application and environment.
Obtain a testing window if the service has operational sensitivity.
Identify a security contact for unexpected mail behavior.
Identify the mail sink hostname, port, and retention period.
Verify that the sink is isolated from external SMTP delivery.
Use a dedicated test account where authentication is required.
Confirm that the test account cannot access another customer’s data.
Confirm whether test mail may appear in monitoring or ticket systems.
Notify the monitoring team if the engagement requires it.
Define a stop condition before the first payload.
Example stop condition: any evidence of external delivery.
Example stop condition: application errors affecting unrelated mail.
Example stop condition: queue growth beyond the agreed threshold.
Maintain a list of endpoints and their observed mail behavior.
Record the framework and mail library when known.
Record whether delivery is synchronous or queued.
Record whether an external email service is used.
Record whether DKIM or relay policies modify the message.
These controls can affect observability but do not fix unsafe construction.
Confirm whether audit logs include the raw header values.
Avoid placing raw malicious-looking strings into systems with broad retention.
Use the minimum marker needed to prove parsing.
Never use a test that causes an email loop.
Never use automatic responders as a validation channel.
Never use a real vendor, client, or employee mailbox as a target.
## Finding Candidate Inputs
Start with fields named `email`, `recipient`, `to`, `contact`, or `reply_to`.
Then inspect `subject`, `name`, `from_name`, and `sender`.
Review JSON API properties as well as HTML form names.
Review GraphQL mutations that create tickets or messages.
Review multipart form submissions.
Review URL-encoded request bodies.
Review import files when they feed notification workflows.
Review query parameters only when they can reach email generation.
Review user profile fields used in notification headers.
Review organization-level email configuration fields.
Review webhook payload fields that populate alerts.
Review issue titles that become notification subjects.
Review chat-to-email bridges.
Review calendar or invitation title fields.
Review exception handlers that include user data in alert subjects.
Review system integrations that add a reply-to address.
Identify the exact code point that creates the message.
Look for `setHeader`, `addHeader`, `Subject`, and recipient methods.
Look for interpolated strings passed to raw message APIs.
Look for explicit `\r\n` sequences in application code.
Raw CRLF is normal in a serializer but risky near untrusted interpolation.
Determine whether the library escapes, rejects, or preserves newlines.
Read library documentation rather than assuming behavior.
Verify the actual version in the deployment when possible.
Look for wrapper functions that bypass library validation.
Look for configuration toggles enabling raw message mode.
Look for fallback code used after a mail-library error.
Look for multiple language runtimes in the notification pipeline.
Treat template engines as part of the data flow.
Subject templates are headers even if they look like content templates.
Treat display names as header components.
Treat reply-to values as header components.
Treat message IDs as sensitive if they derive from user input.
Avoid spending time on body-only fields unless they cross into a header.
## Safe Validation Probes
Use a benign baseline first.
For example, submit a normal subject such as `Assessment baseline`.
Observe the status code, user-visible response, and captured raw message.
Then submit a newline-only validation probe if the environment safely captures mail.
Represent escape sequences accurately for the client you use.
Do not assume JSON `\n` reaches the server as a literal backslash and n.
Use an intercepting proxy or reproducible client request to control encoding.
Use a unique, harmless marker in any expected header.
Example marker: `X-Assessment-Token: assess-2026-001`.
Use test recipient addresses under `example.com`.
Example recipient: `qa-recipient@example.com`.
Do not include real routing domains in examples or testing instructions.
Example conceptual subject value:
```text
Assessment baseline\r\nX-Assessment-Token: assess-2026-001
```
Use this only against an authorized endpoint with a controlled mail sink.
The expected secure result is rejection or safe normalization before mail construction.
The expected vulnerable result is a separate parsed `X-Assessment-Token` header.
Do not use `Bcc` as the first probe when a harmless marker can prove the issue.
Escalate to controlled recipient injection only if authorization requires impact validation.
When approved, keep the injected recipient within `example.com`.
Use one injected recipient only.
Do not send body content beyond a clear assessment notice.
Example conceptual recipient value:
```text
owner@example.com\r\nBcc: controlled-observer@example.com
```
Never paste this value into an unapproved live endpoint.
Verify the raw MIME source in the controlled sink.
Do not rely solely on mailbox recipient displays.
Some mail UIs hide Bcc or normalize malformed headers.
Record whether the mail library rejects the request before queueing.
Record whether the application returns success despite a later transport failure.
Capture validation error text without exposing implementation internals unnecessarily.
Test each candidate header field independently.
Do not combine multiple injection headers in one first-pass probe.
Keep the proof narrowly scoped to the claimed weakness.
## Recipient Header Technique
Assess recipient fields only where the application owns recipient selection.
Establish the normal recipient format accepted by the endpoint.
Determine whether the endpoint accepts a display name and address.
Determine whether it accepts a comma-separated recipient list.
Determine whether it supports Unicode or internationalized addresses.
These behaviors influence parsing but do not justify raw-header construction.
Submit a normal controlled address first.
Confirm the sink receives exactly one message to the intended address.
Submit an authorized newline marker probe next.
Inspect the raw headers for an extra line.
If the application rejects input, capture the rejection evidence.
If it accepts the input but strips newlines, record the normalized value.
If it creates an extra header, stop and preserve evidence.
Do not expand recipient count to demonstrate severity.
Explain that a Bcc header could be injected if the parser accepts arbitrary header lines.
Demonstrate Bcc only with the engagement owner’s explicit approval.
Use `controlled-observer@example.com` for any approved injected recipient.
Verify whether the original recipient remains present.
Verify whether the injected header is visible in the raw message.
Verify whether a message is actually delivered only to the controlled sink.
If the mail library blocks the header, identify whether application validation still needs improvement.
A downstream block can be defense in depth, not a complete fix.
Document the parser or relay behavior separately from application behavior.
## Subject Header Technique
Treat user-controlled subjects as a first-class test surface.
Contact forms frequently map subject text into the `Subject` header.
Ticket titles can become subjects in confirmation and escalation mail.
Account names may be interpolated into subjects.
Start with a benign subject containing normal punctuation.
Then use a controlled CRLF marker probe.
Inspect the raw message for a new header line.
Example conceptual subject probe:
```text
Question about service\r\nX-Assessment-Token: subject-2026-001
```
The secure application rejects CR, LF, and CRLF in the subject input.
It may also normalize other control characters according to its policy.
A vulnerable application passes the marker as a distinct header.
Do not use a misleading subject designed to influence real recipients.
Do not create multipart content or forged authentication headers.
Document whether the issue occurs before or after subject templating.
Test direct API input and the browser UI independently when both exist.
An API-only weakness remains exploitable if external clients can access it.
Check alternate locales if templates use different mail builders.
Check asynchronous notification jobs that generate a subject later.
## Contact Form Technique
Map every contact-form field to its eventual email role.
The sender email may become `Reply-To`.
The sender name may become a display-name component.
The category may become a subject prefix.
The message body should remain a body value.
Do not assume a “message” field is safe without tracing it.
Legacy implementations sometimes build all headers in one string.
Review server-side code for patterns like this:
```php
$headers = "From: " . $name . " <" . $email . ">\r\n";
$headers .= "Reply-To: " . $email . "\r\n";
mail($to, $subject, $message, $headers);
```
This pattern is unsafe when `$name` or `$email` can contain CR or LF.
The risk remains even when client-side email validation exists.
Assess the server endpoint directly with authorized test input.
Use an inert marker header rather than an external recipient.
Trace whether sanitation occurs before every header component.
Check whether validation is bypassed in an alternate JSON endpoint.
Check whether support forms submit to a third-party automation service.
Check whether the service returns a generic success message despite mail failure.
Check whether retries can duplicate an injected message.
Do not trigger repeated submissions unnecessarily.
## Raw SMTP and Custom MIME Builders
Custom SMTP code has a higher risk of protocol-boundary mistakes.
Review each SMTP command construction site.
Recipient injection can occur before MIME construction through envelope commands.
Header injection occurs in the RFC 5322 message data.
Keep these layers distinct in notes and findings.
The SMTP envelope and message headers are related but not identical.
Validate recipient addresses structurally before issuing envelope commands.
Construct message headers using a trusted library serializer.
Do not concatenate user input into `DATA` content as raw header syntax.
Do not accept a prebuilt header block from callers.
Do not provide a “custom headers” feature to untrusted users.
If custom headers are required, use an allowlist of fixed names and safe values.
Log rejected control characters without logging sensitive full payloads.
Review continuation-line behavior as part of parser handling.
Do not rely on header folding to sanitize a newline.
Folding is a protocol feature, not an input-validation substitute.
## Code Review Patterns
Flag direct string concatenation used to build headers.
Flag interpolation in raw header templates.
Flag helper functions that return a newline-delimited header string.
Flag raw `sendmail` command arguments derived from user input.
Flag APIs that accept a single free-form recipient string.
Flag manual MIME boundary and header construction near request values.
Flag generic sanitizers that remove only `\n` but leave `\r`.
Flag sanitizers that operate after values have already been concatenated.
Flag validators used in UI code but absent from backend code.
Flag catch blocks that fall back to a raw mail API.
Flag different mail paths for synchronous and asynchronous delivery.
Flag tests that mock the mail client without inspecting message fields.
Prefer a design where the mail library receives typed values.
Prefer a recipient list of address objects over a comma-separated string.
Prefer a fixed sender address configured outside user input.
Prefer a fixed reply-to unless customization is essential.
Use explicit subject construction with rejected control characters.
## Detection / Defender View
Reject carriage return and line feed in every user-controlled header field.
Apply this rule before templating, queueing, logging, and serialization.
Reject both `\r` and `\n`, not only the CRLF pair.
Do not silently remove control characters when rejection is feasible.
Silent removal can create confusing audit trails and unexpected semantics.
Return a clear validation error to the caller.
Use a mail library that accepts structured recipients.
Do not concatenate raw headers.
Do not assemble a newline-delimited header block from untrusted strings.
Use separate API parameters for recipient, subject, reply-to, and content.
Validate each parameter according to its expected grammar.
Use a well-maintained library’s address parser rather than a homemade regex alone.
Apply application-level allowlists for sender and reply-to policy.
Keep sender addresses server-controlled whenever possible.
Restrict outbound recipients when the business workflow allows it.
Route non-production mail to a sink by environment configuration.
Prevent test and staging environments from forwarding to external SMTP.
Log validation failures with a correlation ID.
Avoid recording raw attacker-controlled text in broadly accessible logs.
Alert on rejected CR or LF in header-bound fields.
Track anomalous validation failures by endpoint and source identity.
Inspect mail queues for unexpected recipient counts.
Inspect raw message samples in a controlled retention process.
Monitor changes to mail-sending code and mail-library versions.
Add regression tests for CR, LF, and CRLF in every header-bound field.
Test UI, API, job, and integration paths.
Test both synchronous and queued delivery implementations.
Ensure error handling cannot fall back to unsafe construction.
Review role-based controls around custom notification templates.
Review data imports that can populate recipient or subject fields.
Use code scanning rules for raw header concatenation.
Treat downstream SMTP rejection as telemetry, not prevention.
Defend at the first boundary where untrusted input enters header semantics.
## Secure Implementation Examples
Use a library-specific structured message API.
The following conceptual TypeScript example rejects header control characters.
```typescript
const rejectHeaderControls = (value: string, field: string): string => {
  if (/[\r\n]/u.test(value)) {
    throw new Error(`${field} must not contain carriage return or line feed`);
  }
  return value;
};
const subject = rejectHeaderControls(input.subject, "subject");
const replyTo = rejectHeaderControls(input.replyTo, "replyTo");
await mailer.send({
  to: [{ address: "support@example.com" }],
  subject,
  replyTo: [{ address: replyTo }],
  text: input.message,
});
```
Keep the sender address outside request-controlled input.
Validate addresses with the mail library or a dedicated address parser.
Do not substitute a regex for protocol-aware parsing when the library already validates.
The following PHP pattern avoids a raw user-built header string conceptually.
```php
if (preg_match('/[\r\n]/', $input['subject'])) {
    throw new InvalidArgumentException('Invalid subject');
}
$message = new EmailMessage();
$message->setTo(['support@example.com']);
$message->setSubject($input['subject']);
$message->setTextBody($input['message']);
$mailer->send($message);
```
Adapt the concrete API to the selected mail library.
The important property is structured header construction and pre-validation.
Do not paste raw headers into a library method that accepts an unparsed string.
## Verification After a Fix
Add regression tests before declaring remediation complete.
Test a normal value for each header-bound field.
Test carriage return alone for each field.
Test line feed alone for each field.
Test the CRLF sequence for each field.
Test UI and direct API routes.
Test queued and synchronous notification paths.
Assert that invalid input receives a validation failure.
Assert that no message is queued for invalid input.
Assert that no raw captured message contains the sentinel header.
Assert that logs provide a safe correlation record.
Retest on the deployed version, not only the development branch.
Confirm configuration does not select a legacy mail path in production.
Confirm staging and development sinks remain isolated.
Document the exact fixed version and test date.
## Reporting Guidance
Title the finding precisely.
Example title: `Email header injection through contact-form subject`.
State the affected endpoint and field.
State the authentication and authorization prerequisites.
State whether the issue was verified in a controlled mail sink.
State whether arbitrary headers could be added.
State whether controlled recipient injection was approved and verified.
Do not overstate impact if downstream controls blocked delivery.
Do not understate impact when application code accepted a new parsed header.
Describe the root cause as unsafe header construction with untrusted input.
Map the weakness to CWE-93.
Reference OWASP Testing for IMAP SMTP Injection.
Explain that CWE-77 is not the appropriate primary classification.
Include a minimal harmless reproduction.
Use a sentinel `X-Assessment-Token` in the report proof.
Redact application cookies, tokens, and internal hostnames.
Describe the expected secure behavior.
Recommend rejecting CR and LF before constructing mail fields.
Recommend a structured mail library API.
Recommend avoiding concatenation of raw headers.
Include a regression-test recommendation.
State any compensating controls separately from the primary fix.
## Engagement Cheatsheet
**Scope check:** Is the endpoint authorized and is a mail sink available?
**Primary classification:** CWE-93, email header injection.
**Not the primary classification:** CWE-77, command injection.
**Related but distinct topic:** HTTP response splitting in `offensive-crlf-injection`.
**First targets:** To, Cc, Bcc, Subject, Reply-To, sender name, contact forms.
**Safest proof:** An injected harmless `X-Assessment-Token` header.
**Recipient safety:** Use only `example.com` addresses.
**Network safety:** Use only `192.0.2.0/24` in IP examples.
**Baseline:** Submit ordinary input and capture the raw message.
**Probe order:** CR, LF, then CRLF.
**Evidence:** Request, response, raw message source, queue state, timestamp.
**Stop condition:** Any external delivery or unexpected queue behavior.
**Secure behavior:** Reject control characters before mail construction.
**Preferred API:** Structured recipients and separate subject/reply-to parameters.
**Unsafe pattern:** Concatenated newline-delimited raw headers.
**Retest:** Verify UI, API, jobs, and integrations after remediation.
## Key References
- CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting').
- Use CWE-93 for header-injection taxonomy in this assessment context.
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection').
- CWE-77 is not the right primary classification for email header injection.
- OWASP Web Security Testing Guide: Testing for IMAP SMTP Injection.
- RFC 5322: Internet Message Format.
- RFC 5321: Simple Mail Transfer Protocol.
- Your organization’s authorized-testing rules and email-delivery change controls.
