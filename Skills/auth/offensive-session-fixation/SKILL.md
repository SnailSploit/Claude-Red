---
name: offensive-session-fixation
description: "Use this skill during an authorized security assessment to evaluate whether an application accepts or preserves attacker-influenced session identifiers across authentication or privilege changes. It guides safe, minimally invasive validation of pre-authentication session reuse, URL-based session tokens, weak cookie attributes, and login-CSRF-assisted fixation. Keep testing within written scope, use only test accounts and controlled browsers, record evidence without collecting unnecessary sensitive data, and stop if an observation could affect another user. This skill focuses on session lifecycle behavior rather than general CSRF or XSS testing; use the dedicated offensive-csrf and offensive-xss skills for those topics."
---
# Session Fixation
Session fixation happens when a known pre-authentication session identifier
survives login and becomes associated with an authenticated account.
You test this only during a written, authorized assessment.
You use dedicated test accounts and isolated browser profiles.
You never induce real users to authenticate.
You never retain live session values outside approved evidence storage.
You use only `example.com` and `192.0.2.0/24` in examples.
This issue maps to CWE-384: Session Fixation.
It differs from session hijacking.
Hijacking steals an existing authenticated identifier.
Fixation establishes or knows an identifier before authentication.
TLS alone does not prevent fixation.
Token entropy alone does not prevent fixation.
The server must replace the authoritative identifier at authentication.
The server should invalidate the prior identifier where applicable.
The server should rotate identifiers after meaningful privilege changes.
This skill does not replace a general authentication assessment.
It does not duplicate offensive-csrf.
It does not duplicate offensive-xss.
Use offensive-csrf for complete CSRF coverage.
Use offensive-xss for complete script-injection coverage.
Use this skill to assess session lifecycle behavior.
## Quick Workflow
1. Confirm target scope, test accounts, and approved flows.
2. Start a clean controlled browser context.
3. Start a separate clean victim-test browser context.
4. Capture the anonymous session identifier in the controlled context.
5. Map the normal login response and redirect sequence.
6. Determine the authoritative authenticated session identifier.
7. Present the permitted anonymous identifier to the victim-test context.
8. Log in only with the dedicated victim-test account.
9. Compare session identifiers before and after login.
10. Verify that the old known identifier cannot authorize a harmless request.
11. Repeat for MFA or role elevation if that flow is in scope.
12. Review URL handling and cookie flags.
13. Capture redacted evidence.
14. Log out and invalidate test sessions.
You stop after obtaining the minimum evidence necessary.
You do not brute-force identifiers.
You do not test another user's account.
You do not use phishing or social engineering.
## Framing
An application may create an anonymous session for legitimate reasons.
Examples include cart state, UI preferences, and CSRF coordination.
An anonymous session is not automatically a vulnerability.
The risk starts when login binds identity to the same identifier.
The risk is stronger when an attacker can choose that identifier.
The risk is stronger when a separate browser can replay it.
Treat authentication as a privilege boundary.
Treat MFA completion as a privilege boundary.
Treat role elevation as a privilege boundary.
Treat account recovery completion as a privilege boundary.
Treat password changes as a session-management event.
Ask which login routes exist before testing.
Include local login when in scope.
Include account registration when in scope.
Include passwordless login when in scope.
Include SSO callbacks when in scope.
Include MFA completion when in scope.
Include password-reset completion when in scope.
Include role-switching only when explicitly approved.
Map each route to the session values it creates and replaces.
Do not assume a cookie named `session` is authoritative.
An application may use multiple cookies.
Some cookies only provide load-balancer affinity.
Some cookies only store preferences.
Some cookies coordinate CSRF defenses.
Some cookies actually authorize the account.
You identify the cookie or token that authorizes a benign authenticated request.
You avoid treating harmless cookies as evidence of fixation.
### Preconditions
Obtain explicit written authorization.
Use a representative non-production environment when available.
Use an account created for the engagement.
Use a second test account only when necessary.
Start with empty target-site storage.
Use browser profiles without target-related extensions.
Use an interception proxy only when permitted.
Protect proxy logs as sensitive assessment data.
Redact tokens in notes, screenshots, and reports.
Verify the resolved target is in scope.
Use `https://example.com` in documentation examples.
Use `https://192.0.2.10` only as an address-literal example.
Never copy a production token into documentation.
### Secure Expected Behavior
The session identifier changes after successful login.
The pre-authentication identifier is no longer authoritative.
The old identifier cannot access authenticated resources.
The identifier changes again after a meaningful privilege increase.
Active session identifiers never appear in URLs.
Session cookies carry appropriate security attributes.
The application rejects untrusted cross-site login requests where applicable.
## Technique: Baseline Lifecycle Mapping
Observe normal behavior before attempting controlled reuse.
Open a clean browser context.
Visit the authorized login page.
For documentation, use `https://example.com/login`.
List cookies created before login.
Record cookie names.
Record domains and paths.
Record expiration attributes.
Record `Secure` status.
Record `HttpOnly` status.
Record `SameSite` status.
Record whether the response sets an anonymous identifier.
Record whether a session value appears in a redirect.
Record whether a session value appears in HTML.
Record whether a session value appears in a form field.
Record whether a session value appears in a URL.
Do not record complete token values.
Use `abc123…redacted` in evidence.
Log in through the ordinary approved flow.
List cookies after login.
Compare names before and after login.
Compare redacted values before and after login.
Record cookies that disappear.
Record cookies that appear.
Record cookies that change.
Observe the full redirect chain.
Repeat after logout.
Repeat after a browser restart when persistence matters.
Example healthy flow:
```text
GET /login       -> Set-Cookie: ANON=redacted
POST /login      -> Set-Cookie: AUTH=redacted; ANON=deleted
GET /account     -> requires AUTH
POST /logout     -> AUTH=deleted
```
Cookie names do not prove security by themselves.
You verify which value the server accepts for authenticated access.
### Baseline Questions
Does the landing page create a server-recognized session?
Does the login response set a new identifier?
Does a new cookie replace an old cookie?
Does the old cookie remain accepted after login?
Does rotation occur only after a redirect?
Does MFA completion cause another rotation?
Does logout invalidate the session server-side?
Does password change revoke prior sessions?
Does SSO callback reuse an anonymous session?
Does URL rewriting carry session state?
Does proxy infrastructure add an authorization-relevant cookie?
## Technique: Pre-Authentication Identifier Reuse
Use two isolated browser contexts.
Call them the controlled context and victim-test context.
Create an anonymous session in the controlled context.
Record the identifier securely and redact it in notes.
Determine whether the application normally accepts that identifier elsewhere.
Use only application-supported channels.
Do not alter server state.
Do not bypass authentication.
Do not use a session belonging to someone else.
Present the permitted anonymous identifier to the victim-test context.
Authenticate the dedicated victim-test account.
Observe whether the identifier changes.
Observe whether a new authoritative token appears.
Make one harmless permitted request from the controlled context.
Use a low-risk self-profile or account-status endpoint when authorized.
Stop after the proof point.
Do not browse sensitive account data unnecessarily.
Expected secure result:
```text
Anonymous before login:  session=redacted-A
Victim before login:     session=redacted-A
Victim after login:      session=redacted-B
Controlled result:       unauthenticated
```
Confirmed fixation result:
```text
Anonymous before login:  session=redacted-A
Victim before login:     session=redacted-A
Victim after login:      session=redacted-A
Controlled result:       authenticated test-account response
```
The cookie name is not material.
The lifecycle behavior is material.
### Interpret the Result Carefully
If the identifier changes, save redacted rotation evidence.
If the identifier does not change, check for a replacement credential.
If a new authentication cookie appears, test whether the old one alone works.
If two values are required, document their combined requirement.
If device binding is present, document it as a compensating control.
If the browser rejects a supplied cookie, record the client-side limitation.
Do not describe a browser cookie-rule limitation as a server-side defense.
If a redirect rotates the cookie, inspect the complete chain.
If an affinity cookie changes, distinguish it from application authorization.
## Technique: Session Identifiers in URLs
Active session identifiers must never appear in a URL.
URLs can reach browser history.
URLs can reach server logs.
URLs can reach proxy logs.
URLs can reach analytics services.
URLs can leak through copied links.
URLs can leak through bookmarks.
URLs can leak through referrer headers.
URL parameters can also help establish a chosen pre-authentication identifier.
Documentation-only examples:
```text
https://example.com/account?sid=redacted
https://example.com/(S(redacted))/account
https://192.0.2.10/login?session=redacted
```
Inspect normal navigation first.
Inspect login GET requests.
Inspect login POST redirects.
Inspect SSO initiation URLs.
Inspect SSO callback URLs.
Inspect registration confirmation URLs.
Inspect password-reset completion URLs.
Inspect MFA challenge URLs.
Inspect logout redirect URLs.
Inspect error-page links.
Use dedicated test mailboxes for email-link flows.
Do not send live tokens to third parties.
Test whether a URL-provided value becomes a pre-authentication session.
Then test whether login rotates the value.
Record canonicalization and removal behavior.
### URL Review Notes
Fragments are not normally sent to servers.
Fragments may still leak through client-side code or copied links.
Query parameters are commonly logged.
Path-based URL rewriting has similar leakage risks.
Referrer policy can reduce some leakage.
Referrer policy does not make URL session identifiers appropriate.
The remediation is to remove active session IDs from URLs entirely.
## Technique: Cookie Flags and Scope
Cookie flags are defense in depth.
Cookie flags do not replace session rotation.
Review every authentication-relevant cookie.
Review `Secure`.
Review `HttpOnly`.
Review `SameSite`.
Review `Domain`.
Review `Path`.
Review `Expires`.
Review `Max-Age`.
Review supported cookie prefixes.
Example:
```http
Set-Cookie: __Host-session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax
```
`Secure` limits normal transmission to HTTPS.
`Secure` does not prevent a known identifier from surviving login.
`HttpOnly` limits JavaScript access.
`HttpOnly` does not rotate a session.
`SameSite` reduces selected cross-site request contexts.
`SameSite` does not replace login-CSRF protections.
`SameSite=Lax` is a common browser-session baseline.
`SameSite=Strict` can disrupt valid identity-provider flows.
`SameSite=None` requires `Secure`.
Broad domain scope increases exposure across subdomains.
Broad path scope can expose a cookie more widely than necessary.
The `__Host-` prefix requires `Secure`, `Path=/`, and no `Domain`.
Use host-only cookies when cross-subdomain sharing is not required.
Keep anonymous state short-lived when practical.
Rotate the identifier regardless of expiration time.
## Technique: Login CSRF-Assisted Fixation
Login CSRF and session fixation are related but distinct.
Login CSRF can make a victim authenticate into an unintended account.
Fixation can preserve a known identifier across authentication.
Together they can create a stronger chain.
Use offensive-csrf for complete CSRF testing.
This skill assesses session rotation in the login flow.
Use only dedicated test accounts.
Do not induce a real user to log in.
Do not send phishing content.
Determine whether the login endpoint has request-specific CSRF defenses.
Determine whether it validates origin or referer where appropriate.
Determine whether successful login rotates the session.
Document each observation separately.
Do not merge them into a single finding without a reproducible authorized chain.
Controlled sequence:
```text
1. Create an anonymous session in Browser A.
2. Present the permitted value to Browser B.
3. Authenticate a dedicated test account in Browser B.
4. Compare the pre-login and post-login identifiers.
5. Confirm Browser A cannot use the old value.
```
Missing login-CSRF protection is not proof of fixation.
Missing rotation is not proof of cross-site login inducement.
Report the evidence you actually observe.
### Scope Boundaries
Do not test XSS within this skill.
Use offensive-xss for XSS-specific discovery.
XSS may expose sessions but has a different root cause.
Do not test every state-changing endpoint here.
Use offensive-csrf for endpoint-wide CSRF coverage.
Do not brute-force token entropy.
Do not access real accounts.
Do not exceed the approved application paths.
## Technique: Privilege-Change Rotation
Login is not the only important rotation event.
Review approved privilege-changing events.
MFA completion may increase assurance.
Role elevation may increase privileges.
Account recovery may restore account control.
Password changes may invalidate prior trust assumptions.
Linking a stronger identity provider may increase assurance.
Use the same before-and-after comparison.
Start from a clean test session.
Capture the redacted pre-transition identifier.
Complete the approved transition normally.
Observe new cookies and deleted cookies.
Observe server-side invalidation if testable.
Verify that the old identifier cannot use elevated privileges.
Use only a harmless proof endpoint.
Do not perform unnecessary administrative actions.
Example:
```text
Transition: password verified -> MFA completed
Before:     session=redacted-A
After:      session=redacted-B
Old value:  denied on /account
New value:  allowed on /account
```
## Evidence Collection
Collect the minimum evidence set.
Record the environment label.
Record the test date and time.
Record the approved authentication flow.
Record request methods and paths.
Record status codes.
Record redacted relevant request headers.
Record redacted `Set-Cookie` response headers.
Record redacted redirect locations.
Record before-and-after comparisons.
Record controlled-context verification when permitted.
Record browser-profile isolation.
Record MFA or SSO involvement.
Avoid full authorization headers in ordinary reports.
Avoid screenshots containing unrelated personal data.
Delete retained session values after the engagement policy allows.
Example evidence:
```http
POST /login HTTP/1.1
Host: example.com
Cookie: session=abc123…redacted
HTTP/1.1 302 Found
Set-Cookie: session=def456…redacted; Path=/; Secure; HttpOnly; SameSite=Lax
Location: /account
```
This shows rotation.
It does not alone prove old-session invalidation.
Add the controlled-context result if authorized.
## Detection / Defender View
Defenders log session lifecycle events.
Defenders avoid logging raw session identifiers.
Use a keyed hash or privacy-preserving fingerprint for correlation.
Record anonymous session creation.
Record authenticated session creation.
Record session rotation.
Record session invalidation.
Record logout.
Record MFA completion.
Record role changes.
Alert when anonymous state becomes authenticated without rotation.
Alert when one identifier appears across unexpected client contexts.
Alert when a session identifier arrives through a URL.
Alert when a successful authentication response lacks expected rotation.
Test every login path in integration tests.
Include local login.
Include SSO callback completion.
Include registration.
Include account recovery.
Include MFA completion.
Use a regression test that establishes an anonymous session first.
Then authenticate a test account.
Then assert the authoritative identifier changes.
Then assert the old identifier cannot access authenticated endpoints.
Defenders rotate the session ID on privilege changes.
Defenders set `Secure` on HTTPS session cookies.
Defenders set `HttpOnly` where scripts do not require access.
Defenders use an appropriate `SameSite` setting.
Defenders never put active session IDs in URLs.
Defenders limit cookie scope.
Defenders invalidate the prior server-side session.
Defenders review custom SSO and middleware paths.
Framework defaults may not cover custom callbacks.
### Defender Regression Example
```python
def test_login_rotates_anonymous_session(client, test_user):
    client.get("https://example.com/login")
    anonymous_id = client.cookies.get("session")
    response = client.post(
        "https://example.com/login",
        data={"username": test_user.name, "password": test_user.password},
    )
    authenticated_id = client.cookies.get("session")
    assert response.status_code in {200, 302}
    assert authenticated_id
    assert authenticated_id != anonymous_id
```
Adapt the assertion to the actual session architecture.
For separate anonymous and auth cookies, test authorization directly.
For stateless credentials, ensure anonymous values never authorize an account.
For SSO, assert rotation after callback processing.
## Engagement Cheatsheet
Confirm written authorization.
Confirm approved target and environment.
Confirm dedicated test accounts.
Start isolated controlled and victim-test browsers.
Create an anonymous session.
Map the ordinary login flow.
Identify authoritative session state.
Present only a permitted pre-authentication identifier.
Authenticate the dedicated account.
Compare identifiers before and after login.
Test one harmless request with the old known value.
Repeat for MFA if in scope.
Repeat for SSO if in scope.
Review URLs for active identifiers.
Review `Secure`.
Review `HttpOnly`.
Review `SameSite`.
Review `Domain` and `Path`.
Review related login-CSRF controls.
Use offensive-csrf for the wider CSRF assessment.
Use offensive-xss for the wider XSS assessment.
Redact evidence.
End and invalidate test sessions.
Report observed conditions and limits.
### Quick Triage Questions
Can you establish a session before login?
Can the application accept the known value normally?
Does the value rotate after login?
Does another credential take over authorization?
Can the old value make a permitted authenticated request?
Does MFA rotate the identifier?
Does role elevation rotate the identifier?
Does any active identifier appear in a URL?
Are session cookies `Secure`?
Are session cookies `HttpOnly`?
Is `SameSite` appropriate for the flow?
Are there compensating client bindings?
Can you prove impact without exceeding scope?
### Minimal Report Template
```markdown
## Finding: Session identifier is not rotated after authentication
**CWE:** CWE-384 (Session Fixation)
**Affected flow:** [authorized test flow]
**Observed behavior:** A pre-authentication session identifier remained unchanged
after a dedicated test account authenticated.
**Impact:** [state only validated impact]
**Evidence:** Redacted requests and responses show the same identifier before
and after authentication. [Add permitted controlled-context result.]
**Recommendation:** Generate and bind a fresh identifier at login, invalidate
the previous anonymous session, rotate after privilege changes, use `Secure`,
`HttpOnly`, and appropriate `SameSite` settings, and never put active session
IDs in URLs.
```
## Key References
- CWE-384: Session Fixation  
  https://cwe.mitre.org/data/definitions/384.html
- OWASP Session Management Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
Use the CSRF reference for login-request protections.
Use the Session Management reference for lifecycle guidance.
Revalidate behavior after framework upgrades.
Revalidate behavior after SSO changes.
Revalidate behavior after custom middleware changes.
End the assessment by removing test artifacts under engagement policy.
