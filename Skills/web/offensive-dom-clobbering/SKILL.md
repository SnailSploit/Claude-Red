---
name: offensive-dom-clobbering
description: "Use this skill during authorized web application assessments to identify and validate DOM clobbering risks: named HTML elements that shadow JavaScript globals or document properties, form and id/name collisions, and attacker-controlled markup that reaches script gadgets or DOM XSS sinks. You map named-property behavior, trace data from markup injection to JavaScript consumption, demonstrate minimal approved impact, and document practical remediation. Keep testing within written authorization, use harmless proof values, avoid persistence or third-party impact, and coordinate before testing production or authenticated workflows. This skill complements, rather than replaces, offensive-xss and offensive-prototype-pollution guidance."
---
# DOM Clobbering
DOM clobbering is a browser behavior in which named HTML elements become properties on browser objects.
You assess whether attacker-controlled markup can create a property that application JavaScript treats as trusted state.
The usual browser objects are `window`, `document`, forms, and element collections.
Use this skill only within explicit written authorization.
Use `example.com` for every illustrative origin and URL.
Use a harmless marker such as `clobber-proof` in every test.
Do not use persistence, credential access, external callbacks, or unrelated user data as proof.
## Framing
DOM clobbering is not inherently a vulnerability.
It becomes a vulnerability when untrusted markup influences a named property read by script.
The usual chain is:
```text
attacker-controlled markup
  -> named browser property or collection member
  -> application JavaScript read
  -> unsafe assumption or gadget
  -> bounded, authorized impact
```
Keep each link in that chain separate in notes and reports.
First, establish that the application accepts or creates attacker-influenced HTML.
Second, establish that the relevant `id` or `name` survives rendering and sanitization.
Third, establish actual named-property behavior in the tested browser.
Fourth, establish an application read of the exact property path.
Fifth, establish a security-relevant result, not merely an interesting console value.
Named access may arise from `id`, `name`, forms, controls, frames, and collections.
Exact behavior varies with browser, element type, document mode, and property precedence.
Verify every claim in the target browser and target rendering path.
Do not assume a proof transfers between browsers.
### Relationship to DOM XSS
DOM clobbering can create attacker-controlled values.
DOM XSS is unsafe execution or interpretation that may occur when that value reaches a dangerous sink.
For sink identification, context-specific validation, and execution rules, use `offensive-xss`.
Do not duplicate the `offensive-xss` payload catalog in this skill.
DOM clobbering can also produce object-shape confusion.
Prototype pollution instead changes inherited properties or merge behavior.
For inherited-property manipulation, use `offensive-prototype-pollution`.
Do not label a named-element collision as prototype pollution.
### Scope and safety
Confirm authorized hosts, routes, accounts, and data-handling rules before testing.
Use a disposable account when a test could disrupt normal application state.
Do not submit secrets, personal data, or customer content as test markup.
Do not navigate privileged workflows merely to prove a property is controlled.
Prefer same-page evidence such as a controlled label, type, or inert URL string.
Stop if stored content appears likely to affect other users outside the agreed scope.
Record browser version, account role, URL, rendering path, and sanitization state.
## Quick Workflow
1. Find each path where attacker-influenced HTML reaches the document.
2. Inspect the final DOM after rendering, not only the server response.
3. Inventory reads from `window`, `document`, forms, and collections.
4. Identify fallback code using `||`, `??`, truthiness checks, or late initialization.
5. Test one harmless `id` or `name` collision at a time.
6. Compare value, type, and ownership before and after the collision.
7. Trace the changed value to the first application-controlled use.
8. Determine whether the use is benign, security-relevant, or a DOM XSS gadget.
9. Demonstrate the smallest permitted impact.
10. Preserve DOM snapshots, source locations, and browser evidence.
11. Retest proposed sanitizer and code-level mitigations.
### Locate the render path
Locate the route or component that renders user-controlled content.
Determine whether it renders server-side, via `innerHTML`, through a framework escape hatch, or in a widget.
Record whether the content exists before target JavaScript executes.
Timing matters because named properties must exist when code reads them.
Use developer tools to inspect the final DOM.
Start with a unique identifier that cannot affect application behavior.
```html
<a id="assessmentMarker">clobber-proof</a>
```
Inspect named access in the document context.
```js
({
  windowValue: window.assessmentMarker,
  documentValue: document.assessmentMarker,
  windowType: typeof window.assessmentMarker,
  documentType: typeof document.assessmentMarker,
})
```
This observation does not establish an application vulnerability by itself.
Search for code that reads the same name or derives a name dynamically.
### Inventory suspicious reads
Search source, formatted bundles, and authorized source maps for direct reads.
```js
window.appConfig
```
```js
document.appConfig
```
```js
document.forms.settings
```
```js
document.forms.namedItem("settings")
```
Prioritize fallback initialization patterns.
```js
const config = window.appConfig || {};
```
A truthy named element can satisfy this fallback.
Inspect optional chaining because it can hide unexpected element types.
```js
const next = window.appConfig?.redirect;
```
Inspect destructuring from ambient globals.
```js
const { appConfig } = window;
```
Inspect guarded initialization.
```js
if (!window.appConfig) window.appConfig = { redirect: "/home" };
```
A named element can prevent a safe default from being created.
### Build a hypothesis
Capture the expected type, trusted producer, read timing, and downstream use.
```text
Name: appConfig
Expected type: plain object
Trusted producer: bootstrap script
Read timing: after content render
Candidate collision: id="appConfig"
Potential use: navigation configuration
```
Reject candidates where trusted code creates an own property before untrusted markup exists.
Reject candidates when browser behavior does not expose the relevant node.
Prioritize candidates with late reads, weak type checks, and visible downstream use.
## Technique: Named `id` globals
Many browsers expose elements with an `id` as named values on `window`.
Begin with a unique name and inspect the returned class.
```html
<div id="assessmentMarker">clobber-proof</div>
```
```js
console.log(window.assessmentMarker);
console.log(window.assessmentMarker instanceof HTMLElement);
```
Only test an application name after identifying a corresponding application read.
```html
<div id="appConfig">clobber-proof</div>
```
Compare ownership as well as the value.
```js
console.log({
  value: window.appConfig,
  constructor: window.appConfig?.constructor?.name,
  own: Object.hasOwn(window, "appConfig"),
});
```
Named access can differ from a trusted own property assigned by script.
Check ownership rather than relying on console display.
An ordinary element may only produce a reliability defect.
Do not report security impact until a meaningful application behavior changes.
### Property-bearing elements
Some elements expose standard fields that resemble configuration.
Relevant examples include `href`, `src`, `value`, `action`, `method`, `name`, and `form`.
Use an inert same-origin example URL during assessment.
```html
<a id="appConfig" href="https://example.com/clobber-proof">proof</a>
```
Observe a field only when it mirrors an application assumption.
```js
const next = window.appConfig?.href;
console.log(next);
```
Do not substitute a handcrafted console read for proof that application code consumes that field.
Trace the target’s own read and use.
Do not assume a collision with a built-in property succeeds.
Properties such as `window.location` often have defined precedence or special behavior.
Focus on application-defined names unless observed code makes a built-in relevant.
## Technique: `name`-based collisions
The `name` attribute can participate in named access for certain elements.
Forms, controls, images, frames, and anchors can expose names through different paths.
Probe a distinct name before testing a candidate collision.
```html
<form name="assessmentForm">
  <input name="marker" value="clobber-proof">
</form>
```
Inspect relevant paths explicitly.
```js
({
  global: window.assessmentForm,
  form: document.forms.assessmentForm,
  control: document.forms.assessmentForm?.elements.marker,
})
```
Do not conflate `id` behavior with `name` behavior.
Sanitizers frequently treat these attributes differently.
When `id` is stripped but `name` survives, prioritize name-based paths.
### Form-based object shapes
Forms can create object-like paths because controls become named members.
```html
<form id="appConfig">
  <input name="redirect" value="https://example.com/clobber-proof">
</form>
```
An application expecting `appConfig.redirect` may instead receive an input element.
```js
const redirectControl = window.appConfig?.redirect;
console.log(redirectControl?.value);
```
This matters only if application code reads a compatible field such as `value`, `href`, or `action`.
Test the exact member resolution in the target browser.
Some forms expose controls directly while others require `elements`.
Avoid names such as `submit`, `reset`, or `action` until you assess workflow disruption.
Use a disposable account if a collision can affect form submission.
### URL-shaped form gadgets
Applications may use configuration fields named `action`, `href`, or `target`.
Use a non-sensitive observation target first.
```html
<form id="navigationConfig" action="https://example.com/clobber-proof">
  <input name="target" value="clobber-proof">
</form>
```
Trace whether application code reads the field and sends it to a navigation or request API.
Follow `offensive-xss` for URL-sink context and validation.
Do not perform a privileged navigation if reading the property establishes control.
## Technique: Duplicate names and collections
Duplicate names or identifiers can produce a collection rather than one element.
That may create a distinct type confusion gadget.
```html
<a id="assetConfig">first</a>
<a id="assetConfig">second</a>
```
Inspect the result before assuming it is indexable or iterable.
```js
console.log(window.assetConfig);
console.log(window.assetConfig?.length);
```
Named access may return an `HTMLCollection` in some observed cases.
Look for application code that uses `.length`, numeric indexing, loops, or `[0]`.
```js
const first = window.assetConfig?.[0];
```
Prove only the property shape needed by the actual gadget.
Do not add duplicate nodes if a single element demonstrates the issue.
### Child-node chains
Research by Gareth Heyes describes cases where nested named elements create object-like chains.
Validate each level in the target rather than copying a chain from an unrelated application.
```html
<form id="appConfig">
  <input name="endpoint" value="https://example.com/clobber-proof">
</form>
```
```js
const endpoint = window.appConfig?.endpoint?.value;
```
Capture each resolved stage.
```text
window.appConfig -> HTMLFormElement
window.appConfig.endpoint -> HTMLInputElement
window.appConfig.endpoint.value -> controlled string
```
This evidence is clearer than a generic payload claim.
## Technique: `document` property clobbering
Some legacy named access behavior exposes elements as properties of `document`.
Test it directly because support is less intuitive than `window` named access.
```html
<img name="assetManifest" alt="clobber-proof">
```
```js
console.log(document.assetManifest);
```
Continue only if application code reads the matching property.
```js
const manifest = document[manifestName];
```
Dynamic property reads raise priority when `manifestName` can be influenced.
Trace the origin of the dynamic name and check for an allowlist.
Avoid clobbering core document methods because that can disrupt the page.
## Technique: Script gadget reconnaissance
A DOM clobbering gadget consumes the named value in a useful application path.
Search for objects initialized from globals or document properties.
```js
const settings = window.settings || {};
```
Search for property reads that reach a DOM API.
```js
target.href = settings.next;
```
Search for implicit coercion.
```js
status.textContent = settings.message;
```
Text assignment usually provides only a safe proof of unexpected value control.
Search for HTML, script, URL, and event sinks with `offensive-xss`.
```js
container.innerHTML = settings.template;
```
The sink above matters only when DOM clobbering controls `settings` or `settings.template`.
Search delayed handlers because they may read state after user markup appears.
```js
button.addEventListener("click", () => open(window.navigationConfig.href));
```
Search hydration and state-restoration logic for repeated ambient reads.
```js
const state = window.pageState ?? document.pageState;
```
### Type assumptions
Developers often assume a named value is a plain object.
Check whether code uses object-only operations.
```js
Object.keys(window.appConfig || {})
```
Check whether code assumes a string.
```js
location.assign(window.appConfig.next)
```
Check whether standard element fields accidentally satisfy the expected schema.
```js
fetch(window.apiConfig.action)
```
Element coercions are leads for tracing, not findings by themselves.
## Technique: Initialization timing
Named access depends on document state when script resolves the property.
Understand whether user content appears before the application reads configuration.
```html
<script>
  console.log(window.appConfig);
</script>
<div id="appConfig">late</div>
```
The order above differs from markup parsed before the script.
Framework hydration may change the order again.
Server-rendered content can exist before bundles execute.
Client-rendered content can arrive after safe defaults are initialized.
Use breakpoints or timestamps to establish actual order.
```js
console.timeStamp("before-config-read");
```
Do not report a theoretical race until you reproduce it reliably.
Do not leave test observers or nodes in shared production pages.
## Technique: Sanitizer differential testing
Sanitizers can stop DOM clobbering by removing or rewriting `id` and `name`.
Build a minimal attribute matrix for the actual content field.
```html
<div id="idProbe" name="nameProbe">clobber-proof</div>
```
Inspect the normalized DOM after it renders.
```js
document.querySelector("[id='idProbe']")
```
```js
document.querySelector("[name='nameProbe']")
```
Record whether the sanitizer removes nodes, strips attributes, prefixes values, or converts markup to text.
Do not treat visible source text as proof that an attribute survived.
Inspect the actual node and attributes.
```js
const node = document.querySelector("#idProbe");
console.log(node?.outerHTML);
```
Test only allowed tags that can reach a candidate gadget.
Avoid broad production fuzzing; use staging where available.
### Prefixing
Some sanitizers prefix user-controlled identifiers.
Prefixing may mitigate collisions with application-owned names.
Verify that every relevant attribute is consistently prefixed after all transformations.
Verify that application code does not remove the prefix later.
```html
<a id="user-content-appConfig">clobber-proof</a>
```
Do not report sanitizer failure merely because arbitrary identifiers are permitted.
The relevant risk is collision with a consumed application name.
## Technique: Framework boundaries
Frameworks usually escape text but applications may opt into raw HTML rendering.
Locate raw HTML APIs, component slots, and markup interpolation escape hatches.
```js
element.innerHTML = trustedMarkup;
```
The variable name `trustedMarkup` is not evidence of a trusted origin.
Trace the origin and sanitization policy.
Shadow DOM can change selector visibility and named-access behavior.
Do not assume a node in a shadow root clobbers the page global.
Test the actual boundary.
```js
const root = host.shadowRoot;
console.log(root?.querySelector("#appConfig"));
```
An iframe is a separate browsing context.
Do not assume an element in one frame clobbers the parent frame.
## Technique: Safe proof construction
Use a proof that changes application behavior without unsafe navigation or execution.
Example application code:
```js
const message = window.bannerConfig?.value || "default";
banner.textContent = message;
```
If approved user markup can create the expected element, use a benign marker.
```html
<input id="bannerConfig" value="clobber-proof">
```
Capture the changed display and the application source location.
This proves substitution of an unexpected element for an assumed configuration value.
For a dangerous downstream sink, transition to `offensive-xss`.
Do not include executable payloads if a benign marker proves the data flow.
## Detection / Defender View
Treat named access as an ambient compatibility feature, never as an application configuration channel.
Do not read `window.someName` or `document.someName` as configuration unless trusted code created and validated it.
Prefer lexical variables, module exports, closures, and explicit DOM queries.
```js
const appConfig = Object.freeze({
  nextPath: "/home",
});
```
Avoid global fallback patterns.
```js
const appConfig = window.appConfig || {};
```
The fallback above can accept a truthy named element.
If a global is unavoidable, define a trusted own property before untrusted markup renders.
```js
Object.defineProperty(window, "appConfig", {
  value: Object.freeze({ nextPath: "/home" }),
  writable: false,
  configurable: false,
});
```
This is targeted hardening, not a substitute for safe HTML handling.
Validate expected types before using any configuration boundary.
```js
function hasSafeConfig(value) {
  return value !== null &&
    Object.getPrototypeOf(value) === Object.prototype &&
    typeof value.nextPath === "string";
}
```
Do not accept `typeof value === "object"` as sufficient validation.
HTML elements are objects.
Do not use truthiness as proof of configuration presence.
### Sanitization controls
Use a strict maintained HTML sanitizer for attacker-controlled markup.
Strip `id` and `name` unless a documented feature requires them.
When identifiers are necessary, prefix them with a namespace that cannot collide with application names.
Apply the same policy to previews and client-side rehydration.
Sanitize before inserting markup into a live document.
Do not delete suspicious nodes after scripts could already have observed them.
Use parser-based sanitization rather than regex replacement.
### Global hardening
Lock down globals that must stay stable.
Avoid mutable application configuration on `window`.
Avoid reading configuration from `document` properties.
Prefer trusted, constant selectors for required application nodes.
```js
const root = document.getElementById("application-root");
```
Scope queries to trusted roots where practical.
```js
const root = document.querySelector("[data-app-root]");
const panel = root?.querySelector("[data-panel='status']");
```
Do not derive selectors or property names from untrusted input.
### Review indicators
Flag direct named-property reads.
```js
window.userOptions
```
Flag document property reads.
```js
document.userOptions
```
Flag fallback initialization from ambient globals.
```js
window.userOptions = window.userOptions || {};
```
Flag form collection reads whose names can be influenced.
```js
document.forms.payment
```
Flag raw HTML rendering near delayed reads of globals or document state.
### Runtime detection
Runtime checks are secondary to removing the trust boundary.
High-risk views can log unexpected element-valued configuration.
```js
if (window.appConfig instanceof HTMLElement) {
  console.warn("Unexpected element-valued appConfig");
}
```
Do not log sensitive values in client-side telemetry.
Content Security Policy can reduce downstream DOM XSS impact.
CSP does not prevent named-property collisions.
Trusted Types can reduce risky HTML and script sink usage.
Trusted Types does not make a clobbered value safe by itself.
## Engagement Cheatsheet
### Triage questions
- Can you introduce HTML into the relevant document?
- Does the final DOM preserve attacker-controlled `id` or `name`?
- Does the browser expose the element through the needed named path?
- Does application code read that exact path after markup exists?
- Does code expect a plain object, URL, string, or collection?
- Can standard element fields satisfy that expectation?
- Does a value reach a meaningful gadget or unsafe sink?
- Can you prove control with a harmless same-page marker?
- Is the behavior reproducible in a supported browser?
### Evidence checklist
- Authorized target, route, and test account role.
- Browser name and version.
- Original rendered DOM and sanitized rendered DOM.
- Exact harmless markup and attribute values.
- Named access result, object type, and ownership result.
- Application source location or formatted bundle excerpt.
- Before-and-after application behavior.
- Minimal downstream impact evidence.
- Mitigation retest or explicit retest procedure.
### Useful console probes
```js
Object.hasOwn(window, "appConfig")
```
```js
window.appConfig?.constructor?.name
```
```js
window.appConfig instanceof HTMLElement
```
```js
document.forms.namedItem("assessmentForm")
```
```js
document.getElementsByName("assessmentMarker")
```
Use probes to observe browser state only.
Do not present probe output as application impact without a matching application code path.
### Reporting language
State the precondition:
```text
An attacker who can submit HTML through the approved content field can create
an element whose identifier is exposed as a named window property.
```
State the unsafe assumption:
```text
Client-side code reads window.appConfig as trusted configuration without
checking that it is an application-created plain object.
```
State only the demonstrated impact:
```text
The injected element changes the URL value consumed by the tested navigation
component to https://example.com/clobber-proof.
```
Do not claim script execution unless `offensive-xss` validation confirms it.
Do not claim cross-user impact unless safe victim rendering is in scope and demonstrated.
### Severity calibration
HTML injection plus a harmless collision but no gadget is an informational or low-confidence lead.
A collision changing only a benign display path is typically low severity.
A collision controlling navigation, request construction, or state decisions can be more serious.
A collision reaching confirmed executable DOM XSS follows the `offensive-xss` severity model.
Account for authentication, author-only content, timing, browser support, and user interaction.
### Remediation acceptance criteria
The content path strips or safely namespaces attacker-controlled `id` and `name`.
Application configuration no longer depends on named `window` or `document` resolution.
Code validates configuration objects and URL values before use.
Regression tests cover the colliding name and render timing.
Tests assert both source behavior and post-sanitization DOM behavior.
## Key References
- CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting).
- Gareth Heyes, PortSwigger Research: DOM clobbering research and browser named-property techniques.
- WHATWG HTML Standard: named access on the `Window` object.
- WHATWG HTML Standard: named properties and collections on `Document`.
Use the current HTML Standard when validating browser semantics.
Browser behavior evolves, so reproduce named access in the supported client environment.
Keep DOM clobbering findings focused on actual application assumptions.
Escalate downstream unsafe HTML or script execution through `offensive-xss`.
Escalate inherited-property manipulation through `offensive-prototype-pollution`.
