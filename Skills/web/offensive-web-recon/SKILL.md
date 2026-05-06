---
name: offensive-web-recon
description: "Web application reconnaissance methodology — content discovery (ffuf, feroxbuster, dirsearch, gobuster), JavaScript bundle analysis for endpoints / API keys / hidden routes, technology fingerprinting (Wappalyzer CLI, whatweb, httpx tech-detect), virtual host enumeration, hidden parameter discovery (Arjun, ParamSpider, x8), API spec discovery (OpenAPI / Swagger / GraphQL introspection), historical content via Wayback Machine, robots.txt / sitemap.xml / .well-known mining, and structured target inventory before active testing. Use at the start of any web app engagement to map the attack surface before probing for bugs."
---

# Web Application Reconnaissance

The biggest source of wasted time on a web pentest is testing the wrong thing — the small public site when the real attack surface is on a subdomain, a JS-bundled internal API, or an old retired version that still works. Recon up front pays back across the whole engagement.

## Quick Workflow

1. Subdomain + virtual host enumeration
2. Content discovery on each in-scope host (paths, files, parameters)
3. JS bundle analysis for endpoints + secrets
4. Technology stack fingerprinting (versions = CVE leads)
5. API spec / introspection mining
6. Build a target inventory: each (host, path, method, params)

---

## Subdomain & Vhost Enumeration

```bash
# Subdomain discovery
subfinder -d target.com -all -recursive -o subs.txt
amass enum -d target.com -active
# Combine, dedupe
cat subs.txt | sort -u > all_subs.txt

# Resolve, identify alive
httpx -l all_subs.txt -title -tech-detect -status-code -o alive.txt

# Virtual host enumeration on a known IP
ffuf -w wordlists/vhosts.txt:HOST -u https://target.com -H "Host: HOST.target.com" -fs <baseline-size>
```

## Content Discovery

```bash
# Recursive dir/file brute on multiple wordlists
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -x php,asp,aspx,jsp,html,bak,old,zip,tar.gz \
  --depth 4 --extract-links

# ffuf with multiple inputs
ffuf -u https://target.com/FUZZ -w wordlists/raft-large-words.txt \
  -mc 200,204,301,302,307,401,403,500 -fs 0 -t 50

# Per-language wordlists yield more
gobuster dir -u https://target.com -w wordlists/Java-Directories.txt \
  -x jsp,do,action -t 30
```

## JavaScript Bundle Analysis

Modern apps embed routes, API endpoints, and sometimes secrets in client-side JS:

```bash
# Pull all JS files
hakrawler -url https://target.com -depth 3 -plain | \
  grep -E "\.js(\?|$)" | sort -u > js_urls.txt

# Mine endpoints with LinkFinder
for url in $(cat js_urls.txt); do
  linkfinder -i "$url" -o cli >> endpoints.txt
done

# Or with subjs + LinkFinder pipeline
subjs -i js_urls.txt | sort -u | xargs -I{} python3 LinkFinder.py -i {} -o cli

# Look for secrets
trufflehog filesystem ./js_dump
gitleaks detect --source ./js_dump --no-git
```

## Technology Fingerprinting

```bash
# Multiple tools, cross-reference
whatweb https://target.com
wappalyzer https://target.com
httpx -l alive.txt -tech-detect -title -server -status-code

# Server-version-specific CVE feed
nuclei -l alive.txt -t cves/ -severity high,critical
```

Version → CVE mapping lives in:
- nuclei templates (templates/cves/)
- CVE Search / cvedb
- vendor advisories

## Hidden Parameter Discovery

```bash
# Arjun — most accurate for real-world apps
arjun -u "https://target.com/api/user" -m GET -t 20

# ParamSpider — pulls from Wayback Machine
paramspider -d target.com -o params.txt

# x8 — newer, faster
x8 -u https://target.com/api/user -w wordlists/parameters.txt
```

Parameters that exist but aren't documented are often the most interesting — debug flags, internal-only switches, dev-mode bypasses.

## API Spec Discovery

```bash
# Common spec paths
for path in /openapi.json /swagger.json /api-docs /v3/api-docs \
            /swagger-ui.html /api/swagger /graphql ; do
  curl -sI "https://target.com$path" | head -1
done

# GraphQL introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

## Historical Content (Wayback)

```bash
# All historical URLs for the domain
waybackurls target.com | tee wayback.txt

# Filter for interesting parameters / endpoints
gf interestingparams < wayback.txt
gf urls-with-passwords < wayback.txt
gf juicyparams < wayback.txt

# Diff old vs new — endpoints removed but maybe still active
comm -13 <(cat current.txt | sort) <(cat wayback.txt | sort) > retired_paths.txt
```

## .well-known + Hints

```bash
# Standard files to inspect
for path in robots.txt sitemap.xml humans.txt security.txt \
            .well-known/security.txt .well-known/openid-configuration \
            .well-known/oauth-authorization-server \
            .well-known/apple-app-site-association \
            .well-known/assetlinks.json ; do
  echo "=== $path ==="
  curl -s "https://target.com/$path" | head
done
```

These reveal:
- Disallowed paths (`robots.txt`) — admin, internal, test
- Auth providers and OIDC config
- Mobile-app deep links (universal links / app links)
- Disclosed contact email for the program

## Cloud Asset Discovery

```bash
# S3 bucket enumeration
s3scanner scan --domain target.com
cloud_enum -k target

# Azure storage
azurefinder -d target

# GCP
gcp_bucket_brute --keyword target
```

Storage buckets named after the company are often public-readable and contain backups, build artifacts, env files.

## Engagement Cheatsheet

```bash
# 1. Subdomains + alive
subfinder -d target.com -all -recursive | httpx -title -tech-detect -o alive.txt

# 2. Content discovery on top targets
feroxbuster -u https://app.target.com --depth 3 -x php,asp,jsp,bak

# 3. JS bundle mining
hakrawler -url https://app.target.com -depth 3 | grep '\.js' | \
  xargs -I{} curl -s {} | grep -oE '"[/a-zA-Z0-9_-]+(\?[^"]*)?"' | sort -u

# 4. Hidden params
arjun -u "https://app.target.com/api/path" -m GET

# 5. Spec / introspection
curl https://app.target.com/openapi.json
curl -X POST https://app.target.com/graphql -d '{"query":"{__schema{types{name}}}"}'

# 6. Historical
waybackurls target.com | gf interestingparams

# 7. Cloud assets
s3scanner scan --domain target.com
```

---

## Key References

- ProjectDiscovery toolchain: subfinder, httpx, nuclei, ffuf-style scanning
- SecLists: github.com/danielmiessler/SecLists
- LinkFinder: github.com/GerbenJavado/LinkFinder
- Arjun: github.com/s0md3v/Arjun
- "Recon for Bug Bounty Hunters" (NahamSec, jhaddix)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/web-recon.md
