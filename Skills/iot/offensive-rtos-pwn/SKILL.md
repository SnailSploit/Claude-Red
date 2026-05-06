---
name: offensive-rtos-pwn
description: "Real-Time Operating System exploitation methodology — FreeRTOS, Zephyr, ThreadX, Mbed OS, ESP-IDF, QNX. Covers single-binary ELF analysis, MMU/MPU bypass when memory protection is misconfigured, stack overflow exploitation in tasks, FreeRTOS task and queue corruption, Zephyr usermode boundaries, MCU peripheral abuse via DMA, supply-chain risks in third-party RTOS components (Amnesia:33 / Ripple20 / Forescout-disclosed bug families), and exploitation differences from full-OS Linux pwn. Use when the target firmware runs on a microcontroller-class device with an embedded RTOS rather than a Linux-class SoC."
---

# RTOS Exploitation

RTOS firmware is a single ELF (or near-equivalent) loaded onto a microcontroller — no MMU on most cheap MCUs, no userspace/kernel separation, often no stack canaries. Once you have a memory corruption primitive, exploit construction is more like 1990s pwning than modern Linux.

## Quick Workflow

1. Identify the RTOS and its version
2. Acquire the firmware binary (see `offensive-flash-dumping`, `offensive-uart-jtag-swd`)
3. Reverse the binary in Ghidra; identify task entry points and IPC
4. Find memory corruption (overflow / format string / OOB)
5. Build exploit; test via JTAG or live network protocol
6. Establish persistence via flash modification

---

## Common RTOS Targets

| RTOS | Common Use | Notes |
|---|---|---|
| FreeRTOS | Cheapest IoT, sensors, Wi-Fi modules | Single binary; cooperative or preemptive scheduling |
| Zephyr | Modern embedded (Nordic, NXP) | Usermode optional; MPU-backed when configured |
| ThreadX (Microsoft Azure RTOS) | Industrial, automotive | Now Microsoft; closed-source for many distros |
| Mbed OS | ARM-vendor IoT | Layered with C/C++; broad community |
| MicroEJ / FreeRTOS+TCP | Japanese consumer | Java + C mix |
| ESP-IDF (FreeRTOS-based) | Espressif chips | Wi-Fi/BLE stacks integrated |
| QNX | Cars, industrial, embedded medical | Microkernel; modern auth in newer versions |
| VxWorks | Industrial, military, aerospace | Many CVEs in older versions (URGENT/11) |

## Identifying the RTOS

```bash
# Strings give the version banner
strings firmware.bin | grep -iE "freertos|zephyr|threadx|mbed|qnx|vxworks"

# FreeRTOS often
strings firmware.bin | grep "FreeRTOS V"
# Zephyr
strings firmware.bin | grep "Zephyr"

# Architectural fingerprints
file firmware.bin    # ELF — architecture (ARM, Xtensa, RISC-V)
```

## Memory Layout Without MMU

Most cheap MCUs (Cortex-M0/M3/M4 without MPU enforcement) treat all memory as one address space:

- Code typically in flash (e.g. 0x08000000 for STM32 family)
- Stack in RAM (e.g. 0x20000000 for STM32)
- Peripherals as memory-mapped registers

Stack overflow → straight RIP control. No NX (or limited via MPU when configured), no ASLR, no stack canaries unless the RTOS adds them.

## FreeRTOS Specifics

### Task Control Blocks (TCB)

Each task has a TCB containing stack pointer, priority, list pointers. TCB lives in the heap (typically `pvPortMalloc`-allocated). A heap overflow into a TCB allows:

- Hijacking the task's stack pointer → RIP control via the next context switch
- Priority manipulation
- Linked-list corruption for arbitrary writes

### Queue / Semaphore Corruption

```c
// FreeRTOS queue is a struct with head/tail pointers
struct QueueDefinition {
    int8_t *pcHead;
    int8_t *pcTail;
    int8_t *pcWriteTo;
    int8_t *pcReadFrom;
    ...
};
```

OOB write past a queue buffer corrupts the next allocation's metadata or its TCB.

### Stack Overflow Detection

FreeRTOS optionally checks task stack with `configCHECK_FOR_STACK_OVERFLOW`. When enabled (rare on cost-sensitive products), overflows cause `vApplicationStackOverflowHook` callback. Bypass: don't overflow the stack canary; use precise structure overwrites.

## Zephyr Specifics

### Usermode (when enabled)

Zephyr 2.0+ supports usermode (CONFIG_USERSPACE=y) with MPU enforcement. Tasks run with restricted memory access, syscall barrier between user and kernel.

Bypass paths:
- Misconfigured MPU regions (overlapping with sensitive memory)
- Vulnerabilities in syscall handlers (input validation gaps)
- Userspace stack overflow → RIP in user task → exploit syscall ABI

### Memory Pools and k_alloc

Zephyr uses memory pools for dynamic allocation. Pool corruption follows similar patterns to FreeRTOS heap.

## Exploit Construction Without ASLR

Without ASLR, all addresses are static across boots. Exploit becomes:

```python
# Stack overflow in network handler
payload  = b'A' * BUFFER_SIZE
payload += p32(0xDEADBEEF)        # saved frame pointer
payload += p32(EXPLOIT_GADGET)    # return address — known fixed in firmware
payload += SHELLCODE              # if executable; or ROP chain if W^X enforced

send_to_target(payload)
```

ROP gadgets in firmware are findable with ROPgadget / ropper:

```bash
ropper --file firmware.elf --search "pop {r4, r5, pc}"
```

## Peripheral DMA Abuse

DMA controllers can write to memory regions the CPU can't (in some setups). A misconfigured DMA descriptor is a write-anywhere primitive:

```
1. Compromise some application code (input validation, etc.)
2. Reconfigure DMA descriptor to write attacker data to flash address
3. Trigger DMA → flash overwrite without going through normal write-protection
```

Specific to platforms where DMA bypasses MPU regions.

## Network-Side Exploitation

Many RTOS devices expose proprietary or LWIP-based TCP/IP. Common bug families:

- Malformed packet parsers (URGENT/11 family in old VxWorks)
- Format strings in debug protocols
- Heap fragmentation via crafted message sequences (Amnesia:33 in proprietary stacks)
- TLS / DTLS implementation flaws

Test:

```bash
# Boofuzz over the device's network ports
pip install boofuzz
# Define field structures based on observed protocol; mutate-fuzz
```

## Persistence

Once you have RCE, persistence is flash-write:

```c
// In the exploit, find the firmware update code and call it with attacker firmware
// Or directly write to flash via the SPI driver
```

Pre-condition: writing to flash from runtime usually requires the bootloader's cooperation (signed updates) — but in many cheap devices, runtime writes to flash are unrestricted.

## Engagement Cheatsheet

```bash
# 1. Identify RTOS + version
strings firmware.bin | grep -iE "(freertos|zephyr|threadx) v"

# 2. Reverse in Ghidra
ghidra-headlessAnalyzer ./project test_project -import firmware.bin

# 3. Identify network listeners and parsers
# Look for socket bind, recvfrom, recv-callback handlers

# 4. Memory corruption hunt
# Overflowing recv buffers, format-string in debug logging,
# integer overflow in length calculations

# 5. Exploit construction (no ASLR — all addresses static)
ropper --file firmware.elf

# 6. Test via JTAG (live debug) or network protocol fuzzing

# 7. Persistence: flash write or env-var manipulation if bootloader-cooperative
```

## Detection / Defenses

| Defense | Bypass |
|---|---|
| MPU when configured | Find unprotected region, exploit there |
| Stack canaries (configCHECK_FOR_STACK_OVERFLOW) | Avoid hitting canary; use precise overwrites |
| W^X (some Zephyr/FreeRTOS configs) | ROP instead of shellcode |
| Watchdog (resets on crash) | Make exploit reliable to avoid crash; or accept reboot |
| Anti-rollback on firmware update | Block persistence |

## Reporting

- Exact RTOS + version + chipset
- Memory protection state (MPU configured? canaries? W^X?)
- Vulnerability class and root cause
- Reliability of exploit (single-shot vs requires retries)
- Persistence achieved or not
- Vendor patch path (firmware update mechanism)

---

## Key References

- "Hacking IoT and RTOS" (various authors)
- FreeRTOS Reference Manual: freertos.org/Documentation
- Zephyr documentation: docs.zephyrproject.org
- URGENT/11 (Armis) — VxWorks vulnerability disclosure
- Amnesia:33 (Forescout) — proprietary stack vulnerabilities
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
