# Reproduction Guide

This document explains how to independently verify the vulnerabilities described in this repository.

## Prerequisites

- A Linux machine (Ubuntu 22.04+ recommended)
- Tools: `git`, `binwalk`, `squashfs-tools`, `binutils`, `radare2`

```bash
sudo apt update
sudo apt install -y binwalk squashfs-tools binutils radare2
```

## Step 1 — Obtain the firmware

```bash
mkdir -p ~/v380 && cd ~/v380
git clone https://github.com/drtanzil/V380-Firmware.git
cd V380-Firmware
unzip "V380_AK_3918E-V200__V2.6.8.7_2021-07-28.zip" -d v2687
```

## Step 2 — Extract the rootfs

```bash
cd v2687
PATCH=updatepatch/67b2c5254afef4f24f371e39f62e1579.patch

# Verify SquashFS is present
binwalk "$PATCH"
# Expected: offset 0x128 → Squashfs filesystem, xz compressed

# Extract
tail -c +297 "$PATCH" > root.sqsh
file root.sqsh
# Expected: Squashfs filesystem, little endian, version 4.0, xz compressed

unsquashfs -d rootfs_out root.sqsh
cd rootfs_out
```

## Step 3 — Run the automated verification script

```bash
chmod +x poc_v380_wifi_cmdi_verify.sh
./poc_v380_wifi_cmdi_verify.sh ~/v380/V380-Firmware/v2687/rootfs_out
```

Expected output: all checks report `[VULN]` for the WiFi command injection and IPC service findings.

## Step 4 — Manual verification

### Verify WiFi command injection (Finding #1)

```bash
# Confirm dangerous format strings
strings -n 5 apps/recorder | grep "wifi_softap.sh.*%s"
# Expected:
#   /tmp/wificonf/wifi_softap.sh %d wpa %s %s %d %d
#   /tmp/wificonf/wifi_softap.sh %d open %s %d %d

# Confirm system() is imported
nm -D apps/recorder | grep " U system"
# Expected: U system

# Disassemble the vulnerable function (requires radare2)
r2 -q -e scr.color=0 -c 'aaa; pd 20 @ 0x35a9c' apps/recorder
# Expected: ldr r1 pointing to wifi_softap.sh format string, followed by bl sprintf,
# then bl to fcn.00043e04 which calls system()
```

### Verify IPC command service (Finding #2)

```bash
# Confirm socket path and marker (binary is NOT stripped)
strings -n 5 apps/mv_syscall_worker | grep -E "uns_system_call|system\]:|/bin/sh"
# Expected:
#   /tmp/uns_system_call.un
#   [system]:
#   /bin/sh

# Confirm execl import
nm -D apps/mv_syscall_worker | grep execl
# Expected: U execl

# View named functions (not stripped!)
nm apps/mv_syscall_worker | grep -i "system_call"
# Expected:
#   system_call
#   system_call_request_processing
```

## File hashes (for verification)

```
SHA256 (recorder):          d17559eebee9cd91903f27365b591559ecea1853c41feef2369dba7f5f3c2d5d
SHA256 (mv_syscall_worker): 68a9d0c01d2847bcdc4e6a2c178997860181890b2710d9baa3eb101da75db020
SHA256 (root.sqsh):         (compute with: sha256sum root.sqsh)
```

## Notes

- This analysis was performed entirely through **static analysis** of publicly available firmware. No live device was accessed or harmed.
- The firmware update package is a **partial update** (delta patch) containing only `apps/`, `lib/`, `local/`, and `modules/` directories — not a complete rootfs.
- All testing was conducted on firmware owned by the researcher in a controlled environment.
