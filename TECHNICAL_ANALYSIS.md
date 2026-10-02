# Technical Analysis — V380 WiFi Command Injection

## 1. Target Information

| Field | Value |
|-------|-------|
| Product | Macro-video Technologies V380E2 C2 IP Camera |
| SoC | Anyka AK3918E-V200 (ARM, little-endian) |
| Firmware | V2.6.8.7 (2021-07-28) |
| Hardware | HWV280E12_WF9_PTZ_20180628 |
| OS | Linux (uClibc-based) |
| Firmware source | https://github.com/drtanzil/V380-Firmware |

## 2. Firmware Extraction

The firmware was obtained from the publicly available update package:

```
V380_AK_3918E-V200__V2.6.8.7_2021-07-28.zip
```

### Extraction steps

```bash
# Unzip the update package
unzip "V380_AK_3918E-V200__V2.6.8.7_2021-07-28.zip" -d v2687

# The update patch structure:
# v2687/
# ├── local_update.conf        (metadata, contains patch MD5)
# ├── patch_reuse              (empty)
# └── updatepatch/
#     └── 67b2c5254afef4f24f371e39f62e1579.patch  (payload)

# binwalk scan reveals SquashFS at offset 296 (0x128)
binwalk v2687/updatepatch/*.patch
# 192    0xC0   Executable script, shebang: "/bin/sh"
# 296    0x128  Squashfs filesystem, little endian, version 4.0, xz compressed

# Extract SquashFS rootfs
PATCH=v2687/updatepatch/67b2c5254afef4f24f371e39f62e1579.patch
tail -c +297 "$PATCH" > root.sqsh
unsquashfs -d rootfs_out root.sqsh
# created 75 files, 5 directories, 2 symlinks
```

### Note on update format

This is a **partial update** (delta patch), not a full firmware image. It contains:
- `apps/` — application binaries (the main targets)
- `lib/` — shared libraries
- `local/` — ISP sensor configuration files
- `modules/` — kernel modules (.ko)

It does **not** contain `/etc`, `/bin`, or other base rootfs files. A full firmware dump (via UART/FTP from a live device) would be needed for complete analysis.

## 3. Binary Triage

### Key binaries identified

| Binary | Size | Stripped | Role |
|--------|------|----------|------|
| `apps/recorder` | 556 KB | Yes | **Main daemon** — handles video, network, cloud, WiFi, RTSP, PTZ |
| `apps/mv_syscall_worker` | 15 KB | **No** | IPC command execution service |
| `apps/vsipbroadcast` | 12 KB | Yes | P2P/broadcast discovery |
| `apps/mvrtsp` | — | Yes | RTSP server |
| `apps/eventhub_core` | — | Yes | Event handling |

### Dangerous function imports

**recorder:**
```
U system        ← direct shell execution
U popen         ← pipe to shell command
U sprintf       ← format string (no bounds check)
U strcpy        ← unbounded copy
U strcat        ← unbounded concatenation
U recv / recvfrom / socket / bind / listen  ← network I/O
U unix_ssocket_data_send / unix_ssocket_data_recv  ← IPC
```

**mv_syscall_worker:**
```
U execl         ← direct program execution
U memcpy        ← memory copy
U sscanf        ← format parsing
```

## 4. Vulnerability #1 — WiFi Command Injection (CWE-78)

### Location

Binary: `/mvs/apps/recorder`  
Function: `fcn.0003581c` (WiFi SoftAP configuration handler)  
Addresses: `0x35a9c` (WPA path), `0x35af4` (Open path)

### Vulnerable code (reconstructed from disassembly)

```c
void wifi_softap_start(int mode, char *ssid, char *password, int channel, int param5) {
    char buf[0x580];   // stack buffer

    if (password[0] != '\0') {
        // WPA mode — SSID and password both injected
        sprintf(buf, "/tmp/wificonf/wifi_softap.sh %d wpa %s %s %d %d",
                mode, ssid, password, channel, param5);
    } else {
        // Open mode — only SSID injected
        sprintf(buf, "/tmp/wificonf/wifi_softap.sh %d open %s %d %d",
                mode, ssid, channel, param5);
    }

    execute_command(buf);  // fcn.00043e04 → system(buf)
}
```

### Disassembly evidence (radare2)

```
; WPA path — sprintf with SSID (%s) and password (%s) unsanitized
0x00035a9c  ldr r1, str._tmp_wificonf_wifi_softap.sh__d_wpa__s__s__d__d
0x00035aa8  bl sym.imp.sprintf

; Result passed to command executor
0x00035ac4  bl fcn.00043e04

; Inside fcn.00043e04:
0x00043e60  bl sym.imp.system       ; system(buf) — shell execution!

; Same function also sends via IPC:
0x00043ebc  ldr r2, str._system_:   ; "[system]:" marker
0x00043edc  bl sym.imp.snprintf     ; build IPC message
0x00043f00  bl sym.imp.unix_ssocket_data_send  ; send to mv_syscall_worker
```

### Data flow

```
User input (SSID/password)
  → V380 Pro app
    → P2P/cloud protocol (unencrypted)
      → recorder daemon
        → fcn.0003581c (WiFi handler)
          → sprintf(buf, "...%s %s...", ssid, password)  // NO SANITIZATION
            → fcn.00043e04 (command executor)
              → system(buf)              // Direct shell execution as root
              → [system]:buf → IPC → mv_syscall_worker → execl(/bin/sh -c buf)
```

## 5. Vulnerability #2 — Unauthenticated IPC Command Service (CWE-78 + CWE-306)

### Location

Binary: `/mvs/apps/mv_syscall_worker`  
Function: `system_call` at `0x8fc8`, called from `system_call_request_processing` at `0x90f0`  
Socket: `/tmp/uns_system_call.un` (UNIX domain)

### Vulnerable code (reconstructed — binary is not stripped)

```c
// system_call_request_processing(request)
void system_call_request_processing(struct request *req) {
    char *marker = strstr(req->data, "[system]:");  // find marker
    if (marker == NULL) return;

    sscanf(req->data, "[%d]:%*", &timeout);  // parse timeout
    char *cmd = marker + 9;                   // everything after "[system]:"

    system_call(cmd, ...);  // execute it
}

// system_call(cmd, ...)
int system_call(char *cmd, ...) {
    printf("exec: %s \n", cmd);    // log the command
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, NULL);  // EXECUTE AS ROOT
        _exit(127);
    }
    waitpid(pid, &status, 0);
    return status;
}
```

### Key observations

- **No authentication**: any local process connecting to the socket can execute commands
- **No input filtering**: the command string is passed directly to `/bin/sh -c`
- **No access control**: socket permissions likely allow any user
- Named functions visible because binary is **not stripped**

## 6. Additional Findings

### 6.1 Multiple unsafe sprintf → system patterns

| Format string | Location | Risk |
|---|---|---|
| `rm -rf %s` | recorder | Arbitrary file deletion if path is user-controlled |
| `insmod %s ...` | recorder (6 instances) | Arbitrary kernel module loading |
| `ifconfig %s down/up` | recorder (3 instances) | Command injection via interface name |
| `cp %s %s` | recorder (2 instances) | Arbitrary file overwrite |

### 6.2 Credential logging

```
Verify username:%s password:%s _result:%d
```
Authentication credentials are logged in plaintext. Combined with `log_upload` binary (which transmits logs to cloud), this is an information disclosure risk.

### 6.3 Hardcoded AES-ECB usage

Strings confirm use of AES-128-ECB mode:
```
AES-128-ECB
AES_ecb_encrypt
/home/datas/twj_datas/.../aes_ecb.cpp
```
ECB mode is cryptographically weak — it preserves patterns in ciphertext.

### 6.4 Internal build paths leaked

```
/home/datas/twj_datas/Common_Structure/common_file_and_tools/mvs_service_bin/...
/mnt/mai_share/motiondetection/opencv-2.4.13-hongshi/...
```
These reveal the vendor's internal directory structure and confirm use of **OpenCV 2.4.13** (2016, multiple known CVEs).

## 7. Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| binwalk | 2.3.3+ | Firmware signature scanning and extraction |
| unsquashfs | 4.6.1 | SquashFS filesystem extraction |
| radare2 | 5.5.0 | ARM binary disassembly and cross-reference analysis |
| strings | GNU binutils | String extraction from binaries |
| nm | GNU binutils | Symbol table inspection |
| file | 5.x | File type identification |
| grep | GNU | Pattern searching across firmware |
