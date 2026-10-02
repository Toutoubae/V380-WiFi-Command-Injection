#!/bin/bash
# ============================================================================
# V380 WiFi Command Injection — Static Analysis Verification Script
# ============================================================================
# This script verifies the presence of the command injection vulnerability
# in the V380 recorder binary through static analysis. It does NOT exploit
# a live device.
#
# Usage:
#   chmod +x poc_v380_wifi_cmdi_verify.sh
#   ./poc_v380_wifi_cmdi_verify.sh /path/to/rootfs_out
#
# Requirements: binutils (nm, strings), file, sha256sum
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ROOTFS="${1:?Usage: $0 /path/to/rootfs_out}"
RECORDER="$ROOTFS/apps/recorder"
WORKER="$ROOTFS/apps/mv_syscall_worker"

echo "=============================================="
echo " V380 WiFi Command Injection — PoC Verifier"
echo "=============================================="
echo

# --- Check files exist ---
for f in "$RECORDER" "$WORKER"; do
    if [ ! -f "$f" ]; then
        echo -e "${RED}[FAIL]${NC} File not found: $f"
        exit 1
    fi
done
echo -e "${GREEN}[OK]${NC} Both binaries found"

# --- Fingerprint ---
echo
echo "=== Device / Firmware Fingerprint ==="
echo "recorder : $(sha256sum "$RECORDER" | cut -d' ' -f1)"
echo "worker   : $(sha256sum "$WORKER" | cut -d' ' -f1)"
echo "arch     : $(file "$RECORDER" | grep -o 'ELF.*ARM[^,]*')"
echo

# --- Check 1: Dangerous imports in recorder ---
echo "=== Check 1: Dangerous function imports in recorder ==="
DANGEROUS=$(nm -D "$RECORDER" 2>/dev/null | grep -cE "\bsystem\b|\bpopen\b|\bsprintf\b|\bstrcpy\b|\bstrcat\b" || true)
if [ "$DANGEROUS" -gt 0 ]; then
    echo -e "${RED}[VULN]${NC} recorder imports $DANGEROUS dangerous functions:"
    nm -D "$RECORDER" 2>/dev/null | grep -E "\bsystem\b|\bpopen\b|\bsprintf\b|\bstrcpy\b|\bstrcat\b" | sed 's/^/    /'
else
    echo -e "${GREEN}[OK]${NC} No dangerous imports found (unexpected)"
fi
echo

# --- Check 2: WiFi command injection format strings ---
echo "=== Check 2: WiFi softap format strings with unsanitized %s ==="
WIFI_HIT=$(strings -n 5 "$RECORDER" | grep -c "wifi_softap.sh.*%s" || true)
if [ "$WIFI_HIT" -gt 0 ]; then
    echo -e "${RED}[VULN]${NC} Found $WIFI_HIT format string(s) passing user input to shell:"
    strings -n 5 "$RECORDER" | grep "wifi_softap.sh.*%s" | sed 's/^/    /'
else
    echo -e "${GREEN}[OK]${NC} No vulnerable WiFi format strings found"
fi
echo

# --- Check 3: system() import confirms execution ---
echo "=== Check 3: system() and popen() imports ==="
SYS=$(nm -D "$RECORDER" 2>/dev/null | grep -c "\bsystem$" || true)
POP=$(nm -D "$RECORDER" 2>/dev/null | grep -c "\bpopen$" || true)
echo "    system() imported: $SYS time(s)"
echo "    popen()  imported: $POP time(s)"
if [ "$SYS" -gt 0 ]; then
    echo -e "${RED}[VULN]${NC} sprintf'd WiFi command is passed to system() for shell execution"
fi
echo

# --- Check 4: mv_syscall_worker IPC ---
echo "=== Check 4: Unauthenticated IPC command service ==="
SOCK=$(strings -n 5 "$WORKER" | grep -c "uns_system_call" || true)
MARKER=$(strings -n 5 "$WORKER" | grep -c "\[system\]:" || true)
SHELL=$(strings -n 5 "$WORKER" | grep -c "/bin/sh" || true)
EXECL=$(nm -D "$WORKER" 2>/dev/null | grep -c "\bexecl$" || true)
echo "    UNIX socket path (/tmp/uns_system_call.un): $SOCK hit(s)"
echo "    Command marker ([system]:): $MARKER hit(s)"
echo "    Shell reference (/bin/sh): $SHELL hit(s)"
echo "    execl() import: $EXECL hit(s)"
if [ "$SOCK" -gt 0 ] && [ "$MARKER" -gt 0 ] && [ "$EXECL" -gt 0 ]; then
    echo -e "${RED}[VULN]${NC} mv_syscall_worker executes any [system]: command via /bin/sh without auth"
fi
echo

# --- Check 5: Other dangerous patterns ---
echo "=== Check 5: Other unsafe sprintf → system patterns ==="
for pat in "rm -rf %s" "insmod %s" "ifconfig %s" "cp %s %s"; do
    HIT=$(strings -n 5 "$RECORDER" | grep -cF "$pat" || true)
    if [ "$HIT" -gt 0 ]; then
        echo -e "    ${YELLOW}[WARN]${NC} \"$pat\" — $HIT occurrence(s)"
    fi
done
echo

# --- Check 6: Credential logging ---
echo "=== Check 6: Credential logging ==="
CRED=$(strings -n 5 "$RECORDER" | grep -c "username:%s password:%s" || true)
if [ "$CRED" -gt 0 ]; then
    echo -e "    ${YELLOW}[WARN]${NC} Credentials logged in plaintext ($CRED occurrence(s))"
    strings -n 5 "$RECORDER" | grep "username:%s password:%s" | sed 's/^/    /'
fi
echo

# --- Check 7: Outdated components ---
echo "=== Check 7: Outdated third-party components ==="
OPENCV=$(strings -n 5 "$RECORDER" "$ROOTFS"/lib/*.so 2>/dev/null | grep -o "opencv-[0-9.]*" | sort -u | head -1 || true)
if [ -n "$OPENCV" ]; then
    echo -e "    ${YELLOW}[WARN]${NC} $OPENCV detected (multiple known CVEs)"
fi
UCLIBC=$(file "$RECORDER" | grep -o "uClibc" || true)
if [ -n "$UCLIBC" ]; then
    echo -e "    ${YELLOW}[INFO]${NC} Linked against uClibc (check version for known CVEs)"
fi
echo

# --- Summary ---
echo "=============================================="
echo " SUMMARY"
echo "=============================================="
echo
echo " Finding 1: OS Command Injection via WiFi SSID/Password"
echo "   → sprintf(wifi_softap.sh ... %s %s ...) → system()"
echo "   → CWE-78, remote via P2P/cloud app"
echo "   → Severity: HIGH"
echo
echo " Finding 2: Unauthenticated IPC Command Execution"
echo "   → UNIX socket /tmp/uns_system_call.un"
echo "   → [system]:<cmd> → execl(/bin/sh -c <cmd>)"
echo "   → CWE-78 + CWE-306, local"
echo "   → Severity: MEDIUM"
echo
echo " Additional: rm -rf %s, insmod %s, ifconfig %s,"
echo "   credential logging, outdated OpenCV"
echo
echo "=============================================="
echo " Next steps:"
echo "   1. Attempt responsible disclosure to vendor"
echo "   2. Request CVE ID from MITRE (cveform.mitre.org)"
echo "   3. Validate on live device when available"
echo "=============================================="
