#!/usr/bin/env bash
# Environment check script for qtbench
# Verifies system dependencies and network benchmarking tools

set -u

ERRORS=0
WARNINGS=0

echo "========= System Environment Pre-check for qtbench ========="

check_cmd() {
    local cmd="$1"
    local required="$2"
    if command -v "$cmd" >/dev/null 2>&1; then
        local version_info=""
        case "$cmd" in
            go) version_info=$(go version 2>&1) ;;
            ping) version_info=$(ping -V 2>&1 || ping -c 1 127.0.0.1 2>&1 | head -n 1) ;;
            tc) version_info=$(tc -V 2>&1 || true) ;;
            ss) version_info=$(ss -V 2>&1 || true) ;;
            *) version_info=$("$cmd" --version 2>&1 | head -n 1 || true) ;;
        esac
        echo "[OK] Found $cmd: $version_info"
    else
        if [ "$required" = "true" ]; then
            echo "[ERROR] Missing required command: $cmd"
            ERRORS=$((ERRORS + 1))
        else
            echo "[WARN] Optional command not found: $cmd"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
}

echo "1. Checking Core Tools."
check_cmd "go" "true"
check_cmd "tshark" "true"
check_cmd "ping" "true"
check_cmd "iperf3" "true"
check_cmd "tc" "true"
check_cmd "ss" "true"

echo "2. Checking Traffic Control (tc netem) Permissions."
if command -v tc >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        echo "[OK] Running with root privileges (tc netem ready)"
    else
        if sudo -n tc qdisc show >/dev/null 2>&1; then
            echo "[OK] Passwordless sudo available for tc netem"
        else
            echo "[WARN] Root or sudo access required to apply tc netem network degradation"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
fi

echo "3. Network Interfaces."
ip -brief addr || true

echo "========= Pre-check Summary ========="
echo "Errors: $ERRORS, Warnings: $WARNINGS"

if [ "$ERRORS" -gt 0 ]; then
    echo "Pre-check failed with $ERRORS error(s). Please install missing dependencies."
    exit 1
else
    echo "Pre-check passed successfully."
    exit 0
fi
