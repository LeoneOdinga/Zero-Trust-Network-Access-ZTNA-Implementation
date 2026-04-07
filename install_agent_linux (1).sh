#!/usr/bin/env bash
# ================================================================
# install_agent_linux.sh
# Zero Trust Linux Agent — Installer
#
# Installs zt_agent_linux.py as a systemd service that starts
# automatically on boot and restarts on failure.
#
# USAGE:
#   chmod +x install_agent_linux.sh
#   sudo ./install_agent_linux.sh --portal http://192.168.0.101:5000
#
# UNINSTALL:
#   sudo ./install_agent_linux.sh --uninstall
# ================================================================

set -e

# ── Defaults ─────────────────────────────────────────────────
PORTAL_URL="http://192.168.0.101:5000"
INSTALL_DIR="/opt/zt-agent"
SERVICE_NAME="zt-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
AGENT_SCRIPT="zt_agent_linux.py"
AGENT_USER="root"       # needs root for cryptsetup, lsblk, ufw queries
UNINSTALL=0

# ── Parse args ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --portal)    PORTAL_URL="$2";  shift 2 ;;
        --uninstall) UNINSTALL=1;      shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Uninstall ─────────────────────────────────────────────────
if [[ $UNINSTALL -eq 1 ]]; then
    echo "[ZT] Uninstalling ${SERVICE_NAME}..."
    systemctl stop    "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    echo "[ZT] Service removed. Files in ${INSTALL_DIR} preserved."
    echo "[ZT] To remove files: sudo rm -rf ${INSTALL_DIR}"
    exit 0
fi

# ── Checks ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[ZT] ERROR: This script must be run as root."
    echo "     sudo ./install_agent_linux.sh --portal ${PORTAL_URL}"
    exit 1
fi

echo "================================================"
echo "  Zero Trust Linux Agent Installer"
echo "  Portal:      ${PORTAL_URL}"
echo "  Install dir: ${INSTALL_DIR}"
echo "  Service:     ${SERVICE_NAME}"
echo "================================================"
echo

# ── Step 1: Install system dependencies ──────────────────────
echo "[1/6] Installing Python dependencies..."

# We do NOT run apt-get update here — it can fail on systems with
# unrelated broken packages (e.g. mariadb-server dpkg errors) and
# would abort the agent install for no reason.
# The agent only needs requests + psutil which pip handles directly.

if ! command -v python3 &>/dev/null; then
    echo "[ZT] ERROR: python3 not found. Fix broken packages first:"
    echo "    sudo dpkg --configure -a"
    echo "    sudo apt-get install -f"
    echo "    sudo apt-get install python3"
    exit 1
fi
echo "    python3 found: $(python3 --version)"

# Install pip without touching apt
if ! python3 -m pip --version &>/dev/null 2>&1; then
    echo "    pip missing -- installing via get-pip.py..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - --quiet \
        || { echo "[ZT] ERROR: pip install failed. Run manually:"; \
             echo "    curl https://bootstrap.pypa.io/get-pip.py | python3"; exit 1; }
fi

# Install only what the agent needs -- no apt involved
python3 -m pip install requests psutil --quiet --break-system-packages 2>/dev/null \
    || pip3 install requests psutil --quiet --break-system-packages 2>/dev/null \
    || python3 -c "import requests, psutil" 2>/dev/null \
    || { echo "[ZT] ERROR: Could not install requests/psutil."; \
         echo "    Run: pip3 install requests psutil --break-system-packages"; exit 1; }

echo "    Dependencies OK"

# ── Step 2: Create install directory ─────────────────────────
echo "[2/6] Creating ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"

# Copy agent script (from same directory as this installer)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/${AGENT_SCRIPT}" ]]; then
    cp "${SCRIPT_DIR}/${AGENT_SCRIPT}" "${INSTALL_DIR}/${AGENT_SCRIPT}"
    echo "    Copied ${AGENT_SCRIPT} to ${INSTALL_DIR}"
elif [[ -f "${INSTALL_DIR}/${AGENT_SCRIPT}" ]]; then
    echo "    ${AGENT_SCRIPT} already in ${INSTALL_DIR} — using existing file"
else
    echo "[ZT] ERROR: ${AGENT_SCRIPT} not found in ${SCRIPT_DIR} or ${INSTALL_DIR}"
    echo "    Copy zt_agent_linux.py to the same directory as this script and re-run."
    exit 1
fi

chmod 750 "${INSTALL_DIR}/${AGENT_SCRIPT}"

# ── Step 3: Test connectivity and collect telemetry once ──────
echo "[3/6] Testing portal connectivity..."
python3 "${INSTALL_DIR}/${AGENT_SCRIPT}" \
    --portal "${PORTAL_URL}" \
    --once > /tmp/zt_agent_test.txt 2>&1

if grep -q "Fingerprint" /tmp/zt_agent_test.txt; then
    FINGERPRINT=$(grep "Fingerprint" /tmp/zt_agent_test.txt | awk '{print $3}')
    HOSTNAME=$(grep "Hostname" /tmp/zt_agent_test.txt | awk '{print $3}')
    echo "    Telemetry collection OK"
    echo "    Fingerprint : ${FINGERPRINT}"
    echo "    Hostname    : ${HOSTNAME}"
else
    echo "    WARNING: Could not verify telemetry collection"
    echo "    Check /tmp/zt_agent_test.txt for details"
fi

# ── Step 4: Register with portal ─────────────────────────────
echo "[4/6] Registering with portal..."
python3 - <<PYEOF
import sys
sys.path.insert(0, "${INSTALL_DIR}")
import zt_agent_linux as ag

fp, hostname, mac = ag.get_stable_fingerprint()
print(f"  Fingerprint: {fp}")
print(f"  Hostname:    {hostname}")
print(f"  MAC:         {mac}")

# Check if already registered
cfg = ag.load_config()
if cfg.get("device_id"):
    print(f"  Already registered as {cfg['device_id']}")
    print("  Skipping re-registration")
    sys.exit(0)

try:
    reg = ag.register_device("${PORTAL_URL}", hostname, fp)
    import json
    cfg = {
        "device_id":   reg["device_id"],
        "secret":      reg["secret"],
        "portal_url":  "${PORTAL_URL}",
        "hostname":    hostname,
        "fingerprint": fp,
    }
    ag.save_config(cfg)
    print(f"  Registered as {reg['device_id']}")
except Exception as e:
    print(f"  ERROR: Registration failed — {e}")
    print("  The service will retry automatically on startup.")
PYEOF

# ── Step 5: Write systemd service unit ───────────────────────
echo "[5/6] Writing systemd service unit..."

cat > "${SERVICE_FILE}" << UNITEOF
[Unit]
Description=Zero Trust Device Agent
Documentation=Zero Trust Architecture — NIST SP 800-207
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/${AGENT_SCRIPT} --portal ${PORTAL_URL}
Restart=always
RestartSec=10
StandardOutput=append:${INSTALL_DIR}/agent.log
StandardError=append:${INSTALL_DIR}/agent.log

# Harden the service process
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${INSTALL_DIR}
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNITEOF

echo "    Service file written to ${SERVICE_FILE}"

# ── Step 6: Enable and start the service ─────────────────────
echo "[6/6] Enabling and starting service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 3

STATUS=$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null)

echo
echo "================================================"
if [[ "$STATUS" == "active" ]]; then
    echo "  Installation complete!"
    echo "  Service status: RUNNING"
else
    echo "  Installation complete (service status: ${STATUS})"
fi
echo
echo "  Useful commands:"
echo "    systemctl status ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -f"
echo "    tail -f ${INSTALL_DIR}/agent.log"
echo "    systemctl stop    ${SERVICE_NAME}"
echo "    systemctl restart ${SERVICE_NAME}"
echo "================================================"
echo
