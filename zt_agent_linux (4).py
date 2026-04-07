# -*- coding: utf-8 -*-
# ================================================================
# zt_agent_linux.py
# Zero Trust Device Agent -- Ubuntu / Debian Linux Agent
#
# Mirrors zt_agent.py (Windows) exactly in structure and payload
# format.  All collectors are re-implemented using Linux-native
# commands (systemctl, ufw, lsblk, cryptsetup, apt, gsettings,
# realm, loginctl, psutil) instead of WMI / PowerShell / winreg.
#
# Runs as a systemd service.  See install_agent_linux.sh.
#
# MANUAL RUN:
#   sudo python3 zt_agent_linux.py --portal http://192.168.0.101:5000
#
# REQUIREMENTS:
#   sudo apt install python3-pip -y
#   pip3 install requests psutil --break-system-packages
#
# CONFIG:  /opt/zt-agent/config.json   (created on first run)
# LOG:     /opt/zt-agent/agent.log
# ================================================================

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# ── Optional imports ──────────────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── IOC detection cache (disk-backed) ────────────────────────
# Written to a JSON file so detections persist across heartbeat
# cycles and survive process restarts (e.g. service reload).
# Key: ioc_string  Value: unix timestamp of last seen
IOC_CACHE_TTL_S  = 300   # remember IOC for 5 minutes after last seen

# ── Paths ─────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(_BASE_DIR, "config.json")
LOG_FILE    = os.path.join(_BASE_DIR, "agent.log")

# ── Logging ───────────────────────────────────────────────────
_log_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3,
    encoding="utf-8"
)
_log_handler.setFormatter(logging.Formatter(
    "%(asctime)s [ZT-AGENT] %(levelname)s %(message)s"
))
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(logging.Formatter(
    "%(asctime)s [ZT-AGENT] %(levelname)s %(message)s"
))

log = logging.getLogger("zt_agent_linux")
log.setLevel(logging.INFO)
log.addHandler(_log_handler)
log.addHandler(_console_handler)

# ── Endpoints ─────────────────────────────────────────────────
REGISTER_ENDPOINT  = "/api/device/register"
HEARTBEAT_ENDPOINT = "/api/device/heartbeat"
HEARTBEAT_INTERVAL = 60   # seconds
IOC_SCAN_INTERVAL  = 5    # background process scan every 5 seconds


# ── Config persistence ────────────────────────────────────────

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not read config: {e}")
    return {}


def save_config(data: dict) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log.info(f"Config saved to {CONFIG_FILE}")
    except Exception as e:
        log.error(f"Could not save config: {e}")


# ── Shell helper ──────────────────────────────────────────────

def run(cmd, timeout=10) -> str:
    """Run a shell command and return stdout as a string."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=isinstance(cmd, str)
        )
        return r.stdout.strip()
    except Exception as e:
        return f"[error: {e}]"


def run_rc(cmd, timeout=10) -> tuple:
    """Run a command and return (stdout, returncode)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=isinstance(cmd, str)
        )
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return f"[error: {e}]", 1


# ── Stable device fingerprint ─────────────────────────────────

def get_stable_fingerprint():
    """
    SHA-256(hostname + primary MAC address).
    Identical algorithm to the Windows agent — same machine always
    returns the same fingerprint regardless of logged-in user.
    """
    hostname = socket.gethostname()
    mac = ""

    if HAS_PSUTIL:
        for iface, addrs in psutil.net_if_addrs().items():
            if iface == "lo":
                continue
            for addr in addrs:
                if addr.family.name == "AF_LINK":
                    candidate = addr.address.upper()
                    if candidate not in ("00:00:00:00:00:00", ""):
                        mac = candidate
                        break
            if mac:
                break

    if not mac:
        # Fallback: read from /sys/class/net
        try:
            for iface in os.listdir("/sys/class/net"):
                if iface == "lo":
                    continue
                mac_path = f"/sys/class/net/{iface}/address"
                if os.path.exists(mac_path):
                    with open(mac_path) as f:
                        candidate = f.read().strip().upper()
                    if candidate and candidate != "00:00:00:00:00:00":
                        mac = candidate
                        break
        except Exception:
            pass

    raw         = f"{hostname}|{mac}"
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return fingerprint, hostname, mac


# ── Telemetry collectors ──────────────────────────────────────

def collect_os_info() -> dict:
    return {
        "system":   platform.system(),
        "release":  platform.release(),
        "version":  platform.version(),
        "machine":  platform.machine(),
        "hostname": socket.gethostname(),
        "python":   platform.python_version(),
        "distro":   run("lsb_release -ds 2>/dev/null || cat /etc/os-release "
                        "| grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"),
    }


def collect_disk_encryption() -> dict:
    """
    Detect LUKS full-disk encryption on Ubuntu/Debian.

    Checks in order:
    1. /etc/crypttab — presence indicates encrypted volumes configured
    2. lsblk -o NAME,TYPE — look for 'crypt' type devices
    3. cryptsetup status on any active dm-crypt device
    """
    # Check 1: /etc/crypttab
    crypttab_entries = []
    try:
        with open("/etc/crypttab") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    crypttab_entries.append(line.split()[0])
    except FileNotFoundError:
        pass

    # Check 2: lsblk for dm-crypt type devices
    lsblk_out = run("lsblk -o NAME,TYPE -r 2>/dev/null")
    crypt_devices = [
        line.split()[0]
        for line in lsblk_out.splitlines()
        if len(line.split()) >= 2 and line.split()[1] == "crypt"
    ]

    # Check 3: cryptsetup status on each crypt device
    active_devices = []
    for dev in crypt_devices:
        status_out = run(f"cryptsetup status /dev/mapper/{dev} 2>/dev/null")
        if "is active" in status_out or "cipher:" in status_out:
            cipher = ""
            for l in status_out.splitlines():
                if "cipher:" in l:
                    cipher = l.split(":", 1)[1].strip()
                    break
            active_devices.append({"device": dev, "cipher": cipher})

    # Check 4: Look for LUKS headers on block devices directly
    luks_detected = False
    if not active_devices:
        blk_out = run("lsblk -o NAME -r -d 2>/dev/null")
        for dev_name in blk_out.splitlines():
            dev_name = dev_name.strip()
            if not dev_name or dev_name == "NAME":
                continue
            luks_out, rc = run_rc(
                f"cryptsetup isLuks /dev/{dev_name} 2>/dev/null"
            )
            if rc == 0:
                luks_detected = True
                active_devices.append({"device": dev_name, "cipher": "LUKS"})

    enabled = bool(active_devices) or bool(crypttab_entries) or luks_detected

    return {
        "enabled":         enabled,
        "method":          "LUKS" if enabled else "None",
        "active_devices":  active_devices,
        "crypttab_entries": crypttab_entries,
    }


def collect_antivirus() -> dict:
    """
    Detect AV/EDR solutions on Ubuntu/Debian.
    Checks for: ClamAV, Sophos, ESET, CrowdStrike Falcon,
    SentinelOne, Carbon Black, Wazuh.
    """
    AV_SERVICES = [
        # (service_name, product_display_name, realtime_capable)
        ("clamav-daemon",         "ClamAV",              False),  # on-demand scanner
        ("clamonacc",             "ClamAV On-Access",    True),   # real-time
        ("sophos-spl-mgmt",       "Sophos",              True),
        ("esets_daemon",          "ESET",                True),
        ("ds_agent",              "Deep Security Agent", True),
        ("falcon-sensor",         "CrowdStrike Falcon",  True),
        ("sentineld",             "SentinelOne",         True),
        ("cbdaemon",              "Carbon Black",        True),
        ("wazuh-agent",           "Wazuh",               True),
    ]

    products_found   = []
    av_enabled       = False
    realtime_enabled = False

    for service, display, realtime in AV_SERVICES:
        out = run(f"systemctl is-active {service} 2>/dev/null")
        if out.strip() == "active":
            products_found.append(display)
            av_enabled = True
            if realtime:
                realtime_enabled = True
            log.debug(f"AV: {display} is active ({service})")

    # ClamAV signature age (if installed)
    sig_age_days = -1
    sig_paths = [
        "/var/lib/clamav/daily.cvd",
        "/var/lib/clamav/daily.cld",
        "/var/lib/clamav/main.cvd",
    ]
    for sig_path in sig_paths:
        if os.path.exists(sig_path):
            try:
                mtime      = os.path.getmtime(sig_path)
                sig_age_days = int((time.time() - mtime) / 86400)
                break
            except Exception:
                pass

    # Freshclam last update
    if sig_age_days < 0:
        freshclam_log = "/var/log/clamav/freshclam.log"
        if os.path.exists(freshclam_log):
            try:
                mtime        = os.path.getmtime(freshclam_log)
                sig_age_days = int((time.time() - mtime) / 86400)
            except Exception:
                pass

    return {
        "product":            ", ".join(products_found) if products_found else "None detected",
        "av_present":         bool(products_found),
        "av_enabled":         av_enabled,
        "realtime_enabled":   realtime_enabled,
        "signature_age_days": sig_age_days,
        "source":             "systemctl",
    }


def collect_firewall() -> dict:
    """
    Detect host firewall status.
    Tries UFW first (most common on Ubuntu/Debian desktop),
    then nftables, then iptables.
    """
    # Method 1: UFW
    ufw_out = run("ufw status 2>/dev/null")
    if "Status: active" in ufw_out:
        rules = [
            l.strip()
            for l in ufw_out.splitlines()
            if l.strip() and not l.startswith("Status") and not l.startswith("To")
        ]
        return {
            "enabled": True,
            "backend": "ufw",
            "rules_count": len(rules),
            "details": ufw_out[:300],
        }

    # Method 2: nftables
    nft_out, nft_rc = run_rc("nft list ruleset 2>/dev/null")
    if nft_rc == 0 and nft_out and "table" in nft_out:
        return {
            "enabled": True,
            "backend": "nftables",
            "rules_count": nft_out.count("rule"),
            "details": nft_out[:300],
        }

    # Method 3: iptables — check if any non-default rules exist
    ipt_out = run("iptables -L -n --line-numbers 2>/dev/null")
    if ipt_out and "[error" not in ipt_out:
        # If only ACCEPT policies and no custom rules → effectively disabled
        custom_rules = [
            l for l in ipt_out.splitlines()
            if l and not l.startswith("Chain") and not l.startswith("target")
            and not l.startswith("num") and "ACCEPT" not in l
        ]
        enabled = len(custom_rules) > 0
        return {
            "enabled": enabled,
            "backend": "iptables",
            "rules_count": len(custom_rules),
            "details": ipt_out[:300],
        }

    return {
        "enabled": False,
        "backend": "none detected",
        "rules_count": 0,
        "details": "No active firewall backend found",
    }


def collect_patch_status() -> dict:
    """
    Check apt patch currency on Ubuntu/Debian.

    1. Last successful apt update timestamp
    2. Number of pending security updates (apt-get --simulate)
    3. Days since last update
    """
    # Last apt update stamp
    STAMP_PATHS = [
        "/var/lib/apt/periodic/update-success-stamp",
        "/var/lib/apt/lists/partial",         # fallback
        "/var/cache/apt/pkgcache.bin",        # last fallback
    ]
    last_update_date = "unknown"
    days_since       = -1

    for path in STAMP_PATHS:
        if os.path.exists(path):
            try:
                mtime            = os.path.getmtime(path)
                days_since       = int((time.time() - mtime) / 86400)
                last_update_date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
                break
            except Exception:
                pass

    # Pending security updates — dry-run apt-get upgrade
    pending = -1
    apt_out = run(
        "apt-get --simulate --assume-no upgrade 2>/dev/null "
        "| grep -c '^Inst'",
        timeout=30
    )
    try:
        pending = int(apt_out.strip())
    except (ValueError, TypeError):
        pass

    # Narrow to security updates only if possible
    sec_pending = -1
    sec_out = run(
        "apt-get --simulate --assume-no upgrade 2>/dev/null "
        "| grep -i security | grep -c '^Inst'",
        timeout=30
    )
    try:
        sec_pending = int(sec_out.strip())
    except (ValueError, TypeError):
        pass

    return {
        "last_update_date":         last_update_date,
        "days_since_last_update":   days_since,
        "pending_security_updates": sec_pending if sec_pending >= 0 else pending,
        "pending_all_updates":      pending,
    }


def collect_screen_lock() -> dict:
    """
    Detect screen lock configuration on Ubuntu/Debian.

    Tries:
    1. GNOME gsettings (most common Ubuntu desktop)
    2. loginctl session idle hint
    3. xset dpms (X11 display power settings)
    4. /etc/systemd/logind.conf IdleAction
    """
    # Method 1: GNOME gsettings
    lock_enabled_out = run(
        "gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null"
    )
    if lock_enabled_out in ("true", "false"):
        timeout_out = run(
            "gsettings get org.gnome.session idle-delay 2>/dev/null"
        )
        # idle-delay returns: uint32 300
        timeout_secs = 0
        m = re.search(r"(\d+)", timeout_out)
        if m:
            timeout_secs = int(m.group(1))

        return {
            "enabled":         lock_enabled_out == "true",
            "timeout_seconds": timeout_secs,
            "source":          "GNOME gsettings",
        }

    # Method 2: GNOME lock-delay setting
    lock_delay_out = run(
        "gsettings get org.gnome.desktop.screensaver lock-delay 2>/dev/null"
    )
    if lock_delay_out and "[error" not in lock_delay_out:
        m = re.search(r"(\d+)", lock_delay_out)
        if m:
            return {
                "enabled":         True,
                "timeout_seconds": int(m.group(1)),
                "source":          "GNOME gsettings lock-delay",
            }

    # Method 3: xset dpms (X11 screen saver)
    xset_out = run("xset q 2>/dev/null")
    if "DPMS" in xset_out and "[error" not in xset_out:
        enabled = "DPMS is Enabled" in xset_out
        standby = 0
        m = re.search(r"Standby:\s*(\d+)", xset_out)
        if m:
            standby = int(m.group(1))
        return {
            "enabled":         enabled,
            "timeout_seconds": standby,
            "source":          "xset DPMS",
        }

    # Method 4: systemd logind.conf
    logind_conf = "/etc/systemd/logind.conf"
    if os.path.exists(logind_conf):
        try:
            with open(logind_conf) as f:
                for line in f:
                    if line.startswith("IdleAction="):
                        action = line.split("=", 1)[1].strip()
                        return {
                            "enabled":         action not in ("ignore", "none"),
                            "timeout_seconds": 0,
                            "source":          f"logind.conf IdleAction={action}",
                        }
        except Exception:
            pass

    return {
        "enabled":         None,
        "timeout_seconds": 0,
        "source":          "Could not determine — no GNOME, X11, or logind config found",
    }


def collect_domain() -> dict:
    """
    Check if the machine is joined to an Active Directory or LDAP domain
    via SSSD / realmd (common on Ubuntu enterprise endpoints).
    """
    # Method 1: realm list (realmd)
    realm_out = run("realm list 2>/dev/null")
    if realm_out and "[error" not in realm_out and "type:" in realm_out:
        domain = ""
        for line in realm_out.splitlines():
            if ":" not in line:
                domain = line.strip()
                break
        return {
            "domain_joined": True,
            "domain_name":   domain,
            "source":        "realm",
        }

    # Method 2: sssd.conf
    sssd_conf = "/etc/sssd/sssd.conf"
    if os.path.exists(sssd_conf):
        try:
            with open(sssd_conf) as f:
                content = f.read()
            m = re.search(r"ad_domain\s*=\s*(.+)", content)
            domain = m.group(1).strip() if m else "AD (details in sssd.conf)"
            return {
                "domain_joined": True,
                "domain_name":   domain,
                "source":        "sssd.conf",
            }
        except Exception:
            pass

    # Method 3: /etc/krb5.conf (Kerberos realm)
    krb5_conf = "/etc/krb5.conf"
    if os.path.exists(krb5_conf):
        try:
            with open(krb5_conf) as f:
                content = f.read()
            m = re.search(r"default_realm\s*=\s*(.+)", content)
            if m:
                return {
                    "domain_joined": True,
                    "domain_name":   m.group(1).strip(),
                    "source":        "krb5.conf",
                }
        except Exception:
            pass

    return {
        "domain_joined": False,
        "domain_name":   "",
        "source":        "not domain-joined",
    }


# ── IOC list (shared across all detection methods) ───────────
IOC_LIST = [
    # Credential dumping
    "mimikatz", "wce", "pwdump", "fgdump", "gsecdump", "cachedump",
    # LSASS / memory access
    "procdump", "nanodump", "handlekatz",
    # Remote execution / lateral movement
    "psexec", "paexec", "remcom", "crackmapexec", "cme",
    # Post-exploitation C2
    "meterpreter", "cobalt", "cobaltstrike", "empire", "powersploit",
    "nishang", "covenant", "silenttrinity", "poshc2",
    # Kerberos attacks
    "rubeus", "kekeo", "impacket", "gettgt", "secretsdump",
    # AD recon
    "bloodhound", "sharphound", "adfind", "adrecon", "pingcastle",
    # Credential harvesting
    "lazagne", "credentialfileview", "netpass", "webbrowserpassview",
    # Network scanning — commonly run on compromised Linux hosts
    "nmap", "masscan", "nbtscan",
]

SECURITY_KEYWORDS = [
    "clamd", "clamav", "falcon-sensor", "sentineld", "cbdaemon",
    "sophos", "wazuh", "ossec", "snort", "suricata",
]


# Path for the persistent IOC cache file
IOC_CACHE_FILE = os.path.join(_BASE_DIR, "ioc_cache.json")


def _load_ioc_cache() -> dict:
    """Load IOC cache from disk. Returns empty dict on any error."""
    try:
        if os.path.exists(IOC_CACHE_FILE):
            with open(IOC_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_ioc_cache(cache: dict) -> None:
    """Persist IOC cache to disk."""
    try:
        with open(IOC_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception as e:
        log.debug(f"IOC cache: could not save — {e}")


def _cache_ioc(label: str) -> None:
    """Record an IOC detection with current timestamp (persisted to disk)."""
    cache = _load_ioc_cache()
    cache[label] = time.time()
    _save_ioc_cache(cache)


def _flush_ioc_cache() -> list:
    """
    Load cache from disk, expire stale entries, save back, return
    all entries still within TTL.
    """
    cache   = _load_ioc_cache()
    now     = time.time()
    expired = [k for k, ts in cache.items() if now - ts > IOC_CACHE_TTL_S]
    for k in expired:
        del cache[k]
        log.info(f"IOC cache: expired '{k}' (>{IOC_CACHE_TTL_S}s old)")
    if expired:
        _save_ioc_cache(cache)
    return list(cache.keys())


def _scan_live_processes() -> list:
    """
    Layer 1: Snapshot scan of currently running processes.
    Catches long-running tools (C2 beacons, persistent scans).
    """
    found = []
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["name", "pid", "cmdline"]):
            try:
                name    = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                if any(k in name or k in cmdline for k in IOC_LIST):
                    found.append(
                        f"{proc.info['name']} (PID {proc.info['pid']})"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    else:
        ps_out = run("ps aux --no-headers 2>/dev/null")
        for line in ps_out.splitlines():
            parts = line.split()
            if len(parts) < 11:
                continue
            name    = os.path.basename(parts[10]).lower()
            cmdline = " ".join(parts[10:]).lower()
            if any(k in name or k in cmdline for k in IOC_LIST):
                found.append(f"{parts[10]} (PID {parts[1]})")
    return found


def _scan_audit_logs() -> list:
    """
    Layer 2: Detect recently executed IOC tools through multiple
    log and execution sources.

    Sources tried (in order of reliability):
      a) Linux Audit subsystem (ausearch) -- most reliable
      b) /proc/<pid>/cmdline scan for recently started processes
         whose start time is within the last 2 minutes
      c) /var/log/syslog or /var/log/messages for sudo executions
      d) journalctl scoped to _COMM field (actual process name)
    """
    found  = []
    seen   = set()
    now_ts = time.time()
    window = 120   # seconds to look back

    def _add(label: str, source: str) -> None:
        key = f"{label} (via {source})"
        if key not in seen:
            found.append(key)
            seen.add(key)
            log.info(f"IOC audit: {key}")

    # ── Source a: Linux Audit (auditd + ausearch) ─────────────
    # auditd records every execve() syscall when configured.
    # Most reliable for catching short-lived processes.
    ausearch_out = run(
        "ausearch -ts recent -i 2>/dev/null | grep -iE 'exe=|cmd='",
        timeout=8
    )
    if ausearch_out and "[error" not in ausearch_out:
        for line in ausearch_out.splitlines():
            line_lo = line.lower()
            for ioc in IOC_LIST:
                if re.search(r'\b' + re.escape(ioc) + r'\b', line_lo):
                    _add(ioc, "auditd")
                    break

    # ── Source b: /proc scan for recently started processes ───
    # Check start time of all /proc/<pid> entries. Processes
    # started within the last `window` seconds are candidates —
    # this catches processes that are still alive but young.
    try:
        boot_time = None
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime"):
                    boot_time = int(line.split()[1])
                    break

        clk_tck = os.sysconf("SC_CLK_TCK")   # usually 100

        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                stat_path = f"/proc/{pid}/stat"
                cmd_path  = f"/proc/{pid}/cmdline"
                if not os.path.exists(stat_path):
                    continue

                with open(stat_path) as f:
                    stat = f.read()
                # Field 22 (0-indexed) is starttime in clock ticks
                fields    = stat.split()
                starttime = int(fields[21])
                proc_start = boot_time + (starttime / clk_tck)
                age        = now_ts - proc_start

                if age > window:
                    continue   # process started too long ago

                with open(cmd_path, "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(
                        "utf-8", errors="replace"
                    ).lower()

                for ioc in IOC_LIST:
                    if re.search(r'\b' + re.escape(ioc) + r'\b', cmdline):
                        _add(f"{ioc} (PID {pid})", "proc-recent")
                        break

            except (OSError, IndexError, ValueError):
                pass
    except Exception as e:
        log.debug(f"_scan_audit_logs: /proc scan error — {e}")

    # ── Source c: syslog sudo records ─────────────────────────
    # Sudo logs every command to syslog. If the user ran nmap via
    # sudo, it will appear in /var/log/syslog or /var/log/auth.log.
    for logfile in ["/var/log/syslog", "/var/log/auth.log",
                    "/var/log/messages"]:
        if not os.path.exists(logfile):
            continue
        try:
            out = run(f"tail -300 {logfile} 2>/dev/null")
            for line in out.splitlines():
                line_lo = line.lower()
                # Only parse recent entries — last 2 minutes
                # Syslog format: "Apr  6 21:08:53 host sudo: ..."
                for ioc in IOC_LIST:
                    if re.search(r'\b' + re.escape(ioc) + r'\b', line_lo):
                        _add(ioc, logfile.split("/")[-1])
                        break
        except Exception:
            pass

    # ── Source d: journalctl by process name ──────────────────
    # Query journal for entries where _COMM matches an IOC name.
    # Unlike a text grep this actually queries the structured
    # journal field, which is reliable.
    for ioc in IOC_LIST:
        out = run(
            f"journalctl _COMM={ioc} --since '-2min' "
            f"--no-pager -q 2>/dev/null | head -5",
            timeout=5
        )
        if out and "[error" not in out and out.strip():
            _add(ioc, "journalctl _COMM")

    return found


def _scan_shell_history() -> list:
    """
    Layer 3: Check recent bash/zsh history for IOC tool invocations.
    Covers cases where an attacker runs a tool from a login shell
    and the process exits before the agent's next scan cycle.

    Reads history files for all users with home directories.
    Only checks entries — does not modify or log passwords.
    """
    found   = []
    seen    = set()
    shells  = [".bash_history", ".zsh_history", ".sh_history"]

    user_homes = []
    try:
        import pwd
        for entry in pwd.getpwall():
            if entry.pw_dir and os.path.isdir(entry.pw_dir):
                user_homes.append(entry.pw_dir)
    except Exception:
        user_homes = [os.path.expanduser("~")]

    for home in set(user_homes):
        for hist_file in shells:
            hist_path = os.path.join(home, hist_file)
            if not os.path.exists(hist_path):
                continue
            try:
                # Only read the last 200 lines to avoid scanning old history
                hist_out = run(f"tail -200 {hist_path} 2>/dev/null")
                for line in hist_out.splitlines():
                    line_lo = line.lower().strip()
                    if not line_lo or line_lo.startswith("#"):
                        continue
                    for ioc in IOC_LIST:
                        if re.search(r'' + re.escape(ioc) + r'', line_lo):
                            label = f"{ioc} (via shell history)"
                            if label not in seen:
                                found.append(label)
                                seen.add(label)
                                log.info(
                                    f"IOC history: matched '{ioc}' "
                                    f"in {hist_path}"
                                )
                            break
            except Exception:
                pass

    return found


def collect_processes() -> dict:
    """
    Scan for IOC indicators across three layers:

    Layer 1 — Live process snapshot (psutil / ps aux)
              Catches persistent tools that are currently running.

    Layer 2 — Audit log scan (journalctl / auth.log, last 2 min)
              Catches short-lived processes that already exited.
              This is why nmap is detected even after it finishes.

    Layer 3 — Shell history scan (bash/zsh history, last 200 lines)
              Catches IOC tool usage that happened between heartbeats.

    Layer 4 — IOC cache (5-minute TTL)
              Any detection from layers 1-3 is cached for 5 minutes.
              Even if the next heartbeat misses the process, the cache
              keeps reporting it until the TTL expires.
    """
    security_found = []
    new_ioc_found  = []

    # ── Layer 1: live processes ───────────────────────────────
    live = _scan_live_processes()
    for entry in live:
        new_ioc_found.append(entry)
        _cache_ioc(entry)

    # Also collect security tools from live processes
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["name"]):
            try:
                name = (proc.info.get("name") or "").lower()
                if any(k in name for k in SECURITY_KEYWORDS):
                    security_found.append(proc.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # ── Layer 2: audit logs ───────────────────────────────────
    audit = _scan_audit_logs()
    for entry in audit:
        if entry not in new_ioc_found:
            new_ioc_found.append(entry)
        _cache_ioc(entry)

    # ── Layer 3: shell history ────────────────────────────────
    history = _scan_shell_history()
    for entry in history:
        if entry not in new_ioc_found:
            new_ioc_found.append(entry)
        _cache_ioc(entry)

    # ── Layer 4: cached detections (survive process exit) ─────
    cached = _flush_ioc_cache()
    all_iocs = list({*new_ioc_found, *cached})

    if all_iocs:
        log.warning(
            f"collect_processes: IOC DETECTED — {all_iocs} "
            f"(live={len(live)} audit={len(audit)} "
            f"history={len(history)} cached={len(cached)})"
        )

    return {
        "ioc_detected":        all_iocs,
        "security_processes":  list(set(security_found)),
        "hard_deny_triggered": len(all_iocs) > 0,
    }


def collect_network() -> dict:
    """Active network interfaces and VPN detection."""
    interfaces  = {}
    vpn_active  = False
    vpn_keywords = ["vpn", "tun", "tap", "wg", "nordvpn",
                    "expressvpn", "proton", "mullvad", "ppp"]

    if HAS_PSUTIL:
        for iface, addrs in psutil.net_if_addrs().items():
            ips  = [a.address for a in addrs if a.family.name == "AF_INET"]
            macs = [a.address for a in addrs if a.family.name == "AF_LINK"]
            if ips or macs:
                interfaces[iface] = {
                    "ips": ips, "mac": macs[0] if macs else ""
                }
            if any(k in iface.lower() for k in vpn_keywords):
                vpn_active = True
    else:
        ip_out = run("ip addr 2>/dev/null")
        interfaces["all"] = {"raw": ip_out[:500]}
        for line in ip_out.splitlines():
            for k in vpn_keywords:
                if k in line.lower():
                    vpn_active = True
                    break

    return {
        "interfaces": interfaces,
        "vpn_active": vpn_active,
    }


def collect_all() -> dict:
    """Collect all telemetry signals and return as a single dict."""
    return {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "platform":    "linux",
        "os":          collect_os_info(),
        "encryption":  collect_disk_encryption(),
        "antivirus":   collect_antivirus(),
        "firewall":    collect_firewall(),
        "patch":       collect_patch_status(),
        "screen_lock": collect_screen_lock(),
        "domain":      collect_domain(),
        "processes":   collect_processes(),
        "network":     collect_network(),
    }


# ── Portal communication ──────────────────────────────────────

def register_device(portal_url: str, hostname: str,
                    fingerprint: str) -> dict:
    if not HAS_REQUESTS:
        raise RuntimeError("requests package not installed — "
                           "pip3 install requests --break-system-packages")
    url  = portal_url.rstrip("/") + REGISTER_ENDPOINT
    resp = requests.post(
        url,
        json={
            "hostname":    hostname,
            "platform":    "linux",
            "fingerprint": fingerprint,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def send_heartbeat(portal_url: str, device_id: str,
                   secret: str, telemetry: dict) -> dict:
    if not HAS_REQUESTS:
        raise RuntimeError("requests not installed")

    payload_dict = {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "telemetry": telemetry,
    }
    payload_str = json.dumps(
        payload_dict, sort_keys=True,
        separators=(",", ":"), default=str
    )
    signature = hmac.new(
        secret.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    url  = portal_url.rstrip("/") + HEARTBEAT_ENDPOINT
    resp = requests.post(
        url,
        data=payload_str,
        headers={
            "Content-Type":       "application/json",
            "X-Device-ID":        device_id,
            "X-Device-Signature": signature,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def telemetry_hash(t: dict) -> str:
    return hashlib.sha256(
        json.dumps(t, sort_keys=True, default=str).encode()
    ).hexdigest()


# ── Main loop ─────────────────────────────────────────────────

def _background_ioc_scanner() -> None:
    """
    Background thread: scan for IOC processes every IOC_SCAN_INTERVAL
    seconds and write hits to the disk cache.

    Running independently of the heartbeat loop means even a 2-second
    nmap scan is almost certain to be caught — the scanner fires every
    5 seconds so the process only needs to overlap with one scan window.

    This thread runs as a daemon so it exits automatically when the
    main process exits.
    """
    log.info(
        f"IOC scanner thread started — "
        f"scanning every {IOC_SCAN_INTERVAL}s"
    )
    while True:
        try:
            hits = _scan_live_processes()
            if hits:
                for h in hits:
                    _cache_ioc(h)
                log.warning(
                    f"IOC scanner: detected {hits} — "
                    f"cached for next heartbeat"
                )
        except Exception as e:
            log.debug(f"IOC scanner error: {e}")
        time.sleep(IOC_SCAN_INTERVAL)


def run_agent(portal_url: str) -> None:
    log.info(f"Linux agent starting. Portal: {portal_url}")

    # Start background IOC scanner thread immediately — before registration
    # so no IOC activity is missed during the registration window.
    scanner_thread = threading.Thread(
        target=_background_ioc_scanner,
        name="ioc-scanner",
        daemon=True
    )
    scanner_thread.start()
    log.info("Background IOC scanner thread started")

    cfg = load_config()

    if not cfg.get("device_id") or not cfg.get("secret"):
        log.info("No saved registration — registering with portal...")
        fp, hostname, mac = get_stable_fingerprint()
        log.info(f"Fingerprint: {fp}  hostname: {hostname}  MAC: {mac}")
        try:
            reg = register_device(portal_url, hostname, fp)
            cfg = {
                "device_id":   reg["device_id"],
                "secret":      reg["secret"],
                "portal_url":  portal_url,
                "hostname":    hostname,
                "fingerprint": fp,
            }
            save_config(cfg)
            log.info(f"Registered as {cfg['device_id']}")
        except Exception as e:
            log.error(f"Registration failed: {e} — retrying in 30s")
            time.sleep(30)
            return run_agent(portal_url)
    else:
        log.info(f"Loaded existing registration: {cfg['device_id']}")

    device_id         = cfg["device_id"]
    secret            = cfg["secret"]
    last_hash         = ""
    consecutive_fails = 0
    MAX_FAILS         = 5

    log.info(
        f"Heartbeat loop started. device_id={device_id} "
        f"interval={HEARTBEAT_INTERVAL}s"
    )

    while True:
        try:
            telemetry = collect_all()
            curr_hash = telemetry_hash(telemetry)
            changed   = curr_hash != last_hash

            result    = send_heartbeat(portal_url, device_id, secret, telemetry)

            score    = result.get("device_score", "--")
            status   = result.get("status", "--")
            warnings = result.get("session_warnings", [])

            if changed:
                log.info(
                    f"Heartbeat sent (telemetry changed) — "
                    f"score={score} status={status}"
                )
            else:
                log.debug(f"Heartbeat sent (unchanged) — score={score}")

            if warnings:
                for w in warnings:
                    log.warning(f"Portal warning: {w}")

            last_hash         = curr_hash
            consecutive_fails = 0

        except requests.exceptions.ConnectionError:
            consecutive_fails += 1
            lvl = log.error if consecutive_fails >= MAX_FAILS else log.warning
            lvl(
                f"Portal unreachable ({consecutive_fails} consecutive fails) — "
                f"will retry in {HEARTBEAT_INTERVAL}s"
            )
        except requests.exceptions.Timeout:
            consecutive_fails += 1
            log.warning(f"Portal timed out — retrying in {HEARTBEAT_INTERVAL}s")
        except Exception as e:
            consecutive_fails += 1
            log.error(f"Heartbeat failed: {e}")

        time.sleep(HEARTBEAT_INTERVAL)


# ── Entry point ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Zero Trust Linux Device Agent"
    )
    parser.add_argument(
        "--portal",
        default="http://192.168.0.101:5000",
        help="Portal base URL (default: http://192.168.0.101:5000)"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect and print telemetry once then exit (for testing)"
    )
    parser.add_argument(
        "--test-ioc",
        dest="test_ioc",
        action="store_true",
        help="Test each IOC detection layer individually and exit"
    )
    args = parser.parse_args()

    if args.once:
        import pprint
        log.info("--once mode: collecting telemetry and exiting")
        fp, hostname, mac = get_stable_fingerprint()
        print(f"\nFingerprint : {fp}")
        print(f"Hostname    : {hostname}")
        print(f"Primary MAC : {mac}\n")
        t = collect_all()
        pprint.pprint(t)
        return

    if args.test_ioc:
        print("\n=== IOC Detection Layer Test ===")
        print("Run an nmap scan in another terminal then check each layer:\n")

        print("[Layer 1] Live process snapshot:")
        live = _scan_live_processes()
        print(f"  Found: {live or 'none'}")

        print("\n[Layer 2a] /proc recent process scan:")
        # Run just the /proc part
        audit_all = _scan_audit_logs()
        print(f"  Found: {audit_all or 'none'}")

        print("\n[Layer 3] Shell history scan:")
        history = _scan_shell_history()
        print(f"  Found: {history or 'none'}")

        print("\n[Cache] Current IOC cache contents:")
        cached = _flush_ioc_cache()
        print(f"  Cached: {cached or 'empty'}")

        print("\n[Full] collect_processes() result:")
        import pprint
        pprint.pprint(collect_processes())

        print("\n[journalctl test] Direct nmap journal query:")
        out = run("journalctl _COMM=nmap --since '-5min' --no-pager -q 2>/dev/null | head -10")
        print(f"  {out or 'no entries'}")

        print("\n[ausearch test] auditd nmap query:")
        out = run("ausearch -ts recent -i 2>/dev/null | grep -i nmap | head -5")
        print(f"  {out or 'no entries (auditd may not be installed)'}")

        print("\n[syslog test] syslog nmap entries (last 5 min):")
        out = run("grep -i nmap /var/log/syslog 2>/dev/null | tail -5")
        print(f"  {out or 'none'}")

        print("\n[history test] Raw bash history check:")
        import pwd
        for entry in pwd.getpwall():
            hist = os.path.join(entry.pw_dir, ".bash_history")
            if os.path.exists(hist):
                out = run(f"grep -i nmap {hist} 2>/dev/null | tail -3")
                if out:
                    print(f"  {entry.pw_name}: {out}")
        return

    run_agent(args.portal)


if __name__ == "__main__":
    main()
