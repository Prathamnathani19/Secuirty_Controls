import json
import platform
import socket
import subprocess
import time
import hashlib
from pathlib import Path
import psutil
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_http_methods
from .models import IPBlockDecision


SERVICE_MAP = {
    "firewalld": "firewalld",
    "suricata": "suricata",
    "snort": "snort",
    "fail2ban": "fail2ban",
    "nginx": "nginx",
    "sshd": "sshd",
}


def run_command(command, timeout=5):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "command timed out",
            "returncode": -1,
        }

    except OSError as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
        }


def parse_active_zones(raw):
    zones = []
    current = None

    for line in raw.splitlines():
        if not line.strip():
            continue

        if not line.startswith((" ", "\t")):
            current = {
                "name": line.strip(),
                "interfaces": [],
            }
            zones.append(current)
            continue

        if current and line.strip().startswith("interfaces:"):
            interfaces = line.split(":", 1)[1].strip()

            if interfaces:
                current["interfaces"] = interfaces.split()

    return zones


def parse_zone_list(raw):
    zones = []

    for zone in raw.split():
        zones.append(zone)

    return zones


def get_zone_data(zone):
    result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--zone",
            zone,
            "--list-all",
        ]
    )

    if not result["success"]:
        return {
            "name": zone,
            "error": result["stderr"] or "unable to read zone",
        }

    data = {
        "name": zone,
        "target": None,
        "interfaces": [],
        "sources": [],
        "services": [],
        "ports": [],
        "protocols": [],
        "forward": False,
        "masquerade": False,
        "forward_ports": [],
        "source_ports": [],
        "icmp_blocks": [],
        "rich_rules": [],
    }

    section = None

    for line in result["stdout"].splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        # Lines belonging to a multi-line section must be handled
        # before generic key:value parsing. Forward-port entries
        # themselves contain ':' characters.
        if section == "forward_ports":
            if ":" not in stripped or stripped.startswith("rule "):
                section = None
            else:
                data["forward_ports"].append(stripped)
                continue

        if section == "source_ports":
            if ":" not in stripped or stripped.startswith("rule "):
                section = None
            else:
                data["source_ports"].append(stripped)
                continue

        if section == "icmp_blocks":
            if ":" not in stripped or stripped.startswith("rule "):
                section = None
            else:
                data["icmp_blocks"].append(stripped)
                continue

        if section == "rich_rules":
            if stripped.startswith("rule "):
                data["rich_rules"].append(stripped)
                continue
            section = None

        if ":" in stripped and not stripped.startswith("rule "):
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key == "target":
                data["target"] = value

            elif key == "interfaces":
                data["interfaces"] = (
                    value.split() if value else []
                )

            elif key == "sources":
                data["sources"] = (
                    value.split() if value else []
                )

            elif key == "services":
                data["services"] = (
                    value.split() if value else []
                )

            elif key == "ports":
                data["ports"] = (
                    value.split() if value else []
                )

            elif key == "protocols":
                data["protocols"] = (
                    value.split() if value else []
                )

            elif key == "forward":
                data["forward"] = (
                    value.lower() == "yes"
                )

            elif key == "masquerade":
                data["masquerade"] = (
                    value.lower() == "yes"
                )

            elif key == "forward-ports":
                section = "forward_ports"

            elif key == "source-ports":
                section = "source_ports"

            elif key == "icmp-blocks":
                section = "icmp_blocks"

            elif key == "rich rules":
                section = "rich_rules"

            continue

        if stripped.startswith("rule "):
            data["rich_rules"].append(stripped)

    # Use firewalld's dedicated commands for colon-heavy
    # forward-port and source-port entries. This avoids ambiguity
    # with the ':' characters inside NAT definitions.
    forward_ports = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--zone",
            zone,
            "--list-forward-ports",
        ]
    )

    if forward_ports["success"]:
        data["forward_ports"] = [
            line.strip()
            for line in forward_ports["stdout"].splitlines()
            if line.strip()
        ]

    source_ports = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--zone",
            zone,
            "--list-source-ports",
        ]
    )

    if source_ports["success"]:
        data["source_ports"] = [
            line.strip()
            for line in source_ports["stdout"].splitlines()
            if line.strip()
        ]

    return data



def auth_me(request):
    """
    Return the currently authenticated Django user.
    """
    if not request.user.is_authenticated:
        return JsonResponse({
            "authenticated": False,
            "user": None,
        })

    return JsonResponse({
        "authenticated": True,
        "user": {
            "id": request.user.id,
            "username": request.user.get_username(),
            "email": request.user.email,
            "is_staff": request.user.is_staff,
            "is_superuser": request.user.is_superuser,
        },
    })


@require_POST
def auth_login(request):
    """
    Authenticate a user using Django's built-in authentication system.
    """
    try:
        data = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({
            "authenticated": False,
            "error": "Invalid JSON request.",
        }, status=400)

    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return JsonResponse({
            "authenticated": False,
            "error": "Username and password are required.",
        }, status=400)

    user = authenticate(
        request,
        username=username,
        password=password,
    )

    if user is None:
        return JsonResponse({
            "authenticated": False,
            "error": "Invalid username or password.",
        }, status=401)

    if not user.is_active:
        return JsonResponse({
            "authenticated": False,
            "error": "User account is disabled.",
        }, status=403)

    login(request, user)

    return JsonResponse({
        "authenticated": True,
        "user": {
            "id": user.id,
            "username": user.get_username(),
            "email": user.email,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
        },
    })


@require_POST
def auth_logout(request):
    """
    Destroy the current Django session.
    """
    logout(request)

    return JsonResponse({
        "authenticated": False,
        "user": None,
    })



@ensure_csrf_cookie
def csrf_token_view(request):
    return JsonResponse({"csrf": True})


def health(request):
    return JsonResponse({
        "status": "ok",
        "service": "HPC Security Gateway API",
        "version": "0.1.0",
    })


def system_info(request):
    memory = psutil.virtual_memory()

    return JsonResponse({
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": {
            "logical": psutil.cpu_count(logical=True),
            "physical": psutil.cpu_count(logical=False),
            "usage_percent": psutil.cpu_percent(interval=0.2),
        },
        "memory": {
            "total_bytes": memory.total,
            "used_bytes": memory.used,
            "available_bytes": memory.available,
            "usage_percent": memory.percent,
        },
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    })


def _service_status(service):
    result = run_command(
        ["/usr/bin/systemctl", "is-active", service],
        timeout=3,
    )

    status = result["stdout"]

    return {
        "service": service,
        "active": status == "active",
        "status": status or "unknown",
    }


def services(request):
    return JsonResponse({
        "services": [
            _service_status(service)
            for service in SERVICE_MAP.values()
        ]
    })



def parse_fail2ban_jails(raw):
    for line in raw.splitlines():
        if "Jail list:" in line:
            value = line.split("Jail list:", 1)[1].strip()
            return [
                jail.strip()
                for jail in value.split(",")
                if jail.strip()
            ]

    return []


def parse_fail2ban_status(jail, raw):
    import re

    data = {
        "name": jail,
        "currently_failed": 0,
        "total_failed": 0,
        "currently_banned": 0,
        "total_banned": 0,
        "banned_ips": [],
        "file_list": [],
        "journal_matches": [],
        "error": None,
    }

    patterns = {
        "currently_failed": r"Currently failed:\s*(\d+)",
        "total_failed": r"Total failed:\s*(\d+)",
        "currently_banned": r"Currently banned:\s*(\d+)",
        "total_banned": r"Total banned:\s*(\d+)",
        "file_list": r"File list:\s*(.*)",
        "journal_matches": r"Journal matches:\s*(.*)",
        "banned_ips": r"Banned IP list:\s*(.*)",
    }

    for line in raw.splitlines():
        for key, pattern in patterns.items():
            match = re.search(pattern, line)

            if not match:
                continue

            value = match.group(1).strip()

            if key in {
                "currently_failed",
                "total_failed",
                "currently_banned",
                "total_banned",
            }:
                data[key] = int(value)

            elif key == "file_list":
                if value:
                    data["file_list"] = value.split()

            elif key == "journal_matches":
                if value:
                    data["journal_matches"] = [value]

            elif key == "banned_ips":
                if value:
                    data["banned_ips"] = value.split()

            break

    return data

def fail2ban_info(request):
    service = _service_status("fail2ban")

    status = run_command(
        [
            "/usr/bin/fail2ban-client",
            "status",
        ],
        timeout=5,
    )

    if not status["success"]:
        return JsonResponse({
            "service": service,
            "jails": [],
            "error": status["stderr"] or "Unable to query Fail2Ban",
        })

    jails = parse_fail2ban_jails(status["stdout"])
    jail_data = []

    for jail in jails:
        result = run_command(
            [
                "/usr/bin/fail2ban-client",
                "status",
                jail,
            ],
            timeout=5,
        )

        if result["success"]:
            jail_data.append(
                parse_fail2ban_status(
                    jail,
                    result["stdout"],
                )
            )
        else:
            jail_data.append({
                "name": jail,
                "currently_failed": 0,
                "total_failed": 0,
                "currently_banned": 0,
                "total_banned": 0,
                "banned_ips": [],
                "file_list": [],
                "journal_matches": [],
                "error": (
                    result["stderr"]
                    or "Unable to query jail"
                ),
            })

    return JsonResponse({
        "service": service,
        "jails": jail_data,
    })


def _read_log_tail(path, limit=50):
    try:
        result = run_command(
            ["/usr/bin/tail", "-n", str(limit), path],
            timeout=3,
        )

        if not result["success"]:
            return {
                "available": False,
                "lines": [],
                "error": result["stderr"] or "unable to read log",
            }

        lines = [
            line
            for line in result["stdout"].splitlines()
            if line.strip()
        ]

        return {
            "available": True,
            "lines": lines,
            "error": None,
        }

    except Exception as exc:
        return {
            "available": False,
            "lines": [],
            "error": str(exc),
        }


def _journal_tail(unit=None, limit=50):
    command = [
        "/usr/bin/journalctl",
        "--no-pager",
        "-n",
        str(limit),
    ]

    if unit:
        command.extend(["-u", unit])

    result = run_command(command, timeout=5)

    if not result["success"]:
        return {
            "available": False,
            "lines": [],
            "error": result["stderr"] or "unable to read journal",
        }

    return {
        "available": True,
        "lines": [
            line
            for line in result["stdout"].splitlines()
            if line.strip()
        ],
        "error": None,
    }



def _snort_alerts(limit=50):
    import glob
    import json
    from collections import deque

    # Read only a bounded tail from the active log and the
    # most recent rotated logs. This avoids loading hundreds
    # of MB of historical Snort alerts into memory.
    paths = ["/var/log/snort/alert_json.txt"]
    paths.extend(
        sorted(
            glob.glob("/var/log/snort/alert_json.txt.*"),
            reverse=True,
        )[:3]
    )

    records = []

    try:
        # A few thousand lines per file is more than enough to
        # find the latest Critical/High alerts while keeping
        # dashboard requests fast.
        tail_lines = max(limit * 20, 1000)

        for path in paths:
            try:
                with open(path, "r", errors="replace") as f:
                    lines = deque(f, maxlen=tail_lines)
            except OSError:
                continue

            for line in reversed(lines):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                priority = event.get("priority")

                if not isinstance(priority, int):
                    continue

                # Snort priority 1 = Critical, priority 2 = High.
                if priority == 1:
                    severity = "critical"
                elif priority == 2:
                    severity = "high"
                else:
                    continue

                records.append({
                    "timestamp": event.get("timestamp"),
                    "source": "snort",
                    "severity": severity,
                    "priority": priority,
                    "classification": event.get("class"),
                    "message": event.get("msg"),
                    "src_ip": event.get("src_addr"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dst_addr"),
                    "dest_port": event.get("dst_port"),
                    "protocol": event.get("proto"),
                    "action": event.get("action", "allow"),
                    "interface": event.get("iface"),
                    "service": event.get("service"),
                    "sid": event.get("sid"),
                    "gid": event.get("gid"),
                    "rev": event.get("rev"),
                    "rule": event.get("rule"),
                })

                if len(records) >= limit:
                    break

            if len(records) >= limit:
                break

        records.reverse()

        return {
            "available": True,
            "lines": records,
            "error": None,
        }

    except Exception as exc:
        return {
            "available": False,
            "lines": [],
            "error": str(exc),
        }

def _suricata_alerts(limit=50):
    path = "/var/log/suricata/eve.json"

    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return {
            "available": False,
            "lines": [],
            "error": str(exc),
        }

    records = []

    for line in reversed(lines):
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert") or {}

        signature = alert.get("signature")
        category = alert.get("category")
        severity_value = alert.get("severity")
        action = alert.get("action")

        try:
            severity_value = int(severity_value)
        except (TypeError, ValueError):
            severity_value = None

        if action == "blocked":
            severity = "blocked"
        elif severity_value == 1:
            severity = "critical"
        elif severity_value == 2:
            severity = "high"
        elif severity_value == 3:
            severity = "medium"
        elif severity_value == 4:
            severity = "low"
        else:
            severity = "alert"

        if action == "blocked":
            normalized_action = "blocked"
        elif action == "allowed":
            normalized_action = "allowed"
        else:
            normalized_action = "alert"

        record = {
            "timestamp": event.get("timestamp"),
            "source": "suricata",
            "severity": severity,
            "priority": severity_value,
            "classification": category,
            "message": signature or "Suricata alert",
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dest_ip": event.get("dest_ip"),
            "dest_port": event.get("dest_port"),
            "protocol": event.get("proto"),
            "action": normalized_action,
            "gid": alert.get("gid"),
            "signature_id": alert.get("signature_id"),
            "rev": alert.get("rev"),
        }

        records.append(record)

        if len(records) >= limit:
            break

    records.reverse()

    return {
        "available": True,
        "lines": records,
        "error": None,
    }


def logs_info(request):
    limit = 50

    try:
        requested = int(request.GET.get("limit", "50"))
        if 1 <= requested <= 200:
            limit = requested
    except (TypeError, ValueError):
        pass

    return JsonResponse({
        "sources": {
            "suricata": _suricata_alerts(limit),
            "snort": _snort_alerts(limit),
            "ssh": _read_log_tail(
                "/var/log/secure",
                limit,
            ),
            "nginx_access": _read_log_tail(
                "/var/log/nginx/access.log",
                limit,
            ),
            "nginx_error": _read_log_tail(
                "/var/log/nginx/error.log",
                limit,
            ),
            "fail2ban": _journal_tail("fail2ban", limit),
            "firewalld": _journal_tail(
                "firewalld",
                limit,
            ),
            "system": _journal_tail(
                None,
                limit,
            ),
        },
    })

def firewall_info(request):
    state = run_command(
        ["/usr/bin/firewall-cmd", "--state"]
    )

    active_zones = run_command(
        ["/usr/bin/firewall-cmd", "--get-active-zones"]
    )

    zones = run_command(
        ["/usr/bin/firewall-cmd", "--get-zones"]
    )

    active_zone_data = parse_active_zones(
        active_zones["stdout"]
    )

    zone_names = parse_zone_list(
        zones["stdout"]
    )

    zone_data = [
        get_zone_data(zone)
        for zone in zone_names
    ]

    return JsonResponse({
        "firewalld": {
            "running": (
                state["success"]
                and state["stdout"] == "running"
            ),
            "state": state["stdout"] or "unknown",
        },
        "active_zones": active_zone_data,
        "zones": zone_data,
    })
def _suricata_build_info():
    result = run_command(
        ["/sbin/suricata", "--build-info"],
        timeout=5,
    )

    if not result["success"]:
        return {
            "version": None,
            "af_packet": False,
            "nfqueue": False,
            "unix_socket": False,
            "detection": False,
            "error": result["stderr"] or "unable to read Suricata build info",
        }

    version = None
    af_packet = False
    nfqueue = False
    unix_socket = False
    detection = False

    for line in result["stdout"].splitlines():
        stripped = line.strip()

        if stripped.startswith("This is Suricata version"):
            parts = stripped.split()
            if len(parts) >= 5:
                version = parts[4]

        elif "AF_PACKET support:" in stripped:
            af_packet = stripped.endswith("yes")

        elif "NFQueue support:" in stripped:
            nfqueue = stripped.endswith("yes")

        elif "Unix socket enabled:" in stripped:
            unix_socket = stripped.endswith("yes")

        elif "Detection enabled:" in stripped:
            detection = stripped.endswith("yes")

    return {
        "version": version,
        "af_packet": af_packet,
        "nfqueue": nfqueue,
        "unix_socket": unix_socket,
        "detection": detection,
    }


def _suricata_stats():
    result = run_command(
        [
            "/usr/bin/tail",
            "-n",
            "500",
            "/var/log/suricata/eve.json",
        ],
        timeout=5,
    )

    empty = {
        "uptime": None,
        "packets": None,
        "bytes": None,
        "accepted": None,
        "blocked": None,
        "rejected": None,
        "signature_drops": None,
        "flow_drops": None,
        "nfq_errors": None,
        "stream_midstream": None,
        "rules_loaded": None,
    }

    if not result["success"]:
        return empty

    latest_stats = None

    for line in reversed(result["stdout"].splitlines()):
        try:
            event = json.loads(line)
            if event.get("event_type") == "stats":
                latest_stats = event.get("stats", {})
                break
        except json.JSONDecodeError:
            continue

    if not latest_stats:
        return empty

    ips = latest_stats.get("ips", {})
    decoder = latest_stats.get("decoder", {})
    detect = latest_stats.get("detect", {})
    engines = detect.get("engines", [])

    rules_loaded = engines[0].get("rules_loaded") if engines else None

    drop_reason = latest_stats.get("drop_reason", {})

    ips_drop_reason = ips.get("drop_reason", {})

    signature_drops = (
        ips_drop_reason.get("rules")
        if isinstance(ips_drop_reason.get("rules"), int)
        else 0
    )

    flow_drops = (
        ips_drop_reason.get("flow_drop")
        if isinstance(ips_drop_reason.get("flow_drop"), int)
        else 0
    )

    nfq_errors = (
        ips_drop_reason.get("nfq_error")
        if isinstance(ips_drop_reason.get("nfq_error"), int)
        else 0
    )

    stream_midstream = (
        ips_drop_reason.get("stream_midstream")
        if isinstance(ips_drop_reason.get("stream_midstream"), int)
        else 0
    )

    return {
        "uptime": latest_stats.get("uptime"),
        "packets": decoder.get("pkts"),
        "bytes": decoder.get("bytes"),
        "accepted": ips.get("accepted"),
        "blocked": ips.get("blocked"),
        "rejected": ips.get("rejected"),
        "signature_drops": signature_drops,
        "flow_drops": flow_drops,
        "nfq_errors": nfq_errors,
        "stream_midstream": stream_midstream,
        "rules_loaded": rules_loaded,
    }



# ---------------------------------------------------------------------------
# Snort custom rule management
# ---------------------------------------------------------------------------

SNORT_CUSTOM_RULES_PATH = "/usr/local/snort/etc/snort/rules/custom.rules"
SNORT_CONFIG_PATH = "/usr/local/snort/etc/snort/snort.lua"
SNORT_BIN = "/usr/local/snort/bin/snort"
SNORT_DAQ_DIR = "/usr/local/libdaq/lib/daq"
SNORT_CUSTOM_SID_MIN = 1000000
SNORT_CUSTOM_SID_MAX = 1999999


def _snort_custom_rule_lines():
    path = Path(SNORT_CUSTOM_RULES_PATH)

    try:
        if not path.exists():
            return []

        return [
            line.strip()
            for line in path.read_text(errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError:
        return []


def _snort_custom_rule_sid(rule):
    import re

    match = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule, re.IGNORECASE)

    if not match:
        return None

    return int(match.group(1))


def _snort_existing_sids():
    sids = set()

    # Custom rules
    for rule in _snort_custom_rule_lines():
        sid = _snort_custom_rule_sid(rule)
        if sid is not None:
            sids.add(sid)

    # Community rules
    community = Path(
        "/usr/local/snort/etc/snort/rules/community/snort3-community.rules"
    )

    try:
        import re

        if community.exists():
            for line in community.read_text(errors="replace").splitlines():
                sid = _snort_custom_rule_sid(line)
                if sid is not None:
                    sids.add(sid)
    except OSError:
        pass

    return sids


def _snort_next_custom_sid():
    used = _snort_existing_sids()

    for sid in range(SNORT_CUSTOM_SID_MIN, SNORT_CUSTOM_SID_MAX + 1):
        if sid not in used:
            return sid

    return None


def _snort_validate_custom_rule(rule):
    import re

    if not isinstance(rule, str):
        return False, "Rule must be a string."

    rule = rule.strip()

    if not rule:
        return False, "Rule cannot be empty."

    if "\n" in rule or "\r" in rule:
        return False, "Rule must be a single line."

    sid = _snort_custom_rule_sid(rule)

    if sid is None:
        return False, "Rule must contain a valid sid option."

    if not (
        SNORT_CUSTOM_SID_MIN
        <= sid
        <= SNORT_CUSTOM_SID_MAX
    ):
        return False, (
            f"SID must be between "
            f"{SNORT_CUSTOM_SID_MIN} and {SNORT_CUSTOM_SID_MAX}."
        )

    # Only administrator-managed Snort rule actions are accepted.
    if not re.match(
        r"^(alert|drop|reject)\s+",
        rule,
        re.IGNORECASE,
    ):
        return False, "Rule action must be alert, drop, or reject."

    # Basic rule structure check.
    if "(" not in rule or ")" not in rule:
        return False, "Rule options must be enclosed in parentheses."

    if not re.search(r"\bmsg\s*:", rule, re.IGNORECASE):
        return False, "Rule must contain a msg option."

    if not re.search(r"\brev\s*:\s*\d+\s*;", rule, re.IGNORECASE):
        return False, "Rule must contain a rev option."

    if sid in _snort_existing_sids():
        return False, f"SID {sid} is already in use."

    return True, None


def _snort_validate_configuration():
    result = run_command(
        [
            SNORT_BIN,
            "--daq-dir",
            SNORT_DAQ_DIR,
            "-T",
            "-c",
            SNORT_CONFIG_PATH,
        ],
        timeout=30,
    )

    if not result["success"]:
        return False, result["stderr"] or result["stdout"]

    return True, None


def _snort_reload():
    result = run_command(
        ["systemctl", "reload", "snort"],
        timeout=15,
    )

    if not result["success"]:
        return False, result["stderr"] or result["stdout"]

    time.sleep(1)

    status = _service_status("snort")

    if not status.get("active"):
        return False, "Snort is not active after reload."

    return True, None


def _snort_write_custom_rules(rules):
    path = Path(SNORT_CUSTOM_RULES_PATH)
    temp = path.with_name(path.name + ".tmp")

    try:
        content = ""
        if rules:
            content = "\n".join(rules) + "\n"

        temp.write_text(content)
        temp.chmod(0o644)
        temp.replace(path)
        return True, None

    except OSError as exc:
        try:
            if temp.exists():
                temp.unlink()
        except OSError:
            pass

        return False, str(exc)


def _snort_custom_rule_apply(new_rules):
    old_rules = _snort_custom_rule_lines()

    ok, error = _snort_write_custom_rules(new_rules)

    if not ok:
        return False, error

    ok, error = _snort_validate_configuration()

    if not ok:
        _snort_write_custom_rules(old_rules)
        return False, f"Snort validation failed: {error}"

    ok, error = _snort_reload()

    if not ok:
        _snort_write_custom_rules(old_rules)
        _snort_validate_configuration()
        _snort_reload()
        return False, f"Snort reload failed: {error}"

    return True, None


def snort_custom_rules(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse(
            {"success": False, "error": "Administrator access required."},
            status=403,
        )

    if request.method == "GET":
        rules = []

        for rule in _snort_custom_rule_lines():
            sid = _snort_custom_rule_sid(rule)

            if sid is not None:
                rules.append({
                    "sid": sid,
                    "rule": rule,
                })

        rules.sort(key=lambda item: item["sid"])

        return JsonResponse({
            "available": True,
            "path": SNORT_CUSTOM_RULES_PATH,
            "sid_min": SNORT_CUSTOM_SID_MIN,
            "sid_max": SNORT_CUSTOM_SID_MAX,
            "count": len(rules),
            "rules": rules,
            "error": None,
        })

    if request.method == "POST":
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON."},
                status=400,
            )

        rule = payload.get("rule")

        valid, error = _snort_validate_custom_rule(rule)

        if not valid:
            return JsonResponse(
                {"success": False, "error": error},
                status=400,
            )

        rules = _snort_custom_rule_lines()
        rules.append(rule.strip())

        ok, error = _snort_custom_rule_apply(rules)

        if not ok:
            return JsonResponse(
                {"success": False, "error": error},
                status=400,
            )

        return JsonResponse({
            "success": True,
            "message": "Snort custom rule added successfully.",
            "sid": _snort_custom_rule_sid(rule),
            "rule": rule.strip(),
        }, status=201)

    return JsonResponse(
        {"success": False, "error": "Method not allowed."},
        status=405,
    )


@require_POST
def snort_custom_rule_validate(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse(
            {"success": False, "error": "Administrator access required."},
            status=403,
        )

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON."},
            status=400,
        )

    rule = payload.get("rule")

    # For validation, allow the caller to provide an automatically generated
    # SID. If no SID exists, allocate one.
    if isinstance(rule, str) and "sid:" not in rule.lower():
        sid = _snort_next_custom_sid()

        if sid is None:
            return JsonResponse(
                {
                    "success": False,
                    "valid": False,
                    "error": "No unused custom SID is available.",
                },
                status=400,
            )

        rule = rule.rstrip()
        if rule.endswith(")"):
            pos = rule.rfind(")")
            rule = (
                rule[:pos]
                + f" sid:{sid}; rev:1;"
                + rule[pos:]
            )

    valid, error = _snort_validate_custom_rule(rule)

    if not valid:
        return JsonResponse({
            "success": True,
            "valid": False,
            "rule": rule,
            "error": error,
        })

    # Candidate-aware validation: temporarily validate current + candidate,
    # then restore the original file. No reload occurs here.
    current_rules = _snort_custom_rule_lines()
    candidate_rules = current_rules + [rule.strip()]

    old_rules = current_rules[:]

    ok, write_error = _snort_write_custom_rules(candidate_rules)

    if not ok:
        return JsonResponse({
            "success": True,
            "valid": False,
            "rule": rule,
            "error": write_error,
        })

    try:
        config_ok, config_error = _snort_validate_configuration()
    finally:
        _snort_write_custom_rules(old_rules)

    if not config_ok:
        return JsonResponse({
            "success": True,
            "valid": False,
            "rule": rule,
            "error": config_error,
        })

    return JsonResponse({
        "success": True,
        "valid": True,
        "rule": rule,
        "error": None,
    })


@require_http_methods(["DELETE"])
def snort_custom_rule_detail(request, sid):
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse(
            {"success": False, "error": "Administrator access required."},
            status=403,
        )

    try:
        sid = int(sid)
    except (TypeError, ValueError):
        return JsonResponse(
            {"success": False, "error": "Invalid SID."},
            status=400,
        )

    rules = _snort_custom_rule_lines()

    remaining = []
    found = False

    for rule in rules:
        rule_sid = _snort_custom_rule_sid(rule)

        if rule_sid == sid:
            found = True
            continue

        remaining.append(rule)

    if not found:
        return JsonResponse(
            {"success": False, "error": f"Custom rule SID {sid} not found."},
            status=404,
        )

    ok, error = _snort_custom_rule_apply(remaining)

    if not ok:
        return JsonResponse(
            {"success": False, "error": error},
            status=400,
        )

    return JsonResponse({
        "success": True,
        "message": f"Snort custom rule SID {sid} deleted successfully.",
        "sid": sid,
    })

def snort_info(request):
    alerts = _snort_alerts()

    return JsonResponse({
        "service": {
            "service": "snort",
            "active": _service_status("snort")["active"],
            "status": _service_status("snort")["status"],
        },
        "alerts": alerts,
    })


def suricata_info(request):
    service = _service_status("suricata")
    build = _suricata_build_info()
    stats = _suricata_stats()
    alerts = _suricata_alerts()

    return JsonResponse({
        "service": service,
        "build": build,
        "stats": stats,
        "alerts": alerts,
    })


def _suricata_rule_inventory():
    path = "/var/lib/suricata/rules/suricata.rules"

    inventory = {
        "available": False,
        "path": path,
        "total_rules": 0,
        "alert_rules": 0,
        "drop_rules": 0,
        "reject_rules": 0,
        "disabled_rules": 0,
        "file_size": None,
        "modified": None,
        "error": None,
    }

    try:
        stat_info = __import__("os").stat(path)

        inventory["available"] = True
        inventory["file_size"] = stat_info.st_size
        inventory["modified"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S%z",
            time.localtime(stat_info.st_mtime),
        )

        with open(path, "r", errors="replace") as rules_file:
            for line in rules_file:
                stripped = line.strip()

                if not stripped:
                    continue

                if stripped.startswith("#"):
                    if stripped[1:].lstrip().startswith(
                        ("alert ", "drop ", "reject ")
                    ):
                        inventory["disabled_rules"] += 1
                    continue

                if stripped.startswith("alert "):
                    inventory["alert_rules"] += 1
                elif stripped.startswith("drop "):
                    inventory["drop_rules"] += 1
                elif stripped.startswith("reject "):
                    inventory["reject_rules"] += 1

        inventory["total_rules"] = (
            inventory["alert_rules"]
            + inventory["drop_rules"]
            + inventory["reject_rules"]
        )

    except OSError as exc:
        inventory["error"] = str(exc)

    return inventory


def _suricata_update_status():
    result = {
        "source": "ET Open",
        "managed_drop_rules": 0,
        "total_drop_rules": 0,
        "last_update": None,
        "last_update_status": "unknown",
        "validation": "unknown",
        "reload": "unknown",
        "automatic_update": "enabled",
        "error": None,
    }

    try:
        drop_conf = "/etc/suricata/drop.conf"

        with open(drop_conf, "r", errors="replace") as f:
            result["managed_drop_rules"] = sum(
                1
                for line in f
                if line.strip() and not line.strip().startswith("#")
            )

        rules_path = "/var/lib/suricata/rules/suricata.rules"

        with open(rules_path, "r", errors="replace") as f:
            result["total_drop_rules"] = sum(
                1 for line in f if line.startswith("drop ")
            )

        log_path = "/var/log/suricata/safe-update.log"

        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()

        for line in reversed(lines):
            if "===== Suricata safe update completed =====" in line:
                result["last_update"] = line.split(
                    " =====", 1
                )[0].strip()
                result["last_update_status"] = "success"
                break

        for line in reversed(lines):
            if "Suricata validation PASSED" in line:
                result["validation"] = "passed"
                break
            if "Suricata validation FAILED" in line:
                result["validation"] = "failed"
                break

        for line in reversed(lines):
            if "Suricata reload successful" in line:
                result["reload"] = "successful"
                break
            if "Suricata reload failed" in line:
                result["reload"] = "failed"
                break

    except OSError as exc:
        result["error"] = str(exc)

    return result


def suricata_rules(request):
    if request.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    return JsonResponse({
        "rules": _suricata_rule_inventory(),
        "update": _suricata_update_status(),
    })


def _parse_suricata_rule(line, line_number):
    import re

    match = re.match(
        r'^\s*(alert|drop|reject)\s+(\S+)\s+(.+?)\s+\((.*)\)\s*$',
        line,
    )

    if not match:
        return None

    action, protocol, header_rest, options = match.groups()

    header_match = re.match(
        r'(.+?)\s+(\S+)\s+(->|<>)\s+(.+?)\s+(\S+)\s*$',
        header_rest,
    )

    if not header_match:
        return None

    source, source_port, direction, destination, destination_port = (
        header_match.groups()
    )

    def option_value(name):
        pattern = rf'{name}:"((?:[^"\\]|\\.)*)"'
        found = re.search(pattern, options)
        return found.group(1) if found else None

    def numeric_option(name):
        found = re.search(rf'{name}:(\d+)', options)
        return int(found.group(1)) if found else None

    return {
        "line": line_number,
        "action": action,
        "protocol": protocol,
        "source": source,
        "source_port": source_port,
        "direction": direction,
        "destination": destination,
        "destination_port": destination_port,
        "message": option_value("msg"),
        "sid": numeric_option("sid"),
        "rev": numeric_option("rev"),
        "classtype": option_value("classtype"),
    }

def _suricata_rule_list(
    search="",
    action="",
    protocol="",
    page=1,
    limit=50,
):
    path = "/var/lib/suricata/rules/suricata.rules"

    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50

    limit = min(max(limit, 1), 100)

    search = (search or "").strip().lower()
    action = (action or "").strip().lower()
    protocol = (protocol or "").strip().lower()

    start_index = (page - 1) * limit
    matched = 0
    returned = []

    try:
        with open(path, "r", errors="replace") as rules_file:
            for line_number, line in enumerate(rules_file, start=1):
                stripped = line.strip()

                # Ignore empty lines and commented/disabled rules.
                if not stripped or stripped.startswith("#"):
                    continue

                # Only process active Suricata rules.
                if not stripped.startswith(("alert ", "drop ", "reject ")):
                    continue

                rule = _parse_suricata_rule(
                    stripped,
                    line_number,
                )

                if rule is None:
                    continue

                # Action filter.
                if action and rule["action"].lower() != action:
                    continue

                # Protocol filter.
                if protocol and rule["protocol"].lower() != protocol:
                    continue

                # Explicit searchable fields.
                if search:
                    searchable_fields = (
                        rule.get("message"),
                        rule.get("sid"),
                        rule.get("rev"),
                        rule.get("action"),
                        rule.get("protocol"),
                        rule.get("source"),
                        rule.get("source_port"),
                        rule.get("direction"),
                        rule.get("destination"),
                        rule.get("destination_port"),
                        rule.get("classtype"),
                    )

                    searchable = " ".join(
                        str(value)
                        for value in searchable_fields
                        if value is not None
                    ).lower()

                    # Match complete search tokens rather than arbitrary
                    # substrings inside unrelated words.
                    import re

                    search_pattern = rf"(?<![A-Za-z0-9_]){re.escape(search)}(?![A-Za-z0-9_])"

                    if not re.search(search_pattern, searchable, re.IGNORECASE):
                        continue

                # Pagination.
                if matched >= start_index and len(returned) < limit:
                    returned.append(rule)

                matched += 1

    except OSError as exc:
        return {
            "available": False,
            "page": page,
            "limit": limit,
            "total_matches": 0,
            "rules": [],
            "error": str(exc),
        }

    return {
        "available": True,
        "page": page,
        "limit": limit,
        "total_matches": matched,
        "rules": returned,
        "error": None,
    }

def suricata_rule_list(request):
    if request.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    result = _suricata_rule_list(
        search=request.GET.get("search", ""),
        action=request.GET.get("action", ""),
        protocol=request.GET.get("protocol", ""),
        page=request.GET.get("page", "1"),
        limit=request.GET.get("limit", "50"),
    )

    return JsonResponse({
        "rules": result,
    })


# =========================================================
# Firewall Rich Rule CRUD API
# =========================================================

def _firewall_json_body(request):
    try:
        body = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return None, JsonResponse(
            {"error": "Invalid JSON request body"},
            status=400,
        )

    if not isinstance(body, dict):
        return None, JsonResponse(
            {"error": "JSON body must be an object"},
            status=400,
        )

    return body, None


def _firewall_authenticated(request):
    if not request.user.is_authenticated:
        return JsonResponse(
            {"error": "Authentication required"},
            status=401,
        )

    if not request.user.is_staff:
        return JsonResponse(
            {"error": "Administrative privileges required"},
            status=403,
        )

    return None


def _firewall_zone_exists(zone):
    result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--get-zones",
        ]
    )

    if not result["success"]:
        return False

    return zone in result["stdout"].split()


def _rich_rule_id(rule):
    return hashlib.sha256(
        rule.encode("utf-8")
    ).hexdigest()[:16]


def _get_rich_rules(zone):
    result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--zone",
            zone,
            "--list-rich-rules",
        ]
    )

    if not result["success"]:
        return None, result["stderr"] or "Unable to read rich rules"

    rules = [
        line.strip()
        for line in result["stdout"].splitlines()
        if line.strip()
    ]

    return rules, None


def _validate_rich_rule(rule):
    if not isinstance(rule, str):
        return "rule must be a string"

    rule = rule.strip()

    if not rule:
        return "rule cannot be empty"

    if len(rule) > 4096:
        return "rule is too long"

    if not rule.startswith("rule "):
        return 'rule must start with "rule "'

    return None



def _build_form_firewall_rule(body):
    """Build a firewalld rich rule from structured GUI fields."""

    action = str(body.get("action", "accept")).strip().lower()
    family = str(body.get("family", "ipv4")).strip().lower()
    protocol = str(body.get("protocol", "tcp")).strip().lower()

    source_type = str(
        body.get("source_type", "any")
    ).strip().lower()

    source_address = str(
        body.get("source_address", "")
    ).strip()

    source_ipset = str(
        body.get("source_ipset", "")
    ).strip()

    source_not = bool(body.get("source_not", False))

    source_port = str(
        body.get("source_port", "")
    ).strip()

    destination_address = str(
        body.get("destination_address", "")
    ).strip()

    destination_port = str(
        body.get("destination_port", "")
    ).strip()

    priority = str(
        body.get("priority", "")
    ).strip()

    if action not in {"accept", "reject", "drop"}:
        return None, "Invalid action"

    if family not in {"ipv4", "ipv6"}:
        return None, "Invalid address family"

    if protocol not in {
        "tcp",
        "udp",
        "sctp",
        "icmp",
        "icmpv6",
    }:
        return None, "Invalid protocol"

    if protocol in {"icmp", "icmpv6"}:
        source_port = ""
        destination_port = ""

    if priority:
        try:
            priority_value = int(priority)
        except ValueError:
            return None, "Priority must be an integer"

        if not -32768 <= priority_value <= 32767:
            return None, "Priority must be between -32768 and 32767"

    parts = ["rule"]

    if priority:
        parts.append(f'priority="{priority}"')

    parts.append(f'family="{family}"')

    if source_type == "address":

        if not source_address:
            return None, "Source address is required"

        if source_not:
            parts.extend([
                "source",
                "NOT",
                f'address="{source_address}"',
            ])
        else:
            parts.append(
                f'source address="{source_address}"'
            )

    elif source_type == "ipset":

        if not source_ipset:
            return None, "Source IP set is required"

        if source_not:
            parts.extend([
                "source",
                "NOT",
                f'ipset="{source_ipset}"',
            ])
        else:
            parts.append(
                f'source ipset="{source_ipset}"'
            )

    elif source_type != "any":
        return None, "Invalid source type"

    if source_port:
        parts.append(
            f'source-port port="{source_port}"'
        )

    if destination_address:
        parts.append(
            f'destination address="{destination_address}"'
        )

    if destination_port:
        parts.append(
            f'port port="{destination_port}"'
        )

    parts.append(f'protocol="{protocol}"')
    parts.append(action)

    return " ".join(parts), None


def _firewall_ipsets():
    result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--get-ipsets",
        ],
        timeout=10,
    )

    if not result["success"]:
        return []

    return [
        line.strip()
        for line in result["stdout"].splitlines()
        if line.strip()
    ]


@require_http_methods(["GET", "POST"])
def firewall_rules(request):

    # GET is also protected so firewall configuration
    # is not exposed to unauthenticated users.
    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method == "GET":

        zone = request.GET.get("zone", "").strip()

        if not zone:
            return JsonResponse(
                {"error": "zone parameter is required"},
                status=400,
            )

        if not _firewall_zone_exists(zone):
            return JsonResponse(
                {"error": f"Unknown firewall zone: {zone}"},
                status=400,
            )

        rules, error = _get_rich_rules(zone)

        if error:
            return JsonResponse(
                {"error": error},
                status=500,
            )

        return JsonResponse(
            {
                "zone": zone,
                "rules": [
                    {
                        "id": _rich_rule_id(rule),
                        "rule": rule,
                    }
                    for rule in rules
                ],
            }
        )

    # -----------------------------------------------------
    # CREATE
    # -----------------------------------------------------

    body, error_response = _firewall_json_body(request)

    if error_response:
        return error_response

    zone = str(body.get("zone", "")).strip()

    # GUI form mode:
    # Build the firewalld rich rule from structured fields.
    #
    # Backward compatibility:
    # If "rule" is supplied directly, continue accepting it.
    if "rule" in body:
        rule = body.get("rule")
    else:
        rule, form_error = _build_form_firewall_rule(body)

        if form_error:
            return JsonResponse(
                {"error": form_error},
                status=400,
            )

    if not zone:
        return JsonResponse(
            {"error": "zone is required"},
            status=400,
        )

    if not _firewall_zone_exists(zone):
        return JsonResponse(
            {"error": f"Unknown firewall zone: {zone}"},
            status=400,
        )

    rule_error = _validate_rich_rule(rule)

    if rule_error:
        return JsonResponse(
            {"error": rule_error},
            status=400,
        )

    rule = rule.strip()

    existing_rules, error = _get_rich_rules(zone)

    if error:
        return JsonResponse(
            {"error": error},
            status=500,
        )

    if rule in existing_rules:
        return JsonResponse(
            {
                "error": "Rule already exists",
                "id": _rich_rule_id(rule),
            },
            status=409,
        )

    add = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--zone",
            zone,
            "--add-rich-rule",
            rule,
        ],
        timeout=10,
    )

    if not add["success"]:
        return JsonResponse(
            {
                "error": add["stderr"]
                or "Unable to add firewall rule",
            },
            status=400,
        )

    reload_result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--reload",
        ],
        timeout=15,
    )

    if not reload_result["success"]:

        run_command(
            [
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--zone",
                zone,
                "--remove-rich-rule",
                rule,
            ],
            timeout=10,
        )

        return JsonResponse(
            {
                "error": reload_result["stderr"]
                or "Firewall reload failed; change rolled back",
            },
            status=500,
        )

    return JsonResponse(
        {
            "success": True,
            "zone": zone,
            "rule": rule,
            "id": _rich_rule_id(rule),
        },
        status=201,
    )


@require_http_methods(["PUT", "DELETE"])
def firewall_rule_detail(request, rule_id):

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    body = {}

    if request.method == "PUT":

        body, error_response = _firewall_json_body(request)

        if error_response:
            return error_response

    zone = str(
        body.get(
            "zone",
            request.GET.get("zone", ""),
        )
    ).strip()

    if not zone:
        return JsonResponse(
            {"error": "zone is required"},
            status=400,
        )

    if not _firewall_zone_exists(zone):
        return JsonResponse(
            {"error": f"Unknown firewall zone: {zone}"},
            status=400,
        )

    rules, error = _get_rich_rules(zone)

    if error:
        return JsonResponse(
            {"error": error},
            status=500,
        )

    old_rule = next(
        (
            rule
            for rule in rules
            if _rich_rule_id(rule) == rule_id
        ),
        None,
    )

    if old_rule is None:
        return JsonResponse(
            {
                "error": "Firewall rule not found",
                "id": rule_id,
            },
            status=404,
        )

    # -----------------------------------------------------
    # DELETE
    # -----------------------------------------------------

    if request.method == "DELETE":

        remove = run_command(
            [
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--zone",
                zone,
                "--remove-rich-rule",
                old_rule,
            ],
            timeout=10,
        )

        if not remove["success"]:
            return JsonResponse(
                {
                    "error": remove["stderr"]
                    or "Unable to delete firewall rule",
                },
                status=400,
            )

        reload_result = run_command(
            [
                "/usr/bin/firewall-cmd",
                "--reload",
            ],
            timeout=15,
        )

        if not reload_result["success"]:

            run_command(
                [
                    "/usr/bin/firewall-cmd",
                    "--permanent",
                    "--zone",
                    zone,
                    "--add-rich-rule",
                    old_rule,
                ],
                timeout=10,
            )

            return JsonResponse(
                {
                    "error": reload_result["stderr"]
                    or "Firewall reload failed; deletion rolled back",
                },
                status=500,
            )

        return JsonResponse(
            {
                "success": True,
                "deleted": {
                    "id": rule_id,
                    "zone": zone,
                    "rule": old_rule,
                },
            }
        )

    # -----------------------------------------------------
    # UPDATE
    # -----------------------------------------------------

    new_rule = body.get("rule")

    rule_error = _validate_rich_rule(new_rule)

    if rule_error:
        return JsonResponse(
            {"error": rule_error},
            status=400,
        )

    new_rule = new_rule.strip()

    if new_rule == old_rule:
        return JsonResponse(
            {
                "success": True,
                "id": rule_id,
                "zone": zone,
                "rule": new_rule,
            }
        )

    if new_rule in rules:
        return JsonResponse(
            {
                "error": "The new rule already exists",
                "id": _rich_rule_id(new_rule),
            },
            status=409,
        )

    # Remove old rule.
    remove = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--zone",
            zone,
            "--remove-rich-rule",
            old_rule,
        ],
        timeout=10,
    )

    if not remove["success"]:
        return JsonResponse(
            {
                "error": remove["stderr"]
                or "Unable to remove existing firewall rule",
            },
            status=400,
        )

    # Add new rule.
    add = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--zone",
            zone,
            "--add-rich-rule",
            new_rule,
        ],
        timeout=10,
    )

    if not add["success"]:

        # Restore original rule.
        run_command(
            [
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--zone",
                zone,
                "--add-rich-rule",
                old_rule,
            ],
            timeout=10,
        )

        return JsonResponse(
            {
                "error": add["stderr"]
                or "Unable to add replacement rule; original restored",
            },
            status=400,
        )

    reload_result = run_command(
        [
            "/usr/bin/firewall-cmd",
            "--reload",
        ],
        timeout=15,
    )

    if not reload_result["success"]:

        # Remove replacement.
        run_command(
            [
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--zone",
                zone,
                "--remove-rich-rule",
                new_rule,
            ],
            timeout=10,
        )

        # Restore original.
        run_command(
            [
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--zone",
                zone,
                "--add-rich-rule",
                old_rule,
            ],
            timeout=10,
        )

        return JsonResponse(
            {
                "error": reload_result["stderr"]
                or "Firewall reload failed; original rule restored",
            },
            status=500,
        )

    return JsonResponse(
        {
            "success": True,
            "id": _rich_rule_id(new_rule),
            "old_id": rule_id,
            "zone": zone,
            "rule": new_rule,
        }
    )
# ---------------------------------------------------------------------------
# HPC blocked IP management
# ---------------------------------------------------------------------------

def _hpc_blocked_ipset_entries():
    """Return current entries from the firewalld hpc_blocked_ips ipset."""
    import subprocess

    result = subprocess.run(
        [
            "firewall-cmd",
            "--ipset=hpc_blocked_ips",
            "--get-entries",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Unable to read hpc_blocked_ips"
        )

    output = result.stdout.strip()

    if not output:
        return []

    return sorted(
        {
            entry.strip()
            for entry in output.splitlines()
            if entry.strip()
        }
    )


def _hpc_blocked_ip_is_local(ip):
    """Prevent blocking an IP currently assigned to this server."""
    import ipaddress
    import subprocess

    try:
        requested_ip = ipaddress.ip_address(ip)
    except ValueError:
        return False

    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        return False

    for line in result.stdout.splitlines():
        parts = line.split()

        for part in parts:
            if "/" not in part:
                continue

            try:
                local_ip = ipaddress.ip_interface(part).ip
            except ValueError:
                continue

            if requested_ip == local_ip:
                return True

    return False


def _hpc_validate_blocked_ip(value):
    """Validate an IPv4 address supplied to the API."""
    import ipaddress

    if not isinstance(value, str):
        raise ValueError("IP address must be a string")

    value = value.strip()

    if not value:
        raise ValueError("IP address is required")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Invalid IP address")

    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported")

    if address.is_unspecified:
        raise ValueError("Unspecified address cannot be blocked")

    if address.is_multicast:
        raise ValueError("Multicast address cannot be blocked")

    if address.is_loopback:
        raise ValueError("Loopback address cannot be blocked")

    if address.is_reserved:
        raise ValueError("Reserved address cannot be blocked")

    return str(address)


def _hpc_firewall_block_ip(ip):
    """Add an IP to runtime and permanent firewalld ipset."""
    import subprocess

    commands = [
        [
            "firewall-cmd",
            "--permanent",
            "--ipset=hpc_blocked_ips",
            "--add-entry=" + ip,
        ],
        [
            "firewall-cmd",
            "--ipset=hpc_blocked_ips",
            "--add-entry=" + ip,
        ],
    ]

    for command in commands:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "firewalld operation failed"
            )


def _hpc_firewall_unblock_ip(ip):
    """Remove an IP from runtime and permanent firewalld ipset."""
    import subprocess

    commands = [
        [
            "firewall-cmd",
            "--permanent",
            "--ipset=hpc_blocked_ips",
            "--remove-entry=" + ip,
        ],
        [
            "firewall-cmd",
            "--ipset=hpc_blocked_ips",
            "--remove-entry=" + ip,
        ],
    ]

    for command in commands:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "firewalld operation failed"
            )


def hpc_blocked_ips(request):
    """
    GET  /api/suricata/blocked-ips/
    POST /api/suricata/blocked-ips/
    """
    from django.http import JsonResponse
    import json

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method == "GET":
        try:
            entries = _hpc_blocked_ipset_entries()

            return JsonResponse(
                {
                    "available": True,
                    "ipset": "hpc_blocked_ips",
                    "count": len(entries),
                    "blocked_ips": entries,
                    "error": None,
                }
            )

        except Exception as exc:
            return JsonResponse(
                {
                    "available": False,
                    "ipset": "hpc_blocked_ips",
                    "count": 0,
                    "blocked_ips": [],
                    "error": str(exc),
                },
                status=500,
            )

    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse(
            {"error": "Request body must contain valid JSON"},
            status=400,
        )

    try:
        ip = _hpc_validate_blocked_ip(payload.get("ip"))

        if _hpc_blocked_ip_is_local(ip):
            return JsonResponse(
                {
                    "error": (
                        "Refusing to block an IP currently assigned "
                        "to this server"
                    )
                },
                status=400,
            )

        existing = _hpc_blocked_ipset_entries()

        if ip in existing:
            return JsonResponse(
                {
                    "success": True,
                    "message": "IP is already blocked",
                    "ip": ip,
                    "already_blocked": True,
                }
            )

        previous_decision = (
            IPBlockDecision.objects.filter(
                ip_address=ip,
            ).first()
        )

        if (
            previous_decision
            and previous_decision.decision
            == IPBlockDecision.DECISION_UNBLOCKED
        ):
            previous_decision.decision = (
                IPBlockDecision.DECISION_PENDING
            )
            previous_decision.source = "FIREWALL"
            previous_decision.reason = (
                "Block request requires administrator "
                "confirmation because this IP was previously "
                "unblocked by an administrator"
            )
            previous_decision.save(
                update_fields=[
                    "decision",
                    "source",
                    "reason",
                    "updated_at",
                ]
            )

            return JsonResponse(
                {
                    "success": False,
                    "pending": True,
                    "message": (
                        "IP was previously unblocked and now "
                        "requires administrator approval before "
                        "it can be blocked again"
                    ),
                    "ip": ip,
                },
                status=202,
            )

        if (
            previous_decision
            and previous_decision.decision
            == IPBlockDecision.DECISION_PENDING
        ):
            return JsonResponse(
                {
                    "success": False,
                    "pending": True,
                    "message": (
                        "IP already has a pending administrator "
                        "block decision"
                    ),
                    "ip": ip,
                },
                status=202,
            )

        if (
            previous_decision
            and previous_decision.decision
            == IPBlockDecision.DECISION_DENIED
        ):
            return JsonResponse(
                {
                    "success": False,
                    "pending": True,
                    "message": (
                        "IP was previously denied and requires "
                        "a new administrator decision"
                    ),
                    "ip": ip,
                },
                status=202,
            )

        _hpc_firewall_block_ip(ip)

        IPBlockDecision.objects.update_or_create(
            ip_address=ip,
            defaults={
                "decision": IPBlockDecision.DECISION_APPROVED,
                "source": "FIREWALL",
                "reason": "Administrator block request",
            },
        )

        return JsonResponse(
            {
                "success": True,
                "message": "IP blocked successfully",
                "ip": ip,
                "already_blocked": False,
            },
            status=201,
        )

    except ValueError as exc:
        return JsonResponse(
            {"error": str(exc)},
            status=400,
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )


def hpc_unblock_ip(request, ip):
    """
    DELETE /api/suricata/blocked-ips/<ip>/
    """
    from django.http import JsonResponse

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "DELETE":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        ip = _hpc_validate_blocked_ip(ip)

        existing = _hpc_blocked_ipset_entries()

        if ip not in existing:
            return JsonResponse(
                {
                    "success": True,
                    "message": "IP is not currently blocked",
                    "ip": ip,
                    "already_unblocked": True,
                }
            )

        _hpc_firewall_unblock_ip(ip)

        IPBlockDecision.objects.update_or_create(
            ip_address=ip,
            defaults={
                "decision": IPBlockDecision.DECISION_UNBLOCKED,
                "source": "FIREWALL",
                "reason": "Administrator manually unblocked the IP",
            },
        )

        return JsonResponse(
            {
                "success": True,
                "message": "IP unblocked successfully",
                "ip": ip,
                "already_unblocked": False,
            }
        )

    except ValueError as exc:
        return JsonResponse(
            {"error": str(exc)},
            status=400,
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )


def hpc_block_decisions(request):
    """
    GET /api/suricata/block-decisions/

    Return administrator block decisions that are currently
    pending, along with their source and reason.
    """
    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "GET":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        decisions = (
            IPBlockDecision.objects
            .filter(
                decision=IPBlockDecision.DECISION_PENDING,
            )
            .values(
                "ip_address",
                "decision",
                "source",
                "reason",
                "created_at",
                "updated_at",
            )
        )

        pending = []

        for item in decisions:
            pending.append(
                {
                    "ip": item["ip_address"],
                    "decision": item["decision"],
                    "source": item["source"],
                    "reason": item["reason"],
                    "created_at": item["created_at"].isoformat(),
                    "updated_at": item["updated_at"].isoformat(),
                }
            )

        return JsonResponse(
            {
                "available": True,
                "count": len(pending),
                "decisions": pending,
                "error": None,
            }
        )

    except Exception as exc:
        return JsonResponse(
            {
                "available": False,
                "count": 0,
                "decisions": [],
                "error": str(exc),
            },
            status=500,
        )


def hpc_approve_block_decision(request, ip):
    """
    POST /api/suricata/block-decisions/<ip>/approve/

    Approve a pending block request and add the IP to the
    administrator-managed firewalld blocklist.
    """
    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        ip = _hpc_validate_blocked_ip(ip)

        if _hpc_blocked_ip_is_local(ip):
            return JsonResponse(
                {
                    "error": (
                        "Refusing to block an IP currently assigned "
                        "to this server"
                    )
                },
                status=400,
            )

        decision = (
            IPBlockDecision.objects
            .filter(ip_address=ip)
            .first()
        )

        if not decision:
            return JsonResponse(
                {
                    "error": "No block decision exists for this IP"
                },
                status=404,
            )

        if (
            decision.decision
            != IPBlockDecision.DECISION_PENDING
        ):
            return JsonResponse(
                {
                    "error": (
                        "IP does not have a pending block decision"
                    ),
                    "ip": ip,
                    "decision": decision.decision,
                },
                status=409,
            )

        existing = _hpc_blocked_ipset_entries()

        if ip not in existing:
            _hpc_firewall_block_ip(ip)

        decision.decision = (
            IPBlockDecision.DECISION_APPROVED
        )
        decision.source = decision.source or "FIREWALL"
        decision.reason = (
            "Administrator approved the pending block request"
        )
        decision.save(
            update_fields=[
                "decision",
                "source",
                "reason",
                "updated_at",
            ]
        )

        return JsonResponse(
            {
                "success": True,
                "message": "Pending block approved",
                "ip": ip,
                "decision": decision.decision,
            }
        )

    except ValueError as exc:
        return JsonResponse(
            {"error": str(exc)},
            status=400,
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )


def hpc_deny_block_decision(request, ip):
    """
    POST /api/suricata/block-decisions/<ip>/deny/

    Deny a pending block request. No firewall change is made.
    """
    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        ip = _hpc_validate_blocked_ip(ip)

        decision = (
            IPBlockDecision.objects
            .filter(ip_address=ip)
            .first()
        )

        if not decision:
            return JsonResponse(
                {
                    "error": "No block decision exists for this IP"
                },
                status=404,
            )

        if (
            decision.decision
            != IPBlockDecision.DECISION_PENDING
        ):
            return JsonResponse(
                {
                    "error": (
                        "IP does not have a pending block decision"
                    ),
                    "ip": ip,
                    "decision": decision.decision,
                },
                status=409,
            )

        decision.decision = (
            IPBlockDecision.DECISION_DENIED
        )
        decision.reason = (
            "Administrator denied the pending block request"
        )
        decision.save(
            update_fields=[
                "decision",
                "reason",
                "updated_at",
            ]
        )

        return JsonResponse(
            {
                "success": True,
                "message": "Pending block denied",
                "ip": ip,
                "decision": decision.decision,
            }
        )

    except ValueError as exc:
        return JsonResponse(
            {"error": str(exc)},
            status=400,
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )


# =========================================================
# Suricata Custom Rule CRUD API
# =========================================================

SURICATA_CUSTOM_RULES_PATH = "/etc/suricata/rules/custom.rules"
SURICATA_MANAGED_RULES_PATH = "/var/lib/suricata/rules/suricata.rules"
SURICATA_CUSTOM_SID_MIN = 1000000
SURICATA_CUSTOM_SID_MAX = 1999999


def _suricata_custom_rule_lines():
    try:
        with open(
            SURICATA_CUSTOM_RULES_PATH,
            "r",
            errors="replace",
        ) as rules_file:
            return rules_file.readlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RuntimeError(
            f"Unable to read custom rules: {exc}"
        )


def _suricata_custom_rules():
    import re

    rules = []

    for line_number, line in enumerate(
        _suricata_custom_rule_lines(),
        start=1,
    ):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        match = re.search(
            r"\bsid\s*:\s*(\d+)\s*;",
            stripped,
            re.IGNORECASE,
        )

        if not match:
            continue

        sid = int(match.group(1))

        rules.append(
            {
                "sid": sid,
                "line": line_number,
                "rule": stripped,
                "enabled": True,
            }
        )

    return rules


def _suricata_existing_sids():
    import re

    sids = set()

    for path in (
        SURICATA_MANAGED_RULES_PATH,
        SURICATA_CUSTOM_RULES_PATH,
    ):
        try:
            with open(
                path,
                "r",
                errors="replace",
            ) as rules_file:
                for line in rules_file:
                    match = re.search(
                        r"\bsid\s*:\s*(\d+)\s*;",
                        line,
                        re.IGNORECASE,
                    )

                    if match:
                        sids.add(int(match.group(1)))

        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError(
                f"Unable to read rule file {path}: {exc}"
            )

    return sids


def _suricata_validate_custom_rule(rule):
    import re

    if not isinstance(rule, str):
        return "rule must be a string"

    rule = rule.strip()

    if not rule:
        return "rule cannot be empty"

    if len(rule) > 8192:
        return "rule is too long"

    if "\n" in rule or "\r" in rule:
        return "rule must contain exactly one rule"

    if not re.match(
        r"^(alert|drop|reject)\s+"
        r"(tcp|udp|icmp|ip)\s+"
        r".+\s+"
        r"(->|<>)\s+"
        r".+\s+\(.+\)$",
        rule,
        re.IGNORECASE,
    ):
        return (
            "unsupported or malformed rule format; "
            "expected action protocol source direction "
            "destination (options)"
        )

    sid_match = re.search(
        r"\bsid\s*:\s*(\d+)\s*;",
        rule,
        re.IGNORECASE,
    )

    if not sid_match:
        return "rule must contain a numeric sid"

    sid = int(sid_match.group(1))

    if not (
        SURICATA_CUSTOM_SID_MIN
        <= sid
        <= SURICATA_CUSTOM_SID_MAX
    ):
        return (
            f"sid must be between "
            f"{SURICATA_CUSTOM_SID_MIN} and "
            f"{SURICATA_CUSTOM_SID_MAX}"
        )

    if not re.search(
        r"\bmsg\s*:",
        rule,
        re.IGNORECASE,
    ):
        return "rule must contain a msg option"

    if not re.search(
        r"\brev\s*:\s*\d+\s*;",
        rule,
        re.IGNORECASE,
    ):
        return "rule must contain a numeric rev option"

    return None


def _suricata_rule_sid(rule):
    import re

    match = re.search(
        r"\bsid\s*:\s*(\d+)\s*;",
        rule,
        re.IGNORECASE,
    )

    return int(match.group(1)) if match else None


def _suricata_validate_configuration():
    return run_command(
        [
            "/usr/sbin/suricata",
            "-T",
            "-c",
            "/etc/suricata/suricata.yaml",
        ],
        timeout=30,
    )


def _suricata_reload():
    result = run_command(
        [
            "/usr/bin/systemctl",
            "reload",
            "suricata",
        ],
        timeout=15,
    )

    if not result["success"]:
        return result

    time.sleep(2)

    active = run_command(
        [
            "/usr/bin/systemctl",
            "is-active",
            "suricata",
        ],
        timeout=5,
    )

    if not active["success"] or active["stdout"] != "active":
        return {
            "success": False,
            "stdout": active["stdout"],
            "stderr": (
                active["stderr"]
                or "Suricata is not active after reload"
            ),
            "returncode": active["returncode"],
        }

    return result


def _suricata_write_custom_rules(rules):
    import os
    import tempfile

    directory = os.path.dirname(
        SURICATA_CUSTOM_RULES_PATH
    )

    os.makedirs(
        directory,
        mode=0o750,
        exist_ok=True,
    )

    fd, temp_path = tempfile.mkstemp(
        prefix=".custom.rules.",
        dir=directory,
        text=True,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as rules_file:
            for rule in rules:
                rules_file.write(
                    rule.rstrip() + "\n"
                )

        os.chmod(temp_path, 0o640)
        os.replace(
            temp_path,
            SURICATA_CUSTOM_RULES_PATH,
        )

    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _suricata_custom_rule_apply(new_rules):
    previous = [
        item["rule"]
        for item in _suricata_custom_rules()
    ]

    _suricata_write_custom_rules(new_rules)

    validation = _suricata_validate_configuration()

    if not validation["success"]:
        _suricata_write_custom_rules(previous)

        return {
            "success": False,
            "stage": "validation",
            "error": (
                validation["stderr"]
                or validation["stdout"]
                or "Suricata validation failed"
            ),
        }

    reload_result = _suricata_reload()

    if not reload_result["success"]:
        _suricata_write_custom_rules(previous)

        rollback_validation = (
            _suricata_validate_configuration()
        )

        if rollback_validation["success"]:
            _suricata_reload()

        return {
            "success": False,
            "stage": "reload",
            "error": (
                reload_result["stderr"]
                or reload_result["stdout"]
                or "Suricata reload failed"
            ),
        }

    return {
        "success": True,
        "stage": "reload",
        "error": None,
    }


def suricata_custom_rules(request):
    """
    GET  /api/suricata/custom-rules/
    POST /api/suricata/custom-rules/
    """

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method == "GET":
        try:
            rules = _suricata_custom_rules()

            return JsonResponse(
                {
                    "available": True,
                    "path": SURICATA_CUSTOM_RULES_PATH,
                    "sid_min": SURICATA_CUSTOM_SID_MIN,
                    "sid_max": SURICATA_CUSTOM_SID_MAX,
                    "count": len(rules),
                    "rules": rules,
                    "error": None,
                }
            )

        except Exception as exc:
            return JsonResponse(
                {
                    "available": False,
                    "path": SURICATA_CUSTOM_RULES_PATH,
                    "sid_min": SURICATA_CUSTOM_SID_MIN,
                    "sid_max": SURICATA_CUSTOM_SID_MAX,
                    "count": 0,
                    "rules": [],
                    "error": str(exc),
                },
                status=500,
            )

    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    body, error = _firewall_json_body(request)

    if error:
        return error

    rule = body.get("rule")

    validation_error = (
        _suricata_validate_custom_rule(rule)
    )

    if validation_error:
        return JsonResponse(
            {
                "success": False,
                "error": validation_error,
            },
            status=400,
        )

    sid = _suricata_rule_sid(rule)

    try:
        existing_sids = _suricata_existing_sids()

        if sid in existing_sids:
            return JsonResponse(
                {
                    "success": False,
                    "error": f"SID {sid} already exists",
                },
                status=409,
            )

        current_rules = [
            item["rule"]
            for item in _suricata_custom_rules()
        ]

        result = _suricata_custom_rule_apply(
            current_rules + [rule.strip()]
        )

        if not result["success"]:
            return JsonResponse(
                result,
                status=400 if result["stage"] == "validation" else 500,
            )

        return JsonResponse(
            {
                "success": True,
                "message": "Custom Suricata rule created",
                "sid": sid,
                "rule": rule.strip(),
            },
            status=201,
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )


def suricata_custom_rule_validate(request):
    """
    POST /api/suricata/custom-rules/validate/

    Validate a submitted custom rule together with the currently
    installed custom rules. The live Suricata process is never
    reloaded by this endpoint.
    """

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "POST":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    body, error = _firewall_json_body(request)

    if error:
        return error

    rule = body.get("rule")

    validation_error = _suricata_validate_custom_rule(rule)

    if validation_error:
        return JsonResponse(
            {
                "valid": False,
                "error": validation_error,
            },
            status=400,
        )

    sid = _suricata_rule_sid(rule)

    try:
        existing_sids = _suricata_existing_sids()

        if sid in existing_sids:
            return JsonResponse(
                {
                    "valid": False,
                    "error": f"SID {sid} already exists",
                },
                status=409,
            )

        current_rules = [
            item["rule"]
            for item in _suricata_custom_rules()
        ]

        candidate_rules = current_rules + [rule]

        _suricata_write_custom_rules(candidate_rules)

        try:
            result = _suricata_validate_configuration()
        finally:
            _suricata_write_custom_rules(current_rules)

        if not result["success"]:
            return JsonResponse(
                {
                    "valid": False,
                    "error": (
                        result["stderr"]
                        or result["stdout"]
                        or "Suricata validation failed"
                    ),
                },
                status=400,
            )

        return JsonResponse(
            {
                "valid": True,
                "sid": sid,
                "message": (
                    "Submitted rule and Suricata configuration "
                    "are valid"
                ),
            }
        )

    except Exception as exc:
        try:
            _suricata_write_custom_rules(current_rules)
        except Exception:
            pass

        return JsonResponse(
            {
                "valid": False,
                "error": str(exc),
            },
            status=500,
        )

def suricata_custom_rule_detail(request, sid):
    """
    DELETE /api/suricata/custom-rules/<sid>/
    """

    auth_error = _firewall_authenticated(request)

    if auth_error:
        return auth_error

    if request.method != "DELETE":
        return JsonResponse(
            {"error": "Method not allowed"},
            status=405,
        )

    try:
        sid = int(sid)

    except (TypeError, ValueError):
        return JsonResponse(
            {"error": "Invalid SID"},
            status=400,
        )

    if not (
        SURICATA_CUSTOM_SID_MIN
        <= sid
        <= SURICATA_CUSTOM_SID_MAX
    ):
        return JsonResponse(
            {"error": "SID is outside the custom rule range"},
            status=400,
        )

    try:
        current_rules = [
            item["rule"]
            for item in _suricata_custom_rules()
        ]

        matching = [
            rule
            for rule in current_rules
            if _suricata_rule_sid(rule) == sid
        ]

        if not matching:
            return JsonResponse(
                {"error": "Custom rule not found"},
                status=404,
            )

        new_rules = [
            rule
            for rule in current_rules
            if _suricata_rule_sid(rule) != sid
        ]

        result = _suricata_custom_rule_apply(
            new_rules
        )

        if not result["success"]:
            return JsonResponse(
                result,
                status=500,
            )

        return JsonResponse(
            {
                "success": True,
                "message": "Custom Suricata rule deleted",
                "sid": sid,
            }
        )

    except Exception as exc:
        return JsonResponse(
            {
                "success": False,
                "error": str(exc),
            },
            status=500,
        )
