import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_POST


FAIL2BAN_CUSTOM_JAIL_DIR = Path("/etc/fail2ban/jail.d")
FAIL2BAN_CUSTOM_FILTER_DIR = Path("/etc/fail2ban/filter.d")

FAIL2BAN_CUSTOM_PREFIX = "hpc-custom-"

FAIL2BAN_JAIL_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$"
)

FAIL2BAN_DURATION_RE = re.compile(
    r"^[0-9]+(?:[smhdw])?$"
)


FAIL2BAN_TRIGGER_DEFINITIONS = {
    "http-400": {
        "label": "Bad HTTP requests (400)",
        "description": "Repeated malformed or invalid HTTP requests.",
        "failregex": r'^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 400',
    },
    "http-401": {
        "label": "Unauthorized requests (401)",
        "description": "Repeated HTTP requests that require authentication.",
        "failregex": r'^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 401',
    },
    "http-403": {
        "label": "Forbidden requests (403)",
        "description": "Repeated HTTP requests rejected by access controls.",
        "failregex": r'^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 403',
    },
    "http-404": {
        "label": "Missing page requests (404)",
        "description": "Repeated requests for resources that do not exist.",
        "failregex": r'^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 404',
    },
}


def _fail2ban_admin(request):
    return (
        request.user.is_authenticated
        and request.user.is_staff
    )


def _fail2ban_command(command, timeout=15):
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
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "stdout": exc.stdout or "",
            "stderr": "Command timed out.",
            "returncode": 124,
        }

    except OSError as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "returncode": 1,
        }


def _fail2ban_status_jails():
    result = _fail2ban_command(
        ["/usr/bin/fail2ban-client", "status"],
        timeout=10,
    )

    if not result["success"]:
        return []

    for line in result["stdout"].splitlines():
        if "Jail list:" not in line:
            continue

        value = line.split("Jail list:", 1)[1].strip()

        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    return []


def _fail2ban_safe_name(name):
    if not isinstance(name, str):
        return False

    return bool(
        FAIL2BAN_JAIL_NAME_RE.fullmatch(name.strip())
    )


def _fail2ban_custom_paths(name):
    jail_name = f"{FAIL2BAN_CUSTOM_PREFIX}{name}"

    return (
        FAIL2BAN_CUSTOM_JAIL_DIR / f"{jail_name}.local",
        FAIL2BAN_CUSTOM_FILTER_DIR / f"{jail_name}.conf",
        jail_name,
    )


def _fail2ban_custom_files():
    files = []

    try:
        for path in sorted(
            FAIL2BAN_CUSTOM_JAIL_DIR.glob(
                f"{FAIL2BAN_CUSTOM_PREFIX}*.local"
            )
        ):
            filename = path.stem

            if not filename.startswith(
                FAIL2BAN_CUSTOM_PREFIX
            ):
                continue

            name = filename[
                len(FAIL2BAN_CUSTOM_PREFIX):
            ]

            if not _fail2ban_safe_name(name):
                continue

            jail_path, filter_path, jail_name = (
                _fail2ban_custom_paths(name)
            )

            files.append(
                {
                    "name": name,
                    "jail_name": jail_name,
                    "jail_path": str(jail_path),
                    "filter_path": str(filter_path),
                }
            )

    except OSError:
        pass

    return files


def _parse_custom_jail(path):
    data = {
        "name": "",
        "jail_name": "",
        "filter": "",
        "logpath": "",
        "maxretry": "",
        "findtime": "",
        "bantime": "",
        "failregex": "",
        "ignoreregex": "",
        "active": False,
        "jail_path": str(path),
        "filter_path": "",
        "error": None,
    }

    try:
        text = path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        section_match = re.search(
            r"^\[([^\]]+)\]",
            text,
            re.MULTILINE,
        )

        if section_match:
            data["jail_name"] = section_match.group(1)

        prefix = FAIL2BAN_CUSTOM_PREFIX

        if data["jail_name"].startswith(prefix):
            data["name"] = data["jail_name"][
                len(prefix):
            ]

        for key in (
            "filter",
            "logpath",
            "maxretry",
            "findtime",
            "bantime",
        ):
            match = re.search(
                rf"^\s*{re.escape(key)}\s*=\s*(.+?)\s*$",
                text,
                re.MULTILINE,
            )

            if match:
                data[key] = match.group(1).strip()

        filter_match = re.search(
            r"^\s*filter\s*=\s*(\S+)",
            text,
            re.MULTILINE,
        )

        if filter_match:
            data["filter_path"] = str(
                FAIL2BAN_CUSTOM_FILTER_DIR
                / f"{filter_match.group(1)}.conf"
            )

        if data["filter_path"]:
            filter_path = Path(data["filter_path"])

            if filter_path.exists():
                filter_text = filter_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )

                match = re.search(
                    r"^\s*failregex\s*=\s*(.+?)\s*$",
                    filter_text,
                    re.MULTILINE,
                )

                if match:
                    data["failregex"] = match.group(1)

                match = re.search(
                    r"^\s*ignoreregex\s*=\s*(.+?)\s*$",
                    filter_text,
                    re.MULTILINE,
                )

                if match:
                    data["ignoreregex"] = match.group(1)

        active_jails = _fail2ban_status_jails()

        data["active"] = (
            data["jail_name"] in active_jails
        )

    except OSError as exc:
        data["error"] = str(exc)

    return data


def _fail2ban_custom_inventory():
    return [
        _parse_custom_jail(Path(item["jail_path"]))
        for item in _fail2ban_custom_files()
    ]


def _validate_custom_jail_payload(payload):
    if not isinstance(payload, dict):
        return False, "Invalid request payload."

    name = payload.get("name", "")
    logpath = payload.get("logpath", "")
    trigger = payload.get("trigger", "")

    maxretry = str(
        payload.get("maxretry", "")
    ).strip()

    findtime = str(
        payload.get("findtime", "")
    ).strip()

    bantime = str(
        payload.get("bantime", "")
    ).strip()

    if not _fail2ban_safe_name(name):
        return (
            False,
            "Jail name must contain only letters, numbers, "
            "underscore, and hyphen, and be 1-48 characters.",
        )

    if not isinstance(logpath, str) or not logpath.strip():
        return False, "Log path is required."

    logpath = logpath.strip()

    if (
        not logpath.startswith("/")
        or "\n" in logpath
        or "\r" in logpath
        or "\x00" in logpath
    ):
        return False, "Log path must be an absolute filesystem path."

    if not isinstance(trigger, str) or not trigger.strip():
        return False, "Trigger is required."

    trigger = trigger.strip()

    if trigger not in FAIL2BAN_TRIGGER_DEFINITIONS:
        return False, "Invalid trigger selected."

    if (
        not maxretry.isdigit()
        or not 1 <= int(maxretry) <= 1000
    ):
        return False, "Failed attempts must be between 1 and 1000."

    for label, value in (
        ("Within", findtime),
        ("Ban time", bantime),
    ):
        if not FAIL2BAN_DURATION_RE.fullmatch(value):
            return (
                False,
                f"{label} must be a number optionally "
                "followed by s, m, h, d, or w.",
            )

    return True, None



def _fail2ban_validate_configuration():
    result = _fail2ban_command(
        ["/usr/bin/fail2ban-client", "-t"],
        timeout=30,
    )

    if not result["success"]:
        return (
            False,
            result["stderr"]
            or result["stdout"]
            or "Fail2Ban configuration validation failed.",
        )

    return True, None


def _fail2ban_reload():
    result = _fail2ban_command(
        ["systemctl", "reload", "fail2ban"],
        timeout=20,
    )

    if not result["success"]:
        return (
            False,
            result["stderr"]
            or result["stdout"]
            or "Fail2Ban reload failed.",
        )

    time.sleep(1)

    result = _fail2ban_command(
        ["systemctl", "is-active", "--quiet", "fail2ban"],
        timeout=5,
    )

    if not result["success"]:
        return False, "Fail2Ban is not active after reload."

    return True, None


def _atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(content)

        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)

        return True, None

    except OSError as exc:
        try:
            os.unlink(temp_name)
        except OSError:
            pass

        return False, str(exc)


def _snapshot_file(path):
    path = Path(path)

    if not path.exists():
        return None

    try:
        return path.read_bytes()
    except OSError:
        return None


def _restore_file(path, content):
    path = Path(path)

    try:
        if content is None:
            if path.exists():
                path.unlink()
        else:
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temp = path.with_name(
                f".{path.name}.rollback"
            )

            temp.write_bytes(content)
            os.chmod(temp, 0o644)
            os.replace(temp, path)

        return True

    except OSError:
        return False


def _apply_custom_jail_files(
    jail_path,
    jail_content,
    filter_path,
    filter_content,
):
    jail_path = Path(jail_path)
    filter_path = Path(filter_path)

    old_jail = _snapshot_file(jail_path)
    old_filter = _snapshot_file(filter_path)

    ok, error = _atomic_write(
        filter_path,
        filter_content,
    )

    if not ok:
        return False, error

    ok, error = _atomic_write(
        jail_path,
        jail_content,
    )

    if not ok:
        _restore_file(
            filter_path,
            old_filter,
        )
        return False, error

    valid, validation_error = (
        _fail2ban_validate_configuration()
    )

    if not valid:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

        return (
            False,
            f"Fail2Ban validation failed: {validation_error}",
        )

    reloaded, reload_error = _fail2ban_reload()

    if not reloaded:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

        _fail2ban_validate_configuration()
        _fail2ban_reload()

        return (
            False,
            f"Fail2Ban reload failed: {reload_error}",
        )

    return True, None


def _delete_custom_jail_files(
    jail_path,
    filter_path,
):
    jail_path = Path(jail_path)
    filter_path = Path(filter_path)

    old_jail = _snapshot_file(jail_path)
    old_filter = _snapshot_file(filter_path)

    try:
        if jail_path.exists():
            jail_path.unlink()

        if filter_path.exists():
            filter_path.unlink()

    except OSError as exc:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

        return False, str(exc)

    valid, validation_error = (
        _fail2ban_validate_configuration()
    )

    if not valid:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

        return (
            False,
            f"Fail2Ban validation failed: {validation_error}",
        )

    reloaded, reload_error = _fail2ban_reload()

    if not reloaded:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

        _fail2ban_validate_configuration()
        _fail2ban_reload()

        return (
            False,
            f"Fail2Ban reload failed: {reload_error}",
        )

    return True, None


def _build_custom_jail_config(payload):
    name = payload["name"].strip()
    logpath = payload["logpath"].strip()
    trigger = payload["trigger"].strip()

    maxretry = str(
        payload["maxretry"]
    ).strip()

    findtime = str(
        payload["findtime"]
    ).strip()

    bantime = str(
        payload["bantime"]
    ).strip()

    trigger_definition = FAIL2BAN_TRIGGER_DEFINITIONS.get(
        trigger
    )

    if trigger_definition is None:
        raise ValueError("Invalid Fail2Ban trigger.")

    failregex = trigger_definition["failregex"]

    _, _, jail_name = _fail2ban_custom_paths(name)

    jail_content = (
        f"[{jail_name}]\n"
        "enabled = true\n"
        f"filter = {jail_name}\n"
        f"logpath = {logpath}\n"
        f"maxretry = {maxretry}\n"
        f"findtime = {findtime}\n"
        f"bantime = {bantime}\n"
        "action = firewallcmd-rich-rules\n"
    )

    filter_content = (
        "[Definition]\n"
        f"failregex = {failregex}\n"
    )

    return jail_content, filter_content




@require_http_methods(["GET", "POST"])
def fail2ban_custom_jails(request):
    if not _fail2ban_admin(request):
        return JsonResponse(
            {
                "success": False,
                "error": "Administrator access required.",
            },
            status=403,
        )

    if request.method == "GET":
        jails = _fail2ban_custom_inventory()

        return JsonResponse({
            "available": True,
            "count": len(jails),
            "jails": jails,
            "jail_directory": str(
                FAIL2BAN_CUSTOM_JAIL_DIR
            ),
            "filter_directory": str(
                FAIL2BAN_CUSTOM_FILTER_DIR
            ),
            "error": None,
        })

    try:
        payload = json.loads(
            request.body or "{}"
        )
    except json.JSONDecodeError:
        return JsonResponse(
            {
                "success": False,
                "error": "Invalid JSON.",
            },
            status=400,
        )

    valid, error = _validate_custom_jail_payload(
        payload
    )

    if not valid:
        return JsonResponse(
            {
                "success": False,
                "error": error,
            },
            status=400,
        )

    name = payload["name"].strip()

    existing_custom = {
        item["name"]
        for item in _fail2ban_custom_files()
    }

    active_jails = set(
        _fail2ban_status_jails()
    )

    _, _, jail_name = _fail2ban_custom_paths(name)

    if name in existing_custom:
        return JsonResponse(
            {
                "success": False,
                "error": "A custom jail with this name already exists.",
            },
            status=409,
        )

    if jail_name in active_jails:
        return JsonResponse(
            {
                "success": False,
                "error": "A Fail2Ban jail with this name is already active.",
            },
            status=409,
        )

    jail_path, filter_path, _ = (
        _fail2ban_custom_paths(name)
    )

    jail_content, filter_content = (
        _build_custom_jail_config(payload)
    )

    ok, apply_error = _apply_custom_jail_files(
        jail_path,
        jail_content,
        filter_path,
        filter_content,
    )

    if not ok:
        return JsonResponse(
            {
                "success": False,
                "error": apply_error,
            },
            status=400,
        )

    return JsonResponse(
        {
            "success": True,
            "message": (
                "Custom Fail2Ban jail added "
                "and activated successfully."
            ),
            "name": name,
            "jail_name": jail_name,
            "jail_path": str(jail_path),
            "filter_path": str(filter_path),
        },
        status=201,
    )


@require_POST
def fail2ban_custom_jail_validate(request):
    if not _fail2ban_admin(request):
        return JsonResponse(
            {
                "success": False,
                "error": "Administrator access required.",
            },
            status=403,
        )

    try:
        payload = json.loads(
            request.body or "{}"
        )
    except json.JSONDecodeError:
        return JsonResponse(
            {
                "success": False,
                "valid": False,
                "error": "Invalid JSON.",
            },
            status=400,
        )

    valid, error = _validate_custom_jail_payload(
        payload
    )

    if not valid:
        return JsonResponse({
            "success": True,
            "valid": False,
            "error": error,
        })

    name = payload["name"].strip()

    existing_custom = {
        item["name"]
        for item in _fail2ban_custom_files()
    }

    active_jails = set(
        _fail2ban_status_jails()
    )

    _, _, jail_name = _fail2ban_custom_paths(name)

    if name in existing_custom:
        return JsonResponse({
            "success": True,
            "valid": False,
            "error": (
                "A custom jail with this name "
                "already exists."
            ),
        })

    if jail_name in active_jails:
        return JsonResponse({
            "success": True,
            "valid": False,
            "error": (
                "A Fail2Ban jail with this name "
                "is already active."
            ),
        })

    jail_path, filter_path, _ = (
        _fail2ban_custom_paths(name)
    )

    jail_content, filter_content = (
        _build_custom_jail_config(payload)
    )

    old_jail = _snapshot_file(jail_path)
    old_filter = _snapshot_file(filter_path)

    ok, write_error = _atomic_write(
        filter_path,
        filter_content,
    )

    if not ok:
        return JsonResponse({
            "success": True,
            "valid": False,
            "error": write_error,
        })

    ok, write_error = _atomic_write(
        jail_path,
        jail_content,
    )

    if not ok:
        _restore_file(filter_path, old_filter)

        return JsonResponse({
            "success": True,
            "valid": False,
            "error": write_error,
        })

    try:
        config_ok, config_error = (
            _fail2ban_validate_configuration()
        )
    finally:
        _restore_file(jail_path, old_jail)
        _restore_file(filter_path, old_filter)

    if not config_ok:
        return JsonResponse({
            "success": True,
            "valid": False,
            "error": config_error,
        })

    return JsonResponse({
        "success": True,
        "valid": True,
        "message": "Custom Fail2Ban jail configuration is valid.",
        "error": None,
    })


@require_http_methods(["DELETE"])
def fail2ban_custom_jail_detail(request, name):
    if not _fail2ban_admin(request):
        return JsonResponse(
            {
                "success": False,
                "error": "Administrator access required.",
            },
            status=403,
        )

    if not _fail2ban_safe_name(name):
        return JsonResponse(
            {
                "success": False,
                "error": "Invalid jail name.",
            },
            status=400,
        )

    jail_path, filter_path, jail_name = (
        _fail2ban_custom_paths(name)
    )

    if not jail_path.exists():
        return JsonResponse(
            {
                "success": False,
                "error": "Custom jail not found.",
            },
            status=404,
        )

    ok, error = _delete_custom_jail_files(
        jail_path,
        filter_path,
    )

    if not ok:
        return JsonResponse(
            {
                "success": False,
                "error": error,
            },
            status=400,
        )

    return JsonResponse({
        "success": True,
        "message": (
            f"Custom Fail2Ban jail "
            f"{jail_name} deleted successfully."
        ),
        "name": name,
    })
