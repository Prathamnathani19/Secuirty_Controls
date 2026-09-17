import csv
import io
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from email.utils import parsedate_to_datetime
from pathlib import Path

from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_GET
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


REPORT_LIMIT = 5000

REPORT_PERIODS = {
    "second": timedelta(seconds=1),
    "minute": timedelta(minutes=1),
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
    "week": timedelta(days=7),
    "month": timedelta(days=30),
    "year": timedelta(days=365),
}


REPORT_TIMEZONE = ZoneInfo("Asia/Kolkata")


def _report_now():
    return datetime.now(REPORT_TIMEZONE)


def _parse_report_datetime(value):
    if not value:
        return None

    try:
        value = value.strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        result = datetime.fromisoformat(value)

        if result.tzinfo is None:
            result = result.replace(tzinfo=REPORT_TIMEZONE)

        return result

    except (TypeError, ValueError):
        return None


def _report_period(request):
    period = request.GET.get("period", "day").strip().lower()
    now = _report_now()

    if period == "custom":
        start = _parse_report_datetime(
            request.GET.get("start")
        )
        end = _parse_report_datetime(
            request.GET.get("end")
        )

        if not start or not end:
            return None, None, "Custom reports require valid start and end times."

        if end <= start:
            return None, None, "Report end time must be after the start time."

        return start, end, None

    if period not in REPORT_PERIODS:
        return (
            None,
            None,
            "Invalid report period. Use second, minute, hour, day, week, month, year, or custom.",
        )

    return now - REPORT_PERIODS[period], now, None


def _run(command, timeout=20):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return result.returncode == 0, result.stdout, result.stderr

    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc)


def _journal_events(unit, start, end, limit=REPORT_LIMIT):
    command = [
        "/usr/bin/journalctl",
        "--no-pager",
        "--output=json",
        "--since",
        start.isoformat(),
        "--until",
        end.isoformat(),
        "-n",
        str(limit),
    ]

    if unit:
        command.insert(3, "-u")
        command.insert(4, unit)

    ok, stdout, stderr = _run(command, timeout=30)

    if not ok:
        return []

    events = []

    for line in stdout.splitlines():
        try:
            item = json.loads(line)

            timestamp = item.get("__REALTIME_TIMESTAMP")

            if timestamp:
                event_time = datetime.fromtimestamp(
                    int(timestamp) / 1_000_000,
                    tz=start.tzinfo,
                )
            else:
                event_time = None

            events.append({
                "timestamp": (
                    event_time.isoformat()
                    if event_time
                    else None
                ),
                "message": item.get("MESSAGE", ""),
                "source": unit or "system",
                "priority": item.get("PRIORITY"),
                "hostname": item.get("_HOSTNAME"),
                "unit": item.get("_SYSTEMD_UNIT"),
            })

        except (ValueError, TypeError, json.JSONDecodeError):
            continue

    return events


def _parse_syslog_timestamp(line, reference_time):
    """
    Parse traditional Rocky/RHEL syslog timestamps such as:
    Sep 10 10:14:44 localhost sshd-session[123]: ...
    The year is inferred from the report/reference time.
    """
    match = re.match(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+"
        r"(\d{2}):(\d{2}):(\d{2})\s+",
        line,
    )

    if not match:
        return None

    month, day, hour, minute, second = match.groups()

    try:
        event_time = datetime.strptime(
            f"{reference_time.year} {month} {day} "
            f"{hour}:{minute}:{second}",
            "%Y %b %d %H:%M:%S",
        )

        return event_time.replace(tzinfo=REPORT_TIMEZONE)

    except ValueError:
        return None


def _parse_nginx_timestamp(line):
    """
    Parse Nginx combined-log timestamp:
    [10/Sep/2026:10:46:50 +0530]
    """
    match = re.search(
        r"\[([0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:"
        r"[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[+-][0-9]{4})\]",
        line,
    )

    if not match:
        return None

    try:
        return datetime.strptime(
            match.group(1),
            "%d/%b/%Y:%H:%M:%S %z",
        )

    except ValueError:
        return None


def _file_events(path, start, end, source, limit=REPORT_LIMIT):
    """
    Read file-backed logs and return only events whose actual
    timestamps fall inside the requested report period.

    This deliberately does NOT use journalctl for file logs because
    journalctl cannot infer the timestamp of an arbitrary log file.
    """
    path = Path(path)

    if not path.exists() or not path.is_file():
        return []

    events = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for line in handle:
                line = line.rstrip("\n")

                if not line.strip():
                    continue

                if source.startswith("nginx"):
                    event_time = _parse_nginx_timestamp(line)
                else:
                    event_time = _parse_syslog_timestamp(
                        line,
                        start,
                    )

                if not event_time:
                    continue

                # Handle year rollover for reports that cross New Year.
                if event_time < start - timedelta(days=1):
                    try:
                        event_time = event_time.replace(
                            year=start.year + 1
                        )
                    except ValueError:
                        pass

                if event_time < start or event_time > end:
                    continue

                events.append({
                    "timestamp": event_time.isoformat(),
                    "message": line,
                    "source": source,
                    "priority": None,
                    "hostname": None,
                    "unit": None,
                })

                if len(events) >= limit:
                    break

    except (OSError, UnicodeError):
        return []

    return events

def _suricata_events(start, end):
    path = Path("/var/log/suricata/eve.json")

    if not path.exists():
        return []

    events = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:
            for line in handle:
                try:
                    item = json.loads(line)

                    if item.get("event_type") != "alert":
                        continue

                    timestamp = item.get("timestamp")

                    event_time = _parse_report_datetime(
                        timestamp
                    )

                    if not event_time:
                        continue

                    if event_time < start or event_time > end:
                        continue

                    alert = item.get("alert") or {}

                    events.append({
                        "timestamp": event_time.isoformat(),
                        "source": "suricata",
                        "message": alert.get(
                            "signature",
                            "Suricata alert",
                        ),
                        "severity": alert.get("severity"),
                        "action": (
                            "Blocked"
                            if item.get("verdict")
                            else "Detected"
                        ),
                        "src_ip": item.get("src_ip"),
                        "dest_ip": item.get("dest_ip"),
                        "protocol": item.get("proto"),
                    })

                except (
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                ):
                    continue

    except OSError:
        return []

    return events[-REPORT_LIMIT:]


def _snort_events(start, end):
    paths = [
        "/var/log/snort/alert",
        "/var/log/snort/alert.fast",
        "/var/log/snort/alerts",
    ]

    events = []

    for path in paths:
        if not Path(path).exists():
            continue

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                for line in handle.readlines()[-REPORT_LIMIT:]:
                    if not line.strip():
                        continue

                    events.append({
                        "timestamp": None,
                        "source": "snort",
                        "message": line.strip(),
                        "severity": None,
                        "action": "Detected",
                    })

        except OSError:
            continue

        if events:
            break

    return events[-REPORT_LIMIT:]


def _fail2ban_events(start, end):
    return _journal_events(
        "fail2ban",
        start,
        end,
    )


def _firewalld_events(start, end):
    return _journal_events(
        "firewalld",
        start,
        end,
    )


def _nginx_events(start, end):
    events = []

    for path, source in (
        ("/var/log/nginx/access.log", "nginx_access"),
        ("/var/log/nginx/error.log", "nginx_error"),
    ):
        events.extend(
            _file_events(
                path,
                start,
                end,
                source,
            )
        )

    return events[-REPORT_LIMIT:]


def _ssh_events(start, end):
    return _file_events(
        "/var/log/secure",
        start,
        end,
        "ssh",
    )[-REPORT_LIMIT:]


def _collect_events(start, end):
    events = []

    events.extend(_suricata_events(start, end))
    events.extend(_snort_events(start, end))
    events.extend(_fail2ban_events(start, end))
    events.extend(_firewalld_events(start, end))
    events.extend(_nginx_events(start, end))
    events.extend(_ssh_events(start, end))

    events.sort(
        key=lambda item: item.get("timestamp") or ""
    )

    return events[-REPORT_LIMIT:]


def _count_events(events, source):
    return sum(
        1
        for event in events
        if event.get("source") == source
    )


def _build_report(start, end):
    events = _collect_events(start, end)

    source_counts = {
        "Firewall": _count_events(
            events,
            "firewalld",
        ),
        "Suricata IPS": _count_events(
            events,
            "suricata",
        ),
        "Snort IDS": _count_events(
            events,
            "snort",
        ),
        "Fail2Ban": _count_events(
            events,
            "fail2ban",
        ),
        "Nginx": (
            _count_events(events, "nginx_access")
            + _count_events(events, "nginx_error")
        ),
        "SSH": _count_events(events, "ssh"),
    }

    blocked = sum(
        1
        for event in events
        if str(event.get("action", "")).lower()
        in {"blocked", "block", "banned", "drop", "dropped"}
    )

    detected = sum(
        1
        for event in events
        if str(event.get("action", "")).lower()
        in {"detected", "alert", "alerted"}
    )

    fail2ban_bans = sum(
        1
        for event in events
        if event.get("source") == "fail2ban"
        and re.search(
            r"\bban\b|\bbanned\b",
            event.get("message", ""),
            re.IGNORECASE,
        )
    )

    top_sources = {}

    for event in events:
        source_ip = (
            event.get("src_ip")
            or event.get("source_ip")
        )

        if source_ip:
            top_sources[source_ip] = (
                top_sources.get(source_ip, 0) + 1
            )

    top_sources = [
        {
            "source": ip,
            "events": count,
        }
        for ip, count in sorted(
            top_sources.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:10]
    ]

    return {
        "period": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "summary": {
            "total_events": len(events),
            "blocked_events": blocked,
            "detected_events": detected,
            "fail2ban_bans": fail2ban_bans,
        },
        "controls": source_counts,
        "top_sources": top_sources,
        "events": events,
    }


@require_GET
def reports(request):
    start, end, error = _report_period(request)

    if error:
        return JsonResponse(
            {
                "success": False,
                "error": error,
            },
            status=400,
        )

    return JsonResponse({
        "success": True,
        "report": _build_report(start, end),
    })


def _report_filename(extension, period):
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    return (
        f"hpc_security_report_"
        f"{period}_{timestamp}.{extension}"
    )


@require_GET
def report_csv(request):
    start, end, error = _report_period(request)

    if error:
        return JsonResponse(
            {
                "success": False,
                "error": error,
            },
            status=400,
        )

    report = _build_report(start, end)

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "HPC Security Report",
    ])

    writer.writerow([
        "Report Start",
        report["period"]["start"],
    ])

    writer.writerow([
        "Report End",
        report["period"]["end"],
    ])

    writer.writerow([])

    writer.writerow([
        "Summary",
        "Value",
    ])

    for key, value in report["summary"].items():
        writer.writerow([
            key.replace("_", " ").title(),
            value,
        ])

    writer.writerow([])

    writer.writerow([
        "Security Control",
        "Events",
    ])

    for control, count in report["controls"].items():
        writer.writerow([
            control,
            count,
        ])

    writer.writerow([])

    writer.writerow([
        "Timestamp",
        "Source",
        "Action",
        "Severity",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Event",
    ])

    for event in report["events"]:
        writer.writerow([
            event.get("timestamp") or "",
            event.get("source") or "",
            event.get("action") or "",
            event.get("severity") or "",
            event.get("src_ip") or "",
            event.get("dest_ip") or "",
            event.get("protocol") or "",
            event.get("message") or "",
        ])

    response = HttpResponse(
        output.getvalue(),
        content_type="text/csv; charset=utf-8",
    )

    period = request.GET.get(
        "period",
        "custom",
    )

    response["Content-Disposition"] = (
        "attachment; filename="
        f'"{_report_filename("csv", period)}"'
    )

    return response


def _pdf_footer(canvas, document):
    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        8,
    )

    canvas.drawString(
        20 * mm,
        10 * mm,
        "HPC Security Gateway",
    )

    canvas.drawRightString(
        A4[0] - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


@require_GET
def report_pdf(request):
    start, end, error = _report_period(request)

    if error:
        return JsonResponse(
            {
                "success": False,
                "error": error,
            },
            status=400,
        )

    report = _build_report(start, end)

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="HPC Security Report",
        author="HPC Security Gateway",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=24,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
    )

    story = []

    story.append(
        Paragraph(
            "HPC Security Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Security activity and control summary",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "Reporting Period",
            heading_style,
        )
    )

    period_table = Table(
        [
            ["Start", report["period"]["start"]],
            ["End", report["period"]["end"]],
            [
                "Generated",
                _report_now().isoformat(),
            ],
        ],
        colWidths=[35 * mm, 135 * mm],
    )

    period_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(period_table)
    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "Executive Summary",
            heading_style,
        )
    )

    summary = report["summary"]

    summary_table = Table(
        [
            ["Metric", "Value"],
            ["Total Security Events", summary["total_events"]],
            ["Blocked Events", summary["blocked_events"]],
            ["Detected Events", summary["detected_events"]],
            ["Fail2Ban Bans", summary["fail2ban_bans"]],
        ],
        colWidths=[100 * mm, 70 * mm],
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(summary_table)

    story.append(
        Paragraph(
            "Security Controls",
            heading_style,
        )
    )

    control_rows = [
        ["Security Control", "Events"],
    ]

    control_rows.extend(
        [
            [control, count]
            for control, count
            in report["controls"].items()
        ]
    )

    control_table = Table(
        control_rows,
        colWidths=[100 * mm, 70 * mm],
    )

    control_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(control_table)

    story.append(
        Paragraph(
            "Top Source IPs",
            heading_style,
        )
    )

    source_rows = [
        ["Source IP", "Events"],
    ]

    source_rows.extend(
        [
            [item["source"], item["events"]]
            for item in report["top_sources"]
        ]
    )

    if len(source_rows) == 1:
        source_rows.append(
            ["No source IP data available", 0]
        )

    source_table = Table(
        source_rows,
        colWidths=[100 * mm, 70 * mm],
    )

    source_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(source_table)

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Security Events",
            heading_style,
        )
    )

    event_rows = [
        [
            "Time",
            "Source",
            "Action",
            "Event",
        ]
    ]

    for event in report["events"][:500]:
        event_rows.append([
            (event.get("timestamp") or "")[:19],
            event.get("source") or "",
            event.get("action") or "",
            Paragraph(
                str(event.get("message") or "")[:300],
                body_style,
            ),
        ])

    if len(event_rows) == 1:
        event_rows.append([
            "-",
            "-",
            "-",
            "No security events found for this period.",
        ])

    event_table = Table(
        event_rows,
        colWidths=[
            32 * mm,
            27 * mm,
            25 * mm,
            86 * mm,
        ],
        repeatRows=1,
    )

    event_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ])
    )

    story.append(event_table)

    document.build(
        story,
        onFirstPage=_pdf_footer,
        onLaterPages=_pdf_footer,
    )

    response = HttpResponse(
        buffer.getvalue(),
        content_type="application/pdf",
    )

    period = request.GET.get(
        "period",
        "custom",
    )

    response["Content-Disposition"] = (
        "attachment; filename="
        f'"{_report_filename("pdf", period)}"'
    )

    return response
