import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from flask import Flask, abort, render_template, request

from config import load_config
from db import (
    get_all_devices,
    get_all_sessions,
    get_dns_top_domains,
    get_device,
    get_dns_logs,
    get_flagged_domains,
    get_latest_device_seen,
    get_mac_randomisation_stats,
    get_overview_devices,
    get_persistent_devices,
    get_sessions,
    get_sni_logs,
    get_sni_summary,
    get_status_history,
    get_summary_stats,
    get_top_dns_devices,
    get_vendor_distribution,
)

app = Flask(__name__)

APP_CONFIG = load_config()
DB_PATH = APP_CONFIG["db_path"]


def _parse_db_timestamp(raw_value: str | None) -> datetime | None:
    if raw_value is None:
        return None

    value = raw_value.strip()
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass

    known_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    )
    for fmt in known_formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _is_recent(last_seen: str | None, minutes: int = 5) -> bool:
    parsed = _parse_db_timestamp(last_seen)
    if parsed is None:
        return False

    now = datetime.now(parsed.tzinfo) if parsed.tzinfo is not None else datetime.now()
    delta = now - parsed
    return timedelta(0) <= delta <= timedelta(minutes=minutes)


def _with_bar_classes(rows: List[Dict[str, Any]], count_key: str) -> Tuple[List[Dict[str, Any]], int]:
    max_count = max((int(row.get(count_key, 0) or 0) for row in rows), default=0)
    enriched: List[Dict[str, Any]] = []

    for row in rows:
        count = int(row.get(count_key, 0) or 0)
        width = int(round((count / max_count) * 100)) if max_count > 0 else 0
        item = dict(row)
        item["bar_class"] = f"bar-w-{width}"
        enriched.append(item)

    return enriched, max_count


@app.route("/")
def index() -> str:
    requested_sort = request.args.get("sort", "last_seen").lower()
    requested_order = request.args.get("order", "desc").lower()

    allowed_sort = {"ip", "vendor", "status", "last_seen"}
    sort = requested_sort if requested_sort in allowed_sort else "last_seen"
    order = "asc" if requested_order == "asc" else "desc"

    devices = get_overview_devices(DB_PATH, sort_column=sort, sort_order=order.upper())
    stats = get_summary_stats(DB_PATH)
    latest_seen = get_latest_device_seen(DB_PATH)
    is_fresh = _is_recent(latest_seen, minutes=5)

    return render_template(
        "index.html",
        devices=devices,
        stats=stats,
        sort=sort,
        order=order,
        is_fresh=is_fresh,
        current_page="overview",
    )


@app.route("/network")
def network() -> str:
    vendor_distribution_raw = get_vendor_distribution(DB_PATH)
    vendor_distribution, _ = _with_bar_classes(vendor_distribution_raw, "cnt")

    top_dns_devices_raw = get_top_dns_devices(DB_PATH)
    top_dns_devices, _ = _with_bar_classes(top_dns_devices_raw, "query_count")

    mac_stats = get_mac_randomisation_stats(DB_PATH)
    persistent_devices = get_persistent_devices(DB_PATH)

    return render_template(
        "network.html",
        vendor_distribution=vendor_distribution,
        top_dns_devices=top_dns_devices,
        mac_stats=mac_stats,
        persistent_devices=persistent_devices,
        current_page="network",
    )


@app.route("/sni")
def sni() -> str:
    sni_logs = get_sni_logs(DB_PATH)
    sni_summary = get_sni_summary(DB_PATH)

    return render_template(
        "sni.html",
        sni_logs=sni_logs,
        sni_summary=sni_summary,
        current_page="sni",
    )


@app.route("/about")
def about() -> str:
    return render_template("about.html", current_page="about")


@app.route("/device/<int:device_id>")
def device_detail(device_id: int) -> str:
    device = get_device(DB_PATH, device_id)
    if device is None:
        abort(404)

    dns_logs = get_dns_logs(DB_PATH, device_id)
    dns_top_raw = get_dns_top_domains(DB_PATH, device_id)
    dns_top, max_count = _with_bar_classes(dns_top_raw, "cnt")
    sessions = get_sessions(DB_PATH, device_id)
    status_history = get_status_history(DB_PATH, device_id)

    return render_template(
        "device.html",
        device=device,
        dns_logs=dns_logs,
        dns_top=dns_top,
        max_count=max_count,
        sessions=sessions,
        status_history=status_history,
        current_page="",
    )


@app.route("/report")
def report() -> str:
    devices = get_all_devices(DB_PATH)
    flagged_domains = get_flagged_domains(DB_PATH)
    stats = get_summary_stats(DB_PATH)
    all_sessions = get_all_sessions(DB_PATH)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "report.html",
        devices=devices,
        flagged_domains=flagged_domains,
        stats=stats,
        all_sessions=all_sessions,
        generated_at=generated_at,
        current_page="report",
    )


if __name__ == "__main__":
    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    except KeyboardInterrupt:
        print("Shutting down ARGUS-IRIS")
        sys.exit(0)