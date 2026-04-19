import sys
from datetime import datetime

from flask import Flask, abort, render_template

from config import load_config
from db import (
    get_all_devices,
    get_all_sessions,
    get_device,
    get_dns_logs,
    get_flagged_domains,
    get_sessions,
    get_status_history,
    get_summary_stats,
)

app = Flask(__name__)

APP_CONFIG = load_config()
DB_PATH = APP_CONFIG["db_path"]


@app.route("/")
def index() -> str:
    devices = get_all_devices(DB_PATH)
    stats = get_summary_stats(DB_PATH)
    return render_template(
        "index.html",
        devices=devices,
        stats=stats,
        current_page="overview",
    )


@app.route("/device/<int:device_id>")
def device_detail(device_id: int) -> str:
    device = get_device(DB_PATH, device_id)
    if device is None:
        abort(404)

    dns_logs = get_dns_logs(DB_PATH, device_id)
    sessions = get_sessions(DB_PATH, device_id)
    status_history = get_status_history(DB_PATH, device_id)
    return render_template(
        "device.html",
        device=device,
        dns_logs=dns_logs,
        sessions=sessions,
        status_history=status_history,
        current_page="network",
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