import datetime
import os
import sqlite3

from config import load_config


def _format_table(headers, rows):
    widths = [len(header) for header in headers]
    normalized_rows = []

    for row in rows:
        normalized_row = []
        for index, value in enumerate(row):
            text_value = "" if value is None else str(value)
            normalized_row.append(text_value)
            widths[index] = max(widths[index], len(text_value))
        normalized_rows.append(normalized_row)

    header_line = " | ".join(
        header.ljust(widths[index]) for index, header in enumerate(headers)
    )
    divider_line = "-+-".join("-" * widths[index] for index in range(len(headers)))

    output_lines = [header_line, divider_line]
    for row in normalized_rows:
        output_lines.append(
            " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        )
    return output_lines


def _get_devices_with_fallbacks(connection):
    schema_rows = connection.execute("PRAGMA table_info(devices)", ()).fetchall()
    column_names = {row["name"] for row in schema_rows}
    has_status = "status" in column_names
    has_os_guess = "os_guess" in column_names

    if has_status and has_os_guess:
        query = (
            "SELECT id, ip, mac, vendor, first_seen, last_seen, status, os_guess "
            "FROM devices ORDER BY last_seen DESC"
        )
        params = ()
    elif not has_status and has_os_guess:
        query = (
            "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, os_guess "
            "FROM devices ORDER BY last_seen DESC"
        )
        params = ("UNKNOWN",)
    elif has_status and not has_os_guess:
        query = (
            "SELECT id, ip, mac, vendor, first_seen, last_seen, status, ? AS os_guess "
            "FROM devices ORDER BY last_seen DESC"
        )
        params = ("Unknown",)
    else:
        query = (
            "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, ? AS os_guess "
            "FROM devices ORDER BY last_seen DESC"
        )
        params = ("UNKNOWN", "Unknown")

    rows = connection.execute(query, params).fetchall()
    return rows, has_status


def generate_text_report(db_path, output_path="argus_disclosure_report.txt"):
    if not os.path.exists(db_path):
        raise RuntimeError(f"Database file not found: {db_path}")

    try:
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row

            devices, has_status = _get_devices_with_fallbacks(connection)

            total_devices_row = connection.execute(
                "SELECT COUNT(*) AS count FROM devices", ()
            ).fetchone()
            total_devices = int(total_devices_row["count"]) if total_devices_row else 0

            if has_status:
                active_devices_row = connection.execute(
                    "SELECT COUNT(*) AS count FROM devices WHERE status = ?", ("ACTIVE",)
                ).fetchone()
                active_devices = (
                    int(active_devices_row["count"]) if active_devices_row else 0
                )
            else:
                active_devices = 0

            total_dns_logs_row = connection.execute(
                "SELECT COUNT(*) AS count FROM dns_logs", ()
            ).fetchone()
            total_dns_logs = int(total_dns_logs_row["count"]) if total_dns_logs_row else 0

            flagged_count_row = connection.execute(
                "SELECT COUNT(*) AS count FROM dns_logs WHERE flagged = ?", (1,)
            ).fetchone()
            flagged_count = int(flagged_count_row["count"]) if flagged_count_row else 0

            total_sessions_row = connection.execute(
                "SELECT COUNT(*) AS count FROM sessions", ()
            ).fetchone()
            total_sessions = int(total_sessions_row["count"]) if total_sessions_row else 0

            flagged_domains = connection.execute(
                "SELECT dns_logs.domain, dns_logs.timestamp, devices.ip, devices.mac "
                "FROM dns_logs JOIN devices ON dns_logs.device_id = devices.id "
                "WHERE dns_logs.flagged = ? "
                "ORDER BY dns_logs.timestamp DESC",
                (1,),
            ).fetchall()

            sessions = connection.execute(
                "SELECT sessions.start_time, sessions.end_time, devices.ip, devices.mac "
                "FROM sessions JOIN devices ON sessions.device_id = devices.id "
                "ORDER BY sessions.start_time DESC",
                (),
            ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to query database: {exc}") from exc

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("ARGUS Network Intelligence - Disclosure Report")
    lines.append(f"Generated: {generated_at}")
    lines.append("=" * 72)
    lines.append("")

    lines.append("SCAN SUMMARY")
    lines.append("-" * 72)
    lines.append(f"Total Devices Discovered: {total_devices}")
    lines.append(f"Active Devices: {active_devices}")
    lines.append(f"Total DNS Queries Logged: {total_dns_logs}")
    lines.append(f"Flagged Domains: {flagged_count}")
    lines.append(f"Total Sessions: {total_sessions}")
    lines.append("")

    lines.append("FLAGGED DOMAINS")
    lines.append("-" * 72)
    if flagged_domains:
        flagged_rows = [
            (row["domain"], row["timestamp"], row["ip"], row["mac"])
            for row in flagged_domains
        ]
        lines.extend(
            _format_table(["Domain", "Timestamp", "Device IP", "Device MAC"], flagged_rows)
        )
    else:
        lines.append("No flagged domains recorded.")
    lines.append("")

    lines.append("SESSION LOG")
    lines.append("-" * 72)
    if sessions:
        session_rows = []
        for row in sessions:
            end_time = row["end_time"] if row["end_time"] else "Ongoing"
            session_rows.append((row["ip"], row["mac"], row["start_time"], end_time))
        lines.extend(
            _format_table(
                ["Device IP", "Device MAC", "Session Start", "Session End"],
                session_rows,
            )
        )
    else:
        lines.append("No sessions recorded.")
    lines.append("")

    lines.append("DEVICE INVENTORY")
    lines.append("-" * 72)
    if devices:
        device_rows = [
            (
                row["ip"],
                row["mac"],
                row["vendor"],
                row["os_guess"],
                row["status"],
                row["first_seen"],
                row["last_seen"],
            )
            for row in devices
        ]
        lines.extend(
            _format_table(
                [
                    "IP",
                    "MAC",
                    "Vendor",
                    "OS Guess",
                    "Status",
                    "First Seen",
                    "Last Seen",
                ],
                device_rows,
            )
        )
    else:
        lines.append("No devices found in database.")
    lines.append("")

    lines.append("METHODOLOGY")
    lines.append("-" * 72)
    lines.append(
        "ARGUS-recon: ARP-based discovery using Scapy, OUI vendor lookup, ICMP "
        "liveness probing, and TTL OS fingerprinting."
    )
    lines.append(
        "ARGUS-veil: Bidirectional ARP poisoning for MITM traffic capture, IP "
        "forwarding, and session recording."
    )
    lines.append(
        "ARGUS-oracle: DNS sniffing on VPN interface (proton0), domain flagging "
        "against a blocklist, and deduplication."
    )
    lines.append(
        "ARGUS-iris: Flask dashboard for data review and disclosure report generation."
    )

    report_text = "\n".join(lines)

    try:
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(report_text)
    except OSError as exc:
        raise RuntimeError(f"Failed to write report file: {output_path}") from exc

    print(f"Report saved to {output_path}")
    return output_path


if __name__ == "__main__":
    try:
        config = load_config()
        generate_text_report(config["db_path"])
    except KeyboardInterrupt:
        print("Interrupted by user")
        raise SystemExit(1)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)