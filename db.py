import sqlite3
from typing import Any, Dict, List, Optional, Tuple


def _connect(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def _devices_has_optional_columns(connection: sqlite3.Connection) -> Tuple[bool, bool]:
    rows = connection.execute("PRAGMA table_info(devices)").fetchall()
    columns = {row["name"] for row in rows}
    return "status" in columns, "os_guess" in columns


def _rows_to_dicts(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(row) for row in rows]


def get_all_devices(db_path: str) -> List[Dict[str, Any]]:
    with _connect(db_path) as connection:
        has_status, has_os_guess = _devices_has_optional_columns(connection)

        if has_status and has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, status, os_guess "
                "FROM devices ORDER BY last_seen DESC"
            )
            params: Tuple[Any, ...] = ()
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
        return _rows_to_dicts(rows)


def get_overview_devices(
    db_path: str,
    sort_column: str = "last_seen",
    sort_order: str = "DESC",
) -> List[Dict[str, Any]]:
    allowed_sort_columns = {
        "ip": "ip",
        "vendor": "vendor",
        "status": "status",
        "last_seen": "last_seen",
    }
    safe_column = allowed_sort_columns.get(sort_column, "last_seen")
    safe_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

    with _connect(db_path) as connection:
        has_status, has_os_guess = _devices_has_optional_columns(connection)

        if has_status and has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, status, os_guess "
                f"FROM devices ORDER BY {safe_column} {safe_order}"
            )
            params: Tuple[Any, ...] = ()
        elif not has_status and has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, os_guess "
                f"FROM devices ORDER BY {safe_column} {safe_order}"
            )
            params = ("UNKNOWN",)
        elif has_status and not has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, status, ? AS os_guess "
                f"FROM devices ORDER BY {safe_column} {safe_order}"
            )
            params = ("Unknown",)
        else:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, ? AS os_guess "
                f"FROM devices ORDER BY {safe_column} {safe_order}"
            )
            params = ("UNKNOWN", "Unknown")

        rows = connection.execute(query, params).fetchall()
        return _rows_to_dicts(rows)


def get_latest_device_seen(db_path: str) -> Optional[str]:
    with _connect(db_path) as connection:
        row = connection.execute("SELECT MAX(last_seen) AS latest FROM devices").fetchone()
        if row is None:
            return None
        return row["latest"]


def get_device(db_path: str, device_id: int) -> Optional[Dict[str, Any]]:
    with _connect(db_path) as connection:
        has_status, has_os_guess = _devices_has_optional_columns(connection)

        if has_status and has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, status, os_guess "
                "FROM devices WHERE id = ?"
            )
            params: Tuple[Any, ...] = (device_id,)
        elif not has_status and has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, os_guess "
                "FROM devices WHERE id = ?"
            )
            params = ("UNKNOWN", device_id)
        elif has_status and not has_os_guess:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, status, ? AS os_guess "
                "FROM devices WHERE id = ?"
            )
            params = ("Unknown", device_id)
        else:
            query = (
                "SELECT id, ip, mac, vendor, first_seen, last_seen, ? AS status, ? AS os_guess "
                "FROM devices WHERE id = ?"
            )
            params = ("UNKNOWN", "Unknown", device_id)

        row = connection.execute(query, params).fetchone()
        return dict(row) if row is not None else None


def get_dns_logs(db_path: str, device_id: int) -> List[Dict[str, Any]]:
    query = (
        "SELECT id, domain, timestamp, flagged "
        "FROM dns_logs WHERE device_id = ? ORDER BY timestamp DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query, (device_id,)).fetchall()
        return _rows_to_dicts(rows)


def get_dns_top_domains(db_path: str, device_id: int) -> List[Dict[str, Any]]:
    query = (
        "SELECT domain, COUNT(*) AS cnt "
        "FROM dns_logs "
        "WHERE device_id = ? "
        "GROUP BY domain "
        "ORDER BY cnt DESC, domain ASC "
        "LIMIT 5"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query, (device_id,)).fetchall()
        return _rows_to_dicts(rows)


def get_sessions(db_path: str, device_id: int) -> List[Dict[str, Any]]:
    query = (
        "SELECT id, start_time, end_time "
        "FROM sessions WHERE device_id = ? ORDER BY start_time DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query, (device_id,)).fetchall()
        return _rows_to_dicts(rows)


def get_status_history(db_path: str, device_id: int) -> List[Dict[str, Any]]:
    query = (
        "SELECT status, timestamp "
        "FROM status_log WHERE device_id = ? ORDER BY timestamp DESC LIMIT 50"
    )
    with _connect(db_path) as connection:
        try:
            rows = connection.execute(query, (device_id,)).fetchall()
        except sqlite3.OperationalError:
            return []
        return _rows_to_dicts(rows)


def get_flagged_domains(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT dns_logs.domain, dns_logs.timestamp, devices.ip, devices.mac "
        "FROM dns_logs JOIN devices ON dns_logs.device_id = devices.id "
        "WHERE dns_logs.flagged = 1 "
        "ORDER BY dns_logs.timestamp DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query).fetchall()
        return _rows_to_dicts(rows)


def get_all_sessions(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT sessions.id, sessions.start_time, sessions.end_time, devices.ip, devices.mac "
        "FROM sessions JOIN devices ON sessions.device_id = devices.id "
        "ORDER BY sessions.start_time DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query).fetchall()
        return _rows_to_dicts(rows)


def get_summary_stats(db_path: str) -> Dict[str, int]:
    with _connect(db_path) as connection:
        total_devices_row = connection.execute(
            "SELECT COUNT(*) AS count FROM devices"
        ).fetchone()
        total_devices = int(total_devices_row["count"]) if total_devices_row else 0

        has_status, _ = _devices_has_optional_columns(connection)
        if has_status:
            active_devices_row = connection.execute(
                "SELECT COUNT(*) AS count FROM devices WHERE status = ?", ("ACTIVE",)
            ).fetchone()
            active_devices = int(active_devices_row["count"]) if active_devices_row else 0
        else:
            active_devices = 0

        total_dns_logs_row = connection.execute(
            "SELECT COUNT(*) AS count FROM dns_logs"
        ).fetchone()
        total_dns_logs = int(total_dns_logs_row["count"]) if total_dns_logs_row else 0

        flagged_count_row = connection.execute(
            "SELECT COUNT(*) AS count FROM dns_logs WHERE flagged = 1"
        ).fetchone()
        flagged_count = int(flagged_count_row["count"]) if flagged_count_row else 0

        total_sessions_row = connection.execute(
            "SELECT COUNT(*) AS count FROM sessions"
        ).fetchone()
        total_sessions = int(total_sessions_row["count"]) if total_sessions_row else 0

    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "total_dns_logs": total_dns_logs,
        "flagged_count": flagged_count,
        "total_sessions": total_sessions,
    }


def get_sni_logs(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT src_ip, hostname, timestamp "
        "FROM sni_logs "
        "ORDER BY timestamp DESC"
    )
    with _connect(db_path) as connection:
        try:
            rows = connection.execute(query).fetchall()
        except sqlite3.OperationalError:
            return []
        return _rows_to_dicts(rows)


def get_sni_summary(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT src_ip, COUNT(DISTINCT hostname) AS unique_hosts, COUNT(*) AS total "
        "FROM sni_logs "
        "GROUP BY src_ip "
        "ORDER BY total DESC"
    )
    with _connect(db_path) as connection:
        try:
            rows = connection.execute(query).fetchall()
        except sqlite3.OperationalError:
            return []
        return _rows_to_dicts(rows)


def get_vendor_distribution(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT COALESCE(NULLIF(vendor, ''), 'Unknown') AS vendor, COUNT(*) AS cnt "
        "FROM devices "
        "GROUP BY COALESCE(NULLIF(vendor, ''), 'Unknown') "
        "ORDER BY cnt DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query).fetchall()
        return _rows_to_dicts(rows)


def get_mac_randomisation_stats(db_path: str) -> Dict[str, Any]:
    with _connect(db_path) as connection:
        total_row = connection.execute("SELECT COUNT(*) AS count FROM devices").fetchone()
        randomised_row = connection.execute(
            "SELECT COUNT(*) AS count FROM devices WHERE vendor = ?",
            ("Unknown (randomised MAC)",),
        ).fetchone()

        total = int(total_row["count"]) if total_row else 0
        randomised = int(randomised_row["count"]) if randomised_row else 0
        real = total - randomised
        rate = round((randomised / total) * 100, 1) if total > 0 else 0

    return {
        "total": total,
        "randomised": randomised,
        "real": real,
        "rate": rate,
    }


def get_top_dns_devices(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT devices.ip, COUNT(dns_logs.id) AS query_count "
        "FROM dns_logs "
        "JOIN devices ON dns_logs.device_id = devices.id "
        "GROUP BY devices.id "
        "ORDER BY query_count DESC "
        "LIMIT 10"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query).fetchall()
        return _rows_to_dicts(rows)


def get_persistent_devices(db_path: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT ip, mac, vendor, first_seen, last_seen "
        "FROM devices "
        "WHERE first_seen != last_seen "
        "ORDER BY first_seen ASC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query).fetchall()
        return _rows_to_dicts(rows)