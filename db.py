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


def get_sessions(db_path: str, device_id: int) -> List[Dict[str, Any]]:
    query = (
        "SELECT id, start_time, end_time "
        "FROM sessions WHERE device_id = ? ORDER BY start_time DESC"
    )
    with _connect(db_path) as connection:
        rows = connection.execute(query, (device_id,)).fetchall()
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