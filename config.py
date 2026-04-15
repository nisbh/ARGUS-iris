import json
import os
from typing import Any, Dict


def load_config() -> Dict[str, Any]:
    base = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base, "config.json")

    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            raw_config = json.load(config_file)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Config file is not valid JSON: {config_path}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not read config file: {config_path}") from exc

    required_keys = ("interface", "gateway_ip", "subnet", "db_path")
    missing_keys = [key for key in required_keys if key not in raw_config]
    if missing_keys:
        missing_str = ", ".join(missing_keys)
        raise RuntimeError(f"Missing required config keys: {missing_str}")

    db_path_value = str(raw_config["db_path"])
    resolved_db_path = os.path.normpath(os.path.join(base, db_path_value))
    resolved_abs_path = os.path.abspath(resolved_db_path)

    allowed_prefix = os.path.dirname(base)
    if not resolved_abs_path.startswith(allowed_prefix):
        raise RuntimeError(
            "Invalid db_path: resolved path must stay within allowed directory scope"
        )

    if not resolved_abs_path.endswith(".db"):
        raise RuntimeError("Invalid db_path: database path must end with '.db'")

    if not os.path.exists(resolved_abs_path):
        raise RuntimeError(f"Database file does not exist: {resolved_abs_path}")

    return {
        "interface": raw_config["interface"],
        "gateway_ip": raw_config["gateway_ip"],
        "subnet": raw_config["subnet"],
        "db_path": resolved_abs_path,
    }