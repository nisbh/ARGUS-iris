# ARGUS-IRIS

ARGUS-IRIS is a local-use Flask dashboard for reviewing network intelligence data stored in SQLite and generating disclosure reports in both HTML and plain text formats.

## What It Includes

- Device overview page with summary stats
- Per-device detail view with DNS logs and sessions
- Disclosure report page optimized for screen and print
- Standalone plain text disclosure report generator

## Project Files

```text
ARGUS-iris/
  config.py          # Config loader and db_path validation
  db.py              # Raw sqlite3 data-access functions
  main.py            # Flask app routes
  report.py          # Plain text report generator
  requirements.txt   # Python dependencies
  templates/         # Jinja2 templates
  static/            # CSS stylesheet
```

## Prerequisites

- Python 3.10+
- A SQLite database file with ARGUS tables

## Setup

1. Open a terminal in the project directory.
2. Create a virtual environment.
3. Install dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Configuration

Create a `config.json` file in the project root:

```json
{
  "interface": "eth0",
  "gateway_ip": "192.168.1.1",
  "subnet": "192.168.1.0/24",
  "db_path": "./data/argus.db"
}
```

Notes:

- `db_path` is resolved relative to the project directory.
- The resolved path must end with `.db`.
- The database file must already exist.

## Run The Flask App

```bash
python main.py
```

Then open:

- http://127.0.0.1:5000/

## Generate A Plain Text Disclosure Report

```bash
python report.py
```

Default output file:

- `argus_disclosure_report.txt`

You can also call it directly from Python:

```python
from report import generate_text_report

generate_text_report("/absolute/path/to/argus.db", "custom_report.txt")
```

## Expected Database Tables

- `devices`: `id`, `ip`, `mac`, `vendor`, `first_seen`, `last_seen`, optional `status`, optional `os_guess`
- `dns_logs`: `id`, `device_id`, `domain`, `timestamp`, `flagged`
- `sessions`: `id`, `device_id`, `start_time`, `end_time`

## Operational Notes

- This app is designed for local use only.
- No authentication is implemented.
- All database access uses raw `sqlite3` with parameterized queries.