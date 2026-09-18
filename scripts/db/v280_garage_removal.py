#!/usr/bin/env python3
"""
One-shot cleanup for HomeNetMon 2.8.0: the garage door feature (2.6.0 board, 2.7.0 Ring camera)
is removed from the code; this removes its traces from an existing database.

Run with the service STOPPED (`systemctl --user stop homenetmon`) after a fresh backup
(`venv/bin/python scripts/backup_database.py`). Idempotent; dry run by default.

    venv/bin/python scripts/db/v280_garage_removal.py            # plan only
    venv/bin/python scripts/db/v280_garage_removal.py --execute  # apply
    venv/bin/python scripts/db/v280_garage_removal.py --db backups/copy.db --execute   # rehearse

Steps
  1. drop the garage_events table
  2. delete configuration rows named garage_* (and their history rows)
  3. delete alerts of the garage_* types
  4. delete the synthetic device rows the feature created (hostname ring-cam-* or
     custom_name 'Garage door (ratgdo)') when they have no monitoring data
"""
import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def resolve_db_path(cli_path):
    if cli_path:
        return Path(cli_path)
    url = os.environ.get('DATABASE_URL')
    if not url:
        env = PROJECT_ROOT / '.env'
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith('DATABASE_URL='):
                    url = line.split('=', 1)[1].strip()
    if not url:
        return PROJECT_ROOT / 'homeNetMon.db'
    if not url.startswith('sqlite:///'):
        sys.exit('this one-shot handles SQLite only')
    path = Path(url[len('sqlite:///'):])
    return path if path.is_absolute() else PROJECT_ROOT / path


def service_running():
    try:
        out = subprocess.run(['systemctl', '--user', 'is-active', 'homenetmon'], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() == 'active'
    except (OSError, subprocess.TimeoutExpired):
        return False


def table_exists(cur, name):
    return cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', help='SQLite file (default: DATABASE_URL / .env / homeNetMon.db)')
    ap.add_argument('--execute', action='store_true', help='apply the changes (default: dry run)')
    ap.add_argument('--force', action='store_true', help='ignore a running service')
    args = ap.parse_args()

    db_path = resolve_db_path(args.db)
    if not db_path.exists():
        sys.exit(f'database not found: {db_path}')
    if args.execute and not args.force and service_running():
        sys.exit('homenetmon is running; stop it first (systemctl --user stop homenetmon) or pass --force.')

    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    print(f"{'EXECUTE' if args.execute else 'DRY RUN'}: {db_path}")

    if table_exists(cur, 'garage_events'):
        rows = cur.execute('SELECT count(*) FROM garage_events').fetchone()[0]
        print(f'  1. drop garage_events ({rows} rows)')
        if args.execute:
            cur.execute('DROP TABLE garage_events')
    else:
        print('  1. garage_events: already gone')

    keys = [r['key'] for r in cur.execute("SELECT key FROM configuration WHERE key LIKE 'garage_%'")]
    history = 0
    if table_exists(cur, 'configuration_history'):
        history = cur.execute("SELECT count(*) FROM configuration_history WHERE config_key LIKE 'garage_%'").fetchone()[0]
    print(f'  2. configuration rows to delete: {keys} (+ {history} history rows)')
    if args.execute:
        cur.execute("DELETE FROM configuration WHERE key LIKE 'garage_%'")
        if history:
            cur.execute("DELETE FROM configuration_history WHERE config_key LIKE 'garage_%'")

    alerts = cur.execute("SELECT count(*) FROM alerts WHERE alert_type LIKE 'garage_%'").fetchone()[0]
    print(f'  3. garage alerts to delete: {alerts}')
    if args.execute and alerts:
        cur.execute("DELETE FROM alerts WHERE alert_type LIKE 'garage_%'")

    devices = cur.execute("SELECT id, hostname, custom_name FROM devices WHERE hostname LIKE 'ring-cam-%' "
                          "OR custom_name = 'Garage door (ratgdo)'").fetchall()
    for d in devices:
        data = cur.execute('SELECT count(*) FROM monitoring_data WHERE device_id = ?', (d['id'],)).fetchone()[0]
        if data:
            print(f"  4. device {d['id']} ({d['hostname'] or d['custom_name']}) kept: {data} monitoring rows")
            continue
        print(f"  4. device {d['id']} ({d['hostname'] or d['custom_name']}) to delete")
        if args.execute:
            cur.execute('DELETE FROM alerts WHERE device_id = ?', (d['id'],))
            cur.execute('DELETE FROM devices WHERE id = ?', (d['id'],))
    if not devices:
        print('  4. synthetic garage device rows: none')

    if args.execute:
        con.commit()
        cur.execute('VACUUM')
        print('done')
    con.close()


if __name__ == '__main__':
    main()
