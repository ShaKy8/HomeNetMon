#!/usr/bin/env python3
"""
One-shot cleanup for HomeNetMon 2.7.0: the ratgdo (garage door board) path is gone.

Removes the runtime settings and the synthetic device row that 2.6.0 created for the
board. Run with the service STOPPED (`systemctl --user stop homenetmon`) after a fresh
backup (`venv/bin/python scripts/backup_database.py`). Idempotent; dry run by default.

    venv/bin/python scripts/db/v270_garage_cleanup.py            # plan only
    venv/bin/python scripts/db/v270_garage_cleanup.py --execute  # apply
    venv/bin/python scripts/db/v270_garage_cleanup.py --db backups/copy.db --execute   # rehearse

Steps
  1. delete configuration rows garage_host / garage_username / garage_password /
     garage_poll_interval / garage_offline_after_polls (and their history rows)
  2. delete the "Garage door (ratgdo)" device row when it has no monitoring data or alerts
"""
import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEAD_KEYS = ('garage_host', 'garage_username', 'garage_password', 'garage_poll_interval', 'garage_offline_after_polls')
DEAD_DEVICE_NAME = 'Garage door (ratgdo)'


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
    raw = url[len('sqlite:///'):]
    path = Path(raw)
    return path if path.is_absolute() else PROJECT_ROOT / path


def service_running():
    try:
        out = subprocess.run(['systemctl', '--user', 'is-active', 'homenetmon'], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() == 'active'
    except (OSError, subprocess.TimeoutExpired):
        return False


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
    mode = 'EXECUTE' if args.execute else 'DRY RUN'
    print(f'{mode}: {db_path}')

    placeholders = ','.join('?' for _ in DEAD_KEYS)
    rows = cur.execute(f'SELECT key FROM configuration WHERE key IN ({placeholders})', DEAD_KEYS).fetchall()
    history = 0
    if cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='configuration_history'").fetchone():
        history = cur.execute(f'SELECT count(*) FROM configuration_history WHERE config_key IN ({placeholders})', DEAD_KEYS).fetchone()[0]
    print(f'  1. configuration rows to delete: {[r["key"] for r in rows]} (+ {history} history rows)')
    if args.execute:
        cur.execute(f'DELETE FROM configuration WHERE key IN ({placeholders})', DEAD_KEYS)
        if history:
            cur.execute(f'DELETE FROM configuration_history WHERE config_key IN ({placeholders})', DEAD_KEYS)

    device = cur.execute('SELECT id FROM devices WHERE custom_name = ?', (DEAD_DEVICE_NAME,)).fetchone()
    if device is None:
        print('  2. ratgdo device row: none')
    else:
        did = device['id']
        data = cur.execute('SELECT count(*) FROM monitoring_data WHERE device_id = ?', (did,)).fetchone()[0]
        alerts = cur.execute('SELECT count(*) FROM alerts WHERE device_id = ?', (did,)).fetchone()[0]
        if data or alerts:
            print(f'  2. ratgdo device row {did} kept: {data} monitoring rows, {alerts} alerts')
        else:
            print(f'  2. ratgdo device row {did} to delete')
            if args.execute:
                cur.execute('DELETE FROM devices WHERE id = ?', (did,))

    if args.execute:
        con.commit()
        print('done')
    con.close()


if __name__ == '__main__':
    main()
