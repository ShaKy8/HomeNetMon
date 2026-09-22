#!/usr/bin/env python3
"""
One-shot cleanup for HomeNetMon 2.9.0 (alert policy): apply to an existing database
what fresh installs get from the code.

Run with the service STOPPED (`systemctl --user stop homenetmon`) after a fresh backup
(`venv/bin/python scripts/backup_database.py`). Idempotent; dry run by default.

    venv/bin/python scripts/db/v290_cleanup.py            # plan only
    venv/bin/python scripts/db/v290_cleanup.py --execute  # apply
    venv/bin/python scripts/db/v290_cleanup.py --db backups/copy.db --execute   # rehearse

Steps
  1. add devices.alert_on_down (nullable boolean; init_db also does this at startup)
  2. migrate the seeded "Quiet Hours - Night Time" suppression rule into the
     notify_quiet_hours_start/end settings when those are unset
  3. delete the eight suppression rules AlertManager.setup_default_suppressions used to
     seed (matched by exact name and created_by='user'); user-made rules are kept
  4. delete alerts of removed types (escalated_alert, anomaly_*)
  5. drop the six bandwidth columns performance_metrics no longer maps (SQLite >= 3.35)
  6. VACUUM
"""
import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SEEDED_RULE_NAMES = [
    'Quiet Hours - Night Time',
    'Performance Warning Suppression',
    'Performance Reliability Rate Limiting',
    'Performance Responsiveness Rate Limiting',
    'Recurring Performance Alert Suppression',
    'Anomaly Alert Suppression',
    'Info Level Recovery Alert Suppression',
    'Performance Alert Burst Protection',
]
QUIET_RULE = 'Quiet Hours - Night Time'
REMOVED_ALERT_TYPES = ('escalated_alert',)
BANDWIDTH_COLUMNS = ['avg_bandwidth_in_mbps', 'avg_bandwidth_out_mbps', 'peak_bandwidth_in_mbps',
                     'peak_bandwidth_out_mbps', 'total_bytes_in', 'total_bytes_out']


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


def columns(cur, table):
    return [r[1] for r in cur.execute(f'PRAGMA table_info({table})')]


def config_value(cur, key):
    row = cur.execute('SELECT value FROM configuration WHERE key = ?', (key,)).fetchone()
    return None if row is None else row[0]


def set_config(cur, key, value, description):
    cur.execute("INSERT INTO configuration (key, value, description, created_at, updated_at, version) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP, "
                "version = coalesce(configuration.version, 0) + 1",
                (key, value, description))


def run(db_path, execute):
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    print(f"{'EXECUTE' if execute else 'DRY RUN'}: {db_path}")

    # 1. devices.alert_on_down
    if 'alert_on_down' in columns(cur, 'devices'):
        print('  1. devices.alert_on_down: already present')
    else:
        print('  1. add devices.alert_on_down BOOLEAN')
        if execute:
            cur.execute('ALTER TABLE devices ADD COLUMN alert_on_down BOOLEAN')

    # 2. quiet-hours migration
    if table_exists(cur, 'alert_suppressions'):
        rule = cur.execute("SELECT * FROM alert_suppressions WHERE name = ? AND created_by = 'user'", (QUIET_RULE,)).fetchone()
        start_set = (config_value(cur, 'notify_quiet_hours_start') or '') != ''
        if rule is None:
            print('  2. quiet-hours rule: not present, nothing to migrate')
        elif start_set:
            print('  2. quiet-hours settings already set; rule not migrated')
        elif rule['daily_start_hour'] is None or rule['daily_end_hour'] is None or not rule['enabled']:
            print('  2. quiet-hours rule has no hours or is disabled; not migrated')
        else:
            print(f"  2. migrate quiet hours {rule['daily_start_hour']:02d}:00-{rule['daily_end_hour']:02d}:00 into notify_quiet_hours_start/end")
            if execute:
                set_config(cur, 'notify_quiet_hours_start', str(rule['daily_start_hour']), 'Quiet hours (local time, 0-23; blank = off)')
                set_config(cur, 'notify_quiet_hours_end', str(rule['daily_end_hour']), 'Quiet hours (local time, 0-23; blank = off)')

        # 3. seeded rules
        placeholders = ','.join('?' * len(SEEDED_RULE_NAMES))
        seeded = cur.execute(f"SELECT id, name FROM alert_suppressions WHERE created_by = 'user' AND name IN ({placeholders})",
                             SEEDED_RULE_NAMES).fetchall()
        print(f"  3. seeded suppression rules to delete: {[r['name'] for r in seeded] or 'none'}")
        if execute and seeded:
            cur.execute(f"DELETE FROM alert_suppressions WHERE id IN ({','.join('?' * len(seeded))})", [r['id'] for r in seeded])
    else:
        print('  2./3. alert_suppressions table missing; skipped')

    # 4. alerts of removed types
    removed = cur.execute("SELECT count(*) FROM alerts WHERE alert_type IN (%s) OR alert_type LIKE 'anomaly_%%'"
                          % ','.join('?' * len(REMOVED_ALERT_TYPES)), REMOVED_ALERT_TYPES).fetchone()[0]
    print(f'  4. alerts of removed types to delete: {removed}')
    if execute and removed:
        cur.execute("DELETE FROM alerts WHERE alert_type IN (%s) OR alert_type LIKE 'anomaly_%%'"
                    % ','.join('?' * len(REMOVED_ALERT_TYPES)), REMOVED_ALERT_TYPES)

    # 5. dead performance_metrics columns
    if table_exists(cur, 'performance_metrics'):
        present = [c for c in BANDWIDTH_COLUMNS if c in columns(cur, 'performance_metrics')]
        if not present:
            print('  5. performance_metrics bandwidth columns: already gone')
        elif sqlite3.sqlite_version_info < (3, 35, 0):
            print(f'  5. SQLite {sqlite3.sqlite_version} cannot DROP COLUMN; leaving {present}')
        else:
            print(f'  5. drop performance_metrics columns {present}')
            if execute:
                for col in present:
                    cur.execute(f'ALTER TABLE performance_metrics DROP COLUMN {col}')
    else:
        print('  5. performance_metrics table missing; skipped')

    if execute:
        con.commit()
        cur.execute('VACUUM')
        print('done')
    con.close()


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
    run(db_path, args.execute)


if __name__ == '__main__':
    main()
