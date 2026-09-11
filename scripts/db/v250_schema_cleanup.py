#!/usr/bin/env python3
"""
One-shot SQLite schema cleanup for HomeNetMon 2.5.0.

Run with the service STOPPED (`systemctl --user stop homenetmon`) after a fresh
backup (`venv/bin/python scripts/backup_database.py`). Idempotent: every step
checks whether it still applies. Dry-run by default; pass --execute to apply.

    venv/bin/python scripts/db/v250_schema_cleanup.py            # plan only
    venv/bin/python scripts/db/v250_schema_cleanup.py --execute  # apply
    venv/bin/python scripts/db/v250_schema_cleanup.py --db backups/copy.db --execute   # rehearse

Steps
  1. quick_check
  2. drop the tables of the models removed in 2.5.0 (escalation, automation rules,
     notification receipts, speed test results, vulnerability/compliance/OS info);
     refuses to drop a non-empty table unless --force
  3. delete anomaly_* / speedtest_* runtime configuration keys (and their history)
  4. add devices.notes / devices.tags / devices.mdns_services (device identification)
  5. archive devices whose IP lies outside the runtime network range
     (the monitor no longer pings them; they resume automatically if the range widens)
  6. wal_checkpoint(TRUNCATE); VACUUM; ANALYZE; integrity_check
"""
import argparse
import ipaddress
import os
import sqlite3
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DROP_TABLES = [
    'escalation_action_logs', 'escalation_executions', 'escalation_rules',
    'rule_executions', 'automation_rules',
    'notification_receipts', 'speed_test_results',
    'security_vulnerabilities', 'compliance_results', 'device_os_info',
]

NEW_DEVICE_COLUMNS = {
    'notes': 'TEXT',
    'tags': 'VARCHAR(255)',
    'mdns_services': 'VARCHAR(500)',
}

DEAD_CONFIG_PREFIXES = ('anomaly_', 'speedtest_')


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
        url = f"sqlite:///{PROJECT_ROOT / 'homeNetMon.db'}"
    if not url.startswith('sqlite:///'):
        sys.exit(f"Only SQLite is supported by this script (DATABASE_URL={url})")
    p = Path(url[len('sqlite:///'):])
    return p if p.is_absolute() else PROJECT_ROOT / p


def size_mb(path):
    total = 0
    for suffix in ('', '-wal', '-shm'):
        f = Path(str(path) + suffix)
        if f.exists():
            total += f.stat().st_size
    return total / 1e6


def app_process_running():
    try:
        import psutil
    except ImportError:
        return False
    for p in psutil.process_iter(['cmdline', 'cwd']):
        try:
            cmd = ' '.join(p.info['cmdline'] or [])
            in_checkout = (p.info['cwd'] or '').startswith(str(PROJECT_ROOT))
            if in_checkout and (cmd.endswith('app.py') or ('gunicorn' in cmd and 'wsgi:app' in cmd)):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


class Cleanup:
    def __init__(self, db_path, execute, force, skip_vacuum):
        self.db_path = db_path
        self.execute = execute
        self.force = force
        self.skip_vacuum = skip_vacuum
        self.conn = sqlite3.connect(str(db_path), timeout=10, isolation_level=None)
        self.conn.execute("PRAGMA foreign_keys=OFF")

    def one(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()[0]

    def run(self, label, sql, params=()):
        t0 = time.monotonic()
        if self.execute:
            self.conn.execute(sql, params)
            print(f"  [done {time.monotonic() - t0:6.1f}s] {label}")
        else:
            print(f"  [plan] {label}")

    def table_exists(self, name):
        return self.one("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) == 1

    def columns(self, table):
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def step_quick_check(self):
        print("1. quick_check")
        result = self.one("PRAGMA quick_check")
        print(f"  {result}")
        if result != 'ok':
            sys.exit("quick_check failed; restore from backup before continuing")

    def step_drop_tables(self):
        print("2. drop tables of removed models")
        for table in DROP_TABLES:
            if not self.table_exists(table):
                print(f"  [skip] {table}: already gone")
                continue
            rows = self.one(f"SELECT count(*) FROM {table}")
            if rows and not self.force:
                sys.exit(f"{table} has {rows} row(s); refusing to drop without --force")
            self.run(f"DROP TABLE {table} ({rows} rows)", f"DROP TABLE {table}")

    def step_dead_config(self):
        print("3. delete runtime configuration keys of removed features")
        for prefix in DEAD_CONFIG_PREFIXES:
            like = prefix.replace('_', r'\_') + '%'
            n = self.one("SELECT count(*) FROM configuration WHERE key LIKE ? ESCAPE '\\'", (like,))
            h = self.one("SELECT count(*) FROM configuration_history WHERE config_key LIKE ? ESCAPE '\\'", (like,)) \
                if self.table_exists('configuration_history') else 0
            if not n and not h:
                print(f"  [skip] {prefix}*: none")
                continue
            self.run(f"DELETE {n} configuration + {h} history rows for {prefix}*",
                     "DELETE FROM configuration WHERE key LIKE ? ESCAPE '\\'", (like,))
            if h:
                self.run(f"DELETE history rows for {prefix}*",
                         "DELETE FROM configuration_history WHERE config_key LIKE ? ESCAPE '\\'", (like,))

    def step_device_columns(self):
        print("4. add device identification columns")
        have = self.columns('devices')
        for col, ddl in NEW_DEVICE_COLUMNS.items():
            if col in have:
                print(f"  [skip] devices.{col}: exists")
            else:
                self.run(f"ALTER TABLE devices ADD COLUMN {col} {ddl}", f"ALTER TABLE devices ADD COLUMN {col} {ddl}")

    def step_archive_out_of_range(self):
        print("5. archive monitored devices outside the network range")
        row = self.conn.execute("SELECT value FROM configuration WHERE key='network_range'").fetchone()
        network_range = row[0] if row else None
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except (ValueError, TypeError):
            print(f"  [skip] no parsable network_range in configuration ({network_range!r})")
            return
        rows = self.conn.execute(
            "SELECT id, ip_address, hostname FROM devices WHERE is_monitored=1 AND ip_address IS NOT NULL").fetchall()
        outside = []
        for dev_id, ip, hostname in rows:
            try:
                if ipaddress.ip_address(ip) not in network:
                    outside.append((dev_id, ip, hostname))
            except ValueError:
                outside.append((dev_id, ip, hostname))
        if not outside:
            print(f"  [skip] every monitored device is inside {network}")
            return
        for dev_id, ip, hostname in outside:
            print(f"    - #{dev_id} {ip} {hostname or ''}")
        ids = ','.join(str(d[0]) for d in outside)
        self.run(f"archive {len(outside)} device(s) outside {network}",
                 f"UPDATE devices SET is_monitored=0, updated_at=CURRENT_TIMESTAMP WHERE id IN ({ids})")

    def step_compact(self):
        print("6. checkpoint / VACUUM / ANALYZE / integrity_check")
        self.run("wal_checkpoint(TRUNCATE)", "PRAGMA wal_checkpoint(TRUNCATE)")
        if self.skip_vacuum:
            print("  [skip] VACUUM (--skip-vacuum)")
        else:
            self.run("VACUUM", "VACUUM")
        self.run("ANALYZE", "ANALYZE")
        if self.execute:
            result = self.one("PRAGMA integrity_check")
            print(f"  integrity_check: {result}")
            if result != 'ok':
                sys.exit("integrity_check FAILED; restore from backup")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', help='SQLite file (default: DATABASE_URL from env or .env)')
    ap.add_argument('--execute', action='store_true', help='apply changes (default: dry run)')
    ap.add_argument('--skip-vacuum', action='store_true')
    ap.add_argument('--force', action='store_true', help='drop non-empty tables / ignore a running app')
    args = ap.parse_args()

    db_path = resolve_db_path(args.db)
    if not db_path.exists():
        sys.exit(f"No such database: {db_path}")
    if args.execute and app_process_running() and not args.force:
        sys.exit("HomeNetMon appears to be running from this checkout. Stop the service first "
                 "(systemctl --user stop homenetmon) or pass --force.")

    print(f"Database: {db_path}  ({size_mb(db_path):,.0f} MB incl. WAL)  mode: {'EXECUTE' if args.execute else 'DRY RUN'}")
    c = Cleanup(db_path, args.execute, args.force, args.skip_vacuum)
    t0 = time.monotonic()
    c.step_quick_check()
    c.step_drop_tables()
    c.step_dead_config()
    c.step_device_columns()
    c.step_archive_out_of_range()
    c.step_compact()
    c.conn.close()
    print(f"Finished in {time.monotonic() - t0:.0f}s. Size now: {size_mb(db_path):,.0f} MB incl. WAL")


if __name__ == '__main__':
    main()
