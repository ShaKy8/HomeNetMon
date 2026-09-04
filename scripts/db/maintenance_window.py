#!/usr/bin/env python3
"""
One-shot SQLite maintenance window for HomeNetMon (Phase 2 of the 2026-09 remediation).

Run with the service STOPPED (`systemctl --user stop homenetmon`) and a fresh
backup taken (`python scripts/backup_database.py`). Idempotent: every step
checks whether it still applies. Dry-run by default; pass --execute to apply.

    venv/bin/python scripts/db/maintenance_window.py            # plan only
    venv/bin/python scripts/db/maintenance_window.py --execute  # apply
    venv/bin/python scripts/db/maintenance_window.py --db /path/copy.db --execute  # rehearse on a copy

Steps
  1. quick_check
  2. drop duplicate / unused indexes on monitoring_data and performance_metrics
  3. empty bandwidth_data (every row was synthetic: host total / N * random())
  4. delete performance_metrics rows computed from no ping data (health == constant 63.0)
  5. bulk-resolve the never-auto-resolved security_new_service alert backlog
  6. rebuild devices with ip_address nullable (scanner IP-conflict path) and 5 indexes instead of 20;
     drops the orphan view device_summary_optimized that referenced it
  7. drop orphan tables left by removed features (users, sessions, ...)
  8. wal_checkpoint(TRUNCATE); VACUUM; ANALYZE; integrity_check
"""
import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DROP_INDEXES = {
    'monitoring_data': [
        # timestamp-only duplicates (keep ix_monitoring_data_timestamp)
        'idx_monitoring_timestamp', 'idx_monitoring_timestamp_only', 'idx_monitoring_data_timestamp',
        # (device_id, timestamp) duplicates (keep model-declared idx_monitoring_device_timestamp)
        'idx_monitoring_data_device_timestamp', 'idx_monitoring_device_timestamp_desc',
        # device_id-only duplicate (keep ix_monitoring_data_device_id)
        'idx_monitoring_data_device_id',
        # covering indexes no query plan needs on a ~250k-row table
        'idx_monitoring_device_response', 'idx_monitoring_device_time_response',
        'idx_monitoring_timestamp_device', 'idx_monitoring_response_time',
    ],
    'performance_metrics': [
        'idx_performance_device_timestamp',   # == idx_perf_device_time
        'idx_performance_metrics_timestamp',  # == ix_performance_metrics_timestamp
        'idx_performance_timestamp_health',   # unused
    ],
}

# devices: 131 rows carried 20 indexes. Keep the unique/lookup ones and one per hot filter.
DEVICES_KEEP_INDEXES = [
    "CREATE UNIQUE INDEX ix_devices_ip_address ON devices (ip_address)",
    "CREATE INDEX ix_devices_mac_address ON devices (mac_address)",
    "CREATE INDEX idx_devices_monitored_last_seen ON devices (is_monitored, last_seen DESC)",
    "CREATE INDEX idx_devices_type_monitored ON devices (device_type, is_monitored)",
    "CREATE INDEX idx_devices_group_monitored ON devices (device_group, is_monitored)",
]

ORPHAN_TABLES = ['users', 'sessions', 'device_summary_cache', 'query_performance_log']


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
            if cmd.endswith('app.py') and (p.info['cwd'] or '').startswith(str(PROJECT_ROOT)):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


class Window:
    def __init__(self, db_path, execute, skip_vacuum):
        self.db_path = db_path
        self.execute = execute
        self.skip_vacuum = skip_vacuum
        self.conn = sqlite3.connect(str(db_path), timeout=10, isolation_level=None)
        self.conn.execute("PRAGMA foreign_keys=OFF")

    def q(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()[0]

    def run(self, label, sql):
        t0 = time.monotonic()
        if self.execute:
            self.conn.execute(sql)
            print(f"  [done {time.monotonic() - t0:6.1f}s] {label}")
        else:
            print(f"  [plan] {label}")

    def index_exists(self, name):
        return self.one("SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?", (name,)) == 1

    def table_exists(self, name):
        return self.one("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) == 1

    # ---- steps -------------------------------------------------------------
    def step_quick_check(self):
        print("1. quick_check")
        t0 = time.monotonic()
        result = self.one("PRAGMA quick_check")
        print(f"  {result} ({time.monotonic() - t0:.1f}s)")
        if result != 'ok':
            sys.exit("Database failed quick_check; aborting")

    def step_drop_indexes(self):
        print("2. drop duplicate/unused indexes")
        for table, names in DROP_INDEXES.items():
            for name in names:
                if self.index_exists(name):
                    ddl = self.one("SELECT sql FROM sqlite_master WHERE name=?", (name,))
                    print(f"  saved DDL: {ddl}")
                    self.run(f"DROP INDEX {name}", f"DROP INDEX IF EXISTS {name}")
                else:
                    print(f"  [skip] {name} already absent")
            remaining = [r[0] for r in self.q(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? ORDER BY name", (table,))]
            print(f"  {table} indexes after: {remaining}")

    def step_empty_bandwidth(self):
        print("3. empty bandwidth_data (synthetic per-device rows)")
        if not self.table_exists('bandwidth_data'):
            print("  [skip] table absent")
            return
        rows = self.one("SELECT count(*) FROM bandwidth_data")
        if rows == 0:
            print("  [skip] already empty")
            return
        ddl = self.one("SELECT sql FROM sqlite_master WHERE type='table' AND name='bandwidth_data'")
        idx_ddls = [r[0] for r in self.q(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='bandwidth_data' AND sql IS NOT NULL")]
        print(f"  {rows:,} rows; dropping and recreating the table with {len(idx_ddls)} index(es)")
        self.run("DROP TABLE bandwidth_data", "DROP TABLE bandwidth_data")
        self.run("CREATE TABLE bandwidth_data", ddl)
        for d in idx_ddls:
            self.run(d.split(' ON ')[0], d)

    def step_delete_garbage_perf(self):
        print("4. delete performance_metrics rows computed from zero ping checks")
        n = self.one("SELECT count(*) FROM performance_metrics WHERE total_checks IS NULL OR total_checks = 0")
        total = self.one("SELECT count(*) FROM performance_metrics")
        print(f"  {n:,} of {total:,} rows")
        if n:
            self.run("DELETE garbage performance_metrics",
                     "DELETE FROM performance_metrics WHERE total_checks IS NULL OR total_checks = 0")

    def step_resolve_security_backlog(self):
        print("5. bulk-resolve security_new_service alert backlog")
        n = self.one("SELECT count(*) FROM alerts WHERE alert_type='security_new_service' AND resolved=0")
        print(f"  {n:,} unresolved")
        if n:
            self.run("UPDATE alerts ... resolved",
                     "UPDATE alerts SET resolved=1, resolved_at=CURRENT_TIMESTAMP "
                     "WHERE alert_type='security_new_service' AND resolved=0")

    def step_rebuild_devices(self):
        print("6. rebuild devices: ip_address nullable, 5 indexes instead of 20")
        cols = self.q("PRAGMA table_info(devices)")
        ip_col = next(c for c in cols if c[1] == 'ip_address')
        n_idx = self.one("SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='devices' AND sql IS NOT NULL")
        if ip_col[3] == 0 and n_idx == len(DEVICES_KEEP_INDEXES):
            print("  [skip] already rebuilt")
            return
        ddl = self.one("SELECT sql FROM sqlite_master WHERE type='table' AND name='devices'")
        if 'ip_address VARCHAR(15) NOT NULL' not in ddl:
            sys.exit(f"Unexpected devices DDL; refusing to rebuild:\n{ddl}")
        new_ddl = ddl.replace('CREATE TABLE devices (', 'CREATE TABLE devices_new (', 1) \
                     .replace('ip_address VARCHAR(15) NOT NULL', 'ip_address VARCHAR(15)', 1)
        col_list = ', '.join(c[1] for c in cols)
        before = self.one("SELECT count(*) FROM devices")
        print(f"  {before} rows; {n_idx} indexes -> {len(DEVICES_KEEP_INDEXES)}")
        if not self.execute:
            print("  [plan] CREATE devices_new / INSERT ... SELECT / DROP devices / RENAME / recreate indexes")
            return
        # Views referencing `devices` block the RENAME. The only one in production
        # (device_summary_optimized) was created by an archived one-shot script and
        # is read by nothing in the runtime, so drop rather than recreate.
        views = self.q("SELECT name, sql FROM sqlite_master WHERE type='view' AND sql LIKE '%devices%'")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for name, sql in views:
                print(f"  dropping view {name} (DDL saved below)\n    {sql[:200].strip()}...")
                self.conn.execute(f"DROP VIEW {name}")
            self.conn.execute(new_ddl)
            self.conn.execute(f"INSERT INTO devices_new ({col_list}) SELECT {col_list} FROM devices")
            self.conn.execute("DROP TABLE devices")
            self.conn.execute("ALTER TABLE devices_new RENAME TO devices")
            for d in DEVICES_KEEP_INDEXES:
                self.conn.execute(d)
            after = self.one("SELECT count(*) FROM devices")
            if after != before:
                raise RuntimeError(f"row count changed {before} -> {after}")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        print(f"  [done] devices rebuilt ({after} rows); FK check:",
              self.q("PRAGMA foreign_key_check(devices)") or "ok")

    def step_drop_orphans(self):
        print("7. drop orphan tables from removed features")
        for t in ORPHAN_TABLES:
            if self.table_exists(t):
                rows = self.one(f"SELECT count(*) FROM {t}")
                self.run(f"DROP TABLE {t} ({rows} rows)", f"DROP TABLE {t}")
            else:
                print(f"  [skip] {t} absent")

    def step_compact(self):
        print("8. checkpoint, vacuum, analyze, integrity_check")
        self.run("PRAGMA wal_checkpoint(TRUNCATE)", "PRAGMA wal_checkpoint(TRUNCATE)")
        if self.skip_vacuum:
            print("  [skip] VACUUM (--skip-vacuum)")
        else:
            self.run("VACUUM", "VACUUM")
        self.run("ANALYZE", "ANALYZE")
        if self.execute:
            t0 = time.monotonic()
            result = self.one("PRAGMA integrity_check")
            print(f"  integrity_check: {result} ({time.monotonic() - t0:.1f}s)")
            if result != 'ok':
                sys.exit("integrity_check FAILED after maintenance; restore from backup")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', help='SQLite file (default: DATABASE_URL from env or .env)')
    ap.add_argument('--execute', action='store_true', help='apply changes (default: dry run)')
    ap.add_argument('--skip-vacuum', action='store_true')
    ap.add_argument('--force', action='store_true', help='proceed even if app.py appears to be running')
    args = ap.parse_args()

    db_path = resolve_db_path(args.db)
    if not db_path.exists():
        sys.exit(f"No such database: {db_path}")
    if args.execute and app_process_running() and not args.force:
        sys.exit("app.py appears to be running from this checkout. Stop the service first "
                 "(systemctl --user stop homenetmon) or pass --force.")

    print(f"Database: {db_path}  ({size_mb(db_path):,.0f} MB incl. WAL)  mode: {'EXECUTE' if args.execute else 'DRY RUN'}")
    w = Window(db_path, args.execute, args.skip_vacuum)
    t0 = time.monotonic()
    w.step_quick_check()
    w.step_drop_indexes()
    w.step_empty_bandwidth()
    w.step_delete_garbage_perf()
    w.step_resolve_security_backlog()
    w.step_rebuild_devices()
    w.step_drop_orphans()
    w.step_compact()
    w.conn.close()
    print(f"Finished in {time.monotonic() - t0:.0f}s. Size now: {size_mb(db_path):,.0f} MB incl. WAL")


if __name__ == '__main__':
    main()
