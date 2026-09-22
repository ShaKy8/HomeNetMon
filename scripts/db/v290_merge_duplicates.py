#!/usr/bin/env python3
"""
One-shot for HomeNetMon 2.9.0: fold duplicate device rows created by rotating
(randomized) MAC addresses into one row per device.

Phones and laptops with "private Wi-Fi address" come back with a new MAC after a
while; every rotation used to create a new row, so one iPhone became five rows.
From 2.9.0 the scanner adopts a rotated MAC into the existing row; this script
cleans up what accumulated before.

Run with the service STOPPED after a fresh backup (`venv/bin/python scripts/backup_database.py`).
Dry run by default; review every group before `--execute`.

    venv/bin/python scripts/db/v290_merge_duplicates.py                  # plan
    venv/bin/python scripts/db/v290_merge_duplicates.py --execute        # apply
    venv/bin/python scripts/db/v290_merge_duplicates.py --only ksp-mac   # one group
    venv/bin/python scripts/db/v290_merge_duplicates.py --skip sonoszp --skip iphone --execute
    venv/bin/python scripts/db/v290_merge_duplicates.py --force-pair 83 134 --execute   # two ids, whatever their names
    venv/bin/python scripts/db/v290_merge_duplicates.py --db backups/copy.db --execute  # rehearse

Grouping: rows share identity_key(hostname) (lower-case, domain suffix stripped).
A group is SKIPPED when
  - two or more rows have real (globally unique) MACs: a product name shared by
    several units (Sonos, Google Home Mini, Espressif boards);
  - it is named by --skip.
Rows that COEXISTED stay separate: two rows that answered pings in three or more of
the same 30-minute windows are two devices (two iPads with the same name; a laptop
on Wi-Fi and on a dock; a stale reverse-DNS name on a reused address). A one- or
two-window overlap is the hand-over when a MAC rotates. The rest of the group is
MERGED into the most recently seen row (tie: real MAC, then lowest id):
monitoring_data, alerts, device_ip_history, security_scans,
security_events, performance_metrics, notification_history and alert_suppressions
move to the kept row; empty name / notes / tags / group / room are filled from the
dropped rows; is_monitored is true if any row was; a device_ip_history note records
what was folded; the dropped rows are deleted. --delete-orphans also removes child
rows whose device no longer exists.
"""
import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
from monitoring.device_classifier import identity_key, is_locally_administered  # noqa: E402

CHILD_TABLES = ('monitoring_data', 'alerts', 'device_ip_history', 'security_scans', 'security_events',
                'performance_metrics', 'notification_history', 'alert_suppressions')
FILL_COLUMNS = ('custom_name', 'notes', 'tags', 'device_group', 'room_location')
COEXIST_WINDOW_SECONDS = 1800


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


def real_mac(row):
    return bool(row['mac_address']) and not is_locally_administered(row['mac_address'])


def presence_buckets(cur, device_id):
    """30-minute buckets in which the device answered a ping."""
    rows = cur.execute(
        "SELECT DISTINCT CAST(strftime('%s', timestamp) / ? AS INTEGER) FROM monitoring_data "
        "WHERE device_id = ? AND response_time IS NOT NULL", (COEXIST_WINDOW_SECONDS, device_id)).fetchall()
    return {r[0] for r in rows}


COEXIST_MIN_BUCKETS = 3


def coexistence_edges(cur, rows):
    """{(id_a, id_b): shared windows} for pairs that answered pings in >= 3 of the same
    30-minute windows: two devices, not one device with a rotated MAC."""
    buckets = {r['id']: presence_buckets(cur, r['id']) for r in rows}
    edges = {}
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            shared = len(buckets[a['id']] & buckets[b['id']])
            if shared >= COEXIST_MIN_BUCKETS:
                edges[(a['id'], b['id'])] = shared
    return edges


def choose_keeper(rows):
    def key(r):
        return (r['last_seen'] or '', 1 if real_mac(r) else 0, -r['id'])
    return max(rows, key=key)


def child_counts(cur, device_id):
    return {t: cur.execute(f'SELECT count(*) FROM {t} WHERE device_id = ?', (device_id,)).fetchone()[0]
            for t in CHILD_TABLES if table_exists(cur, t)}


def merge_group(cur, keep, drops, execute, label):
    moved = {}
    for d in drops:
        for table, n in child_counts(cur, d['id']).items():
            moved[table] = moved.get(table, 0) + n
    fills = {}
    for col in FILL_COLUMNS:
        if not keep[col]:
            for d in drops:
                if d[col]:
                    fills[col] = d[col]
                    break
    monitored = any(r['is_monitored'] for r in [keep, *drops])
    print(f"  MERGE {label}: keep {keep['id']} ({keep['hostname']}, {keep['mac_address']}, last seen {keep['last_seen']})")
    for d in drops:
        print(f"         drop {d['id']} ({d['hostname']}, {d['mac_address']}, last seen {d['last_seen']}, ip {d['ip_address']})")
    print(f"         move {moved}; fill {fills or 'nothing'}; is_monitored={monitored}")
    if not execute:
        return
    drop_ids = [d['id'] for d in drops]
    marks = ','.join('?' * len(drop_ids))
    for table in CHILD_TABLES:
        if table_exists(cur, table):
            cur.execute(f'UPDATE {table} SET device_id = ? WHERE device_id IN ({marks})', [keep['id'], *drop_ids])
    for col, value in fills.items():
        cur.execute(f'UPDATE devices SET {col} = ? WHERE id = ?', (value, keep['id']))
    cur.execute('UPDATE devices SET is_monitored = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (int(monitored), keep['id']))
    if table_exists(cur, 'device_ip_history') and keep['ip_address']:
        note = 'merged rows ' + ', '.join(f"{d['id']} ({d['mac_address'] or 'no MAC'})" for d in drops)
        cur.execute("INSERT INTO device_ip_history (device_id, old_ip_address, new_ip_address, change_detected_at, change_source, notes) "
                    "VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'merge', ?)", (keep['id'], keep['ip_address'], keep['ip_address'], note[:500]))
    cur.execute(f'DELETE FROM devices WHERE id IN ({marks})', drop_ids)


def run(db_path, execute, only=None, skip=(), force_pairs=(), delete_orphans=False):
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    print(f"{'EXECUTE' if execute else 'DRY RUN'}: {db_path}")
    summary = {'merged': 0, 'skipped': 0, 'dropped_rows': 0}

    for keep_id, drop_id in force_pairs:
        keep = cur.execute('SELECT * FROM devices WHERE id = ?', (keep_id,)).fetchone()
        drop = cur.execute('SELECT * FROM devices WHERE id = ?', (drop_id,)).fetchone()
        if keep is None or drop is None:
            print(f'  force-pair {keep_id}/{drop_id}: a row is missing; skipped')
            summary['skipped'] += 1
            continue
        merge_group(cur, keep, [drop], execute, f'forced {keep_id}<-{drop_id}')
        summary['merged'] += 1
        summary['dropped_rows'] += 1

    forced_ids = {drop for _, drop in force_pairs}      # a kept row may still anchor its name group
    groups = {}
    for row in cur.execute('SELECT * FROM devices WHERE hostname IS NOT NULL ORDER BY id'):
        if row['id'] in forced_ids:
            continue
        key = identity_key(row['hostname'])
        if key:
            groups.setdefault(key, []).append(row)

    for key in sorted(groups):
        rows = groups[key]
        if len(rows) < 2 or (only and key != only):
            continue
        if key in skip:
            print(f'  skip  {key}: named by --skip ({len(rows)} rows)')
            summary['skipped'] += 1
            continue
        real = [r for r in rows if real_mac(r)]
        if len(real) >= 2:
            print(f'  skip  {key}: {len(real)} rows have real MACs ({len(rows)} rows) - several units share the name')
            summary['skipped'] += 1
            continue
        edges = coexistence_edges(cur, rows)
        linked = {i for pair in edges for i in pair}
        for (a, b), shared in sorted(edges.items()):
            print(f'  apart {key}: rows {a} and {b} answered pings in {shared} of the same 30-minute windows')
        keep = choose_keeper(rows)
        drops = [r for r in rows if r['id'] != keep['id'] and r['id'] not in linked]
        if not drops:
            print(f'  skip  {key}: every row coexisted with another ({len(rows)} rows)')
            summary['skipped'] += 1
            continue
        merge_group(cur, keep, drops, execute, key)
        summary['merged'] += 1
        summary['dropped_rows'] += len(drops)

    if delete_orphans:
        for table in CHILD_TABLES:
            if not table_exists(cur, table):
                continue
            n = cur.execute(f'SELECT count(*) FROM {table} WHERE device_id IS NOT NULL AND device_id NOT IN (SELECT id FROM devices)').fetchone()[0]
            if n:
                print(f'  orphans in {table}: {n}')
                if execute:
                    cur.execute(f'DELETE FROM {table} WHERE device_id IS NOT NULL AND device_id NOT IN (SELECT id FROM devices)')

    print(f"  groups merged: {summary['merged']}, rows folded: {summary['dropped_rows']}, groups skipped: {summary['skipped']}")
    if execute:
        con.commit()
        cur.execute('VACUUM')
        print('done')
    con.close()
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', help='SQLite file (default: DATABASE_URL / .env / homeNetMon.db)')
    ap.add_argument('--execute', action='store_true', help='apply the changes (default: dry run)')
    ap.add_argument('--force', action='store_true', help='ignore a running service')
    ap.add_argument('--only', help='only this identity key (e.g. ksp-mac)')
    ap.add_argument('--skip', action='append', default=[], help='identity key to leave alone (repeatable)')
    ap.add_argument('--force-pair', nargs=2, type=int, action='append', default=[], metavar=('KEEP', 'DROP'),
                    help='merge DROP into KEEP regardless of names (repeatable)')
    ap.add_argument('--delete-orphans', action='store_true', help='also delete child rows whose device is gone')
    args = ap.parse_args()

    db_path = resolve_db_path(args.db)
    if not db_path.exists():
        sys.exit(f'database not found: {db_path}')
    if args.execute and not args.force and service_running():
        sys.exit('homenetmon is running; stop it first (systemctl --user stop homenetmon) or pass --force.')
    run(db_path, args.execute, only=args.only, skip=set(args.skip), force_pairs=[tuple(p) for p in args.force_pair],
        delete_orphans=args.delete_orphans)


if __name__ == '__main__':
    main()
