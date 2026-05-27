# Restoring HomeNetMon from a Backup

`scripts/backup_database.py` creates timestamped copies of the SQLite database
in `./backups/`. This document covers restoring one of those backups when the
live database is corrupted, lost, or just contains data you want to revert.

## What a backup looks like

Each invocation of `scripts/backup_database.py` (or the cron job set up by
`setup_backup_cron.sh`) produces a file named like:

```
backups/homeNetMon_full_20260527_120000.db
backups/homeNetMon_full_20260527_120000.db.gz    # if --compress was used
```

These are full SQLite database files (or gzipped copies) created via
`shutil.copy2`. They are byte-equivalent to the live DB at the moment of
backup — no schema export, no SQL dump.

## Where the live DB lives

The path depends on how the app was launched. Inspect the unit file or env:

```bash
# If running under user systemd
grep DATABASE_URL ~/.config/systemd/user/homenetmon.service

# Or check the running process
ps eww $(pgrep -f 'python.*app\.py') | tr ' ' '\n' | grep DATABASE_URL
```

For the default production setup, this is:

```
/home/kyle/ClaudeCode/HomeNetMon/production_data/homeNetMon.db
```

## Restore procedure

**1. Stop the app** so it doesn't write to the DB during the copy:

```bash
# user-systemd unit
systemctl --user stop homenetmon

# OR if launched manually with nohup
pkill -TERM -f 'python.*app\.py'
# wait until pgrep is empty
```

**2. Move (don't delete) the current DB aside** so you can roll back if the
backup turns out to be the wrong one:

```bash
cd /home/kyle/ClaudeCode/HomeNetMon/production_data
mv homeNetMon.db        homeNetMon.db.broken
mv homeNetMon.db-wal    homeNetMon.db-wal.broken 2>/dev/null || true
mv homeNetMon.db-shm    homeNetMon.db-shm.broken 2>/dev/null || true
```

The `-wal` and `-shm` files are SQLite's write-ahead log and shared-memory
index. They MUST go aside with the main file — leaving stale ones around
will confuse SQLite and produce a "database disk image is malformed" error.

**3. Copy the backup into place.** If the backup is plain `.db`:

```bash
cp /home/kyle/ClaudeCode/HomeNetMon/backups/homeNetMon_full_20260527_120000.db \
   /home/kyle/ClaudeCode/HomeNetMon/production_data/homeNetMon.db
```

If the backup is gzipped:

```bash
gunzip -c /home/kyle/ClaudeCode/HomeNetMon/backups/homeNetMon_full_20260527_120000.db.gz \
       > /home/kyle/ClaudeCode/HomeNetMon/production_data/homeNetMon.db
```

**4. Sanity-check the restored DB** before starting the app:

```bash
cd /home/kyle/ClaudeCode/HomeNetMon
source venv/bin/activate
python - <<'PY'
import sqlite3
con = sqlite3.connect('production_data/homeNetMon.db')
print('integrity_check:', con.execute('PRAGMA integrity_check').fetchone())
print('devices:',  con.execute('SELECT COUNT(*) FROM devices').fetchone()[0])
print('monitoring_data:', con.execute('SELECT COUNT(*) FROM monitoring_data').fetchone()[0])
print('bandwidth_data:',  con.execute('SELECT COUNT(*) FROM bandwidth_data').fetchone()[0])
print('most recent timestamp:', con.execute(
    'SELECT MAX(timestamp) FROM monitoring_data').fetchone()[0])
con.close()
PY
```

`integrity_check` should report `('ok',)`. Row counts and the most-recent
timestamp tell you which backup you restored.

**5. Start the app:**

```bash
systemctl --user start homenetmon
# OR launch manually with the same env vars as before
```

**6. Verify it serves:**

```bash
curl -sS -w '\nHTTP %{http_code}\n' http://localhost:5000/api/system/health
```

A `200` with `"status": "healthy"` means the app is back. A `503` with
`"stale_threads": [...]` is normal in the first 1-2 minutes while background
threads catch up to their first heartbeat.

## Rollback

If the restored backup turns out to be the wrong one, stop the app, swap the
files back:

```bash
cd /home/kyle/ClaudeCode/HomeNetMon/production_data
mv homeNetMon.db                       homeNetMon.db.restored-and-rejected
mv homeNetMon.db.broken                homeNetMon.db
mv homeNetMon.db-wal.broken            homeNetMon.db-wal 2>/dev/null || true
mv homeNetMon.db-shm.broken            homeNetMon.db-shm 2>/dev/null || true
systemctl --user start homenetmon
```

## Notes

- **Do not** restore a backup from a meaningfully older schema version — if the
  app has migrated tables since the backup, columns may be missing. The app
  attempts a few opportunistic schema upgrades in `models.py:init_db`, but it
  is not a substitute for keeping schema-aligned backups.
- After restore the dashboard will briefly show stale data (last-heartbeat
  ages, alert acknowledgements as of the backup time, etc.). The monitoring
  loop catches up on the next cycle (a few minutes).
- The WAL file is regenerated on first connection, so it's safe to copy *only*
  the main `.db` file from a hot backup as long as the backup was created via
  `sqlite3.Connection.backup()` (which `scripts/backup_database.py` uses).
