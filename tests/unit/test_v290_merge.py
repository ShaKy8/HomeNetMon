"""scripts/db/v290_merge_duplicates.py on a create_all() database file."""

import importlib.util
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from models import db

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('v290_merge', ROOT / 'scripts/db/v290_merge_duplicates.py')
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)

REAL_A, REAL_B = '6c:6e:07:11:e4:3a', '6c:6e:07:11:e4:3b'
RAND_1, RAND_2, RAND_3 = 'd2:5f:2d:99:a0:47', '3a:c1:5f:03:3a:a6', '3a:00:00:00:00:01'
NOW = datetime(2026, 9, 22, 12, 0, 0)


@pytest.fixture
def db_file(tmp_path):
    path = tmp_path / 'merge.db'
    engine = create_engine(f'sqlite:///{path}')
    db.metadata.create_all(engine)
    engine.dispose()
    return path


def _device(cur, hostname, mac, ip, last_seen, **cols):
    cols = {'hostname': hostname, 'mac_address': mac, 'ip_address': ip, 'last_seen': last_seen, 'is_monitored': 1, **cols}
    cur.execute(f"INSERT INTO devices ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", list(cols.values()))
    return cur.lastrowid


def _pings(cur, device_id, start, count, step_minutes=10):
    for i in range(count):
        cur.execute("INSERT INTO monitoring_data (device_id, timestamp, response_time, packet_loss) VALUES (?, ?, 12.0, 0)",
                    (device_id, start + timedelta(minutes=step_minutes * i)))


def _alert(cur, device_id):
    cur.execute("INSERT INTO alerts (device_id, alert_type, severity, message, created_at, resolved) VALUES (?, 'device_down', 'warning', 'm', ?, 0)",
                (device_id, NOW))


class TestMerge:

    def test_rotated_mac_rows_fold_into_the_newest(self, db_file):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        a = _device(cur, 'ksp-mac.lan', RAND_1, None, NOW - timedelta(days=20), notes='old note', device_group='Office')
        b = _device(cur, 'KSP-Mac.local', RAND_2, None, NOW - timedelta(days=5), is_monitored=0)
        c = _device(cur, 'ksp-mac.lan', RAND_3, '192.168.1.51', NOW)
        _pings(cur, a, NOW - timedelta(days=20), 6)
        _pings(cur, b, NOW - timedelta(days=5), 6)
        _pings(cur, c, NOW - timedelta(hours=1), 6)
        _alert(cur, a)
        _alert(cur, b)
        con.commit()
        con.close()

        summary = merge.run(db_file, execute=False)
        assert summary == {'merged': 1, 'dropped_rows': 2, 'skipped': 0}
        con = sqlite3.connect(db_file)
        assert con.execute('SELECT count(*) FROM devices').fetchone()[0] == 3     # dry run changed nothing
        con.close()

        summary = merge.run(db_file, execute=True)
        assert summary['merged'] == 1 and summary['dropped_rows'] == 2
        con = sqlite3.connect(db_file)
        con.row_factory = sqlite3.Row
        rows = con.execute('SELECT * FROM devices').fetchall()
        assert len(rows) == 1 and rows[0]['id'] == c
        keeper = rows[0]
        assert keeper['notes'] == 'old note' and keeper['device_group'] == 'Office' and keeper['is_monitored'] == 1
        assert con.execute('SELECT count(*) FROM monitoring_data WHERE device_id = ?', (c,)).fetchone()[0] == 18
        assert con.execute('SELECT count(*) FROM alerts WHERE device_id = ?', (c,)).fetchone()[0] == 2
        hist = con.execute('SELECT * FROM device_ip_history WHERE device_id = ?', (c,)).fetchone()
        assert hist['change_source'] == 'merge' and str(a) in hist['notes'] and str(b) in hist['notes']
        con.close()

        assert merge.run(db_file, execute=True) == {'merged': 0, 'dropped_rows': 0, 'skipped': 0}   # second run: no-op

    def test_sonos_like_group_is_skipped(self, db_file):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        _device(cur, 'sonoszp.lan', REAL_A, '192.168.1.20', NOW)
        _device(cur, 'sonoszp.lan', REAL_B, '192.168.1.21', NOW)
        _device(cur, 'sonoszp.lan', None, None, NOW - timedelta(days=90))
        con.commit()
        con.close()
        assert merge.run(db_file, execute=True) == {'merged': 0, 'dropped_rows': 0, 'skipped': 1}
        con = sqlite3.connect(db_file)
        assert con.execute('SELECT count(*) FROM devices').fetchone()[0] == 3
        con.close()

    def test_coexisting_rows_stay_apart_and_the_rest_merge(self, db_file):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        ipad_1 = _device(cur, 'iPad-5Doodles.local', RAND_1, '192.168.1.60', NOW)
        ipad_2 = _device(cur, 'iPad-5Doodles.local', RAND_2, '192.168.1.61', NOW)
        stale = _device(cur, 'ipad-5doodles.lan', None, None, NOW - timedelta(days=100))
        _pings(cur, ipad_1, NOW - timedelta(hours=5), 30)       # both answered for five hours
        _pings(cur, ipad_2, NOW - timedelta(hours=5), 30)
        _pings(cur, stale, NOW - timedelta(days=100), 4)
        con.commit()
        con.close()
        summary = merge.run(db_file, execute=True)
        assert summary['merged'] == 1 and summary['dropped_rows'] == 1
        con = sqlite3.connect(db_file)
        ids = {r[0] for r in con.execute('SELECT id FROM devices')}
        assert ids == {ipad_1, ipad_2}
        con.close()

    def test_handover_overlap_is_not_coexistence(self, db_file):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        old = _device(cur, 'phone.lan', RAND_1, None, NOW - timedelta(minutes=20))
        new = _device(cur, 'phone.lan', RAND_2, '192.168.1.70', NOW)
        _pings(cur, old, NOW - timedelta(hours=3), 17)          # up to 20 minutes ago
        _pings(cur, new, NOW - timedelta(minutes=30), 4)        # overlaps one or two windows
        con.commit()
        con.close()
        summary = merge.run(db_file, execute=True)
        assert summary['merged'] == 1 and summary['dropped_rows'] == 1
        con = sqlite3.connect(db_file)
        assert [r[0] for r in con.execute('SELECT id FROM devices')] == [new]
        con.close()

    def test_skip_only_and_force_pair(self, db_file):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        a = _device(cur, 'laptop.lan', RAND_1, None, NOW - timedelta(days=9))
        b = _device(cur, 'laptop.lan', RAND_2, '192.168.1.80', NOW)
        c = _device(cur, None, REAL_A, '192.168.1.81', NOW - timedelta(days=30))
        con.commit()
        con.close()
        assert merge.run(db_file, execute=True, skip={'laptop'}) == {'merged': 0, 'dropped_rows': 0, 'skipped': 1}
        assert merge.run(db_file, execute=True, only='nothing-here') == {'merged': 0, 'dropped_rows': 0, 'skipped': 0}
        summary = merge.run(db_file, execute=True, force_pairs=[(b, c)])
        assert summary['merged'] == 2 and summary['dropped_rows'] == 2      # forced pair + the laptop group
        con = sqlite3.connect(db_file)
        assert [r[0] for r in con.execute('SELECT id FROM devices')] == [b]
        assert a not in {r[0] for r in con.execute('SELECT id FROM devices')}
        con.close()
