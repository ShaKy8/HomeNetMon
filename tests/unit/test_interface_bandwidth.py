"""
Host interface bandwidth: the only bandwidth HomeNetMon can measure honestly.
Replaces the per-device series that was host total / N * random.uniform().
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models import InterfaceBandwidth, db
from monitoring.bandwidth_monitor import BandwidthMonitor

PROC_NET_DEV_T0 = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 1000000 1000 0 0 0 0 0 0 500000 500 0 0 0 0 0 0
docker0: 5 5 0 0 0 0 0 0 5 5 0 0 0 0 0 0
"""
PROC_NET_DEV_T1 = PROC_NET_DEV_T0.replace("1000000 1000", "2250000 2000").replace("500000 500", "1125000 1000")


class TestParsing:

    def test_read_proc_net_dev(self):
        stats = BandwidthMonitor.read_proc_net_dev(PROC_NET_DEV_T0)
        assert stats['eth0'] == {'rx_bytes': 1000000, 'rx_packets': 1000, 'tx_bytes': 500000, 'tx_packets': 500}
        assert 'lo' in stats and 'docker0' in stats

    def test_physical_interface_filter(self):
        assert BandwidthMonitor.is_physical_interface('eth0')
        assert BandwidthMonitor.is_physical_interface('wlp3s0')
        for virt in ('lo', 'docker0', 'veth1a2b', 'br-abc', 'virbr0', 'tailscale0'):
            assert not BandwidthMonitor.is_physical_interface(virt), virt

    def test_calculate_bandwidth_is_deterministic(self):
        t0 = datetime(2026, 1, 1, 0, 0, 0)
        prev = {'timestamp': t0, 'rx_bytes': 1000000, 'tx_bytes': 500000, 'rx_packets': 1000, 'tx_packets': 500}
        cur = {'timestamp': t0 + timedelta(seconds=10), 'rx_bytes': 2250000, 'tx_bytes': 1125000,
               'rx_packets': 2000, 'tx_packets': 1000}
        d = BandwidthMonitor.calculate_bandwidth(cur, prev)
        assert d['bytes_in'] == 1250000 and d['bytes_out'] == 625000
        assert d['bandwidth_in_mbps'] == pytest.approx(1.0)   # 1.25 MB * 8 / 10 s
        assert d['bandwidth_out_mbps'] == pytest.approx(0.5)
        assert BandwidthMonitor.calculate_bandwidth(cur, prev) == d  # no randomness

    def test_counter_reset_and_first_sample_yield_nothing(self):
        t0 = datetime(2026, 1, 1)
        prev = {'timestamp': t0, 'rx_bytes': 500, 'tx_bytes': 500, 'rx_packets': 1, 'tx_packets': 1}
        reset = {'timestamp': t0 + timedelta(seconds=5), 'rx_bytes': 10, 'tx_bytes': 10, 'rx_packets': 0, 'tx_packets': 0}
        assert BandwidthMonitor.calculate_bandwidth(reset, prev) is None
        assert BandwidthMonitor.calculate_bandwidth(prev, None) is None


class TestSampling:

    def test_sample_once_writes_one_row_per_physical_interface(self, app, db_session):
        mon = BandwidthMonitor(app=app)
        with app.app_context():
            with patch('builtins.open', side_effect=lambda *a, **k: _FakeFile(PROC_NET_DEV_T0)):
                assert mon.sample_once(['eth0']) == 0          # first sample: baseline only
            with patch('builtins.open', side_effect=lambda *a, **k: _FakeFile(PROC_NET_DEV_T1)):
                assert mon.sample_once(['eth0']) == 1
            rows = InterfaceBandwidth.query.all()
            assert len(rows) == 1
            r = rows[0]
            assert r.interface == 'eth0' and r.bytes_in == 1250000 and r.bytes_out == 625000
            assert r.mbps_in > 0 and r.interval_seconds > 0

    def test_no_per_device_bandwidth_writer_remains(self):
        import monitoring.bandwidth_monitor as m
        assert not hasattr(m.BandwidthMonitor, 'estimate_device_bandwidth')
        assert 'import random' not in open(m.__file__).read()


class _FakeFile:
    def __init__(self, content):
        self._c = content
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self):
        return self._c
    def readlines(self):
        return self._c.splitlines(True)


class TestBandwidthApi:

    @pytest.fixture
    def samples(self, db_session):
        db_session.query(InterfaceBandwidth).delete()
        now = datetime.utcnow()
        rows = []
        for i in range(6):
            rows.append(InterfaceBandwidth(interface='eth0', timestamp=now - timedelta(minutes=5 * i),
                                           interval_seconds=300, bytes_in=300_000_000, bytes_out=100_000_000,
                                           mbps_in=8.0, mbps_out=2.0 + i))
        rows.append(InterfaceBandwidth(interface='wlan0', timestamp=now, interval_seconds=300,
                                       bytes_in=1, bytes_out=1, mbps_in=0.1, mbps_out=0.1))
        db_session.add_all(rows)
        db_session.commit()

    def test_summary_shape_matches_analytics_page(self, client, samples):
        r = client.get('/api/monitoring/bandwidth/summary?hours=1')
        assert r.status_code == 200
        d = r.get_json()
        assert d['source'] == 'host_interface_counters'
        assert d['current_bandwidth']['current_total_mbps'] > 0
        assert d['peak_bandwidth']['peak_total_mbps'] == pytest.approx(15.0)   # 8 + (2+5)
        assert d['total_data']['total_gb'] > 0
        assert d['statistics']['active_interfaces'] == 2
        assert d['top_consumers'][0]['interface'] == 'eth0'

    def test_timeline_buckets(self, client, samples):
        d = client.get('/api/monitoring/bandwidth/timeline?hours=1&interval=hour').get_json()
        assert d['count'] >= 1
        assert set(d['timeline'][0]) >= {'timestamp', 'avg_bandwidth_in_mbps', 'avg_bandwidth_out_mbps',
                                         'peak_bandwidth_in_mbps', 'total_bytes_in', 'sample_count'}

    def test_devices_ranking_is_per_interface(self, client, samples):
        d = client.get('/api/monitoring/bandwidth/devices?hours=1&limit=10').get_json()
        assert [x['interface'] for x in d['devices']] == ['eth0', 'wlan0']
        assert d['devices'][0]['bandwidth_stats']['measurement_count'] == 6

    def test_raw_rows_filter_by_interface(self, client, samples):
        d = client.get('/api/monitoring/bandwidth?hours=1&interface=wlan0').get_json()
        assert d['count'] == 1 and d['bandwidth_data'][0]['interface'] == 'wlan0'
