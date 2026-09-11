"""The security scanner must heartbeat while scanning and stop promptly."""

import threading
import time
from unittest.mock import patch

from models import Device, db
from services import security_scanner as ss


def _scanner(app):
    s = ss.NetworkSecurityScanner(app)
    s.scan_interval = 3600
    return s


def test_stop_interrupts_the_idle_wait(app):
    scanner = _scanner(app)
    ran = threading.Event()
    scanner.run_security_scan = lambda: ran.set()
    scanner.start_monitoring()
    thread = next(t for t in threading.enumerate() if t.name == 'SecurityScanner')
    assert ran.wait(timeout=5)
    t0 = time.time()
    scanner.stop_monitoring()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert time.time() - t0 < 5
    assert scanner.running is False


def test_heartbeat_recorded_per_device_during_a_sweep(app, db_session):
    d = Device(ip_address='192.168.1.77', mac_address='00:11:22:33:44:77', hostname='sweep-1',
               device_type='computer', is_monitored=True)
    db_session.add(d)
    db_session.commit()
    scanner = _scanner(app)
    with patch.object(ss, 'record_heartbeat') as hb, \
         patch.object(scanner, 'scan_device_ports', return_value=[]):
        scanner.run_security_scan()
    assert hb.call_count >= 1
    assert all(c.args == ('SecurityScanner',) for c in hb.call_args_list)
