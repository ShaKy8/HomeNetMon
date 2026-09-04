"""
Host interface throughput sampler.

Reads /proc/net/dev byte and packet counters for every physical network
interface on the host, differences them per interval, and stores one
InterfaceBandwidth row per interface per interval. This is the only bandwidth
measurement HomeNetMon can make honestly from the machine it runs on;
per-device traffic would need router / SNMP / flow integration.

(The previous implementation split the host total across all devices with a
random factor and stored it as per-device "bandwidth" -- 680 MB of noise.)
"""
import logging
import re
import subprocess
import threading
import time
from datetime import datetime

from config import Config
from models import Configuration, InterfaceBandwidth, db

logger = logging.getLogger(__name__)

# Interfaces that never carry LAN traffic we care about.
_SKIP_PREFIXES = ('lo', 'docker', 'veth', 'br-', 'virbr', 'vnet', 'tun', 'tap', 'wg', 'tailscale', 'zt')


class BandwidthMonitor:
    """Samples host interface counters on Config.BANDWIDTH_INTERVAL (runtime key bandwidth_interval)."""

    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self.monitor_thread = None
        self._stop_event = threading.Event()
        self.interface_stats = {}   # interface -> last sample dict

    def get_config_value(self, key, default):
        """Runtime Configuration value (DB) with fallback; must be called inside an app context."""
        try:
            return Configuration.get_value(key, str(default))
        except Exception as e:
            logger.debug(f"Config read for {key} failed ({e}); using default {default}")
            return str(default)

    # ---- sampling -----------------------------------------------------------
    @staticmethod
    def is_physical_interface(name):
        return not name.startswith(_SKIP_PREFIXES)

    def get_network_interfaces(self):
        """Names of non-virtual interfaces, from `ip link show` (falls back to /proc/net/dev)."""
        names = []
        try:
            result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True,
                                    timeout=10, shell=False)
            for line in result.stdout.splitlines():
                match = re.match(r'^\d+:\s+([^:@\s]+)', line.strip())
                if match:
                    names.append(match.group(1))
        except Exception as e:
            logger.debug(f"`ip link show` failed ({e}); reading /proc/net/dev instead")
        if not names:
            try:
                with open('/proc/net/dev') as f:
                    names = [ln.split(':')[0].strip() for ln in f.readlines()[2:] if ':' in ln]
            except Exception as e:
                logger.error(f"Cannot enumerate network interfaces: {e}")
        return [n for n in names if self.is_physical_interface(n)]

    @staticmethod
    def read_proc_net_dev(text_):
        """Parse /proc/net/dev content -> {interface: counters}."""
        stats = {}
        for line in text_.splitlines()[2:]:
            if ':' not in line:
                continue
            name, rest = line.split(':', 1)
            parts = rest.split()
            if len(parts) < 16:
                continue
            stats[name.strip()] = {
                'rx_bytes': int(parts[0]), 'rx_packets': int(parts[1]),
                'tx_bytes': int(parts[8]), 'tx_packets': int(parts[9]),
            }
        return stats

    def get_interface_stats(self, interface):
        """Counters for one interface right now, or None."""
        try:
            with open('/proc/net/dev') as f:
                stats = self.read_proc_net_dev(f.read())
        except Exception as e:
            logger.error(f"Error reading /proc/net/dev: {e}")
            return None
        counters = stats.get(interface)
        if counters is None:
            return None
        return {'interface': interface, 'timestamp': datetime.utcnow(), **counters}

    @staticmethod
    def calculate_bandwidth(current, previous):
        """Difference two samples into a throughput dict, or None if not computable."""
        if not previous:
            return None
        seconds = (current['timestamp'] - previous['timestamp']).total_seconds()
        if seconds <= 0:
            return None
        rx = current['rx_bytes'] - previous['rx_bytes']
        tx = current['tx_bytes'] - previous['tx_bytes']
        if rx < 0 or tx < 0:      # counter reset (interface bounced)
            return None
        return {
            'interval_seconds': seconds,
            'bytes_in': rx,
            'bytes_out': tx,
            'packets_in': max(0, current['rx_packets'] - previous['rx_packets']),
            'packets_out': max(0, current['tx_packets'] - previous['tx_packets']),
            'bandwidth_in_mbps': (rx * 8) / (seconds * 1_000_000),
            'bandwidth_out_mbps': (tx * 8) / (seconds * 1_000_000),
        }

    def sample_once(self, interfaces):
        """Take one sample of every interface and persist the deltas. Returns rows written."""
        written = 0
        for name in interfaces:
            current = self.get_interface_stats(name)
            if not current:
                continue
            delta = self.calculate_bandwidth(current, self.interface_stats.get(name))
            self.interface_stats[name] = current
            if not delta:
                continue
            db.session.add(InterfaceBandwidth(
                interface=name,
                timestamp=current['timestamp'],
                interval_seconds=delta['interval_seconds'],
                bytes_in=delta['bytes_in'],
                bytes_out=delta['bytes_out'],
                packets_in=delta['packets_in'],
                packets_out=delta['packets_out'],
                mbps_in=delta['bandwidth_in_mbps'],
                mbps_out=delta['bandwidth_out_mbps'],
            ))
            written += 1
        if written:
            try:
                db.session.commit()
            except Exception as e:
                logger.error(f"Error storing interface bandwidth: {e}")
                db.session.rollback()
                return 0
        return written

    # ---- loop ----------------------------------------------------------------
    def monitor_bandwidth(self):
        logger.info("Starting interface bandwidth monitoring")
        interfaces = self.get_network_interfaces()
        if not interfaces:
            logger.warning("No physical network interfaces found; bandwidth monitoring disabled")
            return
        logger.info(f"Sampling interfaces: {interfaces}")

        from core.health import record_heartbeat
        while not self._stop_event.is_set():
            record_heartbeat('BandwidthMonitor')
            # One app context per iteration so the session (and its SQLite read
            # snapshot) is released between samples; a pinned context blocked
            # WAL checkpoints for weeks.
            with self.app.app_context():
                try:
                    self.sample_once(interfaces)
                    try:
                        interval = int(self.get_config_value('bandwidth_interval', Config.BANDWIDTH_INTERVAL))
                    except (TypeError, ValueError):
                        interval = Config.BANDWIDTH_INTERVAL
                except Exception as e:
                    logger.error(f"Error in bandwidth monitoring loop: {e}")
                    interval = 60
            self._stop_event.wait(max(5, interval))
        logger.info("Bandwidth monitoring stopped")

    def start_monitoring(self):
        if self.is_running:
            logger.warning("Bandwidth monitoring is already running")
            return
        self.is_running = True
        self._stop_event.clear()
        # Same name as the outer wrapper thread so the /api/system/health watchdog
        # sees this as the BandwidthMonitor thread.
        self.monitor_thread = threading.Thread(target=self.monitor_bandwidth, name='BandwidthMonitor', daemon=True)
        self.monitor_thread.start()
        logger.info("Bandwidth monitoring started")

    def stop_monitoring(self):
        self.is_running = False
        self._stop_event.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)
        logger.info("Bandwidth monitoring stop requested")

    def reload_config(self):
        """Hot-reload hook (ConfigurationService callback). The interval is re-read
        every iteration, so there is nothing to cache; log for visibility."""
        with self.app.app_context():
            logger.info(f"BandwidthMonitor config reloaded - interval: "
                        f"{self.get_config_value('bandwidth_interval', Config.BANDWIDTH_INTERVAL)}s")

    def get_current_bandwidth_summary(self):
        """Most recent sample per interface (for API/UI)."""
        summary = {}
        for name, sample in self.interface_stats.items():
            summary[name] = {'timestamp': sample['timestamp'].isoformat() + 'Z',
                             'rx_bytes': sample['rx_bytes'], 'tx_bytes': sample['tx_bytes']}
        return summary
