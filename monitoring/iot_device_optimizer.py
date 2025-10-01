"""
IoT Device Monitoring Optimizer
Optimizes monitoring for slow-responding IoT devices like Ring cameras, smart home devices, etc.
"""

import logging
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class IoTDeviceOptimizer:
    """Optimizes monitoring for IoT devices with poor network characteristics"""

    # Known IoT device patterns that typically respond slowly
    SLOW_DEVICE_PATTERNS = {
        'ring': {'timeout': 5, 'interval': 300, 'retries': 1},  # Ring cameras/doorbells
        'wyze': {'timeout': 3, 'interval': 180, 'retries': 1},  # Wyze cameras
        'nest': {'timeout': 3, 'interval': 120, 'retries': 2},  # Nest devices
        'sonos': {'timeout': 2, 'interval': 120, 'retries': 2},  # Sonos speakers
        'chromecast': {'timeout': 2, 'interval': 120, 'retries': 2},  # Chromecasts
        'espressif': {'timeout': 3, 'interval': 180, 'retries': 1},  # ESP32/ESP8266 devices
        'lwip': {'timeout': 3, 'interval': 180, 'retries': 1},  # Lightweight IP devices
        'google-home': {'timeout': 2, 'interval': 120, 'retries': 2},  # Google Home devices
        'google-nest': {'timeout': 2, 'interval': 120, 'retries': 2},  # Google Nest devices
        'litter-robot': {'timeout': 4, 'interval': 300, 'retries': 1},  # Litter Robot
        'lg': {'timeout': 3, 'interval': 180, 'retries': 1},  # LG Smart TVs/appliances
        'samsung': {'timeout': 3, 'interval': 180, 'retries': 1},  # Samsung Smart devices
        'watch': {'timeout': 4, 'interval': 240, 'retries': 1},  # Smart watches
    }

    def __init__(self):
        self.device_performance = defaultdict(lambda: {'failures': 0, 'successes': 0, 'avg_response': 0})
        self.optimized_settings = {}
        self.last_optimization = {}

    def identify_device_type(self, device) -> Optional[str]:
        """Identify the type of IoT device based on hostname, vendor, or MAC"""
        hostname = (device.hostname or '').lower()
        vendor = (device.vendor or '').lower()
        custom_name = (device.custom_name or '').lower()

        # Check all fields for known patterns
        for pattern, settings in self.SLOW_DEVICE_PATTERNS.items():
            if (pattern in hostname or
                pattern in vendor or
                pattern in custom_name):
                return pattern

        return None

    def get_optimized_settings(self, device) -> Dict:
        """Get optimized monitoring settings for a device"""
        device_id = device.id

        # Check if we already have optimized settings
        if device_id in self.optimized_settings:
            return self.optimized_settings[device_id]

        # Identify device type
        device_type = self.identify_device_type(device)

        if device_type:
            # Use known settings for this device type
            settings = self.SLOW_DEVICE_PATTERNS[device_type].copy()
            logger.info(f"Applied {device_type} optimizations for {device.display_name}: timeout={settings['timeout']}s, interval={settings['interval']}s")
        else:
            # Use adaptive settings based on performance
            perf = self.device_performance[device_id]
            if perf['failures'] + perf['successes'] > 10:
                failure_rate = perf['failures'] / (perf['failures'] + perf['successes'])

                if failure_rate > 0.5:
                    # High failure rate - use conservative settings
                    settings = {'timeout': 5, 'interval': 300, 'retries': 1}
                    logger.info(f"Applied conservative settings for poorly performing device {device.display_name}")
                elif failure_rate > 0.2:
                    # Moderate failure rate
                    settings = {'timeout': 3, 'interval': 180, 'retries': 2}
                else:
                    # Low failure rate - use normal settings
                    settings = {'timeout': 2, 'interval': 60, 'retries': 3}
            else:
                # Default settings for unknown devices
                settings = {'timeout': 2, 'interval': 60, 'retries': 3}

        self.optimized_settings[device_id] = settings
        return settings

    def record_ping_result(self, device, success: bool, response_time: Optional[float]):
        """Record the result of a ping attempt for optimization"""
        device_id = device.id
        perf = self.device_performance[device_id]

        if success:
            perf['successes'] += 1
            if response_time:
                # Update average response time
                total_pings = perf['successes'] + perf['failures']
                perf['avg_response'] = ((perf['avg_response'] * (total_pings - 1)) + response_time) / total_pings
        else:
            perf['failures'] += 1

        # Re-evaluate settings every 100 pings
        total_pings = perf['successes'] + perf['failures']
        if total_pings % 100 == 0:
            self.re_evaluate_settings(device)

    def re_evaluate_settings(self, device):
        """Re-evaluate and update device settings based on performance"""
        device_id = device.id
        perf = self.device_performance[device_id]

        if perf['failures'] + perf['successes'] < 50:
            return  # Not enough data

        failure_rate = perf['failures'] / (perf['failures'] + perf['successes'])
        avg_response = perf['avg_response']

        current = self.optimized_settings.get(device_id, {})
        new_settings = current.copy()

        # Adjust timeout based on average response time
        if avg_response > 0:
            if avg_response > 3000:  # >3 seconds average
                new_settings['timeout'] = min(10, int(avg_response / 1000) + 2)
            elif avg_response > 1000:  # >1 second average
                new_settings['timeout'] = min(5, int(avg_response / 1000) + 1)

        # Adjust interval based on failure rate
        if failure_rate > 0.7:
            # Very high failure rate - monitor less frequently
            new_settings['interval'] = 600  # 10 minutes
            new_settings['retries'] = 0  # Don't retry to save time
        elif failure_rate > 0.4:
            new_settings['interval'] = 300  # 5 minutes
            new_settings['retries'] = 1
        elif failure_rate > 0.2:
            new_settings['interval'] = 180  # 3 minutes
            new_settings['retries'] = 2
        else:
            # Good performance - can monitor more frequently
            new_settings['interval'] = 60  # 1 minute
            new_settings['retries'] = 3

        if new_settings != current:
            self.optimized_settings[device_id] = new_settings
            logger.info(f"Updated settings for {device.display_name}: timeout={new_settings['timeout']}s, "
                       f"interval={new_settings['interval']}s, retries={new_settings['retries']} "
                       f"(failure_rate={failure_rate:.1%}, avg_response={avg_response:.0f}ms)")

    def should_skip_monitoring(self, device) -> Tuple[bool, Optional[int]]:
        """Check if device monitoring should be skipped based on interval settings"""
        device_id = device.id
        settings = self.get_optimized_settings(device)

        # Check last monitoring time
        last_check = self.last_optimization.get(device_id)
        if last_check:
            elapsed = (datetime.utcnow() - last_check).total_seconds()
            interval = settings['interval']

            if elapsed < interval:
                # Skip this monitoring cycle
                remaining = int(interval - elapsed)
                return True, remaining

        # Record this monitoring attempt
        self.last_optimization[device_id] = datetime.utcnow()
        return False, None

    def get_device_stats(self, device) -> Dict:
        """Get performance statistics for a device"""
        device_id = device.id
        perf = self.device_performance[device_id]
        settings = self.optimized_settings.get(device_id, {})

        total = perf['failures'] + perf['successes']
        if total > 0:
            success_rate = perf['successes'] / total
            failure_rate = perf['failures'] / total
        else:
            success_rate = 0
            failure_rate = 0

        return {
            'total_pings': total,
            'success_rate': success_rate,
            'failure_rate': failure_rate,
            'avg_response_ms': perf['avg_response'],
            'current_settings': settings,
            'device_type': self.identify_device_type(device)
        }

    def export_optimization_report(self) -> List[Dict]:
        """Export a report of all device optimizations"""
        report = []
        for device_id, perf in self.device_performance.items():
            total = perf['failures'] + perf['successes']
            if total > 0:
                report.append({
                    'device_id': device_id,
                    'total_pings': total,
                    'success_rate': perf['successes'] / total,
                    'avg_response_ms': perf['avg_response'],
                    'settings': self.optimized_settings.get(device_id, {})
                })

        # Sort by failure rate (worst performing first)
        report.sort(key=lambda x: x['success_rate'])
        return report


# Global optimizer instance
iot_optimizer = IoTDeviceOptimizer()