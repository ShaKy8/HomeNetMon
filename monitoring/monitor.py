import time
import threading
import logging
import subprocess
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from models import db, Device, MonitoringData, Configuration
from config import Config

logger = logging.getLogger(__name__)

class DeviceMonitor:
    def __init__(self, socketio=None, app=None):
        self.socketio = socketio
        self.app = app
        self.is_running = False
        self.executor = None
        self._stop_event = threading.Event()
        self.rule_engine_service = None
        
    def get_config_value(self, key, default):
        """Get configuration value from database or use default"""
        try:
            if self.app:
                with self.app.app_context():
                    return Configuration.get_value(key, str(default))
            else:
                return Configuration.get_value(key, str(default))
        except:
            return str(default)
        
    def ping_device(self, device):
        """Ping a single device with retry logic and return response time using system ping command"""
        # Get ping timeout from database configuration
        ping_timeout = float(self.get_config_value('ping_timeout', Config.PING_TIMEOUT))
        
        # For critical infrastructure (router, servers), use more lenient settings
        is_critical_device = (
            device.ip_address.endswith('.1') or  # Router
            'router' in device.device_type.lower() or
            'server' in device.device_type.lower() or
            'nuc' in device.hostname.lower() if device.hostname else False
        )
        
        # Adjust retry logic based on device criticality
        max_retries = 2 if is_critical_device else 1
        retry_delay = 0.5  # 500ms between retries
        
        for attempt in range(max_retries + 1):  # +1 for initial attempt
            try:
                # Use more generous timeout for critical devices
                actual_timeout = ping_timeout * 1.5 if is_critical_device else ping_timeout
                
                # Use system ping command (works without root privileges)
                cmd = ['ping', '-c', '1', '-W', str(int(actual_timeout)), device.ip_address]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=actual_timeout + 2
                )
                
                if result.returncode == 0:
                    # Parse ping output to extract response time
                    # Look for patterns like "time=1.23 ms"
                    time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
                    if time_match:
                        response_time_ms = float(time_match.group(1))
                        device.last_seen = datetime.utcnow()
                        logger.debug(f"Ping successful for {device.ip_address} on attempt {attempt + 1}: {response_time_ms}ms")
                        return response_time_ms
                    else:
                        # Ping succeeded but couldn't parse time, return 0
                        device.last_seen = datetime.utcnow()
                        logger.debug(f"Ping successful for {device.ip_address} on attempt {attempt + 1} (no time parsed)")
                        return 0.0
                else:
                    # Ping failed, try again if we have retries left
                    if attempt < max_retries:
                        logger.debug(f"Ping failed for {device.ip_address} on attempt {attempt + 1}, retrying...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logger.debug(f"Ping failed for {device.ip_address} after {max_retries + 1} attempts")
                        return None
                        
            except subprocess.TimeoutExpired:
                if attempt < max_retries:
                    logger.debug(f"Ping timeout for {device.ip_address} on attempt {attempt + 1}, retrying...")
                    time.sleep(retry_delay)
                    continue
                else:
                    logger.debug(f"Ping timeout for {device.ip_address} after {max_retries + 1} attempts")
                    return None
            except Exception as e:
                if attempt < max_retries:
                    logger.debug(f"Error pinging {device.ip_address} on attempt {attempt + 1}: {e}, retrying...")
                    time.sleep(retry_delay)
                    continue
                else:
                    logger.error(f"Error pinging {device.ip_address} after {max_retries + 1} attempts: {e}")
                    return None
        
        return None
    
    def monitor_device(self, device):
        """Monitor a single device and record data"""
        try:
            # Skip devices that are not marked for monitoring
            if not device.is_monitored:
                return
            
            logger.debug(f"Monitoring device: {device.ip_address}")
            device_id = device.id
            device_ip = device.ip_address
            
            response_time = self.ping_device(device)
            
            if self.app:
                with self.app.app_context():
                    # Re-query the device in this context to ensure proper session binding
                    device_obj = Device.query.get(device_id)
                    if not device_obj:
                        return
                    
                    # Store previous status to detect changes
                    previous_status = device_obj.status
                    
                    # Create monitoring data entry
                    monitoring_data = MonitoringData(
                        device_id=device_id,
                        response_time=response_time,
                        timestamp=datetime.utcnow()
                    )
                    
                    db.session.add(monitoring_data)
                    
                    # Update device last seen if ping was successful
                    if response_time is not None:
                        device_obj.last_seen = datetime.utcnow()
                    
                    db.session.commit()
                    
                    # Check for status changes and trigger rule engine
                    current_status = device_obj.status
                    if previous_status != current_status:
                        self._trigger_rule_engine_for_status_change(device_obj, previous_status, current_status, response_time)
            
            # Emit real-time update via SocketIO
            if self.socketio and self.app:
                with self.app.app_context():
                    device_obj = Device.query.get(device_id)
                    if device_obj:
                        self.socketio.emit('device_status_update', {
                            'device_id': device_id,
                            'ip_address': device_ip,
                            'display_name': device_obj.display_name,
                            'response_time': response_time,
                            'status': device_obj.status,
                            'timestamp': datetime.utcnow().isoformat()
                        })
            
            logger.debug(f"Monitored {device.ip_address}: {response_time}ms" if response_time else f"Monitored {device.ip_address}: NO RESPONSE")
            
            return {
                'device_id': device.id,
                'response_time': response_time,
                'success': response_time is not None
            }
            
        except Exception as e:
            logger.error(f"Error monitoring device {device.ip_address}: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
            return None
    
    def is_critical_device(self, device):
        """Determine if a device is critical infrastructure"""
        # Critical device criteria
        return (
            device.ip_address.endswith('.1') or  # Router/Gateway
            device.ip_address.endswith('.64') or  # Server
            'router' in device.device_type.lower() if device.device_type else False or
            'server' in device.device_type.lower() if device.device_type else False or
            'nuc' in (device.hostname or '').lower() or
            'gateway' in (device.hostname or '').lower()
        )
    
    def monitor_all_devices(self):
        """Monitor devices with intelligent prioritization and batching"""
        try:
            if not self.app:
                logger.error("No Flask app context available for monitoring")
                return
            
            with self.app.app_context():
                # Get all devices that should be monitored
                all_devices = Device.query.filter_by(is_monitored=True).all()
            
            if not all_devices:
                logger.debug("No devices to monitor")
                return
            
            # Separate critical from regular devices
            critical_devices = [d for d in all_devices if self.is_critical_device(d)]
            regular_devices = [d for d in all_devices if not self.is_critical_device(d)]
            
            logger.debug(f"Monitoring: {len(critical_devices)} critical, {len(regular_devices)} regular devices")
            
            # Always monitor critical devices every cycle
            devices_to_monitor = critical_devices[:]
            
            # Rotate through regular devices (monitor subset each cycle)
            if regular_devices:
                # Initialize rotation counter if not exists
                if not hasattr(self, '_device_rotation_index'):
                    self._device_rotation_index = 0
                
                # Monitor 10-15 regular devices per cycle (instead of all 50+)
                batch_size = min(15, len(regular_devices))
                start_idx = self._device_rotation_index
                end_idx = start_idx + batch_size
                
                # Handle wrap-around
                if end_idx <= len(regular_devices):
                    regular_batch = regular_devices[start_idx:end_idx]
                else:
                    regular_batch = regular_devices[start_idx:] + regular_devices[:end_idx - len(regular_devices)]
                
                devices_to_monitor.extend(regular_batch)
                
                # Update rotation index for next cycle
                self._device_rotation_index = (self._device_rotation_index + batch_size) % len(regular_devices)
                
                logger.debug(f"Regular device batch: {start_idx}-{end_idx % len(regular_devices)} ({len(regular_batch)} devices)")
            
            logger.debug(f"Total monitoring this cycle: {len(devices_to_monitor)} devices")
            
            # Get configuration values - use smaller worker pool to reduce load
            max_workers = min(10, len(devices_to_monitor))  # Cap at 10 workers max
            ping_timeout = float(self.get_config_value('ping_timeout', Config.PING_TIMEOUT))
            
            # Use ThreadPoolExecutor with smaller batch size
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit monitoring tasks
                future_to_device = {
                    executor.submit(self.monitor_device, device): device 
                    for device in devices_to_monitor
                }
                
                results = []
                
                # Collect results with timeout
                for future in as_completed(future_to_device, timeout=ping_timeout * 3):
                    device = future_to_device[future]
                    try:
                        result = future.result(timeout=ping_timeout + 1)
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Error getting result for device {device.ip_address}: {e}")
            
            # Emit summary update
            if self.socketio and results:
                successful_pings = sum(1 for r in results if r['success'])
                total_devices = len(results)
                
                self.socketio.emit('monitoring_summary', {
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_devices': total_devices,
                    'devices_up': successful_pings,
                    'devices_down': total_devices - successful_pings,
                    'success_rate': (successful_pings / total_devices * 100) if total_devices > 0 else 0
                })
            
                logger.info(f"Monitoring cycle completed for {len(devices_to_monitor)} devices")
            
        except Exception as e:
            logger.error(f"Error during device monitoring cycle: {e}")
    
    def cleanup_old_data(self):
        """Clean up old monitoring data based on retention policy"""
        if not self.app:
            return
            
        try:
            with self.app.app_context():
                data_retention_days = int(self.get_config_value('data_retention_days', Config.DATA_RETENTION_DAYS))
                cutoff_date = datetime.utcnow() - timedelta(days=data_retention_days)
                
                deleted_count = db.session.query(MonitoringData)\
                    .filter(MonitoringData.timestamp < cutoff_date)\
                    .delete()
                
                db.session.commit()
                
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old monitoring records")
                    
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
    
    def get_device_statistics(self, device_id, hours=24):
        """Get statistics for a specific device"""
        try:
            if not self.app:
                logger.error("No Flask app context available for statistics")
                return None
                
            with self.app.app_context():
                cutoff = datetime.utcnow() - timedelta(hours=hours)
                
                # Get monitoring data for the specified period
                data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff
                ).all()
            
            if not data:
                return None
            
            # Calculate statistics
            response_times = [d.response_time for d in data if d.response_time is not None]
            total_checks = len(data)
            successful_checks = len(response_times)
            failed_checks = total_checks - successful_checks
            
            stats = {
                'total_checks': total_checks,
                'successful_checks': successful_checks,
                'failed_checks': failed_checks,
                'uptime_percentage': (successful_checks / total_checks * 100) if total_checks > 0 else 0,
                'avg_response_time': sum(response_times) / len(response_times) if response_times else None,
                'min_response_time': min(response_times) if response_times else None,
                'max_response_time': max(response_times) if response_times else None,
                'period_hours': hours
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating device statistics: {e}")
            return None
    
    def get_network_statistics(self, hours=24):
        """Get network-wide statistics"""
        try:
            if not self.app:
                logger.error("No Flask app context available for network statistics")
                return None
                
            with self.app.app_context():
                cutoff = datetime.utcnow() - timedelta(hours=hours)
                
                # Get all monitoring data for the period
                data = MonitoringData.query.filter(
                    MonitoringData.timestamp >= cutoff
                ).all()
            
            if not data:
                return None
            
            # Group by device
            device_data = {}
            for d in data:
                if d.device_id not in device_data:
                    device_data[d.device_id] = []
                device_data[d.device_id].append(d)
            
            # Calculate network statistics
            total_devices = len(device_data)
            devices_with_data = 0
            total_uptime = 0
            all_response_times = []
            
            for device_id, device_records in device_data.items():
                if device_records:
                    devices_with_data += 1
                    successful = sum(1 for r in device_records if r.response_time is not None)
                    device_uptime = (successful / len(device_records) * 100) if device_records else 0
                    total_uptime += device_uptime
                    
                    response_times = [r.response_time for r in device_records if r.response_time is not None]
                    all_response_times.extend(response_times)
            
            stats = {
                'total_devices': total_devices,
                'devices_monitored': devices_with_data,
                'network_uptime_avg': total_uptime / devices_with_data if devices_with_data > 0 else 0,
                'avg_response_time': sum(all_response_times) / len(all_response_times) if all_response_times else None,
                'total_checks': len(data),
                'successful_checks': len(all_response_times),
                'period_hours': hours
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating network statistics: {e}")
            return None
    
    def start_monitoring(self):
        """Start the continuous monitoring process"""
        self.is_running = True
        logger.info("Starting device monitoring")
        
        # Cleanup old data on startup
        self.cleanup_old_data()
        
        while not self._stop_event.is_set():
            try:
                # Monitor all devices
                self.monitor_all_devices()
                
                # Clean up old data periodically (every 10 cycles)
                if hasattr(self, '_cleanup_counter'):
                    self._cleanup_counter += 1
                else:
                    self._cleanup_counter = 1
                
                if self._cleanup_counter >= 10:
                    self.cleanup_old_data()
                    self._cleanup_counter = 0
                
                # Wait for next monitoring cycle  
                ping_interval = int(self.get_config_value('ping_interval', Config.PING_INTERVAL))
                self._stop_event.wait(ping_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)  # Wait before retrying
        
        self.is_running = False
        logger.info("Device monitoring stopped")
    
    def stop(self):
        """Stop the monitoring process"""
        logger.info("Stopping device monitor")
        self._stop_event.set()
        self.is_running = False
    
    def force_monitor_device(self, device_id):
        """Force monitoring of a specific device (for manual triggers)"""
        try:
            if not self.app:
                logger.error("No Flask app context available for force monitoring")
                return None
                
            with self.app.app_context():
                device = Device.query.get(device_id)
                if device:
                    return self.monitor_device(device)
                return None
        except Exception as e:
            logger.error(f"Error force monitoring device {device_id}: {e}")
            return None
    
    def _trigger_rule_engine_for_status_change(self, device, previous_status, current_status, response_time):
        """Trigger rule engine evaluation for device status changes"""
        try:
            # Get rule engine service from app if available
            if self.app and hasattr(self.app, 'rule_engine_service'):
                rule_engine_service = self.app.rule_engine_service
                
                # Import here to avoid circular imports
                from services.rule_engine import TriggerContext
                
                # Create trigger context for the device status change event
                context = TriggerContext(
                    event_type='device_status_change',
                    device_id=device.id,
                    device={
                        'id': device.id,
                        'display_name': device.display_name,
                        'ip_address': device.ip_address,
                        'mac_address': device.mac_address,
                        'hostname': device.hostname,
                        'vendor': device.vendor,
                        'device_type': device.device_type,
                        'status': current_status,
                        'is_monitored': device.is_monitored
                    },
                    monitoring_data={
                        'response_time': response_time,
                        'previous_status': previous_status,
                        'current_status': current_status,
                        'timestamp': datetime.utcnow().isoformat()
                    },
                    metadata={
                        'status_changed_from': previous_status,
                        'status_changed_to': current_status,
                        'response_time_ms': response_time,
                        'monitoring_timestamp': datetime.utcnow().isoformat()
                    }
                )
                
                # Evaluate rules in background thread to avoid blocking monitoring
                import threading
                rule_thread = threading.Thread(
                    target=rule_engine_service.evaluate_rules,
                    args=(context,),
                    daemon=True,
                    name=f'RuleEngine-StatusChange-{device.display_name}'
                )
                rule_thread.start()
                
                logger.debug(f"Triggered rule engine for status change: {device.display_name} {previous_status} -> {current_status}")
                
        except Exception as e:
            logger.error(f"Error triggering rule engine for status change: {e}")
            # Don't let rule engine errors affect monitoring