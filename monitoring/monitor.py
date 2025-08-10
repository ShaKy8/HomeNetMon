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
        """Ping a single device and return response time using system ping command"""
        try:
            # Get ping timeout from database configuration
            ping_timeout = float(self.get_config_value('ping_timeout', Config.PING_TIMEOUT))
            
            # Use system ping command (works without root privileges)
            cmd = ['ping', '-c', '1', '-W', str(int(ping_timeout)), device.ip_address]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=ping_timeout + 2
            )
            
            if result.returncode == 0:
                # Parse ping output to extract response time
                # Look for patterns like "time=1.23 ms"
                time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
                if time_match:
                    response_time_ms = float(time_match.group(1))
                    device.last_seen = datetime.utcnow()
                    return response_time_ms
                else:
                    # Ping succeeded but couldn't parse time, return 0
                    device.last_seen = datetime.utcnow()
                    return 0.0
            else:
                return None
                
        except subprocess.TimeoutExpired:
            logger.debug(f"Ping timeout for {device.ip_address}")
            return None
        except Exception as e:
            logger.error(f"Error pinging {device.ip_address}: {e}")
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
    
    def monitor_all_devices(self):
        """Monitor all devices in parallel"""
        try:
            if not self.app:
                logger.error("No Flask app context available for monitoring")
                return
            
            with self.app.app_context():
                # Get all devices that should be monitored
                devices = Device.query.filter_by(is_monitored=True).all()
            
            if not devices:
                logger.debug("No devices to monitor")
                return
            
            logger.debug(f"Monitoring {len(devices)} devices")
            
            # Get configuration values
            max_workers = int(self.get_config_value('max_workers', Config.MAX_WORKERS))
            ping_timeout = float(self.get_config_value('ping_timeout', Config.PING_TIMEOUT))
            
            # Use ThreadPoolExecutor for concurrent monitoring
            with ThreadPoolExecutor(max_workers=min(max_workers, len(devices))) as executor:
                # Submit monitoring tasks
                future_to_device = {
                    executor.submit(self.monitor_device, device): device 
                    for device in devices
                }
                
                results = []
                
                # Collect results
                for future in as_completed(future_to_device, timeout=ping_timeout * 2):
                    device = future_to_device[future]
                    try:
                        result = future.result(timeout=ping_timeout)
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
            
                logger.info(f"Monitoring cycle completed for {len(devices)} devices")
            
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