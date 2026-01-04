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
from monitoring.iot_device_optimizer import iot_optimizer

logger = logging.getLogger(__name__)

class DeviceMonitor:
    def __init__(self, socketio=None, app=None):
        self.socketio = socketio
        self.app = app
        self.is_running = False
        self.executor = None
        self._stop_event = threading.Event()
        self._rotation_lock = threading.Lock()  # Thread safety for device rotation
        self._device_rotation_index = 0
        self.rule_engine_service = None
        
        # Use adaptive thread pool for monitoring
        try:
            from services.thread_pool_manager import get_monitoring_pool
            self._adaptive_pool = get_monitoring_pool()
        except ImportError:
            self._adaptive_pool = None
        
    def get_config_value(self, key, default):
        """Get configuration value from database or use default"""
        try:
            if self.app:
                with self.app.app_context():
                    return Configuration.get_value(key, str(default))
            else:
                return Configuration.get_value(key, str(default))
        except Exception as e:
            logger.debug(f"Failed to get config value '{key}', using default '{default}': {e}")
            return str(default)
        
    def ping_device(self, device):
        """Ping a single device with retry logic and return response time using system ping command"""
        # SECURITY: Validate IP address to prevent command injection
        import ipaddress
        try:
            ipaddress.ip_address(device.ip_address)
        except ValueError:
            logger.warning(f"Invalid IP address format for device {device.id}: {device.ip_address}")
            return None
        
        # Get optimized settings for this device
        optimized = iot_optimizer.get_optimized_settings(device)
        ping_timeout = float(optimized.get('timeout', self.get_config_value('ping_timeout', Config.PING_TIMEOUT)))
        max_retries = optimized.get('retries', 1)

        # Check if we should skip this device based on interval optimization
        should_skip, remaining = iot_optimizer.should_skip_monitoring(device)
        if should_skip:
            logger.debug(f"Skipping {device.display_name} - next check in {remaining}s")
            return None

        # For critical infrastructure (router, servers), use more lenient settings
        is_critical_device = (
            device.ip_address.endswith('.1') or  # Router
            'router' in device.device_type.lower() if device.device_type else False or
            'server' in device.device_type.lower() if device.device_type else False or
            'nuc' in device.hostname.lower() if device.hostname else False
        )

        # Override settings for critical devices
        if is_critical_device:
            max_retries = max(2, max_retries)
            ping_timeout = max(2.0, ping_timeout)

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
                    timeout=actual_timeout + 2,
                    shell=False
                )
                
                if result.returncode == 0:
                    # Parse ping output to extract response time
                    # Look for patterns like "time=1.23 ms"
                    time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
                    if time_match:
                        response_time_ms = float(time_match.group(1))
                        device.last_seen = datetime.utcnow()
                        logger.debug(f"Ping successful for {device.ip_address} on attempt {attempt + 1}: {response_time_ms}ms")
                        # Record success for optimization
                        iot_optimizer.record_ping_result(device, True, response_time_ms)
                        return response_time_ms
                    else:
                        # Ping succeeded but couldn't parse time, return 0
                        device.last_seen = datetime.utcnow()
                        logger.debug(f"Ping successful for {device.ip_address} on attempt {attempt + 1} (no time parsed)")
                        # Record success for optimization
                        iot_optimizer.record_ping_result(device, True, 0)
                        return 0.0
                else:
                    # Ping failed, try again if we have retries left
                    if attempt < max_retries:
                        logger.debug(f"Ping failed for {device.ip_address} on attempt {attempt + 1}, retrying...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logger.debug(f"Ping failed for {device.ip_address} after {max_retries + 1} attempts")
                        # Record failure for optimization
                        iot_optimizer.record_ping_result(device, False, None)
                        return None
                        
            except subprocess.TimeoutExpired:
                if attempt < max_retries:
                    logger.debug(f"Ping timeout for {device.ip_address} on attempt {attempt + 1}, retrying...")
                    time.sleep(retry_delay)
                    continue
                else:
                    logger.debug(f"Ping timeout for {device.ip_address} after {max_retries + 1} attempts")
                    # Record failure for optimization
                    iot_optimizer.record_ping_result(device, False, None)
                    return None
            except Exception as e:
                if attempt < max_retries:
                    logger.debug(f"Error pinging {device.ip_address} on attempt {attempt + 1}: {e}, retrying...")
                    time.sleep(retry_delay)
                    continue
                else:
                    logger.error(f"Error pinging {device.ip_address} after {max_retries + 1} attempts: {e}")
                    # Record failure for optimization
                    iot_optimizer.record_ping_result(device, False, None)
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
                    
                    # PERFORMANCE OPTIMIZATION: Invalidate cache when device data changes
                    try:
                        from services.query_cache import invalidate_device_cache
                        invalidate_device_cache()
                    except Exception as e:
                        # Don't let cache issues break monitoring, but log for debugging
                        logger.debug(f"Cache invalidation failed (non-critical): {e}")
                    
                    # Check for status changes and trigger rule engine
                    current_status = device_obj.status
                    if previous_status != current_status:
                        self._trigger_rule_engine_for_status_change(device_obj, previous_status, current_status, response_time)
            
            # PERFORMANCE OPTIMIZATION: Emit real-time update via SocketIO with throttling
            if self.socketio and self.app:
                # Calculate status directly from response_time to avoid DB query
                # This replicates the logic from the Device.status property
                current_status = 'up'
                if response_time is None:
                    current_status = 'down'
                elif response_time > 1000:  # >1 second
                    current_status = 'warning'
                
                event_data = {
                    'device_id': device_id,
                    'ip_address': device_ip,
                    'display_name': device.custom_name or device.hostname or device_ip,
                    'response_time': response_time,
                    'status': current_status,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Use throttling to prevent WebSocket spam
                from services.websocket_throttle import websocket_throttle
                if websocket_throttle.should_emit_device_update(device_id, event_data):
                    # Emit to specific room for device status updates
                    self.socketio.emit('device_status_update', event_data, room='updates_device_status')
                # If throttled, the update is queued for later emission
            
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
    
    def _is_high_priority_device(self, device):
        """Determine if a device is high priority (routers, servers, network infrastructure)"""
        if not device:
            return False
        
        # Check device type
        if device.device_type in ['router', 'server', 'nas', 'switch', 'access_point', 'gateway']:
            return True
            
        # Check by hostname patterns
        hostname = (device.hostname or '').lower()
        if any(pattern in hostname for pattern in ['router', 'gateway', 'server', 'nas', 'switch', 'ap-']):
            return True
            
        # Check by vendor (network equipment manufacturers)
        vendor = (device.vendor or '').lower()
        if any(vendor_pattern in vendor for vendor_pattern in ['cisco', 'netgear', 'linksys', 'asus', 'tp-link', 'ubiquiti']):
            return True
            
        return False
    
    def _is_low_priority_device(self, device):
        """Determine if a device is low priority (IoT devices, smart home devices)"""
        if not device:
            return False
            
        # Check device type
        if device.device_type in ['iot', 'smart_home', 'camera', 'sensor', 'speaker', 'tv', 'gaming']:
            return True
            
        # Check by hostname patterns
        hostname = (device.hostname or '').lower()
        iot_patterns = ['ring-', 'nest-', 'chromecast', 'echo-', 'alexa', 'google-home', 'wyze', 'sonos', 'roku', 'firetv', 'samsung', 'lg-']
        if any(pattern in hostname for pattern in iot_patterns):
            return True
            
        # Check by vendor (IoT device manufacturers)
        vendor = (device.vendor or '').lower()
        iot_vendors = ['ring', 'nest', 'wyze', 'sonos', 'roku', 'amazon', 'google', 'samsung', 'lg electronics', 'xiaomi']
        if any(vendor_pattern in vendor for vendor_pattern in iot_vendors):
            return True
            
        return False

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
        """Monitor ALL devices every cycle for home network use"""
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
            
            # For home use: monitor ALL devices every cycle
            # No rotation, no prioritization - just check everything
            devices_to_monitor = all_devices
            
            logger.info(f"Monitoring ALL {len(devices_to_monitor)} devices this cycle")
            
            # Get configuration values - use appropriate worker pool for home network
            max_workers = min(20, len(devices_to_monitor))  # Allow up to 20 concurrent pings
            ping_timeout = float(self.get_config_value('ping_timeout', Config.PING_TIMEOUT))
            
            # PERFORMANCE OPTIMIZATION: Use adaptive thread pool for monitoring
            if self._adaptive_pool:
                future_to_device = {
                    self._adaptive_pool.submit(self._ping_device_for_batch, device): device 
                    for device in devices_to_monitor
                }
            else:
                # Fallback to regular ThreadPoolExecutor
                future_to_device = {}
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_device = {
                        executor.submit(self._ping_device_for_batch, device): device 
                        for device in devices_to_monitor
                    }
            
            results = []
            
            # Collect results with timeout
            try:
                for future in as_completed(future_to_device, timeout=ping_timeout * 3):
                    device = future_to_device[future]
                    try:
                        result = future.result(timeout=ping_timeout + 1)
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Error getting result for device {device.ip_address}: {e}")
            except TimeoutError:
                # Some futures didn't complete in time - log and continue
                unfinished = sum(1 for f in future_to_device if not f.done())
                if unfinished > 0:
                    logger.warning(f"{unfinished} device pings did not complete within timeout - continuing")
                # Process the results we did get
                for future in future_to_device:
                    if future.done():
                        device = future_to_device[future]
                        try:
                            result = future.result(timeout=0.1)
                            if result and result not in results:
                                results.append(result)
                        except Exception:
                            pass
            
            # PERFORMANCE OPTIMIZATION: Batch process all monitoring results in a single transaction
            if results:
                self._batch_process_monitoring_results(results)
            
            # Emit summary update
            if self.socketio and results and self.app:
                successful_pings = sum(1 for r in results if r['success'])
                total_devices = len(results)
                
                # Get active alerts count with app context
                with self.app.app_context():
                    from models import Alert
                    active_alerts = Alert.query.filter_by(resolved=False).count()
                
                # PERFORMANCE OPTIMIZATION: Throttle monitoring summary updates
                from services.websocket_throttle import websocket_throttle
                if websocket_throttle.should_emit_global_event('monitoring_summary'):
                    self.socketio.emit('monitoring_summary', {
                        'timestamp': datetime.utcnow().isoformat(),
                        'total_devices': total_devices,
                        'devices_up': successful_pings,
                        'devices_down': total_devices - successful_pings,
                        'active_alerts': active_alerts,
                        'success_rate': (successful_pings / total_devices * 100) if total_devices > 0 else 0
                    }, room='updates_monitoring_summary')
                
                # Emit chart data updates for real-time chart system
                self._emit_chart_data_updates(results)
            
                logger.info(f"Monitoring cycle completed for {len(devices_to_monitor)} devices")
            
        except Exception as e:
            logger.error(f"Error during device monitoring cycle: {e}")
    
    def cleanup_old_data(self, aggressive=False):
        """Clean up old monitoring data based on retention policy"""
        if not self.app:
            logger.debug("No app context for cleanup")
            return
            
        try:
            with self.app.app_context():
                # Use aggressive cleanup (7 days) if requested, otherwise use config value
                if aggressive:
                    data_retention_days = 7
                    logger.info("Running aggressive data cleanup (7 days retention)")
                else:
                    data_retention_days = int(self.get_config_value('data_retention_days', Config.DATA_RETENTION_DAYS))
                
                cutoff_date = datetime.utcnow() - timedelta(days=data_retention_days)
                
                # Clean monitoring data in batches to avoid locking
                total_deleted = 0
                batch_size = 1000  # Reduced batch size for faster processing
                max_iterations = 100  # Limit iterations to prevent infinite loops
                iteration = 0
                
                while iteration < max_iterations:
                    iteration += 1
                    
                    # Select IDs to delete in batches with timeout
                    try:
                        ids_to_delete = db.session.query(MonitoringData.id)\
                            .filter(MonitoringData.timestamp < cutoff_date)\
                            .limit(batch_size).all()
                    except Exception as e:
                        logger.error(f"Error querying old monitoring data: {e}")
                        db.session.rollback()
                        break
                    
                    if not ids_to_delete:
                        break
                    
                    # Delete by IDs
                    id_list = [row[0] for row in ids_to_delete]
                    deleted_count = db.session.query(MonitoringData)\
                        .filter(MonitoringData.id.in_(id_list))\
                        .delete(synchronize_session=False)
                    
                    total_deleted += deleted_count
                    db.session.commit()
                    
                    if len(id_list) < batch_size:
                        break
                
                if total_deleted > 0:
                    logger.info(f"Cleaned up {total_deleted:,} old monitoring records")
                
                # Also cleanup old performance metrics if aggressive
                if aggressive:
                    try:
                        from models import PerformanceMetrics
                        perf_deleted = db.session.query(PerformanceMetrics)\
                            .filter(PerformanceMetrics.timestamp < cutoff_date)\
                            .delete(synchronize_session=False)
                        
                        if perf_deleted > 0:
                            db.session.commit()
                            logger.info(f"Cleaned up {perf_deleted:,} old performance metrics")
                    except Exception as e:
                        logger.warning(f"Performance metrics cleanup failed: {e}")
                        db.session.rollback()
                    
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
        try:
            self.is_running = True
            logger.info("Starting device monitoring thread")
            
            # Run aggressive cleanup on startup for performance with timeout
            logger.info("Running startup database cleanup for optimal performance...")
            try:
                # Use threading-based timeout since signals don't work in background threads
                import threading
                from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

                # Run cleanup with thread-based timeout
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self.cleanup_old_data, aggressive=True)
                    try:
                        future.result(timeout=30)  # 30-second timeout
                        logger.info("Database cleanup completed successfully")
                    except FutureTimeoutError:
                        logger.warning("Database cleanup timed out after 30 seconds. Continuing with monitoring...")
                    except Exception as e:
                        logger.error(f"Error during database cleanup: {e}. Continuing with monitoring...")

            except Exception as e:
                logger.error(f"Error during startup database cleanup: {e}. Continuing with monitoring...")
            
            logger.info("Entering main monitoring loop")
            
        except Exception as e:
            logger.error(f"Critical error starting device monitoring: {e}", exc_info=True)
            self.is_running = False
            return
            
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
                    
                    # Also run alert retention cleanup (less frequent - every 10 cycles)
                    try:
                        from services.alert_retention_policy import alert_retention_policy
                        if self.app:
                            alert_retention_policy.app = self.app
                        alert_retention_policy.run_retention_cleanup()
                    except Exception as e:
                        logger.error(f"Error in alert retention cleanup: {e}")
                    
                    self._cleanup_counter = 0
                
                # Run alert auto-resolution periodically (every 5 cycles)
                if hasattr(self, '_auto_resolve_counter'):
                    self._auto_resolve_counter += 1
                else:
                    self._auto_resolve_counter = 1
                
                if self._auto_resolve_counter >= 5:
                    try:
                        from services.alert_auto_resolver import alert_auto_resolver
                        if self.app:
                            alert_auto_resolver.app = self.app
                        alert_auto_resolver.run_auto_resolution_cycle()
                        self._auto_resolve_counter = 0
                    except Exception as e:
                        logger.error(f"Error in alert auto-resolution: {e}")
                        self._auto_resolve_counter = 0
                
                # Flush any pending WebSocket updates
                if self.socketio:
                    try:
                        from services.websocket_throttle import websocket_throttle
                        websocket_throttle.flush_pending_updates(self.socketio, self.app)
                    except Exception as e:
                        logger.error(f"Error flushing WebSocket updates: {e}")
                
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
    
    def queue_immediate_ping(self, device_id):
        """Queue an immediate ping for a device (alias for force_monitor_device)"""
        return self.force_monitor_device(device_id)
    
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
    
    def _emit_chart_data_updates(self, monitoring_results):
        """Emit real-time chart data updates for the interactive chart system"""
        try:
            if not self.socketio or not self.app:
                return
                
            with self.app.app_context():
                # Get device types breakdown for analytics charts
                from collections import defaultdict
                device_types = defaultdict(lambda: {'up': 0, 'down': 0})
                response_times = []
                
                for result in monitoring_results:
                    device = Device.query.get(result['device_id'])
                    if device:
                        device_type = device.device_type or 'unknown'
                        if result['success']:
                            device_types[device_type]['up'] += 1
                            if result['response_time'] is not None:
                                response_times.append({
                                    'device_id': device.id,
                                    'device_name': device.display_name,
                                    'response_time': result['response_time'],
                                    'timestamp': datetime.utcnow().isoformat()
                                })
                        else:
                            device_types[device_type]['down'] += 1
                
                # Emit device types chart update
                device_types_data = []
                for device_type, counts in device_types.items():
                    total = counts['up'] + counts['down']
                    if total > 0:
                        device_types_data.append({
                            'type': device_type,
                            'total': total,
                            'up': counts['up'],
                            'down': counts['down'],
                            'uptime_percentage': (counts['up'] / total) * 100
                        })
                
                self.socketio.emit('chart_data_update', {
                    'type': 'device_types',
                    'data': device_types_data,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Emit response times update for performance charts
                if response_times:
                    self.socketio.emit('chart_data_update', {
                        'type': 'response_times',
                        'data': response_times[-50:],  # Last 50 data points
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                # Emit network overview metrics
                total_monitored = len(monitoring_results)
                successful_pings = sum(1 for r in monitoring_results if r['success'])
                
                self.socketio.emit('chart_data_update', {
                    'type': 'network_overview', 
                    'data': {
                        'total_devices': total_monitored,
                        'devices_up': successful_pings,
                        'devices_down': total_monitored - successful_pings,
                        'success_rate': (successful_pings / total_monitored * 100) if total_monitored > 0 else 0,
                        'avg_response_time': sum(r.get('response_time', 0) for r in monitoring_results if r.get('response_time')) / max(1, successful_pings)
                    },
                    'timestamp': datetime.utcnow().isoformat()
                })
                
        except Exception as e:
            logger.error(f"Error emitting chart data updates: {e}")
    
    def reload_config(self):
        """Reload configuration for hot-reload support"""
        try:
            logger.info("Reloading DeviceMonitor configuration")
            # Clear any cached config values if we had them
            # For now, just log the reload - actual reloading happens via get_config_value calls
            
            # Log current configuration values
            if self.app:
                with self.app.app_context():
                    ping_interval = self.get_config_value('ping_interval', Config.PING_INTERVAL)
                    ping_timeout = self.get_config_value('ping_timeout', Config.PING_TIMEOUT)
                    data_retention = self.get_config_value('data_retention_days', Config.DATA_RETENTION_DAYS)
                    
                    logger.info(f"DeviceMonitor config reloaded - ping_interval: {ping_interval}s, "
                              f"ping_timeout: {ping_timeout}s, data_retention: {data_retention} days")
        except Exception as e:
            logger.error(f"Error reloading DeviceMonitor configuration: {e}")
    
    def _ping_device_for_batch(self, device):
        """Ping a device and return raw result for batch processing"""
        try:
            response_time = self.ping_device(device)
            
            return {
                'device_id': device.id,
                'device': device,  # Keep reference for batch processing
                'response_time': response_time,
                'success': response_time is not None,
                'timestamp': datetime.utcnow()
            }
        except Exception as e:
            logger.error(f"Error pinging device {device.ip_address} for batch: {e}")
            return {
                'device_id': device.id,
                'device': device,
                'response_time': None,
                'success': False,
                'timestamp': datetime.utcnow()
            }
    
    def _batch_process_monitoring_results(self, ping_results):
        """
        PERFORMANCE OPTIMIZATION: Process all monitoring results in a single transaction
        
        This dramatically reduces database overhead by:
        - Using a single transaction for all monitoring data inserts
        - Batch updating device last_seen timestamps
        - Collecting status changes for bulk rule engine processing
        """
        if not self.app or not ping_results:
            return
        
        try:
            with self.app.app_context():
                status_changes = []
                monitoring_records = []
                device_updates = []
                socketio_events = []
                
                # Prepare batch data
                for result in ping_results:
                    device = result['device']
                    response_time = result['response_time']
                    timestamp = result['timestamp']
                    
                    # Create monitoring data record
                    monitoring_records.append(MonitoringData(
                        device_id=device.id,
                        response_time=response_time,
                        timestamp=timestamp
                    ))
                    
                    # Prepare device update if ping was successful
                    if response_time is not None:
                        device_updates.append({
                            'device_id': device.id,
                            'last_seen': timestamp
                        })
                    
                    # Calculate status for change detection and WebSocket events
                    previous_status = device.status  # This might trigger a query, but we'll optimize
                    current_status = 'up'
                    if response_time is None:
                        current_status = 'down'
                    elif response_time > 1000:
                        current_status = 'warning'
                    
                    # Track status changes for rule engine
                    if previous_status != current_status:
                        status_changes.append({
                            'device': device,
                            'previous_status': previous_status,
                            'current_status': current_status,
                            'response_time': response_time
                        })
                    
                    # Prepare WebSocket events with throttling
                    event_data = {
                        'device_id': device.id,
                        'ip_address': device.ip_address,
                        'display_name': device.custom_name or device.hostname or device.ip_address,
                        'response_time': response_time,
                        'status': current_status,
                        'timestamp': timestamp.isoformat()
                    }
                    socketio_events.append(event_data)
                
                # Batch insert monitoring data
                if monitoring_records:
                    db.session.add_all(monitoring_records)
                
                # Batch update device last_seen timestamps using ORM bulk update
                if device_updates:
                    from models import Device
                    for update in device_updates:
                        # Use ORM update method instead of raw SQL
                        Device.query.filter(Device.id == update['device_id']).update({
                            'last_seen': update['last_seen']
                        })
                
                # Commit all changes in single transaction
                db.session.commit()
                
                logger.debug(f"Batch processed {len(monitoring_records)} monitoring records and {len(device_updates)} device updates")
                
                # Process status changes for rule engine (outside transaction)
                for change in status_changes:
                    self._trigger_rule_engine_for_status_change(
                        change['device'],
                        change['previous_status'],
                        change['current_status'],
                        change['response_time']
                    )
                
                # Emit WebSocket events with throttling
                if self.socketio:
                    from services.websocket_throttle import websocket_throttle
                    for event_data in socketio_events:
                        if websocket_throttle.should_emit_device_update(event_data['device_id'], event_data):
                            self.socketio.emit('device_status_update', event_data, room='updates_device_status')
                
        except Exception as e:
            logger.error(f"Error in batch processing monitoring results: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()