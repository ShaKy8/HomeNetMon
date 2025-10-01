import time
import threading
import logging
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from models import db, Device, MonitoringData, BandwidthData, PerformanceMetrics, Configuration, Alert
from config import Config

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Service for aggregating and analyzing device performance metrics"""
    
    def __init__(self, app=None, socketio=None):
        self.app = app
        self.socketio = socketio
        self.is_running = False
        self.monitor_thread = None
        self._stop_event = threading.Event()
        self.collection_interval = 300  # Default 5 minutes
        
        # Performance alert thresholds
        self.alert_thresholds = {
            'health_score_critical': 50,     # Critical alert when health < 50
            'health_score_warning': 70,      # Warning alert when health < 70
            'health_score_recovery': 80,     # Recovery threshold
            'responsiveness_critical': 40,   # Critical responsiveness threshold
            'reliability_critical': 60,      # Critical reliability threshold
            'consecutive_periods': 2         # Require 2 consecutive periods below threshold
        }
        
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
    
    def collect_device_performance_metrics(self, device_id, collection_period_minutes=60):
        """Collect and aggregate performance metrics for a specific device"""
        try:
            if not self.app:
                logger.error("No Flask app context available for performance collection")
                return None
                
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device or not device.is_monitored:
                    return None
                
                logger.debug(f"Collecting performance metrics for device {device.display_name}")
                
                # Define time window for collection
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(minutes=collection_period_minutes)
                
                # Collect response time data
                response_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= start_time,
                    MonitoringData.timestamp <= end_time
                ).order_by(MonitoringData.timestamp).all()
                
                # Collect bandwidth data
                bandwidth_data = BandwidthData.query.filter(
                    BandwidthData.device_id == device_id,
                    BandwidthData.timestamp >= start_time,
                    BandwidthData.timestamp <= end_time
                ).order_by(BandwidthData.timestamp).all()
                
                if not response_data and not bandwidth_data:
                    logger.debug(f"No data available for device {device.display_name}")
                    return None
                
                # Calculate response time metrics
                response_metrics = self._calculate_response_metrics(response_data)
                
                # Calculate availability metrics
                availability_metrics = self._calculate_availability_metrics(response_data)
                
                # Calculate bandwidth metrics
                bandwidth_metrics = self._calculate_bandwidth_metrics(bandwidth_data)
                
                # Calculate quality metrics (jitter, packet loss)
                quality_metrics = self._calculate_quality_metrics(response_data)
                
                # Calculate health scores
                health_scores = PerformanceMetrics.calculate_health_score(
                    response_metrics, availability_metrics, 
                    bandwidth_metrics, quality_metrics
                )
                
                # Create performance metrics record
                performance_record = PerformanceMetrics(
                    device_id=device_id,
                    timestamp=end_time,
                    
                    # Response time metrics
                    avg_response_time=response_metrics.get('avg_ms'),
                    min_response_time=response_metrics.get('min_ms'),
                    max_response_time=response_metrics.get('max_ms'),
                    response_time_std_dev=response_metrics.get('std_dev_ms'),
                    
                    # Availability metrics
                    uptime_percentage=availability_metrics.get('uptime_percentage'),
                    total_checks=availability_metrics.get('total_checks'),
                    successful_checks=availability_metrics.get('successful_checks'),
                    failed_checks=availability_metrics.get('failed_checks'),
                    
                    # Bandwidth metrics
                    avg_bandwidth_in_mbps=bandwidth_metrics.get('avg_in_mbps'),
                    avg_bandwidth_out_mbps=bandwidth_metrics.get('avg_out_mbps'),
                    peak_bandwidth_in_mbps=bandwidth_metrics.get('peak_in_mbps'),
                    peak_bandwidth_out_mbps=bandwidth_metrics.get('peak_out_mbps'),
                    total_bytes_in=bandwidth_metrics.get('total_bytes_in'),
                    total_bytes_out=bandwidth_metrics.get('total_bytes_out'),
                    
                    # Quality metrics
                    jitter_ms=quality_metrics.get('jitter_ms'),
                    packet_loss_percentage=quality_metrics.get('packet_loss_percentage'),
                    connection_stability_score=quality_metrics.get('stability_score'),
                    
                    # Health scores
                    health_score=health_scores.get('overall_health'),
                    responsiveness_score=health_scores.get('responsiveness'),
                    reliability_score=health_scores.get('reliability'),
                    efficiency_score=health_scores.get('efficiency'),
                    
                    # Collection metadata
                    collection_period_minutes=collection_period_minutes,
                    sample_count=len(response_data) + len(bandwidth_data),
                    anomaly_count=self._count_anomalies(response_data, bandwidth_data)
                )
                
                db.session.add(performance_record)
                db.session.commit()
                
                logger.info(f"Collected performance metrics for {device.display_name}: "
                          f"Health={health_scores.get('overall_health', 0):.1f}")
                
                # Emit real-time performance update via WebSocket
                self._emit_device_performance_update(device, performance_record)
                
                # Check for performance alerts
                self._check_performance_alerts(device, performance_record)
                
                return performance_record
                
        except Exception as e:
            logger.error(f"Error collecting performance metrics for device {device_id}: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
            return None
    
    def _calculate_response_metrics(self, response_data):
        """Calculate response time statistics"""
        if not response_data:
            return {'avg_ms': None, 'min_ms': None, 'max_ms': None, 'std_dev_ms': None}
        
        # Filter out None values (failed pings)
        response_times = [r.response_time for r in response_data if r.response_time is not None]
        
        if not response_times:
            return {'avg_ms': None, 'min_ms': None, 'max_ms': None, 'std_dev_ms': None}
        
        return {
            'avg_ms': statistics.mean(response_times),
            'min_ms': min(response_times),
            'max_ms': max(response_times),
            'std_dev_ms': statistics.stdev(response_times) if len(response_times) > 1 else 0
        }
    
    def _calculate_availability_metrics(self, response_data):
        """Calculate availability and uptime statistics"""
        if not response_data:
            return {
                'uptime_percentage': 0,
                'total_checks': 0,
                'successful_checks': 0,
                'failed_checks': 0
            }
        
        total_checks = len(response_data)
        successful_checks = sum(1 for r in response_data if r.response_time is not None)
        failed_checks = total_checks - successful_checks
        uptime_percentage = (successful_checks / total_checks * 100) if total_checks > 0 else 0
        
        return {
            'uptime_percentage': uptime_percentage,
            'total_checks': total_checks,
            'successful_checks': successful_checks,
            'failed_checks': failed_checks
        }
    
    def _calculate_bandwidth_metrics(self, bandwidth_data):
        """Calculate bandwidth usage statistics"""
        if not bandwidth_data:
            return {
                'avg_in_mbps': 0, 'avg_out_mbps': 0,
                'peak_in_mbps': 0, 'peak_out_mbps': 0,
                'total_bytes_in': 0, 'total_bytes_out': 0
            }
        
        in_rates = [b.bandwidth_in_mbps for b in bandwidth_data if b.bandwidth_in_mbps is not None]
        out_rates = [b.bandwidth_out_mbps for b in bandwidth_data if b.bandwidth_out_mbps is not None]
        
        return {
            'avg_in_mbps': statistics.mean(in_rates) if in_rates else 0,
            'avg_out_mbps': statistics.mean(out_rates) if out_rates else 0,
            'peak_in_mbps': max(in_rates) if in_rates else 0,
            'peak_out_mbps': max(out_rates) if out_rates else 0,
            'total_bytes_in': sum(b.bytes_in for b in bandwidth_data if b.bytes_in),
            'total_bytes_out': sum(b.bytes_out for b in bandwidth_data if b.bytes_out)
        }
    
    def _calculate_quality_metrics(self, response_data):
        """Calculate network quality metrics (jitter, packet loss)"""
        if not response_data:
            return {
                'jitter_ms': None,
                'packet_loss_percentage': 0,
                'stability_score': 0
            }
        
        # Calculate jitter (variation in response times)
        response_times = [r.response_time for r in response_data if r.response_time is not None]
        jitter = 0
        
        if len(response_times) > 1:
            # Calculate jitter as standard deviation of response times
            jitter = statistics.stdev(response_times)
        
        # Calculate packet loss percentage
        total_packets = len(response_data)
        lost_packets = sum(1 for r in response_data if r.response_time is None)
        packet_loss_pct = (lost_packets / total_packets * 100) if total_packets > 0 else 0
        
        # Calculate stability score (higher is better)
        stability_score = 100
        if jitter > 0:
            stability_score = max(0, 100 - (jitter * 2))  # Reduce score based on jitter
        stability_score = max(0, stability_score - (packet_loss_pct * 10))  # Reduce score based on packet loss
        
        return {
            'jitter_ms': jitter,
            'packet_loss_percentage': packet_loss_pct,
            'stability_score': stability_score
        }
    
    def _count_anomalies(self, response_data, bandwidth_data):
        """Count anomalies in the data (spikes, drops, etc.)"""
        anomaly_count = 0
        
        try:
            # Check for response time anomalies
            response_times = [r.response_time for r in response_data if r.response_time is not None]
            if len(response_times) > 3:
                mean_response = statistics.mean(response_times)
                std_response = statistics.stdev(response_times)
                threshold = mean_response + (2 * std_response)  # 2 standard deviations
                
                anomaly_count += sum(1 for rt in response_times if rt > threshold)
            
            # Check for bandwidth anomalies
            if bandwidth_data:
                total_rates = [(b.bandwidth_in_mbps or 0) + (b.bandwidth_out_mbps or 0) 
                              for b in bandwidth_data]
                if len(total_rates) > 3:
                    mean_bandwidth = statistics.mean(total_rates)
                    std_bandwidth = statistics.stdev(total_rates)
                    upper_threshold = mean_bandwidth + (2 * std_bandwidth)
                    
                    anomaly_count += sum(1 for rate in total_rates if rate > upper_threshold)
        
        except Exception as e:
            logger.debug(f"Error counting anomalies: {e}")
        
        return anomaly_count
    
    def collect_all_devices_performance(self):
        """Collect performance metrics for all monitored devices"""
        try:
            if not self.app:
                logger.error("No Flask app context available for performance collection")
                return
                
            with self.app.app_context():
                # Get all monitored devices
                devices = Device.query.filter_by(is_monitored=True).all()
                
                if not devices:
                    logger.debug("No monitored devices found")
                    return
                
                logger.info(f"Collecting performance metrics for {len(devices)} devices")
                
                # Get collection period from configuration
                collection_period = int(self.get_config_value('performance_collection_period', '60'))
                
                successful_collections = 0
                
                for device in devices:
                    try:
                        result = self.collect_device_performance_metrics(
                            device.id, collection_period
                        )
                        if result:
                            successful_collections += 1
                    except Exception as e:
                        logger.error(f"Error collecting metrics for device {device.display_name}: {e}")
                
                logger.info(f"Successfully collected performance metrics for "
                          f"{successful_collections}/{len(devices)} devices")
                
                # Emit network performance summary update
                if successful_collections > 0:
                    self._emit_network_performance_summary()
                
        except Exception as e:
            logger.error(f"Error during performance collection cycle: {e}")
    
    def cleanup_old_performance_data(self):
        """Clean up old performance metrics based on retention policy"""
        if not self.app:
            return
            
        try:
            with self.app.app_context():
                retention_days = int(self.get_config_value('performance_retention_days', '30'))
                cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
                
                deleted_count = db.session.query(PerformanceMetrics)\
                    .filter(PerformanceMetrics.timestamp < cutoff_date)\
                    .delete()
                
                db.session.commit()
                
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old performance records")
                    
        except Exception as e:
            logger.error(f"Error during performance data cleanup: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
    
    def get_network_performance_summary(self, hours=24):
        """Get network-wide performance summary"""
        try:
            if not self.app:
                return None
                
            with self.app.app_context():
                cutoff = datetime.utcnow() - timedelta(hours=hours)
                
                # Get latest performance metrics for each device
                device_performances = db.session.execute(
                    db.text("""
                        SELECT 
                            d.id,
                            COALESCE(d.custom_name, d.hostname, d.ip_address) as display_name,
                            d.ip_address,
                            d.device_type,
                            pm.health_score,
                            pm.responsiveness_score,
                            pm.reliability_score,
                            pm.efficiency_score,
                            pm.uptime_percentage
                        FROM devices d
                        LEFT JOIN (
                            SELECT DISTINCT
                                device_id,
                                health_score,
                                responsiveness_score,
                                reliability_score,
                                efficiency_score,
                                uptime_percentage,
                                ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY timestamp DESC) as rn
                            FROM performance_metrics
                            WHERE timestamp >= :cutoff
                        ) pm ON d.id = pm.device_id AND pm.rn = 1
                        WHERE d.is_monitored = 1
                        ORDER BY pm.health_score DESC NULLS LAST
                    """),
                    {'cutoff': cutoff}
                ).fetchall()
                
                # Calculate network-wide statistics
                health_scores = [row[4] for row in device_performances if row[4] is not None]
                uptime_percentages = [row[8] for row in device_performances if row[8] is not None]
                
                device_count_by_status = defaultdict(int)
                device_count_by_type = defaultdict(int)
                
                for row in device_performances:
                    device_type = row[3] or 'unknown'
                    health_score = row[4]
                    
                    device_count_by_type[device_type] += 1
                    
                    if health_score is None:
                        device_count_by_status['unknown'] += 1
                    elif health_score >= 90:
                        device_count_by_status['excellent'] += 1
                    elif health_score >= 80:
                        device_count_by_status['good'] += 1
                    elif health_score >= 70:
                        device_count_by_status['fair'] += 1
                    elif health_score >= 60:
                        device_count_by_status['poor'] += 1
                    else:
                        device_count_by_status['critical'] += 1
                
                return {
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'period_hours': hours,
                    'network_health': {
                        'avg_health_score': round(statistics.mean(health_scores), 2) if health_scores else 0,
                        'avg_uptime_percentage': round(statistics.mean(uptime_percentages), 2) if uptime_percentages else 0,
                        'total_devices': len(device_performances),
                        'devices_with_data': len(health_scores)
                    },
                    'device_status_breakdown': dict(device_count_by_status),
                    'device_type_breakdown': dict(device_count_by_type),
                    'top_performers': [
                        {
                            'device_id': row[0],
                            'device_name': row[1],
                            'device_ip': row[2],
                            'device_type': row[3],
                            'health_score': row[4],
                            'uptime_percentage': row[8]
                        }
                        for row in device_performances[:10] if row[4] is not None
                    ]
                }
                
        except Exception as e:
            logger.error(f"Error getting network performance summary: {e}")
            return None
    
    def start_monitoring(self):
        """Start the continuous performance monitoring process"""
        self.is_running = True
        logger.info("Starting performance monitoring")
        
        # Cleanup old data on startup
        self.cleanup_old_performance_data()
        
        while not self._stop_event.is_set():
            try:
                # Collect performance metrics for all devices
                self.collect_all_devices_performance()
                
                # Clean up old data periodically (every 10 cycles)
                if hasattr(self, '_cleanup_counter'):
                    self._cleanup_counter += 1
                else:
                    self._cleanup_counter = 1
                
                if self._cleanup_counter >= 10:
                    self.cleanup_old_performance_data()
                    self._cleanup_counter = 0
                
                # Wait for next collection cycle
                collection_interval = int(self.get_config_value('performance_collection_interval', '300'))
                self._stop_event.wait(collection_interval)
                
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying
        
        self.is_running = False
        logger.info("Performance monitoring stopped")
    
    def stop_monitoring(self):
        """Stop the performance monitoring process"""
        logger.info("Stopping performance monitor")
        self._stop_event.set()
        self.is_running = False
    
    def reload_config(self):
        """Reload configuration for hot-reload support"""
        try:
            logger.info("Reloading PerformanceMonitor configuration")
            if self.app:
                with self.app.app_context():
                    collection_interval = self.get_config_value('performance_collection_interval', '300')
                    collection_period = self.get_config_value('performance_collection_period', '60')
                    retention_days = self.get_config_value('performance_retention_days', '30')
                    
                    logger.info(f"PerformanceMonitor config reloaded - "
                              f"collection_interval: {collection_interval}s, "
                              f"collection_period: {collection_period}min, "
                              f"retention: {retention_days} days")
        except Exception as e:
            logger.error(f"Error reloading PerformanceMonitor configuration: {e}")
    
    def _emit_device_performance_update(self, device, performance_record):
        """Emit device performance update via WebSocket"""
        try:
            if not self.socketio:
                return
                
            performance_data = {
                'device_id': device.id,
                'device_name': device.display_name,
                'device_ip': device.ip_address,
                'device_type': device.device_type,
                'performance_metrics': performance_record.to_dict(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.socketio.emit('performance_metrics_update', {
                'type': 'device_performance',
                'data': performance_data
            })
            
            logger.debug(f"Emitted performance update for {device.display_name}")
            
        except Exception as e:
            logger.error(f"Error emitting device performance update: {e}")
    
    def _emit_network_performance_summary(self):
        """Emit network-wide performance summary via WebSocket"""
        try:
            if not self.socketio:
                return
                
            # Get current network summary
            summary = self.get_network_performance_summary(1)  # Last hour
            
            if summary:
                self.socketio.emit('performance_metrics_update', {
                    'type': 'network_summary',
                    'data': summary
                })
                
                # Also emit specific chart updates
                self._emit_performance_chart_updates(summary)
                
                logger.debug("Emitted network performance summary update")
                
        except Exception as e:
            logger.error(f"Error emitting network performance summary: {e}")
    
    def _emit_performance_chart_updates(self, summary):
        """Emit specific chart data updates for real-time charts"""
        try:
            if not self.socketio or not summary:
                return
            
            # Health score distribution update
            device_status_breakdown = summary.get('device_status_breakdown', {})
            self.socketio.emit('chart_data_update', {
                'type': 'health_distribution',
                'data': {
                    'excellent': device_status_breakdown.get('excellent', 0),
                    'good': device_status_breakdown.get('good', 0),
                    'fair': device_status_breakdown.get('fair', 0),
                    'poor': device_status_breakdown.get('poor', 0),
                    'critical': device_status_breakdown.get('critical', 0)
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Network health trend update
            network_health = summary.get('network_health', {})
            self.socketio.emit('chart_data_update', {
                'type': 'health_trend',
                'data': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'health_score': network_health.get('avg_health_score', 0),
                    'uptime_percentage': network_health.get('avg_uptime_percentage', 0)
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Top performers update
            top_performers = summary.get('top_performers', [])
            self.socketio.emit('chart_data_update', {
                'type': 'top_performers',
                'data': top_performers[:10],  # Top 10 performers
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.debug("Emitted performance chart updates")
            
        except Exception as e:
            logger.error(f"Error emitting performance chart updates: {e}")
    
    def set_socketio(self, socketio):
        """Set the SocketIO instance for real-time updates"""
        self.socketio = socketio
    
    def _check_performance_alerts(self, device, performance_record):
        """Check performance metrics and generate alerts if thresholds are exceeded"""
        try:
            if not self.app:
                return
                
            with self.app.app_context():
                health_score = performance_record.health_score or 0
                responsiveness_score = performance_record.responsiveness_score or 0
                reliability_score = performance_record.reliability_score or 0
                
                # Get thresholds from configuration - dramatically less sensitive to reduce alert noise
                critical_threshold = float(self.get_config_value('performance_alert_critical_threshold', '15'))  # Only extremely poor performance
                warning_threshold = float(self.get_config_value('performance_alert_warning_threshold', '25'))   # Only significant issues
                recovery_threshold = float(self.get_config_value('performance_alert_recovery_threshold', '40'))  # Faster recovery
                
                # Check for critical health score alerts
                if health_score < critical_threshold:
                    if self._should_create_alert(device, 'performance_critical', health_score):
                        self._create_performance_alert(
                            device, 'performance_critical', 
                            f"Device performance is critically low: {health_score:.1f}% health score",
                            {
                                'health_score': health_score,
                                'responsiveness_score': responsiveness_score,
                                'reliability_score': reliability_score,
                                'threshold': critical_threshold
                            }
                        )
                
                # Check for warning health score alerts
                elif health_score < warning_threshold:
                    if self._should_create_alert(device, 'performance_warning', health_score):
                        self._create_performance_alert(
                            device, 'performance_warning',
                            f"Device performance is below normal: {health_score:.1f}% health score",
                            {
                                'health_score': health_score,
                                'responsiveness_score': responsiveness_score,
                                'reliability_score': reliability_score,
                                'threshold': warning_threshold
                            }
                        )
                
                # Check for recovery (resolve existing alerts if performance improved)
                elif health_score >= recovery_threshold:
                    self._resolve_performance_alerts(device, health_score)
                
                # Check component-specific alerts - dramatically less sensitive to reduce noise
                if responsiveness_score < 10:  # Only catastrophically poor responsiveness
                    if self._should_create_alert(device, 'performance_responsiveness', responsiveness_score):
                        self._create_performance_alert(
                            device, 'performance_responsiveness',
                            f"Device responsiveness is catastrophically poor: {responsiveness_score:.1f}% score",
                            {'responsiveness_score': responsiveness_score, 'threshold': 10}
                        )

                if reliability_score < 15:  # Only catastrophically poor reliability
                    if self._should_create_alert(device, 'performance_reliability', reliability_score):
                        self._create_performance_alert(
                            device, 'performance_reliability',
                            f"Device reliability is catastrophically poor: {reliability_score:.1f}% score",
                            {'reliability_score': reliability_score, 'threshold': 15}
                        )
                
        except Exception as e:
            logger.error(f"Error checking performance alerts for device {device.display_name}: {e}")
    
    def _should_create_alert(self, device, alert_subtype, current_value):
        """Check if we should create a new alert based on consecutive failures"""
        try:
            # Check if there's already an active alert of this type
            existing_alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type='performance',
                alert_subtype=alert_subtype,
                resolved=False
            ).first()
            
            if existing_alert:
                logger.debug(f"Performance alert already active for {device.display_name}: {alert_subtype}")
                return False
            
            # Check consecutive periods below threshold
            consecutive_periods = int(self.get_config_value('performance_alert_consecutive_periods', '2'))
            
            # Get recent performance records
            recent_cutoff = datetime.utcnow() - timedelta(hours=2)
            recent_records = PerformanceMetrics.query.filter(
                PerformanceMetrics.device_id == device.id,
                PerformanceMetrics.timestamp >= recent_cutoff
            ).order_by(PerformanceMetrics.timestamp.desc()).limit(consecutive_periods).all()
            
            if len(recent_records) < consecutive_periods:
                logger.debug(f"Not enough recent data for {device.display_name}: {len(recent_records)} < {consecutive_periods}")
                return False
            
            # Check if all recent records are below threshold - updated to match new thresholds
            threshold_map = {
                'performance_critical': float(self.get_config_value('performance_alert_critical_threshold', '15')),
                'performance_warning': float(self.get_config_value('performance_alert_warning_threshold', '25')),
                'performance_responsiveness': 10,
                'performance_reliability': 15
            }
            
            threshold = threshold_map.get(alert_subtype, 70)
            
            consecutive_below = 0
            for record in recent_records:
                if alert_subtype.endswith('_responsiveness'):
                    value = record.responsiveness_score or 0
                elif alert_subtype.endswith('_reliability'):
                    value = record.reliability_score or 0
                else:
                    value = record.health_score or 0
                
                if value < threshold:
                    consecutive_below += 1
                else:
                    break
            
            should_alert = consecutive_below >= consecutive_periods
            logger.debug(f"Alert check for {device.display_name} ({alert_subtype}): {consecutive_below}/{consecutive_periods} consecutive periods below {threshold}")
            
            return should_alert
            
        except Exception as e:
            logger.error(f"Error checking if should create alert: {e}")
            return False
    
    def _create_performance_alert(self, device, alert_subtype, message, details):
        """Create a new performance alert"""
        try:
            # Determine severity based on alert type
            severity_map = {
                'performance_critical': 'critical',
                'performance_warning': 'warning', 
                'performance_responsiveness': 'warning',
                'performance_reliability': 'warning'
            }
            
            severity = severity_map.get(alert_subtype, 'warning')
            
            # Create alert record
            alert = Alert(
                device_id=device.id,
                alert_type='performance',
                alert_subtype=alert_subtype,
                severity=severity,
                message=message,
                created_at=datetime.utcnow(),
                resolved=False,
                acknowledged=False
            )
            
            db.session.add(alert)
            db.session.commit()
            
            logger.warning(f"Performance alert created for {device.display_name}: {message}")
            
            # Emit real-time alert update if we have socketio
            if self.socketio:
                try:
                    alert_data = {
                        'id': alert.id,
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'device_ip': device.ip_address,
                        'alert_type': 'performance',
                        'alert_subtype': alert_subtype,
                        'severity': severity,
                        'message': message,
                        'details': details,
                        'created_at': alert.created_at.isoformat() + 'Z',
                        'acknowledged': False,
                        'resolved': False
                    }
                    
                    self.socketio.emit('alert_update', {
                        'type': 'alert_created',
                        'alert': alert_data,
                        'action': 'created',
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                    
                    # Also emit performance-specific alert
                    self.socketio.emit('performance_alert', {
                        'type': 'performance_alert_created',
                        'device': {
                            'id': device.id,
                            'name': device.display_name,
                            'ip': device.ip_address
                        },
                        'alert': alert_data,
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                    
                except Exception as e:
                    logger.error(f"Error emitting performance alert: {e}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Error creating performance alert: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
            return None
    
    def _resolve_performance_alerts(self, device, current_health_score):
        """Resolve existing performance alerts when performance improves"""
        try:
            if not self.app:
                return
                
            with self.app.app_context():
                # Find active performance alerts for this device
                active_alerts = Alert.query.filter_by(
                    device_id=device.id,
                    alert_type='performance',
                    resolved=False
                ).all()
                
                recovery_threshold = float(self.get_config_value('performance_alert_recovery_threshold', '40'))
                
                for alert in active_alerts:
                    should_resolve = False
                    
                    if alert.alert_subtype in ['performance_critical', 'performance_warning']:
                        # Resolve if health score is above recovery threshold
                        should_resolve = current_health_score >= recovery_threshold
                    elif alert.alert_subtype == 'performance_responsiveness':
                        # Get latest responsiveness score - faster recovery with new threshold
                        latest_record = PerformanceMetrics.query.filter_by(device_id=device.id)\
                            .order_by(PerformanceMetrics.timestamp.desc()).first()
                        should_resolve = latest_record and (latest_record.responsiveness_score or 0) >= 25
                    elif alert.alert_subtype == 'performance_reliability':
                        # Get latest reliability score - faster recovery with new threshold
                        latest_record = PerformanceMetrics.query.filter_by(device_id=device.id)\
                            .order_by(PerformanceMetrics.timestamp.desc()).first()
                        should_resolve = latest_record and (latest_record.reliability_score or 0) >= 30
                    
                    if should_resolve:
                        alert.resolved = True
                        alert.resolved_at = datetime.utcnow()
                        alert.resolution_message = f"Performance improved: Health score now {current_health_score:.1f}%"
                        
                        logger.info(f"Resolved performance alert for {device.display_name}: {alert.message}")
                        
                        # Emit resolution update
                        if self.socketio:
                            try:
                                self.socketio.emit('alert_update', {
                                    'type': 'alert_resolved',
                                    'alert': {
                                        'id': alert.id,
                                        'device_id': device.id,
                                        'device_name': device.display_name,
                                        'resolved': True,
                                        'resolution_message': alert.resolution_message
                                    },
                                    'action': 'resolved',
                                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                                })
                                
                                self.socketio.emit('performance_alert', {
                                    'type': 'performance_alert_resolved',
                                    'device': {
                                        'id': device.id,
                                        'name': device.display_name,
                                        'ip': device.ip_address
                                    },
                                    'alert_id': alert.id,
                                    'resolution_message': alert.resolution_message,
                                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                                })
                            except Exception as e:
                                logger.error(f"Error emitting alert resolution: {e}")
                
                db.session.commit()
                
        except Exception as e:
            logger.error(f"Error resolving performance alerts for device {device.display_name}: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
    
    def get_performance_alert_summary(self):
        """Get summary of current performance alerts"""
        try:
            if not self.app:
                return None
                
            with self.app.app_context():
                # Get active performance alerts
                active_alerts = Alert.query.filter_by(
                    alert_type='performance',
                    resolved=False
                ).all()
                
                alert_summary = {
                    'total_active': len(active_alerts),
                    'by_severity': {'critical': 0, 'warning': 0, 'info': 0},
                    'by_subtype': {},
                    'recent_alerts': []
                }
                
                for alert in active_alerts:
                    # Count by severity
                    alert_summary['by_severity'][alert.severity] += 1
                    
                    # Count by subtype
                    subtype = alert.alert_subtype or 'unknown'
                    alert_summary['by_subtype'][subtype] = alert_summary['by_subtype'].get(subtype, 0) + 1
                    
                    # Add to recent alerts (last 10)
                    if len(alert_summary['recent_alerts']) < 10:
                        alert_summary['recent_alerts'].append({
                            'id': alert.id,
                            'device_name': alert.device.display_name,
                            'device_ip': alert.device.ip_address,
                            'severity': alert.severity,
                            'message': alert.message,
                            'created_at': alert.created_at.isoformat() + 'Z',
                            'subtype': alert.alert_subtype
                        })
                
                return alert_summary
                
        except Exception as e:
            logger.error(f"Error getting performance alert summary: {e}")
            return None

# Create global instance
performance_monitor = PerformanceMonitor()