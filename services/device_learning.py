"""
Device Learning and Training System

This service implements machine learning training and continuous improvement for device classification:
1. Learn from user feedback and corrections
2. Train on historical behavior patterns
3. Continuously improve classification accuracy
4. Store and manage training data
5. Export/import device learning models
"""

import logging
import json
import statistics
import time
import threading
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from models import db, Device, MonitoringData, Configuration
from services.device_analytics import DeviceBehaviorAnalytics

logger = logging.getLogger(__name__)


class DeviceLearningSystem:
    """Machine learning system for device classification improvement"""
    
    def __init__(self, app=None):
        self.app = app
        self.device_analytics = DeviceBehaviorAnalytics()
        
        # Learning data storage
        self.training_data = {}
        self.user_feedback = {}
        self.classification_history = {}
        self.model_performance = {}
        
        # Learning configuration
        self.learning_rate = 0.1
        self.confidence_adjustment_rate = 0.05
        self.minimum_training_samples = 5
        self.feedback_weight = 0.8
        
        # Performance tracking
        self.accuracy_metrics = {
            'correct_predictions': 0,
            'total_predictions': 0,
            'user_corrections': 0,
            'learning_sessions': 0
        }
        
        self._last_training = datetime.utcnow()
        
    def record_user_feedback(self, device_id: int, predicted_type: str, actual_type: str, 
                           confidence: float, feedback_type: str = 'correction') -> Dict[str, Any]:
        """Record user feedback for improving classification"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                feedback_record = {
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'predicted_type': predicted_type,
                    'actual_type': actual_type,
                    'confidence': confidence,
                    'feedback_type': feedback_type,
                    'timestamp': datetime.utcnow().isoformat(),
                    'ip_address': device.ip_address,
                    'mac_address': device.mac_address,
                    'vendor': device.vendor,
                    'hostname': device.hostname
                }
                
                # Store feedback
                if device_id not in self.user_feedback:
                    self.user_feedback[device_id] = []
                self.user_feedback[device_id].append(feedback_record)
                
                # Update accuracy metrics
                if predicted_type == actual_type:
                    self.accuracy_metrics['correct_predictions'] += 1
                else:
                    self.accuracy_metrics['user_corrections'] += 1
                self.accuracy_metrics['total_predictions'] += 1
                
                # Trigger learning update if we have enough samples
                feedback_count = len(self.user_feedback[device_id])
                if feedback_count >= self.minimum_training_samples:
                    self._update_device_learning_model(device_id)
                
                logger.info(f"Recorded user feedback for device {device.display_name}: {predicted_type} -> {actual_type}")
                
                return {
                    'success': True,
                    'feedback_recorded': feedback_record,
                    'total_feedback_count': feedback_count,
                    'learning_triggered': feedback_count >= self.minimum_training_samples
                }
                
        except Exception as e:
            logger.error(f"Error recording user feedback: {e}")
            return {'error': str(e)}
    
    def _update_device_learning_model(self, device_id: int):
        """Update learning model based on accumulated feedback"""
        try:
            feedback_records = self.user_feedback.get(device_id, [])
            if not feedback_records:
                return
            
            # Analyze feedback patterns
            actual_types = [record['actual_type'] for record in feedback_records]
            most_common_actual = Counter(actual_types).most_common(1)[0][0]
            
            # Calculate learning adjustments
            prediction_accuracy = sum(1 for record in feedback_records 
                                    if record['predicted_type'] == record['actual_type']) / len(feedback_records)
            
            # Update classification rules for this device type
            device_characteristics = self._extract_device_characteristics(device_id, feedback_records)
            
            # Update training data
            if device_id not in self.training_data:
                self.training_data[device_id] = {
                    'learned_type': most_common_actual,
                    'confidence_adjustment': 0.0,
                    'characteristics': device_characteristics,
                    'accuracy_score': prediction_accuracy,
                    'sample_count': len(feedback_records),
                    'last_updated': datetime.utcnow().isoformat()
                }
            else:
                # Update existing training data
                training_record = self.training_data[device_id]
                training_record['learned_type'] = most_common_actual
                training_record['accuracy_score'] = prediction_accuracy
                training_record['sample_count'] = len(feedback_records)
                training_record['last_updated'] = datetime.utcnow().isoformat()
                
                # Adjust confidence based on accuracy
                if prediction_accuracy < 0.5:
                    training_record['confidence_adjustment'] -= self.confidence_adjustment_rate
                elif prediction_accuracy > 0.8:
                    training_record['confidence_adjustment'] += self.confidence_adjustment_rate
            
            self.accuracy_metrics['learning_sessions'] += 1
            logger.info(f"Updated learning model for device {device_id}: type={most_common_actual}, accuracy={prediction_accuracy:.2f}")
            
        except Exception as e:
            logger.error(f"Error updating device learning model: {e}")
    
    def _extract_device_characteristics(self, device_id: int, feedback_records: List[Dict]) -> Dict[str, Any]:
        """Extract device characteristics from feedback records"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {}
                
                # Get recent behavioral analysis
                behavior_analysis = self.device_analytics.analyze_device_behavior(device_id, days=30)
                
                characteristics = {
                    'vendor': device.vendor,
                    'hostname_pattern': self._categorize_hostname(device.hostname or ''),
                    'ip_pattern': self._categorize_ip_pattern(device.ip_address or ''),
                    'response_pattern': behavior_analysis.response_time_characteristics.get('pattern', 'unknown'),
                    'uptime_pattern': behavior_analysis.uptime_patterns.get('pattern_type', 'unknown'),
                    'feedback_consistency': self._calculate_feedback_consistency(feedback_records)
                }
                
                return characteristics
                
        except Exception as e:
            logger.error(f"Error extracting device characteristics: {e}")
            return {}
    
    def _categorize_hostname(self, hostname: str) -> str:
        """Categorize hostname patterns for learning"""
        hostname_lower = hostname.lower()
        
        if any(pattern in hostname_lower for pattern in ['android', 'samsung', 'pixel']):
            return 'mobile_android'
        elif any(pattern in hostname_lower for pattern in ['iphone', 'ipad', 'macbook', 'imac']):
            return 'apple_device'
        elif any(pattern in hostname_lower for pattern in ['windows', 'pc', 'desktop']):
            return 'windows_computer'
        elif any(pattern in hostname_lower for pattern in ['router', 'gateway', 'access']):
            return 'network_infrastructure'
        elif any(pattern in hostname_lower for pattern in ['camera', 'cam', 'ring']):
            return 'security_camera'
        elif any(pattern in hostname_lower for pattern in ['tv', 'roku', 'chromecast']):
            return 'media_device'
        else:
            return 'generic_named'
    
    def _categorize_ip_pattern(self, ip_address: str) -> str:
        """Categorize IP address patterns"""
        if not ip_address:
            return 'unknown'
        
        if ip_address.endswith('.1'):
            return 'gateway_router'
        elif ip_address.endswith(('.2', '.3', '.4', '.5')):
            return 'infrastructure_static'
        else:
            last_octet = int(ip_address.split('.')[-1])
            if last_octet > 200:
                return 'dhcp_high_range'
            elif last_octet > 100:
                return 'dhcp_mid_range'
            else:
                return 'static_assignment'
    
    def _calculate_feedback_consistency(self, feedback_records: List[Dict]) -> float:
        """Calculate consistency of user feedback"""
        if not feedback_records:
            return 0.0
        
        actual_types = [record['actual_type'] for record in feedback_records]
        most_common_count = Counter(actual_types).most_common(1)[0][1]
        
        return most_common_count / len(feedback_records)
    
    def get_learned_classification(self, device_id: int) -> Dict[str, Any]:
        """Get classification enhanced with learned data"""
        try:
            # Get base classification from analytics
            base_classification = self.device_analytics.classify_device(device_id, days=7)
            
            if 'error' in base_classification:
                return base_classification
            
            # Apply learning adjustments if available
            if device_id in self.training_data:
                training_data = self.training_data[device_id]
                learned_type = training_data['learned_type']
                confidence_adjustment = training_data['confidence_adjustment']
                accuracy_score = training_data['accuracy_score']
                
                # Adjust classification based on learning
                enhanced_classification = base_classification.copy()
                
                # If we have high-confidence learning data, use learned type
                if accuracy_score > 0.8 and training_data['sample_count'] >= self.minimum_training_samples:
                    enhanced_classification['device_type'] = learned_type
                    enhanced_classification['confidence'] = min(1.0, 
                        base_classification['confidence'] + confidence_adjustment + (accuracy_score * 0.2))
                    enhanced_classification['learning_applied'] = True
                    enhanced_classification['learning_source'] = 'user_feedback'
                else:
                    enhanced_classification['confidence'] = max(0.0, 
                        base_classification['confidence'] + confidence_adjustment)
                    enhanced_classification['learning_applied'] = True
                    enhanced_classification['learning_source'] = 'partial_feedback'
                
                enhanced_classification['training_samples'] = training_data['sample_count']
                enhanced_classification['learning_accuracy'] = accuracy_score
                
                return enhanced_classification
            else:
                # No learning data available, return base classification
                base_classification['learning_applied'] = False
                return base_classification
                
        except Exception as e:
            logger.error(f"Error getting learned classification: {e}")
            return {'error': str(e)}
    
    def train_on_historical_data(self, days: int = 30) -> Dict[str, Any]:
        """Train learning system on historical device behavior data"""
        try:
            with self.app.app_context():
                devices = Device.query.filter_by(is_monitored=True).all()
                
                training_results = {
                    'devices_processed': 0,
                    'patterns_learned': 0,
                    'errors': []
                }
                
                for device in devices:
                    try:
                        # Get historical monitoring data
                        cutoff = datetime.utcnow() - timedelta(days=days)
                        monitoring_data = MonitoringData.query.filter(
                            MonitoringData.device_id == device.id,
                            MonitoringData.timestamp >= cutoff
                        ).all()
                        
                        if len(monitoring_data) < 50:  # Need sufficient data
                            continue
                        
                        # Extract patterns for training
                        patterns = self._extract_historical_patterns(device, monitoring_data)
                        
                        # Store as training data if we don't have user feedback
                        if device.id not in self.user_feedback:
                            self.training_data[device.id] = {
                                'learned_type': device.device_type,
                                'confidence_adjustment': 0.0,
                                'characteristics': patterns,
                                'accuracy_score': 0.7,  # Default for historical training
                                'sample_count': len(monitoring_data),
                                'last_updated': datetime.utcnow().isoformat(),
                                'training_source': 'historical_data'
                            }
                            training_results['patterns_learned'] += 1
                        
                        training_results['devices_processed'] += 1
                        
                    except Exception as e:
                        error_msg = f"Error training on device {device.id}: {e}"
                        logger.error(error_msg)
                        training_results['errors'].append(error_msg)
                
                self._last_training = datetime.utcnow()
                
                logger.info(f"Historical training completed: {training_results['devices_processed']} devices, {training_results['patterns_learned']} patterns")
                
                return training_results
                
        except Exception as e:
            logger.error(f"Error in historical training: {e}")
            return {'error': str(e)}
    
    def _extract_historical_patterns(self, device: Device, monitoring_data: List) -> Dict[str, Any]:
        """Extract patterns from historical monitoring data"""
        response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
        
        patterns = {
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'response_consistency': 1.0 - (statistics.stdev(response_times) / statistics.mean(response_times)) 
                                   if len(response_times) > 1 and statistics.mean(response_times) > 0 else 0,
            'uptime_percentage': len(response_times) / len(monitoring_data) * 100,
            'data_point_count': len(monitoring_data),
            'vendor': device.vendor,
            'hostname_pattern': self._categorize_hostname(device.hostname or ''),
            'ip_pattern': self._categorize_ip_pattern(device.ip_address or '')
        }
        
        return patterns
    
    def export_learning_data(self) -> Dict[str, Any]:
        """Export learning data for backup or analysis"""
        try:
            export_data = {
                'training_data': self.training_data,
                'user_feedback': self.user_feedback,
                'accuracy_metrics': self.accuracy_metrics,
                'export_timestamp': datetime.utcnow().isoformat(),
                'learning_configuration': {
                    'learning_rate': self.learning_rate,
                    'confidence_adjustment_rate': self.confidence_adjustment_rate,
                    'minimum_training_samples': self.minimum_training_samples,
                    'feedback_weight': self.feedback_weight
                }
            }
            
            return export_data
            
        except Exception as e:
            logger.error(f"Error exporting learning data: {e}")
            return {'error': str(e)}
    
    def import_learning_data(self, import_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import learning data from backup"""
        try:
            if 'training_data' in import_data:
                self.training_data.update(import_data['training_data'])
            
            if 'user_feedback' in import_data:
                for device_id, feedback_list in import_data['user_feedback'].items():
                    if device_id not in self.user_feedback:
                        self.user_feedback[device_id] = []
                    self.user_feedback[device_id].extend(feedback_list)
            
            if 'accuracy_metrics' in import_data:
                for key, value in import_data['accuracy_metrics'].items():
                    self.accuracy_metrics[key] += value
            
            result = {
                'success': True,
                'imported_training_records': len(import_data.get('training_data', {})),
                'imported_feedback_records': sum(len(feedback) for feedback in import_data.get('user_feedback', {}).values()),
                'import_timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Learning data imported successfully: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error importing learning data: {e}")
            return {'error': str(e)}
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning system statistics"""
        try:
            total_training_records = len(self.training_data)
            total_feedback_records = sum(len(feedback) for feedback in self.user_feedback.values())
            
            # Calculate accuracy statistics
            accuracy_rate = (self.accuracy_metrics['correct_predictions'] / 
                           self.accuracy_metrics['total_predictions'] * 100) if self.accuracy_metrics['total_predictions'] > 0 else 0
            
            correction_rate = (self.accuracy_metrics['user_corrections'] / 
                             self.accuracy_metrics['total_predictions'] * 100) if self.accuracy_metrics['total_predictions'] > 0 else 0
            
            # Analyze device type distribution in training data
            device_type_distribution = Counter()
            for training_record in self.training_data.values():
                device_type_distribution[training_record.get('learned_type', 'unknown')] += 1
            
            # Analyze learning coverage
            with self.app.app_context():
                total_monitored_devices = Device.query.filter_by(is_monitored=True).count()
                learning_coverage = (total_training_records / total_monitored_devices * 100) if total_monitored_devices > 0 else 0
            
            return {
                'learning_summary': {
                    'total_training_records': total_training_records,
                    'total_feedback_records': total_feedback_records,
                    'learning_coverage_percentage': round(learning_coverage, 1),
                    'accuracy_rate_percentage': round(accuracy_rate, 1),
                    'correction_rate_percentage': round(correction_rate, 1)
                },
                'performance_metrics': self.accuracy_metrics,
                'device_type_distribution': dict(device_type_distribution),
                'learning_configuration': {
                    'learning_rate': self.learning_rate,
                    'confidence_adjustment_rate': self.confidence_adjustment_rate,
                    'minimum_training_samples': self.minimum_training_samples,
                    'feedback_weight': self.feedback_weight
                },
                'last_training_session': self._last_training.isoformat(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting learning statistics: {e}")
            return {'error': str(e)}
    
    def start_continuous_learning(self):
        """Start background continuous learning process"""
        def learning_loop():
            while True:
                try:
                    # Run training on historical data every 24 hours
                    if (datetime.utcnow() - self._last_training).total_seconds() > 86400:
                        logger.info("Starting scheduled historical data training")
                        self.train_on_historical_data(days=7)
                    
                    time.sleep(3600)  # Check every hour
                    
                except Exception as e:
                    logger.error(f"Error in continuous learning loop: {e}")
                    time.sleep(3600)
        
        learning_thread = threading.Thread(target=learning_loop, daemon=True, name='DeviceLearning')
        learning_thread.start()
        logger.info("Device learning system continuous training started")


# Global learning system instance
device_learning_system = DeviceLearningSystem()