"""
Unit tests for the PerformanceMetrics model.

Tests cover:
- Model creation and validation
- Health score calculations and algorithm
- Performance grade derivation
- Performance status determination
- Relationships with other models
- Business logic methods
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from models import PerformanceMetrics, Device
from tests.fixtures.factories import (
    PerformanceMetricsFactory, ExcellentPerformanceMetricsFactory,
    PoorPerformanceMetricsFactory, DeviceFactory
)
from tests.fixtures.utils import (
    assert_performance_metrics_properties, PerformanceTestHelper
)


class TestPerformanceMetricsModel:
    """Test the PerformanceMetrics model basic functionality."""
    
    def test_performance_metrics_creation(self, db_session):
        """Test creating performance metrics with all attributes."""
        device = DeviceFactory.create()
        
        metrics_data = {
            'device_id': device.id,
            'health_score': 85.5,
            'responsiveness_score': 88.2,
            'reliability_score': 95.0,
            'efficiency_score': 75.8,
            'avg_response_time': 25.0,
            'min_response_time': 12.5,
            'max_response_time': 50.0,
            'response_time_std_dev': 8.2,
            'uptime_percentage': 98.5,
            'total_checks': 100,
            'successful_checks': 98,
            'failed_checks': 2,
            'avg_bandwidth_in_mbps': 45.2,
            'avg_bandwidth_out_mbps': 12.8,
            'peak_bandwidth_in_mbps': 89.5,
            'peak_bandwidth_out_mbps': 25.6,
            'jitter_ms': 3.2,
            'packet_loss_percentage': 1.5,
            'connection_stability_score': 92.0,
            'collection_period_minutes': 60,
            'sample_count': 50,
            'anomaly_count': 2
        }
        
        metrics = PerformanceMetrics(**metrics_data)
        db_session.add(metrics)
        db_session.commit()
        
        # Verify metrics were created with correct attributes
        assert metrics.id is not None
        assert metrics.device_id == device.id
        assert metrics.health_score == 85.5
        assert metrics.responsiveness_score == 88.2
        assert metrics.reliability_score == 95.0
        assert metrics.efficiency_score == 75.8
        assert metrics.avg_response_time == 25.0
        assert metrics.uptime_percentage == 98.5
        assert metrics.collection_period_minutes == 60
        assert metrics.timestamp is not None

    def test_performance_metrics_creation_minimal(self, db_session):
        """Test creating performance metrics with only required attributes."""
        device = DeviceFactory.create()
        
        metrics = PerformanceMetrics(
            device_id=device.id,
            health_score=75.0
        )
        db_session.add(metrics)
        db_session.commit()
        
        assert metrics.id is not None
        assert metrics.device_id == device.id
        assert metrics.health_score == 75.0
        assert metrics.timestamp is not None

    def test_performance_metrics_repr(self, db_session):
        """Test the string representation of performance metrics."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        metrics = PerformanceMetricsFactory.create(device=device)
        
        repr_str = repr(metrics)
        assert '192.168.1.100' in repr_str
        assert str(metrics.timestamp) in repr_str or 'PerformanceMetrics' in repr_str


class TestHealthScoreCalculations:
    """Test PerformanceMetrics health score calculation algorithms."""
    
    def test_calculate_health_score_excellent_performance(self, db_session):
        """Test health score calculation with excellent metrics."""
        response_metrics = {
            'avg_ms': 8.0,
            'min_ms': 5.0,
            'max_ms': 15.0,
            'std_dev_ms': 2.5
        }
        availability_metrics = {
            'uptime_percentage': 99.8,
            'total_checks': 100,
            'successful_checks': 99,
            'failed_checks': 1
        }
        bandwidth_metrics = {
            'avg_in_mbps': 25.0,
            'avg_out_mbps': 10.0,
            'peak_in_mbps': 50.0,
            'peak_out_mbps': 20.0
        }
        quality_metrics = {
            'jitter_ms': 1.5,
            'packet_loss_percentage': 0.2,
            'stability_score': 98.0
        }
        
        health_score = PerformanceMetrics.calculate_health_score(
            response_metrics, availability_metrics, 
            bandwidth_metrics, quality_metrics
        )
        
        # Should be a high score for excellent performance
        PerformanceTestHelper.assert_health_score_range(health_score, 90, 100)
    
    def test_calculate_health_score_poor_performance(self, db_session):
        """Test health score calculation with poor metrics."""
        response_metrics = {
            'avg_ms': 800.0,  # Very high response time
            'min_ms': 500.0,
            'max_ms': 1200.0,
            'std_dev_ms': 150.0
        }
        availability_metrics = {
            'uptime_percentage': 75.0,  # Poor uptime
            'total_checks': 100,
            'successful_checks': 75,
            'failed_checks': 25
        }
        bandwidth_metrics = {
            'avg_in_mbps': 200.0,  # High bandwidth (may be inefficient)
            'avg_out_mbps': 80.0,
            'peak_in_mbps': 400.0,
            'peak_out_mbps': 160.0
        }
        quality_metrics = {
            'jitter_ms': 25.0,  # High jitter
            'packet_loss_percentage': 8.0,  # High packet loss
            'stability_score': 60.0  # Poor stability
        }
        
        health_score = PerformanceMetrics.calculate_health_score(
            response_metrics, availability_metrics,
            bandwidth_metrics, quality_metrics
        )
        
        # Should be a low score for poor performance
        PerformanceTestHelper.assert_health_score_range(health_score, 0, 50)
    
    def test_calculate_health_score_average_performance(self, db_session):
        """Test health score calculation with average metrics."""
        response_metrics = {
            'avg_ms': 45.0,  # Moderate response time
            'min_ms': 25.0,
            'max_ms': 80.0,
            'std_dev_ms': 12.0
        }
        availability_metrics = {
            'uptime_percentage': 92.5,  # Good uptime
            'total_checks': 100,
            'successful_checks': 92,
            'failed_checks': 8
        }
        bandwidth_metrics = {
            'avg_in_mbps': 50.0,
            'avg_out_mbps': 20.0,
            'peak_in_mbps': 100.0,
            'peak_out_mbps': 40.0
        }
        quality_metrics = {
            'jitter_ms': 8.0,
            'packet_loss_percentage': 3.0,
            'stability_score': 85.0
        }
        
        health_score = PerformanceMetrics.calculate_health_score(
            response_metrics, availability_metrics,
            bandwidth_metrics, quality_metrics
        )
        
        # Should be a moderate score
        PerformanceTestHelper.assert_health_score_range(health_score, 60, 90)
    
    def test_calculate_health_score_missing_data(self, db_session):
        """Test health score calculation with missing or None data."""
        response_metrics = {}
        availability_metrics = {'uptime_percentage': 95.0}
        bandwidth_metrics = {}
        quality_metrics = {}
        
        health_score = PerformanceMetrics.calculate_health_score(
            response_metrics, availability_metrics,
            bandwidth_metrics, quality_metrics
        )
        
        # Should handle missing data gracefully
        PerformanceTestHelper.assert_health_score_range(health_score)


class TestPerformanceGrade:
    """Test PerformanceMetrics performance grade calculations."""
    
    def test_performance_grade_a_plus(self, db_session):
        """Test performance grade A+ for excellent health score."""
        metrics = PerformanceMetricsFactory.create(health_score=97.5)
        
        grade = metrics.performance_grade()
        assert grade == 'A+'
        PerformanceTestHelper.assert_performance_grade(grade)
    
    def test_performance_grade_a(self, db_session):
        """Test performance grade A for high health score."""
        metrics = PerformanceMetricsFactory.create(health_score=92.0)
        
        grade = metrics.performance_grade()
        assert grade == 'A'
        PerformanceTestHelper.assert_performance_grade(grade)
    
    def test_performance_grade_b_plus(self, db_session):
        """Test performance grade B+ for good health score."""
        metrics = PerformanceMetricsFactory.create(health_score=87.0)
        
        grade = metrics.performance_grade()
        assert grade == 'B+'
        PerformanceTestHelper.assert_performance_grade(grade)
    
    def test_performance_grade_b(self, db_session):
        """Test performance grade B for decent health score."""
        metrics = PerformanceMetricsFactory.create(health_score=82.0)
        
        grade = metrics.performance_grade()
        assert grade == 'B'
        PerformanceTestHelper.assert_performance_grade(grade)
    
    def test_performance_grade_c_range(self, db_session):
        """Test performance grades in C range."""
        # C+ grade
        metrics_c_plus = PerformanceMetricsFactory.create(health_score=77.0)
        assert metrics_c_plus.performance_grade() == 'C+'
        
        # C grade
        metrics_c = PerformanceMetricsFactory.create(health_score=72.0)
        assert metrics_c.performance_grade() == 'C'
    
    def test_performance_grade_d_range(self, db_session):
        """Test performance grades in D range."""
        # D+ grade
        metrics_d_plus = PerformanceMetricsFactory.create(health_score=67.0)
        assert metrics_d_plus.performance_grade() == 'D+'
        
        # D grade
        metrics_d = PerformanceMetricsFactory.create(health_score=62.0)
        assert metrics_d.performance_grade() == 'D'
    
    def test_performance_grade_f(self, db_session):
        """Test performance grade F for poor health score."""
        metrics = PerformanceMetricsFactory.create(health_score=45.0)
        
        grade = metrics.performance_grade()
        assert grade == 'F'
        PerformanceTestHelper.assert_performance_grade(grade)
    
    def test_performance_grade_none_health_score(self, db_session):
        """Test performance grade when health score is None."""
        metrics = PerformanceMetricsFactory.create(health_score=None)
        
        grade = metrics.performance_grade()
        assert grade == 'N/A'
        PerformanceTestHelper.assert_performance_grade(grade)


class TestPerformanceStatus:
    """Test PerformanceMetrics performance status calculations."""
    
    def test_performance_status_excellent(self, db_session):
        """Test performance status for excellent health score."""
        metrics = ExcellentPerformanceMetricsFactory.create()
        
        status = metrics.performance_status
        assert status == 'excellent'
    
    def test_performance_status_good(self, db_session):
        """Test performance status for good health score."""
        metrics = PerformanceMetricsFactory.create(health_score=85.0)
        
        status = metrics.performance_status
        assert status == 'good'
    
    def test_performance_status_fair(self, db_session):
        """Test performance status for fair health score."""
        metrics = PerformanceMetricsFactory.create(health_score=75.0)
        
        status = metrics.performance_status
        assert status == 'fair'
    
    def test_performance_status_poor(self, db_session):
        """Test performance status for poor health score."""
        metrics = PoorPerformanceMetricsFactory.create()
        
        status = metrics.performance_status
        assert status == 'poor'
    
    def test_performance_status_unknown(self, db_session):
        """Test performance status when health score is None."""
        metrics = PerformanceMetricsFactory.create(health_score=None)
        
        status = metrics.performance_status
        assert status == 'unknown'


class TestPerformanceMetricsRelationships:
    """Test PerformanceMetrics model relationships."""
    
    def test_device_relationship(self, db_session):
        """Test relationship between PerformanceMetrics and Device."""
        device = DeviceFactory.create()
        metrics = PerformanceMetricsFactory.create(device=device)
        
        # Test relationship works both ways
        assert metrics.device == device
        assert metrics in device.performance_metrics
    
    def test_cascade_delete_from_device(self, db_session):
        """Test that deleting a device cascades to performance metrics."""
        device = DeviceFactory.create()
        metrics = PerformanceMetricsFactory.create(device=device)
        
        metrics_id = metrics.id
        
        # Delete the device
        db_session.delete(device)
        db_session.commit()
        
        # Performance metrics should be deleted too
        deleted_metrics = db_session.query(PerformanceMetrics).filter_by(id=metrics_id).first()
        assert deleted_metrics is None


class TestPerformanceMetricsMethods:
    """Test PerformanceMetrics model business logic methods."""
    
    def test_to_dict_method(self, db_session):
        """Test the to_dict method for API serialization."""
        device = DeviceFactory.create(
            ip_address='192.168.1.100',
            hostname='test-device'
        )
        metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=85.5,
            avg_response_time=25.0
        )
        
        metrics_dict = metrics.to_dict()
        
        assert isinstance(metrics_dict, dict)
        assert metrics_dict['id'] == metrics.id
        assert metrics_dict['device_id'] == device.id
        assert metrics_dict['device_name'] == device.display_name
        assert metrics_dict['device_ip'] == '192.168.1.100'
        assert 'timestamp' in metrics_dict
        
        # Check response time metrics
        response_metrics = metrics_dict['response_time_metrics']
        assert response_metrics['avg_ms'] == 25.0
        assert 'min_ms' in response_metrics
        assert 'max_ms' in response_metrics
        
        # Check availability metrics
        availability_metrics = metrics_dict['availability_metrics']
        assert 'uptime_percentage' in availability_metrics
        assert 'total_checks' in availability_metrics
        
        # Check bandwidth metrics
        bandwidth_metrics = metrics_dict['bandwidth_metrics']
        assert 'avg_in_mbps' in bandwidth_metrics
        assert 'avg_out_mbps' in bandwidth_metrics
        
        # Check quality metrics
        quality_metrics = metrics_dict['quality_metrics']
        assert 'jitter_ms' in quality_metrics
        assert 'packet_loss_percentage' in quality_metrics
        
        # Check health scores
        health_scores = metrics_dict['health_scores']
        assert health_scores['overall'] == 85.5
        assert 'responsiveness' in health_scores
        assert 'reliability' in health_scores
    
    def test_is_anomalous_method(self, db_session):
        """Test the is_anomalous method for detecting anomalies."""
        # Normal metrics (should not be anomalous)
        normal_metrics = PerformanceMetricsFactory.create(
            health_score=85.0,
            anomaly_count=1
        )
        assert normal_metrics.is_anomalous() is False
        
        # Metrics with high anomaly count
        anomalous_metrics = PerformanceMetricsFactory.create(
            health_score=85.0,
            anomaly_count=8
        )
        assert anomalous_metrics.is_anomalous() is True
        
        # Low health score metrics
        low_health_metrics = PerformanceMetricsFactory.create(
            health_score=45.0,
            anomaly_count=2
        )
        assert low_health_metrics.is_anomalous() is True
    
    def test_get_trend_direction(self, db_session):
        """Test getting performance trend direction."""
        device = DeviceFactory.create()
        
        # Create earlier metrics with lower health score
        earlier_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=75.0,
            timestamp=datetime.utcnow() - timedelta(hours=2)
        )
        
        # Create current metrics with higher health score
        current_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=85.0,
            timestamp=datetime.utcnow()
        )
        
        trend = current_metrics.get_trend_direction()
        assert trend == 'improving'
        
        # Test declining trend
        declining_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=65.0,
            timestamp=datetime.utcnow() + timedelta(hours=1)
        )
        
        trend = declining_metrics.get_trend_direction()
        assert trend == 'declining'


class TestPerformanceMetricsFactories:
    """Test the PerformanceMetrics factory classes."""
    
    def test_performance_metrics_factory(self, db_session):
        """Test the basic PerformanceMetricsFactory."""
        metrics = PerformanceMetricsFactory.create()
        assert_performance_metrics_properties(metrics)
        PerformanceTestHelper.assert_health_score_range(metrics.health_score)
    
    def test_excellent_performance_metrics_factory(self, db_session):
        """Test the ExcellentPerformanceMetricsFactory."""
        metrics = ExcellentPerformanceMetricsFactory.create()
        assert_performance_metrics_properties(metrics)
        
        # Should have excellent scores
        PerformanceTestHelper.assert_health_score_range(metrics.health_score, 90, 100)
        assert metrics.uptime_percentage >= 99.0
        assert metrics.avg_response_time <= 20.0
    
    def test_poor_performance_metrics_factory(self, db_session):
        """Test the PoorPerformanceMetricsFactory."""
        metrics = PoorPerformanceMetricsFactory.create()
        assert_performance_metrics_properties(metrics)
        
        # Should have poor scores
        PerformanceTestHelper.assert_health_score_range(metrics.health_score, 30, 60)
        assert metrics.uptime_percentage <= 90.0
        assert metrics.avg_response_time >= 100.0


class TestPerformanceMetricsValidation:
    """Test PerformanceMetrics model validation and constraints."""
    
    def test_health_score_bounds(self, db_session):
        """Test that health scores are within valid bounds."""
        # Valid health score
        valid_metrics = PerformanceMetricsFactory.create(health_score=85.0)
        assert 0 <= valid_metrics.health_score <= 100
        
        # Edge cases
        min_metrics = PerformanceMetricsFactory.create(health_score=0.0)
        assert min_metrics.health_score == 0.0
        
        max_metrics = PerformanceMetricsFactory.create(health_score=100.0)
        assert max_metrics.health_score == 100.0
    
    def test_uptime_percentage_bounds(self, db_session):
        """Test that uptime percentage is within valid bounds."""
        metrics = PerformanceMetricsFactory.create(uptime_percentage=95.5)
        assert 0 <= metrics.uptime_percentage <= 100
    
    def test_response_time_positive(self, db_session):
        """Test that response times are positive values."""
        metrics = PerformanceMetricsFactory.create(
            avg_response_time=25.0,
            min_response_time=10.0,
            max_response_time=50.0
        )
        
        assert metrics.avg_response_time >= 0
        assert metrics.min_response_time >= 0
        assert metrics.max_response_time >= 0
    
    def test_check_counts_consistency(self, db_session):
        """Test that check counts are consistent."""
        metrics = PerformanceMetricsFactory.create(
            total_checks=100,
            successful_checks=95,
            failed_checks=5
        )
        
        assert metrics.total_checks == metrics.successful_checks + metrics.failed_checks
        assert metrics.successful_checks >= 0
        assert metrics.failed_checks >= 0


class TestPerformanceMetricsComparisons:
    """Test PerformanceMetrics comparison and analysis methods."""
    
    def test_compare_with_previous(self, db_session):
        """Test comparing performance metrics with previous period."""
        device = DeviceFactory.create()
        
        # Previous metrics
        previous_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=75.0,
            avg_response_time=50.0,
            timestamp=datetime.utcnow() - timedelta(hours=2)
        )
        
        # Current metrics
        current_metrics = PerformanceMetricsFactory.create(
            device=device,
            health_score=85.0,
            avg_response_time=30.0,
            timestamp=datetime.utcnow()
        )
        
        comparison = current_metrics.compare_with_previous()
        
        assert isinstance(comparison, dict)
        assert 'health_score_change' in comparison
        assert 'response_time_change' in comparison
        assert comparison['health_score_change'] > 0  # Improved
        assert comparison['response_time_change'] < 0  # Faster (improvement)
    
    def test_get_performance_summary(self, db_session):
        """Test getting performance summary."""
        metrics = ExcellentPerformanceMetricsFactory.create()
        
        summary = metrics.get_performance_summary()
        
        assert isinstance(summary, dict)
        assert 'overall_grade' in summary
        assert 'overall_status' in summary
        assert 'key_metrics' in summary
        assert 'recommendations' in summary
        
        # Should have excellent grade and status
        assert summary['overall_grade'] in ['A+', 'A']
        assert summary['overall_status'] == 'excellent'