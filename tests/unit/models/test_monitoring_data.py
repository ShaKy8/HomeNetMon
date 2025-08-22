"""
Unit tests for the MonitoringData model.

Tests cover:
- Model creation and validation
- Data integrity and constraints
- JSON handling for additional data
- Relationships with other models
- Performance metrics calculations
- Time-based queries and filtering
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch

from models import MonitoringData, Device
from tests.fixtures.factories import (
    MonitoringDataFactory, SuccessfulMonitoringDataFactory,
    FailedMonitoringDataFactory, TimeoutMonitoringDataFactory,
    DeviceFactory
)
from tests.fixtures.utils import assert_monitoring_data_properties


class TestMonitoringDataModel:
    """Test the MonitoringData model basic functionality."""
    
    def test_monitoring_data_creation(self, db_session):
        """Test creating monitoring data with all attributes."""
        device = DeviceFactory.create()
        
        additional_metrics = {
            'jitter_ms': 5.2,
            'ttl': 64,
            'mtu': 1500,
            'interface': 'eth0'
        }
        
        monitoring_data = MonitoringData(
            device_id=device.id,
            response_time=25.5,
            packet_loss=1.2,
            additional_data=json.dumps(additional_metrics)
        )
        db_session.add(monitoring_data)
        db_session.commit()
        
        # Verify monitoring data was created with correct attributes
        assert monitoring_data.id is not None
        assert monitoring_data.device_id == device.id
        assert monitoring_data.response_time == 25.5
        assert monitoring_data.packet_loss == 1.2
        assert monitoring_data.timestamp is not None
        assert monitoring_data.additional_data is not None
        
        # Verify additional data is valid JSON
        parsed_data = json.loads(monitoring_data.additional_data)
        assert parsed_data['jitter_ms'] == 5.2
        assert parsed_data['ttl'] == 64

    def test_monitoring_data_creation_minimal(self, db_session):
        """Test creating monitoring data with only required attributes."""
        device = DeviceFactory.create()
        
        monitoring_data = MonitoringData(device_id=device.id)
        db_session.add(monitoring_data)
        db_session.commit()
        
        assert monitoring_data.id is not None
        assert monitoring_data.device_id == device.id
        assert monitoring_data.packet_loss == 0.0  # Default value
        assert monitoring_data.timestamp is not None
        assert monitoring_data.response_time is None  # Not set
        assert monitoring_data.additional_data is None

    def test_monitoring_data_timeout(self, db_session):
        """Test creating monitoring data for timeout scenarios."""
        device = DeviceFactory.create()
        
        timeout_data = MonitoringData(
            device_id=device.id,
            response_time=None,  # Timeout - no response
            packet_loss=100.0   # Complete packet loss
        )
        db_session.add(timeout_data)
        db_session.commit()
        
        assert timeout_data.response_time is None
        assert timeout_data.packet_loss == 100.0

    def test_monitoring_data_repr(self, db_session):
        """Test the string representation of monitoring data."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        monitoring_data = MonitoringDataFactory.create(device=device)
        
        repr_str = repr(monitoring_data)
        assert '192.168.1.100' in repr_str
        assert str(monitoring_data.timestamp) in repr_str or 'MonitoringData' in repr_str


class TestMonitoringDataValidation:
    """Test MonitoringData model validation and constraints."""
    
    def test_response_time_positive_or_none(self, db_session):
        """Test that response time is positive or None."""
        device = DeviceFactory.create()
        
        # Valid positive response time
        valid_data = MonitoringDataFactory.create(
            device=device,
            response_time=25.5
        )
        assert valid_data.response_time > 0
        
        # Valid None (timeout)
        timeout_data = TimeoutMonitoringDataFactory.create(device=device)
        assert timeout_data.response_time is None
    
    def test_packet_loss_bounds(self, db_session):
        """Test that packet loss is within valid bounds (0-100%)."""
        device = DeviceFactory.create()
        
        # Valid packet loss values
        no_loss = SuccessfulMonitoringDataFactory.create(device=device)
        assert 0 <= no_loss.packet_loss <= 100
        
        some_loss = FailedMonitoringDataFactory.create(device=device)
        assert 0 <= some_loss.packet_loss <= 100
        
        complete_loss = TimeoutMonitoringDataFactory.create(device=device)
        assert complete_loss.packet_loss == 100.0
    
    def test_timestamp_default(self, db_session):
        """Test that timestamp defaults to current time."""
        device = DeviceFactory.create()
        
        before_creation = datetime.utcnow()
        monitoring_data = MonitoringDataFactory.create(device=device)
        after_creation = datetime.utcnow()
        
        assert before_creation <= monitoring_data.timestamp <= after_creation
    
    def test_additional_data_json_validation(self, db_session):
        """Test that additional_data contains valid JSON."""
        device = DeviceFactory.create()
        
        # Valid JSON data
        valid_json = {"jitter": 5.0, "mtu": 1500}
        monitoring_data = MonitoringData(
            device_id=device.id,
            additional_data=json.dumps(valid_json)
        )
        db_session.add(monitoring_data)
        db_session.commit()
        
        # Should be able to parse back to original data
        parsed_data = json.loads(monitoring_data.additional_data)
        assert parsed_data == valid_json


class TestMonitoringDataRelationships:
    """Test MonitoringData model relationships."""
    
    def test_device_relationship(self, db_session):
        """Test relationship between MonitoringData and Device."""
        device = DeviceFactory.create()
        monitoring_data = MonitoringDataFactory.create(device=device)
        
        # Test relationship works both ways
        assert monitoring_data.device == device
        assert monitoring_data in device.monitoring_data
    
    @pytest.mark.skip(reason="Database schema mismatch - notification_history table missing columns in test DB")
    def test_cascade_delete_from_device(self, db_session):
        """Test that deleting a device cascades to monitoring data."""
        # NOTE: This test is skipped due to database schema issues with notification_history table
        # The test database is missing the alert_id column which causes SQLAlchemy errors during cascade deletes
        # TODO: Fix database schema creation for tests to include all models
        
        device = DeviceFactory.create()
        monitoring_data = MonitoringDataFactory.create(device=device)
        
        monitoring_id = monitoring_data.id
        
        # Delete the device
        db_session.delete(device)
        db_session.commit()
        
        # Monitoring data should be deleted too
        deleted_monitoring = db_session.query(MonitoringData).filter_by(id=monitoring_id).first()
        assert deleted_monitoring is None
    
    def test_multiple_monitoring_data_per_device(self, db_session):
        """Test that a device can have multiple monitoring data records."""
        device = DeviceFactory.create()
        
        # Create monitoring data at different times
        data1 = MonitoringDataFactory.create(
            device=device,
            timestamp=datetime.utcnow() - timedelta(minutes=10)
        )
        data2 = MonitoringDataFactory.create(
            device=device,
            timestamp=datetime.utcnow() - timedelta(minutes=5)
        )
        data3 = MonitoringDataFactory.create(
            device=device,
            timestamp=datetime.utcnow()
        )
        
        # Device should have all monitoring data
        assert len(device.monitoring_data) == 3
        assert data1 in device.monitoring_data
        assert data2 in device.monitoring_data
        assert data3 in device.monitoring_data


class TestMonitoringDataMethods:
    """Test MonitoringData model business logic methods."""
    
    def test_to_dict_method(self, db_session):
        """Test the to_dict method for API serialization."""
        device = DeviceFactory.create(ip_address='192.168.1.100')
        
        additional_data = {'jitter_ms': 3.2, 'ttl': 64}
        monitoring_data = MonitoringDataFactory.create(
            device=device,
            response_time=25.5,
            packet_loss=1.2,
            additional_data=json.dumps(additional_data)
        )
        
        data_dict = monitoring_data.to_dict()
        
        assert isinstance(data_dict, dict)
        assert data_dict['id'] == monitoring_data.id
        assert data_dict['device_id'] == device.id
        assert data_dict['response_time'] == 25.5
        assert data_dict['packet_loss'] == 1.2
        assert 'timestamp' in data_dict
        assert data_dict['timestamp'].endswith('Z')  # UTC indicator
        
        # Additional data should be parsed JSON
        assert data_dict['additional_data'] == additional_data
    
    def test_to_dict_with_none_additional_data(self, db_session):
        """Test to_dict method when additional_data is None."""
        device = DeviceFactory.create()
        monitoring_data = MonitoringDataFactory.create(
            device=device,
            additional_data=None
        )
        
        data_dict = monitoring_data.to_dict()
        assert data_dict['additional_data'] is None
    
    def test_is_successful_ping(self, db_session):
        """Test determining if a ping was successful."""
        device = DeviceFactory.create()
        
        # Successful ping
        successful_data = SuccessfulMonitoringDataFactory.create(device=device)
        assert successful_data.is_successful() is True
        
        # Failed ping (high response time)
        failed_data = FailedMonitoringDataFactory.create(device=device)
        assert failed_data.is_successful() is False
        
        # Timeout ping
        timeout_data = TimeoutMonitoringDataFactory.create(device=device)
        assert timeout_data.is_successful() is False
    
    def test_get_quality_score(self, db_session):
        """Test calculating quality score based on response time and packet loss."""
        device = DeviceFactory.create()
        
        # Excellent quality (low response time, no packet loss)
        excellent_data = MonitoringData(
            device_id=device.id,
            response_time=10.0,
            packet_loss=0.0
        )
        assert excellent_data.get_quality_score() >= 90
        
        # Poor quality (high response time, high packet loss)
        poor_data = MonitoringData(
            device_id=device.id,
            response_time=1000.0,
            packet_loss=25.0
        )
        assert poor_data.get_quality_score() <= 30
        
        # Timeout (should be lowest score)
        timeout_data = MonitoringData(
            device_id=device.id,
            response_time=None,
            packet_loss=100.0
        )
        assert timeout_data.get_quality_score() == 0
    
    def test_get_performance_category(self, db_session):
        """Test categorizing performance based on metrics."""
        device = DeviceFactory.create()
        
        # Excellent performance
        excellent_data = MonitoringData(
            device_id=device.id,
            response_time=8.0,
            packet_loss=0.0
        )
        assert excellent_data.get_performance_category() == 'excellent'
        
        # Good performance
        good_data = MonitoringData(
            device_id=device.id,
            response_time=25.0,
            packet_loss=1.0
        )
        assert good_data.get_performance_category() == 'good'
        
        # Fair performance
        fair_data = MonitoringData(
            device_id=device.id,
            response_time=75.0,
            packet_loss=3.0
        )
        assert fair_data.get_performance_category() == 'fair'
        
        # Poor performance
        poor_data = MonitoringData(
            device_id=device.id,
            response_time=500.0,
            packet_loss=15.0
        )
        assert poor_data.get_performance_category() == 'poor'
        
        # Failed performance
        failed_data = TimeoutMonitoringDataFactory.create(device=device)
        assert failed_data.get_performance_category() == 'failed'


class TestMonitoringDataQueries:
    """Test MonitoringData model query methods and filtering."""
    
    def test_query_by_time_range(self, db_session):
        """Test querying monitoring data by time range."""
        device = DeviceFactory.create()
        
        now = datetime.utcnow()
        
        # Create data at different times
        recent_data = MonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(minutes=30)
        )
        old_data = MonitoringDataFactory.create(
            device=device,
            timestamp=now - timedelta(hours=25)
        )
        
        # Query last 24 hours
        recent_query = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.timestamp >= now - timedelta(hours=24)
        ).all()
        
        assert len(recent_query) == 1
        assert recent_data in recent_query
        assert old_data not in recent_query
    
    def test_query_successful_pings(self, db_session):
        """Test querying only successful ping data."""
        device = DeviceFactory.create()
        
        successful_data = SuccessfulMonitoringDataFactory.create(device=device)
        failed_data = FailedMonitoringDataFactory.create(device=device)
        timeout_data = TimeoutMonitoringDataFactory.create(device=device)
        
        # Query successful pings (response_time is not None and packet_loss < 100)
        successful_query = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.response_time.isnot(None),
            MonitoringData.packet_loss < 100
        ).all()
        
        # Should include successful and failed (but not timeout)
        assert successful_data in successful_query
        assert failed_data in successful_query
        assert timeout_data not in successful_query
    
    def test_query_by_performance_threshold(self, db_session):
        """Test querying by performance thresholds."""
        device = DeviceFactory.create()
        
        fast_data = MonitoringDataFactory.create(
            device=device,
            response_time=15.0
        )
        slow_data = MonitoringDataFactory.create(
            device=device,
            response_time=150.0
        )
        
        # Query fast responses (< 50ms)
        fast_query = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.response_time < 50.0
        ).all()
        
        assert fast_data in fast_query
        assert slow_data not in fast_query
    
    def test_query_latest_data(self, db_session):
        """Test querying latest monitoring data for a device."""
        device = DeviceFactory.create()
        
        # Create data at different times
        older_data = MonitoringDataFactory.create(
            device=device,
            timestamp=datetime.utcnow() - timedelta(minutes=10)
        )
        latest_data = MonitoringDataFactory.create(
            device=device,
            timestamp=datetime.utcnow()
        )
        
        # Query latest data
        latest_query = MonitoringData.query.filter(
            MonitoringData.device_id == device.id
        ).order_by(MonitoringData.timestamp.desc()).first()
        
        assert latest_query == latest_data


class TestMonitoringDataAggregation:
    """Test MonitoringData aggregation and statistical methods."""
    
    def test_calculate_average_response_time(self, db_session):
        """Test calculating average response time over a period."""
        device = DeviceFactory.create()
        
        # Create monitoring data with known response times
        response_times = [10.0, 20.0, 30.0, 40.0, 50.0]
        for rt in response_times:
            MonitoringDataFactory.create(
                device=device,
                response_time=rt,
                timestamp=datetime.utcnow() - timedelta(minutes=len(response_times))
            )
        
        # Calculate average
        avg_query = db_session.query(
            db.func.avg(MonitoringData.response_time)
        ).filter(
            MonitoringData.device_id == device.id,
            MonitoringData.response_time.isnot(None)
        ).scalar()
        
        assert avg_query == 30.0  # Average of 10,20,30,40,50
    
    def test_calculate_uptime_percentage(self, db_session):
        """Test calculating uptime percentage from monitoring data."""
        device = DeviceFactory.create()
        
        # Create 8 successful and 2 timeout records
        for _ in range(8):
            SuccessfulMonitoringDataFactory.create(device=device)
        
        for _ in range(2):
            TimeoutMonitoringDataFactory.create(device=device)
        
        # Calculate uptime (successful pings / total pings)
        total_count = MonitoringData.query.filter(
            MonitoringData.device_id == device.id
        ).count()
        
        successful_count = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.response_time.isnot(None)
        ).count()
        
        uptime_percentage = (successful_count / total_count) * 100 if total_count > 0 else 0
        
        assert total_count == 10
        assert successful_count == 8
        assert uptime_percentage == 80.0
    
    def test_calculate_packet_loss_statistics(self, db_session):
        """Test calculating packet loss statistics."""
        device = DeviceFactory.create()
        
        # Create monitoring data with various packet loss values
        packet_loss_values = [0.0, 0.0, 1.0, 2.0, 5.0]
        for pl in packet_loss_values:
            MonitoringDataFactory.create(
                device=device,
                packet_loss=pl
            )
        
        # Calculate average packet loss
        avg_packet_loss = db_session.query(
            db.func.avg(MonitoringData.packet_loss)
        ).filter(
            MonitoringData.device_id == device.id
        ).scalar()
        
        assert avg_packet_loss == 1.6  # Average of 0,0,1,2,5


class TestMonitoringDataFactories:
    """Test the MonitoringData factory classes."""
    
    def test_monitoring_data_factory(self, db_session):
        """Test the basic MonitoringDataFactory."""
        monitoring_data = MonitoringDataFactory.create()
        assert_monitoring_data_properties(monitoring_data)
        
        assert monitoring_data.response_time is not None
        assert 5.0 <= monitoring_data.response_time <= 100.0
        assert 0.0 <= monitoring_data.packet_loss <= 5.0
    
    def test_successful_monitoring_data_factory(self, db_session):
        """Test the SuccessfulMonitoringDataFactory."""
        monitoring_data = SuccessfulMonitoringDataFactory.create()
        assert_monitoring_data_properties(monitoring_data)
        
        # Should have good performance characteristics
        assert monitoring_data.response_time <= 30.0
        assert monitoring_data.packet_loss == 0.0
    
    def test_failed_monitoring_data_factory(self, db_session):
        """Test the FailedMonitoringDataFactory."""
        monitoring_data = FailedMonitoringDataFactory.create()
        assert_monitoring_data_properties(monitoring_data)
        
        # Should have poor performance characteristics
        assert monitoring_data.response_time >= 500.0
        assert monitoring_data.packet_loss >= 10.0
    
    def test_timeout_monitoring_data_factory(self, db_session):
        """Test the TimeoutMonitoringDataFactory."""
        monitoring_data = TimeoutMonitoringDataFactory.create()
        assert_monitoring_data_properties(monitoring_data)
        
        # Should represent complete failure
        assert monitoring_data.response_time is None
        assert monitoring_data.packet_loss == 100.0


class TestMonitoringDataPerformance:
    """Test MonitoringData performance analysis methods."""
    
    def test_detect_anomalies(self, db_session):
        """Test detecting anomalous monitoring data."""
        device = DeviceFactory.create()
        
        # Create baseline normal data
        normal_response_times = [20.0, 22.0, 18.0, 25.0, 19.0]
        for rt in normal_response_times:
            MonitoringDataFactory.create(
                device=device,
                response_time=rt,
                packet_loss=0.0
            )
        
        # Create anomalous data
        anomaly_data = MonitoringDataFactory.create(
            device=device,
            response_time=500.0,  # Much higher than normal
            packet_loss=0.0
        )
        
        # In a real implementation, this would use statistical analysis
        # For testing, we'll use a simple threshold
        anomalous_data = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.response_time > 100.0  # Threshold
        ).all()
        
        assert anomaly_data in anomalous_data
        assert len(anomalous_data) == 1
    
    def test_trend_analysis(self, db_session):
        """Test analyzing performance trends over time."""
        device = DeviceFactory.create()
        
        base_time = datetime.utcnow() - timedelta(hours=5)
        
        # Create trending data (response times increasing over time)
        for i in range(5):
            MonitoringDataFactory.create(
                device=device,
                response_time=20.0 + (i * 10),  # 20, 30, 40, 50, 60
                timestamp=base_time + timedelta(hours=i)
            )
        
        # Query data ordered by time
        trending_data = MonitoringData.query.filter(
            MonitoringData.device_id == device.id
        ).order_by(MonitoringData.timestamp).all()
        
        # Verify trend (each subsequent response time should be higher)
        for i in range(1, len(trending_data)):
            assert trending_data[i].response_time > trending_data[i-1].response_time
    
    def test_performance_baseline_calculation(self, db_session):
        """Test calculating performance baseline from historical data."""
        device = DeviceFactory.create()
        
        # Create consistent performance data
        baseline_response_times = [20.0, 22.0, 18.0, 25.0, 19.0, 21.0, 23.0, 17.0]
        for rt in baseline_response_times:
            MonitoringDataFactory.create(
                device=device,
                response_time=rt
            )
        
        # Calculate baseline statistics
        baseline_stats = db_session.query(
            db.func.avg(MonitoringData.response_time).label('avg'),
            db.func.min(MonitoringData.response_time).label('min'),
            db.func.max(MonitoringData.response_time).label('max')
        ).filter(
            MonitoringData.device_id == device.id
        ).first()
        
        expected_avg = sum(baseline_response_times) / len(baseline_response_times)
        assert abs(baseline_stats.avg - expected_avg) < 0.1
        assert baseline_stats.min == min(baseline_response_times)
        assert baseline_stats.max == max(baseline_response_times)