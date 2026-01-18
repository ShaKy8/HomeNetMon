"""
Regression tests for Bug 3: Detached objects in batch processing.

The bug was in _batch_process_monitoring_results() where device objects from
worker threads were detached from the current session. Accessing device.status
could cause DetachedInstanceError or return stale cached values.

Fixed by:
1. Modifying _ping_device_for_batch() to only return device_id, not the device object
2. Modifying _batch_process_monitoring_results() to bulk-query devices by ID
   within the new session context
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta


class TestBatchProcessingSessionBinding:
    """Tests for session binding in batch processing."""

    def test_batch_processing_does_not_use_detached_objects(self, app, db_session):
        """Batch processing should re-query devices, not use detached objects."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, MonitoringData

        # Create test devices
        devices = []
        for i in range(3):
            device = Device(
                ip_address=f'192.168.1.{100+i}',
                mac_address=f'00:11:22:33:44:{50+i:02x}',
                hostname=f'test-device-{i}',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow()
            )
            db_session.add(device)
            devices.append(device)
        db_session.commit()

        device_ids = [d.id for d in devices]

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            # Simulate batch results with device_id only (proper pattern after fix)
            ping_results = [
                {
                    'device_id': device_ids[0],
                    'response_time': 25.0,
                    'success': True,
                    'timestamp': datetime.utcnow()
                },
                {
                    'device_id': device_ids[1],
                    'response_time': 30.0,
                    'success': True,
                    'timestamp': datetime.utcnow()
                },
                {
                    'device_id': device_ids[2],
                    'response_time': None,
                    'success': False,
                    'timestamp': datetime.utcnow()
                }
            ]

            # This should not raise DetachedInstanceError
            monitor._batch_process_monitoring_results(ping_results)

            # Verify monitoring data was created
            monitoring_count = MonitoringData.query.filter(
                MonitoringData.device_id.in_(device_ids)
            ).count()
            assert monitoring_count == 3

    def test_batch_processing_handles_missing_device(self, app, db_session):
        """Batch processing should handle devices that no longer exist."""
        from monitoring.monitor import DeviceMonitor
        from models import MonitoringData

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            # Result for non-existent device
            ping_results = [
                {
                    'device_id': 99999,  # Non-existent
                    'response_time': 25.0,
                    'success': True,
                    'timestamp': datetime.utcnow()
                }
            ]

            # Should not raise, should log warning and skip
            monitor._batch_process_monitoring_results(ping_results)

            # Verify no monitoring data was created for non-existent device
            monitoring_count = MonitoringData.query.filter(
                MonitoringData.device_id == 99999
            ).count()
            assert monitoring_count == 0

    def test_ping_device_for_batch_returns_device_id_only(self, app, db_session):
        """_ping_device_for_batch should return device_id, not device object."""
        from monitoring.monitor import DeviceMonitor
        from models import Device

        device = Device(
            ip_address='192.168.1.110',
            mac_address='00:11:22:33:44:60',
            hostname='batch-test',
            device_type='computer',
            is_monitored=True,
            last_seen=datetime.utcnow()
        )
        db_session.add(device)
        db_session.commit()

        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'time=25.0 ms'

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            with patch('subprocess.run', return_value=mock_result):
                with patch('monitoring.monitor.iot_optimizer') as mock_optimizer:
                    mock_optimizer.should_skip_monitoring.return_value = (False, 0)
                    mock_optimizer.get_optimized_settings.return_value = {'max_retries': 1, 'ping_timeout': 1.0}
                    mock_optimizer.record_ping_result = Mock()

                    result = monitor._ping_device_for_batch(device)

            # Verify result structure
            assert 'device_id' in result
            assert result['device_id'] == device.id
            # After the fix, 'device' key should NOT be in the result
            assert 'device' not in result, \
                "Batch result should not include device object (session binding fix)"
            assert 'response_time' in result
            assert 'success' in result
            assert 'timestamp' in result

    def test_device_status_accessible_in_batch(self, app, db_session):
        """Device status property should be accessible without DetachedInstanceError."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, MonitoringData

        # Create device with recent monitoring data
        device = Device(
            ip_address='192.168.1.111',
            mac_address='00:11:22:33:44:61',
            hostname='status-test',
            device_type='computer',
            is_monitored=True,
            last_seen=datetime.utcnow()
        )
        db_session.add(device)
        db_session.commit()

        # Add monitoring data so status can be calculated
        monitoring_data = MonitoringData(
            device_id=device.id,
            response_time=25.0,
            timestamp=datetime.utcnow()
        )
        db_session.add(monitoring_data)
        db_session.commit()

        device_id = device.id

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            ping_results = [
                {
                    'device_id': device_id,
                    'response_time': 25.0,
                    'success': True,
                    'timestamp': datetime.utcnow()
                }
            ]

            # This should not raise DetachedInstanceError when accessing device.status
            monitor._batch_process_monitoring_results(ping_results)

    def test_batch_processing_bulk_queries_devices(self, app, db_session):
        """Batch processing should query all devices in one query, not N queries."""
        from monitoring.monitor import DeviceMonitor
        from models import Device, MonitoringData, db
        from sqlalchemy import event

        # Create multiple devices
        device_ids = []
        for i in range(5):
            device = Device(
                ip_address=f'192.168.1.{120+i}',
                mac_address=f'00:11:22:33:44:{70+i:02x}',
                hostname=f'bulk-test-{i}',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow()
            )
            db_session.add(device)
            db_session.commit()
            device_ids.append(device.id)

        with app.app_context():
            monitor = DeviceMonitor(app=app)

            ping_results = [
                {
                    'device_id': did,
                    'response_time': 25.0 + i,
                    'success': True,
                    'timestamp': datetime.utcnow()
                }
                for i, did in enumerate(device_ids)
            ]

            # Track query count
            query_count = [0]

            def count_queries(conn, cursor, statement, parameters, context, executemany):
                # Only count SELECT queries that involve devices
                if 'SELECT' in statement.upper() and 'devices' in statement.lower():
                    query_count[0] += 1

            event.listen(db.engine, 'before_cursor_execute', count_queries)

            try:
                monitor._batch_process_monitoring_results(ping_results)
            finally:
                event.remove(db.engine, 'before_cursor_execute', count_queries)

            # With the fix (bulk query), should be 1-2 device queries, not 5
            # (one for bulk fetch, possibly one more for status checks)
            assert query_count[0] <= 3, \
                f"Expected bulk query but got {query_count[0]} device queries for 5 devices"
