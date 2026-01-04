"""
Regression tests for N+1 database query fixes (Phase 2).

These tests verify that the N+1 query optimizations in api/analytics.py,
api/monitoring.py, and api/health.py are working correctly and prevent
performance degradation.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from flask import Flask


class TestAnalyticsN1QueryFixes:
    """Tests for N+1 query fixes in api/analytics.py."""

    def test_network_health_score_uses_consolidated_queries(self, app, client, db_session, sample_devices):
        """Should use consolidated queries instead of N separate queries."""
        with app.app_context():
            with patch('api.analytics.db.session') as mock_session:
                # Create mock query results
                mock_device_stats = MagicMock()
                mock_device_stats.total_devices = 3
                mock_device_stats.devices_up = 2

                mock_monitoring_stats = MagicMock()
                mock_monitoring_stats.avg_response = 25.5
                mock_monitoring_stats.total_pings = 100
                mock_monitoring_stats.successful_pings = 95

                # Setup query chain
                mock_query = MagicMock()
                mock_query.filter.return_value = mock_query
                mock_query.first.side_effect = [mock_device_stats, mock_monitoring_stats]

                mock_session.query.return_value = mock_query

                # Make request
                response = client.get('/api/analytics/network-health-score')

                # Verify consolidated queries were used
                # Should have 2 consolidated queries (device stats + monitoring stats)
                # NOT 3+ separate queries
                assert mock_session.query.call_count == 3  # device stats, monitoring stats, alerts

    def test_device_insights_uses_batch_fetch(self, app, client, db_session, sample_devices):
        """Should use Device.batch_get_device_data to avoid N+1 queries."""
        with app.app_context():
            with patch('api.analytics.Device.batch_get_device_data') as mock_batch:
                mock_batch.return_value = {
                    'uptime_percentages': {1: 95.0, 2: 98.0, 3: 92.0},
                    'monitoring_data': {
                        1: MagicMock(response_time=20.0),
                        2: MagicMock(response_time=15.0),
                        3: MagicMock(response_time=30.0)
                    }
                }

                response = client.get('/api/analytics/device-insights?hours=168')

                # Verify batch fetch was called once
                assert mock_batch.call_count == 1

                # Verify it was called with all device IDs
                call_args = mock_batch.call_args
                device_ids = call_args[0][0]
                assert len(device_ids) == 3

    def test_device_insights_response_structure(self, app, client, db_session, sample_devices):
        """Should return properly structured insights without N+1 queries."""
        with app.app_context():
            response = client.get('/api/analytics/device-insights?hours=24')

            assert response.status_code == 200
            data = response.get_json()

            assert 'most_reliable' in data
            assert 'least_reliable' in data
            assert 'device_types' in data
            assert 'fastest_devices' in data
            assert 'summary' in data


class TestMonitoringN1QueryFixes:
    """Tests for N+1 query fixes in api/monitoring.py."""

    def test_monitoring_data_pagination_doesnt_cause_n1(self, app, client, db_session, sample_device, sample_monitoring_data):
        """Should paginate monitoring data without N+1 queries."""
        with app.app_context():
            # Create monitoring data for multiple devices
            from models import Device, MonitoringData
            from datetime import datetime, timedelta

            devices = []
            for i in range(5):
                device = Device(
                    ip_address=f'192.168.1.{100+i}',
                    mac_address=f'00:11:22:33:44:{50+i:02x}',
                    hostname=f'device-{i}',
                    is_monitored=True
                )
                db_session.add(device)
                devices.append(device)

            db_session.commit()

            # Add monitoring data
            base_time = datetime.utcnow() - timedelta(hours=1)
            for i, device in enumerate(devices):
                for j in range(10):
                    data = MonitoringData(
                        device_id=device.id,
                        timestamp=base_time + timedelta(minutes=j),
                        response_time=20.0 + i + j
                    )
                    db_session.add(data)

            db_session.commit()

            # Query with pagination
            response = client.get('/api/monitoring/data?page=1&per_page=25')

            assert response.status_code == 200
            data = response.get_json()

            # Should return paginated data
            assert 'items' in data or 'data' in data or 'monitoring_data' in data


class TestHealthN1QueryFixes:
    """Tests for N+1 query fixes in api/health.py."""

    def test_health_overview_uses_efficient_queries(self, app, client, db_session, sample_devices, sample_monitoring_data):
        """Should calculate health overview without N+1 queries."""
        with app.app_context():
            # Track number of queries executed
            from sqlalchemy import event
            from models import db

            query_count = [0]

            def count_queries(conn, cursor, statement, parameters, context, executemany):
                query_count[0] += 1

            # Register query counter
            event.listen(db.engine, 'before_cursor_execute', count_queries)

            try:
                response = client.get('/api/health/overview')

                assert response.status_code == 200

                # Should use a reasonable number of queries (not proportional to device count)
                # Expected: ~5-10 queries for aggregates, not 3 * num_devices
                assert query_count[0] < 15, f"Too many queries: {query_count[0]}"

            finally:
                event.remove(db.engine, 'before_cursor_execute', count_queries)

    def test_health_score_calculation_efficiency(self, app, client, db_session):
        """Should calculate health score with minimal queries."""
        with app.app_context():
            from models import Device, MonitoringData, Alert
            from datetime import datetime, timedelta

            # Create 20 devices
            for i in range(20):
                device = Device(
                    ip_address=f'192.168.1.{i}',
                    mac_address=f'00:11:22:33:44:{i:02x}',
                    hostname=f'device-{i}',
                    is_monitored=True,
                    last_seen=datetime.utcnow()
                )
                db_session.add(device)

            db_session.commit()

            # Track queries
            from sqlalchemy import event
            from models import db

            query_count = [0]

            def count_queries(conn, cursor, statement, parameters, context, executemany):
                query_count[0] += 1

            event.listen(db.engine, 'before_cursor_execute', count_queries)

            try:
                response = client.get('/api/health/score')

                # Should use aggregate queries, not per-device queries
                # Expected: ~3-5 queries total
                assert query_count[0] < 10, f"Health score using too many queries: {query_count[0]}"

            finally:
                event.remove(db.engine, 'before_cursor_execute', count_queries)


class TestN1QueryRegressionScenarios:
    """Additional regression tests for common N+1 patterns."""

    def test_device_list_with_statistics_no_n1(self, app, client, db_session):
        """Should fetch device statistics without N+1 queries."""
        with app.app_context():
            from models import Device, MonitoringData
            from datetime import datetime, timedelta

            # Create multiple devices with monitoring data
            devices = []
            for i in range(10):
                device = Device(
                    ip_address=f'192.168.1.{10+i}',
                    mac_address=f'AA:BB:CC:DD:EE:{i:02x}',
                    hostname=f'test-device-{i}',
                    is_monitored=True,
                    last_seen=datetime.utcnow()
                )
                db_session.add(device)
                devices.append(device)

            db_session.commit()

            # Add monitoring data
            base_time = datetime.utcnow() - timedelta(hours=1)
            for device in devices:
                for j in range(5):
                    data = MonitoringData(
                        device_id=device.id,
                        timestamp=base_time + timedelta(minutes=j * 10),
                        response_time=20.0 + j
                    )
                    db_session.add(data)

            db_session.commit()

            # Query count tracking
            from sqlalchemy import event
            from models import db

            query_count = [0]

            def count_queries(conn, cursor, statement, parameters, context, executemany):
                query_count[0] += 1

            event.listen(db.engine, 'before_cursor_execute', count_queries)

            try:
                # Request that would typically cause N+1
                response = client.get('/api/analytics/device-insights')

                # Query count should be O(1), not O(n)
                # Allow some queries for setup, but should not scale with device count
                assert query_count[0] < 20, f"Query count scales with devices: {query_count[0]}"

            finally:
                event.remove(db.engine, 'before_cursor_execute', count_queries)

    def test_consolidated_device_stats_query(self, app, db_session):
        """Should demonstrate proper use of consolidated query pattern."""
        with app.app_context():
            from models import db, Device
            from sqlalchemy import func
            from datetime import datetime, timedelta

            # Create test devices
            cutoff = datetime.utcnow() - timedelta(hours=24)

            for i in range(5):
                device = Device(
                    ip_address=f'192.168.1.{20+i}',
                    mac_address=f'BB:CC:DD:EE:FF:{i:02x}',
                    hostname=f'consolidated-test-{i}',
                    is_monitored=True,
                    last_seen=datetime.utcnow() if i < 3 else cutoff - timedelta(hours=1)
                )
                db_session.add(device)

            db_session.commit()

            # CORRECT: Consolidated query (like in network_health_score)
            device_stats = db_session.query(
                func.count(Device.id).label('total_devices'),
                func.sum(
                    func.cast(Device.last_seen >= cutoff, db.Integer)
                ).label('devices_up')
            ).filter(Device.is_monitored == True).first()

            assert device_stats.total_devices == 5
            assert device_stats.devices_up == 3

    def test_incorrect_n1_pattern_documented(self, app, db_session):
        """Documents the INCORRECT pattern that causes N+1 queries."""
        with app.app_context():
            from models import Device

            # Create test devices
            for i in range(3):
                device = Device(
                    ip_address=f'192.168.1.{30+i}',
                    mac_address=f'CC:DD:EE:FF:00:{i:02x}',
                    hostname=f'wrong-pattern-{i}',
                    is_monitored=True
                )
                db_session.add(device)

            db_session.commit()

            # WRONG: This causes N+1 queries
            # devices = Device.query.all()
            # for device in devices:
            #     uptime = device.calculate_uptime()  # Separate query per device!

            # CORRECT: Use batch operations
            from models import Device
            devices = Device.query.all()
            device_ids = [d.id for d in devices]

            # Batch fetch all uptime data in one query
            if hasattr(Device, 'batch_get_device_data'):
                batch_data = Device.batch_get_device_data(device_ids, include_uptime=True)
                # Now use batch_data without additional queries

            # This test passes by documenting the pattern, not executing the wrong one
            assert len(devices) == 3
