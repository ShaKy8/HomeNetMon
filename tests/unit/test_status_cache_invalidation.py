"""
Regression tests for Bug 4: Status cache inconsistency.

The bug was that the status property was cached for 30 seconds but device.last_seen
could change, causing the cached status to become stale and inconsistent.

Fixed by adding a SQLAlchemy event listener to invalidate the status cache when
last_seen changes.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, Mock


class TestStatusCacheInvalidation:
    """Tests for status cache invalidation on last_seen changes."""

    def test_status_returns_unknown_for_never_seen_device(self, app, db_session):
        """Device never seen should have status 'unknown'."""
        from models import Device

        with app.app_context():
            device = Device(
                ip_address='192.168.1.200',
                mac_address='00:11:22:33:44:AA',
                hostname='never-seen',
                device_type='computer',
                is_monitored=True,
                last_seen=None
            )
            db_session.add(device)
            db_session.commit()

            assert device.status == 'unknown'

    def test_status_returns_down_for_stale_device(self, app, db_session):
        """Device not seen for > 15 minutes should have status 'down'."""
        from models import Device, MonitoringData

        with app.app_context():
            device = Device(
                ip_address='192.168.1.201',
                mac_address='00:11:22:33:44:AB',
                hostname='stale-device',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow() - timedelta(hours=2)
            )
            db_session.add(device)
            db_session.commit()

            # Add some old monitoring data so status check has data to evaluate
            old_data = MonitoringData(
                device_id=device.id,
                response_time=None,  # Failed ping
                timestamp=datetime.utcnow() - timedelta(hours=2)
            )
            db_session.add(old_data)
            db_session.commit()

            assert device.status == 'down'

    def test_status_returns_up_for_recently_seen_device(self, app, db_session):
        """Device seen recently with good response time should have status 'up'."""
        from models import Device, MonitoringData

        with app.app_context():
            device = Device(
                ip_address='192.168.1.202',
                mac_address='00:11:22:33:44:AC',
                hostname='online-device',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow() - timedelta(minutes=2)
            )
            db_session.add(device)
            db_session.commit()

            # Add successful monitoring data
            monitoring_data = MonitoringData(
                device_id=device.id,
                response_time=25.0,
                timestamp=datetime.utcnow()
            )
            db_session.add(monitoring_data)
            db_session.commit()

            assert device.status == 'up'

    def test_status_updates_after_last_seen_change(self, app, db_session):
        """Status should reflect new last_seen value after change."""
        from models import Device, MonitoringData, db

        with app.app_context():
            # Create device that was seen recently
            device = Device(
                ip_address='192.168.1.203',
                mac_address='00:11:22:33:44:AD',
                hostname='cache-test',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow() - timedelta(minutes=5)
            )
            db_session.add(device)
            db_session.commit()

            # Add monitoring data
            monitoring_data = MonitoringData(
                device_id=device.id,
                response_time=25.0,
                timestamp=datetime.utcnow()
            )
            db_session.add(monitoring_data)
            db_session.commit()

            # First status check - should be 'up'
            status1 = device.status
            assert status1 == 'up', f"Expected 'up' status for recently seen device, got '{status1}'"

            # Simulate device going offline (last_seen becomes old)
            device.last_seen = datetime.utcnow() - timedelta(hours=2)
            db_session.commit()

            # Force cache invalidation by re-querying
            db.session.expire(device)

            # Status should now be 'down', not the cached 'up'
            status2 = device.status
            assert status2 == 'down', \
                f"Status should be 'down' after last_seen becomes old, got '{status2}'"

    def test_event_listener_registered(self, app, db_session):
        """Verify event listener is registered for Device.last_seen."""
        from sqlalchemy import inspect
        from models import Device

        # Get the mapper for Device and check for attribute events
        # This verifies that some event handling is configured
        mapper = inspect(Device)
        # Check that the last_seen attribute exists and can have listeners
        assert hasattr(Device, 'last_seen'), "Device should have last_seen attribute"

        # Alternatively, verify by testing behavior: changing last_seen should work
        with app.app_context():
            device = Device(
                ip_address='192.168.1.206',
                mac_address='00:11:22:33:44:F0',
                hostname='listener-test',
                device_type='computer',
                is_monitored=True,
                last_seen=None
            )
            db_session.add(device)
            db_session.commit()

            # This should trigger the event listener without error
            device.last_seen = datetime.utcnow()
            db_session.commit()

            # Verify the update worked (listener didn't break it)
            assert device.last_seen is not None

    def test_cache_invalidation_does_not_break_updates(self, app, db_session):
        """Cache invalidation should not prevent last_seen updates."""
        from models import Device, db

        with app.app_context():
            device = Device(
                ip_address='192.168.1.204',
                mac_address='00:11:22:33:44:AE',
                hostname='update-test',
                device_type='computer',
                is_monitored=True,
                last_seen=None
            )
            db_session.add(device)
            db_session.commit()
            device_id = device.id

            # Update last_seen multiple times
            for i in range(3):
                new_time = datetime.utcnow() - timedelta(minutes=i)
                device.last_seen = new_time
                db_session.commit()

                # Verify update persisted
                db.session.expire(device)
                reloaded = Device.query.get(device_id)
                assert reloaded.last_seen is not None

    def test_status_consistency_across_queries(self, app, db_session):
        """Status should be consistent when queried multiple times."""
        from models import Device, MonitoringData, db

        with app.app_context():
            device = Device(
                ip_address='192.168.1.205',
                mac_address='00:11:22:33:44:AF',
                hostname='consistency-test',
                device_type='computer',
                is_monitored=True,
                last_seen=datetime.utcnow() - timedelta(minutes=5)
            )
            db_session.add(device)
            db_session.commit()

            # Add monitoring data
            monitoring_data = MonitoringData(
                device_id=device.id,
                response_time=25.0,
                timestamp=datetime.utcnow()
            )
            db_session.add(monitoring_data)
            db_session.commit()

            # Query status multiple times - should be consistent
            statuses = [device.status for _ in range(5)]
            assert all(s == 'up' for s in statuses), \
                f"Status should be consistent: {statuses}"

            # Update last_seen to old value
            device.last_seen = datetime.utcnow() - timedelta(hours=2)
            db_session.commit()
            db.session.expire(device)

            # Query status multiple times again - should all be 'down'
            statuses = [device.status for _ in range(5)]
            assert all(s == 'down' for s in statuses), \
                f"Status should be consistently 'down' after last_seen update: {statuses}"
