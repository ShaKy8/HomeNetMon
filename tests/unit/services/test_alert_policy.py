"""AlertManager decision helpers (consecutive-failure detection). Policy tests are added in 2.9.0."""

from datetime import datetime, timedelta

from monitoring.alerts import AlertManager
from tests.fixtures.factories import (
    DeviceFactory,
    SuccessfulMonitoringDataFactory,
    TimeoutMonitoringDataFactory,
)


class TestConsecutiveFailureDetection:
    """Test consecutive failure detection logic."""

    def test_has_consecutive_failures_never_seen(self, db_session):
        """Test consecutive failures for device never seen."""
        manager = AlertManager()
        device = DeviceFactory.create(last_seen=None)

        result = manager.has_consecutive_failures(device, required_failures=2)
        assert result is True  # Never seen = definitely down

    def test_has_consecutive_failures_with_timeouts(self, app, db_session):
        """Test consecutive failures with timeout monitoring data."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()

        # Create consecutive timeout records
        base_time = datetime.utcnow() - timedelta(minutes=30)
        for i in range(3):
            TimeoutMonitoringDataFactory.create(
                device=device,
                timestamp=base_time + timedelta(minutes=i * 5)
            )

        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)

        assert result is True

    def test_has_consecutive_failures_mixed_results(self, app, db_session):
        """Test consecutive failures with mixed success/failure data."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()

        base_time = datetime.utcnow() - timedelta(minutes=30)

        # Create pattern: success, fail, fail, success
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=base_time
        )
        TimeoutMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=5)
        )
        TimeoutMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=10)
        )
        SuccessfulMonitoringDataFactory.create(
            device=device,
            timestamp=base_time + timedelta(minutes=15)
        )

        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)

        # Latest is success, so not consecutive failures
        assert result is False

    def test_has_consecutive_failures_not_enough(self, app, db_session):
        """Test consecutive failures with insufficient failure count."""
        manager = AlertManager(app=app)
        device = DeviceFactory.create()

        # Create only one failure
        TimeoutMonitoringDataFactory.create(device=device)

        with app.app_context():
            result = manager.has_consecutive_failures(device, required_failures=2)

        assert result is False
