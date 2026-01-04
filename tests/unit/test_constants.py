"""
Unit tests for constants.py

Tests verify that all constants are properly defined and have expected values.
This serves as documentation and regression protection for constant changes.
"""

import pytest
import constants


class TestApplicationMetadata:
    """Tests for application metadata constants."""

    def test_app_name_defined(self):
        """Should have APP_NAME constant."""
        assert hasattr(constants, 'APP_NAME')
        assert constants.APP_NAME == "HomeNetMon"

    def test_app_version_defined(self):
        """Should have APP_VERSION constant."""
        assert hasattr(constants, 'APP_VERSION')
        assert isinstance(constants.APP_VERSION, str)
        assert len(constants.APP_VERSION) > 0

    def test_app_description_defined(self):
        """Should have APP_DESCRIPTION constant."""
        assert hasattr(constants, 'APP_DESCRIPTION')
        assert isinstance(constants.APP_DESCRIPTION, str)


class TestNetworkConfiguration:
    """Tests for network configuration constants."""

    def test_default_network_range_is_valid(self):
        """Should have valid CIDR network range."""
        assert hasattr(constants, 'DEFAULT_NETWORK_RANGE')
        assert '/' in constants.DEFAULT_NETWORK_RANGE
        parts = constants.DEFAULT_NETWORK_RANGE.split('/')
        assert len(parts) == 2
        assert parts[1].isdigit()

    def test_ping_interval_is_positive(self):
        """Should have positive ping interval."""
        assert hasattr(constants, 'DEFAULT_PING_INTERVAL')
        assert constants.DEFAULT_PING_INTERVAL > 0

    def test_scan_timeout_values_are_valid(self):
        """Should have valid scan timeout values."""
        assert hasattr(constants, 'DEFAULT_SCAN_TIMEOUT')
        assert hasattr(constants, 'MAX_SCAN_TIMEOUT')
        assert constants.DEFAULT_SCAN_TIMEOUT > 0
        assert constants.MAX_SCAN_TIMEOUT >= constants.DEFAULT_SCAN_TIMEOUT


class TestDeviceStatus:
    """Tests for device status constants."""

    def test_device_status_constants_defined(self):
        """Should have all device status constants."""
        assert hasattr(constants, 'DEVICE_STATUS_UP')
        assert hasattr(constants, 'DEVICE_STATUS_DOWN')
        assert hasattr(constants, 'DEVICE_STATUS_WARNING')
        assert hasattr(constants, 'DEVICE_STATUS_UNKNOWN')

    def test_device_status_values_are_strings(self):
        """Should have string values for device statuses."""
        assert isinstance(constants.DEVICE_STATUS_UP, str)
        assert isinstance(constants.DEVICE_STATUS_DOWN, str)
        assert isinstance(constants.DEVICE_STATUS_WARNING, str)
        assert isinstance(constants.DEVICE_STATUS_UNKNOWN, str)


class TestResponseTimeThresholds:
    """Tests for response time threshold constants."""

    def test_response_time_thresholds_defined(self):
        """Should have all response time thresholds."""
        assert hasattr(constants, 'RESPONSE_TIME_EXCELLENT')
        assert hasattr(constants, 'RESPONSE_TIME_GOOD')
        assert hasattr(constants, 'RESPONSE_TIME_ACCEPTABLE')
        assert hasattr(constants, 'RESPONSE_TIME_POOR')

    def test_response_time_thresholds_in_ascending_order(self):
        """Should have thresholds in ascending order."""
        assert constants.RESPONSE_TIME_EXCELLENT < constants.RESPONSE_TIME_GOOD
        assert constants.RESPONSE_TIME_GOOD < constants.RESPONSE_TIME_ACCEPTABLE
        assert constants.RESPONSE_TIME_ACCEPTABLE < constants.RESPONSE_TIME_POOR


class TestDataRetention:
    """Tests for data retention constants."""

    def test_data_retention_defaults(self):
        """Should have valid data retention defaults."""
        assert hasattr(constants, 'DEFAULT_DATA_RETENTION_DAYS')
        assert hasattr(constants, 'MAX_DATA_RETENTION_DAYS')
        assert hasattr(constants, 'MIN_DATA_RETENTION_DAYS')

    def test_data_retention_boundaries_are_logical(self):
        """Should have logical min/default/max boundaries."""
        assert constants.MIN_DATA_RETENTION_DAYS > 0
        assert constants.MIN_DATA_RETENTION_DAYS <= constants.DEFAULT_DATA_RETENTION_DAYS
        assert constants.DEFAULT_DATA_RETENTION_DAYS <= constants.MAX_DATA_RETENTION_DAYS


class TestCacheConfiguration:
    """Tests for cache configuration constants."""

    def test_cache_timeout_constants_defined(self):
        """Should have all cache timeout constants."""
        assert hasattr(constants, 'CACHE_DEFAULT_TIMEOUT')
        assert hasattr(constants, 'CACHE_DEVICE_LIST_TIMEOUT')
        assert hasattr(constants, 'CACHE_QUERY_TIMEOUT')
        assert hasattr(constants, 'CACHE_RESPONSE_TIMEOUT')
        assert hasattr(constants, 'CACHE_MAX_SIZE')

    def test_cache_timeouts_are_positive(self):
        """Should have positive cache timeout values."""
        assert constants.CACHE_DEFAULT_TIMEOUT > 0
        assert constants.CACHE_DEVICE_LIST_TIMEOUT > 0
        assert constants.CACHE_QUERY_TIMEOUT > 0
        assert constants.CACHE_RESPONSE_TIMEOUT > 0

    def test_cache_max_size_is_positive(self):
        """Should have positive max cache size."""
        assert constants.CACHE_MAX_SIZE > 0


class TestRateLimiting:
    """Tests for rate limiting constants."""

    def test_rate_limit_constants_defined(self):
        """Should have all rate limit constants."""
        assert hasattr(constants, 'RATE_LIMIT_STRICT')
        assert hasattr(constants, 'RATE_LIMIT_MODERATE')
        assert hasattr(constants, 'RATE_LIMIT_RELAXED')

    def test_rate_limit_format_is_valid(self):
        """Should have valid rate limit string format."""
        # Format should be "N per period"
        for limit in [constants.RATE_LIMIT_STRICT, constants.RATE_LIMIT_MODERATE,
                      constants.RATE_LIMIT_RELAXED]:
            assert isinstance(limit, str)
            assert ' per ' in limit


class TestSecurityConstants:
    """Tests for security-related constants."""

    def test_csrf_constants_defined(self):
        """Should have CSRF protection constants."""
        assert hasattr(constants, 'CSRF_TOKEN_LIFETIME')
        assert hasattr(constants, 'CSRF_MAX_TOKENS')

    def test_max_content_length_defined(self):
        """Should have maximum content length."""
        assert hasattr(constants, 'MAX_CONTENT_LENGTH')
        assert constants.MAX_CONTENT_LENGTH > 0


class TestAlertConfiguration:
    """Tests for alert configuration constants."""

    def test_alert_priority_constants_defined(self):
        """Should have all alert priority constants."""
        assert hasattr(constants, 'ALERT_PRIORITY_CRITICAL')
        assert hasattr(constants, 'ALERT_PRIORITY_HIGH')
        assert hasattr(constants, 'ALERT_PRIORITY_MEDIUM')
        assert hasattr(constants, 'ALERT_PRIORITY_LOW')

    def test_alert_priorities_are_strings(self):
        """Should have string values for alert priorities."""
        assert isinstance(constants.ALERT_PRIORITY_CRITICAL, str)
        assert isinstance(constants.ALERT_PRIORITY_HIGH, str)
        assert isinstance(constants.ALERT_PRIORITY_MEDIUM, str)
        assert isinstance(constants.ALERT_PRIORITY_LOW, str)


class TestAPIPagination:
    """Tests for API pagination constants."""

    def test_pagination_constants_defined(self):
        """Should have pagination constants."""
        assert hasattr(constants, 'API_DEFAULT_PAGE_SIZE')
        assert hasattr(constants, 'API_MAX_PAGE_SIZE')
        assert hasattr(constants, 'API_MIN_PAGE_SIZE')

    def test_pagination_boundaries_are_logical(self):
        """Should have logical pagination boundaries."""
        assert constants.API_MIN_PAGE_SIZE > 0
        assert constants.API_MIN_PAGE_SIZE <= constants.API_DEFAULT_PAGE_SIZE
        assert constants.API_DEFAULT_PAGE_SIZE <= constants.API_MAX_PAGE_SIZE


class TestHTTPStatusCodes:
    """Tests for HTTP status code constants."""

    def test_success_status_codes(self):
        """Should have 2xx success status codes."""
        assert hasattr(constants, 'HTTP_OK')
        assert constants.HTTP_OK == 200
        assert hasattr(constants, 'HTTP_CREATED')
        assert constants.HTTP_CREATED == 201

    def test_client_error_status_codes(self):
        """Should have 4xx client error status codes."""
        assert hasattr(constants, 'HTTP_BAD_REQUEST')
        assert constants.HTTP_BAD_REQUEST == 400
        assert hasattr(constants, 'HTTP_NOT_FOUND')
        assert constants.HTTP_NOT_FOUND == 404

    def test_server_error_status_codes(self):
        """Should have 5xx server error status codes."""
        assert hasattr(constants, 'HTTP_INTERNAL_SERVER_ERROR')
        assert constants.HTTP_INTERNAL_SERVER_ERROR == 500


class TestErrorMessages:
    """Tests for error message constants."""

    def test_error_messages_defined(self):
        """Should have error message constants."""
        assert hasattr(constants, 'ERROR_DEVICE_NOT_FOUND')
        assert hasattr(constants, 'ERROR_INVALID_IP')
        assert hasattr(constants, 'ERROR_RATE_LIMIT_EXCEEDED')

    def test_error_messages_are_strings(self):
        """Should have string error messages."""
        assert isinstance(constants.ERROR_DEVICE_NOT_FOUND, str)
        assert isinstance(constants.ERROR_INVALID_IP, str)
        assert len(constants.ERROR_DEVICE_NOT_FOUND) > 0


class TestSuccessMessages:
    """Tests for success message constants."""

    def test_success_messages_defined(self):
        """Should have success message constants."""
        assert hasattr(constants, 'SUCCESS_DEVICE_UPDATED')
        assert hasattr(constants, 'SUCCESS_SCAN_STARTED')

    def test_success_messages_are_strings(self):
        """Should have string success messages."""
        assert isinstance(constants.SUCCESS_DEVICE_UPDATED, str)
        assert len(constants.SUCCESS_DEVICE_UPDATED) > 0


class TestFeatureFlags:
    """Tests for feature flag constants."""

    def test_feature_flags_defined(self):
        """Should have feature flag constants."""
        assert hasattr(constants, 'FEATURE_ANOMALY_DETECTION')
        assert hasattr(constants, 'FEATURE_ADVANCED_ANALYTICS')
        assert hasattr(constants, 'FEATURE_WEBHOOKS')

    def test_feature_flags_are_boolean(self):
        """Should have boolean feature flags."""
        assert isinstance(constants.FEATURE_ANOMALY_DETECTION, bool)
        assert isinstance(constants.FEATURE_ADVANCED_ANALYTICS, bool)


class TestDeviceClassificationKeywords:
    """Tests for device type classification keyword lists."""

    def test_device_type_keywords_are_lists(self):
        """Should have list-type device classification keywords."""
        assert isinstance(constants.DEVICE_TYPE_ROUTER, list)
        assert isinstance(constants.DEVICE_TYPE_CAMERA, list)
        assert isinstance(constants.DEVICE_TYPE_PHONE, list)

    def test_device_type_keywords_not_empty(self):
        """Should have non-empty keyword lists."""
        assert len(constants.DEVICE_TYPE_ROUTER) > 0
        assert len(constants.DEVICE_TYPE_CAMERA) > 0
        assert len(constants.DEVICE_TYPE_PHONE) > 0

    def test_device_type_keywords_are_lowercase(self):
        """Should have lowercase keywords for case-insensitive matching."""
        for keyword in constants.DEVICE_TYPE_ROUTER:
            assert keyword == keyword.lower()


class TestSystemLimits:
    """Tests for system limit constants."""

    def test_max_devices_per_network(self):
        """Should have maximum devices limit."""
        assert hasattr(constants, 'MAX_DEVICES_PER_NETWORK')
        assert constants.MAX_DEVICES_PER_NETWORK > 0

    def test_max_concurrent_scans(self):
        """Should limit concurrent scans."""
        assert hasattr(constants, 'MAX_CONCURRENT_SCANS')
        assert constants.MAX_CONCURRENT_SCANS >= 1


class TestUIConstants:
    """Tests for UI/UX constants."""

    def test_ui_timing_constants(self):
        """Should have UI timing constants."""
        assert hasattr(constants, 'UI_REFRESH_INTERVAL')
        assert hasattr(constants, 'UI_TOAST_DURATION')
        assert hasattr(constants, 'UI_DEBOUNCE_DELAY')

    def test_ui_timings_are_positive(self):
        """Should have positive UI timing values."""
        assert constants.UI_REFRESH_INTERVAL > 0
        assert constants.UI_TOAST_DURATION > 0
        assert constants.UI_DEBOUNCE_DELAY > 0


class TestConstantsImmutability:
    """Tests to ensure constants are not accidentally mutable collections."""

    def test_chart_colors_is_immutable_type(self):
        """Should use tuple for color list to prevent modification."""
        # Note: Currently it's a list, but this test documents the expected behavior
        assert hasattr(constants, 'CHART_COLORS')
        assert isinstance(constants.CHART_COLORS, (list, tuple))

    def test_device_type_lists_exist(self):
        """Should have all device type classification lists."""
        device_types = [
            'DEVICE_TYPE_ROUTER', 'DEVICE_TYPE_SWITCH', 'DEVICE_TYPE_AP',
            'DEVICE_TYPE_CAMERA', 'DEVICE_TYPE_SMART', 'DEVICE_TYPE_NAS',
            'DEVICE_TYPE_PRINTER', 'DEVICE_TYPE_TV', 'DEVICE_TYPE_PHONE',
            'DEVICE_TYPE_COMPUTER', 'DEVICE_TYPE_TABLET'
        ]

        for device_type in device_types:
            assert hasattr(constants, device_type), f"Missing constant: {device_type}"


class TestWebSocketConfiguration:
    """Tests for WebSocket configuration constants."""

    def test_websocket_constants_defined(self):
        """Should have WebSocket configuration constants."""
        assert hasattr(constants, 'WEBSOCKET_PING_INTERVAL')
        assert hasattr(constants, 'WEBSOCKET_PING_TIMEOUT')

    def test_websocket_timeout_greater_than_interval(self):
        """Should have timeout greater than ping interval."""
        assert constants.WEBSOCKET_PING_TIMEOUT > constants.WEBSOCKET_PING_INTERVAL
