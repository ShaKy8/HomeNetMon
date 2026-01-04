"""
Unit tests for core/cache_layer.py

Tests verify integration with UnifiedCache backend and proper delegation
of caching operations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from core.cache_layer import (
    InMemoryCache, QueryResultCache, cached,
    DeviceDataCache, AlertDataCache, get_cache_health
)


class TestInMemoryCacheIntegration:
    """Tests for InMemoryCache wrapper that uses UnifiedCache."""

    @patch('core.cache_layer.get_unified_cache')
    def test_delegates_get_to_unified_cache(self, mock_get_unified):
        """Should delegate get operations to UnifiedCache backend."""
        mock_backend = MagicMock()
        mock_backend.get.return_value = 'cached_value'
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache()
        result = cache.get('test_key')

        assert result == 'cached_value'
        mock_backend.get.assert_called_once_with('test_key')

    @patch('core.cache_layer.get_unified_cache')
    def test_delegates_set_to_unified_cache(self, mock_get_unified):
        """Should delegate set operations to UnifiedCache backend."""
        mock_backend = MagicMock()
        mock_backend.set.return_value = True
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache(default_ttl=300)
        cache.set('test_key', 'test_value', ttl=60)

        mock_backend.set.assert_called_once_with('test_key', 'test_value', 60)

    @patch('core.cache_layer.get_unified_cache')
    def test_uses_default_ttl_when_not_specified(self, mock_get_unified):
        """Should use default TTL when ttl parameter is None."""
        mock_backend = MagicMock()
        mock_backend.set.return_value = True
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache(default_ttl=300)
        cache.set('test_key', 'test_value')

        mock_backend.set.assert_called_once_with('test_key', 'test_value', 300)

    @patch('core.cache_layer.get_unified_cache')
    def test_delegates_delete_to_unified_cache(self, mock_get_unified):
        """Should delegate delete operations to UnifiedCache backend."""
        mock_backend = MagicMock()
        mock_backend.delete.return_value = True
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache()
        result = cache.delete('test_key')

        assert result is True
        mock_backend.delete.assert_called_once_with('test_key')

    @patch('core.cache_layer.get_unified_cache')
    def test_delegates_clear_to_unified_cache(self, mock_get_unified):
        """Should delegate clear operations to UnifiedCache backend."""
        mock_backend = MagicMock()
        mock_backend.clear.return_value = True
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache()
        cache.clear()

        mock_backend.clear.assert_called_once()

    @patch('core.cache_layer.get_unified_cache')
    def test_get_stats_returns_unified_cache_stats(self, mock_get_unified):
        """Should return stats from UnifiedCache backend."""
        mock_backend = MagicMock()
        mock_backend.get_stats.return_value = {
            'size': 50,
            'max_size': 100,
            'hit_rate': 75.5
        }
        mock_get_unified.return_value = mock_backend

        cache = InMemoryCache()
        stats = cache.get_stats()

        assert stats['size'] == 50
        assert stats['hit_rate_percent'] == 75.5  # Should add this alias


class TestQueryResultCache:
    """Tests for specialized query result caching."""

    @patch('core.cache_layer.get_unified_cache')
    def test_cache_query_result_prefixes_key(self, mock_get_unified):
        """Should prefix query keys with 'query:' namespace."""
        mock_backend = MagicMock()
        mock_get_unified.return_value = mock_backend
        cache = InMemoryCache()

        query_cache = QueryResultCache(cache)
        query_cache.cache_query_result('device_list', {'devices': []}, ttl=300)

        # Should call set with prefixed key
        mock_backend.set.assert_called_once()
        call_args = mock_backend.set.call_args
        assert call_args[0][0] == 'query:device_list'

    @patch('core.cache_layer.get_unified_cache')
    def test_get_cached_query_result_prefixes_key(self, mock_get_unified):
        """Should prefix query keys when retrieving."""
        mock_backend = MagicMock()
        mock_backend.get.return_value = {'devices': []}
        mock_get_unified.return_value = mock_backend
        cache = InMemoryCache()

        query_cache = QueryResultCache(cache)
        result = query_cache.get_cached_query_result('device_list')

        mock_backend.get.assert_called_once_with('query:device_list')

    @patch('core.cache_layer.get_unified_cache')
    def test_tracks_query_statistics(self, mock_get_unified):
        """Should track query call counts and cache hits."""
        mock_backend = MagicMock()
        mock_backend.get.return_value = None
        mock_get_unified.return_value = mock_backend
        cache = InMemoryCache()

        query_cache = QueryResultCache(cache)

        # Cache a query result first to initialize stats
        query_cache.cache_query_result('test_query', {'data': 'test'}, ttl=60)

        # First call - cache miss
        mock_backend.get.return_value = None
        query_cache.get_cached_query_result('test_query')

        # Second call - cache hit
        mock_backend.get.return_value = {'data': 'cached'}
        query_cache.get_cached_query_result('test_query')

        # Verify statistics are tracked
        assert 'test_query' in query_cache.query_stats
        stats = query_cache.query_stats['test_query']
        assert stats['calls'] == 2
        assert stats['cache_hits'] == 1


class TestCachedDecorator:
    """Tests for the @cached decorator in cache_layer."""

    @patch('core.cache_layer.globals')
    def test_caches_function_results(self, mock_globals):
        """Should cache function results and reuse them."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None
        mock_globals.return_value = {'global_cache': mock_cache}

        call_count = [0]

        @cached(ttl=60, cache_instance=mock_cache)
        def test_function(x):
            call_count[0] += 1
            return x * 2

        # First call
        result1 = test_function(5)

        # Second call - should use cache
        mock_cache.get.return_value = 10
        result2 = test_function(5)

        assert call_count[0] == 1  # Function only called once


class TestGetCacheHealth:
    """Tests for cache health monitoring."""

    @patch('core.cache_layer.global_cache')
    def test_reports_healthy_status_with_good_hit_rate(self, mock_cache):
        """Should report healthy status when hit rate is good."""
        mock_cache.get_stats.return_value = {
            'hit_rate': 75.0,
            'hit_rate_percent': 75.0,
            'size': 50,
            'max_size': 1000
        }

        health = get_cache_health()

        assert health['status'] == 'healthy'
        assert len(health['issues']) == 0

    @patch('core.cache_layer.global_cache')
    def test_reports_degraded_status_with_low_hit_rate(self, mock_cache):
        """Should report degraded status when hit rate is low."""
        mock_cache.get_stats.return_value = {
            'hit_rate': 30.0,
            'hit_rate_percent': 30.0,
            'size': 50,
            'max_size': 1000
        }

        health = get_cache_health()

        assert health['status'] == 'degraded'
        assert 'Low cache hit rate' in health['issues']

    @patch('core.cache_layer.global_cache')
    def test_reports_degraded_status_with_high_utilization(self, mock_cache):
        """Should report degraded status when cache is nearly full."""
        mock_cache.get_stats.return_value = {
            'hit_rate': 75.0,
            'hit_rate_percent': 75.0,
            'size': 950,
            'max_size': 1000
        }

        health = get_cache_health()

        assert health['status'] == 'degraded'
        assert 'High cache utilization' in health['issues']

    @patch('core.cache_layer.global_cache')
    def test_calculates_utilization_percentage(self, mock_cache):
        """Should calculate correct utilization percentage."""
        mock_cache.get_stats.return_value = {
            'hit_rate': 75.0,
            'hit_rate_percent': 75.0,
            'size': 250,
            'max_size': 1000
        }

        health = get_cache_health()

        assert health['utilization_percent'] == 25.0

    @patch('core.cache_layer.global_cache')
    def test_handles_division_by_zero_in_utilization(self, mock_cache):
        """Should handle edge case of zero max_size."""
        mock_cache.get_stats.return_value = {
            'hit_rate': 75.0,
            'hit_rate_percent': 75.0,
            'size': 0,
            'max_size': 0
        }

        health = get_cache_health()

        # Should not crash and should return 0 utilization
        assert health['utilization_percent'] == 0

    @patch('core.cache_layer.global_cache')
    def test_supports_both_hit_rate_formats(self, mock_cache):
        """Should support both 'hit_rate' and 'hit_rate_percent' stat names."""
        # Test with only 'hit_rate'
        mock_cache.get_stats.return_value = {
            'hit_rate': 80.0,
            'size': 50,
            'max_size': 1000
        }

        health1 = get_cache_health()
        assert health1['status'] == 'healthy'

        # Test with only 'hit_rate_percent'
        mock_cache.get_stats.return_value = {
            'hit_rate_percent': 80.0,
            'size': 50,
            'max_size': 1000
        }

        health2 = get_cache_health()
        assert health2['status'] == 'healthy'


class TestDeviceDataCacheIntegration:
    """Tests for DeviceDataCache integration."""

    @patch('core.cache_layer.get_unified_cache')
    def test_invalidate_device_cache_clears_related_keys(self, mock_get_unified):
        """Should invalidate all cache entries related to a device."""
        mock_backend = MagicMock()
        mock_get_unified.return_value = mock_backend
        cache = InMemoryCache()

        device_cache = DeviceDataCache(cache)
        device_cache.invalidate_device_cache(device_id=123)

        # Should call delete for all device-related cache patterns
        assert mock_backend.delete.call_count >= 3  # status, uptime, network_summary


class TestAlertDataCacheIntegration:
    """Tests for AlertDataCache integration."""

    @patch('core.cache_layer.get_unified_cache')
    def test_caches_alert_data(self, mock_get_unified):
        """Should cache alert data with appropriate TTL."""
        mock_backend = MagicMock()
        mock_get_unified.return_value = mock_backend
        cache = InMemoryCache()

        alert_cache = AlertDataCache(cache)

        # The cached decorator should work with alert cache methods
        # This test verifies the cache instance is properly initialized
        assert alert_cache.cache is not None
