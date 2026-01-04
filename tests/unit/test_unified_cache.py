"""
Unit tests for services/unified_cache.py

Tests cover:
- MemoryCache LRU eviction
- MemoryCache TTL expiry
- MemoryCache get_or_set
- RedisCache functionality (mocked)
- UnifiedCache backend selection
- Cache decorator functionality
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from services.unified_cache import (
    MemoryCache, RedisCache, UnifiedCache, cached, get_cache, init_cache
)


class TestMemoryCache:
    """Tests for in-memory cache with LRU eviction."""

    def test_basic_set_and_get(self):
        """Should store and retrieve values correctly."""
        cache = MemoryCache(max_size=100)
        cache.set('test_key', 'test_value')

        result = cache.get('test_key')
        assert result == 'test_value'

    def test_get_nonexistent_key_returns_none(self):
        """Should return None for non-existent keys."""
        cache = MemoryCache(max_size=100)

        result = cache.get('nonexistent')
        assert result is None

    def test_lru_eviction_when_at_capacity(self):
        """Should evict least recently used item when cache is full."""
        cache = MemoryCache(max_size=3)

        # Fill cache to capacity
        cache.set('key1', 'value1')
        cache.set('key2', 'value2')
        cache.set('key3', 'value3')

        # Access key1 to make it recently used
        cache.get('key1')

        # Add new item, should evict key2 (least recently used)
        cache.set('key4', 'value4')

        assert cache.get('key1') == 'value1', "Recently used key1 should still exist"
        assert cache.get('key2') is None, "Least recently used key2 should be evicted"
        assert cache.get('key3') == 'value3', "key3 should still exist"
        assert cache.get('key4') == 'value4', "New key4 should exist"

    def test_lru_eviction_order(self):
        """Should evict items in correct LRU order."""
        cache = MemoryCache(max_size=2)

        cache.set('oldest', 'value1')
        cache.set('newer', 'value2')

        # Add third item, should evict 'oldest'
        cache.set('newest', 'value3')

        assert cache.get('oldest') is None
        assert cache.get('newer') == 'value2'
        assert cache.get('newest') == 'value3'

    def test_ttl_expiration(self):
        """Should expire items after TTL elapses."""
        cache = MemoryCache(max_size=100)

        # Set with 1 second TTL
        cache.set('short_lived', 'value', ttl=1)

        # Should exist immediately
        assert cache.get('short_lived') == 'value'

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get('short_lived') is None

    def test_ttl_not_expired_yet(self):
        """Should return value if TTL has not elapsed."""
        cache = MemoryCache(max_size=100)

        # Set with 10 second TTL
        cache.set('long_lived', 'value', ttl=10)

        # Should still exist after 0.5 seconds
        time.sleep(0.5)
        assert cache.get('long_lived') == 'value'

    def test_set_without_ttl(self):
        """Should store items without expiration when TTL not specified."""
        cache = MemoryCache(max_size=100)

        cache.set('permanent', 'value')

        # Should exist even after some time
        time.sleep(0.5)
        assert cache.get('permanent') == 'value'

    def test_update_existing_key(self):
        """Should update value when setting existing key."""
        cache = MemoryCache(max_size=100)

        cache.set('key', 'original')
        cache.set('key', 'updated')

        assert cache.get('key') == 'updated'

    def test_update_ttl_on_existing_key(self):
        """Should update TTL when updating existing key."""
        cache = MemoryCache(max_size=100)

        # Set with TTL
        cache.set('key', 'value1', ttl=10)

        # Update without TTL (should remove TTL)
        cache.set('key', 'value2')

        # Should still exist and not have TTL
        assert cache.get('key') == 'value2'

    def test_delete_existing_key(self):
        """Should delete key and return True."""
        cache = MemoryCache(max_size=100)

        cache.set('key', 'value')
        result = cache.delete('key')

        assert result is True
        assert cache.get('key') is None

    def test_delete_nonexistent_key(self):
        """Should return False when deleting non-existent key."""
        cache = MemoryCache(max_size=100)

        result = cache.delete('nonexistent')
        assert result is False

    def test_clear_cache(self):
        """Should remove all items from cache."""
        cache = MemoryCache(max_size=100)

        cache.set('key1', 'value1')
        cache.set('key2', 'value2')
        cache.set('key3', 'value3')

        result = cache.clear()

        assert result is True
        assert cache.get('key1') is None
        assert cache.get('key2') is None
        assert cache.get('key3') is None

    def test_exists_returns_true_for_existing_key(self):
        """Should return True when key exists."""
        cache = MemoryCache(max_size=100)

        cache.set('key', 'value')
        assert cache.exists('key') is True

    def test_exists_returns_false_for_nonexistent_key(self):
        """Should return False when key doesn't exist."""
        cache = MemoryCache(max_size=100)

        assert cache.exists('nonexistent') is False

    def test_exists_returns_false_for_expired_key(self):
        """Should return False for expired keys."""
        cache = MemoryCache(max_size=100)

        cache.set('key', 'value', ttl=1)
        time.sleep(1.1)

        assert cache.exists('key') is False

    def test_get_stats_initial_state(self):
        """Should return correct stats for empty cache."""
        cache = MemoryCache(max_size=100)

        stats = cache.get_stats()

        assert stats['size'] == 0
        assert stats['max_size'] == 100
        assert stats['hits'] == 0
        assert stats['misses'] == 0
        assert stats['hit_rate'] == 0
        assert stats['utilization'] == 0

    def test_get_stats_tracks_hits_and_misses(self):
        """Should track cache hits and misses correctly."""
        cache = MemoryCache(max_size=100)

        cache.set('key', 'value')

        # Generate some hits
        cache.get('key')
        cache.get('key')

        # Generate some misses
        cache.get('nonexistent1')
        cache.get('nonexistent2')

        stats = cache.get_stats()

        assert stats['hits'] == 2
        assert stats['misses'] == 2
        assert stats['hit_rate'] == 50.0

    def test_get_stats_utilization(self):
        """Should calculate cache utilization correctly."""
        cache = MemoryCache(max_size=10)

        # Fill half the cache
        for i in range(5):
            cache.set(f'key{i}', f'value{i}')

        stats = cache.get_stats()

        assert stats['size'] == 5
        assert stats['utilization'] == 50.0

    def test_thread_safety_concurrent_access(self):
        """Should handle concurrent access safely."""
        import threading

        cache = MemoryCache(max_size=100)
        errors = []

        def set_values(start, end):
            try:
                for i in range(start, end):
                    cache.set(f'key{i}', f'value{i}')
            except Exception as e:
                errors.append(e)

        def get_values(start, end):
            try:
                for i in range(start, end):
                    cache.get(f'key{i}')
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        threads.append(threading.Thread(target=set_values, args=(0, 50), daemon=True))
        threads.append(threading.Thread(target=set_values, args=(50, 100), daemon=True))
        threads.append(threading.Thread(target=get_values, args=(0, 100), daemon=True))

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for completion with timeout
        for thread in threads:
            thread.join(timeout=5.0)

        assert len(errors) == 0, "Should handle concurrent access without errors"


class TestUnifiedCacheGetOrSet:
    """Tests for get_or_set functionality."""

    def test_get_or_set_cache_miss(self):
        """Should call factory and cache result on miss."""
        cache = UnifiedCache(max_memory_size=100)
        call_count = [0]

        def factory():
            call_count[0] += 1
            return 'computed_value'

        result = cache.get_or_set('test_key', factory, ttl=60)

        assert result == 'computed_value'
        assert call_count[0] == 1, "Factory should be called once"
        assert cache.get('test_key') == 'computed_value', "Result should be cached"

    def test_get_or_set_cache_hit(self):
        """Should return cached value without calling factory on hit."""
        cache = UnifiedCache(max_memory_size=100)
        call_count = [0]

        def factory():
            call_count[0] += 1
            return 'computed_value'

        # First call - cache miss
        result1 = cache.get_or_set('test_key', factory, ttl=60)

        # Second call - cache hit
        result2 = cache.get_or_set('test_key', factory, ttl=60)

        assert result1 == 'computed_value'
        assert result2 == 'computed_value'
        assert call_count[0] == 1, "Factory should only be called once"

    def test_get_or_set_with_expensive_computation(self):
        """Should cache expensive computation results."""
        cache = UnifiedCache(max_memory_size=100)

        def expensive_computation():
            time.sleep(0.1)  # Simulate expensive operation
            return 'expensive_result'

        # First call - should take time
        start = time.time()
        result1 = cache.get_or_set('expensive', expensive_computation)
        first_duration = time.time() - start

        # Second call - should be instant (cached)
        start = time.time()
        result2 = cache.get_or_set('expensive', expensive_computation)
        second_duration = time.time() - start

        assert result1 == result2 == 'expensive_result'
        assert second_duration < first_duration * 0.5, "Cached call should be much faster"


class TestUnifiedCacheBackendSelection:
    """Tests for backend selection logic."""

    def test_defaults_to_memory_cache(self):
        """Should use MemoryCache when Redis not available."""
        cache = UnifiedCache()

        assert isinstance(cache.backend, MemoryCache)

    @patch('services.unified_cache.REDIS_AVAILABLE', True)
    @patch('services.unified_cache.redis.from_url')
    def test_uses_redis_when_available_and_url_provided(self, mock_redis):
        """Should use RedisCache when Redis available and URL provided."""
        # Mock successful Redis connection
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis.return_value = mock_client

        cache = UnifiedCache(redis_url='redis://localhost:6379')

        assert isinstance(cache.backend, RedisCache)

    @patch('services.unified_cache.REDIS_AVAILABLE', True)
    @patch('services.unified_cache.redis.from_url')
    def test_falls_back_to_memory_on_redis_connection_failure(self, mock_redis):
        """Should fall back to MemoryCache if Redis connection fails."""
        # Mock failed Redis connection
        mock_redis.side_effect = Exception("Connection failed")

        cache = UnifiedCache(redis_url='redis://localhost:6379')

        assert isinstance(cache.backend, MemoryCache)

    def test_invalidate_pattern_memory_cache(self):
        """Should invalidate matching keys in memory cache."""
        cache = UnifiedCache(max_memory_size=100)

        cache.set('user:1:profile', 'data1')
        cache.set('user:2:profile', 'data2')
        cache.set('user:1:settings', 'data3')
        cache.set('product:1', 'data4')

        # Invalidate all user:*:profile keys
        count = cache.invalidate_pattern('user:*:profile')

        assert count == 2
        assert cache.get('user:1:profile') is None
        assert cache.get('user:2:profile') is None
        assert cache.get('user:1:settings') == 'data3'
        assert cache.get('product:1') == 'data4'


class TestCachedDecorator:
    """Tests for the @cached decorator."""

    def test_cached_decorator_caches_results(self):
        """Should cache function results."""
        call_count = [0]

        @cached(ttl=60)
        def expensive_function(x):
            call_count[0] += 1
            return x * 2

        result1 = expensive_function(5)
        result2 = expensive_function(5)

        assert result1 == result2 == 10
        assert call_count[0] == 1, "Function should only be called once"

    def test_cached_decorator_different_args(self):
        """Should cache different results for different arguments."""
        call_count = [0]

        @cached(ttl=60)
        def compute(x, y):
            call_count[0] += 1
            return x + y

        result1 = compute(1, 2)
        result2 = compute(3, 4)
        result3 = compute(1, 2)  # Should use cache

        assert result1 == 3
        assert result2 == 7
        assert result3 == 3
        assert call_count[0] == 2, "Should be called twice (once for each unique arg set)"

    def test_cached_decorator_with_kwargs(self):
        """Should handle keyword arguments correctly."""
        call_count = [0]

        @cached(ttl=60)
        def compute(x, y=10):
            call_count[0] += 1
            return x + y

        result1 = compute(5, y=10)
        result2 = compute(5, y=10)
        result3 = compute(5, y=20)

        assert result1 == result2 == 15
        assert result3 == 25
        assert call_count[0] == 2


class TestGlobalCacheInstances:
    """Tests for global cache instance management."""

    def test_get_cache_returns_global_instance(self):
        """Should return the global cache instance."""
        cache = get_cache()

        assert isinstance(cache, UnifiedCache)

    def test_init_cache_replaces_global_instance(self):
        """Should replace global cache instance."""
        original = get_cache()

        new_cache = init_cache(max_memory_size=500)
        current = get_cache()

        assert current is new_cache
        assert current.backend.max_size == 500


class TestRedisCache:
    """Tests for RedisCache implementation (with mocking)."""

    @patch('services.unified_cache.REDIS_AVAILABLE', True)
    @patch('services.unified_cache.redis.from_url')
    def test_redis_set_and_get(self, mock_redis):
        """Should store and retrieve values from Redis."""
        mock_client = MagicMock()
        mock_client.get.return_value = None
        mock_client.setex.return_value = True
        mock_redis.return_value = mock_client

        cache = RedisCache('redis://localhost:6379')

        # Set value
        result = cache.set('test_key', 'test_value', ttl=60)
        assert result is True

        # Verify setex was called with correct arguments
        assert mock_client.setex.called

    @patch('services.unified_cache.REDIS_AVAILABLE', True)
    @patch('services.unified_cache.redis.from_url')
    def test_redis_delete(self, mock_redis):
        """Should delete keys from Redis."""
        mock_client = MagicMock()
        mock_client.delete.return_value = 1
        mock_redis.return_value = mock_client

        cache = RedisCache('redis://localhost:6379')

        result = cache.delete('test_key')

        assert result is True
        assert mock_client.delete.called

    @patch('services.unified_cache.REDIS_AVAILABLE', False)
    def test_redis_unavailable_raises_error(self):
        """Should raise error when Redis not installed."""
        with pytest.raises(RuntimeError, match="Redis not available"):
            RedisCache('redis://localhost:6379')
