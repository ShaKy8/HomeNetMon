"""PerformanceMetrics.calculate_health_score after removing the fabricated bandwidth term."""

import pytest

from models import PerformanceMetrics


def _score(avg_ms=5, uptime=100, jitter=0, loss=0, checks=10, successful=None):
    if successful is None:
        successful = round(checks * uptime / 100)
    return PerformanceMetrics.calculate_health_score(
        {'avg_ms': avg_ms}, {'uptime_percentage': uptime, 'total_checks': checks, 'successful_checks': successful},
        None, {'jitter_ms': jitter, 'packet_loss_percentage': loss})


class TestHealthScore:

    def test_no_checks_means_no_score(self):
        """The old formula scored devices with zero ping data at a constant 63.0."""
        assert _score(checks=0) is None
        assert PerformanceMetrics.calculate_health_score({}, {}, None, {}) is None

    def test_perfect_device_scores_100(self):
        s = _score()
        assert s['overall_health'] == 100 and s['efficiency'] is None

    def test_offline_device_scores_low(self):
        s = _score(avg_ms=None, uptime=0, loss=100)
        assert s['reliability'] == 0 and s['responsiveness'] == 0
        assert s['overall_health'] < 15

    def test_weights_sum_to_one_and_reliability_dominates(self):
        assert _score(uptime=50)['overall_health'] == pytest.approx(100 - 0.45 * 50, abs=0.01)
        assert _score(avg_ms=600)['overall_health'] < _score(uptime=90)['overall_health']

    def test_bandwidth_argument_is_ignored(self):
        assert _score() == PerformanceMetrics.calculate_health_score(
            {'avg_ms': 5}, {'uptime_percentage': 100, 'total_checks': 10},
            {'avg_in_mbps': 999, 'avg_out_mbps': 999}, {'jitter_ms': 0, 'packet_loss_percentage': 0})
