"""Network health score and recommendations shared by the analytics API and the
health overview. Inputs come from services/device_counts.py definitions."""


def calculate_health_score(devices_online, total_devices, avg_response_time, active_alerts, uptime_percentage):
    """Calculate overall network health score (0-100)"""
    if total_devices == 0:
        return 0

    # Device availability score (40% weight)
    availability_score = (devices_online / total_devices) * 40

    # Response time score (25% weight) - Good: <50ms, Fair: <200ms, Poor: >200ms
    if avg_response_time == 0:
        response_score = 25  # No data, assume neutral
    elif avg_response_time < 50:
        response_score = 25
    elif avg_response_time < 200:
        response_score = 15
    else:
        response_score = 5

    # Alert impact score (20% weight) - Penalty for active alerts
    alert_penalty = min(active_alerts * 5, 20)  # Max 20 points penalty
    alert_score = 20 - alert_penalty

    # Uptime score (15% weight)
    uptime_score = (uptime_percentage / 100) * 15

    # Calculate total score
    total_score = availability_score + response_score + alert_score + uptime_score

    return round(max(0, min(100, total_score)), 1)


def generate_health_recommendations(health_score, avg_response, success_rate, active_alerts=0):
    """Generate health improvement recommendations"""
    recommendations = []

    if health_score < 60:
        recommendations.append("⚠️ Network health is below acceptable levels. Immediate attention required.")

    if active_alerts > 0:
        recommendations.append(f"🚨 {active_alerts} active alert{'s' if active_alerts > 1 else ''} detected. Review alerts page for details.")

    if avg_response > 1000:
        recommendations.append("🐌 High response times detected. Check network congestion or device issues.")

    if success_rate < 90:
        recommendations.append("📡 Low ping success rate. Verify device connectivity and network stability.")

    if success_rate < 70:
        recommendations.append("🔧 Consider checking network infrastructure and device configurations.")

    if health_score >= 90 and active_alerts == 0:
        recommendations.append("✅ Excellent network performance! Keep up the great monitoring.")
    elif health_score >= 75 and active_alerts <= 2:
        recommendations.append("👍 Good network health. Minor optimizations could improve performance.")

    if len(recommendations) == 0:
        recommendations.append("📊 Monitor trends over time to identify patterns and potential issues.")

    return recommendations
