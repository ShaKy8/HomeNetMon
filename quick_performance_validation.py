#!/usr/bin/env python3
"""
Quick Performance Validation for HomeNetMon
Provides immediate performance assessment while comprehensive load testing runs
"""

import time
import requests
import statistics
from datetime import datetime
import concurrent.futures

def test_response_times():
    """Test basic response times"""
    base_url = "http://geekom1:5000"
    endpoints = [
        "/", "/dashboard", "/analytics", "/devices", "/alerts",
        "/api/devices", "/api/monitoring/summary", "/api/system/info"
    ]

    results = []

    print("🚀 Quick Performance Validation")
    print("=" * 50)

    for endpoint in endpoints:
        try:
            url = f"{base_url}{endpoint}"

            # Test 5 requests to get average
            times = []
            for _ in range(5):
                start = time.time()
                response = requests.get(url, timeout=10)
                duration = (time.time() - start) * 1000
                times.append(duration)

                if response.status_code >= 400:
                    print(f"❌ {endpoint}: Error {response.status_code}")
                    break
            else:
                avg_time = statistics.mean(times)
                status = "✅ EXCELLENT" if avg_time < 200 else "⚠️ GOOD" if avg_time < 500 else "❌ SLOW"
                print(f"{status}: {endpoint} - {avg_time:.0f}ms avg")
                results.append(avg_time)

        except Exception as e:
            print(f"❌ {endpoint}: {e}")

    if results:
        overall_avg = statistics.mean(results)
        print(f"\n📊 Overall Average: {overall_avg:.0f}ms")

        if overall_avg < 200:
            print("🎉 EXCELLENT performance - Ready for production!")
        elif overall_avg < 500:
            print("✅ GOOD performance - Suitable for production")
        else:
            print("⚠️ Performance needs optimization")

    return results

def test_concurrent_load():
    """Test concurrent request handling"""
    print(f"\n🔥 Concurrent Load Test (10 users)")

    def make_request():
        start = time.time()
        try:
            response = requests.get("http://geekom1:5000/api/devices", timeout=10)
            duration = (time.time() - start) * 1000
            return {"success": response.status_code < 400, "time_ms": duration}
        except:
            return {"success": False, "time_ms": 0}

    # Run 10 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(10)]
        results = [f.result() for f in futures]

    successful = [r for r in results if r["success"]]
    success_rate = len(successful) / len(results)

    if successful:
        avg_time = statistics.mean([r["time_ms"] for r in successful])
        print(f"✅ Success Rate: {success_rate*100:.0f}%")
        print(f"📊 Avg Response: {avg_time:.0f}ms under load")

        if success_rate >= 0.9 and avg_time < 1000:
            print("🎉 Excellent concurrent performance!")
        elif success_rate >= 0.8:
            print("✅ Good concurrent handling")
        else:
            print("⚠️ Concurrent performance needs attention")
    else:
        print("❌ Failed concurrent load test")

if __name__ == "__main__":
    print(f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}")

    # Basic performance test
    test_response_times()

    # Concurrent load test
    test_concurrent_load()

    print(f"\n✅ Quick validation completed")
    print(f"🔄 Comprehensive load testing running in background...")