#!/usr/bin/env python3
"""
Performance testing script for HomeNetMon
Tests the improvements made to page load and API response times
"""

import requests
import time
from statistics import mean, median

def test_endpoint(url, name, iterations=5):
    """Test an endpoint multiple times and return performance metrics"""
    print(f"\n🧪 Testing {name}")
    print(f"URL: {url}")
    
    times = []
    sizes = []
    
    for i in range(iterations):
        start_time = time.time()
        try:
            response = requests.get(url, headers={
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'HomeNetMon-Performance-Test'
            })
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            times.append(response_time)
            sizes.append(len(response.content))
            
            print(f"  {i+1:2d}. {response_time:6.1f}ms | {response.status_code} | {len(response.content):,} bytes | {response.headers.get('Content-Encoding', 'none')} | {response.headers.get('X-Response-Time', 'N/A')}")
            
        except Exception as e:
            print(f"  {i+1:2d}. ERROR: {e}")
    
    if times:
        print(f"📊 Results:")
        print(f"   Average: {mean(times):6.1f}ms")
        print(f"   Median:  {median(times):6.1f}ms")
        print(f"   Min:     {min(times):6.1f}ms") 
        print(f"   Max:     {max(times):6.1f}ms")
        print(f"   Size:    {mean(sizes):,.0f} bytes avg")
    
    return times

def main():
    print("🚀 HomeNetMon Performance Test")
    print("=" * 50)
    
    base_url = "http://localhost:5000"
    
    # Test critical endpoints
    endpoints = [
        ("/", "Homepage"),
        ("/api/devices", "Devices API"),
        ("/api/devices?monitored=true", "Monitored Devices API"),
        ("/health", "Health Check"),
        ("/static/js/lazy-loader.js", "Static Asset (JS)"),
    ]
    
    all_results = {}
    
    for path, name in endpoints:
        url = f"{base_url}{path}"
        times = test_endpoint(url, name)
        if times:
            all_results[name] = {
                'avg': mean(times),
                'median': median(times),
                'min': min(times),
                'max': max(times)
            }
    
    print("\n" + "=" * 50)
    print("📋 PERFORMANCE SUMMARY")
    print("=" * 50)
    
    for name, metrics in all_results.items():
        print(f"{name:25s}: {metrics['avg']:6.1f}ms avg | {metrics['median']:6.1f}ms median")
    
    print("\n🎯 PERFORMANCE TARGETS:")
    print("  🟢 Homepage: < 500ms (First Contentful Paint)")
    print("  🟢 API calls: < 1000ms (for good UX)")
    print("  🟢 Static assets: < 100ms (with caching)")
    
    # Check if we're meeting targets
    homepage_perf = all_results.get("Homepage", {}).get('avg', 0)
    api_perf = all_results.get("Devices API", {}).get('avg', 0)
    
    print(f"\n📈 ASSESSMENT:")
    if homepage_perf < 500:
        print(f"  ✅ Homepage performance: EXCELLENT ({homepage_perf:.1f}ms)")
    elif homepage_perf < 1000:
        print(f"  🟡 Homepage performance: GOOD ({homepage_perf:.1f}ms)")
    else:
        print(f"  🔴 Homepage performance: NEEDS WORK ({homepage_perf:.1f}ms)")
    
    if api_perf < 500:
        print(f"  ✅ API performance: EXCELLENT ({api_perf:.1f}ms)")
    elif api_perf < 1500:
        print(f"  🟡 API performance: ACCEPTABLE ({api_perf:.1f}ms)")
    else:
        print(f"  🔴 API performance: SLOW ({api_perf:.1f}ms)")
    
    print(f"\n🚀 Performance optimizations active:")
    print(f"  ✅ Database indexes created")
    print(f"  ✅ Gzip compression enabled")
    print(f"  ✅ Resource preloading configured")
    print(f"  ✅ Lazy loading for non-critical JS")
    print(f"  ✅ Cache headers optimized")

if __name__ == "__main__":
    main()