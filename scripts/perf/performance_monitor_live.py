#!/usr/bin/env python3
"""
Live Performance Monitor for HomeNetMon
Shows real-time performance metrics and bottlenecks.
"""

import time
import sqlite3
import psutil
import os
from datetime import datetime, timedelta
from pathlib import Path
import json

class PerformanceMonitor:
    def __init__(self):
        self.db_path = 'homeNetMon.db'
        self.process = psutil.Process()
        
    def get_database_stats(self):
        """Get database performance statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get database size
        db_size = os.path.getsize(self.db_path) / (1024 * 1024)
        
        # Get table counts
        cursor.execute("""
            SELECT 
                'devices' as table_name, COUNT(*) as count FROM devices
            UNION ALL
            SELECT 'monitoring_data', COUNT(*) FROM monitoring_data
            UNION ALL
            SELECT 'alerts', COUNT(*) FROM alerts
            UNION ALL
            SELECT 'performance_metrics', COUNT(*) FROM performance_metrics
        """)
        table_counts = cursor.fetchall()
        
        # Get cache hit ratio (if available)
        cursor.execute("PRAGMA cache_size")
        cache_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'db_size_mb': db_size,
            'tables': dict(table_counts),
            'cache_size': cache_size
        }
    
    def get_system_performance(self):
        """Get system performance metrics."""
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        
        # Network I/O
        net_io = psutil.net_io_counters()
        
        # Process specific
        process_info = {
            'cpu_percent': self.process.cpu_percent(),
            'memory_mb': self.process.memory_info().rss / (1024 * 1024),
            'num_threads': self.process.num_threads(),
            'num_fds': self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
        }
        
        return {
            'cpu': {
                'percent': cpu_percent,
                'frequency_mhz': cpu_freq.current if cpu_freq else 0,
                'cores': psutil.cpu_count()
            },
            'memory': {
                'used_gb': memory.used / (1024**3),
                'available_gb': memory.available / (1024**3),
                'percent': memory.percent
            },
            'disk_io': {
                'read_mb': disk_io.read_bytes / (1024**2),
                'write_mb': disk_io.write_bytes / (1024**2)
            },
            'network': {
                'sent_mb': net_io.bytes_sent / (1024**2),
                'recv_mb': net_io.bytes_recv / (1024**2)
            },
            'process': process_info
        }
    
    def test_query_performance(self):
        """Test performance of common queries."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=-64000")
        cursor = conn.cursor()
        
        queries = [
            ("Device List", "SELECT * FROM devices WHERE is_monitored = 1 LIMIT 100"),
            ("Recent Monitoring", "SELECT * FROM monitoring_data WHERE timestamp > datetime('now', '-1 hour') LIMIT 100"),
            ("Active Alerts", "SELECT * FROM alerts WHERE resolved = 0"),
            ("Device Summary", "SELECT * FROM device_summary_optimized LIMIT 10")
        ]
        
        results = []
        for name, query in queries:
            start = time.time()
            try:
                cursor.execute(query)
                cursor.fetchall()
                elapsed = (time.time() - start) * 1000  # ms
                results.append({'query': name, 'time_ms': elapsed, 'status': 'success'})
            except Exception as e:
                results.append({'query': name, 'time_ms': 0, 'status': f'error: {str(e)}'})
        
        conn.close()
        return results
    
    def get_cache_stats(self):
        """Get cache statistics if available."""
        try:
            from services.ultra_cache import device_cache, query_cache, response_cache
            
            return {
                'device_cache': device_cache.get_stats(),
                'query_cache': query_cache.get_stats(),
                'response_cache': response_cache.get_stats()
            }
        except ImportError:
            return {'error': 'Cache module not available'}
    
    def display_dashboard(self):
        """Display performance dashboard."""
        print("\033[2J\033[H")  # Clear screen
        print("="*80)
        print("🚀 HOMENATMON PERFORMANCE MONITOR")
        print("="*80)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Database stats
        db_stats = self.get_database_stats()
        print("📊 DATABASE:")
        print(f"  Size: {db_stats['db_size_mb']:.1f} MB")
        print("  Table Counts:")
        for table, count in db_stats['tables'].items():
            print(f"    {table}: {count:,}")
        print()
        
        # System performance
        sys_perf = self.get_system_performance()
        print("💻 SYSTEM:")
        print(f"  CPU: {sys_perf['cpu']['percent']:.1f}% ({sys_perf['cpu']['cores']} cores)")
        print(f"  Memory: {sys_perf['memory']['used_gb']:.1f}/{sys_perf['memory']['used_gb']+sys_perf['memory']['available_gb']:.1f} GB ({sys_perf['memory']['percent']:.1f}%)")
        print(f"  Process: {sys_perf['process']['memory_mb']:.1f} MB, {sys_perf['process']['num_threads']} threads")
        print()
        
        # Query performance
        query_perf = self.test_query_performance()
        print("⚡ QUERY PERFORMANCE:")
        for result in query_perf:
            status = "✅" if result['status'] == 'success' else "❌"
            print(f"  {status} {result['query']}: {result['time_ms']:.2f} ms")
        print()
        
        # Cache stats
        cache_stats = self.get_cache_stats()
        if 'error' not in cache_stats:
            print("💾 CACHE STATISTICS:")
            for cache_name, stats in cache_stats.items():
                print(f"  {cache_name}:")
                print(f"    Hit Rate: {stats['hit_rate']:.1f}%")
                print(f"    Size: {stats['size']}/{stats['max_size']}")
        
        print("\n" + "="*80)
        
        # Performance recommendations
        print("📈 RECOMMENDATIONS:")
        
        if db_stats['db_size_mb'] > 500:
            print("  ⚠️  Database is large - consider archiving old data")
        
        if sys_perf['memory']['percent'] > 80:
            print("  ⚠️  High memory usage - consider increasing cache limits")
        
        avg_query_time = sum(r['time_ms'] for r in query_perf if r['status'] == 'success') / len(query_perf)
        if avg_query_time > 100:
            print(f"  ⚠️  Slow queries detected (avg: {avg_query_time:.1f}ms) - check indexes")
        elif avg_query_time < 50:
            print(f"  ✅ Excellent query performance (avg: {avg_query_time:.1f}ms)")
        else:
            print(f"  ✅ Good query performance (avg: {avg_query_time:.1f}ms)")
        
        print("\nPress Ctrl+C to exit")


def main():
    monitor = PerformanceMonitor()
    
    try:
        while True:
            monitor.display_dashboard()
            time.sleep(5)  # Update every 5 seconds
    except KeyboardInterrupt:
        print("\n\nPerformance monitoring stopped.")


if __name__ == '__main__':
    main()