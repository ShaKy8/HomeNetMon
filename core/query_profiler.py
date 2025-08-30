"""
Database query profiling and performance monitoring system.
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from sqlalchemy import event
from sqlalchemy.engine import Engine
from functools import wraps
import statistics
import re

logger = logging.getLogger(__name__)

@dataclass
class QueryProfile:
    """Represents a profiled database query."""
    query_id: str
    sql: str
    normalized_sql: str
    execution_time: float
    timestamp: datetime
    parameters: Optional[Dict] = None
    table_names: List[str] = field(default_factory=list)
    operation_type: str = "UNKNOWN"
    row_count: Optional[int] = None
    
class QueryProfiler:
    """Database query profiler with detailed performance analytics."""
    
    def __init__(self, max_queries: int = 10000):
        self.max_queries = max_queries
        self.queries: deque = deque(maxlen=max_queries)
        self.query_stats: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'total_time': 0.0,
            'min_time': float('inf'),
            'max_time': 0.0,
            'avg_time': 0.0,
            'times': deque(maxlen=1000)  # Keep last 1000 execution times
        })
        self.lock = threading.Lock()
        
        # Performance thresholds
        self.slow_query_threshold = 1.0  # seconds
        self.very_slow_query_threshold = 5.0  # seconds
        
        # Statistics
        self.global_stats = {
            'total_queries': 0,
            'slow_queries': 0,
            'very_slow_queries': 0,
            'avg_query_time': 0.0,
            'queries_per_second': 0.0,
            'last_reset': datetime.now()
        }
        
    def normalize_query(self, sql: str) -> str:
        """Normalize SQL query for pattern analysis."""
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', sql.strip())
        
        # Replace parameter placeholders with generic markers
        normalized = re.sub(r'[?]\s*(?:,\s*[?])*', '?', normalized)
        normalized = re.sub(r':\w+', ':param', normalized)
        normalized = re.sub(r'\$\d+', '$param', normalized)
        
        # Replace literal values
        normalized = re.sub(r"'[^']*'", "'?'", normalized)
        normalized = re.sub(r'\b\d+\b', '?', normalized)
        
        return normalized.upper()
        
    def extract_operation_type(self, sql: str) -> str:
        """Extract the operation type from SQL."""
        sql_upper = sql.upper().strip()
        
        if sql_upper.startswith('SELECT'):
            return 'SELECT'
        elif sql_upper.startswith('INSERT'):
            return 'INSERT'
        elif sql_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif sql_upper.startswith('DELETE'):
            return 'DELETE'
        elif sql_upper.startswith('CREATE'):
            return 'CREATE'
        elif sql_upper.startswith('DROP'):
            return 'DROP'
        elif sql_upper.startswith('ALTER'):
            return 'ALTER'
        else:
            return 'UNKNOWN'
            
    def extract_table_names(self, sql: str) -> List[str]:
        """Extract table names from SQL query."""
        tables = []
        
        # Common table patterns
        patterns = [
            r'FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'JOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        ]
        
        sql_upper = sql.upper()
        for pattern in patterns:
            matches = re.findall(pattern, sql_upper)
            tables.extend(matches)
            
        return list(set(tables))  # Remove duplicates
        
    def record_query(self, sql: str, execution_time: float, 
                    parameters: Optional[Dict] = None, 
                    row_count: Optional[int] = None):
        """Record a query execution for profiling."""
        
        normalized_sql = self.normalize_query(sql)
        operation_type = self.extract_operation_type(sql)
        table_names = self.extract_table_names(sql)
        
        query_profile = QueryProfile(
            query_id=f"{hash(normalized_sql)}",
            sql=sql,
            normalized_sql=normalized_sql,
            execution_time=execution_time,
            timestamp=datetime.now(),
            parameters=parameters,
            table_names=table_names,
            operation_type=operation_type,
            row_count=row_count
        )
        
        with self.lock:
            # Add to queries log
            self.queries.append(query_profile)
            
            # Update statistics
            stats = self.query_stats[normalized_sql]
            stats['count'] += 1
            stats['total_time'] += execution_time
            stats['min_time'] = min(stats['min_time'], execution_time)
            stats['max_time'] = max(stats['max_time'], execution_time)
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['times'].append(execution_time)
            
            # Update global statistics
            self.global_stats['total_queries'] += 1
            
            if execution_time >= self.very_slow_query_threshold:
                self.global_stats['very_slow_queries'] += 1
            elif execution_time >= self.slow_query_threshold:
                self.global_stats['slow_queries'] += 1
                
            # Calculate running average
            total_queries = self.global_stats['total_queries']
            current_avg = self.global_stats['avg_query_time']
            new_avg = ((current_avg * (total_queries - 1)) + execution_time) / total_queries
            self.global_stats['avg_query_time'] = new_avg
            
    def get_slow_queries(self, limit: int = 50, 
                        threshold: float = None) -> List[QueryProfile]:
        """Get slow queries above threshold."""
        if threshold is None:
            threshold = self.slow_query_threshold
            
        with self.lock:
            slow_queries = [
                q for q in self.queries 
                if q.execution_time >= threshold
            ]
            
        # Sort by execution time (slowest first)
        slow_queries.sort(key=lambda q: q.execution_time, reverse=True)
        return slow_queries[:limit]
        
    def get_query_stats(self, normalized_sql: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific query pattern."""
        with self.lock:
            if normalized_sql not in self.query_stats:
                return None
                
            stats = self.query_stats[normalized_sql].copy()
            
            # Calculate percentiles
            times = list(stats['times'])
            if times:
                times.sort()
                stats['median_time'] = statistics.median(times)
                stats['p95_time'] = times[int(len(times) * 0.95)] if len(times) > 20 else stats['max_time']
                stats['p99_time'] = times[int(len(times) * 0.99)] if len(times) > 100 else stats['max_time']
                stats['std_dev'] = statistics.stdev(times) if len(times) > 1 else 0.0
                
            # Remove the times deque for JSON serialization
            del stats['times']
            
        return stats
        
    def get_top_queries_by_time(self, limit: int = 20) -> List[Tuple[str, Dict]]:
        """Get queries sorted by total execution time."""
        with self.lock:
            query_times = [
                (sql, stats) for sql, stats in self.query_stats.items()
            ]
            
        # Sort by total time
        query_times.sort(key=lambda x: x[1]['total_time'], reverse=True)
        return query_times[:limit]
        
    def get_top_queries_by_count(self, limit: int = 20) -> List[Tuple[str, Dict]]:
        """Get queries sorted by execution count."""
        with self.lock:
            query_counts = [
                (sql, stats) for sql, stats in self.query_stats.items()
            ]
            
        # Sort by count
        query_counts.sort(key=lambda x: x[1]['count'], reverse=True)
        return query_counts[:limit]
        
    def get_queries_by_table(self, table_name: str) -> List[QueryProfile]:
        """Get all queries that access a specific table."""
        with self.lock:
            table_queries = [
                q for q in self.queries 
                if table_name.upper() in [t.upper() for t in q.table_names]
            ]
            
        return table_queries
        
    def get_operation_stats(self) -> Dict[str, Dict]:
        """Get statistics by operation type (SELECT, INSERT, etc.)."""
        operation_stats = defaultdict(lambda: {
            'count': 0,
            'total_time': 0.0,
            'avg_time': 0.0
        })
        
        with self.lock:
            for query in self.queries:
                op_stats = operation_stats[query.operation_type]
                op_stats['count'] += 1
                op_stats['total_time'] += query.execution_time
                
        # Calculate averages
        for op_stats in operation_stats.values():
            if op_stats['count'] > 0:
                op_stats['avg_time'] = op_stats['total_time'] / op_stats['count']
                
        return dict(operation_stats)
        
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get overall performance summary."""
        with self.lock:
            # Calculate queries per second
            time_diff = datetime.now() - self.global_stats['last_reset']
            qps = self.global_stats['total_queries'] / max(time_diff.total_seconds(), 1)
            
            # Get recent query times for trending
            recent_queries = [
                q.execution_time for q in list(self.queries)[-1000:]
            ]
            
            recent_avg = statistics.mean(recent_queries) if recent_queries else 0.0
            
        return {
            **self.global_stats,
            'queries_per_second': round(qps, 2),
            'recent_avg_time': round(recent_avg, 3),
            'unique_queries': len(self.query_stats),
            'slow_query_percentage': round(
                (self.global_stats['slow_queries'] / max(self.global_stats['total_queries'], 1)) * 100, 2
            )
        }
        
    def reset_stats(self):
        """Reset all profiling statistics."""
        with self.lock:
            self.queries.clear()
            self.query_stats.clear()
            self.global_stats = {
                'total_queries': 0,
                'slow_queries': 0,
                'very_slow_queries': 0,
                'avg_query_time': 0.0,
                'queries_per_second': 0.0,
                'last_reset': datetime.now()
            }
            
    def export_slow_queries(self, threshold: float = None, 
                           format: str = 'json') -> str:
        """Export slow queries for analysis."""
        import json
        
        slow_queries = self.get_slow_queries(threshold=threshold)
        
        if format == 'json':
            export_data = []
            for query in slow_queries:
                export_data.append({
                    'sql': query.sql,
                    'execution_time': query.execution_time,
                    'timestamp': query.timestamp.isoformat(),
                    'operation_type': query.operation_type,
                    'table_names': query.table_names
                })
            return json.dumps(export_data, indent=2)
            
        elif format == 'sql':
            # Export as SQL with comments
            lines = ['-- Slow Query Analysis Report', 
                    f'-- Generated: {datetime.now().isoformat()}', '']
            
            for query in slow_queries:
                lines.append(f'-- Execution time: {query.execution_time:.3f}s')
                lines.append(f'-- Tables: {", ".join(query.table_names)}')
                lines.append(query.sql)
                lines.append('')
                
            return '\n'.join(lines)
            
        return str(slow_queries)

def profile_query(profiler: QueryProfiler):
    """Decorator to profile individual query functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Try to extract SQL from common ORM patterns
                sql = getattr(result, 'statement', None) or str(func.__name__)
                
                profiler.record_query(
                    sql=sql,
                    execution_time=execution_time
                )
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                profiler.record_query(
                    sql=f"FAILED: {func.__name__}",
                    execution_time=execution_time
                )
                raise
                
        return wrapper
    return decorator

def register_sqlalchemy_profiler(engine: Engine, profiler: QueryProfiler):
    """Register SQLAlchemy event listeners for query profiling."""
    
    # Store query start times per connection
    query_start_times = {}
    
    @event.listens_for(engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Record query start time."""
        conn.info.setdefault('query_start_time', []).append(time.time())
        
    @event.listens_for(engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Record query completion and profile."""
        try:
            start_time = conn.info['query_start_time'].pop(-1)
            execution_time = time.time() - start_time
            
            # Record the query
            profiler.record_query(
                sql=statement,
                execution_time=execution_time,
                parameters=parameters if not executemany else None
            )
            
        except (KeyError, IndexError):
            # Handle missing start time
            pass
            
    logger.info("SQLAlchemy query profiler registered")

# Global profiler instance
global_profiler = QueryProfiler(max_queries=10000)