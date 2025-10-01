"""
Database Connection Pool for HomeNetMon
Provides efficient connection reuse and prevents connection exhaustion
"""

import sqlite3
import threading
import time
from queue import Queue, Empty
from contextlib import contextmanager
from datetime import datetime

class DatabaseConnectionPool:
    """Thread-safe SQLite connection pool"""

    def __init__(self, database_path, max_connections=10, timeout=30):
        self.database_path = database_path
        self.max_connections = max_connections
        self.timeout = timeout
        self.pool = Queue(maxsize=max_connections)
        self.created_connections = 0
        self.lock = threading.Lock()

        # Pre-create initial connections
        for _ in range(min(3, max_connections)):
            self._create_connection()

    def _create_connection(self):
        """Create a new database connection"""
        try:
            conn = sqlite3.connect(
                self.database_path,
                timeout=self.timeout,
                check_same_thread=False
            )
            # Optimize SQLite for performance
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.row_factory = sqlite3.Row

            self.pool.put(conn)
            self.created_connections += 1
            return True
        except Exception as e:
            print(f"Error creating database connection: {e}")
            return False

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            # Try to get existing connection
            try:
                conn = self.pool.get(timeout=5)
            except Empty:
                # Create new connection if pool is empty and under limit
                with self.lock:
                    if self.created_connections < self.max_connections:
                        if self._create_connection():
                            conn = self.pool.get(timeout=1)

                if conn is None:
                    raise Exception("No database connections available")

            # Test connection is still valid
            conn.execute('SELECT 1')
            yield conn

        except Exception as e:
            # If connection is broken, don't return it to pool
            if conn:
                try:
                    conn.close()
                except:
                    pass
                conn = None
            raise e
        finally:
            # Return connection to pool
            if conn:
                try:
                    conn.rollback()  # Ensure clean state
                    self.pool.put(conn, timeout=1)
                except:
                    # If can't return to pool, close it
                    try:
                        conn.close()
                    except:
                        pass
                    # Create replacement connection
                    self._create_connection()

    def close_all(self):
        """Close all connections in the pool"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except:
                pass

# Global connection pool instance
_connection_pool = None

def get_connection_pool(database_path=None):
    """Get or create the global connection pool"""
    global _connection_pool
    if _connection_pool is None and database_path:
        _connection_pool = DatabaseConnectionPool(database_path)
    return _connection_pool

@contextmanager
def get_db_connection(database_path=None):
    """Context manager for getting database connections"""
    pool = get_connection_pool(database_path)
    if pool:
        with pool.get_connection() as conn:
            yield conn
    else:
        # Fallback to direct connection
        conn = sqlite3.connect(database_path or 'homeNetMon.db')
        try:
            yield conn
        finally:
            conn.close()
