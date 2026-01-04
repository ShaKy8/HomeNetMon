"""
Database Connection Pool for HomeNetMon
Provides efficient connection reuse and prevents connection exhaustion
"""

import logging
import sqlite3
import threading
import time
from queue import Queue, Empty, Full
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)

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
        except sqlite3.Error as e:
            logger.error(f"SQLite error creating database connection: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error creating database connection: {e}")
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
                except sqlite3.Error as close_error:
                    logger.warning(f"Error closing broken connection: {close_error}")
                except Exception as close_error:
                    logger.warning(f"Unexpected error closing broken connection: {close_error}")
                conn = None
            raise e
        finally:
            # Return connection to pool
            if conn:
                try:
                    conn.rollback()  # Ensure clean state
                    self.pool.put(conn, timeout=1)
                except Full as e:
                    # Pool is full, close the connection
                    logger.warning(f"Connection pool full, closing connection: {e}")
                    try:
                        conn.close()
                    except sqlite3.Error as close_error:
                        logger.warning(f"Error closing connection when pool full: {close_error}")
                    except Exception as close_error:
                        logger.warning(f"Unexpected error closing connection: {close_error}")
                    # Create replacement connection
                    self._create_connection()
                except Exception as e:
                    # If can't return to pool, close it
                    logger.warning(f"Error returning connection to pool: {e}")
                    try:
                        conn.close()
                    except sqlite3.Error as close_error:
                        logger.warning(f"Error closing connection after pool error: {close_error}")
                    except Exception as close_error:
                        logger.warning(f"Unexpected error closing connection: {close_error}")
                    # Create replacement connection
                    self._create_connection()

    def close_all(self):
        """Close all connections in the pool"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except Empty:
                # Pool is empty, nothing more to close
                break
            except sqlite3.Error as e:
                logger.warning(f"Error closing connection during pool shutdown: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error during pool shutdown: {e}")

# Global connection pool instance and lock for thread-safe initialization
_connection_pool = None
_pool_init_lock = threading.Lock()

def get_connection_pool(database_path=None):
    """Get or create the global connection pool with thread-safe initialization"""
    global _connection_pool

    # Fast path: pool already exists
    if _connection_pool is not None:
        return _connection_pool

    # Slow path: need to create pool with double-checked locking
    if database_path:
        with _pool_init_lock:
            # Double-check after acquiring lock
            if _connection_pool is None:
                _connection_pool = DatabaseConnectionPool(database_path)
                logger.info(f"Database connection pool initialized for {database_path}")

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
