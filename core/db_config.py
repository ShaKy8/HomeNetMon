"""
Optimized database configuration with connection pooling and performance settings.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
from sqlalchemy import create_engine, event, pool
from sqlalchemy.engine import Engine
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import time

logger = logging.getLogger(__name__)

class DatabaseConfig:
    """Database configuration with optimized settings."""
    
    # Default connection pool settings
    POOL_SIZE = 10  # Number of connections to maintain in pool
    MAX_OVERFLOW = 20  # Maximum overflow connections above pool_size
    POOL_TIMEOUT = 30  # Seconds to wait before timing out
    POOL_RECYCLE = 3600  # Recycle connections after 1 hour
    POOL_PRE_PING = True  # Test connections before using them
    
    # Query performance settings
    ECHO = False  # Set to True for SQL debugging
    ECHO_POOL = False  # Set to True for connection pool debugging
    
    # SQLite-specific optimizations
    SQLITE_PRAGMAS = {
        'journal_mode': 'WAL',  # Write-Ahead Logging for better concurrency
        'cache_size': -64000,  # 64MB cache
        'foreign_keys': 1,  # Enable foreign key constraints
        'synchronous': 'NORMAL',  # Balance between safety and speed
        'temp_store': 'MEMORY',  # Use memory for temporary tables
        'mmap_size': 268435456,  # 256MB memory-mapped I/O
        'page_size': 4096,  # Optimize page size
        'optimize': True  # Run OPTIMIZE on connection
    }
    
    @classmethod
    def get_database_uri(cls, database_path: Optional[str] = None) -> str:
        """Get database URI with appropriate settings."""
        if database_path is None:
            database_path = os.environ.get('DATABASE_PATH', 'homeNetMon.db')
            
        # Check if using PostgreSQL or MySQL
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            # Production database (PostgreSQL/MySQL)
            return database_url
            
        # Default to SQLite for development
        return f'sqlite:///{database_path}'
        
    @classmethod
    def configure_app(cls, app: Flask, database_uri: Optional[str] = None) -> None:
        """Configure Flask app with optimized database settings."""
        
        uri = database_uri or cls.get_database_uri()
        
        # Base configuration
        app.config['SQLALCHEMY_DATABASE_URI'] = uri
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SQLALCHEMY_ECHO'] = cls.ECHO
        
        # Determine database type
        if 'postgresql' in uri or 'postgres' in uri:
            cls._configure_postgresql(app)
        elif 'mysql' in uri:
            cls._configure_mysql(app)
        else:
            cls._configure_sqlite(app)
            
    @classmethod
    def _configure_postgresql(cls, app: Flask) -> None:
        """Configure PostgreSQL-specific settings."""
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': cls.POOL_SIZE,
            'max_overflow': cls.MAX_OVERFLOW,
            'pool_timeout': cls.POOL_TIMEOUT,
            'pool_recycle': cls.POOL_RECYCLE,
            'pool_pre_ping': cls.POOL_PRE_PING,
            'echo_pool': cls.ECHO_POOL,
            'connect_args': {
                'connect_timeout': 10,
                'options': '-c statement_timeout=30000'  # 30 second statement timeout
            }
        }
        logger.info("Configured PostgreSQL connection pooling")
        
    @classmethod
    def _configure_mysql(cls, app: Flask) -> None:
        """Configure MySQL-specific settings."""
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': cls.POOL_SIZE,
            'max_overflow': cls.MAX_OVERFLOW,
            'pool_timeout': cls.POOL_TIMEOUT,
            'pool_recycle': cls.POOL_RECYCLE,
            'pool_pre_ping': cls.POOL_PRE_PING,
            'echo_pool': cls.ECHO_POOL,
            'connect_args': {
                'connect_timeout': 10,
                'read_timeout': 30,
                'write_timeout': 30
            }
        }
        logger.info("Configured MySQL connection pooling")
        
    @classmethod
    def _configure_sqlite(cls, app: Flask) -> None:
        """Configure SQLite-specific settings."""
        # SQLite doesn't benefit from connection pooling in the same way
        # but we can optimize it with pragmas
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'poolclass': pool.StaticPool,  # Use StaticPool for SQLite
            'connect_args': {
                'check_same_thread': False,  # Allow multiple threads
                'timeout': 30  # 30 second busy timeout
            }
        }
        logger.info("Configured SQLite with optimizations")
        
    @classmethod
    def register_event_listeners(cls, db: SQLAlchemy) -> None:
        """Register database event listeners for optimization."""
        
        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            """Set SQLite pragmas on connection."""
            # Only apply to SQLite connections
            if 'sqlite' in str(dbapi_conn.__class__).lower():
                cursor = dbapi_conn.cursor()
                
                # Apply pragmas
                for pragma, value in cls.SQLITE_PRAGMAS.items():
                    if pragma == 'optimize':
                        cursor.execute('PRAGMA optimize')
                    else:
                        cursor.execute(f'PRAGMA {pragma} = {value}')
                        
                cursor.close()
                logger.debug("Applied SQLite optimization pragmas")
                
        @event.listens_for(Engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log slow query warnings."""
            conn.info.setdefault('query_start_time', []).append(time.time())
            
        @event.listens_for(Engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Check query execution time."""
            total = time.time() - conn.info['query_start_time'].pop(-1)
            
            # Log slow queries (>1 second)
            if total > 1.0:
                logger.warning(f"Slow query detected ({total:.2f}s): {statement[:100]}...")
                
                
class ConnectionPoolMonitor:
    """Monitor database connection pool health."""
    
    def __init__(self, db: SQLAlchemy):
        self.db = db
        self.metrics = {
            'connections_created': 0,
            'connections_closed': 0,
            'connection_errors': 0,
            'slow_queries': 0,
            'total_queries': 0
        }
        
    def get_pool_status(self) -> Dict[str, Any]:
        """Get current connection pool status."""
        engine = self.db.engine
        pool = engine.pool
        
        return {
            'size': pool.size() if hasattr(pool, 'size') else 0,
            'checked_in': pool.checkedin() if hasattr(pool, 'checkedin') else 0,
            'checked_out': pool.checkedout() if hasattr(pool, 'checkedout') else 0,
            'overflow': pool.overflow() if hasattr(pool, 'overflow') else 0,
            'total': pool.size() + pool.overflow() if hasattr(pool, 'size') else 0
        }
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get connection pool metrics."""
        return {
            **self.metrics,
            'pool_status': self.get_pool_status()
        }
        
    def check_health(self) -> Tuple[bool, str]:
        """Check connection pool health."""
        try:
            # Test database connection
            self.db.session.execute('SELECT 1')
            
            # Check pool status
            status = self.get_pool_status()
            
            # Check if pool is exhausted
            if status['checked_out'] >= status['size']:
                if status['overflow'] >= 10:  # High overflow usage
                    return False, "Connection pool near exhaustion"
                    
            return True, "Connection pool healthy"
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            self.metrics['connection_errors'] += 1
            return False, f"Database error: {str(e)}"
            
            
class DatabaseOptimizer:
    """Automated database optimization tasks."""
    
    def __init__(self, db: SQLAlchemy):
        self.db = db
        
    def vacuum_database(self) -> bool:
        """Run VACUUM to reclaim space (SQLite only)."""
        try:
            from sqlalchemy import text
            
            if 'sqlite' in str(self.db.engine.url):
                self.db.session.execute(text('VACUUM'))
                self.db.session.commit()
                logger.info("Database VACUUM completed")
                return True
            return False
            
        except Exception as e:
            logger.error(f"VACUUM failed: {e}")
            return False
            
    def analyze_database(self) -> bool:
        """Update database statistics for query planner."""
        try:
            from sqlalchemy import text
            
            if 'sqlite' in str(self.db.engine.url):
                self.db.session.execute(text('ANALYZE'))
            elif 'postgresql' in str(self.db.engine.url):
                self.db.session.execute(text('ANALYZE'))
            elif 'mysql' in str(self.db.engine.url):
                # MySQL updates statistics automatically
                pass
                
            self.db.session.commit()
            logger.info("Database statistics updated")
            return True
            
        except Exception as e:
            logger.error(f"ANALYZE failed: {e}")
            return False
            
    def optimize_tables(self) -> bool:
        """Optimize tables for better performance."""
        try:
            if 'mysql' in str(self.db.engine.url):
                tables = ['devices', 'monitoring_data', 'alerts']
                for table in tables:
                    self.db.session.execute(f'OPTIMIZE TABLE {table}')
                self.db.session.commit()
                logger.info(f"Optimized {len(tables)} tables")
                return True
                
            elif 'sqlite' in str(self.db.engine.url):
                self.db.session.execute('PRAGMA optimize')
                self.db.session.commit()
                logger.info("SQLite optimization completed")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Table optimization failed: {e}")
            return False