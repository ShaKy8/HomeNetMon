# Optimized configuration for maximum performance
import os

class OptimizedConfig:
    # Database optimizations
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_MAX_OVERFLOW = 40
    SQLALCHEMY_POOL_TIMEOUT = 30
    SQLALCHEMY_POOL_RECYCLE = 3600
    SQLALCHEMY_POOL_PRE_PING = True
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 40,
        'pool_timeout': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'connect_args': {
            'timeout': 20,
            'check_same_thread': False,
            'isolation_level': None  # Autocommit mode for reads
        }
    }
    
    # Cache configuration  
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year for static files
    
    # Response compression
    COMPRESS_MIMETYPES = ['text/html', 'text/css', 'text/javascript', 'application/json']
    COMPRESS_LEVEL = 6
    COMPRESS_MIN_SIZE = 1000
