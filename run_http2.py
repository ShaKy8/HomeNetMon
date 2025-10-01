#!/usr/bin/env python3
"""
HTTP/2 Production Server for HomeNetMon
Runs the application with HTTP/2 support using Hypercorn.
"""

import os
import sys
import asyncio
import logging
from hypercorn.config import Config as HypercornConfig
from hypercorn.asyncio import serve
from hypercorn.middleware import HTTPToHTTPSRedirectMiddleware

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def create_hypercorn_config():
    """Create Hypercorn configuration for HTTP/2 support."""
    config = HypercornConfig()
    
    # Server binding
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    config.bind = [f"{host}:{port}"]
    
    # Enable HTTP/2 and HTTP/3
    config.alpn_protocols = ['h2', 'http/1.1']  # HTTP/2 preferred
    config.h2_max_concurrent_streams = 100
    config.h2_max_header_list_size = 65536
    config.h2_max_frame_size = 16384
    
    # Performance settings
    config.worker_class = 'asyncio'
    config.workers = 1  # Single worker for home network monitoring
    config.max_requests = 10000
    config.max_requests_jitter = 1000
    config.backlog = 2048
    config.keep_alive = 30
    
    # Compression
    config.compress = True
    config.compress_minimum_size = 500
    
    # Security headers
    config.server_names = ['homeNetMon']
    
    # Logging
    config.loglevel = os.environ.get('LOG_LEVEL', 'INFO')
    config.errorlog = '-'  # stdout
    config.accesslog = '-'  # stdout
    
    # SSL/TLS (if certificates are available)
    cert_file = os.environ.get('SSL_CERT_FILE')
    key_file = os.environ.get('SSL_KEY_FILE')
    
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        config.certfile = cert_file
        config.keyfile = key_file
        config.alpn_protocols = ['h2', 'http/1.1']  # HTTP/2 over TLS
        logging.info(f"HTTPS enabled with HTTP/2 support")
    else:
        logging.info("HTTP/2 over cleartext (h2c) - For production, use HTTPS")
    
    return config

async def main():
    """Main server function."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting HomeNetMon with HTTP/2 support")
    
    # Create Flask app
    app, socketio = create_app()
    
    # Create Hypercorn config
    config = create_hypercorn_config()
    
    # Performance optimization environment variables
    os.environ['ENV'] = 'production'
    os.environ['DEBUG'] = 'false'
    
    logger.info(f"Server starting on {config.bind[0]} with HTTP/2 support")
    logger.info(f"Compression: {config.compress}")
    logger.info(f"HTTP/2 Max Concurrent Streams: {config.h2_max_concurrent_streams}")
    logger.info(f"Keep-Alive Timeout: {config.keep_alive}s")
    
    # Start the server
    try:
        await serve(app, config)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)