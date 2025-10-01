#!/usr/bin/env python3
"""
CDN Manager Service
Manages CDN configuration and asset delivery optimization.
"""

import os
import logging
from typing import Dict, List, Optional
from flask import current_app, url_for, request
from urllib.parse import urljoin
import hashlib
import time

logger = logging.getLogger(__name__)

class CDNManager:
    """
    CDN Manager for optimizing static asset delivery.
    Supports multiple CDN providers and fallback strategies.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.cdn_enabled = False
        self.cdn_domain = None
        self.fallback_enabled = True
        self.asset_versions = {}
        self.cached_urls = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize CDN manager with Flask app."""
        self.app = app
        
        # Load CDN configuration from environment
        self.cdn_enabled = os.environ.get('CDN_ENABLED', 'false').lower() == 'true'
        self.cdn_domain = os.environ.get('CDN_DOMAIN', '')
        self.fallback_enabled = os.environ.get('CDN_FALLBACK_ENABLED', 'true').lower() == 'true'
        
        # Configure popular CDN services
        self.configure_cdn_services()
        
        # Pre-calculate asset versions for cache busting
        self.calculate_asset_versions()
        
        # Register template globals
        app.jinja_env.globals['cdn_url'] = self.get_cdn_url
        app.jinja_env.globals['versioned_url'] = self.get_versioned_url
        
        if self.cdn_enabled:
            logger.info(f"CDN enabled with domain: {self.cdn_domain}")
        else:
            logger.info("CDN disabled - using local asset delivery")
    
    def configure_cdn_services(self):
        """Configure popular CDN services with their endpoints."""
        self.cdn_services = {
            'jsdelivr': {
                'domain': 'cdn.jsdelivr.net',
                'url_pattern': 'https://cdn.jsdelivr.net/npm/{package}@{version}/{path}',
                'supports_compression': True,
                'global_pops': True
            },
            'unpkg': {
                'domain': 'unpkg.com',
                'url_pattern': 'https://unpkg.com/{package}@{version}/{path}',
                'supports_compression': True,
                'global_pops': True
            },
            'cdnjs': {
                'domain': 'cdnjs.cloudflare.com',
                'url_pattern': 'https://cdnjs.cloudflare.com/ajax/libs/{package}/{version}/{path}',
                'supports_compression': True,
                'global_pops': True
            }
        }
    
    def calculate_asset_versions(self):
        """Pre-calculate version hashes for all static assets."""
        static_folder = os.path.join(os.getcwd(), 'static')
        
        if not os.path.exists(static_folder):
            return
        
        for root, dirs, files in os.walk(static_folder):
            for file in files:
                if file.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico')):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, static_folder)
                    
                    try:
                        # Calculate file hash for versioning
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.md5(f.read()).hexdigest()[:8]
                        
                        self.asset_versions[relative_path] = file_hash
                    except Exception as e:
                        logger.warning(f"Could not calculate version for {relative_path}: {e}")
    
    def get_cdn_url(self, filename: str, external_service: Optional[str] = None) -> str:
        """
        Get CDN URL for a static asset with fallback support.
        
        Args:
            filename: Static file path (e.g., 'bundles/core.js')
            external_service: Use external CDN service (jsdelivr, unpkg, cdnjs)
            
        Returns:
            Optimized CDN URL or local fallback URL
        """
        
        # Check cache first
        cache_key = f"{filename}:{external_service or 'local'}"
        if cache_key in self.cached_urls:
            return self.cached_urls[cache_key]
        
        # Use external CDN service if specified
        if external_service and external_service in self.cdn_services:
            cdn_url = self._get_external_cdn_url(filename, external_service)
            if cdn_url:
                self.cached_urls[cache_key] = cdn_url
                return cdn_url
        
        # Use configured CDN domain
        if self.cdn_enabled and self.cdn_domain:
            cdn_url = self._get_custom_cdn_url(filename)
            self.cached_urls[cache_key] = cdn_url
            return cdn_url
        
        # Fallback to local versioned URL
        local_url = self.get_versioned_url(filename)
        self.cached_urls[cache_key] = local_url
        return local_url
    
    def get_versioned_url(self, filename: str) -> str:
        """
        Get versioned local URL for cache busting.
        
        Args:
            filename: Static file path
            
        Returns:
            Versioned local URL
        """
        base_url = url_for('static', filename=filename)
        
        # Add version parameter for cache busting
        version = self.asset_versions.get(filename, int(time.time()))
        versioned_url = f"{base_url}?v={version}"
        
        return versioned_url
    
    def _get_custom_cdn_url(self, filename: str) -> str:
        """Get URL from custom CDN domain."""
        version = self.asset_versions.get(filename, int(time.time()))
        
        # Ensure CDN domain has proper protocol
        if not self.cdn_domain.startswith(('http://', 'https://')):
            cdn_domain = f"https://{self.cdn_domain}"
        else:
            cdn_domain = self.cdn_domain
        
        # Build CDN URL
        cdn_url = urljoin(cdn_domain, f"/static/{filename}?v={version}")
        return cdn_url
    
    def _get_external_cdn_url(self, filename: str, service: str) -> Optional[str]:
        """
        Get URL from external CDN service.
        
        This would be used for common libraries like Bootstrap, jQuery, etc.
        For now, returns None to use local assets for security and reliability.
        """
        
        # Map common assets to CDN packages
        cdn_mappings = {
            'bootstrap@5.3.0/dist/css/bootstrap.min.css': 'css/bootstrap.min.css',
            'bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js': 'js/bootstrap.bundle.min.js',
            'bootstrap-icons@1.10.0/font/bootstrap-icons.css': 'css/bootstrap-icons.css'
        }
        
        # For security and reliability, prefer local assets
        # This can be enhanced in the future if needed
        return None
    
    def get_preload_hints(self) -> List[Dict[str, str]]:
        """
        Get resource preload hints for critical assets.
        
        Returns:
            List of preload hint dictionaries
        """
        critical_assets = [
            {'href': self.get_cdn_url('bundles/core.css'), 'as': 'style', 'type': 'text/css'},
            {'href': self.get_cdn_url('bundles/core.js'), 'as': 'script', 'type': 'application/javascript'},
            {'href': self.get_cdn_url('icons/icon-192x192.png'), 'as': 'image', 'type': 'image/png'}
        ]
        
        return critical_assets
    
    def get_dns_prefetch_hints(self) -> List[str]:
        """
        Get DNS prefetch hints for external domains.
        
        Returns:
            List of domains to prefetch
        """
        prefetch_domains = []
        
        if self.cdn_enabled and self.cdn_domain:
            # Extract domain from CDN URL
            if self.cdn_domain.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(self.cdn_domain)
                prefetch_domains.append(parsed.netloc)
            else:
                prefetch_domains.append(self.cdn_domain)
        
        # Always prefetch external service domains for fallback
        prefetch_domains.extend([
            'cdn.jsdelivr.net',
            'cdn.socket.io'
        ])
        
        return prefetch_domains
    
    def invalidate_cache(self, pattern: Optional[str] = None):
        """
        Invalidate CDN cache for assets.
        
        Args:
            pattern: Optional pattern to match assets (e.g., '*.css')
        """
        if pattern:
            # Clear specific cached URLs
            keys_to_remove = [key for key in self.cached_urls if pattern in key]
            for key in keys_to_remove:
                del self.cached_urls[key]
        else:
            # Clear all cached URLs
            self.cached_urls.clear()
        
        # Recalculate asset versions
        self.calculate_asset_versions()
        
        logger.info(f"CDN cache invalidated for pattern: {pattern or 'all'}")
    
    def get_cache_headers(self, filename: str) -> Dict[str, str]:
        """
        Get appropriate cache headers for static assets.
        
        Args:
            filename: Static file name
            
        Returns:
            Dictionary of cache headers
        """
        file_ext = filename.lower().split('.')[-1]
        
        if file_ext in ['css', 'js']:
            # CSS/JS files - long cache with versioning
            return {
                'Cache-Control': 'public, max-age=31536000, immutable',
                'Expires': 'Thu, 31 Dec 2025 23:59:59 GMT'
            }
        elif file_ext in ['png', 'jpg', 'jpeg', 'gif', 'svg', 'ico']:
            # Images - moderate cache
            return {
                'Cache-Control': 'public, max-age=2592000',  # 30 days
                'Expires': 'Wed, 01 Oct 2025 23:59:59 GMT'
            }
        else:
            # Other files - short cache
            return {
                'Cache-Control': 'public, max-age=86400'  # 1 day
            }
    
    def optimize_delivery(self, request_headers: Dict[str, str]) -> Dict[str, str]:
        """
        Optimize asset delivery based on client capabilities.
        
        Args:
            request_headers: Client request headers
            
        Returns:
            Optimization recommendations
        """
        optimizations = {
            'compression': 'gzip',  # Default compression
            'format': 'original'    # Default format
        }
        
        # Check Accept-Encoding for compression support
        accept_encoding = request_headers.get('Accept-Encoding', '').lower()
        if 'br' in accept_encoding:
            optimizations['compression'] = 'brotli'
        elif 'gzip' in accept_encoding:
            optimizations['compression'] = 'gzip'
        
        # Check Accept header for image format optimization
        accept_header = request_headers.get('Accept', '').lower()
        if 'image/webp' in accept_header:
            optimizations['image_format'] = 'webp'
        elif 'image/avif' in accept_header:
            optimizations['image_format'] = 'avif'
        
        return optimizations


# Global CDN manager instance
cdn_manager = CDNManager()


def setup_cdn_routes(app):
    """Set up CDN-related routes."""
    
    @app.route('/cdn/invalidate', methods=['POST'])
    def invalidate_cdn_cache():
        """Endpoint to invalidate CDN cache."""
        from flask import request, jsonify
        
        data = request.get_json() or {}
        pattern = data.get('pattern')
        
        cdn_manager.invalidate_cache(pattern)
        
        return jsonify({
            'success': True,
            'message': f'CDN cache invalidated for pattern: {pattern or "all"}'
        })
    
    @app.route('/cdn/status', methods=['GET'])
    def get_cdn_status():
        """Get CDN configuration status."""
        from flask import jsonify
        
        return jsonify({
            'enabled': cdn_manager.cdn_enabled,
            'domain': cdn_manager.cdn_domain,
            'fallback_enabled': cdn_manager.fallback_enabled,
            'asset_count': len(cdn_manager.asset_versions),
            'cached_urls': len(cdn_manager.cached_urls)
        })