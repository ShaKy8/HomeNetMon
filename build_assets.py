#!/usr/bin/env python3
"""
Frontend Asset Bundler and Minifier for HomeNetMon
Combines and minifies JavaScript and CSS files for production deployment.
"""

import os
import re
import gzip
import shutil
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Any
import json

logger = logging.getLogger(__name__)


class AssetBundler:
    """Bundles and minifies frontend assets."""
    
    def __init__(self, static_dir: str = 'static'):
        self.static_dir = Path(static_dir)
        self.bundles_dir = self.static_dir / 'bundles'
        self.bundles_dir.mkdir(exist_ok=True)
        
        # Asset configurations
        self.js_bundles = {
            'core.js': [
                'js/app.js',
                'js/real-time-updates.js',
                'js/csrf-handler.js',
                'js/html-sanitizer.js'
            ],
            'dashboard.js': [
                'js/dashboard.js',
                'js/lazy-loader.js'
            ],
            'topology.js': [
                'js/network-topology.js'
            ]
        }
        
        self.css_bundles = {
            'core.css': [
                'css/dashboard.css'  # Add more CSS files as needed
            ],
            'dashboard.css': [
                'css/dashboard.css'
            ]
        }
        
        # Asset manifest for cache busting
        self.manifest = {}
        
        logger.info(f"Asset Bundler initialized for {static_dir}")
    
    def minify_js(self, content: str) -> str:
        """Simple JavaScript minification."""
        
        # Remove comments
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)  # Multi-line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)  # Single-line comments
        
        # Remove extra whitespace
        content = re.sub(r'\s+', ' ', content)  # Multiple spaces to single
        content = re.sub(r';\s*}', '}', content)  # Semicolon before closing brace
        content = re.sub(r'{\s*', '{', content)  # Space after opening brace
        content = re.sub(r'}\s*', '}', content)  # Space after closing brace
        content = re.sub(r';\s*', ';', content)  # Space after semicolon
        
        return content.strip()
    
    def minify_css(self, content: str) -> str:
        """Simple CSS minification."""
        
        # Remove comments
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        
        # Remove extra whitespace
        content = re.sub(r'\s+', ' ', content)  # Multiple spaces to single
        content = re.sub(r';\s*}', '}', content)  # Semicolon before closing brace
        content = re.sub(r'{\s*', '{', content)  # Space after opening brace
        content = re.sub(r'}\s*', '}', content)  # Space after closing brace
        content = re.sub(r';\s*', ';', content)  # Space after semicolon
        content = re.sub(r':\s*', ':', content)  # Space after colon
        
        return content.strip()
    
    def bundle_js_files(self, bundle_name: str, files: List[str]) -> Tuple[str, int]:
        """Bundle and minify JavaScript files."""
        
        bundled_content = [f"/* {bundle_name} - Generated bundle */"]
        original_size = 0
        
        for file_path in files:
            full_path = self.static_dir / file_path
            
            if not full_path.exists():
                logger.warning(f"JavaScript file not found: {full_path}")
                continue
            
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    original_size += len(content)
                
                # Add file separator comment
                bundled_content.append(f"\n/* === {file_path} === */")
                bundled_content.append(content)
                
            except Exception as e:
                logger.error(f"Error reading {full_path}: {e}")
        
        # Combine and minify
        combined = '\n'.join(bundled_content)
        minified = self.minify_js(combined)
        
        # Write bundle
        bundle_path = self.bundles_dir / bundle_name
        with open(bundle_path, 'w', encoding='utf-8') as f:
            f.write(minified)
        
        # Create gzip version
        with open(bundle_path, 'rb') as f_in:
            with gzip.open(f"{bundle_path}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        logger.info(f"Bundled {bundle_name}: {original_size:,} -> {len(minified):,} bytes ({len(minified)/original_size*100:.1f}%)")
        
        return minified, original_size
    
    def bundle_css_files(self, bundle_name: str, files: List[str]) -> Tuple[str, int]:
        """Bundle and minify CSS files."""
        
        bundled_content = [f"/* {bundle_name} - Generated bundle */"]
        original_size = 0
        
        for file_path in files:
            full_path = self.static_dir / file_path
            
            if not full_path.exists():
                logger.warning(f"CSS file not found: {full_path}")
                continue
            
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    original_size += len(content)
                
                # Add file separator comment
                bundled_content.append(f"\n/* === {file_path} === */")
                bundled_content.append(content)
                
            except Exception as e:
                logger.error(f"Error reading {full_path}: {e}")
        
        # Combine and minify
        combined = '\n'.join(bundled_content)
        minified = self.minify_css(combined)
        
        # Write bundle
        bundle_path = self.bundles_dir / bundle_name
        with open(bundle_path, 'w', encoding='utf-8') as f:
            f.write(minified)
        
        # Create gzip version
        with open(bundle_path, 'rb') as f_in:
            with gzip.open(f"{bundle_path}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        logger.info(f"Bundled {bundle_name}: {original_size:,} -> {len(minified):,} bytes ({len(minified)/original_size*100:.1f}%)")
        
        return minified, original_size
    
    def generate_content_hash(self, content: str) -> str:
        """Generate content hash for cache busting."""
        return hashlib.md5(content.encode('utf-8')).hexdigest()[:8]
    
    def build_all_bundles(self) -> Dict[str, Any]:
        """Build all JavaScript and CSS bundles."""
        
        logger.info("Building all asset bundles...")
        
        build_stats = {
            'bundles_created': 0,
            'total_original_size': 0,
            'total_minified_size': 0,
            'bundles': {}
        }
        
        # Build JavaScript bundles
        for bundle_name, files in self.js_bundles.items():
            try:
                minified_content, original_size = self.bundle_js_files(bundle_name, files)
                content_hash = self.generate_content_hash(minified_content)
                
                build_stats['bundles'][bundle_name] = {
                    'type': 'javascript',
                    'files': files,
                    'original_size': original_size,
                    'minified_size': len(minified_content),
                    'compression_ratio': len(minified_content) / original_size if original_size > 0 else 0,
                    'hash': content_hash
                }
                
                # Update manifest
                self.manifest[bundle_name] = {
                    'file': f'bundles/{bundle_name}',
                    'hash': content_hash
                }
                
                build_stats['bundles_created'] += 1
                build_stats['total_original_size'] += original_size
                build_stats['total_minified_size'] += len(minified_content)
                
            except Exception as e:
                logger.error(f"Error building JS bundle {bundle_name}: {e}")
        
        # Build CSS bundles
        for bundle_name, files in self.css_bundles.items():
            try:
                minified_content, original_size = self.bundle_css_files(bundle_name, files)
                content_hash = self.generate_content_hash(minified_content)
                
                build_stats['bundles'][bundle_name] = {
                    'type': 'stylesheet',
                    'files': files,
                    'original_size': original_size,
                    'minified_size': len(minified_content),
                    'compression_ratio': len(minified_content) / original_size if original_size > 0 else 0,
                    'hash': content_hash
                }
                
                # Update manifest
                self.manifest[bundle_name] = {
                    'file': f'bundles/{bundle_name}',
                    'hash': content_hash
                }
                
                build_stats['bundles_created'] += 1
                build_stats['total_original_size'] += original_size
                build_stats['total_minified_size'] += len(minified_content)
                
            except Exception as e:
                logger.error(f"Error building CSS bundle {bundle_name}: {e}")
        
        # Save manifest file
        manifest_path = self.static_dir / 'manifest.json'
        with open(manifest_path, 'w') as f:
            json.dump(self.manifest, f, indent=2)
        
        # Calculate total compression
        if build_stats['total_original_size'] > 0:
            total_compression = (build_stats['total_minified_size'] / build_stats['total_original_size']) * 100
            build_stats['total_compression_ratio'] = total_compression
        else:
            build_stats['total_compression_ratio'] = 0
        
        logger.info(f"Asset bundling complete:")
        logger.info(f"  - {build_stats['bundles_created']} bundles created")
        logger.info(f"  - {build_stats['total_original_size']:,} -> {build_stats['total_minified_size']:,} bytes")
        logger.info(f"  - {build_stats['total_compression_ratio']:.1f}% of original size")
        
        return build_stats
    
    def clean_old_bundles(self):
        """Clean up old bundle files."""
        
        if not self.bundles_dir.exists():
            return
        
        # Remove all files in bundles directory
        for file_path in self.bundles_dir.iterdir():
            if file_path.is_file():
                file_path.unlink()
                logger.debug(f"Removed old bundle: {file_path}")
        
        logger.info("Cleaned up old bundles")


def optimize_static_assets(static_dir: str = 'static') -> Dict[str, Any]:
    """Optimize static assets for production."""
    
    bundler = AssetBundler(static_dir)
    
    # Clean old bundles
    bundler.clean_old_bundles()
    
    # Build new bundles
    build_stats = bundler.build_all_bundles()
    
    return build_stats


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("HomeNetMon Asset Bundler and Minifier")
    print("=====================================")
    
    # Check if static directory exists
    static_dir = Path('static')
    if not static_dir.exists():
        print(f"Error: Static directory '{static_dir}' not found!")
        exit(1)
    
    # Run optimization
    try:
        stats = optimize_static_assets('static')
        
        print(f"\nBuild Summary:")
        print(f"- {stats['bundles_created']} bundles created")
        print(f"- {stats['total_original_size']:,} bytes -> {stats['total_minified_size']:,} bytes")
        print(f"- {stats['total_compression_ratio']:.1f}% compression achieved")
        
        print(f"\nBundle Details:")
        for bundle_name, bundle_info in stats['bundles'].items():
            print(f"  {bundle_name}:")
            print(f"    - Type: {bundle_info['type']}")
            print(f"    - Files: {len(bundle_info['files'])}")
            print(f"    - Size: {bundle_info['original_size']:,} -> {bundle_info['minified_size']:,} bytes")
            print(f"    - Compression: {bundle_info['compression_ratio']*100:.1f}%")
        
        print(f"\nAsset optimization complete!")
        print(f"Your HomeNetMon application will now load much faster.")
        
    except Exception as e:
        print(f"Error during asset optimization: {e}")
        exit(1)