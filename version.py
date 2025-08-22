"""
HomeNetMon Version Management

Central version tracking and system information for HomeNetMon.
"""

import sys
import platform
import psutil
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

# Semantic Versioning for HomeNetMon
VERSION_MAJOR = 2
VERSION_MINOR = 3  
VERSION_PATCH = 2
VERSION_BUILD = "stable"

# Build information (fallback values when Git is not available)
BUILD_DATE = "2025-08-22"
BUILD_AUTHOR = "Envisioned & Designed by ShaKy8 • Coded by Claude Code"

# Git repository information
def get_git_info() -> Dict[str, Any]:
    """Get Git repository information including commit hash, branch, and tag info"""
    git_info = {
        'commit_hash': None,
        'commit_short': None,
        'branch': None,
        'tag': None,
        'is_dirty': False,
        'commit_date': None,
        'commit_author': None,
        'available': False
    }
    
    try:
        # Check if we're in a git repository
        subprocess.run(['git', 'rev-parse', '--git-dir'], 
                      capture_output=True, check=True, timeout=5)
        git_info['available'] = True
        
        # Get commit hash
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                              capture_output=True, text=True, check=True, timeout=5)
        git_info['commit_hash'] = result.stdout.strip()
        git_info['commit_short'] = git_info['commit_hash'][:8] if git_info['commit_hash'] else None
        
        # Get current branch
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True, check=True, timeout=5)
        git_info['branch'] = result.stdout.strip() or None
        
        # Get latest tag (if any)
        try:
            result = subprocess.run(['git', 'describe', '--tags', '--exact-match', 'HEAD'], 
                                  capture_output=True, text=True, check=True, timeout=5)
            git_info['tag'] = result.stdout.strip()
        except subprocess.CalledProcessError:
            # Try to get the latest tag
            try:
                result = subprocess.run(['git', 'describe', '--tags', '--abbrev=0'], 
                                      capture_output=True, text=True, check=True, timeout=5)
                git_info['tag'] = result.stdout.strip()
            except subprocess.CalledProcessError:
                pass
        
        # Check if repository is dirty
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True, check=True, timeout=5)
        git_info['is_dirty'] = bool(result.stdout.strip())
        
        # Get commit date and author
        try:
            result = subprocess.run(['git', 'log', '-1', '--format=%ci'], 
                                  capture_output=True, text=True, check=True, timeout=5)
            git_info['commit_date'] = result.stdout.strip()
        except subprocess.CalledProcessError:
            pass
            
        try:
            result = subprocess.run(['git', 'log', '-1', '--format=%an'], 
                                  capture_output=True, text=True, check=True, timeout=5)
            git_info['commit_author'] = result.stdout.strip()
        except subprocess.CalledProcessError:
            pass
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        # Git not available or not a git repository
        pass
    
    return git_info

def parse_git_version(tag: str) -> Optional[Tuple[int, int, int, str]]:
    """Parse a version tag into components (major, minor, patch, build)"""
    import re
    
    # Match patterns like v2.3.1, 2.3.1-stable, v2.3.1-beta, etc.
    pattern = r'^v?(\d+)\.(\d+)\.(\d+)(?:[-.](.+))?$'
    match = re.match(pattern, tag)
    
    if match:
        major, minor, patch, build = match.groups()
        return int(major), int(minor), int(patch), build or 'stable'
    
    return None

def get_dynamic_version() -> Dict[str, Any]:
    """Get version information from Git if available, fallback to hardcoded values"""
    git_info = get_git_info()
    
    # Start with hardcoded defaults
    version_info = {
        'major': VERSION_MAJOR,
        'minor': VERSION_MINOR,
        'patch': VERSION_PATCH,
        'build': VERSION_BUILD,
        'source': 'hardcoded'
    }
    
    # Try to get version from Git tag
    if git_info['available'] and git_info['tag']:
        parsed = parse_git_version(git_info['tag'])
        if parsed:
            version_info.update({
                'major': parsed[0],
                'minor': parsed[1], 
                'patch': parsed[2],
                'build': parsed[3],
                'source': 'git-tag'
            })
    
    return version_info

def get_version_string() -> str:
    """Get the full version string"""
    version_info = get_dynamic_version()
    return f"{version_info['major']}.{version_info['minor']}.{version_info['patch']}"

def get_version_info() -> Dict[str, Any]:
    """Get comprehensive version and build information"""
    version_info = get_dynamic_version()
    git_info = get_git_info()
    
    # Determine build date - use Git commit date if available, otherwise fallback
    build_date = BUILD_DATE
    if git_info['available'] and git_info['commit_date']:
        try:
            # Parse Git date and format it consistently
            from datetime import datetime
            git_date = datetime.fromisoformat(git_info['commit_date'].replace(' ', 'T').replace(' +', '+').replace(' -', '-'))
            build_date = git_date.strftime('%Y-%m-%d')
        except (ValueError, TypeError):
            pass
    elif git_info['available']:
        # If we have Git but no commit date, use current date for development builds
        build_date = datetime.now().strftime('%Y-%m-%d')
    
    result = {
        'version': get_version_string(),
        'version_major': version_info['major'],
        'version_minor': version_info['minor'], 
        'version_patch': version_info['patch'],
        'version_build': version_info['build'],
        'version_source': version_info['source'],
        'build_date': build_date,
        'build_author': BUILD_AUTHOR,
        'full_version': f"{get_version_string()}-{version_info['build']}",
        'release_name': get_release_name(version_info['major'], version_info['minor'], version_info['patch'])
    }
    
    # Add Git information if available
    if git_info['available']:
        result['git'] = {
            'commit_hash': git_info['commit_hash'],
            'commit_short': git_info['commit_short'],
            'branch': git_info['branch'],
            'tag': git_info['tag'],
            'is_dirty': git_info['is_dirty'],
            'commit_date': git_info['commit_date'],
            'commit_author': git_info['commit_author']
        }
    
    return result

def get_release_name(major: int = None, minor: int = None, patch: int = None) -> str:
    """Get a friendly release name for this version"""
    # Use dynamic version if not provided
    if major is None or minor is None or patch is None:
        version_info = get_dynamic_version()
        major, minor, patch = version_info['major'], version_info['minor'], version_info['patch']
    
    release_names = {
        (2, 3, 2): "Network Guardian Pro",
        (2, 3, 1): "Network Guardian",
        (2, 3, 0): "Smart Monitor", 
        (2, 2, 0): "Alert Master",
        (2, 1, 0): "Discovery Engine",
        (2, 0, 0): "Advanced Core"
    }
    
    version_key = (major, minor, patch)
    git_info = get_git_info()
    
    # For development builds, show branch info
    base_name = release_names.get(version_key, "Development Build")
    if git_info['available'] and git_info['branch'] and git_info['branch'] != 'main':
        if not git_info['tag']:  # Only for non-tagged builds
            base_name += f" ({git_info['branch']})"
    
    return base_name

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    try:
        # Get process info
        process = psutil.Process()
        process_info = {
            'pid': process.pid,
            'started': datetime.fromtimestamp(process.create_time()).isoformat(),
            'memory_usage_mb': round(process.memory_info().rss / 1024 / 1024, 2),
            'cpu_percent': process.cpu_percent(),
            'threads': process.num_threads()
        }
        
        # Get system info
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        system_info = {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version.split()[0],
            'python_build': sys.version_info,
            'total_memory_gb': round(memory.total / 1024 / 1024 / 1024, 2),
            'available_memory_gb': round(memory.available / 1024 / 1024 / 1024, 2),
            'memory_percent': memory.percent,
            'disk_total_gb': round(disk.total / 1024 / 1024 / 1024, 2),
            'disk_free_gb': round(disk.free / 1024 / 1024 / 1024, 2),
            'disk_percent': round((disk.used / disk.total) * 100, 1),
            'cpu_count': psutil.cpu_count(),
            'cpu_count_logical': psutil.cpu_count(logical=True)
        }
        
        # Get uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        system_info['system_uptime'] = str(uptime).split('.')[0]  # Remove microseconds
        
        return {
            'process': process_info,
            'system': system_info
        }
        
    except Exception as e:
        return {
            'error': f'Could not gather system information: {str(e)}',
            'system': {
                'platform': platform.platform(),
                'python_version': sys.version.split()[0]
            }
        }

def get_application_info() -> Dict[str, Any]:
    """Get application-specific information"""
    return {
        'name': 'HomeNetMon',
        'description': 'Comprehensive Home Network Monitoring Solution',
        'author': BUILD_AUTHOR,
        'license': 'MIT License',
        'repository': 'https://github.com/homeNetMon/homeNetMon',
        'documentation': 'Built-in help system and contextual guides',
        'features': [
            'Real-time Device Monitoring',
            'Smart Anomaly Detection with ML',
            'Network Security Scanning', 
            'Push Notifications & Alerts',
            'Rule Engine & Automation',
            'Interactive Network Topology',
            'Speed Testing & Analytics',
            'Configuration Hot-Reload'
        ],
        'technologies': [
            'Python Flask',
            'SQLAlchemy ORM',
            'Socket.IO WebSockets',
            'Bootstrap 5 UI',
            'D3.js Visualization',
            'Chart.js Analytics',
            'nmap Security Scanning',
            'Machine Learning Anomaly Detection'
        ]
    }

def get_complete_info() -> Dict[str, Any]:
    """Get all version, system, and application information"""
    return {
        'version': get_version_info(),
        'application': get_application_info(),
        'system': get_system_info(),
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }

# Constants for easy import
__version__ = get_version_string()
__version_info__ = get_version_info()
__application__ = get_application_info()

if __name__ == "__main__":
    # CLI interface for version info
    import json
    print(json.dumps(get_complete_info(), indent=2))