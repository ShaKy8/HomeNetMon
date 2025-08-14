"""
HomeNetMon Version Management

Central version tracking and system information for HomeNetMon.
"""

import sys
import platform
import psutil
import os
from datetime import datetime
from typing import Dict, Any

# Semantic Versioning for HomeNetMon
VERSION_MAJOR = 2
VERSION_MINOR = 3  
VERSION_PATCH = 1
VERSION_BUILD = "stable"

# Build information
BUILD_DATE = "2025-08-14"
BUILD_AUTHOR = "HomeNetMon Development Team"

def get_version_string() -> str:
    """Get the full version string"""
    return f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"

def get_version_info() -> Dict[str, Any]:
    """Get comprehensive version and build information"""
    return {
        'version': get_version_string(),
        'version_major': VERSION_MAJOR,
        'version_minor': VERSION_MINOR, 
        'version_patch': VERSION_PATCH,
        'version_build': VERSION_BUILD,
        'build_date': BUILD_DATE,
        'build_author': BUILD_AUTHOR,
        'full_version': f"{get_version_string()}-{VERSION_BUILD}",
        'release_name': get_release_name()
    }

def get_release_name() -> str:
    """Get a friendly release name for this version"""
    release_names = {
        (2, 3, 1): "Network Guardian",
        (2, 3, 0): "Smart Monitor", 
        (2, 2, 0): "Alert Master",
        (2, 1, 0): "Discovery Engine",
        (2, 0, 0): "Advanced Core"
    }
    
    version_key = (VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
    return release_names.get(version_key, "Development Build")

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