#!/usr/bin/env python3
"""
Clear device cache to force refresh with fixed query
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from services.query_cache import invalidate_device_cache

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        print("Clearing device cache...")
        invalidate_device_cache()
        print("Device cache cleared successfully!")