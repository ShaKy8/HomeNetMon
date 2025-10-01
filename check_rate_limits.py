#!/usr/bin/env python3
"""
Script to check which API endpoints are missing rate limiting decorators.
This helps ensure all endpoints are properly protected in production.
"""

import os
import re
import ast

def find_api_files():
    """Find all Python files in the api directory."""
    api_dir = os.path.join(os.path.dirname(__file__), 'api')
    api_files = []
    
    for root, dirs, files in os.walk(api_dir):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                api_files.append(os.path.join(root, file))
    
    return api_files

def extract_routes_from_file(file_path):
    """Extract routes and their decorators from a Python file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    routes = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # Look for route decorators
        if '@' in line and '.route(' in line:
            route_line = line.strip()
            # Look for the function definition (should be next non-decorator line)
            j = i + 1
            decorators = [route_line]
            
            # Collect all decorators until we find the function def
            while j < len(lines):
                next_line = lines[j].strip()
                if next_line.startswith('@'):
                    decorators.append(next_line)
                elif next_line.startswith('def '):
                    # Found the function, extract name
                    func_match = re.match(r'def\s+(\w+)', next_line)
                    if func_match:
                        func_name = func_match.group(1)
                        routes.append({
                            'file': os.path.basename(file_path),
                            'line': i + 1,
                            'route': route_line,
                            'function': func_name,
                            'decorators': decorators
                        })
                    break
                elif next_line and not next_line.startswith('#'):
                    # Non-comment, non-decorator line - might be multiline decorator
                    break
                j += 1
    
    return routes

def check_rate_limiting(route_info):
    """Check if a route has rate limiting applied."""
    decorators = route_info['decorators']
    
    # Check for rate limiting decorators
    rate_limit_patterns = [
        r'@create_endpoint_limiter',
        r'@api_strict',
        r'@api_moderate', 
        r'@api_relaxed',
        r'@monitoring_data',
        r'@device_control',
        r'@config_changes',
        r'@bulk_operations',
        r'@speedtest',
        r'@security_scan',
        r'@safe_rate_limit',
    ]
    
    for decorator in decorators:
        for pattern in rate_limit_patterns:
            if re.search(pattern, decorator):
                return True, pattern
    
    return False, None

def analyze_routes():
    """Analyze all routes and identify missing rate limits."""
    api_files = find_api_files()
    all_routes = []
    
    for file_path in api_files:
        routes = extract_routes_from_file(file_path)
        all_routes.extend(routes)
    
    # Analyze rate limiting
    missing_rate_limits = []
    has_rate_limits = []
    
    for route in all_routes:
        has_limit, limit_type = check_rate_limiting(route)
        if has_limit:
            has_rate_limits.append({
                **route,
                'limit_type': limit_type
            })
        else:
            missing_rate_limits.append(route)
    
    return has_rate_limits, missing_rate_limits

def main():
    """Main function to run the analysis."""
    print("🔍 Checking API endpoints for rate limiting...")
    print("=" * 60)
    
    has_limits, missing_limits = analyze_routes()
    
    print(f"\n✅ Endpoints WITH rate limiting: {len(has_limits)}")
    print(f"❌ Endpoints MISSING rate limiting: {len(missing_limits)}")
    
    if missing_limits:
        print(f"\n⚠️  MISSING RATE LIMITS ({len(missing_limits)} endpoints):")
        print("-" * 60)
        
        for route in missing_limits:
            print(f"File: {route['file']}")
            print(f"Line: {route['line']}")
            print(f"Route: {route['route']}")
            print(f"Function: {route['function']}")
            print()
    
    if has_limits:
        print(f"\n✅ PROTECTED ENDPOINTS ({len(has_limits)} endpoints):")
        print("-" * 60)
        
        # Group by rate limit type
        by_type = {}
        for route in has_limits:
            limit_type = route['limit_type']
            if limit_type not in by_type:
                by_type[limit_type] = []
            by_type[limit_type].append(route)
        
        for limit_type, routes in by_type.items():
            print(f"\n{limit_type}: {len(routes)} endpoints")
            for route in routes[:5]:  # Show first 5 of each type
                print(f"  - {route['file']}: {route['function']}")
            if len(routes) > 5:
                print(f"  ... and {len(routes) - 5} more")
    
    # Summary
    total_endpoints = len(has_limits) + len(missing_limits)
    coverage = (len(has_limits) / total_endpoints * 100) if total_endpoints > 0 else 0
    
    print(f"\n📊 SUMMARY:")
    print(f"Total API endpoints: {total_endpoints}")
    print(f"Rate limiting coverage: {coverage:.1f}%")
    
    if coverage < 100:
        print("\n⚠️  RECOMMENDATION:")
        print("Add rate limiting decorators to the missing endpoints above.")
        print("Use @create_endpoint_limiter('relaxed') for read operations")
        print("Use @create_endpoint_limiter('strict') for write operations")
        print("Use @create_endpoint_limiter('critical') for sensitive operations")
        return 1
    else:
        print("\n🎉 All endpoints have rate limiting protection!")
        return 0

if __name__ == "__main__":
    exit(main())