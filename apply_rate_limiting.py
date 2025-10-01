#!/usr/bin/env python3
"""
Script to automatically add rate limiting decorators to API endpoints.
This applies appropriate rate limits based on the endpoint type (GET vs POST/PUT/DELETE).
"""

import os
import re
from typing import List, Dict, Tuple

def determine_rate_limit_type(route_info: Dict) -> str:
    """Determine the appropriate rate limit type based on route characteristics."""
    route = route_info['route']
    function_name = route_info['function']
    
    # Extract HTTP methods
    method_match = re.search(r"methods=\[(.*?)\]", route)
    methods = []
    if method_match:
        methods_str = method_match.group(1).replace("'", "").replace('"', '')
        methods = [m.strip() for m in methods_str.split(',')]
    
    # Critical operations (should have strictest limits)
    critical_patterns = [
        'delete', 'remove', 'clear', 'reset', 'purge', 'truncate',
        'scan', 'test', 'run_', 'trigger', 'execute', 'install',
        'backup', 'restore', 'migrate', 'optimize'
    ]
    
    # Bulk operations (need strict limits)
    bulk_patterns = [
        'bulk_', 'batch_', 'all_', 'mass_'
    ]
    
    # Configuration changes (need strict limits)  
    config_patterns = [
        'config', 'setting', 'update_', 'create_', 'modify_'
    ]
    
    # Check function name and route for patterns
    func_lower = function_name.lower()
    route_lower = route.lower()
    
    # Critical operations
    for pattern in critical_patterns:
        if pattern in func_lower or pattern in route_lower:
            return 'critical'
    
    # Bulk operations
    for pattern in bulk_patterns:
        if pattern in func_lower or pattern in route_lower:
            return 'bulk'
    
    # Configuration changes
    if any(method in methods for method in ['POST', 'PUT', 'DELETE']):
        for pattern in config_patterns:
            if pattern in func_lower or pattern in route_lower:
                return 'strict'
    
    # Write operations (POST, PUT, DELETE) - strict by default
    if any(method in methods for method in ['POST', 'PUT', 'DELETE']):
        return 'strict'
    
    # Read operations (GET) - relaxed by default
    return 'relaxed'

def add_rate_limiting_to_file(file_path: str) -> bool:
    """Add rate limiting decorators to a file's API endpoints."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return False
    
    modified = False
    new_lines = []
    
    # Check if rate limiting import exists
    has_import = False
    for line in lines:
        if 'from api.rate_limited_endpoints import create_endpoint_limiter' in line:
            has_import = True
            break
    
    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        
        # Add import if needed (after other imports)
        if not has_import and (line.startswith('import ') or line.startswith('from ')) and i + 1 < len(lines):
            next_line = lines[i + 1]
            if not (next_line.startswith('import ') or next_line.startswith('from ')):
                new_lines.append('from api.rate_limited_endpoints import create_endpoint_limiter\n')
                has_import = True
                modified = True
        
        # Look for route decorators
        if '@' in line and '.route(' in line:
            route_line = line.strip()
            
            # Check if rate limiting already exists
            has_rate_limit = False
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith('@'):
                if any(pattern in lines[j] for pattern in [
                    '@create_endpoint_limiter', '@api_strict', '@api_moderate', 
                    '@api_relaxed', '@safe_rate_limit'
                ]):
                    has_rate_limit = True
                    break
                j += 1
            
            if not has_rate_limit:
                # Find function definition to determine rate limit type
                k = i + 1
                while k < len(lines):
                    next_line = lines[k].strip()
                    if next_line.startswith('def '):
                        func_match = re.match(r'def\s+(\w+)', next_line)
                        if func_match:
                            func_name = func_match.group(1)
                            
                            # Determine rate limit type
                            route_info = {
                                'route': route_line,
                                'function': func_name
                            }
                            limit_type = determine_rate_limit_type(route_info)
                            
                            # Add rate limiting decorator before function
                            indent = ' ' * (len(lines[k]) - len(lines[k].lstrip()))
                            rate_limit_line = f"{indent}@create_endpoint_limiter('{limit_type}')\n"
                            new_lines.append(rate_limit_line)
                            modified = True
                            break
                    elif next_line and not next_line.startswith('@'):
                        break
                    k += 1
        
        i += 1
    
    # Write back if modified
    if modified:
        try:
            with open(file_path, 'w') as f:
                f.writelines(new_lines)
            print(f"✅ Updated {os.path.basename(file_path)}")
            return True
        except Exception as e:
            print(f"❌ Error writing {file_path}: {e}")
            return False
    
    return False

def find_api_files() -> List[str]:
    """Find all Python files in the api directory."""
    api_dir = os.path.join(os.path.dirname(__file__), 'api')
    api_files = []
    
    for root, dirs, files in os.walk(api_dir):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                api_files.append(os.path.join(root, file))
    
    return api_files

def main():
    """Main function to apply rate limiting to all API files."""
    print("🔧 Adding rate limiting decorators to API endpoints...")
    print("=" * 60)
    
    api_files = find_api_files()
    updated_files = 0
    total_files = len(api_files)
    
    for file_path in api_files:
        if add_rate_limiting_to_file(file_path):
            updated_files += 1
    
    print(f"\n📊 SUMMARY:")
    print(f"Total API files: {total_files}")
    print(f"Files updated: {updated_files}")
    print(f"Files unchanged: {total_files - updated_files}")
    
    if updated_files > 0:
        print(f"\n✅ Successfully added rate limiting to {updated_files} files!")
        print("Run the check_rate_limits.py script to verify coverage.")
    else:
        print("\nℹ️  No files needed updates.")
    
    return 0

if __name__ == "__main__":
    exit(main())