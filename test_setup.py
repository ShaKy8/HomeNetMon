#!/usr/bin/env python3
"""
HomeNetMon Setup Test
This script tests if all dependencies can be imported and basic functionality works.
"""

import sys
import subprocess
import socket

def test_python_version():
    """Test Python version compatibility"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.8+")
        return False

def test_system_commands():
    """Test required system commands"""
    commands = ['nmap', 'ping', 'arp']
    results = []
    
    for cmd in commands:
        try:
            result = subprocess.run(['which', cmd], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {cmd} - Available at {result.stdout.strip()}")
                results.append(True)
            else:
                print(f"❌ {cmd} - Not found")
                results.append(False)
        except Exception as e:
            print(f"❌ {cmd} - Error: {e}")
            results.append(False)
    
    return all(results)

def test_network_access():
    """Test network access for monitoring"""
    try:
        # Test if we can create a socket (for ping operations)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
        print("✅ Network access - Raw sockets available")
        return True
    except PermissionError:
        print("⚠️  Network access - Raw sockets require root/sudo (ping will work with system ping)")
        return True
    except Exception as e:
        print(f"❌ Network access - Error: {e}")
        return False

def test_port_availability():
    """Test if port 5000 is available"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 5000))
        sock.close()
        print("✅ Port 5000 - Available")
        return True
    except OSError:
        print("❌ Port 5000 - Already in use")
        return False

def test_imports():
    """Test if we can import required packages"""
    packages = [
        ('flask', 'Flask'),
        ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
        ('flask_socketio', 'Flask-SocketIO'),
        ('ping3', 'ping3'),
        ('nmap', 'python-nmap'),
        ('requests', 'requests'),
        ('yaml', 'PyYAML'),
        ('manuf', 'manuf'),
    ]
    
    results = []
    for module, name in packages:
        try:
            __import__(module)
            print(f"✅ {name} - Imported successfully")
            results.append(True)
        except ImportError:
            print(f"❌ {name} - Not installed (pip install {name.lower()})")
            results.append(False)
        except Exception as e:
            print(f"❌ {name} - Error: {e}")
            results.append(False)
    
    return all(results)

def main():
    """Run all tests"""
    print("🏠 HomeNetMon Setup Test")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("System Commands", test_system_commands),
        ("Network Access", test_network_access),
        ("Port Availability", test_port_availability),
        ("Python Packages", test_imports),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 Testing {test_name}...")
        result = test_func()
        results.append(result)
    
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    all_passed = all(results)
    if all_passed:
        print("🎉 All tests passed! HomeNetMon should work correctly.")
        print("\nNext steps:")
        print("1. Run: python app.py")
        print("2. Open: http://localhost:5000")
    else:
        print("⚠️  Some tests failed. Please install missing dependencies.")
        print("\nTo install missing packages:")
        print("1. Create virtual environment: python3 -m venv venv")
        print("2. Activate it: source venv/bin/activate")
        print("3. Install packages: pip install -r requirements.txt")
    
    return all_passed

if __name__ == "__main__":
    main()