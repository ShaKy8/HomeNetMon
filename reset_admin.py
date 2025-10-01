#!/usr/bin/env python3
"""
HomeNetMon Admin Password Reset Tool
This script provides multiple ways to reset/verify the admin credentials.
"""

import os
import sys
import secrets
import getpass
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

def print_header():
    print("🔧 HomeNetMon Admin Reset Tool")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def print_success(message):
    print(f"✅ {message}")

def print_error(message):
    print(f"❌ {message}")

def print_info(message):
    print(f"ℹ️  {message}")

def set_environment_password(password):
    """Set the admin password via environment variable."""
    try:
        os.environ['ADMIN_PASSWORD'] = password
        os.environ['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
        os.environ['DEBUG'] = 'true'
        print_success(f"Environment variables set successfully")
        return True
    except Exception as e:
        print_error(f"Failed to set environment variables: {e}")
        return False

def test_authentication(password):
    """Test authentication with the given password."""
    try:
        from flask import Flask
        
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'dev-secret-key'
        
        auth_manager = AuthManager(app)
        
        result = auth_manager.authenticate('admin', password)
        
        if result:
            print_success(f"Authentication test PASSED")
            print_info(f"User: {result.get('username')}")
            print_info(f"Roles: {result.get('roles', [])}")
            return True
        else:
            print_error("Authentication test FAILED")
            return False
            
    except Exception as e:
        print_error(f"Authentication test error: {e}")
        return False

def generate_secure_password():
    """Generate a new secure password."""
    # Generate a memorable but secure password
    words = ['Home', 'Net', 'Mon', 'Admin', 'Secure']
    numbers = secrets.randbelow(999) + 100
    password = f"{secrets.choice(words)}{numbers}!"
    return password

def main():
    print_header()
    
    print("Choose an option:")
    print("1. Test current admin/admin123 credentials")
    print("2. Reset to admin/admin123") 
    print("3. Set custom password")
    print("4. Generate new secure password")
    print("5. Emergency reset (use default)")
    print()
    
    try:
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == '1':
            print("\n🧪 Testing current credentials...")
            set_environment_password('admin123')
            success = test_authentication('admin123')
            
            if success:
                print_success("Current credentials work! Use:")
                print("   URL: http://geekom1:5000/login")
                print("   Username: admin")
                print("   Password: admin123")
            else:
                print_error("Credentials not working. Try option 2-5.")
                
        elif choice == '2':
            print("\n🔄 Resetting to admin/admin123...")
            set_environment_password('admin123')
            success = test_authentication('admin123')
            
            if success:
                print_success("Reset successful! Restart HomeNetMon with:")
                print("   ADMIN_PASSWORD=admin123 venv/bin/python app.py")
            else:
                print_error("Reset failed. Try emergency reset (option 5).")
                
        elif choice == '3':
            print("\n🔐 Setting custom password...")
            new_password = getpass.getpass("Enter new admin password: ")
            if len(new_password) < 8:
                print_error("Password must be at least 8 characters")
                return
                
            set_environment_password(new_password)
            success = test_authentication(new_password)
            
            if success:
                print_success(f"Custom password set! Restart HomeNetMon with:")
                print(f"   ADMIN_PASSWORD={new_password} venv/bin/python app.py")
            else:
                print_error("Failed to set custom password.")
                
        elif choice == '4':
            print("\n🎲 Generating secure password...")
            new_password = generate_secure_password()
            print_info(f"Generated password: {new_password}")
            
            set_environment_password(new_password)
            success = test_authentication(new_password)
            
            if success:
                print_success("Secure password generated! Restart HomeNetMon with:")
                print(f"   ADMIN_PASSWORD={new_password} venv/bin/python app.py")
                print()
                print("⚠️  IMPORTANT: Save this password somewhere safe!")
            else:
                print_error("Failed to set generated password.")
                
        elif choice == '5':
            print("\n🚨 Emergency reset...")
            emergency_password = "HomeNetMon2025!"
            print_info(f"Using emergency password: {emergency_password}")
            
            set_environment_password(emergency_password)
            success = test_authentication(emergency_password)
            
            if success:
                print_success("Emergency reset successful!")
                print("   Username: admin")
                print(f"   Password: {emergency_password}")
                print()
                print("Restart HomeNetMon with:")
                print(f"   ADMIN_PASSWORD={emergency_password} venv/bin/python app.py")
            else:
                print_error("Emergency reset failed. Check system logs.")
                
        else:
            print_error("Invalid choice. Please run the script again.")
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user.")
        
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()