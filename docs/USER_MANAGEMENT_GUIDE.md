# 👥 HomeNetMon User Management Guide

Complete guide for managing admin passwords and user accounts in HomeNetMon.

## 🚀 Quick Start

### Default Credentials
- **Username:** `admin`
- **Password:** `admin123` (or set via `ADMIN_PASSWORD` environment variable)
- **URL:** `http://geekom1:5000/login`

---

## 🔑 Changing Admin Password

### Method 1: Web Interface (Recommended)
1. **Login** to HomeNetMon at `http://geekom1:5000/login`
2. Go to **Settings** → **Profile** tab
3. Fill out the **Change Password** form:
   - Current Password: `admin123`
   - New Password: Your desired password (min 6 chars)
   - Confirm New Password: Same as above
4. Click **Change Password**
5. You'll be automatically logged out - login with new password

### Method 2: Admin Management Script
```bash
# Run the interactive admin manager
venv/bin/python admin_manager.py

# Select option 2: Change admin password
# Follow the prompts
```

### Method 3: Environment Variable
```bash
# Set password and restart HomeNetMon
export ADMIN_PASSWORD="your-new-password"
venv/bin/python app.py
```

---

## 👥 Adding New Users

### Method 1: Web Interface
1. **Login** as admin
2. Go to **Settings** → **System** tab → **User Management** section
3. Click **Add User**
4. Fill out the form:
   - Username (min 3 chars)
   - Password (min 6 chars) 
   - Select roles:
     - **User** - Basic access to dashboard
     - **Admin** - Full access including user management
     - **Readonly** - View-only access
5. Click **Create User**

### Method 2: Admin Management Script
```bash
# Run the interactive admin manager
venv/bin/python admin_manager.py

# Select option 5: Create new user
# Follow the prompts
```

---

## 🔧 Environment Variable Management

### Setting Admin Password

#### Development
```bash
# Start with custom password
ADMIN_PASSWORD="mypassword123" venv/bin/python app.py
```

#### Production with Systemd
```bash
# Edit service environment
sudo systemctl edit homenetmon

# Add in the editor:
[Service]
Environment=ADMIN_PASSWORD=your-secure-password

# Restart service
sudo systemctl restart homenetmon
```

#### Docker
```yaml
# docker-compose.yml
version: '3.8'
services:
  homenetmon:
    environment:
      - ADMIN_PASSWORD=your-secure-password
```

#### .env File (Optional)
```bash
# Create .env file
echo "ADMIN_PASSWORD=your-password" > .env

# Install python-dotenv
pip install python-dotenv

# Load in Python (if configured)
from dotenv import load_dotenv
load_dotenv()
```

---

## 🛠️ Admin Management Script

The `admin_manager.py` script provides complete user management functionality:

```bash
venv/bin/python admin_manager.py
```

### Available Options:
1. **🔐 Test admin login** - Verify current credentials work
2. **🔑 Change admin password** - Interactive password change
3. **🎲 Generate secure password** - Auto-generate strong password
4. **👥 List all users** - Show all users and their roles
5. **➕ Create new user** - Add new users with roles
6. **🚨 Emergency admin reset** - Reset to known password
7. **📖 Show current credentials** - Display working login info
8. **🔧 Environment variable help** - Documentation
9. **❌ Exit** - Close the script

### Example Usage:
```bash
$ venv/bin/python admin_manager.py

🔧 HomeNetMon Admin Management Tool
============================================================
Timestamp: 2025-09-01 10:30:15

📋 Available Actions:
1. 🔐 Test admin login (admin/admin123)
2. 🔑 Change admin password
3. 🎲 Generate new secure admin password
4. 👥 List all users
5. ➕ Create new user
6. 🚨 Emergency admin reset
7. 📖 Show current credentials
8. 🔧 Environment variable help
9. ❌ Exit

Enter your choice (1-9): 1

🧪 Testing admin login...
✅ Admin login successful!
ℹ️  Username: admin
ℹ️  Password: admin123
ℹ️  URL: http://geekom1:5000/login
```

---

## 🔒 User Roles & Permissions

### Role Hierarchy

| Role | Permissions | Use Case |
|------|------------|----------|
| **admin** | Full access, user management, system settings | System administrators |
| **user** | Dashboard access, device monitoring, basic settings | Regular users |
| **readonly** | View-only access to dashboard and reports | Monitoring displays, guests |

### Role Assignment
- Users can have multiple roles
- Admin role automatically includes user permissions
- Roles are checked for each protected route

---

## 🚨 Troubleshooting

### Can't Login?
1. **Check credentials** - Use admin management script option 1
2. **Try emergency reset** - Use admin management script option 6
3. **Check environment variables:**
   ```bash
   echo $ADMIN_PASSWORD
   ```
4. **Restart application** with known password:
   ```bash
   ADMIN_PASSWORD=admin123 venv/bin/python app.py
   ```

### Password Not Persisting?
The authentication system is in-memory by default. Password changes are temporary unless:
1. You restart with the same `ADMIN_PASSWORD` environment variable
2. Or implement database-based user storage (future enhancement)

### User Creation Fails?
1. **Check admin permissions** - Only admins can create users
2. **Verify unique usernames** - Usernames must be unique
3. **Check session** - Make sure you're still logged in

---

## 🔮 Advanced Configuration

### Multiple Admin Users
```bash
# Create additional admin users via script
venv/bin/python admin_manager.py
# Option 5: Create new user → Select admin role
```

### Session Timeout
Default session timeout is 1 hour. Configure in `config.py`:
```python
PERMANENT_SESSION_LIFETIME = 3600  # seconds
```

### Password Requirements
- Minimum length: 6 characters
- Recommended: 12+ characters with mixed case, numbers, symbols
- Use unique passwords for each account

---

## 📚 API Reference

### Session-Based Endpoints (Web Interface)

#### Change Password
```http
POST /api/change-password
Content-Type: application/json

{
  "current_password": "current_password",
  "new_password": "new_password"
}
```

#### Create User
```http
POST /api/users
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123",
  "roles": ["user"]
}
```

#### List Users
```http
GET /api/users
```

### JWT-Based Endpoints (API Access)
Available at `/api/auth/*` - require Bearer token authentication.

---

## 🔐 Security Best Practices

### Password Security
- ✅ Use strong, unique passwords (12+ characters)
- ✅ Enable password managers
- ✅ Rotate passwords regularly
- ❌ Don't reuse passwords from other services
- ❌ Don't share passwords

### Environment Variables
- ✅ Set `ADMIN_PASSWORD` in production
- ✅ Use secure deployment practices
- ✅ Keep secrets out of version control
- ❌ Don't hardcode passwords in code

### Access Control
- ✅ Create separate accounts for different users
- ✅ Use appropriate roles (principle of least privilege)
- ✅ Regularly review user accounts
- ❌ Don't share admin accounts

---

## 📞 Support

If you need help:
1. **Check this guide** for common solutions
2. **Run diagnostic script:** `venv/bin/python admin_manager.py` → Option 7
3. **Check application logs** in `homenetmon.log`
4. **Restart application** with known credentials

---

*Last updated: 2025-09-01*