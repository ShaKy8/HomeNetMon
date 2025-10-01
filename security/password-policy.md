# Password Security Policy for HomeNetMon

## Strong Password Requirements

Passwords must meet the following criteria:
- Minimum 12 characters length
- Include uppercase letters (A-Z)
- Include lowercase letters (a-z)
- Include numbers (0-9)
- Include special characters (!@#$%^&*)
- No common dictionary words
- No personal information
- No reused passwords

## Implementation

1. Update admin password:
   ```bash
   python3 -c "
   import secrets, string
   chars = string.ascii_letters + string.digits + '!@#$%^&*'
   password = ''.join(secrets.choice(chars) for _ in range(16))
   print(f'Strong password: {password}')
   "
   ```

2. Set in environment:
   ```bash
   export ADMIN_PASSWORD='your-strong-password-here'
   ```

3. Store securely and never commit to version control
