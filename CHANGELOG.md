# Changelog

All notable changes to HomeNetMon will be documented in this file.

## [2.3.1] - 2025-08-22

### New Features
- Automated version management system with Git integration
- Dynamic version detection from Git tags
- Enhanced system information page with Git repository details
- Automated release workflows via GitHub Actions
- Release management script for semantic versioning

### Improvements  
- Updated about page to show version source (Git tag vs hardcoded)
- Added Git commit information to system info display
- Improved build date detection using Git commit timestamps
- Enhanced version display with branch and status information

### Technical Changes
- Added `get_git_info()` function for repository information
- Added `get_dynamic_version()` for Git-based version detection
- Updated system info API to include Git metadata
- Created automated release script (`release.py`)
- Added GitHub Actions workflows for CI/CD

### Documentation
- Added comprehensive release management documentation
- Updated system architecture notes with version management details

---

*Previous versions were managed manually. This changelog will be automatically maintained going forward.*

## [2.3.2] - 2025-08-22

### New Features
- f5c8927 feat: implement comprehensive version management and accurate device counting

### Other Changes
- ce152f6 Remove GitHub Actions workflows due to permission restrictions

