# HomeNetMon Release Management

This document describes the automated release management system for HomeNetMon.

## Overview

HomeNetMon now features an automated version management system that:

- **Automatically detects version information from Git tags**
- **Updates the "About" page with current release information** 
- **Includes Git commit details for development builds**
- **Provides automated release workflows via GitHub Actions**
- **Supports semantic versioning (major.minor.patch)**

## Version Detection

The system uses a hybrid approach for version detection:

1. **Git Tags** (preferred): If the current commit has a Git tag (e.g., `v2.3.1`), the version is automatically extracted
2. **Hardcoded fallback**: If no Git tag is found, falls back to hardcoded values in `version.py`

### About Page Updates

The system information page (`/system-info`) now shows:

- **Version Source**: Whether version comes from Git tag or hardcoded values
- **Git Repository Information** (if available):
  - Current commit hash and short hash
  - Current branch with styling
  - Git tag (if any)
  - Repository status (clean/modified)
  - Commit date and author

## Release Management

### Manual Release Process

Use the `release.py` script for creating releases:

```bash
# Create a patch release (2.3.1 → 2.3.2)
python release.py patch

# Create a minor release (2.3.1 → 2.4.0)  
python release.py minor

# Create a major release (2.3.1 → 3.0.0)
python release.py major

# Create a beta release
python release.py patch --build-type beta

# Test what would happen (dry run)
python release.py minor --dry-run
```

The release script will:
1. Bump the version numbers in `version.py`
2. Update the build date
3. Generate changelog entries from Git commits
4. Create a Git commit with the changes
5. Create and push a Git tag
6. Push changes to the remote repository

### Automated Release Process (GitHub Actions)

#### Automatic Releases

Releases are automatically triggered when you push commits with conventional commit messages to the `main` branch:

- `feat:` or `feature:` → **minor** version bump
- `feat!:` or `feature!:` → **major** version bump (breaking change)
- `fix:` or `bug:` → **patch** version bump
- `release:` → **patch** version bump (manual trigger)

Examples:
```bash
git commit -m "feat: add new device discovery algorithm"  # → minor bump
git commit -m "fix: resolve memory leak in scanner"       # → patch bump
git commit -m "feat!: redesign API with breaking changes" # → major bump
```

#### Manual Releases via GitHub Actions

You can also trigger releases manually from the GitHub Actions tab:

1. Go to your repository's "Actions" tab
2. Select "Release Management" workflow
3. Click "Run workflow"
4. Choose release type (patch/minor/major) and build type (stable/beta/alpha/rc)

### Changelog Generation

The system automatically generates changelog entries based on commit messages:

- **New Features**: Commits starting with `feat:`, `feature:`, `add:`, `new:`
- **Bug Fixes**: Commits starting with `fix:`, `bug:`, `patch:`
- **Improvements**: Commits starting with `improve:`, `enhance:`, `update:`, `refactor:`
- **Other Changes**: All other commits

## Configuration

### Version Configuration (`version.py`)

The main version configuration is in `version.py`:

```python
# Fallback version numbers (used when Git tags unavailable)
VERSION_MAJOR = 2
VERSION_MINOR = 3  
VERSION_PATCH = 1
VERSION_BUILD = "stable"

# Build information
BUILD_DATE = "2025-08-22"
BUILD_AUTHOR = "Envisioned & Designed by ShaKy8 • Coded by Claude Code"
```

### Release Names

Friendly release names are automatically assigned based on version numbers and can be customized in the `get_release_name()` function.

### Git Tag Format

The system expects Git tags in the format:
- `v2.3.1` (preferred)
- `2.3.1` 
- `v2.3.1-beta`
- `2.3.1-stable`

## Deployment Integration

### Docker Builds

The GitHub Actions workflow automatically builds and pushes Docker images with multiple tags:
- `latest` (for main branch builds)
- `{version}` (e.g., `2.3.1`)  
- `{commit_hash}` (e.g., `7090f941`)

### Service Restart

After updating the version information, restart the HomeNetMon service to pick up the new version data:

```bash
sudo systemctl restart homeNetMon
# or
python app.py  # for development
```

## Benefits

✅ **Always accurate version information** - No more stale version numbers  
✅ **Automated release process** - Consistent releases with proper tagging  
✅ **Better debugging** - Git commit info visible in production  
✅ **Development vs Production clarity** - Shows branch and modification status  
✅ **Changelog automation** - Automatically generated from commit messages  

## Troubleshooting

### Version Not Updating

If the about page shows old version information:
1. Restart the HomeNetMon service
2. Check that Git is available and working: `git --version`
3. Verify you're in a Git repository: `git status`

### Git Information Not Showing

If Git information doesn't appear on the about page:
1. Ensure you're running from a Git repository
2. Check Git permissions and availability
3. Verify the `get_git_info()` function isn't timing out

### Release Script Issues

Common issues with `release.py`:
- **Permission denied**: Make sure the script is executable: `chmod +x release.py`  
- **Git errors**: Ensure you have write access to the repository
- **Network issues**: Check your Git remote configuration

## Future Enhancements

Potential future improvements:
- [ ] Update checking (compare with latest GitHub release)
- [ ] Automatic dependency updates
- [ ] Release notes templates
- [ ] Integration with issue tracking
- [ ] Rollback functionality