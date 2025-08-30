#!/usr/bin/env python3
"""
HomeNetMon Release Management Script

Automates version bumping, tagging, and release preparation for HomeNetMon.
Supports semantic versioning with automatic changelog generation.
"""

import argparse
import subprocess
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

class ReleaseManager:
    def __init__(self, repo_path: Path = None):
        self.repo_path = repo_path or Path.cwd()
        self.version_file = self.repo_path / "version.py"
        
    def run_command(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a shell command and return the result"""
        print(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, check=check, shell=False)
    
    def get_current_version(self) -> Tuple[int, int, int, str]:
        """Get current version from version.py"""
        try:
            with open(self.version_file, 'r') as f:
                content = f.read()
            
            major_match = re.search(r'VERSION_MAJOR\s*=\s*(\d+)', content)
            minor_match = re.search(r'VERSION_MINOR\s*=\s*(\d+)', content)
            patch_match = re.search(r'VERSION_PATCH\s*=\s*(\d+)', content)
            build_match = re.search(r'VERSION_BUILD\s*=\s*["\']([^"\']+)["\']', content)
            
            if not all([major_match, minor_match, patch_match, build_match]):
                raise ValueError("Could not parse version from version.py")
            
            return (
                int(major_match.group(1)),
                int(minor_match.group(1)),
                int(patch_match.group(1)),
                build_match.group(1)
            )
        except Exception as e:
            raise RuntimeError(f"Failed to read version from {self.version_file}: {e}")
    
    def update_version_file(self, major: int, minor: int, patch: int, build: str = "stable"):
        """Update version numbers in version.py"""
        try:
            with open(self.version_file, 'r') as f:
                content = f.read()
            
            # Update version numbers
            content = re.sub(r'VERSION_MAJOR\s*=\s*\d+', f'VERSION_MAJOR = {major}', content)
            content = re.sub(r'VERSION_MINOR\s*=\s*\d+', f'VERSION_MINOR = {minor}', content)
            content = re.sub(r'VERSION_PATCH\s*=\s*\d+', f'VERSION_PATCH = {patch}', content)
            content = re.sub(r'VERSION_BUILD\s*=\s*["\'][^"\']+["\']', f'VERSION_BUILD = "{build}"', content)
            
            # Update build date
            today = datetime.now().strftime('%Y-%m-%d')
            content = re.sub(r'BUILD_DATE\s*=\s*["\'][^"\']+["\']', f'BUILD_DATE = "{today}"', content)
            
            # Update release names if needed
            new_version_key = f'({major}, {minor}, {patch})'
            if new_version_key not in content:
                # Add new release name entry
                release_name = self.generate_release_name(major, minor, patch)
                release_names_pattern = r'(release_names\s*=\s*\{)(.*?)(\s*\})'
                
                def add_release_name(match):
                    existing_dict = match.group(2)
                    new_entry = f'\n        {new_version_key}: "{release_name}",'
                    return match.group(1) + new_entry + existing_dict + match.group(3)
                
                content = re.sub(release_names_pattern, add_release_name, content, flags=re.DOTALL)
            
            with open(self.version_file, 'w') as f:
                f.write(content)
            
            print(f"Updated version.py: {major}.{minor}.{patch}-{build}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to update version file: {e}")
    
    def generate_release_name(self, major: int, minor: int, patch: int) -> str:
        """Generate a friendly release name"""
        # You can customize this logic
        names = [
            "Network Guardian", "Smart Monitor", "Alert Master", "Discovery Engine",
            "Security Sentinel", "Data Insight", "Network Sage", "Monitoring Pro",
            "System Watcher", "Net Defender", "Analytics Core", "Service Monitor"
        ]
        
        # Simple hash-based selection for consistency
        name_index = (major * 100 + minor * 10 + patch) % len(names)
        return names[name_index]
    
    def get_commits_since_tag(self, tag: str) -> List[str]:
        """Get commit messages since the last tag"""
        try:
            result = self.run_command(['git', 'log', f'{tag}..HEAD', '--oneline'])
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
        except subprocess.CalledProcessError:
            # If no previous tag, get all commits
            result = self.run_command(['git', 'log', '--oneline'])
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
    
    def generate_changelog_entry(self, version: str, commits: List[str]) -> str:
        """Generate changelog entry from commits"""
        if not commits:
            return f"## [{version}] - {datetime.now().strftime('%Y-%m-%d')}\n\n- Initial release\n"
        
        # Categorize commits
        features = []
        fixes = []
        improvements = []
        other = []
        
        for commit in commits:
            commit_lower = commit.lower()
            if any(keyword in commit_lower for keyword in ['feat:', 'feature:', 'add:', 'new:']):
                features.append(commit)
            elif any(keyword in commit_lower for keyword in ['fix:', 'bug:', 'patch:']):
                fixes.append(commit)
            elif any(keyword in commit_lower for keyword in ['improve:', 'enhance:', 'update:', 'refactor:']):
                improvements.append(commit)
            else:
                other.append(commit)
        
        # Build changelog entry
        changelog = f"## [{version}] - {datetime.now().strftime('%Y-%m-%d')}\n\n"
        
        if features:
            changelog += "### New Features\n"
            for commit in features:
                changelog += f"- {commit}\n"
            changelog += "\n"
        
        if improvements:
            changelog += "### Improvements\n"
            for commit in improvements:
                changelog += f"- {commit}\n"
            changelog += "\n"
        
        if fixes:
            changelog += "### Bug Fixes\n"
            for commit in fixes:
                changelog += f"- {commit}\n"
            changelog += "\n"
        
        if other:
            changelog += "### Other Changes\n"
            for commit in other:
                changelog += f"- {commit}\n"
            changelog += "\n"
        
        return changelog
    
    def update_changelog(self, version: str, changelog_entry: str):
        """Update or create CHANGELOG.md file"""
        changelog_file = self.repo_path / "CHANGELOG.md"
        
        if changelog_file.exists():
            with open(changelog_file, 'r') as f:
                existing_content = f.read()
            
            # Insert new entry after the header
            if "# Changelog" in existing_content:
                parts = existing_content.split("# Changelog", 1)
                new_content = f"# Changelog{parts[1]}\n\n{changelog_entry}"
            else:
                new_content = f"# Changelog\n\n{changelog_entry}\n{existing_content}"
        else:
            new_content = f"# Changelog\n\nAll notable changes to HomeNetMon will be documented in this file.\n\n{changelog_entry}"
        
        with open(changelog_file, 'w') as f:
            f.write(new_content)
        
        print(f"Updated CHANGELOG.md with version {version}")
    
    def create_git_tag(self, version: str, message: str = None):
        """Create and push a Git tag"""
        tag_name = f"v{version}"
        tag_message = message or f"Release version {version}"
        
        # Create annotated tag
        self.run_command(['git', 'tag', '-a', tag_name, '-m', tag_message])
        print(f"Created Git tag: {tag_name}")
        
        # Push tag to remote
        try:
            self.run_command(['git', 'push', 'origin', tag_name])
            print(f"Pushed tag {tag_name} to remote")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not push tag to remote: {e}")
    
    def bump_version(self, bump_type: str, build_type: str = "stable") -> str:
        """Bump version and create release"""
        # Get current version
        major, minor, patch, current_build = self.get_current_version()
        print(f"Current version: {major}.{minor}.{patch}-{current_build}")
        
        # Calculate new version
        if bump_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif bump_type == "minor":
            minor += 1
            patch = 0
        elif bump_type == "patch":
            patch += 1
        else:
            raise ValueError(f"Invalid bump type: {bump_type}. Use 'major', 'minor', or 'patch'")
        
        new_version = f"{major}.{minor}.{patch}"
        print(f"New version: {new_version}-{build_type}")
        
        # Get latest tag for changelog generation
        try:
            result = self.run_command(['git', 'describe', '--tags', '--abbrev=0'], check=False)
            last_tag = result.stdout.strip() if result.returncode == 0 else None
        except:
            last_tag = None
        
        # Get commits for changelog
        commits = []
        if last_tag:
            commits = self.get_commits_since_tag(last_tag)
        
        # Update version file
        self.update_version_file(major, minor, patch, build_type)
        
        # Generate and update changelog
        changelog_entry = self.generate_changelog_entry(new_version, commits)
        self.update_changelog(new_version, changelog_entry)
        
        # Stage changes
        self.run_command(['git', 'add', str(self.version_file), 'CHANGELOG.md'])
        
        # Commit changes
        commit_message = f"bump: version {new_version}"
        self.run_command(['git', 'commit', '-m', commit_message])
        
        return new_version
    
    def create_release(self, bump_type: str, build_type: str = "stable", push: bool = True, tag: bool = True):
        """Complete release process"""
        print(f"Creating {bump_type} release...")
        
        # Check if working directory is clean
        result = self.run_command(['git', 'status', '--porcelain'], check=False)
        if result.stdout.strip():
            print("Warning: Working directory is not clean. Uncommitted changes:")
            print(result.stdout)
            if input("Continue anyway? (y/N): ").lower() != 'y':
                sys.exit(1)
        
        # Bump version
        new_version = self.bump_version(bump_type, build_type)
        
        # Create Git tag
        if tag:
            self.create_git_tag(new_version)
        
        # Push changes
        if push:
            try:
                self.run_command(['git', 'push'])
                print("Pushed changes to remote")
            except subprocess.CalledProcessError as e:
                print(f"Warning: Could not push changes to remote: {e}")
        
        print(f"\n✅ Release {new_version} created successfully!")
        print(f"📝 Changelog updated")
        print(f"🏷️  Git tag: v{new_version}")
        
        return new_version

def main():
    parser = argparse.ArgumentParser(description="HomeNetMon Release Management")
    parser.add_argument('bump_type', choices=['major', 'minor', 'patch'], 
                      help="Type of version bump")
    parser.add_argument('--build-type', default='stable', 
                      help="Build type (stable, beta, alpha, rc)")
    parser.add_argument('--no-push', action='store_true', 
                      help="Don't push changes to remote")
    parser.add_argument('--no-tag', action='store_true', 
                      help="Don't create Git tag")
    parser.add_argument('--dry-run', action='store_true', 
                      help="Show what would be done without making changes")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("DRY RUN MODE - No changes will be made")
        release_manager = ReleaseManager()
        major, minor, patch, build = release_manager.get_current_version()
        print(f"Current version: {major}.{minor}.{patch}-{build}")
        
        if args.bump_type == "major":
            new_version = f"{major + 1}.0.0"
        elif args.bump_type == "minor":
            new_version = f"{major}.{minor + 1}.0"
        else:
            new_version = f"{major}.{minor}.{patch + 1}"
        
        print(f"Would create version: {new_version}-{args.build_type}")
        return
    
    try:
        release_manager = ReleaseManager()
        release_manager.create_release(
            bump_type=args.bump_type,
            build_type=args.build_type,
            push=not args.no_push,
            tag=not args.no_tag
        )
    except Exception as e:
        print(f"❌ Release failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()