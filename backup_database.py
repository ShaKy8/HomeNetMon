#!/usr/bin/env python3
"""
HomeNetMon Database Backup Script

This script provides automated database backup capabilities for both SQLite and PostgreSQL.
Supports multiple backup strategies, compression, encryption, and cloud storage integration.

Usage:
    python backup_database.py --type full --storage local --compress
    python backup_database.py --type incremental --storage s3 --encrypt
"""

import os
import sys
import argparse
import logging
import gzip
import shutil
import subprocess
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union
import hashlib

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging for backup operations."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f"backup_{datetime.now().strftime('%Y%m%d')}.log"
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file)
        ]
    )
    return logging.getLogger(__name__)

class BackupManager:
    """Main backup management class."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.backup_dir = Path(config.get('backup_dir', './backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
        # Load database configuration
        self._load_database_config()
    
    def _load_database_config(self):
        """Load database configuration from environment or config file."""
        try:
            from config import Config
            self.db_type = 'postgresql' if Config.SQLALCHEMY_DATABASE_URI.startswith('postgres') else 'sqlite'
            self.db_url = Config.SQLALCHEMY_DATABASE_URI
            
            if self.db_type == 'sqlite':
                # Extract SQLite file path
                self.sqlite_path = self.db_url.replace('sqlite:///', '')
            else:
                # Parse PostgreSQL URL
                from urllib.parse import urlparse
                parsed = urlparse(self.db_url)
                self.pg_config = {
                    'host': parsed.hostname,
                    'port': parsed.port or 5432,
                    'username': parsed.username,
                    'password': parsed.password,
                    'database': parsed.path.lstrip('/')
                }
                
        except Exception as e:
            self.logger.error(f"Failed to load database config: {e}")
            raise

    def create_full_backup(self) -> Dict:
        """Create a full database backup."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if self.db_type == 'sqlite':
            return self._backup_sqlite_full(timestamp)
        else:
            return self._backup_postgresql_full(timestamp)
    
    def _backup_sqlite_full(self, timestamp: str) -> Dict:
        """Create full SQLite backup."""
        backup_filename = f"homeNetMon_full_{timestamp}.db"
        backup_path = self.backup_dir / backup_filename
        
        try:
            # Copy SQLite database file
            shutil.copy2(self.sqlite_path, backup_path)
            
            backup_info = {
                'type': 'full',
                'database': 'sqlite',
                'timestamp': timestamp,
                'filename': backup_filename,
                'path': str(backup_path),
                'size': backup_path.stat().st_size,
                'checksum': self._calculate_checksum(backup_path)
            }
            
            self.logger.info(f"SQLite full backup created: {backup_path}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"SQLite backup failed: {e}")
            raise

    def _backup_postgresql_full(self, timestamp: str) -> Dict:
        """Create full PostgreSQL backup using pg_dump."""
        backup_filename = f"homeNetMon_full_{timestamp}.sql"
        backup_path = self.backup_dir / backup_filename
        
        try:
            # Set up environment for pg_dump
            env = os.environ.copy()
            env['PGPASSWORD'] = self.pg_config['password']
            
            # Run pg_dump
            cmd = [
                'pg_dump',
                '-h', self.pg_config['host'],
                '-p', str(self.pg_config['port']),
                '-U', self.pg_config['username'],
                '-d', self.pg_config['database'],
                '--no-password',
                '--verbose',
                '--format=custom',
                '--compress=9',
                '--file', str(backup_path)
            ]
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"pg_dump failed: {result.stderr}")
            
            backup_info = {
                'type': 'full',
                'database': 'postgresql',
                'timestamp': timestamp,
                'filename': backup_filename,
                'path': str(backup_path),
                'size': backup_path.stat().st_size,
                'checksum': self._calculate_checksum(backup_path)
            }
            
            self.logger.info(f"PostgreSQL full backup created: {backup_path}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"PostgreSQL backup failed: {e}")
            raise

    def create_incremental_backup(self) -> Dict:
        """Create incremental backup (PostgreSQL only)."""
        if self.db_type == 'sqlite':
            self.logger.warning("Incremental backups not supported for SQLite, creating full backup")
            return self.create_full_backup()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return self._backup_postgresql_incremental(timestamp)

    def _backup_postgresql_incremental(self, timestamp: str) -> Dict:
        """Create PostgreSQL incremental backup using WAL archiving."""
        # This is a simplified implementation
        # In production, you'd use proper WAL-E or pgBackRest
        
        backup_filename = f"homeNetMon_incremental_{timestamp}.sql"
        backup_path = self.backup_dir / backup_filename
        
        try:
            # For now, create a data-only dump since last backup
            env = os.environ.copy()
            env['PGPASSWORD'] = self.pg_config['password']
            
            # Get last backup timestamp
            last_backup_time = self._get_last_backup_timestamp()
            
            cmd = [
                'pg_dump',
                '-h', self.pg_config['host'],
                '-p', str(self.pg_config['port']),
                '-U', self.pg_config['username'],
                '-d', self.pg_config['database'],
                '--no-password',
                '--data-only',
                '--format=custom',
                '--compress=9',
                '--file', str(backup_path)
            ]
            
            # Add WHERE clause for incremental data if possible
            # This is simplified - real incremental backups need WAL
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Incremental backup failed: {result.stderr}")
            
            backup_info = {
                'type': 'incremental',
                'database': 'postgresql',
                'timestamp': timestamp,
                'filename': backup_filename,
                'path': str(backup_path),
                'size': backup_path.stat().st_size,
                'checksum': self._calculate_checksum(backup_path),
                'base_timestamp': last_backup_time
            }
            
            self.logger.info(f"PostgreSQL incremental backup created: {backup_path}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Incremental backup failed: {e}")
            raise

    def compress_backup(self, backup_info: Dict) -> Dict:
        """Compress backup file using gzip."""
        if not self.config.get('compress', False):
            return backup_info
        
        try:
            original_path = Path(backup_info['path'])
            compressed_path = original_path.with_suffix(original_path.suffix + '.gz')
            
            with open(original_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove original file
            original_path.unlink()
            
            # Update backup info
            backup_info.update({
                'filename': compressed_path.name,
                'path': str(compressed_path),
                'size': compressed_path.stat().st_size,
                'compressed': True,
                'compression_ratio': backup_info['size'] / compressed_path.stat().st_size
            })
            
            self.logger.info(f"Backup compressed: {compressed_path}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Compression failed: {e}")
            raise

    def encrypt_backup(self, backup_info: Dict) -> Dict:
        """Encrypt backup file using GPG."""
        if not self.config.get('encrypt', False):
            return backup_info
        
        gpg_key = self.config.get('gpg_key')
        if not gpg_key:
            self.logger.warning("Encryption requested but no GPG key specified")
            return backup_info
        
        try:
            original_path = Path(backup_info['path'])
            encrypted_path = original_path.with_suffix(original_path.suffix + '.gpg')
            
            cmd = [
                'gpg', '--trust-model', 'always', '--encrypt',
                '--recipient', gpg_key,
                '--output', str(encrypted_path),
                str(original_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Encryption failed: {result.stderr}")
            
            # Remove original file
            original_path.unlink()
            
            # Update backup info
            backup_info.update({
                'filename': encrypted_path.name,
                'path': str(encrypted_path),
                'size': encrypted_path.stat().st_size,
                'encrypted': True,
                'gpg_key': gpg_key
            })
            
            self.logger.info(f"Backup encrypted: {encrypted_path}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise

    def upload_to_cloud(self, backup_info: Dict) -> Dict:
        """Upload backup to cloud storage."""
        storage_type = self.config.get('storage_type')
        
        if storage_type == 's3':
            return self._upload_to_s3(backup_info)
        elif storage_type == 'gcs':
            return self._upload_to_gcs(backup_info)
        elif storage_type == 'azure':
            return self._upload_to_azure(backup_info)
        else:
            return backup_info  # Local storage only

    def _upload_to_s3(self, backup_info: Dict) -> Dict:
        """Upload backup to AWS S3."""
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            s3_config = self.config.get('s3', {})
            bucket = s3_config.get('bucket')
            prefix = s3_config.get('prefix', 'homeNetMon-backups/')
            
            if not bucket:
                raise Exception("S3 bucket not configured")
            
            s3_client = boto3.client('s3')
            
            backup_path = Path(backup_info['path'])
            s3_key = f"{prefix}{backup_info['filename']}"
            
            # Upload file
            s3_client.upload_file(str(backup_path), bucket, s3_key)
            
            # Set lifecycle policy if configured
            if s3_config.get('lifecycle_days'):
                s3_client.put_object_tagging(
                    Bucket=bucket,
                    Key=s3_key,
                    Tagging={
                        'TagSet': [
                            {'Key': 'AutoDelete', 'Value': str(s3_config['lifecycle_days'])}
                        ]
                    }
                )
            
            backup_info.update({
                'cloud_storage': 's3',
                's3_bucket': bucket,
                's3_key': s3_key,
                'cloud_url': f"s3://{bucket}/{s3_key}"
            })
            
            self.logger.info(f"Backup uploaded to S3: {backup_info['cloud_url']}")
            
            # Remove local file if configured
            if self.config.get('remove_local_after_upload', False):
                backup_path.unlink()
                self.logger.info("Local backup file removed after upload")
            
            return backup_info
            
        except ImportError:
            self.logger.error("boto3 not installed. Install with: pip install boto3")
            raise
        except Exception as e:
            self.logger.error(f"S3 upload failed: {e}")
            raise

    def cleanup_old_backups(self):
        """Clean up old backup files."""
        retention_days = self.config.get('retention_days', 30)
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        removed_count = 0
        
        for backup_file in self.backup_dir.glob('homeNetMon_*'):
            if backup_file.stat().st_mtime < cutoff_date.timestamp():
                backup_file.unlink()
                removed_count += 1
                self.logger.info(f"Removed old backup: {backup_file}")
        
        self.logger.info(f"Cleaned up {removed_count} old backup files")

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _get_last_backup_timestamp(self) -> Optional[str]:
        """Get timestamp of last backup."""
        backup_files = list(self.backup_dir.glob('homeNetMon_*'))
        if not backup_files:
            return None
        
        # Sort by modification time and get the latest
        latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
        
        # Extract timestamp from filename
        import re
        match = re.search(r'_(\d{8}_\d{6})\.', latest_backup.name)
        return match.group(1) if match else None

    def save_backup_metadata(self, backup_info: Dict):
        """Save backup metadata to JSON file."""
        metadata_file = self.backup_dir / 'backup_metadata.json'
        
        # Load existing metadata
        metadata = []
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception:
                pass  # Start fresh if file is corrupted
        
        # Add new backup info
        metadata.append(backup_info)
        
        # Keep only recent entries
        max_entries = self.config.get('metadata_max_entries', 1000)
        if len(metadata) > max_entries:
            metadata = metadata[-max_entries:]
        
        # Save updated metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)

    def create_backup(self, backup_type: str = 'full') -> Dict:
        """Create backup with all configured options."""
        self.logger.info(f"Starting {backup_type} backup...")
        
        try:
            # Create backup
            if backup_type == 'full':
                backup_info = self.create_full_backup()
            elif backup_type == 'incremental':
                backup_info = self.create_incremental_backup()
            else:
                raise ValueError(f"Unknown backup type: {backup_type}")
            
            # Apply post-processing
            backup_info = self.compress_backup(backup_info)
            backup_info = self.encrypt_backup(backup_info)
            backup_info = self.upload_to_cloud(backup_info)
            
            # Save metadata
            self.save_backup_metadata(backup_info)
            
            # Cleanup old backups
            self.cleanup_old_backups()
            
            self.logger.info(f"Backup completed successfully: {backup_info['filename']}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            raise

def load_config(config_file: Optional[str] = None) -> Dict:
    """Load backup configuration."""
    config = {
        'backup_dir': './backups',
        'compress': False,
        'encrypt': False,
        'storage_type': 'local',
        'retention_days': 30,
        'metadata_max_entries': 1000,
        'remove_local_after_upload': False
    }
    
    # Load from file if provided
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load config file: {e}")
    
    # Override with environment variables
    env_mappings = {
        'BACKUP_DIR': 'backup_dir',
        'BACKUP_COMPRESS': 'compress',
        'BACKUP_ENCRYPT': 'encrypt',
        'BACKUP_GPG_KEY': 'gpg_key',
        'BACKUP_STORAGE_TYPE': 'storage_type',
        'BACKUP_RETENTION_DAYS': 'retention_days',
        'BACKUP_S3_BUCKET': ('s3', 'bucket'),
        'BACKUP_S3_PREFIX': ('s3', 'prefix'),
        'BACKUP_REMOVE_LOCAL': 'remove_local_after_upload'
    }
    
    for env_var, config_key in env_mappings.items():
        value = os.environ.get(env_var)
        if value is not None:
            if isinstance(config_key, tuple):
                # Nested config
                if config_key[0] not in config:
                    config[config_key[0]] = {}
                config[config_key[0]][config_key[1]] = value
            else:
                # Handle type conversion
                if config_key in ['compress', 'encrypt', 'remove_local_after_upload']:
                    config[config_key] = value.lower() in ['true', '1', 'yes']
                elif config_key == 'retention_days':
                    config[config_key] = int(value)
                else:
                    config[config_key] = value
    
    return config

def main():
    """Main backup function."""
    parser = argparse.ArgumentParser(description='HomeNetMon Database Backup Tool')
    parser.add_argument('--type', choices=['full', 'incremental'], default='full',
                       help='Type of backup to create')
    parser.add_argument('--config', help='Path to backup configuration file')
    parser.add_argument('--compress', action='store_true',
                       help='Compress backup files')
    parser.add_argument('--encrypt', action='store_true',
                       help='Encrypt backup files')
    parser.add_argument('--storage', choices=['local', 's3', 'gcs', 'azure'], default='local',
                       help='Storage backend for backups')
    parser.add_argument('--retention-days', type=int, default=30,
                       help='Number of days to retain backups')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    logger.info("🗄️ HomeNetMon Database Backup Tool")
    logger.info("=" * 50)
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override with command line arguments
        if args.compress:
            config['compress'] = True
        if args.encrypt:
            config['encrypt'] = True
        if args.storage != 'local':
            config['storage_type'] = args.storage
        config['retention_days'] = args.retention_days
        
        # Create backup manager
        backup_manager = BackupManager(config)
        
        # Create backup
        backup_info = backup_manager.create_backup(args.type)
        
        # Print summary
        logger.info("\n📊 BACKUP SUMMARY:")
        logger.info("=" * 30)
        logger.info(f"Type: {backup_info['type']}")
        logger.info(f"Database: {backup_info['database']}")
        logger.info(f"File: {backup_info['filename']}")
        logger.info(f"Size: {backup_info['size']:,} bytes")
        logger.info(f"Checksum: {backup_info['checksum'][:16]}...")
        
        if backup_info.get('compressed'):
            ratio = backup_info.get('compression_ratio', 1)
            logger.info(f"Compression: {ratio:.1f}x")
        
        if backup_info.get('encrypted'):
            logger.info(f"Encryption: GPG ({backup_info['gpg_key']})")
        
        if backup_info.get('cloud_storage'):
            logger.info(f"Cloud Storage: {backup_info['cloud_storage']}")
            logger.info(f"Cloud URL: {backup_info['cloud_url']}")
        
        logger.info("\n✅ Backup completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        logger.error("\nBackup cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"\nBackup failed: {e}")
        if args.verbose:
            logger.exception("Full error details:")
        return 1

if __name__ == "__main__":
    exit(main())