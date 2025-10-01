#!/usr/bin/env python3
"""
PostgreSQL Migration Script for HomeNetMon

This script helps migrate from SQLite to PostgreSQL for production deployment.
It handles schema migration and data transfer with proper validation and rollback capabilities.

Usage:
    python migrate_to_postgresql.py --postgres-url "postgresql://user:pass@host:port/db"
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from contextlib import contextmanager
from typing import Dict, List, Any

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_logging():
    """Set up logging for the migration process."""
    log_level = logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f'migration_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        ]
    )
    return logging.getLogger(__name__)

def validate_postgresql_connection(postgres_url: str) -> bool:
    """Test PostgreSQL connection and validate requirements."""
    try:
        import psycopg2
        from urllib.parse import urlparse
        
        logger = logging.getLogger(__name__)
        
        # Parse the URL
        parsed = urlparse(postgres_url)
        if parsed.scheme not in ['postgresql', 'postgres']:
            logger.error("Invalid PostgreSQL URL scheme")
            return False
        
        # Test connection
        conn = psycopg2.connect(postgres_url)
        cursor = conn.cursor()
        
        # Check PostgreSQL version
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        logger.info(f"Connected to: {version}")
        
        # Check if database is empty
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        table_count = cursor.fetchone()[0]
        
        if table_count > 0:
            logger.warning(f"Target database has {table_count} existing tables")
            response = input("Continue migration to non-empty database? (y/N): ")
            if response.lower() != 'y':
                return False
        
        conn.close()
        return True
        
    except ImportError:
        logger.error("psycopg2 not installed. Run: pip install psycopg2-binary")
        return False
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        return False

def backup_sqlite_database(sqlite_path: str) -> str:
    """Create a backup of the SQLite database."""
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite database not found: {sqlite_path}")
    
    backup_path = f"{sqlite_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    import shutil
    shutil.copy2(sqlite_path, backup_path)
    
    logger.info(f"SQLite database backed up to: {backup_path}")
    return backup_path

def get_sqlite_schema(sqlite_path: str) -> Dict[str, List[str]]:
    """Extract schema information from SQLite database."""
    import sqlite3
    
    logger = logging.getLogger(__name__)
    
    conn = sqlite3.connect(sqlite_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    schema_info = {}
    
    for table in tables:
        # Get table schema
        cursor.execute(f"PRAGMA table_info({table})")
        columns = cursor.fetchall()
        
        # Get table creation SQL
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,))
        create_sql = cursor.fetchone()[0] if cursor.fetchone() else None
        
        schema_info[table] = {
            'columns': columns,
            'create_sql': create_sql
        }
        
        logger.debug(f"Table {table}: {len(columns)} columns")
    
    conn.close()
    
    logger.info(f"Extracted schema for {len(tables)} tables")
    return schema_info

def create_postgresql_schema(postgres_url: str, app):
    """Create PostgreSQL schema using SQLAlchemy models."""
    logger = logging.getLogger(__name__)
    
    # Temporarily switch to PostgreSQL
    original_database_url = app.config.get('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_DATABASE_URI'] = postgres_url
    
    try:
        from models import db
        
        # Create new engine for PostgreSQL
        from sqlalchemy import create_engine
        engine = create_engine(postgres_url)
        
        # Create all tables
        with app.app_context():
            db.engine = engine
            db.create_all()
        
        logger.info("PostgreSQL schema created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create PostgreSQL schema: {e}")
        raise
    finally:
        # Restore original database URL
        if original_database_url:
            app.config['SQLALCHEMY_DATABASE_URI'] = original_database_url

def migrate_table_data(table_name: str, sqlite_cursor, postgres_cursor, chunk_size: int = 1000):
    """Migrate data from one table with chunked processing."""
    logger = logging.getLogger(__name__)
    
    # Get column names
    sqlite_cursor.execute(f"PRAGMA table_info({table_name})")
    columns_info = sqlite_cursor.fetchall()
    column_names = [col[1] for col in columns_info]
    
    # Count total rows
    sqlite_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    total_rows = sqlite_cursor.fetchone()[0]
    
    if total_rows == 0:
        logger.info(f"Table {table_name}: No data to migrate")
        return True
    
    logger.info(f"Migrating {total_rows} rows from table {table_name}")
    
    # Prepare INSERT statement
    placeholders = ','.join(['%s'] * len(column_names))
    insert_sql = f"INSERT INTO {table_name} ({','.join(column_names)}) VALUES ({placeholders})"
    
    migrated_rows = 0
    
    # Process in chunks
    offset = 0
    while offset < total_rows:
        sqlite_cursor.execute(f"SELECT * FROM {table_name} LIMIT {chunk_size} OFFSET {offset}")
        chunk_data = sqlite_cursor.fetchall()
        
        if not chunk_data:
            break
        
        try:
            postgres_cursor.executemany(insert_sql, chunk_data)
            migrated_rows += len(chunk_data)
            
            # Log progress
            progress = (migrated_rows / total_rows) * 100
            logger.info(f"Table {table_name}: {migrated_rows}/{total_rows} rows ({progress:.1f}%)")
            
        except Exception as e:
            logger.error(f"Error migrating chunk from {table_name}: {e}")
            raise
        
        offset += chunk_size
    
    logger.info(f"Table {table_name}: Migration completed ({migrated_rows} rows)")
    return True

def migrate_data(sqlite_path: str, postgres_url: str, tables_to_migrate: List[str]):
    """Migrate data from SQLite to PostgreSQL."""
    import sqlite3
    import psycopg2
    
    logger = logging.getLogger(__name__)
    
    # Connect to both databases
    sqlite_conn = sqlite3.connect(sqlite_path)
    postgres_conn = psycopg2.connect(postgres_url)
    
    sqlite_cursor = sqlite_conn.cursor()
    postgres_cursor = postgres_conn.cursor()
    
    try:
        # Disable foreign key constraints during migration
        postgres_cursor.execute("SET session_replication_role = replica;")
        
        migration_summary = []
        
        for table in tables_to_migrate:
            try:
                success = migrate_table_data(table, sqlite_cursor, postgres_cursor)
                postgres_conn.commit()
                migration_summary.append({'table': table, 'status': 'success'})
                
            except Exception as e:
                postgres_conn.rollback()
                logger.error(f"Failed to migrate table {table}: {e}")
                migration_summary.append({'table': table, 'status': 'failed', 'error': str(e)})
                raise
        
        # Re-enable foreign key constraints
        postgres_cursor.execute("SET session_replication_role = DEFAULT;")
        postgres_conn.commit()
        
        # Update sequences (for auto-increment fields)
        logger.info("Updating PostgreSQL sequences...")
        for table in tables_to_migrate:
            try:
                postgres_cursor.execute(f"""
                    SELECT setval(pg_get_serial_sequence('{table}', 'id'), 
                                 COALESCE((SELECT MAX(id) FROM {table}), 1), 
                                 MAX(id) IS NOT NULL) 
                    FROM {table};
                """)
            except Exception:
                # Skip tables without id column or sequences
                pass
        
        postgres_conn.commit()
        
        logger.info("Data migration completed successfully")
        return migration_summary
        
    except Exception as e:
        postgres_conn.rollback()
        raise
    finally:
        sqlite_conn.close()
        postgres_conn.close()

def validate_migration(sqlite_path: str, postgres_url: str, tables: List[str]):
    """Validate that migration was successful by comparing row counts."""
    import sqlite3
    import psycopg2
    
    logger = logging.getLogger(__name__)
    
    sqlite_conn = sqlite3.connect(sqlite_path)
    postgres_conn = psycopg2.connect(postgres_url)
    
    validation_results = []
    
    try:
        for table in tables:
            # Get SQLite count
            sqlite_cursor = sqlite_conn.cursor()
            sqlite_cursor.execute(f"SELECT COUNT(*) FROM {table}")
            sqlite_count = sqlite_cursor.fetchone()[0]
            
            # Get PostgreSQL count
            postgres_cursor = postgres_conn.cursor()
            postgres_cursor.execute(f"SELECT COUNT(*) FROM {table}")
            postgres_count = postgres_cursor.fetchone()[0]
            
            match = sqlite_count == postgres_count
            validation_results.append({
                'table': table,
                'sqlite_count': sqlite_count,
                'postgres_count': postgres_count,
                'match': match
            })
            
            status = "✅" if match else "❌"
            logger.info(f"{status} Table {table}: SQLite={sqlite_count}, PostgreSQL={postgres_count}")
    
    finally:
        sqlite_conn.close()
        postgres_conn.close()
    
    return validation_results

def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(description='Migrate HomeNetMon from SQLite to PostgreSQL')
    parser.add_argument('--postgres-url', required=True, 
                       help='PostgreSQL connection URL (postgresql://user:pass@host:port/db)')
    parser.add_argument('--sqlite-path', default='homeNetMon.db',
                       help='Path to SQLite database file')
    parser.add_argument('--chunk-size', type=int, default=1000,
                       help='Number of rows to process at once')
    parser.add_argument('--skip-backup', action='store_true',
                       help='Skip SQLite database backup')
    parser.add_argument('--validate-only', action='store_true',
                       help='Only validate existing migration')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging()
    
    logger.info("🚀 Starting HomeNetMon PostgreSQL Migration")
    logger.info("=" * 60)
    
    try:
        # Validate PostgreSQL connection
        if not validate_postgresql_connection(args.postgres_url):
            logger.error("PostgreSQL validation failed")
            return 1
        
        # Create Flask app context
        from app import create_app
        app = create_app()
        
        # Get list of tables to migrate
        with app.app_context():
            from models import db
            tables_to_migrate = [table.name for table in db.metadata.tables.values()]
        
        logger.info(f"Tables to migrate: {tables_to_migrate}")
        
        if args.validate_only:
            logger.info("Running migration validation...")
            validation_results = validate_migration(args.sqlite_path, args.postgres_url, tables_to_migrate)
            
            all_valid = all(result['match'] for result in validation_results)
            if all_valid:
                logger.info("✅ All tables validated successfully!")
                return 0
            else:
                logger.error("❌ Validation failed for some tables")
                return 1
        
        # Backup SQLite database
        if not args.skip_backup:
            backup_path = backup_sqlite_database(args.sqlite_path)
            logger.info(f"SQLite backup created: {backup_path}")
        
        # Create PostgreSQL schema
        with app.app_context():
            create_postgresql_schema(args.postgres_url, app)
        
        # Migrate data
        logger.info("Starting data migration...")
        migration_summary = migrate_data(args.sqlite_path, args.postgres_url, tables_to_migrate)
        
        # Validate migration
        logger.info("Validating migration...")
        validation_results = validate_migration(args.sqlite_path, args.postgres_url, tables_to_migrate)
        
        # Print summary
        logger.info("\n📊 MIGRATION SUMMARY:")
        logger.info("=" * 40)
        
        for result in validation_results:
            status = "✅" if result['match'] else "❌"
            logger.info(f"{status} {result['table']}: {result['sqlite_count']} → {result['postgres_count']}")
        
        all_valid = all(result['match'] for result in validation_results)
        
        if all_valid:
            logger.info("\n🎉 Migration completed successfully!")
            logger.info("\nNext steps:")
            logger.info("1. Update your environment variables:")
            logger.info(f"   export SQLALCHEMY_DATABASE_URI='{args.postgres_url}'")
            logger.info("2. Restart HomeNetMon application")
            logger.info("3. Test the application thoroughly")
            logger.info("4. Remove SQLite database after confirming everything works")
            return 0
        else:
            logger.error("\n❌ Migration validation failed!")
            logger.error("Some tables have mismatched row counts.")
            logger.error("Please check the logs and retry migration.")
            return 1
        
    except KeyboardInterrupt:
        logger.error("\nMigration cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"\nMigration failed: {e}")
        logger.exception("Full error details:")
        return 1

if __name__ == "__main__":
    exit(main())