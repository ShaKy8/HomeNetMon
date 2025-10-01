# 🗄️ PostgreSQL Migration Guide

This guide helps you migrate HomeNetMon from SQLite to PostgreSQL for production deployment.

## Why Migrate to PostgreSQL?

- **Performance**: Better handling of concurrent connections and large datasets
- **Reliability**: ACID compliance and better crash recovery
- **Scalability**: Supports horizontal scaling and replication
- **Production Ready**: Industry standard for production applications
- **Advanced Features**: Full-text search, JSON support, advanced indexing

## Prerequisites

### 1. Install PostgreSQL Dependencies

```bash
# Install psycopg2 for PostgreSQL connectivity
pip install psycopg2-binary

# Or if you prefer the source version:
pip install psycopg2
```

### 2. Set Up PostgreSQL Database

#### Option A: Local PostgreSQL Installation
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE homeNetMon;
CREATE USER homeNetMon_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE homeNetMon TO homeNetMon_user;
\q
```

#### Option B: Docker PostgreSQL
```bash
# Run PostgreSQL in Docker
docker run -d \
  --name homeNetMon-postgres \
  -e POSTGRES_DB=homeNetMon \
  -e POSTGRES_USER=homeNetMon_user \
  -e POSTGRES_PASSWORD=secure_password \
  -p 5432:5432 \
  postgres:15
```

#### Option C: Cloud PostgreSQL (AWS RDS, Google Cloud SQL, etc.)
- Create a PostgreSQL instance in your cloud provider
- Note the connection details (host, port, username, password, database)

## Migration Process

### Step 1: Backup Current Data

```bash
# The migration script will automatically backup your SQLite database
# But you can create an additional manual backup:
cp homeNetMon.db homeNetMon.db.manual_backup_$(date +%Y%m%d_%H%M%S)
```

### Step 2: Test PostgreSQL Connection

```bash
# Test connection (replace with your actual connection details)
psql "postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon" -c "SELECT version();"
```

### Step 3: Run Migration Script

```bash
# Basic migration
python migrate_to_postgresql.py --postgres-url "postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon"

# Migration with custom SQLite path
python migrate_to_postgresql.py \
  --postgres-url "postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon" \
  --sqlite-path "path/to/your/homeNetMon.db"

# Migration with larger chunk size (for better performance on large datasets)
python migrate_to_postgresql.py \
  --postgres-url "postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon" \
  --chunk-size 5000
```

### Step 4: Validate Migration

```bash
# Run validation only (checks row counts match)
python migrate_to_postgresql.py \
  --postgres-url "postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon" \
  --validate-only
```

### Step 5: Update Configuration

```bash
# Set environment variable for PostgreSQL
export SQLALCHEMY_DATABASE_URI="postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon"

# Or add to your .env file
echo "SQLALCHEMY_DATABASE_URI=postgresql://homeNetMon_user:secure_password@localhost:5432/homeNetMon" >> .env
```

### Step 6: Test Application

```bash
# Start the application with PostgreSQL
python app.py

# Verify functionality:
# - Check dashboard loads correctly
# - Verify device data is present
# - Test monitoring functionality
# - Check historical data
# - Test alerts and notifications
```

## Migration Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `--postgres-url` | PostgreSQL connection URL (required) | None |
| `--sqlite-path` | Path to SQLite database file | `homeNetMon.db` |
| `--chunk-size` | Rows to process at once | `1000` |
| `--skip-backup` | Skip automatic SQLite backup | False |
| `--validate-only` | Only validate existing migration | False |

## Example Connection URLs

```bash
# Local PostgreSQL
postgresql://username:password@localhost:5432/database_name

# PostgreSQL with custom port
postgresql://username:password@localhost:5433/database_name

# Remote PostgreSQL
postgresql://username:password@your-host.com:5432/database_name

# AWS RDS
postgresql://username:password@your-rds-endpoint.region.rds.amazonaws.com:5432/database_name

# Google Cloud SQL
postgresql://username:password@your-cloud-sql-ip:5432/database_name

# With SSL (recommended for production)
postgresql://username:password@host:5432/database_name?sslmode=require
```

## Troubleshooting

### Connection Issues

```bash
# Test basic connectivity
ping your-postgres-host

# Test PostgreSQL port
telnet your-postgres-host 5432

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### Permission Issues

```sql
-- Grant additional permissions if needed
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO homeNetMon_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO homeNetMon_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO homeNetMon_user;
```

### Performance Optimization

```sql
-- Analyze tables after migration for better query planning
ANALYZE;

-- Create additional indexes if needed
CREATE INDEX CONCURRENTLY idx_monitoring_data_timestamp ON monitoring_data (timestamp);
CREATE INDEX CONCURRENTLY idx_monitoring_data_device_id ON monitoring_data (device_id);
CREATE INDEX CONCURRENTLY idx_alerts_created_at ON alerts (created_at);
```

### Large Dataset Migration

For very large datasets (>1M rows), consider:

1. **Increase chunk size**: `--chunk-size 10000`
2. **Disable PostgreSQL synchronous commits temporarily**:
   ```sql
   ALTER SYSTEM SET synchronous_commit = off;
   SELECT pg_reload_conf();
   ```
3. **Increase maintenance_work_mem**:
   ```sql
   ALTER SYSTEM SET maintenance_work_mem = '1GB';
   SELECT pg_reload_conf();
   ```

Remember to reset these settings after migration:
```sql
ALTER SYSTEM RESET synchronous_commit;
ALTER SYSTEM RESET maintenance_work_mem;
SELECT pg_reload_conf();
```

## Post-Migration Checklist

- [ ] All tables migrated successfully
- [ ] Row counts match between SQLite and PostgreSQL  
- [ ] Application starts without errors
- [ ] Dashboard displays correctly
- [ ] Device monitoring is working
- [ ] Historical data is accessible
- [ ] Alerts are functioning
- [ ] WebSocket real-time updates work
- [ ] API endpoints respond correctly
- [ ] Performance is acceptable

## Rollback Procedure

If you need to rollback to SQLite:

1. **Stop the application**
2. **Restore environment variable**:
   ```bash
   export SQLALCHEMY_DATABASE_URI="sqlite:///homeNetMon.db"
   ```
3. **Restore SQLite database from backup** (if needed):
   ```bash
   cp homeNetMon.db.backup_TIMESTAMP homeNetMon.db
   ```
4. **Restart the application**

## Production Recommendations

### Security
- Use SSL connections: `sslmode=require`
- Create dedicated user with minimal required permissions
- Use connection pooling
- Enable PostgreSQL logging for security auditing

### Performance
- Configure appropriate `shared_buffers` (25% of RAM)
- Set `effective_cache_size` (75% of RAM) 
- Enable `autovacuum`
- Monitor query performance with `pg_stat_statements`

### Backup Strategy
- Set up automated database backups
- Test backup restoration procedures
- Consider point-in-time recovery (PITR)
- Monitor backup success

### Monitoring
- Set up PostgreSQL monitoring (pg_stat_activity, pg_stat_database)
- Monitor connection counts and slow queries
- Set up alerts for database issues
- Regular maintenance (VACUUM, ANALYZE)

## Support

If you encounter issues during migration:

1. Check the migration log file (`migration_TIMESTAMP.log`)
2. Verify PostgreSQL connection and permissions
3. Ensure all dependencies are installed
4. Review the troubleshooting section above
5. Create an issue on GitHub with:
   - Migration command used
   - Error messages from logs
   - PostgreSQL version and configuration
   - Dataset size and characteristics