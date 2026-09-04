"""
Single source of truth for time-based data retention.

Every high-volume or append-only table is listed once in RETENTION_TABLES with
its timestamp column, the runtime Configuration key that overrides the default
number of days, and an optional extra predicate. ResourceMonitor calls
run_all() hourly. Deletes are batched by rowid so a large backlog never holds a
long write lock, and a passive WAL checkpoint follows each pass.

Runtime precedence for the number of days:
    Configuration[<config_key>]  ->  Configuration['data_retention_days'] (bulk tables only)
    ->  the default listed here.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import text

from config import Config
from models import Configuration, db

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000
MAX_BATCHES_PER_TABLE = 500          # 500k rows per table per pass; the rest next hour


@dataclass(frozen=True)
class RetentionRule:
    table: str
    ts_column: str
    config_key: str
    default_days: int
    extra_where: Optional[str] = None   # additional SQL predicate, e.g. "resolved = 1"
    follows_global: bool = False        # also honour the global data_retention_days setting
    label: str = ''


RETENTION_TABLES: tuple[RetentionRule, ...] = (
    RetentionRule('monitoring_data', 'timestamp', 'data_retention_days', Config.DATA_RETENTION_DAYS,
                  follows_global=True, label='monitoring records'),
    RetentionRule('performance_metrics', 'timestamp', 'performance_retention_days', Config.DATA_RETENTION_DAYS,
                  follows_global=True, label='performance records'),
    RetentionRule('interface_bandwidth', 'timestamp', 'bandwidth_retention_days', Config.DATA_RETENTION_DAYS,
                  follows_global=True, label='interface bandwidth samples'),
    RetentionRule('bandwidth_data', 'timestamp', 'bandwidth_retention_days', Config.DATA_RETENTION_DAYS,
                  follows_global=True, label='legacy per-device bandwidth rows'),
    RetentionRule('notification_history', 'sent_at', 'notification_retention_days', 30,
                  label='notification history rows'),
    RetentionRule('notification_receipts', 'created_at', 'notification_retention_days', 30,
                  label='notification receipts'),
    RetentionRule('security_scans', 'scanned_at', 'security_retention_days', 90, label='security scan rows'),
    RetentionRule('security_events', 'created_at', 'security_retention_days', 90, label='security events'),
    RetentionRule('security_vulnerabilities', 'discovered_at', 'security_retention_days', 90,
                  extra_where="status != 'open'", label='closed vulnerabilities'),
    RetentionRule('configuration_history', 'changed_at', 'config_history_retention_days', 365,
                  label='configuration history rows'),
    RetentionRule('rule_executions', 'executed_at', 'execution_retention_days', 30, label='rule executions'),
    RetentionRule('escalation_executions', 'created_at', 'execution_retention_days', 30,
                  label='escalation executions'),
    RetentionRule('escalation_action_logs', 'executed_at', 'execution_retention_days', 30,
                  label='escalation action logs'),
    RetentionRule('device_ip_history', 'change_detected_at', 'ip_history_retention_days', 365, label='IP history rows'),
    RetentionRule('speed_test_results', 'timestamp', 'speedtest_retention_days', 180, label='speed test results'),
    RetentionRule('alerts', 'resolved_at', 'resolved_alert_retention_days', 30,
                  extra_where='resolved = 1', label='resolved alerts'),
)

_state_lock = threading.Lock()
_state: dict = {'last_run': None, 'last_duration_s': None, 'last_deleted': {}, 'runs': 0, 'errors': 0}


def status() -> dict:
    """Snapshot for /api/system/health."""
    with _state_lock:
        return dict(_state, last_deleted=dict(_state['last_deleted']))


def _days_for(rule: RetentionRule) -> int:
    """Resolve the retention period for a rule (must run inside an app context)."""
    value = Configuration.get_value(rule.config_key)
    if value is None and rule.follows_global:
        value = Configuration.get_value('data_retention_days')
    try:
        days = int(value) if value is not None else rule.default_days
    except (TypeError, ValueError):
        days = rule.default_days
    return max(1, days)


def _table_exists(name: str) -> bool:
    row = db.session.execute(
        text("SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n") if db.engine.url.get_backend_name() == 'sqlite'
        else text("SELECT 1 FROM information_schema.tables WHERE table_name=:n"),
        {'n': name},
    ).first()
    return row is not None


def purge_table(rule: RetentionRule, days: Optional[int] = None, dry_run: bool = False) -> int:
    """Delete rows older than `days` (default: configured) in rowid batches. Returns rows deleted.

    Must be called inside an app context. Table and column names come only from
    RETENTION_TABLES, never from user input.
    """
    if not _table_exists(rule.table):
        logger.debug(f"Retention: table {rule.table} not present, skipping")
        return 0
    days = days if days is not None else _days_for(rule)
    cutoff = datetime.utcnow() - timedelta(days=days)
    where = f"{rule.ts_column} < :cutoff" + (f" AND ({rule.extra_where})" if rule.extra_where else "")

    if dry_run:
        n = db.session.execute(text(f"SELECT count(*) FROM {rule.table} WHERE {where}"), {'cutoff': cutoff}).scalar()
        logger.info(f"Retention dry-run: {n:,} {rule.label} older than {days} days would be deleted")
        return n

    deleted = 0
    for _ in range(MAX_BATCHES_PER_TABLE):
        result = db.session.execute(
            text(f"DELETE FROM {rule.table} WHERE rowid IN "
                 f"(SELECT rowid FROM {rule.table} WHERE {where} LIMIT :batch)"),
            {'cutoff': cutoff, 'batch': BATCH_SIZE},
        )
        db.session.commit()
        deleted += result.rowcount
        if result.rowcount < BATCH_SIZE:
            break
    else:
        logger.warning(f"Retention: hit the per-pass cap on {rule.table} ({deleted:,} rows); continuing next pass")
    if deleted:
        logger.info(f"Retention: deleted {deleted:,} {rule.label} older than {days} days")
    return deleted


def run_all(app, dry_run: bool = False) -> dict:
    """Apply every retention rule. Safe to call from any thread; opens its own app context."""
    started = time.monotonic()
    deleted: dict[str, int] = {}
    errors = 0
    with app.app_context():
        for rule in RETENTION_TABLES:
            try:
                n = purge_table(rule, dry_run=dry_run)
                if n:
                    deleted[rule.table] = n
            except Exception as e:  # keep going: one bad table must not block the others
                errors += 1
                db.session.rollback()
                logger.error(f"Retention failed for {rule.table}: {e}")
        if not dry_run and db.engine.url.get_backend_name() == 'sqlite':
            try:
                db.session.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
                db.session.commit()
            except Exception as e:
                logger.debug(f"WAL checkpoint skipped: {e}")
    duration = time.monotonic() - started
    with _state_lock:
        _state.update(last_run=datetime.utcnow().isoformat() + 'Z', last_duration_s=round(duration, 2),
                      last_deleted=deleted, runs=_state['runs'] + 1, errors=_state['errors'] + errors)
    logger.info(f"Retention pass finished in {duration:.1f}s: "
                + (', '.join(f"{t}={n:,}" for t, n in deleted.items()) if deleted else 'nothing to delete'))
    return deleted
