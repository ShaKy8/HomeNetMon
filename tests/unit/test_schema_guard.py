"""init_db adds columns that create_all() cannot add to an existing table, idempotently."""

from sqlalchemy import text

from models import _ensure_columns, db


def test_missing_columns_are_added_once(app, db_session):
    with app.app_context():
        db.session.execute(text("CREATE TABLE IF NOT EXISTS guard_probe (id INTEGER PRIMARY KEY)"))
        db.session.commit()
        try:
            assert _ensure_columns('guard_probe', {'notes': 'TEXT', 'tags': 'VARCHAR(255)'}) == ['notes', 'tags']
            assert _ensure_columns('guard_probe', {'notes': 'TEXT', 'tags': 'VARCHAR(255)'}) == []
            cols = {r[1] for r in db.session.execute(text("PRAGMA table_info(guard_probe)")).fetchall()}
            assert {'id', 'notes', 'tags'} <= cols
        finally:
            db.session.execute(text("DROP TABLE guard_probe"))
            db.session.commit()


def test_devices_table_has_identification_columns(app, db_session):
    with app.app_context():
        cols = {r[1] for r in db.session.execute(text("PRAGMA table_info(devices)")).fetchall()}
        assert {'notes', 'tags', 'mdns_services'} <= cols
