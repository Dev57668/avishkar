"""PostgreSQL translation is verified statically here; a live-server run is documented in docs/POSTGRES.md."""
import sqlite3

from avishkar.adapters.db import SCHEMA, Database, _pg_schema


def test_pg_schema_translation_has_no_sqlite_only_syntax():
    pg = _pg_schema(SCHEMA)
    assert "AUTOINCREMENT" not in pg and "BIGSERIAL PRIMARY KEY" in pg
    assert "REAL" not in pg.replace("DOUBLE PRECISION", "") and "DOUBLE PRECISION" in pg
    assert pg.count("CREATE TABLE") == SCHEMA.count("CREATE TABLE")


def test_placeholder_translation():
    d = Database.__new__(Database)
    d.pg = True
    assert d._sql("SELECT * FROM t WHERE a=? AND b=?") == "SELECT * FROM t WHERE a=%s AND b=%s"
    d.pg = False
    assert d._sql("a=?") == "a=?"


def test_sqlite_schema_is_valid_and_idempotent(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    Database(str(tmp_path / "x.db"))  # CREATE IF NOT EXISTS
    tables = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"organization", "app_user", "api_key", "job", "webhook_delivery", "github_installation", "explanation",
            "finding", "analysis_run", "audit_event", "ref_head"} <= tables


def test_no_sqlite_specific_sql_in_store():
    import inspect
    from avishkar.adapters import store
    src = inspect.getsource(store)
    for banned in ("rowid", "INSERT OR", "AUTOINCREMENT", "lastrowid", "sqlite_master"):
        assert banned not in src, banned


def test_failed_statement_rolls_back(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    db.execute("INSERT INTO organization VALUES('o1','a',0)")
    try:
        db.execute("INSERT INTO organization VALUES('o2','a',0)")  # unique name violation
    except sqlite3.IntegrityError:
        pass
    assert len(db.query("SELECT * FROM organization")) == 1
    db.execute("INSERT INTO organization VALUES('o3','b',0)")  # connection still healthy


def test_transaction_is_atomic_and_nests(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        with db.transaction():
            db.execute("INSERT INTO organization VALUES('o1','a',0)")
            with db.transaction():  # nested joins the outer unit
                db.execute("INSERT INTO organization VALUES('o2','b',0)")
            assert len(db.query("SELECT * FROM organization")) == 2  # reads see own uncommitted writes
            raise RuntimeError("abort")
    except RuntimeError:
        pass
    assert db.query("SELECT * FROM organization") == []  # whole unit rolled back
    with db.transaction():
        db.execute("INSERT INTO organization VALUES('o3','c',0)")
    assert len(db.query("SELECT * FROM organization")) == 1


def test_enqueue_survives_idempotency_race(tmp_path, monkeypatch):
    from avishkar.adapters.store import Store
    st = Store(str(tmp_path / "x.db"))
    org = st.create_org("o")["id"]
    first, created = st.enqueue(org, "r", "run1", "archive", {}, "k")
    assert created
    monkeypatch.setattr(st, "job_by_idem", lambda *a: first if not hasattr(st, "_seen") else None)
    real = st.d.query
    calls = {"n": 0}

    def blind(sql, args=()):  # simulate the pre-check missing the concurrent insert
        if "idempotency_key=?" in sql and calls["n"] == 0:
            calls["n"] += 1
            return []
        return real(sql, args)
    monkeypatch.setattr(st.d, "query", blind)
    job, created = st.enqueue(org, "r", "run2", "archive", {}, "k")
    assert not created and job["id"] == first["id"]
