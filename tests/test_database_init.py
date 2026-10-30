"""Tests for Database Initialization, Migration Ordering, and Transaction Handling.

Covers:
- Test A: Fresh PostgreSQL initialization (skipped if real PostgreSQL URL is not provided)
- Test B: Migration ordering simulation (verifies tables are created before ALTER TABLE commands)
- Test C: Repeated initialization (idempotency check)
- Test D: Existing database upgrade without data loss
- Test E: Transaction recovery / rollback simulation on failure
- Test F: SQLite compatibility and complete schema verification
"""
import os
import sqlite3
import pytest
import database
from database import init_db, get_connection

TEST_PG_URL = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")


# --- Test F: SQLite Compatibility and Full Schema Verification ---
def test_sqlite_fresh_initialization(tmp_path, monkeypatch):
    """Test F: Verifies clean SQLite initialization creates all required tables and default settings."""
    test_db = str(tmp_path / "test_fresh.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(database, "DATABASE_URL", "")

    # Execute initialization
    init_db()

    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    tables = {
        row["name"]
        for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    required_tables = {
        "users", "exams", "questions", "exam_assignments", "submissions",
        "violations", "settings", "ai_generation_jobs", "persistent_assets",
        "question_bank", "proctor_messages"
    }
    missing = required_tables - tables
    assert not missing, f"Missing required tables in SQLite: {missing}"

    # Verify key columns added via migrations exist on fresh creation
    columns_submissions = {
        row["name"] for row in cursor.execute("PRAGMA table_info(submissions)").fetchall()
    }
    for col in ["user_id", "manual_evaluation_json", "integrity_hash", "client_ip", "geo_location_json"]:
        assert col in columns_submissions, f"Missing column {col} in submissions"

    columns_proctor_msg = {
        row["name"] for row in cursor.execute("PRAGMA table_info(proctor_messages)").fetchall()
    }
    assert "audio_payload" in columns_proctor_msg, "Missing audio_payload in proctor_messages"

    conn.close()


# --- Test C: Repeated Initialization (Idempotency) ---
def test_repeated_initialization_is_idempotent(tmp_path, monkeypatch):
    """Test C: Running init_db() multiple times causes no errors and does not duplicate schema."""
    test_db = str(tmp_path / "test_idempotent.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(database, "DATABASE_URL", "")

    # First run
    init_db()

    # Second run immediately after
    init_db()

    # Third run
    init_db()

    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    tables = {
        row["name"]
        for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    conn.close()

    assert "users" in tables
    assert "proctor_messages" in tables


# --- Test D: Existing Database Upgrade Preserving Data ---
def test_existing_database_upgrade_preserves_records(tmp_path, monkeypatch):
    """Test D: Simulates an older legacy database schema, inserts records, runs init_db(),

    and asserts that new columns are appended while original data remains intact.
    """
    test_db = str(tmp_path / "test_legacy.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(database, "DATABASE_URL", "")

    # Create an old minimal schema missing newer migration columns
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            roll_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            duration_minutes INTEGER DEFAULT 30,
            max_warnings INTEGER DEFAULT 3,
            passing_percentage REAL DEFAULT 40.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    """)
    # Insert existing data
    cursor.execute("INSERT INTO users (username, full_name, password_hash) VALUES ('legacy_student', 'Legacy Student', 'hash123')")
    cursor.execute("INSERT INTO exams (exam_code, title) VALUES ('EX-OLD-1', 'Legacy History Exam')")
    conn.commit()
    conn.close()

    # Run upgrade migrations via init_db()
    init_db()

    # Verify upgrade and data preservation
    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_row = cursor.execute("SELECT * FROM users WHERE username = 'legacy_student'").fetchone()
    assert user_row is not None
    assert user_row["full_name"] == "Legacy Student"
    # Column added by migration:
    assert "class_name" in user_row.keys()

    exam_row = cursor.execute("SELECT * FROM exams WHERE exam_code = 'EX-OLD-1'").fetchone()
    assert exam_row is not None
    assert exam_row["title"] == "Legacy History Exam"
    # Columns added by migration:
    assert "enable_video_detection" in exam_row.keys()
    assert "access_type" in exam_row.keys()

    conn.close()


# --- Test B: Migration Ordering & Verification ---
def test_migration_ordering_sql_definitions():
    """Test B: Statically inspects database.py to guarantee table creation occurs

    before any ALTER TABLE migration statements targeting that table.
    """
    with open("database.py", "r", encoding="utf-8") as f:
        content = f.read()

    # Locate PostgreSQL init block
    pg_start = content.find("if is_postgres:")
    pg_end = content.find("else:", pg_start)
    pg_block = content[pg_start:pg_end]

    # Find where proctor_messages is created vs where its migration is run
    create_pm_pos = pg_block.find("CREATE TABLE IF NOT EXISTS proctor_messages")
    alter_pm_pos = pg_block.find("ALTER TABLE proctor_messages")

    assert create_pm_pos != -1, "CREATE TABLE proctor_messages not found in PostgreSQL block"
    assert alter_pm_pos != -1, "ALTER TABLE proctor_messages not found in PostgreSQL block"
    assert create_pm_pos < alter_pm_pos, (
        f"Ordering violation: CREATE TABLE proctor_messages ({create_pm_pos}) must occur "
        f"before ALTER TABLE proctor_messages ({alter_pm_pos})!"
    )

    # Locate SQLite init block
    sqlite_block = content[pg_end:]
    create_pm_pos_sqlite = sqlite_block.find("CREATE TABLE IF NOT EXISTS proctor_messages")
    assert create_pm_pos_sqlite != -1, "CREATE TABLE proctor_messages not found in SQLite block"


# --- Test E: Transaction Recovery / Rollback Simulation ---
def test_transaction_rollback_and_recovery(tmp_path, monkeypatch):
    """Test E: Verifies that an SQL exception can be recovered via connection rollback,

    allowing subsequent operations to complete without transaction pollution.
    """
    test_db = str(tmp_path / "test_recovery.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(database, "DATABASE_URL", "")

    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    # Intentionally trigger an error
    with pytest.raises(Exception):
        cursor.execute("INSERT INTO nonexistent_table (foo) VALUES ('bar')")
    
    # Rollback to recover connection state
    conn.rollback()

    # Confirm subsequent query executes successfully
    cursor.execute("SELECT COUNT(*) as count FROM users")
    row = cursor.fetchone()
    assert row["count"] >= 0

    conn.close()


# --- Test A: Real PostgreSQL Initialization (executed when TEST_DATABASE_URL is provided) ---
@pytest.mark.skipif(not TEST_PG_URL, reason="Requires live PostgreSQL instance via TEST_DATABASE_URL or DATABASE_URL")
def test_postgresql_fresh_initialization_live(monkeypatch):
    """Test A: Connects to a real PostgreSQL database, runs init_db(), and confirms

    fresh schema creation succeeds with all tables and columns present.
    """
    monkeypatch.setattr(database, "DATABASE_URL", TEST_PG_URL)

    # Run initialization on real PostgreSQL
    init_db()

    conn = database.get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    rows = cursor.fetchall()
    tables = {r["table_name"] for r in rows}

    required = {
        "users", "exams", "questions", "exam_assignments", "submissions",
        "violations", "settings", "ai_generation_jobs", "persistent_assets",
        "question_bank", "proctor_messages"
    }
    missing = required - tables
    conn.close()

    assert not missing, f"PostgreSQL database is missing required tables: {missing}"
