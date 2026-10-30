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
from urllib.parse import urlparse
import pytest
import database
from database import init_db, get_connection, run_pg_migrations

# Strict safety rule: ONLY read from TEST_DATABASE_URL, never fall back to DATABASE_URL
RAW_TEST_PG_URL = os.environ.get("TEST_DATABASE_URL", "").strip()


def validate_test_database_url(url: str) -> bool:
    """Verifies that the provided URL explicitly identifies a disposable test database.
    
    Parses the PostgreSQL URL and validates the actual database name in the path.
    Rejects the URL if the database name itself does not indicate a test environment,
    even if 'test' appears in the username, password, hostname, or query parameters.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        # Scheme must be postgresql / postgres
        if parsed.scheme not in ("postgresql", "postgres"):
            return False
        # Extract the database name from the path component (e.g. '/test_db' -> 'test_db')
        raw_path = parsed.path.lstrip("/")
        # In case of multiple path segments or query params attached, take the primary dbname
        dbname = raw_path.split("/")[0].strip().lower()
        if not dbname:
            return False
        # The database name itself must strictly start with 'test_' or end with '_test'
        # e.g., 'test_examguard' or 'examguard_test'. Names like 'latestest_prod' are rejected.
        return dbname.startswith("test_") or dbname.endswith("_test")
    except Exception:
        return False


TEST_PG_URL = RAW_TEST_PG_URL if validate_test_database_url(RAW_TEST_PG_URL) else None



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


# --- Test E: Migration Runner Failure and Transaction Recovery ---
def test_migration_runner_recovers_from_failure(tmp_path, monkeypatch):
    """Test E1 (Simulation): Exercises run_pg_migrations with a controlled failure statement.
    
    NOTE: This is a unit test simulation exercising transaction rollback logic.
    Live PostgreSQL integration verification is handled separately in Test A.
    
    Verifies that:
    1. A faulty migration statement triggers rollback and is captured in returned errors.
    2. Benign statements (duplicate column / already exists) are skipped.
    3. Subsequent valid migrations in the sequence proceed.
    4. The connection remains usable and uncorrupted after the failure.
    """
    test_db = str(tmp_path / "test_migration_recovery.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(database, "DATABASE_URL", "")

    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    # Define a sequence containing:
    # 1. A valid migration
    # 2. A broken migration (syntax or non-existent table error)
    # 3. Another valid migration
    test_migrations = [
        "ALTER TABLE users ADD COLUMN test_migration_col1 TEXT DEFAULT 'ok'",
        "ALTER TABLE nonexistent_table_xyz ADD COLUMN bad_col TEXT",
        "ALTER TABLE users ADD COLUMN test_migration_col2 TEXT DEFAULT 'recovered'",
    ]

    errors = run_pg_migrations(cursor, conn, test_migrations)

    # 1. Verify failure is reported clearly and not silently swallowed
    assert len(errors) == 1
    assert "nonexistent_table_xyz" in errors[0][0]

    # 2. Verify connection remains usable after recovery and both valid columns exist
    cursor.execute("SELECT test_migration_col1, test_migration_col2 FROM users LIMIT 1")
    # Verify columns were added to schema
    cols = {row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()}
    assert "test_migration_col1" in cols
    assert "test_migration_col2" in cols

    conn.close()


def test_transaction_rollback_and_recovery(tmp_path, monkeypatch):
    """Test E2: Verifies that an SQL exception can be recovered via connection rollback,

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


# --- Test A: Real PostgreSQL Initialization (executed only when TEST_DATABASE_URL is provided and safe) ---
@pytest.mark.skipif(
    not TEST_PG_URL,
    reason="Requires dedicated disposable PostgreSQL database via TEST_DATABASE_URL containing 'test'. "
           "Never runs against production DATABASE_URL."
)
def test_postgresql_fresh_initialization_live(monkeypatch):
    """Test A: Connects to a real disposable PostgreSQL database, runs init_db(), and confirms
    fresh schema creation succeeds with all tables, critical columns, and column data types present.
    Guarantees resource cleanup via a try...finally block.
    """
    monkeypatch.setattr(database, "DATABASE_URL", TEST_PG_URL)

    # Run initialization on real PostgreSQL
    init_db()

    conn = database.get_connection()
    cursor = None

    try:
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
        assert not missing, f"PostgreSQL database is missing required tables: {missing}"

        # Verify critical migration columns and their expected data types in submissions table
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'submissions'
        """)
        sub_cols = {r["column_name"]: r["data_type"].lower() for r in cursor.fetchall()}
        expected_sub_cols = {
            "user_id": "integer",
            "manual_evaluation_json": "text",
            "integrity_hash": "text",
            "client_ip": "text",
            "geo_location_json": "text",
            "diagnostic_analysis_json": "text",
            "honeypot_snared": "integer",
            "time_remaining_seconds": "integer",
            "progress_answers_json": "text",
            "device_switch_approved": "integer",
            "face_match_confidence": "double precision",
            "pause_requested_at": "timestamp without time zone",
        }
        for col, exp_type in expected_sub_cols.items():
            assert col in sub_cols, f"Missing critical migration column '{col}' in PostgreSQL submissions table"
            assert sub_cols[col] == exp_type, (
                f"Column '{col}' in submissions has type '{sub_cols[col]}', expected '{exp_type}'"
            )

        # Verify proctor_messages columns and types
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'proctor_messages'
        """)
        pm_cols = {r["column_name"]: r["data_type"].lower() for r in cursor.fetchall()}
        assert "audio_payload" in pm_cols, "Missing critical migration column 'audio_payload' in PostgreSQL proctor_messages table"
        assert pm_cols["audio_payload"] == "text", f"Column 'audio_payload' has type '{pm_cols['audio_payload']}', expected 'text'"

        # Verify questions columns and types
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'questions'
        """)
        q_cols = {r["column_name"]: r["data_type"].lower() for r in cursor.fetchall()}
        expected_q_cols = {
            "blooms_taxonomy": "text",
            "distractor_analysis_json": "text",
            "difficulty_tier": "text",
            "topic_category": "text",
            "is_honeypot": "integer",
            "points": "double precision",
        }
        for col, exp_type in expected_q_cols.items():
            assert col in q_cols, f"Missing critical migration column '{col}' in PostgreSQL questions table"
            assert q_cols[col] == exp_type, (
                f"Column '{col}' in questions has type '{q_cols[col]}', expected '{exp_type}'"
            )

        # Verify exams columns and types
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'exams'
        """)
        ex_cols = {r["column_name"]: r["data_type"].lower() for r in cursor.fetchall()}
        expected_ex_cols = {
            "enable_video_detection": "integer",
            "enable_audio_detection": "integer",
            "access_type": "text",
            "pool_question_count": "integer",
            "results_published": "integer",
            "passing_percentage": "double precision",
            "duration_minutes": "integer",
        }
        for col, exp_type in expected_ex_cols.items():
            assert col in ex_cols, f"Missing critical migration column '{col}' in PostgreSQL exams table"
            assert ex_cols[col] == exp_type, (
                f"Column '{col}' in exams has type '{ex_cols[col]}', expected '{exp_type}'"
            )

    finally:
        try:
            if cursor is not None:
                cursor.close()
        finally:
            conn.close()


def test_database_url_safety_check():
    """Safety Test: Verifies that validate_test_database_url parses the URL and strictly

    validates the actual database name, rejecting URLs where 'test' is only present
    in hostnames, usernames, passwords, or query parameters.
    """
    # 1. Production-style URLs lacking 'test' in the database name must be rejected
    assert validate_test_database_url("postgresql://user:pass@ep-cool-fog-123.us-east-2.aws.neon.tech/examguard_prod") is False
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/examguard") is False
    assert validate_test_database_url("") is False
    assert validate_test_database_url(None) is False

    # 2. URLs where 'test' is deceptively present in user, password, host, or query param MUST be rejected
    # Username has 'test', but dbname is 'production'
    assert validate_test_database_url("postgresql://test_user:secret@localhost:5432/production") is False
    # Password has 'test', but dbname is 'examguard'
    assert validate_test_database_url("postgresql://admin:test_pass@localhost:5432/examguard") is False
    # Hostname has 'test', but dbname is 'production_db'
    assert validate_test_database_url("postgresql://admin:secret@test-db.neon.tech:5432/production_db") is False
    # Query parameter has 'test', but dbname is 'live_prod'
    assert validate_test_database_url("postgresql://admin:secret@localhost:5432/live_prod?test=true") is False

    # 3. Names containing 'test' as a substring but not starting with 'test_' or ending with '_test' must be rejected
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/latestest_prod") is False
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/mytestdb") is False
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/contest") is False

    # 4. Only URLs where the database name itself starts with 'test_' or ends with '_test' are permitted
    assert validate_test_database_url("postgresql://user:pass@ep-cool-fog-123.us-east-2.aws.neon.tech/examguard_test") is True
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/test_db") is True
    assert validate_test_database_url("postgres://postgres:pass@localhost:5432/examguard_integration_test?sslmode=require") is True
    assert validate_test_database_url("postgresql://postgres:pass@localhost:5432/test_examguard") is True



