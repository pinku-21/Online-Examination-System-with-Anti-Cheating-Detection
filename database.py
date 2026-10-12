"""Database layer for ExamGuard.

Uses PostgreSQL when DATABASE_URL is configured (e.g. Neon on Render).
Falls back to SQLite for local development when DATABASE_URL is absent.
"""
import os
import re
import sqlite3
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(__file__), "examguard.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

try:
    import psycopg
    from psycopg.rows import dict_row
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError, psycopg.IntegrityError)
except ImportError:
    psycopg = None
    dict_row = None
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)


class PostgresCursor:
    """Small compatibility wrapper for the SQLite-style cursor API used by app.py."""
    _ID_TABLES = {"users", "exams", "questions", "submissions", "violations"}

    def __init__(self, cursor):
        self._cursor = cursor
        self._lastrowid = None

    @staticmethod
    def _translate(sql):
        # Convert the SQLite qmark placeholders to psycopg placeholders.
        sql = sql.replace("?", "%s")
        # Translate SQLite conflict helpers before changing their prefixes.
        if re.match(r"(?is)^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+settings", sql):
            sql = re.sub(r"(?is)^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+settings", "INSERT INTO settings", sql, count=1)
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        elif re.match(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO", sql):
            sql = re.sub(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", sql, count=1)
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        return sql

    def execute(self, sql, params=None):
        self._lastrowid = None
        translated = self._translate(sql)
        match = re.match(r"(?is)^\s*INSERT\s+INTO\s+([a-z_][a-z0-9_]*)", translated)
        table = match.group(1).lower() if match else None
        # Return the generated ID for inserts whose IDs are consumed by app.py.
        if table in self._ID_TABLES and not re.search(r"(?is)\bRETURNING\b", translated):
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
            self._cursor.execute(translated, params)
            row = self._cursor.fetchone()
            if row:
                self._lastrowid = row["id"]
            return self
        self._cursor.execute(translated, params)
        return self

    @property
    def lastrowid(self):
        return self._lastrowid

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        self._cursor.close()


class PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def cursor(self):
        return PostgresCursor(self._connection.cursor())

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def get_connection():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("PostgreSQL is configured but psycopg is not installed. Add psycopg[binary] to requirements.txt.")
        # Neon recommends SSL; its connection string normally includes sslmode=require.
        raw = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return PostgresConnection(raw)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    is_postgres = bool(DATABASE_URL)

    if is_postgres:
        # Create referenced tables before tables that have foreign keys to them.
        id_type = "SERIAL PRIMARY KEY"
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            roll_number TEXT,
            class_name TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS exams (
            id SERIAL PRIMARY KEY,
            exam_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            duration_minutes INTEGER NOT NULL DEFAULT 30,
            max_warnings INTEGER NOT NULL DEFAULT 3,
            passing_percentage DOUBLE PRECISION NOT NULL DEFAULT 40.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            enable_audio_detection INTEGER DEFAULT 1,
            access_type TEXT DEFAULT 'all',
            assigned_class TEXT DEFAULT '',
            schedule_type TEXT DEFAULT 'anytime',
            start_time TEXT,
            end_time TEXT
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS questions (
            id SERIAL PRIMARY KEY,
            exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL DEFAULT 'mcq',
            options_json TEXT,
            correct_answer TEXT NOT NULL,
            explanation TEXT,
            points DOUBLE PRECISION NOT NULL DEFAULT 1.0,
            figure_svg TEXT,
            figure_url TEXT
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS exam_assignments (
            id SERIAL PRIMARY KEY,
            exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (exam_id, user_id)
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS submissions (
            id SERIAL PRIMARY KEY,
            exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
            student_name TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            answers_json TEXT,
            score DOUBLE PRECISION DEFAULT 0.0,
            total_points DOUBLE PRECISION DEFAULT 0.0,
            percentage DOUBLE PRECISION DEFAULT 0.0,
            warnings_count INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'in_progress',
            termination_reason TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP,
            user_id INTEGER
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS violations (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
            violation_type TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        # Safe, repeatable migrations for databases created by an earlier version.
        migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS class_name TEXT DEFAULT ''",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS enable_audio_detection INTEGER DEFAULT 1",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS access_type TEXT DEFAULT 'all'",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS assigned_class TEXT DEFAULT ''",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS schedule_type TEXT DEFAULT 'anytime'",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS start_time TEXT",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS end_time TEXT",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS figure_svg TEXT",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS figure_url TEXT",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS user_id INTEGER",
        ]
        for statement in migrations:
            cursor.execute(statement)
    else:
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            roll_number TEXT,
            class_name TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            duration_minutes INTEGER NOT NULL DEFAULT 30,
            max_warnings INTEGER NOT NULL DEFAULT 3,
            passing_percentage REAL NOT NULL DEFAULT 40.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            enable_audio_detection INTEGER DEFAULT 1,
            access_type TEXT DEFAULT 'all',
            assigned_class TEXT DEFAULT '',
            schedule_type TEXT DEFAULT 'anytime',
            start_time TEXT,
            end_time TEXT
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL DEFAULT 'mcq',
            options_json TEXT,
            correct_answer TEXT NOT NULL,
            explanation TEXT,
            points REAL NOT NULL DEFAULT 1.0,
            figure_svg TEXT,
            figure_url TEXT,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS exam_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE (exam_id, user_id)
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            student_name TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            answers_json TEXT,
            score REAL DEFAULT 0.0,
            total_points REAL DEFAULT 0.0,
            percentage REAL DEFAULT 0.0,
            warnings_count INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'in_progress',
            termination_reason TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            violation_type TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
        # Repair older SQLite databases using the same idempotent migration style.
        for table, column, definition in [
            ("users", "class_name", "TEXT DEFAULT ''"),
            ("exams", "enable_audio_detection", "INTEGER DEFAULT 1"),
            ("exams", "access_type", "TEXT DEFAULT 'all'"),
            ("exams", "assigned_class", "TEXT DEFAULT ''"),
            ("exams", "schedule_type", "TEXT DEFAULT 'anytime'"),
            ("exams", "start_time", "TEXT"),
            ("exams", "end_time", "TEXT"),
            ("questions", "figure_svg", "TEXT"),
            ("questions", "figure_url", "TEXT"),
            ("submissions", "user_id", "INTEGER"),
        ]:
            columns = {row["name"] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in columns:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # Seed an admin only when an initial password is explicitly configured.
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cursor.fetchone():
        initial_password = os.environ.get("ADMIN_INITIAL_PASSWORD", "").strip()
        if initial_password:
            from werkzeug.security import generate_password_hash
            if is_postgres:
                cursor.execute("INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
                               ("admin", "", generate_password_hash(initial_password), "ExamGuard Administrator", "admin"))
            else:
                cursor.execute("INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
                               ("admin", "", generate_password_hash(initial_password), "ExamGuard Administrator", "admin"))
        else:
            print("WARNING: No admin account exists. Set ADMIN_INITIAL_PASSWORD and restart to create the initial admin account.")
    conn.commit()
    conn.close()

def create_user(username, email, password, full_name, role="student", roll_number=None, class_name=None):
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    cursor = conn.cursor()
    try:
        clean_user = username.strip().lower()
        clean_email = email.strip().lower() if email else None
        clean_name = full_name.strip()
        clean_roll = roll_number.strip().upper() if roll_number else None
        clean_class = class_name.strip() if class_name else ""
        
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role, roll_number, class_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (clean_user, clean_email, generate_password_hash(password), clean_name, role, clean_roll, clean_class))
        user_id = cursor.lastrowid
        conn.commit()
        return {"success": True, "user_id": user_id, "username": clean_user, "role": role, "full_name": clean_name, "roll_number": clean_roll, "class_name": clean_class}
    except DB_INTEGRITY_ERRORS:
        return {"success": False, "error": "Username or email is already registered."}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()

def assign_exam_students(exam_id, user_ids):
    """Sets the assigned students for an exam."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM exam_assignments WHERE exam_id = ?", (exam_id,))
    for uid in user_ids:
        try:
            cursor.execute("INSERT OR IGNORE INTO exam_assignments (exam_id, user_id) VALUES (?, ?)", (exam_id, int(uid)))
        except Exception:
            pass
    conn.commit()
    conn.close()

def get_exam_assigned_students(exam_id):
    """Returns list of student users assigned to an exam."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.full_name, u.username, u.roll_number, u.class_name
        FROM exam_assignments ea
        JOIN users u ON ea.user_id = u.id
        WHERE ea.exam_id = ?
        ORDER BY u.full_name ASC
    """, (exam_id,))
    res = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return res

def authenticate_user(identifier, password):
    from werkzeug.security import check_password_hash
    conn = get_connection()
    cursor = conn.cursor()
    clean_id = identifier.strip().lower()
    cursor.execute("""
        SELECT * FROM users 
        WHERE LOWER(username) = ? OR LOWER(email) = ?
    """, (clean_id, clean_id))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user["password_hash"], password):
        return dict(user)
    return None

def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_student_submissions(user_id, roll_number=None):
    conn = get_connection()
    cursor = conn.cursor()
    if user_id and roll_number:
        cursor.execute("""
            SELECT s.*, e.title as exam_title, e.max_warnings, e.passing_percentage, e.exam_code
            FROM submissions s
            JOIN exams e ON s.exam_id = e.id
            WHERE s.user_id = ? OR s.roll_number = ?
            ORDER BY s.started_at DESC
        """, (user_id, roll_number))
    elif user_id:
        cursor.execute("""
            SELECT s.*, e.title as exam_title, e.max_warnings, e.passing_percentage, e.exam_code
            FROM submissions s
            JOIN exams e ON s.exam_id = e.id
            WHERE s.user_id = ?
            ORDER BY s.started_at DESC
        """, (user_id,))
    elif roll_number:
        cursor.execute("""
            SELECT s.*, e.title as exam_title, e.max_warnings, e.passing_percentage, e.exam_code
            FROM submissions s
            JOIN exams e ON s.exam_id = e.id
            WHERE s.roll_number = ?
            ORDER BY s.started_at DESC
        """, (roll_number,))
    else:
        results = []
        conn.close()
        return results

    results = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return results

def get_setting(key, default=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
