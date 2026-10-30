"""Database layer for ExamGuard.

Uses PostgreSQL when DATABASE_URL is configured (e.g. Neon on Render).
Falls back to SQLite for local development when DATABASE_URL is absent.
"""
import os
import re
import sqlite3
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

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
            enable_video_detection INTEGER DEFAULT 1,
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
        cursor.execute("""CREATE TABLE IF NOT EXISTS ai_generation_jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'running',
            result_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS persistent_assets (
            asset_key TEXT PRIMARY KEY,
            mime_type TEXT NOT NULL,
            data_base64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        # Safe, repeatable migrations for databases created by an earlier version.
        migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS class_name TEXT DEFAULT ''",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS enable_video_detection INTEGER DEFAULT 1",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS enable_audio_detection INTEGER DEFAULT 1",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS access_type TEXT DEFAULT 'all'",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS assigned_class TEXT DEFAULT ''",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS schedule_type TEXT DEFAULT 'anytime'",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS start_time TEXT",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS end_time TEXT",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS figure_svg TEXT",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS figure_url TEXT",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS user_id INTEGER",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS manual_evaluation_json TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo TEXT DEFAULT ''",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS verified_face_url TEXT DEFAULT ''",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS is_face_verified INTEGER DEFAULT 0",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS face_match_confidence DOUBLE PRECISION DEFAULT 0.0",
            # Pause/resume and progress-save columns
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS time_remaining_seconds INTEGER",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS progress_answers_json TEXT",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS pause_requested_at TIMESTAMP",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS pause_reason TEXT",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS current_question_index INTEGER DEFAULT 0",
            # Results publishing and single-device session enforcement
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS results_published INTEGER DEFAULT 0",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS is_published INTEGER DEFAULT 0",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS device_switch_approved INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS active_session_token TEXT DEFAULT ''",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS integrity_hash TEXT DEFAULT ''",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS client_ip TEXT DEFAULT ''",
            "ALTER TABLE violations ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'HIGH'",
            "ALTER TABLE violations ADD COLUMN IF NOT EXISTS event_code TEXT DEFAULT 'SEC-ALERT'",
            "ALTER TABLE violations ADD COLUMN IF NOT EXISTS is_resolved INTEGER DEFAULT 0",
            "ALTER TABLE violations ADD COLUMN IF NOT EXISTS snapshot_url TEXT DEFAULT ''",
            # AI Honeypot & Counter-Espionage Trap
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS is_honeypot INTEGER DEFAULT 0",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS honeypot_signature TEXT DEFAULT ''",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS honeypot_perturbation_type TEXT DEFAULT 'none'",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS honeypot_snared INTEGER DEFAULT 0",
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS honeypot_details TEXT DEFAULT ''",
            # Feature 1 & 2: Diagnostic Weak-Area Analysis & Dynamic Permutations
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS diagnostic_analysis_json TEXT DEFAULT ''",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS topic_category TEXT DEFAULT 'General'",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty_tier TEXT DEFAULT 'medium'",
            "ALTER TABLE exams ADD COLUMN IF NOT EXISTS pool_question_count INTEGER DEFAULT 0",
            "ALTER TABLE proctor_messages ADD COLUMN IF NOT EXISTS audio_payload TEXT DEFAULT ''",
            # AI Distractor Analysis & Bloom's Taxonomy
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS blooms_taxonomy TEXT DEFAULT 'Understand'",
            "ALTER TABLE questions ADD COLUMN IF NOT EXISTS distractor_analysis_json TEXT DEFAULT '{}'",
            # IP Geolocation & Hazard Intelligence
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS geo_location_json TEXT DEFAULT ''",
        ]
        cursor.execute("""CREATE TABLE IF NOT EXISTS question_bank (
            id SERIAL PRIMARY KEY,
            tutor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            category TEXT NOT NULL DEFAULT 'General',
            chapter TEXT DEFAULT '',
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL DEFAULT 'mcq',
            options_json TEXT,
            correct_answer TEXT NOT NULL,
            explanation TEXT,
            points DOUBLE PRECISION NOT NULL DEFAULT 1.0,
            difficulty_tier TEXT DEFAULT 'Medium',
            blooms_taxonomy TEXT DEFAULT 'Understand',
            distractor_analysis_json TEXT DEFAULT '{}',
            figure_svg TEXT,
            figure_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS proctor_messages (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            severity TEXT DEFAULT 'warning',
            is_read INTEGER DEFAULT 0,
            audio_payload TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        for statement in migrations:
            try:
                cursor.execute(statement)
            except Exception as e:
                print(f"Migration warning: {e}")
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
            enable_video_detection INTEGER DEFAULT 1,
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
        cursor.execute("""CREATE TABLE IF NOT EXISTS ai_generation_jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'running',
            result_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS persistent_assets (
            asset_key TEXT PRIMARY KEY,
            mime_type TEXT NOT NULL,
            data_base64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        # Repair older SQLite databases using the same idempotent migration style.
        for table, column, definition in [
            ("users", "class_name", "TEXT DEFAULT ''"),
            ("exams", "enable_video_detection", "INTEGER DEFAULT 1"),
            ("exams", "enable_audio_detection", "INTEGER DEFAULT 1"),
            ("exams", "access_type", "TEXT DEFAULT 'all'"),
            ("exams", "assigned_class", "TEXT DEFAULT ''"),
            ("exams", "schedule_type", "TEXT DEFAULT 'anytime'"),
            ("exams", "start_time", "TEXT"),
            ("exams", "end_time", "TEXT"),
            ("questions", "figure_svg", "TEXT"),
            ("questions", "figure_url", "TEXT"),
            ("submissions", "user_id", "INTEGER"),
            ("submissions", "manual_evaluation_json", "TEXT"),
            ("users", "profile_photo", "TEXT DEFAULT ''"),
            ("submissions", "verified_face_url", "TEXT DEFAULT ''"),
            ("submissions", "is_face_verified", "INTEGER DEFAULT 0"),
            ("submissions", "face_match_confidence", "REAL DEFAULT 0.0"),
            # Pause/resume and progress-save columns
            ("submissions", "time_remaining_seconds", "INTEGER"),
            ("submissions", "progress_answers_json", "TEXT"),
            ("submissions", "pause_requested_at", "TIMESTAMP"),
            ("submissions", "pause_reason", "TEXT"),
            ("submissions", "current_question_index", "INTEGER DEFAULT 0"),
            # Results publishing and single-device session enforcement
            ("exams", "results_published", "INTEGER DEFAULT 0"),
            ("submissions", "is_published", "INTEGER DEFAULT 0"),
            ("submissions", "device_switch_approved", "INTEGER DEFAULT 0"),
            ("users", "active_session_token", "TEXT DEFAULT ''"),
            ("submissions", "integrity_hash", "TEXT DEFAULT ''"),
            ("submissions", "client_ip", "TEXT DEFAULT ''"),
            ("violations", "severity", "TEXT DEFAULT 'HIGH'"),
            ("violations", "event_code", "TEXT DEFAULT 'SEC-ALERT'"),
            ("violations", "is_resolved", "INTEGER DEFAULT 0"),
            ("violations", "snapshot_url", "TEXT DEFAULT ''"),
            # AI Honeypot & Counter-Espionage Trap
            ("questions", "is_honeypot", "INTEGER DEFAULT 0"),
            ("questions", "honeypot_signature", "TEXT DEFAULT ''"),
            ("questions", "honeypot_perturbation_type", "TEXT DEFAULT 'none'"),
            ("submissions", "honeypot_snared", "INTEGER DEFAULT 0"),
            ("submissions", "honeypot_details", "TEXT DEFAULT ''"),
            # Feature 1 & 2: Diagnostic Weak-Area Analysis & Dynamic Permutations
            ("submissions", "diagnostic_analysis_json", "TEXT DEFAULT ''"),
            ("questions", "topic_category", "TEXT DEFAULT 'General'"),
            ("questions", "difficulty_tier", "TEXT DEFAULT 'medium'"),
            ("exams", "pool_question_count", "INTEGER DEFAULT 0"),
            ("proctor_messages", "audio_payload", "TEXT DEFAULT ''"),
            # AI Distractor Analysis & Bloom's Taxonomy
            ("questions", "blooms_taxonomy", "TEXT DEFAULT 'Understand'"),
            ("questions", "distractor_analysis_json", "TEXT DEFAULT '{}'"),
            # IP Geolocation & Hazard Intelligence
            ("submissions", "geo_location_json", "TEXT DEFAULT ''"),
        ]:
            columns = {row["name"] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in columns:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

        cursor.execute("""CREATE TABLE IF NOT EXISTS question_bank (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tutor_id INTEGER,
            category TEXT NOT NULL DEFAULT 'General',
            chapter TEXT DEFAULT '',
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL DEFAULT 'mcq',
            options_json TEXT,
            correct_answer TEXT NOT NULL,
            explanation TEXT,
            points REAL NOT NULL DEFAULT 1.0,
            difficulty_tier TEXT DEFAULT 'Medium',
            blooms_taxonomy TEXT DEFAULT 'Understand',
            distractor_analysis_json TEXT DEFAULT '{}',
            figure_svg TEXT,
            figure_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tutor_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS proctor_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            severity TEXT DEFAULT 'warning',
            is_read INTEGER DEFAULT 0,
            audio_payload TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
        )""")

    # Seed initial admin(s) if provided via environment variables.
    from werkzeug.security import generate_password_hash
    
    # Primary Admin
    initial_password = os.environ.get("ADMIN_INITIAL_PASSWORD", "").strip()
    if initial_password:
        initial_username = os.environ.get("ADMIN_INITIAL_USERNAME", "admin").strip()
        initial_email = os.environ.get("ADMIN_INITIAL_EMAIL", f"{initial_username.lower()}@examguard.ai").strip()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (initial_username,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
                           (initial_username, initial_email, generate_password_hash(initial_password), "ExamGuard Administrator", "admin"))
            print(f"Created initial admin account: {initial_username}")

    # Second Admin
    sec_password = os.environ.get("ADMIN_SECOND_INITIAL_PASSWORD", "").strip()
    if sec_password:
        sec_username = os.environ.get("ADMIN_SECOND_INITIAL_USERNAME", "admin2").strip()
        sec_email = os.environ.get("ADMIN_SECOND_INITIAL_EMAIL", f"{sec_username.lower()}@examguard.ai").strip()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (sec_username,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
                           (sec_username, sec_email, generate_password_hash(sec_password), "ExamGuard Co-Administrator", "admin"))
            print(f"Created second admin account: {sec_username}")
        else:
            # If user already exists, ensure role is upgraded to admin
            cursor.execute("UPDATE users SET role = 'admin' WHERE LOWER(username) = LOWER(?)", (sec_username,))

    conn.commit()
    conn.close()

def create_user(username, email, password, full_name, role="student", roll_number=None, class_name=None, profile_photo=""):
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    cursor = conn.cursor()
    try:
        clean_user = username.strip().lower()
        clean_email = email.strip().lower() if email else None
        clean_name = full_name.strip()
        clean_roll = roll_number.strip().upper() if roll_number else None
        clean_class = class_name.strip() if class_name else ""
        clean_photo = (profile_photo or "").strip()
        
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role, roll_number, class_name, profile_photo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (clean_user, clean_email, generate_password_hash(password), clean_name, role, clean_roll, clean_class, clean_photo))
        user_id = cursor.lastrowid
        conn.commit()
        return {"success": True, "user_id": user_id, "username": clean_user, "role": role, "full_name": clean_name, "roll_number": clean_roll, "class_name": clean_class, "profile_photo": clean_photo}
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
    for row in results:
        if row.get("percentage") is None:
            row["percentage"] = 0.0
        else:
            try:
                row["percentage"] = float(row["percentage"])
            except (ValueError, TypeError):
                row["percentage"] = 0.0

        if row.get("passing_percentage") is None:
            row["passing_percentage"] = 40.0
        else:
            try:
                row["passing_percentage"] = float(row["passing_percentage"])
            except (ValueError, TypeError):
                row["passing_percentage"] = 40.0

        if row.get("score") is None:
            row["score"] = 0.0
        if row.get("total_points") is None:
            row["total_points"] = 0.0
        if row.get("warnings_count") is None:
            row["warnings_count"] = 0
        if row.get("max_warnings") is None:
            row["max_warnings"] = 10

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

def save_generation_job(job_id, status="running", result_data=None):
    """Saves or updates an AI generation job in the database (works across all worker processes)."""
    import json
    conn = get_connection()
    cursor = conn.cursor()
    res_str = json.dumps(result_data) if result_data is not None else None
    cursor.execute("""
        INSERT INTO ai_generation_jobs (job_id, status, result_json)
        VALUES (?, ?, ?)
    """, (job_id, status, res_str))
    conn.commit()
    conn.close()

def update_generation_job(job_id, status, result_data):
    """Updates status and result of a background generation job."""
    import json
    conn = get_connection()
    cursor = conn.cursor()
    res_str = json.dumps(result_data) if result_data is not None else None
    cursor.execute("""
        UPDATE ai_generation_jobs
        SET status = ?, result_json = ?
        WHERE job_id = ?
    """, (status, res_str, job_id))
    conn.commit()
    conn.close()

def get_generation_job(job_id):
    """Retrieves an AI generation job from database."""
    import json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT job_id, status, result_json FROM ai_generation_jobs WHERE job_id = ?", (job_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = json.loads(row["result_json"]) if row["result_json"] else None
    return {"job_id": row["job_id"], "status": row["status"], "result": res}

def save_persistent_asset(asset_key, mime_type, data_bytes):
    """Saves an image/asset as base64 in database so it survives Render ephemeral restarts."""
    import base64
    if not asset_key or not data_bytes:
        return
    clean_key = str(asset_key).replace("\\", "/").lstrip("/")
    if clean_key.startswith("static/"):
        clean_key = clean_key[len("static/"):]
    b64_str = base64.b64encode(data_bytes).decode("ascii")
    conn = get_connection()
    cursor = conn.cursor()
    # Upsert pattern (stores both with and without static/ to ensure compatibility)
    cursor.execute("SELECT asset_key FROM persistent_assets WHERE asset_key = ?", (clean_key,))
    if cursor.fetchone():
        cursor.execute("UPDATE persistent_assets SET mime_type = ?, data_base64 = ? WHERE asset_key = ?", (mime_type, b64_str, clean_key))
    else:
        cursor.execute("INSERT INTO persistent_assets (asset_key, mime_type, data_base64) VALUES (?, ?, ?)", (clean_key, mime_type, b64_str))
    conn.commit()
    conn.close()

def get_persistent_asset(asset_key):
    """Retrieves an asset (mime_type, raw_bytes) by key with flexible normalization."""
    import base64
    if not asset_key:
        return None
    clean_key = str(asset_key).replace("\\", "/").lstrip("/")
    candidates = [clean_key]
    if clean_key.startswith("static/"):
        candidates.append(clean_key[len("static/"):])
    else:
        candidates.append(f"static/{clean_key}")

    conn = get_connection()
    cursor = conn.cursor()
    row = None
    for cand in candidates:
        cursor.execute("SELECT mime_type, data_base64 FROM persistent_assets WHERE asset_key = ?", (cand,))
        row = cursor.fetchone()
        if row:
            break
    conn.close()
    if not row or not row["data_base64"]:
        return None
    try:
        raw = base64.b64decode(row["data_base64"])
        return row["mime_type"], raw
    except Exception:
        return None

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
