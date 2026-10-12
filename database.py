import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "examguard.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Exams table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            duration_minutes INTEGER NOT NULL DEFAULT 30,
            max_warnings INTEGER NOT NULL DEFAULT 3,
            passing_percentage REAL NOT NULL DEFAULT 40.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # Questions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL DEFAULT 'mcq', -- mcq, tf, short, descriptive
            options_json TEXT, -- JSON array of strings for MCQ
            correct_answer TEXT NOT NULL,
            explanation TEXT,
            points REAL NOT NULL DEFAULT 1.0,
            figure_svg TEXT,
            figure_url TEXT,
            FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        )
    ''')

    # Schema migrations for existing databases
    try:
        cursor.execute("ALTER TABLE questions ADD COLUMN figure_svg TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE questions ADD COLUMN figure_url TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE exams ADD COLUMN enable_audio_detection INTEGER DEFAULT 1")
    except Exception:
        pass

    # Exam access targeting & schedule migrations
    for col, c_type in [
        ("access_type", "TEXT DEFAULT 'all'"),
        ("assigned_class", "TEXT DEFAULT ''"),
        ("schedule_type", "TEXT DEFAULT 'anytime'"),
        ("start_time", "TEXT"),
        ("end_time", "TEXT")
    ]:
        try:
            cursor.execute(f"ALTER TABLE exams ADD COLUMN {col} {c_type}")
        except Exception:
            pass

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN class_name TEXT DEFAULT ''")
    except Exception:
        pass

    # Exam Assignments table (for assigning exams to specific students)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exam_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE (exam_id, user_id)
        )
    ''')
    
    # Student Submissions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            student_name TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            answers_json TEXT, -- JSON object of {question_id: answer}
            score REAL DEFAULT 0.0,
            total_points REAL DEFAULT 0.0,
            percentage REAL DEFAULT 0.0,
            warnings_count INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'in_progress', -- in_progress, submitted, terminated
            termination_reason TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP,
            FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        )
    ''')
    
    # Violations / Proctoring audit log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            violation_type TEXT NOT NULL, -- tab_switch, blur, fullscreen_exit, copy_paste, devtools
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (submission_id) REFERENCES submissions (id) ON DELETE CASCADE
        )
    ''')

    # Settings table (for storing tutor's Gemini API key locally)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Users table (Role-based authentication: Admin vs Student)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student', -- 'admin' or 'student'
            roll_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add user_id column to submissions if not exists
    try:
        cursor.execute("ALTER TABLE submissions ADD COLUMN user_id INTEGER")
    except Exception:
        pass

    # Seed default Admin account if no admin exists
    from werkzeug.security import generate_password_hash
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, ('PrashantaDas2005', 'prashantadas2005@examguard.ai', generate_password_hash('Prashanta@130504'), 'Prashanta Das', 'admin'))

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
    except sqlite3.IntegrityError:
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
