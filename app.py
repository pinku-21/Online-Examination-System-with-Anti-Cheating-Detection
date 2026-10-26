import os
import json
import random
import string
import threading
import uuid
import time
import secrets
import hashlib
import hmac
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from database import (
    init_db, 
    get_connection, 
    get_setting, 
    set_setting,
    save_generation_job,
    update_generation_job,
    get_generation_job,
    create_user,
    authenticate_user,
    get_user_by_id,
    get_student_submissions,
    save_persistent_asset,
    get_persistent_asset
)
import base64
from ai_service import (
    extract_text_from_pdf, 
    extract_figures_from_pdf,
    generate_questions_with_gemini, 
    generate_questions_with_groq,
    generate_questions_unified,
    parse_pasted_paper_unified,
    generate_mock_questions,
    evaluate_answer_with_ai,
    verify_faces_with_gemini
)

IST = timezone(timedelta(hours=5, minutes=30))

def get_current_time():
    """Returns the current datetime in IST (Indian Standard Time, UTC+5:30) naive representation for comparison."""
    return datetime.now(IST).replace(tzinfo=None)

app = Flask(__name__, static_url_path=None)
app.secret_key = os.environ.get("SECRET_KEY", "examguard-super-secret-key-2026")

# Cookie & Session Security Hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production" or bool(os.environ.get("RENDER")),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

@app.after_request
def apply_security_headers(response):
    """
    Enforces defense-in-depth HTTP security headers and masks server headers
    to prevent fingerprinting and automated scanner version heuristics.
    """
    response.headers["Server"] = "WebServer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Apply HSTS over HTTPS / Render reverse proxy
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
    return response

@app.route("/health")
@app.route("/ping")
def health_check():
    """Lightweight endpoint for uptime monitoring and keeping Render instance awake."""
    return jsonify({
        "status": "healthy",
        "service": "Online Examination System",
        "timestamp": get_current_time().isoformat()
    }), 200

# --- CYBERSECURITY HELPERS (Integrity & SIEM Classification) ---
SECURITY_EVENT_CLASSIFICATION = {
    "virtual_camera_detected": {"code": "SEC-001", "severity": "CRITICAL", "desc": "Virtual Video Device / Stream Spoofing Attempt"},
    "devtools_tamper": {"code": "SEC-002", "severity": "CRITICAL", "desc": "Client-Side DOM / JS Reverse Engineering & Tampering"},
    "devtools_attempt": {"code": "SEC-002", "severity": "HIGH", "desc": "Developer Inspection Shortcut Triggered"},
    "impersonation_mismatch": {"code": "SEC-003", "severity": "CRITICAL", "desc": "Biometric Identity Mismatch / Impersonation"},
    "multiple_faces": {"code": "SEC-004", "severity": "HIGH", "desc": "Physical Perimeter Breach: Multiple Persons Detected"},
    "no_face": {"code": "SEC-005", "severity": "MEDIUM", "desc": "Webcam Feed Obscured / Candidate Absence"},
    "mobile_phone_detected": {"code": "SEC-006", "severity": "CRITICAL", "desc": "Unauthorized Communication Device Detected"},
    "tab_switch": {"code": "SEC-007", "severity": "HIGH", "desc": "Session Window Blur / Unauthorized Tab Switch"},
    "window_blur": {"code": "SEC-008", "severity": "MEDIUM", "desc": "Operating System Focus Loss / External Overlay"},
    "fullscreen_exit": {"code": "SEC-009", "severity": "HIGH", "desc": "Kiosk Environment / Fullscreen Sandbox Escape"},
    "clipboard_attempt": {"code": "SEC-010", "severity": "MEDIUM", "desc": "Restricted Clipboard Injection / Extraction"},
    "right_click": {"code": "SEC-011", "severity": "LOW", "desc": "Unauthorized Context Menu Invocation"},
    "voice_detected": {"code": "SEC-012", "severity": "MEDIUM", "desc": "Acoustic Anomaly / Unauthorized Speech Detected"},
    "session_anomaly": {"code": "SEC-013", "severity": "CRITICAL", "desc": "Concurrent Session / Device Hijacking Attempt"}
}

def generate_submission_integrity_hash(submission_id, roll_number, score, total_points, warnings_count, status):
    """
    Computes an HMAC-SHA-256 cryptographic verification token for the submission.
    Ensures non-repudiation and detects unauthorized tampering in database or transit.
    """
    secret = app.secret_key.encode('utf-8')
    payload = f"EXAMGUARD_V1|SUB:{submission_id}|ROLL:{roll_number}|SCORE:{score}/{total_points}|STRK:{warnings_count}|STATUS:{status}".encode('utf-8')
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def classify_security_event(violation_type):
    """SIEM-style classification for anti-cheat and security violations."""
    return SECURITY_EVENT_CLASSIFICATION.get(violation_type, {
        "code": "SEC-999",
        "severity": "MEDIUM",
        "desc": violation_type.replace('_', ' ').title()
    })

# --- BACKGROUND JOB STORE (thread-safe + database persistent) ---
# Stores AI generation jobs in memory and in the database so any Gunicorn worker process can poll it
_job_store = {}
_job_lock = threading.Lock()

def _cleanup_old_jobs():
    """Remove jobs older than 30 minutes from memory to prevent memory leaks."""
    cutoff = time.time() - 1800
    with _job_lock:
        old = [k for k, v in _job_store.items() if v.get("created_at", 0) < cutoff]
        for k in old:
            del _job_store[k]

def _run_generation_job(job_id, fn, kwargs, extracted_figures=None):
    """Worker thread: runs AI generation, stores result in memory and in database."""
    try:
        result = fn(**kwargs)
        if result and extracted_figures and "extracted_figures" not in result:
            result["extracted_figures"] = extracted_figures
        with _job_lock:
            _job_store[job_id]["status"] = "done"
            _job_store[job_id]["result"] = result
        # Persist to database so any worker process can see it
        try:
            update_generation_job(job_id, "done", result)
        except Exception as db_err:
            print(f"Warning: Failed to update job in DB: {db_err}")
    except Exception as e:
        err_result = {"success": False, "error": str(e)}
        with _job_lock:
            _job_store[job_id]["status"] = "error"
            _job_store[job_id]["result"] = err_result
        try:
            update_generation_job(job_id, "error", err_result)
        except Exception:
            pass

def _parse_to_ist(val):
    """Helper to parse a date/time object or string (stored in UTC) into an IST datetime."""
    if not val:
        return None
    try:
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc).astimezone(IST)
            return val.astimezone(IST)
        val_str = str(val).strip().replace('T', ' ')
        if '.' in val_str:
            val_str = val_str.split('.')[0]
        dt = None
        if len(val_str) == 16:
            dt = datetime.strptime(val_str, "%Y-%m-%d %H:%M")
        elif len(val_str) >= 19:
            dt = datetime.strptime(val_str[:19], "%Y-%m-%d %H:%M:%S")
        if dt:
            return dt.replace(tzinfo=timezone.utc).astimezone(IST)
    except Exception:
        pass
    return None

@app.template_filter('format_datetime_12h')
def format_datetime_12h_filter(val):
    if not val:
        return '—'
    try:
        dt_ist = _parse_to_ist(val)
        if dt_ist:
            return dt_ist.strftime("%b %d, %Y, %I:%M %p")
        return str(val)
    except Exception:
        return str(val)

@app.template_filter('format_date')
def format_date_filter(val):
    if not val:
        return '—'
    try:
        dt_ist = _parse_to_ist(val)
        if dt_ist:
            return dt_ist.strftime("%Y-%m-%d")
        val_str = str(val).strip()
        if len(val_str) >= 10:
            return val_str[:10]
        return val_str
    except Exception:
        return str(val)

@app.template_filter('format_time_12h')
def format_time_12h_filter(val):
    if not val:
        return '—'
    try:
        dt_ist = _parse_to_ist(val)
        if dt_ist:
            return dt_ist.strftime("%I:%M %p")
        return str(val)
    except Exception:
        return str(val)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

# Initialize DB on start
init_db()

def generate_exam_code(length=6):
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


# --- AUTHENTICATION & ACCESS CONTROL HELPERS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        
        # Single-device session verification for students
        if session.get("user_role") == "student":
            my_token = session.get("session_token")
            if my_token:
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT active_session_token FROM users WHERE id = ?", (user_id,))
                urow = cursor.fetchone()
                conn.close()
                if urow and urow["active_session_token"] and urow["active_session_token"] != my_token:
                    session.clear()
                    flash("You have been signed out because your account was logged in from another device. Multiple simultaneous logins are not permitted.", "danger")
                    return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in with your Admin ID and password to access the Tutor area.", "warning")
            return redirect(url_for("login", next=request.path, role="admin"))
        if session.get("user_role") != "admin":
            flash("Access Restricted: Only Admin / Tutor accounts can access this section.", "danger")
            return redirect(url_for("student_dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# --- AUTHENTICATION ROUTES ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "student").strip()
        next_url = request.form.get("next", "").strip()

        user = authenticate_user(identifier, password)
        if user:
            # Check single-device & active-exam security rules for student accounts
            if user["role"] == "student":
                conn = get_connection()
                cursor = conn.cursor()
                
                # Check if this student currently has an active in_progress or paused exam
                cursor.execute("""
                    SELECT s.id, s.exam_id, s.status, s.device_switch_approved, e.title as exam_title
                    FROM submissions s
                    JOIN exams e ON s.exam_id = e.id
                    WHERE (s.user_id = ? OR s.roll_number = ?)
                      AND s.status IN ('in_progress', 'paused', 'pause_requested')
                    ORDER BY s.started_at DESC LIMIT 1
                """, (user["id"], user.get("roll_number") or ""))
                active_exam = cursor.fetchone()

                existing_token = user.get("active_session_token")
                # If student is already attempting an exam and attempts to login from a new session without permission
                if active_exam and existing_token and not active_exam["device_switch_approved"]:
                    conn.close()
                    flash(f"⚠️ Exam In Progress: You are already taking '{active_exam['exam_title']}' on another device! Simultaneous logins are blocked. To switch devices during an exam, please contact your tutor to approve a Device Switch.", "danger")
                    return render_template("login.html", role=role, prefill=identifier, next_url=next_url)

                # Reset device_switch_approved flag once student uses it to log in
                if active_exam and active_exam["device_switch_approved"]:
                    cursor.execute("UPDATE submissions SET device_switch_approved = 0 WHERE id = ?", (active_exam["id"],))

                # Generate new single-device session token and record in user profile
                new_session_token = secrets.token_hex(20)
                cursor.execute("UPDATE users SET active_session_token = ? WHERE id = ?", (new_session_token, user["id"]))
                conn.commit()
                conn.close()
                session["session_token"] = new_session_token
            else:
                new_session_token = secrets.token_hex(20)
                session["session_token"] = new_session_token

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["user_name"] = user["full_name"]
            session["user_role"] = user["role"]
            session["roll_number"] = user.get("roll_number") or ""
            session["class_name"] = user.get("class_name") or ""

            flash(f"Signed in successfully as {user['full_name']}!", "success")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            if user["role"] == "admin":
                return redirect(url_for("tutor_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))
        else:
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html", role=role, prefill=identifier, next_url=next_url)

    role = request.args.get("role", "student")
    next_url = request.args.get("next", "")
    return render_template("login.html", role=role, next_url=next_url)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Allow students to self-register their accounts."""
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        roll_number = request.form.get("roll_number", "").strip().upper()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip().lower() or None
        class_name = request.form.get("class_name", "").strip()
        photo_file = request.files.get("profile_photo")

        if not full_name or not roll_number or not username or not password:
            flash("Full Name, Roll Number, Username, and Password are all required.", "danger")
            return render_template("register.html")

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash("Password must be strong: minimum 8 characters with at least 1 uppercase letter (A-Z) and 1 number (0-9).", "danger")
            return render_template("register.html")

        if not photo_file or not photo_file.filename:
            flash("Biometric Reference Photo is required for student registration to prevent exam impersonation.", "danger")
            return render_template("register.html")

        # Save profile photo
        profile_photo_url = ""
        if photo_file and photo_file.filename:
            _, ext = os.path.splitext(secure_filename(photo_file.filename))
            ext = ext.lower() if ext else ".jpg"
            if ext not in [".jpg", ".jpeg", ".png", ".webp", ".bmp"]:
                ext = ".jpg"
            safe_roll = "".join(c if c.isalnum() else "_" for c in roll_number.lower())
            photo_filename = f"reg_{safe_roll}_{int(datetime.now().timestamp())}{ext}"
            photo_dir = os.path.join(os.path.dirname(__file__), "static", "profile_photos")
            os.makedirs(photo_dir, exist_ok=True)
            photo_bytes = photo_file.read()
            with open(os.path.join(photo_dir, photo_filename), "wb") as f:
                f.write(photo_bytes)
            save_persistent_asset(f"profile_photos/{photo_filename}", photo_file.mimetype or "image/jpeg", photo_bytes)
            profile_photo_url = f"/static/profile_photos/{photo_filename}"

        res = create_user(username, email, password, full_name, role="student", 
                          roll_number=roll_number, class_name=class_name,
                          profile_photo=profile_photo_url)
        if res.get("success"):
            # Sign in the new student automatically
            session.clear()
            session["user_id"] = res["user_id"]
            session["username"] = res["username"]
            session["user_name"] = res["full_name"]
            session["user_role"] = "student"
            session["roll_number"] = res["roll_number"]
            session["class_name"] = res.get("class_name", "")
            if profile_photo_url:
                session["profile_photo"] = profile_photo_url
            flash(f"Welcome, {full_name}! Your account has been created successfully.", "success")
            return redirect(url_for("student_dashboard"))
        else:
            flash(res.get("error", "Failed to register account."), "danger")
            return render_template("register.html")

    return render_template("register.html")

# --- ADMIN: STUDENT MANAGEMENT ROUTES ---

@app.route("/api/admin/create-student", methods=["POST"])
@admin_required
def admin_create_student():
    """Admin creates a new student account with preset credentials.
    Accepts multipart/form-data (with optional profile_photo file) or JSON.
    """
    # Support both multipart FormData and legacy JSON
    if request.content_type and "multipart" in request.content_type:
        full_name = request.form.get("full_name", "").strip()
        roll_number = request.form.get("roll_number", "").strip().upper()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip().lower() or None
        class_name = request.form.get("class_name", "").strip()
        photo_file = request.files.get("profile_photo")
    else:
        data = request.get_json() or {}
        full_name = data.get("full_name", "").strip()
        roll_number = data.get("roll_number", "").strip().upper()
        username = data.get("username", "").strip().lower()
        password = data.get("password", "").strip()
        email = data.get("email", "").strip().lower() or None
        class_name = data.get("class_name", "").strip()
        photo_file = None

    if not full_name or not roll_number or not username or not password:
        return jsonify({"success": False, "error": "Full Name, Roll Number, Username, and Password are all required."})
    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters."})

    # Save profile photo if provided
    profile_photo_url = ""
    if photo_file and photo_file.filename:
        _, ext = os.path.splitext(secure_filename(photo_file.filename))
        ext = ext.lower() if ext else ".jpg"
        if ext not in [".jpg", ".jpeg", ".png", ".webp", ".bmp"]:
            ext = ".jpg"
        safe_roll = "".join(c if c.isalnum() else "_" for c in roll_number.lower())
        photo_filename = f"reg_{safe_roll}_{int(datetime.now().timestamp())}{ext}"
        photo_dir = os.path.join(os.path.dirname(__file__), "static", "profile_photos")
        os.makedirs(photo_dir, exist_ok=True)
        photo_bytes = photo_file.read()
        with open(os.path.join(photo_dir, photo_filename), "wb") as f:
            f.write(photo_bytes)
        save_persistent_asset(f"profile_photos/{photo_filename}", photo_file.mimetype or "image/jpeg", photo_bytes)
        profile_photo_url = f"/static/profile_photos/{photo_filename}"

    res = create_user(username, email, password, full_name, role="student",
                      roll_number=roll_number, class_name=class_name,
                      profile_photo=profile_photo_url)
    if res.get("success"):
        return jsonify({"success": True, "message": f"Student account created for {full_name} ({username}).", "student": {
            "id": res["user_id"], "full_name": full_name, "username": username,
            "roll_number": roll_number, "class_name": class_name,
            "has_photo": bool(profile_photo_url)
        }})
    return jsonify({"success": False, "error": res.get("error", "Failed to create student account.")})

@app.route("/api/admin/delete-student/<int:student_id>", methods=["DELETE"])
@admin_required
def admin_delete_student(student_id):
    """Admin deletes a student account."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_name, role FROM users WHERE id = ?", (student_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Student not found."})
    if user["role"] == "admin":
        conn.close()
        return jsonify({"success": False, "error": "Cannot delete admin accounts."})
    cursor.execute("DELETE FROM users WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Student account deleted."})

@app.route("/api/admin/delete-exam/<int:exam_id>", methods=["DELETE", "POST"])
@admin_required
def admin_delete_exam(exam_id):
    """Admin permanently deletes an exam and its questions, assignments, and submissions."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM exams WHERE id = ?", (exam_id,))
    exam = cursor.fetchone()
    if not exam:
        conn.close()
        return jsonify({"success": False, "error": "Exam not found."}), 404
    
    exam_title = exam["title"]
    # Explicitly cascade delete submissions, questions, assignments, violations for SQLite / Postgres compatibility
    cursor.execute("SELECT id FROM submissions WHERE exam_id = ?", (exam_id,))
    sub_ids = [r["id"] for r in cursor.fetchall()]
    if sub_ids:
        for sid in sub_ids:
            cursor.execute("DELETE FROM violations WHERE submission_id = ?", (sid,))
        cursor.execute("DELETE FROM submissions WHERE exam_id = ?", (exam_id,))
    
    cursor.execute("DELETE FROM questions WHERE exam_id = ?", (exam_id,))
    cursor.execute("DELETE FROM exam_assignments WHERE exam_id = ?", (exam_id,))
    cursor.execute("DELETE FROM exams WHERE id = ?", (exam_id,))
    
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Exam '{exam_title}' has been successfully deleted."})

@app.route("/api/admin/reset-password", methods=["POST"])
@admin_required
def admin_reset_password():
    """Admin resets a student's password."""
    from werkzeug.security import generate_password_hash
    data = request.get_json() or {}
    student_id = data.get("student_id")
    new_password = data.get("new_password", "").strip()
    if not student_id or not new_password:
        return jsonify({"success": False, "error": "Student ID and new password are required."})
    if len(new_password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters."})
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, role FROM users WHERE id = ?", (student_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Student not found."})
    if user["role"] == "admin":
        conn.close()
        return jsonify({"success": False, "error": "Cannot change admin password here."})
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), student_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Password updated successfully."})


@app.route("/api/student/change-password", methods=["POST"])
@login_required
def student_change_password():
    """Logged in student changes their own password."""
    from werkzeug.security import generate_password_hash, check_password_hash
    data = request.get_json() or {}
    user_id = session.get("user_id")
    current_password = data.get("current_password", "").strip()
    new_password = data.get("new_password", "").strip()
    confirm_password = data.get("confirm_password", "").strip()

    if not current_password or not new_password:
        return jsonify({"success": False, "error": "Current password and new password are required."})

    if len(new_password) < 4:
        return jsonify({"success": False, "error": "New password must be at least 4 characters long."})

    if new_password != confirm_password:
        return jsonify({"success": False, "error": "New password and confirmation do not match."})

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "error": "User account not found."})

    if not check_password_hash(user["password_hash"], current_password):
        conn.close()
        return jsonify({"success": False, "error": "Current password is incorrect."})

    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Your password has been updated successfully!"})


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))

# --- HOME & GENERAL ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/portfolio")
def portfolio():
    """Redirects to the independently deployed portfolio website on Vercel."""
    return redirect("https://examguard-portfolio.vercel.app/")

@app.route("/PORTFOLIO_CASE_STUDY.md")
def portfolio_case_study_markdown():
    """Serves the raw markdown case study for technical recruiters and reviewers."""
    from flask import send_file
    case_study_path = os.path.join(os.path.dirname(__file__), "PORTFOLIO_CASE_STUDY.md")
    if os.path.exists(case_study_path):
        return send_file(case_study_path, mimetype="text/markdown")
    return "Case study not found.", 404


# --- TUTOR PORTAL ROUTES (ADMIN ONLY) ---

@app.route("/tutor")
@admin_required
def tutor_dashboard():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, 
               (SELECT COUNT(*) FROM questions WHERE exam_id = e.id) as question_count,
               (SELECT COUNT(*) FROM submissions WHERE exam_id = e.id) as submission_count,
               (SELECT COUNT(*) FROM submissions WHERE exam_id = e.id AND status = 'terminated') as terminated_count,
               (SELECT COUNT(*) FROM exam_assignments WHERE exam_id = e.id) as assigned_student_count
        FROM exams e
        ORDER BY e.created_at DESC
    """)
    exams = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    gemini_key = get_setting("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "") or os.environ.get("GROQ_API_KEY", "").strip()
    openrouter_key = get_setting("openrouter_api_key", "") or os.environ.get("OPENROUTER_API_KEY", "").strip()
    public_url = get_setting("public_url", "")
    has_api_key = bool(
        (gemini_key and len(gemini_key.strip()) > 10) or 
        (groq_key and len(groq_key.strip()) > 10) or
        (openrouter_key and len(openrouter_key.strip()) > 10)
    )
    
    conn2 = get_connection()
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT id, full_name, username, roll_number, email, class_name, profile_photo, created_at FROM users WHERE role = 'student' ORDER BY created_at DESC")
    students = [dict(r) for r in cursor2.fetchall()]
    distinct_classes = sorted(list(set(s['class_name'] for s in students if s.get('class_name'))))
    
    # Query active/unresolved security incidents across all exams for the SIEM Security Operations Center
    cursor2.execute("""
        SELECT v.*, s.student_name, s.roll_number, s.client_ip, s.exam_id, e.title as exam_title
        FROM violations v
        JOIN submissions s ON v.submission_id = s.id
        JOIN exams e ON s.exam_id = e.id
        WHERE COALESCE(v.is_resolved, 0) = 0
        ORDER BY v.timestamp DESC
        LIMIT 25
    """)
    security_incidents = [dict(r) for r in cursor2.fetchall()]
    conn2.close()

    # Calculate SOC stats
    sec_critical_count = sum(1 for inc in security_incidents if (inc.get('severity') or '').upper() == 'CRITICAL')
    sec_high_count = sum(1 for inc in security_incidents if (inc.get('severity') or '').upper() == 'HIGH')

    return render_template(
        "tutor_dashboard.html", 
        exams=exams,
        students=students,
        classes=distinct_classes,
        has_api_key=has_api_key,
        has_gemini_key=bool(gemini_key and len(gemini_key.strip()) > 10),
        has_groq_key=bool(groq_key and len(groq_key.strip()) > 10),
        has_openrouter_key=bool(openrouter_key and len(openrouter_key.strip()) > 10),
        gemini_key_mask=(f"{len([k for k in gemini_key.split(',') if k.strip()])} Keys Active" if "," in gemini_key else ((gemini_key[:4] + "..." + gemini_key[-4:]) if len(gemini_key) > 8 else "")),
        groq_key_mask=(f"{len([k for k in groq_key.split(',') if k.strip()])} Keys Active" if "," in groq_key else ((groq_key[:4] + "..." + groq_key[-4:]) if len(groq_key) > 8 else "")),
        openrouter_key_mask=(f"{len([k for k in openrouter_key.split(',') if k.strip()])} Keys Active" if "," in openrouter_key else ((openrouter_key[:6] + "..." + openrouter_key[-4:]) if len(openrouter_key) > 10 else "")),
        public_url=public_url,
        security_incidents=security_incidents,
        sec_critical_count=sec_critical_count,
        sec_high_count=sec_high_count
    )

@app.route("/tutor/settings", methods=["GET", "POST"])
@admin_required
def tutor_save_settings():
    gemini_key = request.form.get("gemini_api_key", "").strip()
    groq_key = request.form.get("groq_api_key", "").strip()
    openrouter_key = request.form.get("openrouter_api_key", "").strip()
    public_url = request.form.get("public_url", "").strip().rstrip("/")
    
    if gemini_key:
        set_setting("gemini_api_key", gemini_key)
    if groq_key:
        set_setting("groq_api_key", groq_key)
    if openrouter_key:
        set_setting("openrouter_api_key", openrouter_key)
    if public_url is not None:
        set_setting("public_url", public_url)
        
    flash("Settings updated successfully!", "success")
    return redirect(url_for("tutor_dashboard"))

@app.route("/api/tutor/set-public-url", methods=["POST"])
@admin_required
def api_set_public_url():
    data = request.get_json() or {}
    url = data.get("public_url", "").strip().rstrip("/")
    set_setting("public_url", url)
    return jsonify({"success": True, "public_url": url})

@app.route("/tutor/exam/new")
@admin_required
def new_exam():
    gemini_key = get_setting("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "") or os.environ.get("GROQ_API_KEY", "").strip()
    has_api_key = bool(
        (gemini_key and len(gemini_key.strip()) > 10) or 
        (groq_key and len(groq_key.strip()) > 10)
    )
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_name, username, roll_number, class_name FROM users WHERE role = 'student' ORDER BY full_name ASC")
    students = [dict(r) for r in cursor.fetchall()]
    distinct_classes = sorted(list(set(s['class_name'] for s in students if s.get('class_name'))))
    conn.close()
    
    return render_template("create_exam.html", has_api_key=has_api_key, students=students, classes=distinct_classes)

@app.route("/api/generate-questions", methods=["POST"])
@admin_required
def api_generate_questions():
    """
    Accepts PDF/image/text, starts AI generation in a background thread,
    and immediately returns a job_id. The client polls /api/job-status/<job_id>.
    This prevents any HTTP/proxy timeout regardless of how large the PDF is.
    """
    _cleanup_old_jobs()

    topic_text = request.form.get("topic_text", "").strip()
    custom_prompt = request.form.get("custom_prompt", "").strip()
    custom_format_instruction = request.form.get("custom_format_instruction", "").strip()
    if custom_format_instruction:
        if custom_prompt:
            custom_prompt = f"{custom_prompt}\n\n{custom_format_instruction}"
        else:
            custom_prompt = custom_format_instruction

    total_marks = request.form.get("total_marks", "").strip()
    num_questions = int(request.form.get("num_questions", 5))
    difficulty = request.form.get("difficulty", "Medium")
    question_type = request.form.get("question_type", "mcq")
    use_mock = request.form.get("use_mock", "false").lower() == "true"
    
    uploaded_files = request.files.getlist("files")
    saved_images = []
    extracted_pdf_texts = []
    extracted_figures = []
    
    for f in uploaded_files:
        if f and f.filename:
            filename = secure_filename(f.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            f.save(file_path)
            
            ext = os.path.splitext(filename)[1].lower()
            if ext == ".pdf":
                pdf_text = extract_text_from_pdf(file_path)
                if pdf_text:
                    extracted_pdf_texts.append(pdf_text)
                pdf_figs = extract_figures_from_pdf(file_path)
                if pdf_figs:
                    extracted_figures.extend(pdf_figs)
            elif ext in [".jpg", ".jpeg", ".png", ".webp"]:
                saved_images.append(file_path)

    combined_text = ""
    if topic_text:
        combined_text += f"Tutor Instructions / Topics:\n{topic_text}\n\n"
    if extracted_pdf_texts:
        combined_text += "Extracted from Uploaded PDF Documents:\n" + "\n\n".join(extracted_pdf_texts)

    gemini_key = get_setting("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "") or os.environ.get("GROQ_API_KEY", "").strip()

    # Mock: return immediately
    if use_mock or (not gemini_key and not groq_key):
        result = generate_mock_questions(combined_text, num_questions=num_questions, question_type=question_type, total_marks=total_marks)
        result["extracted_figures"] = extracted_figures
        return jsonify({"job_id": None, "status": "done", "result": result})

    # Start background job — returns immediately, no timeout risk
    job_id = str(uuid.uuid4())
    with _job_lock:
        _job_store[job_id] = {
            "status": "running",
            "result": None,
            "created_at": time.time(),
            "extracted_figures": extracted_figures
        }
    try:
        save_generation_job(job_id, "running", None)
    except Exception as db_err:
        print(f"Warning: Failed to save job to DB: {db_err}")

    kwargs = dict(
        gemini_key=gemini_key,
        groq_key=groq_key,
        text_content=combined_text,
        image_paths=saved_images,
        num_questions=num_questions,
        question_type=question_type,
        difficulty=difficulty,
        custom_prompt=custom_prompt,
        total_marks=total_marks,
        available_figures=extracted_figures
    )
    t = threading.Thread(target=_run_generation_job, args=(job_id, generate_questions_unified, kwargs, extracted_figures), daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "status": "running"})

@app.route("/api/parse-pasted-questions", methods=["POST"])
@admin_required
def api_parse_pasted_questions():
    """
    Direct Paper Parser: Receives raw pasted questions or uploaded PDF / photos,
    and runs fast Gemini multimodal extraction to return structured question objects verbatim.
    """
    _cleanup_old_jobs()
    raw_text = request.form.get("raw_text", "").strip()
    uploaded_files = request.files.getlist("files") or request.files.getlist("file")
    
    saved_images = []
    extracted_pdf_texts = []
    extracted_figures = []
    
    for f in uploaded_files:
        if f and f.filename:
            filename = secure_filename(f.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            f.save(file_path)
            
            ext = os.path.splitext(filename)[1].lower()
            if ext == ".pdf":
                pdf_text = extract_text_from_pdf(file_path)
                if pdf_text and len(pdf_text.strip()) > 30:
                    extracted_pdf_texts.append(pdf_text)
                
                # Always extract embedded figures and diagrams from PDF
                try:
                    figs = extract_figures_from_pdf(file_path)
                    if figs:
                        extracted_figures.extend(figs)
                        # Also feed figure images into vision context so Gemini can see the diagrams
                        for fig in figs:
                            local_fig = os.path.join(os.path.dirname(__file__), fig["url"].lstrip("/"))
                            if os.path.exists(local_fig) and local_fig not in saved_images:
                                saved_images.append(local_fig)
                except Exception as e:
                    print("Error extracting figures from PDF:", e)
            elif ext in [".jpg", ".jpeg", ".png", ".webp", ".bmp"]:
                saved_images.append(file_path)

    if extracted_pdf_texts:
        pdf_combined = "\n\n".join(extracted_pdf_texts)
        raw_text = f"{raw_text}\n\n{pdf_combined}".strip() if raw_text else pdf_combined

    if not raw_text and not saved_images:
        return jsonify({"success": False, "error": "No readable text or images found in the uploaded file. Please paste the question text or upload a clear PDF/photo."}), 400

    gemini_key = get_setting("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "") or os.environ.get("GROQ_API_KEY", "").strip()

    job_id = str(uuid.uuid4())
    with _job_lock:
        _job_store[job_id] = {
            "status": "running",
            "result": None,
            "created_at": time.time(),
            "extracted_figures": extracted_figures
        }
    try:
        save_generation_job(job_id, "running", None)
    except Exception as db_err:
        print(f"Warning: Failed to save parse job to DB: {db_err}")

    kwargs = dict(
        gemini_key=gemini_key,
        groq_key=groq_key,
        raw_text=raw_text,
        image_paths=saved_images,
        available_figures=extracted_figures
    )
    t = threading.Thread(target=_run_generation_job, args=(job_id, parse_pasted_paper_unified, kwargs, extracted_figures), daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "status": "running"})


@app.route("/api/job-status/<job_id>", methods=["GET"])
def api_job_status(job_id):
    """Poll endpoint: returns job status and result when ready (checks memory first, then DB)."""
    # 1. Check local worker memory
    with _job_lock:
        job = _job_store.get(job_id)
    
    if job:
        if job["status"] == "running":
            return jsonify({"status": "running"})
        result = job["result"] or {}
        if "extracted_figures" not in result and job.get("extracted_figures"):
            result["extracted_figures"] = job["extracted_figures"]
        return jsonify({"status": job["status"], "result": result})

    # 2. If not found in this worker process's memory, check database
    try:
        db_job = get_generation_job(job_id)
        if db_job:
            if db_job["status"] == "running":
                return jsonify({"status": "running"})
            return jsonify({"status": db_job["status"], "result": db_job["result"] or {}})
    except Exception as e:
        print(f"Error querying job from DB: {e}")

    return jsonify({"status": "not_found"}), 404

@app.route("/api/upload-figure", methods=["POST"])
@admin_required
def api_upload_figure():
    """Uploads a standalone question diagram or image directly from the user's computer."""
    if "figure_file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    file = request.files["figure_file"]
    if not file or not file.filename:
        return jsonify({"success": False, "error": "No file selected"}), 400
        
    filename = secure_filename(file.filename)
    stem, ext = os.path.splitext(filename)
    if ext.lower() not in [".jpg", ".jpeg", ".png", ".webp", ".svg", ".gif"]:
        return jsonify({"success": False, "error": "Only image files (JPG, PNG, WEBP, SVG) are supported"}), 400
        
    unique_name = f"custom_{int(datetime.now().timestamp())}_{filename}"
    figures_dir = os.path.join(os.path.dirname(__file__), "static", "question_figures")
    os.makedirs(figures_dir, exist_ok=True)
    
    file_bytes = file.read()
    save_path = os.path.join(figures_dir, unique_name)
    with open(save_path, "wb") as f:
        f.write(file_bytes)
        
    mime_type = file.mimetype or "image/png"
    save_persistent_asset(f"question_figures/{unique_name}", mime_type, file_bytes)
    
    return jsonify({"success": True, "figure_url": f"/static/question_figures/{unique_name}"})

@app.route("/api/submission/<int:submission_id>/upload-answer-image", methods=["POST"])
@login_required
def api_upload_answer_image(submission_id):
    """Allows student to upload handwritten answer photo/diagram for subjective questions."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    conn.close()
    
    if not submission or submission["status"] != "in_progress":
        return jsonify({"success": False, "error": "Exam session is not currently active."}), 400
        
    # Student authorization: must own this exam session
    if session.get("user_role") == "student" and submission["user_id"] != session.get("user_id"):
        return jsonify({"success": False, "error": "Access denied."}), 403
        
    uploaded_file = request.files.get("answer_image") or request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"success": False, "error": "No image file provided."}), 400
        
    raw_name = uploaded_file.filename or "photo.jpg"
    filename = secure_filename(raw_name) or f"photo_{int(datetime.now().timestamp())}.jpg"
    _, ext = os.path.splitext(filename)
    if not ext:
        if uploaded_file.mimetype and uploaded_file.mimetype.startswith("image/"):
            ext = "." + uploaded_file.mimetype.split("/")[-1].replace("jpeg", "jpg")
        else:
            ext = ".jpg"
        filename += ext
    if ext.lower() not in [".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic"]:
        if uploaded_file.mimetype and uploaded_file.mimetype.startswith("image/"):
            filename = os.path.splitext(filename)[0] + ".jpg"
        else:
            return jsonify({"success": False, "error": "Only image formats (JPG, PNG, WEBP) are supported."}), 400
        
    q_id = request.form.get("question_id", "0")
    unique_name = f"ans_{submission_id}_q{q_id}_{int(datetime.now().timestamp())}_{filename}"
    upload_dir = os.path.join(os.path.dirname(__file__), "static", "student_answers")
    os.makedirs(upload_dir, exist_ok=True)
    
    file_bytes = uploaded_file.read()
    save_path = os.path.join(upload_dir, unique_name)
    with open(save_path, "wb") as f:
        f.write(file_bytes)
    
    # Also save permanently to database so it never vanishes on Render restarts
    mime_type = uploaded_file.mimetype or "image/jpeg"
    save_persistent_asset(f"student_answers/{unique_name}", mime_type, file_bytes)
    
    return jsonify({
        "success": True, 
        "image_url": f"/static/student_answers/{unique_name}"
    })

def _send_static_file_with_persistence(filename):
    """
    Overrides Flask's default static file handler so that if an uploaded file
    (profile photo, answer image, figure) was wiped from disk by Render's ephemeral filesystem,
    it automatically restores and serves it from the database persistent_assets table.
    """
    from flask import send_from_directory, abort, Response
    clean_filename = str(filename).replace("\\", "/").lstrip("/")
    static_root = app.static_folder or os.path.join(os.path.dirname(__file__), "static")
    file_path = os.path.join(static_root, clean_filename)
    
    if os.path.exists(file_path):
        return send_from_directory(static_root, clean_filename)

    # Check database persistent assets (PostgreSQL Neon / Render)
    res = get_persistent_asset(clean_filename)
    if res:
        mime_type, raw_bytes = res
        # Re-materialize to local disk for fast subsequent reads
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(raw_bytes)
        except Exception:
            pass
        resp = Response(raw_bytes, mimetype=mime_type)
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp

    abort(404)

# Hook into Flask's static handler
app.send_static_file = _send_static_file_with_persistence

@app.route("/static/<path:filename>")
def custom_static_serve(filename):
    return app.send_static_file(filename)

@app.route("/asset/<path:asset_key>")
def serve_persistent_asset(asset_key):
    """Fallback endpoint that serves images directly from database if local ephemeral file was erased."""
    res = get_persistent_asset(asset_key)
    if not res:
        return "Asset not found", 404
    mime_type, raw_bytes = res
    from flask import Response
    resp = Response(raw_bytes, mimetype=mime_type)
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp

@app.route("/api/student/upload-profile-photo", methods=["POST"])
@login_required
def api_upload_profile_photo():
    """Allows student or admin to upload their reference profile photo for biometric verification."""
    uploaded_file = request.files.get("profile_photo") or request.files.get("file")
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"success": False, "error": "No image file provided."}), 400

    filename = secure_filename(uploaded_file.filename) or "profile.jpg"
    _, ext = os.path.splitext(filename)
    if not ext:
        ext = ".jpg"
    if ext.lower() not in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".heic"]:
        ext = ".jpg"

    unique_name = f"user_{user_id}_{int(datetime.now().timestamp())}{ext}"
    upload_dir = os.path.join(os.path.dirname(__file__), "static", "profile_photos")
    os.makedirs(upload_dir, exist_ok=True)
    
    file_bytes = uploaded_file.read()
    save_path = os.path.join(upload_dir, unique_name)
    with open(save_path, "wb") as f:
        f.write(file_bytes)
    
    # Save permanently to database persistent_assets
    mime_type = uploaded_file.mimetype or "image/jpeg"
    save_persistent_asset(f"profile_photos/{unique_name}", mime_type, file_bytes)
    rel_url = f"/static/profile_photos/{unique_name}"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET profile_photo = ? WHERE id = ?", (rel_url, user_id))
    conn.commit()
    conn.close()

    session["profile_photo"] = rel_url
    return jsonify({"success": True, "profile_photo_url": rel_url})

@app.route("/api/submission/<int:submission_id>/verify-face-ai", methods=["POST"])
@login_required
def api_verify_face_ai(submission_id):
    """
    Biometric Face Verification endpoint using Gemini Vision AI.
    Compares live webcam snapshot with student's registered reference photo.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, u.profile_photo, u.full_name AS registered_full_name
        FROM submissions s
        LEFT JOIN users u ON (s.user_id = u.id OR (s.roll_number IS NOT NULL AND LOWER(s.roll_number) = LOWER(u.roll_number)))
        WHERE s.id = ?
    """, (submission_id,))
    sub_row = cursor.fetchone()
    if not sub_row:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    # Authorization Check: Student must own this submission
    if session.get("user_role") == "student" and sub_row["user_id"] and sub_row["user_id"] != session.get("user_id"):
        conn.close()
        return jsonify({"success": False, "error": "Access denied."}), 403

    # Extract webcam snapshot
    live_file = request.files.get("snapshot")
    live_b64 = (request.form.get("snapshot_base64") or (request.get_json(silent=True) or {}).get("snapshot_base64") or "").strip()

    upload_dir = os.path.join(os.path.dirname(__file__), "static", "verified_faces")
    os.makedirs(upload_dir, exist_ok=True)
    snapshot_filename = f"verify_sub{submission_id}_{int(datetime.now().timestamp())}.jpg"
    snapshot_path = os.path.join(upload_dir, snapshot_filename)
    snapshot_rel_url = f"/static/verified_faces/{snapshot_filename}"

    snap_bytes = None
    if live_file and live_file.filename:
        snap_bytes = live_file.read()
        with open(snapshot_path, "wb") as f:
            f.write(snap_bytes)
    elif live_b64:
        if "," in live_b64:
            live_b64 = live_b64.split(",", 1)[1]
        try:
            snap_bytes = base64.b64decode(live_b64)
            with open(snapshot_path, "wb") as f:
                f.write(snap_bytes)
        except Exception as b64_err:
            conn.close()
            return jsonify({"success": False, "error": f"Invalid snapshot image: {b64_err}"}), 400
    else:
        conn.close()
        return jsonify({"success": False, "error": "No webcam snapshot provided."}), 400

    if snap_bytes:
        save_persistent_asset(f"verified_faces/{snapshot_filename}", "image/jpeg", snap_bytes)

    # Check for registered reference photo (by linked user, roll number, or session)
    ref_photo_url = (sub_row["profile_photo"] or "").strip()
    if not ref_photo_url and sub_row.get("roll_number"):
        cursor.execute("SELECT profile_photo FROM users WHERE LOWER(roll_number) = LOWER(?) AND profile_photo != ''", (sub_row["roll_number"],))
        u_p = cursor.fetchone()
        if u_p and u_p["profile_photo"]:
            ref_photo_url = u_p["profile_photo"].strip()
    if not ref_photo_url and session.get("profile_photo"):
        ref_photo_url = session.get("profile_photo", "").strip()

    # Zero-Trust Security: Candidates CANNOT upload or swap photos during exam verification.
    # An official reference photo must already be registered with their account.
    if not ref_photo_url:
        conn.close()
        return jsonify({
            "success": False,
            "error": "No registered reference photo found on your account. Please log in to your profile and upload an official photo, or contact your tutor before taking this exam."
        }), 403

    # Resolve local reference image path
    clean_ref = ref_photo_url.lstrip("/").replace("/", os.sep)
    abs_ref_path = os.path.join(os.path.dirname(__file__), clean_ref)

    # If Render ephemeral disk cleared the file, automatically restore it from persistent_assets
    if not os.path.exists(abs_ref_path):
        asset_key = ref_photo_url.replace("/static/", "").lstrip("/")
        db_asset = get_persistent_asset(asset_key)
        if db_asset:
            try:
                os.makedirs(os.path.dirname(abs_ref_path), exist_ok=True)
                with open(abs_ref_path, "wb") as rf:
                    rf.write(db_asset[1])
            except Exception as w_err:
                print(f"Failed to restore reference photo from persistent assets: {w_err}")

    if not os.path.exists(abs_ref_path):
        conn.close()
        return jsonify({
            "success": False, 
            "error": "Reference photo file not found on server. Please click 'Upload/Change Photo' to register your photo."
        }), 400

    gemini_key = get_setting("gemini_api_key", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    student_name = sub_row["registered_full_name"] or sub_row["student_name"] or ""

    verif_res = verify_faces_with_gemini(
        gemini_key=gemini_key,
        reference_image_path=abs_ref_path,
        live_snapshot_path=snapshot_path,
        student_name=student_name
    )

    if not verif_res.get("success"):
        conn.close()
        return jsonify({"success": False, "error": verif_res.get("error", "AI verification failed.")})

    is_match = bool(verif_res.get("is_match", False))
    confidence = float(verif_res.get("confidence", 0.0))
    reason = verif_res.get("reason", "")

    if is_match and confidence >= 60.0:
        cursor.execute("""
            UPDATE submissions 
            SET verified_face_url = ?, is_face_verified = 1, face_match_confidence = ?
            WHERE id = ?
        """, (snapshot_rel_url, confidence, submission_id))
        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "is_match": True,
            "confidence": confidence,
            "verified_face_url": snapshot_rel_url,
            "reference_photo_url": ref_photo_url,
            "reason": reason
        })
    else:
        # Log impersonation attempt and increment strikes
        cursor.execute("""
            INSERT INTO violations (submission_id, violation_type, details)
            VALUES (?, 'impersonation_mismatch', ?)
        """, (submission_id, f"Live face does not match registered profile: {reason} (Confidence: {confidence}%)"))
        
        cursor.execute("UPDATE submissions SET warnings_count = warnings_count + 1 WHERE id = ?", (submission_id,))
        cursor.execute("""
            SELECT s.warnings_count, e.max_warnings
            FROM submissions s
            JOIN exams e ON s.exam_id = e.id
            WHERE s.id = ?
        """, (submission_id,))
        warn_info = cursor.fetchone()
        cur_warn = warn_info["warnings_count"] if warn_info else 1
        max_warn = warn_info["max_warnings"] if warn_info else 10
        is_terminated = False
        if cur_warn >= max_warn:
            is_terminated = True
            term_reason = f"Exceeded maximum allowed anti-cheating warnings ({cur_warn}/{max_warn} strikes). Violation: Biometric Impersonation Mismatch."
            cursor.execute("""
                UPDATE submissions 
                SET status = 'terminated', termination_reason = ?, submitted_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (term_reason, submission_id))

        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "is_match": False,
            "confidence": confidence,
            "warnings_count": cur_warn,
            "max_warnings": max_warn,
            "is_terminated": is_terminated,
            "verified_face_url": snapshot_rel_url,
            "reference_photo_url": ref_photo_url,
            "reason": reason or "Facial landmarks and structure do not match the registered candidate."
        })

@app.route("/api/tutor/submission/<int:submission_id>/update-score", methods=["POST"])
@admin_required
def tutor_update_submission_score(submission_id):
    """Allows tutors to award points or adjust final score for subjective/handwritten answers."""
    data = request.get_json() or {}
    try:
        new_score = float(data.get("score", 0.0))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid score value"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found"}), 404
        
    total_points = float(submission["total_points"]) if submission["total_points"] else 1.0
    percentage = (new_score / total_points * 100) if total_points > 0 else 0.0
    
    cursor.execute("""
        UPDATE submissions 
        SET score = ?, percentage = ?
        WHERE id = ?
    """, (round(new_score, 1), round(percentage, 1), submission_id))
    
    conn.commit()
    conn.close()
    return jsonify({"success": True, "score": round(new_score, 1), "percentage": round(percentage, 1)})


def compute_submission_score_with_or(questions, answers, manual_eval=None):
    """
    Computes total points and earned score for an exam, handling OR / alternative choices (e.g., 17.a and 17.b).
    - If Question 17 has an OR option (indicated by [OR Alternative] in question_text or is_or_choice),
      the question's maximum points are counted ONLY ONCE in total_points.
    - If the student attempts both 17.a and 17.b, they only get the maximum mark earned between the two,
      ensuring they NEVER get double marks.
    """
    if manual_eval is None:
        manual_eval = {}

    # Step 1: Assign display labels and group ID to each question
    grouped_questions = []
    main_num = 0
    group_id = 0

    for idx, q in enumerate(questions):
        q_dict = dict(q)
        q_text = (q_dict.get("question_text") or "").strip()
        is_or = q_text.startswith("[OR Alternative]")

        if not is_or:
            main_num += 1
            group_id = main_num
            # Check if immediately followed by an OR question
            next_is_or = (idx + 1 < len(questions)) and (
                (dict(questions[idx + 1]).get("question_text") or "").strip().startswith("[OR Alternative]")
            )
            sub_label = f"{main_num}.a" if next_is_or else f"{main_num}"
            q_dict["display_label"] = sub_label
            q_dict["main_number"] = main_num
            q_dict["is_or"] = False
            q_dict["group_id"] = group_id
        else:
            # Subsequent OR option for current main_num
            # Count previous items in same group
            prev_group_count = sum(1 for item in grouped_questions if item["group_id"] == group_id)
            sub_letter = chr(ord('a') + prev_group_count)
            q_dict["display_label"] = f"{main_num}.{sub_letter}"
            q_dict["main_number"] = main_num
            q_dict["is_or"] = True
            q_dict["group_id"] = group_id

        grouped_questions.append(q_dict)

    # Step 2: Compute score by grouping
    # For each group:
    # max points = points of the first question (or max points in group)
    # earned score = max(earned score among all options in group)
    from collections import defaultdict
    groups = defaultdict(list)
    for q_item in grouped_questions:
        groups[q_item["group_id"]].append(q_item)

    total_points = 0.0
    total_score = 0.0

    for gid, q_list in groups.items():
        # Points for this question group is only added ONCE
        group_max_pts = max(float(q.get("points") or 1.0) for q in q_list)
        total_points += group_max_pts

        group_earned_scores = []
        for q in q_list:
            qid_str = str(q.get("id"))
            q_pts = float(q.get("points") or 1.0)
            earned = 0.0

            if qid_str in manual_eval:
                earned = float(manual_eval[qid_str].get("awarded_marks", 0.0))
            else:
                ans_raw = answers.get(qid_str, "")
                if isinstance(ans_raw, dict):
                    student_ans = (ans_raw.get("text") or "").strip()
                else:
                    student_ans = str(ans_raw).strip() if ans_raw else ""
                corr = (q.get("correct_answer") or "").strip()
                if corr and student_ans.lower() == corr.lower():
                    earned = q_pts

            group_earned_scores.append(earned)

        # Student only gets the single best score from the choices
        total_score += max(group_earned_scores) if group_earned_scores else 0.0

    percentage = (total_score / total_points * 100) if total_points > 0 else 0.0
    return round(total_score, 1), round(total_points, 1), round(percentage, 1)


def attach_question_display_labels(question_dicts):
    """
    Given a list of question dicts, assigns 'display_label' (e.g. '17.a', '17.b') and cleans [OR Alternative] prefix.
    """
    main_num = 0
    total = len(question_dicts)
    for idx, q_dict in enumerate(question_dicts):
        q_text = (q_dict.get("question_text") or "").strip()
        is_or = q_text.startswith("[OR Alternative]")

        if not is_or:
            main_num += 1
            next_is_or = (idx + 1 < total) and (
                (question_dicts[idx + 1].get("question_text") or "").strip().startswith("[OR Alternative]")
            )
            q_dict["display_label"] = f"{main_num}.a" if next_is_or else f"{main_num}"
            q_dict["main_num"] = main_num
            q_dict["is_or_choice"] = False
        else:
            prev_group_count = sum(1 for item in question_dicts[:idx] if item.get("main_num") == main_num)
            sub_letter = chr(ord('a') + prev_group_count)
            q_dict["display_label"] = f"{main_num}.{sub_letter}"
            q_dict["main_num"] = main_num
            q_dict["is_or_choice"] = True
            # Clean up prefix for display in results
            clean_text = q_text.replace("[OR Alternative]", "").strip()
            q_dict["clean_question_text"] = clean_text
        if "clean_question_text" not in q_dict:
            q_dict["clean_question_text"] = q_dict.get("question_text") or ""
    return question_dicts

@app.route("/api/tutor/submission/<int:submission_id>/evaluate-question", methods=["POST"])
@admin_required
def api_tutor_evaluate_question(submission_id):
    """Uses Google Gemini / Groq AI to check an uploaded photo or handwritten/written answer and assign marks."""
    data = request.get_json() or {}
    question_id = str(data.get("question_id", ""))
    if not question_id:
        return jsonify({"success": False, "error": "Question ID is required."}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    cursor.execute("SELECT * FROM questions WHERE id = ? AND exam_id = ?", (int(question_id), submission["exam_id"]))
    question = cursor.fetchone()
    if not question:
        conn.close()
        return jsonify({"success": False, "error": "Question not found."}), 404

    # Extract student's response (text + single or multi-page images)
    student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
    ans_raw = student_answers.get(question_id)
    student_text = ""
    student_img_url = ""
    student_img_urls = []
    if isinstance(ans_raw, dict):
        student_text = (ans_raw.get("text") or "").strip()
        student_img_url = (ans_raw.get("image_url") or "").strip()
        raw_list = ans_raw.get("image_urls") or []
        if isinstance(raw_list, list):
            student_img_urls = [u.strip() for u in raw_list if isinstance(u, str) and u.strip()]
        if student_img_url and student_img_url not in student_img_urls:
            student_img_urls.insert(0, student_img_url)
        elif not student_img_url and student_img_urls:
            student_img_url = student_img_urls[0]
    elif isinstance(ans_raw, str):
        student_text = ans_raw.strip()

    if not student_text and not student_img_urls:
        conn.close()
        return jsonify({"success": False, "error": "Student did not submit text or photo for this question."}), 400

    # Resolve local file paths for all uploaded pages
    abs_img_paths = []
    for u in student_img_urls:
        clean_rel = u.lstrip("/").replace("/", os.sep)
        local_cand = os.path.join(os.path.dirname(__file__), clean_rel)
        if os.path.exists(local_cand):
            abs_img_paths.append(local_cand)

    gemini_key = get_setting("gemini_api_key", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "").strip() or os.environ.get("GROQ_API_KEY", "").strip()

    eval_result = evaluate_answer_with_ai(
        gemini_key=gemini_key,
        groq_key=groq_key,
        question_text=question["question_text"],
        max_points=question["points"],
        correct_answer=question["correct_answer"] or "",
        student_text=student_text,
        image_path=abs_img_paths[0] if abs_img_paths else None,
        image_paths=abs_img_paths,
        explanation=question["explanation"] or ""
    )

    if not eval_result.get("success"):
        conn.close()
        return jsonify({"success": False, "error": eval_result.get("error", "AI evaluation failed.")})

    awarded = float(eval_result["awarded_marks"])
    feedback = eval_result.get("feedback", "")
    model_used = eval_result.get("model_used", "AI")

    # Save to manual_evaluation_json in submissions
    existing_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}
    existing_eval[question_id] = {
        "awarded_marks": awarded,
        "max_points": float(question["points"]),
        "feedback": feedback,
        "model_used": model_used,
        "evaluated_by": "ai",
        "evaluated_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    }

    # Recalculate total score taking OR alternatives into account
    cursor.execute("SELECT * FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
    all_questions = cursor.fetchall()

    new_total_score, total_exam_points, percentage = compute_submission_score_with_or(
        all_questions, student_answers, existing_eval
    )

    cursor.execute("""
        UPDATE submissions
        SET manual_evaluation_json = ?, score = ?, total_points = ?, percentage = ?
        WHERE id = ?
    """, (json.dumps(existing_eval), new_total_score, total_exam_points, percentage, submission_id))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "awarded_marks": awarded,
        "feedback": feedback,
        "model_used": model_used,
        "new_score": round(new_total_score, 1),
        "total_points": total_exam_points,
        "percentage": round(percentage, 1)
    })

@app.route("/api/tutor/submission/<int:submission_id>/evaluate-all", methods=["POST"])
@admin_required
def api_tutor_evaluate_all(submission_id):
    """Evaluates ALL questions in a submission with AI — text, MCQ, images, short/long answers."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    cursor.execute("SELECT * FROM questions WHERE exam_id = ?", (submission["exam_id"],))
    all_questions = cursor.fetchall()

    student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
    existing_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}

    gemini_key = get_setting("gemini_api_key", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = get_setting("groq_api_key", "").strip() or os.environ.get("GROQ_API_KEY", "").strip()

    results = []
    total_exam_points = 0.0
    new_total_score = 0.0

    for q in all_questions:
        qid_s = str(q["id"])
        q_pts = float(q["points"])
        total_exam_points += q_pts

        ans_raw = student_answers.get(qid_s, "")
        student_text = ""
        student_img_url = ""
        student_img_urls = []
        if isinstance(ans_raw, dict):
            student_text = (ans_raw.get("text") or "").strip()
            student_img_url = (ans_raw.get("image_url") or "").strip()
            raw_list = ans_raw.get("image_urls") or []
            if isinstance(raw_list, list):
                student_img_urls = [u.strip() for u in raw_list if isinstance(u, str) and u.strip()]
            if student_img_url and student_img_url not in student_img_urls:
                student_img_urls.insert(0, student_img_url)
            elif not student_img_url and student_img_urls:
                student_img_url = student_img_urls[0]
        elif isinstance(ans_raw, str):
            student_text = ans_raw.strip()

        # Skip if nothing answered
        if not student_text and not student_img_urls:
            # Use objective grading for blank / unanswered
            results.append({"question_id": qid_s, "question_text": q["question_text"][:60], "success": False, "awarded_marks": 0, "max_points": q_pts, "reason": "Not attempted"})
            continue

        # Resolve image paths for all pages
        abs_img_paths = []
        for u in student_img_urls:
            clean_rel = u.lstrip("/").replace("/", os.sep)
            local_cand = os.path.join(os.path.dirname(__file__), clean_rel)
            if os.path.exists(local_cand):
                abs_img_paths.append(local_cand)

        eval_result = evaluate_answer_with_ai(
            gemini_key=gemini_key,
            groq_key=groq_key,
            question_text=q["question_text"],
            max_points=q["points"],
            correct_answer=q["correct_answer"] or "",
            student_text=student_text,
            image_path=abs_img_paths[0] if abs_img_paths else None,
            image_paths=abs_img_paths,
            explanation=q["explanation"] or ""
        )

        if eval_result.get("success"):
            awarded = float(eval_result["awarded_marks"])
            feedback = eval_result.get("feedback", "")
            model_used = eval_result.get("model_used", "AI")
            existing_eval[qid_s] = {
                "awarded_marks": awarded,
                "max_points": q_pts,
                "feedback": feedback,
                "model_used": model_used,
                "evaluated_by": "ai",
                "evaluated_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
            }
            results.append({"question_id": qid_s, "question_text": q["question_text"][:60], "success": True, "awarded_marks": awarded, "max_points": q_pts})
        else:
            # Fall back to objective check
            corr = (q["correct_answer"] or "").strip().lower()
            awarded = q_pts if (corr and student_text.lower() == corr) else 0.0
            existing_eval[qid_s] = {
                "awarded_marks": awarded,
                "max_points": q_pts,
                "feedback": "Objective check fallback.",
                "model_used": "System",
                "evaluated_by": "auto",
                "evaluated_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
            }
            results.append({"question_id": qid_s, "question_text": q["question_text"][:60], "success": False, "awarded_marks": awarded, "max_points": q_pts, "reason": eval_result.get("error", "AI failed")})

    # Recalculate total score taking OR alternatives into account
    new_total_score, total_exam_points, percentage = compute_submission_score_with_or(
        all_questions, student_answers, existing_eval
    )

    cursor.execute("""
        UPDATE submissions
        SET manual_evaluation_json = ?, score = ?, total_points = ?, percentage = ?
        WHERE id = ?
    """, (json.dumps(existing_eval), new_total_score, total_exam_points, percentage, submission_id))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "results": results,
        "new_score": new_total_score,
        "total_points": total_exam_points,
        "percentage": percentage
    })


@app.route("/api/tutor/submission/<int:submission_id>/update-question-score", methods=["POST"])
@admin_required
def api_tutor_update_question_score(submission_id):
    """Allows tutor to manually edit or override marks for an individual question (2, 3, 4, 5, etc.)."""
    data = request.get_json() or {}
    question_id = str(data.get("question_id", ""))
    if not question_id:
        return jsonify({"success": False, "error": "Question ID is required."}), 400

    try:
        new_marks = float(data.get("awarded_marks", 0.0))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid mark value."}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    cursor.execute("SELECT * FROM questions WHERE id = ? AND exam_id = ?", (int(question_id), submission["exam_id"]))
    question = cursor.fetchone()
    if not question:
        conn.close()
        return jsonify({"success": False, "error": "Question not found."}), 404

    max_pts = float(question["points"])
    new_marks = max(0.0, min(max_pts, round(new_marks, 1)))

    student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
    existing_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}

    existing_eval[question_id] = {
        "awarded_marks": new_marks,
        "max_points": max_pts,
        "feedback": data.get("feedback", "Teacher graded/edited mark."),
        "model_used": "Teacher",
        "evaluated_by": "teacher",
        "evaluated_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    }

    # Recalculate total score taking OR alternatives into account
    cursor.execute("SELECT * FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
    all_questions = cursor.fetchall()

    new_total_score, total_exam_points, percentage = compute_submission_score_with_or(
        all_questions, student_answers, existing_eval
    )

    cursor.execute("""
        UPDATE submissions
        SET manual_evaluation_json = ?, score = ?, total_points = ?, percentage = ?
        WHERE id = ?
    """, (json.dumps(existing_eval), new_total_score, total_exam_points, percentage, submission_id))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "awarded_marks": new_marks,
        "new_score": new_total_score,
        "total_points": total_exam_points,
        "percentage": percentage
    })

@app.route("/api/save-exam", methods=["POST"])
@admin_required
def api_save_exam():
    """Saves the tutor's configured exam and questions."""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
    
    title = data.get("title", "Untitled Exam").strip()
    description = data.get("description", "").strip()
    duration = int(data.get("duration_minutes", 30))
    max_warnings = int(data.get("max_warnings", 3))
    passing_percentage = float(data.get("passing_percentage", 40.0))
    questions_list = data.get("questions", [])
    
    if not questions_list:
        return jsonify({"success": False, "error": "Exam must contain at least 1 question"}), 400

    enable_audio = 1 if data.get("enable_audio_detection", 1) in [1, True, "1"] else 0
    enable_video = 1 if data.get("enable_video_detection", 1) in [1, True, "1"] else 0
    exam_code = generate_exam_code()
    
    # Access and schedule options
    access_type = data.get("access_type", "all")  # "all", "class", "selected"
    assigned_class = data.get("assigned_class", "").strip()
    assigned_students = data.get("assigned_students", [])  # list of student user_ids
    schedule_type = data.get("schedule_type", "anytime")  # "anytime", "scheduled"
    start_time = data.get("start_time", "").strip() or None
    end_time = data.get("end_time", "").strip() or None

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO exams (exam_code, title, description, duration_minutes, max_warnings, passing_percentage, enable_audio_detection, enable_video_detection, access_type, assigned_class, schedule_type, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (exam_code, title, description, duration, max_warnings, passing_percentage, enable_audio, enable_video, access_type, assigned_class, schedule_type, start_time, end_time))
        exam_id = cursor.lastrowid
        
        for q in questions_list:
            cursor.execute("""
                INSERT INTO questions (exam_id, question_text, question_type, options_json, correct_answer, explanation, points, figure_svg, figure_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                exam_id,
                q.get("question_text", ""),
                q.get("question_type", "mcq"),
                json.dumps(q.get("options", [])),
                q.get("correct_answer", ""),
                q.get("explanation", ""),
                float(q.get("points", 1.0)),
                q.get("figure_svg"),
                q.get("figure_url")
            ))
        
        # Save student assignments
        if access_type == "selected" and assigned_students:
            for sid in assigned_students:
                try:
                    cursor.execute("INSERT OR IGNORE INTO exam_assignments (exam_id, user_id) VALUES (?, ?)", (exam_id, int(sid)))
                except Exception:
                    pass
        elif access_type == "class" and assigned_class:
            cursor.execute("SELECT id FROM users WHERE role = 'student' AND LOWER(class_name) = LOWER(?)", (assigned_class,))
            for row in cursor.fetchall():
                cursor.execute("INSERT OR IGNORE INTO exam_assignments (exam_id, user_id) VALUES (?, ?)", (exam_id, row["id"]))

        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "exam_id": exam_id, "exam_code": exam_code})
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        return jsonify({"success": False, "error": f"Failed to save exam: {str(e)}"}), 500

@app.route("/api/tutor/exam/<int:exam_id>/access-schedule", methods=["GET", "POST"])
@admin_required
def api_exam_access_schedule(exam_id):
    conn = get_connection()
    cursor = conn.cursor()
    if request.method == "GET":
        cursor.execute("SELECT id, title, access_type, assigned_class, schedule_type, start_time, end_time, duration_minutes, enable_audio_detection, enable_video_detection FROM exams WHERE id = ?", (exam_id,))
        exam = cursor.fetchone()
        if not exam:
            conn.close()
            return jsonify({"success": False, "error": "Exam not found"}), 404
        
        cursor.execute("SELECT user_id FROM exam_assignments WHERE exam_id = ?", (exam_id,))
        assigned_ids = [r["user_id"] for r in cursor.fetchall()]
        ex_dict = dict(exam)
        def _ser_dt(v):
            if not v:
                return ""
            if isinstance(v, datetime):
                return v.strftime("%Y-%m-%dT%H:%M")
            return str(v)
        st_val = _ser_dt(ex_dict.get("start_time"))
        et_val = _ser_dt(ex_dict.get("end_time"))
        dur_val = int(ex_dict.get("duration_minutes") or 30)
        enable_audio_val = 1 if ex_dict.get("enable_audio_detection") in [1, True, "1"] else 0
        enable_video_val = 1 if ex_dict.get("enable_video_detection") in [1, True, "1"] else 0
        return jsonify({
            "success": True,
            "exam": {
                "id": ex_dict.get("id"),
                "title": ex_dict.get("title"),
                "access_type": ex_dict.get("access_type") or "all",
                "assigned_class": ex_dict.get("assigned_class") or "",
                "schedule_type": ex_dict.get("schedule_type") or "anytime",
                "start_time": st_val,
                "end_time": et_val,
                "duration_minutes": dur_val,
                "enable_audio_detection": enable_audio_val,
                "enable_video_detection": enable_video_val
            },
            "access_type": ex_dict.get("access_type") or "all",
            "assigned_class": ex_dict.get("assigned_class") or "",
            "schedule_type": ex_dict.get("schedule_type") or "anytime",
            "start_time": st_val,
            "end_time": et_val,
            "duration_minutes": dur_val,
            "enable_audio_detection": enable_audio_val,
            "enable_video_detection": enable_video_val,
            "assigned_student_ids": assigned_ids
        })

    data = request.get_json() or {}
    access_type = data.get("access_type", "all")
    assigned_class = data.get("assigned_class", "").strip()
    assigned_students = data.get("assigned_students", [])
    schedule_type = data.get("schedule_type", "anytime")
    start_time = data.get("start_time", "").strip() or None
    end_time = data.get("end_time", "").strip() or None
    duration_minutes = data.get("duration_minutes")

    if duration_minutes is not None:
        try:
            dur_int = max(1, int(duration_minutes))
            cursor.execute("""
                UPDATE exams
                SET access_type = ?, assigned_class = ?, schedule_type = ?, start_time = ?, end_time = ?, duration_minutes = ?
                WHERE id = ?
            """, (access_type, assigned_class, schedule_type, start_time, end_time, dur_int, exam_id))
        except (ValueError, TypeError):
            cursor.execute("""
                UPDATE exams
                SET access_type = ?, assigned_class = ?, schedule_type = ?, start_time = ?, end_time = ?
                WHERE id = ?
            """, (access_type, assigned_class, schedule_type, start_time, end_time, exam_id))
    else:
        cursor.execute("""
            UPDATE exams
            SET access_type = ?, assigned_class = ?, schedule_type = ?, start_time = ?, end_time = ?
            WHERE id = ?
        """, (access_type, assigned_class, schedule_type, start_time, end_time, exam_id))

    enable_audio = data.get("enable_audio_detection")
    enable_video = data.get("enable_video_detection")
    if enable_audio is not None and enable_video is not None:
        ea_val = 1 if enable_audio in [1, True, "1"] else 0
        ev_val = 1 if enable_video in [1, True, "1"] else 0
        cursor.execute("UPDATE exams SET enable_audio_detection = ?, enable_video_detection = ? WHERE id = ?", (ea_val, ev_val, exam_id))
    elif enable_audio is not None:
        ea_val = 1 if enable_audio in [1, True, "1"] else 0
        cursor.execute("UPDATE exams SET enable_audio_detection = ? WHERE id = ?", (ea_val, exam_id))
    elif enable_video is not None:
        ev_val = 1 if enable_video in [1, True, "1"] else 0
        cursor.execute("UPDATE exams SET enable_video_detection = ? WHERE id = ?", (ev_val, exam_id))

    cursor.execute("DELETE FROM exam_assignments WHERE exam_id = ?", (exam_id,))
    if access_type == "selected" and assigned_students:
        for sid in assigned_students:
            try:
                cursor.execute("INSERT OR IGNORE INTO exam_assignments (exam_id, user_id) VALUES (?, ?)", (exam_id, int(sid)))
            except Exception:
                pass
    elif access_type == "class" and assigned_class:
        cursor.execute("SELECT id FROM users WHERE role = 'student' AND LOWER(class_name) = LOWER(?)", (assigned_class,))
        for row in cursor.fetchall():
            cursor.execute("INSERT OR IGNORE INTO exam_assignments (exam_id, user_id) VALUES (?, ?)", (exam_id, row["id"]))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Access & Schedule settings updated successfully."})

@app.route("/tutor/exam/<int:exam_id>")
@admin_required
def tutor_exam_details(exam_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM exams WHERE id = ?", (exam_id,))
    exam = cursor.fetchone()
    if not exam:
        conn.close()
        return "Exam not found", 404
        
    cursor.execute("SELECT * FROM questions WHERE exam_id = ? ORDER BY id ASC", (exam_id,))
    questions = cursor.fetchall()
    
    # Parse options_json
    formatted_questions = []
    for q in questions:
        q_dict = dict(q)
        q_dict["options"] = json.loads(q["options_json"]) if q["options_json"] else []
        formatted_questions.append(q_dict)

    cursor.execute("""
        SELECT s.*,
               (SELECT COUNT(*) FROM violations WHERE submission_id = s.id) as total_violations
        FROM submissions s
        WHERE s.exam_id = ?
        ORDER BY s.started_at DESC
    """, (exam_id,))
    submissions = cursor.fetchall()
    cursor.execute("SELECT id, full_name, roll_number, class_name FROM users WHERE role = 'student' ORDER BY full_name ASC")
    students = cursor.fetchall()

    conn.close()
    
    public_url = get_setting("public_url", "")
    return render_template("exam_details.html", exam=exam, questions=formatted_questions, submissions=submissions, students=students, public_url=public_url)

@app.route("/tutor/submission/<int:submission_id>")
@admin_required
def tutor_submission_details(submission_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, e.title as exam_title, e.max_warnings, e.passing_percentage,
               u.profile_photo AS student_profile_photo
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        LEFT JOIN users u ON s.user_id = u.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return "Submission not found", 404
        
    cursor.execute("SELECT * FROM violations WHERE submission_id = ? ORDER BY timestamp ASC", (submission_id,))
    violations = cursor.fetchall()
    
    cursor.execute("SELECT * FROM questions WHERE exam_id = ?", (submission["exam_id"],))
    raw_questions = cursor.fetchall()
    
    student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
    manual_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}
    
    questions_review = []
    for q in raw_questions:
        q_dict = dict(q)
        q_dict["options"] = json.loads(q["options_json"]) if q["options_json"] else []
        q_id_str = str(q["id"])
        ans_raw = student_answers.get(q_id_str)
        
        student_text = ""
        student_img = ""
        student_imgs = []
        if isinstance(ans_raw, dict):
            student_text = (ans_raw.get("text") or "").strip()
            student_img = (ans_raw.get("image_url") or "").strip()
            raw_list = ans_raw.get("image_urls") or []
            if isinstance(raw_list, list):
                student_imgs = [u.strip() for u in raw_list if isinstance(u, str) and u.strip()]
            if student_img and student_img not in student_imgs:
                student_imgs.insert(0, student_img)
            elif not student_img and student_imgs:
                student_img = student_imgs[0]
        elif isinstance(ans_raw, str):
            student_text = ans_raw.strip()
            
        page_suffix = f" ({len(student_imgs)} Pages Attached)" if len(student_imgs) > 1 else (" (1 Page Attached)" if student_imgs else "")
        q_dict["student_answer"] = student_text if student_text else (f"(Handwritten Solution{page_suffix})" if student_imgs else "Not Attempted")
        q_dict["student_image_url"] = student_img
        q_dict["student_image_urls"] = student_imgs
        
        correct_ans = (q["correct_answer"] or "").strip().lower()
        if correct_ans:
            q_dict["is_correct"] = (student_text.lower() == correct_ans)
        else:
            q_dict["is_correct"] = False

        # Attach manual / AI evaluation data if present
        eval_item = manual_eval.get(q_id_str)
        if eval_item:
            q_dict["awarded_marks"] = float(eval_item.get("awarded_marks", 0.0))
            q_dict["eval_feedback"] = eval_item.get("feedback", "")
            q_dict["eval_by"] = eval_item.get("evaluated_by", "ai")
            q_dict["eval_model"] = eval_item.get("model_used", "")
            q_dict["eval_at"] = eval_item.get("evaluated_at", "")
            q_dict["is_evaluated"] = True
        else:
            # Fallback to objective calculation
            default_pts = float(q["points"]) if q_dict["is_correct"] else 0.0
            q_dict["awarded_marks"] = default_pts
            q_dict["eval_feedback"] = ""
            q_dict["eval_by"] = "auto"
            q_dict["eval_model"] = ""
            q_dict["eval_at"] = ""
            q_dict["is_evaluated"] = False
            
        questions_review.append(q_dict)
        
    questions_review = attach_question_display_labels(questions_review)
    conn.close()
    return render_template("submission_details.html", submission=submission, violations=violations, questions=questions_review)

@app.route("/api/tutor/submission/<int:submission_id>/grant-reattempt", methods=["POST"])
@admin_required
def api_grant_reattempt(submission_id):
    """
    Admin grants a re-attempt with two modes:
      reattempt_type='fresh'  → Deletes the existing submission entirely (student starts from scratch).
      reattempt_type='resume' → Restores the submission to 'in_progress' using the saved partial answers
                               from the point of termination, so the student continues from where they stopped.
    """
    data = request.get_json() or {}
    reattempt_type = data.get("reattempt_type", "fresh")

    conn = get_connection()
    cursor = conn.cursor()

    # Verify submission exists and fetch info for response
    cursor.execute("""
        SELECT s.id, s.student_name, s.roll_number, s.exam_id, s.status,
               s.answers_json, s.time_remaining_seconds, s.current_question_index,
               e.title as exam_title
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()

    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    if reattempt_type == "resume":
        # Restore to in_progress from the saved partial answers (don't delete — keep audit trail)
        # Use answers_json (which was saved at termination) as the restored progress
        saved_answers = submission["answers_json"] or "{}"
        saved_time = submission["time_remaining_seconds"]
        saved_q_idx = submission["current_question_index"] or 0

        cursor.execute("""
            UPDATE submissions
            SET status = 'in_progress',
                termination_reason = NULL,
                submitted_at = NULL,
                warnings_count = 0,
                progress_answers_json = ?,
                time_remaining_seconds = ?,
                current_question_index = ?,
                answers_json = NULL,
                score = NULL,
                total_points = NULL,
                percentage = NULL
            WHERE id = ?
        """, (saved_answers, saved_time, saved_q_idx, submission_id))

        # Clear violations log for a clean slate but keep history in audit
        cursor.execute("DELETE FROM violations WHERE submission_id = ?", (submission_id,))

        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "message": f"Re-attempt (Resume) granted for {submission['student_name']}. They will continue from where they left off.",
            "student_name": submission["student_name"],
            "exam_title": submission["exam_title"],
            "exam_id": submission["exam_id"],
            "reattempt_type": "resume"
        })
    else:
        # Fresh start — delete violations first (foreign key constraint), then the submission
        cursor.execute("DELETE FROM violations WHERE submission_id = ?", (submission_id,))
        cursor.execute("DELETE FROM submissions WHERE id = ?", (submission_id,))

        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "message": f"Fresh re-attempt granted for {submission['student_name']}. Their previous submission has been cleared.",
            "student_name": submission["student_name"],
            "exam_title": submission["exam_title"],
            "exam_id": submission["exam_id"],
            "reattempt_type": "fresh"
        })


@app.route("/student/dashboard")
@login_required
def student_dashboard():
    user_id = session.get("user_id")
    roll_number = session.get("roll_number")
    conn = get_connection()
    cursor = conn.cursor()

    # Get student profile
    cursor.execute("SELECT class_name, profile_photo FROM users WHERE id = ?", (user_id,))
    u_row = cursor.fetchone()
    user_class = (u_row["class_name"] or "").strip().lower() if u_row else ""
    if u_row and u_row["profile_photo"]:
        session["profile_photo"] = u_row["profile_photo"]

    # Fetch all active exams, including any in-progress session for this student
    cursor.execute("""
        SELECT e.*,
               (SELECT COUNT(*) FROM questions WHERE exam_id = e.id) as question_count,
               (SELECT id FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status NOT IN ('in_progress','pause_requested','paused') ORDER BY started_at DESC LIMIT 1) as completed_sub_id,
               (SELECT score FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status NOT IN ('in_progress','pause_requested','paused') ORDER BY started_at DESC LIMIT 1) as completed_score,
               (SELECT percentage FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status NOT IN ('in_progress','pause_requested','paused') ORDER BY started_at DESC LIMIT 1) as completed_pct,
               (SELECT id FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status IN ('in_progress','pause_requested','paused') ORDER BY started_at DESC LIMIT 1) as active_sub_id,
               (SELECT status FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status IN ('in_progress','pause_requested','paused') ORDER BY started_at DESC LIMIT 1) as active_sub_status
        FROM exams e
        WHERE e.is_active = 1
        ORDER BY e.created_at DESC
    """, (user_id, roll_number, user_id, roll_number, user_id, roll_number, user_id, roll_number, user_id, roll_number))
    all_exams = cursor.fetchall()

    cursor.execute("SELECT exam_id FROM exam_assignments WHERE user_id = ?", (user_id,))
    assigned_ids = set(r["exam_id"] for r in cursor.fetchall())
    conn.close()

    accessible_exams = []
    now = get_current_time()
    for ex in all_exams:
        ex_dict = dict(ex)
        acc_type = ex_dict.get("access_type") or "all"
        has_access = False
        if acc_type == "all":
            has_access = True
        elif acc_type == "class" and user_class and (ex_dict.get("assigned_class", "").strip().lower() == user_class or ex_dict["id"] in assigned_ids):
            has_access = True
        elif ex_dict["id"] in assigned_ids:
            has_access = True

        if has_access:
            sched = ex_dict.get("schedule_type") or "anytime"
            if sched == "scheduled":
                start_dt = None
                end_dt = None
                try:
                    if ex_dict.get("start_time"):
                        start_dt = datetime.fromisoformat(ex_dict["start_time"])
                    if ex_dict.get("end_time"):
                        end_dt = datetime.fromisoformat(ex_dict["end_time"])
                except Exception:
                    pass

                if start_dt and now < start_dt:
                    ex_dict["time_status"] = "upcoming"
                    ex_dict["time_status_label"] = f"Starts {start_dt.strftime('%b %d, %I:%M %p')}"
                elif end_dt and now > end_dt:
                    ex_dict["time_status"] = "expired"
                    ex_dict["time_status_label"] = f"Closed {end_dt.strftime('%b %d, %I:%M %p')}"
                else:
                    ex_dict["time_status"] = "live"
                    ex_dict["time_status_label"] = "Live Now" + (f" (Until {end_dt.strftime('%I:%M %p')})" if end_dt else "")
            else:
                ex_dict["time_status"] = "anytime"
                ex_dict["time_status_label"] = "Available Anytime"

            accessible_exams.append(ex_dict)

    submissions = get_student_submissions(user_id, roll_number)
    return render_template("student_dashboard.html", student=session, submissions=submissions, available_exams=accessible_exams)

@app.route("/student")
def student_join():
    code = request.args.get("code", "")
    if not session.get("user_id"):
        return redirect(url_for("login", role="student", next=f"/student?code={code}" if code else "/student"))
    if session.get("user_role") == "admin":
        return redirect(url_for("tutor_dashboard"))
    return render_template("student_join.html", prefill_code=code, student=session)

@app.route("/student/start", methods=["POST"])
def student_start():
    exam_code = request.form.get("exam_code", "").strip().upper()
    student_name = request.form.get("student_name", "").strip() or session.get("user_name", "")
    roll_number = request.form.get("roll_number", "").strip() or session.get("roll_number", "")
    
    if not exam_code or not student_name or not roll_number:
        flash("Please provide Exam Code, Full Name, and Roll Number.", "danger")
        return redirect(url_for("student_join", code=exam_code))
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM exams WHERE exam_code = ? AND is_active = 1", (exam_code,))
    exam = cursor.fetchone()
    
    if not exam:
        conn.close()
        flash("Invalid Exam Code or Exam is no longer active.", "danger")
        return redirect(url_for("student_join"))
        
    user_id = session.get("user_id")

    # 1. Access Permission Check
    access_type = exam["access_type"] or "all"
    if access_type != "all":
        cursor.execute("SELECT class_name FROM users WHERE id = ?", (user_id,))
        u_info = cursor.fetchone()
        u_class = (u_info["class_name"] or "").strip().lower() if u_info else ""
        
        cursor.execute("SELECT id FROM exam_assignments WHERE exam_id = ? AND user_id = ?", (exam["id"], user_id))
        is_assigned = cursor.fetchone() is not None
        
        has_access = False
        if is_assigned:
            has_access = True
        elif access_type == "class" and exam["assigned_class"] and u_class == exam["assigned_class"].strip().lower():
            has_access = True
            
        if not has_access:
            conn.close()
            flash("Access Restricted: This exam is only accessible to specific students or classes. Your account has not been granted access.", "danger")
            return redirect(url_for("student_dashboard"))

    # 2. Schedule Timing Check
    schedule_type = exam["schedule_type"] or "anytime"
    if schedule_type == "scheduled":
        now = get_current_time()
        start_time_str = exam["start_time"]
        end_time_str = exam["end_time"]
        
        if start_time_str:
            try:
                start_dt = datetime.fromisoformat(start_time_str)
                if now < start_dt:
                    conn.close()
                    flash(f"Exam Not Started Yet: This exam is scheduled to open on {start_dt.strftime('%b %d, %Y at %I:%M %p')}. Please return when it begins.", "warning")
                    return redirect(url_for("student_dashboard"))
            except Exception:
                pass
                
        if end_time_str:
            try:
                end_dt = datetime.fromisoformat(end_time_str)
                if now > end_dt:
                    conn.close()
                    flash(f"Exam Window Closed: This exam expired on {end_dt.strftime('%b %d, %Y at %I:%M %p')}.", "danger")
                    return redirect(url_for("student_dashboard"))
            except Exception:
                pass

    # Check if student already has an in_progress submission for this exam
    # (e.g. they refreshed the page or came back after closing the tab)
    # → redirect straight to it instead of creating a duplicate.
    cursor.execute("""
        SELECT id FROM submissions
        WHERE exam_id = ? AND (user_id = ? OR roll_number = ?)
          AND status IN ('in_progress', 'pause_requested', 'paused')
        ORDER BY started_at DESC LIMIT 1
    """, (exam["id"], user_id, roll_number))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return redirect(url_for("student_exam_room", submission_id=existing["id"]))

    # No active session found — create a new in_progress submission
    cursor.execute("""
        INSERT INTO submissions (exam_id, student_name, roll_number, status, started_at, user_id)
        VALUES (?, ?, ?, 'in_progress', CURRENT_TIMESTAMP, ?)
    """, (exam["id"], student_name, roll_number, user_id))
    submission_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return redirect(url_for("student_exam_room", submission_id=submission_id))

@app.route("/student/exam/<int:submission_id>")
@login_required
def student_exam_room(submission_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, e.title, e.duration_minutes, e.max_warnings, e.exam_code, e.enable_audio_detection, e.enable_video_detection,
               e.schedule_type, e.start_time, e.end_time,
               u.profile_photo AS student_profile_photo
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        LEFT JOIN users u ON s.user_id = u.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission:
        conn.close()
        return "Exam session not found", 404

    # Ownership check for students
    if session.get("user_role") == "student":
        sub_uid = submission["user_id"]
        sub_roll = submission["roll_number"]
        curr_uid = session.get("user_id")
        curr_roll = session.get("roll_number")
        if (sub_uid and sub_uid != curr_uid) or (not sub_uid and sub_roll != curr_roll):
            conn.close()
            flash("Access Restricted: You can only access your own exam session.", "danger")
            return redirect(url_for("student_dashboard"))
        
    if submission["status"] in ["submitted", "terminated"]:
        conn.close()
        return redirect(url_for("exam_result", submission_id=submission_id))

    # Check if the scheduled exam window has already ended
    if submission["schedule_type"] == "scheduled" and submission["end_time"]:
        try:
            end_dt = datetime.fromisoformat(str(submission["end_time"]))
            if get_current_time() > end_dt:
                # Window expired — auto-finalize submission if still in_progress
                if submission["status"] == "in_progress":
                    cursor.execute("""
                        UPDATE submissions
                        SET status = 'submitted', submitted_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (submission_id,))
                    conn.commit()
                conn.close()
                flash("The scheduled time window for this exam has ended. The exam is now closed.", "warning")
                return redirect(url_for("student_dashboard"))
        except Exception:
            pass

    # If paused or awaiting tutor approval, show a waiting screen instead of the exam
    if submission["status"] in ["paused", "pause_requested"]:
        conn.close()
        return render_template(
            "exam_paused.html",
            submission=submission,
        )

    cursor.execute("SELECT id, question_text, question_type, options_json, points, figure_svg, figure_url FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
    raw_questions = cursor.fetchall()
    conn.close()
    
    questions = []
    for q in raw_questions:
        q_dict = dict(q)
        q_dict["options"] = json.loads(q["options_json"]) if q["options_json"] else []
        questions.append(q_dict)
        
    # Restore saved progress (answers, timer, current question index) for page-refresh recovery
    saved_progress = None
    saved_time_remaining = None
    saved_question_index = 0
    if submission["status"] == "in_progress":
        if submission["progress_answers_json"]:
            saved_progress = submission["progress_answers_json"]
        if submission["time_remaining_seconds"] is not None:
            saved_time_remaining = int(submission["time_remaining_seconds"])
        if submission["current_question_index"] is not None:
            saved_question_index = int(submission["current_question_index"])

    return render_template(
        "student_exam.html",
        submission=submission,
        questions=questions,
        saved_progress=saved_progress,
        saved_time_remaining=saved_time_remaining,
        saved_question_index=saved_question_index,
    )

@app.route("/api/submission/<int:submission_id>/violation", methods=["POST"])
@login_required
def api_log_violation(submission_id):
    """
    Called by anti-cheating JS engine when a violation occurs:
    e.g. tab_switch, blur, fullscreen_exit, devtools, copy_paste.
    Increments warning counter. If warnings >= max_warnings, terminates exam immediately.
    """
    data = request.get_json() or {}
    violation_type = (data.get("type") or "unknown").strip()
    raw_details = data.get("details", "")
    details = str(raw_details)[:500] if raw_details else ""
    client_ip = (request.remote_addr or "127.0.0.1").strip()
    if request.headers.get("X-Forwarded-For"):
        forwarded = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        if forwarded:
            client_ip = forwarded
    
    sec_meta = classify_security_event(violation_type)
    event_code = sec_meta.get("code", "SEC-ALERT")
    severity = sec_meta.get("severity", "HIGH")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, e.max_warnings, e.id as exam_id
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission or submission["status"] != "in_progress":
        conn.close()
        return jsonify({"terminated": True, "reason": "Exam is already closed or invalid"})

    # Student ownership check: prevents tampering with other candidates' exams
    if session.get("user_role") == "student" and submission["user_id"] != session.get("user_id"):
        conn.close()
        return jsonify({"terminated": False, "error": "Access denied."}), 403
        
    # Insert violation log with SIEM classification
    cursor.execute("""
        INSERT INTO violations (submission_id, violation_type, details, severity, event_code)
        VALUES (?, ?, ?, ?, ?)
    """, (submission_id, violation_type, details, severity, event_code))
    
    new_warnings = submission["warnings_count"] + 1
    max_allowed = submission["max_warnings"]
    
    is_terminated = False
    termination_reason = None
    
    if new_warnings >= max_allowed:
        is_terminated = True
        termination_reason = f"Exceeded maximum allowed anti-cheating warnings ({new_warnings}/{max_allowed} strikes). Violation: {violation_type.replace('_', ' ').title()}"
        
        # Calculate cryptographic integrity token for the terminated record
        term_hash = generate_submission_integrity_hash(
            submission_id, 
            submission["roll_number"], 
            submission.get("score") or 0.0, 
            submission.get("total_points") or 0.0, 
            new_warnings, 
            'terminated'
        )
        
        # Save any partially-answered questions (from progress_answers_json) into answers_json
        cursor.execute("""
            UPDATE submissions 
            SET warnings_count = ?, status = 'terminated', termination_reason = ?, submitted_at = CURRENT_TIMESTAMP,
                client_ip = ?, integrity_hash = ?,
                answers_json = COALESCE(
                    CASE WHEN (answers_json IS NULL OR answers_json = '' OR answers_json = '{}') 
                         THEN progress_answers_json 
                         ELSE answers_json 
                    END,
                    '{}'
                )
            WHERE id = ?
        """, (new_warnings, termination_reason, client_ip, term_hash, submission_id))
    else:
        cursor.execute("UPDATE submissions SET warnings_count = ?, client_ip = ? WHERE id = ?", (new_warnings, client_ip, submission_id))
        
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "warnings_count": new_warnings,
        "max_warnings": max_allowed,
        "is_terminated": is_terminated,
        "reason": termination_reason
    })

@app.route("/api/submission/<int:submission_id>/submit", methods=["POST"])
@login_required
def api_submit_exam(submission_id):
    """Calculates final score, records completion, and computes cryptographic integrity hash."""
    data = request.get_json() or {}
    answers = data.get("answers", {})  # {str(question_id): selected_answer}
    client_ip = (request.remote_addr or "127.0.0.1").strip()
    if request.headers.get("X-Forwarded-For"):
        forwarded = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        if forwarded:
            client_ip = forwarded
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, e.duration_minutes 
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission or submission["status"] not in ["in_progress"]:
        conn.close()
        return jsonify({"success": False, "error": "Submission is already finalized."})

    # Student ownership check: prevents unauthorized submission of other candidates' exams
    if session.get("user_role") == "student" and submission["user_id"] != session.get("user_id"):
        conn.close()
        return jsonify({"success": False, "error": "Access denied."}), 403
        
    cursor.execute("SELECT * FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
    questions = cursor.fetchall()
    
    manual_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}
    total_score, total_points, percentage = compute_submission_score_with_or(
        questions, answers, manual_eval
    )
    
    # Generate cryptographic SHA-256 HMAC for submission integrity & tamper detection
    integrity_token = generate_submission_integrity_hash(
        submission_id, 
        submission["roll_number"], 
        total_score, 
        total_points, 
        submission.get("warnings_count", 0), 
        'submitted'
    )
    
    cursor.execute("""
        UPDATE submissions 
        SET answers_json = ?, score = ?, total_points = ?, percentage = ?, status = 'submitted', 
            submitted_at = CURRENT_TIMESTAMP, client_ip = ?, integrity_hash = ?
        WHERE id = ?
    """, (json.dumps(answers), total_score, total_points, round(percentage, 1), client_ip, integrity_token, submission_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "submission_id": submission_id, "integrity_hash": integrity_token})


# ---------------------------------------------------------------------------
# Exam Progress Auto-Save (called every 30 s by the exam front-end)
# ---------------------------------------------------------------------------
@app.route("/api/submission/<int:submission_id>/save-progress", methods=["POST"])
@login_required
def api_save_progress(submission_id):
    """Auto-saves the student's current answers + timer so the page can recover after a refresh.
    Accepts both JSON (fetch) and raw Blob (navigator.sendBeacon) payloads.
    """
    # navigator.sendBeacon sends Content-Type: application/octet-stream or text/plain
    content_type = request.content_type or ""
    if "application/json" in content_type:
        data = request.get_json(silent=True) or {}
    else:
        # sendBeacon sends raw bytes — decode and parse manually
        try:
            data = json.loads(request.get_data(as_text=True))
        except Exception:
            data = {}

    answers_json = json.dumps(data.get("answers", {}))
    time_remaining = data.get("time_remaining_seconds")
    current_q_index = data.get("current_question_index", 0)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, status, user_id FROM submissions WHERE id = ?", (submission_id,))
    sub = cursor.fetchone()

    if not sub or sub["status"] not in ("in_progress",):
        conn.close()
        return jsonify({"success": False, "error": "Submission not active."})

    # Basic ownership guard
    if session.get("user_role") == "student" and sub["user_id"] != session.get("user_id"):
        conn.close()
        return jsonify({"success": False, "error": "Access denied."})

    cursor.execute("""
        UPDATE submissions
        SET progress_answers_json = ?,
            time_remaining_seconds = ?,
            current_question_index = ?
        WHERE id = ?
    """, (answers_json, time_remaining, current_q_index, submission_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Student Pause Request
# ---------------------------------------------------------------------------
@app.route("/api/submission/<int:submission_id>/request-pause", methods=["POST"])
@login_required
def api_request_pause(submission_id):
    """
    Student asks to pause their exam. Saves current progress and marks
    status='pause_requested'. The tutor must approve to fully pause or allow resume.
    Scheduled exams will NOT allow the student to self-resume — tutor approval is required.
    """
    data = request.get_json() or {}
    reason = (data.get("reason") or "Student requested a pause.").strip()[:500]
    answers_json = json.dumps(data.get("answers", {}))
    time_remaining = data.get("time_remaining_seconds")
    current_q_index = data.get("current_question_index", 0)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, e.schedule_type
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    sub = cursor.fetchone()

    if not sub:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."})

    if sub["status"] not in ("in_progress",):
        conn.close()
        return jsonify({"success": False, "error": f"Cannot pause an exam with status '{sub['status']}'."})

    if session.get("user_role") == "student" and sub["user_id"] != session.get("user_id"):
        conn.close()
        return jsonify({"success": False, "error": "Access denied."})

    cursor.execute("""
        UPDATE submissions
        SET status = 'pause_requested',
            progress_answers_json = ?,
            time_remaining_seconds = ?,
            current_question_index = ?,
            pause_requested_at = CURRENT_TIMESTAMP,
            pause_reason = ?
        WHERE id = ?
    """, (answers_json, time_remaining, current_q_index, reason, submission_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Pause request sent to the tutor. Please wait for approval."})


# ---------------------------------------------------------------------------
# Student polls pause/resume status
# ---------------------------------------------------------------------------
@app.route("/api/submission/<int:submission_id>/pause-status", methods=["GET"])
@login_required
def api_pause_status(submission_id):
    """
    Front-end polls this every 10 s while waiting for tutor to approve/reject the pause.
    Returns current status and, on approval, the saved time & answers so the student can resume.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, status, time_remaining_seconds, progress_answers_json, current_question_index, user_id
        FROM submissions WHERE id = ?
    """, (submission_id,))
    sub = cursor.fetchone()
    conn.close()

    if not sub:
        return jsonify({"success": False, "error": "Not found."})

    if session.get("user_role") == "student" and sub["user_id"] != session.get("user_id"):
        return jsonify({"success": False, "error": "Access denied."})

    return jsonify({
        "success": True,
        "status": sub["status"],
        "time_remaining_seconds": sub["time_remaining_seconds"],
        "current_question_index": sub["current_question_index"] or 0,
        "progress_answers_json": sub["progress_answers_json"] or "{}",
    })


# ---------------------------------------------------------------------------
# Tutor approves or rejects a pause/resume request
# ---------------------------------------------------------------------------
@app.route("/api/tutor/submission/<int:submission_id>/manage-pause", methods=["POST"])
@admin_required
def api_manage_pause(submission_id):
    """
    Tutor can:
      action='approve_pause'  → status becomes 'paused'  (timer frozen, student locked out)
      action='approve_resume' → status returns to 'in_progress' (student can re-enter)
      action='reject_pause'   → status returns to 'in_progress' (deny the student's request)
    """
    data = request.get_json() or {}
    action = data.get("action", "")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, status FROM submissions WHERE id = ?", (submission_id,))
    sub = cursor.fetchone()

    if not sub:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."})

    current_status = sub["status"]

    if action == "approve_pause":
        if current_status != "pause_requested":
            conn.close()
            return jsonify({"success": False, "error": "No pending pause request."})
        cursor.execute("UPDATE submissions SET status = 'paused' WHERE id = ?", (submission_id,))
        msg = "Exam paused. The student cannot continue until you approve their resume request."

    elif action == "approve_resume":
        if current_status not in ("paused", "pause_requested"):
            conn.close()
            return jsonify({"success": False, "error": "Submission is not in a paused state."})
        cursor.execute("""
            UPDATE submissions
            SET status = 'in_progress', pause_requested_at = NULL, pause_reason = NULL
            WHERE id = ?
        """, (submission_id,))
        msg = "Resume approved. The student can now re-enter and continue the exam."

    elif action == "reject_pause":
        if current_status != "pause_requested":
            conn.close()
            return jsonify({"success": False, "error": "No pending pause request to reject."})
        cursor.execute("""
            UPDATE submissions
            SET status = 'in_progress', pause_requested_at = NULL, pause_reason = NULL
            WHERE id = ?
        """, (submission_id,))
        msg = "Pause request rejected. The student's exam timer continues."

    else:
        conn.close()
        return jsonify({"success": False, "error": f"Unknown action '{action}'."})

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": msg})


@app.route("/api/tutor/submission/<int:submission_id>/approve-device-switch", methods=["POST"])
@admin_required
def api_approve_device_switch(submission_id):
    """Admin grants permission for a student to switch devices while their exam is in progress."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, student_name FROM submissions WHERE id = ?", (submission_id,))
    sub = cursor.fetchone()
    if not sub:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    cursor.execute("UPDATE submissions SET device_switch_approved = 1 WHERE id = ?", (submission_id,))
    conn.commit()
    conn.close()
    return jsonify({
        "success": True,
        "message": f"Device switch approved for {sub['student_name']}. They can now sign in and continue their exam on a new device."
    })


@app.route("/api/tutor/exam/<int:exam_id>/toggle-publish-results", methods=["POST"])
@admin_required
def api_toggle_exam_results_published(exam_id):
    """Admin publishes or unpublishes answers & detailed mistakes/evaluation for all students in an exam."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, results_published FROM exams WHERE id = ?", (exam_id,))
    exam = cursor.fetchone()
    if not exam:
        conn.close()
        return jsonify({"success": False, "error": "Exam not found."}), 404

    current_val = int(exam.get("results_published") or 0)
    new_val = 0 if current_val == 1 else 1

    cursor.execute("UPDATE exams SET results_published = ? WHERE id = ?", (new_val, exam_id))
    # Also sync is_published to all submissions for this exam
    cursor.execute("UPDATE submissions SET is_published = ? WHERE exam_id = ?", (new_val, exam_id))

    # When results are officially published, automatically resolve & archive SOC cyber incidents for this exam
    if new_val == 1:
        cursor.execute("""
            UPDATE violations
            SET is_resolved = 1
            WHERE submission_id IN (SELECT id FROM submissions WHERE exam_id = ?)
        """, (exam_id,))

    conn.commit()
    conn.close()

    status_str = "Published to Students" if new_val == 1 else "Hidden from Students (Awaiting Evaluation)"
    return jsonify({
        "success": True,
        "results_published": bool(new_val),
        "message": f"Results and question review are now {status_str}."
    })


@app.route("/api/tutor/submission/<int:submission_id>/toggle-publish", methods=["POST"])
@admin_required
def api_toggle_submission_published(submission_id):
    """Admin publishes or unpublishes evaluation review for an individual student."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, student_name, is_published FROM submissions WHERE id = ?", (submission_id,))
    sub = cursor.fetchone()
    if not sub:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    current_val = int(sub.get("is_published") or 0)
    new_val = 0 if current_val == 1 else 1

    cursor.execute("UPDATE submissions SET is_published = ? WHERE id = ?", (new_val, submission_id))

    # If published, mark violations for this submission as resolved
    if new_val == 1:
        cursor.execute("UPDATE violations SET is_resolved = 1 WHERE submission_id = ?", (submission_id,))

    conn.commit()
    conn.close()

    status_str = "Published" if new_val == 1 else "Unpublished"
    return jsonify({
        "success": True,
        "is_published": bool(new_val),
        "message": f"Evaluation report for {sub['student_name']} is now {status_str}."
    })


@app.route("/api/submission/<int:submission_id>/publish-status", methods=["GET"])
def api_submission_publish_status(submission_id):
    """Allows student result page to poll and automatically refresh once tutor publishes."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_published FROM submissions WHERE id = ?", (submission_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"published": False}), 404
    return jsonify({"published": bool(row["is_published"])})


# ---------------------------------------------------------------------------
# Live Proctoring Cockpit API: Real-time candidate telemetry & status stream
# ---------------------------------------------------------------------------
@app.route("/api/tutor/exam/<int:exam_id>/live-proctor", methods=["GET"])
@admin_required
def api_exam_live_proctor(exam_id):
    """Returns active and recent candidate telemetry for the real-time proctoring cockpit."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.id, s.exam_id, s.user_id, s.student_name, s.roll_number, s.status,
               s.warnings_count, s.score, s.total_points, s.client_ip, s.time_remaining_seconds,
               s.started_at, s.submitted_at, s.verified_face_url, s.is_face_verified,
               s.face_match_confidence, s.pause_reason,
               u.profile_photo AS student_profile_photo,
               (SELECT COUNT(*) FROM violations v WHERE v.submission_id = s.id) AS violation_count,
               (SELECT v.violation_type FROM violations v WHERE v.submission_id = s.id ORDER BY v.timestamp DESC LIMIT 1) AS last_violation_type,
               (SELECT v.timestamp FROM violations v WHERE v.submission_id = s.id ORDER BY v.timestamp DESC LIMIT 1) AS last_violation_time
        FROM submissions s
        LEFT JOIN users u ON s.user_id = u.id
        WHERE s.exam_id = ?
        ORDER BY 
            CASE 
                WHEN s.status = 'in_progress' THEN 1
                WHEN s.status = 'pause_requested' THEN 2
                WHEN s.status = 'paused' THEN 3
                WHEN s.status = 'terminated' THEN 4
                ELSE 5
            END,
            s.started_at DESC
    """, (exam_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    candidates = []
    for r in rows:
        d = dict(r)
        candidates.append(d)
        
    return jsonify({
        "success": True,
        "exam_id": exam_id,
        "total_candidates": len(candidates),
        "candidates": candidates
    })


@app.route("/api/tutor/submission/<int:submission_id>/force-terminate", methods=["POST"])
@admin_required
def api_tutor_force_terminate(submission_id):
    """Tutor immediately terminates an active exam session for severe malpractice."""
    data = request.get_json() or {}
    reason = (data.get("reason") or "Directly terminated by Proctor for academic malpractice.").strip()
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, exam_id, student_name, status FROM submissions WHERE id = ?", (submission_id,))
    sub = cursor.fetchone()
    
    if not sub:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404
        
    cursor.execute("""
        UPDATE submissions 
        SET status = 'terminated', termination_reason = ? 
        WHERE id = ?
    """, (reason, submission_id))
    
    # Log critical violation incident
    cursor.execute("""
        INSERT INTO violations (submission_id, violation_type, details, severity, event_code)
        VALUES (?, 'PROCTOR_MANUAL_TERMINATION', ?, 'CRITICAL', 'SEC-009')
    """, (submission_id, f"Proctor action: {reason}"))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "message": f"Exam attempt for {sub['student_name']} has been terminated immediately."
    })


@app.route("/student/result/<int:submission_id>")
@login_required
def exam_result(submission_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, e.title, e.max_warnings, e.passing_percentage
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission:
        conn.close()
        return "Result not found", 404

    # Authorization Check: Students can ONLY view their own results!
    if session.get("user_role") == "student":
        sub_uid = submission["user_id"]
        sub_roll = submission["roll_number"]
        curr_uid = session.get("user_id")
        curr_roll = session.get("roll_number")
        if (sub_uid and sub_uid != curr_uid) or (not sub_uid and sub_roll != curr_roll):
            conn.close()
            flash("Access Restricted: You can only view your own examination results.", "danger")
            return redirect(url_for("student_dashboard"))
        
    cursor.execute("SELECT * FROM violations WHERE submission_id = ? ORDER BY timestamp ASC", (submission_id,))
    violations = cursor.fetchall()
    conn.close()
    
    sub_dict = dict(submission)
    raw_pct = sub_dict.get("percentage")
    raw_pass = sub_dict.get("passing_percentage")

    try:
        pct_val = float(raw_pct) if raw_pct is not None else 0.0
    except (ValueError, TypeError):
        pct_val = 0.0

    try:
        pass_val = float(raw_pass) if raw_pass is not None else 50.0
    except (ValueError, TypeError):
        pass_val = 50.0

    # Ensure display values in template are never None
    sub_dict["percentage"] = round(pct_val, 1)
    sub_dict["score"] = round(float(sub_dict.get("score") or 0.0), 1)
    sub_dict["total_points"] = round(float(sub_dict.get("total_points") or 0.0), 1)

    passed = (pct_val >= pass_val) and (sub_dict.get("status") != "terminated")
    
    # Check if tutor has published the evaluated results to the student
    is_published = bool(sub_dict.get("is_published") or sub_dict.get("results_published"))
    # Admin / Tutor can always preview full questions
    if session.get("user_role") == "admin":
        is_published = True

    questions_review = []
    if is_published:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
        raw_questions = cursor.fetchall()
        conn.close()

        student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
        manual_eval = json.loads(submission["manual_evaluation_json"]) if submission["manual_evaluation_json"] else {}

        for q in raw_questions:
            q_dict = dict(q)
            q_dict["options"] = json.loads(q["options_json"]) if q["options_json"] else []
            q_id_str = str(q["id"])
            ans_raw = student_answers.get(q_id_str)

            student_text = ""
            student_img = ""
            student_imgs = []
            if isinstance(ans_raw, dict):
                student_text = (ans_raw.get("text") or "").strip()
                student_img = (ans_raw.get("image_url") or "").strip()
                raw_list = ans_raw.get("image_urls") or []
                if isinstance(raw_list, list):
                    student_imgs = [u.strip() for u in raw_list if isinstance(u, str) and u.strip()]
                if student_img and student_img not in student_imgs:
                    student_imgs.insert(0, student_img)
                elif not student_img and student_imgs:
                    student_img = student_imgs[0]
            elif isinstance(ans_raw, str):
                student_text = ans_raw.strip()

            page_suffix = f" ({len(student_imgs)} Pages)" if len(student_imgs) > 1 else (" (1 Page)" if student_imgs else "")
            q_dict["student_answer"] = student_text if student_text else (f"Handwritten Solution{page_suffix}" if student_imgs else "Not Attempted")
            q_dict["student_image_url"] = student_img
            q_dict["student_image_urls"] = student_imgs

            correct_ans = (q["correct_answer"] or "").strip().lower()
            if correct_ans:
                q_dict["is_correct"] = (student_text.lower() == correct_ans)
            else:
                q_dict["is_correct"] = False

            eval_item = manual_eval.get(q_id_str)
            if eval_item:
                q_dict["awarded_marks"] = float(eval_item.get("awarded_marks", 0.0))
                q_dict["eval_feedback"] = eval_item.get("feedback", "")
                q_dict["eval_by"] = eval_item.get("evaluated_by", "ai")
                q_dict["is_evaluated"] = True
            else:
                default_pts = float(q["points"]) if q_dict["is_correct"] else 0.0
                q_dict["awarded_marks"] = default_pts
                q_dict["eval_feedback"] = ""
                q_dict["eval_by"] = "auto"
                q_dict["is_evaluated"] = False

            questions_review.append(q_dict)

        questions_review = attach_question_display_labels(questions_review)

    # Cryptographic Tamper Verification Check (CIA Integrity)
    expected_hash = generate_submission_integrity_hash(
        sub_dict["id"],
        sub_dict["roll_number"],
        sub_dict.get("score") or 0.0,
        sub_dict.get("total_points") or 0.0,
        sub_dict.get("warnings_count") or 0,
        sub_dict.get("status") or "submitted"
    )
    
    stored_hash = sub_dict.get("integrity_hash") or ""
    # If not previously stored (historical submission), persist current valid hash
    if not stored_hash and sub_dict.get("status") in ("submitted", "terminated"):
        try:
            conn = get_connection()
            conn.cursor().execute("UPDATE submissions SET integrity_hash = ? WHERE id = ?", (expected_hash, sub_dict["id"]))
            conn.commit()
            conn.close()
            stored_hash = expected_hash
            sub_dict["integrity_hash"] = expected_hash
        except Exception:
            stored_hash = expected_hash
            
    is_tamper_verified = bool(stored_hash and hmac.compare_digest(stored_hash, expected_hash))

    return render_template("exam_result.html", 
                           submission=sub_dict, 
                           violations=violations, 
                           passed=passed, 
                           is_published=is_published,
                           questions=questions_review,
                           integrity_hash=stored_hash or expected_hash,
                           is_tamper_verified=is_tamper_verified)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
