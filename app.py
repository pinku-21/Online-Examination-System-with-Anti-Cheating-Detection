import os
import json
import random
import string
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename

from database import (
    init_db, 
    get_connection, 
    get_setting, 
    set_setting,
    create_user,
    authenticate_user,
    get_user_by_id,
    get_student_submissions
)
from ai_service import (
    extract_text_from_pdf, 
    extract_figures_from_pdf,
    generate_questions_with_gemini, 
    generate_questions_with_groq,
    generate_questions_unified,
    generate_mock_questions,
    evaluate_answer_with_ai
)

IST = timezone(timedelta(hours=5, minutes=30))

def get_current_time():
    """Returns the current datetime in IST (Indian Standard Time, UTC+5:30) naive representation for comparison."""
    return datetime.now(IST).replace(tzinfo=None)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "examguard-super-secret-key-2026")

@app.template_filter('format_datetime_12h')
def format_datetime_12h_filter(val):
    if not val:
        return '—'
    try:
        if isinstance(val, datetime):
            return val.strftime("%b %d, %Y, %I:%M %p")
        val_str = str(val).strip()
        # Handle SQLite CURRENT_TIMESTAMP (YYYY-MM-DD HH:MM:SS) or ISO (YYYY-MM-DDTHH:MM)
        clean = val_str.replace('T', ' ')
        if '.' in clean:
            clean = clean.split('.')[0]
        if len(clean) == 16:
            dt = datetime.strptime(clean, "%Y-%m-%d %H:%M")
        elif len(clean) >= 19:
            dt = datetime.strptime(clean[:19], "%Y-%m-%d %H:%M:%S")
        else:
            return val_str
        return dt.strftime("%b %d, %Y, %I:%M %p")
    except Exception:
        return str(val)

@app.template_filter('format_date')
def format_date_filter(val):
    if not val:
        return '—'
    try:
        if isinstance(val, datetime):
            return val.strftime("%Y-%m-%d")
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
        if isinstance(val, datetime):
            return val.strftime("%I:%M %p")
        val_str = str(val).strip().replace('T', ' ')
        if '.' in val_str:
            val_str = val_str.split('.')[0]
        if len(val_str) == 16:
            dt = datetime.strptime(val_str, "%Y-%m-%d %H:%M")
        elif len(val_str) >= 19:
            dt = datetime.strptime(val_str[:19], "%Y-%m-%d %H:%M:%S")
        else:
            return val_str
        return dt.strftime("%I:%M %p")
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
        if not session.get("user_id"):
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
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

        if not full_name or not roll_number or not username or not password:
            flash("Full Name, Roll Number, Username, and Password are all required.", "danger")
            return render_template("register.html")

        if len(password) < 4:
            flash("Password must be at least 4 characters long.", "danger")
            return render_template("register.html")

        res = create_user(username, email, password, full_name, role="student", roll_number=roll_number, class_name=class_name)
        if res.get("success"):
            # Sign in the new student automatically
            session.clear()
            session["user_id"] = res["user_id"]
            session["username"] = res["username"]
            session["user_name"] = res["full_name"]
            session["user_role"] = "student"
            session["roll_number"] = res["roll_number"]
            session["class_name"] = res.get("class_name", "")
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
    """Admin creates a new student account with preset credentials."""
    data = request.get_json() or {}
    full_name = data.get("full_name", "").strip()
    roll_number = data.get("roll_number", "").strip().upper()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()
    email = data.get("email", "").strip().lower() or None
    class_name = data.get("class_name", "").strip()

    if not full_name or not roll_number or not username or not password:
        return jsonify({"success": False, "error": "Full Name, Roll Number, Username, and Password are all required."})
    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters."})

    res = create_user(username, email, password, full_name, role="student", roll_number=roll_number, class_name=class_name)
    if res.get("success"):
        return jsonify({"success": True, "message": f"Student account created for {full_name} ({username}).", "student": {
            "id": res["user_id"], "full_name": full_name, "username": username, "roll_number": roll_number, "class_name": class_name
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


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))

# --- HOME & GENERAL ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

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
    public_url = get_setting("public_url", "")
    has_api_key = bool((gemini_key and len(gemini_key.strip()) > 10) or (groq_key and len(groq_key.strip()) > 10))
    
    conn2 = get_connection()
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT id, full_name, username, roll_number, email, class_name, created_at FROM users WHERE role = 'student' ORDER BY created_at DESC")
    students = [dict(r) for r in cursor2.fetchall()]
    distinct_classes = sorted(list(set(s['class_name'] for s in students if s.get('class_name'))))
    conn2.close()

    return render_template(
        "tutor_dashboard.html", 
        exams=exams,
        students=students,
        classes=distinct_classes,
        has_api_key=has_api_key,
        has_gemini_key=bool(gemini_key and len(gemini_key.strip()) > 10),
        has_groq_key=bool(groq_key and len(groq_key.strip()) > 10),
        gemini_key_mask=(gemini_key[:4] + "..." + gemini_key[-4:]) if len(gemini_key) > 8 else "",
        groq_key_mask=(groq_key[:4] + "..." + groq_key[-4:]) if len(groq_key) > 8 else "",
        public_url=public_url
    )

@app.route("/tutor/settings", methods=["GET", "POST"])
@admin_required
def tutor_save_settings():
    gemini_key = request.form.get("gemini_api_key", "").strip()
    groq_key = request.form.get("groq_api_key", "").strip()
    public_url = request.form.get("public_url", "").strip().rstrip("/")
    
    if gemini_key:
        set_setting("gemini_api_key", gemini_key)
    if groq_key:
        set_setting("groq_api_key", groq_key)
    if public_url is not None:
        set_setting("public_url", public_url)
        
    flash("Settings updated successfully!", "success")
    return redirect(url_for("tutor_dashboard"))

@app.route("/api/tutor/set-public-url", methods=["POST"])
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
    has_api_key = bool((gemini_key and len(gemini_key.strip()) > 10) or (groq_key and len(groq_key.strip()) > 10))
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_name, username, roll_number, class_name FROM users WHERE role = 'student' ORDER BY full_name ASC")
    students = [dict(r) for r in cursor.fetchall()]
    distinct_classes = sorted(list(set(s['class_name'] for s in students if s.get('class_name'))))
    conn.close()
    
    return render_template("create_exam.html", has_api_key=has_api_key, students=students, classes=distinct_classes)

@app.route("/api/generate-questions", methods=["POST"])
def api_generate_questions():
    """
    Handles PDF upload, image uploads, and prompt text.
    Calls Gemini API or Groq API (or mock generator if requested/no key).
    """
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
    
    # If user selected mock or no API keys provided
    if use_mock or (not gemini_key and not groq_key):
        result = generate_mock_questions(combined_text, num_questions=num_questions, question_type=question_type, total_marks=total_marks)
        result["extracted_figures"] = extracted_figures
        return jsonify(result)

    # Call unified multi-model AI pipeline (Gemini with Vision -> Groq fallback)
    result = generate_questions_unified(
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
    result["extracted_figures"] = extracted_figures
    
    return jsonify(result)

@app.route("/api/upload-figure", methods=["POST"])
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
    
    save_path = os.path.join(figures_dir, unique_name)
    file.save(save_path)
    
    return jsonify({"success": True, "figure_url": f"/static/question_figures/{unique_name}"})

@app.route("/api/submission/<int:submission_id>/upload-answer-image", methods=["POST"])
def api_upload_answer_image(submission_id):
    """Allows student to upload handwritten answer photo/diagram for subjective questions."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    conn.close()
    
    if not submission or submission["status"] != "in_progress":
        return jsonify({"success": False, "error": "Exam session is not currently active."}), 400
        
    uploaded_file = request.files.get("answer_image") or request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"success": False, "error": "No image file provided."}), 400
        
    filename = secure_filename(uploaded_file.filename)
    _, ext = os.path.splitext(filename)
    if ext.lower() not in [".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic"]:
        return jsonify({"success": False, "error": "Only image formats (JPG, PNG, WEBP, GIF) are supported."}), 400
        
    q_id = request.form.get("question_id", "0")
    unique_name = f"ans_{submission_id}_q{q_id}_{int(datetime.now().timestamp())}_{filename}"
    upload_dir = os.path.join(os.path.dirname(__file__), "static", "student_answers")
    os.makedirs(upload_dir, exist_ok=True)
    
    save_path = os.path.join(upload_dir, unique_name)
    uploaded_file.save(save_path)
    
    return jsonify({
        "success": True, 
        "image_url": f"/static/student_answers/{unique_name}"
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

    # Extract student's response
    student_answers = json.loads(submission["answers_json"]) if submission["answers_json"] else {}
    ans_raw = student_answers.get(question_id)
    student_text = ""
    student_img_url = ""
    if isinstance(ans_raw, dict):
        student_text = (ans_raw.get("text") or "").strip()
        student_img_url = (ans_raw.get("image_url") or "").strip()
    elif isinstance(ans_raw, str):
        student_text = ans_raw.strip()

    if not student_text and not student_img_url:
        conn.close()
        return jsonify({"success": False, "error": "Student did not submit text or photo for this question."}), 400

    # Resolve local file path for image if present
    abs_img_path = None
    if student_img_url:
        # e.g. /static/student_answers/xxx.jpg
        clean_rel = student_img_url.lstrip("/").replace("/", os.sep)
        local_candidate = os.path.join(os.path.dirname(__file__), clean_rel)
        if os.path.exists(local_candidate):
            abs_img_path = local_candidate

    gemini_key = get_setting("gemini_api_key", "").strip()
    groq_key = get_setting("groq_api_key", "").strip()

    eval_result = evaluate_answer_with_ai(
        gemini_key=gemini_key,
        groq_key=groq_key,
        question_text=question["question_text"],
        max_points=question["points"],
        correct_answer=question["correct_answer"] or "",
        student_text=student_text,
        image_path=abs_img_path,
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

    # Recalculate total score
    cursor.execute("SELECT * FROM questions WHERE exam_id = ?", (submission["exam_id"],))
    all_questions = cursor.fetchall()

    new_total_score = 0.0
    total_exam_points = 0.0
    for q in all_questions:
        q_pts = float(q["points"])
        total_exam_points += q_pts
        qid_s = str(q["id"])

        if qid_s in existing_eval:
            new_total_score += float(existing_eval[qid_s]["awarded_marks"])
        else:
            # Default objective grading
            q_ans_raw = student_answers.get(qid_s, "")
            if isinstance(q_ans_raw, dict):
                st_txt = (q_ans_raw.get("text") or "").strip()
            else:
                st_txt = str(q_ans_raw).strip() if q_ans_raw else ""
            if q["correct_answer"] and st_txt.lower() == q["correct_answer"].strip().lower():
                new_total_score += q_pts

    percentage = (new_total_score / total_exam_points * 100) if total_exam_points > 0 else 0.0

    cursor.execute("""
        UPDATE submissions
        SET manual_evaluation_json = ?, score = ?, total_points = ?, percentage = ?
        WHERE id = ?
    """, (json.dumps(existing_eval), round(new_total_score, 1), total_exam_points, round(percentage, 1), submission_id))

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

    # Recalculate total score
    cursor.execute("SELECT * FROM questions WHERE exam_id = ?", (submission["exam_id"],))
    all_questions = cursor.fetchall()

    new_total_score = 0.0
    total_exam_points = 0.0
    for q in all_questions:
        q_pts = float(q["points"])
        total_exam_points += q_pts
        qid_s = str(q["id"])

        if qid_s in existing_eval:
            new_total_score += float(existing_eval[qid_s]["awarded_marks"])
        else:
            q_ans_raw = student_answers.get(qid_s, "")
            if isinstance(q_ans_raw, dict):
                st_txt = (q_ans_raw.get("text") or "").strip()
            else:
                st_txt = str(q_ans_raw).strip() if q_ans_raw else ""
            if q["correct_answer"] and st_txt.lower() == q["correct_answer"].strip().lower():
                new_total_score += q_pts

    percentage = (new_total_score / total_exam_points * 100) if total_exam_points > 0 else 0.0

    cursor.execute("""
        UPDATE submissions
        SET manual_evaluation_json = ?, score = ?, total_points = ?, percentage = ?
        WHERE id = ?
    """, (json.dumps(existing_eval), round(new_total_score, 1), total_exam_points, round(percentage, 1), submission_id))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "awarded_marks": new_marks,
        "new_score": round(new_total_score, 1),
        "total_points": total_exam_points,
        "percentage": round(percentage, 1)
    })

@app.route("/api/save-exam", methods=["POST"])
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
    exam_code = generate_exam_code()
    
    # Access and schedule options
    access_type = data.get("access_type", "all")  # "all", "class", "selected"
    assigned_class = data.get("assigned_class", "").strip()
    assigned_students = data.get("assigned_students", [])  # list of student user_ids
    schedule_type = data.get("schedule_type", "anytime")  # "anytime", "scheduled"
    start_time = data.get("start_time", "").strip() or None
    end_time = data.get("end_time", "").strip() or None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO exams (exam_code, title, description, duration_minutes, max_warnings, passing_percentage, enable_audio_detection, access_type, assigned_class, schedule_type, start_time, end_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (exam_code, title, description, duration, max_warnings, passing_percentage, enable_audio, access_type, assigned_class, schedule_type, start_time, end_time))
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

@app.route("/api/tutor/exam/<int:exam_id>/access-schedule", methods=["GET", "POST"])
@admin_required
def api_exam_access_schedule(exam_id):
    conn = get_connection()
    cursor = conn.cursor()
    if request.method == "GET":
        cursor.execute("SELECT id, title, access_type, assigned_class, schedule_type, start_time, end_time, duration_minutes FROM exams WHERE id = ?", (exam_id,))
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
                "duration_minutes": dur_val
            },
            "access_type": ex_dict.get("access_type") or "all",
            "assigned_class": ex_dict.get("assigned_class") or "",
            "schedule_type": ex_dict.get("schedule_type") or "anytime",
            "start_time": st_val,
            "end_time": et_val,
            "duration_minutes": dur_val,
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
        SELECT s.*, e.title as exam_title, e.max_warnings, e.passing_percentage
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
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
        if isinstance(ans_raw, dict):
            student_text = (ans_raw.get("text") or "").strip()
            student_img = (ans_raw.get("image_url") or "").strip()
        elif isinstance(ans_raw, str):
            student_text = ans_raw.strip()
            
        q_dict["student_answer"] = student_text if student_text else ("(Handwritten Solution Photo Attached)" if student_img else "Not Attempted")
        q_dict["student_image_url"] = student_img
        
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
        
    conn.close()
    return render_template("submission_details.html", submission=submission, violations=violations, questions=questions_review)

@app.route("/api/tutor/submission/<int:submission_id>/grant-reattempt", methods=["POST"])
@admin_required
def api_grant_reattempt(submission_id):
    """
    Admin grants a student a fresh re-attempt by deleting the existing submission
    (and all linked violations). The student can then start the exam again from scratch.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Verify submission exists and fetch info for response
    cursor.execute("""
        SELECT s.id, s.student_name, s.roll_number, s.exam_id, s.status,
               e.title as exam_title
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (submission_id,))
    submission = cursor.fetchone()

    if not submission:
        conn.close()
        return jsonify({"success": False, "error": "Submission not found."}), 404

    # Delete violations first (foreign key constraint), then the submission
    cursor.execute("DELETE FROM violations WHERE submission_id = ?", (submission_id,))
    cursor.execute("DELETE FROM submissions WHERE id = ?", (submission_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Re-attempt granted for {submission['student_name']}. Their previous submission has been cleared.",
        "student_name": submission["student_name"],
        "exam_title": submission["exam_title"],
        "exam_id": submission["exam_id"]
    })


@app.route("/student/dashboard")
@login_required
def student_dashboard():
    user_id = session.get("user_id")
    roll_number = session.get("roll_number")
    conn = get_connection()
    cursor = conn.cursor()

    # Get student profile
    cursor.execute("SELECT class_name FROM users WHERE id = ?", (user_id,))
    u_row = cursor.fetchone()
    user_class = (u_row["class_name"] or "").strip().lower() if u_row else ""

    # Fetch all active exams
    cursor.execute("""
        SELECT e.*,
               (SELECT COUNT(*) FROM questions WHERE exam_id = e.id) as question_count,
               (SELECT id FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status != 'in_progress' LIMIT 1) as completed_sub_id,
               (SELECT score FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status != 'in_progress' LIMIT 1) as completed_score,
               (SELECT percentage FROM submissions WHERE exam_id = e.id AND (user_id = ? OR roll_number = ?) AND status != 'in_progress' LIMIT 1) as completed_pct
        FROM exams e
        WHERE e.is_active = 1
        ORDER BY e.created_at DESC
    """, (user_id, roll_number, user_id, roll_number, user_id, roll_number))
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

    # Create new in_progress submission linked to student user_id
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
        SELECT s.*, e.title, e.duration_minutes, e.max_warnings, e.exam_code, e.enable_audio_detection,
               e.schedule_type, e.start_time, e.end_time
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
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
        
    cursor.execute("SELECT id, question_text, question_type, options_json, points, figure_svg, figure_url FROM questions WHERE exam_id = ? ORDER BY id ASC", (submission["exam_id"],))
    raw_questions = cursor.fetchall()
    conn.close()
    
    questions = []
    for q in raw_questions:
        q_dict = dict(q)
        q_dict["options"] = json.loads(q["options_json"]) if q["options_json"] else []
        questions.append(q_dict)
        
    return render_template("student_exam.html", submission=submission, questions=questions)

@app.route("/api/submission/<int:submission_id>/violation", methods=["POST"])
def api_log_violation(submission_id):
    """
    Called by anti-cheating JS engine when a violation occurs:
    e.g. tab_switch, blur, fullscreen_exit, devtools, copy_paste.
    Increments warning counter. If warnings >= max_warnings, terminates exam immediately.
    """
    data = request.get_json() or {}
    violation_type = data.get("type", "unknown")
    details = data.get("details", "")
    
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
        
    # Insert violation log
    cursor.execute("""
        INSERT INTO violations (submission_id, violation_type, details)
        VALUES (?, ?, ?)
    """, (submission_id, violation_type, details))
    
    new_warnings = submission["warnings_count"] + 1
    max_allowed = submission["max_warnings"]
    
    is_terminated = False
    termination_reason = None
    
    if new_warnings >= max_allowed:
        is_terminated = True
        termination_reason = f"Exceeded maximum allowed anti-cheating warnings ({new_warnings}/{max_allowed} strikes). Violation: {violation_type.replace('_', ' ').title()}"
        cursor.execute("""
            UPDATE submissions 
            SET warnings_count = ?, status = 'terminated', termination_reason = ?, submitted_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_warnings, termination_reason, submission_id))
    else:
        cursor.execute("UPDATE submissions SET warnings_count = ? WHERE id = ?", (new_warnings, submission_id))
        
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
def api_submit_exam(submission_id):
    """Calculates final score and records completion."""
    data = request.get_json() or {}
    answers = data.get("answers", {})  # {str(question_id): selected_answer}
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,))
    submission = cursor.fetchone()
    
    if not submission or submission["status"] not in ["in_progress"]:
        conn.close()
        return jsonify({"success": False, "error": "Submission is already finalized."})
        
    cursor.execute("SELECT * FROM questions WHERE exam_id = ?", (submission["exam_id"],))
    questions = cursor.fetchall()
    
    total_score = 0.0
    total_points = 0.0
    
    for q in questions:
        points = float(q["points"])
        total_points += points
        q_id_str = str(q["id"])
        ans_val = answers.get(q_id_str, "")
        if isinstance(ans_val, dict):
            student_ans = (ans_val.get("text") or "").strip()
        else:
            student_ans = str(ans_val).strip() if ans_val else ""
            
        if q["correct_answer"] and student_ans.lower() == q["correct_answer"].strip().lower():
            total_score += points
            
    percentage = (total_score / total_points * 100) if total_points > 0 else 0.0
    
    cursor.execute("""
        UPDATE submissions 
        SET answers_json = ?, score = ?, total_points = ?, percentage = ?, status = 'submitted', submitted_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (json.dumps(answers), total_score, total_points, round(percentage, 1), submission_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "submission_id": submission_id})

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
    
    passed = (submission["percentage"] >= submission["passing_percentage"]) and (submission["status"] != "terminated")
    
    return render_template("exam_result.html", submission=submission, violations=violations, passed=passed)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
