import pytest
import json
import sqlite3
import database
from app import app

@pytest.fixture
def client(monkeypatch, tmp_path):
    test_db = str(tmp_path / "test_cockpit.db")
    monkeypatch.setattr(database, "DB_PATH", test_db)
    database.init_db()

    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, test_db

def create_user(db_path, username, role="student", class_name=""):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password_hash, full_name, role, class_name) VALUES (?, 'hash', ?, ?, ?)",
        (username, username.title(), role, class_name)
    )
    uid = c.lastrowid
    conn.commit()
    conn.close()
    return uid

def test_subject_column_in_exams_and_save(client):
    c, db_path = client
    tutor_id = create_user(db_path, "admin_tutor", "admin")

    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["username"] = "admin_tutor"
        sess["csrf_token"] = "valid_token"

    payload = {
        "title": "Mathematics Final Exam",
        "subject": "Mathematics",
        "description": "Calculus and Algebra",
        "duration_minutes": 45,
        "max_warnings": 5,
        "passing_percentage": 50,
        "questions": [
            {
                "question_text": "What is 2 + 2?",
                "question_type": "mcq",
                "options": ["3", "4", "5", "6"],
                "correct_answer": "4",
                "points": 1
            }
        ]
    }
    res = c.post("/api/save-exam", headers={"X-CSRF-Token": "valid_token"}, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Check database persistence
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT title, subject FROM exams WHERE id = ?", (data["exam_id"],))
    row = cur.fetchone()
    conn.close()
    assert row[0] == "Mathematics Final Exam"
    assert row[1] == "Mathematics"

def test_time_extension_does_not_create_violation_strike(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_ext", "admin")
    student_id = create_user(db_path, "candidate_ext", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes, subject) VALUES ('EXT1', 'Physics', 30, 'Physics')")
    exam_id = cur.lastrowid
    cur.execute(
        "INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds, warnings_count) VALUES (?, ?, 'R101', 'Candidate Ext', 'in_progress', 600, 0)",
        (exam_id, student_id)
    )
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["username"] = "tutor_ext"
        sess["csrf_token"] = "valid_token"

    # Extend time by 10 minutes (600s)
    res = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 10, "reason": "Network lag"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["new_time_remaining_seconds"] == 1200

    # Verify that NO row was inserted into violations table
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM violations WHERE submission_id = ?", (sub_id,))
    v_count = cur.fetchone()[0]
    # Check submissions table warnings_count
    cur.execute("SELECT warnings_count, time_remaining_seconds FROM submissions WHERE id = ?", (sub_id,))
    sub_row = cur.fetchone()
    conn.close()

    assert v_count == 0, f"Expected 0 violation strikes for time extension, got {v_count}"
    assert sub_row[0] == 0, f"Warnings count must remain 0, got {sub_row[0]}"
    assert sub_row[1] == 1200

def test_live_active_candidates_api(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_live", "admin")
    student_1 = create_user(db_path, "candidate_live_1", "student")
    student_2 = create_user(db_path, "candidate_live_2", "student")
    student_3 = create_user(db_path, "candidate_done", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes, subject) VALUES ('LV1', 'Chemistry', 40, 'Chemistry')")
    exam_id = cur.lastrowid
    # Candidate 1: in_progress
    cur.execute("INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds) VALUES (?, ?, 'R201', 'Cand 1', 'in_progress', 1800)", (exam_id, student_1))
    # Candidate 2: paused
    cur.execute("INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds) VALUES (?, ?, 'R202', 'Cand 2', 'paused', 900)", (exam_id, student_2))
    # Candidate 3: completed/submitted (should NOT show in live active)
    cur.execute("INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds) VALUES (?, ?, 'R203', 'Cand 3', 'completed', 0)", (exam_id, student_3))
    conn.commit()
    conn.close()

    # Unauthenticated request should fail
    unauth_res = c.get("/api/tutor/live-active-candidates")
    assert unauth_res.status_code in (302, 401, 403)

    # Admin request
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["username"] = "tutor_live"

    res = c.get("/api/tutor/live-active-candidates")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total_active"] == 2
    assert data["ongoing_count"] == 1
    assert data["paused_count"] == 1
    c_names = [cand["student_name"] for cand in data["candidates"]]
    assert "Cand 1" in c_names
    assert "Cand 2" in c_names
    assert "Cand 3" not in c_names

def test_request_resume_from_paused_state(client):
    c, db_path = client
    student_id = create_user(db_path, "candidate_paused", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('PZ1', 'Biology', 30)")
    exam_id = cur.lastrowid
    cur.execute("INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status) VALUES (?, ?, 'R301', 'Cand Paused', 'paused')", (exam_id, student_id))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    with c.session_transaction() as sess:
        sess["user_id"] = student_id
        sess["user_role"] = "student"
        sess["username"] = "candidate_paused"
        sess["csrf_token"] = "valid_token"

    # POST /api/submission/<id>/request-pause should successfully transition status to 'pause_requested'
    res = c.post(
        f"/api/submission/{sub_id}/request-pause",
        headers={"X-CSRF-Token": "valid_token"},
        json={"reason": "Candidate requesting proctor approval to resume"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT status FROM submissions WHERE id = ?", (sub_id,))
    status = cur.fetchone()[0]
    conn.close()
    assert status == "pause_requested"
