import pytest
import json
import sqlite3
import database
from app import app

@pytest.fixture
def client(monkeypatch, tmp_path):
    test_db = str(tmp_path / "test_time_ext.db")
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

def test_tutor_extend_time_success(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_timemaster", "admin")
    student_id = create_user(db_path, "student_timetraveler", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('TIME1', 'Time Trial', 30)")
    exam_id = cur.lastrowid
    # Create submission in progress with 600 seconds (10 mins) remaining
    cur.execute("""
        INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds)
        VALUES (?, ?, 'R101', 'Time Traveler', 'in_progress', 600)
    """, (exam_id, student_id))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Tutor extends time by 15 minutes
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["csrf_token"] = "valid_token"

    res = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 15, "reason": "Network latency accommodation"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    # 600 + (15 * 60) = 1500 seconds
    assert data["new_time_remaining_seconds"] == 1500
    assert data["minutes_added"] == 15

    # Check database persistence
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT time_remaining_seconds FROM submissions WHERE id = ?", (sub_id,))
    assert cur.fetchone()[0] == 1500

    # Check audit log in exam_time_extensions
    cur.execute("SELECT minutes_added, previous_deadline_seconds, new_deadline_seconds, reason FROM exam_time_extensions WHERE submission_id = ?", (sub_id,))
    ext_row = cur.fetchone()
    assert ext_row is not None
    assert ext_row[0] == 15
    assert ext_row[1] == 600
    assert ext_row[2] == 1500
    assert ext_row[3] == "Network latency accommodation"

    # Check sync event dispatched
    cur.execute("SELECT event_type, payload_json FROM student_sync_events WHERE submission_id = ?", (sub_id,))
    ev_row = cur.fetchone()
    assert ev_row is not None
    assert ev_row[0] == "exam_time_extended"
    payload = json.loads(ev_row[1])
    assert payload["minutes_added"] == 15
    assert payload["new_time_remaining_seconds"] == 1500
    conn.close()

def test_cumulative_extensions(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_cumulative", "admin")
    student_id = create_user(db_path, "student_cumulative", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('CUMU1', 'Cumulative Exam', 30)")
    exam_id = cur.lastrowid
    cur.execute("""
        INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds)
        VALUES (?, ?, 'R102', 'Cumulative Student', 'in_progress', 300)
    """, (exam_id, student_id))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["csrf_token"] = "valid_token"

    # Add +20 mins: 300 + 1200 = 1500
    r1 = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 20}
    )
    assert r1.status_code == 200
    assert r1.get_json()["new_time_remaining_seconds"] == 1500

    # Add +10 mins: 1500 + 600 = 2100
    r2 = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 10}
    )
    assert r2.status_code == 200
    assert r2.get_json()["new_time_remaining_seconds"] == 2100

def test_student_cannot_extend_time(client):
    c, db_path = client
    student_id = create_user(db_path, "sneaky_student", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('SNK1', 'Sneak Test', 30)")
    exam_id = cur.lastrowid
    cur.execute("""
        INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds)
        VALUES (?, ?, 'R103', 'Sneaky Student', 'in_progress', 100)
    """, (exam_id, student_id))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    with c.session_transaction() as sess:
        sess["user_id"] = student_id
        sess["user_role"] = "student"
        sess["csrf_token"] = "valid_token"

    res = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 30}
    )
    assert res.status_code == 403

def test_cannot_extend_completed_or_terminated_exam(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_guard", "admin")
    student_id = create_user(db_path, "student_finished", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('DONE1', 'Finished Test', 30)")
    exam_id = cur.lastrowid
    cur.execute("""
        INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, time_remaining_seconds)
        VALUES (?, ?, 'R104', 'Finished Student', 'submitted', 0)
    """, (exam_id, student_id))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["csrf_token"] = "valid_token"

    res = c.post(
        f"/api/tutor/submission/{sub_id}/extend-time",
        headers={"X-CSRF-Token": "valid_token"},
        json={"minutes": 15}
    )
    assert res.status_code == 400
    assert "Cannot extend time" in res.get_json()["error"]
