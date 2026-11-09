import pytest
import json
import sqlite3
import database
from app import app

@pytest.fixture
def client(monkeypatch, tmp_path):
    test_db = str(tmp_path / "test_sync.db")
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

def test_sync_events_unauthenticated(client):
    c, _ = client
    res = c.get("/api/student/sync-events")
    assert res.status_code in (302, 401, 403)

def test_sync_events_cursor_and_filtering(client):
    c, db_path = client
    student_1 = create_user(db_path, "student1", "student", "class_a")
    student_2 = create_user(db_path, "student2", "student", "class_b")

    # Insert events directly
    database.publish_student_sync_event("exam_published", target_student_id=None, target_class="", exam_id=1, payload={"title": "Universal Exam"})
    database.publish_student_sync_event("pause_approved", target_student_id=student_1, target_class="", exam_id=1, submission_id=10, payload={"status": "paused"})
    database.publish_student_sync_event("pause_approved", target_student_id=student_2, target_class="", exam_id=1, submission_id=20, payload={"status": "paused"})
    database.publish_student_sync_event("schedule_updated", target_student_id=None, target_class="class_a", exam_id=1, payload={"note": "Class A only"})

    # Student 1 logs in
    with c.session_transaction() as sess:
        sess["user_id"] = student_1
        sess["user_role"] = "student"
        sess["username"] = "student1"

    res = c.get("/api/student/sync-events?since=0")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    # Student 1 should see: Universal event, Student 1 pause event, and Class A schedule update. (NOT student 2 pause event)
    event_types = [e["event_type"] for e in data["events"]]
    assert "exam_published" in event_types
    assert "pause_approved" in event_types
    assert "schedule_updated" in event_types
    assert len(data["events"]) == 3
    cursor_val = data["cursor"]
    assert cursor_val > 0

    # Incremental query with latest cursor returns empty events
    res2 = c.get(f"/api/student/sync-events?since={cursor_val}")
    data2 = res2.get_json()
    assert data2["success"] is True
    assert len(data2["events"]) == 0

def test_publish_on_exam_deletion(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor_admin", "admin")
    student_id = create_user(db_path, "student_listener", "student")

    # Create exam
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('DEL101', 'Test Deletion', 30)")
    exam_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Admin deletes exam
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["username"] = "tutor_admin"
        sess["csrf_token"] = "valid_test_token"

    del_res = c.post(
        f"/api/admin/delete-exam/{exam_id}",
        headers={"X-CSRF-Token": "valid_test_token"}
    )
    assert del_res.status_code == 200

    # Student checks sync events
    with c.session_transaction() as sess:
        sess["user_id"] = student_id
        sess["user_role"] = "student"
        sess["username"] = "student_listener"

    sync_res = c.get("/api/student/sync-events?since=0")
    data = sync_res.get_json()
    assert data["success"] is True
    del_events = [e for e in data["events"] if e["event_type"] == "exam_deleted"]
    assert len(del_events) == 1
    assert del_events[0]["payload"]["exam_id"] == exam_id

def test_publish_on_result_toggle(client):
    c, db_path = client
    tutor_id = create_user(db_path, "tutor2", "admin")
    student_id = create_user(db_path, "student3", "student")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes, results_published) VALUES ('RES101', 'Test Results', 30, 0)")
    exam_id = cur.lastrowid
    cur.execute(
        "INSERT INTO submissions (exam_id, user_id, roll_number, student_name, status, is_published) VALUES (?, ?, 'R103', 'Student 3', 'submitted', 0)",
        (exam_id, student_id)
    )
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Tutor publishes all exam results
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_id
        sess["user_role"] = "admin"
        sess["csrf_token"] = "valid_test_token"

    res = c.post(
        f"/api/tutor/exam/{exam_id}/toggle-publish-results",
        headers={"X-CSRF-Token": "valid_test_token"}
    )
    assert res.status_code == 200

    # Student receives sync event
    with c.session_transaction() as sess:
        sess["user_id"] = student_id
        sess["user_role"] = "student"

    sync_res = c.get("/api/student/sync-events?since=0")
    events = sync_res.get_json()["events"]
    assert any(e["event_type"] == "result_published" and e["exam_id"] == exam_id for e in events)


def test_tutor_dashboard_receives_exam_deleted_sync(client):
    """
    Verify that when an exam is deleted by a tutor, another tutor session/tab
    polling /api/student/sync-events receives the exam_deleted event with the correct exam_id.
    """
    c, db_path = client
    tutor_a = create_user(db_path, "tutor_tab_a", "admin")
    tutor_b = create_user(db_path, "tutor_tab_b", "admin")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES ('SYNC99', 'Cross Tab Exam', 45)")
    exam_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Tutor Tab A deletes the exam
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_a
        sess["user_role"] = "admin"
        sess["username"] = "tutor_tab_a"
        sess["csrf_token"] = "valid_csrf_token_a"

    res = c.delete(
        f"/api/admin/delete-exam/{exam_id}",
        headers={"X-CSRF-Token": "valid_csrf_token_a"}
    )
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Confirm database deletion
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id FROM exams WHERE id = ?", (exam_id,))
    assert cur.fetchone() is None
    conn.close()

    # Tutor Tab B polls for sync events
    with c.session_transaction() as sess:
        sess["user_id"] = tutor_b
        sess["user_role"] = "admin"
        sess["username"] = "tutor_tab_b"

    sync_resp = c.get("/api/student/sync-events?since=0")
    assert sync_resp.status_code == 200
    data = sync_resp.get_json()
    assert data["success"] is True

    deleted_events = [e for e in data["events"] if e["event_type"] == "exam_deleted"]
    assert len(deleted_events) == 1
    assert deleted_events[0]["exam_id"] == exam_id
    assert deleted_events[0]["payload"]["exam_id"] == exam_id
    assert deleted_events[0]["payload"]["title"] == "Cross Tab Exam"
