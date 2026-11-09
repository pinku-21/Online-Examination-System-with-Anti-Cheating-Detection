import os
import json
import pytest
from app import app
from database import get_connection, init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

def get_auth_csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token")


def test_automatic_device_replacement_workflow(client):
    """
    Test new automatic device session replacement workflow:
    1. Student is logged in on Device A (has active_session_token).
    2. Student attempts login on Device B:
       - First attempt (confirm_device_switch != '1'): Prompted with confirmation dialog (prompt_device_switch=True).
       - Old session remains completely untouched on Device A.
    3. Student confirms device switch on Device B (confirm_device_switch = '1'):
       - Login succeeds.
       - A new active_session_token is generated in database.
       - Device switch history is logged.
       - Device A's session is now rejected on protected endpoints.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99999")
    c.execute("DELETE FROM submissions WHERE user_id = 99999")
    c.execute("DELETE FROM exams WHERE id = 77777")
    c.execute("DELETE FROM users WHERE id = 99999")

    from werkzeug.security import generate_password_hash
    pwd = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99999, 'dev_student', ?, 'student', 'Device Test Student', 'ROLL-999', 'old-device-token-111')
    """, (pwd,))

    # Active exam attempt in progress
    c.execute("INSERT INTO exams (id, exam_code, title, duration_minutes) VALUES (77777, 'CODE-77777', 'Device Test Exam', 60)")
    c.execute("""
        INSERT INTO submissions (id, exam_id, user_id, student_name, roll_number, status, device_switch_approved, time_remaining_seconds, progress_answers_json)
        VALUES (66666, 77777, 99999, 'Device Test Student', 'ROLL-999', 'in_progress', 0, 1800, '{"1": "A"}')
    """)
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Step 1: Login attempt without confirmation flag triggers device switch prompt
    res_first = client.post("/login", data={
        "identifier": "dev_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_first.status_code == 200
    html_first = res_first.get_data(as_text=True)
    assert "New Device Login Detected" in html_first
    assert "Live Examination Warning" in html_first or "Device Test Exam" in html_first

    # Verify old session token was NOT modified when unconfirmed
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99999")
    assert c.fetchone()["active_session_token"] == "old-device-token-111"
    conn.close()

    # Step 2: Student confirms replacement by submitting with confirm_device_switch = 1
    res_confirm = client.post("/login", data={
        "identifier": "dev_student",
        "password": "StudentPass123!",
        "role": "student",
        "confirm_device_switch": "1",
        "csrf_token": csrf
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_confirm.status_code == 200
    assert "Signed in successfully" in res_confirm.get_data(as_text=True)

    # Step 3: Check database: new active_session_token exists and is different from old token
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99999")
    new_token = c.fetchone()["active_session_token"]
    assert new_token != ""
    assert new_token != "old-device-token-111"

    # Step 4: Verify device_switch_history record
    c.execute("SELECT * FROM device_switch_history WHERE student_id = 99999 ORDER BY id DESC LIMIT 1")
    hist = c.fetchone()
    assert hist is not None
    assert hist["switch_type"] == "automatic"
    assert hist["had_active_exam"] == 1
    assert hist["exam_id"] == 77777
    assert hist["submission_id"] == 66666

    # Step 5: Verify exam answers and time remaining remain preserved
    c.execute("SELECT status, time_remaining_seconds, progress_answers_json FROM submissions WHERE id = 66666")
    sub = c.fetchone()
    assert sub["status"] == "in_progress"
    assert sub["time_remaining_seconds"] == 1800
    assert sub["progress_answers_json"] == '{"1": "A"}'
    conn.close()

    # Step 6: Old device with old_token tries to access protected endpoint -> immediately rejected
    with client.session_transaction() as sess:
        sess["user_id"] = 99999
        sess["user_role"] = "student"
        sess["session_token"] = "old-device-token-111"

    res_old_device = client.get("/student/dashboard", follow_redirects=True)
    assert res_old_device.status_code == 200
    assert "logged in from another device" in res_old_device.get_data(as_text=True)

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99999")
    c.execute("DELETE FROM submissions WHERE user_id = 99999")
    c.execute("DELETE FROM exams WHERE id = 77777")
    c.execute("DELETE FROM users WHERE id = 99999")
    conn.commit()
    conn.close()


def test_tutor_terminate_student_session(client):
    """
    Test tutor manual session termination endpoint:
    1. Student has active session.
    2. Tutor calls POST /api/admin/student/<id>/terminate-session.
    3. Student active_session_token is wiped out.
    4. Record added to device_switch_history.
    5. Student next request is immediately blocked.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99998")
    c.execute("DELETE FROM users WHERE id IN (99998, 88888)")

    from werkzeug.security import generate_password_hash
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99998, 'dev_student2', ?, 'student', 'Device Student 2', 'ROLL-998', 'active-token-998')
    """, (generate_password_hash("StudentPass123!"),))

    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')
    """, (generate_password_hash("TutorPass123!"),))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Login as admin
    with client.session_transaction() as sess:
        sess["user_id"] = 88888
        sess["user_role"] = "admin"
        sess["username"] = "dev_tutor"

    # Terminate student session
    res_term = client.post("/api/admin/student/99998/terminate-session", headers={
        "X-CSRF-Token": csrf,
        "Origin": "http://localhost"
    })
    assert res_term.status_code == 200
    assert res_term.get_json()["success"] is True

    # Database verification
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99998")
    assert c.fetchone()["active_session_token"] == ""

    c.execute("SELECT * FROM device_switch_history WHERE student_id = 99998")
    hist = c.fetchone()
    assert hist is not None
    assert hist["switch_type"] == "tutor_terminated"
    conn.close()

    # Query device switch history endpoint
    res_hist = client.get("/api/admin/device-switch-history?student_id=99998")
    assert res_hist.status_code == 200
    assert len(res_hist.get_json()["history"]) >= 1

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99998")
    c.execute("DELETE FROM users WHERE id IN (99998, 88888)")
    conn.commit()
    conn.close()


def test_tutor_terminate_all_sessions(client):
    """Test bulk session termination across all active students."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id IN (99995, 99996)")
    c.execute("DELETE FROM users WHERE id IN (99995, 99996, 88888)")

    from werkzeug.security import generate_password_hash
    pwd = generate_password_hash("Pass123!")
    c.execute("INSERT INTO users (id, username, password_hash, role, full_name, active_session_token) VALUES (99995, 's1', ?, 'student', 'S1', 'token-1')", (pwd,))
    c.execute("INSERT INTO users (id, username, password_hash, role, full_name, active_session_token) VALUES (99996, 's2', ?, 'student', 'S2', 'token-2')", (pwd,))
    c.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')", (pwd,))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    with client.session_transaction() as sess:
        sess["user_id"] = 88888
        sess["user_role"] = "admin"

    res = client.post("/api/admin/students/terminate-all-sessions", headers={
        "X-CSRF-Token": csrf,
        "Origin": "http://localhost"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["count"] >= 2

    # Check database
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id IN (99995, 99996)")
    for row in c.fetchall():
        assert row["active_session_token"] == ""
    c.execute("DELETE FROM device_switch_history WHERE student_id IN (99995, 99996)")
    c.execute("DELETE FROM users WHERE id IN (99995, 99996, 88888)")
    conn.commit()
    conn.close()


def test_general_student_requests_preserved(client):
    """Verify general student assistance requests continue operating seamlessly."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99997")
    c.execute("DELETE FROM users WHERE id IN (99997, 88888)")

    from werkzeug.security import generate_password_hash
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number)
        VALUES (99997, 'general_student', ?, 'student', 'General Student', 'ROLL-997')
    """, (generate_password_hash("StudentPass123!"),))

    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')
    """, (generate_password_hash("TutorPass123!"),))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    with client.session_transaction() as sess:
        sess["user_id"] = 99997
        sess["user_role"] = "student"

    # Submit general assistance request
    res = client.post("/api/student/submit-request", json={
        "request_type": "exam_assistance",
        "reason": "Need technical assistance with diagram render."
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res.status_code == 200
    req_id = res.get_json()["request_id"]

    # Admin checks requests
    with client.session_transaction() as sess:
        sess["user_id"] = 88888
        sess["user_role"] = "admin"

    res_list = client.get("/api/tutor/student-requests")
    assert res_list.status_code == 200
    reqs = res_list.get_json()["requests"]
    matching = [r for r in reqs if r["id"] == req_id]
    assert len(matching) == 1
    assert matching[0]["request_type"] == "exam_assistance"

    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99997")
    c.execute("DELETE FROM users WHERE id IN (99997, 88888)")
    conn.commit()
    conn.close()
