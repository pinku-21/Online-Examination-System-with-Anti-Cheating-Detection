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

def test_device_switch_workflow_approval(client):
    """
    Test complete device-switch workflow:
    1. Student in active exam blocked on 2nd device.
    2. Student submits device-switch request.
    3. Pending badge count increases on tutor requests endpoint.
    4. Tutor approves device-switch request.
    5. Old device session token is invalidated.
    6. Student can now log in from new device and resume active exam with answers and remaining time.
    """
    conn = get_connection()
    c = conn.cursor()
    # Create clean test student and tutor
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99999")
    c.execute("DELETE FROM submissions WHERE user_id = 99999")
    c.execute("DELETE FROM exams WHERE id = 77777")
    c.execute("DELETE FROM users WHERE id IN (99999, 88888)")
    
    from werkzeug.security import generate_password_hash
    pwd = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99999, 'dev_student', ?, 'student', 'Device Test Student', 'ROLL-999', 'old-device-token-111')
    """, (pwd,))

    tutor_pwd = generate_password_hash("TutorPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')
    """, (tutor_pwd,))

    # Create exam and active submission
    c.execute("INSERT INTO exams (id, exam_code, title, duration_minutes) VALUES (77777, 'CODE-77777', 'Device Test Exam', 60)")
    c.execute("""
        INSERT INTO submissions (id, exam_id, user_id, student_name, roll_number, status, device_switch_approved, time_remaining_seconds, progress_answers_json)
        VALUES (66666, 77777, 99999, 'Device Test Student', 'ROLL-999', 'in_progress', 0, 1800, '{"1": "A"}')
    """)
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Step 1: Second device attempts login and receives device_switch_blocked
    res_login = client.post("/login", data={
        "identifier": "dev_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)
    assert res_login.status_code == 200
    assert "Simultaneous logins are blocked" in res_login.get_data(as_text=True)

    # Step 2: Student submits device switch request
    res_req = client.post("/api/student/request-device-switch", json={
        "identifier": "dev_student",
        "password": "StudentPass123!",
        "exam_id": 77777,
        "submission_id": 66666
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_req.status_code == 200
    data_req = res_req.get_json()
    assert data_req["success"] is True
    assert data_req["status"] == "pending"
    req_id = data_req["request_id"]

    # Step 3: Tutor inspects pending requests
    with client.session_transaction() as sess:
        sess["user_id"] = 88888
        sess["user_role"] = "admin"
        sess["username"] = "dev_tutor"

    res_tutor_list = client.get("/api/tutor/student-requests")
    assert res_tutor_list.status_code == 200
    tutor_data = res_tutor_list.get_json()
    assert tutor_data["success"] is True
    assert tutor_data["pending_count"] >= 1
    found = any(r["id"] == req_id and r["request_type"] == "device_switch" for r in tutor_data["requests"])
    assert found is True

    # Step 4: Tutor approves the request
    res_resolve = client.post(f"/api/tutor/device-switch/{req_id}/resolve", json={
        "action": "approve"
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_resolve.status_code == 200
    assert res_resolve.get_json()["status"] == "approved"

    # Step 5: Check database state: old token cleared, device_switch_approved = 1
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99999")
    u_row = c.fetchone()
    assert u_row["active_session_token"] == ""  # old device invalidated

    c.execute("SELECT device_switch_approved, status, progress_answers_json, time_remaining_seconds FROM submissions WHERE id = 66666")
    sub_row = c.fetchone()
    assert sub_row["device_switch_approved"] == 1
    assert sub_row["status"] == "in_progress"
    assert sub_row["time_remaining_seconds"] == 1800
    assert sub_row["progress_answers_json"] == '{"1": "A"}'
    conn.close()

    # Step 6: Polling from student side reflects approved
    res_poll = client.get(f"/api/student/device-switch-status/{req_id}")
    assert res_poll.status_code == 200
    poll_data = res_poll.get_json()
    assert poll_data["status"] == "approved"
    assert poll_data["device_switch_approved"] is True

    # Step 7: Student can now successfully log in from new device
    with client.session_transaction() as sess:
        sess.clear()

    csrf2 = get_auth_csrf(client)
    res_new_login = client.post("/login", data={
        "identifier": "dev_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf2
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)
    assert res_new_login.status_code == 200
    assert "Simultaneous logins are blocked" not in res_new_login.get_data(as_text=True)

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99999")
    c.execute("DELETE FROM submissions WHERE user_id = 99999")
    c.execute("DELETE FROM exams WHERE id = 77777")
    c.execute("DELETE FROM users WHERE id IN (99999, 88888)")
    conn.commit()
    conn.close()


def test_device_switch_workflow_rejection(client):
    """
    Test device-switch rejection workflow:
    1. Student submits request.
    2. Tutor rejects with reason.
    3. Old session token remains intact.
    4. Student gets rejected notification with tutor's reason.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99998")
    c.execute("DELETE FROM submissions WHERE user_id = 99998")
    c.execute("DELETE FROM exams WHERE id = 77776")
    c.execute("DELETE FROM users WHERE id IN (99998, 88888)")

    from werkzeug.security import generate_password_hash
    pwd = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99998, 'dev_student2', ?, 'student', 'Device Student 2', 'ROLL-998', 'initial-token-222')
    """, (pwd,))

    tutor_pwd = generate_password_hash("TutorPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')
    """, (tutor_pwd,))
    c.execute("INSERT INTO exams (id, exam_code, title, duration_minutes) VALUES (77776, 'CODE-77776', 'Device Test Exam 2', 60)")
    c.execute("""
        INSERT INTO submissions (id, exam_id, user_id, student_name, roll_number, status, device_switch_approved)
        VALUES (66665, 77776, 99998, 'Device Student 2', 'ROLL-998', 'in_progress', 0)
    """)
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Submit request
    res_req = client.post("/api/student/request-device-switch", json={
        "identifier": "dev_student2",
        "password": "StudentPass123!",
        "exam_id": 77776,
        "submission_id": 66665
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_req.status_code == 200
    req_id = res_req.get_json()["request_id"]

    # Tutor rejects
    with client.session_transaction() as sess:
        sess["user_id"] = 88888
        sess["user_role"] = "admin"

    res_resolve = client.post(f"/api/tutor/device-switch/{req_id}/resolve", json={
        "action": "reject",
        "reason": "Device transfer disallowed during final exam hour."
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_resolve.status_code == 200
    assert res_resolve.get_json()["status"] == "rejected"

    # Poll status
    res_poll = client.get(f"/api/student/device-switch-status/{req_id}")
    poll_data = res_poll.get_json()
    assert poll_data["status"] == "rejected"
    assert "Device transfer disallowed" in poll_data["rejection_reason"]
    assert poll_data["device_switch_approved"] is False

    # Submission remains unauthorized for device switch and original token remains
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT device_switch_approved FROM submissions WHERE id = 66665")
    assert c.fetchone()["device_switch_approved"] == 0
    c.execute("SELECT active_session_token FROM users WHERE id = 99998")
    assert c.fetchone()["active_session_token"] == "initial-token-222"
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99998")
    c.execute("DELETE FROM submissions WHERE user_id = 99998")
    c.execute("DELETE FROM exams WHERE id = 77776")
    c.execute("DELETE FROM users WHERE id IN (99998, 88888)")
    conn.commit()
    conn.close()


def test_other_request_types_continue_working(client):
    """Verify general assistance and special permission requests operate seamlessly in same system."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99997")
    c.execute("DELETE FROM users WHERE id IN (99997, 88888)")

    from werkzeug.security import generate_password_hash
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number)
        VALUES (99997, 'general_student', ?, 'student', 'General Student', 'ROLL-997')
    """, (generate_password_hash("StudentPass123!"),))

    tutor_pwd = generate_password_hash("TutorPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88888, 'dev_tutor', ?, 'admin', 'Device Test Tutor')
    """, (tutor_pwd,))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    with client.session_transaction() as sess:
        sess["user_id"] = 99997
        sess["user_role"] = "student"

    # Student submits general assistance request
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
    assert matching[0]["reason"] == "Need technical assistance with diagram render."

    # Admin approves
    res_appr = client.post(f"/api/tutor/device-switch/{req_id}/resolve", json={
        "action": "approve"
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_appr.status_code == 200

    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_requests WHERE student_id = 99997")
    c.execute("DELETE FROM users WHERE id IN (99997, 88888)")
    conn.commit()
    conn.close()
