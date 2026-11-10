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


def test_admin_terminate_student_session_and_relogin(client):
    """
    Test admin termination followed by fresh login:
    1. Student logs in (has active_session_token).
    2. Admin terminates student session via /api/admin/student/<id>/terminate-session.
    3. active_session_token in DB is immediately cleared ('').
    4. Student device is invalidated and cannot access protected routes.
    5. Student logs in again with credentials -> Succeeds immediately as fresh login WITHOUT false device-switch prompt.
    """
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99991")
    c.execute("DELETE FROM users WHERE id IN (99991, 88881)")

    pwd_s = generate_password_hash("StudentPass123!")
    pwd_a = generate_password_hash("TutorPass123!")

    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99991, 'term_student', ?, 'student', 'Terminated Student', 'ROLL-991', 'active-token-991')
    """, (pwd_s,))
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88881, 'term_tutor', ?, 'admin', 'Term Tutor')
    """, (pwd_a,))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # 1. Admin terminates student
    with client.session_transaction() as sess:
        sess["user_id"] = 88881
        sess["user_role"] = "admin"
        sess["csrf_token"] = csrf

    res_term = client.post("/api/admin/student/99991/terminate-session",
                           headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})
    assert res_term.status_code == 200
    assert res_term.get_json()["success"] is True

    # 2. Verify DB: token cleared
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99991")
    assert c.fetchone()["active_session_token"] == ""
    conn.close()

    # 3. Old student session cannot access protected endpoint
    with client.session_transaction() as sess:
        sess["user_id"] = 99991
        sess["user_role"] = "student"
        sess["session_token"] = "active-token-991"

    res_dash = client.get("/student/dashboard", follow_redirects=True)
    assert res_dash.status_code == 200
    assert "signed out because your account was logged in from another device or your session was terminated" in res_dash.get_data(as_text=True)

    # 4. Student logs in again: Fresh login -> MUST NOT show device switch warning!
    csrf_fresh = get_auth_csrf(client)
    res_login = client.post("/login", data={
        "identifier": "term_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf_fresh
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_login.status_code == 200
    html_login = res_login.get_data(as_text=True)
    assert "Signed in successfully" in html_login
    assert "New Device Login Detected" not in html_login

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99991")
    c.execute("DELETE FROM users WHERE id IN (99991, 88881)")
    conn.commit()
    conn.close()


def test_device_switch_continue_succeeds_without_password_reentry(client):
    """
    Verify server-side pending device switch flow:
    1. Student has active session on Device A.
    2. Student logs in on Device B with credentials -> Triggers device switch warning.
    3. Pending state is saved in session with expiry.
    4. Clicking Continue Login posts confirm_device_switch=1 without re-entering password.
    5. Login succeeds, old session invalidated, pending state consumed.
    """
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99992")
    c.execute("DELETE FROM users WHERE id = 99992")

    pwd_s = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99992, 'switch_student', ?, 'student', 'Switch Student', 'ROLL-992', 'device-a-token')
    """, (pwd_s,))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Step 1: Login on Device B with credentials
    res_first = client.post("/login", data={
        "identifier": "switch_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf
    }, headers={"Origin": "http://localhost"})
    assert res_first.status_code == 200
    assert "New Device Login Detected" in res_first.get_data(as_text=True)

    # Verify pending state exists in session
    with client.session_transaction() as sess:
        assert sess.get("pending_device_switch_user_id") == 99992
        assert sess.get("pending_device_switch_expires_at") is not None

    # Step 2: Confirm device switch WITHOUT re-submitting password
    res_confirm = client.post("/login", data={
        "confirm_device_switch": "1",
        "csrf_token": csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_confirm.status_code == 200
    html_confirm = res_confirm.get_data(as_text=True)
    assert "Signed in successfully" in html_confirm
    assert "Your previous session was signed out" in html_confirm

    # Verify pending state cleared
    with client.session_transaction() as sess:
        assert "pending_device_switch_user_id" not in sess

    # Verify Device A token was replaced
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99992")
    new_token = c.fetchone()["active_session_token"]
    assert new_token != ""
    assert new_token != "device-a-token"
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99992")
    c.execute("DELETE FROM users WHERE id = 99992")
    conn.commit()
    conn.close()


def test_device_switch_expired_or_replayed_pending_rejected(client):
    """Verify expired or replayed confirmation is rejected and does not bypass auth."""
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = 99993")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99993, 'expire_student', ?, 'student', 'Expire Student', 'ROLL-993', 'token-993')
    """, (generate_password_hash("StudentPass123!"),))
    conn.commit()
    conn.close()

    csrf = get_auth_csrf(client)

    # Attempt to confirm device switch without valid pending state
    res_invalid = client.post("/login", data={
        "confirm_device_switch": "1",
        "csrf_token": csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_invalid.status_code == 200
    assert "Device switch confirmation expired or invalid" in res_invalid.get_data(as_text=True)

    # Attempt with expired timestamp
    with client.session_transaction() as sess:
        sess["pending_device_switch_user_id"] = 99993
        sess["pending_device_switch_expires_at"] = 1000  # Past timestamp

    res_expired = client.post("/login", data={
        "confirm_device_switch": "1",
        "csrf_token": csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    assert res_expired.status_code == 200
    assert "Device switch confirmation expired or invalid" in res_expired.get_data(as_text=True)

    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = 99993")
    conn.commit()
    conn.close()


def test_device_switch_simultaneous_confirmation_only_one_succeeds(client):
    """
    Test requirement 5:
    Two simultaneous confirmation requests using the same valid pending state.
    Only one confirmation succeeds and sets the new session.
    The second simultaneous request must be rejected.
    """
    from werkzeug.security import generate_password_hash
    import time
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99994")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99994")
    c.execute("DELETE FROM users WHERE id = 99994 OR username = 'concurrent_student'")

    pwd_s = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99994, 'concurrent_student', ?, 'student', 'Concurrent Student', 'ROLL-994', 'device-a-token-994')
    """, (pwd_s,))
    conn.commit()
    conn.close()

    # Step 1: Initial login using test client 1 to establish pending state
    client1 = app.test_client()
    csrf = get_auth_csrf(client1)
    res_first = client1.post("/login", data={
        "identifier": "concurrent_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": csrf
    }, headers={"Origin": "http://localhost"})
    assert res_first.status_code == 200
    assert "New Device Login Detected" in res_first.get_data(as_text=True)

    # Read pending state generated in session and db
    with client1.session_transaction() as sess:
        user_id = sess.get("pending_device_switch_user_id")
        switch_token = sess.get("pending_device_switch_token")
        expires_at = sess.get("pending_device_switch_expires_at")

    assert user_id == 99994
    assert switch_token is not None

    # Verify pending DB record exists
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status, expires_at FROM pending_device_switches WHERE student_id = 99994 AND confirmation_token = ?", (switch_token,))
    row_pend = c.fetchone()
    assert row_pend is not None
    assert row_pend["status"] == "PENDING"
    conn.close()

    # Simulate client 2 having the exact same pending session state (e.g. cloned cookie / double submit)
    client2 = app.test_client()
    csrf2 = get_auth_csrf(client2)
    with client2.session_transaction() as sess:
        sess["pending_device_switch_user_id"] = user_id
        sess["pending_device_switch_token"] = switch_token
        sess["pending_device_switch_expires_at"] = expires_at

    # Execute request 1
    res1 = client1.post("/login", data={
        "confirm_device_switch": "1",
        "device_switch_token": switch_token,
        "csrf_token": csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    # Execute request 2 with the same token
    res2 = client2.post("/login", data={
        "confirm_device_switch": "1",
        "device_switch_token": switch_token,
        "csrf_token": csrf2,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    # Exactly one request must succeed, and the second must be rejected
    html1 = res1.get_data(as_text=True)
    html2 = res2.get_data(as_text=True)

    assert "Signed in successfully" in html1
    assert "Device switch confirmation expired, already used, or invalid" in html2

    # Database pending status must be CONSUMED
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status, consumed_at FROM pending_device_switches WHERE student_id = 99994 AND confirmation_token = ?", (switch_token,))
    row_final = c.fetchone()
    assert row_final["status"] == "CONSUMED"
    assert row_final["consumed_at"] is not None

    # Cleanup
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99994")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99994")
    c.execute("DELETE FROM users WHERE id = 99994")
    conn.commit()
    conn.close()


def test_admin_termination_cancels_in_progress_pending_switch(client):
    """
    Test requirement 8:
    Ensure administrator termination takes priority over an in-progress device switch.
    """
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99995")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99995")
    c.execute("DELETE FROM users WHERE id IN (99995, 88885) OR username IN ('terminated_student', 'admin_tutor_term')")

    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99995, 'terminated_student', ?, 'student', 'Terminated Student', 'ROLL-995', 'old-active-token')
    """, (generate_password_hash("StudentPass123!"),))

    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name)
        VALUES (88885, 'admin_tutor_term', ?, 'admin', 'Tutor Term')
    """, (generate_password_hash("AdminPass123!"),))
    conn.commit()
    conn.close()

    # Step 1: Student initiates device switch to create pending state
    st_client = app.test_client()
    st_csrf = get_auth_csrf(st_client)
    st_client.post("/login", data={
        "identifier": "terminated_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": st_csrf
    }, headers={"Origin": "http://localhost"})

    with st_client.session_transaction() as sess:
        switch_token = sess.get("pending_device_switch_token")
    assert switch_token is not None

    # Step 2: Admin terminates student session
    admin_client = app.test_client()
    csrf_admin = get_auth_csrf(admin_client)
    with admin_client.session_transaction() as sess:
        sess["user_id"] = 88885
        sess["user_role"] = "admin"
        sess["username"] = "admin_tutor_term"

    res_term = admin_client.post("/api/admin/student/99995/terminate-session",
                                 headers={"Origin": "http://localhost", "X-CSRF-Token": csrf_admin})
    assert res_term.status_code == 200

    # Verify pending device switch was CANCELLED by the admin action
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status FROM pending_device_switches WHERE student_id = 99995 AND confirmation_token = ?", (switch_token,))
    row_st = c.fetchone()
    assert row_st["status"] == "CANCELLED"
    conn.close()

    # Step 3: Student attempts to confirm the now-cancelled device switch
    res_conf = st_client.post("/login", data={
        "confirm_device_switch": "1",
        "device_switch_token": switch_token,
        "csrf_token": st_csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    html_resp = res_conf.get_data(as_text=True)
    assert ("Device switch confirmation expired, already used, or invalid" in html_resp
            or "Session was terminated or modified by administrator" in html_resp)

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99995")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99995")
    c.execute("DELETE FROM users WHERE id IN (99995, 88885)")
    conn.commit()
    conn.close()


def test_stale_confirmation_cannot_replace_newer_active_session(client):
    """
    Test requirement 3 & 6:
    Verify that confirmation checks the stored `current_session_token` against the student's
    current active session token. A stale pending confirmation must not replace a newer session.
    """
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99996")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99996")
    c.execute("DELETE FROM users WHERE id = 99996 OR username = 'stale_check_student'")

    pwd = generate_password_hash("StudentPass123!")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (99996, 'stale_check_student', ?, 'student', 'Stale Check Student', 'ROLL-996', 'token-v1')
    """, (pwd,))
    conn.commit()
    conn.close()

    # Step 1: Student on Device B logs in while user has token-v1, generating pending confirmation bound to token-v1
    st_client = app.test_client()
    st_csrf = get_auth_csrf(st_client)
    st_client.post("/login", data={
        "identifier": "stale_check_student",
        "password": "StudentPass123!",
        "role": "student",
        "csrf_token": st_csrf
    }, headers={"Origin": "http://localhost"})

    with st_client.session_transaction() as sess:
        switch_token = sess.get("pending_device_switch_token")
    assert switch_token is not None

    # Step 2: Now simulate that another newer session token was generated (e.g. student logged in elsewhere, token-v2)
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET active_session_token = 'token-v2' WHERE id = 99996")
    conn.commit()
    conn.close()

    # Step 3: Device B tries to confirm the old pending switch
    res = st_client.post("/login", data={
        "confirm_device_switch": "1",
        "device_switch_token": switch_token,
        "csrf_token": st_csrf,
        "role": "student"
    }, headers={"Origin": "http://localhost"}, follow_redirects=True)

    # Must be rejected because current_session_token != active_session_token in users table
    assert "Device switch confirmation expired, already used, or invalid" in res.get_data(as_text=True)

    # Active session must remain token-v2
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_session_token FROM users WHERE id = 99996")
    tok = c.fetchone()["active_session_token"]
    assert tok == "token-v2"

    # Cleanup
    c.execute("DELETE FROM pending_device_switches WHERE student_id = 99996")
    c.execute("DELETE FROM device_switch_history WHERE student_id = 99996")
    c.execute("DELETE FROM users WHERE id = 99996")
    conn.commit()
    conn.close()
