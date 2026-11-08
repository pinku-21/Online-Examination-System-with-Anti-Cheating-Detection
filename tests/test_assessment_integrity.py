import os
import json
import time
import pytest
from app import app
from database import get_connection, init_db

TEST_CSRF = "test_csrf_token_hex_999888777"

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with app.app_context():
            init_db()
            yield client

def setup_test_exam(*args, **kwargs):
    time.sleep(0.4)
    return _real_setup(*args, **kwargs)

def _real_setup(
    enable_fs=0,
    enable_tab=1,
    allow_copy=0,
    allow_cut=0,
    allow_paste=0,
    enable_dom=1,
    warnings_count=0,
    max_warnings=3
):
    conn = get_connection()
    c = conn.cursor()
    # Clean up test rows
    c.execute("DELETE FROM violations WHERE submission_id IN (88881, 88882)")
    c.execute("DELETE FROM submissions WHERE id IN (88881, 88882)")
    c.execute("DELETE FROM questions WHERE exam_id = 77771")
    c.execute("DELETE FROM exams WHERE id = 77771")
    c.execute("DELETE FROM users WHERE id IN (66661, 66662)")

    # Insert tutor & student
    c.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, roll_number, email)
        VALUES 
            (66661, 'integrity_tutor', 'dummy', 'Integrity Tutor', 'tutor', 'TUT-INT', 'tutor_int@test.com'),
            (66662, 'integrity_student', 'dummy', 'Integrity Student', 'student', 'STU-INT', 'student_int@test.com')
    """)

    # Insert exam with specific integrity settings
    c.execute("""
        INSERT INTO exams (
            id, exam_code, title, duration_minutes, passing_percentage,
            results_published, access_type, schedule_type,
            enable_fullscreen_enforcement, enable_tab_monitoring,
            allow_student_copy, allow_student_cut, allow_student_paste,
            enable_dom_integrity_shield
        ) VALUES (
            77771, 'INT-EXAM-77', 'Integrity Test Exam', 45, 40,
            0, 'all', 'anytime',
            ?, ?, ?, ?, ?, ?
        )
    """, (enable_fs, enable_tab, allow_copy, allow_cut, allow_paste, enable_dom))

    # Insert submission
    c.execute("""
        INSERT INTO submissions (
            id, exam_id, user_id, student_name, roll_number,
            status, warnings_count
        ) VALUES (
            88881, 77771, 66662, 'Integrity Student', 'STU-INT',
            'in_progress', ?
        )
    """, (warnings_count,))

    conn.commit()
    conn.close()

def teardown_test_exam():
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM violations WHERE submission_id IN (88881, 88882)")
    c.execute("DELETE FROM submissions WHERE id IN (88881, 88882)")
    c.execute("DELETE FROM questions WHERE exam_id = 77771")
    c.execute("DELETE FROM exams WHERE id = 77771")
    c.execute("DELETE FROM users WHERE id IN (66661, 66662)")
    conn.commit()
    conn.close()

def get_headers(csrf=TEST_CSRF):
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
    }


# ── TEST SUITE ────────────────────────────────────────────────────────

def test_whitelist_validation_rejects_unknown_violation(client):
    """Test that unauthorized/unknown violation types are rejected with HTTP 400."""
    setup_test_exam()
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "malicious_fake_event", "details": "exploit attempt"},
            headers=get_headers()
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "Invalid or unrecognized" in data["error"]
    finally:
        teardown_test_exam()


def test_submission_ownership_enforcement(client):
    """Test that students cannot report violations for another student's submission."""
    setup_test_exam()
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 99999  # Different student
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "tab_switch", "details": "Tampering attempt"},
            headers=get_headers()
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data["success"] is False
    finally:
        teardown_test_exam()


def test_clipboard_copy_blocked_increments_strike_when_disallowed(client):
    """When allow_student_copy is 0, clipboard_copy logs a strike."""
    setup_test_exam(allow_copy=0, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "clipboard_copy", "details": "Copy blocked by policy on <Q1>."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["warnings_count"] == 1
        assert data["is_terminated"] is False
    finally:
        teardown_test_exam()


def test_clipboard_copy_does_not_increment_strike_when_allowed(client):
    """When allow_student_copy is 1, copy event does not increment candidate strikes."""
    setup_test_exam(allow_copy=1, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "clipboard_copy", "details": "Allowed student copy action."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["warnings_count"] == 0  # No strike added
    finally:
        teardown_test_exam()


def test_clipboard_paste_blocked_increments_strike_when_disallowed(client):
    """When allow_student_paste is 0, paste attempt logs a strike."""
    setup_test_exam(allow_paste=0, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "clipboard_paste", "details": "Paste blocked by policy into [ans-1]."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["warnings_count"] == 1
    finally:
        teardown_test_exam()


def test_clipboard_paste_allowed_by_policy(client):
    """When allow_student_paste is 1, paste attempt does not increment strikes."""
    setup_test_exam(allow_paste=1, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "clipboard_paste", "details": "Paste permitted."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["warnings_count"] == 0
    finally:
        teardown_test_exam()


def test_zero_clipboard_content_retention_in_db(client):
    """Verify that no raw clipboard contents are persisted in the database violations table."""
    setup_test_exam(allow_paste=0, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        metadata_details = "Paste blocked by policy into [answer_textarea]."
        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "clipboard_paste", "details": metadata_details},
            headers=get_headers()
        )
        assert res.status_code == 200

        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT details FROM violations WHERE submission_id = 88881")
        rows = c.fetchall()
        conn.close()

        assert len(rows) == 1
        stored_details = rows[0][0] or rows[0]["details"]
        assert stored_details == metadata_details
        # Confirm it's pure element metadata, zero snippet or character length
        assert "characters" not in stored_details
        assert "[answer_textarea]" in stored_details
    finally:
        teardown_test_exam()


def test_fullscreen_enforcement_policy_strike(client):
    """When fullscreen enforcement is active, exiting fullscreen adds a strike."""
    setup_test_exam(enable_fs=1, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "fullscreen_exit", "details": "Candidate exited fullscreen."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["warnings_count"] == 1
    finally:
        teardown_test_exam()


def test_fullscreen_disabled_policy_no_strike(client):
    """When fullscreen enforcement is disabled, exiting fullscreen logs as informational (0 strikes)."""
    setup_test_exam(enable_fs=0, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "fullscreen_exit", "details": "Candidate exited fullscreen."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["warnings_count"] == 0
    finally:
        teardown_test_exam()


def test_tab_monitoring_disabled_policy_no_strike(client):
    """When tab monitoring is disabled, tab switch logs as informational (0 strikes)."""
    setup_test_exam(enable_tab=0, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "tab_switch", "details": "Tab switch event."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["warnings_count"] == 0
    finally:
        teardown_test_exam()


def test_dom_mutation_detected_strike_when_shield_enabled(client):
    """When DOM integrity shield is enabled, dom_mutation_detected adds a strike."""
    setup_test_exam(enable_dom=1, warnings_count=0)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "dom_mutation_detected", "details": "Critical element #exam-timer removed."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["warnings_count"] == 1
    finally:
        teardown_test_exam()


def test_exam_termination_on_max_warnings(client):
    """When candidate reaches max_warnings, the exam is marked terminated."""
    setup_test_exam(enable_fs=1, warnings_count=2, max_warnings=3)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66662
            sess["user_role"] = "student"
            sess["role"] = "student"
            sess["csrf_token"] = TEST_CSRF

        res = client.post(
            "/api/submission/88881/violation",
            json={"type": "fullscreen_exit", "details": "Third strike fullscreen exit."},
            headers=get_headers()
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["warnings_count"] == 3
        assert data["is_terminated"] is True
    finally:
        teardown_test_exam()


def test_access_schedule_api_persists_integrity_policies(client):
    """Verify GET and POST on /api/tutor/exam/<id>/access-schedule for all 6 integrity policies."""
    setup_test_exam(enable_fs=0, enable_tab=1, allow_copy=0, allow_cut=0, allow_paste=0, enable_dom=1)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = 66661
            sess["user_role"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = TEST_CSRF

        # 1. GET initial state
        res_get = client.get("/api/tutor/exam/77771/access-schedule")
        assert res_get.status_code == 200
        d_get = res_get.get_json()
        assert d_get["success"] is True
        ex = d_get["exam"]
        assert ex["enable_fullscreen_enforcement"] == 0
        assert ex["enable_tab_monitoring"] == 1
        assert ex["allow_student_copy"] == 0

        # 2. POST update to flip toggles
        res_post = client.post(
            "/api/tutor/exam/77771/access-schedule",
            json={
                "access_type": "all",
                "schedule_type": "anytime",
                "duration_minutes": 60,
                "enable_video_detection": 1,
                "enable_audio_detection": 1,
                "enable_fullscreen_enforcement": 1,
                "enable_tab_monitoring": 0,
                "allow_student_copy": 1,
                "allow_student_cut": 1,
                "allow_student_paste": 1,
                "enable_dom_integrity_shield": 0
            },
            headers=get_headers()
        )
        assert res_post.status_code == 200
        d_post = res_post.get_json()
        assert d_post["success"] is True

        # 3. Verify in database
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT enable_fullscreen_enforcement, enable_tab_monitoring,
                   allow_student_copy, allow_student_cut, allow_student_paste,
                   enable_dom_integrity_shield
            FROM exams WHERE id = 77771
        """)
        row = c.fetchone()
        conn.close()

        assert (row[0] if isinstance(row, tuple) else row["enable_fullscreen_enforcement"]) == 1
        assert (row[1] if isinstance(row, tuple) else row["enable_tab_monitoring"]) == 0
        assert (row[2] if isinstance(row, tuple) else row["allow_student_copy"]) == 1
        assert (row[3] if isinstance(row, tuple) else row["allow_student_cut"]) == 1
        assert (row[4] if isinstance(row, tuple) else row["allow_student_paste"]) == 1
        assert (row[5] if isinstance(row, tuple) else row["enable_dom_integrity_shield"]) == 0
    finally:
        teardown_test_exam()
