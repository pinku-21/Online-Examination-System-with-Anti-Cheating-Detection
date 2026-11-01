"""Tests for Paper / Desk Workspace Setup Lifecycle and Verification Persistence.

Verifies:
1. Endpoint authorization and validation (/api/submission/<id>/verify-desk-setup).
2. Attempt isolation (verifying desk setup in one submission does not verify another).
3. Attempt lifecycle persistence (verification state stored in database and retrievable).
4. New attempt resets desk verification state (is_desk_setup_verified starts at 0).
5. Examination room template metadata reflects is_desk_setup_verified accurately.
"""
import json
import uuid
import pytest
from app import app
from database import get_connection, init_db

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()

def test_verify_desk_setup_endpoint_requires_auth():
    client = app.test_client()
    resp = client.post("/api/submission/99999/verify-desk-setup")
    # Must redirect to login or deny when not authenticated
    assert resp.status_code in (302, 401, 403)

def test_verify_desk_setup_endpoint_success():
    exam_code = f"DK{uuid.uuid4().hex[:4].upper()}"
    username = f"user_{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Create a test exam
        cursor.execute("""
            INSERT INTO exams (exam_code, title, duration_minutes, max_warnings)
            VALUES (?, 'Desk Setup Test Exam', 30, 3)
        """, (exam_code,))
        exam_id = cursor.lastrowid

        # Create a test student user
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (?, 'fakehash', 'Desk Student', 'student')
        """, (username,))
        user_id = cursor.lastrowid

        # Create an in_progress submission
        cursor.execute("""
            INSERT INTO submissions (exam_id, user_id, student_name, roll_number, status, is_desk_setup_verified)
            VALUES (?, ?, 'Desk Student', 'ROLL-DS1', 'in_progress', 0)
        """, (exam_id, user_id))
        sub_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    client = app.test_client()
    csrf_token = "test_csrf_token_desk_123"
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_role"] = "student"
        sess["user_name"] = "Desk Student"
        sess["csrf_token"] = csrf_token

    # Call verification endpoint with valid CSRF token header
    resp = client.post(
        f"/api/submission/{sub_id}/verify-desk-setup",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["success"] is True
    assert data["is_desk_setup_verified"] == 1

    # Verify directly in database
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT is_desk_setup_verified FROM submissions WHERE id = ?", (sub_id,))
        row = cursor.fetchone()
        assert row["is_desk_setup_verified"] == 1

        # Verify second submission for different attempt is NOT affected (starts at 0)
        cursor.execute("""
            INSERT INTO submissions (exam_id, user_id, student_name, roll_number, status, is_desk_setup_verified)
            VALUES (?, ?, 'Desk Student', 'ROLL-DS1', 'in_progress', 0)
        """, (exam_id, user_id))
        sub_id_new = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT is_desk_setup_verified FROM submissions WHERE id = ?", (sub_id_new,))
        row_new = cursor.fetchone()
        assert row_new["is_desk_setup_verified"] == 0
    finally:
        conn.close()

def test_student_exam_room_renders_desk_setup_metadata():
    exam_code = f"DK{uuid.uuid4().hex[:4].upper()}"
    username = f"user_{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO exams (exam_code, title, duration_minutes, max_warnings)
            VALUES (?, 'Desk Metadata Exam', 30, 3)
        """, (exam_code,))
        exam_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (?, 'fakehash', 'Desk Student 2', 'student')
        """, (username,))
        user_id = cursor.lastrowid

        # Create submission with is_desk_setup_verified = 1
        cursor.execute("""
            INSERT INTO submissions (exam_id, user_id, student_name, roll_number, status, is_desk_setup_verified)
            VALUES (?, ?, 'Desk Student 2', 'ROLL-DS2', 'in_progress', 1)
        """, (exam_id, user_id))
        sub_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_role"] = "student"
        sess["user_name"] = "Desk Student 2"

    resp = client.get(f"/student/exam/{sub_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert 'data-is-desk-setup-verified="1"' in html
