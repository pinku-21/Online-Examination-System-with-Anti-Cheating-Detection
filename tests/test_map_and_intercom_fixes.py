"""Regression tests for missing map resolution and tutor voice intercom transmission."""
import json
import pytest
import sqlite3
import os
from app import app
from database import get_connection


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-examguard-secret"
    with app.test_client() as c:
        yield c


def test_static_map_svg_serves_valid_dimensions(client):
    """Verify that /static/maps/india.svg serves HTTP 200, contains valid SVG markup with viewBox, width, and height."""
    res = client.get("/static/maps/india.svg")
    assert res.status_code == 200
    assert "image/svg+xml" in res.content_type
    svg_text = res.data.decode("utf-8")
    assert "viewBox=\"0 0 612 696\"" in svg_text
    assert "width=\"612\"" in svg_text
    assert "height=\"696\"" in svg_text
    assert "<path" in svg_text


def test_curriculum_map_endpoints_all_exist(client):
    """Verify all predefined curriculum maps in static/maps are served with HTTP 200."""
    maps = [
        "india.svg",
        "india_physical.svg",
        "india_rivers.svg",
        "world.svg",
        "india_ports.svg",
        "india_crops.svg"
    ]
    for m in maps:
        res = client.get(f"/static/maps/{m}")
        assert res.status_code == 200, f"Map {m} returned {res.status_code}"
        assert len(res.data) > 1000, f"Map {m} payload too small"


def test_tutor_intercom_transmission_lifecycle(client):
    """Test full backend intercom API: validation, audio persistence, transmission confirmation, and student retrieval."""
    conn = get_connection()
    cursor = conn.cursor()

    # Ensure clean test state or create dummy submission
    cursor.execute("""
        INSERT INTO users (username, email, full_name, password_hash, role)
        VALUES ('tutor_test_user', 'tutor_test@test.com', 'Tutor Test User', 'hash_val', 'admin')
    """)
    tutor_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO users (username, email, full_name, password_hash, role)
        VALUES ('student_test_user', 'student_test@test.com', 'Student Test User', 'hash_val', 'student')
    """)
    student_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO exams (exam_code, title, description, duration_minutes, is_active)
        VALUES ('INTERCOM101', 'Intercom Test Exam', 'Test', 30, 1)
    """)
    exam_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO submissions (exam_id, user_id, student_name, roll_number, status, started_at)
        VALUES (?, ?, 'Prashanta kumar Das 1', 'ROLL101', 'in_progress', CURRENT_TIMESTAMP)
    """, (exam_id, student_id))
    sub_id = cursor.lastrowid
    conn.commit()

    try:
        csrf_token = "test_csrf_token_hex_123456"
        with client.session_transaction() as sess:
            sess["user_id"] = tutor_id
            sess["username"] = "tutor_test_user"
            sess["user_role"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = csrf_token

        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf_token
        }

        # 1. Test empty payload rejection
        empty_res = client.post(f"/api/tutor/submission/{sub_id}/send-message", json={}, headers=headers)
        assert empty_res.status_code == 400
        assert empty_res.get_json()["success"] is False

        # 2. Test valid voice intercom transmission
        dummy_audio_b64 = "data:audio/webm;base64,GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQRChYECGFOAZwE="
        valid_res = client.post(f"/api/tutor/submission/{sub_id}/send-message", json={
            "message": "Please adjust your webcam angle. Your full face must remain in frame at all times.",
            "severity": "warning",
            "audio_payload": dummy_audio_b64
        }, headers=headers)
        assert valid_res.status_code == 200
        data = valid_res.get_json()
        assert data["success"] is True
        assert "dispatched" in data["message"].lower()

        # 3. Verify proctor message recorded in database
        cursor.execute("SELECT id, message_text, severity, audio_payload, is_read FROM proctor_messages WHERE submission_id = ?", (sub_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["severity"] == "warning"
        assert row["audio_payload"] == dummy_audio_b64
        assert "webcam angle" in row["message_text"]

        # 4. Verify student message retrieval
        with client.session_transaction() as sess:
            sess["user_id"] = student_id
            sess["username"] = "student_test_user"
            sess["user_role"] = "student"
            sess["role"] = "student"

        student_poll = client.get(f"/api/submission/{sub_id}/proctor-messages")
        assert student_poll.status_code == 200
        poll_data = student_poll.get_json()
        assert poll_data["success"] is True
        assert len(poll_data["messages"]) == 1
        assert poll_data["messages"][0]["audio_payload"] == dummy_audio_b64

        # 5. Verify message marked as read on polling so duplicate alerts are avoided
        student_poll2 = client.get(f"/api/submission/{sub_id}/proctor-messages")
        assert len(student_poll2.get_json()["messages"]) == 0

    finally:
        # Cleanup test rows
        cursor.execute("DELETE FROM proctor_messages WHERE submission_id = ?", (sub_id,))
        cursor.execute("DELETE FROM violations WHERE submission_id = ?", (sub_id,))
        cursor.execute("DELETE FROM submissions WHERE id = ?", (sub_id,))
        cursor.execute("DELETE FROM exams WHERE id = ?", (exam_id,))
        cursor.execute("DELETE FROM users WHERE id IN (?, ?)", (tutor_id, student_id))
        conn.commit()
        conn.close()
