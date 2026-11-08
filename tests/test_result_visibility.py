import json
import pytest
from app import app, get_connection
import database

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client

def create_test_exam_and_submission(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0):
    conn = get_connection()
    cursor = conn.cursor()
    # Create user student
    cursor.execute("SELECT id FROM users WHERE username = 'student_test_vis'")
    existing = cursor.fetchone()
    if existing:
        user_id = existing["id"]
    else:
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role, roll_number, email)
            VALUES ('student_test_vis', 'dummyhash', 'Test Student Visibility', 'student', 'TEST-VIS-001', 'test_vis@examguard.edu')
        """)
        user_id = cursor.lastrowid

    # Create other user student
    cursor.execute("SELECT id FROM users WHERE username = 'other_student_test'")
    other_existing = cursor.fetchone()
    if other_existing:
        other_user_id = other_existing["id"]
    else:
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role, roll_number, email)
            VALUES ('other_student_test', 'dummyhash', 'Other Student', 'student', 'TEST-VIS-999', 'other@examguard.edu')
        """)
        other_user_id = cursor.lastrowid

    # Create exam
    cursor.execute("""
        INSERT INTO exams (title, description, duration_minutes, total_marks, passing_percentage, exam_code, results_published, created_by)
        VALUES ('Visibility Test Exam', 'Test Exam for Visibility', 30, 50, 40, 'VIS123', ?, 1)
    """, (is_published,))
    exam_id = cursor.lastrowid

    # Add questions
    cursor.execute("""
        INSERT INTO questions (exam_id, question_text, question_type, points, correct_option, options_json)
        VALUES (?, 'What is 2+2?', 'mcq', 25, '4', '["1", "2", "3", "4"]')
    """, (exam_id,))
    q1_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO questions (exam_id, question_text, question_type, points, correct_option, options_json)
        VALUES (?, 'What is the capital of France?', 'mcq', 25, 'Paris', '["London", "Berlin", "Paris", "Rome"]')
    """, (exam_id,))
    q2_id = cursor.lastrowid

    answers = {str(q1_id): "4", str(q2_id): "Paris"}
    pct = round((score / total_points) * 100, 1)

    cursor.execute("""
        INSERT INTO submissions (exam_id, student_name, roll_number, user_id, answers_json, score, total_points, percentage, status, is_published, evaluation_status, evaluation_progress, evaluation_total_questions)
        VALUES (?, 'Test Student Visibility', 'TEST-VIS-001', ?, ?, ?, ?, ?, 'submitted', ?, ?, 2, 2)
    """, (exam_id, user_id, json.dumps(answers), score, total_points, pct, is_published, eval_status))
    sub_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return user_id, other_user_id, exam_id, sub_id

def test_student_sees_score_when_evaluated_before_publication(client):
    user_id, _, _, sub_id = create_test_exam_and_submission(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_name"] = "Test Student Visibility"
        sess["user_role"] = "student"
        sess["roll_number"] = "TEST-VIS-001"

    res = client.get(f"/student/result/{sub_id}")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Score should be visible
    assert "38.0" in html
    assert "out of 50.0" in html or "50.0" in html
    assert "76.0%" in html
    assert "Evaluation completed" in html or "AI evaluation completed" in html

    # Detailed questions review and solutions MUST NOT be present before publication
    assert "Published Evaluation & Answer Review" not in html
    assert "What is 2+2?" not in html
    assert "What is the capital of France?" not in html

def test_student_evaluating_in_progress_hides_score(client):
    user_id, _, _, sub_id = create_test_exam_and_submission(eval_status="evaluating", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_name"] = "Test Student Visibility"
        sess["user_role"] = "student"
        sess["roll_number"] = "TEST-VIS-001"

    res = client.get(f"/student/result/{sub_id}")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Score should be hidden
    assert "Hidden" in html
    assert "Available after AI evaluation" in html
    assert "What is 2+2?" not in html

def test_student_unauthorized_access_prevented(client):
    _, other_user_id, _, sub_id = create_test_exam_and_submission(eval_status="awaiting_teacher", is_published=0)
    with client.session_transaction() as sess:
        sess["user_id"] = other_user_id
        sess["user_name"] = "Other Student"
        sess["user_role"] = "student"
        sess["roll_number"] = "TEST-VIS-999"

    res = client.get(f"/student/result/{sub_id}")
    # Redirected to dashboard with warning
    assert res.status_code == 302
    assert "/student/dashboard" in res.headers["Location"]

def test_api_publish_status_returns_score_when_evaluated(client):
    user_id, _, _, sub_id = create_test_exam_and_submission(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_name"] = "Test Student Visibility"
        sess["user_role"] = "student"
        sess["roll_number"] = "TEST-VIS-001"

    res = client.get(f"/api/submission/{sub_id}/publish-status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_published"] is False
    assert data["evaluation_status"] == "awaiting_teacher"
    assert data["score"] == 38.0
    assert data["total_points"] == 50.0
    assert data["percentage"] == 76.0

def test_student_sees_detailed_review_after_publication(client):
    user_id, _, _, sub_id = create_test_exam_and_submission(eval_status="awaiting_teacher", is_published=1, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["user_name"] = "Test Student Visibility"
        sess["user_role"] = "student"
        sess["roll_number"] = "TEST-VIS-001"

    res = client.get(f"/student/result/{sub_id}")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Score is visible
    assert "38.0" in html
    # Questions & review unlocked
    assert "What is 2+2?" in html
    assert "What is the capital of France?" in html
    assert "Published Evaluation & Answer Review" in html
