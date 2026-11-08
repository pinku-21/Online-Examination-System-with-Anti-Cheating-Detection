import json
import pytest
from app import app
from database import get_connection, init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

def setup_visibility_data(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM submissions WHERE id IN (55551, 55552)")
    c.execute("DELETE FROM questions WHERE exam_id = 44441")
    c.execute("DELETE FROM exams WHERE id = 44441")
    c.execute("DELETE FROM users WHERE id IN (33331, 33332)")

    # Insert test users
    c.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, roll_number, email)
        VALUES (33331, 'vis_student_1', 'dummy', 'Visibility Student 1', 'student', 'ROLL-VIS-1', 'vis1@exam.edu')
    """)
    c.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, roll_number, email)
        VALUES (33332, 'vis_student_2', 'dummy', 'Visibility Student 2', 'student', 'ROLL-VIS-2', 'vis2@exam.edu')
    """)

    # Insert test exam
    c.execute("""
        INSERT INTO exams (id, exam_code, title, duration_minutes, passing_percentage, results_published)
        VALUES (44441, 'VIS-EXAM-1', 'Visibility Policy Exam', 30, 40.0, ?)
    """, (is_published,))

    # Insert questions
    c.execute("""
        INSERT INTO questions (id, exam_id, question_text, question_type, points, correct_answer, options_json)
        VALUES (11111, 44441, 'What is the speed of light?', 'mcq', 25.0, '299792458 m/s', '["299792458 m/s", "1000 m/s"]')
    """)
    c.execute("""
        INSERT INTO questions (id, exam_id, question_text, question_type, points, correct_answer, options_json)
        VALUES (11112, 44441, 'Is Python dynamically typed?', 'mcq', 25.0, 'Yes', '["Yes", "No"]')
    """)

    pct = round((score / total_points) * 100, 1)
    answers = {"11111": "299792458 m/s", "11112": "Yes"}

    c.execute("""
        INSERT INTO submissions (
            id, exam_id, user_id, student_name, roll_number,
            answers_json, score, total_points, percentage, status,
            is_published, evaluation_status, evaluation_progress, evaluation_total_questions
        )
        VALUES (55551, 44441, 33331, 'Visibility Student 1', 'ROLL-VIS-1',
                ?, ?, ?, ?, 'submitted', ?, ?, 2, 2)
    """, (json.dumps(answers), score, total_points, pct, is_published, eval_status))

    conn.commit()
    conn.close()

def test_student_sees_score_when_evaluated_before_publication(client):
    setup_visibility_data(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = 33331
        sess["user_name"] = "Visibility Student 1"
        sess["user_role"] = "student"
        sess["roll_number"] = "ROLL-VIS-1"

    res = client.get("/student/result/55551")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Total score should be visible immediately upon evaluation
    assert "38.0" in html
    assert "50.0" in html
    assert "76.0%" in html

    # Answers, question texts, correct answers, and feedback review MUST NOT be visible before publication
    assert "Published Evaluation & Answer Review" not in html
    assert "What is the speed of light?" not in html
    assert "Is Python dynamically typed?" not in html
    assert "299792458 m/s" not in html

def test_student_evaluating_in_progress_hides_score(client):
    setup_visibility_data(eval_status="evaluating", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = 33331
        sess["user_name"] = "Visibility Student 1"
        sess["user_role"] = "student"
        sess["roll_number"] = "ROLL-VIS-1"

    res = client.get("/student/result/55551")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Score should be hidden while evaluation is in progress
    assert "Hidden" in html
    assert "Available after AI evaluation" in html
    assert "Published Evaluation & Answer Review" not in html
    assert "What is the speed of light?" not in html

def test_student_unauthorized_access_prevented(client):
    setup_visibility_data(eval_status="awaiting_teacher", is_published=0)
    with client.session_transaction() as sess:
        sess["user_id"] = 33332
        sess["user_name"] = "Visibility Student 2"
        sess["user_role"] = "student"
        sess["roll_number"] = "ROLL-VIS-2"

    res = client.get("/student/result/55551")
    # Redirected with access restriction flash
    assert res.status_code == 302
    assert "/student/dashboard" in res.headers["Location"]

def test_api_publish_status_endpoint(client):
    setup_visibility_data(eval_status="awaiting_teacher", is_published=0, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = 33331
        sess["user_name"] = "Visibility Student 1"
        sess["user_role"] = "student"
        sess["roll_number"] = "ROLL-VIS-1"

    res = client.get("/api/submission/55551/publish-status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_published"] is False
    assert data["evaluation_status"] == "awaiting_teacher"
    # Score should be included in publish-status when score_visible is True
    assert data["score"] == 38.0
    assert data["total_points"] == 50.0
    assert data["percentage"] == 76.0

def test_student_sees_detailed_review_after_publication(client):
    setup_visibility_data(eval_status="awaiting_teacher", is_published=1, score=38.0, total_points=50.0)
    with client.session_transaction() as sess:
        sess["user_id"] = 33331
        sess["user_name"] = "Visibility Student 1"
        sess["user_role"] = "student"
        sess["roll_number"] = "ROLL-VIS-1"

    res = client.get("/student/result/55551")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Score is visible
    assert "38.0" in html
    # Questions & review unlocked
    assert "What is the speed of light?" in html
    assert "Is Python dynamically typed?" in html
    assert "Published Evaluation & Answer Review" in html
