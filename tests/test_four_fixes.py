import json
import pytest
from app import app, compute_submission_score_with_or, is_mcq_answer_correct, extract_student_response_text, prepare_questions_review

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# ============================================================================
# TASK 1 TESTS: HIDE DESK SETUP WHEN VIDEO PROCTORING IS DISABLED
# ============================================================================

def test_task1_desk_setup_and_video_on_off_states(client):
    """Verify templates and state logic for both video proctoring ON and OFF."""
    with app.app_context():
        tmpl_source = open("templates/student_exam.html", "r", encoding="utf-8").read()
        # Verify guards gating webcam and desk setup
        assert "ENABLE_VIDEO && examRequiresHandwrittenWork && !isDeskSetupVerified" in tmpl_source
        assert "if (!ENABLE_VIDEO || isDeskSetupVerified || isDeskModalActive) return;" in tmpl_source
        assert 'data-enable-video="{{ 1 if submission.enable_video_detection in [1, True, \'1\'] else 0 }}"' in tmpl_source
        assert "{% if submission.enable_video_detection in [1, True, '1'] %}" in tmpl_source
        assert "initWebcam()" in tmpl_source
        assert "if (!ENABLE_VIDEO) {" in tmpl_source

# ============================================================================
# TASK 2 TESTS: VOICE INTERCOM WORKFLOW
# ============================================================================

def test_task2_voice_intercom_workflow_elements():
    """Verify exam_details.html has recording indicator, timer, blob validation, and review playback."""
    with app.app_context():
        tmpl_source = open("templates/exam_details.html", "r", encoding="utf-8").read()
        assert "startVoiceRecording" in tmpl_source
        assert "stopVoiceRecording" in tmpl_source
        assert "recordingTimer" in tmpl_source
        assert "recordingSeconds" in tmpl_source
        assert "getSupportedAudioMimeType" in tmpl_source
        assert "new Blob(proctorAudioChunks" in tmpl_source
        assert "proctorRecordedBase64 = reader.result" in tmpl_source
        assert "cleanupAudioPlayer" in tmpl_source
        assert "audioConversionPromise" in tmpl_source
        assert "isConvertingAudio" in tmpl_source
        assert "Voice Memo Attached" in tmpl_source

# ============================================================================
# TASK 3 & 4 TESTS: CBSE MCQ MARKING & TUTOR/STUDENT RESULT AGREEMENT
# ============================================================================

def test_mcq_correct_option_matching_variations():
    """Verify is_mcq_answer_correct matches option letters, full texts, and trimmed texts."""
    options = [
        "A. Carbon dioxide gains hydrogen, while water loses electrons",
        "B. Carbon dioxide loses oxygen, while water gains oxygen",
        "C. Carbon dioxide is oxidised, while water is reduced",
        "D. Both carbon dioxide and water undergo reaction"
    ]
    correct_ans = "B"

    # Student selected full option string
    assert is_mcq_answer_correct(options[1], correct_ans, options) is True
    # Student selected option letter
    assert is_mcq_answer_correct("B", correct_ans, options) is True
    assert is_mcq_answer_correct("(B)", correct_ans, options) is True
    assert is_mcq_answer_correct("b", correct_ans, options) is True
    # Student selected clean text without letter
    assert is_mcq_answer_correct("Carbon dioxide loses oxygen, while water gains oxygen", correct_ans, options) is True
    assert is_mcq_answer_correct("Carbon dioxide loses oxygen, while water gains oxygen.", correct_ans, options) is True
    # Conflicting letter and text:
    # If student chooses "B. London" but correct answer text is "Paris" or option text differs:
    assert is_mcq_answer_correct("B. London", "B. Paris", ["A. Rome", "B. Paris"]) is False
    assert is_mcq_answer_correct("B. London", correct_ans, options) is False
    assert is_mcq_answer_correct("A. Carbon dioxide loses oxygen, while water gains oxygen", correct_ans, options) is False

    # Different letters with equivalent answer text (e.g., student answers "Carbon dioxide loses oxygen, while water gains oxygen"):
    assert is_mcq_answer_correct("Carbon dioxide loses oxygen, while water gains oxygen", "B", options) is True

    # Incorrect option
    assert is_mcq_answer_correct(options[0], correct_ans, options) is False
    assert is_mcq_answer_correct("A", correct_ans, options) is False
    # Unattempted / empty
    assert is_mcq_answer_correct("", correct_ans, options) is False
    assert is_mcq_answer_correct(None, correct_ans, options) is False

def test_extract_student_response_text():
    """Verify extract_student_response_text distinguishes attempted answers from unattempted."""
    # Plain text / string
    text, is_att = extract_student_response_text("Option B")
    assert text == "Option B" and is_att is True

    # Empty string
    text, is_att = extract_student_response_text("")
    assert text == "" and is_att is False

    # None
    text, is_att = extract_student_response_text(None)
    assert text == "" and is_att is False

    # 'Not Attempted'
    text, is_att = extract_student_response_text("Not Attempted")
    assert text == "" and is_att is False

    # Dict with selected_option
    text, is_att = extract_student_response_text({"selected_option": "B. Oxygen"})
    assert text == "B. Oxygen" and is_att is True

    # Dict with text
    text, is_att = extract_student_response_text({"text": "Photosynthesis is the process..."})
    assert text == "Photosynthesis is the process..." and is_att is True

    # Dict with empty text
    text, is_att = extract_student_response_text({"text": "", "image_url": ""})
    assert text == "" and is_att is False

def test_cbse_mcq_marking_rules_and_scores():
    """
    Test CBSE marking policy:
    * Correct 1-mark MCQ = 1.0
    * Incorrect 1-mark MCQ = 0.0 (strictly 0, no 0.5!)
    * Unattempted 1-mark MCQ = 0.0
    * Correct 2-mark MCQ = 2.0
    * Incorrect 2-mark MCQ = 0.0
    * Descriptive question can still receive partial marks (e.g. 1.5 out of 3.0)
    """
    questions = [
        {
            "id": 1,
            "question_type": "mcq",
            "question_text": "What is 2+2?",
            "correct_answer": "B",
            "options_json": json.dumps(["A. 3", "B. 4", "C. 5", "D. 6"]),
            "points": 1.0
        },
        {
            "id": 2,
            "question_type": "mcq",
            "question_text": "What is the capital of France?",
            "correct_answer": "Paris",
            "options_json": json.dumps(["London", "Berlin", "Paris", "Rome"]),
            "points": 1.0
        },
        {
            "id": 3,
            "question_type": "mcq",
            "question_text": "Advanced 2-mark question",
            "correct_answer": "A",
            "options_json": json.dumps(["A. Option 1", "B. Option 2", "C. Option 3", "D. Option 4"]),
            "points": 2.0
        },
        {
            "id": 4,
            "question_type": "short",
            "question_text": "Explain photosynthesis.",
            "correct_answer": "Process of making food using sunlight.",
            "options_json": "[]",
            "points": 3.0
        }
    ]

    # Student 1:
    # Q1: Correct (1.0)
    # Q2: Incorrect (0.0 - must not be 0.5)
    # Q3: Unattempted (0.0)
    # Q4: Descriptive with partial evaluation (1.5)
    answers = {
        "1": "B. 4",
        "2": "London", # wrong
        # "3" omitted -> unattempted
        "4": {"text": "Plants use light to make food."}
    }
    manual_eval = {
        "4": {"awarded_marks": 1.5, "feedback": "Partial answer"}
    }

    score, total_points, pct = compute_submission_score_with_or(questions, answers, manual_eval)
    assert total_points == 7.0 # 1 + 1 + 2 + 3
    assert score == 2.5 # Q1(1.0) + Q2(0.0) + Q3(0.0) + Q4(1.5)

    # Verification: Manual evaluation CANNOT award marks to an objectively incorrect MCQ
    tampered_manual_eval = {
        "2": {"awarded_marks": 1.0, "feedback": "Teacher mistakenly marked correct"},
        "4": {"awarded_marks": 2.0, "feedback": "Good answer"}
    }
    score_tampered, _, _ = compute_submission_score_with_or(questions, answers, tampered_manual_eval)
    # Q2 is MCQ and objectively incorrect, so it MUST stay 0.0 despite manual_eval giving 1.0!
    # Q4 is descriptive so it gets 2.0. Total: 1.0 (Q1) + 0.0 (Q2) + 0.0 (Q3) + 2.0 (Q4) = 3.0
    assert score_tampered == 3.0

    # Student 2:
    # Q3 correct (2.0)
    # Q1 incorrect (0.0)
    answers_2 = {
        "1": "A. 3", # wrong
        "3": "A. Option 1" # correct 2-mark MCQ
    }
    score_2, total_points_2, _ = compute_submission_score_with_or(questions, answers_2, {})
    assert score_2 == 2.0

def test_tutor_and_student_results_agreement():
    """Verify prepare_questions_review returns identical questions_review for both views."""
    questions = [
        {
            "id": 101,
            "question_type": "mcq",
            "question_text": "Sample MCQ",
            "correct_answer": "B. Correct Choice",
            "options_json": json.dumps(["A. Wrong Choice", "B. Correct Choice", "C. Another Wrong", "D. Last Wrong"]),
            "points": 1.0
        },
        {
            "id": 102,
            "question_type": "mcq",
            "question_text": "Unattempted MCQ",
            "correct_answer": "A. Option",
            "options_json": json.dumps(["A. Option", "B. Option"]),
            "points": 1.0
        }
    ]

    student_answers = {
        "101": "B. Correct Choice"
    }

    review = prepare_questions_review(questions, student_answers, {})
    assert len(review) == 2

    # Q101 was attempted and correct
    q1 = review[0]
    assert q1["is_attempted"] is True
    assert q1["student_answer"] == "B. Correct Choice"
    assert q1["is_correct"] is True
    assert q1["awarded_marks"] == 1.0
    assert q1["rendered_options"][1]["is_correct"] is True
    assert q1["rendered_options"][1]["is_selected"] is True

    # Q102 was unattempted
    q2 = review[1]
    assert q2["is_attempted"] is False
    assert q2["student_answer"] == "Not Attempted"
    assert q2["is_correct"] is False
    assert q2["awarded_marks"] == 0.0
    assert q2["rendered_options"][0]["is_correct"] is True
    assert q2["rendered_options"][0]["is_selected"] is False

# ============================================================================
# TASK 5 TESTS: SQLITE ROW COMPATIBILITY & SUBMISSION ENDPOINT INTEGRITY
# ============================================================================

def test_row_get_and_sqlite_row_compatibility():
    """Verify row_get helper handles sqlite3.Row, dict, and None without AttributeError."""
    import sqlite3
    from app import row_get

    # 1. Test dictionary lookup
    d = {"points": 2.0, "is_honeypot": 1, "none_val": None}
    assert row_get(d, "points") == 2.0
    assert row_get(d, "is_honeypot") == 1
    assert row_get(d, "none_val") is None
    assert row_get(d, "missing", "fallback") == "fallback"
    assert row_get(None, "anything", "safe") == "safe"

    # 2. Test sqlite3.Row lookup
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("CREATE TABLE mock_q (id INT, points REAL, is_honeypot INT, honeypot_signature TEXT, null_col TEXT)")
    cur.execute("INSERT INTO mock_q VALUES (1, 3.5, 1, 'gpt_leak', NULL)")
    cur.execute("SELECT * FROM mock_q")
    row = cur.fetchone()
    conn.close()

    assert type(row) is sqlite3.Row
    # Directly verify row does NOT have .get method (which previously crashed)
    assert not hasattr(row, "get")

    # Verify row_get works seamlessly with sqlite3.Row
    assert row_get(row, "id") == 1
    assert row_get(row, "points") == 3.5
    assert row_get(row, "is_honeypot") == 1
    assert row_get(row, "honeypot_signature") == "gpt_leak"
    assert row_get(row, "null_col") is None
    assert row_get(row, "non_existent_column", "fallback") == "fallback"

def test_prepare_questions_review_with_sqlite_row():
    """Verify prepare_questions_review functions identically with sqlite3.Row inputs as with dicts."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE mock_questions (
            id INT, question_text TEXT, question_type TEXT, options_json TEXT, correct_answer TEXT,
            points REAL, figure_svg TEXT, figure_url TEXT, is_honeypot INT, honeypot_signature TEXT,
            distractor_analysis_json TEXT
        )
    """)
    cur.execute("""
        INSERT INTO mock_questions VALUES (
            1, 'Sample Question?', 'mcq', '["A. Yes", "B. No"]', 'A', 1.0, NULL, NULL, 0, NULL, NULL
        )
    """)
    cur.execute("SELECT * FROM mock_questions")
    raw_rows = cur.fetchall()
    conn.close()

    # Verify prepare_questions_review accepts sqlite3.Row objects without AttributeError
    review = prepare_questions_review(raw_rows, {"1": "A. Yes"}, {})
    assert len(review) == 1
    assert review[0]["is_correct"] is True
    assert review[0]["awarded_marks"] == 1.0
