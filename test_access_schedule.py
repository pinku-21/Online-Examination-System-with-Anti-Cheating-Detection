import requests
from datetime import datetime, timedelta

BASE_URL = "http://127.0.0.1:5000"

def run_tests():
    session_admin = requests.Session()
    import os
    admin_id = os.environ.get("ADMIN_INITIAL_USERNAME", "admin")
    admin_pw = os.environ.get("ADMIN_INITIAL_PASSWORD", "admin123")
    res = session_admin.post(f"{BASE_URL}/login", data={
        "identifier": admin_id,
        "password": admin_pw,
        "role": "admin"
    }, allow_redirects=True)
    assert res.status_code == 200, f"Admin login failed: {res.status_code}"
    print("[PASS] Admin logged in successfully")

    # 2. Create Student A (Class 10-A) and Student B (Class 12-B)
    ts = int(datetime.now().timestamp())
    student_a_user = f"alice_{ts}"
    student_b_user = f"bob_{ts}"

    res = session_admin.post(f"{BASE_URL}/api/admin/create-student", json={
        "full_name": "Alice Walker",
        "roll_number": f"ROLL-A-{ts % 10000}",
        "username": student_a_user,
        "password": "Password123!",
        "email": f"alice_{ts}@example.com",
        "class_name": "Class 10-A"
    })
    data_a = res.json()
    assert data_a.get("success"), f"Failed to create student A: {data_a}"
    student_a_id = data_a["student"]["id"]
    print(f"[PASS] Student A created (ID: {student_a_id}, Class: Class 10-A)")

    res = session_admin.post(f"{BASE_URL}/api/admin/create-student", json={
        "full_name": "Bob Smith",
        "roll_number": f"ROLL-B-{ts % 10000}",
        "username": student_b_user,
        "password": "Password123!",
        "email": f"bob_{ts}@example.com",
        "class_name": "Class 12-B"
    })
    data_b = res.json()
    assert data_b.get("success"), f"Failed to create student B: {data_b}"
    student_b_id = data_b["student"]["id"]
    print(f"[PASS] Student B created (ID: {student_b_id}, Class: Class 12-B)")

    # 3. Create Exam 1: Class 10-A only, Anytime
    res = session_admin.post(f"{BASE_URL}/api/save-exam", json={
        "title": "Mathematics Test Class 10-A",
        "duration_minutes": 20,
        "passing_percentage": 50,
        "max_warnings": 10,
        "enable_audio_detection": 0,
        "access_type": "class",
        "assigned_class": "Class 10-A",
        "schedule_type": "anytime",
        "questions": [
            {
                "question_text": "What is 2 + 2?",
                "question_type": "mcq",
                "correct_answer": "B",
                "options": ["3", "4", "5", "6"],
                "explanation": "2+2=4",
                "points": 1
            }
        ]
    })
    data_e1 = res.json()
    assert data_e1.get("success"), f"Failed to create exam 1: {data_e1}"
    exam1_code = data_e1["exam_code"]
    exam1_id = data_e1["exam_id"]
    print(f"[PASS] Created Exam 1 (Class 10-A, code: {exam1_code})")

    # 4. Create Exam 2: Scheduled in future (Starts 1 day from now)
    future_start = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
    future_end = (datetime.now() + timedelta(days=1, hours=2)).strftime("%Y-%m-%dT%H:%M")
    res = session_admin.post(f"{BASE_URL}/api/save-exam", json={
        "title": "Future Scheduled Physics Test",
        "duration_minutes": 30,
        "passing_percentage": 50,
        "max_warnings": 10,
        "enable_audio_detection": 0,
        "access_type": "all",
        "schedule_type": "scheduled",
        "start_time": future_start,
        "end_time": future_end,
        "questions": [
            {
                "question_text": "What is gravity?",
                "question_type": "mcq",
                "correct_answer": "A",
                "options": ["A force", "A fruit", "A car", "A wave"],
                "explanation": "Gravity is a fundamental force",
                "points": 1
            }
        ]
    })
    data_e2 = res.json()
    assert data_e2.get("success"), f"Failed to create exam 2: {data_e2}"
    exam2_code = data_e2["exam_code"]
    print(f"[PASS] Created Exam 2 (Scheduled future, code: {exam2_code})")

    # 5. Test Student A Session (Class 10-A)
    session_a = requests.Session()
    res = session_a.post(f"{BASE_URL}/login", data={
        "identifier": student_a_user,
        "password": "Password123!",
        "role": "student"
    }, allow_redirects=True)
    assert res.status_code == 200

    dash_a = session_a.get(f"{BASE_URL}/student/dashboard").text
    assert "Mathematics Test Class 10-A" in dash_a, "Exam 1 should be visible to Alice"
    assert "Future Scheduled Physics Test" in dash_a, "Exam 2 should be visible to Alice as upcoming"
    print("[PASS] Alice dashboard correctly lists both accessible exams")

    # Alice starts Exam 1 -> Should succeed
    res = session_a.post(f"{BASE_URL}/student/start", data={
        "exam_code": exam1_code,
        "student_name": "Alice Walker",
        "roll_number": f"ROLL-A-{ts % 10000}"
    }, allow_redirects=False)
    loc = res.headers.get("Location", "")
    assert res.status_code == 302 and ("/exam/" in loc or "/student/exam/" in loc or "exam" in loc), f"Alice should redirect to exam room, got: {res.status_code} | {res.headers}"
    print("[PASS] Alice successfully started Exam 1")

    # Alice tries to start Exam 2 (Future) -> Should be rejected
    res = session_a.post(f"{BASE_URL}/student/start", data={
        "exam_code": exam2_code,
        "student_name": "Alice Walker",
        "roll_number": f"ROLL-A-{ts % 10000}"
    }, allow_redirects=True)
    # The flash message says "Exam Not Started Yet" and redirects to dashboard
    assert "Exam Not Started Yet" in res.text or "scheduled to open" in res.text or res.url.endswith("/student/dashboard"), f"Expected future exam block. Got: {res.url}"
    print("[PASS] Alice prevented from starting future scheduled exam")

    # 6. Test Student B Session (Class 12-B)
    session_b = requests.Session()
    res = session_b.post(f"{BASE_URL}/login", data={
        "identifier": student_b_user,
        "password": "Password123!",
        "role": "student"
    }, allow_redirects=True)
    assert res.status_code == 200

    dash_b = session_b.get(f"{BASE_URL}/student/dashboard").text
    assert "Mathematics Test Class 10-A" not in dash_b, "Exam 1 should NOT be visible to Bob"
    print("[PASS] Bob dashboard hides Class 10-A exam")

    # Bob tries to enter Exam 1 code directly -> Should be rejected
    res = session_b.post(f"{BASE_URL}/student/start", data={
        "exam_code": exam1_code,
        "student_name": "Bob Smith",
        "roll_number": f"ROLL-B-{ts % 10000}"
    }, allow_redirects=True)
    # Flash message says "Access Restricted"
    assert "Access Restricted" in res.text or "specific students or classes" in res.text or res.url.endswith("/student/dashboard"), f"Expected access denied. Got: {res.url} | {res.text[:300]}"
    print("[PASS] Bob blocked from taking Exam 1 with access denial message")

    # 7. Test Admin updating access via /api/tutor/exam/<id>/access-schedule
    # Change Exam 1 access to "selected" and add Bob's ID
    res = session_admin.post(f"{BASE_URL}/api/tutor/exam/{exam1_id}/access-schedule", json={
        "access_type": "selected",
        "assigned_students": [student_b_id],
        "schedule_type": "anytime"
    })
    assert res.json().get("success"), f"Failed to update access schedule: {res.json()}"
    print("[PASS] Admin updated Exam 1 to selected student (Bob)")

    # Now Bob should see and be able to take Exam 1!
    dash_b_updated = session_b.get(f"{BASE_URL}/student/dashboard").text
    assert "Mathematics Test Class 10-A" in dash_b_updated, "Bob should now see Exam 1 after direct assignment"
    print("[PASS] Bob can now access Exam 1 after admin updated permissions!")

    print("\nALL ACCESS AND SCHEDULING INTEGRATION TESTS PASSED 100%!")

if __name__ == "__main__":
    run_tests()
