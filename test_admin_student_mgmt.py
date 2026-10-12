import requests

BASE_URL = "http://127.0.0.1:5000"

def test_admin_student_management():
    print(">>> 1. Verifying public registration is disabled...")
    s_anon = requests.Session()
    r = s_anon.get(f"{BASE_URL}/register", allow_redirects=False)
    assert r.status_code == 302, f"Expected 302 redirect, got {r.status_code}"
    assert "login" in r.headers.get("Location", ""), f"Expected redirect to login, got {r.headers.get('Location')}"
    print("    [PASS] Public registration properly redirects to login.")

    print("\n>>> 2. Verifying admin login...")
    s_admin = requests.Session()
    r = s_admin.post(f"{BASE_URL}/login", data={"identifier": "admin", "password": "admin123", "role": "admin"}, allow_redirects=False)
    assert r.status_code == 302, f"Expected 302 redirect for admin login, got {r.status_code}"
    r_tutor = s_admin.get(f"{BASE_URL}/tutor")
    assert r_tutor.status_code == 200, f"Expected 200 on tutor portal, got {r_tutor.status_code}"
    assert "Student Accounts" in r_tutor.text or "student" in r_tutor.text.lower(), "Student management section missing from tutor dashboard"
    print("    [PASS] Admin logged in and tutor dashboard contains student management.")

    print("\n>>> 3. Admin creates a student account...")
    student_payload = {
        "full_name": "Rohan Sharma",
        "roll_number": "ROLL-2026-999",
        "username": "rohan_test_user",
        "password": "rohanPassword123",
        "email": "rohan@test.edu"
    }
    r_create = s_admin.post(f"{BASE_URL}/api/admin/create-student", json=student_payload)
    res_create = r_create.json()
    assert res_create.get("success") is True, f"Failed to create student: {res_create}"
    student_id = res_create["student"]["id"]
    print(f"    [PASS] Student created successfully with ID: {student_id}")

    print("\n>>> 4. Verifying student can log in...")
    s_student = requests.Session()
    r_slogin = s_student.post(f"{BASE_URL}/login", data={
        "identifier": "rohan_test_user",
        "password": "rohanPassword123",
        "role": "student"
    }, allow_redirects=False)
    assert r_slogin.status_code == 302, f"Student login failed: {r_slogin.status_code}"
    r_sdash = s_student.get(f"{BASE_URL}/student/dashboard")
    assert r_sdash.status_code == 200, "Student could not access their dashboard"
    assert "Rohan Sharma" in r_sdash.text or "rohan" in r_sdash.text.lower(), "Dashboard did not show student's details"
    print("    [PASS] Student logged in and saw private student dashboard.")

    print("\n>>> 5. Verifying student cannot access admin tutor portal...")
    r_sblocked = s_student.get(f"{BASE_URL}/tutor", allow_redirects=False)
    assert r_sblocked.status_code == 302, "Student was not redirected away from /tutor"
    print("    [PASS] Student correctly forbidden from accessing admin tutor portal.")

    print("\n>>> 6. Admin resets student's password...")
    new_pw = "newRohanSecret789"
    r_reset = s_admin.post(f"{BASE_URL}/api/admin/reset-password", json={
        "student_id": student_id,
        "new_password": new_pw
    })
    res_reset = r_reset.json()
    assert res_reset.get("success") is True, f"Failed to reset password: {res_reset}"
    print("    [PASS] Admin successfully reset student password.")

    print("\n>>> 7. Verifying student logs in with new password...")
    s_student2 = requests.Session()
    r_newlogin = s_student2.post(f"{BASE_URL}/login", data={
        "identifier": "rohan_test_user",
        "password": new_pw,
        "role": "student"
    }, allow_redirects=False)
    assert r_newlogin.status_code == 302, f"Student failed to login with new password: {r_newlogin.status_code}"
    print("    [PASS] Student successfully logged in with updated password.")

    print("\n>>> 8. Admin deletes student account...")
    r_del = s_admin.delete(f"{BASE_URL}/api/admin/delete-student/{student_id}")
    res_del = r_del.json()
    assert res_del.get("success") is True, f"Failed to delete student: {res_del}"
    print("    [PASS] Admin successfully deleted student.")

    print("\n>>> 9. Verifying deleted student can no longer log in...")
    s_student3 = requests.Session()
    r_deadlogin = s_student3.post(f"{BASE_URL}/login", data={
        "identifier": "rohan_test_user",
        "password": new_pw,
        "role": "student"
    }, allow_redirects=False)
    # Login failure renders the page or flashes error, does not redirect to dashboard
    if r_deadlogin.status_code == 302:
        assert "dashboard" not in r_deadlogin.headers.get("Location", ""), "Deleted student was able to redirect to dashboard!"
    print("    [PASS] Deleted student blocked from login.")

    print("\n============================================================")
    print("ALL ADMIN STUDENT MANAGEMENT TESTS PASSED WITH 100% SUCCESS!")
    print("============================================================")

if __name__ == "__main__":
    test_admin_student_management()
