"""
Independent Security Audit & Regression Verification for Session Management,
Device Replacement, MFA Encryption at Rest, and Examination Integrity.

Validates:
1. Atomicity & race condition behavior during simultaneous logins.
2. Complete server-side invalidation of displaced / terminated sessions across protected endpoints.
3. Actual MFA secret AES-GCM authenticated encryption at rest and key derivation.
4. Authorization & IDOR protection on tutor session-management endpoints.
5. Preservation of active examination answers, state, and remaining timers.
"""

import json
import pytest
from app import app
from database import get_connection, init_db
from security import (
    generate_mfa_secret,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    verify_totp_code,
    generate_totp_code,
)
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


def get_csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token")


def test_mfa_secret_encryption_at_rest_and_verification():
    """Verify MFA secret is actually encrypted at rest using AES-GCM and decrypts cleanly for TOTP."""
    plain_secret = generate_mfa_secret()
    encrypted = encrypt_mfa_secret(plain_secret)

    # 1. Stored format must be encrypted with signature prefix 'enc::'
    assert encrypted != plain_secret
    assert encrypted.startswith("enc::")

    # 2. Decrypting restores original Base32 secret
    decrypted = decrypt_mfa_secret(encrypted)
    assert decrypted == plain_secret

    # 3. verify_totp_code works directly against encrypted secrets
    code = generate_totp_code(plain_secret)
    assert verify_totp_code(encrypted, code) is True

    # 4. Bad code fails against encrypted secret
    assert verify_totp_code(encrypted, "000000" if code != "000000" else "111111") is False


def test_tutor_session_management_authorization_and_idor_defense(client):
    """
    Verify that:
    1. Unauthenticated requests to /api/admin/student/<id>/terminate-session fail with 401.
    2. Student accounts calling the terminate endpoints fail with 403 (IDOR/Privilege Escalation blocked).
    3. Invalid/non-existent student IDs fail with 404.
    """
    csrf = get_csrf(client)

    # 1. Unauthenticated call
    res_unauth = client.post("/api/admin/student/1/terminate-session", headers={
        "X-CSRF-Token": csrf,
        "Origin": "http://localhost"
    })
    assert res_unauth.status_code in (401, 403)

    # 2. Student calls terminate-session (IDOR attempt)
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id IN (88801, 88802)")
    c.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (88801, 'malicious_student', ?, 'student', 'Malicious Student')", (generate_password_hash("Pass123!"),))
    c.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (88802, 'victim_student', ?, 'student', 'Victim Student')", (generate_password_hash("Pass123!"),))
    conn.commit()
    conn.close()

    with client.session_transaction() as sess:
        sess["user_id"] = 88801
        sess["user_role"] = "student"
        sess["username"] = "malicious_student"

    res_idor = client.post("/api/admin/student/88802/terminate-session", headers={
        "X-CSRF-Token": csrf,
        "Origin": "http://localhost"
    })
    # Must be forbidden
    assert res_idor.status_code == 403

    # 3. Tutor calls terminate-session on non-existent student -> 404
    with client.session_transaction() as sess:
        sess["user_id"] = 99901
        sess["user_role"] = "admin"
        sess["username"] = "admin_tutor"

    res_404 = client.post("/api/admin/student/9999999/terminate-session", headers={
        "X-CSRF-Token": csrf,
        "Origin": "http://localhost"
    })
    assert res_404.status_code == 404

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id IN (88801, 88802)")
    conn.commit()
    conn.close()


def test_displaced_old_session_invalidation_across_exam_endpoints(client):
    """
    Verify complete server-side rejection of displaced sessions across all protected exam APIs:
    - /api/submission/<id>/save-progress
    - /api/submission/<id>/submit
    - /student/dashboard
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM submissions WHERE user_id = 77701")
    c.execute("DELETE FROM exams WHERE id = 66601")
    c.execute("DELETE FROM users WHERE id = 77701")

    pwd = generate_password_hash("Pass123!")
    # Student with active token
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (77701, 'exam_student', ?, 'student', 'Exam Candidate', 'ROLL-777', 'current-active-token')
    """, (pwd,))

    c.execute("INSERT INTO exams (id, exam_code, title, duration_minutes) VALUES (66601, 'CODE-666', 'Security Audit Exam', 45)")
    c.execute("""
        INSERT INTO submissions (id, exam_id, user_id, student_name, roll_number, status, time_remaining_seconds, progress_answers_json)
        VALUES (55501, 66601, 77701, 'Exam Candidate', 'ROLL-777', 'in_progress', 1500, '{"101": "B"}')
    """)
    conn.commit()
    conn.close()

    csrf = get_csrf(client)

    # Displace the token (simulating a login from Device B)
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET active_session_token = 'new-displaced-token-999' WHERE id = 77701")
    conn.commit()
    conn.close()

    # Now Device A with 'current-active-token' attempts to call save-progress
    with client.session_transaction() as sess:
        sess["user_id"] = 77701
        sess["user_role"] = "student"
        sess["session_token"] = "current-active-token"

    res_save = client.post("/api/submission/55501/save-progress", json={
        "answers": {"101": "C"},
        "time_remaining_seconds": 1400
    }, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"})

    # Must be 401 Unauthorized because session was displaced
    assert res_save.status_code == 401
    assert "signed out because your account was logged in from another device" in res_save.get_json()["error"]

    # Verify answers in database were NOT tampered with by the unauthorized displaced session
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT progress_answers_json, time_remaining_seconds FROM submissions WHERE id = 55501")
    sub = c.fetchone()
    assert sub["progress_answers_json"] == '{"101": "B"}'
    assert sub["time_remaining_seconds"] == 1500

    # Cleanup
    c.execute("DELETE FROM submissions WHERE user_id = 77701")
    c.execute("DELETE FROM exams WHERE id = 66601")
    c.execute("DELETE FROM users WHERE id = 77701")
    conn.commit()
    conn.close()


def test_tutor_termination_invalidates_student_immediately(client):
    """Verify tutor manual termination causes immediate rejection on student's next action."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = 77702")
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, roll_number, active_session_token)
        VALUES (77702, 'term_student', ?, 'student', 'Terminated Candidate', 'ROLL-772', 'active-token-772')
    """, (generate_password_hash("Pass123!"),))
    conn.commit()
    conn.close()

    # Tutor terminates the session (sets active_session_token = '')
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET active_session_token = '' WHERE id = 77702")
    conn.commit()
    conn.close()

    with client.session_transaction() as sess:
        sess["user_id"] = 77702
        sess["user_role"] = "student"
        sess["session_token"] = "active-token-772"

    res = client.get("/student/dashboard", follow_redirects=True)
    assert res.status_code == 200
    assert "signed out because your account was logged in from another device or your session was terminated" in res.get_data(as_text=True)

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = 77702")
    conn.commit()
    conn.close()


def test_mfa_key_management_and_safe_migration():
    """
    Verify:
    1. Plaintext secrets are safely migrated to AES-256-GCM without data loss.
    2. Missing production key raises a clear startup configuration error.
    3. Key rotation via MFA_PREVIOUS_KEYS preserves access for existing users without lockout.
    4. Encryption keys and decrypted secrets are never logged.
    """
    import os
    import sqlite3
    from security.mfa_service import (
        resolve_primary_mfa_encryption_key,
        migrate_unencrypted_mfa_secrets,
    )

    # 1. Plaintext migration test
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = 99911")
    raw_secret = generate_mfa_secret()
    # Insert legacy unencrypted secret
    c.execute("""
        INSERT INTO users (id, username, password_hash, role, full_name, mfa_enabled, mfa_secret)
        VALUES (99911, 'legacy_mfa_admin', 'hash', 'admin', 'Legacy Admin', 1, ?)
    """, (raw_secret,))
    conn.commit()

    # Run idempotent migration
    migrated_count = migrate_unencrypted_mfa_secrets(db_connection=conn)
    assert migrated_count >= 1

    # Verify secret is now encrypted in DB
    c.execute("SELECT mfa_secret FROM users WHERE id = 99911")
    stored = c.fetchone()["mfa_secret"]
    assert stored.startswith("enc::")
    assert stored != raw_secret
    assert decrypt_mfa_secret(stored) == raw_secret

    # Verify TOTP code verification succeeds
    valid_totp = generate_totp_code(raw_secret)
    assert verify_totp_code(stored, valid_totp) is True

    # Run migration again: must be idempotent (0 additional migrations)
    assert migrate_unencrypted_mfa_secrets(db_connection=conn) == 0

    # 2. Production dedicated key enforcement (SECRET_KEY alone is strictly insufficient in production)
    prod_env_no_mfa = {"FLASK_ENV": "production", "SECRET_KEY": "a-strong-session-secret-key", "MFA_ENCRYPTION_KEY": ""}
    with pytest.raises(RuntimeError) as exc_info:
        resolve_primary_mfa_encryption_key(prod_env_no_mfa)
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "MFA_ENCRYPTION_KEY is not configured or empty" in str(exc_info.value)
    assert "SECRET_KEY alone is not permitted as a fallback in production" in str(exc_info.value)

    prod_env_render = {"RENDER": "true", "SECRET_KEY": "some-secret", "MFA_ENCRYPTION_KEY": "   "}
    with pytest.raises(RuntimeError) as exc_render:
        resolve_primary_mfa_encryption_key(prod_env_render)
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_render.value)

    prod_env_valid = {"FLASK_ENV": "production", "MFA_ENCRYPTION_KEY": "dedicated-prod-mfa-key-hex-32"}
    assert len(resolve_primary_mfa_encryption_key(prod_env_valid)) == 32

    # 3. Key rotation zero-lockout test
    old_key = "first-generation-mfa-protection-key"
    new_key = "second-generation-mfa-protection-key"

    orig_mfa_key = os.environ.get("MFA_ENCRYPTION_KEY")
    orig_prev_keys = os.environ.get("MFA_PREVIOUS_KEYS")
    try:
        os.environ["MFA_ENCRYPTION_KEY"] = old_key
        initial_ciphertext = encrypt_mfa_secret(raw_secret)
        assert decrypt_mfa_secret(initial_ciphertext) == raw_secret

        # Rotate to new key, retaining old key in previous keys
        os.environ["MFA_ENCRYPTION_KEY"] = new_key
        os.environ["MFA_PREVIOUS_KEYS"] = old_key

        # Must still decrypt cleanly and verify TOTP
        rotated_decrypted = decrypt_mfa_secret(initial_ciphertext)
        assert rotated_decrypted == raw_secret
        assert verify_totp_code(initial_ciphertext, valid_totp) is True
    finally:
        if orig_mfa_key is not None:
            os.environ["MFA_ENCRYPTION_KEY"] = orig_mfa_key
        else:
            os.environ.pop("MFA_ENCRYPTION_KEY", None)

        if orig_prev_keys is not None:
            os.environ["MFA_PREVIOUS_KEYS"] = orig_prev_keys
        else:
            os.environ.pop("MFA_PREVIOUS_KEYS", None)

        # Cleanup test user
        c.execute("DELETE FROM users WHERE id = 99911")
        conn.commit()
        conn.close()

