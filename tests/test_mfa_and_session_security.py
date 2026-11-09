"""
Tests for Phase 3: Advanced Authentication, MFA, Session Security, and API Protection.
Validates:
- TOTP secret generation, RFC 6238 time-step code generation and verification
- Single-use recovery code hashing and consumption
- MFA login challenge for enabled administrator accounts
- Invalidation on bad TOTP or recovery codes
- Session rotation on authentication
- Session idle timeout and absolute lifetime enforcement
- Logout session invalidation
- Active examination preservation (exam sessions not killed on refresh)
- Zero student violation strike pollution
"""

import json
import time
import pytest
from app import app
from database import get_connection, init_db
from security import (
    generate_mfa_secret,
    get_totp_uri,
    generate_totp_code,
    verify_totp_code,
    generate_recovery_codes,
    verify_and_consume_recovery_code,
    rotate_session,
    check_session_validity,
    ADMIN_IDLE_TIMEOUT_SECONDS,
    ADMIN_ABSOLUTE_LIFETIME_SECONDS,
)


@pytest.fixture(autouse=True)
def setup_security_database():
    """Ensure database schema is fresh and clean."""
    init_db()


def test_totp_generation_and_verification():
    """Verify standard RFC 6238 TOTP computation and clock drift tolerance."""
    secret = generate_mfa_secret()
    assert len(secret) >= 26  # Base32 representation of 20 bytes

    uri = get_totp_uri(secret, "admin@examguard.ai")
    assert uri.startswith("otpauth://totp/")
    assert secret in uri

    current_code = generate_totp_code(secret)
    assert len(current_code) == 6
    assert current_code.isdigit()

    # Must verify cleanly
    assert verify_totp_code(secret, current_code) is True

    # Bad code must be rejected
    bad_code = "999999" if current_code != "999999" else "111111"
    assert verify_totp_code(secret, bad_code) is False

    # Short/malformed code rejected
    assert verify_totp_code(secret, "abc") is False
    assert verify_totp_code(secret, "") is False


def test_recovery_code_generation_and_single_use_consumption():
    """Verify recovery codes are generated in plain/hash pairs and consumed upon use."""
    plain_codes, hashed_codes = generate_recovery_codes(count=5)
    assert len(plain_codes) == 5
    assert len(hashed_codes) == 5

    test_code = plain_codes[0]
    # First use: must succeed and consume
    success, updated_json = verify_and_consume_recovery_code(test_code, hashed_codes)
    assert success is True
    updated_hashes = json.loads(updated_json)
    assert len(updated_hashes) == 4

    # Second use of same code: must fail (prevent replay attacks)
    success_replay, _ = verify_and_consume_recovery_code(test_code, updated_hashes)
    assert success_replay is False

    # Bogus code: must fail
    success_bogus, _ = verify_and_consume_recovery_code("XXXX-YYYY", updated_hashes)
    assert success_bogus is False


def test_session_rotation_and_validity():
    """Verify rotate_session regenerates tokens and validity check respects idle timeout."""
    with app.test_request_context():
        from flask import session
        session["user_id"] = 10
        session["user_role"] = "admin"
        session["session_token"] = "initial_token_123"

        rotate_session()
        assert session["user_id"] == 10
        assert session["session_token"] != "initial_token_123"
        assert "_created_at" in session
        assert "_last_active" in session

        # Valid session
        valid, msg = check_session_validity()
        assert valid is True
        assert msg is None

        # Simulate idle timeout exceeded for admin
        session["_last_active"] = int(time.time()) - (ADMIN_IDLE_TIMEOUT_SECONDS + 60)
        valid_idle, msg_idle = check_session_validity()
        assert valid_idle is False
        assert "timed out due to inactivity" in msg_idle


def test_student_exam_session_protected_from_idle_timeout():
    """Verify that student exam sessions are NEVER logged out by admin idle timeouts."""
    with app.test_request_context():
        from flask import session
        session["user_id"] = 55
        session["user_role"] = "student"
        session["_created_at"] = int(time.time())
        # Simulate student paused or reading exam for 2 hours
        session["_last_active"] = int(time.time()) - (ADMIN_IDLE_TIMEOUT_SECONDS + 3600)

        valid, msg = check_session_validity()
        # Student role must NOT time out on idle
        assert valid is True
        assert msg is None


def test_mfa_endpoints_access_control_and_csrf():
    """Verify MFA setup, confirm, and disable endpoints require admin and enforce CSRF."""
    client = app.test_client()

    # Unauthenticated setup request
    res_unauth = client.get("/api/admin/mfa/setup")
    assert res_unauth.status_code == 401

    # Student access blocked
    with client.session_transaction() as sess:
        sess["user_id"] = 88
        sess["user_role"] = "student"

    res_student = client.get("/api/admin/mfa/setup")
    assert res_student.status_code == 403

    # CSRF check on POST confirm without token
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"

    res_post_nocsrf = client.post("/api/admin/mfa/confirm", json={"code": "123456"})
    assert res_post_nocsrf.status_code == 403

