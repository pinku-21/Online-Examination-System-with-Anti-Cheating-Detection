import os
import pytest
from app import (
    app, generate_submission_integrity_hash, generate_legacy_submission_integrity_hash,
    validate_password_strength, classify_security_event
)

def test_security_event_classification():
    """ECC Test: Verifies SIEM event metadata for proctoring violations."""
    meta = classify_security_event("tab_switch")
    assert meta["code"] == "SEC-007"
    assert meta["severity"] == "HIGH"
    assert "Tab Switch" in meta["desc"]

    cam_meta = classify_security_event("virtual_camera_detected")
    assert cam_meta["code"] == "SEC-001"
    assert cam_meta["severity"] == "CRITICAL"

def test_security_event_fallback():
    """ECC Test: Unknown violation types fallback cleanly with SEC-999."""
    meta = classify_security_event("unknown_suspicious_behavior")
    assert meta["code"] == "SEC-999"
    assert meta["severity"] == "MEDIUM"

def test_cryptographic_integrity_hash_consistency():
    """ECC Test: Verifies HMAC-SHA256 signature output and determinism."""
    token1 = generate_submission_integrity_hash(10, "CS-001", 45.0, 50.0, 0, "submitted")
    token2 = generate_submission_integrity_hash(10, "CS-001", 45.0, 50.0, 0, "submitted")
    assert token1 == token2
    assert len(token1) == 64

def test_cryptographic_integrity_tamper_detection():
    """ECC Test: Altering score, strikes, or status completely invalidates hash."""
    original = generate_submission_integrity_hash(10, "CS-001", 45.0, 50.0, 0, "submitted")
    tampered_score = generate_submission_integrity_hash(10, "CS-001", 50.0, 50.0, 0, "submitted")
    tampered_strikes = generate_submission_integrity_hash(10, "CS-001", 45.0, 50.0, 2, "submitted")
    tampered_status = generate_submission_integrity_hash(10, "CS-001", 45.0, 50.0, 0, "terminated")

    assert original != tampered_score
    assert original != tampered_strikes
    assert original != tampered_status

def test_secondary_camera_security_event_classification():
    """ECC Test: Verifies SIEM event metadata for secondary camera disconnection."""
    meta = classify_security_event("secondary_cam_disconnect")
    assert meta["code"] == "SEC-016"
    assert meta["severity"] == "HIGH"
    assert "Secondary Mobile Camera" in meta["desc"]

def test_mobile_companion_pairing_auth():
    """ECC Test: Verifies unauthenticated mobile pairing returns 401/302 redirect."""
    client = app.test_client()
    resp = client.get("/api/submission/999/mobile-pair-token")
    assert resp.status_code in [302, 401]

def test_question_bank_api_auth():
    """ECC Test: Verifies question bank endpoints require tutor authentication."""
    client = app.test_client()
    resp = client.get("/api/tutor/question-bank")
    assert resp.status_code in [302, 401]

    resp_cat = client.get("/api/tutor/question-bank/categories")
    assert resp_cat.status_code in [302, 401]

    resp_post = client.post("/api/tutor/question-bank", json={"category": "Math"})
    assert resp_post.status_code in [302, 401]

def test_pdf_certificate_auth():
    """ECC Test: Verifies unauthenticated certificate download requires login."""
    client = app.test_client()
    resp = client.get("/api/submission/999/download-certificate")
    assert resp.status_code in [302, 401]

def test_public_certificate_verify_route():
    """ECC Test: Verifies public QR certificate route responds with 404 for nonexistent token."""
    client = app.test_client()
    resp = client.get("/verify-certificate/nonexistent_fake_hash_123")
    assert resp.status_code == 404

def test_extension_tamper_security_event_classification():
    """ECC Test: Verifies SIEM event classification for browser extension / DOM injection tamper."""
    meta = classify_security_event("extension_tamper")
    assert meta["code"] == "SEC-015"
    assert meta["severity"] == "CRITICAL"
    assert "Browser Extension" in meta["desc"]






def test_password_policy_accepts_strong_password():
    assert validate_password_strength("SecureExam2026") is None


@pytest.mark.parametrize("password", [
    "", "short", "alllowercasepassword", "ALLUPPERCASE123", "NoDigitsPassword"
])
def test_password_policy_rejects_weak_passwords(password):
    assert validate_password_strength(password)


def test_v2_integrity_hash_binds_submitted_answers():
    answers_a = {"1": "A", "2": {"text": "worked answer"}}
    answers_b = {"1": "B", "2": {"text": "worked answer"}}
    hash_a = generate_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted", answers_a)
    hash_b = generate_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted", answers_b)
    assert hash_a != hash_b


def test_v2_integrity_hash_is_independent_of_json_key_order():
    answers_a = {"1": "A", "2": {"x": 1, "y": 2}}
    answers_b = {"2": {"y": 2, "x": 1}, "1": "A"}
    hash_a = generate_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted", answers_a)
    hash_b = generate_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted", answers_b)
    assert hash_a == hash_b


def test_legacy_integrity_hash_remains_verifiable():
    legacy = generate_legacy_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted")
    assert len(legacy) == 64
    assert legacy == generate_legacy_submission_integrity_hash(10, "CS-001", 45, 50, 0, "submitted")



def test_state_changing_request_requires_csrf_even_without_existing_session():
    client = app.test_client()
    response = client.post("/login", json={})
    assert response.status_code == 403


def test_state_changing_request_accepts_session_csrf_token():
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]
    response = client.post("/login", json={}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
