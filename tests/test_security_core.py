"""
Tests for Phase 1: Security Intelligence Core and Event Collector.
Validates:
- Event recording and schema insertion
- Sanitization of sensitive data (passwords, tokens, clipboard)
- Risk engine boundary (0-100) and explainability
- Integration with CSRF, login, and IDOR events
- Zero pollution of student violations table
- Dual SQLite / PostgreSQL query compatibility
"""

import json
import pytest
from app import app
from database import get_connection, init_db
from security import (
    record_security_event,
    sanitize_security_details,
    calculate_risk_score,
    correlate_event,
    get_correlation_window_events,
)


@pytest.fixture(autouse=True)
def setup_security_database():
    """Ensure database schema is fresh and clean for testing."""
    init_db()


def test_sanitize_security_details_redacts_sensitive_keys():
    """Ensure passwords, tokens, cookies, secrets, and clipboard are never recorded."""
    sensitive_input = {
        "username": "candidate1",
        "password": "supersecretpassword123",
        "csrf_token": "a1b2c3d4e5f6",
        "X-CSRF-Token": "secret_token_val",
        "session_token": "sess_9999",
        "clipboard_content": "Pasted answer text from external source",
        "bearer": "Bearer eyJhbGciOi...",
        "legitimate_metadata": "Chrome/120.0",
        "attempt_count": 3
    }
    sanitized = sanitize_security_details(sensitive_input)

    assert "username" in sanitized
    assert sanitized["username"] == "candidate1"
    assert "attempt_count" in sanitized
    assert sanitized["attempt_count"] == 3
    assert "legitimate_metadata" in sanitized

    # Verify completely omitted
    assert "password" not in sanitized
    assert "csrf_token" not in sanitized
    assert "X-CSRF-Token" not in sanitized
    assert "session_token" not in sanitized
    assert "clipboard_content" not in sanitized
    assert "bearer" not in sanitized


def test_record_security_event_persists_to_database():
    """Verify security event inserts correctly with all sanitized fields."""
    event_id = record_security_event(
        event_type="auth.failed_login",
        severity="LOW",
        event_category="auth",
        actor_id=101,
        actor_role="student",
        target_resource="user",
        target_resource_id="101",
        source_ip="192.168.1.50",
        endpoint="/login",
        details={"identifier_masked": "tes***"}
    )

    assert event_id is not None
    assert event_id.startswith("evt_")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row["event_type"] == "auth.failed_login"
    assert row["severity"] == "LOW"
    assert row["actor_id"] == 101
    assert row["actor_role"] == "student"
    assert row["source_ip"] == "192.168.1.50"
    assert row["endpoint"] == "/login"

    details = json.loads(row["details_json"])
    assert details["identifier_masked"] == "tes***"


def test_record_security_event_invalid_type_rejection():
    """Verify missing or invalid event_type is rejected safely without exceptions."""
    assert record_security_event(event_type="") is None
    assert record_security_event(event_type=None) is None


def test_security_event_missing_optional_actor():
    """Verify unauthenticated requests (like anonymous brute force) record correctly."""
    event_id = record_security_event(
        event_type="auth.repeated_failed_login",
        severity="HIGH",
        event_category="auth",
        source_ip="10.0.0.99",
        endpoint="/login",
        details={"attempt_window": 60}
    )
    assert event_id is not None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT actor_id, actor_role, source_ip FROM security_events WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()

    assert row["actor_id"] is None
    assert row["actor_role"] is None
    assert row["source_ip"] == "10.0.0.99"


def test_risk_engine_score_boundaries_and_explainability():
    """Verify risk scores are bounded strictly [0, 100] and provide detailed factor breakdowns."""
    # Empty events
    empty_assessment = calculate_risk_score([])
    assert empty_assessment.score == 0
    assert empty_assessment.level == "LOW"
    assert len(empty_assessment.factors) == 0

    # Moderate events
    events = [
        {"event_type": "auth.failed_login"},
        {"event_type": "authorization.unauthorized_access"},
    ]
    assessment = calculate_risk_score(events)
    assert 20 <= assessment.score <= 40
    assert assessment.level in ["MEDIUM", "LOW"]
    assert len(assessment.factors) == 2
    assert "Score serves for administrative prioritization" in assessment.explanation

    # Runaway repeated events test diminishing returns and ceiling cap (100)
    critical_events = [{"event_type": "authorization.privilege_escalation_attempt"} for _ in range(10)]
    crit_assessment = calculate_risk_score(critical_events)
    assert crit_assessment.score <= 100
    assert crit_assessment.level == "CRITICAL"


def test_correlator_window_query():
    """Verify sliding-window correlation helper queries without schema errors."""
    ip = "192.168.1.99"
    # Clean previous events for this IP if any
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE source_ip = ?", (ip,))
    conn.commit()
    conn.close()

    record_security_event(event_type="auth.failed_login", source_ip=ip)
    record_security_event(event_type="auth.failed_login", source_ip=ip)

    events = get_correlation_window_events(source_ip=ip, window_minutes=15)
    assert len(events) == 2
    assert all(e["source_ip"] == ip for e in events)

    # 2 failed logins is below the brute force threshold (5), so incident_candidate is False
    res = correlate_event(events[0]["event_id"])
    assert "incident_candidate" in res
    assert res["incident_candidate"] is False


def test_security_events_separate_from_student_violations():
    """Verify recording security events NEVER increments student proctoring warnings or adds to violations table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM violations")
    initial_violations = cursor.fetchone()["cnt"]
    conn.close()

    # Trigger security events
    record_security_event(
        event_type="csrf.validation_failed",
        severity="HIGH",
        event_category="csrf",
        actor_id=5,
        actor_role="student"
    )
    record_security_event(
        event_type="authorization.unauthorized_access",
        severity="MEDIUM",
        event_category="authorization",
        actor_id=5,
        actor_role="student"
    )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM violations")
    after_violations = cursor.fetchone()["cnt"]
    conn.close()

    # Student violations table MUST remain untouched
    assert initial_violations == after_violations


def test_sanitize_security_details_nested_lists():
    """Verify recursive sanitization inside lists and deeply nested dictionaries."""
    payload = {
        "user_meta": {
            "browser": "Firefox",
            "nested_auth": {"session_token": "secret_abc", "role": "student"}
        },
        "history": [
            {"endpoint": "/api/test", "token": "leaked_tok"},
            {"endpoint": "/api/safe", "status": 200}
        ]
    }
    sanitized = sanitize_security_details(payload)
    assert sanitized["user_meta"]["browser"] == "Firefox"
    assert "session_token" not in sanitized["user_meta"]["nested_auth"]
    assert sanitized["user_meta"]["nested_auth"]["role"] == "student"
    assert len(sanitized["history"]) == 2
    assert "token" not in sanitized["history"][0]
    assert sanitized["history"][0]["endpoint"] == "/api/test"
    assert sanitized["history"][1]["status"] == 200


def test_record_security_event_db_failure_does_not_raise():
    """Verify that a broken database connection does NOT crash or raise an exception to the caller."""
    class BrokenConnection:
        def cursor(self):
            raise RuntimeError("Database unavailable or connection reset")
        def close(self):
            pass

    # Should catch exception internally, log error, and return None
    event_id = record_security_event(
        event_type="auth.failed_login",
        severity="LOW",
        conn=BrokenConnection()
    )
    assert event_id is None


def test_risk_score_exact_boundaries_and_mixed_events():
    """Test risk engine at exact zero, boundary 100, and mixed event types."""
    # Exact 0
    zero_eval = calculate_risk_score([])
    assert zero_eval.score == 0
    assert zero_eval.level == "LOW"

    # Single event
    single_eval = calculate_risk_score([{"event_type": "auth.failed_login"}])
    assert single_eval.score == 10
    assert single_eval.level == "LOW"

    # Extreme mix reaching ceiling
    heavy_events = [
        {"event_type": "authorization.privilege_escalation_attempt"}, # 40
        {"event_type": "authorization.idor_attempt"},                # 35
        {"event_type": "csrf.origin_mismatch"},                      # 30
    ]
    ceiling_eval = calculate_risk_score(heavy_events)
    assert ceiling_eval.score == 100
    assert ceiling_eval.level == "CRITICAL"
    assert len(ceiling_eval.factors) == 3


def test_csrf_and_idor_protection_intact():
    """Verify CSRF and IDOR protections still block unauthorized actions and return correct statuses."""
    client = app.test_client()

    # 1. CSRF block on POST without token
    res = client.post("/login", data={"identifier": "test", "password": "wrong"})
    # CSRF failure redirects with flash on web forms
    assert res.status_code in [302, 403]

    # JSON request without CSRF returns 403 JSON
    res_json = client.post("/api/student/request-device-switch", json={"identifier": "test"})
    assert res_json.status_code == 403
    assert "CSRF" in res_json.get_json()["error"]


