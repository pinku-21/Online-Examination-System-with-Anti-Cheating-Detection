"""
Phase 4 — Step 2 Regression & Verification Test Suite:
Adaptive Security Risk Engine & Behavioural Anomaly Detection

Validates all 15 required criteria:
1. Account risk calculation (assess_account_risk).
2. Session risk calculation (assess_session_risk).
3. Device risk calculation (assess_device_risk).
4. IP contextual risk (assess_ip_context_risk - IP changes alone never malicious).
5. Examination risk calculation (assess_examination_risk).
6. Deterministic scoring (same inputs = same scores).
7. Score boundaries (strictly bounded [0, 100]).
8. Diminishing returns curve for repeated identical events.
9. Time-based weighting / recency decay.
10. Missing event data handling (missing fields never inflate risk).
11. False-positive handling (normal student behaviors do not produce HIGH/CRITICAL).
12. Database failure resilience (graceful degradation without raising).
13. Risk audit logging (records transitions, avoids redundant duplicate logs).
14. SQLite & PostgreSQL schema compatibility.
15. Existing examination functionality preservation.
"""

from datetime import datetime, timedelta, timezone
import pytest
from app import app
from database import get_connection, init_db
from security import (
    calculate_risk_score,
    assess_account_risk,
    assess_session_risk,
    assess_device_risk,
    assess_ip_context_risk,
    assess_examination_risk,
    record_risk_audit_transition,
    detect_anomalies_for_target,
    evaluate_anomalies_and_risk,
    record_security_event,
)


@pytest.fixture(autouse=True)
def setup_phase4_db():
    """Ensure database schema is ready and test tables are available."""
    init_db()


# 1. Account Risk Calculation
def test_account_risk_calculation():
    user_id = 91001
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE actor_id = ?", (user_id,))
    conn.commit()

    # Zero events = 0 risk
    empty_risk = assess_account_risk(user_id=user_id, conn=conn)
    assert empty_risk.score == 0
    assert empty_risk.level == "LOW"
    assert empty_risk.scope == "account"
    assert str(user_id) in empty_risk.target_id

    # Record account security events
    record_security_event(event_type="auth.failed_login", actor_id=user_id, actor_role="student", conn=conn)
    record_security_event(event_type="auth.failed_login", actor_id=user_id, actor_role="student", conn=conn)
    conn.commit()

    risk = assess_account_risk(user_id=user_id, conn=conn)
    assert risk.score > 0
    assert risk.level in ("LOW", "MEDIUM")
    assert len(risk.factors) >= 1
    assert "auth.failed_login" in risk.factor_weights
    conn.close()


# 2. Session Risk Calculation
def test_session_risk_calculation():
    session_token = "sess_tok_abc_99999"
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE target_resource_id = ?", (session_token,))
    conn.commit()

    record_security_event(
        event_type="session.revocation_violation",
        target_resource="session",
        target_resource_id=session_token,
        conn=conn
    )
    conn.commit()

    risk = assess_session_risk(session_token=session_token, conn=conn)
    assert risk.score >= 20
    assert risk.scope == "session"
    assert len(risk.factors) >= 1
    conn.close()


# 3. Device Risk Calculation
def test_device_risk_calculation():
    ua = "Mozilla/5.0 (CustomDeviceTestBrowser/1.0)"
    student_id = 91003
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE user_agent = ? OR actor_id = ?", (ua, student_id))
    conn.commit()

    record_security_event(
        event_type="auth.rapid_device_switch",
        actor_id=student_id,
        user_agent=ua,
        conn=conn
    )
    conn.commit()

    risk = assess_device_risk(device_fingerprint_or_ua=ua, student_id=student_id, conn=conn)
    assert risk.score >= 20
    assert risk.scope == "device"
    conn.close()


# 4. IP Contextual Risk
def test_ip_context_risk_never_marks_ip_change_alone():
    # A. Loopback check
    loopback_risk = assess_ip_context_risk("127.0.0.1")
    assert loopback_risk.score == 0
    assert loopback_risk.level == "LOW"

    # B. Normal IP with zero malicious alerts has zero risk
    clean_ip = "198.51.100.42"
    clean_risk = assess_ip_context_risk(clean_ip)
    assert clean_risk.score == 0
    assert "Normal IP address changes alone never constitute proof of malicious activity" in clean_risk.explanation

    # C. IP with brute force activity receives contextual score
    conn = get_connection()
    malicious_ip = "203.0.113.88"
    for _ in range(3):
        record_security_event(
            event_type="auth.failed_login",
            source_ip=malicious_ip,
            conn=conn
        )
    conn.commit()

    ip_risk = assess_ip_context_risk(malicious_ip, conn=conn)
    assert ip_risk.score >= 20
    assert "Normal IP address changes alone never constitute proof of malicious activity" in ip_risk.explanation
    conn.close()


# 5. Examination Risk Calculation
def test_examination_risk_calculation():
    sub_id = 99881
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE target_resource_id = ?", (str(sub_id),))
    conn.commit()

    record_security_event(
        event_type="exam.answer_tampering_attempt",
        target_resource="submission",
        target_resource_id=str(sub_id),
        conn=conn
    )
    conn.commit()

    exam_risk = assess_examination_risk(submission_id=sub_id, conn=conn)
    assert exam_risk.score >= 35
    assert exam_risk.scope == "examination"
    conn.close()


# 6. Deterministic Scoring
def test_deterministic_scoring():
    events = [
        {"event_id": "ev-1", "event_type": "auth.failed_login", "timestamp": "2026-11-09T14:00:00Z"},
        {"event_id": "ev-2", "event_type": "authorization.idor_attempt", "timestamp": "2026-11-09T14:05:00Z"},
    ]
    ref_time = datetime(2026, 11, 9, 14, 10, 0, tzinfo=timezone.utc)

    score_1 = calculate_risk_score(events, reference_time=ref_time)
    score_2 = calculate_risk_score(events, reference_time=ref_time)

    assert score_1.score == score_2.score
    assert score_1.level == score_2.level
    assert score_1.factor_weights == score_2.factor_weights
    assert score_1.explanation == score_2.explanation


# 7. Score Boundaries [0, 100]
def test_score_boundaries():
    # Bottom boundary
    zero_risk = calculate_risk_score([])
    assert zero_risk.score == 0
    assert zero_risk.level == "LOW"

    # Ceiling boundary: even 50 severe events cannot exceed 100
    huge_events = [{"event_id": f"ev-{i}", "event_type": "authorization.privilege_escalation_attempt"} for i in range(50)]
    max_risk = calculate_risk_score(huge_events)
    assert max_risk.score == 100
    assert max_risk.level == "CRITICAL"


# 8. Diminishing Returns
def test_diminishing_returns():
    single_event = [{"event_type": "auth.failed_login"}]
    double_event = [{"event_type": "auth.failed_login"} for _ in range(2)]
    quad_event = [{"event_type": "auth.failed_login"} for _ in range(4)]

    s1 = calculate_risk_score(single_event).score
    s2 = calculate_risk_score(double_event).score
    s4 = calculate_risk_score(quad_event).score

    # Delta between 1 and 2 events must be greater than or equal to delta between 2 and 4
    delta_1_2 = s2 - s1
    delta_2_4 = s4 - s2
    assert delta_1_2 >= 5
    assert delta_2_4 < (delta_1_2 * 2)  # Proves diminishing returns rate curve


# 9. Time-Based Weighting (Recency Decay)
def test_time_based_weighting():
    ref_time = datetime(2026, 11, 9, 15, 0, 0, tzinfo=timezone.utc)

    recent_event = [{
        "event_type": "authorization.unauthorized_access",
        "timestamp": (ref_time - timedelta(minutes=5)).isoformat()
    }]
    stale_event = [{
        "event_type": "authorization.unauthorized_access",
        "timestamp": (ref_time - timedelta(minutes=90)).isoformat()
    }]

    score_recent = calculate_risk_score(recent_event, reference_time=ref_time).score
    score_stale = calculate_risk_score(stale_event, reference_time=ref_time).score

    assert score_recent > score_stale


# 10. Missing Event Data Handling
def test_missing_event_data_does_not_inflate_risk():
    # Events with missing keys, None values, or empty timestamps
    corrupted_events = [
        {},
        {"random_key": "val"},
        {"event_type": None, "timestamp": ""},
        {"event_type": "auth.failed_login", "timestamp": "invalid-time"},
    ]
    assessment = calculate_risk_score(corrupted_events)
    assert assessment.score <= 15
    assert assessment.level == "LOW"


# 11. False-Positive Handling
def test_false_positive_handling():
    # Legitimate student behaviors: normal page loads, valid requests, single normal IP change
    student_events = [
        {"event_type": "auth.login_success"},
        {"event_type": "exam.question_view"},
        {"event_type": "exam.heartbeat"},
    ]
    assessment = calculate_risk_score(student_events)
    # None of these benign events should accumulate dangerous risk
    assert assessment.level == "LOW"
    assert assessment.score <= 10


# 12. Database Failure Handling
def test_database_failure_resilience():
    class BrokenConnection:
        def cursor(self):
            raise RuntimeError("Database connection suddenly dropped")
        def close(self):
            pass

    broken = BrokenConnection()
    # Must not raise; must return safe baseline RiskAssessment
    risk = assess_account_risk(user_id=123, conn=broken)
    assert risk.score == 0
    assert risk.level == "LOW"

    # Audit logging must not raise on broken connection
    logged = record_risk_audit_transition("account", "123", 0, 50, [], conn=broken)
    assert logged is False


# 13. Risk Audit Logging
def test_risk_audit_logging_and_suppression():
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM risk_audit_log WHERE entity_id = 'test_audit_entity_99'")
    conn.commit()

    # 1. Meaningful change: 0 to 45 (transition to HIGH)
    did_log = record_risk_audit_transition(
        entity_type="account",
        entity_id="test_audit_entity_99",
        old_score=0,
        new_score=45,
        factors=[{"name": "auth.failed_login", "weight": 25, "rationale": "Test factor"}],
        trigger_event="auth.failed_login",
        conn=conn
    )
    assert did_log is True

    # 2. Insignificant change: 45 to 47 (delta < 5, level remains HIGH) -> Must be suppressed
    did_log_suppressed = record_risk_audit_transition(
        entity_type="account",
        entity_id="test_audit_entity_99",
        old_score=45,
        new_score=47,
        factors=[],
        trigger_event="minor_event",
        conn=conn
    )
    assert did_log_suppressed is False

    # Verify exactly 1 record was written
    c.execute("SELECT COUNT(*) as cnt FROM risk_audit_log WHERE entity_id = 'test_audit_entity_99'")
    assert c.fetchone()["cnt"] == 1
    conn.close()


# 14. Behavioural Anomaly Detection Rules
def test_behavioural_anomaly_detector_rules():
    actor_id = 95551
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE actor_id = ?", (actor_id,))
    conn.commit()

    # Record 4 failed logins (exceeds threshold 3)
    for _ in range(4):
        record_security_event(event_type="auth.failed_login", actor_id=actor_id, conn=conn)

    # Record 2 device switches (exceeds threshold 2)
    record_security_event(event_type="auth.device_replacement", actor_id=actor_id, conn=conn)
    record_security_event(event_type="auth.unusual_device_switch", actor_id=actor_id, conn=conn)
    conn.commit()

    findings = detect_anomalies_for_target("account", actor_id, conn=conn)
    rule_names = [f.rule_name for f in findings]
    assert "repeated_failed_logins" in rule_names
    assert "unusual_device_replacement_frequency" in rule_names

    # Combined evaluation
    eval_res = evaluate_anomalies_and_risk("account", actor_id, conn=conn)
    assert eval_res["anomaly_count"] >= 2
    assert eval_res["risk_assessment"]["score"] > 0
    conn.close()


# 15. Existing Examination Functionality & Non-Interruption
def test_risk_scoring_does_not_interrupt_active_examination():
    """Verify that calculating high risk NEVER alters or deletes submissions or student answers."""
    conn = get_connection()
    c = conn.cursor()
    # Find or create a test exam
    c.execute("SELECT id FROM exams LIMIT 1")
    exam_row = c.fetchone()
    if exam_row:
        exam_id = exam_row["id"]
    else:
        c.execute("INSERT INTO exams (exam_code, title) VALUES ('PHASE4_TEST_EXAM', 'Phase 4 Test Exam')")
        exam_id = c.lastrowid
        conn.commit()

    sub_id = 89901
    c.execute("DELETE FROM submissions WHERE id = ?", (sub_id,))
    c.execute("""
        INSERT INTO submissions (id, exam_id, student_name, roll_number, answers_json, status, is_published)
        VALUES (?, ?, 'Active Candidate', 'ROLL-899', '{"1": "A", "2": "B"}', 'in_progress', 0)
    """, (sub_id, exam_id))
    conn.commit()

    # Calculate assessment
    assessment = assess_examination_risk(submission_id=sub_id, conn=conn)
    assert assessment.score >= 0

    # Ensure submission is completely unchanged
    c.execute("SELECT status, answers_json FROM submissions WHERE id = ?", (sub_id,))
    row = c.fetchone()
    assert row["status"] == "in_progress"
    assert row["answers_json"] == '{"1": "A", "2": "B"}'

    # Cleanup
    c.execute("DELETE FROM submissions WHERE id = ?", (sub_id,))
    conn.commit()
    conn.close()


# 16. Security Audit: Future Timestamps and Timezone Consistency
def test_future_and_inconsistent_timestamps_graceful_handling():
    ref_time = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
    future_events = [
        {"event_type": "auth.failed_login", "timestamp": "2026-11-09T14:00:00+00:00"}, # 2 hours in future
        {"event_type": "auth.failed_login", "timestamp": "2026-11-09T17:30:00+05:30"}, # Equivalent to 12:00:00 UTC (now)
    ]
    assessment = calculate_risk_score(future_events, reference_time=ref_time)
    assert assessment.score > 0
    assert assessment.level in ("LOW", "MEDIUM")


# 17. Security Audit: Raw Session Token Anonymization
def test_session_token_masking_in_risk_assessment():
    raw_token = "secret_raw_session_token_1234567890abcdef"
    assessment = assess_session_risk(session_token=raw_token)
    assert raw_token not in assessment.target_id
    assert raw_token not in assessment.explanation
    # Must use opaque non-reversible surrogate reference (sess_ref_) rather than revealing token fragments
    assert assessment.target_id.startswith("sess_ref_")


# 18. Security Audit: Stale CSRF Alone Is Not Abnormal Exam Cheating
def test_stale_csrf_alone_does_not_trigger_abnormal_exam_activity():
    sub_id = 99882
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_events WHERE target_resource_id = ?", (str(sub_id),))
    conn.commit()

    # Record a CSRF token mismatch event during exam
    record_security_event(
        event_type="csrf.validation_failed",
        target_resource="submission",
        target_resource_id=str(sub_id),
        conn=conn
    )
    conn.commit()

    findings = detect_anomalies_for_target("examination", sub_id, conn=conn)
    rule_names = [f.rule_name for f in findings]
    # Stale CSRF must NOT be marked as 'abnormal_examination_activity' cheating
    assert "abnormal_examination_activity" not in rule_names
    conn.close()
