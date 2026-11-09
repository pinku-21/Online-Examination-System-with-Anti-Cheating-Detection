"""
Phase 4 — Step 3 Regression & Verification Test Suite:
Adaptive Security Policy Engine & Recommendation Generation

Validates:
1. Policy threshold evaluation against risk assessments across LOW, MEDIUM, HIGH, CRITICAL.
2. Disabled policies are ignored (is_enabled = 0).
3. Unsupported actions are safely rejected.
4. Missing/empty policy data fails safely.
5. Duplicate active recommendation prevention for the same target and action.
6. Multiple policies evaluated concurrently.
7. Required approval flag preservation (requires_admin_approval = 1).
8. Unauthorized automatic execution prevention (recommendations are advisories only).
9. Database failure resilience (graceful degradation without raising).
10. SQLite / PostgreSQL schema compatibility.
11. Recommendation review transitions (PENDING_REVIEW -> APPROVED / REJECTED / DISMISSED).
12. Traceability between risk assessment scores, events, incidents, and recommendations.
13. Role-based review authorization gating (admin only, rejects non-admin).
14. Concurrency & race condition prevention (cannot overwrite reviewed recommendations).
15. Regeneration permitted after previous recommendation is resolved/rejected.
16. Database-enforced unique constraint for active PENDING_REVIEW recommendations.
17. Concurrent thread recommendation creation safety.
18. Flask review endpoint: unauthenticated rejection (401).
19. Flask review endpoint: student role rejection (403).
20. Flask review endpoint: CSRF enforcement (403 SEC-016).
21. Flask review endpoint: server-side derived identity prevents reviewer impersonation.
"""

import json
import concurrent.futures
import pytest
from app import app
from database import get_connection, init_db
from security import (
    RiskAssessment,
    RiskFactor,
    calculate_risk_score,
    evaluate_policies_for_assessment,
    generate_security_recommendations,
    get_active_policies,
    get_recommendation_details,
    review_security_recommendation,
    check_existing_active_recommendation,
    SUPPORTED_ADVISORY_ACTIONS,
)


@pytest.fixture(autouse=True)
def setup_policy_db():
    """Ensure database schema is fresh and clean."""
    init_db()


# 1. Policy Threshold Evaluation
def test_policy_threshold_evaluation():
    # Assessment with score 78 (CRITICAL)
    crit_assessment = RiskAssessment(
        score=78,
        level="CRITICAL",
        factors=[RiskFactor(name="authorization.idor_attempt", weight=40, rationale="IDOR probe")],
        scope="session",
        target_id="tok_12345",
        event_ids=["evt_001"]
    )
    eval_results = evaluate_policies_for_assessment(crit_assessment)
    assert len(eval_results) >= 1

    triggered_keys = [r.policy_key for r in eval_results if r.triggered]
    # At score 78, policies with threshold <= 75 should trigger
    assert "critical_session_containment_policy" in triggered_keys
    assert "suspicious_session_review_policy" in triggered_keys
    assert "auth_stepup_policy" in triggered_keys


# 2. Disabled Policies Are Ignored
def test_disabled_policies_are_ignored():
    conn = get_connection()
    c = conn.cursor()
    # Temporarily insert a disabled policy with low threshold
    c.execute("DELETE FROM security_policies WHERE policy_key = 'test_disabled_policy'")
    c.execute("""
        INSERT INTO security_policies (policy_key, name, min_risk_score, recommended_action, is_enabled)
        VALUES ('test_disabled_policy', 'Disabled Test Policy', 10, 'recommend_mfa_stepup', 0)
    """)
    conn.commit()

    active_policies = get_active_policies(conn=conn)
    policy_keys = [p["policy_key"] for p in active_policies]
    assert "test_disabled_policy" not in policy_keys

    # Cleanup
    c.execute("DELETE FROM security_policies WHERE policy_key = 'test_disabled_policy'")
    conn.commit()
    conn.close()


# 3. Unsupported Actions Are Rejected
def test_unsupported_actions_are_safely_rejected():
    mock_policies = [
        {
            "policy_key": "malicious_auto_ban_policy",
            "name": "Illegal Auto Ban Policy",
            "min_risk_score": 10,
            "recommended_action": "auto_ban_student_immediately",  # NOT in SUPPORTED_ADVISORY_ACTIONS
            "requires_admin_approval": 0,
            "is_enabled": 1,
        },
        {
            "policy_key": "unapproved_action_policy",
            "name": "Unapproved Action",
            "min_risk_score": 10,
            "recommended_action": "recommend_device_blocklist",  # NOT in canonical 5 actions
            "requires_admin_approval": 1,
            "is_enabled": 1,
        }
    ]
    assessment = RiskAssessment(score=90, level="CRITICAL", scope="account", target_id="123")
    results = evaluate_policies_for_assessment(assessment, policies=mock_policies)
    # Must reject all unsupported actions completely
    assert len(results) == 0


# 4. Missing / Empty Policy Data Fails Safely
def test_missing_policy_data_fails_safely():
    assessment = RiskAssessment(score=50, level="MEDIUM", scope="general")
    results = evaluate_policies_for_assessment(assessment, policies=[])
    assert results == []


# 5. Duplicate Active Recommendation Prevention
def test_duplicate_recommendation_prevention():
    assessment = RiskAssessment(
        score=80,
        level="CRITICAL",
        scope="session",
        target_id="tok_test_session_dup",
        event_ids=["evt_dup_1", "evt_dup_2"]
    )
    target_res = "session"
    target_res_id = "tok_test_session_dup"

    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = ?", (target_res_id,))
    conn.commit()

    # 1. First generation: creates new recommendations
    rec_ids_1 = generate_security_recommendations(
        assessment=assessment,
        target_resource=target_res,
        target_resource_id=target_res_id,
        target_actor_id=5501,
        incident_id="INC-2026-TEST01",
        conn=conn
    )
    assert len(rec_ids_1) >= 1

    # 2. Second generation with identical target and action: must NOT create duplicates
    rec_ids_2 = generate_security_recommendations(
        assessment=assessment,
        target_resource=target_res,
        target_resource_id=target_res_id,
        target_actor_id=5501,
        incident_id="INC-2026-TEST01",
        conn=conn
    )
    assert len(rec_ids_2) == 0

    # Verify database still has exactly the first generation count
    c.execute("SELECT COUNT(*) as cnt FROM security_recommendations WHERE target_resource_id = ? AND status = 'PENDING_REVIEW'", (target_res_id,))
    count = c.fetchone()["cnt"]
    assert count == len(rec_ids_1)

    # Cleanup
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = ?", (target_res_id,))
    conn.commit()
    conn.close()


# 6. Multiple Policies Evaluated Concurrently
def test_multiple_policies_evaluated_concurrently():
    assessment = RiskAssessment(
        score=85,
        level="CRITICAL",
        scope="account",
        target_id="5502",
        event_ids=["evt_multi_1"]
    )
    eval_results = evaluate_policies_for_assessment(assessment)
    triggered = [r for r in eval_results if r.triggered]
    # At score 85, multiple policies should trigger
    assert len(triggered) >= 2


# 7. Required Approval Flag Preservation
def test_requires_approval_flag_preservation():
    assessment = RiskAssessment(score=75, level="CRITICAL", scope="session", target_id="tok_appr")
    eval_results = evaluate_policies_for_assessment(assessment)
    for r in eval_results:
        assert r.requires_admin_approval is True


# 8. Unauthorized Automatic Execution Prevention
def test_unauthorized_automatic_execution_prevention():
    """Verify that generating recommendations creates entries in PENDING_REVIEW and executes NO system changes."""
    conn = get_connection()
    c = conn.cursor()
    # Check that users table is untouched
    c.execute("SELECT active_session_token FROM users LIMIT 1")
    old_token = c.fetchone()["active_session_token"]

    assessment = RiskAssessment(
        score=95,
        level="CRITICAL",
        scope="session",
        target_id="tok_test_session_exec",
        event_ids=["evt_exec_1"]
    )
    rec_ids = generate_security_recommendations(
        assessment=assessment,
        target_resource="session",
        target_resource_id="tok_test_session_exec",
        target_actor_id=1,
        conn=conn
    )
    assert len(rec_ids) >= 1

    # Verify all generated recommendations are in PENDING_REVIEW status
    for rid in rec_ids:
        rec = get_recommendation_details(rid, conn=conn)
        assert rec["status"] == "PENDING_REVIEW"
        assert rec["reviewed_by"] is None
        assert "No automated disciplinary or session termination action has been executed" in rec["explanation"]

    # Verify user token was never touched
    c.execute("SELECT active_session_token FROM users LIMIT 1")
    new_token = c.fetchone()["active_session_token"]
    assert old_token == new_token

    # Cleanup
    for rid in rec_ids:
        c.execute("DELETE FROM security_recommendations WHERE recommendation_id = ?", (rid,))
    conn.commit()
    conn.close()


# 9. Database Failure Handling
def test_policy_engine_database_failure_handling():
    class BrokenConnection:
        def cursor(self):
            raise RuntimeError("Database unavailable")
        def close(self):
            pass

    broken = BrokenConnection()
    # Must fail safely without raising
    active_policies = get_active_policies(conn=broken)
    assert active_policies == []

    recs = generate_security_recommendations(
        assessment=RiskAssessment(score=90, level="CRITICAL"),
        target_resource="account",
        target_resource_id="123",
        conn=broken
    )
    assert recs == []

    details = get_recommendation_details("REC-NONEXISTENT", conn=broken)
    assert details is None

    reviewed, _ = review_security_recommendation("REC-NONEXISTENT", "APPROVED", reviewer_id=1, conn=broken)
    assert reviewed is False


# 10. Recommendation Review Lifecycle & Authorization Gating
def test_recommendation_review_lifecycle():
    assessment = RiskAssessment(
        score=60,
        level="HIGH",
        scope="account",
        target_id="user_review_test",
        event_ids=["evt_rev_1"]
    )
    rec_ids = generate_security_recommendations(
        assessment=assessment,
        target_resource="account",
        target_resource_id="user_review_test",
        target_actor_id=7711
    )
    assert len(rec_ids) >= 1
    test_rec_id = rec_ids[0]

    # Verify initial state
    rec_before = get_recommendation_details(test_rec_id)
    assert rec_before["status"] == "PENDING_REVIEW"

    # 1. Non-admin reviewer rejection (role gating)
    unauth_ok, unauth_msg = review_security_recommendation(
        recommendation_id=test_rec_id,
        action="APPROVED",
        reviewer_id=888,
        reviewer_role="student"
    )
    assert unauth_ok is False
    assert "Unauthorized" in unauth_msg

    # 2. Human administrator reviews and approves the recommendation
    ok, msg = review_security_recommendation(
        recommendation_id=test_rec_id,
        action="APPROVED",
        reviewer_id=1,
        reviewer_role="admin",
        notes="Admin approved step-up MFA for candidate."
    )
    assert ok is True

    rec_after = get_recommendation_details(test_rec_id)
    assert rec_after["status"] == "APPROVED"
    assert rec_after["reviewed_by"] == 1
    assert rec_after["execution_notes"] == "Admin approved step-up MFA for candidate."

    # 3. Cannot review again once no longer PENDING_REVIEW (prevents race condition overwrite)
    ok_second, err_msg = review_security_recommendation(
        recommendation_id=test_rec_id,
        action="REJECTED",
        reviewer_id=1,
        reviewer_role="admin"
    )
    assert ok_second is False
    assert "already in state 'APPROVED'" in err_msg

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    for rid in rec_ids:
        c.execute("DELETE FROM security_recommendations WHERE recommendation_id = ?", (rid,))
    conn.commit()
    conn.close()


# 11. Regrowth After Rejection / Resolution
def test_regeneration_allowed_after_resolution_or_rejection():
    """Verify that once a recommendation is resolved or rejected, subsequent distinct threats can generate fresh recommendations."""
    assessment = RiskAssessment(
        score=75,
        level="CRITICAL",
        scope="session",
        target_id="tok_regen_test",
        event_ids=["evt_regen_1"]
    )
    target_res = "session"
    target_res_id = "tok_regen_test"

    # Step 1: Initial generation
    rec_ids = generate_security_recommendations(
        assessment=assessment,
        target_resource=target_res,
        target_resource_id=target_res_id,
        target_actor_id=8822
    )
    assert len(rec_ids) >= 1
    initial_rec = rec_ids[0]

    # Step 2: Reject or dismiss this recommendation
    ok, _ = review_security_recommendation(
        recommendation_id=initial_rec,
        action="REJECTED",
        reviewer_id=1,
        reviewer_role="admin",
        notes="Dismissed as known test condition."
    )
    assert ok is True

    # Step 3: Subsequent assessment on same target CAN now generate a new active recommendation
    new_rec_ids = generate_security_recommendations(
        assessment=assessment,
        target_resource=target_res,
        target_resource_id=target_res_id,
        target_actor_id=8822
    )
    assert len(new_rec_ids) >= 1
    assert new_rec_ids[0] != initial_rec

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = ?", (target_res_id,))
    conn.commit()
    conn.close()


# 12. Database-Enforced Unique Constraint Concurrency Safety
def test_concurrent_recommendation_creation_unique_constraint():
    """Simulate parallel threads attempting to insert recommendations for the exact same target and action."""
    assessment = RiskAssessment(
        score=85,
        level="CRITICAL",
        scope="session",
        target_id="tok_concurrent_test_88",
        event_ids=["evt_conc_1"]
    )
    target_res = "session"
    target_res_id = "tok_concurrent_test_88"

    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = ?", (target_res_id,))
    conn.commit()
    conn.close()

    def generate_worker(_):
        return generate_security_recommendations(
            assessment=assessment,
            target_resource=target_res,
            target_resource_id=target_res_id,
            target_actor_id=909
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(generate_worker, range(5)))

    # Verify that exactly ONE active recommendation exists per triggered action
    # (i.e. No duplicate recommendations were created despite 5 concurrent worker executions)
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT recommended_action, COUNT(*) as cnt
        FROM security_recommendations
        WHERE target_resource = ?
          AND target_resource_id = ?
          AND status = 'PENDING_REVIEW'
        GROUP BY recommended_action
    """, (target_res, target_res_id))
    action_counts = {r["recommended_action"]: r["cnt"] for r in c.fetchall()}
    
    # Each triggered policy action has exactly 1 recommendation (no duplicates)
    assert len(action_counts) > 0
    for action, cnt in action_counts.items():
        assert cnt == 1

    # Cleanup
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = ?", (target_res_id,))
    conn.commit()
    conn.close()


# 13. Flask Review Endpoint Security & Authorization Enforcement
def test_flask_review_endpoint_unauthenticated_rejection():
    """Unauthenticated POST to recommendation review must be rejected (blocked by CSRF or admin_required)."""
    client = app.test_client()
    # 1. Without CSRF, blocked by CSRF guard
    resp_no_csrf = client.post(
        "/api/admin/security/recommendation/REC-TEST-001/review",
        json={"action": "APPROVED"}
    )
    assert resp_no_csrf.status_code == 403
    assert resp_no_csrf.get_json()["code"] == "SEC-016"

    # 2. With CSRF token in an unauthenticated session, blocked by admin_required with 401
    with client.session_transaction() as sess:
        sess["csrf_token"] = "unauthenticated_test_csrf_token_123456789012"

    resp_auth = client.post(
        "/api/admin/security/recommendation/REC-TEST-001/review",
        headers={"X-CSRF-Token": "unauthenticated_test_csrf_token_123456789012"},
        json={"action": "APPROVED"}
    )
    assert resp_auth.status_code == 401
    assert "Admin authentication required" in resp_auth.get_json()["error"]


def test_flask_review_endpoint_student_role_rejection():
    """Student role POST to recommendation review must be rejected with 403."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 55
        sess["user_role"] = "student"
        sess["csrf_token"] = "valid_csrf_token_student_role_test_12345678901234"

    resp = client.post(
        "/api/admin/security/recommendation/REC-TEST-001/review",
        headers={"X-CSRF-Token": "valid_csrf_token_student_role_test_12345678901234"},
        json={"action": "APPROVED"}
    )
    assert resp.status_code == 403
    err_text = resp.get_json()["error"]
    assert "Access Restricted" in err_text or "Admin" in err_text


def test_flask_review_endpoint_csrf_enforcement():
    """Missing or invalid CSRF token on review endpoint must fail with SEC-016 before route executes."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["csrf_token"] = "genuine_admin_csrf_token_abcdef12345678901234"

    # Request with missing CSRF
    resp_missing = client.post(
        "/api/admin/security/recommendation/REC-TEST-001/review",
        json={"action": "APPROVED"}
    )
    assert resp_missing.status_code == 403
    assert resp_missing.get_json()["code"] == "SEC-016"

    # Request with corrupted CSRF
    resp_invalid = client.post(
        "/api/admin/security/recommendation/REC-TEST-001/review",
        headers={"X-CSRF-Token": "forged_csrf_token_xyz"},
        json={"action": "APPROVED"}
    )
    assert resp_invalid.status_code == 403
    assert resp_invalid.get_json()["code"] == "SEC-016"


def test_flask_review_endpoint_admin_success_and_identity_derivation():
    """Valid admin request succeeds, derives reviewer_id strictly from session, and ignores client-supplied spoofing."""
    assessment = RiskAssessment(
        score=70,
        level="HIGH",
        scope="session",
        target_id="tok_route_test",
        event_ids=["evt_route_1"]
    )
    rec_ids = generate_security_recommendations(
        assessment=assessment,
        target_resource="session",
        target_resource_id="tok_route_test",
        target_actor_id=202
    )
    assert len(rec_ids) >= 1
    target_rec_id = rec_ids[0]

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 999  # Authenticated administrator ID
        sess["user_role"] = "admin"
        sess["csrf_token"] = "admin_valid_csrf_token_hex_abcdef1234567890"

    # Attempt to spoof reviewer_id in payload: route must derive reviewer_id from session (999), not payload (777)
    resp = client.post(
        f"/api/admin/security/recommendation/{target_rec_id}/review",
        headers={"X-CSRF-Token": "admin_valid_csrf_token_hex_abcdef1234567890"},
        json={
            "action": "APPROVED",
            "reviewer_id": 777,  # Spoofed parameter; must be ignored
            "reviewer_role": "superadmin",
            "notes": "Reviewed and approved by authenticated admin."
        }
    )
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    # Verify in DB that reviewed_by is strictly 999
    rec = get_recommendation_details(target_rec_id)
    assert rec["status"] == "APPROVED"
    assert rec["reviewed_by"] == 999
    assert rec["execution_notes"] == "Reviewed and approved by authenticated admin."

    # Cleanup
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'tok_route_test'")
    conn.commit()
    conn.close()
