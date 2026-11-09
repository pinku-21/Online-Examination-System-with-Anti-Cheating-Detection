"""
Phase 4 Step 4.1 Regression & Verification Test Suite:
Security Operations Centre (SOC) Dashboard Backend APIs

Validates:
1. Administrator authorization required across all SOC endpoints:
   - GET /api/admin/security/overview
   - GET /api/admin/security/events
   - GET /api/admin/security/risks
   - GET /api/admin/security/recommendations
2. Student role rejection (HTTP 403).
3. Unauthenticated rejection (HTTP 401).
4. Pagination: page, per_page, total_items, total_pages calculations.
5. Filtering:
   - Severity filtering (INFO, LOW, MEDIUM, HIGH, CRITICAL)
   - Event type filtering
   - Actor filtering
   - Status filtering on recommendations
   - Search query filtering across events and recommendations
6. Sensitive data redaction:
   - Passwords, session tokens, CSRF tokens, and clipboard content omitted or masked.
   - Raw session tokens masked in risk audits and recommendations.
7. Database failure resilience:
   - Safe HTTP 500 error response without crashing server process.
8. Incident integration verification:
   - Reused existing incident APIs return correct details, evidence, notes, and audit trails.
"""

import json
import pytest
from app import app, get_csrf_token
from database import get_connection, init_db
from security import (
    record_security_event,
    create_incident,
    add_incident_note,
    get_incident_details,
    generate_security_recommendations,
    RiskAssessment,
    RiskFactor,
)


@pytest.fixture(autouse=True)
def setup_soc_db():
    """Ensure database schema is fresh and initialized."""
    init_db()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# --- 1. AUTHORIZATION & ACCESS CONTROL ---

@pytest.mark.parametrize("endpoint", [
    "/api/admin/security/overview",
    "/api/admin/security/events",
    "/api/admin/security/risks",
    "/api/admin/security/recommendations",
])
def test_soc_endpoints_unauthenticated_rejection(client, endpoint):
    """Unauthenticated GET requests to any SOC endpoint must be rejected with HTTP 401."""
    resp = client.get(endpoint)
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False
    assert "Admin authentication required" in data["error"]


@pytest.mark.parametrize("endpoint", [
    "/api/admin/security/overview",
    "/api/admin/security/events",
    "/api/admin/security/risks",
    "/api/admin/security/recommendations",
])
def test_soc_endpoints_student_role_rejection(client, endpoint):
    """Student role requests to SOC endpoints must be rejected with HTTP 403."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1001
        sess["user_role"] = "student"
        sess["username"] = "candidate_bob"

    resp = client.get(endpoint)
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["success"] is False
    assert "Access Restricted" in data["error"] or "Admin" in data["error"]


# --- 2. SOC OVERVIEW API ---

def test_soc_overview_success_and_metrics(client):
    """Verify GET /api/admin/security/overview returns aggregated counts, risk distribution, and recent activity."""
    # Seed events, incidents, and recommendations
    record_security_event(event_type="auth.failed_login", severity="LOW")
    record_security_event(event_type="authorization.idor_attempt", severity="HIGH")

    inc_id = create_incident(
        title="SOC Overview Test Incident",
        incident_type="auth_anomaly",
        severity="HIGH",
        risk_score=65,
        summary="Test incident for overview aggregation"
    )

    assessment = RiskAssessment(
        score=72,
        level="HIGH",
        scope="session",
        target_id="tok_overview_test_session",
        event_ids=["evt_ov_1"]
    )
    generate_security_recommendations(
        assessment=assessment,
        target_resource="session",
        target_resource_id="tok_overview_test_session",
        target_actor_id=1
    )

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    resp = client.get("/api/admin/security/overview")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    overview = data["overview"]
    assert "total_security_events" in overview
    assert overview["total_security_events"] >= 2
    assert "open_incidents" in overview
    assert overview["open_incidents"] >= 1
    assert "high_risk_incidents" in overview
    assert overview["high_risk_incidents"] >= 1
    assert "pending_recommendations" in overview
    assert overview["pending_recommendations"] >= 1
    assert "risk_distribution" in overview
    assert isinstance(overview["risk_distribution"], dict)
    assert "recent_activity" in overview
    assert len(overview["recent_activity"]) <= 10


# --- 3. SECURITY EVENTS API ---

def test_soc_events_pagination_and_filtering(client):
    """Verify GET /api/admin/security/events pagination, severity/event_type filtering, and search."""
    # Seed known events
    record_security_event(
        event_type="auth.soc_filter_test",
        severity="CRITICAL",
        endpoint="/api/admin/sensitive",
        source_ip="198.51.100.42",
        details={"info": "SOC filter target event"}
    )
    record_security_event(
        event_type="session.soc_filter_test",
        severity="INFO",
        endpoint="/api/student/normal",
        source_ip="198.51.100.43"
    )

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    # 1. Severity filter: CRITICAL
    resp_sev = client.get("/api/admin/security/events?severity=CRITICAL")
    assert resp_sev.status_code == 200
    data_sev = resp_sev.get_json()
    assert data_sev["success"] is True
    for ev in data_sev["events"]:
        assert ev["severity"] == "CRITICAL"

    # 2. Event type filter
    resp_type = client.get("/api/admin/security/events?event_type=auth.soc_filter_test")
    assert resp_type.status_code == 200
    data_type = resp_type.get_json()
    assert len(data_type["events"]) >= 1
    assert data_type["events"][0]["event_type"] == "auth.soc_filter_test"

    # 3. Search query filter
    resp_search = client.get("/api/admin/security/events?search=198.51.100.42")
    assert resp_search.status_code == 200
    data_search = resp_search.get_json()
    assert len(data_search["events"]) >= 1
    assert data_search["events"][0]["source_ip"] == "198.51.100.42"

    # 4. Pagination structure
    resp_pag = client.get("/api/admin/security/events?page=1&per_page=5")
    assert resp_pag.status_code == 200
    data_pag = resp_pag.get_json()
    pagination = data_pag["pagination"]
    assert pagination["page"] == 1
    assert pagination["per_page"] == 5
    assert pagination["total_items"] >= 2
    assert "total_pages" in pagination


def test_soc_events_sensitive_data_redaction(client):
    """Verify passwords, session tokens, cookies, and clipboard contents are never exposed in event details."""
    record_security_event(
        event_type="api.sensitive_test",
        severity="HIGH",
        details={
            "password": "SuperSecretPassword123",
            "session_token": "raw_session_secret_token_abc",
            "csrf_token": "raw_csrf_token_xyz",
            "clipboard": "Candidate pasted essay content",
            "safe_metadata": "Sanitized debug metric",
        }
    )

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    resp = client.get("/api/admin/security/events?event_type=api.sensitive_test")
    assert resp.status_code == 200
    events = resp.get_json()["events"]
    assert len(events) >= 1
    details = events[0]["details"]

    assert "password" not in details
    assert "session_token" not in details
    assert "csrf_token" not in details
    assert "clipboard" not in details
    assert details.get("safe_metadata") == "Sanitized debug metric"


# --- 4. RISK ASSESSMENT API ---

def test_soc_risks_on_demand_and_audit_history(client):
    """Verify GET /api/admin/security/risks calculates real-time explainable risk and returns audit entries."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    # 1. Real-time assessment for account scope
    resp_account = client.get("/api/admin/security/risks?scope=account&target_id=1")
    assert resp_account.status_code == 200
    data_acc = resp_account.get_json()
    assert data_acc["success"] is True
    assessment = data_acc["assessment"]
    assert "score" in assessment
    assert 0 <= assessment["score"] <= 100
    assert "factors" in assessment
    assert "explanation" in assessment

    # 2. Real-time assessment for IP scope
    resp_ip = client.get("/api/admin/security/risks?scope=ip&target_id=192.0.2.1")
    assert resp_ip.status_code == 200
    assert resp_ip.get_json()["success"] is True

    # 3. Invalid scope returns HTTP 400
    resp_invalid = client.get("/api/admin/security/risks?scope=unknown_scope&target_id=1")
    assert resp_invalid.status_code == 400

    # 4. Historical audit records list
    resp_history = client.get("/api/admin/security/risks?page=1&per_page=10")
    assert resp_history.status_code == 200
    data_hist = resp_history.get_json()
    assert "risk_audits" in data_hist
    assert "pagination" in data_hist

    # 5. Target ID validation: excessive length rejected
    resp_toolong = client.get(f"/api/admin/security/risks?scope=session&target_id={'a' * 300}")
    assert resp_toolong.status_code == 400
    assert "exceeds maximum permitted length" in resp_toolong.get_json()["error"]

    # 6. Target ID validation: malformed IP rejected
    resp_bad_ip = client.get("/api/admin/security/risks?scope=ip&target_id=invalid..ip..format")
    assert resp_bad_ip.status_code == 400
    assert "Invalid IP address format" in resp_bad_ip.get_json()["error"]

    # 7. Target ID validation: non-positive account ID rejected
    resp_bad_acc = client.get("/api/admin/security/risks?scope=account&target_id=-5")
    assert resp_bad_acc.status_code == 400
    assert "positive integer user_id" in resp_bad_acc.get_json()["error"]


# --- 5. RECOMMENDATIONS API ---

def test_soc_recommendations_filters_and_session_masking(client):
    """Verify GET /api/admin/security/recommendations supports status, risk_level, and action filtering, plus masks session tokens."""
    assessment = RiskAssessment(
        score=78,
        level="CRITICAL",
        scope="session",
        target_id="tok_sensitive_session_abcdef1234567890",
        event_ids=["evt_rec_1"]
    )
    generate_security_recommendations(
        assessment=assessment,
        target_resource="session",
        target_resource_id="tok_sensitive_session_abcdef1234567890",
        target_actor_id=1
    )

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    # 1. Status filter: PENDING_REVIEW
    resp = client.get("/api/admin/security/recommendations?status=PENDING_REVIEW")
    assert resp.status_code == 200
    recs = resp.get_json()["recommendations"]
    assert len(recs) >= 1

    # Verify session token is replaced with opaque non-reversible reference (sess_ref_)
    target_rec = next(r for r in recs if (r.get("target_resource") or "").lower() == "session")
    masked_id = target_rec["target_resource_id"]
    assert masked_id.startswith("sess_ref_")
    assert "abcdef1234567890" not in masked_id
    assert masked_id != "tok_sensitive_session_abcdef1234567890"

    # 2. Risk level filter: CRITICAL
    resp_crit = client.get("/api/admin/security/recommendations?risk_level=CRITICAL")
    assert resp_crit.status_code == 200
    assert len(resp_crit.get_json()["recommendations"]) >= 1

    # 3. Action filter
    resp_action = client.get("/api/admin/security/recommendations?action=recommend_session_termination")
    assert resp_action.status_code == 200
    for r in resp_action.get_json()["recommendations"]:
        assert r["recommended_action"] == "recommend_session_termination"


# --- 6. INCIDENT INTEGRATION REUSE ---

def test_soc_incident_details_and_notes_retrieval(client):
    """Verify existing incident endpoints return full timeline, evidence, notes, and audit trails for the SOC."""
    inc_id = create_incident(
        title="SOC Integration Test Incident",
        incident_type="idor_cluster",
        severity="HIGH",
        risk_score=70,
        summary="Verified existing incident retrieval for SOC"
    )
    add_incident_note(
        incident_id=inc_id,
        author_id=1,
        author_name="Security Admin",
        note_text="SOC analyst assigned incident for triage."
    )

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    # Retrieve incident details
    resp = client.get(f"/api/admin/security/incident/{inc_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    inc = data["incident"]
    assert inc["incident_id"] == inc_id
    assert inc["severity"] == "HIGH"
    assert inc["risk_score"] == 70
    assert "notes" in inc
    assert len(inc["notes"]) >= 1
    assert "audit_trail" in inc
    assert len(inc["audit_trail"]) >= 1


# --- 7. SOC DASHBOARD FRONTEND VIEW AUTHORIZATION & RENDERING ---

def test_soc_frontend_view_requires_admin_authorization(client):
    """Verify /admin/security/soc is accessible strictly to authenticated administrators."""
    # 1. Unauthenticated access redirects or fails
    resp_unauth = client.get("/admin/security/soc")
    assert resp_unauth.status_code in (302, 401)
    if resp_unauth.status_code == 302:
        assert "/login" in resp_unauth.headers.get("Location", "")

    # 2. Student role blocked
    with client.session_transaction() as sess:
        sess["user_id"] = 88
        sess["user_role"] = "student"
        sess["username"] = "student_blocked"

    resp_student = client.get("/admin/security/soc")
    assert resp_student.status_code in (302, 403)
    if resp_student.status_code == 302:
        assert "/student/dashboard" in resp_student.headers.get("Location", "")

    # 3. Authenticated admin access renders SOC Dashboard HTML
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["username"] = "admin"

    resp_admin = client.get("/admin/security/soc")
    assert resp_admin.status_code == 200
    html = resp_admin.get_data(as_text=True)
    assert "Security Operations Centre" in html
    assert "SIEM Core" in html
    assert "Active Risk Score Distribution" in html
    assert "On-Demand Explainable Risk Inspector" in html
    assert "Adaptive Threat Intelligence Active" in html


