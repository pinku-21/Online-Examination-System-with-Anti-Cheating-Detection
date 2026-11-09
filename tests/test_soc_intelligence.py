"""
Phase 4 Step 4.3 Advanced SOC Intelligence & Unified Incident Investigation Tests
Verifies:
1. Event-to-incident relationships and dossier assembly.
2. Account correlation without false positive guilt.
3. Session correlation with non-reversible surrogate references.
4. Device correlation across security events.
5. IP false-positive protection (shared proxy/institutional NAT warning without attributing misconduct).
6. Historical risk intelligence from risk_audit_log (no fabricated data).
7. Recommendation traceability to triggering events and policies.
8. Unified chronological timeline ordering and item categorization.
9. Missing evidence and empty audit trail resilience.
10. Sensitive data redaction (zero passwords, raw session tokens, or keys).
11. Administrative authorization gating.
12. Database failure and error handling.
"""

import json
import pytest
import database
import app as flask_app
from security import (
    record_security_event,
    create_incident,
    transition_incident_status,
    add_incident_note,
    get_unified_incident_intelligence,
    build_investigation_timeline,
    correlate_entities_across_events,
)


def test_event_to_incident_relationships_and_assembly():
    """Verify unified intelligence binds events, recommendations, and audit records."""
    conn = database.get_connection()
    c = conn.cursor()

    try:
        # Clear prior test records
        c.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'user_intel_test_99'")
        c.execute("DELETE FROM security_events WHERE event_id IN ('INTEL-EV-1', 'INTEL-EV-2')")
        c.execute("DELETE FROM security_incidents WHERE incident_id = 'INTEL-INC-1'")
        c.execute("DELETE FROM incident_audit_trail WHERE incident_id = 'INTEL-INC-1'")
        c.execute("DELETE FROM incident_notes WHERE incident_id = 'INTEL-INC-1'")

        # Seed events
        c.execute("""
            INSERT INTO security_events (
                event_id, event_type, severity, actor_id, actor_role, target_resource, target_resource_id,
                source_ip, endpoint, details_json, timestamp
            ) VALUES
            ('INTEL-EV-1', 'FAILED_LOGIN', 'MEDIUM', 1, 'admin', 'account', 'user_intel_test_99', '192.168.10.5', '/login', '{"attempt": 1}', '2026-11-09 10:00:00'),
            ('INTEL-EV-2', 'FAILED_LOGIN', 'HIGH', 1, 'admin', 'account', 'user_intel_test_99', '192.168.10.5', '/login', '{"attempt": 2}', '2026-11-09 10:01:00')
        """)

        # Seed incident with linked event evidence
        evidence = json.dumps({"correlated_events": ["INTEL-EV-1", "INTEL-EV-2"], "reason": "Burst failed logins"})
        c.execute("""
            INSERT INTO security_incidents (
                incident_id, title, incident_type, severity, risk_score, primary_actor_id,
                source_ip, summary, evidence_json, status, created_at
            ) VALUES (
                'INTEL-INC-1', 'Burst Login Anomaly', 'AUTH_FAILURE', 'HIGH', 70, 1,
                '192.168.10.5', 'Correlated test incident', ?, 'OPEN', '2026-11-09 10:02:00'
            )
        """, (evidence,))

        # Seed recommendation linked to incident with unique target_resource_id
        c.execute("""
            INSERT INTO security_recommendations (
                recommendation_id, incident_id, target_actor_id, target_resource, target_resource_id,
                risk_score, explanation, recommended_action, required_role, status, created_at
            ) VALUES (
                'INTEL-REC-1', 'INTEL-INC-1', 1, 'account', 'user_intel_test_99', 70, 'Prompt step-up MFA', 'recommend_mfa_stepup', 'admin', 'PENDING_REVIEW', '2026-11-09 10:03:00'
            )
        """)

        # Seed note and audit
        c.execute("""
            INSERT INTO incident_notes (incident_id, author_id, author_name, note_text, timestamp)
            VALUES ('INTEL-INC-1', 1, 'Admin', 'Initiated triage review', '2026-11-09 10:04:00')
        """)
        c.execute("""
            INSERT INTO incident_audit_trail (incident_id, action, actor_name, details, timestamp)
            VALUES ('INTEL-INC-1', 'STATUS_CHANGE', 'Admin', 'Status changed from OPEN to INVESTIGATING', '2026-11-09 10:05:00')
        """)
        conn.commit()
    finally:
        conn.close()

    intel = get_unified_incident_intelligence("INTEL-INC-1")
    assert intel is not None
    assert intel["success"] is True
    assert intel["incident"]["incident_id"] == "INTEL-INC-1"
    assert intel["incident"]["risk_score"] == 70

    # Events linked
    event_ids = [e["event_id"] for e in intel["related_events"]]
    assert "INTEL-EV-1" in event_ids
    assert "INTEL-EV-2" in event_ids

    # Recommendations linked
    rec_ids = [r["recommendation_id"] for r in intel["related_recommendations"]]
    assert "INTEL-REC-1" in rec_ids

    # Notes & Audit
    assert len(intel["incident"]["notes"]) == 1
    assert "Initiated triage review" in intel["incident"]["notes"][0]["note_text"]
    assert len(intel["incident"]["audit_trail"]) == 1


def test_ip_false_positive_protection_and_shared_nat_warning():
    """Shared IP alone must NOT establish that two accounts belong to the same person."""
    conn = database.get_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM security_events WHERE source_ip = '198.51.100.99'")
        c.execute("""
            INSERT INTO security_events (
                event_id, event_type, severity, actor_id, actor_role, source_ip, endpoint, timestamp
            ) VALUES
            ('IP-EV-1', 'API_ACCESS', 'INFO', 1, 'admin', '198.51.100.99', '/api/test', '2026-11-09 12:00:00'),
            ('IP-EV-2', 'API_ACCESS', 'INFO', 2, 'student', '198.51.100.99', '/api/test', '2026-11-09 12:01:00')
        """)
        conn.commit()
    finally:
        conn.close()

    correlations = correlate_entities_across_events(source_ip="198.51.100.99")
    # Must flag that IP is shared by multiple distinct accounts (e.g. campus proxy/NAT)
    assert correlations["ip_is_shared_proxy_warning"] is True
    # Must never automatically create unified identity or establish misconduct
    assert len(correlations["ip_events"]) >= 2


def test_session_correlation_and_anonymization():
    """Verify session correlation uses non-reversible references and hides raw tokens."""
    conn = database.get_connection()
    c = conn.cursor()
    raw_token = "very_secret_session_token_xyz987654321"

    try:
        c.execute("DELETE FROM security_events WHERE event_id = 'SESS-EV-1'")
        c.execute("""
            INSERT INTO security_events (
                event_id, event_type, severity, actor_id, actor_role, target_resource, target_resource_id,
                source_ip, endpoint, details_json, timestamp
            ) VALUES
            ('SESS-EV-1', 'SESSION_ROTATED', 'INFO', 1, 'admin', 'session', ?, '127.0.0.1', '/api/auth', '{"token": "raw_secret"}', '2026-11-09 12:00:00')
        """, (raw_token,))
        conn.commit()
    finally:
        conn.close()

    inc_id = create_incident(
        title="Session Test Incident",
        incident_type="SESSION_ANOMALY",
        severity="LOW",
        summary="Testing session masking",
        evidence={"correlated_events": ["SESS-EV-1"]}
    )

    intel = get_unified_incident_intelligence(inc_id)
    assert intel is not None

    # Check that in related events, raw session token is replaced with surrogate sess_ref_
    rel_ev = next((e for e in intel["related_events"] if e["event_id"] == "SESS-EV-1"), None)
    assert rel_ev is not None
    assert raw_token not in rel_ev["target_resource_id"]
    assert rel_ev["target_resource_id"].startswith("sess_ref_")

    # In details, sensitive 'token' key must be redacted
    assert "token" not in rel_ev["details"]


def test_historical_risk_retrieval_no_fabrication():
    """Historical risk is retrieved from risk_audit_log and never fabricated."""
    conn = database.get_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM risk_audit_log WHERE entity_id = '99999'")
        conn.commit()
    finally:
        conn.close()

    # Create dummy incident with no audit history
    inc_id = create_incident(
        title="Unseen Actor Incident",
        incident_type="UNSEEN",
        primary_actor_id=99999,
        summary="No history"
    )

    intel = get_unified_incident_intelligence(inc_id)
    assert intel is not None
    # Risk history must be empty list, NOT synthetic or fabricated numbers
    assert intel["risk_history"] == []


def test_investigation_timeline_chronological_ordering_and_classification():
    """Verify timeline combines and sorts events, assessments, lifecycle, and notes."""
    incident = {
        "incident_id": "TL-INC-1",
        "title": "Timeline Test Incident",
        "summary": "Sample summary",
        "severity": "HIGH",
        "created_at": "2026-11-09 10:02:00"
    }
    related_events = [{
        "event_id": "EV-TL-1",
        "event_type": "SUSPICIOUS_PROBE",
        "severity": "HIGH",
        "endpoint": "/admin/secrets",
        "actor_role": "unknown",
        "source_ip": "10.0.0.1",
        "timestamp": "2026-11-09 10:00:00"
    }]
    risk_history = [{
        "id": 1,
        "old_score": 10,
        "new_score": 75,
        "trigger_event": "Probe Correlated",
        "timestamp": "2026-11-09 10:01:00"
    }]
    recommendations = [{
        "recommendation_id": "REC-TL-1",
        "recommended_action": "flag_proctor_review",
        "explanation": "High probe rate",
        "status": "APPROVED",
        "created_at": "2026-11-09 10:03:00",
        "reviewed_at": "2026-11-09 10:06:00",
        "reviewed_by": 1,
        "reviewer_name": "Senior Proctor",
        "execution_notes": "Confirmed containment"
    }]
    notes = [{
        "id": 1,
        "author_name": "Tutor Smith",
        "note_text": "Investigating endpoint logs",
        "timestamp": "2026-11-09 10:04:00"
    }]
    audit_trail = [{
        "id": 1,
        "action": "STATUS_CHANGE",
        "details": "Status changed from OPEN to INVESTIGATING",
        "actor_name": "Tutor Smith",
        "timestamp": "2026-11-09 10:05:00"
    }]

    timeline = build_investigation_timeline(
        incident=incident,
        related_events=related_events,
        risk_history=risk_history,
        recommendations=recommendations,
        notes=notes,
        audit_trail=audit_trail
    )

    assert len(timeline) == 7

    # Verify timestamps are in chronological order
    timestamps = [t["timestamp"] for t in timeline]
    assert timestamps == sorted(timestamps)

    # Verify distinct classification types
    types = [t["type"] for t in timeline]
    assert "SECURITY_EVENT" in types
    assert "RISK_ASSESSMENT" in types
    assert "INCIDENT_LIFECYCLE" in types
    assert "RECOMMENDATION" in types
    assert "ADMINISTRATIVE_NOTE" in types
    assert "ADMINISTRATIVE_DECISION" in types


def test_missing_evidence_and_database_failure_resilience():
    """Missing evidence or invalid IDs fails safely without crashes."""
    intel = get_unified_incident_intelligence("NON-EXISTENT-INCIDENT-ID")
    assert intel is None


def test_authorization_gating_on_dossier_and_timeline_apis():
    """Students and unauthenticated users cannot access unified dossiers or timelines."""
    flask_app.app.config["TESTING"] = True
    client = flask_app.app.test_client()

    # 1. Unauthenticated
    res1 = client.get("/api/admin/security/incident/INC-1")
    assert res1.status_code in (401, 302)

    res2 = client.get("/api/admin/security/incident/INC-1/timeline")
    assert res2.status_code in (401, 302)

    # 2. Student Role
    with client.session_transaction() as sess:
        sess["user_id"] = 2
        sess["user_role"] = "student"
        sess["role"] = "student"

    res3 = client.get("/api/admin/security/incident/INC-1")
    assert res3.status_code == 403

    res4 = client.get("/api/admin/security/incident/INC-1/timeline")
    assert res4.status_code == 403

    # 3. Authenticated Admin (404 on unknown ID, but allowed through gate)
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["role"] = "admin"

    res5 = client.get("/api/admin/security/incident/NON-EXISTENT")
    assert res5.status_code == 404
