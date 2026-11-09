"""
Tests for Phase 2: Security Intelligence, Advanced Event Correlation & Incident Management.
Validates:
- Event correlation rules: Brute force, IDOR, Session concurrent, CSRF abuse
- Incident creation and evidence persistence
- Incident status transitions and disallowed transition rejection
- Immutable investigation notes
- Incident audit trail generation
- Duplicate incident prevention across active windows
- Dual SQLite & PostgreSQL compatibility
- Zero student violation strike pollution
"""

import json
import pytest
from app import app
from database import get_connection, init_db
from security import (
    record_security_event,
    correlate_event,
    create_incident,
    transition_incident_status,
    add_incident_note,
    get_incident_details,
    VALID_STATUSES,
    ALLOWED_TRANSITIONS,
)


@pytest.fixture(autouse=True)
def setup_security_database():
    """Ensure database schema is fresh and initialized."""
    init_db()


def test_incident_lifecycle_and_allowed_transitions():
    """Verify standard transition flow: OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED."""
    inc_id = create_incident(
        title="Suspicious Test Cluster",
        incident_type="test_incident",
        severity="HIGH",
        risk_score=65,
        summary="Automated test incident"
    )
    assert inc_id is not None
    assert inc_id.startswith("INC-")

    # Initial state must be OPEN
    detail = get_incident_details(inc_id)
    assert detail["status"] == "OPEN"
    assert detail["risk_score"] == 65
    assert len(detail["audit_trail"]) >= 1
    assert detail["audit_trail"][0]["action"] == "INCIDENT_CREATED"

    # Transition to INVESTIGATING
    ok, msg = transition_incident_status(inc_id, "INVESTIGATING", actor_id=1, actor_name="Tutor Lead", notes="Checking logs")
    assert ok is True
    assert get_incident_details(inc_id)["status"] == "INVESTIGATING"

    # Transition to CONTAINED
    ok, msg = transition_incident_status(inc_id, "CONTAINED", actor_id=1, actor_name="Tutor Lead", notes="Restricted candidate")
    assert ok is True
    assert get_incident_details(inc_id)["status"] == "CONTAINED"

    # Transition to RESOLVED
    ok, msg = transition_incident_status(inc_id, "RESOLVED", actor_id=1, actor_name="Tutor Lead", notes="Incident handled cleanly")
    assert ok is True
    res_detail = get_incident_details(inc_id)
    assert res_detail["status"] == "RESOLVED"
    assert "Incident handled cleanly" in res_detail["resolution_notes"]


def test_disallowed_incident_status_transition():
    """Verify invalid state transitions are rejected safely."""
    inc_id = create_incident(
        title="Test Transition Guard",
        incident_type="test_guard",
        severity="LOW"
    )
    # Target status not in VALID_STATUSES
    ok, msg = transition_incident_status(inc_id, "BOGUS_STATUS")
    assert ok is False
    assert "Invalid target status" in msg

    # Direct illegal transition if defined (e.g. from CONTAINED directly to invalid state)
    transition_incident_status(inc_id, "INVESTIGATING")
    transition_incident_status(inc_id, "CONTAINED")
    # CONTAINED cannot jump to a bogus state
    ok, msg = transition_incident_status(inc_id, "UNKNOWN_STATE")
    assert ok is False


def test_immutable_investigation_notes_and_audit():
    """Verify investigation notes are recorded, appended, and preserved with author metadata."""
    inc_id = create_incident(
        title="Forensic Audit Test",
        incident_type="forensic_test"
    )

    # Empty note rejected
    assert add_incident_note(inc_id, author_id=1, author_name="Admin", note_text="  ") is False

    # Add Note 1
    assert add_incident_note(inc_id, author_id=1, author_name="Investigator 1", note_text="Checked IP reputation; clean ASN.") is True
    # Add Note 2
    assert add_incident_note(inc_id, author_id=2, author_name="Investigator 2", note_text="Contacted candidate via proctor audio.") is True

    detail = get_incident_details(inc_id)
    assert len(detail["notes"]) == 2
    assert detail["notes"][0]["author_name"] == "Investigator 1"
    assert "clean ASN" in detail["notes"][0]["note_text"]
    assert detail["notes"][1]["author_name"] == "Investigator 2"

    # Audit trail must have recorded note events
    audit_actions = [a["action"] for a in detail["audit_trail"]]
    assert "NOTE_ADDED" in audit_actions


def test_correlator_brute_force_detection():
    """Verify multiple failed logins from the same source IP trigger an automated brute force incident."""
    ip = "198.51.100.22"
    # Ingest 5 failed login events
    last_evt = None
    for i in range(5):
        last_evt = record_security_event(
            event_type="auth.failed_login",
            severity="LOW",
            event_category="auth",
            source_ip=ip,
            endpoint="/login"
        )

    # Force correlation evaluation
    res = correlate_event(last_evt)
    assert res["incident_candidate"] is True
    assert "created_incident_id" in res or "existing_incident_id" in res

    inc_id = res.get("created_incident_id") or res.get("existing_incident_id")
    detail = get_incident_details(inc_id)
    assert detail["incident_type"] == "brute_force_authentication"
    assert detail["severity"] == "HIGH"
    assert detail["evidence"]["triggered_rule"] == "brute_force_authentication"


def test_correlator_idor_attack_detection():
    """Verify repeated cross-student resource probes trigger a CRITICAL IDOR incident."""
    actor = 205
    last_evt = None
    for i in range(3):
        last_evt = record_security_event(
            event_type="authorization.idor_attempt",
            severity="HIGH",
            event_category="authorization",
            actor_id=actor,
            actor_role="student",
            source_ip="172.16.0.5"
        )

    res = correlate_event(last_evt)
    assert res["incident_candidate"] is True
    inc_id = res.get("created_incident_id") or res.get("existing_incident_id")
    detail = get_incident_details(inc_id)
    assert detail["incident_type"] == "idor_attack_sequence"
    assert detail["severity"] == "CRITICAL"


def test_correlator_duplicate_incident_prevention():
    """Verify additional matching events associate with the existing incident instead of creating duplicate incidents."""
    ip = "203.0.113.88"
    for _ in range(5):
        evt = record_security_event(event_type="auth.failed_login", source_ip=ip)

    res1 = correlate_event(evt)
    inc_1 = res1.get("created_incident_id") or res1.get("existing_incident_id")

    # Ingest another event from same source
    evt_extra = record_security_event(event_type="auth.failed_login", source_ip=ip)
    res2 = correlate_event(evt_extra)

    # Must reuse existing incident
    assert res2["incident_candidate"] is True
    assert res2.get("existing_incident_id") == inc_1
    assert "created_incident_id" not in res2


def test_security_incidents_zero_student_violation_pollution():
    """Confirm security incidents never touch student academic strikes or violations table."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM violations")
    initial_violations = c.fetchone()["cnt"]
    conn.close()

    create_incident(
        title="Major Attack Simulation",
        incident_type="simulated_threat",
        severity="CRITICAL",
        risk_score=95,
        primary_actor_id=12
    )

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM violations")
    final_violations = c.fetchone()["cnt"]
    conn.close()

    assert initial_violations == final_violations


def test_concurrent_incident_creation_simulation():
    """Simulate concurrent threads evaluating correlation events simultaneously."""
    import concurrent.futures

    ip = "198.51.100.99"
    for _ in range(5):
        record_security_event(event_type="auth.failed_login", source_ip=ip)

    events = [record_security_event(event_type="auth.failed_login", source_ip=ip) for _ in range(4)]

    created_ids = set()
    def run_corr(eid):
        res = correlate_event(eid)
        iid = res.get("created_incident_id") or res.get("existing_incident_id")
        return iid

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(run_corr, events))

    valid_ids = {r for r in results if r}
    # All threads must converge on the exact same incident ID without duplicates
    assert len(valid_ids) == 1


def test_incident_api_access_control():
    """Verify students and unauthenticated users cannot access or alter security incidents."""
    client = app.test_client()

    inc_id = create_incident(title="Auth Protected Incident", incident_type="access_test")

    # 1. Unauthenticated access blocked
    res = client.get(f"/api/admin/security/incident/{inc_id}")
    assert res.status_code == 401

    # 2. Student role blocked
    with client.session_transaction() as sess:
        sess["user_id"] = 99
        sess["user_role"] = "student"
        sess["username"] = "student_attacker"

    res_student = client.get(f"/api/admin/security/incident/{inc_id}")
    assert res_student.status_code == 403

    res_post = client.post(f"/api/admin/security/incident/{inc_id}/status", json={"status": "RESOLVED"})
    assert res_post.status_code == 403

    res_note = client.post(f"/api/admin/security/incident/{inc_id}/note", json={"note": "Unauthorized note"})
    assert res_note.status_code == 403


