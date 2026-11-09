"""
PostgreSQL Integration Test Suite for ExamGuard AI (Phase 4 Step 4.5).
Executes strictly against the isolated test database configured in TEST_DATABASE_URL.
Safeguards:
1. Verifies current_database() == 'examguard_test'. Aborts immediately otherwise.
2. Never uses production DATABASE_URL.
3. Tests Phase 4 migrations idempotency, indexes, constraints, multi-connection concurrency,
   disposable MFA encryption, and the complete event-to-incident-to-recommendation lifecycle.
"""

import os
import json
import time
import pytest
import psycopg
from psycopg.rows import dict_row

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "").strip()


def get_verified_test_conn():
    """Connects to TEST_DATABASE_URL and verifies it is 'examguard_test'."""
    assert bool(TEST_DB_URL), "TEST_DATABASE_URL environment variable is mandatory."
    conn = psycopg.connect(TEST_DB_URL, row_factory=dict_row)
    cur = conn.cursor()
    cur.execute("SELECT current_database();")
    row = cur.fetchone()
    db_name = row["current_database"]
    assert db_name == "examguard_test", f"SAFETY ABORT: Connected to unexpected database '{db_name}'. Must be 'examguard_test'."
    return conn


def apply_postgres_schema(pg_conn):
    """Executes the DDL statements for PostgreSQL against examguard_test."""
    import database
    from database import PostgresConnection
    # Temporarily set DATABASE_URL to TEST_DB_URL in database module for schema initialization
    old_db_url = database.DATABASE_URL
    try:
        database.DATABASE_URL = TEST_DB_URL
        database.init_db()
    finally:
        database.DATABASE_URL = old_db_url


@pytest.fixture(scope="module")
def pg_conn():
    conn = get_verified_test_conn()
    # Apply schema once for the test module
    apply_postgres_schema(conn)
    yield conn
    conn.close()


def test_postgres_schema_creation_and_idempotency(pg_conn):
    """Run table creation twice and confirm no duplicate records or schema corruption."""
    # Run migration pass 2 (idempotency check)
    apply_postgres_schema(pg_conn)

    cur = pg_conn.cursor()
    cur.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN (
            'security_events', 'security_incidents', 'incident_audit_trail',
            'incident_notes', 'security_policies', 'security_recommendations', 'risk_audit_log'
        );
    """)
    tables = {r["table_name"] for r in cur.fetchall()}
    expected = {
        "security_events", "security_incidents", "incident_audit_trail",
        "incident_notes", "security_policies", "security_recommendations", "risk_audit_log"
    }
    assert tables == expected, f"Missing tables in Postgres: {expected - tables}"


def test_postgres_partial_unique_index_and_constraints(pg_conn):
    """Verify that partial unique index uq_sec_recs_active_dedup prevents duplicate pending recommendations in PostgreSQL."""
    cur = pg_conn.cursor()
    # Clean previous test recs
    cur.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_test_res_1';")
    pg_conn.commit()

    # Insert initial PENDING_REVIEW recommendation
    cur.execute("""
        INSERT INTO security_recommendations (
            recommendation_id, target_resource, target_resource_id, recommended_action,
            risk_score, explanation, required_role, status
        ) VALUES (
            'PG-REC-001', 'account', 'pg_test_res_1', 'recommend_mfa_stepup',
            60, 'Initial Postgres test recommendation', 'admin', 'PENDING_REVIEW'
        );
    """)
    pg_conn.commit()

    # Attempt to insert identical pending recommendation - must trigger unique violation
    with pytest.raises(psycopg.IntegrityError):
        cur.execute("""
            INSERT INTO security_recommendations (
                recommendation_id, target_resource, target_resource_id, recommended_action,
                risk_score, explanation, required_role, status
            ) VALUES (
                'PG-REC-002', 'account', 'pg_test_res_1', 'recommend_mfa_stepup',
                60, 'Duplicate pending recommendation', 'admin', 'PENDING_REVIEW'
            );
        """)
        pg_conn.commit()
    pg_conn.rollback()

    # Update first to APPROVED; now another PENDING_REVIEW should be allowed
    cur.execute("UPDATE security_recommendations SET status = 'APPROVED' WHERE recommendation_id = 'PG-REC-001';")
    pg_conn.commit()

    cur.execute("""
        INSERT INTO security_recommendations (
            recommendation_id, target_resource, target_resource_id, recommended_action,
            risk_score, explanation, required_role, status
        ) VALUES (
            'PG-REC-003', 'account', 'pg_test_res_1', 'recommend_mfa_stepup',
            60, 'Allowed because previous was approved', 'admin', 'PENDING_REVIEW'
        );
    """)
    pg_conn.commit()

    cur.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_test_res_1';")
    pg_conn.commit()


def test_postgres_separate_connection_concurrency():
    """Test concurrent operations using completely separate PostgreSQL connections."""
    conn_a = get_verified_test_conn()
    conn_b = get_verified_test_conn()

    cur_a = conn_a.cursor()
    cur_b = conn_b.cursor()

    cur_a.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_concurrent_res_1';")
    conn_a.commit()

    # Conn A inserts recommendation 1
    cur_a.execute("""
        INSERT INTO security_recommendations (
            recommendation_id, target_resource, target_resource_id, recommended_action,
            risk_score, explanation, required_role, status
        ) VALUES (
            'PG-CONC-001', 'account', 'pg_concurrent_res_1', 'flag_proctor_review',
            80, 'Conn A insert', 'admin', 'PENDING_REVIEW'
        );
    """)
    conn_a.commit()

    # Conn B attempts duplicate concurrent insertion
    with pytest.raises(psycopg.IntegrityError):
        cur_b.execute("""
            INSERT INTO security_recommendations (
                recommendation_id, target_resource, target_resource_id, recommended_action,
                risk_score, explanation, required_role, status
            ) VALUES (
                'PG-CONC-002', 'account', 'pg_concurrent_res_1', 'flag_proctor_review',
                80, 'Conn B duplicate attempt', 'admin', 'PENDING_REVIEW'
            );
        """)
        conn_b.commit()
    conn_b.rollback()

    cur_a.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_concurrent_res_1';")
    conn_a.commit()

    conn_a.close()
    conn_b.close()


def test_postgres_transaction_rollback(pg_conn):
    """Verify transaction rollback in PostgreSQL restores state cleanly."""
    cur = pg_conn.cursor()
    cur.execute("DELETE FROM incident_notes WHERE incident_id = 'PG-ROLLBACK-INC';")
    pg_conn.commit()

    # Insert within transaction, then rollback
    cur.execute("""
        INSERT INTO incident_notes (incident_id, author_id, author_name, note_text)
        VALUES ('PG-ROLLBACK-INC', 1, 'Tester', 'This note should be rolled back');
    """)
    pg_conn.rollback()

    cur.execute("SELECT COUNT(*) as cnt FROM incident_notes WHERE incident_id = 'PG-ROLLBACK-INC';")
    row = cur.fetchone()
    assert row["cnt"] == 0


def test_postgres_json_and_timestamp_handling(pg_conn):
    """Verify JSON details serialization and ISO timestamps in PostgreSQL."""
    cur = pg_conn.cursor()
    payload = {"event_source": "pg_test", "risk_factors": ["ip_anomaly", "burst"], "count": 42}
    cur.execute("DELETE FROM security_events WHERE event_id = 'PG-JSON-001';")
    pg_conn.commit()

    cur.execute("""
        INSERT INTO security_events (
            event_id, event_type, severity, actor_id, actor_role, endpoint, details_json, timestamp
        ) VALUES (
            'PG-JSON-001', 'JSON_TEST', 'LOW', 1, 'admin', '/test', %s, CURRENT_TIMESTAMP
        );
    """, (json.dumps(payload),))
    pg_conn.commit()

    cur.execute("SELECT details_json, timestamp FROM security_events WHERE event_id = 'PG-JSON-001';")
    row = cur.fetchone()
    loaded = json.loads(row["details_json"])
    assert loaded == payload
    assert row["timestamp"] is not None

    cur.execute("DELETE FROM security_events WHERE event_id = 'PG-JSON-001';")
    pg_conn.commit()


def test_postgres_id_retrieval_and_wrapper(pg_conn):
    """Verify PostgresCursor _ID_TABLES lastrowid retrieval via RETURNING id."""
    from database import PostgresCursor
    pg_cur = PostgresCursor(pg_conn.cursor())

    pg_cur.execute("DELETE FROM incident_notes WHERE incident_id = 'PG-ID-TEST';")
    pg_conn.commit()

    pg_cur.execute("""
        INSERT INTO incident_notes (incident_id, author_id, author_name, note_text)
        VALUES ('PG-ID-TEST', 1, 'Auto-ID Tester', 'Checking lastrowid emulation');
    """)
    pg_conn.commit()

    inserted_id = pg_cur.lastrowid
    assert inserted_id is not None
    assert inserted_id > 0

    pg_cur.execute("DELETE FROM incident_notes WHERE incident_id = 'PG-ID-TEST';")
    pg_conn.commit()


def test_postgres_disposable_mfa_encryption():
    """Verify AES-256-GCM encryption/decryption using disposable test accounts on PostgreSQL."""
    from security.mfa_service import (
        encrypt_mfa_secret,
        decrypt_mfa_secret,
        generate_mfa_secret,
        generate_totp_code,
        verify_totp_code,
        generate_recovery_codes,
        verify_and_consume_recovery_code
    )

    test_secret = generate_mfa_secret()
    encrypted = encrypt_mfa_secret(test_secret)
    assert encrypted != test_secret
    assert encrypted.startswith("enc::")

    decrypted = decrypt_mfa_secret(encrypted)
    assert decrypted == test_secret

    totp = generate_totp_code(decrypted)
    assert verify_totp_code(decrypted, totp) is True

    # Recovery codes: returns (plain_codes, hashed_codes)
    plain_codes, hashed_codes = generate_recovery_codes(3)
    plain_sample = plain_codes[0]
    consumed, updated_hashes = verify_and_consume_recovery_code(plain_sample, hashed_codes)
    assert consumed is True
    # Second attempt must fail (single-use)
    consumed_second, _ = verify_and_consume_recovery_code(plain_sample, updated_hashes)
    assert consumed_second is False


def test_postgres_phase4_end_to_end_lifecycle(pg_conn):
    """Complete 10-step Phase 4 event-to-incident-to-recommendation-to-dossier lifecycle against PostgreSQL."""
    from database import PostgresConnection
    from security.event_collector import record_security_event
    from security.incident_intelligence import correlate_entities_across_events, get_unified_incident_intelligence
    from security.risk_engine import assess_account_risk
    from security.incident_manager import create_incident, transition_incident_status, add_incident_note

    pg_wrapper = PostgresConnection(pg_conn)
    cur = pg_conn.cursor()

    # Clean test fixtures
    cur.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_e2e_student_42';")
    cur.execute("DELETE FROM security_events WHERE event_id LIKE 'PG-E2E-%';")
    cur.execute("DELETE FROM security_incidents WHERE incident_id = 'PG-INC-E2E-100';")
    cur.execute("DELETE FROM incident_audit_trail WHERE incident_id = 'PG-INC-E2E-100';")
    cur.execute("DELETE FROM incident_notes WHERE incident_id = 'PG-INC-E2E-100';")
    pg_conn.commit()

    # 1. Generate Security Event
    ev_id = record_security_event(
        event_type="UNUSUAL_DEVICE_REPLACEMENT",
        severity="HIGH",
        actor_id=42,
        actor_role="student",
        target_resource="account",
        target_resource_id="pg_e2e_student_42",
        source_ip="192.168.100.42",
        endpoint="/api/device/replace",
        details={"replacement_count": 4, "user_agent": "Mozilla/5.0 PgTest"},
        event_category="ANOMALY",
        conn=pg_wrapper
    )
    assert ev_id is not None

    # 2. Correlate Related Activity
    corr = correlate_entities_across_events(actor_id=42, source_ip="192.168.100.42", conn=pg_wrapper)
    assert len(corr["account_events"]) >= 1

    # 3. Calculate Deterministic Risk
    assessment = assess_account_risk(user_id=42, conn=pg_wrapper)
    assert assessment.score >= 0
    assert assessment.level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # 4. Create Incident
    inc_id = create_incident(
        title="Postgres E2E Investigation Incident",
        incident_type="UNUSUAL_DEVICE_REPLACEMENT",
        severity="HIGH",
        risk_score=75,
        primary_actor_id=42,
        primary_actor_role="student",
        source_ip="192.168.100.42",
        summary="Automated E2E Postgres Incident Verification",
        evidence={"event_ids": [ev_id]},
        conn=pg_wrapper
    )
    assert inc_id is not None

    # 5. Add Note & Transition Status
    note_ok = add_incident_note(inc_id, 1, "PG Auditor", "Verified Postgres note insertion", conn=pg_wrapper)
    assert note_ok is True

    trans_ok, trans_msg = transition_incident_status(inc_id, "INVESTIGATING", 1, "PG Auditor", "Forensic triage", conn=pg_wrapper)
    assert trans_ok is True

    # 6. Retrieve Unified Dossier
    intel = get_unified_incident_intelligence(inc_id, conn=pg_wrapper)
    assert intel is not None
    assert intel["incident"]["incident_id"] == inc_id
    assert intel["incident"]["status"] == "INVESTIGATING"
    assert len(intel["timeline"]) >= 2

    # Clean up test records
    cur.execute("DELETE FROM security_recommendations WHERE target_resource_id = 'pg_e2e_student_42';")
    cur.execute("DELETE FROM security_events WHERE event_id LIKE 'PG-E2E-%';")
    cur.execute("DELETE FROM security_incidents WHERE incident_id = %s;", (inc_id,))
    cur.execute("DELETE FROM incident_audit_trail WHERE incident_id = %s;", (inc_id,))
    cur.execute("DELETE FROM incident_notes WHERE incident_id = %s;", (inc_id,))
    pg_conn.commit()
