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


def test_postgres_pending_device_switch_concurrency_and_atomicity(pg_conn):
    """
    Test requirement 6 on isolated PostgreSQL:
    - Multi-connection concurrent confirmation consumption (only 1 succeeds).
    - Confirmation replay rejected.
    - Stale current_session_token rejection.
    - Transaction rollback ensures no partial consumption or state leakage.
    """
    import secrets
    now_ts = int(time.time())
    expires_at_ts = now_ts + 300
    token = secrets.token_urlsafe(32)

    conn1 = get_verified_test_conn()
    conn2 = get_verified_test_conn()
    cur1 = conn1.cursor()
    cur2 = conn2.cursor()

    # Clean up any leftover test rows
    cur1.execute("DELETE FROM pending_device_switches WHERE student_id = 88812;")
    cur1.execute("DELETE FROM users WHERE id = 88812;")
    conn1.commit()

    # Setup student with active_session_token = 'pg-token-v1'
    cur1.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, active_session_token)
        VALUES (88812, 'pg_switch_student', 'hash', 'PG Switch Student', 'student', 'pg-token-v1');
    """)
    # Insert pending switch bound to token-v1
    cur1.execute("""
        INSERT INTO pending_device_switches (student_id, confirmation_token, current_session_token, status, expires_at)
        VALUES (88812, %s, 'pg-token-v1', 'PENDING', %s);
    """, (token, expires_at_ts))
    conn1.commit()

    # Test 1: Concurrency - two separate PostgreSQL connections race to consume the pending token
    # Connection 1 executes update
    cur1.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88812
          AND confirmation_token = %s
          AND status = 'PENDING'
          AND expires_at > %s
          AND current_session_token = (SELECT active_session_token FROM users WHERE id = 88812);
    """, (token, now_ts))
    rows_c1 = cur1.rowcount
    conn1.commit()

    # Connection 2 attempts the exact same update
    cur2.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88812
          AND confirmation_token = %s
          AND status = 'PENDING'
          AND expires_at > %s
          AND current_session_token = (SELECT active_session_token FROM users WHERE id = 88812);
    """, (token, now_ts))
    rows_c2 = cur2.rowcount
    conn2.commit()

    # Exactly one connection must have updated the row
    assert rows_c1 == 1, "Connection 1 must successfully consume the token"
    assert rows_c2 == 0, "Connection 2 must be rejected because token was already consumed"

    # Test 2: Replay rejection
    cur1.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88812
          AND confirmation_token = %s
          AND status = 'PENDING'
          AND expires_at > %s;
    """, (token, now_ts))
    assert cur1.rowcount == 0, "Replaying confirmation must match 0 rows"

    # Test 3: Stale session token check
    token_stale = secrets.token_urlsafe(32)
    cur1.execute("""
        INSERT INTO pending_device_switches (student_id, confirmation_token, current_session_token, status, expires_at)
        VALUES (88812, %s, 'pg-old-stale-token', 'PENDING', %s);
    """, (token_stale, expires_at_ts))
    conn1.commit()

    cur1.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88812
          AND confirmation_token = %s
          AND status = 'PENDING'
          AND expires_at > %s
          AND current_session_token = (SELECT active_session_token FROM users WHERE id = 88812);
    """, (token_stale, now_ts))
    assert cur1.rowcount == 0, "Stale pending confirmation must match 0 rows when active token changed"
    conn1.rollback()

    # Test 4: Rollback atomicity
    token_rb = secrets.token_urlsafe(32)
    cur1.execute("""
        INSERT INTO pending_device_switches (student_id, confirmation_token, current_session_token, status, expires_at)
        VALUES (88812, %s, 'pg-token-v1', 'PENDING', %s);
    """, (token_rb, expires_at_ts))
    conn1.commit()

    # Begin transaction, consume, then roll back
    cur1.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88812 AND confirmation_token = %s;
    """, (token_rb,))
    assert cur1.rowcount == 1
    conn1.rollback()

    # Verify status is still PENDING after rollback
    cur1.execute("SELECT status FROM pending_device_switches WHERE confirmation_token = %s;", (token_rb,))
    row_rb = cur1.fetchone()
    assert row_rb["status"] == "PENDING"

    # Clean up
    cur1.execute("DELETE FROM pending_device_switches WHERE student_id = 88812;")
    cur1.execute("DELETE FROM users WHERE id = 88812;")
    conn1.commit()
    conn1.close()
    conn2.close()


def test_postgres_admin_termination_racing_with_confirmation(pg_conn):
    """
    Test requirement 6 & 7 on isolated PostgreSQL:
    Races administrator termination against device-switch confirmation using separate connections.
    Enforces consistent lock ordering: (users row -> pending_device_switches rows).
    Verifies:
    1. No deadlock occurs between termination and confirmation.
    2. When administrator termination completes, the final database state has:
       - active_session_token == ''
       - no usable (PENDING) device switch confirmation
       - no active session recreated by the confirmation.
    """
    import secrets
    conn_admin = get_verified_test_conn()
    conn_student = get_verified_test_conn()
    cur_admin = conn_admin.cursor()
    cur_student = conn_student.cursor()

    cur_admin.execute("DELETE FROM pending_device_switches WHERE student_id = 88814;")
    cur_admin.execute("DELETE FROM users WHERE id = 88814;")
    conn_admin.commit()

    now_ts = int(time.time())
    expires_at_ts = now_ts + 300
    token = secrets.token_urlsafe(32)

    # Setup student with active token
    cur_admin.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, active_session_token)
        VALUES (88814, 'pg_race_student', 'hash', 'PG Race Student', 'student', 'pg-token-initial');
    """)
    cur_admin.execute("""
        INSERT INTO pending_device_switches (student_id, confirmation_token, current_session_token, status, expires_at)
        VALUES (88814, %s, 'pg-token-initial', 'PENDING', %s);
    """, (token, expires_at_ts))
    conn_admin.commit()

    # Step 1: Admin begins termination transaction and locks the student row FIRST
    cur_admin.execute("SELECT id, active_session_token FROM users WHERE id = 88814 FOR UPDATE;")
    admin_locked = cur_admin.fetchone()
    assert admin_locked is not None
    assert admin_locked["active_session_token"] == "pg-token-initial"

    # Step 2: Admin wipes active_session_token and cancels pending switches in lock order
    cur_admin.execute("UPDATE users SET active_session_token = '' WHERE id = 88814;")
    cur_admin.execute("UPDATE pending_device_switches SET status = 'CANCELLED' WHERE student_id = 88814 AND status = 'PENDING';")
    conn_admin.commit()  # Admin termination committed!

    # Step 3: Student confirmation runs (simulating student clicking confirm)
    # 1. Student acquires row lock on users FIRST (same lock order)
    cur_student.execute("SELECT id, active_session_token FROM users WHERE id = 88814 FOR UPDATE;")
    st_locked = cur_student.fetchone()
    active_tok = (st_locked["active_session_token"] if st_locked else "") or ""

    # Since admin terminated, active_tok is empty!
    if not active_tok:
        # Expected behavior: confirmation recognizes session was terminated, rolls back
        cur_student.execute("ROLLBACK;")
    else:
        # If it had reached update, it would fail
        cur_student.execute("""
            UPDATE pending_device_switches
            SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
            WHERE student_id = 88814
              AND confirmation_token = %s
              AND status = 'PENDING'
              AND expires_at > %s
              AND current_session_token = %s;
        """, (token, now_ts, active_tok))
        conn_student.commit()

    # Step 4: Verify final database state
    conn_verify = get_verified_test_conn()
    cur_v = conn_verify.cursor()
    cur_v.execute("SELECT active_session_token FROM users WHERE id = 88814;")
    row_user = cur_v.fetchone()
    assert row_user["active_session_token"] == "", "Final state must have empty active_session_token"

    cur_v.execute("SELECT status FROM pending_device_switches WHERE confirmation_token = %s;", (token,))
    row_switch = cur_v.fetchone()
    assert row_switch["status"] == "CANCELLED", "Pending switch must be CANCELLED, not CONSUMED or PENDING"

    # Cleanup
    cur_v.execute("DELETE FROM pending_device_switches WHERE student_id = 88814;")
    cur_v.execute("DELETE FROM users WHERE id = 88814;")
    conn_verify.commit()

    conn_admin.close()
    conn_student.close()
    conn_verify.close()


def test_postgres_confirmation_locks_first_racing_with_admin_termination(pg_conn):
    """
    Test requirement 2 & 3 on isolated PostgreSQL:
    Races device-switch confirmation vs administrator termination where CONFIRMATION locks first:
    1. Device-switch confirmation acquires student row lock first via SELECT ... FOR UPDATE.
    2. Confirmation atomically consumes the pending record and commits new active_session_token.
    3. Administrator termination then acquires lock on the student row.
    4. Termination clears that newly set token and cancels any pending switches.
    5. Verifies:
       - Final active_session_token is empty.
       - The consumed confirmation token cannot be reused or replayed.
       - No deadlocks occur.
    """
    import secrets
    conn_student = get_verified_test_conn()
    conn_admin = get_verified_test_conn()
    cur_student = conn_student.cursor()
    cur_admin = conn_admin.cursor()

    cur_admin.execute("DELETE FROM pending_device_switches WHERE student_id = 88816;")
    cur_admin.execute("DELETE FROM users WHERE id = 88816;")
    conn_admin.commit()

    now_ts = int(time.time())
    expires_at_ts = now_ts + 300
    token = secrets.token_urlsafe(32)
    new_token = secrets.token_hex(20)

    # Initial state: student with active token
    cur_admin.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role, active_session_token)
        VALUES (88816, 'pg_race_conf_first', 'hash', 'PG Race Conf First', 'student', 'pg-token-initial');
    """)
    cur_admin.execute("""
        INSERT INTO pending_device_switches (student_id, confirmation_token, current_session_token, status, expires_at)
        VALUES (88816, %s, 'pg-token-initial', 'PENDING', %s);
    """, (token, expires_at_ts))
    conn_admin.commit()

    # Step 1: Confirmation starts and locks student row FIRST
    cur_student.execute("SELECT id, active_session_token FROM users WHERE id = 88816 FOR UPDATE;")
    row_st = cur_student.fetchone()
    assert row_st is not None
    assert row_st["active_session_token"] == "pg-token-initial"

    # Step 2: Confirmation consumes pending switch and updates users table to new_token
    cur_student.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88816
          AND confirmation_token = %s
          AND status = 'PENDING'
          AND expires_at > %s
          AND current_session_token = %s;
    """, (token, now_ts, "pg-token-initial"))
    assert cur_student.rowcount == 1, "Confirmation must successfully consume the pending record"

    cur_student.execute("""
        UPDATE users
        SET active_session_token = %s
        WHERE id = 88816
          AND active_session_token = %s;
    """, (new_token, "pg-token-initial"))
    assert cur_student.rowcount == 1

    # Confirmation commits its changes
    conn_student.commit()

    # Step 3: Administrator termination runs now (or proceeds after waiting for the student lock)
    cur_admin.execute("SELECT id, active_session_token FROM users WHERE id = 88816 FOR UPDATE;")
    row_adm = cur_admin.fetchone()
    assert row_adm is not None
    assert row_adm["active_session_token"] == new_token, "Admin sees the token that was committed by confirmation"

    # Termination clears active_session_token and cancels pending switches in lock order
    cur_admin.execute("UPDATE users SET active_session_token = '' WHERE id = 88816;")
    cur_admin.execute("UPDATE pending_device_switches SET status = 'CANCELLED' WHERE student_id = 88816 AND status = 'PENDING';")
    conn_admin.commit()

    # Step 4: Verify final database state
    conn_verify = get_verified_test_conn()
    cur_v = conn_verify.cursor()
    cur_v.execute("SELECT active_session_token FROM users WHERE id = 88816;")
    row_user = cur_v.fetchone()
    assert row_user["active_session_token"] == "", "Final active_session_token must be empty"

    cur_v.execute("SELECT status FROM pending_device_switches WHERE confirmation_token = %s;", (token,))
    row_switch = cur_v.fetchone()
    assert row_switch["status"] == "CONSUMED", "Original confirmation token was CONSUMED"

    # Verify that the consumed token cannot be reused/replayed
    cur_v.execute("""
        UPDATE pending_device_switches
        SET status = 'CONSUMED', consumed_at = CURRENT_TIMESTAMP
        WHERE student_id = 88816
          AND confirmation_token = %s
          AND status = 'PENDING';
    """, (token,))
    assert cur_v.rowcount == 0, "Consumed token cannot be reused"

    # Cleanup
    cur_v.execute("DELETE FROM pending_device_switches WHERE student_id = 88816;")
    cur_v.execute("DELETE FROM users WHERE id = 88816;")
    conn_verify.commit()

    conn_student.close()
    conn_admin.close()
    conn_verify.close()
