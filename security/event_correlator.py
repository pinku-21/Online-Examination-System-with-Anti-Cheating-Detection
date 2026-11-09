"""
Advanced Event Correlation Engine for ExamGuard AI.
Performs time-window correlation across security events to detect:
1. Brute-force authentication & credential stuffing
2. Suspicious session transitions & concurrent logins
3. Authorization & IDOR attack probes
4. CSRF and API abuse sequences

Generates structured incidents with linked evidence without duplicate creation.
"""

import json
import logging
from datetime import datetime, timezone
from database import get_connection
from .incident_manager import create_incident
from .risk_engine import calculate_risk_score

logger = logging.getLogger("examguard.security.correlator")

# Configurable Correlation Thresholds
CORRELATION_THRESHOLDS = {
    "brute_force_failed_logins": 5,        # 5 failures from same IP or account in window
    "concurrent_session_attempts": 3,      # 3 concurrent session attempts in window
    "unusual_device_switches": 3,          # 3 device switch requests in window
    "idor_attempts": 3,                    # 3 IDOR attempts in window
    "csrf_failures": 4,                    # 4 CSRF failures from same origin/IP
}


def get_correlation_window_events(
    source_ip: str | None = None,
    actor_id: int | None = None,
    window_minutes: int = 15,
    conn=None,
) -> list[dict]:
    """
    Retrieves recent security events for a specific IP or actor within a sliding time window.
    """
    if not source_ip and not actor_id:
        return []

    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        query = """
            SELECT event_id, event_type, severity, actor_id, actor_role,
                   source_ip, endpoint, event_category, timestamp, details_json
            FROM security_events
            WHERE (source_ip = ? OR (? IS NOT NULL AND actor_id = ?))
            ORDER BY id DESC
            LIMIT 50
        """
        cursor.execute(query, (source_ip, actor_id, actor_id))
        rows = cursor.fetchall()

        events = []
        for r in rows:
            if isinstance(r, dict):
                ev = dict(r)
            else:
                ev = {
                    "event_id": r[0],
                    "event_type": r[1],
                    "severity": r[2],
                    "actor_id": r[3],
                    "actor_role": r[4],
                    "source_ip": r[5],
                    "endpoint": r[6],
                    "event_category": r[7],
                    "timestamp": r[8],
                    "details_json": r[9],
                }
            if isinstance(ev.get("details_json"), str):
                try:
                    ev["details"] = json.loads(ev["details_json"])
                except Exception:
                    ev["details"] = {}
            events.append(ev)
        return events
    except Exception as e:
        logger.error("Error retrieving correlation window events: %s", e)
        return []
    finally:
        if close_after:
            conn.close()


def check_existing_open_incident(incident_type: str, source_ip: str | None, actor_id: int | None, conn=None) -> str | None:
    """
    Checks if there is already an active (OPEN or INVESTIGATING) incident for this pattern
    to prevent alert flooding and duplicate incident generation.
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT incident_id FROM security_incidents
            WHERE incident_type = ? AND status IN ('OPEN', 'INVESTIGATING')
              AND ((? IS NOT NULL AND source_ip = ?) OR (? IS NOT NULL AND primary_actor_id = ?))
            LIMIT 1
            """,
            (incident_type, source_ip, source_ip, actor_id, actor_id),
        )
        row = cursor.fetchone()
        if row:
            return row["incident_id"] if isinstance(row, dict) else row[0]
        return None
    except Exception as e:
        logger.error("Error checking open incident: %s", e)
        return None
    finally:
        if close_after:
            conn.close()


def correlate_event(event_id: str, conn=None) -> dict:
    """
    Evaluates the newly ingested event against sliding-window detection rules.
    If a correlation threshold is met and no open incident exists, generates a security incident.
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
        current_event = cursor.fetchone()
        if not current_event:
            return {"event_id": event_id, "correlated_events_count": 0, "incident_candidate": False}

        current_event = dict(current_event)
        source_ip = current_event.get("source_ip")
        actor_id = current_event.get("actor_id")
        actor_role = current_event.get("actor_role")
        event_type = current_event.get("event_type")

        # Retrieve window events
        window_events = get_correlation_window_events(source_ip=source_ip, actor_id=actor_id, conn=conn)

        # Count event types in window
        counts = {}
        for ev in window_events:
            et = ev.get("event_type")
            counts[et] = counts.get(et, 0) + 1

        triggered_rule = None
        incident_title = None
        incident_sev = "MEDIUM"

        # Rule A: Brute Force Authentication
        failed_count = counts.get("auth.failed_login", 0) + counts.get("auth.repeated_failed_login", 0)
        if failed_count >= CORRELATION_THRESHOLDS["brute_force_failed_logins"]:
            triggered_rule = "brute_force_authentication"
            incident_title = f"Repeated Authentication Failures ({failed_count} attempts)"
            incident_sev = "HIGH"

        # Rule B: Suspicious Session / Device Switching
        elif counts.get("auth.concurrent_session_attempt", 0) >= CORRELATION_THRESHOLDS["concurrent_session_attempts"]:
            triggered_rule = "suspicious_concurrent_sessions"
            incident_title = "Multiple Concurrent Exam Session Attempts"
            incident_sev = "MEDIUM"
        elif counts.get("auth.unusual_device_switch", 0) >= CORRELATION_THRESHOLDS["unusual_device_switches"]:
            triggered_rule = "frequent_device_switches"
            incident_title = "Repeated Rapid Device Switch Requests"
            incident_sev = "MEDIUM"

        # Rule C: Authorization & IDOR Probing
        elif counts.get("authorization.idor_attempt", 0) >= CORRELATION_THRESHOLDS["idor_attempts"]:
            triggered_rule = "idor_attack_sequence"
            incident_title = "Repeated Cross-Student Resource Access Probes (IDOR)"
            incident_sev = "CRITICAL"

        # Rule D: CSRF Abuse
        elif (counts.get("csrf.validation_failed", 0) + counts.get("csrf.origin_mismatch", 0)) >= CORRELATION_THRESHOLDS["csrf_failures"]:
            triggered_rule = "repeated_csrf_failures"
            incident_title = "Multiple Cross-Origin / CSRF Validation Failures"
            incident_sev = "HIGH"

        if triggered_rule:
            existing_inc_id = check_existing_open_incident(triggered_rule, source_ip, actor_id, conn=conn)
            if existing_inc_id:
                # Update last_activity on existing incident instead of creating a duplicate
                cursor.execute(
                    "UPDATE security_incidents SET last_activity = CURRENT_TIMESTAMP WHERE incident_id = ?",
                    (existing_inc_id,),
                )
                conn.commit()
                return {
                    "event_id": event_id,
                    "correlated_events_count": len(window_events),
                    "incident_candidate": True,
                    "existing_incident_id": existing_inc_id,
                    "correlation_summary": f"Associated with existing active incident '{existing_inc_id}'."
                }

            # Calculate deterministic risk score
            assessment = calculate_risk_score(window_events)
            evidence = {
                "triggered_rule": triggered_rule,
                "window_events_count": len(window_events),
                "event_counts": counts,
                "first_event_id": window_events[-1]["event_id"] if window_events else event_id,
                "latest_event_id": event_id,
                "risk_factors": [f.rationale for f in assessment.factors],
                "sample_event_ids": [ev["event_id"] for ev in window_events[:10]]
            }

            new_incident_id = create_incident(
                title=incident_title,
                incident_type=triggered_rule,
                severity=incident_sev,
                risk_score=assessment.score,
                primary_actor_id=actor_id,
                primary_actor_role=actor_role,
                source_ip=source_ip,
                summary=f"Automated correlation rule '{triggered_rule}' detected a cluster of {len(window_events)} related events.",
                evidence=evidence,
                conn=conn
            )

            return {
                "event_id": event_id,
                "correlated_events_count": len(window_events),
                "incident_candidate": True,
                "created_incident_id": new_incident_id,
                "correlation_summary": f"Generated new security incident '{new_incident_id}'."
            }

        return {
            "event_id": event_id,
            "correlated_events_count": len(window_events),
            "incident_candidate": False,
            "correlation_summary": "No threat correlation threshold exceeded."
        }

    except Exception as e:
        logger.error("Error during event correlation: %s", e)
        return {"event_id": event_id, "correlated_events_count": 0, "incident_candidate": False}
    finally:
        if close_after:
            conn.close()
