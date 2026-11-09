"""
Incident Management Workflow for ExamGuard AI.
Implements incident creation, validated state transitions, timeline generation,
immutable investigation notes, and audit trails.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from database import get_connection

logger = logging.getLogger("examguard.security.incidents")

VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}

# Valid state transitions
# RESOLVED and FALSE_POSITIVE are terminal and can only transition to INVESTIGATING with formal documentation
ALLOWED_TRANSITIONS = {
    "OPEN": {"INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"CONTAINED", "RESOLVED", "FALSE_POSITIVE", "OPEN"},
    "CONTAINED": {"RESOLVED", "INVESTIGATING", "FALSE_POSITIVE"},
    "RESOLVED": {"INVESTIGATING"},  # Can only be formally reopened to INVESTIGATING
    "FALSE_POSITIVE": {"INVESTIGATING"},
}


def create_incident(
    title: str,
    incident_type: str,
    severity: str = "MEDIUM",
    risk_score: int = 0,
    primary_actor_id: int | None = None,
    primary_actor_role: str | None = None,
    source_ip: str | None = None,
    summary: str | None = None,
    evidence: dict | None = None,
    created_by_id: int | None = None,
    created_by_name: str | None = None,
    conn=None,
) -> str | None:
    """
    Creates a new security incident and records the initial creation in incident_audit_trail.
    Returns incident_id (e.g. INC-2026-XXXX) or None.
    """
    try:
        clean_sev = (severity or "MEDIUM").upper()
        if clean_sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            clean_sev = "MEDIUM"

        year = datetime.now().year
        incident_id = f"INC-{year}-{uuid.uuid4().hex[:8].upper()}"
        evidence_json = json.dumps(evidence or {})

        close_after = False
        if conn is None:
            conn = get_connection()
            close_after = True

        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_incidents (
                    incident_id, title, incident_type, severity, status,
                    risk_score, primary_actor_id, primary_actor_role,
                    source_ip, summary, evidence_json
                ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    title[:255],
                    incident_type[:64],
                    clean_sev,
                    int(risk_score),
                    primary_actor_id,
                    primary_actor_role[:32] if primary_actor_role else None,
                    source_ip[:64] if source_ip else None,
                    summary,
                    evidence_json,
                ),
            )

            # Record in audit trail
            cursor.execute(
                """
                INSERT INTO incident_audit_trail (
                    incident_id, action, actor_id, actor_name, details
                ) VALUES (?, 'INCIDENT_CREATED', ?, ?, ?)
                """,
                (
                    incident_id,
                    created_by_id,
                    created_by_name or "System Correlator",
                    f"Created incident '{title}' with severity {clean_sev} and initial risk score {risk_score}."
                ),
            )
            conn.commit()
            return incident_id
        finally:
            if close_after:
                conn.close()

    except Exception as e:
        logger.error("Failed to create security incident: %s", e)
        return None


def transition_incident_status(
    incident_id: str,
    new_status: str,
    actor_id: int | None = None,
    actor_name: str | None = None,
    notes: str | None = None,
    conn=None,
) -> tuple[bool, str]:
    """
    Validates and executes a state transition for an incident.
    Records transition in the audit trail.
    """
    clean_status = (new_status or "").upper().strip()
    if clean_status not in VALID_STATUSES:
        return False, f"Invalid target status '{new_status}'."

    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT status, resolution_notes FROM security_incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return False, f"Incident '{incident_id}' not found."

        current_status = (row["status"] if isinstance(row, dict) else row[0]).upper()
        if current_status == clean_status:
            return True, f"Incident is already in status '{clean_status}'."

        allowed = ALLOWED_TRANSITIONS.get(current_status, set())
        if clean_status not in allowed:
            return False, f"Cannot transition incident from '{current_status}' to '{clean_status}'. Allowed: {list(allowed)}"

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        res_notes = notes or ""

        if clean_status in ("RESOLVED", "FALSE_POSITIVE"):
            if not res_notes.strip():
                return False, f"Resolution documentation is required when closing an incident as '{clean_status}'."
            cursor.execute(
                """
                UPDATE security_incidents
                SET status = ?, resolution_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
                """,
                (clean_status, res_notes, incident_id),
            )
        elif current_status in ("RESOLVED", "FALSE_POSITIVE") and clean_status == "INVESTIGATING":
            if not res_notes.strip():
                return False, "Reopening a resolved or false-positive incident requires documented rationale."
            cursor.execute(
                """
                UPDATE security_incidents
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
                """,
                (clean_status, incident_id),
            )
        else:
            cursor.execute(
                """
                UPDATE security_incidents
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
                """,
                (clean_status, incident_id),
            )

        # Audit trail
        audit_details = f"Status changed from {current_status} to {clean_status}."
        if notes:
            audit_details += f" Rationale: {notes}"

        cursor.execute(
            """
            INSERT INTO incident_audit_trail (
                incident_id, action, actor_id, actor_name, details
            ) VALUES (?, 'STATUS_CHANGE', ?, ?, ?)
            """,
            (incident_id, actor_id, actor_name or "System", audit_details),
        )
        conn.commit()
        return True, f"Incident status updated to '{clean_status}'."
    except Exception as e:
        logger.error("Failed to transition incident status: %s", e)
        return False, f"Database error during transition: {str(e)}"
    finally:
        if close_after:
            conn.close()


def add_incident_note(
    incident_id: str,
    author_id: int,
    author_name: str,
    note_text: str,
    conn=None,
) -> bool:
    """
    Appends an immutable investigation note to an incident.
    """
    clean_text = (note_text or "").strip()
    if not clean_text:
        return False

    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incident_notes (incident_id, author_id, author_name, note_text)
            VALUES (?, ?, ?, ?)
            """,
            (incident_id, author_id, author_name, clean_text),
        )
        cursor.execute(
            """
            INSERT INTO incident_audit_trail (incident_id, action, actor_id, actor_name, details)
            VALUES (?, 'NOTE_ADDED', ?, ?, ?)
            """,
            (incident_id, author_id, author_name, f"Added investigation note: {clean_text[:80]}..."),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to add incident note: %s", e)
        return False
    finally:
        if close_after:
            conn.close()


def get_incident_details(incident_id: str, conn=None) -> dict | None:
    """
    Retrieves complete incident object, its chronological audit history, and investigation notes.
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None

        incident = dict(row)
        if isinstance(incident.get("evidence_json"), str):
            try:
                incident["evidence"] = json.loads(incident["evidence_json"])
            except Exception:
                incident["evidence"] = {}

        # Fetch audit trail
        cursor.execute(
            "SELECT action, actor_name, details, timestamp FROM incident_audit_trail WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        )
        incident["audit_trail"] = [dict(r) for r in cursor.fetchall()]

        # Fetch notes
        cursor.execute(
            "SELECT author_name, note_text, timestamp FROM incident_notes WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        )
        incident["notes"] = [dict(r) for r in cursor.fetchall()]

        return incident
    except Exception as e:
        logger.error("Failed to retrieve incident details: %s", e)
        return None
    finally:
        if close_after:
            conn.close()

