"""
Advanced Incident Intelligence & Investigation Service for ExamGuard AI.
Implements:
1. Unified Incident Intelligence (Events, Risks, Recommendations, Relationships, Notes, Audit Trail)
2. Safe Multi-Entity Event Correlation (Account, Session, Device, Exam, IP)
3. Historical Risk Intelligence from risk_audit_log
4. Recommendation Traceability to triggering events and policies
5. Unified Chronological Investigation Timeline with strict event/derived/administrative classification
"""

import json
import logging
from datetime import datetime, timezone
from database import get_connection
from .event_collector import sanitize_security_details, anonymize_session_identifier

logger = logging.getLogger("examguard.security.intelligence")


def get_unified_incident_intelligence(incident_id: str, conn=None) -> dict | None:
    """
    Compiles a comprehensive, unified investigation dossier for an incident.
    Returns:
    - incident: Primary incident metadata
    - actor_info: Anonymized/redacted user and profile details
    - related_events: Correlated security events linked by event IDs, correlation IDs, or actor/resource
    - related_recommendations: Recommendations linked to this incident or its target entities
    - risk_history: Historical risk transitions from risk_audit_log for this entity
    - timeline: Unified chronological investigation timeline with classified item types
    - entity_relationships: Identified relationships (account, session, device, submission, IP)
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()

        # 1. Fetch Incident Record
        cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        if not inc_row:
            return None

        incident = dict(inc_row)
        evidence = {}
        if isinstance(incident.get("evidence_json"), str):
            try:
                evidence = json.loads(incident["evidence_json"])
            except Exception:
                evidence = {}
        incident["evidence"] = sanitize_security_details(evidence)

        # 2. Fetch Actor Information
        actor_id = incident.get("primary_actor_id")
        actor_info = None
        if actor_id:
            cursor.execute(
                "SELECT id, username, full_name, role, email, roll_number, mfa_enabled FROM users WHERE id = ?",
                (actor_id,),
            )
            u_row = cursor.fetchone()
            if u_row:
                actor_info = dict(u_row)

        # 3. Fetch Investigation Notes
        cursor.execute(
            "SELECT id, author_id, author_name, note_text, timestamp FROM incident_notes WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        )
        notes = [dict(r) for r in cursor.fetchall()]
        incident["notes"] = notes

        # 4. Fetch Audit Trail
        cursor.execute(
            "SELECT id, action, actor_name, details, timestamp FROM incident_audit_trail WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        )
        audit_trail = [dict(r) for r in cursor.fetchall()]
        incident["audit_trail"] = audit_trail

        # 5. Extract Linked Event IDs from Evidence
        linked_event_ids = set()
        if isinstance(evidence.get("correlated_events"), list):
            for eid in evidence["correlated_events"]:
                if eid:
                    linked_event_ids.add(str(eid))
        if isinstance(evidence.get("event_ids"), list):
            for eid in evidence["event_ids"]:
                if eid:
                    linked_event_ids.add(str(eid))

        # 6. Fetch Related Security Events (by event_id, or actor_id, bounded to 50 max)
        related_events = []
        if linked_event_ids:
            placeholders = ",".join(["?"] * len(linked_event_ids))
            cursor.execute(
                f"""
                SELECT event_id, event_type, severity, actor_id, actor_role,
                       target_resource, target_resource_id, correlation_id,
                       source_ip, endpoint, event_category, details_json, timestamp
                FROM security_events
                WHERE event_id IN ({placeholders})
                ORDER BY timestamp ASC, id ASC
                """,
                list(linked_event_ids),
            )
            related_events = [dict(r) for r in cursor.fetchall()]

        # If few or no direct event IDs, correlate by primary actor or source_ip within incident period
        if len(related_events) < 5 and (actor_id or incident.get("source_ip")):
            cursor.execute(
                """
                SELECT event_id, event_type, severity, actor_id, actor_role,
                       target_resource, target_resource_id, correlation_id,
                       source_ip, endpoint, event_category, details_json, timestamp
                FROM security_events
                WHERE (? IS NOT NULL AND actor_id = ?)
                ORDER BY timestamp DESC, id DESC
                LIMIT 30
                """,
                (actor_id, actor_id),
            )
            existing_ids = {e["event_id"] for e in related_events}
            for r in cursor.fetchall():
                ev = dict(r)
                if ev["event_id"] not in existing_ids:
                    related_events.append(ev)
                    existing_ids.add(ev["event_id"])

        # Sanitize details & anonymize session tokens in related events
        for ev in related_events:
            try:
                dt = json.loads(ev.get("details_json") or "{}")
            except Exception:
                dt = {}
            ev["details"] = sanitize_security_details(dt)
            ev.pop("details_json", None)
            if (ev.get("target_resource") or "").lower() == "session":
                ev["target_resource_id"] = anonymize_session_identifier(ev.get("target_resource_id"))

        # 7. Fetch Related Security Recommendations
        cursor.execute(
            """
            SELECT r.id, r.recommendation_id, r.incident_id, r.target_actor_id,
                   r.target_resource, r.target_resource_id, r.risk_score,
                   r.triggering_events_json, r.explanation, r.recommended_action,
                   r.potential_impact, r.required_role, r.status, r.reviewed_by,
                   r.reviewed_at, r.execution_notes, r.created_at,
                   u.full_name as reviewer_name
            FROM security_recommendations r
            LEFT JOIN users u ON r.reviewed_by = u.id
            WHERE r.incident_id = ? OR (? IS NOT NULL AND r.target_actor_id = ?)
            ORDER BY r.created_at ASC
            LIMIT 30
            """,
            (incident_id, actor_id, actor_id),
        )
        recommendations = []
        for r in cursor.fetchall():
            rec = dict(r)
            try:
                rec["triggering_events"] = json.loads(rec.get("triggering_events_json") or "[]")
            except Exception:
                rec["triggering_events"] = []
            rec.pop("triggering_events_json", None)
            if (rec.get("target_resource") or "").lower() == "session":
                rec["target_resource_id"] = anonymize_session_identifier(rec.get("target_resource_id"))
            recommendations.append(rec)

        # 8. Fetch Historical Risk Transitions from risk_audit_log
        # Entity can be account (actor_id), or incident target
        risk_history = []
        if actor_id:
            cursor.execute(
                """
                SELECT id, entity_type, entity_id, old_score, new_score, factors_json, trigger_event, timestamp
                FROM risk_audit_log
                WHERE entity_type = 'account' AND entity_id = ?
                ORDER BY timestamp ASC, id ASC
                LIMIT 50
                """,
                (str(actor_id),),
            )
            for r in cursor.fetchall():
                rh = dict(r)
                try:
                    rh["factors"] = json.loads(rh.get("factors_json") or "[]")
                except Exception:
                    rh["factors"] = []
                rh.pop("factors_json", None)
                risk_history.append(rh)

        # 9. Extract Entity Relationships
        # Identifies associated sessions, devices, exams, IPs
        entity_relationships = {
            "account": {
                "id": actor_id,
                "name": actor_info.get("full_name") if actor_info else None,
                "role": actor_info.get("role") if actor_info else incident.get("primary_actor_role"),
            },
            "sessions": set(),
            "devices": set(),
            "examinations": set(),
            "ip_addresses": set(),
        }

        if incident.get("source_ip"):
            entity_relationships["ip_addresses"].add(incident["source_ip"])

        for ev in related_events:
            if ev.get("source_ip"):
                entity_relationships["ip_addresses"].add(ev["source_ip"])
            tres = (ev.get("target_resource") or "").lower()
            tid = ev.get("target_resource_id")
            if tres == "session" and tid:
                entity_relationships["sessions"].add(tid)
            elif tres == "device" and tid:
                entity_relationships["devices"].add(tid)
            elif tres in ("examination", "submission") and tid:
                entity_relationships["examinations"].add(tid)

            # Details JSON inspection
            dt = ev.get("details", {})
            if dt.get("submission_id"):
                entity_relationships["examinations"].add(str(dt["submission_id"]))
            if dt.get("device_fingerprint"):
                entity_relationships["devices"].add(str(dt["device_fingerprint"]))
            if dt.get("ip_address"):
                entity_relationships["ip_addresses"].add(str(dt["ip_address"]))

        # Convert sets to sorted lists for JSON serialization
        entity_relationships["sessions"] = sorted(list(entity_relationships["sessions"]))
        entity_relationships["devices"] = sorted(list(entity_relationships["devices"]))
        entity_relationships["examinations"] = sorted(list(entity_relationships["examinations"]))
        entity_relationships["ip_addresses"] = sorted(list(entity_relationships["ip_addresses"]))

        # 10. Build Unified Chronological Investigation Timeline
        timeline = build_investigation_timeline(
            incident=incident,
            related_events=related_events,
            risk_history=risk_history,
            recommendations=recommendations,
            notes=notes,
            audit_trail=audit_trail,
        )

        return {
            "success": True,
            "incident": incident,
            "actor_info": actor_info,
            "related_events": related_events,
            "related_recommendations": recommendations,
            "risk_history": risk_history,
            "entity_relationships": entity_relationships,
            "timeline": timeline,
        }

    except Exception as e:
        logger.error("Error generating unified incident intelligence for '%s': %s", incident_id, e)
        return None
    finally:
        if close_after:
            conn.close()


def build_investigation_timeline(
    incident: dict,
    related_events: list[dict],
    risk_history: list[dict],
    recommendations: list[dict],
    notes: list[dict],
    audit_trail: list[dict],
) -> list[dict]:
    """
    Constructs a unified, chronological, typed timeline.
    Classifies every entry into distinct categories:
    - SECURITY_EVENT: Actual captured telemetry (login fail, rate limit, device switch)
    - ANOMALY_DETECTION: Correlated anomaly detection
    - RISK_ASSESSMENT: Deterministic score calculation/transition
    - INCIDENT_LIFECYCLE: Incident creation, status transition, closure
    - RECOMMENDATION: Adaptive policy recommendation generated/reviewed
    - ADMINISTRATIVE_NOTE: Human proctor/tutor investigation note
    """
    timeline_items = []

    # A. Security Events
    for ev in related_events:
        timeline_items.append({
            "type": "SECURITY_EVENT",
            "category": "TELEMETRY",
            "title": f"Security Event: {ev.get('event_type')}",
            "description": f"Severity {ev.get('severity')} on endpoint {ev.get('endpoint') or '--'}",
            "reference_id": ev.get("event_id"),
            "severity": ev.get("severity"),
            "actor": ev.get("actor_role") or "System",
            "source_ip": ev.get("source_ip"),
            "timestamp": ev.get("timestamp") or "1970-01-01 00:00:00",
        })

    # B. Risk History Transitions
    for rh in risk_history:
        old_s = rh.get("old_score", 0)
        new_s = rh.get("new_score", 0)
        direction = "Elevated" if new_s > old_s else "Reduced" if new_s < old_s else "Recalculated"
        timeline_items.append({
            "type": "RISK_ASSESSMENT",
            "category": "DERIVED_INTELLIGENCE",
            "title": f"Risk Score {direction} ({old_s} → {new_s})",
            "description": f"Trigger: {rh.get('trigger_event') or 'Engine Audit'}",
            "reference_id": f"risk_audit_{rh.get('id')}",
            "score": new_s,
            "factors": rh.get("factors", []),
            "timestamp": rh.get("timestamp") or "1970-01-01 00:00:00",
        })

    # C. Incident Creation & Lifecycle
    created_at = incident.get("created_at") or incident.get("timestamp") or "1970-01-01 00:00:00"
    timeline_items.append({
        "type": "INCIDENT_LIFECYCLE",
        "category": "LIFECYCLE",
        "title": f"Incident Created: {incident.get('title')}",
        "description": incident.get("summary") or "Initial automated incident creation.",
        "reference_id": incident.get("incident_id"),
        "severity": incident.get("severity"),
        "timestamp": created_at,
    })

    # D. Recommendations & Human Reviews
    for rec in recommendations:
        clean_action = (rec.get("recommended_action") or "").replace("_", " ").title()
        timeline_items.append({
            "type": "RECOMMENDATION",
            "category": "DERIVED_INTELLIGENCE",
            "title": f"Recommendation: {clean_action}",
            "description": rec.get("explanation") or "",
            "reference_id": rec.get("recommendation_id"),
            "status": rec.get("status"),
            "timestamp": rec.get("created_at") or "1970-01-01 00:00:00",
        })
        if rec.get("reviewed_at") and rec.get("status") in ("APPROVED", "REJECTED", "DISMISSED"):
            timeline_items.append({
                "type": "ADMINISTRATIVE_DECISION",
                "category": "ADMINISTRATIVE",
                "title": f"Recommendation {rec.get('status')}: {clean_action}",
                "description": rec.get("execution_notes") or f"Reviewed by {rec.get('reviewer_name') or 'Admin'}",
                "reference_id": rec.get("recommendation_id"),
                "actor": rec.get("reviewer_name") or "Admin",
                "timestamp": rec.get("reviewed_at"),
            })

    # E. Investigation Notes
    for n in notes:
        timeline_items.append({
            "type": "ADMINISTRATIVE_NOTE",
            "category": "ADMINISTRATIVE",
            "title": f"Note by {n.get('author_name')}",
            "description": n.get("note_text"),
            "reference_id": f"note_{n.get('id')}",
            "actor": n.get("author_name"),
            "timestamp": n.get("timestamp") or "1970-01-01 00:00:00",
        })

    # F. Status Audit Transitions
    for a in audit_trail:
        if a.get("action") == "STATUS_CHANGE":
            timeline_items.append({
                "type": "INCIDENT_LIFECYCLE",
                "category": "LIFECYCLE",
                "title": f"Incident Status Updated",
                "description": a.get("details"),
                "reference_id": f"audit_{a.get('id')}",
                "actor": a.get("actor_name"),
                "timestamp": a.get("timestamp") or "1970-01-01 00:00:00",
            })

    # Sort safely by timestamp string (ISO format: YYYY-MM-DD HH:MM:SS)
    def safe_sort_key(item):
        ts = item.get("timestamp") or ""
        # Handle string variations or nulls
        return str(ts)

    timeline_items.sort(key=safe_sort_key)
    return timeline_items


def correlate_entities_across_events(
    actor_id: int | None = None,
    session_ref: str | None = None,
    device_id: str | None = None,
    exam_id: str | None = None,
    source_ip: str | None = None,
    conn=None,
) -> dict:
    """
    Discovers correlated security events and candidate entities across five dimensions:
    Account, Session, Device, Examination, and IP.
    Applies strict anti-false-positive boundaries:
    - Shared IP addresses alone NEVER link two accounts.
    - Session identifiers are non-reversible references.
    - Correlation does not establish guilt or automatically trigger penalties.
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        cursor = conn.cursor()
        correlations = {
            "account_events": [],
            "session_events": [],
            "device_events": [],
            "exam_events": [],
            "ip_events": [],
            "shared_ip_accounts": [],
            "ip_is_shared_proxy_warning": False,
        }

        # 1. Account Events
        if actor_id:
            cursor.execute(
                """
                SELECT event_id, event_type, severity, source_ip, endpoint, timestamp
                FROM security_events WHERE actor_id = ?
                ORDER BY timestamp DESC LIMIT 20
                """,
                (actor_id,),
            )
            correlations["account_events"] = [dict(r) for r in cursor.fetchall()]

        # 2. Session Events
        if session_ref:
            cursor.execute(
                """
                SELECT event_id, event_type, severity, source_ip, endpoint, timestamp
                FROM security_events WHERE target_resource = 'session' AND target_resource_id = ?
                ORDER BY timestamp DESC LIMIT 20
                """,
                (session_ref,),
            )
            correlations["session_events"] = [dict(r) for r in cursor.fetchall()]

        # 3. Device Events
        if device_id:
            cursor.execute(
                """
                SELECT event_id, event_type, severity, source_ip, endpoint, timestamp
                FROM security_events WHERE target_resource = 'device' AND target_resource_id = ?
                ORDER BY timestamp DESC LIMIT 20
                """,
                (device_id,),
            )
            correlations["device_events"] = [dict(r) for r in cursor.fetchall()]

        # 4. Examination Events
        if exam_id:
            cursor.execute(
                """
                SELECT event_id, event_type, severity, source_ip, endpoint, timestamp
                FROM security_events WHERE target_resource IN ('examination', 'submission') AND target_resource_id = ?
                ORDER BY timestamp DESC LIMIT 20
                """,
                (str(exam_id),),
            )
            correlations["exam_events"] = [dict(r) for r in cursor.fetchall()]

        # 5. IP Events & Shared Subnet Detection
        if source_ip:
            cursor.execute(
                """
                SELECT event_id, event_type, severity, actor_id, endpoint, timestamp
                FROM security_events WHERE source_ip = ?
                ORDER BY timestamp DESC LIMIT 25
                """,
                (source_ip,),
            )
            correlations["ip_events"] = [dict(r) for r in cursor.fetchall()]

            # Count distinct accounts using this IP to detect institutional proxy / campus NAT
            cursor.execute(
                """
                SELECT COUNT(DISTINCT actor_id) as act_cnt
                FROM security_events
                WHERE source_ip = ? AND actor_id IS NOT NULL
                """,
                (source_ip,),
            )
            cnt_row = cursor.fetchone()
            act_count = cnt_row["act_cnt"] if cnt_row else 0
            if act_count > 1:
                correlations["ip_is_shared_proxy_warning"] = True

        return correlations
    except Exception as e:
        logger.error("Error during entity correlation: %s", e)
        return {}
    finally:
        if close_after:
            conn.close()

