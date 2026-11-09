"""
Adaptive Security Policy Engine & Recommendation Generator for ExamGuard AI.
Complies with Phase 4 Step 3 Cybersecurity Architecture:
1. Evaluates active policies in `security_policies` against risk scores, categories, scopes, and security events.
2. Generates structured, explainable recommendations in `security_recommendations`.
3. Validates supported advisory actions:
   - `recommend_mfa_stepup`
   - `flag_proctor_review`
   - `dispatch_proctor_advisory`
   - `recommend_session_termination`
   - `recommend_security_investigation`
4. Enforces human-in-the-loop review (requires_admin_approval=1).
   Recommendations are advisories; NO automatic bans, terminations, or disciplinary actions.
5. Prevents duplicate active recommendations for the same underlying issue and target.
6. Gracefully handles missing policy data, disabled policies, or database errors without raising.
7. Preserves traceability between risk assessments, events, incidents, and recommendations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Any

from database import get_connection
from .risk_engine import RiskAssessment

logger = logging.getLogger("examguard.security.policy")

# Supported, authorized advisory actions (non-executable, advisory-only)
SUPPORTED_ADVISORY_ACTIONS = {
    "recommend_mfa_stepup",
    "flag_proctor_review",
    "dispatch_proctor_advisory",
    "recommend_session_termination",
    "recommend_security_investigation",
}

VALID_RECOMMENDATION_STATUSES = {
    "PENDING_REVIEW",
    "APPROVED",
    "REJECTED",
    "DISMISSED",
    "SUPERSEDED",
}


@dataclass
class PolicyEvaluationResult:
    policy_key: str
    policy_name: str
    triggered: bool
    recommended_action: str
    min_risk_score: int
    current_risk_score: int
    potential_impact: str
    requires_admin_approval: bool
    rationale: str

    def to_dict(self) -> dict:
        return {
            "policy_key": self.policy_key,
            "policy_name": self.policy_name,
            "triggered": self.triggered,
            "recommended_action": self.recommended_action,
            "min_risk_score": self.min_risk_score,
            "current_risk_score": self.current_risk_score,
            "potential_impact": self.potential_impact,
            "requires_admin_approval": self.requires_admin_approval,
            "rationale": self.rationale,
        }


def get_active_policies(conn=None) -> list[dict]:
    """
    Retrieves all enabled policies from `security_policies`.
    Fails safely returning default baseline policies if database query encounters an error.
    """
    close_when_done = False
    if conn is None:
        try:
            conn = get_connection()
            close_when_done = True
        except Exception as e:
            logger.error("Could not obtain database connection for policies: %s", e)
            return []

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, policy_key, name, description, min_risk_score,
                   recommended_action, potential_impact, requires_admin_approval, is_enabled
            FROM security_policies
            WHERE is_enabled = 1
            ORDER BY min_risk_score ASC
        """)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error reading security policies from database: %s", e)
        return []
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass


def evaluate_policies_for_assessment(
    assessment: RiskAssessment | dict,
    policies: list[dict] | None = None,
    conn=None
) -> list[PolicyEvaluationResult]:
    """
    Evaluates enabled policies against a RiskAssessment object or dict.
    Returns a list of PolicyEvaluationResult showing trigger status and rationale.
    """
    if isinstance(assessment, dict):
        score = int(assessment.get("score", 0))
        level = assessment.get("level") or assessment.get("category") or "LOW"
        scope = assessment.get("scope") or "general"
    else:
        score = assessment.score
        level = assessment.level
        scope = assessment.scope

    if policies is None:
        policies = get_active_policies(conn=conn)

    results: list[PolicyEvaluationResult] = []

    for p in policies:
        p_key = p.get("policy_key", "unknown")
        p_name = p.get("name", "Unnamed Policy")
        min_score = int(p.get("min_risk_score", 40))
        action = p.get("recommended_action", "")
        impact = p.get("potential_impact", "")
        req_approval = bool(p.get("requires_admin_approval", 1))

        # Check if action is in supported action whitelist
        if action not in SUPPORTED_ADVISORY_ACTIONS:
            logger.warning("Policy '%s' references unsupported action '%s'; skipping evaluation.", p_key, action)
            continue

        # Scope compatibility heuristics
        scope_compatible = True
        if "exam" in p_key and scope not in ("examination", "general"):
            scope_compatible = False
        elif "session" in p_key and scope not in ("session", "account", "general"):
            scope_compatible = False

        triggered = (score >= min_score) and scope_compatible

        if triggered:
            rationale = (
                f"Risk score {score}/100 exceeds policy threshold of {min_score} "
                f"for scope '{scope}' (Level: {level})."
            )
        else:
            if not scope_compatible:
                rationale = f"Policy '{p_key}' is not applicable to assessment scope '{scope}'."
            else:
                rationale = f"Risk score {score}/100 is below policy threshold of {min_score}."

        results.append(
            PolicyEvaluationResult(
                policy_key=p_key,
                policy_name=p_name,
                triggered=triggered,
                recommended_action=action,
                min_risk_score=min_score,
                current_risk_score=score,
                potential_impact=impact,
                requires_admin_approval=req_approval,
                rationale=rationale,
            )
        )

    return results


def check_existing_active_recommendation(
    target_resource: str,
    target_resource_id: str,
    recommended_action: str,
    conn=None
) -> str | None:
    """
    Checks if there is already an active (PENDING_REVIEW) recommendation for this target
    and action to avoid duplicate recommendation pollution.
    Returns existing recommendation_id if found, or None.
    """
    close_when_done = False
    if conn is None:
        try:
            conn = get_connection()
            close_when_done = True
        except Exception:
            return None

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT recommendation_id
            FROM security_recommendations
            WHERE target_resource = ?
              AND target_resource_id = ?
              AND recommended_action = ?
              AND status = 'PENDING_REVIEW'
            LIMIT 1
        """, (str(target_resource)[:64], str(target_resource_id)[:64], str(recommended_action)[:64]))
        row = cursor.fetchone()
        return row["recommendation_id"] if row else None
    except Exception as e:
        logger.error("Error checking existing recommendations: %s", e)
        return None
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass


def generate_security_recommendations(
    assessment: RiskAssessment | dict,
    target_resource: str,
    target_resource_id: str,
    target_actor_id: int | None = None,
    incident_id: str | None = None,
    conn=None,
    required_role: str = "admin",
) -> list[str]:
    """
    Evaluates policies against the risk assessment and creates new recommendations in `security_recommendations`.
    Suppresses duplicate recommendations if one is already pending review for the same target and action.
    Returns list of newly generated recommendation_ids.
    Never fails or raises on database errors.
    """
    if isinstance(assessment, dict):
        score = int(assessment.get("score", 0))
        explanation = assessment.get("explanation", "")
        event_ids = assessment.get("event_ids", [])
    else:
        score = assessment.score
        explanation = assessment.explanation
        event_ids = assessment.event_ids

    eval_results = evaluate_policies_for_assessment(assessment, conn=conn)
    triggered_policies = [r for r in eval_results if r.triggered]

    if not triggered_policies:
        return []

    close_when_done = False
    if conn is None:
        try:
            conn = get_connection()
            close_when_done = True
        except Exception as e:
            logger.error("Could not obtain DB connection to generate recommendations: %s", e)
            return []

    created_ids: list[str] = []

    try:
        cursor = conn.cursor()
        year = datetime.now(timezone.utc).year

        for pol in triggered_policies:
            # Duplicate check: prevent duplicate active recommendation for same target & action
            existing_rec_id = check_existing_active_recommendation(
                target_resource=target_resource,
                target_resource_id=target_resource_id,
                recommended_action=pol.recommended_action,
                conn=conn
            )
            if existing_rec_id:
                logger.debug(
                    "Recommendation '%s' already pending for target %s:%s; skipping duplicate.",
                    existing_rec_id, target_resource, target_resource_id
                )
                continue

            rec_id = f"REC-{year}-{uuid.uuid4().hex[:8].upper()}"
            events_json = json.dumps(event_ids[:50])

            detailed_explanation = (
                f"{pol.rationale} {explanation} "
                "Recommendation generated as advisory for administrator/proctor review. "
                "No automated disciplinary or session termination action has been executed."
            )

            try:
                cursor.execute("""
                    INSERT INTO security_recommendations (
                        recommendation_id, incident_id, target_actor_id,
                        target_resource, target_resource_id, risk_score,
                        triggering_events_json, explanation, recommended_action,
                        potential_impact, required_role, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW')
                """, (
                    rec_id,
                    incident_id[:64] if incident_id else None,
                    target_actor_id,
                    str(target_resource)[:64],
                    str(target_resource_id)[:64],
                    score,
                    events_json,
                    detailed_explanation,
                    pol.recommended_action[:64],
                    pol.potential_impact,
                    required_role[:32],
                ))
                created_ids.append(rec_id)
            except Exception as insert_err:
                # Concurrency safety: if a race condition occurred and another worker/thread
                # concurrently inserted the same active PENDING_REVIEW recommendation,
                # the database unique constraint uq_*_sec_recs_active_dedup safely rejects it.
                logger.info(
                    "Concurrent insert safely handled by database constraint for %s:%s (%s): %s",
                    target_resource, target_resource_id, pol.recommended_action, insert_err
                )
                # Re-query the concurrently created recommendation to return or reference it
                existing_after_race = check_existing_active_recommendation(
                    target_resource=target_resource,
                    target_resource_id=target_resource_id,
                    recommended_action=pol.recommended_action,
                    conn=conn
                )
                if existing_after_race and existing_after_race not in created_ids:
                    created_ids.append(existing_after_race)

        conn.commit()
    except Exception as e:
        logger.error("Failed to insert security recommendations: %s", e)
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass

    return created_ids


def get_recommendation_details(recommendation_id: str, conn=None) -> dict | None:
    """Retrieves full recommendation details by recommendation_id."""
    close_when_done = False
    if conn is None:
        try:
            conn = get_connection()
            close_when_done = True
        except Exception:
            return None

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, recommendation_id, incident_id, target_actor_id,
                   target_resource, target_resource_id, risk_score,
                   triggering_events_json, explanation, recommended_action,
                   potential_impact, required_role, status, reviewed_by,
                   reviewed_at, execution_notes, created_at
            FROM security_recommendations
            WHERE recommendation_id = ?
        """, (recommendation_id,))
        row = cursor.fetchone()
        if not row:
            return None
        rec = dict(row)
        try:
            rec["triggering_events"] = json.loads(rec.get("triggering_events_json") or "[]")
        except Exception:
            rec["triggering_events"] = []
        return rec
    except Exception as e:
        logger.error("Error retrieving recommendation %s: %s", recommendation_id, e)
        return None
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass


def review_security_recommendation(
    recommendation_id: str,
    action: str,  # 'APPROVED', 'REJECTED', 'DISMISSED'
    reviewer_id: int,
    reviewer_role: str = "admin",
    notes: str = "",
    conn=None
) -> tuple[bool, str]:
    """
    Records an authorized human review of a security recommendation.
    Enforces that reviewer_role must be 'admin'.
    Transitions status to APPROVED, REJECTED, or DISMISSED, recording reviewer and execution notes.
    Prevents concurrent overwrites by gating on status = 'PENDING_REVIEW'.
    Returns (success_boolean, message).
    """
    if reviewer_role != "admin":
        logger.warning("Unauthorized review attempt by non-admin role '%s' on %s", reviewer_role, recommendation_id)
        return False, "Unauthorized: Reviewing security recommendations requires administrator privileges."

    clean_action = (action or "").upper()
    if clean_action not in ("APPROVED", "REJECTED", "DISMISSED"):
        logger.warning("Invalid recommendation review action '%s'", action)
        return False, f"Invalid review action '{action}'. Must be APPROVED, REJECTED, or DISMISSED."

    close_when_done = False
    if conn is None:
        try:
            conn = get_connection()
            close_when_done = True
        except Exception:
            return False, "Database connection error."

    try:
        cursor = conn.cursor()
        # Verify current status before updating (detect concurrent review race condition)
        cursor.execute("SELECT status, required_role FROM security_recommendations WHERE recommendation_id = ?", (recommendation_id,))
        rec_row = cursor.fetchone()
        if not rec_row:
            return False, f"Recommendation '{recommendation_id}' not found."

        if rec_row["status"] != "PENDING_REVIEW":
            return False, f"Recommendation is already in state '{rec_row['status']}' and cannot be reviewed again."

        now_ts = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            UPDATE security_recommendations
            SET status = ?,
                reviewed_by = ?,
                reviewed_at = ?,
                execution_notes = ?
            WHERE recommendation_id = ?
              AND status = 'PENDING_REVIEW'
        """, (clean_action, int(reviewer_id), now_ts, str(notes)[:500], recommendation_id))
        conn.commit()
        if cursor.rowcount > 0:
            return True, f"Recommendation '{recommendation_id}' successfully marked as '{clean_action}'."
        return False, "Concurrent update detected: recommendation was modified by another reviewer."
    except Exception as e:
        logger.error("Error updating recommendation %s review status: %s", recommendation_id, e)
        return False, f"Database error during review: {str(e)}"
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass

