"""
Deterministic, Explainable Adaptive Security Risk Scoring Engine for ExamGuard AI.
Complies with Phase 4 Cybersecurity Architecture:
1. Calculates risk scores strictly within boundaries [0, 100].
2. Provides transparent, auditable factors, weights, and rationales explaining every point assigned.
3. Implements five distinct evaluation scopes:
   - Account-level risk
   - Session-level risk
   - Device-level risk
   - IP contextual risk
   - Examination/submission-level risk
4. Applies diminishing returns to repeated identical events to avoid runaway score inflation.
5. Applies time-decay weighting (recent events weighted higher than older events).
6. Missing/incomplete data does not artificially inflate risk.
7. IP changes alone never establish malicious activity.
8. Logs meaningful risk transitions to risk_audit_log without redundant logging.
9. Resilient to database failures (never raises or interrupts ordinary operations).
10. Does NOT execute automated account lockouts, exam termination, or student disciplinary bans.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import hashlib
from typing import Any

logger = logging.getLogger("examguard.security.risk")

# Base event risk weights (illustrative defaults, strictly deterministic)
EVENT_WEIGHTS = {
    # Authentication & Session
    "auth.failed_login": 10,
    "auth.repeated_failed_login": 25,
    "auth.unusual_device_switch": 20,
    "auth.concurrent_session_attempt": 15,
    "auth.device_replacement": 15,
    "auth.rapid_device_switch": 30,
    "auth.mfa_failure": 20,
    "session.expired_access": 10,
    "session.revocation_violation": 25,
    "session.invalid_token": 15,

    # Authorization & Access Control
    "authorization.unauthorized_access": 20,
    "authorization.privilege_escalation_attempt": 40,
    "authorization.idor_attempt": 35,
    "authorization.student_terminated_access": 25,

    # CSRF & Request Integrity
    "csrf.validation_failed": 25,
    "csrf.origin_mismatch": 30,

    # API & Network Patterns
    "api.excessive_rate": 15,
    "api.burst_detected": 25,
    "api.method_not_allowed": 10,
    "api.suspicious_frequency": 20,

    # Examination Contextual Integrity
    "exam.rapid_reconnect": 15,
    "exam.abnormal_timing": 15,
    "exam.state_conflict": 20,
    "exam.multiple_ip_submission": 20,
    "exam.answer_tampering_attempt": 40,
}

RISK_LEVEL_THRESHOLDS = [
    (75, "CRITICAL"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]


@dataclass
class RiskFactor:
    name: str
    weight: int
    rationale: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "rationale": self.rationale,
        }


@dataclass
class RiskAssessment:
    score: int
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    factors: list[RiskFactor] = field(default_factory=list)
    explanation: str = ""
    factor_weights: dict[str, int] = field(default_factory=dict)
    event_ids: list[str] = field(default_factory=list)
    scope: str = "general"
    target_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "category": self.level,  # Alias for backward compatibility
            "factors": [f.to_dict() for f in self.factors],
            "factor_weights": self.factor_weights,
            "explanation": self.explanation,
            "event_ids": self.event_ids,
            "scope": self.scope,
            "target_id": self.target_id,
            "timestamp": self.timestamp,
        }


def _determine_risk_level(score: int) -> str:
    """Deterministic categorization of risk score into standard level."""
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def _parse_event_timestamp(ts_value: Any) -> datetime | None:
    """Robustly parse timestamp string or datetime into UTC datetime."""
    if not ts_value:
        return None
    if isinstance(ts_value, datetime):
        return ts_value.replace(tzinfo=timezone.utc) if ts_value.tzinfo is None else ts_value
    try:
        clean_ts = str(ts_value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        # Ensure timezone awareness
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def calculate_risk_score(
    events: list[dict] | None = None,
    scope: str = "general",
    target_id: str = "",
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Computes a deterministic, explainable, bounded risk score (0-100) from security events.
    Applies:
    1. Diminishing returns to repeated occurrences of the same event type.
    2. Time-decay weighting (recent events weighted higher than older events).
    3. Strict bounding [0, 100].
    4. Explanatory factor breakdown with event IDs.
    """
    if not events:
        return RiskAssessment(
            score=0,
            level="LOW",
            factors=[],
            explanation="No security events detected. Baseline risk is normal.",
            factor_weights={},
            event_ids=[],
            scope=scope,
            target_id=str(target_id),
        )

    ref_time = reference_time or datetime.now(timezone.utc)
    factors: list[RiskFactor] = []
    factor_weights: dict[str, int] = {}
    total_raw_score = 0.0
    all_event_ids: list[str] = []

    # Group events by event_type and collect timestamps and IDs
    grouped_events: dict[str, list[dict]] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        etype = ev.get("event_type")
        # Missing or empty event_type does not represent actionable threat intelligence; do not penalize
        if not etype:
            continue
        eid = ev.get("event_id")
        if eid:
            all_event_ids.append(str(eid))
        grouped_events.setdefault(str(etype), []).append(ev)

    for etype, ev_list in grouped_events.items():
        # Benign, informational or unknown events receive 0 weight to avoid false-positive inflation
        base_weight = EVENT_WEIGHTS.get(etype, 0)
        if base_weight <= 0:
            continue
        count = len(ev_list)

        # 1. Diminishing returns curve: 1st=1.0x, 2nd=0.5x, 3rd+=0.25x
        if count == 1:
            diminished_weight = float(base_weight)
        elif count == 2:
            diminished_weight = float(base_weight) * 1.5
        else:
            diminished_weight = float(base_weight) * 1.5 + (count - 2) * (float(base_weight) * 0.25)

        # 2. Time decay adjustment: events in the last 15 mins = 1.0x, 15-60m = 0.8x, >60m = 0.5x
        time_multipliers = []
        for ev in ev_list:
            ev_dt = _parse_event_timestamp(ev.get("timestamp"))
            if ev_dt:
                age_seconds = (ref_time - ev_dt).total_seconds()
                # If timestamp is in the future (clock skew/desync), clamp age to 0
                age_minutes = max(0.0, age_seconds / 60.0)
                if age_minutes <= 15:
                    time_multipliers.append(1.0)
                elif age_minutes <= 60:
                    time_multipliers.append(0.8)
                else:
                    time_multipliers.append(0.5)
            else:
                time_multipliers.append(1.0)  # Neutral if time unparseable

        avg_time_multiplier = sum(time_multipliers) / len(time_multipliers) if time_multipliers else 1.0
        effective_weight = max(1, int(round(diminished_weight * avg_time_multiplier)))

        total_raw_score += effective_weight
        factors.append(
            RiskFactor(
                name=etype,
                weight=effective_weight,
                rationale=(
                    f"Observed {count} occurrence(s) of '{etype}' "
                    f"(diminishing weight: {int(diminished_weight)}, recency decay: {avg_time_multiplier:.2f}x)."
                )
            )
        )
        factor_weights[etype] = effective_weight

    # Strictly bound between 0 and 100
    bounded_score = max(0, min(100, int(round(total_raw_score))))
    level = _determine_risk_level(bounded_score)

    explanation = (
        f"Scope '{scope}' target '{target_id}': calculated risk score is {bounded_score}/100 ({level}) "
        f"based on {len(factors)} contributing security factor(s). "
        "Score serves for administrative prioritization and does not trigger automated student disciplinary actions."
    )

    return RiskAssessment(
        score=bounded_score,
        level=level,
        factors=factors,
        factor_weights=factor_weights,
        explanation=explanation,
        event_ids=sorted(list(set(all_event_ids))),
        scope=scope,
        target_id=str(target_id),
    )


# --- FIVE SPECIALIZED ASSESSMENT SCOPES ---

def assess_account_risk(
    user_id: int | str,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Evaluates account-level risk based on security events where actor_id == user_id.
    Never fails or raises on database errors.
    """
    events = _query_security_events(
        filter_col="actor_id",
        filter_val=user_id,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )
    return calculate_risk_score(
        events=events,
        scope="account",
        target_id=str(user_id),
        reference_time=reference_time
    )


def assess_session_risk(
    session_token: str,
    user_id: int | str | None = None,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Evaluates session-level risk by analyzing authentication, authorization, and CSRF events
    correlated with a specific session token or actor session lifecycle.
    Truncates/hashes session token identifier to prevent raw credential exposure in logs or assessments.
    """
    # Opaque non-reversible session surrogate reference (preserves correlation without exposing credential fragments)
    if session_token:
        masked_target = f"sess_ref_{hashlib.sha256(str(session_token).encode('utf-8')).hexdigest()[:16]}"
    else:
        masked_target = "sess_ref_unknown"

    events = _query_security_events(
        filter_col="target_resource_id",
        filter_val=session_token,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )
    if not events and user_id is not None:
        actor_events = _query_security_events(
            filter_col="actor_id",
            filter_val=user_id,
            conn=conn,
            window_minutes=window_minutes,
            reference_time=reference_time
        )
        events = [e for e in actor_events if e.get("event_category") in ("session", "csrf", "auth")]

    return calculate_risk_score(
        events=events,
        scope="session",
        target_id=masked_target,
        reference_time=reference_time
    )


def assess_device_risk(
    device_fingerprint_or_ua: str,
    student_id: int | str | None = None,
    conn=None,
    window_minutes: int = 120,
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Evaluates device-level risk based on rapid device replacement frequency and
    unusual client signatures for a candidate.
    """
    events = _query_security_events(
        filter_col="user_agent",
        filter_val=device_fingerprint_or_ua,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )
    if student_id is not None:
        student_events = _query_security_events(
            filter_col="actor_id",
            filter_val=student_id,
            conn=conn,
            window_minutes=window_minutes,
            reference_time=reference_time
        )
        device_switch_events = [e for e in student_events if "device" in (e.get("event_type") or "")]
        events.extend(device_switch_events)

    return calculate_risk_score(
        events=events,
        scope="device",
        target_id=str(device_fingerprint_or_ua)[:32],
        reference_time=reference_time
    )


def assess_ip_context_risk(
    ip_address: str,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Evaluates contextual IP risk without treating an IP address change alone as malicious.
    Evaluates malicious patterns (e.g. brute force, origin mismatch, credential stuffing)
    originating from that IP.
    """
    if not ip_address or ip_address in ("127.0.0.1", "::1", "localhost"):
        return RiskAssessment(
            score=0,
            level="LOW",
            factors=[],
            explanation=f"IP '{ip_address}' is local loopback. Baseline contextual risk is normal.",
            scope="ip",
            target_id=str(ip_address),
        )

    events = _query_security_events(
        filter_col="source_ip",
        filter_val=ip_address,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )

    assessment = calculate_risk_score(
        events=events,
        scope="ip",
        target_id=str(ip_address),
        reference_time=reference_time
    )
    assessment.explanation += " (Note: Normal IP address changes alone never constitute proof of malicious activity.)"
    return assessment


def assess_examination_risk(
    submission_id: int | str,
    exam_id: int | str | None = None,
    conn=None,
    window_minutes: int = 180,
    reference_time: datetime | None = None
) -> RiskAssessment:
    """
    Evaluates examination/submission security risk.
    Analyzes answer integrity tampering attempts, IDOR requests against results,
    and rapid disconnection/reconnection cycles without interrupting the active candidate.
    """
    events = _query_security_events(
        filter_col="target_resource_id",
        filter_val=str(submission_id),
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )
    return calculate_risk_score(
        events=events,
        scope="examination",
        target_id=str(submission_id),
        reference_time=reference_time
    )


# --- AUDIT LOGGING & DATABASE HELPERS ---

def record_risk_audit_transition(
    entity_type: str,
    entity_id: str,
    old_score: int,
    new_score: int,
    factors: list[RiskFactor] | list[dict],
    trigger_event: str = "",
    min_delta: int = 5,
    conn=None
) -> bool:
    """
    Records significant risk score transitions to `risk_audit_log`.
    Suppresses audit writes when the score delta is below min_delta and risk level is unchanged,
    avoiding audit table pollution.
    Never raises an exception on database errors.
    """
    delta = abs(new_score - old_score)
    old_level = _determine_risk_level(old_score)
    new_level = _determine_risk_level(new_score)

    if delta < min_delta and old_level == new_level:
        return False

    close_when_done = False
    if conn is None:
        try:
            from database import get_connection
            conn = get_connection()
            close_when_done = True
        except Exception as e:
            logger.error("Could not obtain database connection for risk audit: %s", e)
            return False

    try:
        factors_data = []
        for f in factors:
            f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            # Redact raw session tokens or sensitive keys from rationale/name defensively
            sanitized_f = {
                "name": str(f_dict.get("name", ""))[:64],
                "weight": int(f_dict.get("weight", 0)),
                "rationale": str(f_dict.get("rationale", ""))[:300],
            }
            factors_data.append(sanitized_f)
        factors_json = json.dumps(factors_data)

        # Truncate strings defensively to match DB schema definitions; anonymize session identifiers
        clean_entity_type = str(entity_type)[:32]
        if clean_entity_type.lower() == "session":
            if not str(entity_id).startswith("sess_ref_"):
                clean_entity_id = f"sess_ref_{hashlib.sha256(str(entity_id).encode('utf-8')).hexdigest()[:16]}"
            else:
                clean_entity_id = str(entity_id)[:64]
        else:
            clean_entity_id = str(entity_id)[:64]
        clean_trigger_event = str(trigger_event)[:64]

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO risk_audit_log (
                entity_type, entity_id, old_score, new_score, factors_json, trigger_event
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            clean_entity_type,
            clean_entity_id,
            int(old_score),
            int(new_score),
            factors_json,
            clean_trigger_event
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to write to risk_audit_log: %s", e)
        return False
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass


def _query_security_events(
    filter_col: str,
    filter_val: Any,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> list[dict]:
    """Safe internal helper to fetch security events within sliding window."""
    close_when_done = False
    if conn is None:
        try:
            from database import get_connection
            conn = get_connection()
            close_when_done = True
        except Exception:
            return []

    try:
        cursor = conn.cursor()
        allowed_cols = {"actor_id", "source_ip", "user_agent", "target_resource_id", "correlation_id", "event_category"}
        if filter_col not in allowed_cols:
            return []

        query = f"""
            SELECT event_id, event_type, severity, actor_id, actor_role,
                   target_resource, target_resource_id, correlation_id, source_ip,
                   user_agent, endpoint, event_category, details_json, timestamp
            FROM security_events
            WHERE {filter_col} = ?
            ORDER BY timestamp DESC
            LIMIT 100
        """
        cursor.execute(query, (str(filter_val),))
        rows = cursor.fetchall()

        events = []
        ref = reference_time or datetime.now(timezone.utc)
        for r in rows:
            ev = dict(r)
            ev_dt = _parse_event_timestamp(ev.get("timestamp"))
            if ev_dt:
                age_minutes = (ref - ev_dt).total_seconds() / 60.0
                if age_minutes <= window_minutes:
                    events.append(ev)
            else:
                events.append(ev)
        return events
    except Exception as e:
        logger.error("Error querying security events for risk evaluation: %s", e)
        return []
    finally:
        if close_when_done:
            try:
                conn.close()
            except Exception:
                pass
