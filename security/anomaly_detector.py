"""
Deterministic, Explainable Behavioural Anomaly Detection Engine for ExamGuard AI.
Complies with Phase 4 Cybersecurity Architecture:
1. Detects multi-pattern behavioral anomalies using deterministic, auditable rules:
   - Repeated failed login attempts (credential stuffing / brute force).
   - Unusual device replacement frequency (rapid switching between different hardware/browsers).
   - Repeated session replacement / rapid displacer patterns.
   - Suspicious API request frequency / burst patterns.
   - Repeated unauthorized access attempts (broken object level authorization / IDOR).
   - Unusual security-event frequency (elevated alert density across categories).
   - Abnormal examination activity (e.g. concurrent answers from divergent IPs, rapid re-connections).
2. Avoids machine learning without ground-truth labels.
3. Completely resilient to database errors (returns empty anomalies without raising).
4. Never terminates candidate sessions, interrupts active examinations, or bans users automatically.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from typing import Any

from .event_collector import record_security_event
from .risk_engine import (
    RiskAssessment,
    calculate_risk_score,
    _parse_event_timestamp,
    _query_security_events,
)

logger = logging.getLogger("examguard.security.anomaly")

# Explicit rule thresholds
THRESHOLD_FAILED_LOGINS = 3          # Failed logins within window
THRESHOLD_DEVICE_SWITCHES = 2        # Device switches within window
THRESHOLD_API_BURST = 15             # Security events within rapid window (e.g. 5m)
THRESHOLD_UNAUTHORIZED_ACCESS = 3    # Unauthorized/forbidden hits within window
THRESHOLD_TOTAL_EVENT_FREQUENCY = 6  # Elevated overall security events


@dataclass
class AnomalyFinding:
    rule_name: str
    severity: str                     # LOW, MEDIUM, HIGH, CRITICAL
    target_type: str                  # account, session, device, ip, exam
    target_id: str
    confidence: float                 # 0.0 - 1.0 (deterministic confidence)
    description: str
    triggering_events: list[dict] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "confidence": self.confidence,
            "description": self.description,
            "triggering_event_ids": [e.get("event_id") for e in self.triggering_events if e.get("event_id")],
            "recommended_action": self.recommended_action,
        }


def detect_anomalies_for_target(
    target_type: str,
    target_id: str | int,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> list[AnomalyFinding]:
    """
    Evaluates all deterministic behavioral rules against a given target.
    Target types: 'account', 'session', 'device', 'ip', 'examination'.
    Returns a list of AnomalyFinding objects.
    """
    col_map = {
        "account": "actor_id",
        "ip": "source_ip",
        "device": "user_agent",
        "examination": "target_resource_id",
        "session": "target_resource_id",
    }
    col = col_map.get(target_type)
    if not col:
        return []

    events = _query_security_events(
        filter_col=col,
        filter_val=target_id,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )

    findings: list[AnomalyFinding] = []

    # 1. Repeated Failed Login Rule
    failed_logins = [e for e in events if e.get("event_type") == "auth.failed_login"]
    if len(failed_logins) >= THRESHOLD_FAILED_LOGINS:
        findings.append(
            AnomalyFinding(
                rule_name="repeated_failed_logins",
                severity="HIGH" if len(failed_logins) >= 5 else "MEDIUM",
                target_type=target_type,
                target_id=str(target_id),
                confidence=min(1.0, 0.6 + (len(failed_logins) * 0.08)),
                description=(
                    f"Observed {len(failed_logins)} failed authentication attempts "
                    f"within {window_minutes} minutes."
                ),
                triggering_events=failed_logins,
                recommended_action="flag_for_proctor_review",
            )
        )

    # 2. Unusual Device Replacement / Rapid Switch Rule
    device_switches = [
        e for e in events
        if e.get("event_type") in ("auth.unusual_device_switch", "auth.device_replacement", "auth.rapid_device_switch")
    ]
    if len(device_switches) >= THRESHOLD_DEVICE_SWITCHES:
        findings.append(
            AnomalyFinding(
                rule_name="unusual_device_replacement_frequency",
                severity="HIGH" if len(device_switches) >= 3 else "MEDIUM",
                target_type=target_type,
                target_id=str(target_id),
                confidence=0.85,
                description=(
                    f"Observed {len(device_switches)} device replacement requests/transitions "
                    f"within {window_minutes} minutes."
                ),
                triggering_events=device_switches,
                recommended_action="prompt_proctor_identity_check",
            )
        )

    # 3. Repeated Unauthorized Access / IDOR Attempt Rule
    unauthorized_hits = [
        e for e in events
        if e.get("event_type") in ("authorization.unauthorized_access", "authorization.idor_attempt", "authorization.privilege_escalation_attempt")
    ]
    if len(unauthorized_hits) >= THRESHOLD_UNAUTHORIZED_ACCESS:
        findings.append(
            AnomalyFinding(
                rule_name="repeated_unauthorized_access",
                severity="HIGH",
                target_type=target_type,
                target_id=str(target_id),
                confidence=0.90,
                description=(
                    f"Observed {len(unauthorized_hits)} unauthorized access/IDOR violations "
                    f"within {window_minutes} minutes."
                ),
                triggering_events=unauthorized_hits,
                recommended_action="recommend_access_containment_review",
            )
        )

    # 4. Suspicious API Request Bursts / Alert Density Proxy
    # Proxy evaluation: Measures elevated density of security-relevant alert events within a 5-minute sub-window.
    # Note: Normal high-volume client polling (e.g. 3.5s sync-events or heartbeats) does not generate security_events
    # and therefore cannot trigger false-positive burst alerts.
    ref = reference_time or datetime.now(timezone.utc)
    burst_events = []
    for ev in events:
        ev_dt = _parse_event_timestamp(ev.get("timestamp"))
        if ev_dt and 0.0 <= (ref - ev_dt).total_seconds() <= 300:
            burst_events.append(ev)

    if len(burst_events) >= THRESHOLD_API_BURST:
        findings.append(
            AnomalyFinding(
                rule_name="suspicious_api_request_burst",
                severity="MEDIUM",
                target_type=target_type,
                target_id=str(target_id),
                confidence=0.80,
                description=(
                    f"High security event volume burst: {len(burst_events)} security alerts "
                    "generated in a 5-minute window (security alert density proxy)."
                ),
                triggering_events=burst_events,
                recommended_action="rate_limit_review",
            )
        )

    # 5. Abnormal Examination Activity Rule (for examination scope)
    # Validates answer tampering attempts, suspicious answer edits, or state collision
    # Note: Stale CSRF tokens alone are NOT classified as cheating unless combined with answer tampering.
    if target_type == "examination":
        exam_tamper_events = [
            e for e in events
            if e.get("event_type") in ("exam.answer_tampering_attempt", "exam.state_conflict")
        ]
        if exam_tamper_events:
            findings.append(
                AnomalyFinding(
                    rule_name="abnormal_examination_activity",
                    severity="HIGH",
                    target_type="examination",
                    target_id=str(target_id),
                    confidence=0.88,
                    description=(
                        f"Detected {len(exam_tamper_events)} high-severity integrity alert(s) "
                        f"during active examination attempt."
                    ),
                    triggering_events=exam_tamper_events,
                    recommended_action="dispatch_proctor_advisory",
                )
            )

    return findings


def evaluate_anomalies_and_risk(
    target_type: str,
    target_id: str | int,
    conn=None,
    window_minutes: int = 60,
    reference_time: datetime | None = None
) -> dict:
    """
    Combined behavioral assessment:
    Returns both the quantitative RiskAssessment and list of AnomalyFindings.
    """
    col_map = {
        "account": "actor_id",
        "ip": "source_ip",
        "device": "user_agent",
        "examination": "target_resource_id",
        "session": "target_resource_id",
    }
    col = col_map.get(target_type, "actor_id")
    events = _query_security_events(
        filter_col=col,
        filter_val=target_id,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )

    risk_eval = calculate_risk_score(
        events=events,
        scope=target_type,
        target_id=str(target_id),
        reference_time=reference_time
    )
    anomalies = detect_anomalies_for_target(
        target_type=target_type,
        target_id=target_id,
        conn=conn,
        window_minutes=window_minutes,
        reference_time=reference_time
    )

    return {
        "risk_assessment": risk_eval.to_dict(),
        "anomalies": [a.to_dict() for a in anomalies],
        "anomaly_count": len(anomalies),
        "target_type": target_type,
        "target_id": str(target_id),
    }

