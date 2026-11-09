"""
ExamGuard AI — Security Package
Provides centralized security event collection, advanced event correlation,
incident management lifecycle, deterministic risk scoring, TOTP multi-factor authentication,
and session protection.
"""

from .event_collector import record_security_event, sanitize_security_details, anonymize_session_identifier
from .event_correlator import correlate_event, get_correlation_window_events, CORRELATION_THRESHOLDS
from .incident_manager import (
    create_incident,
    transition_incident_status,
    add_incident_note,
    get_incident_details,
    VALID_STATUSES,
    ALLOWED_TRANSITIONS,
)
from .risk_engine import (
    calculate_risk_score,
    assess_account_risk,
    assess_session_risk,
    assess_device_risk,
    assess_ip_context_risk,
    assess_examination_risk,
    record_risk_audit_transition,
    RiskAssessment,
    RiskFactor,
)
from .anomaly_detector import (
    detect_anomalies_for_target,
    evaluate_anomalies_and_risk,
    AnomalyFinding,
)
from .mfa_service import (
    generate_mfa_secret,
    get_totp_uri,
    generate_totp_code,
    verify_totp_code,
    generate_recovery_codes,
    verify_and_consume_recovery_code,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    resolve_primary_mfa_encryption_key,
    get_all_mfa_decryption_keys,
    migrate_unencrypted_mfa_secrets,
)
from .policy_engine import (
    evaluate_policies_for_assessment,
    generate_security_recommendations,
    get_active_policies,
    get_recommendation_details,
    review_security_recommendation,
    check_existing_active_recommendation,
    SUPPORTED_ADVISORY_ACTIONS,
    VALID_RECOMMENDATION_STATUSES,
    PolicyEvaluationResult,
)
from .session_security import (
    rotate_session,
    check_session_validity,
    ADMIN_IDLE_TIMEOUT_SECONDS,
    ADMIN_ABSOLUTE_LIFETIME_SECONDS,
)
from .incident_intelligence import (
    get_unified_incident_intelligence,
    build_investigation_timeline,
    correlate_entities_across_events,
)

__all__ = [
    "record_security_event",
    "sanitize_security_details",
    "anonymize_session_identifier",
    "correlate_event",
    "get_correlation_window_events",
    "CORRELATION_THRESHOLDS",
    "create_incident",
    "transition_incident_status",
    "add_incident_note",
    "get_incident_details",
    "get_unified_incident_intelligence",
    "build_investigation_timeline",
    "correlate_entities_across_events",
    "VALID_STATUSES",
    "ALLOWED_TRANSITIONS",
    "calculate_risk_score",
    "RiskAssessment",
    "generate_mfa_secret",
    "get_totp_uri",
    "generate_totp_code",
    "verify_totp_code",
    "generate_recovery_codes",
    "verify_and_consume_recovery_code",
    "rotate_session",
    "check_session_validity",
    "ADMIN_IDLE_TIMEOUT_SECONDS",
    "ADMIN_ABSOLUTE_LIFETIME_SECONDS",
]
