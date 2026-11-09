"""
Centralized Security Event Collector for ExamGuard AI.
Ingests, sanitizes, and persists security-relevant telemetry.
Maintains strict data minimization: NEVER records passwords, tokens, cookies, or clipboard contents.
"""

import json
import logging
import uuid
import hashlib
from datetime import datetime, timezone

from database import get_connection

logger = logging.getLogger("examguard.security")

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CATEGORIES = {"auth", "authorization", "session", "api", "csrf", "exam_integrity", "general"}

# Sensitive fields that must NEVER appear in security event details
REDACTED_KEYS = {
    "password", "passwd", "secret", "token", "csrf_token", "x-csrf-token",
    "cookie", "session", "session_token", "clipboard", "clipboard_content",
    "authorization", "auth_token", "bearer", "private_key", "key",
    "mfa_secret", "totp_secret", "recovery_code", "recovery_codes",
}


def anonymize_session_identifier(identifier: str | None) -> str:
    """
    Transforms a raw session token into an opaque, non-reversible surrogate identifier
    using SHA-256 with a security prefix (e.g. 'sess_ref_a1b2c3d4e5f6').
    Never exposes raw tokens, token prefixes, or suffixes.
    Preserves internal correlation without exposing authentication credentials.
    """
    if not identifier:
        return "sess_ref_unknown"
    ident_str = str(identifier).strip()
    if not ident_str:
        return "sess_ref_unknown"
    if ident_str.startswith("sess_ref_"):
        return ident_str
    digest = hashlib.sha256(ident_str.encode("utf-8")).hexdigest()[:16]
    return f"sess_ref_{digest}"


def sanitize_security_details(details: dict | None) -> dict:
    """Sanitizes metadata dictionary removing any passwords, secrets, tokens, or sensitive PII."""
    if not details or not isinstance(details, dict):
        return {}

    sanitized = {}
    for key, val in details.items():
        k_lower = str(key).lower()
        if any(redacted in k_lower for redacted in REDACTED_KEYS):
            continue  # Completely omit sensitive keys
        if isinstance(val, dict):
            sanitized[key] = sanitize_security_details(val)
        elif isinstance(val, (str, int, float, bool)) or val is None:
            # Bound string length to prevent log bloating or injection
            if isinstance(val, str) and len(val) > 500:
                sanitized[key] = val[:500] + "...[truncated]"
            else:
                sanitized[key] = val
        elif isinstance(val, list):
            sanitized_list = []
            for item in val[:20]:
                if isinstance(item, dict):
                    sanitized_list.append(sanitize_security_details(item))
                elif isinstance(item, (str, int, float, bool)) or item is None:
                    if isinstance(item, str) and len(item) > 500:
                        sanitized_list.append(item[:500] + "...[truncated]")
                    else:
                        sanitized_list.append(item)
            sanitized[key] = sanitized_list
    return sanitized


def record_security_event(
    event_type: str,
    severity: str = "LOW",
    event_category: str = "general",
    actor_id: int | None = None,
    actor_role: str | None = None,
    target_resource: str | None = None,
    target_resource_id: str | None = None,
    correlation_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    endpoint: str | None = None,
    details: dict | None = None,
    conn=None,
) -> str | None:
    """
    Central function to record a security event.
    Returns the unique event_id if successful, or None on failure.
    Guaranteed NEVER to raise exceptions to callers so application execution remains unaffected.
    """
    try:
        if not event_type or not isinstance(event_type, str):
            logger.warning("Rejected security event with invalid or missing event_type.")
            return None

        clean_severity = (severity or "LOW").upper()
        if clean_severity not in VALID_SEVERITIES:
            clean_severity = "LOW"

        clean_category = (event_category or "general").lower()
        if clean_category not in VALID_CATEGORIES:
            clean_category = "general"

        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        sanitized_details = sanitize_security_details(details)
        details_json = json.dumps(sanitized_details)

        # Truncate string fields defensively
        clean_target_resource = target_resource[:64] if target_resource else None
        clean_target_id = str(target_resource_id)[:64] if target_resource_id else None
        clean_correlation_id = correlation_id[:64] if correlation_id else None
        clean_source_ip = source_ip[:64] if source_ip else None
        clean_user_agent = user_agent[:500] if user_agent else None
        clean_endpoint = endpoint[:255] if endpoint else None
        clean_role = actor_role[:32] if actor_role else None

        close_after = False
        if conn is None:
            conn = get_connection()
            close_after = True

        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_events (
                    event_id, event_type, severity, actor_id, actor_role,
                    target_resource, target_resource_id, correlation_id,
                    source_ip, user_agent, endpoint, event_category, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    clean_severity,
                    actor_id,
                    clean_role,
                    clean_target_resource,
                    clean_target_id,
                    clean_correlation_id,
                    clean_source_ip,
                    clean_user_agent,
                    clean_endpoint,
                    clean_category,
                    details_json,
                ),
            )
            conn.commit()

            # Trigger background correlation evaluation without blocking
            try:
                from .event_correlator import correlate_event
                correlate_event(event_id, conn=conn)
            except Exception as ce:
                logger.debug("Correlation check failed: %s", ce)

            return event_id
        finally:
            if close_after:
                conn.close()

    except Exception as e:
        logger.error("Failed to record security event %s: %s", event_type, e, exc_info=False)
        return None

