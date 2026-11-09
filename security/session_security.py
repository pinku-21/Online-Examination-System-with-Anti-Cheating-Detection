"""
Session Security and Lifecycle Protection for ExamGuard AI.
Enforces session rotation, idle timeouts, absolute session expiry,
and active administrator session tracking without disrupting student examination attempts.
"""

from datetime import datetime, timezone, timedelta
import logging
import secrets
from flask import session, request

logger = logging.getLogger("examguard.security.session")

# Session Limits
ADMIN_IDLE_TIMEOUT_SECONDS = 3600       # 1 hour idle timeout for tutors/admins
ADMIN_ABSOLUTE_LIFETIME_SECONDS = 43200  # 12 hours max session for admins
STUDENT_ABSOLUTE_LIFETIME_SECONDS = 86400 # 24 hours max session for students


def rotate_session():
    """
    Rotates the session ID and synchronizer tokens upon authentication/privilege change.
    Preserves essential identity keys while regenerating the session token to prevent session fixation.
    """
    old_data = dict(session)
    session.clear()

    # Re-insert identity keys
    for k, v in old_data.items():
        session[k] = v

    # Generate fresh synchronizer and session tokens
    session["csrf_token"] = secrets.token_hex(24)
    session["session_token"] = secrets.token_hex(20)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    session["_created_at"] = now_ts
    session["_last_active"] = now_ts


def check_session_validity() -> tuple[bool, str | None]:
    """
    Checks if the current session has exceeded idle timeout or absolute lifetime.
    Students actively taking an exam are protected from idle disconnection.
    """
    if not session.get("user_id"):
        return True, None

    now_ts = int(datetime.now(timezone.utc).timestamp())
    role = session.get("user_role", "student")

    created_at = session.get("_created_at", now_ts)
    last_active = session.get("_last_active", now_ts)

    # 1. Absolute Lifetime Check
    max_lifetime = ADMIN_ABSOLUTE_LIFETIME_SECONDS if role == "admin" else STUDENT_ABSOLUTE_LIFETIME_SECONDS
    if (now_ts - created_at) > max_lifetime:
        return False, "Your session has reached its absolute maximum lifetime. Please sign in again."

    # 2. Idle Timeout Check (Admins only; students taking exams must never be prematurely logged out)
    if role == "admin":
        if (now_ts - last_active) > ADMIN_IDLE_TIMEOUT_SECONDS:
            return False, "Your session timed out due to inactivity. Please sign in again."

    # Update activity timestamp
    session["_last_active"] = now_ts
    return True, None

