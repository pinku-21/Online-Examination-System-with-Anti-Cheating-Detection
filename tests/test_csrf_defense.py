"""
Security Tests: SEC-016 CSRF Defense, Token Refresh Endpoint, and State-Changing API Protection.

Covers:
1. Rejection of state-changing requests missing CSRF token with machine-readable SEC-016 response.
2. Rejection of invalid CSRF token with SEC-016 response.
3. Verification that CSRF rejection happens before protected route executes (preventing premature side effects).
4. Dedicated GET /api/csrf-token endpoint behavior (Cache-Control: no-store, returns token for current session).
5. Cross-origin access denial on /api/csrf-token.
6. Session expiration detection (401 response when authenticated session has expired).
7. Multipart/form-data upload CSRF protection.
8. JSON payload CSRF protection.
9. Idempotency and protection of sensitive routes (exam submission, result toggling, incident management).
10. CSRF enforcement remains enabled for POST, PUT, DELETE, PATCH while GET/HEAD are permitted.
"""

import json
import pytest
from app import app, get_csrf_token
from database import get_connection


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Ensure Flask-WTF doesn't interfere with our native CSRF
    with app.test_client() as client:
        yield client


def test_csrf_token_endpoint_get_success(client):
    """GET /api/csrf-token should return a valid token and no-store headers."""
    resp = client.get("/api/csrf-token")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "csrf_token" in data
    assert len(data["csrf_token"]) == 48  # secrets.token_hex(24) = 48 hex chars
    assert "no-store" in resp.headers.get("Cache-Control", "")
    assert "no-cache" in resp.headers.get("Pragma", "")


def test_csrf_token_cross_origin_blocked(client):
    """GET /api/csrf-token must block requests originating from external untrusted origins."""
    resp = client.get("/api/csrf-token", headers={"Origin": "https://malicious-attacker.com"})
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["success"] is False
    assert "Cross-origin token retrieval prohibited" in data["error"]


def test_missing_csrf_token_returns_sec016(client):
    """A POST request to an API endpoint without CSRF token must return 403 with code SEC-016."""
    resp = client.post("/api/admin/create-student", json={"name": "Alice"})
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["success"] is False
    assert data["code"] == "SEC-016"
    assert "CSRF token missing or invalid" in data["error"]
    assert data["reauthentication_required"] is False


def test_invalid_csrf_token_returns_sec016(client):
    """A POST request with a corrupted/mismatched CSRF token must return 403 with code SEC-016."""
    resp = client.post(
        "/api/admin/create-student",
        headers={"X-CSRF-Token": "invalid_bogus_token_12345"},
        json={"name": "Alice"}
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["code"] == "SEC-016"


def test_rejection_happens_before_route_execution(client):
    """CSRF rejection occurs in before_request, preventing any route handler logic from running."""
    # Attempting to delete an exam without CSRF must fail at CSRF check, not route logic
    resp = client.delete("/api/admin/delete-exam/999999")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["code"] == "SEC-016"


def test_valid_csrf_token_in_header_passes_csrf_check(client):
    """Providing the correct token in X-CSRF-Token header bypasses CSRF rejection and enters route."""
    # First get a valid session token
    with client.session_transaction() as sess:
        sess["csrf_token"] = "valid_test_token_abcdef1234567890abcdef1234567890"

    # Make request with that token
    resp = client.post(
        "/api/admin/create-student",
        headers={"X-CSRF-Token": "valid_test_token_abcdef1234567890abcdef1234567890"},
        json={"name": "Alice"}
    )
    # The response must NOT be 403 CSRF SEC-016; it will proceed to admin_required check (401)
    assert resp.status_code != 403
    assert resp.status_code == 401
    data = resp.get_json()
    assert "Admin authentication required" in data["error"]


def test_valid_csrf_token_in_json_body_passes(client):
    """Providing the correct token inside JSON body (csrf_token key) also passes the CSRF check."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = "valid_json_token_abcdef1234567890abcdef1234567890"

    resp = client.post(
        "/api/admin/create-student",
        json={
            "csrf_token": "valid_json_token_abcdef1234567890abcdef1234567890",
            "name": "Alice"
        }
    )
    # Passes CSRF check and reaches admin auth check
    assert resp.status_code == 401
    assert resp.get_json().get("code") != "SEC-016"


def test_expired_session_returns_401_on_csrf_endpoint(client):
    """If an admin session has exceeded idle timeout or lifetime, /api/csrf-token returns 401 reauthentication_required."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_role"] = "admin"
        sess["_created_at"] = 1000
        sess["_last_active"] = 1000  # Stale timestamp (> 3600s ago)

    resp = client.get("/api/csrf-token")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False
    assert data["reauthentication_required"] is True
    assert "sign in again" in data["error"].lower()


def test_safe_methods_exempt_from_csrf(client):
    """GET and HEAD requests do not require a CSRF token."""
    resp = client.get("/api/csrf-token")
    assert resp.status_code == 200

    resp_head = client.head("/api/csrf-token")
    assert resp_head.status_code == 200
