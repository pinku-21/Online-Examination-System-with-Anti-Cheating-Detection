import time
import json
import threading
import socket
import pytest
from playwright.sync_api import sync_playwright
import app as flask_app
import database

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="module")
def live_server():
    flask_app.app.config['TESTING'] = True
    port = get_free_port()
    base_url = f"http://127.0.0.1:{port}"

    server = threading.Thread(
        target=lambda: flask_app.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True
    )
    server.start()
    time.sleep(1.2)
    yield base_url

def seed_test_soc_records():
    """Seeds predictable test recommendations and incidents for browser workflow tests."""
    conn = database.get_connection()
    c = conn.cursor()

    # Clear prior test records if any
    c.execute("DELETE FROM security_recommendations WHERE recommendation_id LIKE 'TEST-REC-%'")
    c.execute("DELETE FROM security_incidents WHERE incident_id LIKE 'TEST-INC-%'")
    c.execute("DELETE FROM incident_audit_trail WHERE incident_id LIKE 'TEST-INC-%'")
    c.execute("DELETE FROM incident_notes WHERE incident_id LIKE 'TEST-INC-%'")

    # 1. Seed 3 pending recommendations (Approve, Reject, Dismiss)
    c.execute("""
        INSERT INTO security_recommendations (
            recommendation_id, target_actor_id, target_resource, target_resource_id,
            risk_score, explanation, recommended_action, required_role, status
        ) VALUES
        ('TEST-REC-001', 1, 'account', '1', 65, 'Suspicious API burst test 1', 'recommend_mfa_stepup', 'admin', 'PENDING_REVIEW'),
        ('TEST-REC-002', 1, 'device', 'dev_fp_test2', 78, 'Suspicious device replacement', 'flag_proctor_review', 'admin', 'PENDING_REVIEW'),
        ('TEST-REC-003', 1, 'ip', '192.168.1.99', 35, 'IP subnet discrepancy', 'recommend_ip_verification', 'admin', 'PENDING_REVIEW')
    """)

    # 2. Seed a test incident with evidence and notes
    evidence = json.dumps({"source": "network_analyzer", "packet_loss": 0.05, "correlated_events": ["EV-01", "EV-02"]})
    c.execute("""
        INSERT INTO security_incidents (
            incident_id, title, incident_type, severity, risk_score, primary_actor_id,
            source_ip, summary, evidence_json, status
        ) VALUES (
            'TEST-INC-100', 'Automated E2E Test Anomaly', 'SUSPICIOUS_ACTIVITY', 'HIGH', 72, 1,
            '10.0.0.42', 'E2E automated proctoring verification incident', ?, 'OPEN'
        )
    """, (evidence,))

    c.execute("""
        INSERT INTO incident_audit_trail (incident_id, action, actor_name, details)
        VALUES ('TEST-INC-100', 'INCIDENT_CREATED', 'System', 'Initial creation during test setup')
    """)

    conn.commit()
    conn.close()

def test_soc_dashboard_browser_access_and_rendering(live_server):
    seed_test_soc_records()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()

        # 1. Unauthenticated access redirects / gets restricted
        page.goto(f"{live_server}/admin/security/soc")
        assert "/login" in page.url or page.locator("text=Login").count() > 0

        # 2. Login as Admin
        page.goto(f"{live_server}/login")
        page.fill('input[name="identifier"]', "admin")
        page.fill('input[name="password"]', "admin123")
        page.click('button[type="submit"]')
        page.wait_for_timeout(1000)

        # 3. Navigate to SOC Console
        page.goto(f"{live_server}/admin/security/soc")
        page.wait_for_selector("#stat-total-events", timeout=10000)

        # 4. Check KPIs and Header
        header_text = page.locator("h1").inner_text()
        assert "Security Operations Centre" in header_text

        # Verify Canonical Risk Threshold Badges in DOM
        assert page.locator("text=Critical (75–100)").count() > 0
        assert page.locator("text=High (45–74)").count() > 0
        assert page.locator("text=Medium (20–44)").count() > 0
        assert page.locator("text=Low (0–19)").count() > 0

        # 5. Check Section Switching
        incidents_tab = page.locator("#tab-soc-incidents")
        incidents_tab.click()
        page.wait_for_timeout(500)
        assert page.locator("#section-soc-incidents").is_visible()

        events_tab = page.locator("#tab-soc-events")
        events_tab.click()
        page.wait_for_timeout(500)
        assert page.locator("#section-soc-events").is_visible()

        # 6. Test Responsive Viewports
        page.set_viewport_size({'width': 375, 'height': 667})
        page.wait_for_timeout(200)
        assert page.locator("#stat-total-events").is_visible()

        page.set_viewport_size({'width': 768, 'height': 1024})
        page.wait_for_timeout(200)
        assert page.locator("#stat-total-events").is_visible()

        page.set_viewport_size({'width': 1280, 'height': 800})
        page.wait_for_timeout(300)
        browser.close()

def test_recommendation_workflow_browser(live_server):
    seed_test_soc_records()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()

        # Accept all browser dialogs (confirm prompts)
        page.on("dialog", lambda dialog: dialog.accept())

        # Login as Admin
        page.goto(f"{live_server}/login")
        page.fill('input[name="identifier"]', "admin")
        page.fill('input[name="password"]', "admin123")
        page.click('button[type="submit"]')
        page.wait_for_timeout(1000)

        page.goto(f"{live_server}/admin/security/soc")
        page.wait_for_selector("#recs-table-container", timeout=10000)

        # Verify test recommendations loaded
        page.wait_for_selector("text=TEST-REC-001", timeout=10000)
        assert page.locator("text=TEST-REC-001").count() > 0

        # --- A. Approve TEST-REC-001 ---
        # Find row for TEST-REC-001 and click Review
        row_1 = page.locator("tr", has_text="TEST-REC-001")
        row_1.locator("button", has_text="Review").click()
        page.wait_for_selector("#modal-rec-review:not(.hidden)", timeout=5000)

        page.fill("#review-rec-notes", "Approved by Playwright E2E automation")
        page.click("button:has-text('Approve Advisory')")
        page.wait_for_timeout(1000)

        # Verify status in database
        conn = database.get_connection()
        c = conn.cursor()
        c.execute("SELECT status, execution_notes FROM security_recommendations WHERE recommendation_id = 'TEST-REC-001'")
        rec1 = c.fetchone()
        assert rec1["status"] == "APPROVED"
        assert "Approved by Playwright E2E" in rec1["execution_notes"]

        # --- B. Reject TEST-REC-002 ---
        page.wait_for_selector("text=TEST-REC-002", timeout=5000)
        row_2 = page.locator("tr", has_text="TEST-REC-002")
        row_2.locator("button", has_text="Review").click()
        page.wait_for_selector("#modal-rec-review:not(.hidden)", timeout=5000)

        page.fill("#review-rec-notes", "Rejected false positive risk condition")
        page.click("button:has-text('Reject')")
        page.wait_for_timeout(1000)

        c.execute("SELECT status, execution_notes FROM security_recommendations WHERE recommendation_id = 'TEST-REC-002'")
        rec2 = c.fetchone()
        assert rec2["status"] == "REJECTED"
        assert "Rejected false positive" in rec2["execution_notes"]

        # --- C. Dismiss TEST-REC-003 ---
        page.wait_for_selector("text=TEST-REC-003", timeout=5000)
        row_3 = page.locator("tr", has_text="TEST-REC-003")
        row_3.locator("button", has_text="Review").click()
        page.wait_for_selector("#modal-rec-review:not(.hidden)", timeout=5000)

        page.fill("#review-rec-notes", "Dismissed test noise")
        page.click("button:has-text('Dismiss')")
        page.wait_for_timeout(1000)

        c.execute("SELECT status, execution_notes FROM security_recommendations WHERE recommendation_id = 'TEST-REC-003'")
        rec3 = c.fetchone()
        assert rec3["status"] == "DISMISSED"
        assert "Dismissed test noise" in rec3["execution_notes"]
        conn.close()

        # Capture screenshot of recommendation workflow result
        page.screenshot(path="C:/Users/DELL/.gemini/antigravity/brain/be1d17a2-2083-4d9e-b26e-82edc273b5d5/soc_recs_workflow_playwright.png")
        browser.close()

def test_incident_workflow_browser(live_server):
    seed_test_soc_records()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()

        # Login as Admin
        page.goto(f"{live_server}/login")
        page.fill('input[name="identifier"]', "admin")
        page.fill('input[name="password"]', "admin123")
        page.click('button[type="submit"]')
        page.wait_for_timeout(1000)

        page.goto(f"{live_server}/admin/security/soc")
        page.wait_for_selector("#tab-soc-incidents", timeout=10000)

        # Switch to incidents tab
        page.click("#tab-soc-incidents")
        page.wait_for_selector("text=TEST-INC-100", timeout=10000)

        # Open Incident Modal
        inc_row = page.locator("tr", has_text="TEST-INC-100")
        inc_row.locator("button", has_text="Investigate").click()
        page.wait_for_selector("#modal-incident-detail:not(.hidden)", timeout=5000)

        # Verify evidence is rendered
        assert page.locator("text=Correlated Telemetry Evidence").count() > 0
        assert page.locator("text=network_analyzer").count() > 0

        # Verify initial audit trail
        assert page.locator("text=Initial creation during test setup").count() > 0

        # Add Investigation Note
        page.fill("#input-new-incident-note", "Containment protocol verified by Playwright tester.")
        page.click("button:has-text('Post Note')")
        page.wait_for_timeout(1000)

        # Verify Note in Modal DOM
        assert page.locator("text=Containment protocol verified by Playwright tester.").count() > 0

        # Transition Incident Status to INVESTIGATING
        page.select_option("#select-incident-status", "INVESTIGATING")
        page.fill("#input-incident-status-notes", "Beginning forensic verification")
        page.click("button:has-text('Update Status')")
        page.wait_for_timeout(1000)

        # Check in DB
        conn = database.get_connection()
        c = conn.cursor()
        c.execute("SELECT status FROM security_incidents WHERE incident_id = 'TEST-INC-100'")
        inc_state = c.fetchone()
        assert inc_state["status"] == "INVESTIGATING"

        # Verify Audit History updated in Modal
        assert page.locator("text=Status changed from OPEN to INVESTIGATING").count() > 0
        conn.close()

        # Capture screenshot of incident modal
        page.screenshot(path="C:/Users/DELL/.gemini/antigravity/brain/be1d17a2-2083-4d9e-b26e-82edc273b5d5/soc_incident_modal_playwright.png")
        browser.close()

def test_api_failure_handling_browser(live_server):
    seed_test_soc_records()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()

        # Login as Admin
        page.goto(f"{live_server}/login")
        page.fill('input[name="identifier"]', "admin")
        page.fill('input[name="password"]', "admin123")
        page.click('button[type="submit"]')
        page.wait_for_timeout(1000)

        page.goto(f"{live_server}/admin/security/soc")
        page.wait_for_selector("#stat-total-events", timeout=10000)

        # Capture initial KPI values to verify they remain intact across errors
        initial_events_text = page.locator("#stat-total-events").inner_text()
        assert initial_events_text != ""

        # --- A. Simulate Network Failure / Interrupted Fetch ---
        page.route("**/api/admin/security/overview", lambda route: route.abort("failed"))
        # Trigger manual refresh
        page.click("button[onclick='triggerManualRefresh()']")
        page.wait_for_timeout(1000)

        # Existing data remains visible and fallback message appears
        assert page.locator("#stat-total-events").inner_text() == initial_events_text
        refresh_badge = page.locator("#soc-last-refresh").inner_text()
        assert "Interrupted" in refresh_badge or "degraded" in refresh_badge.lower()

        # --- B. Simulate HTTP 500 ---
        page.route("**/api/admin/security/overview", lambda route: route.fulfill(
            status=500,
            content_type="application/json",
            body=json.dumps({"success": False, "error": "Internal Database Error"})
        ))
        page.click("button[onclick='triggerManualRefresh()']")
        page.wait_for_timeout(1000)
        assert page.locator("#stat-total-events").inner_text() == initial_events_text

        # --- C. Simulate HTTP 403 (Permission Denial) ---
        page.route("**/api/admin/security/overview", lambda route: route.fulfill(
            status=403,
            content_type="application/json",
            body=json.dumps({"success": False, "error": "Access Restricted: Administrative Privileges Required"})
        ))
        page.click("button[onclick='triggerManualRefresh()']")
        page.wait_for_timeout(1000)
        refresh_text_403 = page.locator("#soc-last-refresh").inner_text()
        assert "Access Restricted" in refresh_text_403 or "Privileges Required" in refresh_text_403
        # Ensure it was not mislabeled as Session Expired
        assert "Session Expired" not in refresh_text_403

        # --- D. Simulate HTTP 401 (Authentication Expired) ---
        page.route("**/api/admin/security/overview", lambda route: route.fulfill(
            status=401,
            content_type="application/json",
            body=json.dumps({"success": False, "error": "Authentication required"})
        ))
        page.click("button[onclick='triggerManualRefresh()']")
        page.wait_for_timeout(1000)
        refresh_text_401 = page.locator("#soc-last-refresh").inner_text()
        assert "Session Expired" in refresh_text_401

        # Capture error handling screenshot
        page.screenshot(path="C:/Users/DELL/.gemini/antigravity/brain/be1d17a2-2083-4d9e-b26e-82edc273b5d5/soc_failure_handling_playwright.png")
        browser.close()
