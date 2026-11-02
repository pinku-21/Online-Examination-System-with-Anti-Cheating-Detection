import os
import pytest
from app import app

def test_google_search_console_verification_route():
    """Verify Google Search Console HTML verification file is served publicly with exact content."""
    verification_filename = "googlede1ba37c9959b88b.html"
    file_path = os.path.join(app.root_path, verification_filename)

    # 1. Assert the physical file exists on disk and read exact raw content
    assert os.path.isfile(file_path), f"Verification file {verification_filename} must exist on disk."
    with open(file_path, "r", encoding="utf-8") as f:
        expected_content = f.read()

    assert expected_content.strip() == "google-site-verification: googlede1ba37c9959b88b.html"

    # 2. Assert public unauthenticated GET request returns 200, correct MIME type, and exact file body
    with app.test_client() as client:
        response = client.get(f"/{verification_filename}")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("Content-Type", "")
        assert response.data.decode("utf-8") == expected_content

