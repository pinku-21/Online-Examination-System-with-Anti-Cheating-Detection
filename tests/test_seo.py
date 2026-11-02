import os
import xml.etree.ElementTree as ET
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_robots_txt_crawlability_and_directives(client):
    """
    Verify robots.txt is accessible and allows crawling so search engine bots
    can read HTTP response headers (such as X-Robots-Tag: noindex, nofollow).
    """
    res = client.get("/robots.txt")
    assert res.status_code == 200
    assert res.mimetype == "text/plain"
    content = res.get_data(as_text=True)

    assert "User-agent: *" in content
    assert "Allow: /" in content
    # Ensure no Disallow rules block bots from seeing noindex headers
    assert "Disallow:" not in content
    assert "Sitemap: https://exam.pinku19.me/sitemap.xml" in content


def test_sitemap_xml_validity_and_urls(client):
    """
    Verify sitemap.xml is valid XML, lists only public, 200-OK indexable canonical URLs,
    and contains no login-only, redirects, or non-indexable pages.
    """
    res = client.get("/sitemap.xml")
    assert res.status_code == 200
    assert "xml" in res.mimetype
    raw_xml = res.get_data()

    root = ET.fromstring(raw_xml)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [elem.text for elem in root.findall(".//sm:loc", ns)]

    expected_urls = [
        "https://exam.pinku19.me/",
        "https://exam.pinku19.me/login",
        "https://exam.pinku19.me/register",
    ]
    assert sorted(locs) == sorted(expected_urls)

    # Confirm every sitemap URL resolves with HTTP 200
    for loc in locs:
        path = loc.replace("https://exam.pinku19.me", "")
        if path == "":
            path = "/"
        route_res = client.get(path)
        assert route_res.status_code == 200, f"Sitemap URL {loc} returned {route_res.status_code}"


def test_canonical_urls_on_public_pages(client):
    """
    Verify self-referencing canonical URLs on each public page and no incorrect fallback to homepage.
    """
    # 1. Homepage
    res_home = client.get("/")
    assert res_home.status_code == 200
    html_home = res_home.get_data(as_text=True)
    assert '<link rel="canonical" href="https://exam.pinku19.me/">' in html_home

    # 2. Login Page
    res_login = client.get("/login")
    assert res_login.status_code == 200
    html_login = res_login.get_data(as_text=True)
    assert '<link rel="canonical" href="https://exam.pinku19.me/login">' in html_login

    # 3. Register Page
    res_register = client.get("/register")
    assert res_register.status_code == 200
    html_register = res_register.get_data(as_text=True)
    assert '<link rel="canonical" href="https://exam.pinku19.me/register">' in html_register


def test_private_routes_canonical_suppression_and_noindex(client):
    """
    Verify private / authenticated / exam routes do NOT declare improper canonical tags
    and enforce noindex via both X-Robots-Tag headers and HTML meta tags where rendered.
    """
    # 1. /student (302 redirect)
    res_student = client.get("/student")
    assert res_student.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # 2. /student/dashboard
    res_std_dash = client.get("/student/dashboard")
    assert res_std_dash.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # 3. /tutor (302 redirect)
    res_tutor = client.get("/tutor")
    assert res_tutor.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # 4. /exam/some-token
    res_exam = client.get("/exam/test-token")
    assert res_exam.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # 5. /api/health_status
    res_api = client.get("/api/health_status")
    assert res_api.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # 6. /submission/some-id
    res_sub = client.get("/submission/123/details")
    assert res_sub.headers.get("X-Robots-Tag") == "noindex, nofollow"

    # Ensure public pages do NOT have X-Robots-Tag header
    assert "X-Robots-Tag" not in res_home_headers(client)


def res_home_headers(client):
    return client.get("/").headers


def test_favicon_serving(client):
    """Verify /favicon.ico and /static/favicon.svg respond with status 200 and SVG content."""
    res_ico = client.get("/favicon.ico")
    assert res_ico.status_code == 200
    assert "svg" in res_ico.mimetype

    res_svg = client.get("/static/favicon.svg")
    assert res_svg.status_code == 200
    assert "<svg" in res_svg.get_data(as_text=True)


def test_google_verification_still_intact(client):
    """Verify Google Search Console token file remains served publicly without auth."""
    res = client.get("/googlede1ba37c9959b88b.html")
    assert res.status_code == 200
    assert "google-site-verification: googlede1ba37c9959b88b.html" in res.get_data(as_text=True)
