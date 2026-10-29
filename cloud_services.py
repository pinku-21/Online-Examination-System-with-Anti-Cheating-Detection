"""
Cloud Services & Free-Tier Integrations Manager for ExamGuard AI
Provides resilient, fallback-ready wrappers for services featured in free-for-dev:
1. Cloudinary: Persistent storage for candidate biometric photos & cheating snapshots
2. Resend: 3,000 free transactional emails/month for scorecard publication & invitations
3. Sentry: Real-time application error & crash monitoring
"""

import os
import io
import time
import base64
from database import get_setting

# ── 1. SENTRY ERROR & CRASH MONITORING ───────────────────────────────────────
def init_sentry(app=None):
    """Initializes Sentry SDK if SENTRY_DSN is configured in environment or settings."""
    dsn = os.environ.get("SENTRY_DSN", "").strip() or get_setting("sentry_dsn", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(
            dsn=dsn,
            integrations=[FlaskIntegration()] if app else [],
            traces_sample_rate=0.2,
            environment=os.environ.get("FLASK_ENV", "production")
        )
        print("[CloudServices] Sentry error monitoring initialized successfully.")
        return True
    except Exception as e:
        print(f"[CloudServices] Sentry init warning: {e}")
        return False


# ── 2. CLOUDINARY PERSISTENT MEDIA STORAGE ──────────────────────────────────
def upload_image_to_cloud(file_bytes_or_path, folder="examguard", public_id=None):
    """
    Uploads an image (raw bytes or local file path) to Cloudinary free media cloud.
    Falls back gracefully to local storage if Cloudinary is not configured.
    Returns: (is_cloud: bool, url_or_local_path: str)
    """
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME", "").strip() or get_setting("cloudinary_cloud_name", "").strip()
    api_key = os.environ.get("CLOUDINARY_API_KEY", "").strip() or get_setting("cloudinary_api_key", "").strip()
    api_secret = os.environ.get("CLOUDINARY_API_SECRET", "").strip() or get_setting("cloudinary_api_secret", "").strip()

    if not (cloud_name and api_key and api_secret):
        return False, None

    try:
        import cloudinary
        import cloudinary.uploader
        cloudinary.config(
            cloud_name=cloud_name,
            api_key=api_key,
            api_secret=api_secret,
            secure=True
        )

        upload_kwargs = {"folder": folder}
        if public_id:
            upload_kwargs["public_id"] = public_id

        if isinstance(file_bytes_or_path, bytes):
            res = cloudinary.uploader.upload(io.BytesIO(file_bytes_or_path), **upload_kwargs)
        elif isinstance(file_bytes_or_path, str) and file_bytes_or_path.startswith("data:image/"):
            res = cloudinary.uploader.upload(file_bytes_or_path, **upload_kwargs)
        else:
            res = cloudinary.uploader.upload(file_bytes_or_path, **upload_kwargs)

        secure_url = res.get("secure_url") or res.get("url")
        return True, secure_url
    except Exception as e:
        print(f"[CloudServices] Cloudinary upload fallback to local: {e}")
        return False, None


# ── 3. RESEND TRANSACTIONAL EMAIL SERVICE ────────────────────────────────────
def send_transactional_email(to_email, subject, html_content):
    """
    Sends an email using Resend (free 3,000 emails/month).
    Falls back safely if no API key is set.
    """
    api_key = os.environ.get("RESEND_API_KEY", "").strip() or get_setting("resend_api_key", "").strip()
    from_email = os.environ.get("RESEND_FROM_EMAIL", "").strip() or get_setting("resend_from_email", "").strip() or "onboarding@resend.dev"

    if not api_key:
        return {"success": False, "error": "Resend API key not configured."}

    try:
        import resend
        resend.api_key = api_key

        params = {
            "from": f"ExamGuard AI <{from_email}>",
            "to": [to_email] if isinstance(to_email, str) else to_email,
            "subject": subject,
            "html": html_content
        }
        resp = resend.Emails.send(params)
        return {"success": True, "id": resp.get("id")}
    except Exception as e:
        print(f"[CloudServices] Resend email send error: {e}")
        return {"success": False, "error": str(e)}


# ── 4. IP GEOLOCATION & PROXY/VPN DETECTOR (free-for-dev) ──────────────────────
def get_ip_intelligence(client_ip):
    """
    Looks up IP geolocation and VPN/hosting/datacenter flags via ipapi.co (free tier).
    Returns a dict with location, ISP, and risk indicators.
    """
    if not client_ip or client_ip in ("127.0.0.1", "::1", "localhost"):
        return {
            "ip": client_ip,
            "city": "Localhost / Dev",
            "region": "Local",
            "country": "Local",
            "isp": "Local Loopback",
            "is_suspicious": False,
            "risk_reason": None
        }

    try:
        import urllib.request
        import json

        # Support clean comma-separated X-Forwarded-For IPs
        clean_ip = client_ip.split(",")[0].strip()
        url = f"https://ipapi.co/{clean_ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "ExamGuardAI/1.0"})

        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("error"):
            return {
                "ip": clean_ip,
                "city": "Unknown",
                "country": "Unknown",
                "isp": "Unknown",
                "is_suspicious": False,
                "risk_reason": None
            }

        city = data.get("city") or "Unknown"
        region = data.get("region") or ""
        country = data.get("country_name") or data.get("country") or "Unknown"
        org = data.get("org") or data.get("asn") or ""

        # Known datacenter/hosting/VPN providers that indicate candidates not taking exam directly
        vpn_indicators = [
            "digitalocean", "linode", "ovh", "hetzner", "amazon", "aws", "microsoft",
            "azure", "google cloud", "vultr", "nordvpn", "expressvpn", "mullvad",
            "surfshark", "proton", "datacenter", "hosting", "tor exit"
        ]

        org_lower = org.lower()
        is_suspicious = any(indicator in org_lower for indicator in vpn_indicators)
        risk_reason = f"Datacenter/VPN/Proxy ASN: {org}" if is_suspicious else None

        return {
            "ip": clean_ip,
            "city": city,
            "region": region,
            "country": country,
            "isp": org,
            "is_suspicious": is_suspicious,
            "risk_reason": risk_reason
        }
    except Exception as e:
        print(f"[CloudServices] IP Geolocation lookup warning for {client_ip}: {e}")
        return {
            "ip": client_ip,
            "city": "Undetected",
            "region": "",
            "country": "",
            "isp": "",
            "is_suspicious": False,
            "risk_reason": None
        }


