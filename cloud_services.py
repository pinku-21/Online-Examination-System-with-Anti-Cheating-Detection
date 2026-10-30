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

# ── 1. SENTRY ERROR & CRASH MONITORING (DISABLED) ───────────────────────────
def init_sentry(app=None):
    """Sentry error monitoring has been disabled per user request."""
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

    clean_ip = client_ip.split(",")[0].strip()
    bdc_key = os.environ.get("BIGDATACLOUD_API_KEY", "").strip() or get_setting("bigdatacloud_api_key", "").strip()

    import urllib.request
    import json

    # 1. Try BigDataCloud if API key is configured (provides dedicated VPN & Tor hazard analysis)
    if bdc_key:
        try:
            bdc_url = f"https://api.bigdatacloud.net/data/ip-geolocation-full?ip={clean_ip}&key={bdc_key}"
            with urllib.request.urlopen(bdc_url, timeout=3.5) as resp:
                bdc_data = json.loads(resp.read().decode("utf-8"))
            
            city = (bdc_data.get("location") or {}).get("city") or "Unknown"
            country = (bdc_data.get("country") or {}).get("name") or "Unknown"
            isp = (bdc_data.get("network") or {}).get("organisation") or ""
            hazard = bdc_data.get("hazardReport") or {}

            is_vpn = hazard.get("isKnownAsVpn", False)
            is_tor = hazard.get("isKnownAsTorServer", False)
            is_proxy = hazard.get("isKnownAsProxy", False)
            is_hosting = hazard.get("isHostingAsn", False) or hazard.get("hostingLikelihood", 0) > 50

            is_suspicious = is_vpn or is_tor or is_proxy or is_hosting
            reasons = []
            if is_vpn: reasons.append("VPN Detected")
            if is_tor: reasons.append("Tor Exit Node")
            if is_proxy: reasons.append("Proxy Server")
            if is_hosting: reasons.append("Datacenter IP")

            return {
                "ip": clean_ip,
                "city": city,
                "region": (bdc_data.get("location") or {}).get("principalSubdivision") or "",
                "country": country,
                "isp": isp,
                "is_suspicious": is_suspicious,
                "risk_reason": " | ".join(reasons) if reasons else None
            }
        except Exception as bdc_err:
            print(f"[CloudServices] BigDataCloud lookup warning: {bdc_err}, falling back to ipapi...")

    # 2. Fallback to free ipapi.co
    try:
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


