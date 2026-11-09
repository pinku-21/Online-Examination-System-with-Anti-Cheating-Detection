"""
Multi-Factor Authentication (MFA) & TOTP Service for ExamGuard AI.
Complies with RFC 6238 (TOTP) and RFC 4226 (HOTP) using Python standard libraries.
Generates standard base32 secrets, otpauth:// enrollment URIs, time-synchronized TOTP codes,
and cryptographically hashed recovery codes.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from urllib.parse import quote

logger = logging.getLogger("examguard.security.mfa")

# MFA Secret at-rest Authenticated Encryption (AES-256-GCM) with Multi-Key Rotation Support
DEFAULT_DEV_MFA_KEY = "examguard-fallback-mfa-protection-key-2026"


def is_production_environment(environ=None) -> bool:
    """Checks whether the application is running under production mode."""
    env = environ if environ is not None else os.environ
    return env.get("FLASK_ENV") == "production" or bool(env.get("RENDER"))


def resolve_primary_mfa_encryption_key(environ=None) -> bytes:
    """
    Derives the active 32-byte authenticated encryption key for MFA secrets.
    
    In production environments (FLASK_ENV='production' or RENDER detected):
    - Requires an explicit, dedicated MFA_ENCRYPTION_KEY.
    - Never falls back to SECRET_KEY.
    - If missing or blank, raises a fatal RuntimeError to prevent silent insecure key generation
      or locking out users due to ephemeral keys.
      
    In local development / testing:
    - Uses MFA_ENCRYPTION_KEY, SECRET_KEY, or falls back to DEFAULT_DEV_MFA_KEY.
    """
    env = environ if environ is not None else os.environ
    
    if is_production_environment(env):
        mfa_key = env.get("MFA_ENCRYPTION_KEY") or ""
        if not mfa_key.strip():
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: MFA_ENCRYPTION_KEY is not configured or empty. "
                "In production (FLASK_ENV='production' or Render deployment), an explicit, dedicated "
                "MFA_ENCRYPTION_KEY environment variable is mandatory to encrypt and decrypt stored "
                "administrator MFA secrets. SECRET_KEY alone is not permitted as a fallback in production. "
                "Configure a strong, 64-character hex key via `secrets.token_hex(32)`."
            )
        return hashlib.sha256(mfa_key.encode("utf-8")).digest()
        
    dev_key = env.get("MFA_ENCRYPTION_KEY") or env.get("SECRET_KEY") or DEFAULT_DEV_MFA_KEY
    return hashlib.sha256(dev_key.encode("utf-8")).digest()


def get_all_mfa_decryption_keys(environ=None) -> list[bytes]:
    """
    Returns ordered list of candidate 32-byte keys for decrypting MFA secrets.
    The primary active key is checked first, followed by any previous keys listed in
    MFA_PREVIOUS_KEYS (comma-separated list of previous keys) to support seamless
    zero-downtime key rotation without user lockout.
    In development mode only, dev fallback keys are also evaluated.
    """
    env = environ if environ is not None else os.environ
    keys: list[bytes] = []
    
    try:
        primary = resolve_primary_mfa_encryption_key(env)
        keys.append(primary)
    except RuntimeError:
        if is_production_environment(env):
            raise

    # 1. Check previous rotation keys from MFA_PREVIOUS_KEYS
    prev_raw = env.get("MFA_PREVIOUS_KEYS", "").strip()
    if prev_raw:
        for k in prev_raw.split(","):
            clean_k = k.strip()
            if clean_k:
                k_bytes = hashlib.sha256(clean_k.encode("utf-8")).digest()
                if k_bytes not in keys:
                    keys.append(k_bytes)

    # 2. In non-production only, allow SECRET_KEY and DEFAULT_DEV_MFA_KEY as candidate fallbacks
    if not is_production_environment(env):
        sec_key = env.get("SECRET_KEY", "").strip()
        if sec_key:
            k_bytes = hashlib.sha256(sec_key.encode("utf-8")).digest()
            if k_bytes not in keys:
                keys.append(k_bytes)

        dev_k_bytes = hashlib.sha256(DEFAULT_DEV_MFA_KEY.encode("utf-8")).digest()
        if dev_k_bytes not in keys:
            keys.append(dev_k_bytes)

    return keys


def get_mfa_encryption_key() -> bytes:
    """Public helper returning the primary encryption key."""
    return resolve_primary_mfa_encryption_key()


def encrypt_mfa_secret(secret: str) -> str:
    """
    Encrypts a plaintext Base32 MFA secret using AES-256-GCM.
    Prefixes with 'enc::' to distinguish encrypted secrets from legacy plain secrets.
    Never logs or leaks the secret or encryption key.
    """
    if not secret:
        return ""
    if secret.startswith("enc::"):
        return secret  # already encrypted

    key = resolve_primary_mfa_encryption_key()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, secret.encode("utf-8"), None)
        payload = base64.b64encode(nonce + ciphertext).decode("utf-8")
        return f"enc::{payload}"
    except Exception as e:
        logger.error("Failed to encrypt MFA secret (type: %s)", type(e).__name__)
        # Fail safe
        return secret


def decrypt_mfa_secret(stored_secret: str) -> str:
    """
    Decrypts an encrypted Base32 MFA secret using available active and rotated keys.
    Transparently supports unencrypted secrets for backwards-compatibility.
    Never logs or leaks the secret or encryption key.
    """
    if not stored_secret:
        return ""
    if not stored_secret.startswith("enc::"):
        return stored_secret  # legacy plaintext secret

    payload = stored_secret[5:]
    try:
        raw = base64.b64decode(payload.encode("utf-8"))
        if len(raw) < 28:  # 12 nonce + 16 auth tag minimum
            logger.error("MFA secret payload too short to be valid ciphertext.")
            return ""
        nonce = raw[:12]
        ciphertext = raw[12:]
    except Exception as e:
        logger.error("Failed to decode MFA ciphertext payload (type: %s)", type(e).__name__)
        return ""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    candidate_keys = get_all_mfa_decryption_keys()
    for key in candidate_keys:
        try:
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode("utf-8")
        except Exception:
            continue

    logger.error("Failed to decrypt MFA secret with any configured active or historical keys.")
    return ""


def migrate_unencrypted_mfa_secrets(db_connection=None) -> int:
    """
    Idempotent migration utility:
    Scans the users table for unencrypted MFA secrets (secrets that don't start with 'enc::')
    and securely encrypts them in place using AES-256-GCM under the primary active key.
    Returns the count of migrated user records.
    Never logs or prints secret values or keys.
    """
    close_when_done = False
    if db_connection is None:
        from database import get_connection
        conn = get_connection()
        close_when_done = True
    else:
        conn = db_connection

    cursor = conn.cursor()
    migrated_count = 0
    try:
        cursor.execute("SELECT id, mfa_secret FROM users WHERE mfa_secret IS NOT NULL AND mfa_secret != ''")
        rows = cursor.fetchall()
        for row in rows:
            user_id = row["id"]
            sec = row["mfa_secret"]
            if sec and not sec.startswith("enc::"):
                enc = encrypt_mfa_secret(sec)
                cursor.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (enc, user_id))
                migrated_count += 1
        conn.commit()
    finally:
        if close_when_done:
            cursor.close()
            conn.close()

    if migrated_count > 0:
        logger.info("Migrated %d plaintext MFA secret(s) to AES-256-GCM encryption at rest.", migrated_count)
    return migrated_count


def generate_mfa_secret() -> str:
    """Generates a secure 160-bit (20-byte) random Base32 secret for TOTP enrollment."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")


def get_totp_uri(secret: str, username: str, issuer: str = "ExamGuard AI") -> str:
    """Constructs the standard otpauth:// URI for authenticator app QR code scanning."""
    safe_issuer = quote(issuer)
    safe_user = quote(username)
    return f"otpauth://totp/{safe_issuer}:{safe_user}?secret={secret}&issuer={safe_issuer}&algorithm=SHA1&digits=6&period=30"


def generate_totp_code(secret: str, for_time: int | None = None, time_step: int = 30, digits: int = 6) -> str:
    """Calculates the 6-digit TOTP code for a given timestamp using standard HMAC-SHA1."""
    if for_time is None:
        for_time = int(time.time())

    # Add padding to base32 secret if necessary
    secret_clean = secret.strip().replace(" ", "").upper()
    padding = (8 - len(secret_clean) % 8) % 8
    key = base64.b32decode(secret_clean + "=" * padding, casefold=True)

    counter = for_time // time_step
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    offset = digest[19] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code_int:0{digits}d}"


def verify_totp_code(secret: str, token: str, window: int = 1) -> bool:
    """
    Verifies a 6-digit TOTP code against the secret (auto-decrypts if encrypted at rest).
    Allows clock drift window of ±1 step (±30 seconds) per RFC 6238 recommendation.
    """
    if not secret or not token:
        return False

    # Auto-decrypt if secret is stored encrypted
    plain_secret = decrypt_mfa_secret(secret)
    if not plain_secret:
        return False

    clean_token = str(token).strip()
    if not clean_token.isdigit() or len(clean_token) != 6:
        return False

    now = int(time.time())
    for offset in range(-window, window + 1):
        expected = generate_totp_code(plain_secret, for_time=now + (offset * 30))
        if secrets.compare_digest(clean_token, expected):
            return True
    return False


def generate_recovery_codes(count: int = 8) -> tuple[list[str], list[str]]:
    """
    Generates plain recovery codes for one-time display to user,
    and returns a list of SHA-256 hashed representations for secure database storage.
    """
    plain_codes = []
    hashed_codes = []
    for _ in range(count):
        # Format: XXXX-XXXX (e.g. 7F2A-9C4B)
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        plain_codes.append(code)

        # Hash with SHA-256 before storage
        h = hashlib.sha256(code.encode("utf-8")).hexdigest()
        hashed_codes.append(h)

    return plain_codes, hashed_codes


def verify_and_consume_recovery_code(entered_code: str, hashed_codes_json: str | list) -> tuple[bool, str]:
    """
    Checks if an entered recovery code matches any hashed recovery code.
    If matched, consumes (removes) it from the set to prevent reuse.
    Returns (success_boolean, updated_hashed_codes_json).
    """
    clean_code = entered_code.strip().upper()
    if not clean_code:
        return False, json.dumps(hashed_codes_json if isinstance(hashed_codes_json, list) else [])

    if isinstance(hashed_codes_json, str):
        try:
            stored_hashes = json.loads(hashed_codes_json)
        except Exception:
            stored_hashes = []
    else:
        stored_hashes = list(hashed_codes_json)

    entered_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()

    matched_index = None
    for idx, h in enumerate(stored_hashes):
        if secrets.compare_digest(entered_hash, h):
            matched_index = idx
            break

    if matched_index is not None:
        # Consume the single-use recovery code
        stored_hashes.pop(matched_index)
        return True, json.dumps(stored_hashes)

    return False, json.dumps(stored_hashes)

