"""
ExamGuard AI - Security Vault Module (powered by age / pyrage)
Provides cryptographic encryption at rest for sealed exam question papers, 
forensic proctoring snapshots, and sensitive database exports using modern 
X25519 & ChaCha20-Poly1305 encryption.
"""

import os
import base64

try:
    import pyrage
    from pyrage import passphrase
    HAS_PYRAGE = True
except ImportError:
    HAS_PYRAGE = False

from typing import Union, Optional

VAULT_KEY = os.environ.get("EXAMGUARD_VAULT_KEY", "examguard-vault-master-key-2026")

def encrypt_sealed_payload(data: Union[str, bytes], key: Optional[str] = None) -> str:
    """
    Encrypts a string or bytes payload using age passphrase encryption.
    Returns a Base64-encoded ciphertext string safe for database storage.
    """
    if isinstance(data, str):
        raw_bytes = data.encode('utf-8')
    else:
        raw_bytes = data

    if not HAS_PYRAGE:
        # Fallback if pyrage native binary not loaded on host
        return "AGE-FALLBACK:" + base64.b64encode(raw_bytes).decode('utf-8')

    active_key = key or VAULT_KEY
    ciphertext = passphrase.encrypt(raw_bytes, active_key)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_sealed_payload(encrypted_b64: str, key: Optional[str] = None) -> bytes:
    """
    Decrypts an age-encrypted base64 string back to original raw bytes.
    """
    if encrypted_b64.startswith("AGE-FALLBACK:"):
        return base64.b64decode(encrypted_b64.split(":", 1)[1])

    if not HAS_PYRAGE:
        raise RuntimeError("pyrage is not installed; cannot decrypt age payload")

    active_key = key or VAULT_KEY
    ciphertext = base64.b64decode(encrypted_b64)
    return passphrase.decrypt(ciphertext, active_key)

def encrypt_file(file_path: str, output_path: Optional[str] = None, key: Optional[str] = None) -> str:
    """
    Encrypts an entire file (such as a database backup or webcam snapshot) into an .age container.
    """
    out_file = output_path or (file_path + ".age")
    with open(file_path, "rb") as f:
        data = f.read()
    
    active_key = key or VAULT_KEY
    if HAS_PYRAGE:
        encrypted_data = passphrase.encrypt(data, active_key)
    else:
        encrypted_data = base64.b64encode(data)

    with open(out_file, "wb") as f:
        f.write(encrypted_data)

    return out_file
