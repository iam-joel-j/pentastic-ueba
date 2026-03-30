from cryptography.fernet import Fernet
import os

# ── Key Management ─────────────────────────────────────────────────────────────
# Key is stored in a file so it persists across restarts
# NEVER commit this file to git — add SECRET.key to .gitignore
KEY_FILE = "SECRET.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print("🔑 New encryption key generated and saved to SECRET.key")
        print("⚠️  Keep SECRET.key safe — losing it means logs cannot be decrypted!")
        return key

# Load key once on import
_key    = load_or_create_key()
_fernet = Fernet(_key)

# ── Encrypt / Decrypt ──────────────────────────────────────────────────────────
def encrypt(value: str) -> str:
    """Encrypt a string value → returns encrypted string"""
    if not value:
        return value
    return _fernet.encrypt(value.encode()).decode()

def decrypt(value: str) -> str:
    """Decrypt an encrypted string → returns original value"""
    if not value:
        return value
    try:
        return _fernet.decrypt(value.encode()).decode()
    except Exception:
        return "[decryption failed]"

def encrypt_log(log: dict) -> dict:
    """Encrypt sensitive fields in a log entry before saving to DB"""
    sensitive_fields = ["username", "ip_address", "device"]
    encrypted = dict(log)
    for field in sensitive_fields:
        if field in encrypted and encrypted[field]:
            encrypted[field] = encrypt(str(encrypted[field]))
    return encrypted

def decrypt_log(log: dict) -> dict:
    """Decrypt sensitive fields when reading from DB"""
    sensitive_fields = ["username", "ip_address", "device"]
    decrypted = dict(log)
    for field in sensitive_fields:
        if field in decrypted and decrypted[field]:
            decrypted[field] = decrypt(str(decrypted[field]))
    return decrypted