import hashlib
from cryptography.fernet import Fernet

# IMPORTANT: Use a static key in real deployment, not this
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def verify_hash(data: bytes, expected_hash: str) -> bool:
    return compute_hash(data) == expected_hash
