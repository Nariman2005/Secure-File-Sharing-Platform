from cryptography.fernet import Fernet

# Use a secure key in production (load from environment or config)
FERNET_KEY = Fernet.generate_key()  # Replace with static key for consistency
fernet = Fernet(FERNET_KEY)

def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)
