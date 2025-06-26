# pip install cryptography
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordEncryptor:
    def __init__(self, password: str, salt: bytes | None = None):
        self.salt = salt
        if self.salt is None:
            self.salt = os.urandom(16)
        self.passwords = password

        self.key = base64.urlsafe_b64encode(
            PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=480000,
            ).derive(password.encode())
        )

        self.fernet = Fernet(self.key)

    def encrypt(self, data: str) -> bytes:
        return self.fernet.encrypt(data.encode())

    def decrypt(self, data: bytes) -> str:
        return self.fernet.decrypt(data).decode()