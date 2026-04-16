"""
Crypto utility for AES-256 encryption of connector configurations.
Uses Fernet (symmetric encryption) from cryptography library.
"""
import os
import base64
from cryptography.fernet import Fernet
from typing import Optional


class CryptoService:
    """
    Handles AES-256 encryption and decryption of sensitive connector configs.
    Uses Fernet which provides authenticated symmetric encryption.
    """

    def __init__(self):
        self.key = os.environ.get("ENCRYPTION_KEY")
        if not self.key:
            # Generate a new key if not set (WARNING: data will be lost on restart)
            self.key = Fernet.generate_key().decode()
            print(f"WARNING: No ENCRYPTION_KEY set. Generated new key: {self.key}")
            print("Set this as an environment variable to persist encrypted data.")

        if isinstance(self.key, str):
            self.key = self.key.encode()

        # Validate key length (Fernet requires 32-byte url-safe base64-encoded key)
        try:
            self.fernet = Fernet(self.key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key. Must be a 32-byte url-safe base64-encoded key. Error: {e}")

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt a string and return ciphertext bytes.
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty string")

        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = self.fernet.encrypt(plaintext_bytes)
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypt ciphertext bytes and return the original string.
        """
        if not ciphertext:
            raise ValueError("Cannot decrypt empty bytes")

        plaintext_bytes = self.fernet.decrypt(ciphertext)
        return plaintext_bytes.decode("utf-8")

    def encrypt_dict(self, data: dict) -> bytes:
        """
        Encrypt a dictionary as JSON string.
        """
        import json
        json_str = json.dumps(data, sort_keys=True)
        return self.encrypt(json_str)

    def decrypt_to_dict(self, ciphertext: bytes) -> dict:
        """
        Decrypt ciphertext and parse as JSON dictionary.
        """
        import json
        json_str = self.decrypt(ciphertext)
        return json.loads(json_str)

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet key. Use this to create an ENCRYPTION_KEY env var."""
        return Fernet.generate_key().decode()


# Singleton instance
crypto_service = CryptoService()
