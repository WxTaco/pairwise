import secrets
import base64
from typing import Optional, Callable
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class KeyManager:
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.peer_public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.shared_secret: Optional[bytes] = None
        self.encryption_key: Optional[bytes] = None
        self.aes_gcm: Optional[AESGCM] = None
        self.logger = logger

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(f"[CRYPTO] {message}")

    def generate_key_pair(self) -> str:
        """Generate a new ECDSA key pair"""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # Get the public key in a shareable format
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_str = base64.b64encode(public_key_bytes).decode('utf-8')

        self._log(f"Generated new ECDSA key pair: {public_key_str[:16]}...")
        return public_key_str

    def set_peer_public_key(self, public_key_str: str) -> bool:
        """Set the peer's public key from base64 encoded string"""
        try:
            public_key_bytes = base64.b64decode(public_key_str.encode('utf-8'))
            loaded_key = serialization.load_pem_public_key(public_key_bytes)

            # Ensure it's an EC public key
            if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
                self._log("Invalid key type: expected EllipticCurvePublicKey")
                return False

            self.peer_public_key = loaded_key
            self._log(f"Set peer public key: {public_key_str[:16]}...")
            return True
        except Exception as e:
            self._log(f"Failed to set peer public key: {e}")
            return False

    def sign_challenge(self, challenge: str) -> Optional[str]:
        """Sign a challenge with our private key"""
        self._log(f"Signing challenge: {challenge[:8]}...")

        if not self.private_key:
            self._log("Signing failed: No private key")
            return None

        try:
            signature = self.private_key.sign(
                challenge.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            self._log(f"Created signature: {signature_b64[:16]}...")
            return signature_b64
        except Exception as e:
            self._log(f"Signing failed: {e}")
            return None

    def verify_signature(self, challenge: str, signature_b64: str) -> bool:
        """Verify a signature using the peer's public key"""
        self._log(f"Verifying signature for challenge: {challenge[:8]}...")

        if not self.peer_public_key:
            self._log("Verification failed: No peer public key set")
            return False

        try:
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            self.peer_public_key.verify(
                signature,
                challenge.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            self._log("Signature verification: SUCCESS")
            return True
        except Exception as e:
            self._log(f"Signature verification: FAILED - {e}")
            return False

    def generate_challenge(self) -> str:
        """Generate a random challenge"""
        challenge = secrets.token_hex(16)
        self._log(f"Generated challenge: {challenge[:8]}...")
        return challenge

    def get_public_key_string(self) -> Optional[str]:
        """Get our public key as a base64 string"""
        if not self.public_key:
            return None

        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_bytes).decode('utf-8')

    def derive_shared_secret(self) -> bool:
        """Derive shared secret using ECDH and set up encryption"""
        if not self.private_key or not self.peer_public_key:
            self._log("Cannot derive shared secret: missing keys")
            return False

        try:
            self.shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)

            # Derive encryption key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES-256
                salt=None,
                info=b'pairwise-encryption-key'
            )
            self.encryption_key = hkdf.derive(self.shared_secret)
            self.aes_gcm = AESGCM(self.encryption_key)

            self._log("Successfully derived shared encryption key")
            return True
        except Exception as e:
            self._log(f"Failed to derive shared secret: {e}")
            return False

    def encrypt_message(self, plaintext: str) -> Optional[str]:
        """Encrypt a message using AES-GCM"""
        if not self.aes_gcm:
            self._log("Cannot encrypt: no encryption key available")
            return None

        try:
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            ciphertext = self.aes_gcm.encrypt(nonce, plaintext.encode('utf-8'), None)

            # Combine nonce + ciphertext and encode as base64
            encrypted_data = nonce + ciphertext
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')

            self._log(f"Encrypted message: {len(plaintext)} bytes -> {len(encrypted_data)} bytes")
            return encrypted_b64
        except Exception as e:
            self._log(f"Encryption failed: {e}")
            return None

    def decrypt_message(self, encrypted_b64: str) -> Optional[str]:
        """Decrypt a message using AES-GCM"""
        if not self.aes_gcm:
            self._log("Cannot decrypt: no encryption key available")
            return None

        try:
            encrypted_data = base64.b64decode(encrypted_b64.encode('utf-8'))

            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            plaintext_bytes = self.aes_gcm.decrypt(nonce, ciphertext, None)
            plaintext = plaintext_bytes.decode('utf-8')

            self._log(f"Decrypted message: {len(encrypted_data)} bytes -> {len(plaintext)} bytes")
            return plaintext
        except Exception as e:
            self._log(f"Decryption failed: {e}")
            return None

    # Legacy methods for backward compatibility (deprecated)
    def generate_key(self) -> str:
        """Legacy method - use generate_key_pair() instead"""
        return self.generate_key_pair()

    def set_peer_key(self, key: str) -> bool:
        """Legacy method - use set_peer_public_key() instead"""
        return self.set_peer_public_key(key)

    def verify_challenge(self, challenge: str, response: str) -> bool:
        """Legacy method - use verify_signature() instead"""
        return self.verify_signature(challenge, response)

    def create_response(self, challenge: str) -> Optional[str]:
        """Legacy method - use sign_challenge() instead"""
        return self.sign_challenge(challenge)
