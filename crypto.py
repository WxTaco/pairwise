import hashlib
import secrets
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import base64

class KeyManager:
    def __init__(self, logger=None):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.logger = logger

    def _log(self, message):
        if self.logger:
            self.logger(f"[CRYPTO] {message}")

    def generate_key_pair(self):
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

    def set_peer_public_key(self, public_key_str):
        """Set the peer's public key from base64 encoded string"""
        try:
            public_key_bytes = base64.b64decode(public_key_str.encode('utf-8'))
            self.peer_public_key = serialization.load_pem_public_key(public_key_bytes)
            self._log(f"Set peer public key: {public_key_str[:16]}...")
            return True
        except Exception as e:
            self._log(f"Failed to set peer public key: {e}")
            return False

    def sign_challenge(self, challenge):
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

    def verify_signature(self, challenge, signature_b64):
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

    def generate_challenge(self):
        """Generate a random challenge"""
        challenge = secrets.token_hex(16)
        self._log(f"Generated challenge: {challenge[:8]}...")
        return challenge

    def get_public_key_string(self):
        """Get our public key as a base64 string"""
        if not self.public_key:
            return None

        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_bytes).decode('utf-8')

    # Legacy methods for backward compatibility (deprecated)
    def generate_key(self):
        """Legacy method - use generate_key_pair() instead"""
        return self.generate_key_pair()

    def set_peer_key(self, key):
        """Legacy method - use set_peer_public_key() instead"""
        return self.set_peer_public_key(key)

    def verify_challenge(self, challenge, response):
        """Legacy method - use verify_signature() instead"""
        return self.verify_signature(challenge, response)

    def create_response(self, challenge):
        """Legacy method - use sign_challenge() instead"""
        return self.sign_challenge(challenge)
