import hashlib
import secrets
import hmac

class KeyManager:
    def __init__(self, logger=None):
        self.private_key = None
        self.peer_key = None
        self.logger = logger

    def _log(self, message):
        if self.logger:
            self.logger(f"[CRYPTO] {message}")

    def generate_key(self):
        self.private_key = secrets.token_hex(32)
        self._log(f"Generated new private key: {self.private_key[:8]}...")
        return self.private_key

    def set_peer_key(self, key):
        self.peer_key = key
        self._log(f"Set peer key: {key[:8]}...")

    def verify_challenge(self, challenge, response):
        self._log(f"Verifying challenge: {challenge[:8]}... with response: {response[:8]}...")

        if not self.peer_key:
            self._log("Verification failed: No peer key set")
            return False

        expected = hmac.new(
            self.peer_key.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()

        result = hmac.compare_digest(expected, response)
        self._log(f"Challenge verification: {'SUCCESS' if result else 'FAILED'}")
        self._log(f"Expected: {expected[:8]}..., Got: {response[:8]}...")

        return result

    def create_response(self, challenge):
        self._log(f"Creating response for challenge: {challenge[:8]}...")

        if not self.private_key:
            self._log("Response creation failed: No private key")
            return None

        response = hmac.new(
            self.private_key.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()

        self._log(f"Created response: {response[:8]}...")
        return response

    def generate_challenge(self):
        challenge = secrets.token_hex(16)
        self._log(f"Generated challenge: {challenge[:8]}...")
        return challenge
