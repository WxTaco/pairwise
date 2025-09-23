import json
from enum import Enum
from typing import Optional, Callable, Dict, Any
from crypto import KeyManager
from network import NetworkManager

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    KEY_EXCHANGE = "key_exchange"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"

class PairwiseProtocol:
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self.logger = logger
        self.key_manager = KeyManager(logger)
        self.network = NetworkManager(logger=logger)
        self.state = ConnectionState.DISCONNECTED
        self.pending_challenge: Optional[str] = None
        self.peer_challenge: Optional[str] = None
        self.message_callback: Optional[Callable[[str, str], None]] = None
        self.is_initiator = False

        self.network.set_message_callback(self._handle_message)
        self.network.set_connection_callback(self._handle_connection)
        self._log("Pairwise protocol initialized")

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(f"[PROTOCOL] {message}")

    def set_message_callback(self, callback: Callable[[str, str], None]) -> None:
        self.message_callback = callback

    def generate_key_pair(self) -> str:
        public_key = self.key_manager.generate_key_pair()
        self._log("Generated new ECDSA key pair for this session")
        return public_key

    def start_listening(self) -> None:
        self._log("Starting to listen for incoming connections")
        self.network.start_server()
        self.state = ConnectionState.CONNECTING
        self._log(f"State changed to: {self.state.value}")

    def connect_to_peer(self, ip: str) -> None:
        self._log(f"Initiating connection to peer at {ip}")
        self.is_initiator = True
        self.state = ConnectionState.CONNECTING
        self._log(f"State changed to: {self.state.value}")
        success = self.network.connect_to_peer(ip)
        if not success:
            self.state = ConnectionState.DISCONNECTED
            self._log(f"Connection failed, state changed to: {self.state.value}")

    def send_chat_message(self, text: str) -> bool:
        if self.state != ConnectionState.CONNECTED:
            self._log("Cannot send chat message: Not in connected state")
            return False

        self._log(f"Sending encrypted chat message: {text[:30]}...")
        return self._send_encrypted_message('chat', {'text': text})

    def _send_encrypted_message(self, message_type: str, data: Dict[str, Any]) -> bool:
        """Send an encrypted message"""
        encrypted_data = self.key_manager.encrypt_message(str(data))
        if not encrypted_data:
            self._log("Failed to encrypt message")
            return False

        return self.network.send_message(message_type, {'encrypted': encrypted_data})

    def _handle_connection(self, connected: bool) -> None:
        if connected and self.state == ConnectionState.CONNECTING:
            self._log("Network connection established, starting key exchange")
            self._start_key_exchange()
        elif not connected:
            self._log("Network connection lost")
            self.state = ConnectionState.DISCONNECTED
            self._log(f"State changed to: {self.state.value}")
            if self.message_callback:
                self.message_callback('system', 'Connection lost')

    def _start_key_exchange(self) -> None:
        self._log("=== STARTING KEY EXCHANGE ===")
        self.state = ConnectionState.KEY_EXCHANGE
        self._log(f"State changed to: {self.state.value}")

        if self.is_initiator:
            self._log("Step 1: Sending our public key to peer")
            public_key = self.key_manager.get_public_key_string()
            self.network.send_message('key_exchange', {'public_key': public_key})
        else:
            self._log("Waiting for peer to send their public key")

    def _handle_message(self, message: Dict[str, Any]) -> None:
        msg_type = message.get('type')
        data = message.get('data', {})

        self._log(f"Processing incoming message: {msg_type}")

        if msg_type == 'key_exchange':
            self._handle_key_exchange(data)
        elif msg_type == 'key_exchange_response':
            self._handle_key_exchange_response(data)
        elif msg_type == 'auth_challenge':
            self._handle_auth_challenge(data)
        elif msg_type == 'auth_response':
            self._handle_auth_response(data)
        elif msg_type == 'auth_success':
            self._handle_auth_success()
        elif msg_type == 'auth_failure':
            self._handle_auth_failure()
        elif msg_type == 'chat':
            self._handle_chat_message(data)
        else:
            self._log(f"Unknown message type received: {msg_type}")

    def _handle_key_exchange(self, data: Dict[str, Any]) -> None:
        self._log("=== RECEIVED KEY EXCHANGE ===")
        peer_public_key = data.get('public_key')
        if not peer_public_key:
            self._log("Invalid key exchange: no public key provided")
            self.network.send_message('auth_failure', {})
            return

        self._log("Step 2: Setting peer's public key")
        if not self.key_manager.set_peer_public_key(peer_public_key):
            self._log("Failed to set peer's public key")
            self.network.send_message('auth_failure', {})
            return

        if not self.is_initiator:
            # We're the server, send our public key back
            self._log("Step 3: Sending our public key in response")
            our_public_key = self.key_manager.get_public_key_string()
            self.network.send_message('key_exchange_response', {'public_key': our_public_key})

        # Derive shared secret for encryption
        self._log("Key exchange complete, deriving shared secret")
        if not self.key_manager.derive_shared_secret():
            self._log("Failed to derive shared secret")
            self.network.send_message('auth_failure', {})
            return

        # Start authentication phase
        self._log("Shared secret derived, starting authentication")
        self._start_authentication()

    def _handle_key_exchange_response(self, data: Dict[str, Any]) -> None:
        self._log("=== RECEIVED KEY EXCHANGE RESPONSE ===")
        peer_public_key = data.get('public_key')
        if not peer_public_key:
            self._log("Invalid key exchange response: no public key provided")
            self.network.send_message('auth_failure', {})
            return

        self._log("Step 4: Setting peer's public key from response")
        if not self.key_manager.set_peer_public_key(peer_public_key):
            self._log("Failed to set peer's public key")
            self.network.send_message('auth_failure', {})
            return

        # Derive shared secret for encryption
        self._log("Key exchange complete, deriving shared secret")
        if not self.key_manager.derive_shared_secret():
            self._log("Failed to derive shared secret")
            self.network.send_message('auth_failure', {})
            return

        # Start authentication phase
        self._log("Shared secret derived, starting authentication")
        self._start_authentication()

    def _start_authentication(self) -> None:
        self._log("=== STARTING AUTHENTICATION ===")
        self.state = ConnectionState.AUTHENTICATING
        self._log(f"State changed to: {self.state.value}")

        # Generate and send our challenge
        self._log("Step 5: Generating challenge for peer")
        challenge = self.key_manager.generate_challenge()
        self.pending_challenge = challenge
        self.network.send_message('auth_challenge', {'challenge': challenge})

    def _handle_auth_challenge(self, data: Dict[str, Any]) -> None:
        self._log("=== RECEIVED AUTHENTICATION CHALLENGE ===")
        challenge = data.get('challenge')
        if not challenge:
            self._log("Invalid challenge received (empty)")
            self.network.send_message('auth_failure', {})
            return

        self._log("Step 6: Signing challenge with our private key")
        signature = self.key_manager.sign_challenge(challenge)
        if signature:
            self._log("Step 7: Sending signed response back to peer")
            self.network.send_message('auth_response', {'challenge': challenge, 'signature': signature})

            # Also send our own challenge if we haven't already
            if not self.peer_challenge:
                self._log("Step 8: Sending our own challenge to peer")
                our_challenge = self.key_manager.generate_challenge()
                self.peer_challenge = our_challenge
                self.network.send_message('auth_challenge', {'challenge': our_challenge})
        else:
            self._log("Failed to sign challenge - no private key available")
            self.network.send_message('auth_failure', {})
    
    def _handle_auth_response(self, data: Dict[str, Any]) -> None:
        self._log("=== RECEIVED AUTHENTICATION RESPONSE ===")
        challenge = data.get('challenge')
        signature = data.get('signature')

        if not challenge or not signature:
            self._log("Invalid response: missing challenge or signature")
            self.network.send_message('auth_failure', {})
            return

        self._log("Step 9: Verifying peer's signature using their public key")
        if self.key_manager.verify_signature(challenge, signature):
            self._log("Step 10: Peer authentication successful!")

            # Check if we've completed mutual authentication
            if self.peer_challenge and challenge == self.pending_challenge:
                # Both sides authenticated successfully
                self.network.send_message('auth_success', {})
                self.state = ConnectionState.CONNECTED
                self._log(f"State changed to: {self.state.value}")
                self._log("=== PAIRWISE CONNECTION ESTABLISHED ===")
                if self.message_callback:
                    self.message_callback('system', 'Authentication successful - Connected!')
            else:
                # Still waiting for our challenge to be answered
                self._log("Waiting for peer to respond to our challenge")
        else:
            self._log("Step 10: Peer authentication failed! Invalid signature")
            self.network.send_message('auth_failure', {})
            if self.message_callback:
                self.message_callback('system', 'Authentication failed - Invalid signature')

    def _handle_auth_success(self) -> None:
        self._log("=== AUTHENTICATION SUCCESS CONFIRMED ===")
        self.state = ConnectionState.CONNECTED
        self._log(f"State changed to: {self.state.value}")
        self._log("=== PAIRWISE CONNECTION ESTABLISHED ===")
        if self.message_callback:
            self.message_callback('system', 'Authentication successful - Connected!')

    def _handle_auth_failure(self) -> None:
        self._log("=== AUTHENTICATION FAILED ===")
        self.state = ConnectionState.DISCONNECTED
        self._log(f"State changed to: {self.state.value}")
        if self.message_callback:
            self.message_callback('system', 'Authentication failed')

    def _handle_chat_message(self, data: Dict[str, Any]) -> None:
        if 'encrypted' in data:
            # Decrypt the message
            encrypted_data = data.get('encrypted', '')
            decrypted_str = self.key_manager.decrypt_message(encrypted_data)
            if not decrypted_str:
                self._log("Failed to decrypt chat message")
                return

            try:
                # Parse the decrypted data back to dict
                decrypted_data = json.loads(decrypted_str.replace("'", '"'))
                text = decrypted_data.get('text', '')
            except (json.JSONDecodeError, AttributeError):
                self._log("Failed to parse decrypted chat message")
                return
        else:
            # Fallback for unencrypted messages (backward compatibility)
            text = data.get('text', '')

        self._log(f"Received chat message: {text[:30]}...")
        if self.message_callback and self.state == ConnectionState.CONNECTED:
            self.message_callback('peer', text)

    def get_state(self) -> ConnectionState:
        return self.state

    def close(self) -> None:
        self._log("Closing pairwise protocol")
        self.network.close()
