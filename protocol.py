from enum import Enum
from crypto import KeyManager
from network import NetworkManager

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"

class PairwiseProtocol:
    def __init__(self, logger=None):
        self.logger = logger
        self.key_manager = KeyManager(logger)
        self.network = NetworkManager(logger=logger)
        self.state = ConnectionState.DISCONNECTED
        self.pending_challenge = None
        self.message_callback = None

        self.network.set_message_callback(self._handle_message)
        self.network.set_connection_callback(self._handle_connection)
        self._log("Pairwise protocol initialized")

    def _log(self, message):
        if self.logger:
            self.logger(f"[PROTOCOL] {message}")
    
    def set_message_callback(self, callback):
        self.message_callback = callback

    def generate_key(self):
        key = self.key_manager.generate_key()
        self._log("Generated new identity key for this session")
        return key

    def start_listening(self):
        self._log("Starting to listen for incoming connections")
        self.network.start_server()
        self.state = ConnectionState.CONNECTING
        self._log(f"State changed to: {self.state.value}")

    def connect_to_peer(self, ip: str, peer_key: str):
        self._log(f"Initiating connection to peer at {ip}")
        self._log("Setting peer's public key for authentication")
        self.key_manager.set_peer_key(peer_key)
        self.state = ConnectionState.CONNECTING
        self._log(f"State changed to: {self.state.value}")
        success = self.network.connect_to_peer(ip)
        if not success:
            self.state = ConnectionState.DISCONNECTED
            self._log(f"Connection failed, state changed to: {self.state.value}")
    
    def send_chat_message(self, text: str):
        if self.state != ConnectionState.CONNECTED:
            self._log("Cannot send chat message: Not in connected state")
            return False

        self._log(f"Sending chat message: {text[:30]}...")
        return self.network.send_message('chat', {'text': text})

    def _handle_connection(self, connected: bool):
        if connected and self.state == ConnectionState.CONNECTING:
            self._log("Network connection established, starting authentication")
            self._start_authentication()
        elif not connected:
            self._log("Network connection lost")
            self.state = ConnectionState.DISCONNECTED
            self._log(f"State changed to: {self.state.value}")
            if self.message_callback:
                self.message_callback('system', 'Connection lost')
    
    def _start_authentication(self):
        self._log("=== STARTING PAIRWISE AUTHENTICATION ===")
        self.state = ConnectionState.AUTHENTICATING
        self._log(f"State changed to: {self.state.value}")

        self._log("Step 1: Generating cryptographic challenge")
        challenge = self.key_manager.generate_challenge()
        self.pending_challenge = challenge

        self._log("Step 2: Sending challenge to peer for verification")
        self.network.send_message('auth_challenge', {'challenge': challenge})
    
    def _handle_message(self, message):
        msg_type = message.get('type')
        data = message.get('data', {})

        self._log(f"Processing incoming message: {msg_type}")

        if msg_type == 'auth_challenge':
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
    
    def _handle_auth_challenge(self, data):
        self._log("=== RECEIVED AUTHENTICATION CHALLENGE ===")
        challenge = data.get('challenge')
        if not challenge:
            self._log("Invalid challenge received (empty)")
            return

        self._log("Step 3: Peer sent challenge, creating response using our private key")
        response = self.key_manager.create_response(challenge)
        if response:
            self._log("Step 4: Sending authentication response back to peer")
            self.network.send_message('auth_response', {'response': response})
        else:
            self._log("Failed to create response - no private key available")
            self.network.send_message('auth_failure', {})
    
    def _handle_auth_response(self, data):
        self._log("=== RECEIVED AUTHENTICATION RESPONSE ===")
        response = data.get('response')
        if not response or not self.pending_challenge:
            self._log("Invalid response or no pending challenge")
            self.network.send_message('auth_failure', {})
            return

        self._log("Step 5: Verifying peer's response using their public key")
        if self.key_manager.verify_challenge(self.pending_challenge, response):
            self._log("Step 6: Authentication successful! Peer has correct key")
            self.network.send_message('auth_success', {})
            self.state = ConnectionState.CONNECTED
            self._log(f"State changed to: {self.state.value}")
            self._log("=== PAIRWISE CONNECTION ESTABLISHED ===")
            if self.message_callback:
                self.message_callback('system', 'Authentication successful - Connected!')
        else:
            self._log("Step 6: Authentication failed! Peer has incorrect key")
            self.network.send_message('auth_failure', {})
            if self.message_callback:
                self.message_callback('system', 'Authentication failed - Invalid key')
    
    def _handle_auth_success(self):
        self._log("=== AUTHENTICATION SUCCESS CONFIRMED ===")
        self.state = ConnectionState.CONNECTED
        self._log(f"State changed to: {self.state.value}")
        self._log("=== PAIRWISE CONNECTION ESTABLISHED ===")
        if self.message_callback:
            self.message_callback('system', 'Authentication successful - Connected!')

    def _handle_auth_failure(self):
        self._log("=== AUTHENTICATION FAILED ===")
        self.state = ConnectionState.DISCONNECTED
        self._log(f"State changed to: {self.state.value}")
        if self.message_callback:
            self.message_callback('system', 'Authentication failed')

    def _handle_chat_message(self, data):
        text = data.get('text', '')
        self._log(f"Received chat message: {text[:30]}...")
        if self.message_callback and self.state == ConnectionState.CONNECTED:
            self.message_callback('peer', text)
    
    def get_state(self):
        return self.state

    def close(self):
        self._log("Closing pairwise protocol")
        self.network.close()
