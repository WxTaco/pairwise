from enum import Enum
from crypto import KeyManager
from network import NetworkManager

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"

class PairwiseProtocol:
    def __init__(self):
        self.key_manager = KeyManager()
        self.network = NetworkManager()
        self.state = ConnectionState.DISCONNECTED
        self.pending_challenge = None
        self.message_callback = None
        
        self.network.set_message_callback(self._handle_message)
        self.network.set_connection_callback(self._handle_connection)
    
    def set_message_callback(self, callback):
        self.message_callback = callback
    
    def generate_key(self):
        return self.key_manager.generate_key()
    
    def start_listening(self):
        self.network.start_server()
        self.state = ConnectionState.CONNECTING
    
    def connect_to_peer(self, ip: str, peer_key: str):
        self.key_manager.set_peer_key(peer_key)
        self.state = ConnectionState.CONNECTING
        self.network.connect_to_peer(ip)
    
    def send_chat_message(self, text: str):
        if self.state != ConnectionState.CONNECTED:
            return False
        
        return self.network.send_message('chat', {'text': text})
    
    def _handle_connection(self, connected: bool):
        if connected and self.state == ConnectionState.CONNECTING:
            self._start_authentication()
        elif not connected:
            self.state = ConnectionState.DISCONNECTED
            if self.message_callback:
                self.message_callback('system', 'Connection lost')
    
    def _start_authentication(self):
        self.state = ConnectionState.AUTHENTICATING
        challenge = self.key_manager.generate_challenge()
        self.pending_challenge = challenge
        self.network.send_message('auth_challenge', {'challenge': challenge})
    
    def _handle_message(self, message):
        msg_type = message.get('type')
        data = message.get('data', {})
        
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
    
    def _handle_auth_challenge(self, data):
        challenge = data.get('challenge')
        if not challenge:
            return
        
        response = self.key_manager.create_response(challenge)
        if response:
            self.network.send_message('auth_response', {'response': response})
        else:
            self.network.send_message('auth_failure', {})
    
    def _handle_auth_response(self, data):
        response = data.get('response')
        if not response or not self.pending_challenge:
            self.network.send_message('auth_failure', {})
            return
        
        if self.key_manager.verify_challenge(self.pending_challenge, response):
            self.network.send_message('auth_success', {})
            self.state = ConnectionState.CONNECTED
            if self.message_callback:
                self.message_callback('system', 'Authentication successful - Connected!')
        else:
            self.network.send_message('auth_failure', {})
            if self.message_callback:
                self.message_callback('system', 'Authentication failed - Invalid key')
    
    def _handle_auth_success(self):
        self.state = ConnectionState.CONNECTED
        if self.message_callback:
            self.message_callback('system', 'Authentication successful - Connected!')
    
    def _handle_auth_failure(self):
        self.state = ConnectionState.DISCONNECTED
        if self.message_callback:
            self.message_callback('system', 'Authentication failed')
    
    def _handle_chat_message(self, data):
        text = data.get('text', '')
        if self.message_callback and self.state == ConnectionState.CONNECTED:
            self.message_callback('peer', text)
    
    def get_state(self):
        return self.state
    
    def close(self):
        self.network.close()
