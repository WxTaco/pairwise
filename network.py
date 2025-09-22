import socket
import json
import threading
from typing import Callable, Optional

class NetworkManager:
    def __init__(self, port: int = 8888, logger=None):
        self.port = port
        self.socket = None
        self.peer_socket = None
        self.is_server = False
        self.message_callback: Optional[Callable] = None
        self.connection_callback: Optional[Callable] = None
        self.logger = logger

    def _log(self, message):
        if self.logger:
            self.logger(f"[NETWORK] {message}")
    
    def set_message_callback(self, callback: Callable):
        self.message_callback = callback
    
    def set_connection_callback(self, callback: Callable):
        self.connection_callback = callback
    
    def start_server(self):
        self._log(f"Starting server on port {self.port}")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', self.port))
        self.socket.listen(1)
        self.is_server = True
        self._log("Server socket created and listening for connections")

        thread = threading.Thread(target=self._accept_connections)
        thread.daemon = True
        thread.start()

    def connect_to_peer(self, ip: str, port: int = None):
        if port is None:
            port = self.port

        self._log(f"Attempting to connect to peer at {ip}:{port}")
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.peer_socket.connect((ip, port))
            self._log(f"Successfully connected to {ip}:{port}")
        except Exception as e:
            self._log(f"Failed to connect to {ip}:{port}: {e}")
            return False

        thread = threading.Thread(target=self._handle_peer, args=(self.peer_socket,))
        thread.daemon = True
        thread.start()

        if self.connection_callback:
            self.connection_callback(True)

        return True
    
    def send_message(self, message_type: str, data: dict):
        if not self.peer_socket:
            self._log("Cannot send message: No peer connection")
            return False

        message = {
            'type': message_type,
            'data': data
        }

        self._log(f"Sending message: {message_type} with data: {str(data)[:50]}...")

        try:
            message_json = json.dumps(message)
            self.peer_socket.send(message_json.encode() + b'\n')
            self._log(f"Message sent successfully: {len(message_json)} bytes")
            return True
        except Exception as e:
            self._log(f"Failed to send message: {e}")
            return False
    
    def _accept_connections(self):
        self._log("Waiting for incoming connections...")
        while True:
            try:
                peer_socket, addr = self.socket.accept()
                self._log(f"Accepted connection from {addr[0]}:{addr[1]}")
                self.peer_socket = peer_socket

                thread = threading.Thread(target=self._handle_peer, args=(peer_socket,))
                thread.daemon = True
                thread.start()

                if self.connection_callback:
                    self.connection_callback(True)

            except Exception as e:
                self._log(f"Error accepting connections: {e}")
                break
    
    def _handle_peer(self, peer_socket):
        self._log("Started handling peer connection")
        buffer = ""
        while True:
            try:
                data = peer_socket.recv(1024).decode()
                if not data:
                    self._log("Peer disconnected (no data received)")
                    break

                self._log(f"Received {len(data)} bytes from peer")
                buffer += data

                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self._log(f"Processing message: {line[:50]}...")
                        try:
                            message = json.loads(line)
                            self._log(f"Parsed message type: {message.get('type', 'unknown')}")
                            if self.message_callback:
                                self.message_callback(message)
                        except json.JSONDecodeError as e:
                            self._log(f"Failed to parse JSON message: {e}")
            except Exception as e:
                self._log(f"Error handling peer connection: {e}")
                break

        self._log("Peer connection closed")
        if self.connection_callback:
            self.connection_callback(False)
    
    def close(self):
        self._log("Closing network connections")
        if self.peer_socket:
            self.peer_socket.close()
            self._log("Peer socket closed")
        if self.socket:
            self.socket.close()
            self._log("Server socket closed")
