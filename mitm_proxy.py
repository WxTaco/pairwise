#!/usr/bin/env python3

import socket
import threading
import json
import time
from typing import Optional, Dict, Any
from datetime import datetime

class MITMProxy:
    """
    Man-in-the-Middle proxy to demonstrate what an attacker would see
    when intercepting encrypted pairwise communications.
    """
    
    def __init__(self, listen_port: int = 8888, target_host: str = "localhost", target_port: int = 9999):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        
    def start(self) -> None:
        """Start the MITM proxy server"""
        print(f"🕵️  MITM Proxy starting on port {self.listen_port}")
        print(f"📡 Forwarding to {self.target_host}:{self.target_port}")
        print(f"🔍 Will show all intercepted traffic\n")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.listen_port))
        self.server_socket.listen(1)
        self.running = True
        
        print(f"✅ MITM Proxy listening on port {self.listen_port}")
        print("💡 Connect your client to this proxy instead of the real server\n")
        
        try:
            while self.running:
                client_socket, client_addr = self.server_socket.accept()
                print(f"🔗 New connection from {client_addr[0]}:{client_addr[1]}")
                
                # Create connection to real server
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    server_socket.connect((self.target_host, self.target_port))
                    print(f"🔗 Connected to real server {self.target_host}:{self.target_port}")
                    
                    # Start forwarding threads
                    client_to_server = threading.Thread(
                        target=self._forward_data,
                        args=(client_socket, server_socket, "CLIENT→SERVER", client_addr[0])
                    )
                    server_to_client = threading.Thread(
                        target=self._forward_data,
                        args=(server_socket, client_socket, "SERVER→CLIENT", "server")
                    )
                    
                    client_to_server.daemon = True
                    server_to_client.daemon = True
                    
                    client_to_server.start()
                    server_to_client.start()
                    
                except Exception as e:
                    print(f"❌ Failed to connect to server: {e}")
                    client_socket.close()
                    server_socket.close()
                    
        except KeyboardInterrupt:
            print("\n🛑 MITM Proxy shutting down...")
        finally:
            self.stop()
    
    def _forward_data(self, source: socket.socket, destination: socket.socket, 
                     direction: str, source_name: str) -> None:
        """Forward data between sockets while logging everything"""
        buffer = ""
        
        try:
            while self.running:
                data = source.recv(1024)
                if not data:
                    break
                    
                # Forward the data
                destination.send(data)
                
                # Log what we intercepted
                decoded_data = data.decode('utf-8', errors='ignore')
                buffer += decoded_data
                
                # Process complete JSON messages
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self._log_intercepted_message(line.strip(), direction, source_name)
                        
        except Exception as e:
            print(f"❌ Connection error in {direction}: {e}")
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass
    
    def _log_intercepted_message(self, message: str, direction: str, source: str) -> None:
        """Log and analyze intercepted messages"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            # Try to parse as JSON
            parsed = json.loads(message)
            msg_type = parsed.get('type', 'unknown')
            data = parsed.get('data', {})
            
            print(f"\n📦 [{timestamp}] {direction} ({source})")
            print(f"   Message Type: {msg_type}")
            
            if msg_type == 'key_exchange' or msg_type == 'key_exchange_response':
                public_key = data.get('public_key', '')
                print(f"   🔑 PUBLIC KEY EXPOSED: {public_key[:50]}...")
                print(f"   ⚠️  ATTACKER CAN SEE: Public keys (but can't derive private keys)")
                
            elif msg_type == 'auth_challenge':
                challenge = data.get('challenge', '')
                print(f"   🎯 CHALLENGE: {challenge}")
                print(f"   ⚠️  ATTACKER CAN SEE: Random challenges (but can't forge signatures)")
                
            elif msg_type == 'auth_response':
                challenge = data.get('challenge', '')
                signature = data.get('signature', '')
                print(f"   🎯 CHALLENGE: {challenge}")
                print(f"   ✍️  SIGNATURE: {signature[:50]}...")
                print(f"   ⚠️  ATTACKER CAN SEE: Signatures (but can't forge new ones)")
                
            elif msg_type == 'auth_success' or msg_type == 'auth_failure':
                print(f"   ✅ AUTH RESULT: {msg_type}")
                print(f"   ⚠️  ATTACKER CAN SEE: Authentication outcome")
                
            elif msg_type == 'chat':
                if 'encrypted' in data:
                    encrypted_data = data.get('encrypted', '')
                    print(f"   🔒 ENCRYPTED MESSAGE: {encrypted_data[:50]}...")
                    print(f"   🛡️  ATTACKER CANNOT READ: Message is AES-GCM encrypted!")
                    print(f"   🔐 ENCRYPTION WORKING: Content is completely hidden")
                else:
                    # Unencrypted message (shouldn't happen in E2EE mode)
                    text = data.get('text', '')
                    print(f"   ⚠️  PLAINTEXT MESSAGE: {text}")
                    print(f"   🚨 SECURITY BREACH: Message is not encrypted!")
            else:
                print(f"   📄 Raw Data: {str(data)[:100]}...")
                
        except json.JSONDecodeError:
            print(f"\n📦 [{timestamp}] {direction} ({source})")
            print(f"   📄 Non-JSON Data: {message[:100]}...")
        
        print("   " + "─" * 60)
    
    def stop(self) -> None:
        """Stop the MITM proxy"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

def main() -> None:
    print("🕵️  Pairwise E2EE Man-in-the-Middle Demonstration")
    print("=" * 50)
    print("This tool shows what an attacker would see when intercepting")
    print("encrypted pairwise communications.\n")
    
    print("Setup:")
    print("1. Start your pairwise server on port 9999 (python main.py -> listen)")
    print("2. Run this MITM proxy (it will listen on port 8888)")
    print("3. Connect your client to port 8888 instead of 9999")
    print("4. Watch what the attacker can and cannot see!\n")
    
    proxy = MITMProxy(listen_port=8888, target_host="localhost", target_port=9999)
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()
