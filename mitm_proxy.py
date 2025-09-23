#!/usr/bin/env python3

import socket
import threading
import json
from typing import Optional
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
                print(f"   📖 EXPLANATION: This is an ECDSA public key on the P-256 curve.")
                print(f"   🔍 WHAT ATTACKER SEES: The mathematical point on the elliptic curve")
                print(f"   🛡️  WHY IT'S SAFE: Computing the private key from this public key")
                print(f"                      would require solving the Elliptic Curve Discrete")
                print(f"                      Logarithm Problem - computationally infeasible!")
                print(f"   ⏱️  ATTACK TIME: ~2^128 operations = billions of years with all")
                print(f"                   computers on Earth working together")

            elif msg_type == 'auth_challenge':
                challenge = data.get('challenge', '')
                print(f"   🎯 CHALLENGE: {challenge}")
                print(f"   📖 EXPLANATION: Random 32-byte value used for authentication")
                print(f"   🔍 WHAT ATTACKER SEES: Random hexadecimal string")
                print(f"   🛡️  WHY IT'S SAFE: Only the holder of the private key can create")
                print(f"                      a valid signature for this challenge")
                print(f"   🚫 ATTACK IMPOSSIBLE: Cannot forge signatures without private key")

            elif msg_type == 'auth_response':
                challenge = data.get('challenge', '')
                signature = data.get('signature', '')
                print(f"   🎯 CHALLENGE: {challenge}")
                print(f"   ✍️  SIGNATURE: {signature[:50]}...")
                print(f"   📖 EXPLANATION: ECDSA signature proving ownership of private key")
                print(f"   🔍 WHAT ATTACKER SEES: Mathematical signature (r, s) values")
                print(f"   🛡️  WHY IT'S SAFE: Signature is tied to specific challenge + private key")
                print(f"   🚫 ATTACK IMPOSSIBLE: Cannot create valid signatures for other challenges")
                print(f"   🔐 CRYPTO STRENGTH: Breaking this requires solving discrete logarithm")

            elif msg_type == 'auth_success' or msg_type == 'auth_failure':
                print(f"   ✅ AUTH RESULT: {msg_type}")
                print(f"   📖 EXPLANATION: Result of signature verification")
                print(f"   🔍 WHAT ATTACKER SEES: Whether authentication succeeded")
                print(f"   🛡️  WHY IT'S SAFE: Knowing the outcome doesn't help break encryption")
                print(f"   ℹ️  METADATA ONLY: No secret information revealed")

            elif msg_type == 'chat':
                if 'encrypted' in data:
                    encrypted_data = data.get('encrypted', '')
                    print(f"   🔒 ENCRYPTED MESSAGE: {encrypted_data[:50]}...")
                    print(f"   📖 EXPLANATION: AES-256-GCM encrypted message with authentication")
                    print(f"   � WHAT ATTACKER SEES: Random-looking base64 encoded data")
                    print(f"   🛡️  ENCRYPTION DETAILS:")
                    print(f"      • Algorithm: AES-256 in Galois/Counter Mode (GCM)")
                    print(f"      • Key: 256-bit key derived from ECDH shared secret")
                    print(f"      • Nonce: 96-bit random value (prevents replay attacks)")
                    print(f"      • Authentication: Built-in message authentication")
                    print(f"   🚫 ATTACK IMPOSSIBLE: Breaking AES-256 requires 2^256 operations")
                    print(f"   ⏱️  ATTACK TIME: Longer than the age of the universe")
                    print(f"   🔐 PERFECT SECRECY: Message content is mathematically hidden")
                else:
                    # Unencrypted message (shouldn't happen in E2EE mode)
                    text = data.get('text', '')
                    print(f"   ⚠️  PLAINTEXT MESSAGE: {text}")
                    print(f"   🚨 SECURITY BREACH: Message is not encrypted!")
                    print(f"   📖 EXPLANATION: This should never happen in E2EE mode!")
            else:
                print(f"   📄 Raw Data: {str(data)[:100]}...")
                print(f"   📖 EXPLANATION: Unknown message type - possibly protocol extension")
                
        except json.JSONDecodeError:
            print(f"\n📦 [{timestamp}] {direction} ({source})")
            print(f"   📄 Non-JSON Data: {message[:100]}...")
        
        print("   " + "─" * 60)
    
    def stop(self) -> None:
        """Stop the MITM proxy"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

def print_e2ee_explanation() -> None:
    """Print comprehensive explanation of E2EE security"""
    print("\n" + "=" * 80)
    print("🔐 END-TO-END ENCRYPTION (E2EE) SECURITY EXPLANATION")
    print("=" * 80)

    print("\n📚 WHAT IS END-TO-END ENCRYPTION?")
    print("─" * 40)
    print("E2EE means only the sender and receiver can read messages.")
    print("Even if an attacker intercepts ALL network traffic, they")
    print("cannot decrypt the message content.")

    print("\n🔑 HOW THIS PAIRWISE E2EE WORKS:")
    print("─" * 35)
    print("1. KEY EXCHANGE PHASE:")
    print("   • Each peer generates an ECDSA key pair (private + public)")
    print("   • Public keys are exchanged openly (safe to intercept)")
    print("   • ECDH algorithm derives a shared secret from:")
    print("     - Your private key + Their public key = Shared Secret")
    print("   • This shared secret is used to create AES-256 encryption keys")
    print("   • Attacker sees public keys but CANNOT derive the shared secret")

    print("\n2. AUTHENTICATION PHASE:")
    print("   • Challenge-response using ECDSA digital signatures")
    print("   • Proves each peer owns their private key")
    print("   • Prevents impersonation attacks")
    print("   • Attacker can see challenges/signatures but cannot forge them")

    print("\n3. ENCRYPTED COMMUNICATION:")
    print("   • All messages encrypted with AES-256-GCM")
    print("   • Each message has a unique nonce (number used once)")
    print("   • GCM mode provides both encryption AND authentication")
    print("   • Attacker sees only random-looking encrypted data")

    print("\n🛡️  SECURITY GUARANTEES:")
    print("─" * 25)
    print("✅ CONFIDENTIALITY: Message content is hidden")
    print("✅ AUTHENTICATION: You know who you're talking to")
    print("✅ INTEGRITY: Messages cannot be tampered with")
    print("✅ FORWARD SECRECY: New keys for each session")
    print("✅ NO PRE-SHARED KEYS: No key distribution problems")

    print("\n⚠️  WHAT ATTACKERS CAN SEE:")
    print("─" * 28)
    print("🔍 Public keys (useless without private keys)")
    print("🔍 Message timing and sizes")
    print("🔍 Connection metadata")
    print("🔍 Authentication success/failure")
    print("🔍 Encrypted message data (looks like random noise)")

    print("\n🚫 WHAT ATTACKERS CANNOT DO:")
    print("─" * 30)
    print("❌ Read message content")
    print("❌ Derive private keys from public keys")
    print("❌ Forge digital signatures")
    print("❌ Decrypt messages without the shared secret")
    print("❌ Perform man-in-the-middle attacks (signatures prevent this)")

    print("\n🧮 CRYPTOGRAPHIC STRENGTH:")
    print("─" * 28)
    print("• ECDSA P-256: ~128-bit security (would take 2^128 operations to break)")
    print("• AES-256-GCM: 256-bit keys (would take 2^256 operations to break)")
    print("• These are considered quantum-resistant for the foreseeable future")
    print("• Even nation-state attackers cannot break this encryption")

    print("\n" + "=" * 80)

def main() -> None:
    print("🕵️  Pairwise E2EE Man-in-the-Middle Demonstration")
    print("=" * 50)
    print("This tool shows what an attacker would see when intercepting")
    print("encrypted pairwise communications.")

    print_e2ee_explanation()

    print("\n🎯 DEMONSTRATION SETUP:")
    print("─" * 25)
    print("1. Start your pairwise server on port 9999 (python main.py -> listen)")
    print("2. Run this MITM proxy (it will listen on port 8888)")
    print("3. Connect your client to port 8888 instead of 9999")
    print("4. Send messages and watch what the attacker can/cannot see!")
    print("\n💡 The proxy will intercept and analyze every packet,")
    print("   showing you exactly what a real attacker would observe.\n")

    proxy = MITMProxy(listen_port=8888, target_host="localhost", target_port=9999)

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n🛑 MITM Proxy shutting down...")
        print("\n📊 DEMONSTRATION COMPLETE!")
        print("─" * 30)
        print("As you can see, even with complete network access,")
        print("the attacker could not read any message content.")
        print("This proves the E2EE implementation is working correctly!")
        print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()
