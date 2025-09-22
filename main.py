#!/usr/bin/env python3

import sys
import time
from protocol import PairwiseProtocol, ConnectionState
from terminal_ui import TerminalUI

class PairwiseApp:
    def __init__(self):
        self.protocol = PairwiseProtocol()
        self.ui = TerminalUI()
        self.my_key = None
        
        self.protocol.set_message_callback(self._handle_protocol_message)
        self.ui.set_message_callback(self._handle_user_input)
    
    def start(self):
        self.ui.clear_screen()
        print("=== Pairwise Chat ===")
        print()
        
        self.my_key = self.protocol.generate_key()
        print(f"Your key: {self.my_key}")
        print()
        print("Commands:")
        print("  listen                    - Start listening for connections")
        print("  connect <ip> <peer_key>   - Connect to peer")
        print("  quit                      - Exit")
        print()
        
        self.ui.start()
        
        try:
            while self.ui.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            self.protocol.close()
    
    def _handle_protocol_message(self, sender: str, message: str):
        self.ui.display_message(sender, message)
    
    def _handle_user_input(self, text: str):
        parts = text.split()
        command = parts[0].lower() if parts else ""
        
        if command == "quit":
            self.ui.running = False
            return
        
        elif command == "listen":
            self.protocol.start_listening()
            self.ui.display_info("Listening for connections...")
        
        elif command == "connect":
            if len(parts) != 3:
                self.ui.display_info("Usage: connect <ip> <peer_key>")
                return
            
            ip = parts[1]
            peer_key = parts[2]
            
            self.ui.display_info(f"Connecting to {ip}...")
            self.protocol.connect_to_peer(ip, peer_key)
        
        elif self.protocol.get_state() == ConnectionState.CONNECTED:
            if self.protocol.send_chat_message(text):
                self.ui.display_message('you', text)
            else:
                self.ui.display_info("Failed to send message")
        
        else:
            self.ui.display_info("Not connected. Use 'listen' or 'connect <ip> <peer_key>'")

def main():
    app = PairwiseApp()
    app.start()

if __name__ == "__main__":
    main()
