#!/usr/bin/env python3

import sys
import time
from datetime import datetime
from protocol import PairwiseProtocol, ConnectionState
from terminal_ui import TerminalUI

class PairwiseApp:
    def __init__(self):
        self.log_enabled = True
        self.protocol = PairwiseProtocol(logger=self._log)
        self.ui = TerminalUI(logger=self._log)
        self.my_key = None

        self.protocol.set_message_callback(self._handle_protocol_message)
        self.ui.set_message_callback(self._handle_user_input)

    def _log(self, message):
        if self.log_enabled:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"\n[{timestamp}] {message}")
            print("> ", end="", flush=True)
    
    def start(self):
        self.ui.clear_screen()
        print("=== Pairwise Chat with Detailed Logging ===")
        print()

        print("Initializing pairwise protocol...")
        self.my_key = self.protocol.generate_key_pair()
        print(f"Your public key: {self.my_key[:32]}...")
        print()
        print("Commands:")
        print("  listen                    - Start listening for connections")
        print("  connect <ip>              - Connect to peer (no pre-shared key needed)")
        print("  logs on/off               - Toggle detailed logging")
        print("  quit                      - Exit")
        print()
        print("=== Detailed logging is ON - you'll see every step of the pairwise process ===")
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

        elif command == "logs":
            if len(parts) > 1 and parts[1].lower() == "off":
                self.log_enabled = False
                self.ui.display_info("Detailed logging disabled")
            elif len(parts) > 1 and parts[1].lower() == "on":
                self.log_enabled = True
                self.ui.display_info("Detailed logging enabled")
            else:
                self.ui.display_info("Usage: logs on/off")
            return

        elif command == "listen":
            self.ui.display_info("Starting to listen for connections...")
            self.protocol.start_listening()

        elif command == "connect":
            if len(parts) != 2:
                self.ui.display_info("Usage: connect <ip>")
                return

            ip = parts[1]

            self.ui.display_info(f"Initiating connection to {ip}...")
            self.protocol.connect_to_peer(ip)

        elif self.protocol.get_state() == ConnectionState.CONNECTED:
            if self.protocol.send_chat_message(text):
                self.ui.display_message('you', text)
            else:
                self.ui.display_info("Failed to send message")

        else:
            self.ui.display_info("Not connected. Use 'listen' or 'connect <ip>'")

def main():
    app = PairwiseApp()
    app.start()

if __name__ == "__main__":
    main()
