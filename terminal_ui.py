import threading
from datetime import datetime

class TerminalUI:
    def __init__(self, logger=None):
        self.running = False
        self.input_thread = None
        self.message_callback = None
        self.logger = logger

    def _log(self, message):
        if self.logger:
            self.logger(f"[UI] {message}")
    
    def set_message_callback(self, callback):
        self.message_callback = callback
    
    def start(self):
        self.running = True
        self.input_thread = threading.Thread(target=self._input_loop)
        self.input_thread.daemon = True
        self.input_thread.start()
    
    def stop(self):
        self.running = False
    
    def display_message(self, sender: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if sender == 'system':
            print(f"\n[{timestamp}] SYSTEM: {message}")
        elif sender == 'peer':
            print(f"\n[{timestamp}] PEER: {message}")
        elif sender == 'you':
            print(f"[{timestamp}] YOU: {message}")
        
        self._show_prompt()
    
    def display_info(self, message: str):
        print(f"\n{message}")
        self._show_prompt()
    
    def _show_prompt(self):
        print("> ", end="", flush=True)
    
    def _input_loop(self):
        self._show_prompt()
        while self.running:
            try:
                line = input()
                if line.strip() and self.message_callback:
                    self.message_callback(line.strip())
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break
    
    def clear_screen(self):
        print("\033[2J\033[H", end="")
