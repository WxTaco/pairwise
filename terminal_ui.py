import threading
from typing import Optional, Callable
from datetime import datetime

class TerminalUI:
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self.running = False
        self.input_thread: Optional[threading.Thread] = None
        self.message_callback: Optional[Callable[[str], None]] = None
        self.logger = logger

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(f"[UI] {message}")

    def set_message_callback(self, callback: Callable[[str], None]) -> None:
        self.message_callback = callback

    def start(self) -> None:
        self.running = True
        self.input_thread = threading.Thread(target=self._input_loop)
        self.input_thread.daemon = True
        self.input_thread.start()

    def stop(self) -> None:
        self.running = False
    
    def display_message(self, sender: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")

        if sender == 'system':
            print(f"\n[{timestamp}] SYSTEM: {message}")
        elif sender == 'peer':
            print(f"\n[{timestamp}] PEER: {message}")
        elif sender == 'you':
            print(f"[{timestamp}] YOU: {message}")

        self._show_prompt()

    def display_info(self, message: str) -> None:
        print(f"\n{message}")
        self._show_prompt()

    def _show_prompt(self) -> None:
        print("> ", end="", flush=True)

    def _input_loop(self) -> None:
        self._show_prompt()
        while self.running:
            try:
                line = input()
                if line.strip() and self.message_callback:
                    self.message_callback(line.strip())
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

    def clear_screen(self) -> None:
        print("\033[2J\033[H", end="")
