"""Chained Block progress display."""
from __future__ import annotations
import sys
import time

class NullProgress:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def set_total(self, n): pass
    def target(self, url): pass
    def phase_start(self, name, detail=""): pass
    def phase_end(self, name, detail=""): pass
    def domain_started(self, name): pass
    def domain_done(self, name, findings=0): pass
    def ai_call(self, current, total): pass
    def detail(self, text): pass

class ScanProgress:
    def __init__(self):
        self.start_time = 0
        self.current_phase = ""
        self.current_detail = ""
        self.phase_start_time = 0
        self.is_running = False
        
        # ANSI Colors
        self.CYAN = "\033[1;36m"
        self.GREEN = "\033[1;32m"
        self.WHITE = "\033[1;37m"
        self.DIM = "\033[2m"
        self.RESET = "\033[0m"
        self.CLEAR = "\r\033[K"

    def __enter__(self):
        self.start_time = time.monotonic()
        self.is_running = True
        return self

    def __exit__(self, *a):
        self.is_running = False
        if self.current_phase:
            self.phase_end(self.current_phase, self.current_detail)

    def _render_bar(self, width=24):
        """Creates a chained link progress bar."""
        elapsed = time.monotonic() - self.phase_start_time
        fill_pct = min(1.0, elapsed / 1.5)
        pos = int(fill_pct * width)
        
        # Chain Link Style (▰ filled, ▱ empty)
        filled = "▰" * pos
        empty = "▱" * (width - pos)
        return f"{self.WHITE}{filled}{self.DIM}{empty}{self.RESET}"

    def target(self, url):
        print(f"\n{self.CYAN}>{self.RESET} {url}\n")

    def phase_start(self, name, detail=""):
        if not self.is_running: return
        if self.current_phase and self.current_phase != name:
            self.phase_end(self.current_phase, self.current_detail)
            
        self.current_phase = name
        self.current_detail = detail
        self.phase_start_time = time.monotonic()
        
        bar = self._render_bar()
        sys.stdout.write(f"{self.CLEAR}  {name:<10} {bar} {self.DIM}{detail}{self.RESET}")
        sys.stdout.flush()

    def detail(self, text):
        if not self.is_running or not self.current_phase: return
        self.current_detail = text
        bar = self._render_bar()
        sys.stdout.write(f"{self.CLEAR}  {self.current_phase:<10} {bar} {self.DIM}{text}{self.RESET}")
        sys.stdout.flush()

    def phase_end(self, name, detail=""):
        if not self.is_running: return
        elapsed = time.monotonic() - self.phase_start_time
        if detail:
            self.current_detail = detail
        
        # Complete bar (fully filled with chained blocks)
        bar = f"{self.GREEN}{'▰' * 24}{self.RESET}"
        time_str = f"in {elapsed:.2f}s" if elapsed >= 0.1 else "< 0.1s"
        
        sys.stdout.write(f"{self.CLEAR}  {name:<10} {bar} {self.DIM}{self.current_detail} {time_str}{self.RESET}\n")
        sys.stdout.flush()
        self.current_phase = ""

    def domain_started(self, name): self.detail(f"crawling {name}")
    def domain_done(self, name, findings=0): self.detail(f"finished {name} ({findings} findings)")
    def ai_call(self, current, total): self.detail(f"retracting {current}/{total}")

def make_progress(quiet: bool = False):
    if quiet or not sys.stdout.isatty(): return NullProgress()
    return ScanProgress()
