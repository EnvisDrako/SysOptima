"""
SysOptima Event Filter
Sliding-window deduplicator to filter high-frequency duplicate telemetry events.
"""
import time
from typing import Dict, Tuple

class EventFilter:
    """High-performance sliding-window event deduplicator"""
    
    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        # Key: (pid, event_type, identifier) -> float timestamp
        self.seen_events: Dict[Tuple[int, int, str], float] = {}
    
    def should_allow(self, pid: int, event_type: int, identifier: str) -> bool:
        """
        Check if the event is unique inside the sliding window.
        Returns True if the event is new, False if it should be deduplicated (dropped).
        """
        now = time.monotonic()
        key = (pid, event_type, identifier)
        
        # Prune old cache entries if it gets large to keep memory usage small
        if len(self.seen_events) > 2000:
            self.seen_events = {k: v for k, v in self.seen_events.items() if now - v < self.window_seconds}
            
        last_seen = self.seen_events.get(key, 0.0)
        if now - last_seen < self.window_seconds:
            return False
            
        self.seen_events[key] = now
        return True
