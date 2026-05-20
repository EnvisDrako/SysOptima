"""
SysOptima EDR Graph-Processor Test Suite
"""

import os
import sys
import queue
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from graph_engine import ThreatGraph
from event_filter import EventFilter
from lineage_tracker import LineageTracker
from response_orchestrator import ResponseOrchestrator
from config_manager import ConfigManager
from main import AIObserver

class TestGraphProcessor(unittest.TestCase):
    def setUp(self):
        self.cmd_queue = queue.Queue()
        self.ai_observer = AIObserver()
        self.config = ConfigManager()
        self.graph = ThreatGraph(self.cmd_queue, self.ai_observer)
        self.orchestrator = ResponseOrchestrator(self.cmd_queue, self.graph)
        self.graph.response_orchestrator = self.orchestrator

    def test_event_deduplication(self):
        """Test that EventFilter sliding-window correctly filters duplicates"""
        filt = EventFilter(window_seconds=1.0)
        
        # First file write event should be allowed
        self.assertTrue(filt.should_allow(1234, 'FILE_WRITE', 'C:\\Windows\\System32\\cmd.exe'))
        
        # Second immediate identical write should be blocked
        self.assertFalse(filt.should_allow(1234, 'FILE_WRITE', 'C:\\Windows\\System32\\cmd.exe'))
        
        # Event with different argument or PID should be allowed
        self.assertTrue(filt.should_allow(1234, 'FILE_WRITE', 'C:\\Windows\\System32\\notepad.exe'))
        self.assertTrue(filt.should_allow(5678, 'FILE_WRITE', 'C:\\Windows\\System32\\cmd.exe'))
        
        # Event after window expiry should be allowed
        time.sleep(1.1)
        self.assertTrue(filt.should_allow(1234, 'FILE_WRITE', 'C:\\Windows\\System32\\cmd.exe'))

    def test_guid_process_tracking_and_lineage(self):
        """Test GUID-based process creation, lineage topology tracking, and metrics extraction"""
        # 1. Create a parent process node
        ts1 = int(time.time() * 1000)
        p_id = self.graph.add_process(
            pid=1000,
            ppid=0,
            name="explorer.exe",
            origin="SYSTEM",
            threat_level=0,
            timestamp=ts1,
            is_signed=True,
            full_path="C:\\Windows\\explorer.exe"
        )
        self.assertTrue(p_id.startswith("proc_1000_"))
        self.assertIn(1000, self.graph.active_pids)
        self.assertEqual(self.graph.active_pids[1000], p_id)
        
        # 2. Create child process node under parent PID
        ts2 = ts1 + 100
        c_id = self.graph.add_process(
            pid=2000,
            ppid=1000,
            name="cmd.exe",
            origin="USER",
            threat_level=1,
            timestamp=ts2,
            is_signed=True,
            full_path="C:\\Windows\\System32\\cmd.exe"
        )
        self.assertTrue(c_id.startswith("proc_2000_"))
        self.assertEqual(self.graph.active_pids[2000], c_id)
        
        # Check parent-child edge
        self.assertTrue(self.graph.G.has_edge(p_id, c_id))
        
        # 3. Test Lineage Tracker on the active processes using class-level methods
        depth = LineageTracker.calculate_tree_depth(self.graph.G, c_id)
        suspicious = LineageTracker.calculate_suspicious_parent_flag(self.graph.G, c_id)
        score = LineageTracker.calculate_lineage_threat_score(self.graph.G, c_id)
        
        self.assertEqual(depth, 1)
        self.assertEqual(suspicious, 0)
        self.assertEqual(score, 5.0)  # explorer.exe has threat 0, contributing 5.0 points
        
        # 4. Trigger process exit
        self.graph.remove_active_pid(2000)
        self.assertNotIn(2000, self.graph.active_pids)

    def test_smart_terminate_bottom_up(self):
        """Test bottom-up smart kill execution"""
        ts = int(time.time() * 1000)
        # Setup: explorer.exe -> cmd.exe -> malware.exe (threat level 2)
        p1 = self.graph.add_process(100, 0, "explorer.exe", "SYSTEM", 0, ts, True, "explorer.exe")
        p2 = self.graph.add_process(200, 100, "cmd.exe", "USER", 0, ts+10, True, "cmd.exe")
        p3 = self.graph.add_process(300, 200, "malware.exe", "INTERNET", 2, ts+20, False, "malware.exe")
        
        # We manually trigger handle_threat or test bottom-up smart kill on PID 300
        # For PID 300, the lineages should walk down/up to resolve targets
        lineage = self.graph.get_process_lineage(300)
        descendants = lineage.get('descendants', [])
        
        self.assertEqual(len(descendants), 0) # No children
        
        # Trigger kill tree
        self.orchestrator._execute_kill_tree(300, "Test smart terminate")
        
        # Inspect commands inside cmd_queue
        cmds = []
        while not self.cmd_queue.empty():
            cmds.append(self.cmd_queue.get())
        
        self.assertTrue(len(cmds) >= 2) # Should include kill pid and kill tree fallback

if __name__ == "__main__":
    unittest.main()
