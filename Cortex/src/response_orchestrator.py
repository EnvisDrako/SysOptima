"""
SysOptima Response Orchestrator
Graduated response system: Monitor → Suspend → Kill based on threat + trust
"""

import time
from typing import Dict, List

from protocol import CMD_KILL_PID, CMD_SUSPEND_PID, CMD_KILL_TREE, pack_command

class ResponseOrchestrator:
    """Intelligent response system with graduated actions"""
    
    def __init__(self, command_queue, graph):
        self.command_queue = command_queue
        self.graph = graph
        self.pending_reviews = []  # Processes awaiting user confirmation
        self.suspended_processes = {}  # PID -> suspend_time
        self.quarantine_manager = None  # Will be set by main.py
        # [PASS] ADD KILL PROTECTION
        self.protected_processes = {
            'chrome.exe', 'msedge.exe', 'firefox.exe',
            'code.exe', 'explorer.exe', 'python.exe'  # Don't kill ourselves!
        }
        
    def handle_threat(self, pid: int, threat_level: int, trust_score: int, 
                     tags: List[str], name: str, full_path: str):
        """
        Main decision engine
        Returns: action taken (for logging)
        """
        if name.lower() in self.protected_processes:
            print(f"[PROTECTION] Refusing to kill protected process: {name}")
            return {'type': 'MONITOR', 'reason': 'Protected process'}
        
        # Special pattern overrides (instant kill regardless of trust)
        if self._check_critical_patterns(tags):
            action = self._execute_kill_tree(pid, "Critical pattern detected")
            print(f"[RESPONSE] CRITICAL PATTERN → Kill Tree: {name} (PID {pid})")
            return action
        
        # Decision matrix based on threat + trust
        action = self._decide_action(threat_level, trust_score, tags, name)
        
        if action['requires_confirmation']:
            self._queue_for_review(pid, action, threat_level, trust_score, name, full_path)
        else:
            self._execute_action(pid, action, name)
        
        return action
    
    def _check_critical_patterns(self, tags: List[str]) -> bool:
        """Check for patterns that always trigger instant kill"""
        critical_patterns = [
            'TAG_MASQUERADING',  # Fake system process
            'TAG_RANSOMWARE',    # Mass encryption
            'TAG_CREDENTIAL_LSASS'  # LSASS dumping
        ]
        
        for pattern in critical_patterns:
            if any(pattern in tag for tag in tags):
                return True
        return False
    
    def _decide_action(self, threat_level: int, trust_score: int, 
                      tags: List[str], name: str) -> Dict:
        """
        Decision Matrix:
        
        Threat=0 (Safe) + Any Trust = MONITOR
        Threat=1 (Suspicious) + High Trust (40+) = MONITOR + FLAG
        Threat=1 (Suspicious) + Medium Trust (-40 to 40) = SUSPEND + REVIEW
        Threat=1 (Suspicious) + Low Trust (-100 to -40) = KILL
        Threat=2 (Critical) + High Trust (40+) = SUSPEND + URGENT REVIEW
        Threat=2 (Critical) + Medium Trust (-40 to 40) = SUSPEND + AUTO-KILL TIMER
        Threat=2 (Critical) + Low Trust (-100 to -40) = KILL TREE
        """
        if threat_level == 0:
            return {
                'type': 'MONITOR',
                'reason': 'Normal behavior',
                'requires_confirmation': False,
                'urgency': 'NONE'
            }
        
        elif threat_level == 1:
            if trust_score >= 40:
                return {
                    'type': 'MONITOR',
                    'reason': 'Trusted app with suspicious behavior - watching',
                    'requires_confirmation': False,
                    'urgency': 'LOW'
                }
            elif trust_score >= -40:
                return {
                    'type': 'SUSPEND',
                    'reason': 'Suspicious behavior - awaiting review',
                    'requires_confirmation': True,
                    'urgency': 'MEDIUM',
                    'auto_kill_timer': 60
                }
            else:
                return {
                    'type': 'KILL',
                    'reason': 'Untrusted suspicious process',
                    'requires_confirmation': False,
                    'urgency': 'HIGH'
                }
        
        else:  # threat_level == 2 (Critical)
            if trust_score >= 40:
                return {
                    'type': 'SUSPEND',
                    'reason': 'ANOMALY: Trusted app showing critical threat behavior!',
                    'requires_confirmation': True,
                    'urgency': 'CRITICAL'
                }
            elif trust_score >= -40:
                return {
                    'type': 'SUSPEND',
                    'reason': 'Critical threat - auto-kill in 60s if not reviewed',
                    'requires_confirmation': False,
                    'urgency': 'HIGH',
                    'auto_kill_timer': 60
                }
            else:
                return {
                    'type': 'KILL_TREE',
                    'reason': 'Critical untrusted threat',
                    'requires_confirmation': False,
                    'urgency': 'CRITICAL'
                }
    
    def _execute_action(self, pid: int, action: Dict, name: str):
        """Execute the decided action"""
        action_type = action['type']
        reason = action['reason']
        
        if action_type == 'MONITOR':
            print(f"[RESPONSE] MONITOR: {name} (PID {pid}) - {reason}")
        
        elif action_type == 'SUSPEND':
            self._execute_suspend(pid, reason, name)
            
            if 'auto_kill_timer' in action:
                self.suspended_processes[pid] = {
                    'suspend_time': time.time(),
                    'auto_kill_seconds': action['auto_kill_timer'],
                    'name': name,
                    'reason': reason
                }
        
        elif action_type == 'KILL':
            self._execute_kill(pid, reason, name)
        
        elif action_type == 'KILL_TREE':
            self._execute_kill_tree(pid, reason, name)
    
    def _execute_suspend(self, pid: int, reason: str, name: str):
        """Send suspend command to C++"""
        self.command_queue.put(pack_command(CMD_SUSPEND_PID, pid))
        print(f"[RESPONSE] [SUSPEND] {name} (PID {pid}) - {reason}")
    
    def _execute_kill(self, pid: int, reason: str, name: str):
        """Send kill command to C++ and quarantine files"""
        if self.quarantine_manager:
            try:
                proc_info = self.graph.GetProcess(pid)
                if proc_info and proc_info.get('full_path'):
                    full_path = proc_info['full_path']
                    threat_level = proc_info.get('threat_level', 2)
                    
                    quarantine_id = self.quarantine_manager.quarantine_file(
                        file_path=full_path,
                        threat_level=threat_level,
                        threat_reason=reason,
                        process_pid=pid,
                        process_name=name
                    )
                    
                    if quarantine_id:
                        print(f"[RESPONSE] [QUARANTINE] {name} -> {quarantine_id}")
                    
            except Exception as e:
                print(f"[RESPONSE] Quarantine failed for {name}: {e}")
        
        self.command_queue.put(pack_command(CMD_KILL_PID, pid))
        print(f"[RESPONSE] [KILL] {name} (PID {pid}) - {reason}")
    
    def _execute_kill_tree(self, pid: int, reason: str, name: str = ""):
        """Execute a smart bottom-up process tree snipping, terminating leaves first to prevent watchdog recovery"""
        try:
            lineage = self.graph.get_process_lineage(pid)
        except Exception as e:
            print(f"[RESPONSE] Failed to fetch process lineage for smart terminate: {e}")
            lineage = {'ancestors': [], 'descendants': [], 'process': None}
            
        if self.quarantine_manager:
            try:
                if lineage.get('process'):
                    proc = lineage['process']
                    if proc.get('full_path'):
                        quarantine_id = self.quarantine_manager.quarantine_file(
                            file_path=proc['full_path'],
                            threat_level=proc.get('threat', 2),
                            threat_reason=f"Process tree root: {reason}",
                            process_pid=pid,
                            process_name=proc.get('label', name)
                        )
                        if quarantine_id:
                            print(f"[RESPONSE] [QUARANTINE] Tree root: {proc.get('label', name)} -> {quarantine_id}")
                
                for descendant in lineage.get('descendants', []):
                    if descendant.get('full_path'):
                        quarantine_id = self.quarantine_manager.quarantine_file(
                            file_path=descendant['full_path'],
                            threat_level=descendant.get('threat', 2),
                            threat_reason=f"Process tree child: {reason}",
                            process_pid=descendant.get('pid'),
                            process_name=descendant.get('label', 'Unknown')
                        )
                        if quarantine_id:
                            print(f"[RESPONSE] [QUARANTINE] Tree child: {descendant.get('label', 'Unknown')} -> {quarantine_id}")
                            
            except Exception as e:
                print(f"[RESPONSE] Tree quarantine failed: {e}")
        
        descendants = lineage.get('descendants', [])
        if descendants:
            print(f"[RESPONSE] [TREE_KILL] Initiating smart bottom-up snipping for {len(descendants)} children...")
            import time
            for descendant in reversed(descendants):
                desc_pid = descendant.get('pid')
                desc_name = descendant.get('label', 'Unknown')
                if desc_pid and desc_pid != pid:
                    self.command_queue.put(pack_command(CMD_KILL_PID, desc_pid))
                    print(f"[RESPONSE] [KILL] Smart Terminate (Child Leaf): {desc_name} (PID {desc_pid})")
                    time.sleep(0.05)
        
        self.command_queue.put(pack_command(CMD_KILL_PID, pid))
        self.command_queue.put(pack_command(CMD_KILL_TREE, pid))
        print(f"[RESPONSE] [TREE_KILL] Smart Kill Tree completed for root: {name} (PID {pid}) - {reason}")
        return {'type': 'KILL_TREE', 'reason': reason}
    
    def _queue_for_review(self, pid: int, action: Dict, threat_level: int,
                         trust_score: int, name: str, full_path: str):
        """Add to pending review queue"""
        self.pending_reviews.append({
            'pid': pid,
            'name': name,
            'full_path': full_path,
            'action': action,
            'threat_level': threat_level,
            'trust_score': trust_score,
            'queued_time': time.time()
        })
        print(f"[REVIEW NEEDED] {name} (PID {pid}) - {action['reason']}")
        print(f"                Threat: {threat_level}, Trust: {trust_score}")
    
    def check_auto_kill_timers(self):
        """Check if any suspended processes should be auto-killed"""
        now = time.time()
        to_kill = []
        
        for pid, info in list(self.suspended_processes.items()):
            elapsed = now - info['suspend_time']
            if elapsed >= info['auto_kill_seconds']:
                to_kill.append(pid)
        
        for pid in to_kill:
            info = self.suspended_processes.pop(pid)
            print(f"[AUTO-KILL] Timer expired for {info['name']} (PID {pid})")
            self._execute_kill(pid, "Auto-kill timer expired", info['name'])
    
    def get_pending_reviews(self) -> List[Dict]:
        """Get list of processes awaiting user decision"""
        return self.pending_reviews
    
    def get_suspended_processes(self) -> Dict:
        """Get list of currently suspended processes"""
        return self.suspended_processes
    
    def approve_kill(self, pid: int):
        """User approved kill for a pending review"""
        for i, review in enumerate(self.pending_reviews):
            if review['pid'] == pid:
                self._execute_kill(pid, "User approved", review['name'])
                self.pending_reviews.pop(i)
                return True
        return False
    
    def whitelist_and_resume(self, pid: int):
        """User whitelisted process - resume and remember"""
        for i, review in enumerate(self.pending_reviews):
            if review['pid'] == pid:
                self.graph.trust_engine.add_to_whitelist(review['full_path'])
                print(f"[WHITELIST] Added {review['name']} to whitelist - resuming")
                self.pending_reviews.pop(i)
                
                if pid in self.suspended_processes:
                    del self.suspended_processes[pid]
                
                return True
        return False
