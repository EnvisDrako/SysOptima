"""
SysOptima Graph Behavior Engine
Handles semantic translation, temporal correlation, and GUID-based Threat Graph tracking.
"""
import os
import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Optional
import networkx as nx

from trust_engine import TrustEngine
from lineage_tracker import LineageTracker
from protocol import (
    EVT_PROCESS_START,
    EVT_FILE_WRITE,
    EVT_REGISTRY_SET,
    EVT_MEMORY_ALERT,
    EVT_NETWORK_CONNECT,
    EVT_THREAT_DETECTED,
    EVT_AGGREGATED,
    CMD_KILL_PID,
    pack_command,
)

# Constants
MAX_NODES = 500

# ================================================================
# SEMANTIC TRANSLATOR
# ================================================================

class SemanticTranslator:
    """Translates raw events into behavioral tags with optimized regex"""
    
    def __init__(self):
        # Pre-compile all regex patterns for speed
        self.persistence_patterns = {
            'run_key': re.compile(r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', re.I),
            'runonce_key': re.compile(r'\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', re.I),
            'startup_folder': re.compile(r'\\Start Menu\\Programs\\Startup', re.I),
            'services': re.compile(r'\\System\\CurrentControlSet\\Services', re.I),
            'winlogon': re.compile(r'\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', re.I),
        }
        
        self.credential_patterns = {
            'lsass': re.compile(r'lsass\.exe', re.I),
            'sam': re.compile(r'\\config\\SAM', re.I),
            'system': re.compile(r'\\config\\SYSTEM', re.I),
            'ntds': re.compile(r'\\NTDS\\ntds\.dit', re.I),
        }
        
        self.defense_evasion_patterns = {
            'amsi': re.compile(r'amsi\.dll', re.I),
            'etw': re.compile(r'\\Microsoft\\Windows\\CurrentVersion\\WINEVT', re.I),
            'defender': re.compile(r'Windows Defender', re.I),
        }
        
        self.discovery_patterns = {
            'whoami': re.compile(r'whoami\.exe', re.I),
            'net': re.compile(r'net\.exe', re.I),
            'ipconfig': re.compile(r'ipconfig\.exe', re.I),
            'systeminfo': re.compile(r'systeminfo\.exe', re.I),
        }
        
        self.lateral_patterns = {
            'psexec': re.compile(r'psexec', re.I),
            'wmic': re.compile(r'wmic\.exe', re.I),
            'rdp': re.compile(r'mstsc\.exe', re.I),
        }
        
        # Exact match cache (no regex needed)
        self.exact_matches = {
            'cmd.exe': 'TAG_SHELL',
            'powershell.exe': 'TAG_POWERSHELL',
            'pwsh.exe': 'TAG_POWERSHELL',
            'regedit.exe': 'TAG_REGISTRY_TOOL',
            'reg.exe': 'TAG_REGISTRY_TOOL',
        }
    
    def translate(self, event: Dict) -> List[str]:
        """Fast semantic translation with pre-compiled patterns"""
        tags = set()
        
        name = event.get('name', '').lower()
        full_path = event.get('full_path', '').lower()
        extra_data = event.get('extra_data', '').lower()
        
        # Exact match lookup (fastest)
        if name in self.exact_matches:
            tags.add(self.exact_matches[name])
        
        # Persistence detection
        for pattern_name, pattern in self.persistence_patterns.items():
            if pattern.search(full_path) or pattern.search(extra_data):
                tags.add(f'TAG_PERSISTENCE_{pattern_name.upper()}')
        
        # Credential access
        for pattern_name, pattern in self.credential_patterns.items():
            if pattern.search(full_path) or pattern.search(name):
                tags.add(f'TAG_CREDENTIAL_{pattern_name.upper()}')
        
        # Defense evasion
        for pattern_name, pattern in self.defense_evasion_patterns.items():
            if pattern.search(full_path):
                tags.add(f'TAG_DEFENSE_EVASION_{pattern_name.upper()}')
        
        # Discovery
        for pattern_name, pattern in self.discovery_patterns.items():
            if pattern.search(name):
                tags.add(f'TAG_DISCOVERY_{pattern_name.upper()}')
        
        # Lateral movement
        for pattern_name, pattern in self.lateral_patterns.items():
            if pattern.search(name) or pattern.search(full_path):
                tags.add(f'TAG_LATERAL_{pattern_name.upper()}')
        
        # Behavioral tags from event data
        if event.get('file_writes', 0) > 100:
            tags.add('TAG_MASS_FILE_WRITE')
        
        if event.get('registry_writes', 0) > 50:
            tags.add('TAG_MASS_REGISTRY_WRITE')
        
        if event.get('network_connections', 0) > 20:
            tags.add('TAG_MASS_NETWORK_ACTIVITY')
        
        if not event.get('is_signed', True):
            tags.add('TAG_UNSIGNED')
        
        if event.get('origin_tag') == 'Internet':
            tags.add('TAG_INTERNET_ORIGIN')
        
        return list(tags)

# ================================================================
# MULTI-WINDOW TEMPORAL BUFFER
# ================================================================

@dataclass
class TemporalEvent:
    timestamp: int
    pid: int
    event_type: int
    tags: List[str]
    threat_level: int

class TemporalBuffer:
    """Three-window temporal correlation for attack pattern detection"""
    
    def __init__(self):
        self.micro_window = deque(maxlen=50)      # 0-500ms
        self.short_window = deque(maxlen=200)     # 0-5s
        self.long_window = deque(maxlen=1000)     # 0-60min
        
        # Attack patterns
        self.attack_patterns = {
            'RANSOMWARE_EXECUTION': {
                'window': 'short',
                'sequence': ['TAG_MASS_FILE_WRITE', 'TAG_PERSISTENCE_', 'TAG_NETWORK'],
                'threat_multiplier': 3.0,
                'mitre': ['T1486', 'T1547']
            },
            'CREDENTIAL_THEFT': {
                'window': 'micro',
                'sequence': ['TAG_CREDENTIAL_LSASS', 'TAG_MASS_FILE_WRITE'],
                'threat_multiplier': 2.5,
                'mitre': ['T1003']
            },
            'LATERAL_MOVEMENT': {
                'window': 'short',
                'sequence': ['TAG_DISCOVERY_', 'TAG_LATERAL_', 'TAG_NETWORK'],
                'threat_multiplier': 2.0,
                'mitre': ['T1021', 'T1570']
            },
            'PERSISTENCE_SETUP': {
                'window': 'short',
                'sequence': ['TAG_REGISTRY_TOOL', 'TAG_PERSISTENCE_', 'TAG_SHELL'],
                'threat_multiplier': 1.8,
                'mitre': ['T1547']
            },
            'PROCESS_INJECTION': {
                'window': 'micro',
                'sequence': ['TAG_MEMORY_RWX', 'TAG_UNSIGNED'],
                'threat_multiplier': 2.5,
                'mitre': ['T1055']
            },
        }
    
    def add_event(self, event: TemporalEvent):
        """Add event to all windows"""
        now = time.time() * 1000
        
        self.micro_window.append(event)
        self.short_window.append(event)
        self.long_window.append(event)
        
        # Prune old events
        self._prune_window(self.micro_window, now, 500)
        self._prune_window(self.short_window, now, 5000)
        self._prune_window(self.long_window, now, 60000)
    
    def _prune_window(self, window, now, max_age_ms):
        """Remove events older than max_age_ms"""
        while window and (now - window[0].timestamp) > max_age_ms:
            window.popleft()
    
    def detect_patterns(self, pid: int) -> List[Dict]:
        """Detect attack patterns in temporal windows"""
        matches = []
        
        for pattern_name, pattern_def in self.attack_patterns.items():
            window_name = pattern_def['window']
            window = self._get_window(window_name)
            
            # Get events for this PID only
            pid_events = [e for e in window if e.pid == pid]
            if len(pid_events) < 2:
                continue
            
            # Check if sequence matches
            if self._matches_sequence(pid_events, pattern_def['sequence']):
                matches.append({
                    'pattern': pattern_name,
                    'multiplier': pattern_def['threat_multiplier'],
                    'mitre': pattern_def['mitre'],
                    'events': len(pid_events)
                })
        
        return matches
    
    def _get_window(self, name: str):
        """Get window by name"""
        if name == 'micro':
            return self.micro_window
        elif name == 'short':
            return self.short_window
        else:
            return self.long_window
    
    def _matches_sequence(self, events: List[TemporalEvent], sequence: List[str]) -> bool:
        """Check if events match the attack sequence"""
        all_tags = []
        for event in events:
            all_tags.extend(event.tags)
        
        # Check if all sequence items are present
        for required in sequence:
            found = False
            for tag in all_tags:
                if required in tag:
                    found = True
                    break
            if not found:
                return False
        
        return True

# ================================================================
# THREAT GRAPH (GUID-BASED & ROLLING PRUNING)
# ================================================================

class ThreatGraph:
    """Enhanced graph with temporal analysis, AI integration, and GUID process mapping"""
    
    def __init__(self, command_queue, ai_observer, database=None, config=None):
        self.G = nx.DiGraph()
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        self.threat_history = deque(maxlen=100)
        self.translator = SemanticTranslator()
        self.temporal_buffer = TemporalBuffer()
        self.ai_observer = ai_observer
        self.command_queue = command_queue
        self.db = database
        self.config = config
        
        # GUID-based process mapping to prevent PID reuse issues
        # active_pids: Dict[int, str] maps a raw PID to its unique active proc node ID
        self.active_pids: Dict[int, str] = {}
        
        # Pattern match history
        self.pattern_matches = []
        self.trust_engine = TrustEngine(config_manager=config)
        self.response_orchestrator = None
    
    def remove_active_pid(self, pid: int):
        """Called when a process terminates, breaking active PID reuse linkage"""
        with self.lock:
            if pid in self.active_pids:
                del self.active_pids[pid]
                
    def add_process(self, pid, ppid, name, origin, threat_level, timestamp, is_signed, full_path, **kwargs):
        """Add process with full semantic analysis, GUID registration, and lineage context features"""
        with self.lock:
            node_id = f"proc_{pid}_{timestamp}"
            
            # Map this PID directly to our brand new unique GUID node ID
            self.active_pids[pid] = node_id

            # Calculate trust score FIRST
            process_info = {
                'name': name,
                'full_path': full_path,
                'is_signed': is_signed,
                'origin': origin
            }
            trust_score = self.trust_engine.calculate_trust_score(process_info)
                
            # Semantic translation
            event_data = {
                'name': name,
                'full_path': full_path,
                'file_writes': kwargs.get('file_writes', 0),
                'registry_writes': kwargs.get('registry_writes', 0),
                'network_connections': kwargs.get('network_connections', 0),
                'is_signed': is_signed,
                'origin_tag': origin,
                'extra_data': kwargs.get('extra_data', ''),
            }
            tags = self.translator.translate(event_data)
            
            # Add to temporal buffer
            temp_event = TemporalEvent(
                timestamp=timestamp,
                pid=pid,
                event_type=EVT_PROCESS_START,
                tags=tags,
                threat_level=threat_level
            )
            self.temporal_buffer.add_event(temp_event)
            
            # Detect patterns
            patterns = self.temporal_buffer.detect_patterns(pid)
            
            # Calculate enhanced threat score
            enhanced_threat = threat_level
            mitre_techniques = []
            
            for pattern in patterns:
                enhanced_threat = int(enhanced_threat * pattern['multiplier'])
                mitre_techniques.extend(pattern['mitre'])
                self.pattern_matches.append({
                    'time': datetime.now(),
                    'pid': pid,
                    'pattern': pattern['pattern'],
                    'name': name
                })
                print(f"[PATTERN] {pattern['pattern']} detected in {name} (PID {pid})")
            
            # Cap at 2
            enhanced_threat = min(enhanced_threat, 2)
            
            # Adjust threat by trust
            adjusted_threat_score = enhanced_threat * 40 - trust_score  # Convert to 0-100 scale
            
            # Reclassify based on adjusted score
            if adjusted_threat_score >= 80:
                final_threat = 2  # Critical
            elif adjusted_threat_score >= 40:
                final_threat = 1  # Suspicious
            else:
                final_threat = 0  # Safe
            
            # Override: High trust (>40) never gets killed even if suspicious behavior
            if trust_score >= 40 and enhanced_threat < 2:
                final_threat = 0  # Trust override
            
            # Override: Masquerading is always critical
            if trust_score <= -80:  # Masquerading detection
                final_threat = 2
            
            enhanced_threat = final_threat

            # Inject node to graph first so that LineageTracker can find ancestors!
            self.G.add_node(
                node_id,
                pid=pid,
                ppid=ppid,
                label=name,
                origin=origin,
                threat=enhanced_threat,
                trust_score=trust_score,
                timestamp=timestamp,
                is_signed=is_signed,
                full_path=full_path,
                tags=tags,
                mitre=mitre_techniques,
                ai_anomaly=False,
                ai_confidence=0.0,
                node_type='process',
                **kwargs
            )
            
            # Link to parent using active PID map GUID or search fallback
            parent_node = self.active_pids.get(ppid)
            if not parent_node:
                parent_node = self._find_latest_node_by_pid(ppid)
            if parent_node:
                self.G.add_edge(parent_node, node_id, relation='spawned')

            # Calculate graph lineage context features
            tree_depth = LineageTracker.calculate_tree_depth(self.G, node_id)
            suspicious_parent = LineageTracker.calculate_suspicious_parent_flag(self.G, node_id)
            lineage_score = LineageTracker.calculate_lineage_threat_score(self.G, node_id)

            # Store computed topological context on the process node
            self.G.nodes[node_id]['tree_depth'] = tree_depth
            self.G.nodes[node_id]['suspicious_parent'] = suspicious_parent
            self.G.nodes[node_id]['lineage_score'] = lineage_score

            # AI anomaly detection using graph topological features
            ai_result = {'is_anomaly': False, 'confidence': 0.0}
            ai_enabled_state = self.config.get('ai.enabled', False) if self.config else False
            if ai_enabled_state and self.ai_observer.is_trained:
                features = {
                    'file_writes': kwargs.get('file_writes', 0),
                    'registry_writes': kwargs.get('registry_writes', 0),
                    'network_connections': kwargs.get('network_connections', 0),
                    'child_count': len(list(self.G.successors(node_id))),
                    'threat_level': enhanced_threat,
                    'is_signed': is_signed,
                    'tags': tags,
                    # Graph topological features
                    'tree_depth': tree_depth,
                    'suspicious_parent': suspicious_parent,
                    'lineage_score': lineage_score
                }
                ai_result = self.ai_observer.detect_anomaly(features)
                
                if ai_result['is_anomaly']:
                    enhanced_threat = 2  # AI flags as critical
                    tags.append('TAG_AI_ANOMALY')
                    self.G.nodes[node_id]['threat'] = 2
                    self.G.nodes[node_id]['tags'] = tags
                    self.G.nodes[node_id]['ai_anomaly'] = True
                    self.G.nodes[node_id]['ai_confidence'] = ai_result['confidence']
                    print(f"[AI] Anomaly detected: {name} (PID {pid}) - Confidence: {ai_result['confidence']:.2f}")
            
            # Add to training data if in learning mode
            # To be safe, we always check training mode on observer
            if self.ai_observer.is_training:
                self.ai_observer.add_training_sample({
                    'file_writes': kwargs.get('file_writes', 0),
                    'registry_writes': kwargs.get('registry_writes', 0),
                    'network_connections': kwargs.get('network_connections', 0),
                    'child_count': len(list(self.G.successors(node_id))),
                    'threat_level': threat_level,
                    'is_signed': is_signed,
                    'tags': tags,
                    'tree_depth': tree_depth,
                    'suspicious_parent': suspicious_parent,
                    'lineage_score': lineage_score
                })
            
            self.update_stats(enhanced_threat, is_signed, ai_result['is_anomaly'])
            
            # Database logging
            if self.db:
                self.db.insert_event({
                    'timestamp': timestamp,
                    'event_type': EVT_PROCESS_START,
                    'pid': pid,
                    'ppid': ppid,
                    'name': name,
                    'full_path': full_path,
                    'threat_level': enhanced_threat,
                    'is_signed': is_signed,
                    'origin': origin,
                    'file_writes': kwargs.get('file_writes', 0),
                    'registry_writes': kwargs.get('registry_writes', 0),
                    'network_connections': kwargs.get('network_connections', 0),
                    'extra_data': str(tags)
                })
                
                for pattern in patterns:
                    self.db.insert_pattern_match({
                        'timestamp': timestamp,
                        'pid': pid,
                        'name': name,
                        'pattern': pattern['pattern'],
                        'multiplier': pattern['multiplier'],
                        'mitre': pattern['mitre'],
                        'event_count': pattern['events']
                    })
                
                # Log threat if dangerous
                if enhanced_threat >= 1:
                    self.db.insert_threat({
                        'timestamp': timestamp,
                        'pid': pid,
                        'name': name,
                        'threat_level': enhanced_threat,
                        'action': 'killed' if enhanced_threat >= 2 else 'monitored',
                        'tags': tags,
                        'mitre': mitre_techniques,
                        'ai_anomaly': ai_result['is_anomaly'],
                        'ai_confidence': ai_result['confidence'],
                        'patterns': [p['pattern'] for p in patterns]
                    })
            
            # Auto-response execution
            if self.response_orchestrator:
                self.response_orchestrator.handle_threat(
                    pid=pid,
                    threat_level=enhanced_threat,
                    trust_score=trust_score,
                    tags=tags,
                    name=name,
                    full_path=full_path
                )
            else:
                if enhanced_threat >= 2:
                    print(f"[AUTO-RESPONSE] Killing Critical Threat: {name} ({pid})")
                    self.send_kill_command(pid)
            
            return node_id
    
    def add_file_write(self, pid, filepath, timestamp):
        """Link file write node to active unique process GUID"""
        with self.lock:
            filename = os.path.basename(filepath)
            file_node = f"file_{filename}_{timestamp}"
            
            self.G.add_node(
                file_node,
                label=filename,
                full_path=filepath,
                timestamp=timestamp,
                node_type='file'
            )
            
            proc_node = self.active_pids.get(pid)
            if not proc_node:
                proc_node = self._find_latest_node_by_pid(pid)
            if proc_node:
                self.G.add_edge(proc_node, file_node, relation='wrote')
    
    def add_memory_alert(self, pid, timestamp):
        """Increase threat score of active process on suspicious RWX detection"""
        with self.lock:
            proc_node = self.active_pids.get(pid)
            if not proc_node:
                proc_node = self._find_latest_node_by_pid(pid)
                
            if proc_node:
                current_threat = self.G.nodes[proc_node].get('threat', 0)
                trust_score = self.G.nodes[proc_node].get('trust_score', 0)
                
                if 'tags' not in self.G.nodes[proc_node]:
                    self.G.nodes[proc_node]['tags'] = []
                if 'TAG_MEMORY_RWX' not in self.G.nodes[proc_node]['tags']:
                    self.G.nodes[proc_node]['tags'].append('TAG_MEMORY_RWX')
                
                if current_threat < 2:
                    new_threat = min(current_threat + 1, 2)
                    self.G.nodes[proc_node]['threat'] = new_threat
                    
                    if self.response_orchestrator:
                        name = self.G.nodes[proc_node].get('label', 'unknown')
                        full_path = self.G.nodes[proc_node].get('full_path', '')
                        tags = self.G.nodes[proc_node].get('tags', [])
                        
                        self.response_orchestrator.handle_threat(
                            pid=pid,
                            threat_level=new_threat,
                            trust_score=trust_score,
                            tags=tags,
                            name=name,
                            full_path=full_path
                        )
    
    def add_registry_set(self, pid, key_name, timestamp):
        """Link registry key set to active process unique GUID"""
        with self.lock:
            reg_node = f"reg_{key_name}_{timestamp}"
            self.G.add_node(
                reg_node,
                label=key_name,
                timestamp=timestamp,
                node_type='registry'
            )
            
            proc_node = self.active_pids.get(pid)
            if not proc_node:
                proc_node = self._find_latest_node_by_pid(pid)
            if proc_node:
                self.G.add_edge(proc_node, reg_node, relation='set')
    
    def add_network_connect(self, pid, dest_ip, timestamp):
        """Link destination network connect node to active process unique GUID"""
        with self.lock:
            net_node = f"net_{dest_ip}_{timestamp}"
            self.G.add_node(
                net_node,
                label=dest_ip,
                timestamp=timestamp,
                node_type='network'
            )
            
            proc_node = self.active_pids.get(pid)
            if not proc_node:
                proc_node = self._find_latest_node_by_pid(pid)
            if proc_node:
                self.G.add_edge(proc_node, net_node, relation='connected')
    
    def send_kill_command(self, pid):
        self.command_queue.put(pack_command(CMD_KILL_PID, pid))
    
    def update_stats(self, threat, is_signed, ai_anomaly):
        self.stats['total_processes'] += 1
        self.stats[f'threat_level_{threat}'] += 1
        if not is_signed:
            self.stats['unsigned_processes'] += 1
        if ai_anomaly:
            self.stats['ai_anomalies'] += 1
        
        self.threat_history.append({
            'time': time.time(),
            'threat': threat,
            'ai_anomaly': ai_anomaly
        })
    
    def _find_latest_node_by_pid(self, pid):
        candidates = [
            (n, self.G.nodes[n]['timestamp']) 
            for n in self.G.nodes() 
            if self.G.nodes[n].get('pid') == pid and self.G.nodes[n].get('node_type') == 'process'
        ]
        if candidates:
            return max(candidates, key=lambda x: x[1])[0]
        return None
    
    def prune_old_nodes(self):
        """Rolling window graph pruning (prevents memory leak, retains active/suspicious context)"""
        with self.lock:
            current_time = int(time.time() * 1000)
            threshold = 600000  # 10 minutes (600,000 ms)
            
            active_nodes = set(self.active_pids.values())
            
            to_remove = []
            for n in self.G.nodes():
                node_data = self.G.nodes[n]
                # Prune if node is older than 10 minutes
                if current_time - node_data.get('timestamp', 0) > threshold:
                    # Do NOT prune active process nodes!
                    if n in active_nodes:
                        continue
                    # Do NOT prune suspicious or critical threat nodes!
                    if node_data.get('threat', 0) >= 1:
                        continue
                    to_remove.append(n)
            
            self.G.remove_nodes_from(to_remove)
            if to_remove:
                print(f"[GRAPH] Pruned {len(to_remove)} inactive safe processes from RAM.")
    
    def get_visualization_data(self):
        with self.lock:
            G_copy = self.G.copy()
            
            # FILTER: Remove safe processes in SMART/PRODUCTION mode
            mode = self.config.get_mode() if self.config else 'SMART'
            
            if mode in ['SMART', 'PRODUCTION']:
                safe_nodes = [
                    n for n in G_copy.nodes() 
                    if G_copy.nodes[n].get('threat', 0) == 0 
                    and G_copy.nodes[n].get('node_type') == 'process'
                ]
                G_copy.remove_nodes_from(safe_nodes)
                print(f"[GRAPH] Filtered {len(safe_nodes)} safe processes from visualization")
            
            # Limit total nodes
            if G_copy.number_of_nodes() > MAX_NODES:
                nodes = sorted(
                    G_copy.nodes(), 
                    key=lambda n: G_copy.nodes[n].get('threat', 0), 
                    reverse=True
                )
                G_copy.remove_nodes_from(nodes[MAX_NODES:])
            
            return G_copy, dict(self.stats), list(self.threat_history), list(self.pattern_matches)    
    
    def query_by_behavior(self, pattern: str) -> List[str]:
        """Find all processes matching behavior pattern"""
        with self.lock:
            matches = []
            for node in self.G.nodes():
                node_data = self.G.nodes[node]
                if node_data.get('node_type') != 'process':
                    continue
                
                tags = node_data.get('tags', [])
                is_signed = node_data.get('is_signed', True)
                
                # Simple pattern matching
                if 'unsigned' in pattern.lower() and not is_signed:
                    if 'credential' in pattern.lower():
                        if any('CREDENTIAL' in tag for tag in tags):
                            matches.append(node)
                    else:
                        matches.append(node)
                elif 'persistence' in pattern.lower():
                    if any('PERSISTENCE' in tag for tag in tags):
                        matches.append(node)
            
            return matches
    
    def get_process_lineage(self, pid: int) -> Dict:
        """Query process lineage by delegating to LineageTracker"""
        with self.lock:
            target = self.active_pids.get(pid)
            if not target:
                target = self._find_latest_node_by_pid(pid)
            if not target:
                return {'ancestors': [], 'descendants': [], 'process': None}
            return LineageTracker.get_process_lineage(self.G, target)
    
    def export_to_json(self, filepath: str):
        """Export graph to JSON for reports"""
        with self.lock:
            import json
            
            nodes_data = []
            for node in self.G.nodes():
                node_dict = {'id': node, **self.G.nodes[node]}
                if 'tags' in node_dict:
                    node_dict['tags'] = ','.join(node_dict['tags'])
                if 'mitre' in node_dict:
                    node_dict['mitre'] = ','.join(node_dict['mitre'])
                nodes_data.append(node_dict)
            
            edges_data = []
            for edge in self.G.edges():
                edges_data.append({
                    'source': edge[0],
                    'target': edge[1],
                    'relation': self.G.edges[edge].get('relation', 'unknown')
                })
            
            data = {
                'nodes': nodes_data,
                'edges': edges_data,
                'stats': dict(self.stats),
                'export_time': time.time() * 1000
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"[GRAPH] Exported to {filepath}")
    
    def GetProcess(self, pid):
        """Get process node data by PID"""
        with self.lock:
            node = self.active_pids.get(pid)
            if not node:
                node = self._find_latest_node_by_pid(pid)
            if node:
                return {
                    'pid': pid,
                    'name': self.G.nodes[node].get('label', 'unknown'),
                    'full_path': self.G.nodes[node].get('full_path', ''),
                    'threat_level': self.G.nodes[node].get('threat', 0),
                    'trust_score': self.G.nodes[node].get('trust_score', 0),
                    'tags': self.G.nodes[node].get('tags', []),
                    'is_signed': self.G.nodes[node].get('is_signed', True),
                }
            return None

    def calculate_graph_metrics(self) -> Dict:
        """Calculate graph analysis metrics using process-only subgraphs"""
        with self.lock:
            if self.G.number_of_nodes() == 0:
                return {}
            
            process_nodes = [n for n in self.G.nodes() if self.G.nodes[n].get('node_type') == 'process']
            if not process_nodes:
                return {}
            
            G_procs = self.G.subgraph(process_nodes)
            
            metrics = {
                'total_processes': len(process_nodes),
                'total_edges': G_procs.number_of_edges(),
            }
            
            if G_procs.number_of_nodes() > 0:
                try:
                    degree_cent = nx.degree_centrality(G_procs)
                    top_spawners = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:5]
                    metrics['top_spawners'] = [
                        {
                            'process': self.G.nodes[n]['label'],
                            'pid': self.G.nodes[n]['pid'],
                            'centrality': score
                        }
                        for n, score in top_spawners
                    ]
                except:
                    pass
            
            return metrics
