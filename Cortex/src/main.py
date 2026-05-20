"""
SYSOPTIMA COMPLETE PYTHON BRAIN - PRODUCTION READY
Includes: Semantic Translation, Temporal Analysis, AI Training, Visualization
No further changes needed - Feature complete!
"""
import sys
import struct
import win32file
import win32pipe
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch
import matplotlib.patches as mpatches
import threading
import queue
import time
from collections import defaultdict, deque
from datetime import datetime
import numpy as np
import os
import json
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
import pickle
from trust_engine import TrustEngine
from response_orchestrator import ResponseOrchestrator
from config_manager import ConfigManager
from memory_scanner import MemoryScanner
from quarantine_manager import QuarantineManager
from malware_launcher import MalwareLauncher

# AI/ML imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    print("[!] scikit-learn not installed. AI features disabled.")
    print("    Install with: pip install scikit-learn")
    ML_AVAILABLE = False

# Database import
try:
    from database import EventDatabase
    DB_AVAILABLE = True
except ImportError:
    print("[!] database.py not found. Database logging disabled.")
    DB_AVAILABLE = False

# ================================================================
# CONFIGURATION
# ================================================================

PIPE_DATA_NAME = r'\\.\pipe\SysOptimaData'
PIPE_CTRL_NAME = r'\\.\pipe\SysOptimaControl'
BINARY_EVENT_SIZE = 1097  # Updated to match new C++ struct

# Event Types (must match C++)
EVT_PROCESS_START = 1
EVT_PROCESS_END = 2
EVT_FILE_WRITE = 3
EVT_THREAT_DETECTED = 4
EVT_REGISTRY_SET = 5
EVT_MEMORY_ALERT = 6
EVT_NETWORK_CONNECT = 7
EVT_PROCESS_KILLED = 8
EVT_AGGREGATED = 9
EVT_BEACON_DETECTED = 10

# Command Types
CMD_KILL_PID = 1
CMD_SUSPEND_PID = 2
CMD_KILL_TREE = 3
CMD_QUARANTINE = 4
CMD_CLEANUP_PERSISTENCE = 5

# Modes
MODE_PRODUCTION = 0  # Only critical threats
MODE_SMART = 1       # Moderate filtering
MODE_LEARNING = 2    # Collect everything for AI training

# Current mode (can be changed via UI)
CURRENT_MODE = MODE_SMART

# Visualization Config
MAX_NODES = 500
THREAT_COLORS = {
    0: '#2ecc71',  # Safe - Green
    1: '#f39c12',  # Suspicious - Orange
    2: '#e74c3c',  # Dangerous - Red
}

# AI Configuration
AI_BASELINE_FILE = "sysoptima_baseline.pkl"
AI_MODEL_FILE = "sysoptima_models.pkl"
AI_TRAINING_SAMPLES = 1000  # Minimum samples before AI activates
AI_ENABLED = False
AI_TRAINING_MODE = False

# ================================================================
# LAYER 3.2: ADVANCED SEMANTIC TRANSLATOR
# ================================================================

from graph_engine import ThreatGraph
from event_filter import EventFilter

class AIObserver:
    """Machine learning for baseline and anomaly detection"""
    
    def __init__(self):
        self.is_trained = False
        self.is_training = False
        self.training_data = []
        self.scaler = StandardScaler()
        self.models = {}
        self.baseline_stats = {}
        
        if ML_AVAILABLE:
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.models['one_class_svm'] = OneClassSVM(
                kernel='rbf',
                gamma='auto',
                nu=0.1
            )
    
    def start_training(self):
        """Begin training mode"""
        global AI_TRAINING_MODE
        AI_TRAINING_MODE = True
        self.is_training = True
        self.training_data = []
        print("[AI] Training mode activated - collecting baseline data...")
    
    def add_training_sample(self, features: Dict):
        """Add sample during training"""
        if not self.is_training:
            return
        
        self.training_data.append(features)
        
        if len(self.training_data) % 100 == 0:
            print(f"[AI] Collected {len(self.training_data)} samples...")
    
    def finish_training(self):
        """Train models on collected data"""
        global AI_TRAINING_MODE, AI_ENABLED
        
        if len(self.training_data) < AI_TRAINING_SAMPLES:
            print(f"[AI] Not enough samples ({len(self.training_data)}/{AI_TRAINING_SAMPLES})")
            return False
        
        print(f"[AI] Training models on {len(self.training_data)} samples...")
        
        # Extract feature vectors
        X = self._extract_feature_matrix(self.training_data)
        
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)
        
        # Train models
        if ML_AVAILABLE:
            self.models['isolation_forest'].fit(X_scaled)
            self.models['one_class_svm'].fit(X_scaled)
        
        # Calculate baseline statistics
        self.baseline_stats = {
            'mean_file_writes': np.mean([d['file_writes'] for d in self.training_data]),
            'mean_registry_writes': np.mean([d['registry_writes'] for d in self.training_data]),
            'mean_network_conns': np.mean([d['network_connections'] for d in self.training_data]),
            'max_threat_seen': max([d['threat_level'] for d in self.training_data]),
        }
        
        self.is_trained = True
        self.is_training = False
        AI_TRAINING_MODE = False
        AI_ENABLED = True
        
        # Save models
        self._save_models()
        
        print("[AI] [PASS] Training complete! AI detection enabled.")
        print(f"[AI] Baseline: {self.baseline_stats}")
        return True
    
    def detect_anomaly(self, features: Dict) -> Dict:
        """Detect if features are anomalous"""
        if not self.is_trained or not ML_AVAILABLE:
            return {'is_anomaly': False, 'confidence': 0.0}
        
        X = self._extract_feature_vector(features)
        X_scaled = self.scaler.transform([X])
        
        # Get predictions from both models
        iso_pred = self.models['isolation_forest'].predict(X_scaled)[0]
        svm_pred = self.models['one_class_svm'].predict(X_scaled)[0]
        
        # -1 = anomaly, 1 = normal
        votes = [iso_pred, svm_pred]
        anomaly_votes = sum(1 for v in votes if v == -1)
        
        is_anomaly = anomaly_votes >= 1  # At least 1 model flags it
        confidence = anomaly_votes / len(votes)
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'iso_forest': iso_pred == -1,
            'svm': svm_pred == -1
        }
    
    def _extract_feature_vector(self, features: Dict) -> np.array:
        """Convert features dict to numpy array, enriched with graph topological context"""
        return np.array([
            features.get('file_writes', 0),
            features.get('registry_writes', 0),
            features.get('network_connections', 0),
            features.get('child_count', 0),
            features.get('threat_level', 0),
            1 if features.get('is_signed', True) else 0,
            len(features.get('tags', [])),
            features.get('tree_depth', 0),
            features.get('suspicious_parent', 0),
            features.get('lineage_score', 0.0)
        ])
    
    def _extract_feature_matrix(self, samples: List[Dict]) -> np.array:
        """Convert list of feature dicts to matrix"""
        return np.array([self._extract_feature_vector(s) for s in samples])
    
    def _save_models(self):
        """Save trained models to disk"""
        data = {
            'scaler': self.scaler,
            'models': self.models,
            'baseline_stats': self.baseline_stats,
            'training_data': self.training_data
        }
        with open(AI_MODEL_FILE, 'wb') as f:
            pickle.dump(data, f)
        print(f"[AI] Models saved to {AI_MODEL_FILE}")
    
    def load_models(self):
        """Load pre-trained models"""
        if not os.path.exists(AI_MODEL_FILE):
            return False
        
        try:
            with open(AI_MODEL_FILE, 'rb') as f:
                data = pickle.load(f)
            
            self.scaler = data['scaler']
            self.models = data['models']
            self.baseline_stats = data['baseline_stats']
            self.is_trained = True
            
            global AI_ENABLED
            AI_ENABLED = True
            
            print("[AI] [PASS] Models loaded successfully!")
            print(f"[AI] Baseline: {self.baseline_stats}")
            return True
        except Exception as e:
            print(f"[AI] Failed to load models: {e}")
            return False

# ================================================================
# PROTOCOL HANDLERS
# ================================================================

def parse_binary_event(data):
    if len(data) < BINARY_EVENT_SIZE:
        return None
    try:
        parts = struct.unpack('=IQIIIBiiii256s512s32s256s', data[:BINARY_EVENT_SIZE])
        return {
            'event_type': parts[0],
            'timestamp': parts[1],
            'pid': parts[2],
            'ppid': parts[3],
            'threat_level': parts[4],
            'is_signed': bool(parts[5]),
            'file_writes': parts[6],
            'registry_writes': parts[7],
            'child_count': parts[8],
            'network_connections': parts[9],
            'name': parts[10].decode('utf-8', errors='ignore').rstrip('\x00'),
            'full_path': parts[11].decode('utf-8', errors='ignore').rstrip('\x00'),
            'origin_tag': parts[12].decode('utf-8', errors='ignore').rstrip('\x00'),
            'extra_data': parts[13].decode('utf-8', errors='ignore').rstrip('\x00'),
        }
    except Exception as e:
        print(f"[!] Parse error: {e}")
        return None

def pipe_reader_thread(graph, event_queue):
    print(f"[*] Connecting to Data Pipe: {PIPE_DATA_NAME}")
    retry_count = 0
    while True:
        try:
            pipe = win32file.CreateFile(PIPE_DATA_NAME, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None)
            print("[+] Connected to Data Stream")
            break
        except Exception as e:
            retry_count += 1
            if retry_count % 5 == 0:
                print(f"[!] Still waiting for C++ (attempt {retry_count})... Is SysOptimaSentinel.exe running?")
            time.sleep(1)
    
    buffer = b''
    while True:
        try:
            hr, data = win32file.ReadFile(pipe, 4096)
            buffer += data
            while len(buffer) >= BINARY_EVENT_SIZE:
                event_data = buffer[:BINARY_EVENT_SIZE]
                buffer = buffer[BINARY_EVENT_SIZE:]
                evt = parse_binary_event(event_data)
                if evt:
                    event_queue.put(evt)
        except win32file.error:
            print("[!] Pipe disconnected")
            break

def pipe_writer_thread(command_queue):
    print(f"[*] Connecting to Control Pipe: {PIPE_CTRL_NAME}")
    retry_count = 0
    while True:
        try:
            pipe = win32file.CreateFile(PIPE_CTRL_NAME, win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
            print("[+] Connected to Control Stream")
            break
        except Exception as e:
            retry_count += 1
            if retry_count % 5 == 0:
                print(f"[!] Still waiting for C++ (attempt {retry_count})...")
            time.sleep(1)
    
    while True:
        try:
            cmd_bytes = command_queue.get()
            win32file.WriteFile(pipe, cmd_bytes)
        except Exception as e:
            print(f"[!] Write error: {e}")
            break

def event_processor_thread(graph, event_queue):
    last_prune = time.time()
    event_filter = EventFilter(window_seconds=2.0)

    while True:
        try:
            event = event_queue.get(timeout=0.1)
            e_type = event['event_type']
            
            if e_type in [EVT_PROCESS_START, EVT_THREAT_DETECTED, EVT_AGGREGATED]:
                # Rename origin_tag to origin to match function signature
                if 'origin_tag' in event:
                    event['origin'] = event.pop('origin_tag')
                graph.add_process(**event)
            elif e_type == EVT_FILE_WRITE:
                if event_filter.should_allow(event['pid'], 'FILE_WRITE', event['full_path']):
                    graph.add_file_write(event['pid'], event['full_path'], event['timestamp'])
            elif e_type == EVT_MEMORY_ALERT:
                # Memory RWX detected - don't instant kill, just add to threat score
                print(f"[ALERT] Suspicious RWX memory in PID {event['pid']} - flagging")
                graph.add_memory_alert(event['pid'], event['timestamp'])
            elif e_type == EVT_REGISTRY_SET:
                if event_filter.should_allow(event['pid'], 'REGISTRY_SET', event['extra_data']):
                    graph.add_registry_set(event['pid'], event['extra_data'], event['timestamp'])
            elif e_type == EVT_NETWORK_CONNECT:
                if event_filter.should_allow(event['pid'], 'NETWORK_CONNECT', event['extra_data']):
                    graph.add_network_connect(event['pid'], event['extra_data'], event['timestamp'])
            elif e_type == EVT_BEACON_DETECTED:
                print(f"[BEACON] C2 beaconing in PID {event['pid']}: {event['extra_data']}")
            elif e_type == EVT_PROCESS_KILLED:
                print(f"[CONFIRM] Process {event['pid']} Killed by Sentinel")
            elif e_type == EVT_PROCESS_END:
                graph.remove_active_pid(event['pid'])
            if time.time() - last_prune > 60:  # Every 60 seconds
                graph.prune_old_nodes()  # <--- THIS FREES THE PYTHON RAM
                last_prune = time.time()
        except queue.Empty:
            continue

# ================================================================
# ADVANCED VISUALIZATION
# ================================================================
def handle_keyboard(ai_observer, orchestrator):
    """
    Keyboard handler for console controls
    Note: This is a fallback for console-only mode
    Flask dashboard provides a better UI for these actions
    """
    import msvcrt
    
    print("\n" + "="*60)
    print("  KEYBOARD CONTROLS (Console Mode)")
    print("="*60)
    print("  [T] - Start/Stop AI Training")
    print("  [M] - Change Mode (Production/Smart/Learning)")
    print("  [S] - Save AI Models")
    print("  [L] - Load AI Models")
    print("  [R] - Show Pending Reviews")
    print("  [P] - Show Suspended Processes")
    print("  [C] - Show Configuration")
    print("  [D] - Database Statistics")
    print("  [Q] - Quit")
    print("="*60 + "\n")
    
    while True:
        try:
            if msvcrt.kbhit():
                key = msvcrt.getch().decode('utf-8').upper()
                
                if key == 'T':
                    # Toggle AI training
                    if ai_observer.is_training:
                        print("\n[AI] Stopping training...")
                        success = ai_observer.finish_training()
                        if success:
                            print("[AI] [PASS] Training complete! AI detection enabled.")
                        else:
                            print("[AI] [WARN] Not enough samples collected.")
                    else:
                        print("\n[AI] Starting training mode...")
                        ai_observer.start_training()
                        print("[AI] Collecting baseline data... (Press T again to finish)")
                
                elif key == 'M':
                    # Change mode
                    print("\n[MODE] Select mode:")
                    print("  1. PRODUCTION (threats only)")
                    print("  2. SMART (balanced)")
                    print("  3. LEARNING (collect all)")
                    mode_choice = input("Enter choice (1-3): ").strip()
                    
                    modes = {
                        '1': 'PRODUCTION',
                        '2': 'SMART',
                        '3': 'LEARNING'
                    }
                    
                    if mode_choice in modes:
                        new_mode = modes[mode_choice]
                        config.set_mode(new_mode)
                        print(f"[MODE] Changed to {new_mode}")
                    else:
                        print("[MODE] Invalid choice")
                
                elif key == 'S':
                    # Save AI models
                    if ai_observer.is_trained:
                        ai_observer._save_models()
                        print("[AI] [PASS] Models saved")
                    else:
                        print("[AI] [WARN] No trained models to save")
                
                elif key == 'L':
                    # Load AI models
                    if ai_observer.load_models():
                        print("[AI] [PASS] Models loaded successfully")
                    else:
                        print("[AI] [FAIL] Failed to load models")
                
                elif key == 'R':
                    # Show pending reviews
                    reviews = orchestrator.get_pending_reviews()
                    if reviews:
                        print(f"\n[REVIEWS] {len(reviews)} processes awaiting review:")
                        for r in reviews:
                            print(f"  • {r['name']} (PID {r['pid']}) - {r['action']['reason']}")
                    else:
                        print("\n[REVIEWS] No pending reviews")
                
                elif key == 'P':
                    # Show suspended processes
                    suspended = orchestrator.get_suspended_processes()
                    if suspended:
                        print(f"\n[SUSPENDED] {len(suspended)} processes:")
                        for pid, info in suspended.items():
                            print(f"  • {info['name']} (PID {pid}) - Auto-kill in {info.get('time_remaining', 0)}s")
                    else:
                        print("\n[SUSPENDED] No suspended processes")
                
                elif key == 'C':
                    # Show configuration
                    print("\n[CONFIG] Current configuration:")
                    print(f"  Mode: {config.get_mode()}")
                    print(f"  AI Enabled: {config.get('ai.enabled', False)}")
                    print(f"  Auto-kill: {config.get('response.auto_kill_enabled', True)}")
                    print(f"  Dashboard Port: {config.get('ui.dashboard_port', 8050)}")
                
                elif key == 'D':
                    # Database statistics
                    if database:
                        stats = database.get_stats()
                        print("\n[DATABASE] Statistics:")
                        print(f"  Total Events: {stats.get('total_events', 0)}")
                        print(f"  Total Threats: {stats.get('total_threats', 0)}")
                        print(f"  AI Anomalies: {stats.get('ai_anomalies', 0)}")
                        print(f"  Patterns Detected: {stats.get('total_patterns', 0)}")
                    else:
                        print("\n[DATABASE] Not available")
                
                elif key == 'Q':
                    print("\n[*] Shutting down...")
                    # import sys
                    # sys.exit(0)
                    import os      # Make sure os is imported
                    os._exit(0)    # <-- ADD THIS (Kills the whole process immediately)
            
            time.sleep(0.1)  # Don't hog CPU
        
        except Exception as e:
            print(f"[!] Keyboard handler error: {e}")
            time.sleep(1)

def auto_kill_timer_thread(orchestrator):
    """Check for expired suspend timers"""
    while True:
        try:
            orchestrator.check_auto_kill_timers()
        except Exception as e:
            print(f"[AUTO-KILL] Error: {e}")
        time.sleep(5)

# ================================================================
# MAIN
# ================================================================

def main():
    """
    SysOptima Complete Initialization
    Starts all components in correct order with proper error handling
    """
    
    # ================================================================
    # HEADER & INITIAL SETUP
    # ================================================================
    
    print("="*70)
    print("  🛡️  SYSOPTIMA EDR - Complete Endpoint Detection & Response")
    print("  Production System with Real-Time Monitoring + Web Dashboard")
    print("="*70)
    print()
    
    # Make these global so they can be accessed by threads
    global config, threat_graph, ai_observer, response_orchestrator, database
    global cmd_queue, evt_queue, memory_scanner, quarantine_manager, malware_launcher
    # ================================================================
    # STEP 1: CONFIGURATION SYSTEM
    # ================================================================
    
    print("📋 STEP 1: Loading Configuration")
    print("-" * 70)
    
    try:
        config = ConfigManager()
        print(f"[✓] Configuration loaded from: {config.config_file}")
        print(f"[✓] Operating Mode: {config.get_mode()}")
        print(f"[✓] AI Enabled: {config.get('ai.enabled', False)}")
        print(f"[✓] Dashboard Port: {config.get('ui.dashboard_port', 8050)}")
    except Exception as e:
        print(f"[✗] CRITICAL: Failed to load configuration: {e}")
        print(f"[!] Creating default configuration...")
        config = ConfigManager()
        config.reset_to_defaults()
    
    print()
    
    # ================================================================
    # STEP 2: DATABASE INITIALIZATION
    # ================================================================
    
    print("📊 STEP 2: Initializing Event Database")
    print("-" * 70)
    
    database = None
    if DB_AVAILABLE:
        try:
            db_path = config.get('database.path', 'sysoptima_events.db')
            print(f"[*] Database path: {db_path}")
            
            database = EventDatabase(db_path)
            
            # Cleanup old data if enabled
            if config.get('database.auto_cleanup_enabled', True):
                retention_days = config.get('database.retention_days', 7)
                print(f"[*] Running cleanup (retention: {retention_days} days)...")
                database.cleanup_old_data(retention_days=retention_days)
            
            # Vacuum if enabled
            if config.get('database.vacuum_on_startup', False):
                print(f"[*] Optimizing database...")
                database.vacuum()
            
            # Show stats
            stats = database.get_stats()
            print(f"[✓] Database ready")
            print(f"    Total events: {stats.get('total_events', 0)}")
            print(f"    Total threats: {stats.get('total_threats', 0)}")
            print(f"    AI anomalies: {stats.get('ai_anomalies', 0)}")
            
        except Exception as e:
            print(f"[✗] Database initialization failed: {e}")
            print(f"[!] Continuing without database (events won't be persisted)")
            database = None
    else:
        print("[!] Database module not available (database.py missing)")
        print("[!] Install required: No action needed, but events won't be saved")
    
    print()
    
    # ================================================================
    # STEP 3: AI OBSERVER
    # ================================================================
    
    print("🤖 STEP 3: Initializing AI Observer")
    print("-" * 70)
    
    try:
        ai_observer = AIObserver()
        
        # Configure from config
        ai_observer.training_samples_required = config.get('ai.training_samples_required', 1000)
        
        # Try to load pre-trained models if AI enabled
        if config.get('ai.enabled', False):
            model_path = config.get('ai.model_path', 'sysoptima_models.pkl')
            
            if os.path.exists(model_path):
                print(f"[*] Found existing AI models at: {model_path}")
                if ai_observer.load_models():
                    print(f"[✓] AI models loaded successfully")
                    print(f"    Baseline samples: {len(ai_observer.training_data)}")
                    print(f"    Status: ACTIVE DETECTION")
                else:
                    print(f"[✗] Failed to load AI models")
                    print(f"[!] Run training mode to create new models")
            else:
                print(f"[!] No pre-trained models found at: {model_path}")
                print(f"[!] AI detection disabled - press 'T' to start training")
        else:
            print(f"[!] AI disabled in configuration")
            print(f"[!] Set ai.enabled=true in config to enable")
        
        if not ML_AVAILABLE:
            print(f"[!] WARNING: scikit-learn not installed")
            print(f"[!] Install: pip install scikit-learn")
            print(f"[!] AI features will be disabled")
    
    except Exception as e:
        print(f"[✗] AI initialization failed: {e}")
        ai_observer = AIObserver()  # Create empty one
    
    print()
    
    # ================================================================
    # STEP 4: THREAT GRAPH
    # ================================================================
    
    print("🕸️  STEP 4: Initializing Threat Graph")
    print("-" * 70)
    
    try:
        cmd_queue = queue.Queue()
        evt_queue = queue.Queue()
        
        threat_graph = ThreatGraph(cmd_queue, ai_observer, database=database)
        
        print(f"[✓] Threat graph initialized")
        print(f"    Trust engine: ACTIVE")
        print(f"    Semantic translator: ACTIVE")
        print(f"    Temporal buffer: ACTIVE")
        print(f"    Database logging: {'ENABLED' if database else 'DISABLED'}")
        
    except Exception as e:
        print(f"[✗] CRITICAL: Threat graph initialization failed: {e}")
        return 1
    
    print()
    
    # ================================================================
    # STEP 5: RESPONSE ORCHESTRATOR
    # ================================================================
    
    print("⚡ STEP 5: Initializing Response Orchestrator")
    print("-" * 70)
    
    try:
        response_orchestrator = ResponseOrchestrator(cmd_queue, threat_graph)
        threat_graph.response_orchestrator = response_orchestrator
        
        print(f"[✓] Response orchestrator initialized")
        print(f"    Graduated response: ENABLED")
        print(f"    Auto-kill: {config.get('response.auto_kill_enabled', True)}")
        print(f"    Auto-suspend: {config.get('response.auto_suspend_enabled', True)}")
        print(f"    Require confirmation: {config.get('response.require_confirmation_for_trusted', True)}")
        
    except Exception as e:
        print(f"[✗] CRITICAL: Response orchestrator initialization failed: {e}")
        return 1
    
    print()
    
    # ================================================================
    # STEP 6: MEMORY SCANNER
    # ================================================================
    
    print("🧠 STEP 6: Initializing Memory Scanner")
    print("-" * 70)
    
    memory_scanner = None
    try:
        memory_scanner = MemoryScanner(
            trust_engine=threat_graph.trust_engine,
            config_manager=config
        )
        
        # Start scanning if enabled
        if config.get('detection.memory_scan_enabled', True):
            memory_scanner.start_scanning()
            print(f"[✓] Memory scanner started")
            print(f"    Scan interval: {config.get('detection.memory_scan_interval_ms', 10000)}ms")
            print(f"    Trust threshold skip: {config.get('trust.trust_threshold_skip_scan', 40)}")
            print(f"    Skip trusted processes: {config.get('trust.skip_memory_scan_for_trusted', True)}")
        else:
            print(f"[!] Memory scanning disabled in configuration")
        
    except Exception as e:
        print(f"[✗] Memory scanner initialization failed: {e}")
        print(f"[!] Continuing without memory scanning")
    
    print()
    
    # ================================================================
    # STEP 7: QUARANTINE MANAGER
    # ================================================================
    
    print("🔒 STEP 7: Initializing Quarantine Manager")
    print("-" * 70)
    
    quarantine_manager = None
    try:
        quarantine_manager = QuarantineManager(
            config_manager=config,
            database=database
        )
        
        # Show quarantine statistics
        stats = quarantine_manager.get_statistics()
        print(f"[✓] Quarantine manager initialized")
        print(f"    Quarantine path: {stats['quarantine_path']}")
        print(f"    Current files: {stats['current_files']}")
        print(f"    Restored files: {stats['restored_files']}")
        print(f"    Total size: {stats['total_size_mb']:.1f} MB")
        print(f"    Retention: {stats['retention_days']} days")
        
        # Connect to response orchestrator
        if response_orchestrator:
            response_orchestrator.quarantine_manager = quarantine_manager
        
    except Exception as e:
        print(f"[✗] Quarantine manager initialization failed: {e}")
        print(f"[!] Continuing without quarantine capability")
    
    print()
    
    # ================================================================
    # STEP 8: MALWARE LAUNCHER
    # ================================================================
    
    print("[START] STEP 8: Initializing Malware Launcher")
    print("-" * 70)
    
    malware_launcher = None
    if config.get('malware_launcher.enabled', False):
        try:
            if not quarantine_manager:
                print(f"[!] Quarantine manager required for malware launcher")
            else:
                malware_launcher = MalwareLauncher(
                    config_manager=config,
                    quarantine_manager=quarantine_manager,
                    database=database
                )
                
                # Show launcher statistics
                stats = malware_launcher.get_statistics()
                print(f"[✓] Malware launcher initialized")
                print(f"    Sandbox path: {stats['sandbox_path']}")
                print(f"    Max concurrent: {stats['max_concurrent']}")
                print(f"    Execution timeout: {stats['execution_timeout']}s")
                print(f"    Network isolation: {stats['network_isolation']}")
                print(f"    Filesystem isolation: {stats['filesystem_isolation']}")
        
        except Exception as e:
            print(f"[✗] Malware launcher initialization failed: {e}")
            print(f"[!] Continuing without malware launcher")
    else:
        print(f"[!] Malware launcher disabled in configuration")
        print(f"[!] Set malware_launcher.enabled=true to enable")
    
    print()
    
    # ================================================================
    # STEP 9: THREAT INTELLIGENCE (OPTIONAL)
    # ================================================================
    
    print("[FIND] STEP 9: Initializing Threat Intelligence")
    print("-" * 70)
    
    threat_intel = None
    if config.get('threat_intel.enabled', False):
        try:
            from threat_intel import ThreatIntelUpdater
            
            threat_intel = ThreatIntelUpdater(control_queue=cmd_queue)
            
            # Set API key if configured
            api_key = config.get('threat_intel.abuseipdb_api_key', '')
            if api_key:
                threat_intel.set_abuseipdb_key(api_key)
                print(f"[✓] AbuseIPDB API key configured")
            else:
                print(f"[!] AbuseIPDB API key not set")
                print(f"[!] Get free key at: https://www.abuseipdb.com/register")
            
            # Start auto-updates if enabled
            if config.get('threat_intel.auto_update_enabled', False):
                interval = config.get('threat_intel.update_interval_hours', 24)
                threat_intel.start_auto_update(interval_hours=interval)
                print(f"[✓] Auto-update enabled (every {interval} hours)")
            else:
                print(f"[!] Auto-update disabled")
            
            print(f"[✓] Threat intelligence ready")
            
        except ImportError:
            print(f"[!] threat_intel.py not found")
            print(f"[!] Threat feed updates disabled")
        except Exception as e:
            print(f"[✗] Threat intelligence initialization failed: {e}")
    else:
        print(f"[!] Threat intelligence disabled in configuration")
        print(f"[!] Set threat_intel.enabled=true to enable")
    
    print()
    
    # ================================================================
    # STEP 10: WORKER THREADS
    # ================================================================
    
    print("🔧 STEP 10: Starting Worker Threads")
    print("-" * 70)
    
    try:
        # Named pipe communication threads
        print("[*] Starting named pipe threads...")
        threading.Thread(
            target=pipe_reader_thread, 
            args=(threat_graph, evt_queue), 
            daemon=True,
            name="PipeReader"
        ).start()
        print("    [✓] Pipe reader thread started")
        
        threading.Thread(
            target=pipe_writer_thread, 
            args=(cmd_queue,), 
            daemon=True,
            name="PipeWriter"
        ).start()
        print("    [✓] Pipe writer thread started")
        
        # Event processor thread
        print("[*] Starting event processor...")
        threading.Thread(
            target=event_processor_thread, 
            args=(threat_graph, evt_queue), 
            daemon=True,
            name="EventProcessor"
        ).start()
        print("    [✓] Event processor thread started")
        
        # Keyboard handler thread
        print("[*] Starting keyboard handler...")
        threading.Thread(
            target=handle_keyboard, 
            args=(ai_observer, response_orchestrator), 
            daemon=True,
            name="KeyboardHandler"
        ).start()
        print("    [✓] Keyboard handler thread started")
        
        # Auto-kill timer thread
        print("[*] Starting auto-kill timer...")
        def auto_kill_timer_thread(orchestrator):  # ⬅️ ADD PARAMETER
            """Check for expired suspend timers"""
            while True:
                try:
                    orchestrator.check_auto_kill_timers()  # ⬅️ USE PARAMETER
                except Exception as e:
                    print(f"[!] Auto-kill timer error: {e}")
                time.sleep(5)  # Check every 5 seconds
        
        threading.Thread(
            target=auto_kill_timer_thread, 
            args=(response_orchestrator,),  # ⬅️ PASS ARGUMENT
            daemon=True,
            name="AutoKillTimer"
        ).start()
        print("    [✓] Auto-kill timer thread started")
        
        print(f"[✓] All worker threads started")
        
    except Exception as e:
        print(f"[✗] CRITICAL: Worker thread initialization failed: {e}")
        return 1
    
    print()
    
    # ================================================================
    # STEP 11: WEB DASHBOARD
    # ================================================================
    
    print("="*70)
    print("  🌐 LAUNCHING WEB DASHBOARD")
    print("="*70)
    print()
    
    dashboard_port = config.get('ui.dashboard_port', 8050)
    
    print(f"Dashboard URL: http://localhost:{dashboard_port}")
    print()
    print("Console Controls:")
    print("  [T] - Start/Stop AI training")
    print("  [M] - Change Mode")
    print("  [S] - Save AI models")
    print("  [L] - Load AI models")
    print("  [R] - Show pending reviews")
    print("  [P] - Show suspended processes")
    print("  [C] - Show configuration")
    print("  [Q] - Quit")
    print()
    print("="*70)
    print()
    
    try:
        from flask_backend import init_flask
        
        # This call BLOCKS (runs forever)
        # Flask will handle all HTTP/WebSocket requests
        init_flask(
            graph=threat_graph,
            ai=ai_observer,
            orchestrator=response_orchestrator,
            db=database,
            cfg=config,
            mem_scanner=memory_scanner,
            quarantine=quarantine_manager,
            malware=malware_launcher,
            port=dashboard_port
        )
        
    except ImportError as e:
        print(f"[✗] Flask backend import error: {e}")
        print()
        print("="*70)
        print("  [WARN]  FLASK NOT AVAILABLE - CONSOLE MODE ONLY")
        print("="*70)
        print()
        print("To install Flask:")
        print("  pip install flask flask-socketio eventlet")
        print()
        print("Running in console-only mode...")
        print("Press Ctrl+C to exit")
        print()
        
        # Fallback: just keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            return 0
    
    except Exception as e:
        print(f"[✗] Dashboard error: {e}")
        print()
        print("Falling back to console mode...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            return 0
    
    return 0


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)