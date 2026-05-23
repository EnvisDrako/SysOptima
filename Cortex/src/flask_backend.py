"""
SysOptima Flask Backend
REST API + WebSocket for real-time threat monitoring
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import json
import win32api

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sysoptima_secret_key_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global references (set by main.py)
threat_graph = None
ai_observer = None
response_orchestrator = None
database = None
config = None
memory_scanner = None
quarantine_manager = None
malware_launcher = None

# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

@app.before_request
def check_authentication():
    """Verify Bearer API Token for REST API endpoints"""
    # Exclude UI templates and simple health check from authentication
    if request.path.startswith('/api/') and request.path != '/api/health':
        auth_header = request.headers.get('Authorization')
        expected_token = "SysOptimaHardenedToken2026"
        
        if config:
            expected_token = config.get('api.token', expected_token)
            
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = request.args.get('token')
            
        if not token or token != expected_token:
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid or missing API token'}), 401

# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/health')
def get_health():
    """Get runtime component health for dashboard/operator checks."""
    graph_nodes = None
    command_queue_size = None

    if threat_graph:
        try:
            graph_nodes = threat_graph.G.number_of_nodes()
        except Exception:
            graph_nodes = None

        try:
            command_queue_size = threat_graph.command_queue.qsize()
        except Exception:
            command_queue_size = None

    health = {
        'status': 'degraded' if not threat_graph else 'ok',
        'timestamp': time.time(),
        'components': {
            'graph': threat_graph is not None,
            'ai_observer': ai_observer is not None,
            'response_orchestrator': response_orchestrator is not None,
            'database': database is not None,
            'config': config is not None,
            'memory_scanner': memory_scanner is not None,
            'quarantine_manager': quarantine_manager is not None,
            'malware_launcher': malware_launcher is not None,
        },
        'metrics': {
            'graph_nodes': graph_nodes,
            'command_queue_size': command_queue_size,
        }
    }

    if config:
        health['config'] = {
            'mode': config.get_mode(),
            'dashboard_port': config.get('ui.dashboard_port', 8050),
            'ai_enabled': config.get('ai.enabled', False),
            'memory_scan_enabled': config.get('detection.memory_scan_enabled', False),
            'threat_intel_enabled': config.get('threat_intel.enabled', False),
        }

    if ai_observer:
        health['ai'] = {
            'is_trained': ai_observer.is_trained,
            'is_training': ai_observer.is_training,
            'samples_collected': len(ai_observer.training_data),
        }

    if memory_scanner:
        try:
            health['memory_scanner'] = memory_scanner.get_statistics()
        except Exception as e:
            health['memory_scanner'] = {'error': str(e)}

    return jsonify(health)

@app.route('/api/graph/snapshot')
def get_graph_snapshot():
    """Get current graph state for visualization"""
    if not threat_graph:
        return jsonify({'nodes': [], 'edges': [], 'stats': {}})
    
    G, stats, history, patterns = threat_graph.get_visualization_data()
    
    return jsonify({
        'nodes': serialize_nodes(G),
        'edges': serialize_edges(G),
        'stats': stats,
        'timestamp': time.time()
    })

@app.route('/api/action/approve_kill/<int:pid>', methods=['POST'])
def approve_kill_review(pid):
    """User approved pending kill decision"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    success = response_orchestrator.approve_kill(pid)
    return jsonify({'status': 'success' if success else 'not_found'})

@app.route('/api/process/<int:pid>')
def get_process_details(pid):
    """Get detailed information for specific process"""
    if not threat_graph:
        return jsonify({'error': 'Graph not initialized'}), 500
    
    proc = threat_graph.GetProcess(pid)
    if not proc:
        return jsonify({'error': 'Process not found'}), 404
    
    # Get timeline from database
    timeline = []
    if database:
        events = database.query_events_by_pid(pid)
        timeline = [{
            'timestamp': evt['timestamp'],
            'type': evt['event_type'],
            'description': format_event_description(evt)
        } for evt in events[-20:]]  # Last 20 events
    
    return jsonify({
        'pid': pid,
        'name': proc.get('name', 'unknown'),
        'full_path': proc.get('full_path', ''),
        'threat_level': proc.get('threat_level', 0),
        'trust_score': proc.get('trust_score', 0),
        'is_signed': proc.get('is_signed', True),
        'origin': proc.get('origin', 'unknown'),
        'tags': list(proc.get('tags', [])),
        'mitre': proc.get('mitre', []),
        'ai_anomaly': proc.get('ai_anomaly', False),
        'timeline': timeline,
        'files_modified': proc.get('files_modified', []),
        'registry_keys': proc.get('registry_keys', []),
        'network_connections': proc.get('network_destinations', []),
        'children': proc.get('children_pids', [])
    })

@app.route('/api/stats/summary')
def get_stats_summary():
    """Get overall statistics"""
    if not threat_graph:
        return jsonify({})
    
    return jsonify(threat_graph.stats)

@app.route('/api/history')
def get_history():
    """Get historical events"""
    if not database:
        return jsonify([])
    
    hours = request.args.get('hours', 24, type=int)
    threat_filter = request.args.get('threat', None, type=int)
    
    events = database.query_events(hours=hours, threat_level=threat_filter)
    return jsonify(events)

@app.route('/api/ai/status')
def get_ai_status():
    """Get AI training status"""
    if not ai_observer:
        return jsonify({'enabled': False})
    
    return jsonify({
        'enabled': config.get('ai.enabled', False) if config else False,
        'is_trained': ai_observer.is_trained,
        'is_training': ai_observer.is_training,
        'samples_collected': len(ai_observer.training_data),
        'samples_required': ai_observer.training_samples_required if hasattr(ai_observer, 'training_samples_required') else 1000,
        'baseline_stats': ai_observer.baseline_stats if ai_observer.is_trained else {}
    })

@app.route('/api/pending/reviews')
def get_pending_reviews():
    """Get processes awaiting user decision"""
    if not response_orchestrator:
        return jsonify([])
    
    return jsonify(response_orchestrator.get_pending_reviews())

@app.route('/api/pending/suspended')
def get_suspended_processes():
    """Get currently suspended processes"""
    if not response_orchestrator:
        return jsonify({})
    
    suspended = response_orchestrator.get_suspended_processes()
    
    # Add time remaining
    result = {}
    for pid, info in suspended.items():
        elapsed = time.time() - info['suspend_time']
        remaining = info['auto_kill_seconds'] - elapsed
        result[str(pid)] = {
            'name': info['name'],
            'reason': info['reason'],
            'time_remaining': max(0, int(remaining)),
            'suspend_time': info['suspend_time']
        }
    
    return jsonify(result)

# ============================================================================
# ACTION ENDPOINTS
# ============================================================================

@app.route('/api/action/kill/<int:pid>', methods=['POST'])
def kill_process(pid):
    """Kill a process"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    response_orchestrator._execute_kill(pid, "User requested", f"PID {pid}")
    return jsonify({'status': 'success', 'action': 'kill', 'pid': pid})

@app.route('/api/action/suspend/<int:pid>', methods=['POST'])
def suspend_process(pid):
    """Suspend a process"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    response_orchestrator._execute_suspend(pid, "User requested", f"PID {pid}")
    return jsonify({'status': 'success', 'action': 'suspend', 'pid': pid})

@app.route('/api/action/kill_tree/<int:pid>', methods=['POST'])
def kill_tree(pid):
    """Kill entire process tree"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    response_orchestrator._execute_kill_tree(pid, "User requested", f"PID {pid}")
    return jsonify({'status': 'success', 'action': 'kill_tree', 'pid': pid})

@app.route('/api/action/whitelist/<int:pid>', methods=['POST'])
def whitelist_process(pid):
    """Add process to whitelist"""
    if not threat_graph:
        return jsonify({'error': 'Graph not initialized'}), 500
    
    proc = threat_graph.GetProcess(pid)
    if not proc:
        return jsonify({'error': 'Process not found'}), 404
    
    threat_graph.trust_engine.add_to_whitelist(proc.full_path)
    
    if ai_observer:
        ai_observer.add_feedback(proc, is_anomaly=False)
        
    return jsonify({'status': 'success', 'path': proc.full_path})

@app.route('/api/action/approve_kill/<int:pid>', methods=['POST'])
def approve_kill(pid):
    """Approve kill for pending review"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    success = response_orchestrator.approve_kill(pid)
    return jsonify({'status': 'success' if success else 'not_found'})

@app.route('/api/action/whitelist_resume/<int:pid>', methods=['POST'])
def whitelist_and_resume(pid):
    """Whitelist and resume suspended process"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    proc = None
    if threat_graph:
        proc = threat_graph.GetProcess(pid)
        
    success = response_orchestrator.whitelist_and_resume(pid)
    
    if success and proc and ai_observer:
        ai_observer.add_feedback(proc, is_anomaly=False)
        
    return jsonify({'status': 'success' if success else 'not_found'})

@app.route('/api/action/resume/<int:pid>', methods=['POST'])
def resume_process(pid):
    """Resume suspended process"""
    if not response_orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 500
    
    # Resume all threads of the process
    import win32process
    import win32con
    
    h_snapshot = win32process.CreateToolhelp32Snapshot(win32con.TH32CS_SNAPTHREAD, 0)
    thread_entry = win32process.Thread32First(h_snapshot)
    
    while thread_entry:
        if thread_entry.th32OwnerProcessID == pid:
            try:
                h_thread = win32api.OpenThread(win32con.THREAD_SUSPEND_RESUME, False, thread_entry.th32ThreadID)
                win32process.ResumeThread(h_thread)
                win32api.CloseHandle(h_thread)
            except:
                pass
        thread_entry = win32process.Thread32Next(h_snapshot)
    
    win32api.CloseHandle(h_snapshot)
    
    # Remove from suspended list
    if pid in response_orchestrator.suspended_processes:
        del response_orchestrator.suspended_processes[pid]
    
    return jsonify({'status': 'success', 'action': 'resume', 'pid': pid})

@app.route('/api/config/mode', methods=['GET', 'PUT'])
def manage_mode():
    """Get or change operating mode"""
    if not config:
        return jsonify({'error': 'Config not available'}), 500
    
    if request.method == 'GET':
        return jsonify({'mode': config.get_mode()})
    else:
        new_mode = request.json.get('mode')
        if new_mode in ['PRODUCTION', 'SMART', 'LEARNING']:
            config.set_mode(new_mode)
            return jsonify({'status': 'success', 'mode': new_mode})
        return jsonify({'error': 'Invalid mode'}), 400

# ============================================================================
# AI ENDPOINTS
# ============================================================================

@app.route('/api/ai/train/start', methods=['POST'])
def start_ai_training():
    """Start AI training mode"""
    if not ai_observer:
        return jsonify({'error': 'AI not available'}), 500
    
    ai_observer.start_training()
    if config:
        config.set('ai.training_mode', True)
    
    return jsonify({'status': 'training_started'})

@app.route('/api/ai/train/stop', methods=['POST'])
def stop_ai_training():
    """Finish AI training"""
    if not ai_observer:
        return jsonify({'error': 'AI not available'}), 500
    
    success = ai_observer.finish_training()
    if success and config:
        config.set('ai.enabled', True)
        config.set('ai.training_mode', False)
    
    return jsonify({'status': 'success' if success else 'insufficient_samples'})

# ============================================================================
# CONFIG ENDPOINTS
# ============================================================================

@app.route('/api/memory/statistics')
def get_memory_statistics():
    """Get memory scanner statistics"""
    if not memory_scanner:
        return jsonify({'error': 'Memory scanner not available'}), 500
    
    return jsonify(memory_scanner.get_statistics())

@app.route('/api/memory/scan/<int:pid>', methods=['POST'])
def force_memory_scan(pid):
    """Force scan a specific process"""
    if not memory_scanner:
        return jsonify({'error': 'Memory scanner not available'}), 500
    
    findings = memory_scanner.force_scan_process(pid)
    return jsonify({
        'pid': pid,
        'findings': findings,
        'findings_count': len(findings)
    })

@app.route('/api/quarantine/list')
def list_quarantined_files():
    """Get list of quarantined files"""
    if not quarantine_manager:
        return jsonify({'error': 'Quarantine manager not available'}), 500
    
    include_restored = request.args.get('include_restored', 'false').lower() == 'true'
    files = quarantine_manager.list_quarantined_files(include_restored=include_restored)
    
    return jsonify(files)

@app.route('/api/quarantine/<quarantine_id>')
def get_quarantine_info(quarantine_id):
    """Get detailed quarantine information"""
    if not quarantine_manager:
        return jsonify({'error': 'Quarantine manager not available'}), 500
    
    info = quarantine_manager.get_file_info(quarantine_id)
    if not info:
        return jsonify({'error': 'Quarantined file not found'}), 404
    
    return jsonify(info)

@app.route('/api/quarantine/<quarantine_id>/restore', methods=['POST'])
def restore_quarantined_file(quarantine_id):
    """Restore a quarantined file"""
    if not quarantine_manager:
        return jsonify({'error': 'Quarantine manager not available'}), 500
    
    restore_path = request.json.get('restore_path') if request.json else None
    success = quarantine_manager.restore_file(quarantine_id, restore_path)
    
    return jsonify({
        'success': success,
        'quarantine_id': quarantine_id,
        'restore_path': restore_path
    })

@app.route('/api/quarantine/<quarantine_id>/delete', methods=['DELETE'])
def delete_quarantined_file(quarantine_id):
    """Permanently delete a quarantined file"""
    if not quarantine_manager:
        return jsonify({'error': 'Quarantine manager not available'}), 500
    
    reason = request.json.get('reason', 'Manual deletion') if request.json else 'Manual deletion'
    success = quarantine_manager.delete_quarantined_file(quarantine_id, reason)
    
    return jsonify({
        'success': success,
        'quarantine_id': quarantine_id,
        'reason': reason
    })

@app.route('/api/quarantine/statistics')
def get_quarantine_statistics():
    """Get quarantine statistics"""
    if not quarantine_manager:
        return jsonify({'error': 'Quarantine manager not available'}), 500
    
    return jsonify(quarantine_manager.get_statistics())

@app.route('/api/malware/launch', methods=['POST'])
def launch_malware_sample():
    """Launch malware sample for analysis"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    data = request.json
    if not data or 'sample_path' not in data:
        return jsonify({'error': 'sample_path required'}), 400
    
    execution_id = malware_launcher.launch_malware_sample(
        sample_path=data['sample_path'],
        execution_params=data.get('execution_params', {})
    )
    
    if execution_id:
        return jsonify({
            'success': True,
            'execution_id': execution_id
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to launch sample'
        }), 500

@app.route('/api/malware/launch_quarantined', methods=['POST'])
def launch_quarantined_sample():
    """Launch quarantined malware sample for analysis"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    data = request.json
    if not data or 'quarantine_id' not in data:
        return jsonify({'error': 'quarantine_id required'}), 400
    
    execution_id = malware_launcher.launch_quarantined_sample(
        quarantine_id=data['quarantine_id'],
        execution_params=data.get('execution_params', {})
    )
    
    if execution_id:
        return jsonify({
            'success': True,
            'execution_id': execution_id
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to launch quarantined sample'
        }), 500

@app.route('/api/malware/executions')
def list_malware_executions():
    """Get list of active malware executions"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    executions = malware_launcher.list_active_executions()
    return jsonify(executions)

@app.route('/api/malware/execution/<execution_id>')
def get_execution_status(execution_id):
    """Get execution status"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    status = malware_launcher.get_execution_status(execution_id)
    if not status:
        return jsonify({'error': 'Execution not found'}), 404
    
    return jsonify(status)

@app.route('/api/malware/execution/<execution_id>/stop', methods=['POST'])
def stop_malware_execution(execution_id):
    """Stop a running execution"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    reason = request.json.get('reason', 'Manual stop') if request.json else 'Manual stop'
    success = malware_launcher.stop_execution(execution_id, reason)
    
    return jsonify({
        'success': success,
        'execution_id': execution_id,
        'reason': reason
    })

@app.route('/api/malware/execution/<execution_id>/results')
def get_execution_results(execution_id):
    """Get detailed execution results"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    results = malware_launcher.get_execution_results(execution_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(results)

@app.route('/api/malware/statistics')
def get_malware_statistics():
    """Get malware launcher statistics"""
    if not malware_launcher:
        return jsonify({'error': 'Malware launcher not available'}), 500
    
    return jsonify(malware_launcher.get_statistics())

# ============================================================================
# PROCESS MEMORY DUMP & NETWORK ISOLATION MITIGATIONS
# ============================================================================

def dump_process_memory_win32(pid, output_path):
    """Genuine Win32 process memory minidumper using dbghelp.dll"""
    import ctypes
    import os
    
    PROCESS_ALL_ACCESS = 0x001F0FFF
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MiniDumpWithFullMemory = 2
    
    h_process = None
    h_file = None
    try:
        kernel32 = ctypes.windll.kernel32
        dbghelp = ctypes.windll.dbghelp
        
        # Open process handle
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        
        if not h_process:
            print(f"[DUMP] Failed to open process handle for PID {pid}")
            return False
            
        # Create output directory
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Open destination file using win32 API CreateFileW
        GENERIC_WRITE = 0x40000000
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80
        
        h_file = kernel32.CreateFileW(
            ctypes.c_wchar_p(str(output_path)),
            GENERIC_WRITE,
            0,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
        
        if h_file == -1 or h_file == 0xFFFFFFFFFFFFFFFF:
            print(f"[DUMP] Failed to create dump file: {output_path}")
            kernel32.CloseHandle(h_process)
            return False
            
        # Write minidump
        success = dbghelp.MiniDumpWriteDump(
            h_process,
            pid,
            h_file,
            MiniDumpWithFullMemory,
            None,
            None,
            None
        )
        
        kernel32.CloseHandle(h_file)
        kernel32.CloseHandle(h_process)
        return bool(success)
    except Exception as e:
        print(f"[DUMP] Minidump failed for PID {pid}: {e}")
        return False

@app.route('/api/action/dump_memory/<int:pid>', methods=['POST'])
def dump_memory(pid):
    """Trigger native Win32 process memory dump"""
    import os
    from pathlib import Path
    
    # Save inside static/dumps for direct browser downloading
    dump_dir = Path(app.root_path) / 'static' / 'dumps'
    output_filename = f"minidump_{pid}_{int(time.time())}.dmp"
    output_path = dump_dir / output_filename
    
    success = dump_process_memory_win32(pid, output_path)
    if success:
        return jsonify({
            'status': 'success',
            'download_url': f"/static/dumps/{output_filename}",
            'filename': output_filename
        })
    else:
        return jsonify({'status': 'failed', 'error': 'Failed to create memory dump. Ensure the process is active and running elevated.'}), 500

@app.route('/api/action/isolate_network/<int:pid>', methods=['POST'])
def isolate_network(pid):
    """Isolate process network activity via temporary Windows Defender Firewall outbound block rule"""
    import subprocess
    
    if not threat_graph:
        return jsonify({'error': 'Graph not initialized'}), 500
        
    proc = threat_graph.GetProcess(pid)
    if not proc or not proc.full_path:
        return jsonify({'error': 'Process executable path not resolved'}), 400
        
    # Inject firewall block rule
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name=SysOptima_EDR_Isolate_{pid}",
        "dir=out", "action=block",
        f"program={proc.full_path}", "enable=yes"
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            return jsonify({'status': 'success', 'isolated': True})
        else:
            return jsonify({'status': 'failed', 'error': res.stderr or "Permission Denied. Run as Admin."}), 500
    except Exception as e:
        return jsonify({'status': 'failed', 'error': str(e)}), 500

@app.route('/api/action/restore_network/<int:pid>', methods=['POST'])
def restore_network(pid):
    """Restore network activity by removing custom process firewall block rule"""
    import subprocess
    
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name=SysOptima_EDR_Isolate_{pid}"
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # firewall delete returns non-zero if rule doesn't exist, but that's fine
        return jsonify({'status': 'success', 'isolated': False})
    except Exception as e:
        return jsonify({'status': 'failed', 'error': str(e)}), 500

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    """Get or update configuration"""
    if not config:
        return jsonify({'error': 'Config not available'}), 500
    
    if request.method == 'GET':
        return jsonify(config.config)
    else:
        new_config = request.json
        config.config = new_config
        config.save_config()
        return jsonify({'status': 'updated'})

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('[WEBSOCKET] Client connected')
    emit('connected', {'message': 'Connected to SysOptima'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('[WEBSOCKET] Client disconnected')

@socketio.on('subscribe_graph')
def handle_subscribe_graph():
    """Client wants real-time graph updates"""
    print('[WEBSOCKET] Client subscribed to graph updates')
    # Background thread will push updates

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def serialize_nodes(G):
    """Convert NetworkX graph nodes to JSON"""
    nodes = []
    for node_id in G.nodes():
        node = G.nodes[node_id]
        nodes.append({
            'id': node_id,
            'label': node.get('label', ''),
            'pid': node.get('pid'),
            'threat': node.get('threat', 0),
            'trust': node.get('trust_score', 0),
            'type': node.get('node_type', 'process'),
            'tags': list(node.get('tags', [])),
            'timestamp': node.get('timestamp'),
            'is_signed': node.get('is_signed', True),
            'ai_anomaly': node.get('ai_anomaly', False),
            'origin': node.get('origin', 'Unknown')
        })
    return nodes

def serialize_edges(G):
    """Convert NetworkX graph edges to JSON"""
    edges = []
    for source, target in G.edges():
        edge = G.edges[source, target]
        edges.append({
            'source': source,
            'target': target,
            'relation': edge.get('relation', 'unknown')
        })
    return edges

def format_event_description(event):
    """Format event for timeline display"""
    event_types = {
        1: 'Process Started',
        2: 'Process Ended',
        3: 'File Write',
        4: 'Threat Detected',
        5: 'Registry Set',
        6: 'Memory Alert',
        7: 'Network Connect',
        8: 'Process Killed',
        9: 'Aggregated Activity'
    }
    return event_types.get(event['event_type'], 'Unknown Event')

# ============================================================================
# BACKGROUND THREAD - Push Updates to Clients
# ============================================================================

def push_updates_thread():
    last_update = 0
    update_interval = 5.0  # [PASS] Changed from 2s to 5s
    node_limit = 100       # [PASS] Limit nodes sent
    
    while True:
        try:
            now = time.time()
            if now - last_update < update_interval:
                time.sleep(0.5)
                continue
            
            last_update = now
            
            if not threat_graph:
                time.sleep(1)
                continue
            
            G, stats, history, patterns = threat_graph.get_visualization_data()
            
            # [PASS] CRITICAL: Limit nodes sent
            nodes_data = serialize_nodes(G)
            if len(nodes_data) > node_limit:
                # Sort by threat level (highest first)
                nodes_data.sort(key=lambda n: n.get('threat', 0), reverse=True)
                nodes_data = nodes_data[:node_limit]
            
            # [PASS] Only send if not empty
            if len(nodes_data) > 0:
                socketio.emit('graph_update', {
                    'nodes': nodes_data,
                    'edges': serialize_edges(G),
                    'stats': stats,
                    'timestamp': now,
                    'limited': len(nodes_data) >= node_limit  # [PASS] Tell frontend it's limited
                })
        
        except Exception as e:
            print(f"[WEBSOCKET] Error: {e}")
            time.sleep(2)

# ============================================================================
# INITIALIZATION
# ============================================================================

def init_flask(graph, ai, orchestrator, db, cfg, mem_scanner=None, quarantine=None, malware=None, port=8050):
    """Initialize Flask app with global references"""
    global threat_graph, ai_observer, response_orchestrator, database, config
    global memory_scanner, quarantine_manager, malware_launcher
    
    threat_graph = graph
    ai_observer = ai
    response_orchestrator = orchestrator
    database = db
    config = cfg
    memory_scanner = mem_scanner
    quarantine_manager = quarantine
    malware_launcher = malware
    
    # Start background push thread
    threading.Thread(target=push_updates_thread, daemon=True).start()
    
    print(f"\n{'='*60}")
    print(f"  🌐 FLASK DASHBOARD STARTING")
    print(f"  URL: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
