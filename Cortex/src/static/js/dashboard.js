/**
 * dashboard.js - Main Entry Point (Refactored to ES6 Module)
 * Orchestrates API, WebSocket, Graph, and UI interactions
 */

import * as api from './api.js';
import * as graph from './graph.js';
import * as socketHandler from './socket.js';

let graphFrozen = false;
let selectedNodePid = null;
let filterThreatsOnly = false;
const isolatedPids = new Set();

document.addEventListener('DOMContentLoaded', () => {
    console.log('[Dashboard] Initializing Modules...');
    
    // Init Graph
    graph.initGraph('graph-container', 
        (pid) => {
            selectedNodePid = pid;
            window.showProcessDetails(pid);
        },
        () => {
            selectedNodePid = null;
        }
    );
    
    // Init Socket
    socketHandler.initSocket(
        () => {
            document.getElementById('connection-status').textContent = '● CONNECTED';
            document.getElementById('connection-status').classList.add('active');
        },
        () => {
            document.getElementById('connection-status').textContent = '● DISCONNECTED';
            document.getElementById('connection-status').classList.remove('active');
        },
        (data) => {
            if (!graphFrozen) {
                graph.updateGraph(data, filterThreatsOnly);
                updateStats(data.stats);
            }
        },
        (reviews) => {
            if (!graphFrozen) updatePendingReviews(reviews);
        }
    );
    
    setupEventHandlers();
    loadInitialData();
});

// ============================================================================
// UI UPDATES
// ============================================================================

function updateStats(stats) {
    if(!stats) return;
    document.getElementById('stat-total').textContent = stats.total_processes || 0;
    document.getElementById('stat-safe').textContent = stats.threat_level_0 || 0;
    document.getElementById('stat-suspicious').textContent = stats.threat_level_1 || 0;
    document.getElementById('stat-critical').textContent = stats.threat_level_2 || 0;
    document.getElementById('stat-unsigned').textContent = stats.unsigned_processes || 0;
    document.getElementById('stat-ai').textContent = stats.ai_anomalies || 0;
}

function updateAIStatus(data) {
    const statusDiv = document.querySelector('.ai-status');
    const progressFill = document.getElementById('ai-progress-fill');
    const progressText = document.getElementById('ai-progress-text');
    const trainBtn = document.getElementById('btn-ai-train');
    
    if (data.is_trained) {
        statusDiv.textContent = '✅ TRAINED & ACTIVE';
        statusDiv.style.color = '#10b981';
        progressFill.style.width = '100%';
        progressText.textContent = `${data.samples_collected} samples`;
        trainBtn.textContent = 'Retrain';
    } else if (data.is_training) {
        statusDiv.textContent = '⏳ TRAINING IN PROGRESS';
        statusDiv.style.color = '#f59e0b';
        const progress = (data.samples_collected / data.samples_required) * 100;
        progressFill.style.width = `${progress}%`;
        progressText.textContent = `${data.samples_collected} / ${data.samples_required} samples`;
        trainBtn.textContent = 'Stop Training';
    } else {
        statusDiv.textContent = '❌ NOT TRAINED';
        statusDiv.style.color = '#ef4444';
        progressFill.style.width = '0%';
        progressText.textContent = 'Press button to start training';
        trainBtn.textContent = 'Start Training';
    }
}

function updatePendingReviews(reviews) {
    const container = document.getElementById('reviews-list');
    if (!reviews || reviews.length === 0) {
        container.innerHTML = '<div class="empty-state">No pending reviews</div>';
        return;
    }
    
    container.innerHTML = '';
    reviews.forEach(review => {
        const item = document.createElement('div');
        item.className = 'review-item';
        item.innerHTML = `
            <strong>${review.name}</strong> (PID ${review.pid})<br>
            <small>Threat: ${review.threat_level} | Trust: ${review.trust_score}</small><br>
            <small>${review.action.reason}</small><br>
            <button onclick="approveKill(${review.pid})" class="btn btn-danger" style="margin-top: 0.5rem; padding: 0.3rem 0.6rem; font-size: 0.8rem;">Kill</button>
            <button onclick="whitelistReview(${review.pid})" class="btn btn-success" style="margin-top: 0.5rem; padding: 0.3rem 0.6rem; font-size: 0.8rem;">Whitelist</button>
        `;
        container.appendChild(item);
    });
}

function updateSuspendedProcesses(suspended) {
    const container = document.getElementById('suspended-list');
    if (!suspended || Object.keys(suspended).length === 0) {
        container.innerHTML = '<div class="empty-state">No suspended processes</div>';
        return;
    }
    
    container.innerHTML = '';
    for (const [pid, info] of Object.entries(suspended)) {
        const item = document.createElement('div');
        item.className = 'suspended-item';
        item.innerHTML = `
            <strong>${info.name}</strong> (PID ${pid})<br>
            <small>Auto-kill in: ${info.time_remaining}s</small><br>
            <small>${info.reason}</small>
        `;
        container.appendChild(item);
    }
}

// ============================================================================
// DATA LOADERS
// ============================================================================

async function loadInitialData() {
    const graphData = await api.fetchGraphSnapshot();
    graph.updateGraph(graphData, filterThreatsOnly);
    updateStats(graphData.stats);
    
    const aiData = await api.fetchAIStatus();
    updateAIStatus(aiData);
    
    const reviewsData = await api.fetchPendingReviews();
    updatePendingReviews(reviewsData);
    
    const suspendedData = await api.fetchSuspendedProcesses();
    updateSuspendedProcesses(suspendedData);
}

window.loadTaskGrid = async function() {
    const data = await api.fetchGraphSnapshot();
    const tbody = document.querySelector('#task-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data.nodes || data.nodes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No active processes monitored</td></tr>';
        return;
    }
    
    const processNodes = data.nodes.filter(n => n.type === 'process').sort((a, b) => a.pid - b.pid);
    processNodes.forEach(node => {
        const tr = document.createElement('tr');
        const badgeClass = node.threat === 2 ? 'critical' : node.threat === 1 ? 'suspended' : 'active';
        const badgeLabel = node.threat === 2 ? 'CRITICAL' : node.threat === 1 ? 'SUSPICIOUS' : 'SAFE';
        
        tr.innerHTML = `
            <td><strong>${node.pid}</strong></td>
            <td><span class="badge-status ${badgeClass}" style="margin-right: 0.5rem;">●</span> <strong>${node.label}</strong></td>
            <td><span class="badge-status ${badgeClass}">${badgeLabel}</span></td>
            <td><strong>${node.trust}</strong></td>
            <td>${node.is_signed ? '✓ Yes' : '✗ No'}</td>
            <td>${node.origin}</td>
            <td style="font-family: monospace; font-size: 0.75rem; word-break: break-all;">${node.full_path || '-'}</td>
            <td><button class="btn btn-primary" onclick="showProcessDetails(${node.pid})" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; border-radius: 4px;">🔍 Inspect</button></td>
        `;
        tbody.appendChild(tr);
    });
};

window.loadQuarantineGrid = async function() {
    const response = await fetch('/api/quarantine/list');
    const data = await response.json();
    const tbody = document.querySelector('#quarantine-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No files isolated</td></tr>';
        return;
    }
    
    data.forEach(item => {
        const tr = document.createElement('tr');
        const qTime = new Date(item.quarantine_time * 1000).toLocaleString();
        const sizeKB = (item.file_size / 1024).toFixed(1);
        
        tr.innerHTML = `
            <td><code>${item.quarantine_id}</code></td>
            <td><strong>${item.original_name}</strong></td>
            <td style="font-family: monospace; font-size: 0.75rem;">${item.original_path}</td>
            <td><span class="badge-status critical">${item.threat_reason || 'Threat'}</span></td>
            <td><strong>${sizeKB} KB</strong></td>
            <td>${qTime}</td>
            <td><span class="badge-status ${item.is_restored ? 'active' : 'critical'}">${item.is_restored ? 'RESTORED' : 'ISOLATED'}</span></td>
            <td>
                ${!item.is_restored ? `<button class="btn btn-success" onclick="restoreQuarantinedFile('${item.quarantine_id}')">✅ Restore</button>` : ''}
                <button class="btn btn-danger" onclick="deleteQuarantinedFile('${item.quarantine_id}')">❌ Purge</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
};

window.loadDetonationGrid = async function() {
    const response = await fetch('/api/malware/executions');
    const data = await response.json();
    const tbody = document.querySelector('#detonation-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data || Object.keys(data).length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No executions recorded</td></tr>';
        return;
    }
    
    for (const [execId, info] of Object.entries(data)) {
        const tr = document.createElement('tr');
        const badgeClass = info.status === 'COMPLETED' ? 'active' : info.status === 'RUNNING' ? 'suspended' : 'critical';
        const duration = info.duration ? `${info.duration.toFixed(2)}s` : 'Active...';
        
        tr.innerHTML = `
            <td><code>${execId}</code></td>
            <td><strong>${info.sample_name || 'sample'}</strong></td>
            <td><span class="badge-status ${badgeClass}">${info.status}</span></td>
            <td>${duration}</td>
            <td><span class="badge-status critical" style="font-size: 0.75rem;">${(info.behavior_tags || []).join(', ') || 'No hostile signs'}</span></td>
            <td>
                ${info.status === 'RUNNING' ? `<button class="btn btn-danger" onclick="stopDetonation('${execId}')">⏹️ Terminate</button>` : ''}
                <button class="btn btn-info" onclick="viewDetonationResults('${execId}')">📊 Report</button>
            </td>
        `;
        tbody.appendChild(tr);
    }
};

// ============================================================================
// MODAL & GLOBAL ACTIONS
// ============================================================================

window.showProcessDetails = async function(pid) {
    const data = await api.fetchProcessDetails(pid);
    if (data.error) return alert('Process not found');
    
    selectedNodePid = pid;
    window.switchModalTab('overview');
    
    document.getElementById('modal-title').textContent = data.name;
    document.getElementById('detail-pid').textContent = pid;
    document.getElementById('detail-name').textContent = data.name;
    document.getElementById('detail-path').textContent = data.full_path;
    
    const isoBtn = document.getElementById('btn-isolate-network');
    if (isoBtn) isoBtn.textContent = isolatedPids.has(pid) ? '🔓 Restore Network' : '🔒 Isolate Network';
    
    const getBadge = (lvl) => `<span style="color: ${['#10b981', '#f59e0b', '#ef4444'][lvl]}; font-weight: bold;">${['SAFE', 'SUSPICIOUS', 'CRITICAL'][lvl]}</span>`;
    document.getElementById('detail-threat').innerHTML = getBadge(data.threat_level);
    document.getElementById('detail-trust').innerHTML = `<span style="color: ${data.trust_score>=40?'#10b981':data.trust_score>=0?'#f59e0b':'#ef4444'}; font-weight: bold;">${data.trust_score}</span>`;
    document.getElementById('detail-signed').textContent = data.is_signed ? '✓ Yes' : '✗ No';
    document.getElementById('detail-origin').textContent = data.origin;
    
    const tagsContainer = document.getElementById('detail-tags');
    tagsContainer.innerHTML = '';
    data.tags.forEach(tag => {
        const el = document.createElement('span');
        el.className = 'tag'; el.textContent = tag;
        tagsContainer.appendChild(el);
    });
    
    const populateList = (id, badgeId, arr, emptyMsg) => {
        const ul = document.getElementById(id);
        ul.innerHTML = '';
        document.getElementById(badgeId).textContent = arr.length;
        if(arr.length === 0) ul.innerHTML = `<li class="empty-state">${emptyMsg}</li>`;
        else arr.forEach(item => { const li = document.createElement('li'); li.textContent = item; ul.appendChild(li); });
    };
    populateList('detail-files', 'modal-badge-files', data.files_modified || [], 'No files written');
    populateList('detail-network', 'modal-badge-network', data.network_connections || [], 'No active connections');
    populateList('detail-registry', 'modal-badge-registry', data.registry_keys || [], 'No registry transactions');
    
    const tlContainer = document.getElementById('detail-timeline');
    tlContainer.innerHTML = '';
    data.timeline.forEach(ev => {
        const el = document.createElement('div');
        el.className = 'timeline-event';
        el.textContent = `${new Date(ev.timestamp).toLocaleTimeString()} - ${ev.description}`;
        tlContainer.appendChild(el);
    });
    
    document.getElementById('detail-modal').classList.remove('hidden');
};

window.closeModal = function() {
    document.getElementById('detail-modal').classList.add('hidden');
};

window.switchConsoleTab = function(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`tab-btn-${tabId}`).classList.add('active');
    document.querySelectorAll('.console-tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(`tab-content-${tabId}`).classList.add('active');
    
    if (tabId === 'task-manager') window.loadTaskGrid();
    else if (tabId === 'quarantine-vault') window.loadQuarantineGrid();
    else if (tabId === 'detonation-lab') window.loadDetonationGrid();
};

window.switchModalTab = function(tabId) {
    document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`modal-tab-btn-${tabId}`).classList.add('active');
    document.querySelectorAll('.modal-tab-content-pane').forEach(pane => pane.classList.remove('active'));
    document.getElementById(`modal-content-${tabId}`).classList.add('active');
};

// Map actions to global window object
window.killProcess = async () => { if(selectedNodePid && confirm(`Kill PID ${selectedNodePid}?`)) { await api.killProcess(selectedNodePid); window.closeModal(); } };
window.killTree = async () => { if(selectedNodePid && confirm(`Kill Tree PID ${selectedNodePid}?`)) { await api.killTree(selectedNodePid); window.closeModal(); } };
window.suspendProcess = async () => { if(selectedNodePid) { await api.suspendProcess(selectedNodePid); window.closeModal(); } };
window.whitelistProcess = async () => { if(selectedNodePid && confirm(`Whitelist PID ${selectedNodePid}?`)) { await api.whitelistProcess(selectedNodePid); window.closeModal(); } };
window.approveKill = async (pid) => { await api.approveKill(pid); loadInitialData(); };
window.whitelistReview = async (pid) => { await api.whitelistReview(pid); loadInitialData(); };
window.changeGraphLayout = () => { graph.changeLayout(document.getElementById('select-layout').value); };
window.filterGraphNodes = () => { graph.filterNodes(document.getElementById('node-search').value.toLowerCase().trim()); };
window.filterTaskTable = () => {
    const q = document.getElementById('task-search').value.toLowerCase().trim();
    document.querySelectorAll('#task-grid-table tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
};

function setupEventHandlers() {
    document.getElementById('btn-freeze').addEventListener('click', function() {
        graphFrozen = !graphFrozen;
        this.textContent = graphFrozen ? '▶️' : '❄️';
    });
    document.getElementById('btn-reset-zoom').addEventListener('click', () => graph.fitGraph());
    document.getElementById('btn-filter-threats').addEventListener('click', function() {
        filterThreatsOnly = !filterThreatsOnly;
        this.style.background = filterThreatsOnly ? '#ef4444' : '';
    });
    document.getElementById('btn-ai-train').addEventListener('click', async function() {
        const start = this.textContent === 'Start Training';
        await api.toggleAI(start);
        this.textContent = start ? 'Stop Training' : 'Start Training';
    });
    document.addEventListener('keydown', (e) => { if (e.key === 'f' || e.key === 'F') document.getElementById('btn-freeze').click(); });
}

setInterval(async () => {
    if (!graphFrozen) {
        updatePendingReviews(await api.fetchPendingReviews());
        updateSuspendedProcesses(await api.fetchSuspendedProcesses());
        updateAIStatus(await api.fetchAIStatus());
        
        const activeTab = document.querySelector('.console-tab-content.active');
        if (activeTab) {
            if (activeTab.id === 'tab-content-task-manager') window.loadTaskGrid();
            else if (activeTab.id === 'tab-content-quarantine-vault') window.loadQuarantineGrid();
            else if (activeTab.id === 'tab-content-detonation-lab') window.loadDetonationGrid();
        }
    }
}, 5000);

// Global Mitigation exports
window.toggleNetworkIsolation = async function() {
    if (!selectedNodePid) return;
    const isIso = isolatedPids.has(selectedNodePid);
    const btn = document.getElementById('btn-isolate-network');
    btn.textContent = '⏳ Processing...';
    try {
        const res = await fetch(isIso ? `/api/action/restore_network/${selectedNodePid}` : `/api/action/isolate_network/${selectedNodePid}`, { method: 'POST' });
        const data = await res.json();
        if(data.status === 'success') {
            if(isIso) isolatedPids.delete(selectedNodePid); else isolatedPids.add(selectedNodePid);
            btn.textContent = isIso ? '🔒 Isolate Network' : '🔓 Restore Network';
            alert(`Network ${isIso ? 'restored' : 'isolated'} successfully.`);
        } else { alert('Failed: ' + data.error); btn.textContent = isIso ? '🔓 Restore Network' : '🔒 Isolate Network'; }
    } catch(e) { alert('Error: ' + e); btn.textContent = isIso ? '🔓 Restore Network' : '🔒 Isolate Network'; }
};

window.dumpProcessMemory = async function() {
    if (!selectedNodePid) return;
    if (!confirm(`Dump memory for PID ${selectedNodePid}?`)) return;
    try {
        const res = await fetch(`/api/action/dump_memory/${selectedNodePid}`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') { alert('Dump success!'); window.open(data.download_url, '_blank'); }
        else alert('Dump failed: ' + data.error);
    } catch(e) { alert('Error: ' + e); }
};

// Global Quarantine/Sandbox exports
window.restoreQuarantinedFile = async (id) => {
    if(confirm('Restore file?')) {
        const r = await fetch(`/api/quarantine/${id}/restore`, {method: 'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
        if ((await r.json()).success) window.loadQuarantineGrid(); else alert('Failed');
    }
};
window.deleteQuarantinedFile = async (id) => {
    if(confirm('Shred file?')) {
        const r = await fetch(`/api/quarantine/${id}/delete`, {method: 'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({reason:'Operator requested'})});
        if ((await r.json()).success) window.loadQuarantineGrid(); else alert('Failed');
    }
};
window.launchSandboxSample = async () => {
    const p = document.getElementById('sandbox-sample-path').value.trim();
    if(!p) return alert('Path required');
    const r = await fetch('/api/malware/launch', {method: 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({sample_path: p, execution_params: {timeout: 10, use_sandbox: document.getElementById('sandbox-isolation').value === 'sandbox'}})});
    if((await r.json()).success) window.loadDetonationGrid(); else alert('Failed');
};
window.stopDetonation = async (id) => {
    if(confirm('Stop sandbox?')) {
        await fetch(`/api/malware/execution/${id}/stop`, {method: 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({reason: 'Operator requested'})});
        window.loadDetonationGrid();
    }
};
window.viewDetonationResults = async (id) => {
    try {
        const r = await fetch(`/api/malware/execution/${id}/results`);
        const d = await r.json();
        alert(`Status: ${d.status}\nDuration: ${d.duration}s\nTags: ${d.behavior_tags}`);
    } catch(e) { alert('Error: ' + e); }
};