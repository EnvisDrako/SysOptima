/**
 * SysOptima Dashboard - Frontend Logic
 * Handles Cytoscape.js graph, WebSocket updates, and user interactions
 */

let cy = null;
let socket = null;
let graphFrozen = false;
let selectedNodePid = null;
let filterThreatsOnly = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('[Dashboard] Initializing...');
    initializeGraph();
    connectWebSocket();
    setupEventHandlers();
    loadInitialData();
});

// ============================================================================
// CYTOSCAPE GRAPH INITIALIZATION
// ============================================================================

function initializeGraph() {
    cy = cytoscape({
        container: document.getElementById('graph-container'),
        
        style: [
            // Base node style
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'font-size': '10px',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#e2e8f0',
                    'text-outline-width': 2,
                    'text-outline-color': '#000',
                    'background-opacity': 0.9,
                    'transition-property': 'background-color, border-color, opacity',
                    'transition-duration': '0.5s'
                }
            },
            
            // Safe processes (green)
            {
                selector: 'node[threat = 0]',
                style: {
                    'background-color': '#2ecc71',
                    'width': 30,
                    'height': 30,
                    'opacity': 0.7
                }
            },
            
            // Suspicious (orange)
            {
                selector: 'node[threat = 1]',
                style: {
                    'background-color': '#f39c12',
                    'width': 40,
                    'height': 40,
                    'opacity': 0.9,
                    'shape': 'triangle'
                }
            },
            
            // Critical (red)
            {
                selector: 'node[threat = 2]',
                style: {
                    'background-color': '#e74c3c',
                    'width': 50,
                    'height': 50,
                    'opacity': 1,
                    'shape': 'hexagon',
                    'border-width': 3,
                    'border-color': '#c0392b'
                }
            },
            
            // AI anomaly (purple outline)
            {
                selector: 'node[ai_anomaly = "true"]',
                style: {
                    'border-width': 4,
                    'border-color': '#9b59b6',
                    'border-style': 'dashed'
                }
            },
            
            // File nodes
            {
                selector: 'node[type = "file"]',
                style: {
                    'background-color': '#ffffff',
                    'width': 20,
                    'height': 20,
                    'shape': 'square',
                    'opacity': 0.6
                }
            },
            
            // Network nodes
            {
                selector: 'node[type = "network"]',
                style: {
                    'background-color': '#3498db',
                    'width': 20,
                    'height': 20,
                    'shape': 'diamond',
                    'opacity': 0.6
                }
            },
            
            // Selected node
            {
                selector: 'node:selected',
                style: {
                    'border-width': 5,
                    'border-color': '#06b6d4',
                    'z-index': 999
                }
            },
            
            // Edge styles
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#34495e',
                    'target-arrow-color': '#34495e',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.6
                }
            },
            
            // Spawned relationship
            {
                selector: 'edge[relation = "spawned"]',
                style: {
                    'line-color': '#95a5a6'
                }
            },
            
            // File write
            {
                selector: 'edge[relation = "wrote"]',
                style: {
                    'line-color': '#ffffff',
                    'line-style': 'dotted'
                }
            },
            
            // Network connection
            {
                selector: 'edge[relation = "connected"]',
                style: {
                    'line-color': '#3498db',
                    'line-style': 'dashed'
                }
            }
        ],
        
        layout: {
            name: 'cose',
            animate: true,
            animationDuration: 1000,
            nodeRepulsion: 8000,
            idealEdgeLength: 100,
            edgeElasticity: 100,
            gravity: 0.1
        },
        
        wheelSensitivity: 0.2,
        minZoom: 0.3,
        maxZoom: 3
    });
    
    // Node click event
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const nodeData = node.data();
        
        if (nodeData.type === 'process') {
            selectedNodePid = nodeData.pid;
            showProcessDetails(nodeData.pid);
        }
    });
    
    // Background click (deselect)
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            selectedNodePid = null;
        }
    });
    
    console.log('[Graph] Cytoscape initialized');
}

// ============================================================================
// WEBSOCKET CONNECTION
// ============================================================================

function connectWebSocket() {
    socket = io.connect(window.location.origin);

    let updatesPaused = false;  // ✅ Add pause flag
    let lastUpdate = 0;         // ✅ Throttle updates
    
    socket.on('connect', function() {
        console.log('[WebSocket] Connected');
        document.getElementById('connection-status').textContent = '● CONNECTED';
        document.getElementById('connection-status').classList.add('active');
        socket.emit('subscribe_graph');
    });
    
    socket.on('disconnect', function() {
        console.log('[WebSocket] Disconnected');
        document.getElementById('connection-status').textContent = '● DISCONNECTED';
        document.getElementById('connection-status').classList.remove('active');
    });
    
     socket.on('graph_update', function(data) {
        // ✅ Throttle: max 1 update per second client-side
        const now = Date.now();
        if (now - lastUpdate < 1000) {
            console.log('[Graph] Skipping update (too fast)');
            return;
        }
        lastUpdate = now;
        
        if (!graphFrozen && !updatesPaused) {
            updateGraph(data);
        }
    });
    
    // ✅ Add circuit breaker
    let updateCount = 0;
    setInterval(() => {
        if (updateCount > 10) {  // More than 10 updates/sec = something's wrong
            console.warn('[Graph] Too many updates - pausing for 5s');
            updatesPaused = true;
            setTimeout(() => {
                updatesPaused = false;
                updateCount = 0;
            }, 5000);
        }
        updateCount = 0;
    }, 1000);
    
    socket.on('pending_reviews', function(reviews) {
        updatePendingReviews(reviews);
    });
}

// ============================================================================
// GRAPH UPDATE
// ============================================================================

function updateGraph(data) {
    const now = Date.now();
    const fadeTime = 600000; // 10 minutes
    
    // Apply threat filter if enabled
    let nodes = data.nodes;
    if (filterThreatsOnly) {
        nodes = nodes.filter(n => n.threat > 0);
    }
    
    // Calculate opacity based on age
    nodes.forEach(nodeData => {
        const age = now - nodeData.timestamp;
        nodeData.opacity = Math.max(0.3, 1 - (age / fadeTime));
    });
    
    // Update nodes
    nodes.forEach(nodeData => {
        const existingNode = cy.getElementById(nodeData.id);
        
        if (existingNode.length > 0) {
            // Update existing node
            existingNode.data(nodeData);
            existingNode.style('opacity', nodeData.opacity);
        } else {
            // Add new node
            cy.add({
                group: 'nodes',
                data: nodeData,
                style: { opacity: nodeData.opacity }
            });
        }
    });
    
    // Update edges
    const currentEdgeIds = data.edges.map(e => `${e.source}-${e.target}`);
    const existingEdges = cy.edges();
    
    // Remove edges not in new data
    existingEdges.forEach(edge => {
        const edgeId = `${edge.data('source')}-${edge.data('target')}`;
        if (!currentEdgeIds.includes(edgeId)) {
            edge.remove();
        }
    });
    
    // Add new edges
    data.edges.forEach(edgeData => {
        const edgeId = `${edgeData.source}-${edgeData.target}`;
        const existingEdge = cy.getElementById(edgeId);
        
        if (existingEdge.length === 0) {
            cy.add({
                group: 'edges',
                data: edgeData
            });
        }
    });
    
    // Update stats
    updateStats(data.stats);
    
    // Re-run layout occasionally
    if (Math.random() < 0.1) { // 10% chance
        cy.layout({
            name: 'cose',
            animate: true,
            animationDuration: 500,
            randomize: false
        }).run();
    }
}

// ============================================================================
// STATS UPDATE
// ============================================================================

function updateStats(stats) {
    document.getElementById('stat-total').textContent = stats.total_processes || 0;
    document.getElementById('stat-safe').textContent = stats.threat_level_0 || 0;
    document.getElementById('stat-suspicious').textContent = stats.threat_level_1 || 0;
    document.getElementById('stat-critical').textContent = stats.threat_level_2 || 0;
    document.getElementById('stat-unsigned').textContent = stats.unsigned_processes || 0;
    document.getElementById('stat-ai').textContent = stats.ai_anomalies || 0;
}

// ============================================================================
// PROCESS DETAILS MODAL
// ============================================================================

let isolatedPids = new Set(); // Track network isolated PIDs

async function showProcessDetails(pid) {
    const response = await fetch(`/api/process/${pid}`);
    const data = await response.json();
    
    if (data.error) {
        alert('Process not found');
        return;
    }
    
    selectedNodePid = pid;
    
    // Set default modal tab active
    switchModalTab('overview');
    
    // Populate modal overview
    document.getElementById('modal-title').textContent = data.name;
    document.getElementById('detail-pid').textContent = pid;
    document.getElementById('detail-name').textContent = data.name;
    document.getElementById('detail-path').textContent = data.full_path;
    document.getElementById('detail-threat').innerHTML = getThreatBadge(data.threat_level);
    document.getElementById('detail-trust').innerHTML = getTrustBadge(data.trust_score);
    document.getElementById('detail-signed').textContent = data.is_signed ? '✓ Yes' : '✗ No';
    document.getElementById('detail-origin').textContent = data.origin;
    
    // Populate Network Isolation button text
    const isoBtn = document.getElementById('btn-isolate-network');
    if (isoBtn) {
        isoBtn.textContent = isolatedPids.has(pid) ? '🔓 Restore Network' : '🔒 Isolate Network';
    }
    
    // Tags
    const tagsContainer = document.getElementById('detail-tags');
    tagsContainer.innerHTML = '';
    data.tags.forEach(tag => {
        const tagEl = document.createElement('span');
        tagEl.className = 'tag';
        tagEl.textContent = tag;
        tagsContainer.appendChild(tagEl);
    });
    
    // Forensic: Files
    const filesUl = document.getElementById('detail-files');
    filesUl.innerHTML = '';
    const filesList = data.files_modified || [];
    document.getElementById('modal-badge-files').textContent = filesList.length;
    if (filesList.length === 0) {
        filesUl.innerHTML = '<li class="empty-state">No files written or modified by this process</li>';
    } else {
        filesList.forEach(file => {
            const li = document.createElement('li');
            li.textContent = file;
            filesUl.appendChild(li);
        });
    }
    
    // Forensic: Network
    const netUl = document.getElementById('detail-network');
    netUl.innerHTML = '';
    const netList = data.network_connections || [];
    document.getElementById('modal-badge-network').textContent = netList.length;
    if (netList.length === 0) {
        netUl.innerHTML = '<li class="empty-state">No active connections or outbound sockets established</li>';
    } else {
        netList.forEach(conn => {
            const li = document.createElement('li');
            li.textContent = conn;
            netUl.appendChild(li);
        });
    }
    
    // Forensic: Registry
    const regUl = document.getElementById('detail-registry');
    regUl.innerHTML = '';
    const regList = data.registry_keys || [];
    document.getElementById('modal-badge-registry').textContent = regList.length;
    if (regList.length === 0) {
        regUl.innerHTML = '<li class="empty-state">No registry key transactions logged for this process</li>';
    } else {
        regList.forEach(key => {
            const li = document.createElement('li');
            li.textContent = key;
            regUl.appendChild(li);
        });
    }
    
    // Timeline
    const timelineContainer = document.getElementById('detail-timeline');
    timelineContainer.innerHTML = '';
    data.timeline.forEach(event => {
        const eventEl = document.createElement('div');
        eventEl.className = 'timeline-event';
        eventEl.textContent = `${formatTime(event.timestamp)} - ${event.description}`;
        timelineContainer.appendChild(eventEl);
    });
    
    // Show modal
    document.getElementById('detail-modal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('detail-modal').classList.add('hidden');
}

function getThreatBadge(level) {
    const colors = ['#2ecc71', '#f39c12', '#e74c3c'];
    const labels = ['SAFE', 'SUSPICIOUS', 'CRITICAL'];
    return `<span style="color: ${colors[level]}; font-weight: bold;">${labels[level]}</span>`;
}

function getTrustBadge(score) {
    const color = score >= 40 ? '#2ecc71' : score >= 0 ? '#f39c12' : '#e74c3c';
    return `<span style="color: ${color}; font-weight: bold;">${score}</span>`;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
}

// ============================================================================
// ACTION BUTTONS
// ============================================================================

async function killProcess() {
    if (!selectedNodePid) return;
    
    if (confirm(`Kill process PID ${selectedNodePid}?`)) {
        await fetch(`/api/action/kill/${selectedNodePid}`, { method: 'POST' });
        closeModal();
    }
}

async function killTree() {
    if (!selectedNodePid) return;
    
    if (confirm(`Kill entire process tree for PID ${selectedNodePid}?`)) {
        await fetch(`/api/action/kill_tree/${selectedNodePid}`, { method: 'POST' });
        closeModal();
    }
}

async function suspendProcess() {
    if (!selectedNodePid) return;
    
    await fetch(`/api/action/suspend/${selectedNodePid}`, { method: 'POST' });
    closeModal();
}

async function whitelistProcess() {
    if (!selectedNodePid) return;
    
    if (confirm(`Add PID ${selectedNodePid} to whitelist?`)) {
        await fetch(`/api/action/whitelist/${selectedNodePid}`, { method: 'POST' });
        closeModal();
    }
}

// ============================================================================
// CONTROL BUTTONS
// ============================================================================

function setupEventHandlers() {
    // Freeze/Unfreeze
    document.getElementById('btn-freeze').addEventListener('click', function() {
        graphFrozen = !graphFrozen;
        this.textContent = graphFrozen ? '▶️' : '❄️';
        this.title = graphFrozen ? 'Unfreeze graph' : 'Freeze graph';
    });
    
    // Reset zoom
    document.getElementById('btn-reset-zoom').addEventListener('click', function() {
        cy.fit();
        cy.zoom(1);
    });
    
    // Filter threats only
    document.getElementById('btn-filter-threats').addEventListener('click', function() {
        filterThreatsOnly = !filterThreatsOnly;
        this.style.background = filterThreatsOnly ? '#e74c3c' : '';
        this.title = filterThreatsOnly ? 'Show all processes' : 'Show threats only';
    });
    
    // AI Training button
    document.getElementById('btn-ai-train').addEventListener('click', async function() {
        const currentText = this.textContent;
        
        if (currentText === 'Start Training') {
            await fetch('/api/ai/train/start', { method: 'POST' });
            this.textContent = 'Stop Training';
        } else {
            await fetch('/api/ai/train/stop', { method: 'POST' });
            this.textContent = 'Start Training';
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'f' || e.key === 'F') {
            document.getElementById('btn-freeze').click();
        }
    });
}

// ============================================================================
// INITIAL DATA LOAD
// ============================================================================

async function loadInitialData() {
    // Load graph
    const graphResp = await fetch('/api/graph/snapshot');
    const graphData = await graphResp.json();
    updateGraph(graphData);
    
    // Load AI status
    const aiResp = await fetch('/api/ai/status');
    const aiData = await aiResp.json();
    updateAIStatus(aiData);
    
    // Load pending reviews
    const reviewsResp = await fetch('/api/pending/reviews');
    const reviewsData = await reviewsResp.json();
    updatePendingReviews(reviewsData);
    
    // Load suspended processes
    const suspendedResp = await fetch('/api/pending/suspended');
    const suspendedData = await suspendedResp.json();
    updateSuspendedProcesses(suspendedData);
}

// ============================================================================
// AI STATUS UPDATE
// ============================================================================

function updateAIStatus(data) {
    const statusDiv = document.querySelector('.ai-status');
    const progressFill = document.getElementById('ai-progress-fill');
    const progressText = document.getElementById('ai-progress-text');
    const trainBtn = document.getElementById('btn-ai-train');
    
    if (data.is_trained) {
        statusDiv.textContent = '✅ TRAINED & ACTIVE';
        statusDiv.style.color = '#2ecc71';
        progressFill.style.width = '100%';
        progressText.textContent = `${data.samples_collected} samples`;
        trainBtn.textContent = 'Retrain';
    } else if (data.is_training) {
        statusDiv.textContent = '⏳ TRAINING IN PROGRESS';
        statusDiv.style.color = '#f39c12';
        const progress = (data.samples_collected / data.samples_required) * 100;
        progressFill.style.width = `${progress}%`;
        progressText.textContent = `${data.samples_collected} / ${data.samples_required} samples`;
        trainBtn.textContent = 'Stop Training';
    } else {
        statusDiv.textContent = '❌ NOT TRAINED';
        statusDiv.style.color = '#e74c3c';
        progressFill.style.width = '0%';
        progressText.textContent = 'Press button to start training';
        trainBtn.textContent = 'Start Training';
    }
}

// ============================================================================
// PENDING REVIEWS UPDATE
// ============================================================================

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

async function approveKill(pid) {
    await fetch(`/api/action/approve_kill/${pid}`, { method: 'POST' });
    loadInitialData(); // Refresh
}

async function whitelistReview(pid) {
    await fetch(`/api/action/whitelist_resume/${pid}`, { method: 'POST' });
    loadInitialData(); // Refresh
}

// ============================================================================
// SUSPENDED PROCESSES UPDATE
// ============================================================================

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

setInterval(async () => {
    if (!graphFrozen) {
        // Refresh pending reviews and suspended
        const reviewsResp = await fetch('/api/pending/reviews');
        const reviewsData = await reviewsResp.json();
        updatePendingReviews(reviewsData);
        
        const suspendedResp = await fetch('/api/pending/suspended');
        const suspendedData = await suspendedResp.json();
        updateSuspendedProcesses(suspendedData);
        
        const aiResp = await fetch('/api/ai/status');
        const aiData = await aiResp.json();
        updateAIStatus(aiData);
        
        // Dynamic grid auto-refreshes if their tabs are active
        const activeTab = document.querySelector('.console-tab-content.active');
        if (activeTab) {
            const activeId = activeTab.id;
            if (activeId === 'tab-content-task-manager') {
                loadTaskGrid();
            } else if (activeId === 'tab-content-quarantine-vault') {
                loadQuarantineGrid();
            } else if (activeId === 'tab-content-detonation-lab') {
                loadDetonationGrid();
            }
        }
    }
}, 5000); // Every 5 seconds

// ============================================================================
// CONSOLE & DETAIL MODAL TABS NAVIGATION
// ============================================================================

function switchConsoleTab(tabId) {
    // Switch active state of header buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`tab-btn-${tabId}`).classList.add('active');
    
    // Switch active state of tab contents
    document.querySelectorAll('.console-tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(`tab-content-${tabId}`).classList.add('active');
    
    // Immediate data load based on tab selection
    if (tabId === 'task-manager') {
        loadTaskGrid();
    } else if (tabId === 'quarantine-vault') {
        loadQuarantineGrid();
    } else if (tabId === 'detonation-lab') {
        loadDetonationGrid();
    }
}

function switchModalTab(tabId) {
    // Switch active state of modal tab buttons
    document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`modal-tab-btn-${tabId}`).classList.add('active');
    
    // Switch active state of modal content panes
    document.querySelectorAll('.modal-tab-content-pane').forEach(pane => pane.classList.remove('active'));
    document.getElementById(`modal-content-${tabId}`).classList.add('active');
}

// ============================================================================
// GRAPH LAYOUT & INTERACTIVE FOCUS CONTROLS
// ============================================================================

function changeGraphLayout() {
    const layoutName = document.getElementById('select-layout').value;
    cy.layout({
        name: layoutName,
        animate: true,
        animationDuration: 800,
        nodeRepulsion: 8000,
        idealEdgeLength: 100
    }).run();
}

function filterGraphNodes() {
    const query = document.getElementById('node-search').value.toLowerCase().trim();
    if (!query) {
        cy.elements().removeClass('faded');
        return;
    }
    
    // Dim all elements first
    cy.elements().addClass('faded');
    
    // Highlight elements matching process criteria
    const matchedNodes = cy.nodes().filter(node => {
        const d = node.data();
        return String(d.pid).includes(query) || 
               String(d.label).toLowerCase().includes(query) || 
               (d.tags && d.tags.some(t => t.toLowerCase().includes(query)));
    });
    
    matchedNodes.removeClass('faded');
    matchedNodes.connectedEdges().removeClass('faded');
    
    // Fit matched elements on screen
    if (matchedNodes.length > 0) {
        cy.animate({
            fit: {
                eles: matchedNodes,
                padding: 60
            },
            duration: 300
        });
    }
}

// ============================================================================
// FINE TELEMETRY & MITIGATION ACTIONS
// ============================================================================

async function toggleNetworkIsolation() {
    if (!selectedNodePid) return;
    
    const isIsolated = isolatedPids.has(selectedNodePid);
    const url = isIsolated ? `/api/action/restore_network/${selectedNodePid}` : `/api/action/isolate_network/${selectedNodePid}`;
    
    const btn = document.getElementById('btn-isolate-network');
    const originalText = btn.textContent;
    btn.textContent = '⏳ Processing...';
    btn.disabled = true;
    
    try {
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            if (isIsolated) {
                isolatedPids.delete(selectedNodePid);
                btn.textContent = '🔒 Isolate Network';
                alert(`[FIREWALL RESTORED] Process PID ${selectedNodePid} network access restored successfully.`);
            } else {
                isolatedPids.add(selectedNodePid);
                btn.textContent = '🔓 Restore Network';
                alert(`[NETWORK ISOLATED] Process PID ${selectedNodePid} network activity isolated successfully.`);
            }
        } else {
            alert('Mitigation failed: ' + (data.error || 'Access Denied.'));
            btn.textContent = originalText;
        }
    } catch (err) {
        alert('Communication error: ' + err);
        btn.textContent = originalText;
    } finally {
        btn.disabled = false;
    }
}

async function dumpProcessMemory() {
    if (!selectedNodePid) return;
    
    const confirmDump = confirm(`Generate process memory minidump for PID ${selectedNodePid}?`);
    if (!confirmDump) return;
    
    const originalFooterHtml = document.querySelector('.modal-footer').innerHTML;
    document.querySelector('.modal-footer').innerHTML = '<span style="color: #06b6d4; font-weight: bold; margin-right: auto; animation: pulse 1s infinite;">⏳ Writing native full-memory minidump...</span>';
    
    try {
        const res = await fetch(`/api/action/dump_memory/${selectedNodePid}`, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`[DUMP COMPLETE] Process Memory Dump succeeded!\nSaved as: ${data.filename}`);
            // Direct browser download
            window.open(data.download_url, '_blank');
        } else {
            alert('Memory dump failed: ' + (data.error || 'Access Denied. Ensure process is active and running elevated.'));
        }
    } catch (err) {
        alert('Dump transaction failed: ' + err);
    } finally {
        // Restore footer markup
        document.querySelector('.modal-footer').innerHTML = originalFooterHtml;
        
        // Update network button state correctly
        const isoBtn = document.getElementById('btn-isolate-network');
        if (isoBtn) {
            isoBtn.textContent = isolatedPids.has(selectedNodePid) ? '🔓 Restore Network' : '🔒 Isolate Network';
        }
    }
}

// ============================================================================
// TASK MANAGER GRID LOADER
// ============================================================================

async function loadTaskGrid() {
    const res = await fetch('/api/graph/snapshot');
    const data = await res.json();
    
    const tbody = document.querySelector('#task-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data.nodes || data.nodes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No active processes monitored in this window</td></tr>';
        return;
    }
    
    // Sort process nodes by PID ascending
    const processNodes = data.nodes.filter(n => n.type === 'process');
    processNodes.sort((a, b) => a.pid - b.pid);
    
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
            <td>
                <button class="btn btn-primary" onclick="showProcessDetails(${node.pid})" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; border-radius: 4px;">🔍 Inspect</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterTaskTable() {
    const query = document.getElementById('task-search').value.toLowerCase().trim();
    const rows = document.querySelectorAll('#task-grid-table tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        if (text.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// ============================================================================
// QUARANTINE VAULT GRID LOADER
// ============================================================================

async function loadQuarantineGrid() {
    const res = await fetch('/api/quarantine/list');
    const data = await res.json();
    
    const tbody = document.querySelector('#quarantine-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No files have been isolated in the Quarantine Vault</td></tr>';
        return;
    }
    
    data.forEach(item => {
        const tr = document.createElement('tr');
        const qTime = new Date(item.quarantine_time * 1000).toLocaleString();
        const sizeKB = (item.file_size / 1024).toFixed(1);
        
        tr.innerHTML = `
            <td><code>${item.quarantine_id}</code></td>
            <td><strong>${item.original_name}</strong></td>
            <td style="font-family: monospace; font-size: 0.75rem; word-break: break-all;">${item.original_path}</td>
            <td><span class="badge-status critical" style="font-size: 0.7rem;">${item.threat_reason || 'Threat Detected'}</span></td>
            <td><strong>${sizeKB} KB</strong></td>
            <td>${qTime}</td>
            <td><span class="badge-status ${item.is_restored ? 'active' : 'critical'}">${item.is_restored ? 'RESTORED' : 'SECURELY ISOLATED'}</span></td>
            <td>
                ${!item.is_restored ? `<button class="btn btn-success" onclick="restoreQuarantinedFile('${item.quarantine_id}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 4px;">✅ Restore</button>` : ''}
                <button class="btn btn-danger" onclick="deleteQuarantinedFile('${item.quarantine_id}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 4px;">❌ Purge</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function restoreQuarantinedFile(qId) {
    if (confirm(`Restore quarantined file ${qId} back to its original path?`)) {
        try {
            const res = await fetch(`/api/quarantine/${qId}/restore`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                alert('[RESTORE SUCCESS] File successfully recovered from quarantine vault.');
                loadQuarantineGrid();
            } else {
                alert('Restore failed: ' + (data.error || 'Access Denied.'));
            }
        } catch (err) {
            alert('Restore transaction error: ' + err);
        }
    }
}

async function deleteQuarantinedFile(qId) {
    if (confirm(`Irreversibly delete and securely shred quarantined file ${qId} from system storage?`)) {
        try {
            const res = await fetch(`/api/quarantine/${qId}/delete`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: 'Operator requested secure shred' })
            });
            const data = await res.json();
            if (data.success) {
                alert('[PURGE COMPLETE] File successfully shredded and deleted.');
                loadQuarantineGrid();
            } else {
                alert('Purge transaction failed.');
            }
        } catch (err) {
            alert('Purge error: ' + err);
        }
    }
}

// ============================================================================
// DETONATION LAB CONTAINER LOADER
// ============================================================================

async function loadDetonationGrid() {
    const res = await fetch('/api/malware/executions');
    const data = await res.json();
    
    const tbody = document.querySelector('#detonation-grid-table tbody');
    tbody.innerHTML = '';
    
    if (!data || Object.keys(data).length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No sandboxed detonations recorded in this session</td></tr>';
        return;
    }
    
    for (const [execId, info] of Object.entries(data)) {
        const tr = document.createElement('tr');
        const badgeClass = info.status === 'COMPLETED' ? 'active' : info.status === 'RUNNING' ? 'suspended' : 'critical';
        const duration = info.duration ? `${info.duration.toFixed(2)}s` : 'Active detonation...';
        
        tr.innerHTML = `
            <td><code>${execId}</code></td>
            <td><strong>${info.sample_name || 'sample'}</strong></td>
            <td><span class="badge-status ${badgeClass}">${info.status}</span></td>
            <td>${duration}</td>
            <td><span class="badge-status critical" style="font-size: 0.75rem;">${(info.behavior_tags || []).join(', ') || 'No hostile signs'}</span></td>
            <td>
                ${info.status === 'RUNNING' ? `<button class="btn btn-danger" onclick="stopDetonation('${execId}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 4px;">⏹️ Terminate</button>` : ''}
                <button class="btn btn-info" onclick="viewDetonationResults('${execId}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 4px;">📊 Report</button>
            </td>
        `;
        tbody.appendChild(tr);
    }
}

async function launchSandboxSample() {
    const path = document.getElementById('sandbox-sample-path').value.trim();
    const timeout = parseInt(document.getElementById('sandbox-timeout').value) || 10;
    const mode = document.getElementById('sandbox-isolation').value;
    
    if (!path) {
        alert('Please specify a valid host sample path.');
        return;
    }
    
    const btn = document.querySelector('.btn-explode');
    btn.textContent = '⏳ Initializing Detonation Lab...';
    btn.disabled = true;
    
    try {
        const res = await fetch('/api/malware/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sample_path: path,
                execution_params: {
                    timeout: timeout,
                    use_sandbox: mode === 'sandbox'
                }
            })
        });
        const data = await res.json();
        
        if (data.success) {
            alert(`[LAB ACTIVATED] Sandbox execution successfully initialized.\nExecution ID: ${data.execution_id}`);
            loadDetonationGrid();
        } else {
            alert('Detonation failed to launch: ' + (data.error || 'Check Sandbox configs.'));
        }
    } catch (err) {
        alert('Explosion failed: ' + err);
    } finally {
        btn.textContent = '💥 Explode Sample in Isolation';
        btn.disabled = false;
    }
}

async function stopDetonation(execId) {
    if (confirm(`Forcibly terminate active sandboxed detonation ${execId}?`)) {
        await fetch(`/api/malware/execution/${execId}/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'Operator requested sandbox stop' })
        });
        loadDetonationGrid();
    }
}

async function viewDetonationResults(execId) {
    try {
        const res = await fetch(`/api/malware/execution/${execId}/results`);
        const data = await res.json();
        
        alert(`[DETONATION LAB FORENSIC REPORT]\n\nExecution ID: ${execId}\nStatus: ${data.status}\nDuration: ${data.duration ? data.duration.toFixed(2) : '-'} seconds\nBehavioral Signs: ${JSON.stringify(data.behavior_tags || [])}\nProcesses Spawned: ${JSON.stringify(data.processes_spawned || [])}\nCreated Files Count: ${data.files_created_count || 0}`);
    } catch (err) {
        alert('Failed to parse detonation logs: ' + err);
    }
}