/**
 * graph.js - Cytoscape graph initialization and updates
 */

export let cy = null;

export function initGraph(containerId, onNodeSelected, onBackgroundTap) {
    cy = cytoscape({
        container: document.getElementById(containerId),
        
        style: [
            // Base node style
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'font-size': '10px',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#f8fafc',
                    'text-outline-width': 2,
                    'text-outline-color': '#050814',
                    'background-opacity': 0.95,
                    'transition-property': 'background-color, border-color, opacity',
                    'transition-duration': '0.3s'
                }
            },
            
            // Safe processes (green)
            {
                selector: 'node[threat = 0]',
                style: {
                    'background-color': '#10b981',
                    'width': 34,
                    'height': 34,
                    'opacity': 0.95
                }
            },
            
            // Suspicious (orange)
            {
                selector: 'node[threat = 1]',
                style: {
                    'background-color': '#f59e0b',
                    'width': 44,
                    'height': 44,
                    'opacity': 0.95,
                    'shape': 'triangle',
                    'border-width': 2,
                    'border-color': '#d97706'
                }
            },
            
            // Critical (red)
            {
                selector: 'node[threat = 2]',
                style: {
                    'background-color': '#ef4444',
                    'width': 54,
                    'height': 54,
                    'opacity': 1,
                    'shape': 'hexagon',
                    'border-width': 3,
                    'border-color': '#b91c1c'
                }
            },
            
            // Exited processes (grey & faded)
            {
                selector: 'node[exited = "true"]',
                style: {
                    'background-color': '#475569',
                    'opacity': 0.2,
                    'color': '#94a3b8',
                    'text-outline-color': '#050814',
                    'border-width': 0
                }
            },
            
            // AI anomaly (purple outline)
            {
                selector: 'node[ai_anomaly = "true"]',
                style: {
                    'border-width': 4,
                    'border-color': '#8b5cf6',
                    'border-style': 'dashed'
                }
            },
            
            // Selected node
            {
                selector: 'node:selected',
                style: {
                    'border-width': 5,
                    'border-color': '#3b82f6',
                    'z-index': 999
                }
            },
            
            // Edge styles
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#475569',
                    'target-arrow-color': '#475569',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.5,
                    'transition-property': 'opacity, line-color, target-arrow-color',
                    'transition-duration': '0.3s'
                }
            },
            
            // Spawned relationship
            {
                selector: 'edge[relation = "spawned"]',
                style: {
                    'line-color': '#64748b'
                }
            },
            
            // Faded elements (highlighting fallback)
            {
                selector: '.faded',
                style: {
                    'opacity': 0.08
                }
            }
        ],
        
        layout: {
            name: 'fcose',
            animate: true,
            animationDuration: 1000,
            nodeRepulsion: 6500,
            idealEdgeLength: 100,
            randomize: false
        },
        
        wheelSensitivity: 0.2,
        minZoom: 0.2,
        maxZoom: 3
    });
    
    // Event listeners
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const nodeData = node.data();
        if (nodeData.type === 'process') {
            if (nodeData.isGroup && nodeData.pids) {
                // Pass first PID and the whole group list of PIDs
                onNodeSelected(nodeData.pids[0], nodeData.pids);
            } else {
                onNodeSelected(nodeData.pid, [nodeData.pid]);
            }
        }
    });
    
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            onBackgroundTap();
        }
    });

    // Hover highlighting (trace predecessor/successor path)
    cy.on('mouseover', 'node', function(evt) {
        const node = evt.target;
        const path = node.predecessors().union(node.successors()).union(node);
        cy.elements().difference(path).addClass('faded');
    });

    cy.on('mouseout', 'node', function(evt) {
        cy.elements().removeClass('faded');
    });
    
    return cy;
}

export function updateGraph(data, filterThreatsOnly) {
    if (!cy) return;
    
    // 1. Filter to processes only
    let inputNodes = (data.nodes || []).filter(n => n.type === 'process');
    if (filterThreatsOnly) {
        inputNodes = inputNodes.filter(n => n.threat > 0);
    }
    
    // Create mapping of unique node ID string to raw PID
    const nodeIdToPid = {};
    inputNodes.forEach(n => {
        nodeIdToPid[n.id] = n.pid;
    });
    
    // 2. Process Grouping Algorithm
    const groups = {}; // label -> array of nodes
    const finalNodes = [];
    const pidToNodeIdMap = {}; // raw pid -> target node id in Cytoscape
    
    inputNodes.forEach(node => {
        let emoji = node.is_signed ? '🛡️' : '⚙️';
        if (node.exited) {
            emoji = '💤';
        }
        node.labelWithEmoji = `${emoji} ${node.label}`;
        
        // Group only safe (threat == 0) and active (exited == false) processes
        if (node.threat === 0 && !node.exited) {
            if (!groups[node.label]) {
                groups[node.label] = [];
            }
            groups[node.label].push(node);
        } else {
            // Keep separate and map directly
            finalNodes.push(node);
            pidToNodeIdMap[node.pid] = node.id;
        }
    });
    
    // Resolve grouped processes
    Object.keys(groups).forEach(label => {
        const gNodes = groups[label];
        if (gNodes.length === 1) {
            const singleNode = gNodes[0];
            finalNodes.push(singleNode);
            pidToNodeIdMap[singleNode.pid] = singleNode.id;
        } else if (gNodes.length > 1) {
            const groupNodeId = `group_${label.replace(/\./g, '_')}`;
            const pids = gNodes.map(n => n.pid);
            
            finalNodes.push({
                id: groupNodeId,
                label: `📦 ${label} (${gNodes.length})`,
                labelWithEmoji: `📦 ${label} (${gNodes.length})`,
                pids: pids,
                threat: 0,
                trust: gNodes[0].trust,
                type: 'process',
                tags: [],
                timestamp: Math.max(...gNodes.map(n => n.timestamp)),
                is_signed: gNodes.every(n => n.is_signed),
                ai_anomaly: false,
                origin: gNodes[0].origin,
                exited: false,
                isGroup: true
            });
            
            pids.forEach(pid => {
                pidToNodeIdMap[pid] = groupNodeId;
            });
        }
    });
    
    // Apply final labels
    finalNodes.forEach(n => {
        n.label = n.labelWithEmoji;
    });
    
    // 3. Map edges to final node IDs (group node or individual node)
    const finalEdges = [];
    const edgeKeys = new Set();
    
    (data.edges || []).forEach(edge => {
        const sourcePid = nodeIdToPid[edge.source];
        const targetPid = nodeIdToPid[edge.target];
        
        if (sourcePid && targetPid) {
            const finalSourceId = pidToNodeIdMap[sourcePid];
            const finalTargetId = pidToNodeIdMap[targetPid];
            
            if (finalSourceId && finalTargetId && finalSourceId !== finalTargetId) {
                const edgeKey = `${finalSourceId}-${finalTargetId}`;
                if (!edgeKeys.has(edgeKey)) {
                    edgeKeys.add(edgeKey);
                    finalEdges.push({
                        id: edgeKey,
                        source: finalSourceId,
                        target: finalTargetId,
                        relation: edge.relation || 'spawned'
                    });
                }
            }
        }
    });
    
    let needsLayout = false;
    const finalNodeIds = finalNodes.map(n => n.id);
    
    // Remove old nodes from Cytoscape
    cy.nodes().forEach(node => {
        if (!finalNodeIds.includes(node.id())) {
            node.remove();
            needsLayout = true;
        }
    });
    
    // Add or update nodes
    finalNodes.forEach(nodeData => {
        const existingNode = cy.getElementById(nodeData.id);
        if (existingNode.length > 0) {
            existingNode.data(nodeData);
            // Apply exited style dynamically if exited state changed
            if (nodeData.exited) {
                existingNode.style({
                    'background-color': '#475569',
                    'opacity': 0.2,
                    'color': '#94a3b8'
                });
            }
        } else {
            cy.add({
                group: 'nodes',
                data: nodeData
            });
            needsLayout = true;
        }
    });
    
    // Handle edges removal
    const finalEdgeIds = finalEdges.map(e => e.id);
    cy.edges().forEach(edge => {
        if (!finalEdgeIds.includes(edge.id())) {
            edge.remove();
            needsLayout = true;
        }
    });
    
    // Add edges
    finalEdges.forEach(edgeData => {
        if (cy.getElementById(edgeData.id).length === 0) {
            cy.add({
                group: 'edges',
                data: edgeData
            });
            needsLayout = true;
        }
    });
    
    // Trigger layout run on change
    if (needsLayout) {
        cy.layout({
            name: 'fcose',
            animate: true,
            animationDuration: 500,
            randomize: false,
            nodeRepulsion: 6500,
            idealEdgeLength: 100
        }).run();
    }
}

export function filterNodes(query) {
    if (!cy) return;
    if (!query) {
        cy.elements().removeClass('faded');
        return;
    }
    
    cy.elements().addClass('faded');
    
    const matchedNodes = cy.nodes().filter(node => {
        const d = node.data();
        return String(d.pid).includes(query) || 
               (d.pids && d.pids.some(p => String(p).includes(query))) ||
               String(d.label).toLowerCase().includes(query.toLowerCase()) || 
               (d.tags && d.tags.some(t => t.toLowerCase().includes(query.toLowerCase())));
    });
    
    matchedNodes.removeClass('faded');
    matchedNodes.connectedEdges().removeClass('faded');
    
    if (matchedNodes.length > 0) {
        cy.animate({
            fit: { eles: matchedNodes, padding: 60 },
            duration: 300
        });
    }
}

export function changeLayout(layoutName) {
    if (!cy) return;
    cy.layout({
        name: layoutName,
        animate: true,
        animationDuration: 800,
        nodeRepulsion: 6500,
        idealEdgeLength: 100
    }).run();
}

export function fitGraph() {
    if (cy) {
        cy.fit();
        cy.zoom(1);
    }
}

export let lineageCy = null;

export function renderLineageGraph(containerId, lineageData) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    if (lineageCy) {
        lineageCy.destroy();
    }
    
    const elements = [];
    
    // Add ancestors
    const ancestors = lineageData.ancestors || [];
    ancestors.forEach(a => {
        let emoji = a.is_signed ? '🛡️' : '⚙️';
        if (a.exited) emoji = '💤';
        elements.push({
            group: 'nodes',
            data: {
                id: a.id,
                label: `${emoji} ${a.label} (${a.pid})`,
                threat: a.threat,
                type: 'process',
                is_signed: a.is_signed,
                exited: a.exited ? "true" : "false"
            }
        });
    });
    
    // Add descendants
    const descendants = lineageData.descendants || [];
    descendants.forEach(d => {
        let emoji = d.is_signed ? '🛡️' : '⚙️';
        if (d.exited) emoji = '💤';
        elements.push({
            group: 'nodes',
            data: {
                id: d.id,
                label: `${emoji} ${d.label} (${d.pid})`,
                threat: d.threat,
                type: 'process',
                is_signed: d.is_signed,
                exited: d.exited ? "true" : "false"
            }
        });
    });
    
    // Add target process itself
    const target = lineageData.process;
    if (target) {
        let emoji = target.is_signed ? '🛡️' : '⚙️';
        if (target.exited) emoji = '💤';
        elements.push({
            group: 'nodes',
            data: {
                id: target.id,
                label: `${emoji} ${target.label} (${target.pid})`,
                threat: target.threat,
                type: 'process',
                is_signed: target.is_signed,
                exited: target.exited ? "true" : "false"
            }
        });
    }
    
    // Build parent-child connections
    const allNodes = [target, ...ancestors, ...descendants].filter(Boolean);
    const nodeIds = new Set(allNodes.map(n => n.id));
    
    allNodes.forEach(node => {
        if (node.ppid) {
            const parent = allNodes.find(n => n.pid === node.ppid);
            if (parent && nodeIds.has(parent.id) && nodeIds.has(node.id)) {
                elements.push({
                    group: 'edges',
                    data: {
                        id: `${parent.id}-${node.id}`,
                        source: parent.id,
                        target: node.id,
                        relation: 'spawned'
                    }
                });
            }
        }
    });
    
    lineageCy = cytoscape({
        container: container,
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'font-size': '10px',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#f8fafc',
                    'text-outline-width': 2,
                    'text-outline-color': '#050814',
                    'background-opacity': 0.95
                }
            },
            {
                selector: 'node[threat = 0]',
                style: {
                    'background-color': '#10b981',
                    'width': 34,
                    'height': 34
                }
            },
            {
                selector: 'node[threat = 1]',
                style: {
                    'background-color': '#f59e0b',
                    'width': 44,
                    'height': 44,
                    'shape': 'triangle'
                }
            },
            {
                selector: 'node[threat = 2]',
                style: {
                    'background-color': '#ef4444',
                    'width': 54,
                    'height': 54,
                    'shape': 'hexagon',
                    'border-width': 3,
                    'border-color': '#b91c1c'
                }
            },
            {
                selector: 'node[exited = "true"]',
                style: {
                    'background-color': '#475569',
                    'opacity': 0.25,
                    'color': '#94a3b8'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2.5,
                    'line-color': '#3b82f6',
                    'target-arrow-color': '#3b82f6',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.6
                }
            }
        ],
        layout: {
            name: 'breadthfirst',
            directed: true,
            padding: 30,
            spacingFactor: 1.25,
            animate: true,
            animationDuration: 500
        },
        wheelSensitivity: 0.2
    });
    
    lineageCy.ready(() => {
        lineageCy.fit();
    });
}
