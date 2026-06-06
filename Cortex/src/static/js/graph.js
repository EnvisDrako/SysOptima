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
                    'background-opacity': 0.9,
                    'transition-property': 'background-color, border-color, opacity',
                    'transition-duration': '0.5s'
                }
            },
            
            // Safe processes (green)
            {
                selector: 'node[threat = 0]',
                style: {
                    'background-color': '#10b981',
                    'width': 30,
                    'height': 30,
                    'opacity': 0.7
                }
            },
            
            // Suspicious (orange)
            {
                selector: 'node[threat = 1]',
                style: {
                    'background-color': '#f59e0b',
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
                    'background-color': '#ef4444',
                    'width': 50,
                    'height': 50,
                    'opacity': 1,
                    'shape': 'hexagon',
                    'border-width': 3,
                    'border-color': '#b91c1c'
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
                    'background-color': '#0ea5e9',
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
                    'border-color': '#0ea5e9',
                    'z-index': 999
                }
            },
            
            // Edge styles
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#334155',
                    'target-arrow-color': '#334155',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.6
                }
            },
            
            // Spawned relationship
            {
                selector: 'edge[relation = "spawned"]',
                style: {
                    'line-color': '#64748b'
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
                    'line-color': '#0ea5e9',
                    'line-style': 'dashed'
                }
            },
            
            // Faded elements
            {
                selector: '.faded',
                style: {
                    'opacity': 0.15
                }
            }
        ],
        
        layout: {
            name: 'cose',
            animate: true,
            animationDuration: 1000,
            nodeRepulsion: 12000,
            idealEdgeLength: 120,
            edgeElasticity: 100,
            gravity: 0.1
        },
        
        wheelSensitivity: 0.2,
        minZoom: 0.3,
        maxZoom: 3
    });
    
    // Event listeners
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const nodeData = node.data();
        if (nodeData.type === 'process') {
            onNodeSelected(nodeData.pid);
        }
    });
    
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            onBackgroundTap();
        }
    });
    
    return cy;
}

export function updateGraph(data, filterThreatsOnly) {
    if (!cy) return;
    
    const now = Date.now();
    const fadeTime = 600000; // 10 minutes
    
    let nodes = data.nodes;
    if (filterThreatsOnly) {
        nodes = nodes.filter(n => n.threat > 0);
    }
    
    nodes.forEach(nodeData => {
        const age = now - nodeData.timestamp;
        nodeData.opacity = Math.max(0.3, 1 - (age / fadeTime));
    });
    
    let needsLayout = false;
    
    // Add/update nodes efficiently
    nodes.forEach(nodeData => {
        const existingNode = cy.getElementById(nodeData.id);
        if (existingNode.length > 0) {
            existingNode.data(nodeData);
            existingNode.style('opacity', nodeData.opacity);
        } else {
            cy.add({
                group: 'nodes',
                data: nodeData,
                style: { opacity: nodeData.opacity }
            });
            needsLayout = true;
        }
    });
    
    // Handle edges
    const currentEdgeIds = data.edges.map(e => `${e.source}-${e.target}`);
    const existingEdges = cy.edges();
    
    existingEdges.forEach(edge => {
        const edgeId = `${edge.data('source')}-${edge.data('target')}`;
        if (!currentEdgeIds.includes(edgeId)) {
            edge.remove();
            needsLayout = true;
        }
    });
    
    data.edges.forEach(edgeData => {
        const edgeId = `${edgeData.source}-${edgeData.target}`;
        if (cy.getElementById(edgeId).length === 0) {
            cy.add({
                group: 'edges',
                data: edgeData
            });
            needsLayout = true;
        }
    });
    
    // Run layout on additions or removals
    if (needsLayout) {
        cy.layout({
            name: 'cose',
            animate: true,
            animationDuration: 500,
            randomize: false,
            nodeRepulsion: 12000,
            idealEdgeLength: 120
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
               String(d.label).toLowerCase().includes(query) || 
               (d.tags && d.tags.some(t => t.toLowerCase().includes(query)));
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
        nodeRepulsion: 8000,
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
    
    // Clean up previous lineage cy instance
    if (lineageCy) {
        lineageCy.destroy();
    }
    
    const elements = [];
    
    // Add ancestors
    const ancestors = lineageData.ancestors || [];
    ancestors.forEach(a => {
        elements.push({
            group: 'nodes',
            data: {
                id: a.id,
                label: `${a.label} (${a.pid})`,
                threat: a.threat,
                type: 'process',
                is_signed: a.is_signed
            }
        });
    });
    
    // Add descendants
    const descendants = lineageData.descendants || [];
    descendants.forEach(d => {
        elements.push({
            group: 'nodes',
            data: {
                id: d.id,
                label: `${d.label} (${d.pid})`,
                threat: d.threat,
                type: 'process',
                is_signed: d.is_signed
            }
        });
    });
    
    // Add target process itself
    const target = lineageData.process;
    if (target) {
        elements.push({
            group: 'nodes',
            data: {
                id: target.id,
                label: `${target.label} (${target.pid})`,
                threat: target.threat,
                type: 'process',
                is_signed: target.is_signed
            }
        });
    }
    
    // Build parent-child connections
    const allNodes = [target, ...ancestors, ...descendants].filter(Boolean);
    const nodeIds = new Set(allNodes.map(n => n.id));
    
    allNodes.forEach(node => {
        if (node.ppid) {
            // Find parent node ID if it's in allNodes
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
                    'background-opacity': 0.9
                }
            },
            {
                selector: 'node[threat = 0]',
                style: {
                    'background-color': '#10b981',
                    'width': 30,
                    'height': 30
                }
            },
            {
                selector: 'node[threat = 1]',
                style: {
                    'background-color': '#f59e0b',
                    'width': 40,
                    'height': 40,
                    'shape': 'triangle'
                }
            },
            {
                selector: 'node[threat = 2]',
                style: {
                    'background-color': '#ef4444',
                    'width': 50,
                    'height': 50,
                    'shape': 'hexagon',
                    'border-width': 3,
                    'border-color': '#b91c1c'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2.5,
                    'line-color': '#3b82f6',
                    'target-arrow-color': '#3b82f6',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier'
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
    
    // Fit graph
    lineageCy.ready(() => {
        lineageCy.fit();
    });
}
