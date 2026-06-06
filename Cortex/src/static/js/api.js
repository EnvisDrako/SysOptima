/**
 * api.js - Handles all REST API communications with Bearer token authentication
 */

const token = window.SYSOPTIMA_TOKEN || '';

async function authFetch(url, options = {}) {
    if (!options.headers) {
        options.headers = {};
    }
    options.headers['Authorization'] = `Bearer ${token}`;
    return fetch(url, options);
}

// Telemetry Snapshot APIs
export async function fetchGraphSnapshot() {
    const response = await authFetch('/api/graph/snapshot');
    return response.json();
}

export async function fetchProcesses() {
    const response = await authFetch('/api/processes');
    return response.json();
}

export async function fetchProcessLineage(pid) {
    const response = await authFetch(`/api/process/${pid}/lineage`);
    return response.json();
}

export async function fetchAIStatus() {
    const response = await authFetch('/api/ai/status');
    return response.json();
}

export async function fetchPendingReviews() {
    const response = await authFetch('/api/pending/reviews');
    return response.json();
}

export async function fetchSuspendedProcesses() {
    const response = await authFetch('/api/pending/suspended');
    return response.json();
}

export async function fetchProcessDetails(pid) {
    const response = await authFetch(`/api/process/${pid}`);
    return response.json();
}

// Mitigations and Actions
export async function killProcess(pid) {
    return authFetch(`/api/action/kill/${pid}`, { method: 'POST' });
}

export async function killTree(pid) {
    return authFetch(`/api/action/kill_tree/${pid}`, { method: 'POST' });
}

export async function suspendProcess(pid) {
    return authFetch(`/api/action/suspend/${pid}`, { method: 'POST' });
}

export async function whitelistProcess(pid) {
    return authFetch(`/api/action/whitelist/${pid}`, { method: 'POST' });
}

export async function approveKill(pid) {
    return authFetch(`/api/action/approve_kill/${pid}`, { method: 'POST' });
}

export async function whitelistReview(pid) {
    return authFetch(`/api/action/whitelist_resume/${pid}`, { method: 'POST' });
}

export async function toggleAI(start) {
    const endpoint = start ? '/api/ai/train/start' : '/api/ai/train/stop';
    return authFetch(endpoint, { method: 'POST' });
}

export async function isolateNetwork(pid) {
    const response = await authFetch(`/api/action/isolate_network/${pid}`, { method: 'POST' });
    return response.json();
}

export async function restoreNetwork(pid) {
    const response = await authFetch(`/api/action/restore_network/${pid}`, { method: 'POST' });
    return response.json();
}

export async function dumpMemory(pid) {
    const response = await authFetch(`/api/action/dump_memory/${pid}`, { method: 'POST' });
    return response.json();
}

// Quarantine vault APIs
export async function fetchQuarantineList() {
    const response = await authFetch('/api/quarantine/list');
    return response.json();
}

export async function restoreQuarantinedFile(id) {
    const response = await authFetch(`/api/quarantine/${id}/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
    });
    return response.json();
}

export async function deleteQuarantinedFile(id) {
    const response = await authFetch(`/api/quarantine/${id}/delete`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Operator requested' })
    });
    return response.json();
}

// Detonation sandbox APIs
export async function fetchMalwareExecutions() {
    const response = await authFetch('/api/malware/executions');
    return response.json();
}

export async function launchSandboxSample(samplePath, useSandbox) {
    const response = await authFetch('/api/malware/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            sample_path: samplePath,
            execution_params: {
                timeout: 10,
                use_sandbox: useSandbox
            }
        })
    });
    return response.json();
}

export async function stopDetonation(id) {
    const response = await authFetch(`/api/malware/execution/${id}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Operator requested' })
    });
    return response.json();
}

export async function viewDetonationResults(id) {
    const response = await authFetch(`/api/malware/execution/${id}/results`);
    return response.json();
}
