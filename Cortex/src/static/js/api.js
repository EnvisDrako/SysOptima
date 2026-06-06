/**
 * api.js - Handles all REST API communications
 */

export async function fetchGraphSnapshot() {
    const response = await fetch('/api/graph/snapshot');
    return response.json();
}

export async function fetchAIStatus() {
    const response = await fetch('/api/ai/status');
    return response.json();
}

export async function fetchPendingReviews() {
    const response = await fetch('/api/pending/reviews');
    return response.json();
}

export async function fetchSuspendedProcesses() {
    const response = await fetch('/api/pending/suspended');
    return response.json();
}

export async function fetchProcessDetails(pid) {
    const response = await fetch(`/api/process/${pid}`);
    return response.json();
}

// Actions
export async function killProcess(pid) {
    return fetch(`/api/action/kill/${pid}`, { method: 'POST' });
}

export async function killTree(pid) {
    return fetch(`/api/action/kill_tree/${pid}`, { method: 'POST' });
}

export async function suspendProcess(pid) {
    return fetch(`/api/action/suspend/${pid}`, { method: 'POST' });
}

export async function whitelistProcess(pid) {
    return fetch(`/api/action/whitelist/${pid}`, { method: 'POST' });
}

export async function approveKill(pid) {
    return fetch(`/api/action/approve_kill/${pid}`, { method: 'POST' });
}

export async function whitelistReview(pid) {
    return fetch(`/api/action/whitelist_resume/${pid}`, { method: 'POST' });
}

export async function toggleAI(start) {
    const endpoint = start ? '/api/ai/train/start' : '/api/ai/train/stop';
    return fetch(endpoint, { method: 'POST' });
}
