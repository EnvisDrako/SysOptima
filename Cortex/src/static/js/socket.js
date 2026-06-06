/**
 * socket.js - Handles Socket.IO connections and message routing
 */

export let socket = null;
let updatesPaused = false;
let lastUpdate = 0;
let updateCount = 0;

export function initSocket(onConnect, onDisconnect, onGraphUpdate, onPendingReviewsUpdate) {
    socket = io.connect(window.location.origin, {
        auth: {
            token: window.SYSOPTIMA_TOKEN || ''
        }
    });
    
    socket.on('connect', () => {
        console.log('[WebSocket] Connected');
        if (onConnect) onConnect();
        socket.emit('subscribe_graph');
    });
    
    socket.on('disconnect', () => {
        console.log('[WebSocket] Disconnected');
        if (onDisconnect) onDisconnect();
    });
    
    socket.on('graph_update', (data) => {
        updateCount++;
        const now = Date.now();
        
        // Client-side throttle
        if (now - lastUpdate < 1000) {
            return;
        }
        lastUpdate = now;
        
        if (!updatesPaused && onGraphUpdate) {
            onGraphUpdate(data);
        }
    });
    
    // Circuit breaker logic
    setInterval(() => {
        if (updateCount > 10) {
            console.warn('[Graph] Too many updates - pausing for 5s');
            updatesPaused = true;
            setTimeout(() => {
                updatesPaused = false;
                updateCount = 0;
            }, 5000);
        }
        updateCount = 0;
    }, 1000);
    
    socket.on('pending_reviews', (reviews) => {
        if (onPendingReviewsUpdate) {
            onPendingReviewsUpdate(reviews);
        }
    });
    
    return socket;
}
