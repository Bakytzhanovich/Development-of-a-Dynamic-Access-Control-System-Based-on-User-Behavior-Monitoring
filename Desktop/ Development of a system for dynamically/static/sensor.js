/**
 * Behavioral Sensor - Collects keystroke dynamics and mouse movement data
 * Sends data to backend every 10 seconds or after 20 keystrokes
 */

(function() {
    'use strict';

    // Configuration
    const SEND_INTERVAL_MS = 10000; // 10 seconds
    const KEYSTROKE_THRESHOLD = 20; // Send after 20 keystrokes
    
    // Data storage
    let keystrokes = [];
    let mouseMovements = [];
    let lastKeyTime = null;
    let lastKeyDownTime = null;
    let lastMouseTime = null;
    let sendInterval = null;
    
    // Performance optimization: throttle mouse tracking
    let mouseThrottle = 0;
    const MOUSE_THROTTLE_MS = 15; // Track mouse every 15ms (was 50ms)
    
    /**
     * Initialize the sensor
     */
    function init() {
        // Check if we're on a page that needs monitoring
        if (window.location.pathname === '/dashboard' || window.location.pathname.includes('dashboard')) {
            attachEventListeners();
            startSendInterval();
            console.log('Behavioral sensor initialized');
        }
    }
    
    /**
     * Attach event listeners for keystroke and mouse tracking
     */
    function attachEventListeners() {
        // Keystroke tracking
        document.addEventListener('keydown', handleKeyDown, true);
        document.addEventListener('keyup', handleKeyUp, true);
        
        // Mouse movement tracking
        document.addEventListener('mousemove', handleMouseMove, true);
        
        // Clean up on page unload
        window.addEventListener('beforeunload', cleanup);
    }
    
    /**
     * Handle keydown event - record dwell time start
     */
    function handleKeyDown(event) {
        const now = Date.now();
        
        // Skip special keys that don't produce characters
        if (event.key.length > 1 && !['Enter', 'Space', 'Backspace', 'Delete'].includes(event.key)) {
            return;
        }
        
        lastKeyDownTime = now;
        
        // Calculate flight time (time between key presses)
        let flightTime = null;
        if (lastKeyTime !== null) {
            flightTime = now - lastKeyTime;
        }
        
        // Store keydown event (will be updated on keyup with dwell time)
        const keystroke = {
            key: event.key,
            keyCode: event.keyCode,
            timestamp: now,
            flightTime: flightTime,
            dwellTime: null // Will be set on keyup
        };
        
        keystrokes.push(keystroke);
        lastKeyTime = now;
        
        // Check if we've reached the keystroke threshold
        if (keystrokes.length >= KEYSTROKE_THRESHOLD) {
            sendBehaviorData();
        }
    }
    
    /**
     * Handle keyup event - calculate dwell time
     */
    function handleKeyUp(event) {
        if (lastKeyDownTime === null) return;
        
        const now = Date.now();
        const dwellTime = now - lastKeyDownTime;
        
        // Update the last keystroke with dwell time
        if (keystrokes.length > 0) {
            const lastKeystroke = keystrokes[keystrokes.length - 1];
            if (lastKeystroke.timestamp === lastKeyDownTime) {
                lastKeystroke.dwellTime = dwellTime;
            }
        }
        
        lastKeyDownTime = null;
    }
    
    /**
     * Handle mouse movement - track velocity
     */
    function handleMouseMove(event) {
        const now = Date.now();
        
        // Throttle mouse tracking for performance
        if (now - mouseThrottle < MOUSE_THROTTLE_MS) {
            return;
        }
        mouseThrottle = now;
        
        const movement = {
            x: event.clientX,
            y: event.clientY,
            timestamp: now
        };
        
        mouseMovements.push(movement);
        
        // Log mouse tracking (debug)
        if (mouseMovements.length % 10 === 0) {
            console.log(`🖱️  Mouse tracking: ${mouseMovements.length} movements collected`);
        }
        
        // Limit stored movements to prevent memory issues (keep last 100)
        if (mouseMovements.length > 100) {
            mouseMovements = mouseMovements.slice(-100);
        }
    }
    
    /**
     * Start the interval for sending data periodically
     */
    function startSendInterval() {
        if (sendInterval) {
            clearInterval(sendInterval);
        }
        
        sendInterval = setInterval(() => {
            if (keystrokes.length > 0 || mouseMovements.length > 0) {
                sendBehaviorData();
            }
        }, SEND_INTERVAL_MS);
    }
    
    /**
     * Send behavioral data to backend
     */
    async function sendBehaviorData() {
        const token = localStorage.getItem('access_token');
        
        // Prepare data to send
        
        let loginTime = localStorage.getItem('loginTime');
        if (!loginTime) {
            loginTime = Date.now();
            localStorage.setItem('loginTime', loginTime);
        }
        const sessionDuration = Math.floor((Date.now() - parseInt(loginTime)) / 1000);
        
        const dataToSend = {
            keystrokes: keystrokes.slice(), // Copy array
            mouse_movements: mouseMovements.slice(), // Copy array
            session_duration: sessionDuration
        };
        
        // Debug logging
        console.log(`📊 Sending behavior data: ${dataToSend.keystrokes.length} keystrokes, ${dataToSend.mouse_movements.length} mouse movements`);
        
        // Don't send if no data
        if (dataToSend.keystrokes.length === 0 && dataToSend.mouse_movements.length === 0) {
            return;
        }
        
        try {
            const headers = { 'Content-Type': 'application/json' };
            if (token) {
                headers.Authorization = `Bearer ${token}`;
            }
            const response = await fetch('/api/analyze-behavior', {
                method: 'POST',
                headers,
                body: JSON.stringify(dataToSend)
            });

            // 401 — token is genuinely invalid: clear session and redirect.
            if (response.status === 401) {
                console.warn('Session token invalid. Redirecting to login.');
                cleanup();
                localStorage.removeItem('access_token');
                localStorage.removeItem('user_id');
                localStorage.removeItem('username');
                localStorage.removeItem('role');
                window.location.href = '/login';
                return;
            }

            // 423 — session is LOCKED by risk engine, not invalid. Previously
            // we redirected to /login, which caused a relogin loop (login →
            // locked → logout → login → …). Don't redirect; keep the session.
            //
            // IMPORTANT: 423 responses still carry the full analysis payload
            // (status, risk_score, score_breakdown, reasons, …) — feed it to
            // the UI exactly like a 200 so the breakdown / risk cards update
            // instead of staying at +0. Then pause further polling.
            if (response.status === 423) {
                console.warn('Session locked by risk engine. Behavior sensor paused.');
                let lockedResult = null;
                try { lockedResult = await response.clone().json(); } catch (e) { lockedResult = null; }
                if (lockedResult) {
                    try {
                        window.dispatchEvent(new CustomEvent('behaviorAnalyzed', {
                            detail: {
                                riskScore: lockedResult.risk_score || 0,
                                status: lockedResult.status || 'locked',
                                message: lockedResult.message,
                                requiresMfa: !!lockedResult.requires_mfa,
                                rawData: lockedResult,
                            }
                        }));
                    } catch (e) { /* noop */ }
                }
                keystrokes = [];
                mouseMovements = [];
                if (sendInterval) { clearInterval(sendInterval); sendInterval = null; }
                try {
                    window.dispatchEvent(new CustomEvent('sensorPaused', {
                        detail: { reason: 'session_locked', status: 423, payload: lockedResult }
                    }));
                } catch (e) { /* noop */ }
                return;
            }
            
            const result = await response.json();
            
            // Debug logging for mouse analysis
            if (result.score_breakdown && result.score_breakdown['Mouse Anomaly'] > 0) {
                console.warn(`🔴 MOUSE ANOMALY DETECTED: +${result.score_breakdown['Mouse Anomaly']} risk`);
            }
            
            // Dispatch custom event with results
            const event = new CustomEvent('behaviorAnalyzed', {
                detail: {
                    riskScore: result.risk_score || 0,
                    status: result.status,
                    message: result.message,
                    requiresMfa: result.requires_mfa || false,
                    rawData: result
                }
            });
            window.dispatchEvent(event);
            
            // Calculate and dispatch metrics
            const metrics = calculateMetrics(dataToSend);
            const metricsEvent = new CustomEvent('metricsUpdated', {
                detail: metrics
            });
            window.dispatchEvent(metricsEvent);
            
            // Clear sent data (keep last few for continuity)
            keystrokes = keystrokes.slice(-5);
            mouseMovements = mouseMovements.slice(-10);
            
        } catch (error) {
            console.error('Error sending behavior data:', error);
        }
    }
    
    /**
     * Calculate metrics from collected data
     */
    function calculateMetrics(data) {
        const keystrokes = data.keystrokes || [];
        const mouseMovements = data.mouse_movements || [];
        
        // Calculate typing speed
        let typingSpeed = 0;
        if (keystrokes.length >= 2) {
            const firstKey = keystrokes[0];
            const lastKey = keystrokes[keystrokes.length - 1];
            const totalTime = (lastKey.timestamp - firstKey.timestamp) / 1000; // seconds
            if (totalTime > 0) {
                typingSpeed = keystrokes.length / totalTime;
            }
        }
        
        // Calculate average mouse velocity
        let mouseVelocity = 0;
        if (mouseMovements.length >= 2) {
            let totalDistance = 0;
            let totalTime = 0;
            
            for (let i = 1; i < mouseMovements.length; i++) {
                const prev = mouseMovements[i - 1];
                const curr = mouseMovements[i];
                
                const dx = curr.x - prev.x;
                const dy = curr.y - prev.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                const time = curr.timestamp - prev.timestamp;
                
                totalDistance += distance;
                totalTime += time;
            }
            
            if (totalTime > 0) {
                mouseVelocity = totalDistance / totalTime;
            }
        }
        
        return {
            keystrokeCount: keystrokes.length,
            typingSpeed: typingSpeed,
            mouseCount: mouseMovements.length,
            mouseVelocity: mouseVelocity
        };
    }
    
    /**
     * Cleanup function
     */
    function cleanup() {
        if (sendInterval) {
            clearInterval(sendInterval);
        }
        
        // Send any remaining data
        if (keystrokes.length > 0 || mouseMovements.length > 0) {
            sendBehaviorData();
        }
    }
    
    /**
     * Diagnostic function - expose to global scope for testing
     */
    window.sensorDiagnostics = function() {
        console.log('========== SENSOR DIAGNOSTICS ==========');
        console.log(`✅ Behavioral sensor is running`);
        console.log(`📍 Mouse movements collected: ${mouseMovements.length}`);
        console.log(`🎹 Keystrokes collected: ${keystrokes.length}`);
        console.log(`⏱️  Send interval: ${SEND_INTERVAL_MS}ms`);
        console.log(`🎯 Keystroke threshold: ${KEYSTROKE_THRESHOLD}`);
        
        if (mouseMovements.length > 0) {
            const lastMouse = mouseMovements[mouseMovements.length - 1];
            const firstMouse = mouseMovements[0];
            console.log(`\n🖱️  Last mouse position: (${lastMouse.x}, ${lastMouse.y})`);
            console.log(`📊 First to last: ${mouseMovements.length} movements`);
            console.log(`⏰ Time span: ${lastMouse.timestamp - firstMouse.timestamp}ms`);
        } else {
            console.log(`\n⚠️  NO MOUSE MOVEMENTS DETECTED - Try moving your mouse!`);
        }
        
        if (keystrokes.length > 0) {
            console.log(`\n🎹 Sample keystrokes:`, keystrokes.slice(0, 3));
        }
        
        console.log('========== END DIAGNOSTICS ==========');
        return {
            mouseCount: mouseMovements.length,
            keystrokeCount: keystrokes.length,
            lastMousePosition: mouseMovements.length > 0 ? 
                { x: mouseMovements[mouseMovements.length - 1].x, 
                  y: mouseMovements[mouseMovements.length - 1].y } : null
        };
    };
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
})();
