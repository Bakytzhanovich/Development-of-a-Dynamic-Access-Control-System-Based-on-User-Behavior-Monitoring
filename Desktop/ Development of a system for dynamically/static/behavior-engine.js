/**
 * BehaviorEngine — advanced client-side behavioral biometrics.
 *
 * Adds a layer of cybersecurity-oriented behavior analysis on top of the
 * existing sensor.js pipeline WITHOUT changing any backend logic. The engine:
 *
 *   1. Computes per-module trust / risk scores (typing, mouse, click,
 *      paste, focus, session, device, navigation, abuse, travel).
 *   2. Emits a `behaviorAnomaly` CustomEvent for the UI.
 *   3. Reports each anomaly to the existing `/api/security-event` endpoint
 *      so it shows up in the admin AccessLog table.
 *
 * Public API:
 *   BehaviorEngine.init({ userId, role, page, autoLog })
 *   BehaviorEngine.getState()
 *   BehaviorEngine.report(category, message, risk)
 *   BehaviorEngine.resetBaseline()
 *
 * Events:
 *   window.addEventListener('behaviorAnomaly', e => e.detail)
 *   window.addEventListener('behaviorStateChange', e => e.detail)
 */
(function () {
    'use strict';

    if (window.BehaviorEngine) return; // singleton

    // --- constants ---
    const STORAGE_KEYS = {
        deviceFp: 'bx_device_fingerprint',
        lastCountry: 'bx_last_country',
        startTime: 'bx_engine_start',
        navHistory: 'bx_nav_history',
        baseline: 'bx_typing_baseline',
    };

    const CATEGORY = {
        TYPING: 'typing_anomaly',
        PASTE: 'paste_detected',
        MOUSE: 'robotic_mouse',
        CLICK: 'click_automation',
        FOCUS: 'tab_switching',
        SESSION: 'session_anomaly',
        DEVICE: 'device_change',
        NAVIGATION: 'navigation_anomaly',
        ABUSE: 'resource_abuse',
        TRAVEL: 'impossible_travel',
    };

    const SEVERITY = {
        INFO: 'info',
        LOW: 'low',
        MEDIUM: 'medium',
        HIGH: 'high',
        CRITICAL: 'critical',
    };

    // --- engine state ---
    const state = {
        userId: null,
        role: null,
        page: null,
        autoLog: true,
        startedAt: Date.now(),

        // per-module scores (0-100, higher = more anomalous)
        scores: {
            typing: 0,
            mouse: 0,
            click: 0,
            paste: 0,
            focus: 0,
            session: 0,
            device: 0,
            navigation: 0,
            abuse: 0,
            travel: 0,
        },

        // per-module trust scores (0-100, higher = more trustworthy)
        trust: {
            typing: 100,
            mouse: 100,
            click: 100,
        },

        // aggregated
        trustScore: 100,
        riskScore: 0,
        threatLevel: 'Low',
        accessDecision: 'Full access',

        // recent anomaly feed (newest first)
        feed: [],
        threatCounts: {},

        // device fingerprint
        deviceFp: null,
        deviceFpDelta: null,
    };

    // ============================================================
    // Utilities
    // ============================================================

    function now() { return Date.now(); }

    function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

    function mean(arr) {
        if (!arr.length) return 0;
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    function stdev(arr) {
        if (arr.length < 2) return 0;
        const m = mean(arr);
        const variance = arr.reduce((s, x) => s + Math.pow(x - m, 2), 0) / arr.length;
        return Math.sqrt(variance);
    }

    function coefficientOfVariation(arr) {
        const m = mean(arr);
        if (m === 0) return 0;
        return stdev(arr) / m;
    }

    function hashString(str) {
        // FNV-1a 32-bit
        let h = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
        }
        return ('00000000' + h.toString(16)).slice(-8);
    }

    function authHeader() {
        const token = localStorage.getItem('access_token');
        const h = { 'Content-Type': 'application/json' };
        if (token) h.Authorization = `Bearer ${token}`;
        return h;
    }

    function dispatch(name, detail) {
        try {
            window.dispatchEvent(new CustomEvent(name, { detail }));
        } catch (e) { /* noop */ }
    }

    // ============================================================
    // Risk / threat aggregation
    // ============================================================

    function recomputeAggregate() {
        const s = state.scores;
        // Weighted blend; mouse/typing carry most weight, then critical signals
        const weighted =
            s.typing * 0.18 +
            s.mouse * 0.18 +
            s.click * 0.10 +
            s.paste * 0.08 +
            s.focus * 0.08 +
            s.session * 0.10 +
            s.device * 0.10 +
            s.navigation * 0.06 +
            s.abuse * 0.06 +
            s.travel * 0.06;

        state.riskScore = clamp(weighted, 0, 100);
        state.trustScore = clamp(100 - state.riskScore, 0, 100);

        if (state.riskScore >= 80) {
            state.threatLevel = 'Critical';
            state.accessDecision = 'Session blocked';
        } else if (state.riskScore >= 60) {
            state.threatLevel = 'High';
            state.accessDecision = 'Step-up authentication';
        } else if (state.riskScore >= 35) {
            state.threatLevel = 'Medium';
            state.accessDecision = 'Limited access';
        } else {
            state.threatLevel = 'Low';
            state.accessDecision = 'Full access';
        }

        dispatch('behaviorStateChange', snapshot());

        // Hand the Critical state off to the server so the lock becomes
        // authoritative (works even if the client refuses to react to it).
        if (state.threatLevel === 'Critical') {
            maybeEscalate();
        }
    }

    // ============================================================
    // Server-side escalation
    // ============================================================
    // When local aggregate risk hits Critical, ask the backend to lock the
    // session via /api/escalate. The backend response is shaped like a
    // /api/analyze-behavior payload so the dashboard can run it through
    // applyDecision() and trigger the existing 5-second kill-switch.
    let escalating = false;
    let lastEscalationAt = 0;
    const ESCALATION_COOLDOWN_MS = 30000;

    async function maybeEscalate() {
        if (!state.autoLog) return;
        if (escalating) return;
        if (now() - lastEscalationAt < ESCALATION_COOLDOWN_MS) return;
        escalating = true;
        try {
            // Take the top 3 distinct categories by score…
            const topCategories = Object.entries(state.scores)
                .filter(([, v]) => v > 0)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 3)
                .map(([cat]) => cat);

            // …and the freshest matching reasons from the anomaly feed.
            const reasons = [];
            const seenCats = new Set();
            for (const item of state.feed) {
                if (reasons.length >= 3) break;
                if (item && item.message && !seenCats.has(item.category)) {
                    reasons.push(item.message);
                    seenCats.add(item.category);
                }
            }
            if (reasons.length === 0) {
                reasons.push('Aggregate behavioral risk ' + Math.round(state.riskScore));
            }

            const res = await fetch('/api/escalate', {
                method: 'POST',
                headers: authHeader(),
                keepalive: true,
                body: JSON.stringify({
                    risk_score: state.riskScore,
                    reasons: reasons,
                    top_categories: topCategories,
                    threat_level: state.threatLevel,
                }),
            });

            const data = await res.json().catch(() => null);
            if (data) {
                lastEscalationAt = now();
                // Let the dashboard pipe this through its existing
                // applyDecision() flow (paints the cards red, starts the
                // 5-second kill-switch, locks the UI).
                dispatch('behaviorCriticalEscalation', data);
            }
        } catch (e) {
            // Network failure — try again on the next Critical tick.
        } finally {
            escalating = false;
        }
    }

    function resetEscalation() {
        lastEscalationAt = 0;
        escalating = false;
    }

    function snapshot() {
        return {
            userId: state.userId,
            role: state.role,
            scores: Object.assign({}, state.scores),
            trust: Object.assign({}, state.trust),
            riskScore: state.riskScore,
            trustScore: state.trustScore,
            threatLevel: state.threatLevel,
            accessDecision: state.accessDecision,
            feed: state.feed.slice(0, 50),
            threatCounts: Object.assign({}, state.threatCounts),
            deviceFp: state.deviceFp,
            deviceFpDelta: state.deviceFpDelta,
        };
    }

    // ============================================================
    // Anomaly reporting
    // ============================================================

    // Per-category cooldown so that fast-firing detectors (e.g. click spam,
    // tab switching) don't post 4-5 identical anomalies to the feed within
    // the same second. We let each category fire once every REPORT_COOLDOWN
    // milliseconds; critical-severity events ignore the cooldown so real
    // attacks are never silenced.
    const REPORT_COOLDOWN_MS = 4000;
    const lastReportAt = {};

    function report(category, message, riskDelta, severity, extra) {
        severity = severity || (riskDelta >= 25 ? SEVERITY.CRITICAL
            : riskDelta >= 15 ? SEVERITY.HIGH
            : riskDelta >= 8 ? SEVERITY.MEDIUM
            : SEVERITY.LOW);

        const tNow = now();
        const last = lastReportAt[category] || 0;
        if (severity !== SEVERITY.CRITICAL && tNow - last < REPORT_COOLDOWN_MS) {
            // Quietly drop the duplicate — score state was already updated by
            // the caller, so the dashboard still reflects the new risk.
            return null;
        }
        lastReportAt[category] = tNow;

        const item = {
            id: 'bx_' + tNow + '_' + Math.floor(Math.random() * 9999),
            ts: new Date().toISOString(),
            category,
            severity,
            message,
            risk: Math.round(riskDelta || 0),
            extra: extra || null,
        };

        state.feed.unshift(item);
        if (state.feed.length > 200) state.feed.pop();

        state.threatCounts[category] = (state.threatCounts[category] || 0) + 1;

        dispatch('behaviorAnomaly', item);

        if (state.autoLog) {
            try {
                fetch('/api/security-event', {
                    method: 'POST',
                    headers: authHeader(),
                    keepalive: true,
                    body: JSON.stringify({
                        action: 'bx_' + category,
                        message: '[BehaviorEngine] ' + message,
                        risk_score: clamp(Math.round(state.riskScore || riskDelta || 0), 0, 100),
                    }),
                }).catch(() => { /* offline */ });
            } catch (e) { /* noop */ }
        }

        return item;
    }

    // ============================================================
    // MODULE 1 — Typing Rhythm
    // ============================================================
    const typingModule = (function () {
        const flightTimes = [];
        const dwellTimes = [];
        let lastDown = null;
        let lastUp = null;
        let backspaceCount = 0;
        let totalKeys = 0;
        let lastEvalAt = 0;
        let burstWindow = [];
        let baseline = null;

        try {
            const stored = localStorage.getItem(STORAGE_KEYS.baseline);
            if (stored) baseline = JSON.parse(stored);
        } catch (e) { baseline = null; }

        function onKeyDown(e) {
            const t = now();
            if (lastDown !== null) {
                const flight = t - lastDown;
                if (flight > 30 && flight < 4000) flightTimes.push(flight);
                if (flightTimes.length > 80) flightTimes.shift();
            }
            lastDown = t;

            if (e.key === 'Backspace' || e.key === 'Delete') backspaceCount += 1;
            totalKeys += 1;

            burstWindow.push(t);
            const windowStart = t - 2000;
            while (burstWindow.length && burstWindow[0] < windowStart) burstWindow.shift();

            if (totalKeys - lastEvalAt >= 6) {
                lastEvalAt = totalKeys;
                evaluate();
            }
        }

        function onKeyUp(e) {
            const t = now();
            if (lastDown) {
                const dwell = t - lastDown;
                if (dwell > 10 && dwell < 600) dwellTimes.push(dwell);
                if (dwellTimes.length > 80) dwellTimes.shift();
            }
            lastUp = t;
        }

        function evaluate() {
            if (flightTimes.length < 6) return;

            const fCV = coefficientOfVariation(flightTimes);
            const fMean = mean(flightTimes);
            const dCV = dwellTimes.length >= 4 ? coefficientOfVariation(dwellTimes) : 0.4;
            const burst = burstWindow.length; // keys in last 2s
            const backspaceRatio = totalKeys > 0 ? backspaceCount / totalKeys : 0;

            let score = 0;
            const reasons = [];

            // Robotic / bot-like — extremely uniform timing
            if (fCV < 0.08 && flightTimes.length >= 10) {
                score += 35;
                reasons.push('Uniform key intervals (CV ' + fCV.toFixed(2) + ')');
            } else if (fCV < 0.18 && flightTimes.length >= 10) {
                score += 18;
                reasons.push('Low typing variance');
            } else if (fCV < 0.35 && flightTimes.length >= 8) {
                // Mild variance — small "engagement" score so the module is
                // visibly active during normal typing instead of staying 0.
                score += 6;
            }

            // Dwell time uniform
            if (dCV > 0 && dCV < 0.1 && dwellTimes.length >= 8) {
                score += 12;
                reasons.push('Uniform key dwell time');
            }

            // Extreme burst — paste-like or scripted entry
            if (burst >= 20) {
                score += 22;
                reasons.push('Burst typing (' + burst + ' keys / 2s)');
            }

            // Excessive backspace — hesitation / unfamiliar credentials
            if (backspaceRatio > 0.25 && totalKeys >= 12) {
                score += 14;
                reasons.push('Excessive backspace (' + Math.round(backspaceRatio * 100) + '%)');
            }

            // Hesitation pattern — long pauses between bursts
            const longPauses = flightTimes.filter(x => x > 1500).length;
            if (longPauses >= 3) {
                score += 8;
                reasons.push('Hesitation pattern');
            }

            // Compare to baseline if available
            if (baseline && baseline.fMean) {
                const dev = Math.abs(fMean - baseline.fMean) / baseline.fMean;
                if (dev > 0.6) {
                    score += 12;
                    reasons.push('Deviation from baseline (' + Math.round(dev * 100) + '%)');
                }
            } else if (flightTimes.length >= 25) {
                // Lock baseline once we have enough data and behavior looked normal
                if (score < 10) {
                    baseline = { fMean: fMean, dMean: mean(dwellTimes), at: now() };
                    try { localStorage.setItem(STORAGE_KEYS.baseline, JSON.stringify(baseline)); } catch (e) { /* noop */ }
                }
            }

            score = clamp(score, 0, 100);
            state.scores.typing = score;
            state.trust.typing = clamp(100 - score, 0, 100);

            if (reasons.length && score >= 18) {
                report(CATEGORY.TYPING, 'Suspicious typing rhythm: ' + reasons.join('; '), score * 0.4, undefined, {
                    fCV, dCV, burst, backspaceRatio: +backspaceRatio.toFixed(2),
                });
            }
            recomputeAggregate();
        }

        function onPaste(e) {
            const target = e.target;
            const fieldName = (target && (target.name || target.id || target.placeholder || target.type) || 'field').toString().toLowerCase();
            const isPassword = fieldName.indexOf('pass') >= 0 || (target && target.type === 'password');
            const delta = isPassword ? 25 : 12;
            state.scores.paste = clamp(state.scores.paste + delta, 0, 100);
            const msg = isPassword
                ? 'Password pasted instead of typed'
                : 'Field "' + fieldName + '" was pasted instead of typed';
            report(CATEGORY.PASTE, msg, delta, isPassword ? SEVERITY.HIGH : SEVERITY.MEDIUM, { field: fieldName });
            recomputeAggregate();
        }

        function reset() {
            flightTimes.length = 0;
            dwellTimes.length = 0;
            burstWindow.length = 0;
            backspaceCount = 0;
            totalKeys = 0;
            lastEvalAt = 0;
            state.scores.typing = 0;
            state.scores.paste = 0;
            state.trust.typing = 100;
        }

        return { onKeyDown, onKeyUp, onPaste, reset };
    })();

    // ============================================================
    // MODULE 2 — Mouse Trajectory
    // ============================================================
    const mouseModule = (function () {
        const samples = []; // {x, y, t}
        let lastEvalAt = 0;
        let throttle = 0;
        // "Engagement" gauge so the module is visibly active during normal
        // mouse use, not only when an anomaly fires. Capped low so it can't
        // be confused with a real anomaly score.
        let activity = 0;
        const ACTIVITY_CAP = 12;

        function onMove(e) {
            const t = now();
            if (t - throttle < 12) return;
            throttle = t;
            samples.push({ x: e.clientX, y: e.clientY, t });
            if (samples.length > 240) samples.shift();

            // Each accepted sample bumps engagement; cap keeps it subtle.
            activity = clamp(activity + 0.7, 0, ACTIVITY_CAP);
            // Reflect immediately so the UI reacts on the very first moves
            // (the heavier evaluator only runs every ~30 samples).
            const floor = Math.round(activity);
            if (floor > state.scores.mouse) {
                state.scores.mouse = floor;
                state.trust.mouse = clamp(100 - floor, 0, 100);
                recomputeAggregate();
            }

            if (samples.length - lastEvalAt >= 30) {
                lastEvalAt = samples.length;
                evaluate();
            }
        }

        function evaluate() {
            if (samples.length < 20) return;

            // Compute segment velocities, angles, accelerations
            const vels = [];
            const angles = [];
            let jumps = 0;
            let straight = 0;
            let totalDist = 0;
            let totalTime = 0;

            for (let i = 1; i < samples.length; i++) {
                const a = samples[i - 1];
                const b = samples[i];
                const dx = b.x - a.x;
                const dy = b.y - a.y;
                const dt = b.t - a.t || 1;
                const dist = Math.hypot(dx, dy);
                const v = dist / dt;
                vels.push(v);
                totalDist += dist;
                totalTime += dt;

                if (dist > 280 && dt < 40) jumps += 1; // teleport

                const ang = Math.atan2(dy, dx);
                angles.push(ang);
            }

            // Straight-line robot: consecutive angles nearly identical
            let nearlySameAngle = 0;
            for (let i = 1; i < angles.length; i++) {
                if (Math.abs(angles[i] - angles[i - 1]) < 0.03) nearlySameAngle += 1;
            }
            if (nearlySameAngle / angles.length > 0.7) straight = 1;

            // Acceleration variance — humans accelerate non-uniformly
            const accels = [];
            for (let i = 1; i < vels.length; i++) {
                accels.push(Math.abs(vels[i] - vels[i - 1]));
            }
            const accCV = coefficientOfVariation(accels);
            const velCV = coefficientOfVariation(vels);

            let score = 0;
            const reasons = [];

            if (straight) {
                score += 28;
                reasons.push('Robotic straight-line trajectory');
            }
            if (velCV < 0.12 && vels.length >= 30) {
                score += 18;
                reasons.push('Unnatural velocity uniformity');
            } else if (velCV < 0.25 && vels.length >= 25) {
                // Engagement indicator — slight uniformity, not anomalous.
                score += 4;
            }
            if (accCV < 0.18 && accels.length >= 25) {
                score += 12;
                reasons.push('Smooth machine-like acceleration');
            }
            if (jumps >= 3) {
                score += 22;
                reasons.push('Cursor teleport jumps (' + jumps + ')');
            } else if (jumps >= 1) {
                score += 3; // single sharp move — minor engagement signal
            }

            // Inactivity vs burst — if a lot of samples bunched in time
            const span = samples[samples.length - 1].t - samples[0].t;
            if (span > 0 && samples.length / (span / 1000) > 80) {
                score += 8;
                reasons.push('Movement burst rate');
            }

            score = clamp(score, 0, 100);
            // Combine the anomaly score with the engagement floor so the
            // module shows a visible non-zero value during normal motion.
            score = Math.max(score, Math.round(activity));
            state.scores.mouse = score;
            state.trust.mouse = clamp(100 - score, 0, 100);

            if (score >= 22 && reasons.length) {
                report(CATEGORY.MOUSE, 'Robotic mouse pattern: ' + reasons.join('; '), score * 0.45, undefined, {
                    velCV: +velCV.toFixed(3), accCV: +accCV.toFixed(3), jumps, straight,
                });
            }
            recomputeAggregate();
        }

        function decay() {
            // Fade engagement when the user stops moving so the module
            // visibly relaxes back to 0 instead of sticking at 12.
            if (activity > 0) activity = clamp(activity - 3, 0, ACTIVITY_CAP);
            // Mirror into the score, but only while the score is in the
            // engagement band — anomaly-driven scores stay until evaluate()
            // re-runs.
            if (state.scores.mouse > 0 && state.scores.mouse <= ACTIVITY_CAP) {
                const next = clamp(state.scores.mouse - 1.5, 0, 100);
                state.scores.mouse = next;
                state.trust.mouse = clamp(100 - next, 0, 100);
            }
        }

        function reset() {
            samples.length = 0;
            lastEvalAt = 0;
            activity = 0;
            state.scores.mouse = 0;
            state.trust.mouse = 100;
        }

        return { onMove, decay, reset };
    })();

    // ============================================================
    // MODULE 3 — Click Rhythm
    // ============================================================
    const clickModule = (function () {
        const intervals = [];
        const times = [];
        let lastClickAt = null;
        let rapidWindow = [];

        function onClick(e) {
            const t = now();
            if (lastClickAt) {
                const dt = t - lastClickAt;
                if (dt < 3000) intervals.push(dt);
                if (intervals.length > 60) intervals.shift();
            }
            lastClickAt = t;
            times.push(t);

            rapidWindow.push(t);
            const wStart = t - 1000;
            while (rapidWindow.length && rapidWindow[0] < wStart) rapidWindow.shift();

            evaluate();
        }

        function evaluate() {
            let score = 0;
            const reasons = [];

            if (rapidWindow.length >= 6) {
                score += 30;
                reasons.push('Spam clicking (' + rapidWindow.length + '/sec)');
            }

            if (intervals.length >= 5) {
                const cv = coefficientOfVariation(intervals);
                if (cv < 0.06) {
                    score += 32;
                    reasons.push('Identical click intervals (CV ' + cv.toFixed(3) + ')');
                } else if (cv < 0.15) {
                    score += 15;
                    reasons.push('Highly regular click cadence');
                } else if (cv < 0.35) {
                    score += 4; // engagement signal — clicks form a pattern
                }
                const minDt = Math.min.apply(null, intervals);
                if (minDt < 60) {
                    score += 12;
                    reasons.push('Sub-human click latency (' + minDt + 'ms)');
                }
            } else if (intervals.length >= 2) {
                // Just a couple clicks — minor activity signal
                score += 2;
            }

            score = clamp(score, 0, 100);
            state.scores.click = score;
            state.trust.click = clamp(100 - score, 0, 100);

            if (score >= 22 && reasons.length) {
                report(CATEGORY.CLICK, 'Automated click pattern: ' + reasons.join('; '), score * 0.4);
            }
            recomputeAggregate();
        }

        function reset() {
            intervals.length = 0;
            times.length = 0;
            rapidWindow.length = 0;
            lastClickAt = null;
            state.scores.click = 0;
            state.trust.click = 100;
        }

        return { onClick, reset };
    })();

    // ============================================================
    // MODULE 4 — Tab / Focus
    // ============================================================
    const focusModule = (function () {
        const switches = [];
        let hiddenSince = null;
        let totalHidden = 0;

        function onVisibility() {
            const t = now();
            if (document.hidden) {
                hiddenSince = t;
                switches.push(t);
                const wStart = t - 60000;
                while (switches.length && switches[0] < wStart) switches.shift();

                // Real users frequently alt-tab while working. Old thresholds
                // (3 / 5 in 60s) were tripped by ordinary multitasking and
                // flooded the timeline. New thresholds match typical SOC
                // tuning — only sustained tab cycling counts.
                if (switches.length >= 15) {
                    bump(20, 'Frequent tab switching (' + switches.length + ' in 60s)', SEVERITY.MEDIUM);
                } else if (switches.length >= 10) {
                    bump(10, 'Repeated tab switching');
                }
            } else if (hiddenSince) {
                const away = t - hiddenSince;
                totalHidden += away;
                hiddenSince = null;
                if (away > 120000) {
                    bump(18, 'Long hidden tab duration (' + Math.round(away / 1000) + 's)', SEVERITY.MEDIUM);
                } else if (away > 30000) {
                    bump(8, 'Tab hidden ' + Math.round(away / 1000) + 's');
                }
            }
            recomputeAggregate();
        }

        function onBlur() {
            const t = now();
            switches.push(t);
            const wStart = t - 60000;
            while (switches.length && switches[0] < wStart) switches.shift();
            if (switches.length >= 12) {
                bump(15, 'Repeated window blur events');
            }
        }

        function bump(delta, msg, sev) {
            state.scores.focus = clamp(state.scores.focus + delta * 0.7, 0, 100);
            report(CATEGORY.FOCUS, msg, delta, sev);
        }

        function decay() {
            // gradual fade so it doesn't stay at 100 forever
            state.scores.focus = clamp(state.scores.focus - 1, 0, 100);
        }

        function reset() {
            switches.length = 0;
            hiddenSince = null;
            totalHidden = 0;
            state.scores.focus = 0;
        }

        return { onVisibility, onBlur, decay, reset };
    })();

    // ============================================================
    // MODULE 5 — Session Activity
    // ============================================================
    const sessionModule = (function () {
        let lastActivity = now();
        let activityCount = 0;
        let bursts = 0;
        let idleReported = false;

        function ping() {
            const t = now();
            const idle = t - lastActivity;
            activityCount += 1;
            lastActivity = t;
            if (idle < 25 && activityCount > 50) {
                bursts += 1;
                if (bursts === 30 || bursts === 100) {
                    state.scores.session = clamp(state.scores.session + 14, 0, 100);
                    report(CATEGORY.SESSION, 'Hyperactive interaction burst (' + bursts + ' rapid events)', 12);
                    recomputeAggregate();
                }
            }
            if (idle > 5 * 60 * 1000 && !idleReported) {
                idleReported = true;
                state.scores.session = clamp(state.scores.session + 10, 0, 100);
                report(CATEGORY.SESSION, 'User returned after long idle (' + Math.round(idle / 1000) + 's)', 10);
                recomputeAggregate();
            }
        }

        function tick() {
            // periodic decay
            state.scores.session = clamp(state.scores.session - 0.4, 0, 100);
        }

        function reset() {
            lastActivity = now();
            activityCount = 0;
            bursts = 0;
            idleReported = false;
            state.scores.session = 0;
        }

        return { ping, tick, reset };
    })();

    // ============================================================
    // MODULE 6 — Device Fingerprint
    // ============================================================
    const deviceModule = (function () {
        function compute() {
            try {
                const parts = [
                    navigator.userAgent,
                    navigator.language,
                    navigator.languages ? navigator.languages.join(',') : '',
                    navigator.platform,
                    navigator.hardwareConcurrency || 0,
                    navigator.deviceMemory || 0,
                    screen.width + 'x' + screen.height,
                    screen.colorDepth,
                    Intl.DateTimeFormat().resolvedOptions().timeZone,
                    new Date().getTimezoneOffset(),
                ];
                const raw = parts.join('|');
                return {
                    hash: hashString(raw),
                    raw,
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    language: navigator.language,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    screen: screen.width + 'x' + screen.height,
                    cores: navigator.hardwareConcurrency || 0,
                };
            } catch (e) {
                return { hash: 'unknown', raw: '' };
            }
        }

        function check() {
            const fp = compute();
            state.deviceFp = fp;
            let stored = null;
            try { stored = localStorage.getItem(STORAGE_KEYS.deviceFp); } catch (e) { /* noop */ }

            if (!stored) {
                try { localStorage.setItem(STORAGE_KEYS.deviceFp, fp.hash); } catch (e) { /* noop */ }
                state.deviceFpDelta = null;
                return fp;
            }

            if (stored !== fp.hash) {
                state.deviceFpDelta = { from: stored, to: fp.hash };
                state.scores.device = 65;
                report(CATEGORY.DEVICE,
                    'Device fingerprint mismatch (was ' + stored + ', now ' + fp.hash + ')',
                    35, SEVERITY.HIGH, fp);
                try { localStorage.setItem(STORAGE_KEYS.deviceFp, fp.hash); } catch (e) { /* noop */ }
                recomputeAggregate();
            } else {
                state.scores.device = 0;
            }
            return fp;
        }

        function reset() {
            try { localStorage.removeItem(STORAGE_KEYS.deviceFp); } catch (e) { /* noop */ }
            state.scores.device = 0;
            state.deviceFpDelta = null;
        }

        return { compute, check, reset };
    })();

    // ============================================================
    // MODULE 7 — Navigation
    // ============================================================
    const navigationModule = (function () {
        function record() {
            const path = window.location.pathname;
            let history = [];
            try {
                history = JSON.parse(localStorage.getItem(STORAGE_KEYS.navHistory) || '[]');
            } catch (e) { history = []; }
            history.push({ path, ts: now() });
            if (history.length > 50) history = history.slice(-50);
            try { localStorage.setItem(STORAGE_KEYS.navHistory, JSON.stringify(history)); } catch (e) { /* noop */ }

            // Privilege abuse: non-admin user landing on /admin/* would be 403 server-side
            // but we flag the *attempt*.
            const role = state.role || 'employee';
            if (path.indexOf('/admin') === 0 && role !== 'admin') {
                state.scores.navigation = clamp(state.scores.navigation + 35, 0, 100);
                report(CATEGORY.NAVIGATION,
                    'Privilege escalation attempt by role "' + role + '" → ' + path,
                    30, SEVERITY.HIGH, { path, role });
                recomputeAggregate();
            }

            // Rapid navigation: many distinct paths in 30s
            const recent = history.filter(h => now() - h.ts < 30000);
            const distinct = new Set(recent.map(h => h.path));
            if (distinct.size >= 5) {
                state.scores.navigation = clamp(state.scores.navigation + 12, 0, 100);
                report(CATEGORY.NAVIGATION, 'Rapid navigation across ' + distinct.size + ' routes', 12);
                recomputeAggregate();
            }
        }

        function reset() {
            try { localStorage.removeItem(STORAGE_KEYS.navHistory); } catch (e) { /* noop */ }
            state.scores.navigation = 0;
        }

        return { record, reset };
    })();

    // ============================================================
    // MODULE 8 — Sensitive Resource Abuse
    // ============================================================
    const abuseModule = (function () {
        const hits = [];

        function record(resource) {
            const t = now();
            hits.push({ resource, t });
            while (hits.length && hits[0].t < t - 60000) hits.shift();

            const lastMinute = hits.length;
            if (lastMinute >= 12) {
                state.scores.abuse = clamp(state.scores.abuse + 22, 0, 100);
                report(CATEGORY.ABUSE,
                    'Excessive protected-resource requests (' + lastMinute + '/min)',
                    20, SEVERITY.HIGH, { count: lastMinute });
                recomputeAggregate();
            } else if (lastMinute >= 6) {
                state.scores.abuse = clamp(state.scores.abuse + 8, 0, 100);
                report(CATEGORY.ABUSE,
                    'Elevated sensitive-data request rate (' + lastMinute + '/min)', 8);
                recomputeAggregate();
            }
        }

        function reset() { hits.length = 0; state.scores.abuse = 0; }

        return { record, reset };
    })();

    // ============================================================
    // MODULE 9 — Impossible Travel (mock)
    // ============================================================
    const travelModule = (function () {
        // Geo-IP mock. We previously picked the country randomly from a hash
        // of the user id, which produced absurd output (timezone Asia/Almaty
        // but country = "Russia"). Now the "current" country is derived from
        // the browser's IANA timezone, which is what a real Geo-IP service
        // would return for a local user. Hash-based picking is only used as
        // a fallback when the timezone is unknown.
        const POOL = [
            { country: 'Kazakhstan', code: 'KZ' },
            { country: 'Russia', code: 'RU' },
            { country: 'Germany', code: 'DE' },
            { country: 'United States', code: 'US' },
            { country: 'Singapore', code: 'SG' },
            { country: 'United Kingdom', code: 'GB' },
            { country: 'Turkey', code: 'TR' },
            { country: 'China', code: 'CN' },
        ];

        // Coarse timezone → country mapping. Covers the locations we care
        // about for the demo; anything else falls back to the hash pick.
        const TZ_COUNTRY = {
            'Asia/Almaty': { country: 'Kazakhstan', code: 'KZ' },
            'Asia/Aqtobe': { country: 'Kazakhstan', code: 'KZ' },
            'Asia/Atyrau': { country: 'Kazakhstan', code: 'KZ' },
            'Asia/Qyzylorda': { country: 'Kazakhstan', code: 'KZ' },
            'Asia/Oral': { country: 'Kazakhstan', code: 'KZ' },
            'Europe/Moscow': { country: 'Russia', code: 'RU' },
            'Europe/Samara': { country: 'Russia', code: 'RU' },
            'Asia/Yekaterinburg': { country: 'Russia', code: 'RU' },
            'Asia/Novosibirsk': { country: 'Russia', code: 'RU' },
            'Europe/Berlin': { country: 'Germany', code: 'DE' },
            'America/New_York': { country: 'United States', code: 'US' },
            'America/Los_Angeles': { country: 'United States', code: 'US' },
            'America/Chicago': { country: 'United States', code: 'US' },
            'Asia/Singapore': { country: 'Singapore', code: 'SG' },
            'Europe/London': { country: 'United Kingdom', code: 'GB' },
            'Europe/Istanbul': { country: 'Turkey', code: 'TR' },
            'Asia/Shanghai': { country: 'China', code: 'CN' },
            'Asia/Hong_Kong': { country: 'China', code: 'CN' },
        };

        function pickFromHash(hash) {
            let n = 0;
            for (let i = 0; i < hash.length; i++) n = (n * 31 + hash.charCodeAt(i)) >>> 0;
            return POOL[n % POOL.length];
        }

        function detectCountry() {
            try {
                const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                if (tz && TZ_COUNTRY[tz]) return TZ_COUNTRY[tz];
            } catch (e) { /* noop */ }
            return null;
        }

        function check(ip) {
            ip = ip || ('mock-' + (state.userId || 'u'));
            // Prefer real timezone-based country; only roll the dice if the
            // browser doesn't tell us where it is.
            const current = detectCountry() || pickFromHash(hashString(ip + '|' + (state.deviceFp ? state.deviceFp.hash : '')));
            let last = null;
            try { last = JSON.parse(localStorage.getItem(STORAGE_KEYS.lastCountry) || 'null'); } catch (e) { last = null; }

            if (last && last.code !== current.code) {
                const elapsedHours = (now() - (last.ts || 0)) / 3600000;
                // Approx min hours required between two countries
                const requiredHours = 3;
                if (elapsedHours < requiredHours) {
                    state.scores.travel = 70;
                    report(CATEGORY.TRAVEL,
                        'Impossible travel detected: ' + last.country + ' → ' + current.country +
                        ' in ' + elapsedHours.toFixed(2) + 'h',
                        45, SEVERITY.CRITICAL, { from: last, to: current });
                } else {
                    state.scores.travel = 25;
                    report(CATEGORY.TRAVEL,
                        'New geo-location: ' + last.country + ' → ' + current.country,
                        18, SEVERITY.MEDIUM, { from: last, to: current });
                }
                recomputeAggregate();
            }
            try {
                localStorage.setItem(STORAGE_KEYS.lastCountry,
                    JSON.stringify({ country: current.country, code: current.code, ts: now() }));
            } catch (e) { /* noop */ }
            return current;
        }

        function reset() {
            try { localStorage.removeItem(STORAGE_KEYS.lastCountry); } catch (e) { /* noop */ }
            state.scores.travel = 0;
        }

        return { check, reset };
    })();

    // ============================================================
    // Engine init / public API
    // ============================================================
    let attached = false;
    let tickTimer = null;

    function init(opts) {
        opts = opts || {};
        state.userId = opts.userId || localStorage.getItem('user_id') || null;
        state.role = opts.role || localStorage.getItem('role') || 'employee';
        state.page = opts.page || window.location.pathname;
        state.autoLog = opts.autoLog !== false;
        state.startedAt = now();

        if (attached) return snapshot();
        attached = true;

        // Listeners
        document.addEventListener('keydown', (e) => {
            typingModule.onKeyDown(e);
            sessionModule.ping();
        }, true);
        document.addEventListener('keyup', (e) => {
            typingModule.onKeyUp(e);
        }, true);
        document.addEventListener('paste', (e) => {
            typingModule.onPaste(e);
            sessionModule.ping();
        }, true);
        document.addEventListener('mousemove', (e) => {
            mouseModule.onMove(e);
            // Note: we deliberately DO NOT call sessionModule.ping() here.
            // mousemove fires every ~12 ms (throttled), which would always
            // beat the burst detector's "idle < 25ms && count > 50"
            // threshold and produce false-positive "Hyperactive interaction
            // burst" events for normal mouse motion. Discrete actions
            // (keydown / paste / click) are sufficient signal for that
            // module.
        }, true);
        document.addEventListener('click', (e) => {
            clickModule.onClick(e);
            sessionModule.ping();
        }, true);
        document.addEventListener('visibilitychange', focusModule.onVisibility, true);
        window.addEventListener('blur', focusModule.onBlur, true);

        // Initial passive checks
        deviceModule.check();
        navigationModule.record();
        travelModule.check();

        // Tick — gradual decay so scores don't stick at max forever after a
        // single event. Without this, paste / focus / abuse / mouse scores
        // would remain at 100 for the rest of the session.
        tickTimer = setInterval(() => {
            focusModule.decay();
            sessionModule.tick();
            mouseModule.decay();
            // Paste & abuse have no dedicated module decay function, so we
            // bleed them off here directly. Half-life ~32s.
            state.scores.paste = clamp(state.scores.paste - 1.5, 0, 100);
            state.scores.abuse = clamp(state.scores.abuse - 1.5, 0, 100);
            // Click score should also gradually fade when no clicks happen.
            state.scores.click = clamp(state.scores.click - 2, 0, 100);
            recomputeAggregate();
        }, 4000);

        recomputeAggregate();
        return snapshot();
    }

    function resetBaseline() {
        typingModule.reset();
        mouseModule.reset();
        clickModule.reset();
        focusModule.reset();
        sessionModule.reset();
        deviceModule.reset();
        navigationModule.reset();
        abuseModule.reset();
        travelModule.reset();
        resetEscalation();
        state.feed.length = 0;
        state.threatCounts = {};
        try { localStorage.removeItem(STORAGE_KEYS.baseline); } catch (e) { /* noop */ }
        recomputeAggregate();
    }

    // ============================================================
    // Public API — demo / simulation triggers for live presentation
    // ============================================================
    function simulate(category) {
        const c = (category || '').toLowerCase();
        switch (c) {
            case 'typing':
            case 'typing_anomaly':
                state.scores.typing = clamp(state.scores.typing + 45, 0, 100);
                report(CATEGORY.TYPING,
                    'Demo: bot-like typing rhythm — uniform key intervals (CV 0.04), burst typing (24 keys / 2s)',
                    40, SEVERITY.HIGH, { demo: true });
                break;
            case 'paste':
            case 'paste_detected':
                state.scores.paste = clamp(state.scores.paste + 30, 0, 100);
                report(CATEGORY.PASTE,
                    'Demo: password pasted instead of typed',
                    25, SEVERITY.HIGH, { demo: true, field: 'password' });
                break;
            case 'mouse':
            case 'robotic_mouse':
                state.scores.mouse = clamp(state.scores.mouse + 55, 0, 100);
                report(CATEGORY.MOUSE,
                    'Demo: robotic mouse pattern — straight-line trajectory, uniform velocity, teleport jumps (4)',
                    45, SEVERITY.HIGH, { demo: true, velCV: 0.05, accCV: 0.08, jumps: 4 });
                break;
            case 'click':
            case 'click_automation':
                state.scores.click = clamp(state.scores.click + 50, 0, 100);
                report(CATEGORY.CLICK,
                    'Demo: automated click pattern — identical 50ms intervals, sub-human latency',
                    40, SEVERITY.HIGH, { demo: true });
                break;
            case 'focus':
            case 'tab_switching':
                state.scores.focus = clamp(state.scores.focus + 25, 0, 100);
                report(CATEGORY.FOCUS,
                    'Demo: frequent tab switching (6 switches in 60s)',
                    20, SEVERITY.MEDIUM, { demo: true });
                break;
            case 'session':
            case 'session_anomaly':
                state.scores.session = clamp(state.scores.session + 25, 0, 100);
                report(CATEGORY.SESSION,
                    'Demo: hyperactive interaction burst — 100 rapid events',
                    20, SEVERITY.MEDIUM, { demo: true });
                break;
            case 'device':
            case 'device_change':
                // Force re-check by clearing stored fingerprint, then re-run check.
                try { localStorage.removeItem(STORAGE_KEYS.deviceFp); } catch (e) { /* noop */ }
                // Pre-store a fake "previous" fingerprint so the next check trips.
                try { localStorage.setItem(STORAGE_KEYS.deviceFp, 'demoprev'); } catch (e) { /* noop */ }
                deviceModule.check();
                break;
            case 'navigation':
            case 'navigation_anomaly':
                state.scores.navigation = clamp(state.scores.navigation + 40, 0, 100);
                report(CATEGORY.NAVIGATION,
                    'Demo: rapid navigation across 6 routes in 25s',
                    30, SEVERITY.HIGH, { demo: true });
                break;
            case 'abuse':
            case 'resource_abuse':
                state.scores.abuse = clamp(state.scores.abuse + 40, 0, 100);
                report(CATEGORY.ABUSE,
                    'Demo: excessive protected-resource requests (14 / minute)',
                    30, SEVERITY.HIGH, { demo: true, count: 14 });
                break;
            case 'travel':
            case 'impossible_travel':
                // Force impossible-travel by reseting last country to "remote".
                try {
                    localStorage.setItem(STORAGE_KEYS.lastCountry, JSON.stringify({
                        country: 'Germany', code: 'DE',
                        ts: Date.now() - 5 * 60 * 1000, // 5 minutes ago
                    }));
                } catch (e) { /* noop */ }
                state.scores.travel = clamp(state.scores.travel + 70, 0, 100);
                report(CATEGORY.TRAVEL,
                    'Demo: impossible travel detected: Germany → Kazakhstan in 0.08h',
                    50, SEVERITY.CRITICAL, { demo: true, from: 'DE', to: 'KZ' });
                break;
            default:
                console.warn('BehaviorEngine.simulate: unknown category', category);
                return null;
        }
        recomputeAggregate();
        return snapshot();
    }

    window.BehaviorEngine = {
        CATEGORY,
        SEVERITY,
        init,
        report,
        getState: snapshot,
        resetBaseline,
        recordResourceAccess: abuseModule.record,
        recordNavigation: navigationModule.record,
        checkDevice: deviceModule.check,
        checkTravel: travelModule.check,
        simulate,
    };
})();
