(function() {
    'use strict';

    // 1. Freeze Console to prevent students from testing payloads in DevTools
    const noop = function() {};
    const methods = ['log', 'debug', 'info', 'dir', 'table'];
    for (let i = 0; i < methods.length; i++) {
        if (window.console && window.console[methods[i]]) {
            window.console[methods[i]] = noop;
        }
    }

    // 2. High-Frequency Anti-Debugging Trap (Halts DevTools inspection)
    let checkDebugger = function() {
        function devtoolsTrap(step) {
            if (('' + step / step)['length'] !== 1 || step % 20 === 0) {
                (function() {}.constructor('debugger')());
            } else {
                (function() {}.constructor('debugger')());
            }
            devtoolsTrap(++step);
        }
        try {
            devtoolsTrap(0);
        } catch (err) {}
    };

    // Run debugger verification safely
    setInterval(function() {
        const start = performance.now();
        (function() {}.constructor('debugger')());
        const elapsed = performance.now() - start;
        // If developer opened DevTools and paused execution via breakpoint
        if (elapsed > 100) {
            if (typeof window.triggerViolation === 'function') {
                window.triggerViolation('devtools_debugger_pause', 'Debugger latency anomaly detected. Inspecting or modifying exam runtime is strictly prohibited.');
            }
        }
    }, 2000);

    // 3. Prevent tampering with crucial anti-cheating globals
    const protectProperty = function(obj, prop) {
        let val = obj[prop];
        Object.defineProperty(obj, prop, {
            configurable: false,
            enumerable: true,
            get: function() { return val; },
            set: function(newVal) {
                if (typeof window.triggerViolation === 'function') {
                    window.triggerViolation('tamper_attempt', 'Attempted modification of protected client property: ' + prop);
                }
                return val;
            }
        });
    };

    window.__examguard_armor_active = true;
})();
