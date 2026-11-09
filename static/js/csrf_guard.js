/**
 * ExamGuard AI - Robust CSRF Interceptor & Session Recovery Engine
 * 
 * Features:
 * 1. Automatically attaches X-CSRF-Token to all state-changing same-origin requests (POST, PUT, DELETE, PATCH).
 * 2. Works seamlessly across JSON bodies, FormData, URLSearchParams, and custom Headers.
 * 3. Handles both string URLs and Request instances (preserving/cloning consumed bodies).
 * 4. Never overwrites valid, explicitly provided CSRF headers unnecessarily.
 * 5. Intercepts confirmed SEC-016 responses ("CSRF token missing or invalid").
 * 6. Uses a shared in-flight Promise for concurrent requests so only ONE /api/csrf-token refresh call is made.
 * 7. Exactly ONE retry attempt per request; prevents infinite retry loops.
 * 8. If /api/csrf-token returns 401 (session expired), gracefully preserves student examination state / forms,
 *    and displays a non-destructive reauthentication modal or warning.
 * 9. Never blindly retries uncertain failures, 500 errors, or unrelated 403 authorization failures.
 */

(function() {
    'use strict';

    if (window.__examguard_csrf_interceptor_installed) {
        return;
    }
    window.__examguard_csrf_interceptor_installed = true;

    let refreshPromise = null;

    // Helper: get current CSRF token from DOM or window cache
    function getCurrentCsrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta && meta.getAttribute('content')) {
            return meta.getAttribute('content');
        }
        return window.__EXAMGUARD_CSRF_TOKEN || '';
    }

    // Helper: update CSRF token in DOM and window cache
    function updateCsrfToken(newToken) {
        if (!newToken) return;
        window.__EXAMGUARD_CSRF_TOKEN = newToken;
        let meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) {
            meta.setAttribute('content', newToken);
        } else {
            meta = document.createElement('meta');
            meta.name = 'csrf-token';
            meta.content = newToken;
            document.head.appendChild(meta);
        }
        // Also update any hidden form inputs with name="csrf_token"
        document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
            input.value = newToken;
        });
    }

    // Helper: fetch a fresh token from /api/csrf-token (deduplicated across concurrent requests)
    function fetchFreshCsrfToken() {
        if (refreshPromise) {
            return refreshPromise;
        }

        refreshPromise = (async () => {
            try {
                const resp = await window.__examguard_original_fetch('/api/csrf-token', {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' },
                    cache: 'no-store'
                });

                if (resp.status === 401) {
                    const data = await resp.json().catch(() => ({}));
                    handleSessionExpired(data.error || 'Your authenticated session has expired.');
                    throw new Error('SESSION_EXPIRED');
                }

                if (!resp.ok) {
                    throw new Error(`Failed to fetch CSRF token: ${resp.status}`);
                }

                const data = await resp.json();
                if (data.success && data.csrf_token) {
                    updateCsrfToken(data.csrf_token);
                    return data.csrf_token;
                } else {
                    throw new Error(data.error || 'Invalid token response');
                }
            } finally {
                refreshPromise = null;
            }
        })();

        return refreshPromise;
    }

    // Session expiration handler with state preservation
    function handleSessionExpired(message) {
        const isExamActive = (typeof SUBMISSION_ID !== 'undefined' && SUBMISSION_ID) ||
                             window.location.pathname.startsWith('/student/exam/') ||
                             document.getElementById('exam-active-flag') !== null;

        if (isExamActive) {
            console.warn('[ExamGuard Security] Session token refresh reported session expiry during active exam.');
            // Do NOT immediately wipe or kick student out of their active exam room
            // Let the local sync engine and submission cache retain all pending answers
            if (typeof Swal !== 'undefined') {
                Swal.fire({
                    icon: 'warning',
                    title: 'Authentication Warning',
                    text: 'Your background session credentials require verification. Your exam answers are safely cached locally. Please do not close this window.',
                    confirmButtonText: 'Understood',
                    confirmButtonColor: '#4f46e5'
                });
            }
            return;
        }

        if (typeof Swal !== 'undefined') {
            Swal.fire({
                icon: 'warning',
                title: 'Session Expired',
                text: message + ' Please log in again to continue.',
                confirmButtonText: 'Go to Sign In',
                confirmButtonColor: '#0284c7',
                showCancelButton: true,
                cancelButtonText: 'Stay on Page'
            }).then((res) => {
                if (res.isConfirmed) {
                    window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname + window.location.search);
                }
            });
        } else {
            if (confirm(message + '\n\nWould you like to go to the login page now? (Your unsaved inputs on this page might be lost if you leave)')) {
                window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname + window.location.search);
            }
        }
    }

    // Attach CSRF header to init object
    function attachCsrfToken(init, token) {
        if (!token) return;

        if (init.headers instanceof Headers) {
            if (!init.headers.has('X-CSRF-Token')) {
                init.headers.set('X-CSRF-Token', token);
            }
        } else if (Array.isArray(init.headers)) {
            const hasCsrf = init.headers.some(([k]) => k.toLowerCase() === 'x-csrf-token');
            if (!hasCsrf) {
                init.headers.push(['X-CSRF-Token', token]);
            }
        } else if (init.headers && typeof init.headers === 'object') {
            const hasCsrf = Object.keys(init.headers).some(k => k.toLowerCase() === 'x-csrf-token');
            if (!hasCsrf) {
                init.headers['X-CSRF-Token'] = token;
            }
        } else {
            init.headers = { 'X-CSRF-Token': token };
        }
    }

    // Replace or set CSRF token unconditionally (used on verified retry)
    function overrideCsrfToken(init, token) {
        if (!token) return;

        if (init.headers instanceof Headers) {
            init.headers.set('X-CSRF-Token', token);
        } else if (Array.isArray(init.headers)) {
            const idx = init.headers.findIndex(([k]) => k.toLowerCase() === 'x-csrf-token');
            if (idx >= 0) {
                init.headers[idx] = ['X-CSRF-Token', token];
            } else {
                init.headers.push(['X-CSRF-Token', token]);
            }
        } else if (init.headers && typeof init.headers === 'object') {
            const keys = Object.keys(init.headers);
            for (const k of keys) {
                if (k.toLowerCase() === 'x-csrf-token') {
                    delete init.headers[k];
                }
            }
            init.headers['X-CSRF-Token'] = token;
        } else {
            init.headers = { 'X-CSRF-Token': token };
        }
    }

    function isSameOrigin(url) {
        try {
            const parsed = new URL(url, window.location.href);
            return parsed.origin === window.location.origin;
        } catch (e) {
            return true; // Relative URLs are always same-origin
        }
    }

    const originalFetch = window.fetch;
    window.__examguard_original_fetch = originalFetch;

    window.fetch = async function(resource, init = {}) {
        let targetUrl = '';
        let method = 'GET';
        let isRequestObject = false;

        if (typeof resource === 'string') {
            targetUrl = resource;
            method = (init.method || 'GET').toUpperCase();
        } else if (typeof Request !== 'undefined' && resource instanceof Request) {
            isRequestObject = true;
            targetUrl = resource.url;
            method = (init.method || resource.method || 'GET').toUpperCase();
        } else if (resource && resource.url) {
            targetUrl = resource.url;
            method = (init.method || resource.method || 'GET').toUpperCase();
        }

        const isStateChanging = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);

        // If resource is a Request object, extract body/headers into init if needed
        if (isRequestObject && isStateChanging && isSameOrigin(targetUrl)) {
            const headers = new Headers(resource.headers);
            if (init.headers) {
                const initHeaders = new Headers(init.headers);
                initHeaders.forEach((val, key) => headers.set(key, val));
            }
            init.headers = headers;
            if (init.body === undefined && !resource.bodyUsed) {
                try {
                    const clonedReq = resource.clone();
                    init.body = await clonedReq.blob();
                } catch (e) {}
            }
            resource = targetUrl;
        }

        // Only attach and handle CSRF for same-origin state-changing requests
        if (isStateChanging && isSameOrigin(targetUrl)) {
            const currentToken = getCurrentCsrfToken();
            attachCsrfToken(init, currentToken);
        }

        // Execute original request
        const response = await originalFetch(resource, init);

        // Check if request was rejected specifically with SEC-016 before execution
        if (isStateChanging && response.status === 403 && !init.__is_csrf_retry && isSameOrigin(targetUrl)) {
            try {
                // Clone response to inspect JSON without consuming original body stream
                const clonedResp = response.clone();
                const errData = await clonedResp.json().catch(() => null);

                if (errData && (errData.code === 'SEC-016' || (typeof errData.error === 'string' && errData.error.includes('SEC-016')))) {
                    console.warn(`[ExamGuard CSRF] Request to ${targetUrl} rejected with SEC-016. Refreshing token and retrying once...`);

                    try {
                        const freshToken = await fetchFreshCsrfToken();
                        if (freshToken) {
                            // Prepare one-time retry
                            const retryInit = { ...init, __is_csrf_retry: true };
                            overrideCsrfToken(retryInit, freshToken);

                            // Execute exact single retry
                            const retryResponse = await originalFetch(resource, retryInit);
                            return retryResponse;
                        }
                    } catch (refreshErr) {
                        console.error('[ExamGuard CSRF] Token refresh failed during retry:', refreshErr);
                        return response;
                    }
                }
            } catch (e) {
                return response;
            }
        }

        return response;
    };
})();
