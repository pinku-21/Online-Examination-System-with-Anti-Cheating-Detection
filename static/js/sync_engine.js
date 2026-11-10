/**
 * ExamGuard AI - Universal Student Synchronization Engine
 * Lightweight authenticated cursor polling client for real-time exam and administrative sync.
 */
(function() {
    'use strict';

    // Only run if student is authenticated or on a student-facing page
    const userRoleMeta = document.querySelector('meta[name="user-role"]');
    const userRole = userRoleMeta ? userRoleMeta.getAttribute('content') : (window.USER_ROLE || '');

    // Check if session has student role, admin role, or if we are on student/tutor pages
    const isSyncPage = window.location.pathname.startsWith('/student') ||
                       window.location.pathname.startsWith('/tutor') ||
                       window.location.pathname.startsWith('/exam/') ||
                       document.getElementById('device-switch-modal') !== null ||
                       ['student', 'admin'].includes(userRole);

    if (!isSyncPage) {
        return;
    }

    const STORAGE_KEY = 'examguard_student_sync_cursor';
    let pollIntervalMs = 3500;
    let pollTimer = null;
    let isPolling = false;
    let consecutiveFailures = 0;

    function getCursor() {
        try {
            return parseInt(sessionStorage.getItem(STORAGE_KEY) || '0', 10) || 0;
        } catch (e) {
            return 0;
        }
    }

    function setCursor(val) {
        try {
            sessionStorage.setItem(STORAGE_KEY, String(val));
        } catch (e) {}
    }

    async function pollSyncEvents() {
        if (isPolling) return;
        if (document.hidden) return; // Save bandwidth and avoid background tab throttling

        isPolling = true;
        const currentCursor = getCursor();

        try {
            const resp = await fetch(`/api/student/sync-events?since=${currentCursor}`, {
                headers: { 'Accept': 'application/json' }
            });

            if (!resp.ok) {
                if (resp.status === 401 || resp.status === 403) {
                    // Not authenticated or logged out
                    stopPolling();
                    return;
                }
                consecutiveFailures++;
                scheduleNextPoll();
                return;
            }

            const data = await resp.json();
            consecutiveFailures = 0;

            if (data.success) {
                if (data.cursor && data.cursor > currentCursor) {
                    setCursor(data.cursor);
                }

                if (Array.isArray(data.events) && data.events.length > 0) {
                    dispatchEvents(data.events);
                }
            }
        } catch (err) {
            consecutiveFailures++;
        } finally {
            isPolling = false;
            scheduleNextPoll();
        }
    }

    function dispatchEvents(events) {
        events.forEach(ev => {
            // General sync event
            window.dispatchEvent(new CustomEvent('examguard:sync', { detail: ev }));

            // Granular event types
            const eventType = ev.event_type;
            if (eventType) {
                window.dispatchEvent(new CustomEvent(`examguard:${eventType}`, { detail: ev }));
            }

            // Universal session termination handler for students
            if (eventType === 'session_replaced' || eventType === 'session_terminated') {
                handleSessionRevoked(ev);
            }
        });
    }

    function handleSessionRevoked(ev) {
        stopPolling();
        const payload = ev.payload || {};
        const reason = payload.reason || 'Your account was signed into from another device or terminated by an administrator.';

        if (typeof Swal !== 'undefined') {
            Swal.fire({
                title: 'Session Terminated',
                text: reason,
                icon: 'warning',
                allowOutsideClick: false,
                allowEscapeKey: false,
                confirmButtonText: 'Return to Login',
                confirmButtonColor: '#0284c7'
            }).then(() => {
                window.location.href = '/logout';
            });
        } else {
            alert('Session Terminated: ' + reason);
            window.location.href = '/logout';
        }
    }

    function scheduleNextPoll() {
        if (pollTimer) clearTimeout(pollTimer);
        // Exponential backoff up to 15s if multiple consecutive network failures occur
        const backoff = Math.min(15000, pollIntervalMs + (consecutiveFailures * 2000));
        pollTimer = setTimeout(pollSyncEvents, backoff);
    }

    function startPolling() {
        if (pollTimer) clearTimeout(pollTimer);
        pollSyncEvents();
    }

    function stopPolling() {
        if (pollTimer) {
            clearTimeout(pollTimer);
            pollTimer = null;
        }
    }

    // React immediately when user returns to visible tab
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            startPolling();
        }
    });

    // Start polling immediately when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startPolling);
    } else {
        startPolling();
    }

    // Expose engine API globally
    window.ExamGuardSync = {
        pollNow: pollSyncEvents,
        getCursor: getCursor,
        resetCursor: () => setCursor(0),
        stop: stopPolling,
        start: startPolling
    };
})();
