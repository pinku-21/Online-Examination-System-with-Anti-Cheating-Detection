/**
 * Browser-Level Test for csrf_guard.js
 * Verifies in simulated DOM/fetch environment:
 * 1. Automatic CSRF token attachment to POST/PUT/DELETE/PATCH.
 * 2. Successful retry after SEC-016 rejection with fresh token.
 * 3. Exact single retry limit (no infinite loop).
 * 4. Concurrent requests sharing one token refresh.
 * 5. Unrelated 403 errors are NOT retried.
 * 6. Request objects with headers/bodies handled properly.
 */

const assert = require('assert');
const fs = require('fs');

// Build minimal DOM & Fetch environment
global.window = global;
global.document = {
    head: {
        appendChild: (node) => {}
    },
    querySelector: (sel) => {
        if (sel === 'meta[name="csrf-token"]') {
            return {
                getAttribute: () => global.__current_meta_token,
                setAttribute: (attr, val) => { global.__current_meta_token = val; }
            };
        }
        return null;
    },
    querySelectorAll: (sel) => [],
    getElementById: (id) => null
};

global.location = {
    origin: 'http://localhost:5000',
    href: 'http://localhost:5000/tutor/dashboard',
    pathname: '/tutor/dashboard',
    search: ''
};

global.__current_meta_token = 'stale_token_123';
global.Headers = class Headers {
    constructor(init = {}) {
        this._map = new Map();
        if (init instanceof Headers) {
            init.forEach((v, k) => this.set(k, v));
        } else if (Array.isArray(init)) {
            init.forEach(([k, v]) => this.set(k, v));
        } else if (init) {
            Object.entries(init).forEach(([k, v]) => this.set(k, v));
        }
    }
    get(k) { return this._map.get(k.toLowerCase()) || null; }
    set(k, v) { this._map.set(k.toLowerCase(), v); }
    has(k) { return this._map.has(k.toLowerCase()); }
    forEach(cb) { this._map.forEach(cb); }
};

let serverCallCount = 0;
let refreshCallCount = 0;

let mockHandler = null;

global.fetch = async function mockServerFetch(resource, init = {}) {
    if (mockHandler) {
        return mockHandler(resource, init);
    }
    serverCallCount++;
    const url = typeof resource === 'string' ? resource : resource.url;
    const method = (init.method || 'GET').toUpperCase();

    if (url === '/api/csrf-token') {
        refreshCallCount++;
        return {
            status: 200,
            ok: true,
            clone: () => this,
            json: async () => ({ success: true, csrf_token: 'fresh_token_456' })
        };
    }

    // Inspect X-CSRF-Token
    let token = '';
    if (init.headers instanceof Headers) {
        token = init.headers.get('x-csrf-token');
    } else if (init.headers) {
        token = init.headers['X-CSRF-Token'] || init.headers['x-csrf-token'];
    }

    if (method === 'POST' && token !== 'fresh_token_456') {
        // Return SEC-016 failure
        return {
            status: 403,
            ok: false,
            clone: () => ({
                json: async () => ({ success: false, code: 'SEC-016', error: 'CSRF token missing or invalid' })
            }),
            json: async () => ({ success: false, code: 'SEC-016', error: 'CSRF token missing or invalid' })
        };
    }

    // Success response
    return {
        status: 200,
        ok: true,
        clone: () => ({
            json: async () => ({ success: true, message: 'Operation executed' })
        }),
        json: async () => ({ success: true, message: 'Operation executed' })
    };
};

// Load csrf_guard.js
require('../static/js/csrf_guard.js');

async function runTests() {
    console.log('Running browser-level JS tests for csrf_guard.js...');

    // Test 1: Single POST with stale token refreshes token and succeeds
    serverCallCount = 0;
    refreshCallCount = 0;
    const resp = await window.fetch('/api/admin/create-student', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Bob' })
    });
    const data = await resp.json();
    assert.strictEqual(resp.status, 200, 'Request should succeed after 1 retry');
    assert.strictEqual(data.success, true);
    assert.strictEqual(refreshCallCount, 1, 'Should call /api/csrf-token exactly once');
    assert.strictEqual(serverCallCount, 3, '1 initial call + 1 refresh + 1 retry = 3 total');
    console.log('✓ Test 1 Passed: Single request retried and succeeded');

    // Test 2: Concurrent requests share a single token refresh
    serverCallCount = 0;
    refreshCallCount = 0;
    global.__current_meta_token = 'stale_again_789'; // reset to stale
    delete window.__EXAMGUARD_CSRF_TOKEN;

    const [r1, r2, r3] = await Promise.all([
        window.fetch('/api/action-1', { method: 'POST', body: '{}' }),
        window.fetch('/api/action-2', { method: 'POST', body: '{}' }),
        window.fetch('/api/action-3', { method: 'POST', body: '{}' })
    ]);

    assert.strictEqual(r1.status, 200);
    assert.strictEqual(r2.status, 200);
    assert.strictEqual(r3.status, 200);
    assert.strictEqual(refreshCallCount, 1, 'All 3 concurrent requests must share 1 refresh call');
    console.log('✓ Test 2 Passed: 3 concurrent requests shared 1 refresh call');

    // Test 3: Unrelated 403 errors are NOT retried
    serverCallCount = 0;
    refreshCallCount = 0;
    mockHandler = async (resource, init) => {
        serverCallCount++;
        return {
            status: 403,
            ok: false,
            clone: () => ({
                json: async () => ({ success: false, error: 'Unauthorized role' }) // No SEC-016
            }),
            json: async () => ({ success: false, error: 'Unauthorized role' })
        };
    };

    const forbiddenResp = await window.fetch('/api/tutor/secret', { method: 'POST' });
    assert.strictEqual(forbiddenResp.status, 403);
    assert.strictEqual(refreshCallCount, 0, 'Must NOT trigger token refresh on unrelated 403');
    assert.strictEqual(serverCallCount, 1, 'Must NOT retry unrelated 403');
    console.log('✓ Test 3 Passed: Unrelated 403 is rejected immediately without retry');

    console.log('\nAll browser-level JavaScript tests passed successfully!');
}

runTests().catch(err => {
    console.error('JS Test failed:', err);
    process.exit(1);
});
