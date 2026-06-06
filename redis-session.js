"use strict";

/**
 * SafeSocket - redis-session.js
 * Member 2: Secure Developer - Deliverable 5
 * Redis Secure Sessions Implementation
 * SRD-003: Cryptographically random session IDs
 * SRD-004: HttpOnly, Secure, SameSite=Lax cookies
 * SRD-020: 1 hour session expiry
 */

const session = require('express-session');
const crypto  = require('crypto');

// ══════════════════════════════════════════════════════════
// REDIS CLIENT — real Redis or in-memory mock fallback
// ══════════════════════════════════════════════════════════
let redisClient;
let usingMock = false;

try {
    const RedisMock = require('ioredis-mock');
    redisClient     = new RedisMock();
    usingMock       = true;
    console.log('[REDIS] ✅ ioredis-mock active (in-memory fallback)');

    // Try real Redis in background — swap if available
    try {
        const realRedis = new Redis({
    host:            process.env.REDIS_HOST || 'localhost',
    port:            Number(process.env.REDIS_PORT) || 6379,
    connectTimeout:  2000,
    lazyConnect:     true,
    maxRetriesPerRequest: 0,
    retryStrategy:   () => null,  // disable retries
    enableOfflineQueue: false,
});
        realRedis.connect()
            .then(() => {
                redisClient = realRedis;
                usingMock   = false;
                console.log('[REDIS] ✅ Connected to real Redis server');
            })
            .catch(() => {
                console.warn('[REDIS] ⚠️  Real Redis unavailable — staying on mock');
            });
    } catch (e) {
        // ioredis not installed — stay on mock
    }

} catch (err) {
    // ioredis-mock not installed — use plain object store
    console.warn('[REDIS] ⚠️  Using memory store (no ioredis-mock)');
    usingMock = true;
}

// ══════════════════════════════════════════════════════════
// SESSION STORE
// ══════════════════════════════════════════════════════════
let sessionStore;

try {
    const { RedisStore } = require('connect-redis');
    sessionStore = new RedisStore({
        client: redisClient,
        prefix: 'safesocket:sess:',
        ttl:    3600,
    });
    console.log('[REDIS] ✅ RedisStore session store ready');
} catch (err) {
    console.warn('[REDIS] ⚠️  connect-redis failed — using default memory store');
    sessionStore = undefined; // express-session uses MemoryStore by default
}

// ══════════════════════════════════════════════════════════
// SESSION MIDDLEWARE
// SRD-003: crypto.randomBytes session ID
// SRD-004: HttpOnly, Secure, SameSite=Lax
// SRD-020: 1 hour expiry
// ══════════════════════════════════════════════════════════
const sessionConfig = {
    secret:            process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    name:              'safesocket.sid',
    resave:            false,
    saveUninitialized: false,
    genid:             () => crypto.randomBytes(32).toString('hex'), // SRD-003
    cookie: {
        httpOnly: true,                                   // SRD-004
        secure:   process.env.NODE_ENV === 'production',  // SRD-004
        sameSite: 'lax',                                  // SRD-004
        maxAge:   60 * 60 * 1000,                         // SRD-020: 1 hour
    }
};

if (sessionStore) sessionConfig.store = sessionStore;

const sessionMiddleware = session(sessionConfig);

// ══════════════════════════════════════════════════════════
// STATUS
// ══════════════════════════════════════════════════════════
function getStatus() {
    return {
        connected:  !usingMock,
        mode:       usingMock ? 'ioredis-mock (in-memory)' : 'Redis server',
        host:       process.env.REDIS_HOST || 'localhost',
        port:       Number(process.env.REDIS_PORT) || 6379,
        prefix:     'safesocket:sess:',
        ttl:        '3600 seconds (1 hour)',
        cookieName: 'safesocket.sid',
        httpOnly:   true,
        sameSite:   'lax',
        secure:     process.env.NODE_ENV === 'production',
        srdControls: {
            'SRD-003': 'crypto.randomBytes(32) session ID',
            'SRD-004': 'HttpOnly + SameSite=Lax + Secure(prod)',
            'SRD-020': '1 hour session expiry',
        }
    };
}

// ══════════════════════════════════════════════════════════
// SESSION HELPERS
// ══════════════════════════════════════════════════════════
function saveUserSession(req, username, role) {
    req.session.username = username;
    req.session.role     = role;
    req.session.loginAt  = Date.now();
    req.session.ip       = req.ip;
}

function destroySession(req) {
    return new Promise((resolve) => {
        req.session.destroy((err) => {
            if (err) console.error('[REDIS] Session destroy error:', err.message);
            resolve();
        });
    });
}

function isValidSession(req) {
    return !!(req.session && req.session.username);
}

module.exports = {
    sessionMiddleware,
    redisClient,
    getStatus,
    saveUserSession,
    destroySession,
    isValidSession,
};
