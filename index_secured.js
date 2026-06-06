"use strict";
require('dotenv').config();

/**
 * SafeSocket - index_secured.js
 * Member 2: Secure Developer
 * D1: Secure Microservices Code
 * D2: OAuth2/JWT + RBAC
 * D3: AES-256-GCM + TLS 1.3
 * D4: Kafka Event Streaming
 * D5: Redis Secure Sessions
 */

const express   = require('express');
const app       = express();
const fs        = require('fs');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');

// ── D2: JWT + RBAC ────────────────────────────────────────
const {
    generateToken, verifyToken, requirePermission,
    socketAuthMiddleware, ROLES, userStore, hasPermission
} = require('./auth');

// ── D3: AES-256-GCM ───────────────────────────────────────
const { encrypt, decrypt, hashMessage } = require('./crypto-utils');

// ── D4: Kafka ─────────────────────────────────────────────
const kafka = require('./kafka');

// ── D5: Redis Sessions ────────────────────────────────────
const {
    sessionMiddleware,
    getStatus: getRedisStatus,
    saveUserSession,
    destroySession,
    isValidSession
} = require('./redis-session');

// ══════════════════════════════════════════════════════════
// D3: SERVER — HTTPS TLS 1.3 with HTTP fallback
// ══════════════════════════════════════════════════════════
let server;
try {
    const https      = require('https');
    const tlsOptions = {
        key:        fs.readFileSync('./certs/key.pem'),
        cert:       fs.readFileSync('./certs/cert.pem'),
        minVersion: 'TLSv1.3',
    };
    server = https.createServer(tlsOptions, app);
    console.log('[TLS] ✅ HTTPS server with TLS 1.3 enabled');
} catch (err) {
    console.warn('[TLS] ⚠️  Certs not found — running HTTP for development');
    const http = require('http');
    server     = http.createServer(app);
}

const io = require('socket.io')(server);

// ══════════════════════════════════════════════════════════
// SRD-010: SECURITY HEADERS
// ══════════════════════════════════════════════════════════
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
        'frame-ancestors': ["'none'"],
        'default-src':     ["'self'"],
        'script-src':      ["'self'", "'unsafe-inline'"],
        'style-src':       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        'font-src':        ["'self'", 'https://fonts.gstatic.com']
    }
}));

// ══════════════════════════════════════════════════════════
// SRD-009: GLOBAL RATE LIMIT
// ══════════════════════════════════════════════════════════
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// ══════════════════════════════════════════════════════════
// SRD-013: LOGIN RATE LIMIT
// ══════════════════════════════════════════════════════════
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Try again in 5 minutes.'
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/public', express.static('public'));

// ── D5: Apply session middleware ──────────────────────────
app.use(sessionMiddleware);

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index_secured.html');
});

// ══════════════════════════════════════════════════════════
// STORAGE
// ══════════════════════════════════════════════════════════
let usernames      = {};
let userRooms      = new Map();
let messageHistory = [];
let csrfTokens     = new Map();

// ══════════════════════════════════════════════════════════
// SRD-005, SRD-021: Input Sanitization
// ══════════════════════════════════════════════════════════
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#x27;')
        .replace(/\//g, '&#x2F;');
};

// ══════════════════════════════════════════════════════════
// CSRF Token helpers
// ══════════════════════════════════════════════════════════
const generateCsrfToken = (socketId) => {
    const crypto = require('crypto');
    const token  = crypto.randomBytes(32).toString('hex');
    csrfTokens.set(socketId, token);
    setTimeout(() => csrfTokens.delete(socketId), 3600000);
    return token;
};

const verifyCsrfToken = (socketId, token) => {
    return csrfTokens.get(socketId) === token;
};

const check_key = v => {
    let val = '';
    for (let key in usernames) {
        if (usernames[key] === v) val = key;
    }
    return val;
};

// ══════════════════════════════════════════════════════════
// D5: REDIS SESSION ENDPOINTS
// ══════════════════════════════════════════════════════════

// Redis status
app.get('/api/session/status', (req, res) => {
    res.json({
        redis:       getRedisStatus(),
        session:     isValidSession(req),
        sessionId:   req.session?.id ? 'present' : 'none',
        cookieName:  'safesocket.sid',
    });
});

// Session login (stores in Redis)
app.post('/api/session/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        const cleanUsername = username.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
        if (cleanUsername.length < 3) {
            return res.status(400).json({ error: 'Invalid username format' });
        }

        let userRole = 'user';
        if (userStore[cleanUsername]) {
            if (userStore[cleanUsername].password !== password) {
                console.log(`[SECURITY] Failed session login for "${cleanUsername}"`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            userRole = userStore[cleanUsername].role;
        } else {
            userStore[cleanUsername] = { password, role: 'user' };
        }

        // SRD-003: Save to Redis-backed session
        saveUserSession(req, cleanUsername, userRole);

        console.log(`[SESSION] Login: ${cleanUsername} → session ${req.session.id}`);

        res.json({
            message:    'Session created',
            username:   cleanUsername,
            role:       userRole,
            sessionId:  'set (HttpOnly cookie)',
            expiresIn:  '1 hour (SRD-020)',
            cookieFlags:'HttpOnly, SameSite=Lax (SRD-004)',
        });
    } catch (err) {
        console.error('[ERROR]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Session logout
app.post('/api/session/logout', async (req, res) => {
    const username = req.session?.username;
    await destroySession(req);
    res.clearCookie('safesocket.sid');
    console.log(`[SESSION] Logout: ${username}`);
    res.json({ message: 'Session destroyed', loggedOut: username });
});

// Session profile (requires valid session)
app.get('/api/session/profile', (req, res) => {
    if (!isValidSession(req)) {
        return res.status(401).json({ error: 'No active session' });
    }
    res.json({
        username:  req.session.username,
        role:      req.session.role,
        loginAt:   new Date(req.session.loginAt).toISOString(),
        ip:        req.session.ip,
        sessionId: 'hidden (HttpOnly)',
    });
});

// ══════════════════════════════════════════════════════════
// D3: ENCRYPTION TEST ENDPOINT
// ══════════════════════════════════════════════════════════
app.get('/api/crypto/test', (req, res) => {
    try {
        const testMsg   = 'SafeSocket AES-256-GCM Test Message';
        const encrypted = encrypt(testMsg);
        const decrypted = decrypt(encrypted);
        const hash      = hashMessage(testMsg);
        const passed    = decrypted === testMsg;
        res.json({
            algorithm:    'AES-256-GCM',
            original:     testMsg,
            encrypted:    encrypted,
            decrypted:    decrypted,
            hash_sha256:  hash,
            test_passed:  passed,
            tls_version:  'TLS 1.3 (minVersion enforced)',
            key_source:   'Environment variable (SRD-011)',
            key_rotation: 'Every 90 days (SRD-025)',
        });
    } catch (err) {
        res.status(500).json({ error: 'Encryption test failed', details: err.message });
    }
});

// D3: KEY ROTATION (admin only)
app.post('/api/crypto/rotate-key', requirePermission('manage_users'), (req, res) => {
    const { generateNewKey } = require('./crypto-utils');
    const newKey = generateNewKey();
    res.json({
        message:     'New AES key generated',
        newKey:      newKey,
        instruction: 'Update AES_KEY in .env and restart server',
        rotatedBy:   req.user.sub,
    });
});

// ══════════════════════════════════════════════════════════
// D4: KAFKA ENDPOINTS
// ══════════════════════════════════════════════════════════
app.get('/api/kafka/status', (req, res) => {
    res.json(kafka.getStatus());
});

app.post('/api/kafka/publish', requirePermission('write'), async (req, res) => {
    try {
        const { room, message } = req.body;
        if (!room || !message) {
            return res.status(400).json({ error: 'room and message required' });
        }
        const published = await kafka.publishMessage(
            room, req.user.sub, sanitizeInput(message), 'public'
        );
        res.json({
            published:   published,
            via:         published ? 'kafka' : 'fallback',
            room, from:  req.user.sub,
            message:     sanitizeInput(message),
            timestamp:   new Date().toISOString(),
            kafkaStatus: kafka.getStatus()
        });
    } catch (err) {
        res.status(500).json({ error: 'Publish failed' });
    }
});

// ══════════════════════════════════════════════════════════
// D2: JWT LOGIN ENDPOINT
// ══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        const cleanUsername = username.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
        if (cleanUsername.length < 3) {
            return res.status(400).json({ error: 'Invalid username format' });
        }
        let userRole = 'user';
        if (userStore[cleanUsername]) {
            if (userStore[cleanUsername].password !== password) {
                console.log(`[SECURITY] Failed login for "${cleanUsername}" at ${new Date().toISOString()}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            userRole = userStore[cleanUsername].role;
        } else {
            userStore[cleanUsername] = { password, role: 'user' };
        }
        const token = generateToken(cleanUsername, userRole);
        console.log(`[AUTH] Login success: ${cleanUsername} (${userRole})`);
        res.json({
            message:     'Login successful',
            token:       token,
            username:    cleanUsername,
            role:        userRole,
            permissions: ROLES[userRole].permissions,
            expiresIn:   '1h'
        });
    } catch (err) {
        console.error('[ERROR]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// D2: TOKEN VERIFY
app.get('/api/auth/verify', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ valid: false, error: 'No token provided' });
    }
    const token   = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ valid: false, error: 'Invalid or expired token' });
    }
    res.json({
        valid:       true,
        username:    decoded.sub,
        role:        decoded.role,
        permissions: ROLES[decoded.role]?.permissions || [],
        expiresAt:   new Date(decoded.exp * 1000).toISOString()
    });
});

// D2: RBAC ROUTES
app.get('/api/chat/history', requirePermission('read'), (req, res) => {
    res.json({ messages: messageHistory, count: messageHistory.length, user: req.user.sub, role: req.user.role });
});

app.delete('/api/chat/message', requirePermission('delete'), (req, res) => {
    res.json({ message: 'Message deleted', deletedBy: req.user.sub, role: req.user.role });
});

app.get('/api/admin/users', requirePermission('manage_users'), (req, res) => {
    res.json({ users: Object.keys(userStore).map(u => ({ username: u, role: userStore[u].role })) });
});

app.get('/api/admin/logs', requirePermission('view_logs'), (req, res) => {
    res.json({ message: 'Logs endpoint active', requestedBy: req.user.sub, role: req.user.role });
});

// ══════════════════════════════════════════════════════════
// SRD-012: Global Error Handler
// ══════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ══════════════════════════════════════════════════════════
// SOCKET.IO
// ══════════════════════════════════════════════════════════
io.on('connection', socket => {
    console.log(`[INFO] New connection: ${socket.id}`);

    const csrfToken = generateCsrfToken(socket.id);
    socket.emit('csrf_token', csrfToken);

    let messageCount = 0;
    let lastReset    = Date.now();

    const checkRateLimit = () => {
        const now = Date.now();
        if (now - lastReset > 60000) { messageCount = 0; lastReset = now; }
        if (messageCount > 30) {
            socket.emit('error', 'Rate limit exceeded. Slow down!');
            return false;
        }
        messageCount++;
        return true;
    };

    socket.on('adduser', (username, token) => {
        if (!verifyCsrfToken(socket.id, token)) { socket.emit('error', 'Invalid CSRF token'); return; }
        username = sanitizeInput(username);
        if (!username || username.length < 3 || username.length > 20) { socket.emit('error', 'Invalid username'); return; }
        if (usernames[username]) { socket.emit('error', 'Username already taken'); return; }
        socket.username     = username;
        usernames[username] = socket.id;
        userRooms.set(username, [`user_${username}`]);
        socket.emit('updatechat', 'Chat Bot', `${socket.username} you have joined the chat securely`);
        socket.emit('store_username', username);
        socket.emit('csrf_token', generateCsrfToken(socket.id));
    });

    socket.on('sendchat', async (data, token) => {
        if (!verifyCsrfToken(socket.id, token)) { socket.emit('error', 'Invalid CSRF token'); return; }
        if (!checkRateLimit()) return;
        if (typeof data !== 'string' || data.length > 10240) { socket.emit('error', 'Message too large'); return; }
        const sanitizedData = sanitizeInput(data);
        const published = await kafka.publishMessage('public', socket.username, sanitizedData, 'public');
        if (!published) { io.emit('updatechat', socket.username, sanitizedData); }
        messageHistory.push({ timestamp: new Date().toISOString(), user: socket.username, message: sanitizedData, via: published ? 'kafka' : 'direct' });
        if (messageHistory.length > 100) messageHistory.shift();
    });

    socket.on('msg_user', (to_user, from_user, msg, token) => {
        if (!verifyCsrfToken(socket.id, token)) { socket.emit('error', 'Invalid CSRF token'); return; }
        if (!checkRateLimit()) return;
        if (socket.username !== from_user) { socket.emit('error', 'Unauthorized'); return; }
        if (!usernames[to_user]) { socket.emit('error', 'User not found'); return; }
        if (typeof msg !== 'string' || msg.length > 10240) { socket.emit('error', 'Message too large'); return; }
        const sanitizedMsg = sanitizeInput(msg);
        const allowedUsers = userRooms.get(from_user) || [];
        if (!allowedUsers.includes(`user_${to_user}`) && from_user !== to_user) {
            userRooms.set(from_user, [...allowedUsers, `user_${to_user}`]);
        }
        io.to(usernames[to_user]).emit('msg_user_handle', from_user, sanitizedMsg);
        try {
            const encryptedMsg = encrypt(sanitizedMsg);
            const msgHash      = hashMessage(sanitizedMsg);
            const wstream      = fs.createWriteStream('chat_data.txt', { flags: 'a' });
            wstream.write(`[${new Date().toISOString()}] PRIVATE from="${from_user}" to="${to_user}" hash="${msgHash}" encrypted="${encryptedMsg}"\n`);
            wstream.end();
        } catch (err) {
            console.error('[CRYPTO] Failed to encrypt log:', err.message);
        }
    });

    socket.on('check_user', (asker, id) => {
        if (socket.username !== asker) { socket.emit('error', 'Unauthorized'); return; }
        io.to(usernames[asker]).emit('msg_user_found', check_key(id));
    });

    socket.on('disconnect', () => {
        if (socket.username) {
            delete usernames[socket.username];
            userRooms.delete(socket.username);
            csrfTokens.delete(socket.id);
            console.log(`[INFO] ${socket.username} disconnected`);
        }
    });
});

// ══════════════════════════════════════════════════════════
// D4: Connect Kafka
// ══════════════════════════════════════════════════════════
kafka.connect().then(() => {
    if (kafka.getStatus().connected) kafka.startConsumer(io);
});

// ══════════════════════════════════════════════════════════
// START SERVER
// ══════════════════════════════════════════════════════════
const PORT = Number(process.env.PORT || 3000);

const startServer = (port) => {
    server.listen(port, () => {
        console.log(`\n🔒 SafeSocket secure server listening on *:${port}`);
        console.log(`[D2] JWT Auth     → http://localhost:${port}/api/auth/login`);
        console.log(`[D2] Verify       → http://localhost:${port}/api/auth/verify`);
        console.log(`[D3] Crypto Test  → http://localhost:${port}/api/crypto/test`);
        console.log(`[D4] Kafka Status → http://localhost:${port}/api/kafka/status`);
        console.log(`[D5] Redis Status → http://localhost:${port}/api/session/status`);
        console.log(`[D5] Sess Login   → http://localhost:${port}/api/session/login`);
        console.log(`[D5] Sess Profile → http://localhost:${port}/api/session/profile\n`);
    });
};

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const fallbackPort = PORT + 1;
        console.warn(`Port ${PORT} busy. Retrying on ${fallbackPort}...`);
        startServer(fallbackPort);
        return;
    }
    throw err;
});

startServer(PORT);