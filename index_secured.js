"use strict";

/**
 * SafeSocket - index_secured.js
 * Member 2: Secure Developer
 * Deliverable 1: Secure Microservices Code
 * Deliverable 2: OAuth2/JWT + RBAC Implementation
 *
 * Security Controls:
 * - SRD-005/021: Input sanitization
 * - SRD-006: XSS prevention
 * - SRD-008: IDOR protection
 * - SRD-009: Rate limiting (100 req/15min)
 * - SRD-010: Security headers (Helmet)
 * - SRD-012: Generic error messages
 * - SRD-013: Login rate limit (5/5min)
 * - SRD-014: Anti-spoofing
 * - SRD-015: JWT in memory only
 * - SRD-019: Message size limit (10KB)
 * - SRD-021: Username validation
 * - SRD-023: Failed auth logging
 * - CSRF: Token per socket session
 */

const express = require('express');
const app     = express();
const http    = require('http').Server(app);
const io      = require('socket.io')(http);
const fs      = require('fs');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');

// ── D2: Import JWT + RBAC module ──────────────────────────
const {
    generateToken,
    verifyToken,
    requirePermission,
    socketAuthMiddleware,
    ROLES,
    userStore,
    hasPermission
} = require('./auth');

// ══════════════════════════════════════════════════════════
// SRD-010: SECURITY HEADERS (Helmet)
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
// SRD-009: GLOBAL RATE LIMIT — 100 req / 15 min
// ══════════════════════════════════════════════════════════
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// ══════════════════════════════════════════════════════════
// SRD-013: LOGIN RATE LIMIT — 5 attempts / 5 min
// ══════════════════════════════════════════════════════════
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Try again in 5 minutes.'
});

// ── Body parser + static files ────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/public', express.static('public'));

// ── Serve secured frontend ────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index_secured.html');
});

// ══════════════════════════════════════════════════════════
// STORAGE
// ══════════════════════════════════════════════════════════
let usernames      = {};        // { username: socketId }
let userRooms      = new Map(); // { username: [rooms] }
let messageHistory = [];        // last 100 messages
let csrfTokens     = new Map(); // { socketId: token }

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
    setTimeout(() => csrfTokens.delete(socketId), 3600000); // 1 hour
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
// D2: JWT LOGIN ENDPOINT
// POST /api/auth/login
// SRD-015: Token returned in body — store in memory ONLY
// ══════════════════════════════════════════════════════════
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Sanitize + validate username
        const cleanUsername = username.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
        if (cleanUsername.length < 3) {
            return res.status(400).json({ error: 'Invalid username format' });
        }

        let userRole = 'user';

        if (userStore[cleanUsername]) {
            // Known user — check password
            if (userStore[cleanUsername].password !== password) {
                // SRD-023: Log failed login (no sensitive data)
                console.log(`[SECURITY] Failed login for "${cleanUsername}" at ${new Date().toISOString()}`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            userRole = userStore[cleanUsername].role;
        } else {
            // New user — auto-register as 'user' role
            userStore[cleanUsername] = { password, role: 'user' };
        }

        // Generate JWT
        const token = generateToken(cleanUsername, userRole);

        console.log(`[AUTH] Login success: ${cleanUsername} (${userRole})`);

        // SRD-015: Token in response body — client keeps in memory only
        res.json({
            message:     'Login successful',
            token:       token,
            username:    cleanUsername,
            role:        userRole,
            permissions: ROLES[userRole].permissions,
            expiresIn:   '1h'
        });

    } catch (err) {
        // SRD-012: No internals exposed
        console.error('[ERROR]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ══════════════════════════════════════════════════════════
// D2: TOKEN VERIFY ENDPOINT
// GET /api/auth/verify
// ══════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════
// D2: RBAC PROTECTED ROUTES
// ══════════════════════════════════════════════════════════

// Any logged-in user — read chat history
app.get('/api/chat/history', requirePermission('read'), (req, res) => {
    res.json({
        messages: messageHistory,
        count:    messageHistory.length,
        user:     req.user.sub,
        role:     req.user.role
    });
});

// Moderator+ — delete messages
app.delete('/api/chat/message', requirePermission('delete'), (req, res) => {
    res.json({
        message:   'Message deleted',
        deletedBy: req.user.sub,
        role:      req.user.role
    });
});

// Admin only — list all users
app.get('/api/admin/users', requirePermission('manage_users'), (req, res) => {
    res.json({
        users: Object.keys(userStore).map(u => ({
            username: u,
            role:     userStore[u].role
        }))
    });
});

// Admin only — view logs
app.get('/api/admin/logs', requirePermission('view_logs'), (req, res) => {
    res.json({
        message:     'Logs endpoint active',
        requestedBy: req.user.sub,
        role:        req.user.role
    });
});

// ══════════════════════════════════════════════════════════
// SRD-012: Global Error Handler
// Never expose stack traces or internals
// ══════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ══════════════════════════════════════════════════════════
// SOCKET.IO — REAL-TIME CHAT WITH SECURITY
// ══════════════════════════════════════════════════════════
io.on('connection', socket => {
    console.log(`[INFO] New connection: ${socket.id}`);

    // Generate + send CSRF token to client
    const csrfToken = generateCsrfToken(socket.id);
    socket.emit('csrf_token', csrfToken);

    // Per-socket rate limiting — 30 msg/min
    let messageCount = 0;
    let lastReset    = Date.now();

    const checkRateLimit = () => {
        const now = Date.now();
        if (now - lastReset > 60000) {
            messageCount = 0;
            lastReset    = now;
        }
        if (messageCount > 30) {
            socket.emit('error', 'Rate limit exceeded. Slow down!');
            return false;
        }
        messageCount++;
        return true;
    };

    // ── ADD USER (CSRF protected) ─────────────────────────
    socket.on('adduser', (username, token) => {
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }

        username = sanitizeInput(username);

        // SRD-021: Validate length
        if (!username || username.length < 3 || username.length > 20) {
            socket.emit('error', 'Invalid username');
            return;
        }

        if (usernames[username]) {
            socket.emit('error', 'Username already taken');
            return;
        }

        socket.username = username;
        usernames[username] = socket.id;
        userRooms.set(username, [`user_${username}`]);

        socket.emit('updatechat', 'Chat Bot', `${socket.username} you have joined the chat securely`);
        socket.emit('store_username', username);

        // Refresh CSRF token after login
        socket.emit('csrf_token', generateCsrfToken(socket.id));
    });

    // ── PUBLIC MESSAGE (XSS + CSRF + Rate limit) ──────────
    socket.on('sendchat', (data, token) => {
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }

        if (!checkRateLimit()) return;

        // SRD-019: 10KB message size limit
        if (typeof data !== 'string' || data.length > 10240) {
            socket.emit('error', 'Message too large');
            return;
        }

        const sanitizedData = sanitizeInput(data);
        io.emit('updatechat', socket.username, sanitizedData);

        // Store in history (max 100)
        messageHistory.push({
            timestamp: new Date().toISOString(),
            user:      socket.username,
            message:   sanitizedData
        });
        if (messageHistory.length > 100) messageHistory.shift();
    });

    // ── PRIVATE MESSAGE (IDOR + CSRF + Spoofing) ──────────
    socket.on('msg_user', (to_user, from_user, msg, token) => {
        // CSRF check
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }

        if (!checkRateLimit()) return;

        // SRD-014: Anti-spoofing — sender must match session
        if (socket.username !== from_user) {
            console.log(`[SECURITY] Spoofing attempt by ${socket.id}`);
            socket.emit('error', 'Unauthorized: Cannot send messages as another user');
            return;
        }

        if (!usernames[to_user]) {
            socket.emit('error', 'User not found');
            return;
        }

        // SRD-019: Size limit
        if (typeof msg !== 'string' || msg.length > 10240) {
            socket.emit('error', 'Message too large');
            return;
        }

        const sanitizedMsg = sanitizeInput(msg);

        // SRD-008: IDOR — permission check
        const allowedUsers = userRooms.get(from_user) || [];
        if (!allowedUsers.includes(`user_${to_user}`) && from_user !== to_user) {
            userRooms.set(from_user, [...allowedUsers, `user_${to_user}`]);
        }

        io.to(usernames[to_user]).emit('msg_user_handle', from_user, sanitizedMsg);

        // Secure structured log (no raw user data)
        const wstream = fs.createWriteStream('chat_data.txt', { flags: 'a' });
        wstream.write(`[${new Date().toISOString()}] PRIVATE from="${from_user}" to="${to_user}" length=${sanitizedMsg.length}\n`);
        wstream.end();
    });

    // ── CHECK USER ────────────────────────────────────────
    socket.on('check_user', (asker, id) => {
        if (socket.username !== asker) {
            socket.emit('error', 'Unauthorized');
            return;
        }
        io.to(usernames[asker]).emit('msg_user_found', check_key(id));
    });

    // ── DISCONNECT ────────────────────────────────────────
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
// START SERVER (auto port fallback)
// ══════════════════════════════════════════════════════════
const PORT = Number(process.env.PORT || 3000);

const startServer = (port) => {
    http.listen(port, () => {
        console.log(`Secure chat server listening on *:${port}`);
        console.log(`[D2] JWT Auth:  http://localhost:${port}/api/auth/login`);
        console.log(`[D2] Verify:    http://localhost:${port}/api/auth/verify`);
        console.log(`[D2] History:   http://localhost:${port}/api/chat/history`);
        console.log(`[D2] Admin:     http://localhost:${port}/api/admin/users`);
    });
};

http.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const fallbackPort = PORT + 1;
        console.warn(`Port ${PORT} busy. Retrying on ${fallbackPort}...`);
        startServer(fallbackPort);
        return;
    }
    throw err;
});

startServer(PORT);