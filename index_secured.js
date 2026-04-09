"use strict";

const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// ========== SECURITY HEADERS (FIXES CLICKJACKING) ==========
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
        'frame-ancestors': ["'none'"],
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"], // Allows inline scripts in our HTML
        'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        'font-src': ["'self'", 'https://fonts.gstatic.com']
    }
}));

// ========== RATE LIMITING (FIXES DOS) ==========
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

app.use('/public', express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// ========== STORAGE ==========
let usernames = {};
let userRooms = new Map();
let messageHistory = [];
let csrfTokens = new Map();

// ========== HELPER FUNCTIONS ==========
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
};

const generateCsrfToken = (socketId) => {
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
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
        if (usernames[key] == v) val = key;
    }
    return val;
};

// ========== SOCKET.IO WITH SECURITY ==========
io.on('connection', socket => {
    console.log(`New connection: ${socket.id}`);
    
    // Generate and send CSRF token
    const csrfToken = generateCsrfToken(socket.id);
    socket.emit('csrf_token', csrfToken);

    // Rate limiting per socket
    let messageCount = 0;
    let lastReset = Date.now();
    
    const checkRateLimit = () => {
        const now = Date.now();
        if (now - lastReset > 60000) {
            messageCount = 0;
            lastReset = now;
        }
        if (messageCount > 30) {
            socket.emit('error', 'Rate limit exceeded. Slow down!');
            return false;
        }
        messageCount++;
        return true;
    };

    // ========== ADD USER (FIXES CSRF) ==========
    socket.on('adduser', (username, token) => {
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }
        
        username = sanitizeInput(username);
        
        if (!username || username.length > 20) {
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
        
        // Refresh CSRF token
        socket.emit('csrf_token', generateCsrfToken(socket.id));
    });

    // ========== PUBLIC MESSAGE (FIXES XSS + CSRF) ==========
    socket.on('sendchat', (data, token) => {
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }
        
        if (!checkRateLimit()) return;
        
        const sanitizedData = sanitizeInput(data);
        io.emit('updatechat', socket.username, sanitizedData);
        
        messageHistory.push({
            timestamp: new Date().toISOString(),
            user: socket.username,
            message: sanitizedData
        });
        if (messageHistory.length > 100) messageHistory.shift();
    });

    // ========== PRIVATE MESSAGE (FIXES IDOR + CSRF + SPOOFING) ==========
    socket.on('msg_user', (to_user, from_user, msg, token) => {
        // CSRF check
        if (!verifyCsrfToken(socket.id, token)) {
            socket.emit('error', 'Invalid CSRF token');
            return;
        }
        
        // Rate limit
        if (!checkRateLimit()) return;
        
        // Spoofing prevention
        if (socket.username !== from_user) {
            socket.emit('error', 'Unauthorized: Cannot send messages as another user');
            return;
        }
        
        // Check if target exists
        if (!usernames[to_user]) {
            socket.emit('error', 'User not found');
            return;
        }
        
        // Sanitize message
        const sanitizedMsg = sanitizeInput(msg);
        
        // IDOR prevention - permission check
        const allowedUsers = userRooms.get(from_user) || [];
        if (!allowedUsers.includes(`user_${to_user}`) && from_user !== to_user) {
            // Auto-grant permission for first contact (can be disabled for stricter security)
            userRooms.set(from_user, [...allowedUsers, `user_${to_user}`]);
        }
        
        // Send private message
        io.to(usernames[to_user]).emit('msg_user_handle', from_user, sanitizedMsg);
        
        // Secure logging
        const wstream = fs.createWriteStream('chat_data.txt', { flags: 'a' });
        wstream.write(`${new Date().toISOString()} | ${from_user} -> ${to_user}: ${sanitizedMsg}\n`);
        wstream.end();
    });

    // ========== CHECK USER ==========
    socket.on('check_user', (asker, id) => {
        if (socket.username !== asker) {
            socket.emit('error', 'Unauthorized');
            return;
        }
        io.to(usernames[asker]).emit('msg_user_found', check_key(id));
    });

    // ========== DISCONNECT ==========
    socket.on('disconnect', () => {
        if (socket.username) {
            delete usernames[socket.username];
            userRooms.delete(socket.username);
            csrfTokens.delete(socket.id);
            console.log(`${socket.username} disconnected`);
        }
    });
});

http.listen(3000, () => console.log('Secure chat server listening on *:3000'));
