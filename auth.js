"use strict";
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY = '1h';

const ROLES = {
    admin:     { level: 3, permissions: ['read','write','delete','manage_users','view_logs'] },
    moderator: { level: 2, permissions: ['read','write','delete'] },
    user:      { level: 1, permissions: ['read','write'] },
    guest:     { level: 0, permissions: ['read'] },
};

const userStore = {
    admin:     { password: 'admin123', role: 'admin' },
    moderator: { password: 'mod123',   role: 'moderator' },
};

function generateToken(username, role) {
    return jwt.sign(
        { sub: username, role, iat: Math.floor(Date.now() / 1000) },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY, algorithm: 'HS256' }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) { return null; }
}

function hasPermission(role, permission) {
    const roleData = ROLES[role];
    if (!roleData) return false;
    return roleData.permissions.includes(permission);
}

function requirePermission(permission) {
    return (req, res, next) => {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }
        const token   = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        if (!hasPermission(decoded.role, permission)) {
            return res.status(403).json({
                error: `Forbidden: requires '${permission}' permission`,
                yourRole: decoded.role
            });
        }
        req.user = decoded;
        next();
    };
}

function socketAuthMiddleware(socket, next) {
    const token = socket.handshake.auth?.token;
    if (!token) { socket.jwtRole = 'guest'; return next(); }
    const decoded = verifyToken(token);
    if (!decoded) { socket.jwtRole = 'guest'; return next(); }
    socket.jwtUser = decoded.sub;
    socket.jwtRole = decoded.role;
    next();
}

module.exports = {
    generateToken,
    verifyToken,
    hasPermission,
    requirePermission,
    socketAuthMiddleware,
    ROLES,
    userStore,
    JWT_SECRET,
};