"use strict";

const crypto = require('crypto');

// ── AES-256-GCM settings ──────────────────────────────────
const ALGORITHM  = 'aes-256-gcm';

// SRD-011: Key from environment — NEVER hardcoded
// 32 bytes = 256 bits
const KEY_HEX    = process.env.AES_KEY ||
                   crypto.randomBytes(32).toString('hex');
const KEY_BUFFER = Buffer.from(KEY_HEX, 'hex');

// ══════════════════════════════════════════════════════════
// ENCRYPT
// Returns base64 string: IV + AuthTag + Ciphertext
// ══════════════════════════════════════════════════════════
function encrypt(plaintext) {
    if (typeof plaintext !== 'string') {
        throw new Error('Plaintext must be a string');
    }

    // Random 96-bit IV (recommended for GCM)
    const iv      = crypto.randomBytes(12);
    const cipher  = crypto.createCipheriv(ALGORITHM, KEY_BUFFER, iv);

    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);

    // 128-bit authentication tag
    const authTag = cipher.getAuthTag();

    // Pack: [IV(12)] + [AuthTag(16)] + [Ciphertext]
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

// ══════════════════════════════════════════════════════════
// DECRYPT
// Takes base64 payload, returns plaintext string
// ══════════════════════════════════════════════════════════
function decrypt(payload) {
    if (typeof payload !== 'string') {
        throw new Error('Payload must be a base64 string');
    }

    const buf        = Buffer.from(payload, 'base64');
    const iv         = buf.slice(0, 12);
    const authTag    = buf.slice(12, 28);
    const ciphertext = buf.slice(28);

    const decipher   = crypto.createDecipheriv(ALGORITHM, KEY_BUFFER, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]).toString('utf8');
}

// ══════════════════════════════════════════════════════════
// KEY ROTATION
// SRD-025: Generate new AES key (rotate every 90 days)
// ══════════════════════════════════════════════════════════
function generateNewKey() {
    const newKey = crypto.randomBytes(32).toString('hex');
    console.log('[CRYPTO] New AES-256 key generated for rotation:');
    console.log(`[CRYPTO] Update AES_KEY in .env: ${newKey}`);
    return newKey;
}

// ══════════════════════════════════════════════════════════
// HASH (for message integrity)
// ══════════════════════════════════════════════════════════
function hashMessage(message) {
    return crypto
        .createHash('sha256')
        .update(message)
        .digest('hex');
}

// ══════════════════════════════════════════════════════════
// SELF-TEST — runs on require to verify encryption works
// ══════════════════════════════════════════════════════════
function selfTest() {
    try {
        const testMsg     = 'SafeSocket AES-256-GCM Test';
        const encrypted   = encrypt(testMsg);
        const decrypted   = decrypt(encrypted);
        const passed      = decrypted === testMsg;
        console.log(`[CRYPTO] AES-256-GCM self-test: ${passed ? '✅ PASSED' : '❌ FAILED'}`);
        return passed;
    } catch (err) {
        console.error('[CRYPTO] Self-test failed:', err.message);
        return false;
    }
}

selfTest();

module.exports = { encrypt, decrypt, generateNewKey, hashMessage };