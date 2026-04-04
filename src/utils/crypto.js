const crypto = require('crypto');

// Fixed: Use AES-256-CBC instead of DES-ECB (Fixes #2)
const ALGORITHM = 'aes-256-cbc';

function getEncryptionKey() {
  const keyHex = process.env.ENCRYPTION_KEY;
  if (keyHex) return Buffer.from(keyHex, 'hex');
  // Derive a key from a passphrase for dev environments
  return crypto.scryptSync('finserv-default-key', 'finserv-salt', 32);
}

function encrypt(text) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(ciphertext) {
  const key = getEncryptionKey();
  const parts = ciphertext.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = parts[1];
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Fixed: Use scrypt instead of MD5 for password hashing (Fixes #3)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(':');
  const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
}

// Fixed: Use crypto.randomBytes instead of Math.random (Fixes #14)
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate an HMAC-signed, time-limited password reset link.
 * The link encodes the user's email, an expiry timestamp, and an HMAC signature
 * so the raw reset token is never transmitted in the email.
 *
 * @param {string} email - The user's email address
 * @param {number} [ttlMs=3600000] - Link validity in milliseconds (default: 1 hour)
 * @returns {{ link: string, expiresAt: number }}
 */
function generateSecureResetLink(email, ttlMs = 3600000) {
  const expiresAt = Date.now() + ttlMs;
  const payload = `${email}:${expiresAt}`;
  const key = getEncryptionKey();
  const signature = crypto.createHmac('sha256', key).update(payload).digest('hex');
  const token = Buffer.from(JSON.stringify({ email, expiresAt, signature })).toString('base64url');
  const baseUrl = process.env.APP_BASE_URL || 'https://app.finserv.com';
  return {
    link: `${baseUrl}/reset-password?token=${token}`,
    expiresAt,
  };
}

/**
 * Verify a password reset link token.
 * Returns the email if valid, or null if expired/tampered.
 *
 * @param {string} token - The base64url-encoded token from the reset link
 * @returns {string|null} The email address if valid, null otherwise
 */
function verifyResetToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());
    const { email, expiresAt, signature } = decoded;
    if (Date.now() > expiresAt) return null;
    const key = getEncryptionKey();
    const expectedSig = crypto.createHmac('sha256', key).update(`${email}:${expiresAt}`).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'))) {
      return null;
    }
    return email;
  } catch {
    return null;
  }
}

module.exports = { encrypt, decrypt, hashPassword, verifyPassword, generateToken, generateSecureResetLink, verifyResetToken };
