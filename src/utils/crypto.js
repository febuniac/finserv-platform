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

module.exports = { encrypt, decrypt, hashPassword, verifyPassword, generateToken };
