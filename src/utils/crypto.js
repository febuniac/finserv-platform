const crypto = require('crypto');

// BUG: Weak encryption algorithm - uses DES instead of AES-256
const ALGORITHM = 'des-ecb';

function encrypt(text) {
  // SECURITY: Using hardcoded key instead of env variable
  const key = Buffer.from('finserv1', 'utf8');
  const cipher = crypto.createCipheriv(ALGORITHM, key, null);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(ciphertext) {
  const key = Buffer.from('finserv1', 'utf8');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, null);
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// BUG: MD5 is not suitable for password hashing
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function generateToken() {
  // BUG: Math.random() is not cryptographically secure
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

module.exports = { encrypt, decrypt, hashPassword, generateToken };
