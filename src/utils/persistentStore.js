const fs = require('fs');
const path = require('path');
const { logger } = require('./logger');
const { encrypt, decrypt } = require('./crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '../../data');

/**
 * A Map-like store that persists data to disk with AES-256-CBC encryption.
 * Values are encrypted both in memory and on disk to protect against
 * memory dumps and unauthorized file access (PCI-DSS compliance).
 * Maintains the same public API as Map for minimal code changes.
 */
class PersistentStore {
  constructor(name) {
    this.name = name;
    this.filePath = path.join(DATA_DIR, `${name}.json`);
    this.data = new Map();
    this._ensureDataDir();
    this._load();
  }

  _ensureDataDir() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  _encryptValue(value) {
    const json = JSON.stringify(value);
    return encrypt(json);
  }

  _decryptValue(encrypted) {
    const json = decrypt(encrypted);
    return JSON.parse(json);
  }

  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        const parsed = JSON.parse(raw);

        if (parsed && parsed.encrypted === true && Array.isArray(parsed.data)) {
          // Encrypted format - load directly
          this.data = new Map(parsed.data);
          logger.info(`PersistentStore "${this.name}" loaded ${this.data.size} encrypted entries from disk`);
        } else if (Array.isArray(parsed)) {
          // Legacy plaintext format - migrate to encrypted
          this.data = new Map();
          for (const [key, value] of parsed) {
            this.data.set(key, this._encryptValue(value));
          }
          this._save();
          logger.info(`PersistentStore "${this.name}" migrated ${this.data.size} entries to encrypted format`);
        }
      }
    } catch (err) {
      logger.error(`PersistentStore "${this.name}" failed to load data:`, err.message);
      this.data = new Map();
    }
  }

  _save() {
    try {
      const entries = Array.from(this.data.entries());
      const payload = { encrypted: true, version: 1, data: entries };
      const json = JSON.stringify(payload, null, 2);
      // Write to temp file then rename for atomicity
      const tmpPath = this.filePath + '.tmp';
      fs.writeFileSync(tmpPath, json, 'utf8');
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      logger.error(`PersistentStore "${this.name}" failed to save data:`, err.message);
    }
  }

  get(key) {
    const encrypted = this.data.get(key);
    if (encrypted === undefined) return undefined;
    return this._decryptValue(encrypted);
  }

  set(key, value) {
    this.data.set(key, this._encryptValue(value));
    this._save();
    return this;
  }

  has(key) {
    return this.data.has(key);
  }

  delete(key) {
    const result = this.data.delete(key);
    if (result) {
      this._save();
    }
    return result;
  }

  values() {
    const self = this;
    const iterator = this.data.values();
    return {
      [Symbol.iterator]() {
        return {
          next() {
            const result = iterator.next();
            if (result.done) return result;
            return { value: self._decryptValue(result.value), done: false };
          },
        };
      },
    };
  }

  entries() {
    const self = this;
    const iterator = this.data.entries();
    return {
      [Symbol.iterator]() {
        return {
          next() {
            const result = iterator.next();
            if (result.done) return result;
            const [key, encrypted] = result.value;
            return { value: [key, self._decryptValue(encrypted)], done: false };
          },
        };
      },
    };
  }

  keys() {
    return this.data.keys();
  }

  get size() {
    return this.data.size;
  }

  clear() {
    this.data.clear();
    this._save();
  }

  forEach(callback) {
    this.data.forEach((encrypted, key) => {
      callback(this._decryptValue(encrypted), key);
    });
  }
}

// Shared store instances to ensure all modules reference the same data
const stores = {};

function getStore(name) {
  if (!stores[name]) {
    stores[name] = new PersistentStore(name);
  }
  return stores[name];
}

module.exports = { PersistentStore, getStore, DATA_DIR };
