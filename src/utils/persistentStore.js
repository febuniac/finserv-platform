const fs = require('fs');
const path = require('path');
const { logger } = require('./logger');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '../../data');

/**
 * A Map-like store that persists data to a JSON file on disk.
 * Maintains the same API as Map for minimal code changes,
 * while ensuring data survives server restarts.
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

  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        const entries = JSON.parse(raw);
        this.data = new Map(entries);
        logger.info(`PersistentStore "${this.name}" loaded ${this.data.size} entries from disk`);
      }
    } catch (err) {
      logger.error(`PersistentStore "${this.name}" failed to load data:`, err.message);
      this.data = new Map();
    }
  }

  _save() {
    try {
      const entries = Array.from(this.data.entries());
      const json = JSON.stringify(entries, null, 2);
      // Write to temp file then rename for atomicity
      const tmpPath = this.filePath + '.tmp';
      fs.writeFileSync(tmpPath, json, 'utf8');
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      logger.error(`PersistentStore "${this.name}" failed to save data:`, err.message);
    }
  }

  get(key) {
    return this.data.get(key);
  }

  set(key, value) {
    this.data.set(key, value);
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
    return this.data.values();
  }

  entries() {
    return this.data.entries();
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
    this.data.forEach(callback);
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
