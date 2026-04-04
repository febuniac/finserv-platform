const fs = require('fs');
const path = require('path');

// Use a temporary directory for test data
const TEST_DATA_DIR = path.join(__dirname, '../../data-test-' + process.pid);
process.env.DATA_DIR = TEST_DATA_DIR;

const { PersistentStore, getStore } = require('../../src/utils/persistentStore');

describe('PersistentStore', () => {
  afterAll(() => {
    // Clean up test data directory
    if (fs.existsSync(TEST_DATA_DIR)) {
      fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
    }
  });

  describe('basic Map-like operations', () => {
    let store;

    beforeEach(() => {
      store = new PersistentStore('test-basic');
      store.clear();
    });

    afterEach(() => {
      const filePath = path.join(TEST_DATA_DIR, 'test-basic.json');
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    });

    it('should set and get values', () => {
      store.set('key1', { name: 'Alice' });
      expect(store.get('key1')).toEqual({ name: 'Alice' });
    });

    it('should check if a key exists with has()', () => {
      store.set('key1', 'value1');
      expect(store.has('key1')).toBe(true);
      expect(store.has('nonexistent')).toBe(false);
    });

    it('should delete values', () => {
      store.set('key1', 'value1');
      expect(store.delete('key1')).toBe(true);
      expect(store.has('key1')).toBe(false);
      expect(store.delete('nonexistent')).toBe(false);
    });

    it('should return all values with values()', () => {
      store.set('key1', 'val1');
      store.set('key2', 'val2');
      const values = Array.from(store.values());
      expect(values).toEqual(['val1', 'val2']);
    });

    it('should return all entries with entries()', () => {
      store.set('k1', 'v1');
      store.set('k2', 'v2');
      const entries = Array.from(store.entries());
      expect(entries).toEqual([['k1', 'v1'], ['k2', 'v2']]);
    });

    it('should return correct size', () => {
      expect(store.size).toBe(0);
      store.set('key1', 'value1');
      expect(store.size).toBe(1);
      store.set('key2', 'value2');
      expect(store.size).toBe(2);
    });

    it('should clear all data', () => {
      store.set('key1', 'value1');
      store.set('key2', 'value2');
      store.clear();
      expect(store.size).toBe(0);
    });

    it('should iterate with forEach', () => {
      store.set('a', 1);
      store.set('b', 2);
      const collected = {};
      store.forEach((value, key) => {
        collected[key] = value;
      });
      expect(collected).toEqual({ a: 1, b: 2 });
    });
  });

  describe('persistence across restarts', () => {
    const storeName = 'test-persistence';
    const filePath = path.join(TEST_DATA_DIR, `${storeName}.json`);

    afterEach(() => {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    });

    it('should persist data to disk on set()', () => {
      const store = new PersistentStore(storeName);
      store.set('user1', { email: 'alice@test.com', name: 'Alice' });

      expect(fs.existsSync(filePath)).toBe(true);
      const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      expect(raw).toEqual([['user1', { email: 'alice@test.com', name: 'Alice' }]]);
    });

    it('should load persisted data on construction (simulating restart)', () => {
      // First "session" - write data
      const store1 = new PersistentStore(storeName);
      store1.set('account1', { id: 'account1', balance: 1000, status: 'active' });
      store1.set('account2', { id: 'account2', balance: 500, status: 'active' });

      // Second "session" - simulate restart by creating new store with same name
      const store2 = new PersistentStore(storeName);
      expect(store2.get('account1')).toEqual({ id: 'account1', balance: 1000, status: 'active' });
      expect(store2.get('account2')).toEqual({ id: 'account2', balance: 500, status: 'active' });
      expect(store2.size).toBe(2);
    });

    it('should persist deletes across restarts', () => {
      const store1 = new PersistentStore(storeName);
      store1.set('key1', 'value1');
      store1.set('key2', 'value2');
      store1.delete('key1');

      const store2 = new PersistentStore(storeName);
      expect(store2.has('key1')).toBe(false);
      expect(store2.has('key2')).toBe(true);
      expect(store2.size).toBe(1);
    });

    it('should persist updates across restarts', () => {
      const store1 = new PersistentStore(storeName);
      store1.set('user1', { name: 'Alice', role: 'user' });
      store1.set('user1', { name: 'Alice', role: 'admin' });

      const store2 = new PersistentStore(storeName);
      expect(store2.get('user1')).toEqual({ name: 'Alice', role: 'admin' });
    });

    it('should handle complex nested objects', () => {
      const store1 = new PersistentStore(storeName);
      const transaction = {
        id: 'tx-123',
        fromAccountId: 'acc-1',
        toAccountId: 'acc-2',
        amount: 150.75,
        status: 'completed',
        createdAt: '2024-01-15T10:30:00.000Z',
      };
      store1.set(transaction.id, transaction);

      const store2 = new PersistentStore(storeName);
      expect(store2.get('tx-123')).toEqual(transaction);
    });

    it('should handle corrupted data file gracefully', () => {
      // Write invalid JSON to the data file
      if (!fs.existsSync(TEST_DATA_DIR)) {
        fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(filePath, 'not valid json{{{', 'utf8');

      // Store should initialize with empty data instead of crashing
      const store = new PersistentStore(storeName);
      expect(store.size).toBe(0);
    });
  });

  describe('getStore (singleton pattern)', () => {
    it('should return the same instance for the same store name', () => {
      const store1 = getStore('shared-test');
      const store2 = getStore('shared-test');
      expect(store1).toBe(store2);
    });

    it('should share data between modules using the same store name', () => {
      const storeA = getStore('shared-data');
      storeA.set('key1', 'from module A');

      const storeB = getStore('shared-data');
      expect(storeB.get('key1')).toBe('from module A');
    });
  });
});
