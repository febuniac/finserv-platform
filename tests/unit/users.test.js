const { users, usersById, addUser, removeUser } = require('../../src/api/users');

describe('User Store - Secondary Index (Fixes #34)', () => {
  beforeEach(() => {
    users.clear();
    usersById.clear();
  });

  describe('addUser', () => {
    it('should add user to both maps', () => {
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice' });

      expect(users.has('alice@example.com')).toBe(true);
      expect(usersById.has('1')).toBe(true);
      expect(usersById.get('1')).toBe('alice@example.com');
    });

    it('should handle user without id gracefully', () => {
      addUser('bob@example.com', { email: 'bob@example.com', name: 'Bob' });

      expect(users.has('bob@example.com')).toBe(true);
      expect(usersById.size).toBe(0);
    });

    it('should update existing user and maintain index', () => {
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice' });
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice Updated' });

      expect(users.get('alice@example.com').name).toBe('Alice Updated');
      expect(usersById.get('1')).toBe('alice@example.com');
      expect(usersById.size).toBe(1);
    });
  });

  describe('removeUser', () => {
    it('should remove user from both maps', () => {
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice' });

      removeUser('alice@example.com');

      expect(users.has('alice@example.com')).toBe(false);
      expect(usersById.has('1')).toBe(false);
    });

    it('should handle removing non-existent user gracefully', () => {
      expect(() => removeUser('nonexistent@example.com')).not.toThrow();
    });

    it('should not affect other users when removing one', () => {
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice' });
      addUser('bob@example.com', { id: '2', email: 'bob@example.com', name: 'Bob' });

      removeUser('alice@example.com');

      expect(users.has('alice@example.com')).toBe(false);
      expect(usersById.has('1')).toBe(false);
      expect(users.has('bob@example.com')).toBe(true);
      expect(usersById.has('2')).toBe(true);
    });
  });

  describe('O(1) lookup by ID', () => {
    it('should find user email by ID in O(1) via usersById', () => {
      addUser('alice@example.com', { id: '100', email: 'alice@example.com', name: 'Alice' });
      addUser('bob@example.com', { id: '200', email: 'bob@example.com', name: 'Bob' });
      addUser('charlie@example.com', { id: '300', email: 'charlie@example.com', name: 'Charlie' });

      // O(1) lookup instead of O(n) linear scan
      const email = usersById.get('200');
      expect(email).toBe('bob@example.com');
      expect(users.get(email).name).toBe('Bob');
    });

    it('should return undefined for non-existent ID', () => {
      addUser('alice@example.com', { id: '1', email: 'alice@example.com', name: 'Alice' });

      expect(usersById.get('999')).toBeUndefined();
    });

    it('should maintain consistency after multiple add/remove operations', () => {
      addUser('a@example.com', { id: '1', email: 'a@example.com', name: 'A' });
      addUser('b@example.com', { id: '2', email: 'b@example.com', name: 'B' });
      addUser('c@example.com', { id: '3', email: 'c@example.com', name: 'C' });

      removeUser('b@example.com');

      expect(users.size).toBe(2);
      expect(usersById.size).toBe(2);
      expect(usersById.has('2')).toBe(false);
      expect(usersById.get('1')).toBe('a@example.com');
      expect(usersById.get('3')).toBe('c@example.com');

      addUser('d@example.com', { id: '4', email: 'd@example.com', name: 'D' });

      expect(users.size).toBe(3);
      expect(usersById.size).toBe(3);
      expect(usersById.get('4')).toBe('d@example.com');
    });
  });
});
