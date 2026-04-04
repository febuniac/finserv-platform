const { AccountLock } = require('../../src/utils/accountLock');

/**
 * Tests that demonstrate the race condition fix for issue #33.
 *
 * The old lock used `${fromAccountId}-${toAccountId}` as the key, meaning
 * concurrent transfers from the same source to different destinations used
 * different lock keys and could interleave, allowing the balance to go negative.
 *
 * The new AccountLock serializes all operations touching the same account,
 * ensuring the balance check + deduction are atomic.
 */
describe('Transfer overdraft protection (Fixes #33)', () => {
  let lock;
  let accounts;

  beforeEach(() => {
    lock = new AccountLock();
    accounts = new Map();
    accounts.set('alice', { id: 'alice', balance: 100 });
    accounts.set('bob', { id: 'bob', balance: 50 });
    accounts.set('charlie', { id: 'charlie', balance: 0 });
  });

  async function transfer(fromId, toId, amount) {
    return lock.withLock([fromId, toId], async () => {
      const from = accounts.get(fromId);
      const to = accounts.get(toId);

      const amountCents = Math.round(amount * 100);
      const fromBalanceCents = Math.round(from.balance * 100);

      if (fromBalanceCents < amountCents) {
        return { success: false, error: 'Insufficient funds' };
      }

      // Simulate async delay (e.g. database write) between check and deduction
      await new Promise((r) => setTimeout(r, 10));

      from.balance = (fromBalanceCents - amountCents) / 100;
      to.balance = (Math.round(to.balance * 100) + amountCents) / 100;

      return { success: true, fromBalance: from.balance, toBalance: to.balance };
    });
  }

  it('should reject a single transfer exceeding balance', async () => {
    const result = await transfer('alice', 'bob', 150);
    expect(result.success).toBe(false);
    expect(result.error).toBe('Insufficient funds');
    expect(accounts.get('alice').balance).toBe(100);
    expect(accounts.get('bob').balance).toBe(50);
  });

  it('should allow a valid transfer', async () => {
    const result = await transfer('alice', 'bob', 60);
    expect(result.success).toBe(true);
    expect(accounts.get('alice').balance).toBe(40);
    expect(accounts.get('bob').balance).toBe(110);
  });

  it('should prevent balance going negative with concurrent transfers to different destinations', async () => {
    // This is the exact race condition from issue #33:
    // Alice has $100, two concurrent transfers of $80 each to different accounts.
    // Without proper locking, both see balance=100, both pass the check, balance goes to -$60.
    const t1 = transfer('alice', 'bob', 80);
    const t2 = transfer('alice', 'charlie', 80);

    const [r1, r2] = await Promise.all([t1, t2]);

    // One should succeed, one should fail
    const results = [r1, r2];
    const successes = results.filter((r) => r.success);
    const failures = results.filter((r) => !r.success);

    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(1);
    expect(failures[0].error).toBe('Insufficient funds');

    // Alice's balance must never go negative
    expect(accounts.get('alice').balance).toBeGreaterThanOrEqual(0);
    expect(accounts.get('alice').balance).toBe(20); // 100 - 80
  });

  it('should prevent overdraft with many concurrent transfers', async () => {
    // Alice has $100, 10 concurrent transfers of $20 each
    accounts.set('alice', { id: 'alice', balance: 100 });

    const destinations = [];
    for (let i = 0; i < 10; i++) {
      const destId = `dest-${i}`;
      accounts.set(destId, { id: destId, balance: 0 });
      destinations.push(destId);
    }

    const transfers = destinations.map((destId) => transfer('alice', destId, 20));
    const results = await Promise.all(transfers);

    const successes = results.filter((r) => r.success);
    const failures = results.filter((r) => !r.success);

    // Exactly 5 should succeed (5 * $20 = $100)
    expect(successes).toHaveLength(5);
    expect(failures).toHaveLength(5);

    // Alice's balance must be exactly 0
    expect(accounts.get('alice').balance).toBe(0);

    // Total money in the system should be conserved
    const totalBalance = Array.from(accounts.values()).reduce((sum, acc) => sum + acc.balance, 0);
    expect(totalBalance).toBe(150); // alice(100) + bob(50) + charlie(0) + dest accounts(0)
  });

  it('should handle concurrent opposing transfers without deadlock', async () => {
    // Alice sends to Bob AND Bob sends to Alice concurrently
    // The lock sorts account IDs so both acquire locks in the same order
    const t1 = transfer('alice', 'bob', 30);
    const t2 = transfer('bob', 'alice', 20);

    const [r1, r2] = await Promise.all([t1, t2]);

    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);

    // Alice: 100 - 30 + 20 = 90
    expect(accounts.get('alice').balance).toBe(90);
    // Bob: 50 + 30 - 20 = 60
    expect(accounts.get('bob').balance).toBe(60);
  });
});
