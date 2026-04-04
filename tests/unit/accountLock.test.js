const { AccountLock } = require('../../src/utils/accountLock');

describe('AccountLock', () => {
  let lock;

  beforeEach(() => {
    lock = new AccountLock();
  });

  it('should execute a single callback immediately', async () => {
    const result = await lock.withLock(['account-1'], async () => 'done');
    expect(result).toBe('done');
  });

  it('should serialize concurrent operations on the same account', async () => {
    const order = [];

    const op1 = lock.withLock(['account-1'], async () => {
      order.push('op1-start');
      await new Promise((r) => setTimeout(r, 50));
      order.push('op1-end');
      return 1;
    });

    const op2 = lock.withLock(['account-1'], async () => {
      order.push('op2-start');
      await new Promise((r) => setTimeout(r, 10));
      order.push('op2-end');
      return 2;
    });

    const [r1, r2] = await Promise.all([op1, op2]);

    expect(r1).toBe(1);
    expect(r2).toBe(2);
    // op2 must not start until op1 finishes
    expect(order).toEqual(['op1-start', 'op1-end', 'op2-start', 'op2-end']);
  });

  it('should allow parallel operations on different accounts', async () => {
    const order = [];

    const op1 = lock.withLock(['account-1'], async () => {
      order.push('op1-start');
      await new Promise((r) => setTimeout(r, 50));
      order.push('op1-end');
    });

    const op2 = lock.withLock(['account-2'], async () => {
      order.push('op2-start');
      await new Promise((r) => setTimeout(r, 50));
      order.push('op2-end');
    });

    await Promise.all([op1, op2]);

    // Both should start before either ends (parallel execution)
    expect(order.indexOf('op1-start')).toBeLessThan(order.indexOf('op1-end'));
    expect(order.indexOf('op2-start')).toBeLessThan(order.indexOf('op2-end'));
    // op2 should start before op1 ends (they run in parallel)
    expect(order.indexOf('op2-start')).toBeLessThan(order.indexOf('op1-end'));
  });

  it('should release the lock even if the callback throws', async () => {
    await expect(
      lock.withLock(['account-1'], async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');

    // Lock should be released — next operation should proceed
    const result = await lock.withLock(['account-1'], async () => 'recovered');
    expect(result).toBe('recovered');
  });

  it('should acquire locks in sorted order to prevent deadlocks', async () => {
    const order = [];

    // op1 locks [B, A] and op2 locks [A, B] — both should sort to [A, B]
    const op1 = lock.withLock(['account-B', 'account-A'], async () => {
      order.push('op1-start');
      await new Promise((r) => setTimeout(r, 50));
      order.push('op1-end');
    });

    const op2 = lock.withLock(['account-A', 'account-B'], async () => {
      order.push('op2-start');
      await new Promise((r) => setTimeout(r, 10));
      order.push('op2-end');
    });

    await Promise.all([op1, op2]);

    // They share accounts, so must be serialized
    expect(order).toEqual(['op1-start', 'op1-end', 'op2-start', 'op2-end']);
  });

  it('should serialize transfers from the same source to different destinations', async () => {
    // This is the exact race condition from issue #33
    const order = [];

    const op1 = lock.withLock(['source-account', 'dest-1'], async () => {
      order.push('transfer1-start');
      await new Promise((r) => setTimeout(r, 30));
      order.push('transfer1-end');
    });

    const op2 = lock.withLock(['source-account', 'dest-2'], async () => {
      order.push('transfer2-start');
      await new Promise((r) => setTimeout(r, 10));
      order.push('transfer2-end');
    });

    await Promise.all([op1, op2]);

    // transfer2 must not start until transfer1 ends because they share source-account
    expect(order).toEqual([
      'transfer1-start',
      'transfer1-end',
      'transfer2-start',
      'transfer2-end',
    ]);
  });
});
