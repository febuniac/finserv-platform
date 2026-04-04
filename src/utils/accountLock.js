/**
 * Per-account mutex lock to prevent race conditions in concurrent transfers.
 *
 * Ensures that operations on the same account are serialized, preventing
 * the balance check + deduction from being interleaved by concurrent requests.
 *
 * Fixes #33: Account balance can go negative - no overdraft protection
 */

class AccountLock {
  constructor() {
    // Map of accountId -> Promise chain
    this._locks = new Map();
  }

  /**
   * Acquire locks on one or more accounts (sorted to prevent deadlocks),
   * execute the callback, then release the locks.
   *
   * @param {string[]} accountIds - Account IDs to lock
   * @param {Function} fn - Async function to execute while locks are held
   * @returns {Promise<*>} Result of the callback
   */
  async withLock(accountIds, fn) {
    // Sort account IDs to acquire locks in consistent order (prevents deadlocks)
    const sortedIds = [...new Set(accountIds)].sort();

    // Chain onto existing lock promises for each account
    let release;
    const lockPromises = sortedIds.map((id) => {
      const prev = this._locks.get(id) || Promise.resolve();
      let resolveLock;
      const next = new Promise((resolve) => {
        resolveLock = resolve;
      });
      this._locks.set(id, next);
      return { id, prev, resolveLock };
    });

    // Wait for all previous lock holders to finish
    await Promise.all(lockPromises.map((l) => l.prev));

    try {
      return await fn();
    } finally {
      // Release all locks
      for (const { id, resolveLock } of lockPromises) {
        resolveLock();
        // Clean up if no one else is waiting
        // (the resolved promise will be the current value)
      }
    }
  }
}

module.exports = { AccountLock };
