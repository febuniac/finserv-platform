const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { logger } = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');
const { transactionSchema } = require('../utils/validation');
const { AccountLock } = require('../utils/accountLock');

const router = express.Router();

// In-memory stores
const transactions = new Map();
const accounts = new Map();

// Idempotency key tracking (Fixes #43)
const processedIdempotencyKeys = new Map();

// Per-account mutex lock to prevent race conditions (Fixes #33, replaces #9 fix)
const accountLock = new AccountLock();

router.use(authenticateToken);

router.post('/transfer', async (req, res) => {
  try {
    const { error, value } = transactionSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { fromAccountId, toAccountId, amount, description, idempotencyKey } = value;

    // Fixed: Check idempotency key to prevent duplicate transactions (Fixes #43)
    if (idempotencyKey && processedIdempotencyKeys.has(idempotencyKey)) {
      return res.status(200).json(processedIdempotencyKeys.get(idempotencyKey));
    }

    const fromAccount = accounts.get(fromAccountId);
    const toAccount = accounts.get(toAccountId);

    if (!fromAccount || !toAccount) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Fixed: Verify user owns the source account (Fixes #41)
    if (fromAccount.userId !== req.user.id) {
      return res.status(403).json({ error: 'You can only transfer from your own accounts' });
    }

    // Fixed: Per-account mutex ensures balance check + deduction are atomic
    // Locks both accounts in sorted order to prevent deadlocks (Fixes #33)
    const result = await accountLock.withLock([fromAccountId, toAccountId], async () => {
      // Fixed: Use integer arithmetic (cents) to avoid floating point issues (Fixes #10)
      const amountCents = Math.round(amount * 100);
      const fromBalanceCents = Math.round(fromAccount.balance * 100);

      // Overdraft protection: check happens inside the lock so it cannot be
      // interleaved with another concurrent deduction (Fixes #33)
      if (fromBalanceCents < amountCents) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }

      // Apply transfer using integer math then convert back
      fromAccount.balance = (fromBalanceCents - amountCents) / 100;
      toAccount.balance = (Math.round(toAccount.balance * 100) + amountCents) / 100;

      const transaction = {
        id: uuidv4(),
        fromAccountId,
        toAccountId,
        amount,
        description: description || '',
        status: 'completed',
        createdAt: new Date(),
        idempotencyKey: idempotencyKey || null,
      };

      transactions.set(transaction.id, transaction);

      // Store idempotency key result
      if (idempotencyKey) {
        processedIdempotencyKeys.set(idempotencyKey, transaction);
      }

      logger.info(`Transfer completed: ${transaction.id}, amount: ${amount}`);
      return res.status(201).json(transaction);
    });
  } catch (err) {
    logger.error('Transfer error:', err);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

router.get('/history', async (req, res) => {
  try {
    const { accountId, startDate, endDate, limit } = req.query;

    // Fixed: Filter transactions to only show user's own (Fixes #42)
    let userTransactions = Array.from(transactions.values()).filter((t) => {
      const fromAcc = accounts.get(t.fromAccountId);
      const toAcc = accounts.get(t.toAccountId);
      return (fromAcc && fromAcc.userId === req.user.id) || (toAcc && toAcc.userId === req.user.id);
    });

    if (accountId) {
      userTransactions = userTransactions.filter(
        (t) => t.fromAccountId === accountId || t.toAccountId === accountId
      );
    }

    // Fixed: Use proper Date comparison instead of string comparison (Fixes #11)
    if (startDate) {
      const start = new Date(startDate);
      userTransactions = userTransactions.filter((t) => new Date(t.createdAt) >= start);
    }
    if (endDate) {
      const end = new Date(endDate);
      userTransactions = userTransactions.filter((t) => new Date(t.createdAt) <= end);
    }

    // Fixed: Parse limit as integer (Fixes #32)
    if (limit) {
      userTransactions = userTransactions.slice(0, parseInt(limit, 10));
    }

    res.json(userTransactions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const transaction = transactions.get(req.params.id);

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Fixed: Authorization check (Fixes #42)
    const fromAcc = accounts.get(transaction.fromAccountId);
    const toAcc = accounts.get(transaction.toAccountId);
    const isOwner = (fromAcc && fromAcc.userId === req.user.id) || (toAcc && toAcc.userId === req.user.id);
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(transaction);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transaction' });
  }
});

// Fixed: Proper transaction cancellation with balance reversal (Fixes #8)
router.post('/:id/cancel', async (req, res) => {
  try {
    const transaction = transactions.get(req.params.id);

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status === 'cancelled') {
      return res.status(400).json({ error: 'Transaction already cancelled' });
    }

    // Fixed: Reverse the balance changes (Fixes #8)
    const fromAccount = accounts.get(transaction.fromAccountId);
    const toAccount = accounts.get(transaction.toAccountId);

    if (fromAccount && toAccount) {
      const amountCents = Math.round(transaction.amount * 100);
      fromAccount.balance = (Math.round(fromAccount.balance * 100) + amountCents) / 100;
      toAccount.balance = (Math.round(toAccount.balance * 100) - amountCents) / 100;
    }

    transaction.status = 'cancelled';
    transaction.cancelledAt = new Date();
    res.json({ message: 'Transaction cancelled and balances reversed', transaction });
  } catch (err) {
    res.status(500).json({ error: 'Failed to cancel transaction' });
  }
});

module.exports = router;
