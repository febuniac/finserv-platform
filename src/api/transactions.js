const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { logger } = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');
const { transactionSchema } = require('../utils/validation');

const router = express.Router();

// In-memory stores
const transactions = new Map();
const accounts = new Map();

router.use(authenticateToken);

router.post('/transfer', async (req, res) => {
  try {
    const { error, value } = transactionSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { fromAccountId, toAccountId, amount, description } = value;
    const fromAccount = accounts.get(fromAccountId);
    const toAccount = accounts.get(toAccountId);

    if (!fromAccount || !toAccount) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // BUG: No check if user owns the source account
    // BUG: Race condition - no locking mechanism for concurrent transfers
    if (fromAccount.balance < amount) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // BUG: Not using database transactions - if second update fails, money disappears
    fromAccount.balance -= amount;
    toAccount.balance += amount;

    // BUG: Floating point arithmetic issues with currency
    // e.g., 0.1 + 0.2 !== 0.3 in JavaScript

    const transaction = {
      id: uuidv4(),
      fromAccountId,
      toAccountId,
      amount,
      description: description || '',
      status: 'completed',
      createdAt: new Date(),
      // BUG: No idempotency key - duplicate requests create duplicate transactions
    };

    transactions.set(transaction.id, transaction);
    logger.info(`Transfer completed: ${transaction.id}, amount: ${amount}`);

    res.status(201).json(transaction);
  } catch (err) {
    logger.error('Transfer error:', err);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

router.get('/history', async (req, res) => {
  try {
    const { accountId, startDate, endDate, limit } = req.query;

    let userTransactions = Array.from(transactions.values());

    if (accountId) {
      userTransactions = userTransactions.filter(
        (t) => t.fromAccountId === accountId || t.toAccountId === accountId
      );
    }

    // BUG: Date filtering doesn't work correctly - string comparison instead of date comparison
    if (startDate) {
      userTransactions = userTransactions.filter((t) => t.createdAt > startDate);
    }
    if (endDate) {
      userTransactions = userTransactions.filter((t) => t.createdAt < endDate);
    }

    // BUG: limit is a string from query params, comparison doesn't work as expected
    if (limit) {
      userTransactions = userTransactions.slice(0, limit);
    }

    // BUG: No authorization check - can see any user's transactions
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

    // SECURITY: No authorization check
    res.json(transaction);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transaction' });
  }
});

// BUG: Allowing transaction cancellation without proper reversal logic
router.post('/:id/cancel', async (req, res) => {
  try {
    const transaction = transactions.get(req.params.id);

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // BUG: Just changes status without reversing the actual balance changes
    transaction.status = 'cancelled';
    res.json({ message: 'Transaction cancelled', transaction });
  } catch (err) {
    res.status(500).json({ error: 'Failed to cancel transaction' });
  }
});

module.exports = router;
