const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { logger } = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');
const { accountSchema } = require('../utils/validation');

const router = express.Router();

// In-memory account store
const accounts = new Map();

router.use(authenticateToken);

router.post('/', async (req, res) => {
  try {
    const { error, value } = accountSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const account = {
      id: uuidv4(),
      userId: req.user.id,
      name: value.name,
      type: value.type,
      currency: value.currency,
      balance: value.initialBalance,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    accounts.set(account.id, account);
    logger.info(`Account created: ${account.id} for user ${req.user.id}`);
    res.status(201).json(account);
  } catch (err) {
    logger.error('Account creation error:', err);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

router.get('/', async (req, res) => {
  try {
    // Fixed: Add pagination (Fixes #39)
    const page = parseInt(req.query.page || '1', 10);
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const offset = (page - 1) * limit;

    const userAccounts = Array.from(accounts.values()).filter(
      (acc) => acc.userId === req.user.id
    );

    const paginated = userAccounts.slice(offset, offset + limit);
    res.json({
      data: paginated,
      pagination: { page, limit, total: userAccounts.length, totalPages: Math.ceil(userAccounts.length / limit) },
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const account = accounts.get(req.params.id);

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Fixed: Check account ownership to prevent IDOR (Fixes #4)
    if (account.userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(account);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch account' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const account = accounts.get(req.params.id);

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Fixed: Check ownership (Fixes #4)
    if (account.userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Fixed: Only allow safe fields, prevent direct balance manipulation (Fixes #44)
    const allowedFields = ['name', 'type', 'currency', 'status'];
    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    }

    const updated = { ...account, ...updates, updatedAt: new Date() };
    accounts.set(req.params.id, updated);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update account' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const account = accounts.get(req.params.id);

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Fixed: Check ownership
    if (account.userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Fixed: Prevent deletion of accounts with non-zero balance (Fixes #13)
    if (account.balance !== 0) {
      return res.status(400).json({ error: 'Cannot delete account with non-zero balance. Transfer or withdraw funds first.' });
    }

    // Fixed: Soft delete instead of hard delete (Fixes #45)
    account.status = 'deleted';
    account.deletedAt = new Date();
    account.updatedAt = new Date();
    accounts.set(req.params.id, account);

    logger.info(`Account soft-deleted: ${req.params.id}`);
    res.json({ message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

module.exports = router;
