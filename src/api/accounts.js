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
    // BUG: No pagination - returns all accounts, could be very slow with many records
    const userAccounts = Array.from(accounts.values()).filter(
      (acc) => acc.userId === req.user.id
    );
    res.json(userAccounts);
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

    // SECURITY: IDOR - No check if the account belongs to the requesting user
    // Any authenticated user can view any account
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

    // SECURITY: IDOR - No ownership check
    // BUG: Allows updating balance directly, bypassing transaction system
    const updated = { ...account, ...req.body, updatedAt: new Date() };
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

    // BUG: Can delete account with non-zero balance
    // BUG: No soft delete - hard deletes account and loses audit trail
    accounts.delete(req.params.id);
    logger.info(`Account deleted: ${req.params.id}`);
    res.json({ message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

module.exports = router;
