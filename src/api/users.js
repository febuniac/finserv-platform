const express = require('express');
const { logger } = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { encrypt } = require('../utils/crypto');
const { getStore } = require('../utils/persistentStore');
const { sanitizeString } = require('../utils/sanitize');

const router = express.Router();

// Persistent user store (survives server restarts)
const users = getStore('users');

router.use(authenticateToken);

router.get('/profile', async (req, res) => {
  try {
    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Fixed: Strip password hash from response (Fixes #36)
    const { password, ...safeUser } = user;
    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

router.put('/profile', async (req, res) => {
  try {
    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Fixed: Only allow safe fields to be updated (Fixes #15, #22)
    // SECURITY: Allowlist prevents mass-assignment of role, email, id, password, etc.
    const allowedFields = ['name'];
    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = typeof req.body[field] === 'string' ? sanitizeString(req.body[field]) : req.body[field];
      }
    }
    const updated = { ...user, ...updates, updatedAt: new Date() };
    users.set(req.user.email, updated);

    logger.info(`Profile updated for ${req.user.email}`);
    const { password, ...safeUpdated } = updated;
    res.json(safeUpdated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Admin endpoint
router.get('/all', requireRole('admin'), async (req, res) => {
  try {
    // Fixed: Strip password hashes from response (Fixes #36)
    const allUsers = Array.from(users.values()).map(({ password, ...safe }) => safe);
    res.json(allUsers);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

router.delete('/:id', requireRole('admin'), async (req, res) => {
  try {
    // BUG: Deleting by ID but Map is keyed by email
    const found = Array.from(users.entries()).find(([, u]) => u.id === req.params.id);

    if (!found) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Prevent admin from deleting themselves
    if (found[0] === req.user.email) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    users.delete(found[0]);
    logger.info(`User deleted: ${req.params.id}`);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Export user data
router.get('/export', async (req, res) => {
  try {
    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // SECURITY: Encrypting with weak DES algorithm from crypto.js
    const encryptedData = encrypt(JSON.stringify(user));

    // Fixed: Set correct content-type for encrypted binary data
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename=user-data.enc');
    res.send(encryptedData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export data' });
  }
});

module.exports = router;
