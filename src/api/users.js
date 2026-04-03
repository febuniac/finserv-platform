const express = require('express');
const { logger } = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { encrypt } = require('../utils/crypto');

const router = express.Router();

// In-memory user store
const users = new Map();

router.use(authenticateToken);

router.get('/profile', async (req, res) => {
  try {
    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // BUG: Returning sensitive fields including password hash
    res.json(user);
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

    // SECURITY: Mass assignment vulnerability - user can change their own role
    const updated = { ...user, ...req.body, updatedAt: new Date() };
    users.set(req.user.email, updated);

    logger.info(`Profile updated for ${req.user.email}`);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Admin endpoint
router.get('/all', requireRole('admin'), async (req, res) => {
  try {
    // SECURITY: Returns all user data including password hashes
    const allUsers = Array.from(users.values());
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

    // BUG: No check to prevent admin from deleting themselves
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

    // BUG: Setting wrong content-type for encrypted data
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=user-data.enc');
    res.send(encryptedData);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export data' });
  }
});

module.exports = router;
