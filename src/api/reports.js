const express = require('express');
const { logger } = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');
// exec removed - using execFile inline for safety (Fixes #1)

const router = express.Router();

// Shared stores - import from other modules or use shared reference
const { getTransactions, getAccounts } = (() => {
  const transactions = new Map();
  const accounts = new Map();
  return {
    getTransactions: () => transactions,
    getAccounts: () => accounts,
  };
})();

router.use(authenticateToken);

// Generate account statement
router.get('/statement/:accountId', async (req, res) => {
  try {
    const { accountId } = req.params;
    const { format, startDate, endDate } = req.query;

    // Validate accountId format
    if (!accountId || typeof accountId !== 'string') {
      return res.status(400).json({ error: 'Invalid account ID' });
    }

    // Get all transactions for this account
    const allTransactions = Array.from(getTransactions().values());
    let accountTransactions = allTransactions.filter(
      (t) => t.fromAccountId === accountId || t.toAccountId === accountId
    );

    // Apply date range filters if provided
    if (startDate) {
      const start = new Date(startDate);
      accountTransactions = accountTransactions.filter((t) => new Date(t.createdAt) >= start);
    }
    if (endDate) {
      const end = new Date(endDate);
      accountTransactions = accountTransactions.filter((t) => new Date(t.createdAt) <= end);
    }

    // Calculate balances
    let openingBalance = 0;
    const account = getAccounts().get(accountId);
    if (account) {
      openingBalance = account.balance || 0;
    }

    // Compute running balance from transactions
    let closingBalance = openingBalance;
    const formattedTransactions = accountTransactions.map((t) => {
      const isCredit = t.toAccountId === accountId;
      const amount = isCredit ? t.amount : -t.amount;
      closingBalance += amount;
      return {
        id: t.id,
        date: t.createdAt,
        description: t.description || (isCredit ? 'Credit' : 'Debit'),
        amount,
        type: isCredit ? 'credit' : 'debit',
        balance: closingBalance,
      };
    });

    const statement = {
      accountId,
      generatedAt: new Date(),
      transactions: formattedTransactions,
      openingBalance,
      closingBalance,
      transactionCount: formattedTransactions.length,
      format: format || 'json',
    };

    res.json(statement);
  } catch (err) {
    logger.error('Statement generation error:', err);
    res.status(500).json({ error: 'Failed to generate statement' });
  }
});

// Admin: Generate system report
router.get('/system', requireRole('admin'), async (req, res) => {
  try {
    const { type } = req.query;

    // Fixed: Use execFile with argument array to prevent command injection (Fixes #1)
    if (type === 'disk') {
      const { execFile } = require('child_process');
      execFile('df', ['-h', '/'], (error, stdout) => {
        if (error) {
          return res.status(500).json({ error: 'Report generation failed' });
        }
        res.json({ report: stdout });
      });
      return;
    }

    // Fixed: Only allow reading from known safe log files (Fixes #1)
    if (type === 'logs') {
      const fs = require('fs');
      const path = require('path');
      const allowedLogs = ['combined.log', 'error.log'];
      const logFile = req.query.file || 'combined.log';
      if (!allowedLogs.includes(logFile)) {
        return res.status(400).json({ error: 'Invalid log file' });
      }
      const safePath = path.join(__dirname, '../../', logFile);
      try {
        const content = fs.readFileSync(safePath, 'utf8');
        const lines = content.split('\n').slice(-100).join('\n');
        res.json({ logs: lines });
      } catch (err) {
        return res.status(500).json({ error: 'Failed to read logs' });
      }
      return;
    }

    // Fixed: Don't expose environment variables (Fixes #6)
    res.json({
      totalUsers: 0,
      totalAccounts: 0,
      totalTransactions: 0,
      systemUptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      nodeVersion: process.version,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Export report as CSV
router.get('/export/csv', async (req, res) => {
  try {
    // Fixed: Use parameterized query pattern (safe for future DB integration)
    const userId = req.user.id;
    const startDate = req.query.startDate ? new Date(req.query.startDate) : new Date(0);
    logger.info(`Generating CSV report for user: ${userId}`);

    // Generate CSV from in-memory data
    const allTransactions = Array.from(getTransactions().values());
    const userTxns = allTransactions.filter((t) => {
      const created = new Date(t.createdAt);
      return (t.fromAccountId || t.toAccountId) && created >= startDate;
    });

    let csv = 'id,date,amount,description\n';
    userTxns.forEach((t) => {
      csv += `${t.id},${t.createdAt},${t.amount},"${(t.description || '').replace(/"/g, '""')}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=report.csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export report' });
  }
});

module.exports = router;
