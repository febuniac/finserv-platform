const express = require('express');
const { logger } = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { exec } = require('child_process');

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

    // SECURITY: Command injection vulnerability
    if (type === 'disk') {
      exec(`df -h ${req.query.path || '/'}`, (error, stdout) => {
        if (error) {
          return res.status(500).json({ error: 'Report generation failed' });
        }
        res.json({ report: stdout });
      });
      return;
    }

    // SECURITY: Another command injection via user input
    if (type === 'logs') {
      const logFile = req.query.file || 'combined.log';
      exec(`tail -100 ${logFile}`, (error, stdout) => {
        if (error) {
          return res.status(500).json({ error: 'Failed to read logs' });
        }
        res.json({ logs: stdout });
      });
      return;
    }

    res.json({
      totalUsers: 0,
      totalAccounts: 0,
      totalTransactions: 0,
      systemUptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      // SECURITY: Exposing environment variables
      environment: process.env,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Export report as CSV
router.get('/export/csv', async (req, res) => {
  try {
    // BUG: SQL injection if this were using a real database
    const query = `SELECT * FROM transactions WHERE user_id = '${req.user.id}' AND date > '${req.query.startDate}'`;
    logger.info(`Generating CSV report with query: ${query}`);

    // BUG: Not actually executing query, just simulating
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=report.csv');
    res.send('id,date,amount,description\n');
  } catch (err) {
    res.status(500).json({ error: 'Failed to export report' });
  }
});

module.exports = router;
