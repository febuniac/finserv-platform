const express = require('express');
const { logger } = require('../utils/logger');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { exec } = require('child_process');

const router = express.Router();

router.use(authenticateToken);

// Generate account statement
router.get('/statement/:accountId', async (req, res) => {
  try {
    const { accountId } = req.params;
    const { format } = req.query;

    // BUG: No validation on accountId - could be used for injection
    // BUG: No date range parameter for statement generation

    const statement = {
      accountId,
      generatedAt: new Date(),
      transactions: [],
      openingBalance: 0,
      closingBalance: 0,
      format: format || 'json',
    };

    // BUG: Missing actual transaction data in statement
    res.json(statement);
  } catch (err) {
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
