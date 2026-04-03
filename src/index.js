const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const { logger } = require('./utils/logger');
const authRoutes = require('./api/auth');
const accountRoutes = require('./api/accounts');
const transactionRoutes = require('./api/transactions');
const userRoutes = require('./api/users');
const reportRoutes = require('./api/reports');
const { errorHandler } = require('./middleware/errorHandler');
const { rateLimiter } = require('./middleware/rateLimiter');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(rateLimiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/accounts', accountRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/users', userRoutes);
app.use('/api/reports', reportRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.4.1' });
});

// Error handler
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`FinServ Platform running on port ${PORT}`);
});

module.exports = app;
