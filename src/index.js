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
const { csrfProtection } = require('./middleware/auth');
const { httpsEnforcement } = require('./middleware/httpsEnforcement');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Enforce HTTPS before any other middleware so insecure requests are
// redirected immediately without processing through CORS/helmet/etc.
app.use(httpsEnforcement);

// Fixed: Restrict CORS to allowed origins instead of wildcard (Fixes #30)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. server-to-server, curl)
    if (!origin) {
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn(`CORS request blocked from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 86400,
};
app.use(cors(corsOptions));

// Fixed: Enhanced security headers (Fixes #21)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

app.use(express.json({ limit: '10kb' }));
app.use(rateLimiter);
app.use(csrfProtection);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/accounts', accountRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/users', userRoutes);
app.use('/api/reports', reportRoutes);

// CSRF token endpoint – clients call this to obtain a token for state-changing requests
app.get('/api/csrf-token', (req, res) => {
  // The csrfProtection middleware already sets the cookie on GET requests.
  // Read it back so the client has the value without parsing cookies themselves.
  const crypto = require('crypto');
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)_csrf_token=([^;]+)/);
  const token = match ? match[1] : res.getHeader('set-cookie')?.toString().match(/_csrf_token=([^;]+)/)?.[1];
  res.json({ csrfToken: token || null });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.4.1' });
});

// Error handler
app.use(errorHandler);

if (require.main === module) {
  app.listen(PORT, () => {
    logger.info(`FinServ Platform running on port ${PORT}`);
  });
}

module.exports = app;
