const Joi = require('joi');

const accountSchema = Joi.object({
  name: Joi.string().min(1).max(100).required(),
  type: Joi.string().valid('checking', 'savings', 'investment').required(),
  currency: Joi.string().length(3).default('USD'),
  initialBalance: Joi.number().min(0).default(0),
});

const transactionSchema = Joi.object({
  fromAccountId: Joi.string().uuid().required(),
  toAccountId: Joi.string().uuid().required(),
  amount: Joi.number().positive().required(),
  description: Joi.string().max(500),
  currency: Joi.string().length(3).default('USD'),
  idempotencyKey: Joi.string().uuid(),
});

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  // Fixed: Enforce strong passwords for financial app (Fixes #23)
  password: Joi.string().min(12).max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+\[\]{}|;:'",.<>\/\\`~])/)
    .required()
    .messages({
      'string.min': 'Password must be at least 12 characters long',
      'string.max': 'Password must not exceed 128 characters',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'string.empty': 'Password is required',
    }),
  name: Joi.string().min(1).max(100).required(),
  role: Joi.string().valid('user', 'admin', 'auditor'),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

module.exports = {
  accountSchema,
  transactionSchema,
  userSchema,
  loginSchema,
};
