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
  // BUG: Missing currency validation allows cross-currency transfers without conversion
});

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(), // BUG: Min 6 is too weak for a financial app
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
