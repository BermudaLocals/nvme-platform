const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const auth = require('../middleware/auth');
const router = express.Router();

// Get wallet balance and transactions
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('wallet.transactions');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      balance: user.wallet.balance,
      transactions: user.wallet.transactions
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get transaction history
router.get('/transactions', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.json(transactions);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add funds to wallet
router.post('/deposit', auth, [
  body('amount').isNumeric().withMessage('Amount must be a number'),
  body('paymentMethod').isIn(['paypal', 'cashapp', 'applepay', 'googlepay', 'crypto', 'bermudabank', 'wire']),
  body('reference').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, paymentMethod, reference } = req.body;

    if (amount <= 0) {
      return res.status(400).json({ message: 'Amount must be greater than 0' });
    }

    // Create transaction
    const transaction = new Transaction({
      user: req.user.id,
      type: 'deposit',
      amount,
      paymentMethod,
      description: `Deposit via ${paymentMethod}`,
      reference,
      status: 'pending'
    });

    await transaction.save();

    // In a real implementation, you would process the payment here
    // For now, we'll just mark it as completed
    transaction.status = 'completed';
    transaction.completedAt = new Date();
    await transaction.save();

    // Update user balance
    const user = await User.findById(req.user.id);
    user.wallet.balance += amount;
    user.wallet.transactions.push(transaction._id);
    await user.save();

    res.json({
      transaction,
      newBalance: user.wallet.balance
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Withdraw funds from wallet
router.post('/withdraw', auth, [
  body('amount').isNumeric().withMessage('Amount must be a number'),
  body('paymentMethod').isIn(['paypal', 'cashapp', 'crypto', 'bermudabank', 'wire']),
  body('recipient').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, paymentMethod, recipient } = req.body;

    if (amount <= 0) {
      return res.status(400).json({ message: 'Amount must be greater than 0' });
    }

    const user = await User.findById(req.user.id);

    if (user.wallet.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Create transaction
    const transaction = new Transaction({
      user: req.user.id,
      type: 'withdrawal',
      amount: -amount,
      paymentMethod,
      description: `Withdrawal via ${paymentMethod}`,
      status: 'pending'
    });

    await transaction.save();

    // In a real implementation, you would process the withdrawal here
    // For now, we'll just mark it as pending
    // Update user balance (will be updated when withdrawal is completed)
    user.wallet.balance -= amount;
    user.wallet.transactions.push(transaction._id);
    await user.save();

    res.json({
      transaction,
      newBalance: user.wallet.balance,
      message: 'Withdrawal request submitted. It will be processed shortly.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;