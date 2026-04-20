const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const auth = require('../middleware/auth');
const router = express.Router();

// Get available payment providers
router.get('/providers', auth, async (req, res) => {
  try {
    const providers = [
      { id: 'paypal', name: 'PayPal', status: 'active' },
      { id: 'cashapp', name: 'Cash App', status: 'active' },
      { id: 'applepay', name: 'Apple Pay', status: 'active' },
      { id: 'googlepay', name: 'Google Pay', status: 'active' },
      { id: 'crypto', name: 'Cryptocurrency', status: 'active' },
      { id: 'bermudabank', name: 'Bermuda Bank', status: 'active' },
      { id: 'wire', name: 'Wire Transfer', status: 'active' }
    ];

    res.json(providers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Process payment
router.post('/checkout', auth, [
  body('amount').isNumeric().withMessage('Amount must be a number'),
  body('paymentMethod').isIn(['paypal', 'cashapp', 'applepay', 'googlepay', 'crypto', 'bermudabank', 'wire']),
  body('plan').optional().isIn(['creator', 'pro', 'legend'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, paymentMethod, plan } = req.body;

    if (amount <= 0) {
      return res.status(400).json({ message: 'Amount must be greater than 0' });
    }

    // Create transaction
    const transaction = new Transaction({
      user: req.user.id,
      type: plan ? 'subscription' : 'deposit',
      amount,
      paymentMethod,
      description: plan ? `Subscription: ${plan} plan` : `Deposit via ${paymentMethod}`,
      status: 'pending'
    });

    await transaction.save();

    // In a real implementation, you would integrate with payment providers here
    // For now, we'll simulate a successful payment
    setTimeout(async () => {
      transaction.status = 'completed';
      transaction.completedAt = new Date();
      await transaction.save();

      // Update user balance or subscription
      const user = await User.findById(req.user.id);
      
      if (plan) {
        // Update subscription
        user.subscription.plan = plan;
        user.subscription.status = 'active';
        user.subscription.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
      } else {
        // Update balance
        user.wallet.balance += amount;
        user.wallet.transactions.push(transaction._id);
      }
      
      await user.save();
    }, 2000); // Simulate 2-second processing time

    res.json({
      transaction,
      message: 'Payment processing. You will be notified when completed.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Request payout
router.post('/payout', auth, [
  body('amount').isNumeric().withMessage('Amount must be a number'),
  body('paymentMethod').isIn(['paypal', 'cashapp', 'crypto', 'bermudabank', 'wire']),
  body('recipient').notEmpty().withMessage('Recipient information is required')
], async (req, res) => {
  try {
    javascript
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
      description: `Payout via ${paymentMethod}`,
      status: 'pending',
      metadata: { recipient }
    });

    await transaction.save();

    // Update user balance
    user.wallet.balance -= amount;
    user.wallet.transactions.push(transaction._id);
    await user.save();

    res.json({
      transaction,
      message: 'Payout request submitted. It will be processed within 24-48 hours.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;