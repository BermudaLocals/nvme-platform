const express = require('express');
const { body, validationResult } = require('express-validator');
const Game = require('../models/Game');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const auth = require('../middleware/auth');
const router = express.Router();

// Play Crown & Anchor game
router.post('/crown-anchor', auth, [
  body('betAmount').isNumeric().withMessage('Bet amount must be a number'),
  body('selectedSymbol').isIn(['👑', '⚓', '❤️', '💎', '♣️', '⚡'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { betAmount, selectedSymbol } = req.body;

    if (betAmount <= 0) {
      return res.status(400).json({ message: 'Bet amount must be greater than 0' });
    }

    const user = await User.findById(req.user.id);

    if (user.wallet.balance < betAmount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Create game record
    const game = new Game({
      user: req.user.id,
      gameType: 'crown-anchor',
      betAmount,
      selectedSymbol
    });

    // Generate random results
    const symbols = ['👑', '⚓', '❤️', '💎', '♣️', '⚡'];
    const results = [
      symbols[Math.floor(Math.random() * symbols.length)],
      symbols[Math.floor(Math.random() * symbols.length)],
      symbols[Math.floor(Math.random() * symbols.length)]
    ];

    game.results = results;

    // Calculate matches and payout
    const matches = results.filter(symbol => symbol === selectedSymbol).length;
    game.matches = matches;
    game.payout = matches * betAmount;
    game.status = matches > 0 ? 'won' : 'lost';

    await game.save();

    // Update user balance
    if (matches > 0) {
      user.wallet.balance += game.payout;
      
      // Create transaction for winnings
      const transaction = new Transaction({
        user: req.user.id,
        type: 'earning',
        amount: game.payout,
        description: `Crown & Anchor winnings`,
        status: 'completed',
        paymentMethod: 'wallet'
      });
      
      await transaction.save();
      user.wallet.transactions.push(transaction._id);
    } else {
      user.wallet.balance -= betAmount;
      
      // Create transaction for bet
      const transaction = new Transaction({
        user: req.user.id,
        type: 'withdrawal',
        amount: -betAmount,
        description: `Crown & Anchor bet`,
        status: 'completed',
        paymentMethod: 'wallet'
      });
      
      await transaction.save();
      user.wallet.transactions.push(transaction._id);
    }

    await user.save();

    res.json({
      game,
      results,
      matches,
      payout: game.payout,
      newBalance: user.wallet.balance
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get game history
router.get('/history', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const games = await Game.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.json(games);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;