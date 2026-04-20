const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'gift', 'earning', 'subscription'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'USD'
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  description: String,
  reference: {
    type: String,
    unique: true
  },
  paymentMethod: {
    type: String,
    enum: ['paypal', 'cashapp', 'applepay', 'googlepay', 'crypto', 'bermudabank', 'wire', 'stripe'],
    required: true
  },
  metadata: {
    contentId: mongoose.Schema.Types.ObjectId,
    giftId: String,
    senderId: mongoose.Schema.Types.ObjectId,
    recipientId: mongoose.Schema.Types.ObjectId
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  completedAt: Date
}, {
  timestamps: true
});

// Generate reference ID before saving
transactionSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
  }
  next();
});

module.exports = mongoose.model('Transaction', transactionSchema);