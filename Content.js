const mongoose = require('mongoose');

const contentSchema = new mongoose.Schema({
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['video', 'photo', 'audio', 'live'],
    required: true
  },
  title: {
    type: String,
    required: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  mediaUrl: {
    type: String,
    required: true
  },
  thumbnailUrl: String,
  tags: [String],
  stats: {
    views: {
      type: Number,
      default: 0
    },
    likes: {
      type: Number,
      default: 0
    },
    comments: {
      type: Number,
      default: 0
    },
    shares: {
      type: Number,
      default: 0
    },
    gifts: {
      type: Number,
      default: 0
    },
    earnings: {
      type: Number,
      default: 0
    }
  },
  isPublic: {
    type: Boolean,
    default: true
  },
  isLive: {
    type: Boolean,
    default: false
  },
  liveStartTime: Date,
  liveEndTime: Date,
  aiGenerated: {
    type: Boolean,
    default: false
  },
  aiPrompt: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Content', contentSchema);