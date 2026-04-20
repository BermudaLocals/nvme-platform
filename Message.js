const express = require('express');
const { body, validationResult } = require('express-validator');
const Message = require('../models/Message');
const User = require('../models/User');
const auth = require('../middleware/auth');
const router = express.Router();

// Get conversations list
router.get('/', auth, async (req, res) => {
  try {
    // Get all messages where user is sender or recipient
    const messages = await Message.find({
      $or: [
        { sender: req.user.id },
        { recipient: req.user.id }
      ]
    })
    .sort({ createdAt: -1 })
    .populate('sender', 'username profile.displayName profile.avatar')
    .populate('recipient', 'username profile.displayName profile.avatar');

    // Group messages by conversation
    const conversations = {};
    messages.forEach(message => {
      const otherUserId = message.sender._id.toString() === req.user.id.toString() 
        ? message.recipient._id.toString() 
        : message.sender._id.toString();
      
      if (!conversations[otherUserId]) {
        conversations[otherUserId] = {
          user: message.sender._id.toString() === req.user.id.toString() ? message.recipient : message.sender,
          lastMessage: message,
          unreadCount: 0
        };
      }
      
      // Count unread messages
      if (message.recipient._id.toString() === req.user.id.toString() && !message.isRead) {
        conversations[otherUserId].unreadCount++;
      }
    });

    // Convert to array and sort by last message time
    const conversationList = Object.values(conversations).sort((a, b) => 
      new Date(b.lastMessage.createdAt) - new Date(a.lastMessage.createdAt)
    );

    res.json(conversationList);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get conversation with specific user
router.get('/:userId', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const messages = await Message.find({
      $or: [
        { sender: req.user.id, recipient: req.params.userId },
        { sender: req.params.userId, recipient: req.user.id }
      ]
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .populate('sender', 'username profile.displayName profile.avatar')
    .populate('recipient', 'username profile.displayName profile.avatar');

    // Mark messages as read
    await Message.updateMany(
      { sender: req.params.userId, recipient: req.user.id, isRead: false },
      { isRead: true, readAt: new Date() }
    );

    res.json(messages.reverse()); // Reverse to show oldest first
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send message
router.post('/', auth, [
  body('recipient').isMongoId().withMessage('Invalid recipient ID'),
  body('content').isLength({ min: 1, max: 1000 }).withMessage('Message content is required'),
  body('messageType').optional().isIn(['text', 'image', 'video', 'audio', 'gift'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { recipient, content, messageType, mediaUrl } = req.body;

    // Check if recipient exists
    const recipientUser = await User.findById(recipient);
    if (!recipientUser) {
      return res.status(404).json({ message: 'Recipient not found' });
    }

    // Create message
    const message = new Message({
      sender: req.user.id,
      recipient,
      content,
      messageType: messageType || 'text',
      mediaUrl
    });

    await message.save();

    // Populate sender and recipient info
    await message.populate('sender', 'username profile.displayName profile.avatar');
    await message.populate('recipient', 'username profile.displayName profile.avatar');

    // Emit real-time message via socket.io
    const io = req.app.get('io');
    if (io) {
      io.to(`user-${recipient}`).emit('new-message', message);
    }

    res.status(201).json(message);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete message
router.delete('/:messageId', auth, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);

    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Check if user is sender or recipient
    if (message.sender.toString() !== req.user.id && message.recipient.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to delete this message' });
    }

    await Message.findByIdAndDelete(req.params.messageId);

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;