const express = require('express');
const { body, validationResult } = require('express-validator');
const Content = require('../models/Content');
const auth = require('../middleware/auth');
const router = express.Router();

// Get feed content
router.get('/feed', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const content = await Content.find({ isPublic: true })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('creator', 'username profile.displayName profile.avatar');

    res.json(content);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's content
router.get('/user/:userId', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const content = await Content.find({ 
      creator: req.params.userId,
      isPublic: true 
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('creator', 'username profile.displayName profile.avatar');

    res.json(content);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new content
router.post('/', auth, [
  body('type').isIn(['video', 'photo', 'audio', 'live']),
  body('title').isLength({ min: 1, max: 100 }),
  body('mediaUrl').isURL(),
  body('description').optional().isLength({ max: 500 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { type, title, mediaUrl, thumbnailUrl, description, tags, isLive, aiGenerated, aiPrompt } = req.body;

    const content = new Content({
      creator: req.user.id,
      type,
      title,
      mediaUrl,
      thumbnailUrl,
      description,
      tags: tags || [],
      isLive: isLive || false,
      liveStartTime: isLive ? new Date() : undefined,
      aiGenerated: aiGenerated || false,
      aiPrompt
    });

    await content.save();

    // Update user's post count
    const User = require('../models/User');
    await User.findByIdAndUpdate(req.user.id, { $inc: { 'stats.posts': 1 } });

    res.status(201).json(content);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like content
router.post('/:contentId/like', auth, async (req, res) => {
  try {
    const content = await Content.findById(req.params.contentId);
    if (!content) {
      return res.status(404).json({ message: 'Content not found' });
    }

    content.stats.likes++;
    await content.save();

    res.json({ likes: content.stats.likes });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// View content
router.post('/:contentId/view', async (req, res) => {
  try {
    const content = await Content.findById(req.params.contentId);
    if (!content) {
      return res.status(404).json({ message: 'Content not found' });
    }

    content.stats.views++;
    await content.save();

    // Update creator's total views
    const User = require('../models/User');
    await User.findByIdAndUpdate(content.creator, { $inc: { 'stats.views': 1 } });

    res.json({ views: content.stats.views });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get content details
router.get('/:contentId', async (req, res) => {
  try {
    const content = await Content.findById(req.params.contentId)
      .populate('creator', 'username profile.displayName profile.avatar');

    if (!content) {
      return res.status(404).json({ message: 'Content not found' });
    }

    res.json(content);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;