const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const auth = require('../middleware/auth');
const router = express.Router();

// Get user profile
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      profile: user.profile,
      stats: user.stats,
      subscription: user.subscription,
      wallet: user.wallet
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
router.put('/profile', auth, [
  body('displayName').optional().isLength({ min: 1, max: 50 }),
  body('bio').optional().isLength({ max: 500 }),
  body('location').optional().isLength({ max: 100 }),
  body('website').optional().isURL()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { displayName, bio, location, website } = req.body;
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update profile fields
    if (displayName) user.profile.displayName = displayName;
    if (bio !== undefined) user.profile.bio = bio;
    if (location) user.profile.location = location;
    if (website) user.profile.website = website;

    await user.save();

    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      profile: user.profile,
      stats: user.stats,
      subscription: user.subscription,
      wallet: user.wallet
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get public user profile
router.get('/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user._id,
      username: user.username,
      profile: user.profile,
      stats: user.stats
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Follow/unfollow user
router.post('/:userId/follow', auth, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const currentUserId = req.user.id;

    if (targetUserId === currentUserId) {
      return res.status(400).json({ message: 'You cannot follow yourself' });
    }

    const targetUser = await User.findById(targetUserId);
    const currentUser = await User.findById(currentUserId);

    if (!targetUser || !currentUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if already following
    const isFollowing = currentUser.following && currentUser.following.includes(targetUserId);

    if (isFollowing) {
      // Unfollow
      currentUser.following = currentUser.following.filter(id => id.toString() !== targetUserId);
      targetUser.followers = targetUser.followers.filter(id => id.toString() !== currentUserId);
      targetUser.stats.followers--;
      currentUser.stats.following--;
    } else {
      // Follow
      if (!currentUser.following) currentUser.following = [];
      if (!targetUser.followers) targetUser.followers = [];
      
      currentUser.following.push(targetUserId);
      targetUser.followers.push(currentUserId);
      targetUser.stats.followers++;
      currentUser.stats.following++;
    }

    await currentUser.save();
    await targetUser.save();

    res.json({
      following: !isFollowing,
      followersCount: targetUser.stats.followers,
      followingCount: currentUser.stats.following
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;