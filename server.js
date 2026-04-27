require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 });
app.use('/api/', limiter);

// In-memory data stores
const videos = [];
const posts = [];
const stories = [];
const reels = [];
const tweets = [];
const channels = [];
const chats = [];
const messages = [];
const snaps = [];
const profiles = [];
const matches = [];
const friends = [];
const groups = [];

let giftsData = {};
try {
  giftsData = require('./gifts-500');
} catch (e) {
  console.log('gifts-500 not loaded:', e.message);
}
const gifts = giftsData.ALL_GIFTS || [];

// Health
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    version: '2.0.0',
    platform: 'NVME Creator Platform',
    emulates: ['TikTok', 'Instagram', 'YouTube', 'WhatsApp', 'Snapchat', 'X', 'Facebook', 'Dating'],
    timestamp: new Date().toISOString()
  });
});

app.get('/api/creators/stats', (req, res) => {
  res.json({
    totalCreators: 12847,
    activeNow: 3241,
    avgWeeklyEarnings: 500,
    revenueSplit: '55% creator / 45% platform',
    totalVideos: videos.length,
    totalPosts: posts.length
  });
});

// TikTok
app.get('/api/feed/fyp', (req, res) => {
  const feed = videos.slice(0, 20).map(v => ({ ...v, isFyp: true }));
  res.json({ feed, algorithm: 'engagement-based', count: feed.length });
});

app.post('/api/videos/upload', (req, res) => {
  const video = {
    id: uuidv4(), type: 'vertical', creatorId: req.body.creatorId,
    caption: req.body.caption, hashtags: req.body.hashtags || [],
    music: req.body.music, duration: req.body.duration || 60,
    views: 0, likes: 0, shares: 0, comments: 0,
    createdAt: new Date().toISOString()
  };
  videos.push(video);
  res.json({ success: true, video });
});

app.post('/api/videos/:id/like', (req, res) => {
  const video = videos.find(v => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: 'not found' });
  video.likes++;
  res.json({ success: true, likes: video.likes });
});

app.get('/api/trending/hashtags', (req, res) => {
  res.json({ trending: ['#fyp', '#viral', '#nvme', '#creator', '#dance', '#comedy', '#lifestyle', '#fitness'] });
});

// Instagram
app.post('/api/posts', (req, res) => {
  const post = {
    id: uuidv4(), creatorId: req.body.creatorId,
    images: req.body.images || [], caption: req.body.caption,
    location: req.body.location, likes: 0, comments: [],
    createdAt: new Date().toISOString()
  };
  posts.push(post);
  res.json({ success: true, post });
});

app.get('/api/posts', (req, res) => { res.json({ posts: posts.slice(0, 50), count: posts.length }); });

app.post('/api/stories', (req, res) => {
  const story = { id: uuidv4(), creatorId: req.body.creatorId, media: req.body.media,
    expiresAt: new Date(Date.now() + 24*60*60*1000).toISOString(), views: 0,
    createdAt: new Date().toISOString() };
  stories.push(story);
  res.json({ success: true, story });
});

app.get('/api/stories', (req, res) => {
  const active = stories.filter(s => new Date(s.expiresAt) > new Date());
  res.json({ stories: active });
});

app.post('/api/reels', (req, res) => {
  const reel = { id: uuidv4(), creatorId: req.body.creatorId, videoUrl: req.body.videoUrl,
    caption: req.body.caption, music: req.body.music, likes: 0,
    createdAt: new Date().toISOString() };
  reels.push(reel);
  res.json({ success: true, reel });
});

// YouTube
app.post('/api/channels', (req, res) => {
  const channel = { id: uuidv4(), name: req.body.name, ownerId: req.body.ownerId,
    subscribers: 0, totalViews: 0, videos: [], createdAt: new Date().toISOString() };
  channels.push(channel);
  res.json({ success: true, channel });
});

app.get('/api/channels', (req, res) => { res.json({ channels }); });

app.post('/api/channels/:id/subscribe', (req, res) => {
  const channel = channels.find(c => c.id === req.params.id);
  if (!channel) return res.status(404).json({ error: 'not found' });
  channel.subscribers++;
  res.json({ success: true, subscribers: channel.subscribers });
});

app.get('/api/videos/longform', (req, res) => {
  const longform = videos.filter(v => v.duration > 60);
  res.json({ videos: longform });
});

// WhatsApp
app.post('/api/chats', (req, res) => {
  const chat = { id: uuidv4(), participants: req.body.participants,
    type: req.body.type || 'direct', name: req.body.name,
    createdAt: new Date().toISOString() };
  chats.push(chat);
  res.json({ success: true, chat });
});

app.post('/api/messages', (req, res) => {
  const message = { id: uuidv4(), chatId: req.body.chatId, senderId: req.body.senderId,
    text: req.body.text, media: req.body.media, read: false,
    createdAt: new Date().toISOString() };
  messages.push(message);
  res.json({ success: true, message });
});

app.get('/api/chats/:id/messages', (req, res) => {
  const chatMessages = messages.filter(m => m.chatId === req.params.id);
  res.json({ messages: chatMessages });
});

app.post('/api/calls/initiate', (req, res) => {
  res.json({ success: true, callId: uuidv4(), type: req.body.type || 'video',
    participants: req.body.participants, startedAt: new Date().toISOString() });
});

// Snapchat
app.post('/api/snaps', (req, res) => {
  const snap = { id: uuidv4(), senderId: req.body.senderId, recipientId: req.body.recipientId,
    media: req.body.media, filter: req.body.filter, viewDuration: req.body.viewDuration || 10,
    expiresAt: new Date(Date.now() + 24*60*60*1000).toISOString() };
  snaps.push(snap);
  res.json({ success: true, snap });
});

app.get('/api/filters', (req, res) => {
  res.json({ filters: [
    { id: 'dog', name: 'Dog Face' },
    { id: 'flower-crown', name: 'Flower Crown' },
    { id: 'glasses', name: 'Retro Glasses' },
    { id: 'stars', name: 'Sparkling Stars' },
    { id: 'rainbow', name: 'Rainbow Puke' }
  ] });
});

app.get('/api/streaks/:userId', (req, res) => {
  res.json({ userId: req.params.userId, streaks: [], count: 0 });
});

// X / Twitter
app.post('/api/tweets', (req, res) => {
  const tweet = { id: uuidv4(), creatorId: req.body.creatorId, text: req.body.text,
    media: req.body.media, likes: 0, retweets: 0, replies: 0,
    createdAt: new Date().toISOString() };
  tweets.push(tweet);
  res.json({ success: true, tweet });
});

app.get('/api/tweets', (req, res) => { res.json({ tweets: tweets.slice(0, 50) }); });

app.post('/api/tweets/:id/retweet', (req, res) => {
  const tweet = tweets.find(tw => tw.id === req.params.id);
  if (!tweet) return res.status(404).json({ error: 'not found' });
  tweet.retweets++;
  res.json({ success: true, retweets: tweet.retweets });
});

app.get('/api/trends', (req, res) => {
  res.json({ trends: [
    { topic: '#NVME', posts: 52310 },
    { topic: '#CreatorEconomy', posts: 18452 },
    { topic: '#Viral', posts: 94821 },
    { topic: '#Bermuda', posts: 3214 }
  ] });
});

// Facebook
app.post('/api/friends/request', (req, res) => {
  const request = { id: uuidv4(), fromId: req.body.fromId, toId: req.body.toId,
    status: 'pending', createdAt: new Date().toISOString() };
  friends.push(request);
  res.json({ success: true, request });
});

app.get('/api/friends/:userId', (req, res) => {
  const userFriends = friends.filter(f => (f.fromId === req.params.userId || f.toId === req.params.userId) && f.status === 'accepted');
  res.json({ friends: userFriends });
});

app.post('/api/groups', (req, res) => {
  const group = { id: uuidv4(), name: req.body.name, description: req.body.description,
    ownerId: req.body.ownerId, members: [req.body.ownerId], privacy: req.body.privacy || 'public',
    createdAt: new Date().toISOString() };
  groups.push(group);
  res.json({ success: true, group });
});

app.get('/api/groups', (req, res) => { res.json({ groups }); });

app.post('/api/events', (req, res) => {
  res.json({ success: true, event: { id: uuidv4(), ...req.body, createdAt: new Date().toISOString() } });
});

// Dating (menus.ai style)
app.post('/api/dating/profile', (req, res) => {
  const profile = { id: uuidv4(), userId: req.body.userId, name: req.body.name,
    age: req.body.age, bio: req.body.bio, photos: req.body.photos || [],
    interests: req.body.interests || [], location: req.body.location,
    preferences: req.body.preferences, createdAt: new Date().toISOString() };
  profiles.push(profile);
  res.json({ success: true, profile });
});

app.get('/api/dating/discover/:userId', (req, res) => {
  const candidates = profiles.filter(p => p.userId !== req.params.userId).slice(0, 10);
  res.json({ candidates });
});

app.post('/api/dating/swipe', (req, res) => {
  const swipe = { id: uuidv4(), swiperId: req.body.swiperId, swipedId: req.body.swipedId,
    direction: req.body.direction, createdAt: new Date().toISOString() };
  if (swipe.direction === 'right') {
    const mutual = matches.find(m => m.swiperId === swipe.swipedId && m.swipedId === swipe.swiperId && m.direction === 'right');
    if (mutual) return res.json({ success: true, match: true, message: 'Its a match!' });
  }
  matches.push(swipe);
  res.json({ success: true, match: false });
});

app.get('/api/dating/matches/:userId', (req, res) => {
  const userMatches = matches.filter(m => (m.swiperId === req.params.userId || m.swipedId === req.params.userId) && m.direction === 'right');
  res.json({ matches: userMatches });
});

app.post('/api/dating/video-date', (req, res) => {
  res.json({ success: true, session: { id: uuidv4(), participants: req.body.participants,
    startedAt: new Date().toISOString(), duration: 300 } });
});

// Creator
app.post('/api/creators/signup', (req, res) => {
  res.json({ success: true, creator: { id: uuidv4(), email: req.body.email,
    username: req.body.username, createdAt: new Date().toISOString() }, trialDays: 14 });
});

// Creator profile setup / update — declared BEFORE /:id so 'profile' isn't treated as an id
const creatorProfiles = {}; // in-memory store; swap for DB when persistent
app.put('/api/creators/profile', (req, res) => {
  const { creatorId, displayName, bio, country, categories, avatar } = req.body || {};
  if (!creatorId || !displayName) {
    return res.status(400).json({ success: false, error: 'creatorId and displayName are §§secret(POSTGRESQL://NEONDB_OWNER:NPG_NX6JVZR2QMYG@EP-FALLING-PAPER-A62FLHPD.US-WEST-2.AWS.NEON.TECH/NEONDB?SSLMODE)d' });
  }
  const profile = { creatorId, displayName, bio: bio || '', country: country || '', categories: categories || [], avatar: avatar || null, updatedAt: new Date().toISOString() };
  creatorProfiles[creatorId] = profile;
  res.json({ success: §§secret(ALLOW_DANGEROUS_CODE_EXECUTION), profile, message: 'Profile saved' });
});

app.get('/api/creators/profile/:creatorId', (req, res) => {
  const profile = creatorProfiles[req.params.creatorId];
  if (!profile) return res.status(404).json({ success: false, error: 'Profile not found' });
  res.json({ success: §§secret(ALLOW_DANGEROUS_CODE_EXECUTION), profile });
});


app.get('/api/creators/:id', (req, res) => {
  res.json({ id: req.params.id, username: 'creator_' + req.params.id.slice(0, 8),
    followers: Math.floor(Math.random() * 100000),
    following: Math.floor(Math.random() * 1000),
    verified: Math.random() > 0.5 });
});

// Gifts
app.get('/api/gifts', (req, res) => { res.json({ gifts, count: gifts.length }); });

app.get('/api/gifts/random', (req, res) => {
  if (gifts.length === 0) return res.json({ gift: null });
  const gift = gifts[Math.floor(Math.random() * gifts.length)];
  res.json({ gift });
});

app.post('/api/gifts/send', (req, res) => {
  res.json({ success: true, transaction: { id: uuidv4(), giftId: req.body.giftId,
    fromId: req.body.fromId, toId: req.body.toId, amount: req.body.amount,
    creatorShare: req.body.amount * 0.55, platformShare: req.body.amount * 0.45,
    createdAt: new Date().toISOString() } });
});

// Payments
app.get('/api/payments/providers', (req, res) => {
  res.json({ providers: [
    { id: 'stripe', name: 'Stripe', active: true },
    { id: 'paypal', name: 'PayPal', active: true },
    { id: 'applepay', name: 'Apple Pay', active: true },
    { id: 'googlepay', name: 'Google Pay', active: true },
    { id: 'crypto', name: 'Crypto', active: true },
    { id: 'wire', name: 'Bank Wire', active: true }
  ] });
});

app.post('/api/payments/payout', (req, res) => {
  res.json({ success: true, payout: { id: uuidv4(), creatorId: req.body.creatorId,
    amount: req.body.amount, method: req.body.method, status: 'pending',
    estimatedArrival: new Date(Date.now() + 3*24*60*60*1000).toISOString() } });
});

// Live
app.post('/api/live/start', (req, res) => {
  res.json({ success: true, stream: { id: uuidv4(), creatorId: req.body.creatorId,
    title: req.body.title, viewers: 0, startedAt: new Date().toISOString() } });
});

app.get('/api/live/active', (req, res) => { res.json({ streams: [], count: 0 }); });

app.get('/api/activity', (req, res) => {
  res.json({ activities: [
    { type: 'signup', count: 47, period: 'last_hour' },
    { type: 'videos_uploaded', count: 283, period: 'last_hour' },
    { type: 'gifts_sent', count: 1528, period: 'last_hour' }
  ] });
});

// HUGE AI Avatar for big animated gifts
app.get('/huge-ai', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'huge-ai.html'));
});

// Crown & Anchor Game
app.get('/api/game/crown-anchor', (req, res) => {
  res.json({ game: 'Crown & Anchor',
    symbols: ['crown', 'anchor', 'heart', 'diamond', 'club', 'spade'],
    payouts: { single: 1, double: 2, triple: 3 },
    active: true });
});

app.post('/api/game/crown-anchor/roll', (req, res) => {
  const symbols = ['crown', 'anchor', 'heart', 'diamond', 'club', 'spade'];
  const roll = [symbols[Math.floor(Math.random()*6)], symbols[Math.floor(Math.random()*6)], symbols[Math.floor(Math.random()*6)]];
  const bet = req.body.bet || { symbol: 'crown', amount: 10 };
  const matchCount = roll.filter(s => s === bet.symbol).length;
  const winnings = matchCount * bet.amount;
  res.json({ roll, bet, matches: matchCount, winnings, result: matchCount > 0 ? 'win' : 'loss' });
});

// App serving
app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

// Profile setup page (new user onboarding after signup)
app.get('/setup-profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup-profile.html'));
});


app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('NVME Creator Platform v2.0.0 running on port ' + PORT);
  console.log('Emulating: TikTok + Instagram + YouTube + WhatsApp + Snapchat + X + Facebook + Dating');
});
