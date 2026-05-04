require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { pool, initDB, audit } = require('./db');
const { signAccessToken, signRefreshToken, hashToken, deviceFingerprint, requireAuth, optionalAuth, cookieOpts, REFRESH_EXPIRY_DAYS } = require('./middleware/auth');
const { validate } = require('./middleware/validation');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.paypal.com", "https://js.stripe.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      mediaSrc: ["'self'", "blob:", "data:"],
      connectSrc: ["'self'", "https://api.paypal.com"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
app.use(cookieParser(process.env.SESSION_SECRET || process.env.JWT_SECRET || 'nvme-cookie-secret'));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// General API rate limit
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);

// Strict limiter for auth endpoints - 10 attempts per 15 min per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

// In-memory data stores
const memCreators = {}; // email -> creator (fallback when no DATABASE_URL)
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


// ============ AUTHENTICATION & SECURITY ============

// Initialize database on startup (non-blocking)
initDB().then(ok => {
  if (ok) console.log('OK Database ready');
  else console.log('INFO Running without persistent database');
});

// Check account lockout
async function checkLockout(email) {
  if (!process.env.DATABASE_URL) return { locked: false };
  try {
    const r = await pool.query('SELECT id, failed_login_count, locked_until FROM creators WHERE email=$1', [email]);
    if (r.rows.length === 0) return { locked: false };
    const row = r.rows[0];
    if (row.locked_until && new Date(row.locked_until) > new Date()) {
      return { locked: true, until: row.locked_until, id: row.id };
    }
    return { locked: false, id: row.id, fails: row.failed_login_count };
  } catch (e) {
    return { locked: false };
  }
}

// POST /api/auth/signup - Create account with hashed password + JWT session
app.post('/api/auth/signup', authLimiter, validate('signup'), async (req, res) => {
  const { email, username, password } = req.body;
  const ip = req.ip;
  const ua = req.get('user-agent') || '';
  try {
    const hash = await bcrypt.hash(password, 12);
    if (process.env.DATABASE_URL) {
      // DB-backed signup
      try {
        const result = await pool.query(
          'INSERT INTO creators (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, email, username, created_at',
          [email.toLowerCase(), username, hash]
        );
        const creator = result.rows[0];
        const access = signAccessToken({ sub: creator.id, username: creator.username, email: creator.email });
        const refresh = signRefreshToken();
        const refreshHash = hashToken(refresh);
        const expires = new Date(Date.now() + REFRESH_EXPIRY_DAYS * 86400000);
        await pool.query(
          'INSERT INTO sessions (creator_id, refresh_token_hash, device_fingerprint, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
          [creator.id, refreshHash, deviceFingerprint(req), ip, ua, expires]
        );
        await audit(creator.id, 'signup', ip, ua);
        res.cookie('nvme_access', access, cookieOpts(15 * 60 * 1000));
        res.cookie('nvme_refresh', refresh, cookieOpts(REFRESH_EXPIRY_DAYS * 86400000));
        return res.json({ success: true, creator: { id: creator.id, email: creator.email, username: creator.username }, accessToken: access });
      } catch (dbErr) {
        if (dbErr.code === '23505') {
          return res.status(409).json({ error: 'Email or username already registered' });
        }
        console.error('Signup DB error:', dbErr.message);
        return res.status(500).json({ error: 'signup failed' });
      }
    }
    // Memory fallback (no DATABASE_URL set)
    const id = uuidv4();
    memCreators[email.toLowerCase()] = { id, email: email.toLowerCase(), username, passwordHash: hash, createdAt: new Date() };
    const access = signAccessToken({ sub: id, username, email: email.toLowerCase() });
    const refresh = signRefreshToken();
    res.cookie('nvme_access', access, cookieOpts(15 * 60 * 1000));
    res.cookie('nvme_refresh', refresh, cookieOpts(30 * 86400000));
    res.json({ success: true, creator: { id, email: email.toLowerCase(), username }, accessToken: access });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'signup failed' });
  }
});

// POST /api/auth/login - Authenticate with bcrypt + issue JWT
app.post('/api/auth/login', authLimiter, validate('login'), async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip;
  const ua = req.get('user-agent') || '';
  if (!process.env.DATABASE_URL) {
    // Memory mode login
    const memUser = memCreators[email.toLowerCase()];
    if (!memUser) return res.status(401).json({ error: 'invalid credentials' });
    const valid = await bcrypt.compare(password, memUser.passwordHash);
    if (!valid) return res.status(401).json({ error: 'invalid credentials' });
    const access = signAccessToken({ sub: memUser.id, username: memUser.username, email: memUser.email });
    const refresh = signRefreshToken();
    res.cookie('nvme_access', access, cookieOpts(15 * 60 * 1000));
    res.cookie('nvme_refresh', refresh, cookieOpts(30 * 86400000));
    return res.json({ success: true, creator: { id: memUser.id, email: memUser.email, username: memUser.username }, accessToken: access });
  }
  try {
    const lockout = await checkLockout(email.toLowerCase());
    if (lockout.locked) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }
    const r = await pool.query('SELECT id, email, username, password_hash FROM creators WHERE email=$1', [email.toLowerCase()]);
    if (r.rows.length === 0) {
      await audit(null, 'login_failed_no_user', ip, ua, { email });
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const creator = r.rows[0];
    const valid = await bcrypt.compare(password, creator.password_hash);
    if (!valid) {
      // Increment failed attempts; lock after 5
      await pool.query(
        'UPDATE creators SET failed_login_count = failed_login_count + 1, locked_until = CASE WHEN failed_login_count + 1 >= 5 THEN NOW() + INTERVAL \'15 minutes\' ELSE NULL END WHERE id=$1',
        [creator.id]
      );
      await audit(creator.id, 'login_failed', ip, ua);
      return res.status(401).json({ error: 'invalid credentials' });
    }
    // Success - reset counter, issue tokens
    await pool.query('UPDATE creators SET failed_login_count=0, locked_until=NULL, last_login_at=NOW(), last_login_ip=$1 WHERE id=$2', [ip, creator.id]);
    const access = signAccessToken({ sub: creator.id, username: creator.username, email: creator.email });
    const refresh = signRefreshToken();
    const refreshHash = hashToken(refresh);
    const expires = new Date(Date.now() + REFRESH_EXPIRY_DAYS * 86400000);
    await pool.query(
      'INSERT INTO sessions (creator_id, refresh_token_hash, device_fingerprint, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [creator.id, refreshHash, deviceFingerprint(req), ip, ua, expires]
    );
    await audit(creator.id, 'login', ip, ua);
    res.cookie('nvme_access', access, cookieOpts(15 * 60 * 1000));
    res.cookie('nvme_refresh', refresh, cookieOpts(REFRESH_EXPIRY_DAYS * 86400000));
    res.json({ success: true, creator: { id: creator.id, email: creator.email, username: creator.username }, accessToken: access });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'login failed' });
  }
});

// POST /api/auth/logout - Revoke session
app.post('/api/auth/logout', optionalAuth, async (req, res) => {
  const refresh = req.cookies && req.cookies.nvme_refresh;
  if (refresh && process.env.DATABASE_URL) {
    try {
      await pool.query('UPDATE sessions SET revoked=true WHERE refresh_token_hash=$1', [hashToken(refresh)]);
      if (req.user) await audit(req.user.sub, 'logout', req.ip, req.get('user-agent') || '');
    } catch (e) { /* continue */ }
  }
  res.clearCookie('nvme_access');
  res.clearCookie('nvme_refresh');
  res.json({ success: true });
});

// GET /api/auth/me - Get current authenticated user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  if (!process.env.DATABASE_URL) {
    const memUser = Object.values(memCreators).find(u => u.id === req.user.sub);
    const user = memUser ? { id: memUser.id, email: memUser.email, username: memUser.username } : { id: req.user.sub, username: req.user.username, email: req.user.email };
    return res.json({ user });
  }
  try {
    const r = await pool.query(
      'SELECT id, email, username, display_name, bio, country, categories, avatar_url, followers, following, verified, email_verified, phone_verified, two_fa_enabled FROM creators WHERE id=$1',
      [req.user.sub]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    res.json({ user: r.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'fetch failed' });
  }
});

// PUT /api/auth/profile - Update authenticated user's profile (PERSISTENT to DB)
app.put('/api/auth/profile', requireAuth, validate('profile'), async (req, res) => {
  if (!process.env.DATABASE_URL) {
    return res.status(503).json({ error: 'profile update §§secret(POSTGRESQL://NEONDB_OWNER:NPG_NX6JVZR2QMYG@EP-FALLING-PAPER-A62FLHPD.US-WEST-2.AWS.NEON.TECH/NEONDB?SSLMODE)s database' });
  }
  const { displayName, bio, country, categories, avatarUrl } = req.body;
  try {
    const r = await pool.query(
      `UPDATE creators SET display_name=$1, bio=$2, country=$3, categories=$4, avatar_url=COALESCE($5, avatar_url), updated_at=NOW() WHERE id=$6 RETURNING id, display_name, bio, country, categories, avatar_url`,
      [displayName, bio, country, categories, avatarUrl || null, req.user.sub]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'user not found' });
    await audit(req.user.sub, 'profile_update', req.ip, req.get('user-agent') || '');
    res.json({ success: true, profile: r.rows[0] });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ error: 'update failed' });
  }
});

// ============ END AUTH ============

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
    return res.status(400).json({ success: false, error: 'creatorId and displayName are requiredd' });
  }
  const profile = { creatorId, displayName, bio: bio || '', country: country || '', categories: categories || [], avatar: avatar || null, updatedAt: new Date().toISOString() };
  creatorProfiles[creatorId] = profile;
  res.json({ success: true, profile, message: 'Profile saved' });
});

app.get('/api/creators/profile/:creatorId', (req, res) => {
  const profile = creatorProfiles[req.params.creatorId];
  if (!profile) return res.status(404).json({ success: false, error: 'Profile not found' });
  res.json({ success: true, profile });
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

// NVME HelpNet — Offline Emergency & Community Aid
const helpNetRouter = require('./routes-helpnet');
app.use('/api/helpnet', helpNetRouter);
app.get('/helpnet', (req, res) => res.sendFile(path.join(__dirname, 'public', 'helpnet.html')));

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

// ── SARA AI CHAT — Real Claude-powered responses ─────────────
app.post('/api/ai/chat', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });

  const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_KEY) {
    return res.json({ reply: "Hey! I'm Sara 👋 I'm warming up my AI brain. Ask me about earning, live streaming, gifts, or getting started on NVME!" });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 300,
        system: `You are Sara, the friendly AI assistant for NVME.live — a creator monetization platform that combines TikTok, Instagram, YouTube, WhatsApp, Snapchat, X, Facebook, and Dating all in one. Your job is to help creators sign up, understand how to earn money, and get excited about the platform.

Key facts about NVME:
- Creators earn $2–10 per 1,000 views PLUS fan gifts
- Top creators earned $84,000 last week
- 8 payment methods: PayPal, Stripe, Cash App, Apple Pay, Google Pay, Crypto, Wire, Bermuda Bank
- Plans: Creator $9/mo, Pro $29/mo, Legend $79/mo — all with 14-day free trial
- AI tools: video generator, 29 avatars, voice cloning, lip-sync, text-to-video
- HelpNet: offline emergency SMS network for communities
- Based in Bermuda, open to creators worldwide
- No credit card needed to start

Keep responses short (2-4 sentences), enthusiastic, and always end with an action (sign up, try free, ask more). Use 1-2 emojis max. Never make up specific numbers unless listed above.`,
        messages: [{ role: 'user', content: message }]
      })
    });

    const data = await response.json();
    const reply = data.content?.[0]?.text || "Great question! Sign up free and explore everything NVME has to offer 🚀";
    res.json({ reply });
  } catch (err) {
    console.error('Sara AI error:', err.message);
    res.json({ reply: "I'm having a quick brain moment! 😅 Try asking me again, or just hit Sign Up Free to get started!" });
  }
});
