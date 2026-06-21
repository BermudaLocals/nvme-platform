'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nvme-dev-secret';

// ── DB ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── MIDDLEWARE ──────────────────────────────────────
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ─────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

// ── HEALTH ──────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok', service: 'nvme-live', version: '1.0.0', env: process.env.NODE_ENV
}));

// ── AUTH ROUTES ─────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username, display_name } = req.body;
    if (!email || !password || !username) return res.status(400).json({ error: 'email, password, username required' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email or username taken' });
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users(id,email,username,display_name,password_hash) VALUES($1,$2,$3,$4,$5) RETURNING id,email,username,display_name,avatar_url,plan,created_at',
      [uuidv4(), email, username, display_name || username, hash]
    );
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    delete user.password_hash;
    res.json({ token, user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USER ROUTES ─────────────────────────────────────
app.get('/api/users/:username', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id,username,display_name,avatar_url,bio,followers_count,following_count,plan,created_at FROM users WHERE username=$1',
      [req.params.username]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id,email,username,display_name,avatar_url,bio,plan,followers_count,following_count FROM users WHERE id=$1', [req.user.id]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VIDEO ROUTES ────────────────────────────────────
app.get('/api/feed', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const r = await pool.query(
      `SELECT v.*, u.username, u.display_name, u.avatar_url
       FROM videos v JOIN users u ON v.user_id=u.id
       WHERE v.status='published' ORDER BY v.created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    res.json({ videos: r.rows, limit, offset });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos', auth, async (req, res) => {
  try {
    const { title, description, video_url, thumbnail_url, duration } = req.body;
    if (!title || !video_url) return res.status(400).json({ error: 'title and video_url required' });
    const r = await pool.query(
      'INSERT INTO videos(id,user_id,title,description,video_url,thumbnail_url,duration) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [uuidv4(), req.user.id, title, description, video_url, thumbnail_url, duration || 0]
    );
    res.status(201).json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT v.*, u.username, u.display_name, u.avatar_url FROM videos v JOIN users u ON v.user_id=u.id WHERE v.id=$1',
      [req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Video not found' });
    await pool.query('UPDATE videos SET views_count=views_count+1 WHERE id=$1', [req.params.id]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── FOLLOW ROUTES ───────────────────────────────────
app.post('/api/follow/:userId', auth, async (req, res) => {
  try {
    const followerId = req.user.id;
    const followingId = req.params.userId;
    if (followerId === followingId) return res.status(400).json({ error: 'Cannot follow yourself' });
    await pool.query('INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [followerId, followingId]);
    await pool.query('UPDATE users SET followers_count=followers_count+1 WHERE id=$1', [followingId]);
    await pool.query('UPDATE users SET following_count=following_count+1 WHERE id=$1', [followerId]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/follow/:userId', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, req.params.userId]);
    await pool.query('UPDATE users SET followers_count=GREATEST(0,followers_count-1) WHERE id=$1', [req.params.userId]);
    await pool.query('UPDATE users SET following_count=GREATEST(0,following_count-1) WHERE id=$1', [req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GIFT ROUTES ─────────────────────────────────────
app.post('/api/gifts/send', auth, async (req, res) => {
  try {
    const { recipient_id, gift_type, amount, video_id } = req.body;
    if (!recipient_id || !gift_type || !amount) return res.status(400).json({ error: 'recipient_id, gift_type, amount required' });
    const r = await pool.query(
      'INSERT INTO gifts(id,sender_id,recipient_id,gift_type,amount,video_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
      [uuidv4(), req.user.id, recipient_id, gift_type, amount, video_id]
    );
    await pool.query('UPDATE users SET earnings=earnings+$1 WHERE id=$2', [amount * 0.7, recipient_id]);
    res.status(201).json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── COMMENTS ────────────────────────────────────────
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT c.*, u.username, u.display_name, u.avatar_url FROM comments c JOIN users u ON c.user_id=u.id WHERE c.video_id=$1 ORDER BY c.created_at DESC LIMIT 50',
      [req.params.id]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/comments', auth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'content required' });
    const r = await pool.query(
      'INSERT INTO comments(id,video_id,user_id,content) VALUES($1,$2,$3,$4) RETURNING *',
      [uuidv4(), req.params.id, req.user.id, content]
    );
    res.status(201).json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SUBSCRIPTIONS ───────────────────────────────────
app.get('/api/subscriptions/plans', (req, res) => {
  res.json([
    { id: 'creator_monthly', name: 'Creator', price: 9.99, interval: 'month', features: ['Upload unlimited videos', 'Analytics dashboard', 'Priority support'] },
    { id: 'pro_monthly', name: 'Pro Creator', price: 29.99, interval: 'month', features: ['Everything in Creator', 'Live streaming', 'Custom branding', 'Revenue share boost'] },
    { id: 'studio_monthly', name: 'Studio', price: 99.99, interval: 'month', features: ['Everything in Pro', 'Team accounts', 'API access', 'Dedicated support'] }
  ]);
});

// ── SEARCH ──────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q) return res.status(400).json({ error: 'q required' });
    if (type === 'users') {
      const r = await pool.query(
        'SELECT id,username,display_name,avatar_url,followers_count FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 LIMIT 20',
        [`%${q}%`]
      );
      return res.json(r.rows);
    }
    const r = await pool.query(
      `SELECT v.*, u.username, u.display_name FROM videos v JOIN users u ON v.user_id=u.id
       WHERE v.title ILIKE $1 AND v.status='published' ORDER BY v.views_count DESC LIMIT 20`,
      [`%${q}%`]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TRENDING ────────────────────────────────────────
app.get('/api/trending', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT v.*, u.username, u.display_name, u.avatar_url
       FROM videos v JOIN users u ON v.user_id=u.id
       WHERE v.status='published' AND v.created_at > NOW() - INTERVAL '7 days'
       ORDER BY v.views_count DESC, v.likes_count DESC LIMIT 20`
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SPA FALLBACK ────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
    if (err) res.json({ status: 'nvme.live API running', version: '1.0.0' });
  });
});

// ── DB INIT ─────────────────────────────────────────
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT,
        password_hash TEXT,
        avatar_url TEXT,
        bio TEXT,
        plan TEXT DEFAULT 'free',
        followers_count INTEGER DEFAULT 0,
        following_count INTEGER DEFAULT 0,
        earnings NUMERIC(10,2) DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS videos (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT,
        video_url TEXT NOT NULL,
        thumbnail_url TEXT,
        duration INTEGER DEFAULT 0,
        views_count INTEGER DEFAULT 0,
        likes_count INTEGER DEFAULT 0,
        comments_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'published',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS follows (
        follower_id UUID REFERENCES users(id) ON DELETE CASCADE,
        following_id UUID REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY(follower_id, following_id)
      );
      CREATE TABLE IF NOT EXISTS gifts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
        recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
        gift_type TEXT NOT NULL,
        amount NUMERIC(10,2) NOT NULL,
        video_id UUID,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS comments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        likes_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS subscriptions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        plan TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        paypal_subscription_id TEXT,
        started_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ
      );
    `);
    console.log('✅ Database tables ready');
  } catch(e) {
    console.warn('⚠️  DB init warning:', e.message);
  }
}

app.listen(PORT, async () => {
  await initDB();
  console.log(`\n🎬 nvme.live v1.0.0 — ${process.env.NODE_ENV || 'development'}`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Routes: auth · feed · videos · follows · gifts · comments · search · trending\n`);
});
