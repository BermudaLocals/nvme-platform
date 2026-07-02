'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3090;
const IS_PROD = process.env.NODE_ENV === 'production';

// ── SESSION (required for passport) ──────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET || 'nvme-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: IS_PROD, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ── GOOGLE OAUTH STRATEGY ────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      const username = profile.displayName?.replace(/\s+/g,'_').toLowerCase() || 'user_' + profile.id;
      const avatar = profile.photos?.[0]?.value || null;
      let result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
      let user;
      if (result.rows.length === 0) {
        const r = await pool.query(
          'INSERT INTO users (id,email,username,password_hash,avatar_url,created_at) VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *',
          [uuidv4(), email, username, 'GOOGLE_OAUTH', avatar]
        );
        user = r.rows[0];
      } else {
        user = result.rows[0];
        if (avatar && !user.avatar_url) {
          await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2',[avatar,user.id]);
          user.avatar_url = avatar;
        }
      }
      return done(null, { id: user.id, email: user.email, username: user.username });
    } catch(e) { return done(e); }
  }));
}

// ── Production env guardrails (resilient) ────────────────────
if (IS_PROD) {
  const required = ['DATABASE_URL', 'JWT_SECRET'];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error(`[nvme.live] WARNING: missing env in production: ${missing.join(', ')} — set these in Railway variables!`);
  }
  if (!process.env.JWT_SECRET) {
    // never ship a weak hardcoded secret: generate strong ephemeral one (sessions reset on redeploy)
    process.env.JWT_SECRET = require('crypto').randomBytes(48).toString('hex');
    console.error('[nvme.live] WARNING: JWT_SECRET missing — using ephemeral random secret until env var is set');
  }
}

// ── DB ──────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ── Middleware ───────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));

// ── Auth helper ──────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'kush-empire-jwt-secret-2026';
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'invalid token' }); }
}
function optionalAuth(req, res, next) {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) {
    try { req.user = jwt.verify(h.slice(7), JWT_SECRET); } catch (e) { /* anonymous */ }
  }
  next();
}

// ── DB Init ──────────────────────────────────────────────────
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS videos (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT NOT NULL,
      thumbnail TEXT,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL,
      paypal_subscription_id TEXT,
      status TEXT DEFAULT 'active',
      starts_at TIMESTAMPTZ DEFAULT NOW(),
      ends_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS comments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS follows (
      follower_id UUID REFERENCES users(id) ON DELETE CASCADE,
      followee_id UUID REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (follower_id, followee_id)
    );
    CREATE TABLE IF NOT EXISTS video_likes (
      video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (video_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS gifts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
      receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
      video_id UUID REFERENCES videos(id) ON DELETE SET NULL,
      credits NUMERIC NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_credits NUMERIC DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS url TEXT;
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail TEXT;
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0;
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS likes INTEGER DEFAULT 0;
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS plan TEXT;
    -- migrate legacy schema.sql-era columns (video_url/thumbnail_url/view_count/like_count) if present
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='videos' AND column_name='video_url') THEN
        UPDATE videos SET url = COALESCE(url, video_url);
        ALTER TABLE videos ALTER COLUMN video_url DROP NOT NULL;
      END IF;
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='videos' AND column_name='thumbnail_url') THEN
        UPDATE videos SET thumbnail = COALESCE(thumbnail, thumbnail_url);
      END IF;
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='videos' AND column_name='view_count') THEN
        UPDATE videos SET views = COALESCE(views, view_count), likes = COALESCE(likes, like_count);
      END IF;
    END $$;
  `).catch(e => console.warn('DB init warning:', e.message));
}

// ── Routes: Health ───────────────────────────────────────────

// ── GOOGLE OAUTH ROUTES ──────────────────────────────────────────────────────
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth=failed' }),
  (req, res) => {
    const token = signToken({ id: req.user.id, email: req.user.email });
    // Redirect to frontend with token in query param; frontend stores it
    res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify({ id:req.user.id, email:req.user.email, username:req.user.username }))}`);
  }
);

app.get('/health', (req, res) => res.json({
  app: 'nvme.live',
  status: 'ONLINE',
  version: '1.0.0',
  empire: 'Dollar Double Empire',
  founder: 'John B. Jefferis .Esq — Digital King AGI',
  ts: new Date().toISOString()
}));

// ── Routes: Auth ─────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password || !username) return res.status(400).json({ error: 'email, password, username required' });
    if (password.length < 8) return res.status(400).json({ error: 'password min 8 chars' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
      'INSERT INTO users (email, password_hash, username) VALUES ($1,$2,$3) RETURNING id, email, username, plan, created_at',
      [email.toLowerCase().trim(), hash, username.trim()]
    );
    const user = rows[0];
    res.status(201).json({ ok: true, token: signToken({ id: user.id, email: user.email }), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email or username already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ ok: true, token: signToken({ id: user.id, email: user.email }), user: { id: user.id, email: user.email, username: user.username, plan: user.plan } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id, email, username, plan, created_at FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'user not found' });
    res.json({ ok: true, user: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Videos ───────────────────────────────────────────
app.get('/api/videos', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT v.*, u.username FROM videos v JOIN users u ON u.id=v.user_id ORDER BY v.created_at DESC LIMIT 50');
    res.json({ ok: true, videos: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos', authMiddleware, async (req, res) => {
  try {
    const { title, description, url, thumbnail } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'title and url required' });
    const { rows } = await db.query(
      'INSERT INTO videos (user_id, title, description, url, thumbnail) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title, description || '', url, thumbnail || '']
    );
    res.status(201).json({ ok: true, video: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Feed (ranked) ────────────────────────────────────
app.get('/api/feed', optionalAuth, async (req, res) => {
  try {
    const viewerId = req.user ? req.user.id : null;
    const { rows } = await db.query(`
      SELECT v.id, v.title, v.description, v.url, v.thumbnail, v.views, v.created_at,
             u.username, u.avatar_url, u.id AS author_id,
             COALESCE(l.like_count, 0)::int AS like_count,
             COALESCE(c.comment_count, 0)::int AS comment_count,
             CASE WHEN $1::uuid IS NOT NULL AND vl.user_id IS NOT NULL THEN true ELSE false END AS viewer_liked,
             (COALESCE(l.like_count, 0) * 3 + COALESCE(c.comment_count, 0) * 2 + v.views
              + GREATEST(0, 48 - EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 3600)) AS score
      FROM videos v
      JOIN users u ON u.id = v.user_id
      LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id = v.id
      LEFT JOIN (SELECT video_id, COUNT(*) AS comment_count FROM comments GROUP BY video_id) c ON c.video_id = v.id
      LEFT JOIN video_likes vl ON vl.video_id = v.id AND vl.user_id = $1::uuid
      ORDER BY score DESC, v.created_at DESC
      LIMIT 20
    `, [viewerId]);
    res.json({ ok: true, feed: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/like', authMiddleware, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { rows: vrows } = await db.query('SELECT id FROM videos WHERE id=$1', [videoId]);
    if (!vrows.length) return res.status(404).json({ error: 'video not found' });
    const { rowCount } = await db.query('DELETE FROM video_likes WHERE video_id=$1 AND user_id=$2', [videoId, req.user.id]);
    let liked = false;
    if (rowCount === 0) {
      await db.query('INSERT INTO video_likes (video_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [videoId, req.user.id]);
      liked = true;
    }
    const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM video_likes WHERE video_id=$1', [videoId]);
    res.json({ ok: true, liked, count: rows[0].count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/view', async (req, res) => {
  try {
    const { rows } = await db.query('UPDATE videos SET views=views+1 WHERE id=$1 RETURNING id, views', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'video not found' });
    res.json({ ok: true, views: rows[0].views });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Comments ─────────────────────────────────────────
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT c.id, c.text, c.created_at, u.username, u.avatar_url
      FROM comments c JOIN users u ON u.id = c.user_id
      WHERE c.video_id = $1 ORDER BY c.created_at DESC LIMIT 100
    `, [req.params.id]);
    res.json({ ok: true, comments: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/comments', authMiddleware, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text || text.length > 500) return res.status(400).json({ error: 'text required, 1-500 chars' });
    const { rows: vrows } = await db.query('SELECT id FROM videos WHERE id=$1', [req.params.id]);
    if (!vrows.length) return res.status(404).json({ error: 'video not found' });
    const { rows } = await db.query(
      'INSERT INTO comments (video_id, user_id, text) VALUES ($1,$2,$3) RETURNING id, text, created_at',
      [req.params.id, req.user.id, text]
    );
    res.status(201).json({ ok: true, comment: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Follows & Profiles ───────────────────────────────
app.post('/api/users/:id/follow', authMiddleware, async (req, res) => {
  try {
    const followeeId = req.params.id;
    if (followeeId === req.user.id) return res.status(400).json({ error: 'cannot follow yourself' });
    const { rows: urows } = await db.query('SELECT id FROM users WHERE id=$1', [followeeId]);
    if (!urows.length) return res.status(404).json({ error: 'user not found' });
    const { rowCount } = await db.query('DELETE FROM follows WHERE follower_id=$1 AND followee_id=$2', [req.user.id, followeeId]);
    let following = false;
    if (rowCount === 0) {
      await db.query('INSERT INTO follows (follower_id, followee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, followeeId]);
      following = true;
    }
    const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [followeeId]);
    res.json({ ok: true, following, followers: rows[0].count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:username', async (req, res) => {
  try {
    const { rows: urows } = await db.query(
      'SELECT id, username, avatar_url, created_at FROM users WHERE username=$1', [req.params.username]
    );
    if (!urows.length) return res.status(404).json({ error: 'user not found' });
    const user = urows[0];
    const [followers, following, videos] = await Promise.all([
      db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [user.id]),
      db.query('SELECT COUNT(*)::int AS count FROM follows WHERE follower_id=$1', [user.id]),
      db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.created_at,
               COALESCE(l.like_count, 0)::int AS like_count
        FROM videos v
        LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id = v.id
        WHERE v.user_id = $1 ORDER BY v.created_at DESC LIMIT 50
      `, [user.id])
    ]);
    res.json({
      ok: true,
      user: { id: user.id, username: user.username, avatar_url: user.avatar_url, created_at: user.created_at },
      stats: {
        followers: followers.rows[0].count,
        following: following.rows[0].count,
        videos: videos.rows.length,
        total_views: videos.rows.reduce((s, v) => s + v.views, 0)
      },
      videos: videos.rows
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Gifts ────────────────────────────────────────────
app.post('/api/gifts', authMiddleware, async (req, res) => {
  const client = await db.connect();
  try {
    const { receiver_id, video_id, credits } = req.body;
    const amount = Number(credits);
    if (!receiver_id || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'receiver_id and positive credits required' });
    }
    if (receiver_id === req.user.id) return res.status(400).json({ error: 'cannot gift yourself' });
    await client.query('BEGIN');
    const { rows: srows } = await client.query(
      'SELECT balance_credits FROM users WHERE id=$1 FOR UPDATE', [req.user.id]
    );
    if (!srows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'sender not found' }); }
    if (Number(srows[0].balance_credits) < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'insufficient balance' });
    }
    const { rows: rrows } = await client.query('SELECT id FROM users WHERE id=$1', [receiver_id]);
    if (!rrows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'receiver not found' }); }
    const receiverShare = Math.round(amount * 0.7 * 100) / 100;
    await client.query('UPDATE users SET balance_credits = balance_credits - $1 WHERE id=$2', [amount, req.user.id]);
    await client.query('UPDATE users SET balance_credits = balance_credits + $1 WHERE id=$2', [receiverShare, receiver_id]);
    const { rows } = await client.query(
      'INSERT INTO gifts (sender_id, receiver_id, video_id, credits) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, receiver_id, video_id || null, amount]
    );
    await client.query('COMMIT');
    res.status(201).json({ ok: true, gift: rows[0], receiver_credited: receiverShare });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: e.message });
  } finally { client.release(); }
});

// ── Routes: Upload (phase 2 stub) ────────────────────────────
app.get('/api/videos/upload-url', authMiddleware, (req, res) => {
  res.status(501).json({ error: 'direct upload coming — use url field' });
});

// ── Routes: Payments (PayPal ONLY) ──────────────────────────
app.post('/api/subscribe', authMiddleware, async (req, res) => {
  try {
    const { plan, paypal_subscription_id } = req.body;
    const plans = { pro: 9.99, creator: 24.99, enterprise: 99.99 };
    if (!plans[plan]) return res.status(400).json({ error: 'invalid plan' });
    await db.query('UPDATE users SET plan=$1 WHERE id=$2', [plan, req.user.id]);
    await db.query(
      'INSERT INTO subscriptions (user_id, plan, paypal_subscription_id) VALUES ($1,$2,$3)',
      [req.user.id, plan, paypal_subscription_id || 'manual']
    );
    res.json({ ok: true, plan, message: 'subscription activated' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/donate', (req, res) => {
  res.redirect(process.env.PAYPAL_DONATE_LINK || 'https://paypal.me/DollarDoubleEmpire');
});

// ── Frontend: Landing Page ───────────────────────────────────
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>nvme.live — The Future of Short Video Entertainment</title>
<style>
  :root{--bg:#0a0a0f;--card:#13131a;--border:#1e1e2e;--accent:#7c3aed;--accent2:#06b6d4;--text:#f8fafc;--muted:#64748b}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;min-height:100vh}
  nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(10,10,15,0.95);backdrop-filter:blur(12px);z-index:100}
  .logo{font-size:1.5rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .nav-links{display:flex;gap:1.5rem;align-items:center}
  .nav-links a{color:var(--muted);text-decoration:none;transition:color .2s}  
  .nav-links a:hover{color:var(--text)}
  .btn{padding:.6rem 1.4rem;border-radius:8px;border:none;cursor:pointer;font-weight:600;transition:all .2s;text-decoration:none;display:inline-block}
  .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
  .btn-primary:hover{opacity:.9;transform:translateY(-1px)}
  .btn-outline{border:1px solid var(--accent);color:var(--accent);background:transparent}
  .btn-outline:hover{background:var(--accent);color:#fff}
  .hero{text-align:center;padding:6rem 2rem 4rem;max-width:800px;margin:0 auto}
  .hero h1{font-size:clamp(2.5rem,6vw,4.5rem);font-weight:900;line-height:1.1;margin-bottom:1.5rem}
  .hero h1 span{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .hero p{font-size:1.2rem;color:var(--muted);margin-bottom:2.5rem;max-width:600px;margin-left:auto;margin-right:auto}
  .hero-cta{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1.5rem;padding:3rem 2rem;max-width:900px;margin:0 auto}
  .stat{text-align:center;padding:1.5rem;background:var(--card);border-radius:16px;border:1px solid var(--border)}
  .stat-num{font-size:2.5rem;font-weight:900;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .stat-label{color:var(--muted);font-size:.9rem;margin-top:.25rem}
  .features{padding:4rem 2rem;max-width:1100px;margin:0 auto}
  .features h2{text-align:center;font-size:2.5rem;font-weight:800;margin-bottom:3rem}
  .features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem}
  .feature-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;transition:border-color .2s}
  .feature-card:hover{border-color:var(--accent)}
  .feature-icon{font-size:2.5rem;margin-bottom:1rem}
  .feature-card h3{font-size:1.2rem;font-weight:700;margin-bottom:.75rem}
  .feature-card p{color:var(--muted);line-height:1.6}
  .pricing{padding:4rem 2rem;background:linear-gradient(180deg,var(--bg),var(--card));}
  .pricing h2{text-align:center;font-size:2.5rem;font-weight:800;margin-bottom:.75rem}
  .pricing-subtitle{text-align:center;color:var(--muted);margin-bottom:3rem}
  .pricing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1.5rem;max-width:900px;margin:0 auto}
  .plan{background:var(--bg);border:1px solid var(--border);border-radius:16px;padding:2rem}
  .plan.featured{border-color:var(--accent);position:relative}
  .plan.featured::before{content:'POPULAR';position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;padding:.25rem .75rem;border-radius:99px;font-size:.75rem;font-weight:700}
  .plan-name{font-size:1.1rem;font-weight:700;margin-bottom:.5rem}
  .plan-price{font-size:3rem;font-weight:900;margin:.75rem 0}
  .plan-price span{font-size:1rem;color:var(--muted);font-weight:400}
  .plan ul{list-style:none;margin:1.5rem 0;display:flex;flex-direction:column;gap:.75rem}
  .plan ul li{color:var(--muted);display:flex;align-items:center;gap:.5rem}
  .plan ul li::before{content:'✓';color:var(--accent);font-weight:700}
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center}
  .modal-overlay.active{display:flex}
  .modal{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:2.5rem;width:100%;max-width:440px;position:relative}
  .modal h2{font-size:1.5rem;font-weight:800;margin-bottom:.5rem}
  .modal p{color:var(--muted);margin-bottom:1.5rem;font-size:.9rem}
  .form-group{margin-bottom:1rem}
  .form-group label{display:block;color:var(--muted);font-size:.85rem;margin-bottom:.4rem;font-weight:500}
  .form-group input{width:100%;padding:.75rem 1rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1rem;outline:none;transition:border-color .2s}
  .form-group input:focus{border-color:var(--accent)}
  .modal-close{position:absolute;top:1rem;right:1rem;background:none;border:none;color:var(--muted);font-size:1.5rem;cursor:pointer}
  .tab-btns{display:flex;gap:.5rem;margin-bottom:1.5rem;background:var(--bg);padding:.35rem;border-radius:8px}
  .tab-btn{flex:1;padding:.5rem;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:.9rem;background:none;color:var(--muted);transition:all .2s}
  .tab-btn.active{background:var(--accent);color:#fff}
  .msg{padding:.75rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem;display:none}
  .msg.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#f87171;display:block}
  .msg.success{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#4ade80;display:block}
  footer{text-align:center;padding:3rem 2rem;color:var(--muted);border-top:1px solid var(--border)}
  footer a{color:var(--muted);text-decoration:none}
  footer a:hover{color:var(--text)}
  .feed-view{display:none;height:calc(100vh - 65px);overflow-y:scroll;scroll-snap-type:y mandatory;background:var(--bg)}
  .feed-view.active{display:block}
  .feed-card{height:calc(100vh - 65px);scroll-snap-align:start;scroll-snap-stop:always;position:relative;display:flex;align-items:center;justify-content:center;background:#000}
  .feed-card video{max-height:100%;max-width:100%;width:auto;height:100%;object-fit:contain}
  .feed-info{position:absolute;left:1rem;bottom:1.5rem;right:5rem;z-index:5}
  .feed-info .feed-user{font-weight:700;font-size:1rem;margin-bottom:.35rem}
  .feed-info .feed-title{color:var(--text);font-size:.95rem;opacity:.9}
  .feed-actions{position:absolute;right:.75rem;bottom:1.5rem;display:flex;flex-direction:column;gap:1.1rem;z-index:5;align-items:center}
  .feed-btn{background:rgba(19,19,26,.7);border:1px solid var(--border);color:var(--text);border-radius:50%;width:48px;height:48px;font-size:1.3rem;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
  .feed-btn:hover{border-color:var(--accent)}
  .feed-btn.liked{color:#f87171;border-color:#f87171}
  .feed-btn-label{font-size:.75rem;color:var(--muted);text-align:center;margin-top:.25rem}
  .feed-empty{text-align:center;padding:4rem 2rem;color:var(--muted)}
  .comment-panel{position:fixed;left:0;right:0;bottom:-100%;height:55vh;background:var(--card);border-top:1px solid var(--border);border-radius:20px 20px 0 0;z-index:900;transition:bottom .3s ease;display:flex;flex-direction:column}
  .comment-panel.open{bottom:0}
  .comment-panel-head{display:flex;justify-content:space-between;align-items:center;padding:1rem 1.25rem;border-bottom:1px solid var(--border)}
  .comment-list{flex:1;overflow-y:auto;padding:1rem 1.25rem}
  .comment-item{margin-bottom:1rem}
  .comment-item .c-user{font-weight:600;font-size:.85rem;color:var(--accent2)}
  .comment-item .c-text{color:var(--text);font-size:.95rem;margin-top:.15rem}
  .comment-input-row{display:flex;gap:.5rem;padding:1rem 1.25rem;border-top:1px solid var(--border)}
  .comment-input-row input{flex:1;padding:.65rem 1rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);outline:none}
  .comment-input-row input:focus{border-color:var(--accent)}
  @media(max-width:640px){.hero{padding:4rem 1.5rem 3rem}.hero-cta{flex-direction:column;align-items:center}nav{padding:1rem}}
</style>
</head>
<body>
<nav>
  <div class="logo">nvme.live</div>
  <div class="nav-links" id="navLoggedOut">
    <a href="#features">Features</a>
    <a href="#pricing">Pricing</a>
    <a class="btn btn-outline" href="#" onclick="openModal('login')">Log In</a>
    <a class="btn btn-primary" href="#" onclick="openModal('register')">Get Started</a>
  </div>
  <div class="nav-links" id="navLoggedIn" style="display:none">
    <span id="navUsername" style="color:var(--text);font-weight:600"></span>
    <a class="btn btn-outline" href="#" onclick="doLogout()">Logout</a>
  </div>
</nav>

<!-- Feed View (logged-in) -->
<div class="feed-view" id="feedView"></div>

<!-- Comment Panel -->
<div class="comment-panel" id="commentPanel">
  <div class="comment-panel-head">
    <strong>Comments</strong>
    <button class="modal-close" style="position:static" onclick="closeComments()">&times;</button>
  </div>
  <div class="comment-list" id="commentList"></div>
  <div class="comment-input-row">
    <input type="text" id="commentInput" maxlength="500" placeholder="Add a comment...">
    <button class="btn btn-primary" onclick="postComment()">Post</button>
  </div>
</div>

<div id="landingView">
<section class="hero">
  <h1>The Future of<br><span>Short Video</span><br>Entertainment</h1>
  <p>AI-powered creator platform. Upload, share, and monetize your short videos. Built for the next generation of content creators.</p>
  <div class="hero-cta">
    <a class="btn btn-primary" href="#" onclick="openModal('register')" style="font-size:1.1rem;padding:.85rem 2.5rem">Start Creating Free</a>
    <a class="btn btn-outline" href="#features" style="font-size:1.1rem;padding:.85rem 2.5rem">See Features</a>
  </div>
</section>

<div class="stats">
  <div class="stat"><div class="stat-num">57</div><div class="stat-label">AI Agents Working</div></div>
  <div class="stat"><div class="stat-num">4K</div><div class="stat-label">Max Resolution</div></div>
  <div class="stat"><div class="stat-num">99.9%</div><div class="stat-label">Uptime SLA</div></div>
  <div class="stat"><div class="stat-num">$0</div><div class="stat-label">to Start</div></div>
</div>

<section class="features" id="features">
  <h2>Everything You Need to Create</h2>
  <div class="features-grid">
    <div class="feature-card">
      <div class="feature-icon">🎬</div>
      <h3>AI Video Enhancement</h3>
      <p>Automatic captions, smart trimming, and AI-powered quality enhancement on every upload.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">💰</div>
      <h3>Creator Monetization</h3>
      <p>Earn from views, tips, and subscriptions. PayPal payouts weekly, no minimum threshold.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🌍</div>
      <h3>Global Distribution</h3>
      <p>CDN-powered delivery to 190+ countries. Your content loads fast everywhere, always.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🔒</div>
      <h3>Privacy Controls</h3>
      <p>Public, private, or subscriber-only content. You control who sees what, always.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📊</div>
      <h3>Real-Time Analytics</h3>
      <p>Live view counts, engagement metrics, and revenue dashboard updated every 30 seconds.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🤖</div>
      <h3>AI Empire Powered</h3>
      <p>57 specialized AI agents working 24/7 to optimize your content reach and monetization.</p>
    </div>
  </div>
</section>

<section class="pricing" id="pricing">
  <h2>Simple Pricing</h2>
  <p class="pricing-subtitle">Start free. Upgrade when you're ready.</p>
  <div class="pricing-grid">
    <div class="plan">
      <div class="plan-name">Free</div>
      <div class="plan-price">$0<span>/mo</span></div>
      <ul>
        <li>5 videos/month</li>
        <li>720p max resolution</li>
        <li>Basic analytics</li>
        <li>Community support</li>
      </ul>
      <a class="btn btn-outline" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Get Started</a>
    </div>
    <div class="plan featured">
      <div class="plan-name">Pro Creator</div>
      <div class="plan-price">$9.99<span>/mo</span></div>
      <ul>
        <li>Unlimited videos</li>
        <li>4K resolution</li>
        <li>Advanced analytics</li>
        <li>Monetization enabled</li>
        <li>Priority AI processing</li>
      </ul>
      <a class="btn btn-primary" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Start Pro</a>
    </div>
    <div class="plan">
      <div class="plan-name">Creator+</div>
      <div class="plan-price">$24.99<span>/mo</span></div>
      <ul>
        <li>Everything in Pro</li>
        <li>Custom branding</li>
        <li>API access</li>
        <li>Dedicated AI agent</li>
        <li>White-label option</li>
      </ul>
      <a class="btn btn-outline" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Start Creator+</a>
    </div>
  </div>
</section>

<footer>
  <p style="margin-bottom:.75rem"><strong>nvme.live</strong> &mdash; Dollar Double Empire | Founder: John B. Jefferis .Esq</p>
  <p><a href="/health">System Status</a> &bull; <a href="/donate">Support Us</a> &bull; &copy; 2026 nvme.live</p>
</footer>
</div><!-- /landingView -->

<!-- Auth Modal -->
<div class="modal-overlay" id="authModal" onclick="closeModalOutside(event)">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">&times;</button>
    <div class="tab-btns">
      <button class="tab-btn active" id="tabLogin" onclick="switchTab('login')">Log In</button>
      <button class="tab-btn" id="tabRegister" onclick="switchTab('register')">Sign Up</button>
    </div>
    <div id="msgBox" class="msg"></div>
    <div id="loginForm">
      <h2>Welcome back</h2>
      <p>Sign in to your nvme.live account</p>
      <div class="form-group"><label>Email</label><input type="email" id="loginEmail" placeholder="you@email.com"></div>
      <div class="form-group"><label>Password</label><input type="password" id="loginPass" placeholder="Password"></div>
      <button class="btn btn-primary" style="width:100%;margin-top:.5rem" onclick="doLogin()">Log In</button>
      <div style="display:flex;align-items:center;gap:10px;margin:14px 0 10px;"><hr style="flex:1;border:none;border-top:1px solid #ddd;"><span style="font-size:12px;color:#888;">or</span><hr style="flex:1;border:none;border-top:1px solid #ddd;"></div>
      <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;border:1.5px solid #ddd;border-radius:8px;background:white;color:#333;font-weight:600;font-size:14px;text-decoration:none;cursor:pointer;"><svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.6 2.5 30.2 0 24 0 14.7 0 6.8 5.4 2.9 13.3l7.8 6.1C12.5 13.1 17.8 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8c4.4-4.1 7.1-10.1 7.1-17z"/><path fill="#FBBC05" d="M10.7 28.6A14.6 14.6 0 0 1 9.5 24c0-1.6.3-3.2.8-4.6l-7.8-6.1A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.7l8.2-6.1z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.5-5.8c-2 1.4-4.6 2.2-7.7 2.2-6.2 0-11.5-4.2-13.3-9.8l-8.2 6.1C6.8 42.6 14.7 48 24 48z"/></svg> Continue with Google</a>
    </div>
    <div id="registerForm" style="display:none">
      <h2>Join nvme.live</h2>
      <p>Create your free creator account</p>
      <div class="form-group"><label>Username</label><input type="text" id="regUsername" placeholder="yourcreatorname"></div>
      <div class="form-group"><label>Email</label><input type="email" id="regEmail" placeholder="you@email.com"></div>
      <div class="form-group"><label>Password</label><input type="password" id="regPass" placeholder="Min 8 characters"></div>
      <button class="btn btn-primary" style="width:100%;margin-top:.5rem" onclick="doRegister()">Create Account</button>
      <div style="display:flex;align-items:center;gap:10px;margin:14px 0 10px;"><hr style="flex:1;border:none;border-top:1px solid #ddd;"><span style="font-size:12px;color:#888;">or</span><hr style="flex:1;border:none;border-top:1px solid #ddd;"></div>
      <a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;border:1.5px solid #ddd;border-radius:8px;background:white;color:#333;font-weight:600;font-size:14px;text-decoration:none;cursor:pointer;"><svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.6 2.5 30.2 0 24 0 14.7 0 6.8 5.4 2.9 13.3l7.8 6.1C12.5 13.1 17.8 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8c4.4-4.1 7.1-10.1 7.1-17z"/><path fill="#FBBC05" d="M10.7 28.6A14.6 14.6 0 0 1 9.5 24c0-1.6.3-3.2.8-4.6l-7.8-6.1A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.7l8.2-6.1z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.5-5.8c-2 1.4-4.6 2.2-7.7 2.2-6.2 0-11.5-4.2-13.3-9.8l-8.2 6.1C6.8 42.6 14.7 48 24 48z"/></svg> Sign up with Google</a>
    </div>
  </div>
</div>

<script>
const API = '';

// ── GOOGLE OAUTH CALLBACK TOKEN HANDLER ──────────────────────────────────────
(function(){
  const p = new URLSearchParams(window.location.search);
  const tok = p.get('token');
  const usr = p.get('user');
  if(tok){
    localStorage.setItem('nvme_token', tok);
    if(usr){ try{ localStorage.setItem('nvme_user', decodeURIComponent(usr)); }catch(e){} }
    window.history.replaceState({}, '', '/');
    setTimeout(()=>{ if(typeof checkAuth === 'function') checkAuth(); else location.reload(); }, 100);
  }
  const authFailed = p.get('auth');
  if(authFailed==='failed') { setTimeout(()=>alert('Google sign-in failed. Please try again.'),200); }
})();
function openModal(tab) { document.getElementById('authModal').classList.add('active'); switchTab(tab); }
function closeModal() { document.getElementById('authModal').classList.remove('active'); }
function closeModalOutside(e) { if (e.target.id === 'authModal') closeModal(); }
function switchTab(tab) {
  document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
  document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
  document.getElementById('tabLogin').classList.toggle('active', tab === 'login');
  document.getElementById('tabRegister').classList.toggle('active', tab === 'register');
  document.getElementById('msgBox').className = 'msg';
}
function showMsg(msg, type) {
  const el = document.getElementById('msgBox');
  el.textContent = msg; el.className = 'msg ' + type;
}
async function doLogin() {
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPass').value;
  try {
    const r = await fetch(API + '/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, password}) });
    const d = await r.json();
    if (!r.ok) return showMsg(d.error || 'Login failed', 'error');
    localStorage.setItem('nvme_token', d.token);
    showMsg('Welcome back, ' + d.user.username + '! Loading your feed...', 'success');
    setTimeout(() => { closeModal(); enterLoggedInState(d.user); }, 800);
  } catch(e) { showMsg('Network error. Try again.', 'error'); }
}
async function doRegister() {
  const username = document.getElementById('regUsername').value;
  const email = document.getElementById('regEmail').value;
  const password = document.getElementById('regPass').value;
  try {
    const r = await fetch(API + '/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, email, password}) });
    const d = await r.json();
    if (!r.ok) return showMsg(d.error || 'Registration failed', 'error');
    localStorage.setItem('nvme_token', d.token);
    showMsg('Account created! Welcome to nvme.live!', 'success');
    setTimeout(() => { closeModal(); enterLoggedInState(d.user); }, 800);
  } catch(e) { showMsg('Network error. Try again.', 'error'); }
}

// ── Logged-in state & feed engine ──────────────────────────
let currentUser = null;
let activeCommentVideoId = null;
const viewedVideos = {};

function authHeaders() {
  const t = localStorage.getItem('nvme_token');
  const h = { 'Content-Type': 'application/json' };
  if (t) h['Authorization'] = 'Bearer ' + t;
  return h;
}

function enterLoggedInState(user) {
  currentUser = user;
  document.getElementById('navLoggedOut').style.display = 'none';
  document.getElementById('navLoggedIn').style.display = 'flex';
  document.getElementById('navUsername').textContent = '@' + user.username;
  document.getElementById('landingView').style.display = 'none';
  document.getElementById('feedView').classList.add('active');
  loadFeed();
}

function enterLoggedOutState() {
  currentUser = null;
  document.getElementById('navLoggedOut').style.display = 'flex';
  document.getElementById('navLoggedIn').style.display = 'none';
  document.getElementById('landingView').style.display = 'block';
  document.getElementById('feedView').classList.remove('active');
  closeComments();
}

function doLogout() {
  localStorage.removeItem('nvme_token');
  enterLoggedOutState();
}

async function checkAuth() {
  const t = localStorage.getItem('nvme_token');
  if (!t) return;
  try {
    const r = await fetch(API + '/api/auth/me', { headers: authHeaders() });
    if (!r.ok) { localStorage.removeItem('nvme_token'); return; }
    const d = await r.json();
    enterLoggedInState(d.user);
  } catch(e) { /* stay logged out on network error */ }
}

const videoObserver = ('IntersectionObserver' in window) ? new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    const vid = entry.target;
    if (entry.isIntersecting && entry.intersectionRatio >= 0.6) {
      vid.play().catch(() => {});
      const id = vid.dataset.videoId;
      if (id && !viewedVideos[id]) {
        viewedVideos[id] = true;
        fetch(API + '/api/videos/' + id + '/view', { method: 'POST' }).catch(() => {});
      }
    } else {
      vid.pause();
    }
  });
}, { threshold: [0.6] }) : null;

async function loadFeed() {
  const feedEl = document.getElementById('feedView');
  try {
    const r = await fetch(API + '/api/feed', { headers: authHeaders() });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'feed failed');
    feedEl.innerHTML = '';
    if (!d.feed.length) {
      feedEl.innerHTML = '<div class="feed-empty"><h2>No videos yet</h2><p>Be the first creator to post on nvme.live!</p></div>';
      return;
    }
    d.feed.forEach((v) => feedEl.appendChild(buildFeedCard(v)));
  } catch(e) {
    feedEl.innerHTML = '<div class="feed-empty"><h2>Feed unavailable</h2><p>' + e.message + '</p></div>';
  }
}

function buildFeedCard(v) {
  const card = document.createElement('div');
  card.className = 'feed-card';

  const video = document.createElement('video');
  video.src = v.url;
  video.muted = true;
  video.loop = true;
  video.playsInline = true;
  video.preload = 'metadata';
  video.dataset.videoId = v.id;
  video.addEventListener('click', () => { video.paused ? video.play() : video.pause(); });
  card.appendChild(video);
  if (videoObserver) videoObserver.observe(video);

  const info = document.createElement('div');
  info.className = 'feed-info';
  const userEl = document.createElement('div');
  userEl.className = 'feed-user';
  userEl.textContent = '@' + v.username;
  const titleEl = document.createElement('div');
  titleEl.className = 'feed-title';
  titleEl.textContent = v.title;
  info.appendChild(userEl);
  info.appendChild(titleEl);
  card.appendChild(info);

  const actions = document.createElement('div');
  actions.className = 'feed-actions';

  const likeWrap = document.createElement('div');
  const likeBtn = document.createElement('button');
  likeBtn.className = 'feed-btn' + (v.viewer_liked ? ' liked' : '');
  likeBtn.textContent = '❤';
  const likeLabel = document.createElement('div');
  likeLabel.className = 'feed-btn-label';
  likeLabel.textContent = v.like_count;
  likeBtn.addEventListener('click', async () => {
    try {
      const r = await fetch(API + '/api/videos/' + v.id + '/like', { method: 'POST', headers: authHeaders() });
      const d = await r.json();
      if (!r.ok) return alert(d.error || 'like failed');
      likeBtn.classList.toggle('liked', d.liked);
      likeLabel.textContent = d.count;
    } catch(e) { alert('Network error'); }
  });
  likeWrap.appendChild(likeBtn);
  likeWrap.appendChild(likeLabel);
  actions.appendChild(likeWrap);

  const cmtWrap = document.createElement('div');
  const cmtBtn = document.createElement('button');
  cmtBtn.className = 'feed-btn';
  cmtBtn.textContent = '💬';
  const cmtLabel = document.createElement('div');
  cmtLabel.className = 'feed-btn-label';
  cmtLabel.textContent = v.comment_count;
  cmtBtn.addEventListener('click', () => openComments(v.id, cmtLabel));
  cmtWrap.appendChild(cmtBtn);
  cmtWrap.appendChild(cmtLabel);
  actions.appendChild(cmtWrap);

  if (!currentUser || currentUser.id !== v.author_id) {
    const followWrap = document.createElement('div');
    const followBtn = document.createElement('button');
    followBtn.className = 'feed-btn';
    followBtn.textContent = '➕';
    const followLabel = document.createElement('div');
    followLabel.className = 'feed-btn-label';
    followLabel.textContent = 'Follow';
    followBtn.addEventListener('click', async () => {
      try {
        const r = await fetch(API + '/api/users/' + v.author_id + '/follow', { method: 'POST', headers: authHeaders() });
        const d = await r.json();
        if (!r.ok) return alert(d.error || 'follow failed');
        followBtn.textContent = d.following ? '✓' : '➕';
        followLabel.textContent = d.following ? 'Following' : 'Follow';
      } catch(e) { alert('Network error'); }
    });
    followWrap.appendChild(followBtn);
    followWrap.appendChild(followLabel);
    actions.appendChild(followWrap);

    const giftWrap = document.createElement('div');
    const giftBtn = document.createElement('button');
    giftBtn.className = 'feed-btn';
    giftBtn.textContent = '🎁';
    const giftLabel = document.createElement('div');
    giftLabel.className = 'feed-btn-label';
    giftLabel.textContent = 'Gift';
    giftBtn.addEventListener('click', async () => {
      const amt = prompt('Send credits to @' + v.username + ':');
      if (!amt) return;
      try {
        const r = await fetch(API + '/api/gifts', {
          method: 'POST', headers: authHeaders(),
          body: JSON.stringify({ receiver_id: v.author_id, video_id: v.id, credits: Number(amt) })
        });
        const d = await r.json();
        if (!r.ok) return alert(d.error || 'gift failed');
        alert('Gift sent! @' + v.username + ' received ' + d.receiver_credited + ' credits 🎉');
      } catch(e) { alert('Network error'); }
    });
    giftWrap.appendChild(giftBtn);
    giftWrap.appendChild(giftLabel);
    actions.appendChild(giftWrap);
  }

  card.appendChild(actions);
  return card;
}

// ── Comments panel ──────────────────────────────────────────
let activeCommentCountEl = null;
async function openComments(videoId, countEl) {
  activeCommentVideoId = videoId;
  activeCommentCountEl = countEl || null;
  document.getElementById('commentPanel').classList.add('open');
  const list = document.getElementById('commentList');
  list.innerHTML = '<p style="color:var(--muted)">Loading...</p>';
  try {
    const r = await fetch(API + '/api/videos/' + videoId + '/comments');
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'failed');
    renderComments(d.comments);
  } catch(e) { list.innerHTML = '<p style="color:var(--muted)">Could not load comments.</p>'; }
}

function renderComments(comments) {
  const list = document.getElementById('commentList');
  list.innerHTML = '';
  if (!comments.length) {
    list.innerHTML = '<p style="color:var(--muted)">No comments yet. Say something!</p>';
    return;
  }
  comments.forEach((c) => {
    const item = document.createElement('div');
    item.className = 'comment-item';
    const u = document.createElement('div');
    u.className = 'c-user';
    u.textContent = '@' + c.username;
    const t = document.createElement('div');
    t.className = 'c-text';
    t.textContent = c.text;
    item.appendChild(u);
    item.appendChild(t);
    list.appendChild(item);
  });
}

function closeComments() {
  document.getElementById('commentPanel').classList.remove('open');
  activeCommentVideoId = null;
  activeCommentCountEl = null;
}

async function postComment() {
  const input = document.getElementById('commentInput');
  const text = input.value.trim();
  if (!text || !activeCommentVideoId) return;
  try {
    const r = await fetch(API + '/api/videos/' + activeCommentVideoId + '/comments', {
      method: 'POST', headers: authHeaders(), body: JSON.stringify({ text })
    });
    const d = await r.json();
    if (!r.ok) return alert(d.error || 'comment failed');
    input.value = '';
    if (activeCommentCountEl) activeCommentCountEl.textContent = Number(activeCommentCountEl.textContent || 0) + 1;
    openComments(activeCommentVideoId, activeCommentCountEl);
  } catch(e) { alert('Network error'); }
}

document.getElementById('commentInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') postComment();
});

// Fix login loop: restore session on page load
checkAuth();
</script>
</body>
</html>`);
});

// ── Start ─────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[nvme.live] ONLINE :${PORT} | Empire: Dollar Double Empire`);
  });
}).catch(e => {
  console.error('[nvme.live] DB init failed:', e.message);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[nvme.live] ONLINE :${PORT} (no DB — check DATABASE_URL)`);
  });
});
