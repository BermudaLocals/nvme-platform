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
const http = require('http');
const { Server: IOServer } = require('socket.io');
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: '*', credentials: true } });
// ============ PROGRESSIVE JACKPOT ============
// GET jackpot pool (public)
app.get('/api/jackpot', async (req, res) => {
  try {
    const r = await db.query('SELECT pool, total_entries, last_winner_username, last_won_at FROM jackpot_pool WHERE id=1');
    const jp = r.rows[0] || { pool: 25000, total_entries: 0 };
    res.json({ ok: true, pool: jp.pool, entries: jp.total_entries, lastWinner: jp.last_winner_username, lastWonAt: jp.last_won_at });
  } catch(e) { res.json({ ok: true, pool: 25000, entries: 0, lastWinner: null }); }
});

// POST enter jackpot — 50 coins per ticket, 1:500 chance
app.post('/api/jackpot/enter', authMiddleware, async (req, res) => {
  const TICKET = 50;
  const ODDS = 500;
  const SEED = 25000;
  try {
    const u = await db.query('SELECT balance_credits, username FROM users WHERE id=$1', [req.user.id]);
    const user = u.rows[0];
    if (!user || user.balance_credits < TICKET)
      return res.status(400).json({ ok: false, error: `Need ${TICKET} coins to enter` });
    // Deduct ticket cost
    await db.query('UPDATE users SET balance_credits = balance_credits - $1 WHERE id=$2', [TICKET, req.user.id]);
    // 50% of ticket seeds the pool
    await db.query('UPDATE jackpot_pool SET pool = pool + $1, total_entries = total_entries + 1 WHERE id=1', [Math.floor(TICKET * 0.5)]);
    // Roll for jackpot
    const won = Math.floor(Math.random() * ODDS) === 0;
    if (won) {
      const jp = await db.query('SELECT pool FROM jackpot_pool WHERE id=1');
      const prize = jp.rows[0].pool;
      await db.query('UPDATE users SET balance_credits = balance_credits + $1 WHERE id=$2', [prize, req.user.id]);
      await db.query('UPDATE jackpot_pool SET pool=$1, last_winner_username=$2, last_won_at=NOW(), total_paid=total_paid+$3 WHERE id=1',
        [SEED, user.username, prize]);
      return res.json({ ok: true, won: true, prize, newBalance: user.balance_credits - TICKET + prize,
        message: `🎉 JACKPOT! You won ${prize.toLocaleString()} coins!` });
    }
    const jp2 = await db.query('SELECT pool FROM jackpot_pool WHERE id=1');
    res.json({ ok: true, won: false, pool: jp2.rows[0].pool, newBalance: user.balance_credits - TICKET,
      message: `No win. Jackpot now ${jp2.rows[0].pool.toLocaleString()} coins!` });
  } catch(e) { console.error('Jackpot error:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ============ PROFILE EDIT ROUTES ============

// Upload profile photo
const multer = require('multer');
const uploadStorage = multer.diskStorage({
  destination: (req,file,cb) => cb(null, 'public/uploads/avatars/'),
  filename: (req,file,cb) => {
    const ext = file.originalname.split('.').pop();
    cb(null, 'avatar_' + req.user.id + '_' + Date.now() + '.' + ext);
  }
});
const avatarUpload = multer({
  storage: uploadStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req,file,cb) => {
    if(file.mimetype.startsWith('image/')) cb(null,true);
    else cb(new Error('Images only'));
  }
});

// Ensure avatars directory exists
const fs = require('fs');
if(!fs.existsSync('public/uploads/avatars')) fs.mkdirSync('public/uploads/avatars', { recursive: true });

// ── Sticker Storage ─────────────────────────────────────────────────────────
const stickerStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/stickers/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + path.extname(file.originalname))
});
const stickerUpload = multer({
  storage: stickerStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    if (/image\/(png|gif|webp|jpeg)/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only PNG, GIF, WEBP, JPG allowed'));
  }
});
if (!fs.existsSync('public/uploads/stickers')) fs.mkdirSync('public/uploads/stickers', { recursive: true });

// Default empire sticker pack
const DEFAULT_STICKERS = [
  { id: 'def_1', url: null, emoji: '👑', name: 'Crown', is_default: true },
  { id: 'def_2', url: null, emoji: '💰', name: 'Money', is_default: true },
  { id: 'def_3', url: null, emoji: '🔥', name: 'Fire', is_default: true },
  { id: 'def_4', url: null, emoji: '💎', name: 'Diamond', is_default: true },
  { id: 'def_5', url: null, emoji: '🚀', name: 'Rocket', is_default: true },
  { id: 'def_6', url: null, emoji: '⭐', name: 'Star', is_default: true },
  { id: 'def_7', url: null, emoji: '🎯', name: 'Target', is_default: true },
  { id: 'def_8', url: null, emoji: '💜', name: 'Heart', is_default: true },
  { id: 'def_9', url: null, emoji: '🎬', name: 'Clapper', is_default: true },
  { id: 'def_10', url: null, emoji: '🏆', name: 'Trophy', is_default: true },
  { id: 'def_11', url: null, emoji: '⚡', name: 'Lightning', is_default: true },
  { id: 'def_12', url: null, emoji: '🎵', name: 'Music', is_default: true },
];

// POST /api/stickers/upload — upload custom sticker
app.post('/api/stickers/upload', authMiddleware, stickerUpload.single('sticker'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded' });
    const stickerUrl = '/uploads/stickers/' + req.file.filename;
    const name = req.body.name || 'Custom Sticker';
    // Save to DB
    await db.query(
      `INSERT INTO stickers (user_id, url, name) VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [req.user.id, stickerUrl, name]
    ).catch(async () => {
      // Table might not exist yet — create it
      await db.query(`CREATE TABLE IF NOT EXISTS stickers (
        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        name TEXT DEFAULT 'Custom',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
      await db.query(`INSERT INTO stickers (user_id, url, name) VALUES ($1, $2, $3)`, [req.user.id, stickerUrl, name]);
    });
    res.json({ ok: true, url: stickerUrl, name });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/stickers — get user stickers + default pack
app.get('/api/stickers', authMiddleware, async (req, res) => {
  try {
    let userStickers = [];
    try {
      const result = await db.query(
        `SELECT id, url, name, created_at FROM stickers WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
        [req.user.id]
      );
      userStickers = result.rows.map(s => ({ ...s, is_default: false }));
    } catch(e) { /* table not created yet */ }
    res.json({ ok: true, stickers: [...DEFAULT_STICKERS, ...userStickers] });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// DELETE /api/stickers/:id — delete custom sticker
app.delete('/api/stickers/:id', authMiddleware, async (req, res) => {
  try {
    await db.query(`DELETE FROM stickers WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});


// POST /api/profile/avatar — upload profile photo
app.post('/api/profile/avatar', authMiddleware, avatarUpload.single('avatar'), async (req, res) => {
  try {
    if(!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded' });
    const avatarUrl = '/uploads/avatars/' + req.file.filename;
    await db.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [avatarUrl, req.user.id]);
    res.json({ ok: true, avatar_url: avatarUrl });
  } catch(e) { console.error('Avatar upload error:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// PUT /api/profile — update display name, bio, username
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { display_name, bio, username, profile_link, avatar_url } = req.body;
    // Validate username if provided
    if(username) {
      if(!/^[a-zA-Z0-9_]{3,30}$/.test(username))
        return res.status(400).json({ ok: false, error: 'Username must be 3-30 chars, letters/numbers/underscores only' });
      // Check not taken
      const taken = await db.query('SELECT id FROM users WHERE username=$1 AND id!=$2', [username, req.user.id]);
      if(taken.rows.length > 0)
        return res.status(400).json({ ok: false, error: 'Username already taken' });
    }
    // Build update query dynamically
    const updates = [];
    const values = [];
    let idx = 1;
    if(display_name !== undefined) { updates.push(`display_name=$${idx++}`); values.push(display_name.slice(0,50)); }
    if(bio !== undefined) { updates.push(`bio=$${idx++}`); values.push(bio.slice(0,160)); }
    if(username !== undefined) { updates.push(`username=$${idx++}`); values.push(username); }
    if(profile_link !== undefined) { updates.push(`profile_link=$${idx++}`); values.push(profile_link.slice(0,200)); }
    if(avatar_url !== undefined && avatar_url.startsWith('data:image')) {
      // Base64 avatar — store directly in DB (Railway-safe, no disk needed)
      updates.push(`avatar_url=$${idx++}`); values.push(avatar_url);
    }
    if(updates.length === 0) return res.status(400).json({ ok: false, error: 'Nothing to update' });
    values.push(req.user.id);
    const result = await db.query(
      `UPDATE users SET ${updates.join(',')} WHERE id=$${idx} RETURNING id,username,display_name,bio,avatar_url,profile_link`,
      values
    );
    res.json({ ok: true, user: result.rows[0] });
  } catch(e) { console.error('Profile update error:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ============ LIVE BATTLE GUEST SYSTEM ============
// Invite up to 2 guests to a live battle
app.post('/api/streams/:id/invite-guest', authMiddleware, async (req, res) => {
  try {
    const { guest_username } = req.body;
    const streamId = req.params.id;
    // Check stream exists and belongs to host
    const stream = await db.query('SELECT * FROM live_streams WHERE id=$1', [streamId]);
    if(!stream.rows[0]) return res.status(404).json({ ok:false, error:'Stream not found' });
    // Find guest user
    const guest = await db.query('SELECT id, username, avatar_url FROM users WHERE username=$1', [guest_username]);
    if(!guest.rows[0]) return res.status(404).json({ ok:false, error:'User not found' });
    // Check current guest count (max 2)
    const currentGuests = await db.query(
      "SELECT * FROM stream_guests WHERE stream_id=$1 AND status='active'", [streamId]
    ).catch(() => ({ rows: [] }));
    if(currentGuests.rows.length >= 2)
      return res.status(400).json({ ok:false, error:'Maximum 2 guests allowed in battle' });
    // Create or update guest_slots table
    await db.query(`
      CREATE TABLE IF NOT EXISTS stream_guests (
        id SERIAL PRIMARY KEY,
        stream_id TEXT NOT NULL,
        guest_user_id TEXT NOT NULL,
        guest_username VARCHAR(100),
        guest_avatar TEXT,
        status VARCHAR(20) DEFAULT 'invited',
        slot INTEGER DEFAULT 1,
        invited_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(()=>{});
    const slot = currentGuests.rows.length + 1;
    await db.query(
      'INSERT INTO stream_guests (stream_id, guest_user_id, guest_username, guest_avatar, status, slot) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
      [streamId, guest.rows[0].id, guest.rows[0].username, guest.rows[0].avatar_url, 'invited', slot]
    );
    // Notify via socket
    if(global.io) {
      global.io.to(`stream_${streamId}`).emit('guest_invited', {
        streamId, guest: guest.rows[0], slot
      });
      // Also notify the guest directly
      global.io.emit('you_are_invited', {
        streamId, hostUsername: req.user.username, slot
      });
    }
    res.json({ ok:true, guest: guest.rows[0], slot, message:`${guest.rows[0].username} invited as Guest ${slot}` });
  } catch(e) { console.error('Guest invite error:', e.message); res.status(500).json({ ok:false, error:e.message }); }
});

// GET guests for a stream
app.get('/api/streams/:id/guests', async (req, res) => {
  try {
    const r = await db.query(
      "SELECT * FROM stream_guests WHERE stream_id=$1 AND status='active' ORDER BY slot",
      [req.params.id]
    ).catch(() => ({ rows: [] }));
    res.json({ ok:true, guests: r.rows });
  } catch(e) { res.json({ ok:true, guests:[] }); }
});

// POST guest accepts/joins
app.post('/api/streams/:id/join-as-guest', authMiddleware, async (req, res) => {
  try {
    await db.query(
      "UPDATE stream_guests SET status='active' WHERE stream_id=$1 AND guest_user_id=$2",
      [req.params.id, req.user.id]
    ).catch(()=>{});
    if(global.io) {
      global.io.to(`stream_${req.params.id}`).emit('guest_joined', {
        streamId: req.params.id,
        guest: { id: req.user.id, username: req.user.username }
      });
    }
    res.json({ ok:true, message:'Joined as guest' });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// DELETE remove guest
app.delete('/api/streams/:id/guests/:guestId', authMiddleware, async (req, res) => {
  try {
    await db.query(
      "UPDATE stream_guests SET status='removed' WHERE stream_id=$1 AND guest_user_id=$2",
      [req.params.id, req.params.guestId]
    ).catch(()=>{});
    if(global.io) {
      global.io.to(`stream_${req.params.id}`).emit('guest_removed', {
        streamId: req.params.id, guestId: req.params.guestId
      });
    }
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

const PORT = process.env.PORT || 3090;
const IS_PROD = process.env.NODE_ENV === 'production';

// ── SESSION (required for passport) ──────────────────────────────────────────
// Railway: PostgreSQL-only sessions (empire Redis must NOT be used on Railway)
let sessionStore = undefined;
if (process.env.DATABASE_URL) {
  try {
    const pgSession = require('connect-pg-simple')(session);
    sessionStore = new pgSession({
      conString: process.env.DATABASE_URL,
      tableName: 'nvme_sessions',
      createTableIfMissing: true,
      errorLog: (e) => { if (!e.message?.includes('already exists')) console.error('[Session PG]', e.message); }
    });
    console.log('[Session] PostgreSQL session store active');
  } catch(e2) { console.log('[Session] PG session fallback failed:', e2.message); }
}
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET || 'nvme-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: IS_PROD, sameSite: IS_PROD ? 'lax' : false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ── GOOGLE OAUTH STRATEGY ────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const username = profile.displayName?.replace(/\s+/g, '_').toLowerCase() || 'user_' + profile.id;
          const avatar = profile.photos?.[0]?.value || null;
          let result = await db.query('SELECT * FROM users WHERE email=$1', [email]);
          let user;
          if (result.rows.length === 0) {
            const r = await db.query(
              'INSERT INTO users (id,email,username,password_hash,avatar_url,created_at) VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *',
              [uuidv4(), email, username, 'GOOGLE_OAUTH', avatar]
            );
            user = r.rows[0];
          } else {
            user = result.rows[0];
            if (avatar && !user.avatar_url) {
              await db.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [avatar, user.id]);
              user.avatar_url = avatar;
            }
            // Fix null username for existing users
            if (!user.username) {
              const fixedUsername = profile.displayName?.replace(/\s+/g, '_').toLowerCase() || 'user_' + profile.id;
              await db.query('UPDATE users SET username=$1 WHERE id=$2', [fixedUsername, user.id]);
              user.username = fixedUsername;
            }
          }
          const displayName = user.username || user.email.split('@')[0].replace(/[^a-z0-9_]/gi, '_');
          return done(null, { id: user.id, email: user.email, username: displayName });
        } catch (err) {
          console.error('[GoogleOAuth] Callback error:', err.stack);
          return done(null, false);
        }
      }
    )
  );
}
// Duplicate GoogleStrategy removed

// ── Production env guardrails (resilient) ────────────────────
if (IS_PROD) {
  const required = ['DATABASE_URL', 'JWT_SECRET'];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error(`[nvme.live] WARNING: missing env in production: ${missing.join(', ')} — set these in Railway variables!`);
  }
  if (!process.env.JWT_SECRET) {
    // Use consistent fallback — avoids token invalidation on every restart
    process.env.JWT_SECRET = 'nvme-empire-2026-jwt-kush-dollar-double-empire-secret-key';
    console.error('[nvme.live] WARNING: JWT_SECRET not set in Railway env vars — using consistent fallback. Set JWT_SECRET in Railway Variables for production security.');
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
app.get('/shop', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  let html = fs.readFileSync(path.join(__dirname, 'public/shop.html'), 'utf8');
  html = html.replace('</head>', `<script>window.__PAYPAL_CLIENT_ID=${JSON.stringify(process.env.PAYPAL_CLIENT_ID||'')};</script>\n</head>`);
  res.type('html').send(html);
});


// ── Privacy toggle ──
app.put('/api/profile/privacy', authMiddleware, async (req, res) => {
  try {
    const { is_private } = req.body;
    await db.query('UPDATE users SET is_private=$1 WHERE id=$2', [is_private, req.user.id]);
    res.json({ ok: true, is_private: is_private });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Get pending follow requests ──
app.get('/api/follow-requests', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT fr.id, fr.created_at, fr.requester_id,
             u.username, u.display_name, u.avatar_url
      FROM follow_requests fr
      JOIN users u ON u.id = fr.requester_id
      WHERE fr.target_id = $1 AND fr.status = 'pending'
      ORDER BY fr.created_at DESC
    `, [req.user.id]);
    res.json({ ok: true, requests: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Accept or decline a follow request ──
app.post('/api/follow-requests/:id/respond', authMiddleware, async (req, res) => {
  try {
    const { action } = req.body;
    const { rows } = await db.query(
      "SELECT * FROM follow_requests WHERE id=$1 AND target_id=$2 AND status='pending'",
      [req.params.id, req.user.id]
    );
    const request = rows[0];
    if (action === 'accept') {
      await db.query(
        'INSERT INTO follows (follower_id, followee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [request.requester_id, req.user.id]
      );
    }
    await db.query('DELETE FROM follow_requests WHERE id=$1', [request.id]);
    res.json({ ok: true, action });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Follow / unfollow / request ──
app.post('/api/users/:id/follow', authMiddleware, async (req, res) => {
  try {
    const followeeId = req.params.id;
    if (followeeId === req.user.id) return res.status(400).json({ error: 'cannot follow yourself' });
    const { rows: urows } = await db.query('SELECT id, is_private FROM users WHERE id=$1', [followeeId]);
    const target = urows[0];

    const { rowCount: unfollowed } = await db.query(
      'DELETE FROM follows WHERE follower_id=$1 AND followee_id=$2', [req.user.id, followeeId]
    );
    if (unfollowed > 0) {
      const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [followeeId]);
      return res.json({ ok: true, status: 'unfollowed', followers: rows[0].count });
    }

    const { rowCount: cancelled } = await db.query(
      "DELETE FROM follow_requests WHERE requester_id=$1 AND target_id=$2 AND status='pending'",
      [req.user.id, followeeId]
    );
    if (cancelled > 0) {
      const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [followeeId]);
      return res.json({ ok: true, status: 'request_cancelled', followers: rows[0].count });
    }

    if (target.is_private) {
      await db.query(
        'INSERT INTO follow_requests (requester_id, target_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [req.user.id, followeeId]
      );
      const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [followeeId]);
      return res.json({ ok: true, status: 'requested', followers: rows[0].count });
    }

    await db.query(
      'INSERT INTO follows (follower_id, followee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.user.id, followeeId]
    );
    const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [followeeId]);
    res.json({ ok: true, status: 'following', followers: rows[0].count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Discover: ALL non-private users + online presence (Explore default view) ──
// NOTE: must be registered BEFORE '/api/users/:username' or it gets swallowed by the wildcard.
app.get('/api/users/discover', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.display_name, u.avatar_url, u.plan, u.bio,
              (SELECT COUNT(*)::int FROM follows f WHERE f.followee_id=u.id) AS followers
       FROM users u WHERE u.is_private IS NOT TRUE
       ORDER BY followers DESC, u.created_at DESC LIMIT 100`
    );
    const users = rows.map(u => ({ ...u, online: onlineUsers.has(u.id) || onlineUsers.has(String(u.id)) }));
    res.json({ ok: true, users, online_count: users.filter(u => u.online).length });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Public user profile ──
app.get('/api/users/:username', async (req, res) => {
  try {
    let viewerId = null;
    try {
      const tok = req.cookies?.token || req.headers.authorization?.split(' ')[1];
      if (tok) {
        const jwt = require('jsonwebtoken');
        const dec = jwt.verify(tok, process.env.JWT_SECRET || 'nvme-secret');
        viewerId = dec.userId;
      }
    } catch {}

    const { rows: urows } = await db.query(
      'SELECT id, username, display_name, bio, avatar_url, is_private, created_at FROM users WHERE username=$1',
      [req.params.username]
    );
    const user = urows[0];

    const [followersR, followingR] = await Promise.all([
      db.query('SELECT COUNT(*)::int AS count FROM follows WHERE followee_id=$1', [user.id]),
      db.query('SELECT COUNT(*)::int AS count FROM follows WHERE follower_id=$1', [user.id]),
    ]);

    let relationship = 'none';
    if (viewerId === user.id) {
      relationship = 'self';
    } else if (viewerId) {
      const { rows: frows } = await db.query(
        'SELECT 1 FROM follows WHERE follower_id=$1 AND followee_id=$2', [viewerId, user.id]
      );
      if (frows.length) {
        relationship = 'following';
      } else {
        const { rows: rrows } = await db.query(
          "SELECT 1 FROM follow_requests WHERE requester_id=$1 AND target_id=$2 AND status='pending'",
          [viewerId, user.id]
        );
        if (rrows.length) relationship = 'requested';
      }
    }

    let videos = [];
    if (canSeeContent) {
      const { rows: vrows } = await db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.created_at,
               COALESCE(l.like_count,0)::int AS like_count
        FROM videos v
        LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id=v.id
        WHERE v.user_id=$1 ORDER BY v.created_at DESC LIMIT 50
      `, [user.id]);
      videos = vrows;
    }

    res.json({
      ok: true,
      user: { id: user.id, username: user.username, display_name: user.display_name,
              bio: canSeeContent ? user.bio : null, avatar_url: user.avatar_url,
              is_private: user.is_private, created_at: user.created_at },
      stats: { followers: followersR.rows[0].count, following: followingR.rows[0].count,
               videos: canSeeContent ? videos.length : null },
      relationship, can_see_content: canSeeContent, videos
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Serve profile page ──
app.get('/u/:username', (req, res) => {
  res.sendFile(require('path').join(__dirname, 'frontend', 'profile-view.html'));
});

// Never cache app.html — preserves OAuth ?token= query params
const serveApp = (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(require('path').join(__dirname, 'public', 'app.html'));
};
app.get('/app.html', serveApp);
app.get('/app', serveApp);
// Pretty routes for full-page experiences
app.get('/live', (req, res) => res.sendFile(require('path').join(__dirname, 'public', 'live.html')));
app.get('/creator', (req, res) => res.sendFile(require('path').join(__dirname, 'public', 'creator.html')));
app.get('/messages', (req, res) => res.sendFile(require('path').join(__dirname, 'public', 'messages.html')));
app.get('/merch', (req, res) => res.sendFile(require('path').join(__dirname, 'public', 'merch.html')));

// ── Landing: 3D-enhanced NVME design served from public/index.html via static middleware below.
// (Next.js static export retired 2026-08-02 — kept in public/next/ for reference; Digital King chose the 3D design.)
app.use(require('express').static(require('path').join(__dirname, 'public')));

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
    -- Add profile columns if missing (safe migrations)
    -- Fix any videos with null URL (placeholder for text posts)
    UPDATE videos SET url='https://nvme.live/placeholder.mp4' WHERE url IS NULL OR url='';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_link TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 500;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_credits INTEGER DEFAULT 500;
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
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS text TEXT DEFAULT '';
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS content TEXT DEFAULT '';
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS image_url TEXT;
    ALTER TABLE comments ALTER COLUMN content DROP NOT NULL;
    ALTER TABLE comments ALTER COLUMN text DROP NOT NULL;
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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT false;
    CREATE TABLE IF NOT EXISTS follow_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      requester_id UUID REFERENCES users(id) ON DELETE CASCADE,
      target_id UUID REFERENCES users(id) ON DELETE CASCADE,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (requester_id, target_id)
    );
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

  // ── Gift catalog table (ORBAT tiers) ──────────────────────
  await db.query(`
    CREATE TABLE IF NOT EXISTS gift_catalog (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT UNIQUE NOT NULL,
      emoji TEXT NOT NULL,
      icon_url TEXT,
      credit_cost NUMERIC NOT NULL,
      usd_value NUMERIC NOT NULL,
      creator_pct INTEGER DEFAULT 70,
      platform_pct INTEGER DEFAULT 30,
      is_active BOOLEAN DEFAULT true,
      tier_level INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `).catch(e => console.warn('gift_catalog init warning:', e.message));

  // ── Seed ORBAT gift tiers ─────────────────────────────────
  await db.query(`
    INSERT INTO gift_catalog (name, emoji, icon_url, credit_cost, usd_value, creator_pct, platform_pct, tier_level, is_active) VALUES
    ('Recruit',      '🪙', '/gifts/recruit.png',      10,    0.10, 70, 30, 1, true),
    ('Soldier',      '⚔️', '/gifts/soldier.png',      50,    0.50, 70, 30, 2, true),
    ('Captain',      '🔥', '/gifts/captain.png',      200,   2.00, 70, 30, 3, true),
    ('Director',     '⚡', '/gifts/director.png',     500,   5.00, 70, 30, 4, true),
    ('Commander',    '👑', '/gifts/commander.png',    1000, 10.00, 70, 30, 5, true),
    ('CxO Elite',    '💎', '/gifts/cxo.png',          5000, 50.00, 70, 30, 6, true),
    ('DIGITAL KING', '🔱', '/gifts/king.png',        10000,100.00, 70, 30, 7, true)
    ON CONFLICT (name) DO NOTHING
  `).catch(() => {});
}

// ── Routes: Health ───────────────────────────────────────────

// ── GOOGLE OAUTH ROUTES ──────────────────────────────────────────────────────
// Auth failure safety net — catches any strategy-level failures
app.get('/auth/failure', (req, res) => {
  res.redirect('/?auth=failed&reason=google_strategy_error');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth=failed', session: false }),
  (req, res) => {
    try {
      if (!req.user) return res.redirect('/?auth=failed&reason=no_user');
      const token = signToken({ id: req.user.id, email: req.user.email });
      // Use hash fragment (#) — not intercepted by Service Workers or cached
      // Fixes Samsung Internet + all mobile browsers — hash never sent to server
      return res.redirect('/app.html#token=' + token);
    } catch(e) {
      console.error('[OAuth callback error]', e.message);
      return res.redirect('/?auth=failed&reason=server_error');
    }
  }
);


// POST /api/wallet/deduct — deduct coins for platform features
app.post('/api/wallet/deduct', authMiddleware, async (req, res) => {
  try {
    const { amount, reason } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ ok: false, error: 'Invalid amount' });
    // Check current balance
    const result = await db.query(`SELECT coins FROM users WHERE id=$1`, [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
    const current = result.rows[0].coins || 0;
    if (current < amount) return res.status(402).json({ ok: false, error: 'Insufficient coins', balance: current });
    // Deduct
    const updated = await db.query(
      `UPDATE users SET coins = coins - $1 WHERE id=$2 RETURNING coins`,
      [amount, req.user.id]
    );
    const newBal = updated.rows[0].coins;
    console.log(`[coins] ${req.user.email} spent ${amount} on ${reason} — balance: ${newBal}`);
    res.json({ ok: true, balance: newBal, spent: amount, reason });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/wallet/balance — get current coin balance
app.get('/api/wallet/balance', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(`SELECT coins FROM users WHERE id=$1`, [req.user.id]);
    const balance = result.rows[0]?.coins || 0;
    res.json({ ok: true, balance });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

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
    const hash = user.password_hash || user.password;
    if (!hash) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ ok: true, token: signToken({ id: user.id, email: user.email }), user: { id: user.id, email: user.email, username: user.username, plan: user.plan } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT id, email, username, plan, coins, role, is_creator, verified, avatar_url, bio, created_at FROM users WHERE id=$1',
      [req.user.id]
    );
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
      WHERE v.url IS NOT NULL AND v.url <> ''
      ORDER BY score DESC, v.created_at DESC
      LIMIT 20
    `, [viewerId]);
    res.json({ ok: true, feed: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/users/:username/videos — public: a user's own videos for their profile grid (TikTok-style)
app.get('/api/users/:username/videos', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.created_at,
             COALESCE(l.like_count, 0)::int AS like_count,
             COALESCE(c.comment_count, 0)::int AS comment_count
      FROM videos v
      JOIN users u ON u.id = v.user_id
      LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id = v.id
      LEFT JOIN (SELECT video_id, COUNT(*) AS comment_count FROM comments GROUP BY video_id) c ON c.video_id = v.id
      WHERE u.username = $1 AND v.url IS NOT NULL AND v.url <> ''
      ORDER BY v.created_at DESC
      LIMIT 60
    `, [req.params.username]);
    res.json({ ok: true, videos: rows });
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
      SELECT c.id, COALESCE(NULLIF(c.text,''), c.content, '') AS text, c.image_url, c.created_at, u.username, u.display_name, u.avatar_url
      FROM comments c JOIN users u ON u.id = c.user_id
      WHERE c.video_id = $1 ORDER BY c.created_at DESC LIMIT 100
    `, [req.params.id]);
    res.json({ ok: true, comments: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/comments', authMiddleware, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    let imageUrl = null;
    if (typeof req.body.image === 'string' && req.body.image.startsWith('data:image') && req.body.image.length < 3000000) imageUrl = req.body.image;
    if ((!text && !imageUrl) || text.length > 500) return res.status(400).json({ error: 'text or image required (text max 500 chars)' });
    const { rows: vrows } = await db.query('SELECT id FROM videos WHERE id=$1', [req.params.id]);
    if (!vrows.length) return res.status(404).json({ error: 'video not found' });
    const { rows } = await db.query(
      'INSERT INTO comments (video_id, user_id, text, content, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING id, text, image_url, created_at',
      [req.params.id, req.user.id, text || '', text || '', imageUrl]
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
  :root{--bg:#07070d;--card:#0f0f1a;--border:#1a1a2e;--accent:#e91e8c;--accent2:#00d4ff;--text:#f8fafc;--muted:#7a8499}
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

  /* TikTok/Instagram style bottom navigation */
  .bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;height:60px;background:rgba(7,7,13,.97);border-top:1px solid var(--border);z-index:200;align-items:center;justify-content:space-around;padding-bottom:env(safe-area-inset-bottom)}
  .bottom-nav.visible{display:flex}
  .bnav-btn{display:flex;flex-direction:column;align-items:center;gap:2px;background:none;border:none;color:var(--muted);cursor:pointer;padding:.4rem .6rem;border-radius:8px;transition:color .2s;min-width:52px;font-size:.65rem;font-weight:600;text-decoration:none}
  .bnav-btn:hover,.bnav-btn.active{color:var(--text)}
  .bnav-btn svg,.bnav-btn .bicon{font-size:1.4rem;line-height:1}
  .bnav-btn.create-btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border-radius:12px;padding:.45rem .8rem;margin-top:-8px;box-shadow:0 4px 15px rgba(233,30,140,.4)}
  .bnav-btn.create-btn:hover{opacity:.9;transform:scale(1.05)}
  body.app-mode{padding-bottom:60px}

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
  <div id="navLoggedIn" style="display:none;align-items:center;gap:.75rem">
    <span id="navUsername" style="color:var(--accent);font-weight:700;font-size:.95rem;cursor:pointer" onclick="openProfile()"></span>
    <button onclick="doLogout()" style="background:none;border:1px solid rgba(233,30,140,.4);color:var(--muted);padding:.3rem .8rem;border-radius:20px;font-size:.8rem;cursor:pointer">Logout</button>
  </div>
</nav>

<!-- TikTok/Instagram/Clapper style bottom navigation (visible when logged in) -->
<nav class="bottom-nav" id="bottomNav">
  <button class="bnav-btn active" id="bnavHome" onclick="bnavGo('home')">
    <span class="bicon">🏠</span>Home
  </button>
  <button class="bnav-btn" id="bnavExplore" onclick="bnavGo('explore')">
    <span class="bicon">🔍</span>Explore
  </button>
  <button class="bnav-btn create-btn" id="bnavCreate" onclick="openUploadModal()">
    <span class="bicon">＋</span>Create
  </button>
  <a class="bnav-btn" id="bnavShop" href="/shop">
    <span class="bicon">🎁</span>Shop
  </a>
  <button class="bnav-btn" id="bnavProfile" onclick="openProfile()">
    <span class="bicon">👤</span>Profile
  </button>
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
  // Handle feed/live nav tabs
  if (tab === 'feed') { document.getElementById('feedView').scrollTop = 0; return; }
  if (tab === 'live') { window.location.href = '/shop#live'; return; }
  // Handle auth modal tabs
  const lf = document.getElementById('loginForm');
  const rf = document.getElementById('registerForm');
  if (lf) lf.style.display = tab === 'login' ? 'block' : 'none';
  if (rf) rf.style.display = tab === 'register' ? 'block' : 'none';
  const tl = document.getElementById('tabLogin');
  const tr = document.getElementById('tabRegister');
  if (tl) tl.classList.toggle('active', tab === 'login');
  if (tr) tr.classList.toggle('active', tab === 'register');
  const mb = document.getElementById('msgBox');
  if (mb) mb.className = 'msg';
}
function openUploadModal() {
  if (!currentUser) { openModal('login'); return; }
  const msg = 'Upload coming soon! For now, share your video URL in your profile.
Contact: dollardoublemarketing@gmail.com';
  alert(msg);
}
function openProfile() {
  if (!currentUser) return;
  const slug = currentUser.username || currentUser.email?.split('@')[0];
  window.location.href = '/profile/' + slug;
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
  document.getElementById('navUsername').textContent = '@' + (user.username || user.email?.split('@')[0] || 'creator');
  document.getElementById('landingView').style.display = 'none';
  document.getElementById('feedView').classList.add('active');
  // Show TikTok-style bottom nav
  const bn = document.getElementById('bottomNav');
  if (bn) { bn.classList.add('visible'); document.body.classList.add('app-mode'); }
  loadFeed();
}
function bnavGo(tab) {
  document.querySelectorAll('.bnav-btn').forEach(b => b.classList.remove('active'));
  if (tab === 'home') { document.getElementById('bnavHome').classList.add('active'); document.getElementById('feedView').scrollTop = 0; }
  if (tab === 'explore') { document.getElementById('bnavExplore').classList.add('active'); }
}

function enterLoggedOutState() {
  currentUser = null;
  document.getElementById('navLoggedOut').style.display = 'flex';
  document.getElementById('navLoggedIn').style.display = 'none';
  document.getElementById('landingView').style.display = 'block';
  document.getElementById('feedView').classList.remove('active');
  // Hide bottom nav
  const bn = document.getElementById('bottomNav');
  if (bn) { bn.classList.remove('visible'); document.body.classList.remove('app-mode'); }
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

// ── NEW DB TABLES: DMs + Live Chat ────────────────────────────────────────
// (run at startup alongside existing initDB)
async function initRealtimeDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS dm_conversations (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      participant_a UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      participant_b UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_message_at TIMESTAMPTZ DEFAULT NOW(),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(participant_a, participant_b)
    );
    CREATE TABLE IF NOT EXISTS dm_messages (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
      sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      media_url TEXT,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS livestream_chat (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Realtime DB tables ready');
}
initRealtimeDB().catch(e => console.error('initRealtimeDB error:', e.message));

// ── REST: Livestream endpoints ────────────────────────────────────────────
app.post('/api/streams', authMiddleware, async (req, res) => {
  try {
    const { title, description, is_premium, price_credits } = req.body;
    const streamKey = uuidv4().replace(/-/g,'').substring(0,24);
    const { rows } = await db.query(
      'INSERT INTO livestreams (user_id,title,description,stream_key,is_premium,price_credits) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.id, title||'Live Stream', description||'', streamKey, is_premium||false, price_credits||0]
    );
    res.status(201).json({ ok: true, stream: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/streams/:id/go-live', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      "UPDATE livestreams SET status='live', started_at=NOW(), viewer_count=0 WHERE id=$1 AND user_id=$2 RETURNING *",
      [req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'stream not found' });
    io.emit('stream_live', { streamId: rows[0].id, userId: rows[0].user_id, title: rows[0].title });
    res.json({ ok: true, stream: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/streams/:id/end-live', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      "UPDATE livestreams SET status='ended', ended_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING *",
      [req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'stream not found' });
    io.to(`stream:${rows[0].id}`).emit('stream_ended', { streamId: rows[0].id });
    res.json({ ok: true, stream: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/streams/live', async (req, res) => {
  try {
    const { rows } = await db.query("SELECT ls.*, u.username, u.avatar_url FROM live_streams ls JOIN users u ON u.id=ls.user_id WHERE ls.is_active=true ORDER BY ls.viewer_count DESC");
    res.json({ ok: true, streams: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/streams/:id/chat', async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT lc.*, u.username, u.avatar_url FROM livestream_chat lc JOIN users u ON u.id=lc.user_id WHERE lc.stream_id=$1 ORDER BY lc.created_at DESC LIMIT 100',
      [req.params.id]
    );
    res.json({ ok: true, chat: rows.reverse() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── REST: DM endpoints ────────────────────────────────────────────────────
app.get('/api/dm/conversations', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT dc.*,
        CASE WHEN dc.participant_a=$1 THEN u2.username ELSE u1.username END AS other_username,
        CASE WHEN dc.participant_a=$1 THEN u2.avatar_url ELSE u1.avatar_url END AS other_avatar,
        CASE WHEN dc.participant_a=$1 THEN dc.participant_b ELSE dc.participant_a END AS other_user_id,
        (SELECT content FROM dm_messages WHERE conversation_id=dc.id ORDER BY created_at DESC LIMIT 1) AS last_message,
        (SELECT COUNT(*) FROM dm_messages WHERE conversation_id=dc.id AND sender_id!=$1 AND is_read=false)::int AS unread_count
      FROM dm_conversations dc
      JOIN users u1 ON u1.id=dc.participant_a
      JOIN users u2 ON u2.id=dc.participant_b
      WHERE dc.participant_a=$1 OR dc.participant_b=$1
      ORDER BY dc.last_message_at DESC`,
      [req.user.id]
    );
    res.json({ ok: true, conversations: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/dm/:conversationId/messages', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT dm.*, u.username, u.avatar_url FROM dm_messages dm JOIN users u ON u.id=dm.sender_id WHERE dm.conversation_id=$1 ORDER BY dm.created_at ASC LIMIT 100',
      [req.params.conversationId]
    );
    res.json({ ok: true, messages: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── DATING / DISCOVER ROUTES ─────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

// Ensure swipes table exists
db.query(`CREATE TABLE IF NOT EXISTS swipes (
  id SERIAL PRIMARY KEY,
  swiper_id UUID NOT NULL,
  swiped_id UUID NOT NULL,
  direction VARCHAR(4) NOT NULL CHECK (direction IN ('like','pass')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(swiper_id, swiped_id)
)`).catch(()=>{});

db.query(`CREATE TABLE IF NOT EXISTS dating_matches (
  id SERIAL PRIMARY KEY,
  user_a UUID NOT NULL,
  user_b UUID NOT NULL,
  matched_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_a, user_b)
)`).catch(()=>{});

// GET /api/dating/profiles — get discover profiles (not yet swiped)
app.get('/api/dating/profiles', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT id, username, display_name, avatar_url, bio,
             (SELECT COUNT(*) FROM follows WHERE followee_id=u.id) AS followers
      FROM users u
      WHERE u.id != $1
      AND u.id NOT IN (
        SELECT swiped_id FROM swipes WHERE swiper_id=$1
      )
      ORDER BY RANDOM()
      LIMIT 10
    `, [req.user.id]);
    res.json({ ok: true, profiles: rows });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// POST /api/dating/swipe — like or pass
app.post('/api/dating/swipe', authMiddleware, async (req, res) => {
  try {
    const { targetId, direction } = req.body;
    if (!['like','pass'].includes(direction)) return res.status(400).json({ ok: false, error: 'direction must be like or pass' });
    await db.query(
      'INSERT INTO swipes (swiper_id, swiped_id, direction) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
      [req.user.id, targetId, direction]
    );
    let matched = false;
    if (direction === 'like') {
      // Check if target already liked this user
      const { rows } = await db.query(
        'SELECT id FROM swipes WHERE swiper_id=$1 AND swiped_id=$2 AND direction=$3',
        [targetId, req.user.id, 'like']
      );
      if (rows.length > 0) {
        const a = req.user.id < targetId ? req.user.id : targetId;
        const b = req.user.id < targetId ? targetId : req.user.id;
        await db.query('INSERT INTO dating_matches (user_a, user_b) VALUES ($1,$2) ON CONFLICT DO NOTHING', [a, b]);
        // Create DM conversation for the match
        await db.query(
          'INSERT INTO dm_conversations (participant_a, participant_b) VALUES ($1,$2) ON CONFLICT DO NOTHING',
          [a, b]
        );
        matched = true;
      }
    }
    res.json({ ok: true, matched });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/dating/matches — get all mutual matches
app.get('/api/dating/matches', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT m.id, m.matched_at,
        u.id AS user_id, u.username, u.display_name, u.avatar_url, u.bio
      FROM dating_matches m
      JOIN users u ON u.id = CASE WHEN m.user_a=$1 THEN m.user_b ELSE m.user_a END
      WHERE m.user_a=$1 OR m.user_b=$1
      ORDER BY m.matched_at DESC
    `, [req.user.id]);
    res.json({ ok: true, matches: rows });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── STORIES ROUTES ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

db.query(`CREATE TABLE IF NOT EXISTS stories (
  id SERIAL PRIMARY KEY,
  user_id UUID NOT NULL,
  media_url TEXT NOT NULL,
  media_type VARCHAR(10) DEFAULT 'image',
  caption VARCHAR(200),
  view_count INT DEFAULT 0,
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours'),
  created_at TIMESTAMPTZ DEFAULT NOW()
)`).catch(()=>{});

db.query(`CREATE TABLE IF NOT EXISTS story_views (
  story_id INT NOT NULL,
  viewer_id UUID NOT NULL,
  viewed_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (story_id, viewer_id)
)`).catch(()=>{});

// GET /api/stories — get active stories (last 24h) from followed users + own
app.get('/api/stories', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT s.*, u.username, u.display_name, u.avatar_url,
        EXISTS(SELECT 1 FROM story_views sv WHERE sv.story_id=s.id AND sv.viewer_id=$1) AS viewed
      FROM stories s
      JOIN users u ON u.id = s.user_id
      WHERE s.expires_at > NOW()
      AND (s.user_id=$1 OR s.user_id IN (SELECT followee_id FROM follows WHERE follower_id=$1))
      ORDER BY u.id, s.created_at ASC
    `, [req.user.id]);
    // Group by user
    const grouped = {};
    rows.forEach(s => {
      if (!grouped[s.user_id]) grouped[s.user_id] = { user_id:s.user_id, username:s.username, display_name:s.display_name, avatar_url:s.avatar_url, stories:[], all_viewed:true };
      grouped[s.user_id].stories.push(s);
      if (!s.viewed) grouped[s.user_id].all_viewed = false;
    });
    res.json({ ok: true, users: Object.values(grouped) });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// POST /api/stories — create a story (base64 or URL)
app.post('/api/stories', authMiddleware, async (req, res) => {
  try {
    const { media_url, media_type = 'image', caption = '' } = req.body;
    if (!media_url) return res.status(400).json({ ok: false, error: 'media_url required' });
    const { rows } = await db.query(
      'INSERT INTO stories (user_id, media_url, media_type, caption) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, media_url, media_type, caption.slice(0,200)]
    );
    res.json({ ok: true, story: rows[0] });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// POST /api/stories/:id/view
app.post('/api/stories/:id/view', authMiddleware, async (req, res) => {
  try {
    await db.query('INSERT INTO story_views (story_id, viewer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id, req.user.id]);
    await db.query('UPDATE stories SET view_count=view_count+1 WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: true }); }
});

// DELETE /api/stories/:id
app.delete('/api/stories/:id', authMiddleware, async (req, res) => {
  try {
    await db.query('DELETE FROM stories WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── PAYOUT / WITHDRAWAL ROUTES ──────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

db.query(`CREATE TABLE IF NOT EXISTS payout_requests (
  id SERIAL PRIMARY KEY,
  user_id UUID NOT NULL,
  coins_requested INT NOT NULL,
  usd_amount DECIMAL(10,2) NOT NULL,
  paypal_email VARCHAR(255) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
)`).catch(()=>{});

// POST /api/wallet/payout — request a payout (1000 coins = $1)
app.post('/api/wallet/payout', authMiddleware, async (req, res) => {
  try {
    const { coins, paypal_email } = req.body;
    if (!coins || coins < 1000) return res.status(400).json({ ok: false, error: 'Minimum payout is 1,000 coins ($1.00)' });
    if (!paypal_email || !paypal_email.includes('@')) return res.status(400).json({ ok: false, error: 'Valid PayPal email required' });
    // Check balance
    const { rows } = await db.query('SELECT balance_credits FROM users WHERE id=$1', [req.user.id]);
    const balance = rows[0]?.balance_credits || 0;
    if (balance < coins) return res.status(400).json({ ok: false, error: `Insufficient balance. You have ${balance} coins.` });
    const usd = (coins / 1000).toFixed(2);
    // Deduct coins
    await db.query('UPDATE users SET balance_credits=balance_credits-$1 WHERE id=$2', [coins, req.user.id]);
    // Create payout request
    const pr = await db.query(
      'INSERT INTO payout_requests (user_id, coins_requested, usd_amount, paypal_email) VALUES ($1,$2,$3,$4) RETURNING id',
      [req.user.id, coins, usd, paypal_email]
    );
    res.json({ ok: true, message: `Payout of $${usd} requested to ${paypal_email}. Processed within 3-5 business days.`, request_id: pr.rows[0].id });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/wallet/payouts — payout history
app.get('/api/wallet/payouts', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT id, coins_requested, usd_amount, paypal_email, status, created_at FROM payout_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20',
      [req.user.id]
    );
    res.json({ ok: true, payouts: rows });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── INVITES / CONTACTS ───────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/videos/:id/share — log a share event
app.post('/api/videos/:id/share', optionalAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query(`UPDATE videos SET shares = COALESCE(shares, 0) + 1 WHERE id=$1`, [id]);
    if (req.user) {
      await db.query(
        `INSERT INTO user_activity (user_id, action, target_id, created_at) VALUES ($1,'share',$2,NOW()) ON CONFLICT DO NOTHING`,
        [req.user.id, id]
      ).catch(() => {}); // table may not exist yet — safe ignore
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: true }); } // non-critical
});

// POST /api/invites/sms — send Twilio SMS invite to a phone number
app.post('/api/invites/sms', authMiddleware, async (req, res) => {
  try {
    const { phone, name } = req.body;
    if (!phone) return res.status(400).json({ ok: false, error: 'Phone number required' });
    // Clean phone number
    const cleanPhone = phone.replace(/[^+\d]/g, '');
    if (cleanPhone.length < 7) return res.status(400).json({ ok: false, error: 'Invalid phone number' });
    // Check Twilio config
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromPhone = process.env.TWILIO_PHONE;
    if (!accountSid || !authToken || !fromPhone) {
      return res.status(503).json({ ok: false, error: 'SMS not configured' });
    }
    const sender = req.user;
    const senderName = sender?.display_name || sender?.username || 'Someone';
    const inviteUrl = process.env.APP_URL || 'https://nvme.live';
    const message = `${senderName} invited you to NVME.live! Create, stream, battle & earn. Join free: ${inviteUrl}`;
    // Send via Twilio REST API
    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
    const twilioUrl = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
    const body = new URLSearchParams({ To: cleanPhone, From: fromPhone, Body: message });
    const response = await fetch(twilioUrl, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const result = await response.json();
    if (result.sid) {
      res.json({ ok: true, message: `Invite sent to ${name || cleanPhone}` });
    } else {
      res.status(400).json({ ok: false, error: result.message || 'SMS failed' });
    }
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── SOCKET.IO REAL-TIME ENGINE ─────────────────────────────────────────────
const onlineUsers = new Map(); // userId -> socketId
const callPeer = new Map();    // userId -> userId (active/ringing call partner)

io.on('connection', (socket) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  let userId = null;
  if (token) {
    try { const d = jwt.verify(token, JWT_SECRET); userId = d.id || d.userId; } catch {}
  }

  if (userId) {
    onlineUsers.set(userId, socket.id);
    io.emit('user_online', { userId });
  }

  // ── LIVE STREAMING ──────────────────────────────────────────────────────
  socket.on('join_stream', async ({ streamId }) => {
    socket.join(`stream:${streamId}`);
    try {
      const { rows } = await db.query(
        'UPDATE livestreams SET viewer_count=viewer_count+1, peak_viewer_count=GREATEST(peak_viewer_count, viewer_count+1) WHERE id=$1 AND status=$2 RETURNING viewer_count',
        [streamId, 'live']
      );
      if (rows[0]) io.to(`stream:${streamId}`).emit('viewer_count', { streamId, count: rows[0].viewer_count });
    } catch {}
  });

  socket.on('leave_stream', async ({ streamId }) => {
    socket.leave(`stream:${streamId}`);
    try {
      const { rows } = await db.query(
        'UPDATE livestreams SET viewer_count=GREATEST(0,viewer_count-1) WHERE id=$1 RETURNING viewer_count',
        [streamId]
      );
      if (rows[0]) io.to(`stream:${streamId}`).emit('viewer_count', { streamId, count: rows[0].viewer_count });
    } catch {}
  });

  socket.on('live_chat', async ({ streamId, message }) => {
    if (!userId || !message?.trim()) return;
    try {
      const { rows: urows } = await db.query('SELECT username, avatar_url FROM users WHERE id=$1', [userId]);
      const user = urows[0];
      await db.query('INSERT INTO livestream_chat (stream_id,user_id,message) VALUES ($1,$2,$3)', [streamId, userId, message.trim()]);
      io.to(`stream:${streamId}`).emit('live_chat', {
        streamId, userId, username: user?.username, avatar: user?.avatar_url,
        message: message.trim(), ts: new Date().toISOString()
      });
    } catch {}
  });

  socket.on('send_gift', async ({ streamId, giftId }) => {
    if (!userId) return;
    try {
      const { rows: grows } = await db.query('SELECT * FROM gift_catalog WHERE id=$1 AND is_active=true', [giftId]);
      const gift = grows[0];
      if (!gift) return;
      const { rows: urows } = await db.query('SELECT balance_credits, username FROM users WHERE id=$1', [userId]);
      const sender = urows[0];
      if (!sender || sender.balance_credits < gift.credit_cost) {
        socket.emit('gift_error', { error: 'insufficient credits' }); return;
      }
      await db.query('UPDATE users SET balance_credits=balance_credits-$1 WHERE id=$2', [gift.credit_cost, userId]);
      await db.query('UPDATE livestreams SET total_gifts_received=total_gifts_received+$1 WHERE id=$2', [gift.usd_value, streamId]).catch(()=>{});
      io.to(`stream:${streamId}`).emit('gift_received', {
        streamId, senderId: userId, senderName: sender.username,
        gift: { name: gift.name, emoji: gift.emoji, value: gift.usd_value, level: gift.tier_level }, ts: new Date().toISOString()
      });
    } catch {}
  });

  // ── ORBAT GIFT: send by name ────────────────────────────────────────────
  socket.on('send_gift_by_name', async ({ streamId, giftName }) => {
    if (!userId) return;
    try {
      const { rows: grows } = await db.query('SELECT * FROM gift_catalog WHERE name=$1 AND is_active=true', [giftName]);
      const gift = grows[0];
      if (!gift) return;
      const { rows: urows } = await db.query('SELECT balance_credits, username FROM users WHERE id=$1', [userId]);
      const sender = urows[0];
      if (!sender || sender.balance_credits < gift.credit_cost) {
        socket.emit('gift_error', { error: 'insufficient credits' }); return;
      }
      await db.query('UPDATE users SET balance_credits=balance_credits-$1 WHERE id=$2', [gift.credit_cost, userId]);
      await db.query('UPDATE livestreams SET total_gifts_received=total_gifts_received+$1 WHERE id=$2', [gift.usd_value, streamId]).catch(()=>{});
      const ORBAT_NAMES = ['Recruit','Soldier','Captain','Director','Commander','CxO Elite','DIGITAL KING'];
      const level = gift.tier_level || (ORBAT_NAMES.indexOf(giftName) + 1);
      io.to(`stream:${streamId}`).emit('gift_received', {
        streamId,
        senderId: userId,
        senderName: sender.username,
        gift: { name: gift.name, emoji: gift.emoji, value: gift.usd_value, level },
        ts: new Date().toISOString()
      });
    } catch(e) { socket.emit('gift_error', { error: e.message }); }
  });

  // ── DIRECT MESSAGES (WhatsApp style) ────────────────────────────────────
  socket.on('dm_send', async ({ toUserId, content, mediaUrl }) => {
    if (!userId || !content?.trim()) return;
    try {
      const a = userId < toUserId ? userId : toUserId;
      const b = userId < toUserId ? toUserId : userId;
      let { rows: convRows } = await db.query(
        'INSERT INTO dm_conversations (participant_a,participant_b) VALUES ($1,$2) ON CONFLICT (participant_a,participant_b) DO UPDATE SET last_message_at=NOW() RETURNING id',
        [a, b]
      );
      const convId = convRows[0].id;
      const { rows: msgRows } = await db.query(
        'INSERT INTO dm_messages (conversation_id,sender_id,content,media_url) VALUES ($1,$2,$3,$4) RETURNING *',
        [convId, userId, content.trim(), mediaUrl || null]
      );
      const msg = msgRows[0];
      const { rows: senderRows } = await db.query('SELECT username, avatar_url FROM users WHERE id=$1', [userId]);
      const payload = { ...msg, sender: senderRows[0] };
      socket.emit('dm_message', payload);
      const toSocket = onlineUsers.get(toUserId);
      if (toSocket) io.to(toSocket).emit('dm_message', payload);
    } catch {}
  });

  socket.on('dm_typing', ({ toUserId, isTyping }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('dm_typing', { fromUserId: userId, isTyping });
  });

  socket.on('dm_read', async ({ conversationId }) => {
    if (!userId) return;
    try {
      await db.query('UPDATE dm_messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2', [conversationId, userId]);
      socket.emit('dm_read_ack', { conversationId });
    } catch {}
  });

  // ── WebRTC Video/Voice Call Signaling ────────────────────────────────────
  socket.on('vc_offer', ({ toUserId, offer, withVideo }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('vc_offer', { fromUserId: userId, offer, withVideo });
  });

  socket.on('vc_answer', ({ toUserId, answer }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('vc_answer', { fromUserId: userId, answer });
  });

  socket.on('vc_ice_candidate', ({ toUserId, candidate }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('vc_ice_candidate', { fromUserId: userId, candidate });
  });

  socket.on('vc_reject', ({ toUserId }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('vc_reject', { fromUserId: userId });
  });

  socket.on('vc_hangup', ({ toUserId }) => {
    if (!userId) return;
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) io.to(toSocket).emit('vc_hangup', { fromUserId: userId });
  });

  // ── DISCONNECT ──────────────────────────────────────────────────────────
  
  // ── DM Handlers ──────────────────────────────────────────────
  socket.on('join_dm', ({ withUserId }) => {
    if (!userId) return;
    const roomId = [userId, withUserId].sort().join(':');
    socket.join('dm:' + roomId);
  });
  socket.on('send_dm', async ({ toUserId, message }) => {
    if (!userId || !message) return;
    const roomId = [userId, toUserId].sort().join(':');
    const msg = { from: userId, to: toUserId, message, ts: new Date().toISOString() };
    try {
      await db.query(
        'INSERT INTO messages (id, sender_id, recipient_id, content, created_at) VALUES (gen_random_uuid(), $1, $2, $3, NOW()) ON CONFLICT DO NOTHING',
        [userId, toUserId, message]
      ).catch(() => {});
    } catch(e) {}
    io.to('dm:' + roomId).emit('receive_dm', msg);
  });
  socket.on('typing_dm', ({ toUserId }) => {
    if (!userId) return;
    const roomId = [userId, toUserId].sort().join(':');
    socket.to('dm:' + roomId).emit('typing_dm', { fromUserId: userId });
  });

  socket.on('disconnect', () => {
    if (userId) {
      const peerId = callPeer.get(userId);
      if (peerId) {
        const peerSock = onlineUsers.get(peerId);
        if (peerSock) io.to(peerSock).emit('vc_hangup', { fromUserId: userId, reason: 'peer_disconnected' });
        callPeer.delete(peerId); callPeer.delete(userId);
      }
      onlineUsers.delete(userId);
      io.emit('user_offline', { userId });
    }
  });
});

// ── Credit Packages ─────────────────────────────────────────────────────────
const CREDIT_PACKAGES = [
  { id: 'credits_100',   credits: 100,   usd: 0.99,  label: 'Starter Pack' },
  { id: 'credits_500',   credits: 500,   usd: 3.99,  label: 'Captain Pack' },
  { id: 'credits_1200',  credits: 1200,  usd: 7.99,  label: 'Commander Pack' },
  { id: 'credits_3000',  credits: 3000,  usd: 17.99, label: 'Elite Pack' },
  { id: 'credits_7000',  credits: 7000,  usd: 34.99, label: 'CxO Pack' },
  { id: 'credits_20000', credits: 20000, usd: 89.99, label: 'DIGITAL KING Pack' },
];

app.get('/api/credits/packages', (req, res) => res.json({ ok: true, packages: CREDIT_PACKAGES }));

app.get('/api/credits/balance', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT balance_credits FROM users WHERE id=$1', [req.user.id]);
    res.json({ ok: true, balance: rows[0]?.balance_credits || 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PayPal order create for credits
app.post('/api/credits/create-order', authMiddleware, async (req, res) => {
  const { packageId } = req.body;
  const pkg = CREDIT_PACKAGES.find(p => p.id === packageId);
  if (!pkg) return res.status(400).json({ error: 'invalid package' });
  try {
    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET || process.env.PAYPAL_SECRET}`).toString('base64');
    const tokenRes = await fetch('https://api-m.paypal.com/v1/oauth2/token', {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials'
    });
    const { access_token } = await tokenRes.json();
    const orderRes = await fetch('https://api-m.paypal.com/v2/checkout/orders', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{ amount: { currency_code: 'USD', value: pkg.usd.toFixed(2) }, description: `nvme.live — ${pkg.label} (${pkg.credits} credits)` }],
        application_context: { brand_name: 'nvme.live', user_action: 'PAY_NOW' }
      })
    });
    const order = await orderRes.json();
    res.json({ ok: true, orderId: order.id, package: pkg });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PayPal capture + credit top-up
app.post('/api/credits/capture-order', authMiddleware, async (req, res) => {
  const { orderId, packageId } = req.body;
  const pkg = CREDIT_PACKAGES.find(p => p.id === packageId);
  if (!pkg) return res.status(400).json({ error: 'invalid package' });
  try {
    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET || process.env.PAYPAL_SECRET}`).toString('base64');
    const tokenRes = await fetch('https://api-m.paypal.com/v1/oauth2/token', {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials'
    });
    const { access_token } = await tokenRes.json();
    const captureRes = await fetch(`https://api-m.paypal.com/v2/checkout/orders/${orderId}/capture`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' }
    });
    const capture = await captureRes.json();
    if (capture.status === 'COMPLETED') {
      await db.query('UPDATE users SET balance_credits=balance_credits+$1 WHERE id=$2', [pkg.credits, req.user.id]);
      await db.query(
        'INSERT INTO transactions (user_id,type,amount_usd,credits_delta,description) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
        [req.user.id, 'credit_purchase', pkg.usd, pkg.credits, pkg.label]
      ).catch(() => {});
      const { rows: bal } = await db.query('SELECT balance_credits FROM users WHERE id=$1', [req.user.id]);
      res.json({ ok: true, credits_added: pkg.credits, new_balance: bal[0]?.balance_credits || null });
    } else {
      res.status(402).json({ error: 'payment not completed', status: capture.status });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── User profile ──────────────────────────────────────────────────────────────
app.get('/api/profile/:username', async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT id,username,display_name,avatar_url,bio,is_creator,is_verified,follower_count,following_count,created_at FROM users WHERE username=$1',
      [req.params.username]
    );
    if (!rows[0]) return res.status(404).json({ error: 'user not found' });
    res.json({ ok: true, profile: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profile/:username/gifts-sent', async (req, res) => {
  try {
    const { rows: user } = await db.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
    if (!user[0]) return res.status(404).json({ error: 'user not found' });
    const { rows } = await db.query(
      `SELECT gc.name, gc.emoji, gc.tier_level, COUNT(*)::int as times_sent, SUM(gc.usd_value) as total_usd
       FROM livestream_chat lc
       JOIN gift_catalog gc ON gc.name = lc.message
       WHERE lc.user_id=$1
       GROUP BY gc.name, gc.emoji, gc.tier_level
       ORDER BY gc.tier_level DESC`,
      [user[0].id]
    );
    res.json({ ok: true, gifts: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/streams/:id/gift-leaderboard', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT u.username, u.avatar_url, SUM(gc.usd_value) as total_gifted, COUNT(*)::int as gift_count
       FROM livestream_chat lc
       JOIN users u ON u.id=lc.user_id
       JOIN gift_catalog gc ON gc.name=lc.message
       WHERE lc.stream_id=$1
       GROUP BY u.username, u.avatar_url
       ORDER BY total_gifted DESC LIMIT 10`,
      [req.params.id]
    );
    res.json({ ok: true, leaderboard: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Creator stream dashboard ──────────────────────────────────────────────────
app.get('/api/creator/streams', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT * FROM livestreams WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20',
      [req.user.id]
    );
    res.json({ ok: true, streams: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Start ─────────────────────────────────────────────────────
initDB().then(() => {
  
// ── Crown & Anchor Game ─────────────────────────────────────────
app.post('/api/games/roll', authMiddleware, async (req, res) => {
  try {
    const { bet = 50, symbol } = req.body;
    const betAmount = Math.min(Math.max(parseInt(bet) || 50, 10), 10000);
    const symbols = ['👑','⚓','❤️','💎','♣️','⚡'];
    if (!symbol || !symbols.includes(symbol)) return res.status(400).json({ error: 'Invalid symbol' });
    // Check balance
    const { rows } = await db.query('SELECT balance_credits FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const balance = parseFloat(rows[0].balance_credits) || 0;
    if (balance < betAmount) return res.status(400).json({ error: 'Insufficient coins', balance });
    // Roll 3 dice
    const dice = [symbols[Math.floor(Math.random()*6)], symbols[Math.floor(Math.random()*6)], symbols[Math.floor(Math.random()*6)]];
    const matches = dice.filter(d => d === symbol).length;
    // Payout table: 16.9% house edge, 6:1 jackpot on triple
    // 0 match: lose bet | 1 match: win 0.7x | 2 match: win 2x | 3 match: win 6x (jackpot)
    const payoutMultiplier = matches === 0 ? -1 : matches === 1 ? 0.7 : matches === 2 ? 2 : 6;
    const netChange = Math.round(betAmount * payoutMultiplier);
    const winAmount = netChange > 0 ? netChange : 0;
    // Update balance
    await db.query('UPDATE users SET balance_credits = balance_credits + $1 WHERE id=$2', [netChange, req.user.id]);
    // 5% of each bet seeds the progressive jackpot
    const jackpotSeed = Math.floor(betAmount * 0.05);
    await db.query('UPDATE jackpot_pool SET pool = pool + $1, total_entries = total_entries + 1 WHERE id=1', [jackpotSeed]);
    const newBalance = balance + netChange;
    res.json({ ok: true, dice, matches, won: matches > 0, winAmount, netChange, newBalance: Math.max(0, newBalance) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── File Upload — Supabase Storage (persistent) with disk fallback ──
const multer = require('multer');
const path = require('path');
const uploadDir = __dirname + '/public/uploads';
require('fs').mkdirSync(uploadDir, { recursive: true });

// Use memory storage so we can pipe to Supabase if available
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });
app.use('/uploads', require('express').static(uploadDir));

// Supabase Storage client (wired when env vars are set)
let supabaseStorage = null;
try {
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
    const { createClient } = require('@supabase/supabase-js');
    supabaseStorage = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
    console.log('[Upload] Supabase Storage connected — videos survive deploys');
  } else {
    console.log('[Upload] No Supabase keys — using ephemeral disk (add SUPABASE_URL + SUPABASE_SERVICE_KEY to Railway)');
  }
} catch(e) { console.log('[Upload] Supabase init error:', e.message); }

app.post('/api/upload', authMiddleware, upload.single('video'), async (req, res) => {
  try {
    const title = req.body.title || (req.file ? req.file.originalname : 'Untitled');
    const caption = req.body.caption || '';
    let url = req.body.video_url || null;

    if (!url && req.file) {
      if (supabaseStorage) {
        // Upload to Supabase Storage — permanent, survives all Railway reboots
        const bucket = 'nvme-videos';
        const filename = Date.now() + '-' + req.file.originalname.replace(/[^a-zA-Z0-9.]/g,'_');
        const { data, error } = await supabaseStorage.storage
          .from(bucket)
          .upload(filename, req.file.buffer, {
            contentType: req.file.mimetype,
            upsert: false
          });
        if (error) throw new Error('Supabase upload failed: ' + error.message);
        const { data: publicData } = supabaseStorage.storage.from(bucket).getPublicUrl(filename);
        url = publicData.publicUrl;
        console.log('[Upload] Stored in Supabase:', url);
      } else {
        // Fallback: save to disk (ephemeral — wiped on Railway redeploy)
        const filename = Date.now() + '-' + req.file.originalname.replace(/[^a-zA-Z0-9.]/g,'_');
        const filepath = uploadDir + '/' + filename;
        require('fs').writeFileSync(filepath, req.file.buffer);
        url = '/uploads/' + filename;
        console.log('[Upload] Stored on disk (ephemeral):', url);
      }
    }

    if (!url) return res.status(400).json({ error: 'No file or video_url provided' });

    const { rows } = await db.query(
      'INSERT INTO videos (user_id, title, description, url, thumbnail) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title, caption, url, '']
    );
    res.json({ ok: true, video: rows[0], url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── Founder Bonus (one-time 10K coins for founder) ────────────────
app.post('/api/wallet/founder-bonus', authMiddleware, async (req,res) => {
  try {
    const { rows } = await db.query('SELECT email, balance_credits FROM users WHERE id=$1',[req.user.id]);
    if(!rows.length) return res.status(404).json({error:'not found'});
    const founderEmails = ['dollardoublemarketing@gmail.com','digitalking@empire.com'];
    if(!founderEmails.includes(rows[0].email)) return res.status(403).json({error:'Founders only'});
    if(rows[0].balance_credits >= 1000) return res.json({ok:true,message:'Already has coins',balance:rows[0].balance_credits});
    await db.query('UPDATE users SET balance_credits=10000 WHERE id=$1',[req.user.id]);
    res.json({ok:true,message:'10,000 founder coins added!',balance:10000});
  } catch(e){res.status(500).json({error:e.message});}
});


// ============================================================
// NVME NATIVE CRYPTO WALLET ROUTES
// Ethereum HD wallet via Alchemy API
// ============================================================
const cryptoWallet = require('./modules/crypto-wallet');

// Auto-create crypto_wallets table
db.query(`
  CREATE TABLE IF NOT EXISTS crypto_wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    eth_address VARCHAR(42) NOT NULL,
    wallet_index INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
`).catch(e => console.log('crypto_wallets table ready'));

// GET /api/wallet/crypto/address - get or create user ETH deposit address
app.get('/api/wallet/crypto/address', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    // Check if user already has a wallet
    let result = await db.query('SELECT eth_address, wallet_index FROM crypto_wallets WHERE user_id = $1', [userId]);
    if (result.rows.length > 0) {
      const bal = await cryptoWallet.getEthBalance(result.rows[0].eth_address);
      return res.json({ ok: true, address: result.rows[0].eth_address, balance: bal });
    }
    // Generate new address — use count of existing wallets as index
    const countRes = await db.query('SELECT COUNT(*) FROM crypto_wallets');
    const walletIndex = parseInt(countRes.rows[0].count) || 0;
    const ethAddress = cryptoWallet.getUserWalletAddress(walletIndex);
    if (!ethAddress) throw new Error('Wallet generation failed');
    await db.query(
      'INSERT INTO crypto_wallets (user_id, eth_address, wallet_index) VALUES ($1, $2, $3)',
      [userId, ethAddress, walletIndex]
    );
    const bal = await cryptoWallet.getEthBalance(ethAddress);
    res.json({ ok: true, address: ethAddress, balance: bal, new: true });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/wallet/crypto/balance - get ETH balance + USD value
app.get('/api/wallet/crypto/balance', authMiddleware, async (req, res) => {
  try {
    const result = await db.query('SELECT eth_address FROM crypto_wallets WHERE user_id = $1', [req.user.id]);
    if (!result.rows.length) return res.json({ ok: true, eth: '0.000000', usd: 0, address: null });
    const address = result.rows[0].eth_address;
    const [bal, ethPrice] = await Promise.all([
      cryptoWallet.getEthBalance(address),
      cryptoWallet.getEthPrice()
    ]);
    const usd = (parseFloat(bal.eth) * ethPrice).toFixed(2);
    res.json({ ok: true, eth: bal.eth, usd, address, ethPrice });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/wallet/crypto/transactions - recent ETH transactions
app.get('/api/wallet/crypto/transactions', authMiddleware, async (req, res) => {
  try {
    const result = await db.query('SELECT eth_address FROM crypto_wallets WHERE user_id = $1', [req.user.id]);
    if (!result.rows.length) return res.json({ ok: true, txs: [] });
    const txs = await cryptoWallet.getRecentTxs(result.rows[0].eth_address, 10);
    res.json({ ok: true, txs });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/wallet/crypto/eth-price - current ETH price in USD
app.get('/api/wallet/crypto/eth-price', async (req, res) => {
  try {
    const price = await cryptoWallet.getEthPrice();
    res.json({ ok: true, price, symbol: 'ETH', currency: 'USD' });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── TikTok Parity Features ───────────────────────────────────
try {
  require('./nvme-tiktok-features')(app, db, authMiddleware, optionalAuth);
  require('./nvme-ai-studio')(app, db, authMiddleware, optionalAuth);
  console.log('[nvme.live] ✅ TikTok features module loaded');
} catch(e) {
  console.error('[nvme.live] TikTok features module error:', e.message);
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[nvme.live] ONLINE :${PORT} | Empire: Dollar Double Empire`);
  });
}).catch(e => {
  console.error('[nvme.live] DB init failed:', e.message);
});





// ── ROUTE ALIASES (app.html compatibility) ─────────────────────────────────
// /api/auth/signup — full handler (deduped)
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password || !username) return res.status(400).json({ error: 'email, password and username required' });
  try {
    const exists = await db.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email or username already taken' });
    const bcrypt = require('bcryptjs');
    const hash = await bcrypt.hash(password, 10);
    const { v4: uuidv4 } = require('uuid');
    const r = await db.query(
      'INSERT INTO users (id,email,username,password_hash,created_at) VALUES ($1,$2,$3,$4,NOW()) RETURNING id,email,username,plan',
      [uuidv4(), email.toLowerCase().trim(), username.trim(), hash]
    );
    const user = r.rows[0];
    const token = require('jsonwebtoken').sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || 'nvme-secret', { expiresIn: '30d' });
    res.json({ ok: true, token, user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// /api/auth/logout
app.post('/api/auth/logout', (req, res) => { res.json({ ok: true }); });


// /api/live/streams → alias for /api/streams/live
app.get('/api/live/streams', async (req, res) => {
  try {
    const { rows } = await db.query("SELECT * FROM live_streams WHERE is_active=true ORDER BY viewer_count DESC LIMIT 20");
    res.json({ streams: rows, live: rows });
  } catch(e) { res.json({ streams: [], live: [] }); }
});

// /api/videos/feed → alias for /api/feed
app.get('/api/videos/feed', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT v.*,u.username,u.avatar_url FROM videos v JOIN users u ON v.user_id=u.id ORDER BY v.created_at DESC LIMIT 20');
    res.json({ videos: rows, items: rows });
  } catch(e) { res.json({ videos: [], items: [] }); }
});

// /api/messages/conversations
app.get('/api/messages/conversations', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT c.*,u.username,u.avatar_url FROM conversations c JOIN users u ON (c.user1_id=u.id OR c.user2_id=u.id) WHERE (c.user1_id=$1 OR c.user2_id=$1) AND u.id!=$1 ORDER BY c.updated_at DESC LIMIT 30',
      [req.user.id]
    );
    res.json({ conversations: rows });
  } catch(e) { res.json({ conversations: [] }); }
});

// /api/messages/:convId
app.get('/api/messages/:convId', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT m.*,u.username,u.avatar_url FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.conversation_id=$1 ORDER BY m.created_at ASC LIMIT 100',
      [req.params.convId]
    );
    res.json({ messages: rows });
  } catch(e) { res.json({ messages: [] }); }
});

// /api/messages/send
app.post('/api/messages/send', authMiddleware, async (req, res) => {
  const { conversation_id, content } = req.body;
  try {
    const { rows } = await db.query(
      'INSERT INTO messages (id,conversation_id,sender_id,content,created_at) VALUES (gen_random_uuid(),$1,$2,$3,NOW()) RETURNING *',
      [conversation_id, req.user.id, content]
    );
    res.json({ ok: true, message: rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// /api/live/start
app.post('/api/live/start', authMiddleware, async (req, res) => {
  const { title } = req.body;
  try {
    const streamKey = require('crypto').randomBytes(16).toString('hex');
    const { rows } = await db.query(
      'INSERT INTO live_streams (id,user_id,title,stream_key,is_active,created_at) VALUES (gen_random_uuid(),$1,$2,$3,true,NOW()) RETURNING *',
      [req.user.id, title || 'Live Stream', streamKey]
    );
    res.json({ ok: true, stream: rows[0], streamKey, rtmpUrl: `rtmp://nvme.live/live/${streamKey}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// /api/videos/upload (stub — returns presigned-style response)
app.post('/api/videos/upload', authMiddleware, async (req, res) => {
  const { title, description, video_url } = req.body;
  if (!video_url) return res.status(400).json({ error: 'video_url required' });
  try {
    const { rows } = await db.query(
      'INSERT INTO videos (user_id,title,description,url,thumbnail) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title||'Untitled', description||'', video_url, '']
    );
    res.json({ ok: true, video: rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// ── AI Video Studio ─────────────────────────────────────────────────────────
const { fal } = require('@fal-ai/client');
if (process.env.FAL_KEY) fal.config({ credentials: process.env.FAL_KEY });

app.get('/api/ai/models', authMiddleware, (req, res) => {
  res.json({ models: [
    { id: 'fal-ai/minimax/video-01', name: 'MiniMax Video', description: 'Fast 6-sec vertical clips', speed: 'Fast (~30s)' },
    { id: 'fal-ai/kling-video/v2/master/text-to-video', name: 'Kling v2 Master', description: 'Cinematic quality 5-10s', speed: 'Slow (~3min)' },
    { id: 'fal-ai/hunyuan-video', name: 'HunyuanVideo', description: 'High quality long form', speed: 'Slow (~5min)' }
  ]});
});

app.post('/api/ai/generate-video', authMiddleware, async (req, res) => {
  const { prompt, title, model } = req.body;
  if (!prompt) return res.status(400).json({ error: 'prompt required' });
  if (!process.env.FAL_KEY) return res.status(503).json({ error: 'AI generation not configured — add FAL_KEY to Railway env' });
  try {
    console.log(`[AI Studio] Generating for user ${req.user.id}: ${prompt}`);
    const selectedModel = model || 'fal-ai/minimax/video-01';
    const result = await fal.subscribe(selectedModel, {
      input: { prompt, duration: 6, aspect_ratio: '9:16' },
      logs: false
    });
    const videoUrl = result?.data?.video?.url || result?.data?.video_url || result?.video?.url;
    if (!videoUrl) return res.status(500).json({ error: 'No video URL returned from AI model' });

    // Download + upload to Supabase
    const fetchMod = require('node-fetch');
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
    const videoRes = await fetchMod(videoUrl);
    const videoBuffer = await videoRes.buffer();
    const fileName = `ai-${Date.now()}-${Math.random().toString(36).slice(2)}.mp4`;
    await supabase.storage.from('nvme-videos').upload(fileName, videoBuffer, { contentType: 'video/mp4', upsert: false });
    const { data: pubData } = supabase.storage.from('nvme-videos').getPublicUrl(fileName);
    const publicUrl = pubData.publicUrl;

    // Generate thumbnail via fal flux
    let thumbUrl = '';
    try {
      const thumbResult = await fal.subscribe('fal-ai/flux/schnell', {
        input: { prompt: prompt + ', vertical thumbnail, vibrant', image_size: 'portrait_4_3', num_images: 1 },
        logs: false
      });
      thumbUrl = thumbResult?.data?.images?.[0]?.url || '';
    } catch(_) {}

    const { rows } = await db.query(
      'INSERT INTO videos (user_id, title, description, url, thumbnail) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title || 'AI Generated Video', prompt, publicUrl, thumbUrl]
    );
    console.log(`[AI Studio] Posted video ${rows[0].id} to feed`);
    res.json({ ok: true, video: rows[0], url: publicUrl });
  } catch(e) {
    console.error('[AI Studio] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});
// ── SEARCH ──────────────────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.json({ users: [], videos: [] });
  try {
    const term = `%${q.toLowerCase()}%`;
    const [users, videos] = await Promise.all([
      db.query(`SELECT id, username, display_name, avatar_url, plan FROM users WHERE (is_private IS NOT TRUE) AND (LOWER(username) LIKE $1 OR LOWER(display_name) LIKE $1) LIMIT 10`, [term]),
      db.query(`SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.likes, u.username, u.avatar_url FROM videos v JOIN users u ON v.user_id=u.id WHERE LOWER(v.title) LIKE $1 OR LOWER(v.description) LIKE $1 ORDER BY v.created_at DESC LIMIT 20`, [term])
    ]);
    res.json({ users: users.rows, videos: videos.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TRANSACTION HISTORY ─────────────────────────────────────────────────────
app.get('/api/wallet/transactions', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT 'gift_sent' AS type, -g.credits AS amount, 'Gift sent' AS label, g.created_at
      FROM gifts g WHERE g.sender_id=$1
      UNION ALL
      SELECT 'gift_received' AS type, g.credits AS amount, 'Gift received' AS label, g.created_at
      FROM gifts g WHERE g.receiver_id=$1
      ORDER BY created_at DESC LIMIT 50
    `, [req.user.id]);
    res.json({ ok: true, transactions: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── NOTIFICATIONS ────────────────────────────────────────────────────────────
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    // Build notifications from follows, likes, comments, gifts
    const { rows } = await db.query(`
      SELECT 'follow' AS type, u.username AS actor, u.avatar_url, f.created_at, NULL AS extra
      FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.followee_id=$1
      UNION ALL
      SELECT 'like' AS type, u.username AS actor, u.avatar_url, vl.created_at, v.title AS extra
      FROM video_likes vl JOIN users u ON u.id=vl.user_id JOIN videos v ON v.id=vl.video_id WHERE v.user_id=$1 AND vl.user_id!=$1
      UNION ALL
      SELECT 'comment' AS type, u.username AS actor, u.avatar_url, c.created_at, c.text AS extra
      FROM comments c JOIN users u ON u.id=c.user_id JOIN videos v ON v.id=c.video_id WHERE v.user_id=$1 AND c.user_id!=$1
      UNION ALL
      SELECT 'gift' AS type, u.username AS actor, u.avatar_url, g.created_at, g.credits::text AS extra
      FROM gifts g JOIN users u ON u.id=g.sender_id WHERE g.receiver_id=$1
      ORDER BY created_at DESC LIMIT 30
    `, [req.user.id]);
    res.json({ ok: true, notifications: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications/count', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT (
        (SELECT COUNT(*) FROM follows WHERE followee_id=$1 AND created_at > NOW()-INTERVAL '24 hours') +
        (SELECT COUNT(*) FROM video_likes vl JOIN videos v ON v.id=vl.video_id WHERE v.user_id=$1 AND vl.user_id!=$1 AND vl.created_at > NOW()-INTERVAL '24 hours') +
        (SELECT COUNT(*) FROM comments c JOIN videos v ON v.id=c.video_id WHERE v.user_id=$1 AND c.user_id!=$1 AND c.created_at > NOW()-INTERVAL '24 hours') +
        (SELECT COUNT(*) FROM gifts WHERE receiver_id=$1 AND created_at > NOW()-INTERVAL '24 hours')
      ) AS count
    `, [req.user.id]);
    res.json({ ok: true, count: parseInt(rows[0].count) || 0 });
  } catch(e) { res.json({ ok: true, count: 0 }); }
});
// ── END ROUTE ALIASES ────────────────────────────────────────────────────────
