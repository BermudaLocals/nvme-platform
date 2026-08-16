// ========================================
// 🚀 NVME.live — Server
// ========================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const OpenAI = require('openai');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const paypal = require('@paypal/checkout-server-sdk');

// ========================================
// 📦 Initialize
// ========================================
const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? ['https://nvme.live', 'https://www.nvme.live']
      : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling']
});
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.NODE_ENV === 'production' ? 'https://nvme.live' : 'http://localhost:3000';

// ========================================
// 🗄️ Database (NeonDB)
// ========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: { rejectUnauthorized: false }
});
pool.connect((err) => {
  if (err) console.error('❌ DB error:', err.stack);
  else console.log('✅ NeonDB connected');
});
pool.on('error', (err) => {
  console.error('⚠️  Idle Postgres client error (pool will recover):', err.message);
});

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    email: u.email,
    avatar_url: u.avatar_url,
    bio: u.bio,
    is_creator: u.is_creator,
    is_verified: u.is_verified,
    followers: u.follower_count,
    following: u.following_count,
    balance_credits: u.balance_credits,
    paypal_email: u.paypal_email
  };
}

// ========================================
// 🤖 AI Clients
// ========================================
const nvidiaClient = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY,
  baseURL: process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1',
});
const kimiClient = new OpenAI({
  apiKey: process.env.MOONSHOT_API_KEY,
  baseURL: process.env.KIMI_BASE_URL || 'https://api.moonshot.cn/v1',
});
async function generateWithFallback(systemPrompt, userPrompt, maxTokens) {
  try {
    const completion = await nvidiaClient.chat.completions.create({
      model: 'nvidia/llama-3.1-nemotron-70b-instruct',
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }],
      temperature: 0.8,
      max_tokens: maxTokens,
    });
    return { content: completion.choices[0].message.content, provider: 'nvidia' };
  } catch (e) {
    console.log('NVIDIA failed, falling back to Kimi:', e.message);
  }
  const completion = await kimiClient.chat.completions.create({
    model: process.env.KIMI_DEFAULT_MODEL || 'kimi-k3',
    messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }],
    temperature: 0.8,
    max_tokens: maxTokens,
  });
  return { content: completion.choices[0].message.content, provider: 'kimi' };
}

// ========================================
// 💳 PayPal
// ========================================
function paypalClient() {
  const env = process.env.PAYPAL_MODE === 'live'
    ? new paypal.core.LiveEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
    : new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET);
  return new paypal.core.PayPalHttpClient(env);
}

// ========================================
// 🔒 Middleware
// ========================================
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://nvme.live', 'https://www.nvme.live']
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(session({
  store: new (require('connect-pg-simple')(session))({ pool, createTableIfMissing: true }),
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 5 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', limiter);
app.use(express.static('public', { extensions: ['html'] }));
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ========================================
// 🔐 Auth Middleware
// ========================================
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = (authHeader && authHeader.split(' ')[1]) || req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = (authHeader && authHeader.split(' ')[1]) || req.cookies?.token;
  if (!token) return next();
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length > 0) req.user = result.rows[0];
  } catch (err) { /* proceed anonymously */ }
  next();
};

function issueToken(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });
}

// ========================================
// 🔑 Auth Routes
// ========================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'username, email, and password are required' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', [email, username]);
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Username or email already in use' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, display_name)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [username, email, passwordHash, username]
    );
    const user = result.rows[0];
    res.json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Failed to register' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (user.is_banned) return res.status(403).json({ error: 'Account suspended' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// ========================================
// 🔑 Google OAuth
// ========================================
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${FRONTEND_URL}/auth/google/callback`
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      let user = result.rows[0];
      if (!user) {
        const baseUsername = (profile.displayName || email.split('@')[0]).replace(/[^a-zA-Z0-9_]/g, '').slice(0, 40) || 'user';
        let username = baseUsername;
        let n = 0;
        while ((await pool.query('SELECT 1 FROM users WHERE username = $1', [username])).rows.length > 0) {
          n += 1;
          username = `${baseUsername}${n}`;
        }
        const randomPassword = await bcrypt.hash(uuidv4(), 12);
        const insertResult = await pool.query(
          `INSERT INTO users (username, email, password_hash, display_name, avatar_url, is_verified)
           VALUES ($1, $2, $3, $4, $5, false) RETURNING *`,
          [username, email, randomPassword, profile.displayName || username, profile.photos?.[0]?.value || null]
        );
        user = insertResult.rows[0];
      }
      done(null, user);
    } catch (err) {
      done(err);
    }
  }));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
      done(null, result.rows[0]);
    } catch (err) { done(err); }
  });
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND_URL}/?auth_error=1` }),
    (req, res) => {
      const jwtToken = issueToken(req.user);
      res.redirect(`${FRONTEND_URL}/app?token=${jwtToken}`);
    }
  );
} else {
  app.get('/auth/google', (req, res) => res.status(503).json({ error: 'Google OAuth not configured' }));
}

// ========================================
// 🤖 AI Studio
// ========================================
const AI_PROMPTS = {
  script: (topic) => `Write a viral short-video script for: ${topic}. Include hook, body, and CTA.`,
  caption: (topic) => `Write 5 engaging captions for: ${topic}. Include hashtags.`,
  hashtags: (topic) => `Generate 30+ trending hashtags for: ${topic}.`,
  idea: (topic) => `Generate 10 viral content ideas for: ${topic}.`,
};
const AI_SYSTEM_PROMPT = 'You are a viral content expert for social media creators.';
function tokenBudget(user) {
  const isPro = user.is_creator || (user.plan_ends && new Date(user.plan_ends) > new Date());
  return isPro ? 2000 : 1000;
}
app.get('/api/ai/status', authenticateToken, (req, res) => {
  res.json({ ok: true, providers: ['nvidia', 'kimi'], studio: 'nvme-ai-studio' });
});
app.get('/api/ai/usage', authenticateToken, (req, res) => {
  res.json({ ok: true, providers: ['nvidia', 'kimi'], studio: 'nvme-ai-studio' });
});
app.post('/api/ai/generate', authenticateToken, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'prompt is required' });
    const { content, provider } = await generateWithFallback(AI_SYSTEM_PROMPT, prompt, tokenBudget(req.user));
    res.json({ success: true, content, provider });
  } catch (error) {
    console.error('AI generate error:', error);
    res.status(500).json({ error: 'All AI providers failed' });
  }
});
for (const type of ['captions', 'hashtags', 'script']) {
  app.post(`/api/ai/${type}`, authenticateToken, async (req, res) => {
    try {
      const { topic } = req.body;
      if (!topic) return res.status(400).json({ error: 'topic is required' });
      const key = type === 'captions' ? 'caption' : type;
      const userPrompt = (AI_PROMPTS[key] || AI_PROMPTS.idea)(topic);
      const { content, provider } = await generateWithFallback(AI_SYSTEM_PROMPT, userPrompt, tokenBudget(req.user));
      res.json({ success: true, content, provider });
    } catch (error) {
      console.error(`AI ${type} error:`, error);
      res.status(500).json({ error: 'All AI providers failed' });
    }
  });
}

// ========================================
// 📹 Video Upload
// ========================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: parseInt(process.env.MAX_VIDEO_SIZE) || 2147483648 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/mov', 'video/avi', 'video/mkv', 'video/webm'];
    allowedTypes.includes(file.mimetype) ? cb(null, true) : cb(new Error('Invalid file type.'));
  }
});
app.post('/api/upload', authenticateToken, upload.single('video'), async (req, res) => {
  try {
    const user = req.user;
    const { title, description, tags } = req.body;
    if (!req.file || !title) return res.status(400).json({ error: 'Video file and title are required' });
    const videoId = uuidv4();
    let videoUrl = '', thumbnailUrl = '';
    try {
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { resource_type: 'video', public_id: `videos/${videoId}`, folder: 'nvme-videos',
            eager: [{ width: 720, height: 480, crop: 'pad' }], eager_async: true },
          (error, result) => error ? reject(error) : resolve(result)
        );
        uploadStream.end(req.file.buffer);
      });
      videoUrl = result.secure_url;
      thumbnailUrl = result.eager?.[0]?.secure_url || result.secure_url.replace('.mp4', '.jpg');
    } catch (uploadError) {
      console.error('Cloudinary error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload video to Cloudinary' });
    }
    const result = await pool.query(
      `INSERT INTO videos (id, user_id, title, description, video_url, thumbnail_url, tags, is_published)
       VALUES ($1, $2, $3, $4, $5, $6, $7::text[], true) RETURNING *`,
      [videoId, user.id, title, description || '', videoUrl, thumbnailUrl,
       tags ? tags.split(',').map(t => t.trim()) : []]
    );
    res.json({ success: true, url: videoUrl, thumbnail: thumbnailUrl, video: result.rows[0] });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

// ========================================
// 🎬 Feed / Videos
// ========================================
app.get('/api/feed', async (req, res) => {
  try {
    const { cursor, limit = 20 } = req.query;
    const params = [];
    let where = 'WHERE v.is_published = true';
    if (cursor) {
      params.push(cursor);
      where += ` AND v.created_at < $${params.length}`;
    }
    params.push(parseInt(limit));
    const result = await pool.query(
      `SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.title, v.description,
              v.view_count AS views, v.like_count, v.comment_count, v.created_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM videos v
       JOIN users u ON v.user_id = u.id
       ${where}
       ORDER BY v.created_at DESC
       LIMIT $${params.length}`,
      params
    );
    let feed = result.rows;
    if (!feed.length) {
      await pool.query(
        `UPDATE livestreams SET status = 'ended', ended_at = NOW()
         WHERE status = 'live' AND started_at IS NOT NULL
           AND started_at < NOW() - INTERVAL '6 hours'`
      );
      const lives = await pool.query(
        `SELECT s.id, s.title, s.description, s.thumbnail_url, s.viewer_count, s.started_at,
                u.id AS host_id, u.username, u.avatar_url
         FROM livestreams s JOIN users u ON s.user_id = u.id
         WHERE s.status = 'live'
         ORDER BY s.viewer_count DESC LIMIT 20`
      );
      feed = lives.rows.map((s) => ({
        id: 'live_' + s.id,
        url: null,
        thumbnail: s.thumbnail_url,
        title: s.title,
        description: s.description,
        views: s.viewer_count,
        like_count: 0,
        comment_count: 0,
        created_at: s.started_at,
        author_id: s.host_id,
        username: s.username,
        avatar_url: s.avatar_url,
        is_live: true,
        stream_id: s.id,
        viewer_count: s.viewer_count,
      }));
    }
    const nextCursor = result.rows.length === parseInt(limit)
      ? result.rows[result.rows.length - 1].created_at
      : undefined;
    res.json({ feed, nextCursor });
  } catch (error) {
    console.error('Feed error:', error);
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.title, v.description,
              v.view_count AS views, v.like_count, v.comment_count, v.created_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.is_published = true
       ORDER BY v.created_at DESC
       LIMIT 40`
    );
    res.json({ videos: result.rows });
  } catch (error) {
    console.error('Videos list error:', error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

app.get('/api/videos/:id', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.title, v.description,
              v.view_count AS views, v.like_count, v.comment_count, v.created_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM videos v JOIN users u ON v.user_id = u.id
       WHERE v.id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Video not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

app.get('/api/users/:username/videos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.title, v.description,
              v.view_count AS views, v.like_count, v.comment_count, v.created_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM videos v JOIN users u ON v.user_id = u.id
       WHERE u.username = $1 AND v.is_published = true
       ORDER BY v.created_at DESC`,
      [req.params.username]
    );
    res.json({ videos: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

app.post('/api/videos/:id/view', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE videos SET view_count = COALESCE(view_count, 0) + 1 WHERE id = $1 RETURNING view_count',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Video not found' });
    res.json({ success: true, views: result.rows[0].view_count });
  } catch (error) {
    console.error('View count error:', error.message);
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// ========================================
// ❤️ Likes
// ========================================
app.post('/api/videos/:id/like', authenticateToken, async (req, res) => {
  const videoId = req.params.id;
  const user = req.user;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const videoResult = await client.query('SELECT id FROM videos WHERE id = $1 FOR UPDATE', [videoId]);
    if (videoResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Video not found' });
    }
    const existing = await client.query('SELECT 1 FROM likes WHERE video_id = $1 AND user_id = $2', [videoId, user.id]);
    let liked;
    if (existing.rows.length > 0) {
      await client.query('DELETE FROM likes WHERE video_id = $1 AND user_id = $2', [videoId, user.id]);
      await client.query('UPDATE videos SET like_count = GREATEST(COALESCE(like_count, 0) - 1, 0) WHERE id = $1', [videoId]);
      liked = false;
    } else {
      await client.query('INSERT INTO likes (video_id, user_id) VALUES ($1, $2)', [videoId, user.id]);
      await client.query('UPDATE videos SET like_count = COALESCE(like_count, 0) + 1 WHERE id = $1', [videoId]);
      liked = true;
    }
    const countResult = await client.query('SELECT like_count FROM videos WHERE id = $1', [videoId]);
    await client.query('COMMIT');
    const likeCount = countResult.rows[0].like_count;
    io.to(`video-${videoId}`).emit('like-update', { videoId, liked, likeCount });
    res.json({ success: true, liked, like_count: likeCount });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to update like' });
  } finally {
    client.release();
  }
});

// ========================================
// 💬 Comments
// ========================================
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.text, c.image_url, c.created_at, u.username, u.display_name, u.avatar_url
       FROM comments c JOIN users u ON c.user_id = u.id
       WHERE c.video_id = $1
       ORDER BY c.created_at DESC LIMIT 100`,
      [req.params.id]
    );
    res.json({ comments: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.post('/api/videos/:id/comments', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { text, image } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment text is required' });
    if (text.length > 500) return res.status(400).json({ error: 'Comment too long (500 char max)' });
    const videoResult = await pool.query('SELECT id FROM videos WHERE id = $1', [videoId]);
    if (videoResult.rows.length === 0) return res.status(404).json({ error: 'Video not found' });
    const result = await pool.query(
      `INSERT INTO comments (video_id, user_id, text, image_url) VALUES ($1, $2, $3, $4) RETURNING *`,
      [videoId, req.user.id, text.trim(), image || null]
    );
    await pool.query('UPDATE videos SET comment_count = COALESCE(comment_count, 0) + 1 WHERE id = $1', [videoId]);
    const comment = { ...result.rows[0], username: req.user.username, display_name: req.user.display_name, avatar_url: req.user.avatar_url };
    io.to(`video-${videoId}`).emit('new-comment', comment);
    res.json({ success: true, comment });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

// ========================================
// 👥 Users / Social
// ========================================
app.get('/api/users/discover', optionalAuth, async (req, res) => {
  try {
    const excludeId = req.user?.id || null;
    const result = await pool.query(
      `SELECT id, username, display_name, avatar_url, bio, follower_count AS followers, is_verified
       FROM users
       WHERE is_banned = false AND ($1::uuid IS NULL OR id != $1)
       ORDER BY follower_count DESC NULLS LAST, created_at DESC
       LIMIT 30`,
      [excludeId]
    );
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/users/:username/stats', async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, follower_count, following_count FROM users WHERE username = $1',
      [req.params.username]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userResult.rows[0];
    const videoStats = await pool.query(
      'SELECT COUNT(*) AS video_count, COALESCE(SUM(view_count), 0) AS total_views FROM videos WHERE user_id = $1 AND is_published = true',
      [user.id]
    );
    res.json({
      followers: user.follower_count,
      following: user.following_count,
      videos: parseInt(videoStats.rows[0].video_count),
      total_views: parseInt(videoStats.rows[0].total_views)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ── Privacy toggle ──────────────────────────────────────────
app.put('/api/profile/privacy', authenticateToken, async (req, res) => {
  try {
    const { is_private } = req.body;
    await pool.query('UPDATE users SET is_private = $1 WHERE id = $2', [!!is_private, req.user.id]);
    res.json({ ok: true, is_private: !!is_private });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Follow / unfollow / request (privacy-aware) ─────────────
app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  const targetId = req.params.userId;
  const user = req.user;
  if (targetId === user.id) return res.status(400).json({ error: "You can't follow yourself" });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const target = await client.query('SELECT id, is_private FROM users WHERE id = $1', [targetId]);
    if (target.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }
    const isPrivate = target.rows[0].is_private;

    // Already following? — unfollow
    const existing = await client.query(
      'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2',
      [user.id, targetId]
    );
    if (existing.rows.length > 0) {
      await client.query('DELETE FROM follows WHERE follower_id = $1 AND following_id = $2', [user.id, targetId]);
      await client.query('UPDATE users SET following_count = GREATEST(COALESCE(following_count, 0) - 1, 0) WHERE id = $1', [user.id]);
      await client.query('UPDATE users SET follower_count = GREATEST(COALESCE(follower_count, 0) - 1, 0) WHERE id = $1', [targetId]);
      await client.query('COMMIT');
      return res.json({ ok: true, following: false, status: 'unfollowed' });
    }

    // Pending request? — cancel it
    const pendingReq = await client.query(
      "SELECT 1 FROM follow_requests WHERE requester_id = $1 AND target_id = $2 AND status = 'pending'",
      [user.id, targetId]
    );
    if (pendingReq.rows.length > 0) {
      await client.query(
        "DELETE FROM follow_requests WHERE requester_id = $1 AND target_id = $2 AND status = 'pending'",
        [user.id, targetId]
      );
      await client.query('COMMIT');
      return res.json({ ok: true, following: false, status: 'request_cancelled' });
    }

    if (isPrivate) {
      // Private — send follow request
      await client.query(
        'INSERT INTO follow_requests (requester_id, target_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [user.id, targetId]
      );
      await client.query('COMMIT');
      return res.json({ ok: true, following: false, status: 'requested' });
    }

    // Public — follow directly
    await client.query('INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)', [user.id, targetId]);
    await client.query('UPDATE users SET following_count = COALESCE(following_count, 0) + 1 WHERE id = $1', [user.id]);
    await client.query('UPDATE users SET follower_count = COALESCE(follower_count, 0) + 1 WHERE id = $1', [targetId]);
    await client.query('COMMIT');
    res.json({ ok: true, following: true, status: 'following' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Follow error:', error);
    res.status(500).json({ error: 'Failed to update follow' });
  } finally {
    client.release();
  }
});

// ── Get pending follow requests ──────────────────────────────
app.get('/api/follow-requests', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
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

// ── Accept or decline a follow request ──────────────────────
app.post('/api/follow-requests/:id/respond', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body;
    const { rows } = await pool.query(
      "SELECT * FROM follow_requests WHERE id = $1 AND target_id = $2 AND status = 'pending'",
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Request not found' });
    const request = rows[0];
    if (action === 'accept') {
      await pool.query(
        'INSERT INTO follows (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [request.requester_id, req.user.id]
      );
      await pool.query('UPDATE users SET follower_count = COALESCE(follower_count, 0) + 1 WHERE id = $1', [req.user.id]);
      await pool.query('UPDATE users SET following_count = COALESCE(following_count, 0) + 1 WHERE id = $1', [request.requester_id]);
    }
    await pool.query('DELETE FROM follow_requests WHERE id = $1', [request.id]);
    res.json({ ok: true, action });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Public user profile (privacy-aware) ─────────────────────
app.get('/api/users/:username', optionalAuth, async (req, res) => {
  try {
    const viewerId = req.user?.id || null;
    const { rows: urows } = await pool.query(
      `SELECT id, username, display_name, bio, avatar_url, is_private, is_verified,
              follower_count, following_count, created_at
       FROM users WHERE username = $1`,
      [req.params.username]
    );
    if (!urows.length) return res.status(404).json({ error: 'user not found' });
    const user = urows[0];

    // Determine relationship
    let relationship = 'none';
    if (viewerId === user.id) {
      relationship = 'self';
    } else if (viewerId) {
      const { rows: frows } = await pool.query(
        'SELECT 1 FROM follows WHERE follower_id = $1 AND following_id = $2', [viewerId, user.id]
      );
      if (frows.length) {
        relationship = 'following';
      } else {
        const { rows: rrows } = await pool.query(
          "SELECT 1 FROM follow_requests WHERE requester_id = $1 AND target_id = $2 AND status = 'pending'",
          [viewerId, user.id]
        );
        if (rrows.length) relationship = 'requested';
      }
    }

    const canSeeContent = !user.is_private || relationship === 'following' || relationship === 'self';

    let videos = [];
    if (canSeeContent) {
      const { rows: vrows } = await pool.query(`
        SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail,
               v.title, v.description, v.view_count AS views, v.like_count, v.created_at
        FROM videos v
        WHERE v.user_id = $1 AND v.is_published = true
        ORDER BY v.created_at DESC LIMIT 50
      `, [user.id]);
      videos = vrows;
    }

    res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        bio: canSeeContent ? user.bio : null,
        avatar_url: user.avatar_url,
        is_private: user.is_private,
        is_verified: user.is_verified,
        created_at: user.created_at
      },
      stats: {
        followers: user.follower_count || 0,
        following: user.following_count || 0,
        videos: canSeeContent ? videos.length : null
      },
      relationship,
      can_see_content: canSeeContent,
      videos
    });
  } catch (e) {
    console.error('Profile error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Profile update ───────────────────────────────────────────
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { display_name, bio, avatar_url, username, profile_link } = req.body;
    const result = await pool.query(
      `UPDATE users SET
         display_name = COALESCE($1, display_name),
         bio = COALESCE($2, bio),
         avatar_url = COALESCE($3, avatar_url),
         username = COALESCE($4, username),
         updated_at = NOW()
       WHERE id = $5 RETURNING *`,
      [display_name, bio, avatar_url, username, req.user.id]
    );
    res.json({ ok: true, user: publicUser(result.rows[0]) });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ========================================
// 🔎 Search
// ========================================
app.get('/api/search', async (req, res) => {
  try {
    const q = `%${req.query.q || ''}%`;
    const [users, videos] = await Promise.all([
      pool.query(
        `SELECT id, username, display_name, avatar_url, follower_count AS followers
         FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 LIMIT 20`,
        [q]
      ),
      pool.query(
        `SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.title, v.description,
                v.view_count AS views, u.username, u.avatar_url
         FROM videos v JOIN users u ON v.user_id = u.id
         WHERE v.is_published = true AND (v.title ILIKE $1 OR v.description ILIKE $1)
         LIMIT 20`,
        [q]
      )
    ]);
    res.json({ users: users.rows, videos: videos.rows });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ========================================
// 🎬 Live Streaming
// ========================================
app.get('/api/streams/live', async (req, res) => {
  try {
    await pool.query(
      `UPDATE livestreams SET status = 'ended', ended_at = NOW()
       WHERE status = 'live' AND started_at IS NOT NULL
         AND started_at < NOW() - INTERVAL '6 hours'`
    );
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.thumbnail_url, s.viewer_count, s.started_at,
              u.id AS host_id, u.username, u.display_name, u.avatar_url, u.is_verified
       FROM livestreams s JOIN users u ON s.user_id = u.id
       WHERE s.status = 'live'
       ORDER BY s.viewer_count DESC LIMIT 50`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch live streams' });
  }
});

app.get('/api/streams/live/now', async (req, res) => {
  try {
    await pool.query(
      `UPDATE livestreams SET status = 'ended', ended_at = NOW()
       WHERE status = 'live' AND started_at IS NOT NULL
         AND started_at < NOW() - INTERVAL '6 hours'`
    );
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.thumbnail_url, s.viewer_count, s.started_at,
              u.id AS host_id, u.username, u.display_name, u.avatar_url, u.is_verified
       FROM livestreams s JOIN users u ON s.user_id = u.id
       WHERE s.status = 'live'
       ORDER BY s.viewer_count DESC LIMIT 50`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch live streams' });
  }
});

app.get('/api/streams/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.thumbnail_url, s.viewer_count, s.started_at, s.status,
              u.id AS host_id, u.username, u.display_name, u.avatar_url, u.is_verified
       FROM livestreams s JOIN users u ON s.user_id = u.id
       WHERE s.id = $1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Stream not found' });
    const srow = result.rows[0];
    res.json({
      ...srow,
      is_live: srow.status === 'live',
      playback_url: '/live?id=' + encodeURIComponent(srow.id),
    });
  } catch (error) {
    console.error('Stream by id error:', error.message);
    res.status(500).json({ error: 'Failed to fetch stream' });
  }
});

app.get('/api/creator/streams', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const result = await pool.query(
      `SELECT id, title, description, thumbnail_url, status, viewer_count, peak_viewer_count,
              total_gifts_received, started_at, ended_at, created_at
       FROM livestreams WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [req.user.id, limit]
    );
    res.json({ streams: result.rows });
  } catch (error) {
    console.error('Creator streams error:', error.message);
    res.status(500).json({ error: 'Failed to fetch streams' });
  }
});

app.post('/api/streams', authenticateToken, async (req, res) => {
  try {
    const { title, description, is_premium, price_credits } = req.body;
    const streamKey = uuidv4();
    const result = await pool.query(
      `INSERT INTO livestreams (user_id, title, description, stream_key, is_premium, price_credits, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'offline') RETURNING *`,
      [req.user.id, title || 'Live Stream', description || '', streamKey, !!is_premium, price_credits || 0]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create stream error:', error.message);
    res.status(500).json({ error: 'Failed to create stream' });
  }
});

app.post('/api/streams/:id/go-live', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE livestreams SET status = 'live', started_at = NOW()
       WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Stream not found' });
    io.emit('stream-started', { streamId: result.rows[0].id, username: req.user.username, title: result.rows[0].title });
    res.json({ success: true, stream: result.rows[0] });
  } catch (error) {
    console.error('Go-live error:', error.message);
    res.status(500).json({ error: 'Failed to go live' });
  }
});

app.post('/api/streams/:id/end-live', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE livestreams SET status = 'ended', ended_at = NOW()
       WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Stream not found' });
    io.emit('stream-ended', { streamId: req.params.id });
    io.to(`stream-${req.params.id}`).emit('stream_ended', { streamId: req.params.id });
    res.json({ success: true, stream: result.rows[0] });
  } catch (error) {
    console.error('End-live error:', error.message);
    res.status(500).json({ error: 'Failed to end stream' });
  }
});

app.post('/api/streams/:id/goal', authenticateToken, async (req, res) => {
  try {
    const { target, reward } = req.body;
    const result = await pool.query(
      `UPDATE livestreams SET goal_target = $1, goal_reward = $2, goal_current = 0
       WHERE id = $3 AND user_id = $4 RETURNING id, goal_target, goal_reward, goal_current`,
      [target, reward || null, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Stream not found' });
    res.json({ success: true, goal: result.rows[0] });
  } catch (error) {
    console.error('Set goal error:', error.message);
    res.status(500).json({ error: 'Failed to set goal' });
  }
});

app.get('/api/streams/:id/gift-leaderboard', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.avatar_url, SUM(gt.credits_spent) AS total
       FROM gift_transactions gt JOIN users u ON gt.from_user_id = u.id
       WHERE gt.stream_id = $1
       GROUP BY u.id, u.username, u.avatar_url
       ORDER BY total DESC LIMIT 20`,
      [req.params.id]
    );
    res.json({ leaderboard: result.rows });
  } catch (error) {
    console.error('Leaderboard error:', error.message);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

app.post('/api/streams/:id/battle', authenticateToken, async (req, res) => {
  try {
    const streamId = req.params.id;
    const { battle_type, team_a_name, team_b_name } = req.body || {};
    const owned = await pool.query(
      'SELECT id FROM livestreams WHERE id = $1 AND user_id = $2',
      [streamId, req.user.id]
    );
    if (!owned.rows.length) return res.status(404).json({ ok: false, error: 'Stream not found' });
    const battleResult = await pool.query(
      `INSERT INTO stream_battles (stream_id, host_id, status) VALUES ($1, $2, 'waiting') RETURNING *`,
      [streamId, req.user.id]
    );
    const battle = battleResult.rows[0];
    await pool.query(
      `INSERT INTO battle_participants (battle_id, user_id, team) VALUES ($1, $2, 'a')
       ON CONFLICT DO NOTHING`,
      [battle.id, req.user.id]
    ).catch(async () => {
      await pool.query(
        `INSERT INTO battle_participants (battle_id, user_id, team) VALUES ($1, $2, 'a')`,
        [battle.id, req.user.id]
      );
    });
    if (team_a_name || team_b_name || battle_type) {
      await pool.query(
        `UPDATE stream_battles SET team_a_name = COALESCE($1, team_a_name), team_b_name = COALESCE($2, team_b_name), battle_type = COALESCE($3, battle_type) WHERE id = $4`,
        [team_a_name || null, team_b_name || null, battle_type || null, battle.id]
      ).catch(() => {});
    }
    const participants = await pool.query(
      `SELECT bp.*, u.username, u.avatar_url FROM battle_participants bp
       JOIN users u ON bp.user_id = u.id WHERE bp.battle_id = $1`,
      [battle.id]
    );
    io.to(`stream-${streamId}`).emit('battle_created', { battle, participants: participants.rows });
    res.json({ ok: true, battle, participants: participants.rows });
  } catch (error) {
    console.error('Create stream battle error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to create battle' });
  }
});

// ========================================
// 🎁 Gifts
// ========================================
app.post('/api/gifts/send', authenticateToken, async (req, res) => {
  const { streamId, giftName, quantity = 1, message } = req.body;
  const fromUser = req.user;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const giftResult = await client.query('SELECT * FROM gifts WHERE name = $1 AND is_active = true', [giftName]);
    if (giftResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Unknown gift type' });
    }
    const gift = giftResult.rows[0];
    const totalCredits = parseFloat(gift.credit_cost) * quantity;
    const senderResult = await client.query('SELECT balance_credits FROM users WHERE id = $1 FOR UPDATE', [fromUser.id]);
    if (parseFloat(senderResult.rows[0].balance_credits) < totalCredits) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient credits' });
    }
    const streamResult = await client.query('SELECT user_id FROM livestreams WHERE id = $1', [streamId]);
    if (streamResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Stream not found' });
    }
    const toUserId = streamResult.rows[0].user_id;
    const creatorCredits = totalCredits * (parseFloat(gift.creator_pct) / 100);
    const platformCredits = totalCredits * (parseFloat(gift.platform_pct) / 100);
    await client.query('UPDATE users SET balance_credits = balance_credits - $1 WHERE id = $2', [totalCredits, fromUser.id]);
    await client.query(
      'UPDATE users SET balance_credits = balance_credits + $1, total_earned = total_earned + $1 WHERE id = $2',
      [creatorCredits, toUserId]
    );
    await client.query(
      `UPDATE livestreams SET total_gifts_received = total_gifts_received + $1 WHERE id = $2`,
      [creatorCredits, streamId]
    );
    const txResult = await client.query(
      `INSERT INTO gift_transactions (gift_id, stream_id, from_user_id, to_user_id, quantity, credits_spent, creator_credits, platform_credits, message)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [gift.id, streamId, fromUser.id, toUserId, quantity, totalCredits, creatorCredits, platformCredits, message || '']
    );
    await client.query(
      `INSERT INTO transactions (user_id, type, amount_usd, credits_amount, description)
       VALUES ($1, 'gift_received', $2, $2, $3)`,
      [toUserId, creatorCredits, `${gift.name} x${quantity} from ${fromUser.username}`]
    );
    await client.query('COMMIT');
    io.to(`stream-${streamId}`).emit('new-gift', {
      giftName: gift.name, emoji: gift.emoji, fromUser: fromUser.username,
      quantity, creatorCredits, playSound: true, soundFile: `/sounds/gift-${gift.name.toLowerCase()}.mp3`
    });
    res.json({ success: true, gift: gift.name, quantity, creatorCredits, transaction: txResult.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Gift error:', error);
    res.status(500).json({ error: 'Failed to send gift' });
  } finally {
    client.release();
  }
});

// ========================================
// ⚔️ LIVE Battles
// ========================================
app.post('/api/battles/invite', authenticateToken, async (req, res) => {
  try {
    const { to_stream_id, to_user_id } = req.body;
    if (!to_stream_id || !to_user_id) return res.status(400).json({ error: 'to_stream_id and to_user_id are required' });
    const myStream = await pool.query(
      "SELECT id FROM livestreams WHERE user_id = $1 AND status = 'live' ORDER BY started_at DESC LIMIT 1",
      [req.user.id]
    );
    if (myStream.rows.length === 0) return res.status(400).json({ ok: false, error: 'You must be live to send a battle invite' });
    const result = await pool.query(
      `INSERT INTO battle_invites (from_stream_id, from_user_id, to_stream_id, to_user_id)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [myStream.rows[0].id, req.user.id, to_stream_id, to_user_id]
    );
    io.to(`user-${to_user_id}`).emit('battle-invite', { invite: result.rows[0], fromUsername: req.user.username });
    io.to(`user-${to_user_id}`).emit('battle_invite_received', { invite: result.rows[0], fromUsername: req.user.username });
    res.json({ ok: true, invite: result.rows[0] });
  } catch (error) {
    console.error('Battle invite error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to send invite' });
  }
});

app.post('/api/battles/invite/:id/accept', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inviteResult = await client.query(
      "SELECT * FROM battle_invites WHERE id = $1 AND to_user_id = $2 AND status = 'pending' FOR UPDATE",
      [req.params.id, req.user.id]
    );
    if (inviteResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ ok: false, error: 'Invite not found or already handled' });
    }
    const invite = inviteResult.rows[0];
    const battleResult = await client.query(
      `INSERT INTO stream_battles (stream_id, host_id, status) VALUES ($1, $2, 'waiting') RETURNING *`,
      [invite.from_stream_id, invite.from_user_id]
    );
    const battle = battleResult.rows[0];
    await client.query(
      `INSERT INTO battle_participants (battle_id, user_id, team) VALUES ($1, $2, 'a'), ($1, $3, 'b')`,
      [battle.id, invite.from_user_id, invite.to_user_id]
    );
    await client.query(
      "UPDATE battle_invites SET status = 'accepted', responded_at = NOW(), battle_id = $1 WHERE id = $2",
      [battle.id, invite.id]
    );
    await client.query('COMMIT');
    io.to(`user-${invite.from_user_id}`).emit('battle-invite-accepted', { battle });
    io.to(`user-${invite.from_user_id}`).emit('battle_invite_accepted', { battle });
    res.json({ ok: true, battle });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Accept invite error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to accept invite' });
  } finally {
    client.release();
  }
});

app.post('/api/battles/invite/:id/decline', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE battle_invites SET status = 'declined', responded_at = NOW() WHERE id = $1 AND to_user_id = $2 RETURNING *",
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ ok: false, error: 'Invite not found' });
    io.to(`user-${result.rows[0].from_user_id}`).emit('battle-invite-declined', { inviteId: req.params.id });
    io.to(`user-${result.rows[0].from_user_id}`).emit('battle_invite_declined', { inviteId: req.params.id });
    res.json({ ok: true });
  } catch (error) {
    console.error('Decline invite error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to decline invite' });
  }
});

app.get('/api/battles/:id', authenticateToken, async (req, res) => {
  try {
    const battleResult = await pool.query('SELECT * FROM stream_battles WHERE id = $1', [req.params.id]);
    if (battleResult.rows.length === 0) return res.status(404).json({ error: 'Battle not found' });
    const participants = await pool.query(
      `SELECT bp.*, u.username, u.avatar_url FROM battle_participants bp
       JOIN users u ON bp.user_id = u.id WHERE bp.battle_id = $1`,
      [req.params.id]
    );
    const battle = battleResult.rows[0];
    res.json({ ok: true, battle, participants: participants.rows, ...battle });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch battle' });
  }
});

app.post('/api/battles/:id/start', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE stream_battles SET status = 'active', started_at = NOW() WHERE id = $1 AND host_id = $2 RETURNING *",
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ ok: false, error: 'Battle not found' });
    io.emit('battle-started', { battleId: req.params.id });
    io.emit('battle_started', { battleId: req.params.id });
    res.json({ ok: true, battle: result.rows[0] });
  } catch (error) {
    console.error('Battle start error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to start battle' });
  }
});

app.post('/api/battles/:id/end', authenticateToken, async (req, res) => {
  try {
    const participants = await pool.query(
      'SELECT * FROM battle_participants WHERE battle_id = $1 ORDER BY gifts_received DESC',
      [req.params.id]
    );
    const winnerId = participants.rows[0]?.user_id || null;
    const result = await pool.query(
      "UPDATE stream_battles SET status = 'ended', ended_at = NOW(), winner_id = $1 WHERE id = $2 AND host_id = $3 RETURNING *",
      [winnerId, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ ok: false, error: 'Battle not found' });
    io.emit('battle-ended', { battleId: req.params.id, winnerId });
    io.emit('battle_ended', { battleId: req.params.id, winnerId });
    res.json({ ok: true, battle: result.rows[0] });
  } catch (error) {
    console.error('Battle end error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to end battle' });
  }
});

app.post('/api/battles/:id/attack', authenticateToken, async (req, res) => {
  const { gift_type, cost, damage, stream_id } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const senderResult = await client.query('SELECT balance_credits FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    if (parseFloat(senderResult.rows[0].balance_credits) < cost) {
      await client.query('ROLLBACK');
      return res.json({ ok: false, error: 'Insufficient credits' });
    }
    const targetResult = await client.query(
      `SELECT bp.id FROM battle_participants bp
       WHERE bp.battle_id = $1 AND bp.user_id != $2 AND bp.status = 'active' LIMIT 1`,
      [req.params.id, req.user.id]
    );
    if (targetResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.json({ ok: false, error: 'No active opponent found' });
    }
    const targetParticipantId = targetResult.rows[0].id;
    const updated = await client.query(
      'UPDATE users SET balance_credits = balance_credits - $1 WHERE id = $2 RETURNING balance_credits',
      [cost, req.user.id]
    );
    await client.query(
      'UPDATE battle_participants SET gifts_received = gifts_received + $1, votes = votes + 1 WHERE id = $2',
      [cost, targetParticipantId]
    );
    await client.query(
      `INSERT INTO battle_attacks (battle_id, attacker_id, target_participant_id, gift_type, cost, damage)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.params.id, req.user.id, targetParticipantId, gift_type || null, cost, damage || 0]
    );
    await client.query('COMMIT');
    io.emit('battle-attack', { battleId: req.params.id, targetParticipantId, damage, gift_type });
    res.json({ ok: true, new_balance: parseFloat(updated.rows[0].balance_credits) });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Battle attack error:', error.message);
    res.json({ ok: false, error: 'Attack failed' });
  } finally {
    client.release();
  }
});

app.post('/api/battles/:id/background', authenticateToken, async (req, res) => {
  try {
    const { participant_id, bg_data_url } = req.body;
    await pool.query(
      'UPDATE battle_participants SET background_url = $1 WHERE id = $2 AND user_id = $3',
      [bg_data_url, participant_id, req.user.id]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Battle background error:', error.message);
    res.status(500).json({ ok: false, error: 'Failed to save background' });
  }
});

// ========================================
// 💰 Wallet
// ========================================
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT balance_credits, total_earned FROM users WHERE id = $1', [req.user.id]);
  res.json({ balance: parseFloat(result.rows[0].balance_credits), total_earned: parseFloat(result.rows[0].total_earned) });
});

app.get('/api/wallet', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT balance_credits, total_earned FROM users WHERE id = $1', [req.user.id]);
  res.json({ balance: parseFloat(result.rows[0].balance_credits), total_earned: parseFloat(result.rows[0].total_earned) });
});

app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100',
    [req.user.id]
  );
  res.json({ transactions: result.rows });
});

app.post('/api/wallet/connect', authenticateToken, async (req, res) => {
  try {
    const { address } = req.body;
    if (!address) return res.status(400).json({ error: 'address is required' });
    await pool.query('UPDATE users SET wallet_address = $1 WHERE id = $2', [address, req.user.id]);
    res.json({ ok: true, address });
  } catch (error) {
    res.status(500).json({ error: 'Failed to connect wallet' });
  }
});

app.post('/api/wallet/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const minAmount = parseFloat(process.env.MIN_PAYOUT_AMOUNT || 5);
    if (!amount || amount < minAmount) return res.status(400).json({ error: `Minimum payout is $${minAmount}` });
    if (!req.user.paypal_email) return res.status(400).json({ error: 'Set a PayPal email on your profile first' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const balanceResult = await client.query('SELECT balance_credits FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
      if (parseFloat(balanceResult.rows[0].balance_credits) < amount) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      await client.query('UPDATE users SET balance_credits = balance_credits - $1 WHERE id = $2', [amount, req.user.id]);
      const tx = await client.query(
        `INSERT INTO transactions (user_id, type, amount_usd, status, description)
         VALUES ($1, 'withdrawal', $2, 'pending', $3) RETURNING *`,
        [req.user.id, amount, `Payout to ${req.user.paypal_email}`]
      );
      await client.query('COMMIT');
      res.json({ success: true, transaction: tx.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Withdraw error:', error);
    res.status(500).json({ error: 'Failed to request payout' });
  }
});

// ========================================
// 💳 PayPal
// ========================================
app.post('/api/payments/paypal/create-order', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const amounts = { starter: '9.99', creator: '29.99', pro: '99.99' };
    const value = amounts[plan];
    if (!value) return res.status(400).json({ error: 'Unknown plan' });
    const request = new paypal.orders.OrdersCreateRequest();
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{ amount: { currency_code: 'USD', value } }]
    });
    const order = await paypalClient().execute(request);
    res.json({ orderId: order.result.id });
  } catch (error) {
    console.error('PayPal create-order error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.post('/api/payments/paypal/capture-order', authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ error: 'orderId is required' });
    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    request.requestBody({});
    const capture = await paypalClient().execute(request);
    const amountUsd = parseFloat(capture.result.purchase_units[0].payments.captures[0].amount.value);
    await pool.query(
      `UPDATE users SET balance_credits = balance_credits + $1 WHERE id = $2`,
      [amountUsd, req.user.id]
    );
    const tx = await pool.query(
      `INSERT INTO transactions (user_id, type, amount_usd, credits_amount, status, description)
       VALUES ($1, 'credit_purchase', $2, $2, 'completed', $3) RETURNING *`,
      [req.user.id, amountUsd, `PayPal order ${orderId}`]
    );
    res.json({ success: true, transaction: tx.rows[0] });
  } catch (error) {
    console.error('PayPal capture-order error:', error);
    res.status(500).json({ error: 'Failed to capture order' });
  }
});

// ========================================
// 📡 WebSocket
// ========================================
io.on('connection', (socket) => {
  const handshakeToken = (socket.handshake.auth && socket.handshake.auth.token)
    || (socket.handshake.query && socket.handshake.query.token)
    || null;
  if (handshakeToken && process.env.JWT_SECRET) {
    try {
      const payload = jwt.verify(handshakeToken, process.env.JWT_SECRET);
      if (payload && payload.id) {
        socket.data.userId = payload.id;
        socket.join('user-' + payload.id);
      }
    } catch (_) { /* anonymous viewer */ }
  }

  const onJoinUser = (p = {}) => {
    const userId = p.userId || p.user_id;
    if (userId) socket.join('user-' + userId);
  };
  socket.on('user-online', onJoinUser);
  socket.on('user_online', onJoinUser);

  const emitViewerCount = (streamId) => {
    const room = io.sockets.adapter.rooms.get('stream-' + streamId);
    const n = room ? room.size : 0;
    io.to('stream-' + streamId).emit('viewer_count', { viewer_count: n, streamId });
    io.to('stream-' + streamId).emit('viewer-count', { viewer_count: n, streamId });
  };

  const onJoinStream = (p = {}) => {
    const streamId = p.streamId || p.stream_id || p.id;
    if (!streamId) return;
    socket.join('stream-' + streamId);
    emitViewerCount(streamId);
  };
  const onLeaveStream = (p = {}) => {
    const streamId = p.streamId || p.stream_id || p.id;
    if (!streamId) return;
    socket.leave('stream-' + streamId);
    emitViewerCount(streamId);
  };
  socket.on('join-stream', onJoinStream);
  socket.on('join_stream', onJoinStream);
  socket.on('leave-stream', onLeaveStream);
  socket.on('leave_stream', onLeaveStream);

  socket.on('join-video', ({ videoId } = {}) => { if (videoId) socket.join('video-' + videoId); });
  socket.on('leave-video', ({ videoId } = {}) => { if (videoId) socket.leave('video-' + videoId); });

  const onChat = (p = {}) => {
    const streamId = p.streamId || p.stream_id;
    const message = p.message || p.text || p.content;
    const username = p.username || p.user || 'Anonymous';
    if (!streamId || !message) return;
    const payload = { username, message, text: message, time: new Date().toISOString() };
    io.to('stream-' + streamId).emit('new-message', payload);
    io.to('stream-' + streamId).emit('live_chat', payload);
    io.to('stream-' + streamId).emit('live-chat', payload);
  };
  socket.on('send-message', onChat);
  socket.on('live_chat', onChat);
  socket.on('live-chat', onChat);

  const onJoinBattle = (p = {}) => {
    const battleId = p.battleId || p.battle_id;
    if (battleId) socket.join('battle-' + battleId);
  };
  socket.on('join_battle', onJoinBattle);
  socket.on('join-battle', onJoinBattle);

  const onGiftByName = async (p = {}) => {
    const streamId = p.streamId || p.stream_id;
    const giftName = p.giftName || p.gift_name || p.name;
    if (!streamId || !giftName) {
      socket.emit('gift_error', { error: 'stream and gift name required' });
      return;
    }
    const payload = {
      giftName, emoji: p.emoji || '🎁', fromUser: p.username || 'fan',
      quantity: p.quantity || 1, streamId
    };
    io.to('stream-' + streamId).emit('gift_received', payload);
    io.to('stream-' + streamId).emit('new-gift', payload);
  };
  socket.on('send_gift_by_name', onGiftByName);
  socket.on('send-gift-by-name', onGiftByName);

  // WebRTC signaling for host/viewer (live test today)
  ['webrtc_offer', 'webrtc_answer', 'webrtc_ice', 'webrtc_viewer_join'].forEach((ev) => {
    socket.on(ev, (p = {}) => {
      const target = p.targetSocketId;
      const streamId = p.stream_id || p.streamId;
      const payload = Object.assign({}, p, { from: socket.id });
      if (target) return socket.to(target).emit(ev, payload);
      if (streamId) return socket.to('stream-' + streamId).emit(ev, payload);
    });
  });
});

// ========================================
// 🏠 Serve Frontend
// ========================================
// Public profile page
app.get('/u/:username', (req, res) => {
  res.sendFile('profile-view.html', { root: 'public' });
});

app.get('/battles', (req, res) => res.sendFile('creator.html', { root: 'public' }));
app.get('/profile', (req, res) => res.sendFile('app.html', { root: 'public' }));
app.get('/discover', (req, res) => res.sendFile('app.html', { root: 'public' }));
app.get('/inbox', (req, res) => res.sendFile('messages.html', { root: 'public' }));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/auth') || req.path.startsWith('/socket.io')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile('index.html', { root: 'public' });
});

// ========================================
// 🚀 Start Server
// ========================================
server.listen(PORT, () => {
  console.log(`🚀 NVME.live running on http://localhost:${PORT}`);
  console.log(`🔐 Auth: register/login/me/google — enabled`);
  console.log(`❤️  Likes / 💬 Comments / 👥 Follows / 🔒 Privacy / 🔎 Search: enabled`);
  console.log(`💰 Gifts, wallet, PayPal: enabled`);
  console.log(`⚔️  Battles: enabled`);
});

process.on('unhandledRejection', (err) => console.error('Unhandled Rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught Exception:', err));
