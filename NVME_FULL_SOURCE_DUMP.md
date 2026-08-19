C:\Users\Digital King\nvme-platform> Get-Content ".\server.js" -Raw
// ========================================
// ðŸš€ NVME.live â€” Server
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
// ðŸ“¦ Initialize
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
// ðŸ—„ï¸ Database (NeonDB)
// ========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: { rejectUnauthorized: false }
});
pool.connect((err) => {
  if (err) console.error('âŒ DB error:', err.stack);
  else console.log('âœ… NeonDB connected');
});
pool.on('error', (err) => {
  console.error('âš ï¸  Idle Postgres client error (pool will recover):', err.message);
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
// ðŸ¤– AI Clients
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
// ðŸ’³ PayPal
// ========================================
function paypalClient() {
  const env = process.env.PAYPAL_MODE === 'live'
    ? new paypal.core.LiveEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
    : new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET);
  return new paypal.core.PayPalHttpClient(env);
}

// ========================================
// ðŸ”’ Middleware
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
// ðŸ” Auth Middleware
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
// ðŸ”‘ Auth Routes
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
// ðŸ”‘ Google OAuth
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
// ðŸ¤– AI Studio
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
// ðŸ“¹ Video Upload
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
// ðŸŽ¬ Feed / Videos
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
// â¤ï¸ Likes
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
// ðŸ’¬ Comments
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
// ðŸ‘¥ Users / Social
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

// â”€â”€ Privacy toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/profile/privacy', authenticateToken, async (req, res) => {
  try {
    const { is_private } = req.body;
    await pool.query('UPDATE users SET is_private = $1 WHERE id = $2', [!!is_private, req.user.id]);
    res.json({ ok: true, is_private: !!is_private });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// â”€â”€ Follow / unfollow / request (privacy-aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // Already following? â€” unfollow
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

    // Pending request? â€” cancel it
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
      // Private â€” send follow request
      await client.query(
        'INSERT INTO follow_requests (requester_id, target_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [user.id, targetId]
      );
      await client.query('COMMIT');
      return res.json({ ok: true, following: false, status: 'requested' });
    }

    // Public â€” follow directly
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

// â”€â”€ Get pending follow requests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ Accept or decline a follow request â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ Public user profile (privacy-aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ Profile update â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
// ðŸ”Ž Search
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
// ðŸŽ¬ Live Streaming
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
// ðŸŽ Gifts
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
// âš”ï¸ LIVE Battles
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
// ðŸ’° Wallet
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
// ðŸ’³ PayPal
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
// ðŸ“¡ WebSocket
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
      giftName, emoji: p.emoji || 'ðŸŽ', fromUser: p.username || 'fan',
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
// ðŸ  Serve Frontend
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
// ðŸš€ Start Server
// ========================================
server.listen(PORT, () => {
  console.log(`ðŸš€ NVME.live running on http://localhost:${PORT}`);
  console.log(`ðŸ” Auth: register/login/me/google â€” enabled`);
  console.log(`â¤ï¸  Likes / ðŸ’¬ Comments / ðŸ‘¥ Follows / ðŸ”’ Privacy / ðŸ”Ž Search: enabled`);
  console.log(`ðŸ’° Gifts, wallet, PayPal: enabled`);
  console.log(`âš”ï¸  Battles: enabled`);
});

process.on('unhandledRejection', (err) => console.error('Unhandled Rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught Exception:', err));

PS C:\Users\Digital King\nvme-platform> Get-Content ".\src\backend\db.js" -Raw
const { Pool } = require('pg');

// Use the same pool config as server.js (from your root)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client', err.message);
});

module.exports = pool;

PS C:\Users\Digital King\nvme-platform> Get-Content ".\src\backend\lib\scraper.js" -Raw
Get-Content : Cannot find path 'C:\Users\Digital King\nvme-platform\src\backend\lib\scraper.js' because it does not
exist.
At line:1 char:1
+ Get-Content ".\src\backend\lib\scraper.js" -Raw
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Digita...\lib\scraper.js:String) [Get-Content], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand

PS C:\Users\Digital King\nvme-platform> Get-Content ".\nvme-tiktok-features.js" -Raw
// ============================================================
// NVME.LIVE â€” TikTok Parity Features Module
// Added: Hashtags, Sounds, Duets, Creator Fund, Tips, Shop
// ============================================================
'use strict';

module.exports = function(app, db, authMiddleware, optionalAuth) {

  // â”€â”€ INIT: Add missing columns & tables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  (async () => {
    try {
      // Hashtags on videos
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}'`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS sound_id UUID`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS duet_of UUID`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_url TEXT`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_title TEXT`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_price NUMERIC(10,2)`);

      // Shop on users
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_url TEXT`);
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_description TEXT`);
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS creator_coins_earned INTEGER DEFAULT 0`);

      // Sounds table
      await db.query(`
        CREATE TABLE IF NOT EXISTS sounds (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name TEXT NOT NULL,
          artist TEXT DEFAULT 'Unknown',
          url TEXT NOT NULL,
          cover_url TEXT,
          duration_sec INTEGER DEFAULT 30,
          use_count INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Tips table
      await db.query(`
        CREATE TABLE IF NOT EXISTS tips (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          from_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          to_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          coins INTEGER NOT NULL,
          message TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Hashtag challenges table
      await db.query(`
        CREATE TABLE IF NOT EXISTS hashtag_challenges (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          tag TEXT UNIQUE NOT NULL,
          description TEXT,
          prize_coins INTEGER DEFAULT 0,
          starts_at TIMESTAMPTZ DEFAULT NOW(),
          ends_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Creator fund log
      await db.query(`
        CREATE TABLE IF NOT EXISTS creator_fund_log (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
          coins_earned INTEGER NOT NULL,
          view_milestone INTEGER NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Seed default sounds if empty
      const { rows: soundCheck } = await db.query('SELECT COUNT(*) FROM sounds');
      if (parseInt(soundCheck[0].count) === 0) {
        const defaultSounds = [
          { name: 'Empire Rise', artist: 'Kush Beats', url: '' },
          { name: 'Island Vibes', artist: 'Bermuda Sound', url: '' },
          { name: 'Money Moves', artist: 'Empire HQ', url: '' },
          { name: 'AI Dreams', artist: 'Kush AI', url: '' },
          { name: 'Crown Anthem', artist: 'Dollar Double', url: '' },
          { name: 'Night Hustle', artist: 'Empire Collective', url: '' },
          { name: 'Viral Energy', artist: 'NVME Sounds', url: '' },
          { name: 'Creator Flow', artist: 'Studio Mix', url: '' },
        ];
        for (const s of defaultSounds) {
          await db.query(
            'INSERT INTO sounds (name, artist, url) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
            [s.name, s.artist, s.url]
          );
        }
      }

      console.log('[nvme-tiktok] âœ… Schema migrations complete');
    } catch (e) {
      console.error('[nvme-tiktok] Schema init error:', e.message);
    }
  })();

  const CREATOR_FUND_RATE = parseFloat(process.env.CREATOR_FUND_RATE || '0.5'); // coins per 1000 views
  const CREATOR_FUND_MILESTONE = parseInt(process.env.CREATOR_FUND_MILESTONE || '1000');

  // â”€â”€ HASHTAGS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/hashtags/trending â€” top 20 hashtags by video count (7 days)
  app.get('/api/hashtags/trending', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(*) AS video_count
        FROM videos, UNNEST(tags) AS tag
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY tag
        ORDER BY video_count DESC
        LIMIT 20
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/all â€” all-time top hashtags
  app.get('/api/hashtags/all', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(*) AS video_count
        FROM videos, UNNEST(tags) AS tag
        GROUP BY tag
        ORDER BY video_count DESC
        LIMIT 50
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/:tag/videos â€” videos with this hashtag
  app.get('/api/hashtags/:tag/videos', optionalAuth, async (req, res) => {
    try {
      const tag = req.params.tag.toLowerCase().replace(/^#/, '');
      const viewerId = req.user ? req.user.id : null;
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.description, v.url, v.thumbnail, v.views, v.tags, v.created_at,
               u.username, u.avatar_url, u.id AS author_id,
               COALESCE(l.like_count, 0)::int AS like_count,
               COALESCE(c.comment_count, 0)::int AS comment_count,
               CASE WHEN $2::uuid IS NOT NULL AND vl.user_id IS NOT NULL THEN true ELSE false END AS viewer_liked
        FROM videos v
        JOIN users u ON u.id = v.user_id
        LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id = v.id
        LEFT JOIN (SELECT video_id, COUNT(*) AS comment_count FROM comments GROUP BY video_id) c ON c.video_id = v.id
        LEFT JOIN video_likes vl ON vl.video_id = v.id AND vl.user_id = $2::uuid
        WHERE $1 = ANY(v.tags)
        ORDER BY v.created_at DESC
        LIMIT 30
      `, [tag, viewerId]);
      res.json({ ok: true, tag, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/videos/:id/tags â€” set tags on video
  app.post('/api/videos/:id/tags', authMiddleware, async (req, res) => {
    try {
      const { tags } = req.body; // array of strings
      if (!Array.isArray(tags)) return res.status(400).json({ error: 'tags must be array' });
      const clean = tags.map(t => t.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 30)).filter(Boolean).slice(0, 10);
      const { rows } = await db.query(
        'UPDATE videos SET tags=$1 WHERE id=$2 AND user_id=$3 RETURNING id, tags',
        [clean, req.params.id, req.user.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found or not yours' });
      res.json({ ok: true, tags: rows[0].tags });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ SOUNDS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/sounds/trending
  app.get('/api/sounds/trending', async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT * FROM sounds ORDER BY use_count DESC, created_at DESC LIMIT 20'
      );
      res.json({ ok: true, sounds: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/sounds/:id
  app.get('/api/sounds/:id', async (req, res) => {
    try {
      const { rows } = await db.query('SELECT * FROM sounds WHERE id=$1', [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: 'sound not found' });
      res.json({ ok: true, sound: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/sounds â€” create a sound
  app.post('/api/sounds', authMiddleware, async (req, res) => {
    try {
      const { name, artist, url, cover_url, duration_sec } = req.body;
      if (!name || !url) return res.status(400).json({ error: 'name and url required' });
      const { rows } = await db.query(
        'INSERT INTO sounds (name, artist, url, cover_url, duration_sec) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [name, artist || 'Unknown', url, cover_url || null, duration_sec || 30]
      );
      res.json({ ok: true, sound: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/sounds/:id/videos â€” videos using this sound
  app.get('/api/sounds/:id/videos', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.sound_id = $1
        ORDER BY v.views DESC LIMIT 30
      `, [req.params.id]);
      res.json({ ok: true, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ DUETS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/videos/:id/duets
  app.get('/api/videos/:id/duets', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.created_at,
               u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.duet_of = $1
        ORDER BY v.created_at DESC LIMIT 20
      `, [req.params.id]);
      res.json({ ok: true, duets: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ CREATOR FUND â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // Override view endpoint with creator fund logic
  app.post('/api/videos/:id/view-cf', async (req, res) => {
    try {
      const { rows } = await db.query(
        'UPDATE videos SET views=views+1 WHERE id=$1 RETURNING id, views, user_id',
        [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found' });
      const { views, user_id } = rows[0];

      // Creator Fund: award coins at every 1000-view milestone
      if (views % CREATOR_FUND_MILESTONE === 0) {
        const coinsEarned = Math.round(CREATOR_FUND_RATE);
        if (coinsEarned > 0) {
          await db.query(
            'UPDATE users SET coins = COALESCE(coins,0) + $1, creator_coins_earned = COALESCE(creator_coins_earned,0) + $1 WHERE id = $2',
            [coinsEarned, user_id]
          );
          await db.query(
            'INSERT INTO creator_fund_log (user_id, video_id, coins_earned, view_milestone) VALUES ($1,$2,$3,$4)',
            [user_id, req.params.id, coinsEarned, views]
          );
        }
      }

      res.json({ ok: true, views });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator/fund-earnings
  app.get('/api/creator/fund-earnings', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT SUM(coins_earned) AS total_coins,
               COUNT(*) AS milestone_count,
               MAX(created_at) AS last_earned
        FROM creator_fund_log WHERE user_id = $1
      `, [req.user.id]);
      const { rows: urows } = await db.query(
        'SELECT creator_coins_earned FROM users WHERE id=$1', [req.user.id]
      );
      res.json({
        ok: true,
        total_coins_earned: parseInt(rows[0].total_coins) || 0,
        milestone_count: parseInt(rows[0].milestone_count) || 0,
        last_earned: rows[0].last_earned,
        lifetime_creator_coins: parseInt(urows[0]?.creator_coins_earned) || 0
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ TIPS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // POST /api/tips â€” send a tip (100% to creator, no platform cut)
  app.post('/api/tips', authMiddleware, async (req, res) => {
    try {
      const { to_user_id, coins, message } = req.body;
      if (!to_user_id || !coins || coins < 1) return res.status(400).json({ error: 'to_user_id and coins (min 1) required' });
      if (to_user_id === req.user.id) return res.status(400).json({ error: 'cannot tip yourself' });

      // Check sender balance
      const { rows: sender } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if (!sender.length || (sender[0].coins || 0) < coins) {
        return res.status(400).json({ error: 'insufficient coins' });
      }

      // Deduct from sender
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [coins, req.user.id]);
      // Credit receiver (100% - no platform cut on tips)
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [coins, to_user_id]);
      // Log tip
      const { rows } = await db.query(
        'INSERT INTO tips (from_user_id, to_user_id, coins, message) VALUES ($1,$2,$3,$4) RETURNING *',
        [req.user.id, to_user_id, coins, message || null]
      );
      res.json({ ok: true, tip: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/tips/received
  app.get('/api/tips/received', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT t.id, t.coins, t.message, t.created_at, u.username AS from_username, u.avatar_url AS from_avatar
        FROM tips t JOIN users u ON u.id = t.from_user_id
        WHERE t.to_user_id = $1 ORDER BY t.created_at DESC LIMIT 50
      `, [req.user.id]);
      res.json({ ok: true, tips: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/tips/sent
  app.get('/api/tips/sent', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT t.id, t.coins, t.message, t.created_at, u.username AS to_username
        FROM tips t JOIN users u ON u.id = t.to_user_id
        WHERE t.from_user_id = $1 ORDER BY t.created_at DESC LIMIT 50
      `, [req.user.id]);
      res.json({ ok: true, tips: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ PRODUCT LINKS / CREATOR SHOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // PUT /api/profile/shop â€” update user shop
  app.put('/api/profile/shop', authMiddleware, async (req, res) => {
    try {
      const { shop_url, shop_description } = req.body;
      const { rows } = await db.query(
        'UPDATE users SET shop_url=$1, shop_description=$2 WHERE id=$3 RETURNING id, shop_url, shop_description',
        [shop_url || null, shop_description || null, req.user.id]
      );
      res.json({ ok: true, shop: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PUT /api/videos/:id/product â€” add product link to video
  app.put('/api/videos/:id/product', authMiddleware, async (req, res) => {
    try {
      const { product_url, product_title, product_price } = req.body;
      const { rows } = await db.query(
        'UPDATE videos SET product_url=$1, product_title=$2, product_price=$3 WHERE id=$4 AND user_id=$5 RETURNING id, product_url, product_title, product_price',
        [product_url || null, product_title || null, product_price || null, req.params.id, req.user.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found or not yours' });
      res.json({ ok: true, product: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/videos/:id/product
  app.get('/api/videos/:id/product', async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT product_url, product_title, product_price FROM videos WHERE id=$1',
        [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'not found' });
      res.json({ ok: true, product: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ ENHANCED SEARCH â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/search?q=query â€” search users, videos, hashtags, sounds
  app.get('/api/search', optionalAuth, async (req, res) => {
    try {
      const q = (req.query.q || '').trim();
      if (!q) return res.json({ ok: true, users: [], videos: [], hashtags: [], sounds: [] });
      const like = `%${q.toLowerCase()}%`;
      const tag = q.toLowerCase().replace(/^#/, '').replace(/[^a-z0-9_]/g, '');

      const [usersR, videosR, hashtagsR, soundsR] = await Promise.all([
        db.query(
          `SELECT id, username, avatar_url, bio FROM users
           WHERE LOWER(username) LIKE $1 OR LOWER(COALESCE(bio,'')) LIKE $1
           LIMIT 10`, [like]
        ),
        db.query(
          `SELECT v.id, v.title, v.description, v.url, v.thumbnail, v.views, v.tags, v.created_at,
                  u.username, u.avatar_url
           FROM videos v JOIN users u ON u.id = v.user_id
           WHERE LOWER(v.title) LIKE $1 OR LOWER(COALESCE(v.description,'')) LIKE $1
              OR $2 = ANY(v.tags)
           ORDER BY v.views DESC LIMIT 20`, [like, tag]
        ),
        db.query(
          `SELECT tag, COUNT(*) AS video_count
           FROM videos, UNNEST(tags) AS tag
           WHERE LOWER(tag) LIKE $1
           GROUP BY tag ORDER BY video_count DESC LIMIT 10`, [like]
        ),
        db.query(
          `SELECT id, name, artist, use_count FROM sounds
           WHERE LOWER(name) LIKE $1 OR LOWER(COALESCE(artist,'')) LIKE $1
           ORDER BY use_count DESC LIMIT 10`, [like]
        ),
      ]);

      res.json({
        ok: true,
        query: q,
        users: usersR.rows,
        videos: videosR.rows,
        hashtags: hashtagsR.rows,
        sounds: soundsR.rows
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ HASHTAG CHALLENGES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/challenges â€” active hashtag challenges
  app.get('/api/challenges', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT hc.*, COUNT(v.id)::int AS participant_count
        FROM hashtag_challenges hc
        LEFT JOIN videos v ON hc.tag = ANY(v.tags)
        WHERE hc.ends_at IS NULL OR hc.ends_at > NOW()
        GROUP BY hc.id
        ORDER BY participant_count DESC, hc.created_at DESC
        LIMIT 10
      `);
      res.json({ ok: true, challenges: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/challenges â€” create challenge (admin/founder only)
  app.post('/api/challenges', authMiddleware, async (req, res) => {
    try {
      const { tag, description, prize_coins, ends_at } = req.body;
      if (!tag) return res.status(400).json({ error: 'tag required' });
      const { rows } = await db.query(
        'INSERT INTO hashtag_challenges (tag, description, prize_coins, ends_at) VALUES ($1,$2,$3,$4) ON CONFLICT (tag) DO UPDATE SET description=$2, prize_coins=$3, ends_at=$4 RETURNING *',
        [tag.toLowerCase().replace(/^#/,''), description||null, prize_coins||0, ends_at||null]
      );
      res.json({ ok: true, challenge: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ CREATOR LEADERBOARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // GET /api/leaderboard/creators â€” top earners this week
  app.get('/api/leaderboard/creators', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT u.id, u.username, u.avatar_url,
               COALESCE(SUM(g.credits),0)::int AS gifts_received,
               COALESCE(u.creator_coins_earned,0)::int AS fund_earned,
               COALESCE(SUM(v.views),0)::int AS total_views
        FROM users u
        LEFT JOIN gifts g ON g.receiver_id = u.id AND g.created_at > NOW() - INTERVAL '7 days'
        LEFT JOIN videos v ON v.user_id = u.id
        GROUP BY u.id
        ORDER BY (COALESCE(SUM(g.credits),0) + COALESCE(u.creator_coins_earned,0)) DESC
        LIMIT 20
      `);
      res.json({ ok: true, creators: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ SERIES (Paid exclusive content) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // CREATE TABLE series
  db.query(`
    CREATE TABLE IF NOT EXISTS series (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      creator_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      price_coins INTEGER DEFAULT 100,
      cover_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});

  db.query(`
    CREATE TABLE IF NOT EXISTS series_access (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      series_id UUID REFERENCES series(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      granted_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(series_id, user_id)
    )
  `).catch(() => {});

  db.query(`
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS series_id UUID
  `).catch(() => {});

  // GET /api/series â€” all series
  app.get('/api/series', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT s.*, u.username AS creator_username, u.avatar_url AS creator_avatar,
               COUNT(v.id)::int AS episode_count
        FROM series s JOIN users u ON u.id = s.creator_id
        LEFT JOIN videos v ON v.series_id = s.id
        GROUP BY s.id, u.username, u.avatar_url
        ORDER BY s.created_at DESC LIMIT 30
      `);
      res.json({ ok: true, series: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/series â€” create series
  app.post('/api/series', authMiddleware, async (req, res) => {
    try {
      const { title, description, price_coins, cover_url } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const { rows } = await db.query(
        'INSERT INTO series (creator_id, title, description, price_coins, cover_url) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [req.user.id, title, description||null, price_coins||100, cover_url||null]
      );
      res.json({ ok: true, series: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/series/:id/unlock â€” pay coins to access series
  app.post('/api/series/:id/unlock', authMiddleware, async (req, res) => {
    try {
      const { rows: srows } = await db.query('SELECT * FROM series WHERE id=$1', [req.params.id]);
      if (!srows.length) return res.status(404).json({ error: 'series not found' });
      const series = srows[0];

      // Check already unlocked
      const { rows: access } = await db.query(
        'SELECT id FROM series_access WHERE series_id=$1 AND user_id=$2',
        [series.id, req.user.id]
      );
      if (access.length) return res.json({ ok: true, already_unlocked: true });

      // Check balance
      const { rows: urows } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if ((urows[0]?.coins || 0) < series.price_coins) {
        return res.status(400).json({ error: 'insufficient coins' });
      }

      // Deduct + credit creator + grant access
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [series.price_coins, req.user.id]);
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [Math.round(series.price_coins * 0.7), series.creator_id]);
      await db.query('INSERT INTO series_access (series_id, user_id) VALUES ($1,$2)', [series.id, req.user.id]);

      res.json({ ok: true, unlocked: true, coins_spent: series.price_coins });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // â”€â”€ LIVE SUBSCRIPTIONS (Creator monthly subs) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  db.query(`
    CREATE TABLE IF NOT EXISTS creator_subscriptions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      subscriber_id UUID REFERENCES users(id) ON DELETE CASCADE,
      creator_id UUID REFERENCES users(id) ON DELETE CASCADE,
      coins_per_month INTEGER DEFAULT 500,
      status TEXT DEFAULT 'active',
      started_at TIMESTAMPTZ DEFAULT NOW(),
      next_billing TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days',
      UNIQUE(subscriber_id, creator_id)
    )
  `).catch(() => {});

  // POST /api/creator-subs/:creatorId â€” subscribe to a creator
  app.post('/api/creator-subs/:creatorId', authMiddleware, async (req, res) => {
    try {
      const { coins_per_month = 500 } = req.body;
      const creatorId = req.params.creatorId;
      if (creatorId === req.user.id) return res.status(400).json({ error: 'cannot sub to yourself' });

      const { rows: urows } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if ((urows[0]?.coins || 0) < coins_per_month) {
        return res.status(400).json({ error: 'insufficient coins for first month' });
      }

      // First month payment
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [coins_per_month, req.user.id]);
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [Math.round(coins_per_month * 0.7), creatorId]);

      const { rows } = await db.query(`
        INSERT INTO creator_subscriptions (subscriber_id, creator_id, coins_per_month)
        VALUES ($1,$2,$3)
        ON CONFLICT (subscriber_id, creator_id) DO UPDATE SET status='active', next_billing=NOW()+INTERVAL '30 days'
        RETURNING *
      `, [req.user.id, creatorId, coins_per_month]);

      res.json({ ok: true, subscription: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator-subs/my â€” my subscriptions
  app.get('/api/creator-subs/my', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT cs.*, u.username AS creator_username, u.avatar_url AS creator_avatar
        FROM creator_subscriptions cs JOIN users u ON u.id = cs.creator_id
        WHERE cs.subscriber_id = $1 AND cs.status = 'active'
      `, [req.user.id]);
      res.json({ ok: true, subscriptions: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator-subs/subscribers â€” my subscribers (as creator)
  app.get('/api/creator-subs/subscribers', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT cs.*, u.username AS subscriber_username, u.avatar_url AS subscriber_avatar
        FROM creator_subscriptions cs JOIN users u ON u.id = cs.subscriber_id
        WHERE cs.creator_id = $1 AND cs.status = 'active'
      `, [req.user.id]);
      res.json({ ok: true, subscribers: rows, count: rows.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  console.log('[nvme-tiktok] âœ… TikTok-parity routes registered: hashtags, sounds, duets, creator-fund, tips, shop, series, challenges, leaderboard, creator-subs');
};

PS C:\Users\Digital King\nvme-platform> Get-Content ".\nvme-ai-studio.js" -Raw
// ============================================================
// NVME.LIVE â€” AI Studio Module (Kimi K3 via OpenRouter)
// Endpoints: captions, hashtags, scripts, comment replies,
//            feed ranking, status. Powers TikTok/Epic Studio UX.
// ============================================================
'use strict';

module.exports = function(app, db, authMiddleware, optionalAuth) {

  const AI_MODEL = process.env.AI_MODEL || 'moonshotai/kimi-k3';
  const OR_URL = 'https://openrouter.ai/api/v1/chat/completions';

  function aiKey() {
    return process.env.OPENROUTER_API_KEY || process.env.API_KEY_OPENROUTER || '';
  }

  async function kimi(messages, opts = {}) {
    const key = aiKey();
    if (!key) {
      const e = new Error('AI offline: set OPENROUTER_API_KEY');
      e.code = 'NO_KEY';
      throw e;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || 60000);
    try {
      const r = await fetch(OR_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://nvme.live',
          'X-Title': 'NVME.LIVE AI Studio'
        },
        body: JSON.stringify({
          model: AI_MODEL,
          messages,
          temperature: opts.temperature ?? 0.8,
          max_tokens: opts.maxTokens ?? 900
        }),
        signal: controller.signal
      });
      if (!r.ok) {
        const txt = await r.text().catch(() => '');
        throw new Error(`OpenRouter ${r.status}: ${txt.slice(0, 200)}`);
      }
      const data = await r.json();
      return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content || '').trim();
    } finally {
      clearTimeout(timer);
    }
  }

  function parseJSONLoose(text, fallback) {
    try {
      const m = text.match(/[\[\{][\s\S]*[\]\}]/);
      return m ? JSON.parse(m[0]) : fallback;
    } catch (_) { return fallback; }
  }

  async function logGen(userId, kind, prompt, result) {
    try {
      await db.query(
        'INSERT INTO ai_generations (user_id, kind, prompt, result) VALUES ($1,$2,$3,$4)',
        [userId || null, kind, String(prompt).slice(0, 2000), String(result).slice(0, 4000)]
      );
    } catch (_) { /* logging must never break generation */ }
  }

  // â”€â”€ INIT: usage log table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  (async () => {
    try {
      await db.query(`
        CREATE TABLE IF NOT EXISTS ai_generations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID,
          kind TEXT NOT NULL,
          prompt TEXT,
          result TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);
      await db.query('CREATE INDEX IF NOT EXISTS idx_ai_gen_user ON ai_generations(user_id, created_at DESC)');
      console.log('[AI-STUDIO] ready â€” model:', AI_MODEL);
    } catch (e) { console.error('[AI-STUDIO] init warn:', e.message); }
  })();

  // â”€â”€ STATUS (public) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  app.get('/api/ai/status', (req, res) => {
    res.json({ ok: !!aiKey(), model: AI_MODEL, studio: 'nvme-ai-studio v1', ts: new Date().toISOString() });
  });

  // â”€â”€ CAPTIONS: 5 scroll-stopping variants + hashtags â”€â”€â”€â”€â”€â”€â”€
  app.post('/api/ai/captions', authMiddleware, async (req, res) => {
    try {
      const { title = '', description = '', niche = 'general', tone = 'bold' } = req.body || {};
      if (!title && !description) return res.status(400).json({ error: 'title or description required' });
      const out = await kimi([
        { role: 'system', content: 'You are a TikTok growth strategist. Return ONLY a JSON array of 5 objects: {"caption": string (<120 chars, may include emojis), "hashtags": string (4-6 space-separated #tags)}. No markdown, no commentary.' },
        { role: 'user', content: `Video title: ${title}\nDescription: ${description}\nNiche: ${niche}\nTone: ${tone}\nPlatform: NVME.LIVE (short-form vertical video, TikTok-style feed)` }
      ], { maxTokens: 700 });
      const captions = parseJSONLoose(out, null);
      if (!Array.isArray(captions)) return res.status(502).json({ error: 'AI returned unexpected format', raw: out.slice(0, 300) });
      await logGen(req.user.id, 'captions', `${title} | ${description}`, out);
      res.json({ captions: captions.slice(0, 5), model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // â”€â”€ HASHTAG LAB: niche tag sets ranked by reach tier â”€â”€â”€â”€â”€â”€
  app.post('/api/ai/hashtags', authMiddleware, async (req, res) => {
    try {
      const { topic = '', niche = 'general' } = req.body || {};
      if (!topic) return res.status(400).json({ error: 'topic required' });
      const out = await kimi([
        { role: 'system', content: 'You are a short-form video SEO expert. Return ONLY JSON: {"mega":["#tag"...3], "mid":["#tag"...5], "niche":["#tag"...5], "branded":["#tag"...2]}. mega=huge reach, mid=100k-1M, niche=targeted, branded=NVME-themed. No markdown.' },
        { role: 'user', content: `Topic: ${topic}\nNiche: ${niche}` }
      ], { maxTokens: 400 });
      const tags = parseJSONLoose(out, null);
      if (!tags) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'hashtags', topic, out);
      res.json({ ...tags, model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // â”€â”€ SCRIPT STUDIO: viral short-form script (hook/beat/CTA) â”€
  app.post('/api/ai/script', authMiddleware, async (req, res) => {
    try {
      const { topic = '', style = 'educational', duration = 30 } = req.body || {};
      if (!topic) return res.status(400).json({ error: 'topic required' });
      const out = await kimi([
        { role: 'system', content: 'You are an elite short-form scriptwriter. Return ONLY JSON: {"hook": string (first 3 seconds, spoken), "beats": [string] (3-5 visual/action beats), "cta": string, "caption": string, "hashtags": string}. Scripts must fit the requested duration. No markdown.' },
        { role: 'user', content: `Topic: ${topic}\nStyle: ${style}\nDuration: ${duration}s vertical video` }
      ], { maxTokens: 800, temperature: 0.9 });
      const script = parseJSONLoose(out, null);
      if (!script) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'script', `${topic} (${style}, ${duration}s)`, out);
      res.json({ ...script, model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // â”€â”€ COMMENT REPLY: 3 on-brand reply suggestions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  app.post('/api/ai/comment-reply', authMiddleware, async (req, res) => {
    try {
      const { comment = '', videoTitle = '', tone = 'friendly' } = req.body || {};
      if (!comment) return res.status(400).json({ error: 'comment required' });
      const out = await kimi([
        { role: 'system', content: 'You are a creator-community manager. Return ONLY a JSON array of 3 short reply strings (<100 chars each), varied: one warm, one witty, one engagement-baiting question. No markdown.' },
        { role: 'user', content: `Comment: "${comment}"\nOn video: ${videoTitle}\nCreator tone: ${tone}` }
      ], { maxTokens: 300 });
      const replies = parseJSONLoose(out, null);
      if (!Array.isArray(replies)) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'comment-reply', comment, out);
      res.json({ replies: replies.slice(0, 3), model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // â”€â”€ FEED RANK: engagement-weighted For-You ordering â”€â”€â”€â”€â”€â”€â”€
  // Pulls recent videos with live engagement signals and returns
  // ranked IDs. Falls back to recency if AI unavailable.
  app.get('/api/ai/feed-rank', optionalAuth, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.caption,
               COALESCE(v.likes_count,0) likes, COALESCE(v.views_count,0) views,
               COALESCE(v.comments_count,0) comments,
               EXTRACT(EPOCH FROM (NOW() - v.created_at))/3600 age_hrs
        FROM videos v
        WHERE v.created_at > NOW() - INTERVAL '7 days'
        ORDER BY v.created_at DESC LIMIT 60
      `);
      if (rows.length < 3 || !aiKey()) {
        return res.json({ ranked: rows.map(r => r.id), source: 'recency', model: null });
      }
      const digest = rows.map((r, i) =>
        `${i}:${r.id}|likes${r.likes}|views${r.views}|comments${r.comments}|age${Math.round(r.age_hrs)}h|${(r.title || '').slice(0, 40)}`
      ).join('\n');
      const out = await kimi([
        { role: 'system', content: 'You are a For-You feed ranking engine. Rank for watch-time potential: favor engagement rate over raw views, penalize stale posts, diversify creators. Return ONLY a JSON array of the numeric indices in ranked order.' },
        { role: 'user', content: digest }
      ], { maxTokens: 300, temperature: 0.2 });
      const order = parseJSONLoose(out, null);
      if (!Array.isArray(order)) return res.json({ ranked: rows.map(r => r.id), source: 'recency-fallback', model: AI_MODEL });
      const ranked = order.filter(i => Number.isInteger(i) && rows[i]).map(i => rows[i].id);
      const missing = rows.map(r => r.id).filter(id => !ranked.includes(id));
      res.json({ ranked: [...ranked, ...missing], source: 'kimi-k3', model: AI_MODEL });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // â”€â”€ CREATOR ANALYTICS: usage stats for the AI Studio tab â”€â”€
  app.get('/api/ai/usage', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        `SELECT kind, COUNT(*)::int count, MAX(created_at) last_used
         FROM ai_generations WHERE user_id=$1 GROUP BY kind ORDER BY count DESC`,
        [req.user.id]
      );
      res.json({ usage: rows, model: AI_MODEL });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  console.log('[AI-STUDIO] routes mounted: /api/ai/{status,captions,hashtags,script,comment-reply,feed-rank,usage}');
};

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\lib\api.ts" -Raw
/* Centralized API layer â€” wired to the VERIFIED live NVME monolith.
   Same-origin by default (Next rewrites proxy /api + /auth + /socket.io). */

const BASE = process.env.NEXT_PUBLIC_API_URL || '';

export interface NvmeUser {
  id: string;
  username: string;
  display_name?: string;
  email?: string;
  avatar_url?: string;
  bio?: string;
  profile_link?: string;
  followers?: number;
  online?: boolean;
  is_private?: boolean;
}

export interface NvmeVideo {
  id: string;
  url: string;
  thumbnail?: string;
  title?: string;
  description?: string;
  username?: string;
  author_id?: string;
  avatar_url?: string;
  like_count?: number;
  comment_count?: number;
  views?: number;
  created_at?: string;
}

export interface NvmeComment {
  id: string;
  text?: string;
  image_url?: string;
  username?: string;
  display_name?: string;
  avatar_url?: string;
  created_at?: string;
}

function token(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('nvme_token') || sessionStorage.getItem('nvme_token') || localStorage.getItem('empire_token');
}

export function authHeaders(json = true): Record<string, string> {
  const h: Record<string, string> = {};
  if (json) h['Content-Type'] = 'application/json';
  const t = token();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { ...authHeaders(!(opts.body instanceof FormData)), ...(opts.headers || {}) }
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch { /* non-json */ }
    throw new Error(msg);
  }
  return res.json();
}

/* ---------- AUTH ---------- */
export const auth = {
  login: (email: string, password: string) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  register: (username: string, email: string, password: string) =>
    req<{ token: string; user: NvmeUser }>('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) }),
  me: () => req<{ user: NvmeUser } | NvmeUser>('/api/auth/me'),
  googleUrl: () => `${BASE}/auth/google`
};

/* ---------- FEED / VIDEOS ---------- */
export const videos = {
  feed: async (cursor?: string): Promise<{ items: NvmeVideo[]; nextCursor?: string }> => {
    const d = await req<any>(`/api/feed${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`);
    const items: NvmeVideo[] = d.feed || d.videos || (Array.isArray(d) ? d : []);
    return { items: items.filter(v => v && v.url), nextCursor: d.nextCursor };
  },
  get: (id: string) => req<NvmeVideo>(`/api/videos/${id}`),
  like: (id: string) => req<any>(`/api/videos/${id}/like`, { method: 'POST' }),
  view: (id: string) => fetch(`${BASE}/api/videos/${id}/view`, { method: 'POST' }).catch(() => {}),
  comments: async (id: string): Promise<NvmeComment[]> => {
    const d = await req<any>(`/api/videos/${id}/comments`);
    return d.comments || d || [];
  },
  postComment: (id: string, text: string, image?: string | null) =>
    req<any>(`/api/videos/${id}/comments`, { method: 'POST', body: JSON.stringify({ text, image: image || undefined }) }),
  byUser: async (username: string): Promise<NvmeVideo[]> => {
    const d = await req<any>(`/api/users/${encodeURIComponent(username)}/videos`);
    return d.videos || [];
  }
};

/* ---------- USERS / SOCIAL ---------- */
export const users = {
  discover: async (): Promise<NvmeUser[]> => {
    const d = await req<any>('/api/users/discover');
    return d.users || d || [];
  },
  follow: (userId: string) => req<{ ok: boolean; following?: boolean }>(`/api/users/${userId}/follow`, { method: 'POST' }),
  stats: (username: string) => req<any>(`/api/users/${encodeURIComponent(username)}/stats`),
  updateProfile: (body: Partial<NvmeUser>) => req<{ ok: boolean; user: NvmeUser }>('/api/profile', { method: 'PUT', body: JSON.stringify(body) })
};

/* ---------- SEARCH ---------- */
export async function search(q: string): Promise<{ users: NvmeUser[]; videos: NvmeVideo[] }> {
  const d = await req<any>(`/api/search?q=${encodeURIComponent(q)}`);
  return { users: d.users || [], videos: (d.videos || []).filter((v: NvmeVideo) => v.url) };
}

/* ---------- UPLOAD ---------- */
export async function uploadVideo(file: File, title: string, description: string): Promise<{ url?: string; thumbnail?: string }> {
  const fd = new FormData();
  fd.append('video', file);
  fd.append('title', title);
  fd.append('description', description);
  return req('/api/upload', { method: 'POST', body: fd });
}

/* ---------- AI STUDIO ---------- */
export const ai = {
  status: () => req<any>('/api/ai/status'),
  captions: (topic: string) => req<any>('/api/ai/captions', { method: 'POST', body: JSON.stringify({ topic }) }),
  hashtags: (topic: string) => req<any>('/api/ai/hashtags', { method: 'POST', body: JSON.stringify({ topic }) }),
  script: (topic: string) => req<any>('/api/ai/script', { method: 'POST', body: JSON.stringify({ topic }) }),
  generate: (prompt: string) => req<any>('/api/ai/generate', { method: 'POST', body: JSON.stringify({ prompt }) })
};

/* ---------- WALLET ---------- */
export const wallet = {
  balance: () => req<{ balance?: number; coins?: number }>('/api/wallet/balance'),
  transactions: () => req<any>('/api/wallet/transactions'),
  connect: (address: string) => req<any>('/api/wallet/connect', { method: 'POST', body: JSON.stringify({ address }) })
};

/* ---------- PAYMENTS ---------- */
export const payments = {
  createOrder: (plan: string) => req<any>('/api/payments/paypal/create-order', { method: 'POST', body: JSON.stringify({ plan }) }),
  captureOrder: (orderId: string) => req<any>('/api/payments/paypal/capture-order', { method: 'POST', body: JSON.stringify({ orderId }) })
};

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\components\VideoFeed.tsx" -Raw
'use client';
import { useEffect, useRef, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Loader2, RefreshCw } from 'lucide-react';
import VideoCard from './VideoCard';
import { videos, type NvmeVideo } from '@/lib/api';

export default function VideoFeed() {
  const containerRef = useRef<HTMLDivElement>(null);
  const videoEls = useRef<Map<number, HTMLVideoElement>>(new Map());
  const cardEls = useRef<Map<number, HTMLDivElement>>(new Map());
  const [activeIdx, setActiveIdx] = useState(0);
  const [pullY, setPullY] = useState(0);
  const touchStart = useRef(0);

  const query = useInfiniteQuery({
    queryKey: ['feed'],
    queryFn: ({ pageParam }) => videos.feed(pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor,
    staleTime: 5 * 60 * 1000
  });

  const items: NvmeVideo[] = (query.data?.pages || []).flatMap((p) => p.items);

  // TikTok autoplay: play the card 60%+ visible, pause everything else
  useEffect(() => {
    const root = containerRef.current;
    if (!root) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        const idx = Number((e.target as HTMLElement).dataset.idx);
        const v = videoEls.current.get(idx);
        if (!v) return;
        if (e.intersectionRatio >= 0.6) {
          setActiveIdx(idx);
          videos.view(items[idx]?.id);
          v.play().catch(() => {});
        } else {
          v.pause();
        }
      });
    }, { root, threshold: [0, 0.25, 0.6, 0.9] });
    cardEls.current.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
  }, [items.length]);

  // Load more when near the end
  useEffect(() => {
    if (activeIdx >= items.length - 3 && query.hasNextPage && !query.isFetchingNextPage) {
      query.fetchNextPage();
    }
  }, [activeIdx]); // eslint-disable-line react-hooks/exhaustive-deps

  // Pull-to-refresh (only at the top)
  function onTouchStart(e: React.TouchEvent) {
    if ((containerRef.current?.scrollTop || 0) <= 0) touchStart.current = e.touches[0].clientY;
  }
  function onTouchMove(e: React.TouchEvent) {
    if (!touchStart.current) return;
    const dy = e.touches[0].clientY - touchStart.current;
    if (dy > 0) setPullY(Math.min(110, dy * 0.5));
  }
  function onTouchEnd() {
    if (pullY > 70) query.refetch();
    setPullY(0);
    touchStart.current = 0;
  }

  if (query.isLoading) {
    return (
      <div className="flex h-full items-center justify-center bg-black">
        <div className="text-center">
          <Loader2 className="mx-auto animate-spin text-nvme-gold" size={36} />
          <p className="mt-3 text-sm text-nvme-muted">Loading your feedâ€¦</p>
        </div>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex h-full items-center justify-center bg-black">
        <div className="text-center">
          <p className="text-nvme-coral">Feed failed to load</p>
          <button onClick={() => query.refetch()} className="btn-gold mt-4"><RefreshCw size={15} /> Retry</button>
        </div>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-black px-8 text-center">
        <div>
          <p className="font-display text-2xl">NO VIDEOS YET</p>
          <p className="mt-2 text-sm text-nvme-muted">Be the first creator â€” upload from the Studio.</p>
          <a href="/studio" className="btn-gold mt-5 inline-flex">Open Studio</a>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="feed-snap relative h-full overflow-y-auto bg-black"
      onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}
    >
      {pullY > 0 && (
        <motion.div style={{ height: pullY }} className="flex items-end justify-center pb-2 text-nvme-gold">
          <RefreshCw size={22} className={pullY > 70 ? 'animate-spin' : ''} />
        </motion.div>
      )}
      {items.map((v, i) => (
        <div key={v.id || i} data-idx={i} className="h-full w-full">
          <VideoCard
            video={v}
            isActive={activeIdx === i}
            registerRef={(el) => { el ? videoEls.current.set(i, el) : videoEls.current.delete(i); }}
            ref={(el) => { el ? cardEls.current.set(i, el) : cardEls.current.delete(i); }}
          />
        </div>
      ))}
      {query.isFetchingNextPage && (
        <div className="flex h-24 items-center justify-center text-nvme-gold"><Loader2 className="animate-spin" /></div>
      )}
    </div>
  );
}

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\components\VideoCard.tsx" -Raw
'use client';
import { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Heart, MessageCircle, Share2, Bookmark, Music2, X, Send, Loader2, ImagePlus } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { videos, type NvmeVideo, type NvmeComment } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { formatCount, gradientFor, cn } from '@/lib/utils';

interface Props {
  video: NvmeVideo;
  isActive: boolean;
  registerRef: (el: HTMLVideoElement | null) => void;
}

const VideoCard = forwardRef<HTMLDivElement, Props>(function VideoCard({ video, isActive, registerRef }, ref) {
  const [liked, setLiked] = useState(false);
  const [likeCount, setLikeCount] = useState(video.like_count || 0);
  const [commentCount, setCommentCount] = useState(video.comment_count || 0);
  const [saved, setSaved] = useState(false);
  const [muted, setMuted] = useState(true);
  const [heartBurst, setHeartBurst] = useState<number | null>(null);
  const [commentsOpen, setCommentsOpen] = useState(false);
  const [commentText, setCommentText] = useState('');
  const [commentImg, setCommentImg] = useState<string | null>(null);
  const localVid = useRef<HTMLVideoElement | null>(null);
  const lastTap = useRef(0);
  const qc = useQueryClient();
  const { openAuth } = useAuthStore();

  useEffect(() => {
    if (localVid.current) localVid.current.muted = muted;
  }, [muted]);

  const doLike = useCallback(async () => {
    if (liked) return;
    setLiked(true);
    setLikeCount((c) => c + 1);
    try { await videos.like(video.id); } catch { setLiked(false); setLikeCount((c) => Math.max(0, c - 1)); }
  }, [liked, video.id]);

  function onTap() {
    const now = Date.now();
    if (now - lastTap.current < 280) {
      // double-tap â†’ like + heart burst
      setHeartBurst(now);
      doLike();
      lastTap.current = 0;
      return;
    }
    lastTap.current = now;
    setTimeout(() => {
      if (lastTap.current && Date.now() - lastTap.current >= 280) {
        const v = localVid.current;
        if (v) { v.paused ? v.play().catch(() => {}) : v.pause(); }
        lastTap.current = 0;
      }
    }, 290);
  }

  const commentsQuery = useQuery({
    queryKey: ['comments', video.id],
    queryFn: () => videos.comments(video.id),
    enabled: commentsOpen,
    staleTime: 60_000
  });

  const postMutation = useMutation({
    mutationFn: () => videos.postComment(video.id, commentText, commentImg),
    onSuccess: () => {
      setCommentText(''); setCommentImg(null);
      setCommentCount((c) => c + 1);
      qc.invalidateQueries({ queryKey: ['comments', video.id] });
    }
  });

  function attachPhoto(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const img = new Image();
    const url = URL.createObjectURL(f);
    img.onload = () => {
      const MAX = 900;
      const scale = Math.min(1, MAX / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      c.getContext('2d')!.drawImage(img, 0, 0, c.width, c.height);
      setCommentImg(c.toDataURL('image/jpeg', 0.8));
      URL.revokeObjectURL(url);
    };
    img.src = url;
  }

  function share() {
    const url = `${location.origin}/feed?v=${video.id}`;
    if (navigator.share) navigator.share({ title: video.title || 'NVME', url }).catch(() => {});
    else navigator.clipboard?.writeText(url);
  }

  return (
    <div ref={ref} className="feed-snap-item relative h-full w-full overflow-hidden bg-black" onClick={onTap}>
      <video
        ref={(el) => { localVid.current = el; registerRef(el); }}
        className="absolute inset-0 h-full w-full object-cover"
        src={video.url}
        poster={video.thumbnail || undefined}
        loop muted playsInline preload="metadata"
        aria-label={video.title || 'NVME video'}
      />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-transparent to-black/40" />

      {/* Double-tap heart burst */}
      <AnimatePresence>
        {heartBurst && (
          <motion.div key={heartBurst}
            initial={{ scale: 0, opacity: 0 }} animate={{ scale: [0, 1.4, 1], opacity: [0, 1, 0.9], rotate: [0, -8, 0] }}
            exit={{ scale: 1.6, opacity: 0 }} transition={{ duration: 0.7 }}
            className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <Heart size={110} className="fill-nvme-coral text-nvme-coral drop-shadow-[0_0_30px_rgba(255,62,62,0.8)]" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Top-left creator chip */}
      <div className="absolute left-4 top-4 flex items-center gap-2.5" onClick={(e) => e.stopPropagation()}>
        <span className={cn('flex h-10 w-10 items-center justify-center overflow-hidden rounded-full border-2 border-nvme-gold bg-gradient-to-br text-sm font-black text-black', gradientFor(video.username))}>
          {video.avatar_url ? <img src={video.avatar_url} alt="" className="h-full w-full object-cover" /> : (video.username || 'N')[0].toUpperCase()}
        </span>
        <div>
          <p className="text-sm font-bold text-white drop-shadow">@{video.username || 'nvme'}</p>
          <p className="text-[10px] uppercase tracking-wider text-nvme-gold">NVME Creator</p>
        </div>
      </div>

      {/* Mute pill */}
      <button aria-label={muted ? 'Unmute' : 'Mute'} onClick={(e) => { e.stopPropagation(); setMuted(!muted); }}
        className="focus-ring absolute right-4 top-4 rounded-full bg-black/50 px-3 py-1.5 text-xs font-bold backdrop-blur">
        {muted ? 'ðŸ”‡' : 'ðŸ”Š'}
      </button>

      {/* Right action rail */}
      <div className="absolute bottom-24 right-3 flex flex-col items-center gap-5" onClick={(e) => e.stopPropagation()}>
        <motion.button whileTap={{ scale: 0.75 }} aria-label="Like" onClick={doLike} className="flex flex-col items-center gap-1">
          <motion.span animate={liked ? { scale: [1, 1.5, 1] } : {}} transition={{ type: 'spring', stiffness: 500, damping: 12 }}>
            <Heart size={30} className={liked ? 'fill-nvme-coral text-nvme-coral' : 'text-white'} />
          </motion.span>
          <span className="text-xs font-bold">{formatCount(likeCount)}</span>
        </motion.button>
        <button aria-label="Comments" onClick={() => setCommentsOpen(true)} className="flex flex-col items-center gap-1">
          <MessageCircle size={30} className="text-white" />
          <span className="text-xs font-bold">{formatCount(commentCount)}</span>
        </button>
        <button aria-label="Share" onClick={share} className="flex flex-col items-center gap-1">
          <Share2 size={30} className="text-white" />
          <span className="text-xs font-bold">Share</span>
        </button>
        <button aria-label="Save" onClick={() => setSaved(!saved)} className="flex flex-col items-center gap-1">
          <Bookmark size={30} className={saved ? 'fill-nvme-gold text-nvme-gold' : 'text-white'} />
          <span className="text-xs font-bold">Save</span>
        </button>
      </div>

      {/* Caption + music */}
      <div className="absolute bottom-6 left-4 right-20" onClick={(e) => e.stopPropagation()}>
        <p className="line-clamp-2 text-sm text-white/95">{video.description || video.title || ''}</p>
        <p className="mt-2 flex items-center gap-2 text-xs text-nvme-muted">
          <Music2 size={13} className="text-nvme-gold" />
          <span className="animate-pulse">original sound â€” @{video.username || 'nvme'}</span>
        </p>
      </div>

      {/* Comments sheet */}
      <AnimatePresence>
        {commentsOpen && (
          <motion.div initial={{ y: '100%' }} animate={{ y: 0 }} exit={{ y: '100%' }} transition={{ type: 'spring', damping: 30, stiffness: 280 }}
            className="absolute inset-x-0 bottom-0 z-20 flex max-h-[72%] flex-col rounded-t-3xl border-t border-nvme-gold/20 bg-nvme-surface"
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-3.5">
              <p className="text-sm font-bold">{formatCount(commentCount)} comments</p>
              <button aria-label="Close comments" onClick={() => setCommentsOpen(false)} className="focus-ring rounded-full p-1.5 text-nvme-muted hover:text-white"><X size={18} /></button>
            </div>
            <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
              {commentsQuery.isLoading && <p className="py-6 text-center text-sm text-nvme-muted"><Loader2 className="mx-auto animate-spin" /></p>}
              {commentsQuery.isError && <p className="py-6 text-center text-sm text-nvme-coral">Couldn&apos;t load comments. Tap to retry.</p>}
              {commentsQuery.data?.length === 0 && <p className="py-6 text-center text-sm text-nvme-muted">Be the first to comment âœ¨</p>}
              {(commentsQuery.data || []).map((c: NvmeComment) => (
                <div key={c.id} className="flex gap-3">
                  <span className={cn('flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-[11px] font-black text-black', gradientFor(c.username))}>
                    {c.avatar_url ? <img src={c.avatar_url} alt="" className="h-full w-full object-cover" /> : (c.username || 'N')[0].toUpperCase()}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-nvme-gold">@{c.username} <span className="font-normal text-nvme-muted">{c.display_name}</span></p>
                    {c.text && <p className="mt-0.5 text-sm text-white/90">{c.text}</p>}
                    {c.image_url && <img src={c.image_url} alt="comment attachment" className="mt-2 max-h-40 rounded-xl" />}
                  </div>
                </div>
              ))}
            </div>
            <div className="border-t border-white/5 p-3">
              {commentImg && (
                <div className="relative mb-2 inline-block">
                  <img src={commentImg} alt="preview" className="h-14 rounded-lg" />
                  <button aria-label="Remove photo" onClick={() => setCommentImg(null)} className="absolute -right-1.5 -top-1.5 rounded-full bg-nvme-coral p-0.5"><X size={12} /></button>
                </div>
              )}
              <div className="flex items-center gap-2">
                <label aria-label="Attach photo" className="cursor-pointer rounded-full p-2 text-nvme-muted transition-colors hover:text-nvme-gold">
                  <ImagePlus size={20} /><input type="file" accept="image/*" className="hidden" onChange={attachPhoto} />
                </label>
                <input value={commentText} onChange={(e) => setCommentText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (commentText.trim() || commentImg) && postMutation.mutate()}
                  placeholder="Add a comment..."
                  className="flex-1 rounded-full border border-white/10 bg-black/40 px-4 py-2.5 text-sm outline-none focus:border-nvme-gold" />
                <button aria-label="Post comment" disabled={(!commentText.trim() && !commentImg) || postMutation.isPending}
                  onClick={() => postMutation.mutate()}
                  className="focus-ring rounded-full bg-nvme-gold p-2.5 text-black transition-all hover:bg-nvme-goldlight disabled:opacity-40">
                  {postMutation.isPending ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
});

export default VideoCard;

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\components\VideoCard.tsx" -Raw
'use client';
import { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Heart, MessageCircle, Share2, Bookmark, Music2, X, Send, Loader2, ImagePlus } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { videos, type NvmeVideo, type NvmeComment } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { formatCount, gradientFor, cn } from '@/lib/utils';

interface Props {
  video: NvmeVideo;
  isActive: boolean;
  registerRef: (el: HTMLVideoElement | null) => void;
}

const VideoCard = forwardRef<HTMLDivElement, Props>(function VideoCard({ video, isActive, registerRef }, ref) {
  const [liked, setLiked] = useState(false);
  const [likeCount, setLikeCount] = useState(video.like_count || 0);
  const [commentCount, setCommentCount] = useState(video.comment_count || 0);
  const [saved, setSaved] = useState(false);
  const [muted, setMuted] = useState(true);
  const [heartBurst, setHeartBurst] = useState<number | null>(null);
  const [commentsOpen, setCommentsOpen] = useState(false);
  const [commentText, setCommentText] = useState('');
  const [commentImg, setCommentImg] = useState<string | null>(null);
  const localVid = useRef<HTMLVideoElement | null>(null);
  const lastTap = useRef(0);
  const qc = useQueryClient();
  const { openAuth } = useAuthStore();

  useEffect(() => {
    if (localVid.current) localVid.current.muted = muted;
  }, [muted]);

  const doLike = useCallback(async () => {
    if (liked) return;
    setLiked(true);
    setLikeCount((c) => c + 1);
    try { await videos.like(video.id); } catch { setLiked(false); setLikeCount((c) => Math.max(0, c - 1)); }
  }, [liked, video.id]);

  function onTap() {
    const now = Date.now();
    if (now - lastTap.current < 280) {
      // double-tap â†’ like + heart burst
      setHeartBurst(now);
      doLike();
      lastTap.current = 0;
      return;
    }
    lastTap.current = now;
    setTimeout(() => {
      if (lastTap.current && Date.now() - lastTap.current >= 280) {
        const v = localVid.current;
        if (v) { v.paused ? v.play().catch(() => {}) : v.pause(); }
        lastTap.current = 0;
      }
    }, 290);
  }

  const commentsQuery = useQuery({
    queryKey: ['comments', video.id],
    queryFn: () => videos.comments(video.id),
    enabled: commentsOpen,
    staleTime: 60_000
  });

  const postMutation = useMutation({
    mutationFn: () => videos.postComment(video.id, commentText, commentImg),
    onSuccess: () => {
      setCommentText(''); setCommentImg(null);
      setCommentCount((c) => c + 1);
      qc.invalidateQueries({ queryKey: ['comments', video.id] });
    }
  });

  function attachPhoto(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const img = new Image();
    const url = URL.createObjectURL(f);
    img.onload = () => {
      const MAX = 900;
      const scale = Math.min(1, MAX / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      c.getContext('2d')!.drawImage(img, 0, 0, c.width, c.height);
      setCommentImg(c.toDataURL('image/jpeg', 0.8));
      URL.revokeObjectURL(url);
    };
    img.src = url;
  }

  function share() {
    const url = `${location.origin}/feed?v=${video.id}`;
    if (navigator.share) navigator.share({ title: video.title || 'NVME', url }).catch(() => {});
    else navigator.clipboard?.writeText(url);
  }

  return (
    <div ref={ref} className="feed-snap-item relative h-full w-full overflow-hidden bg-black" onClick={onTap}>
      <video
        ref={(el) => { localVid.current = el; registerRef(el); }}
        className="absolute inset-0 h-full w-full object-cover"
        src={video.url}
        poster={video.thumbnail || undefined}
        loop muted playsInline preload="metadata"
        aria-label={video.title || 'NVME video'}
      />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-transparent to-black/40" />

      {/* Double-tap heart burst */}
      <AnimatePresence>
        {heartBurst && (
          <motion.div key={heartBurst}
            initial={{ scale: 0, opacity: 0 }} animate={{ scale: [0, 1.4, 1], opacity: [0, 1, 0.9], rotate: [0, -8, 0] }}
            exit={{ scale: 1.6, opacity: 0 }} transition={{ duration: 0.7 }}
            className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <Heart size={110} className="fill-nvme-coral text-nvme-coral drop-shadow-[0_0_30px_rgba(255,62,62,0.8)]" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Top-left creator chip */}
      <div className="absolute left-4 top-4 flex items-center gap-2.5" onClick={(e) => e.stopPropagation()}>
        <span className={cn('flex h-10 w-10 items-center justify-center overflow-hidden rounded-full border-2 border-nvme-gold bg-gradient-to-br text-sm font-black text-black', gradientFor(video.username))}>
          {video.avatar_url ? <img src={video.avatar_url} alt="" className="h-full w-full object-cover" /> : (video.username || 'N')[0].toUpperCase()}
        </span>
        <div>
          <p className="text-sm font-bold text-white drop-shadow">@{video.username || 'nvme'}</p>
          <p className="text-[10px] uppercase tracking-wider text-nvme-gold">NVME Creator</p>
        </div>
      </div>

      {/* Mute pill */}
      <button aria-label={muted ? 'Unmute' : 'Mute'} onClick={(e) => { e.stopPropagation(); setMuted(!muted); }}
        className="focus-ring absolute right-4 top-4 rounded-full bg-black/50 px-3 py-1.5 text-xs font-bold backdrop-blur">
        {muted ? 'ðŸ”‡' : 'ðŸ”Š'}
      </button>

      {/* Right action rail */}
      <div className="absolute bottom-24 right-3 flex flex-col items-center gap-5" onClick={(e) => e.stopPropagation()}>
        <motion.button whileTap={{ scale: 0.75 }} aria-label="Like" onClick={doLike} className="flex flex-col items-center gap-1">
          <motion.span animate={liked ? { scale: [1, 1.5, 1] } : {}} transition={{ type: 'spring', stiffness: 500, damping: 12 }}>
            <Heart size={30} className={liked ? 'fill-nvme-coral text-nvme-coral' : 'text-white'} />
          </motion.span>
          <span className="text-xs font-bold">{formatCount(likeCount)}</span>
        </motion.button>
        <button aria-label="Comments" onClick={() => setCommentsOpen(true)} className="flex flex-col items-center gap-1">
          <MessageCircle size={30} className="text-white" />
          <span className="text-xs font-bold">{formatCount(commentCount)}</span>
        </button>
        <button aria-label="Share" onClick={share} className="flex flex-col items-center gap-1">
          <Share2 size={30} className="text-white" />
          <span className="text-xs font-bold">Share</span>
        </button>
        <button aria-label="Save" onClick={() => setSaved(!saved)} className="flex flex-col items-center gap-1">
          <Bookmark size={30} className={saved ? 'fill-nvme-gold text-nvme-gold' : 'text-white'} />
          <span className="text-xs font-bold">Save</span>
        </button>
      </div>

      {/* Caption + music */}
      <div className="absolute bottom-6 left-4 right-20" onClick={(e) => e.stopPropagation()}>
        <p className="line-clamp-2 text-sm text-white/95">{video.description || video.title || ''}</p>
        <p className="mt-2 flex items-center gap-2 text-xs text-nvme-muted">
          <Music2 size={13} className="text-nvme-gold" />
          <span className="animate-pulse">original sound â€” @{video.username || 'nvme'}</span>
        </p>
      </div>

      {/* Comments sheet */}
      <AnimatePresence>
        {commentsOpen && (
          <motion.div initial={{ y: '100%' }} animate={{ y: 0 }} exit={{ y: '100%' }} transition={{ type: 'spring', damping: 30, stiffness: 280 }}
            className="absolute inset-x-0 bottom-0 z-20 flex max-h-[72%] flex-col rounded-t-3xl border-t border-nvme-gold/20 bg-nvme-surface"
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-3.5">
              <p className="text-sm font-bold">{formatCount(commentCount)} comments</p>
              <button aria-label="Close comments" onClick={() => setCommentsOpen(false)} className="focus-ring rounded-full p-1.5 text-nvme-muted hover:text-white"><X size={18} /></button>
            </div>
            <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
              {commentsQuery.isLoading && <p className="py-6 text-center text-sm text-nvme-muted"><Loader2 className="mx-auto animate-spin" /></p>}
              {commentsQuery.isError && <p className="py-6 text-center text-sm text-nvme-coral">Couldn&apos;t load comments. Tap to retry.</p>}
              {commentsQuery.data?.length === 0 && <p className="py-6 text-center text-sm text-nvme-muted">Be the first to comment âœ¨</p>}
              {(commentsQuery.data || []).map((c: NvmeComment) => (
                <div key={c.id} className="flex gap-3">
                  <span className={cn('flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-[11px] font-black text-black', gradientFor(c.username))}>
                    {c.avatar_url ? <img src={c.avatar_url} alt="" className="h-full w-full object-cover" /> : (c.username || 'N')[0].toUpperCase()}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-nvme-gold">@{c.username} <span className="font-normal text-nvme-muted">{c.display_name}</span></p>
                    {c.text && <p className="mt-0.5 text-sm text-white/90">{c.text}</p>}
                    {c.image_url && <img src={c.image_url} alt="comment attachment" className="mt-2 max-h-40 rounded-xl" />}
                  </div>
                </div>
              ))}
            </div>
            <div className="border-t border-white/5 p-3">
              {commentImg && (
                <div className="relative mb-2 inline-block">
                  <img src={commentImg} alt="preview" className="h-14 rounded-lg" />
                  <button aria-label="Remove photo" onClick={() => setCommentImg(null)} className="absolute -right-1.5 -top-1.5 rounded-full bg-nvme-coral p-0.5"><X size={12} /></button>
                </div>
              )}
              <div className="flex items-center gap-2">
                <label aria-label="Attach photo" className="cursor-pointer rounded-full p-2 text-nvme-muted transition-colors hover:text-nvme-gold">
                  <ImagePlus size={20} /><input type="file" accept="image/*" className="hidden" onChange={attachPhoto} />
                </label>
                <input value={commentText} onChange={(e) => setCommentText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (commentText.trim() || commentImg) && postMutation.mutate()}
                  placeholder="Add a comment..."
                  className="flex-1 rounded-full border border-white/10 bg-black/40 px-4 py-2.5 text-sm outline-none focus:border-nvme-gold" />
                <button aria-label="Post comment" disabled={(!commentText.trim() && !commentImg) || postMutation.isPending}
                  onClick={() => postMutation.mutate()}
                  className="focus-ring rounded-full bg-nvme-gold p-2.5 text-black transition-all hover:bg-nvme-goldlight disabled:opacity-40">
                  {postMutation.isPending ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
});

export default VideoCard;

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\app\feed\page.tsx" -Raw
'use client';
import VideoFeed from '@/components/VideoFeed';

export default function FeedPage() {
  return (
    <div className="fixed inset-0 top-0 bg-black pt-16">
      <VideoFeed />
    </div>
  );
}

PS C:\Users\Digital King\nvme-platform> Get-Content ".\frontend\app\page.tsx" -Raw
'use client';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Users, Crown, Globe2, Music2, UploadCloud, BadgeDollarSign, Film, Sparkles } from 'lucide-react';
import SectionWrapper, { SectionTitle } from '@/components/SectionWrapper';
import AnimatedCounter from '@/components/AnimatedCounter';
import Footer from '@/components/Footer';
import { useAuth } from '@/hooks/useAuth';
import { useQuery } from '@tanstack/react-query';
import { users as usersApi, type NvmeUser } from '@/lib/api';
import { formatCount, gradientFor, cn } from '@/lib/utils';

const CATS = ['Music', 'Comedy', 'Film', 'Dance', 'Fashion', 'Gaming'];
const TEES = [
  { name: 'Blackout Tee', grad: 'from-zinc-900 to-zinc-700' },
  { name: 'Gold Standard', grad: 'from-[#c9a227] to-[#7a5f10]' },
  { name: 'Coral Run', grad: 'from-[#ff3e3e] to-[#7a1414]' },
  { name: 'White Label', grad: 'from-zinc-200 to-zinc-400' }
];

export default function LandingPage() {
  const { isAuthenticated, openAuth } = useAuth();

  const statsQ = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      try {
        const r = await fetch('/api/stats');
        if (!r.ok) throw new Error();
        return r.json();
      } catch {
        return { creators: 2847291, watched: 892000000 };
      }
    },
    staleTime: 5 * 60 * 1000
  });

  const creatorsQ = useQuery({
    queryKey: ['creators', 'featured'],
    queryFn: () => usersApi.discover(),
    staleTime: 5 * 60 * 1000,
    retry: false
  });

  const featured: NvmeUser[] = (creatorsQ.data || []).slice(0, 6);

  return (
    <div className="relative">
      {/* ---------- HERO ---------- */}
      <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-[radial-gradient(ellipse_at_top,rgba(201,162,39,0.12),transparent_55%)] px-6 text-center">
        <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="mb-5 inline-flex items-center gap-2 rounded-full border border-nvme-gold/30 bg-nvme-gold/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.25em] text-nvme-gold">
          <Sparkles size={13} /> The Future of Short Video Entertainment
        </motion.p>
        <h1 className="font-display text-[13vw] leading-[0.95] tracking-wider sm:text-7xl md:text-8xl">
          {['WATCH.', 'CREATE.', 'EARN.'].map((w, i) => (
            <motion.span key={w} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 + i * 0.15, duration: 0.6 }}
              className={cn('block', i === 2 && 'bg-gradient-to-r from-nvme-gold to-nvme-coral bg-clip-text text-transparent')}>
              {w}
            </motion.span>
          ))}
        </h1>
        <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.7, duration: 0.6 }}
          className="mt-6 max-w-xl text-base leading-relaxed text-nvme-muted sm:text-lg">
          NVME is where audiences earn, creators grow, and digital ownership expands.
          This is bigger than content. This is an economy.
        </motion.p>
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-4">
          {isAuthenticated
            ? <Link href="/studio" className="btn-gold animate-pulse-gold">Start Creating</Link>
            : <button onClick={() => openAuth('signup')} className="btn-gold animate-pulse-gold">Start Creating</button>}
          <Link href="/feed" className="btn-outline">Explore Feed</Link>
        </motion.div>

        {/* Stats bar */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.1 }}
          className="absolute bottom-0 left-0 right-0 border-t border-white/5 bg-black/50 backdrop-blur-md">
          <div className="mx-auto grid max-w-5xl grid-cols-1 divide-y divide-white/5 py-5 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <div className="py-2 text-center">
              <p className="font-display text-2xl text-nvme-gold"><AnimatedCounter target={statsQ.data?.creators ?? 2847291} /></p>
              <p className="text-xs uppercase tracking-widest text-nvme-muted">Creators on NVME</p>
            </div>
            <div className="py-2 text-center">
              <p className="font-display text-2xl text-nvme-gold"><AnimatedCounter target={statsQ.data?.watched ?? 892000000} /></p>
              <p className="text-xs uppercase tracking-widest text-nvme-muted">Videos Watched</p>
            </div>
            <div className="flex items-center justify-center gap-2 py-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-nvme-gold opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-nvme-gold" />
              </span>
              <p className="text-sm font-semibold text-white">New creators joining now</p>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ---------- FEATURED CREATORS ---------- */}
      <SectionWrapper>
        <SectionTitle title="Featured Creators" subtitle="Support creators building with the NVME community." />
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {(featured.length > 0 ? featured : Array.from({ length: 6 }).map((_, i) => ({ id: `ph-${i}`, username: ['Nova', 'KingMel', 'AyoBeats', 'QueenJ', 'TrapScribe', 'LunaVibe'][i], followers: 12000 + i * 3700 } as NvmeUser))).map((c, i) => (
            <motion.div key={c.id}
              initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
              className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-6">
              <div className="flex items-center gap-4">
                <span className={cn('flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-lg font-black text-black ring-2 ring-nvme-gold/40', gradientFor(c.username))}>
                  {c.avatar_url ? <img src={c.avatar_url} alt="" className="h-full w-full object-cover" /> : (c.username || 'N')[0].toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-bold">{c.display_name || c.username}</p>
                  <p className="text-xs text-nvme-muted">{CATS[i % CATS.length]} Â· {formatCount(c.followers)} followers</p>
                </div>
              </div>
              <button
                onClick={async () => { try { await usersApi.follow(c.id); } catch { /* not signed in */ } }}
                className="mt-5 w-full rounded-full border border-nvme-gold/50 py-2 text-sm font-bold text-nvme-gold transition-all hover:bg-nvme-gold hover:text-black">
                Follow
              </button>
            </motion.div>
          ))}
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.6 }}
            className="flex flex-col items-center justify-center rounded-2xl bg-gradient-to-br from-nvme-gold to-[#8a6d15] p-6 text-center text-black">
            <Crown size={30} />
            <p className="mt-3 font-display text-lg leading-snug">BE ONE OF THE FIRST FEATURED CREATORS</p>
            <Link href="/studio" className="mt-4 rounded-full bg-black px-6 py-2.5 text-sm font-bold text-nvme-gold transition-all hover:scale-[1.03]">Apply Now</Link>
          </motion.div>
        </div>
      </SectionWrapper>

      {/* ---------- NVME UNIFORM ---------- */}
      <SectionWrapper className="!max-w-none bg-nvme-surface/40">
        <div className="mx-auto max-w-7xl">
          <SectionTitle title="THE NVME UNIFORM" subtitle="Wear The Platform. Represent The Culture." />
          <div className="grid items-center gap-10 lg:grid-cols-2">
            <div>
              <ul className="space-y-4">
                {['Support creator-owned digital infrastructure', 'Help fund creators, films, and original content', 'Represent the movement everywhere you go'].map((b, i) => (
                  <motion.li key={b} initial={{ opacity: 0, x: -16 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
                    className="flex items-start gap-3 text-base text-white/90">
                    <span className="mt-1 h-2 w-2 shrink-0 rotate-45 bg-nvme-gold" /> {b}
                  </motion.li>
                ))}
              </ul>
              <a href="https://store.nvme.live" target="_blank" rel="noreferrer" className="btn-gold mt-8">ORDER NOW â€” STORE.NVME.LIVE</a>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {TEES.map((t, i) => (
                <motion.div key={t.name} initial={{ opacity: 0, scale: 0.94 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} transition={{ delay: i * 0.08 }}
                  className={cn('card-hover flex aspect-[3/4] flex-col items-center justify-end rounded-2xl border border-white/10 bg-gradient-to-br p-4', t.grad)}>
                  <p className="font-display text-sm tracking-wider drop-shadow">{t.name.toUpperCase()}</p>
                  <p className="text-[10px] uppercase tracking-[0.3em] opacity-80">NVME</p>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </SectionWrapper>

      {/* ---------- NVME NATION ---------- */}
      <SectionWrapper>
        <SectionTitle title="NVME Nation" subtitle="This is more than a platform. This is a digital kingdom." />
        <div className="grid gap-5 md:grid-cols-3">
          {[
            { icon: Users, t: 'Be part of a powerful creator community' },
            { icon: Crown, t: 'Create, shop, and own your content' },
            { icon: Globe2, t: 'Connect with creators worldwide' }
          ].map((f, i) => (
            <motion.div key={f.t} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
              className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-8 text-center">
              <f.icon size={34} className="mx-auto text-nvme-gold" />
              <p className="mt-4 font-semibold leading-relaxed">{f.t}</p>
            </motion.div>
          ))}
        </div>
        <div className="mt-10 text-center">
          {isAuthenticated
            ? <Link href="/feed" className="btn-gold">Enter the Nation</Link>
            : <button onClick={() => openAuth('signup')} className="btn-gold">Join NVME Nation</button>}
        </div>
      </SectionWrapper>

      {/* ---------- NVME MUSIC ---------- */}
      <SectionWrapper className="!max-w-none bg-[radial-gradient(ellipse_at_bottom,rgba(255,62,62,0.08),transparent_60%)]">
        <div className="mx-auto max-w-7xl">
          <SectionTitle title="NVME Music" subtitle="A new era for independent artists." />
          <div className="grid gap-5 md:grid-cols-3">
            {[
              { icon: Globe2, t: 'Get discovered globally' },
              { icon: UploadCloud, t: 'Upload and monetize instantly' },
              { icon: BadgeDollarSign, t: 'Earn 70%+ revenue' }
            ].map((f, i) => (
              <motion.div key={f.t} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}
                className="card-hover rounded-2xl border border-nvme-border bg-nvme-surface p-8 text-center">
                <f.icon size={34} className="mx-auto text-nvme-gold" />
                <p className="mt-4 font-semibold">{f.t}</p>
              </motion.div>
            ))}
          </div>
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="mt-10 flex flex-col items-center gap-4 rounded-2xl border border-nvme-gold/25 bg-black/40 p-8 text-center">
            <Film size={30} className="text-nvme-gold" />
            <h3 className="font-display text-2xl tracking-wide">Distribute Your Film on NVME Networks</h3>
            <p className="max-w-2xl text-sm leading-relaxed text-nvme-muted">
              Filmmakers: bring your shorts, docs, and features to a platform built for ownership.
              Keep your rights, reach a global audience, and get paid directly by the culture you move.
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <Link href="/discover?cat=Music" className="btn-gold">Explore NVME Music</Link>
              <Link href="/studio" className="btn-outline">Submit Your Film</Link>
            </div>
          </motion.div>
        </div>
      </SectionWrapper>

      <Footer />
    </div>
  );
}

PS C:\Users\Digital King\nvme-platform> Get-Content ".\db\schema.sql" -Raw
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name VARCHAR(100),
  avatar_url TEXT,
  bio TEXT,
  is_creator BOOLEAN DEFAULT FALSE,
  is_verified BOOLEAN DEFAULT FALSE,
  is_banned BOOLEAN DEFAULT FALSE,
  balance_credits NUMERIC(12,2) DEFAULT 0.00,
  total_earned NUMERIC(12,2) DEFAULT 0.00,
  paypal_email VARCHAR(255),
  follower_count INTEGER DEFAULT 0,
  following_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE videos (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  video_url TEXT NOT NULL,
  thumbnail_url TEXT,
  duration_seconds INTEGER,
  view_count INTEGER DEFAULT 0,
  like_count INTEGER DEFAULT 0,
  comment_count INTEGER DEFAULT 0,
  is_published BOOLEAN DEFAULT FALSE,
  is_premium BOOLEAN DEFAULT FALSE,
  price_credits NUMERIC(10,2) DEFAULT 0.00,
  tags TEXT[],
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE livestreams (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  stream_key TEXT UNIQUE NOT NULL,
  playback_url TEXT,
  thumbnail_url TEXT,
  status VARCHAR(20) DEFAULT 'offline' CHECK (status IN ('offline','live','ended')),
  viewer_count INTEGER DEFAULT 0,
  peak_viewer_count INTEGER DEFAULT 0,
  total_gifts_received NUMERIC(12,2) DEFAULT 0.00,
  is_premium BOOLEAN DEFAULT FALSE,
  price_credits NUMERIC(10,2) DEFAULT 0.00,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Backward-compat view for any external tools referencing live_streams
CREATE OR REPLACE VIEW live_streams AS SELECT * FROM livestreams;

CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  subscriber_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tier VARCHAR(50) DEFAULT 'basic',
  price_usd NUMERIC(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active','cancelled','expired','paused')),
  paypal_subscription_id VARCHAR(255) UNIQUE,
  current_period_start TIMESTAMPTZ NOT NULL,
  current_period_end TIMESTAMPTZ NOT NULL,
  cancelled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(subscriber_id, creator_id)
);

CREATE TABLE transactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL CHECK (type IN ('credit_purchase','gift_sent','gift_received','subscription','withdrawal','refund','tip')),
  amount_usd NUMERIC(10,2) NOT NULL,
  credits_amount NUMERIC(10,2),
  status VARCHAR(20) DEFAULT 'completed',
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE gifts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  emoji VARCHAR(20),
  icon_url TEXT,
  credit_cost NUMERIC(10,2) NOT NULL,
  usd_value NUMERIC(10,2) NOT NULL,
  creator_pct NUMERIC(5,2) DEFAULT 70.00,
  platform_pct NUMERIC(5,2) DEFAULT 30.00,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE stream_guests (
  id SERIAL PRIMARY KEY,
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  guest_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guest_username VARCHAR(100),
  guest_avatar TEXT,
  status VARCHAR(20) DEFAULT 'invited',
  slot INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(stream_id, guest_user_id)
);

CREATE TABLE livestream_chat (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE jackpot_pool (
  id INTEGER PRIMARY KEY DEFAULT 1,
  pool NUMERIC(12,2) DEFAULT 25000,
  total_entries INTEGER DEFAULT 0,
  total_paid NUMERIC(12,2) DEFAULT 0,
  last_winner_username VARCHAR(100),
  last_won_at TIMESTAMPTZ
);


-- â”€â”€ BATTLE SYSTEM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS stream_battles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  host_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  battle_type VARCHAR(20) DEFAULT 'ffa' CHECK (battle_type IN ('ffa','team')),
  status VARCHAR(20) DEFAULT 'waiting' CHECK (status IN ('waiting','active','ended')),
  max_participants INTEGER DEFAULT 20,
  team_a_name VARCHAR(50) DEFAULT 'Team A',
  team_b_name VARCHAR(50) DEFAULT 'Team B',
  elimination_interval_seconds INTEGER DEFAULT 60,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  winner_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS battle_participants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  battle_id UUID NOT NULL REFERENCES stream_battles(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team VARCHAR(10) DEFAULT 'a' CHECK (team IN ('a','b')),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active','eliminated','winner')),
  gifts_received NUMERIC(12,2) DEFAULT 0,
  votes INTEGER DEFAULT 0,
  eliminated_at TIMESTAMPTZ,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(battle_id, user_id)
);

-- â”€â”€ PRIVACY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT FALSE;

-- â”€â”€ EPIC STUDIOS TRANSFER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS epic_transfers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epic_username VARCHAR(100) NOT NULL,
  epic_diamonds INTEGER DEFAULT 0,
  epic_level INTEGER DEFAULT 1,
  diamonds_converted NUMERIC(12,2) DEFAULT 0,
  transfer_status VARCHAR(20) DEFAULT 'pending' CHECK (transfer_status IN ('pending','completed','failed')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- â”€â”€ FOUNDER BADGES & LEVELS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ALTER TABLE users ADD COLUMN IF NOT EXISTS join_rank INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS founder_badge VARCHAR(20);
ALTER TABLE users ADD COLUMN IF NOT EXISTS level INTEGER DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS diamond_balance NUMERIC(12,2) DEFAULT 0;

-- Auto-assign founder badges to first 100/1000 users (silent, no error if already set)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE join_rank IS NULL LIMIT 1) THEN
    UPDATE users SET
      join_rank = sub.rank,
      founder_badge = CASE
        WHEN sub.rank <= 100 THEN 'founder-100'
        WHEN sub.rank <= 1000 THEN 'founder-1000'
        ELSE NULL
      END
    FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) as rank FROM users) sub
    WHERE users.id = sub.id AND users.join_rank IS NULL;
  END IF;
END $$;

-- â”€â”€ BATTLE INVITES (live user â†’ live user) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS battle_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending','accepted','declined','expired')),
  battle_id UUID REFERENCES stream_battles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  responded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_battle_invites_to_user ON battle_invites(to_user_id, status);
CREATE INDEX IF NOT EXISTS idx_battle_invites_from_user ON battle_invites(from_user_id, status);


PS C:\Users\Digital King\nvme-platform> Get-Content ".\db\migration_002_social_features.sql" -Raw
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
-- Migration 002: social features + auth fields the frontend already expects
-- Safe to re-run â€” every statement is idempotent (IF NOT EXISTS / WHERE NOT EXISTS).
-- Run with: npm run migrate
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

-- â”€â”€ USERNAME (both frontends require it; base schema only has display_name) â”€â”€
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(255);

-- Backfill any existing rows that predate the column, so the UNIQUE constraint
-- doesn't choke on NULLs colliding (Postgres allows multiple NULLs under
-- UNIQUE, so this is only a courtesy backfill, not strictly required).
UPDATE users SET username = 'user_' || substr(id::text, 1, 8)
WHERE username IS NULL;

-- â”€â”€ LIKES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (video_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_video ON likes(video_id);
CREATE INDEX IF NOT EXISTS idx_likes_user ON likes(user_id);

-- â”€â”€ COMMENTS (schema only ever had a comment_count counter, no rows) â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  image_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id, created_at DESC);

-- â”€â”€ FOLLOWS (simple free follow; `subscriptions` table is paid-tier only) â”€â”€
CREATE TABLE IF NOT EXISTS follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (follower_id, following_id),
  CHECK (follower_id != following_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);

-- â”€â”€ GIFT TRANSACTIONS (schema's `gifts` table is a catalog of gift TYPES â€”
-- there was never a table logging who-sent-what-to-whom) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
-- DROP + recreate rather than IF NOT EXISTS: an earlier partial run left a
-- gift_transactions table missing the to_user_id column, which then made
-- CREATE TABLE IF NOT EXISTS silently skip it and broke the index below.
-- Nothing could have written real rows here yet (the only writer,
-- /api/gifts/send, would 500 without to_user_id), so dropping is safe.
DROP TABLE IF EXISTS gift_transactions CASCADE;
CREATE TABLE gift_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gift_id UUID NOT NULL REFERENCES gifts(id),
  stream_id UUID REFERENCES livestreams(id) ON DELETE SET NULL,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  quantity INTEGER DEFAULT 1,
  credits_spent NUMERIC(12,2) NOT NULL,
  creator_credits NUMERIC(12,2) NOT NULL,
  platform_credits NUMERIC(12,2) NOT NULL,
  message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gift_tx_stream ON gift_transactions(stream_id);
CREATE INDEX IF NOT EXISTS idx_gift_tx_to_user ON gift_transactions(to_user_id);

-- â”€â”€ SEED DEFAULT GIFT CATALOG (matches the values server.js used to
-- hardcode: crown/rocket/heart/star/diamond) â€” only inserts if missing â”€â”€â”€â”€â”€
-- The live `gifts` table has drifted from what schema.sql describes (it was
-- missing `emoji` here, and possibly other columns below) â€” these
-- ALTER...ADD COLUMN IF NOT EXISTS calls self-heal it to match schema.sql's
-- definition before the seed insert runs, regardless of what's actually
-- there today.
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS emoji VARCHAR(20);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS icon_url TEXT;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS credit_cost NUMERIC(10,2);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS usd_value NUMERIC(10,2);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS creator_pct NUMERIC(5,2) DEFAULT 70.00;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS platform_pct NUMERIC(5,2) DEFAULT 30.00;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
INSERT INTO gifts (name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
SELECT * FROM (VALUES
  ('Heart',   'â¤ï¸', 10::numeric,  10::numeric, 70::numeric, 30::numeric),
  ('Star',    'â­', 5::numeric,   5::numeric,  70::numeric, 30::numeric),
  ('Crown',   'ðŸ‘‘', 50::numeric,  50::numeric, 70::numeric, 30::numeric),
  ('Rocket',  'ðŸš€', 100::numeric, 100::numeric,70::numeric, 30::numeric),
  ('Diamond', 'ðŸ’Ž', 200::numeric, 200::numeric,70::numeric, 30::numeric)
) AS v(name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
WHERE NOT EXISTS (SELECT 1 FROM gifts g WHERE g.name = v.name);

PS C:\Users\Digital King\nvme-platform> Get-Content ".\db\migration_002_social_features.sql" -Raw
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
-- Migration 002: social features + auth fields the frontend already expects
-- Safe to re-run â€” every statement is idempotent (IF NOT EXISTS / WHERE NOT EXISTS).
-- Run with: npm run migrate
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

-- â”€â”€ USERNAME (both frontends require it; base schema only has display_name) â”€â”€
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(255);

-- Backfill any existing rows that predate the column, so the UNIQUE constraint
-- doesn't choke on NULLs colliding (Postgres allows multiple NULLs under
-- UNIQUE, so this is only a courtesy backfill, not strictly required).
UPDATE users SET username = 'user_' || substr(id::text, 1, 8)
WHERE username IS NULL;

-- â”€â”€ LIKES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (video_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_video ON likes(video_id);
CREATE INDEX IF NOT EXISTS idx_likes_user ON likes(user_id);

-- â”€â”€ COMMENTS (schema only ever had a comment_count counter, no rows) â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  image_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id, created_at DESC);

-- â”€â”€ FOLLOWS (simple free follow; `subscriptions` table is paid-tier only) â”€â”€
CREATE TABLE IF NOT EXISTS follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (follower_id, following_id),
  CHECK (follower_id != following_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);

-- â”€â”€ GIFT TRANSACTIONS (schema's `gifts` table is a catalog of gift TYPES â€”
-- there was never a table logging who-sent-what-to-whom) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
-- DROP + recreate rather than IF NOT EXISTS: an earlier partial run left a
-- gift_transactions table missing the to_user_id column, which then made
-- CREATE TABLE IF NOT EXISTS silently skip it and broke the index below.
-- Nothing could have written real rows here yet (the only writer,
-- /api/gifts/send, would 500 without to_user_id), so dropping is safe.
DROP TABLE IF EXISTS gift_transactions CASCADE;
CREATE TABLE gift_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gift_id UUID NOT NULL REFERENCES gifts(id),
  stream_id UUID REFERENCES livestreams(id) ON DELETE SET NULL,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  quantity INTEGER DEFAULT 1,
  credits_spent NUMERIC(12,2) NOT NULL,
  creator_credits NUMERIC(12,2) NOT NULL,
  platform_credits NUMERIC(12,2) NOT NULL,
  message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gift_tx_stream ON gift_transactions(stream_id);
CREATE INDEX IF NOT EXISTS idx_gift_tx_to_user ON gift_transactions(to_user_id);

-- â”€â”€ SEED DEFAULT GIFT CATALOG (matches the values server.js used to
-- hardcode: crown/rocket/heart/star/diamond) â€” only inserts if missing â”€â”€â”€â”€â”€
-- The live `gifts` table has drifted from what schema.sql describes (it was
-- missing `emoji` here, and possibly other columns below) â€” these
-- ALTER...ADD COLUMN IF NOT EXISTS calls self-heal it to match schema.sql's
-- definition before the seed insert runs, regardless of what's actually
-- there today.
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS emoji VARCHAR(20);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS icon_url TEXT;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS credit_cost NUMERIC(10,2);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS usd_value NUMERIC(10,2);
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS creator_pct NUMERIC(5,2) DEFAULT 70.00;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS platform_pct NUMERIC(5,2) DEFAULT 30.00;
ALTER TABLE gifts ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
INSERT INTO gifts (name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
SELECT * FROM (VALUES
  ('Heart',   'â¤ï¸', 10::numeric,  10::numeric, 70::numeric, 30::numeric),
  ('Star',    'â­', 5::numeric,   5::numeric,  70::numeric, 30::numeric),
  ('Crown',   'ðŸ‘‘', 50::numeric,  50::numeric, 70::numeric, 30::numeric),
  ('Rocket',  'ðŸš€', 100::numeric, 100::numeric,70::numeric, 30::numeric),
  ('Diamond', 'ðŸ’Ž', 200::numeric, 200::numeric,70::numeric, 30::numeric)
) AS v(name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
WHERE NOT EXISTS (SELECT 1 FROM gifts g WHERE g.name = v.name);

PS C:\Users\Digital King\nvme-platform> Get-Content ".\db\migration_003_battles_goals.sql" -Raw
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
-- Migration 003: LIVE Battles + stream goals support
-- creator.html (Creator Studio) calls a battles/goals API that the base
-- schema's stream_battles/battle_participants/battle_invites tables don't
-- quite cover yet. Safe to re-run â€” idempotent.
-- Run with: npm run migrate:003  (see updated scripts/migrate.js)
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

-- â”€â”€ STREAM GOALS (creator.html's "Set Goal" panel â€” target/reward/current
-- gift progress toward a stream milestone) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_target NUMERIC(12,2);
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_reward TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_current NUMERIC(12,2) DEFAULT 0;

-- â”€â”€ BATTLE PARTICIPANT BACKGROUNDS (creator.html lets a battler upload a
-- custom background image mid-battle, stored as a data URL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ALTER TABLE battle_participants ADD COLUMN IF NOT EXISTS background_url TEXT;

-- â”€â”€ BATTLE ATTACK LOG (creator.html's gift-based "attack" mechanic â€” needs
-- its own log since it deducts credits and deals damage, distinct from a
-- normal gift_transactions row) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE IF NOT EXISTS battle_attacks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  battle_id UUID NOT NULL REFERENCES stream_battles(id) ON DELETE CASCADE,
  attacker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_participant_id UUID NOT NULL REFERENCES battle_participants(id) ON DELETE CASCADE,
  gift_type VARCHAR(50),
  cost NUMERIC(12,2) NOT NULL,
  damage INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_battle_attacks_battle ON battle_attacks(battle_id);

PS C:\Users\Digital King\nvme-platform> Get-Content ".\db\migration_004_schema_healing.sql" -Raw
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
-- Migration 004: schema drift healing
-- Twice now the live database has been missing columns that db/schema.sql
-- claims exist (gift_transactions.to_user_id from an earlier partial run,
-- gifts.emoji from real drift). Rather than keep discovering these one at a
-- time, this ensures every optional/counter column server.js queries on
-- users, videos, livestreams, and transactions actually exists â€” using
-- ADD COLUMN IF NOT EXISTS, which is a no-op wherever the column is already
-- correct. Core required columns (username, email, video_url, etc.) are
-- deliberately left alone â€” if those are missing, the table is
-- fundamentally different and needs a human to look, not an auto-heal.
-- Safe to re-run.
-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

-- users
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_creator BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_credits NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS total_earned NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_email VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS follower_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS following_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- videos
ALTER TABLE videos ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS like_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS comment_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_published BOOLEAN DEFAULT FALSE;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS price_credits NUMERIC(10,2) DEFAULT 0.00;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS tags TEXT[];
ALTER TABLE videos ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- livestreams
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS playback_url TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'offline';
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS viewer_count INTEGER DEFAULT 0;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS peak_viewer_count INTEGER DEFAULT 0;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS total_gifts_received NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS price_credits NUMERIC(10,2) DEFAULT 0.00;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS ended_at TIMESTAMPTZ;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- transactions
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS credits_amount NUMERIC(10,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT;

PS C:\Users\Digital King\nvme-platform> Get-ChildItem .\src\backend -File                                               
