// ========================================
// 🚀 NVME.live - Complete Server
// Free to Join. Pay for Coins & AI Tokens.
// Features: 70% Payouts, Streaming, Calls, AI (NVIDIA + Kimi)
// Likes / Comments / Shares wired up
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
const session = require('express-session'); // ✅ Added for Google OAuth

// ========================================
// 📦 Initialize
// ========================================

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? ['https://nvme.live', 'https://www.nvme.live', 'https://nvme-platform.up.railway.app']
      : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling']
});

// ✅ Added to fix "X-Forwarded-For" warning
app.set('trust proxy', 1);

// ✅ Added to enable Passport sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'nvme-session-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

const PORT = process.env.PORT || 3000;

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

// ========================================
// 🤖 AI Clients (NVIDIA + Kimi)
// ========================================

const nvidiaClient = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY,
  baseURL: process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1',
});

const kimiClient = new OpenAI({
  apiKey: process.env.MOONSHOT_API_KEY,
  baseURL: process.env.KIMI_BASE_URL || 'https://api.moonshot.cn/v1',
});

// ========================================
// 🔒 Middleware
// ========================================

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://nvme.live', 'https://www.nvme.live', 'https://nvme-platform.up.railway.app']
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', limiter);

app.use(express.static('public'));

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ========================================
// 🔐 Auth Middleware (Backwards Compatible)
// ========================================

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Optional auth: attaches req.user if a valid token is present, but never blocks.
// Used for endpoints like view-count that anonymous visitors should still hit.
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return next();
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length > 0) req.user = result.rows[0];
  } catch (err) {
    // invalid/expired token on an optional-auth route: just proceed anonymously
  }
  next();
};

// ========================================
// 🤖 AI Studio (NVIDIA + Kimi) - Unlimited for free users!
// ========================================

app.post('/api/ai/generate', authenticateToken, async (req, res) => {
  try {
    const { type, prompt, tone, provider } = req.body;

    const prompts = {
      script: `Write a viral ${tone || 'professional'} script for: ${prompt}. Include hook, body, and CTA.`,
      caption: `Write 5 engaging captions for: ${prompt}. Include hashtags.`,
      hashtags: `Generate 30+ trending hashtags for: ${prompt}.`,
      idea: `Generate 10 viral content ideas for: ${prompt}.`,
      bio: `Write a compelling bio for a creator in: ${prompt}.`,
    };

    const userPrompt = prompts[type] || prompt;
    const systemPrompt = 'You are a viral content expert for social media creators.';

    let result = null;
    let usedProvider = '';

    // Try NVIDIA
    if (provider !== 'kimi') {
      try {
        const completion = await nvidiaClient.chat.completions.create({
          model: 'nvidia/llama-3.1-nemotron-70b-instruct',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          temperature: 0.8,
          max_tokens: 2000,
        });
        result = completion.choices[0].message.content;
        usedProvider = 'nvidia';
      } catch (e) { console.log('NVIDIA failed:', e.message); }
    }

    // Fallback to Kimi
    if (!result) {
      try {
        const completion = await kimiClient.chat.completions.create({
          model: 'kimi-k3',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          temperature: 0.8,
          max_tokens: 2000,
        });
        result = completion.choices[0].message.content;
        usedProvider = 'kimi';
      } catch (e) {
        console.error('Kimi failed:', e);
        return res.status(500).json({ error: 'All AI providers failed.' });
      }
    }

    res.json({ success: true, content: result, provider: usedProvider });

  } catch (error) {
    console.error('AI Error:', error);
    res.status(500).json({ error: 'Failed to generate content' });
  }
});

// ========================================
// 💰 70% Payout System
// ========================================

const CREATOR_PERCENT = parseFloat(process.env.CREATOR_PAYOUT_PERCENT || 70) / 100;
const PLATFORM_PERCENT = parseFloat(process.env.PLATFORM_FEE_PERCENT || 30) / 100;

const processPayout = async (userId, amount, source, sourceId, client = null) => {
  const creatorAmount = amount * CREATOR_PERCENT;
  const platformFee = amount * PLATFORM_PERCENT;

  const ownConnection = !client;
  const dbClient = client || await pool.connect();

  try {
    if (ownConnection) await dbClient.query('BEGIN');

    await dbClient.query(
      `UPDATE users
       SET total_earnings = COALESCE(total_earnings, 0) + $1,
           total_payouts = COALESCE(total_payouts, 0) + $2,
           platform_fees = COALESCE(platform_fees, 0) + $3
       WHERE id = $4`,
      [amount, creatorAmount, platformFee, userId]
    );
    const result = await dbClient.query(
      `INSERT INTO payouts (user_id, amount, platform_fee, creator_amount, source, source_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')
       RETURNING *`,
      [userId, amount, platformFee, creatorAmount, source, sourceId]
    );

    if (ownConnection) await dbClient.query('COMMIT');
    return result.rows[0];
  } catch (err) {
    if (ownConnection) await dbClient.query('ROLLBACK');
    throw err;
  } finally {
    if (ownConnection) dbClient.release();
  }
};

app.post('/api/payouts/request', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { amount, paypalEmail } = req.body;

    if (!paypalEmail) return res.status(400).json({ error: 'PayPal email required' });

    const minAmount = parseFloat(process.env.MIN_PAYOUT_AMOUNT || 5);
    if (amount < minAmount) {
      return res.status(400).json({ error: `Minimum payout is $${minAmount}` });
    }

    const balanceResult = await pool.query(
      'SELECT COALESCE(total_payouts, 0) as total_payouts, COALESCE(payout_pending, 0) as payout_pending FROM users WHERE id = $1',
      [user.id]
    );
    const balance = balanceResult.rows[0].total_payouts - balanceResult.rows[0].payout_pending;

    if (amount > balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const payoutId = uuidv4();
    await pool.query(
      `INSERT INTO payouts (payout_id, user_id, amount, platform_fee, creator_amount, source, status, paypal_email)
       VALUES ($1, $2, $3, $4, $5, 'payout_request', 'pending', $6)`,
      [payoutId, user.id, amount, amount * PLATFORM_PERCENT, amount * CREATOR_PERCENT, paypalEmail]
    );

    await pool.query(
      'UPDATE users SET payout_pending = COALESCE(payout_pending, 0) + $1 WHERE id = $2',
      [amount, user.id]
    );

    res.json({
      success: true,
      payoutId,
      amount,
      creatorAmount: amount * CREATOR_PERCENT,
      platformFee: amount * PLATFORM_PERCENT,
      message: `💰 Payout requested. 70% ($${(amount * CREATOR_PERCENT).toFixed(2)}) to PayPal.`
    });

  } catch (error) {
    console.error('Payout error:', error);
    res.status(500).json({ error: 'Failed to process payout' });
  }
});

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

app.post('/api/videos/upload', authenticateToken, upload.single('video'), async (req, res) => {
  try {
    const user = req.user;
    const { title, description, category, tags, isPublic } = req.body;

    if (!req.file || !title) {
      return res.status(400).json({ error: 'Video file and title are required' });
    }

    const videoId = uuidv4();
    let videoUrl = '', thumbnailUrl = '';

    try {
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            resource_type: 'video',
            public_id: `videos/${videoId}`,
            folder: 'nvme-videos',
            eager: [{ width: 720, height: 480, crop: 'pad' }],
            eager_async: true
          },
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

    await pool.query(
      `INSERT INTO videos (video_id, user_id, username, title, description, category, tags, video_url, thumbnail_url, is_public, is_processing)
       VALUES ($1, $2, $3, $4, $5, $6, $7::text[], $8, $9, $10, false)`,
      [videoId, user.id, user.username, title, description || '', category || 'General',
       tags ? tags.split(',').map(t => t.trim()) : [], videoUrl, thumbnailUrl, isPublic !== 'false']
    );

    res.json({ success: true, videoId, videoUrl, thumbnailUrl, message: 'Video uploaded successfully!' });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

app.get('/api/videos/feed', async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const result = await pool.query(
      `SELECT v.*, u.display_name, u.avatar, u.is_verified
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.is_public = true AND v.is_processing = false
       ORDER BY v.created_at DESC
       LIMIT $1`,
      [parseInt(limit)]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

// ========================================
// ❤️ Likes
// ========================================

app.post('/api/videos/:videoId/like', authenticateToken, async (req, res) => {
  const { videoId } = req.params;
  const user = req.user;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const videoResult = await client.query('SELECT id, user_id FROM videos WHERE video_id = $1 FOR UPDATE', [videoId]);
    if (videoResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Video not found' });
    }

    const existing = await client.query(
      'SELECT 1 FROM likes WHERE video_id = $1 AND user_id = $2',
      [videoId, user.id]
    );

    let liked;
    if (existing.rows.length > 0) {
      await client.query('DELETE FROM likes WHERE video_id = $1 AND user_id = $2', [videoId, user.id]);
      await client.query('UPDATE videos SET likes = GREATEST(COALESCE(likes, 0) - 1, 0) WHERE video_id = $1', [videoId]);
      liked = false;
    } else {
      await client.query('INSERT INTO likes (video_id, user_id, created_at) VALUES ($1, $2, NOW())', [videoId, user.id]);
      await client.query('UPDATE videos SET likes = COALESCE(likes, 0) + 1 WHERE video_id = $1', [videoId]);
      liked = true;
    }

    const countResult = await client.query('SELECT likes FROM videos WHERE video_id = $1', [videoId]);
    await client.query('COMMIT');

    const likeCount = countResult.rows[0].likes;

    io.to(`video-${videoId}`).emit('like-update', { videoId, liked, likeCount });

    res.json({ success: true, liked, likeCount });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Like error:', error);
    res.status(500).json({ error: 'Failed to update like' });
  } finally {
    client.release();
  }
});

app.get('/api/videos/:videoId/like-status', authenticateToken, async (req, res) => {
  try {
    const { videoId } = req.params;
    const result = await pool.query(
      'SELECT 1 FROM likes WHERE video_id = $1 AND user_id = $2',
      [videoId, req.user.id]
    );
    res.json({ liked: result.rows.length > 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch like status' });
  }
});

// ========================================
// 💬 Comments
// ========================================

app.post('/api/videos/:videoId/comments', authenticateToken, async (req, res) => {
  try {
    const { videoId } = req.params;
    const { text } = req.body;
    const user = req.user;

    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Comment text is required' });
    }
    if (text.length > 500) {
      return res.status(400).json({ error: 'Comment too long (500 char max)' });
    }

    const videoResult = await pool.query('SELECT video_id FROM videos WHERE video_id = $1', [videoId]);
    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const commentId = uuidv4();
    const result = await pool.query(
      `INSERT INTO comments (comment_id, video_id, user_id, username, avatar, text, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       RETURNING *`,
      [commentId, videoId, user.id, user.username, user.avatar || null, text.trim()]
    );

    await pool.query('UPDATE videos SET comment_count = COALESCE(comment_count, 0) + 1 WHERE video_id = $1', [videoId]);

    const comment = result.rows[0];
    io.to(`video-${videoId}`).emit('new-comment', comment);

    res.json({ success: true, comment });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

app.get('/api/videos/:videoId/comments', async (req, res) => {
  try {
    const { videoId } = req.params;
    const { limit = 50, before } = req.query;

    const params = [videoId];
    let query = `SELECT c.*, u.avatar, u.is_verified
                 FROM comments c
                 LEFT JOIN users u ON c.user_id = u.id
                 WHERE c.video_id = $1`;

    if (before) {
      params.push(before);
      query += ` AND c.created_at < $${params.length}`;
    }

    params.push(parseInt(limit));
    query += ` ORDER BY c.created_at DESC LIMIT $${params.length}`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch comments error:', error);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const user = req.user;

    const result = await pool.query(
      'DELETE FROM comments WHERE comment_id = $1 AND user_id = $2 RETURNING video_id',
      [commentId, user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Comment not found or not yours' });
    }

    await pool.query(
      'UPDATE videos SET comment_count = GREATEST(COALESCE(comment_count, 0) - 1, 0) WHERE video_id = $1',
      [result.rows[0].video_id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Delete comment error:', error);
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

// ========================================
// 🔗 Shares
// ========================================

app.post('/api/videos/:videoId/share', optionalAuth, async (req, res) => {
  try {
    const { videoId } = req.params;
    const { platform } = req.body;

    const videoResult = await pool.query(
      'UPDATE videos SET shares = COALESCE(shares, 0) + 1 WHERE video_id = $1 RETURNING shares',
      [videoId]
    );

    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    if (req.user) {
      await pool.query(
        'INSERT INTO shares (share_id, video_id, user_id, platform, created_at) VALUES ($1, $2, $3, $4, NOW())',
        [uuidv4(), videoId, req.user.id, platform || 'unknown']
      );
    }

    const shareUrl = `https://nvme.live/video/${videoId}`;

    io.to(`video-${videoId}`).emit('share-update', { videoId, shareCount: videoResult.rows[0].shares });

    res.json({ success: true, shareCount: videoResult.rows[0].shares, shareUrl });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to record share' });
  }
});

// ========================================
// 👁️ View counter
// ========================================

app.post('/api/videos/:videoId/view', optionalAuth, async (req, res) => {
  try {
    const { videoId } = req.params;
    const result = await pool.query(
      'UPDATE videos SET views = COALESCE(views, 0) + 1 WHERE video_id = $1 RETURNING views',
      [videoId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    res.json({ success: true, views: result.rows[0].views });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// ========================================
// 🎬 Live Streaming
// ========================================

const activeStreams = new Map();

app.post('/api/streams/start', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { title, category } = req.body;

    const existing = await pool.query(
      'SELECT * FROM streams WHERE user_id = $1 AND is_live = true',
      [user.id]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'You already have an active stream' });
    }

    const streamId = `stream_${uuidv4().replace(/-/g, '')}`;
    const result = await pool.query(
      `INSERT INTO streams (stream_id, user_id, username, title, category, is_live, started_at)
       VALUES ($1, $2, $3, $4, $5, true, NOW())
       RETURNING *`,
      [streamId, user.id, user.username, title || 'Live Stream', category || 'General']
    );

    activeStreams.set(streamId, { stream: result.rows[0], viewers: new Set() });
    io.emit('stream-started', { streamId, username: user.username, title: result.rows[0].title });

    res.json({ success: true, streamId, message: 'Stream started!' });

  } catch (error) {
    console.error('Stream start error:', error);
    res.status(500).json({ error: 'Failed to start stream' });
  }
});

app.post('/api/streams/end', authenticateToken, async (req, res) => {
  try {
    const { streamId } = req.body;
    const user = req.user;

    const result = await pool.query(
      `UPDATE streams
       SET is_live = false, ended_at = NOW(), duration = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER
       WHERE stream_id = $1 AND user_id = $2
       RETURNING *`,
      [streamId, user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Stream not found' });
    }

    activeStreams.delete(streamId);
    io.emit('stream-ended', { streamId });

    res.json({ success: true, duration: result.rows[0].duration, message: 'Stream ended' });

  } catch (error) {
    console.error('Stream end error:', error);
    res.status(500).json({ error: 'Failed to end stream' });
  }
});

app.get('/api/streams/live', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, u.display_name, u.avatar, u.is_verified
       FROM streams s
       JOIN users u ON s.user_id = u.id
       WHERE s.is_live = true
       ORDER BY s.viewer_count DESC
       LIMIT 50`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch live streams' });
  }
});

// ========================================
// 📞 Video Calls
// ========================================

app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
  try {
    const { receiverId } = req.body;
    const caller = req.user;

    const receiverResult = await pool.query('SELECT * FROM users WHERE id = $1', [receiverId]);
    if (receiverResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const callId = `call_${uuidv4().replace(/-/g, '')}`;
    await pool.query(
      `INSERT INTO video_calls (call_id, caller_id, receiver_id, status, started_at)
       VALUES ($1, $2, $3, 'initiated', NOW())`,
      [callId, caller.id, receiverId]
    );

    io.to(`user-${receiverId}`).emit('incoming-call', {
      callId,
      callerId: caller.id,
      callerName: caller.display_name || caller.username,
      callerAvatar: caller.avatar
    });

    res.json({ success: true, callId });

  } catch (error) {
    console.error('Call error:', error);
    res.status(500).json({ error: 'Failed to initiate call' });
  }
});

// ========================================
// 🎁 Gifts & Gift Sounds
// ========================================

app.post('/api/gifts/send', authenticateToken, async (req, res) => {
  const { streamId, giftType, message } = req.body;
  const fromUser = req.user;
  const client = await pool.connect();

  try {
    const giftValues = { crown: 50, rocket: 100, heart: 10, star: 5, diamond: 200 };
    const value = giftValues[giftType] || 10;
    const giftId = uuidv4();

    await client.query('BEGIN');

    const streamResult = await client.query('SELECT * FROM streams WHERE stream_id = $1', [streamId]);
    if (streamResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Stream not found' });
    }

    const stream = streamResult.rows[0];
    const toUserId = stream.user_id;

    await processPayout(toUserId, value, 'gift', giftId, client);

    await client.query(
      `INSERT INTO gifts (gift_id, stream_id, from_user_id, to_user_id, gift_type, value, message)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [giftId, streamId, fromUser.id, toUserId, giftType, value, message || '']
    );

    await client.query('COMMIT');

    io.to(`stream-${streamId}`).emit('new-gift', {
      giftType,
      fromUser: fromUser.username,
      value,
      creatorAmount: value * CREATOR_PERCENT,
      playSound: true,
      soundFile: `/sounds/gift-${giftType}.mp3`
    });

    res.json({
      success: true,
      giftId,
      value,
      creatorAmount: value * CREATOR_PERCENT,
      message: `🎁 ${giftType} sent! 70% to creator.`
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Gift error:', error);
    res.status(500).json({ error: 'Failed to send gift' });
  } finally {
    client.release();
  }
});

// ========================================
// 📊 Dashboard
// ========================================

app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    const streamStats = await pool.query(
      `SELECT COUNT(*) as total_streams,
              SUM(viewer_count) as total_viewers,
              SUM(total_gifts) as total_gifts
       FROM streams WHERE user_id = $1`,
      [user.id]
    );

    const videoStats = await pool.query(
      `SELECT COUNT(*) as total_videos, SUM(views) as total_views
       FROM videos WHERE user_id = $1 AND is_processing = false`,
      [user.id]
    );

    res.json({
      user: {
        id: user.id,
        username: user.username,
        display_name: user.display_name || user.username,
        avatar: user.avatar,
        followers: user.followers || 0,
        is_verified: user.is_verified || false
      },
      earnings: {
        total_earnings: user.total_earnings || 0,
        total_payouts: user.total_payouts || 0,
        platform_fees: user.platform_fees || 0,
        payout_pending: user.payout_pending || 0
      },
      stats: {
        total_streams: parseInt(streamStats.rows[0]?.total_streams || 0),
        total_viewers: parseInt(streamStats.rows[0]?.total_viewers || 0),
        total_gifts: parseFloat(streamStats.rows[0]?.total_gifts || 0),
        total_videos: parseInt(videoStats.rows[0]?.total_videos || 0),
        total_video_views: parseInt(videoStats.rows[0]?.total_views || 0)
      }
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// ========================================
// 📡 WebSocket
// ========================================

io.on('connection', (socket) => {
  console.log('🟢 Client connected:', socket.id);

  socket.on('user-online', (data) => {
    const { userId } = data;
    if (userId) socket.join(`user-${userId}`);
  });

  socket.on('join-stream', (data) => {
    const { streamId } = data;
    if (streamId) {
      socket.join(`stream-${streamId}`);
      const streamData = activeStreams.get(streamId);
      if (streamData) {
        streamData.viewers.add(socket.id);
        io.to(`stream-${streamId}`).emit('viewer-count', streamData.viewers.size);
      }
    }
  });

  socket.on('leave-stream', (data) => {
    const { streamId } = data;
    if (streamId) {
      socket.leave(`stream-${streamId}`);
      const streamData = activeStreams.get(streamId);
      if (streamData) {
        streamData.viewers.delete(socket.id);
        io.to(`stream-${streamId}`).emit('viewer-count', streamData.viewers.size);
      }
    }
  });

  socket.on('join-video', (data) => {
    const { videoId } = data;
    if (videoId) socket.join(`video-${videoId}`);
  });

  socket.on('leave-video', (data) => {
    const { videoId } = data;
    if (videoId) socket.leave(`video-${videoId}`);
  });

  socket.on('send-message', (data) => {
    const { streamId, message, username } = data;
    if (streamId && message) {
      io.to(`stream-${streamId}`).emit('new-message', {
        username: username || 'Anonymous',
        message,
        time: new Date().toISOString()
      });
    }
  });

  socket.on('disconnect', () => {
    console.log('🔴 Client disconnected:', socket.id);
    activeStreams.forEach((data, streamId) => {
      if (data.viewers.has(socket.id)) {
        data.viewers.delete(socket.id);
        io.to(`stream-${streamId}`).emit('viewer-count', data.viewers.size);
      }
    });
  });
});

// ========================================
// 🔐 Google OAuth Authentication
// ========================================
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, result.rows[0]);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.APP_URL || 'https://nvme.live'}/api/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const avatar = profile.photos[0]?.value || null;
    
    // Check if user exists in NeonDB
    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];

    if (!user) {
      // Create new user seamlessly
      const newUser = await pool.query(
        `INSERT INTO users (id, username, email, display_name, avatar, provider, provider_id, plan, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'free', NOW())
         RETURNING *`,
        [uuidv4(), email.split('@')[0], email, name, avatar, 'google', profile.id]
      );
      user = newUser.rows[0];
    }
    return done(null, user);
  }
));

// Initialize Passport (this MUST come AFTER the session middleware)
app.use(passport.initialize());
app.use(passport.session());

// Route: Start Google OAuth flow
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Route: Google OAuth callback
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Success! Generate a JWT for your frontend
    const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET);
    res.redirect(`/?token=${token}`);
  }
);

// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/');
  });
});

// ========================================
// 🏠 Serve Frontend
// ========================================

app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

// ========================================
// 🚀 Start Server
// ========================================

server.listen(PORT, () => {
  console.log(`🚀 NVME.live running on http://localhost:${PORT}`);
  console.log(`💰 Creator Payouts: 70% / 30% split`);
  console.log(`🤖 AI Studio: NVIDIA + Kimi (auto-fallback)`);
  console.log(`❤️  Likes / 💬 Comments / 🔗 Shares: enabled`);
});

process.on('unhandledRejection', (err) => console.error('Unhandled Rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught Exception:', err));
