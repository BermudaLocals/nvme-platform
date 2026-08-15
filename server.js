// ========================================
// 🚀 NVME.live - Complete Server
// Features: Streaming, Calls, Uploads, 70% Payouts, AI Studio (NVIDIA + Kimi)
// ========================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const multerS3 = require('multer-s3');
const cloudinary = require('cloudinary').v2;
const { createClient } = require('redis');
const { Pool } = require('pg');
const RedisStore = require('connect-redis')(session);
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk');
const OpenAI = require('openai');

// ========================================
// 📦 Initialize
// ========================================

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? ['https://nvme.live', 'https://www.nvme.live'] 
      : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

const PORT = process.env.PORT || 3000;

// ========================================
// 🔗 Database Connections
// ========================================

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Redis
const redis = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});
redis.on('error', (err) => console.error('Redis Client Error', err));
redis.connect().then(() => console.log('✅ Redis connected'));

// ========================================
// 🤖 AI Clients (NVIDIA + Kimi)
// ========================================

// NVIDIA NIM Client (Free Tier)
const nvidiaClient = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY,
  baseURL: process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1',
});

// Kimi API Client (Moonshot AI)
const kimiClient = new OpenAI({
  apiKey: process.env.MOONSHOT_API_KEY,
  baseURL: process.env.KIMI_BASE_URL || 'https://api.moonshot.cn/v1',
});

// ========================================
// 🔒 Middleware
// ========================================

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', limiter);

// Session
app.use(session({
  store: new RedisStore({ client: redis }),
  secret: process.env.JWT_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Static files
app.use(express.static('public'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ========================================
// 🔐 Auth Middleware
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

// ========================================
// 🤖 AI Studio (NVIDIA + Kimi)
// ========================================

// AI Models Configuration
const NVIDIA_MODELS = {
  'llama-3.3-70b': 'nvidia/llama-3.1-nemotron-70b-instruct',
  'qwen-coder-32b': 'qwen/qwen2.5-coder-32b-instruct',
  'mistral-large': 'mistralai/mistral-large-2-instruct',
  'nemotron-70b': 'nvidia/llama-3.1-nemotron-70b-instruct',
  'glm-5.2': 'z-ai/glm-5.2',
};

const KIMI_MODELS = {
  'k3': 'kimi-k3',
  'k2.7-code': 'kimi-k2.7-code-highspeed',
  'k2.6': 'kimi-k2.6',
};

// Generate content with AI
app.post('/api/ai/generate', authenticateToken, async (req, res) => {
  try {
    const { type, prompt, tone, provider, model } = req.body;
    const user = req.user;

    // Check plan limits
    const isPro = user.plan === 'pro' || (user.trial_ends && new Date(user.trial_ends) > new Date());
    const maxTokens = isPro ? 2000 : 1000;

    // Build specialized prompts
    const prompts = {
      script: `Write a viral ${tone || 'professional'} script for: ${prompt}. Include hook (0-3s), body (3-20s), and CTA. Make it engaging for social media.`,
      caption: `Write 5 engaging captions for: ${prompt}. Include relevant hashtags.`,
      hashtags: `Generate 30+ trending hashtags for: ${prompt}. Include niche and broad tags.`,
      idea: `Generate 10 viral content ideas for: ${prompt}. Include different formats.`,
      bio: `Write a compelling bio for a creator in: ${prompt}. Include emojis and CTA.`,
    };

    const userPrompt = prompts[type] || prompt;
    const systemPrompt = 'You are a viral content expert for social media creators.';

    // Try NVIDIA first, fallback to Kimi
    let result = null;
    let usedProvider = '';

    // Try NVIDIA
    try {
      const nvidiaModel = model && NVIDIA_MODELS[model] ? NVIDIA_MODELS[model] : 'nvidia/llama-3.1-nemotron-70b-instruct';
      const completion = await nvidiaClient.chat.completions.create({
        model: nvidiaModel,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.8,
        max_tokens: maxTokens,
      });
      result = completion.choices[0].message.content;
      usedProvider = 'nvidia';
    } catch (nvidiaError) {
      console.log('NVIDIA failed, falling back to Kimi:', nvidiaError.message);
      
      // Try Kimi as fallback
      try {
        const kimiModel = model && KIMI_MODELS[model] ? KIMI_MODELS[model] : 'kimi-k3';
        const completion = await kimiClient.chat.completions.create({
          model: kimiModel,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          temperature: 0.8,
          max_tokens: maxTokens,
        });
        result = completion.choices[0].message.content;
        usedProvider = 'kimi';
      } catch (kimiError) {
        console.error('All AI providers failed:', kimiError);
        return res.status(500).json({ error: 'All AI providers failed. Please try again later.' });
      }
    }

    res.json({
      success: true,
      content: result,
      provider: usedProvider,
      model: usedProvider === 'nvidia' ? 'nemotron-70b' : 'k3',
    });

  } catch (error) {
    console.error('AI Generation Error:', error);
    res.status(500).json({ error: 'Failed to generate content' });
  }
});

// Streaming AI response
app.post('/api/ai/stream', authenticateToken, async (req, res) => {
  try {
    const { prompt, type, tone } = req.body;

    const prompts = {
      script: `Write a viral ${tone || 'professional'} script for: ${prompt}. Include hook, body, and CTA.`,
      caption: `Write 5 engaging captions for: ${prompt}. Include hashtags.`,
      hashtags: `Generate 30+ trending hashtags for: ${prompt}.`,
      idea: `Generate 10 viral content ideas for: ${prompt}.`,
      bio: `Write a compelling bio for a creator in: ${prompt}.`,
    };

    const userPrompt = prompts[type] || prompt;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    // Try NVIDIA first
    try {
      const stream = await nvidiaClient.chat.completions.create({
        model: 'nvidia/llama-3.1-nemotron-70b-instruct',
        messages: [
          { role: 'system', content: 'You are a viral content expert.' },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.8,
        max_tokens: 2000,
        stream: true,
      });

      for await (const chunk of stream) {
        const content = chunk.choices[0]?.delta?.content || '';
        if (content) {
          res.write(`data: ${JSON.stringify({ text: content })}\n\n`);
        }
      }
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    } catch (nvidiaError) {
      console.log('NVIDIA streaming failed, falling back to Kimi:', nvidiaError.message);
    }

    // Fallback to Kimi
    try {
      const stream = await kimiClient.chat.completions.create({
        model: 'kimi-k3',
        messages: [
          { role: 'system', content: 'You are a viral content expert.' },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.8,
        max_tokens: 4000,
        stream: true,
      });

      for await (const chunk of stream) {
        const content = chunk.choices[0]?.delta?.content || '';
        if (content) {
          res.write(`data: ${JSON.stringify({ text: content })}\n\n`);
        }
      }
      res.write('data: [DONE]\n\n');
      res.end();
    } catch (kimiError) {
      console.error('Kimi streaming failed:', kimiError);
      res.write(`data: ${JSON.stringify({ error: 'All AI providers failed' })}\n\n`);
      res.end();
    }

  } catch (error) {
    console.error('Streaming AI Error:', error);
    res.status(500).json({ error: 'Streaming failed' });
  }
});

// Get available AI models
app.get('/api/ai/models', authenticateToken, async (req, res) => {
  res.json({
    nvidia: Object.keys(NVIDIA_MODELS),
    kimi: Object.keys(KIMI_MODELS),
  });
});

// ========================================
// 💰 70% Payout System
// ========================================

const CREATOR_PERCENT = parseFloat(process.env.CREATOR_PAYOUT_PERCENT || 70) / 100;
const PLATFORM_PERCENT = parseFloat(process.env.PLATFORM_FEE_PERCENT || 30) / 100;

// Process a payout
const processPayout = async (userId, amount, source, sourceId) => {
  const creatorAmount = amount * CREATOR_PERCENT;
  const platformFee = amount * PLATFORM_PERCENT;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `UPDATE users 
       SET total_earnings = total_earnings + $1,
           total_payouts = total_payouts + $2,
           platform_fees = platform_fees + $3
       WHERE id = $4`,
      [amount, creatorAmount, platformFee, userId]
    );

    const result = await client.query(
      `INSERT INTO payouts (user_id, amount, platform_fee, creator_amount, source, source_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')
       RETURNING *`,
      [userId, amount, platformFee, creatorAmount, source, sourceId]
    );

    await client.query('COMMIT');
    return result.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
};

// Request payout
app.post('/api/payouts/request', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { amount, paypalEmail } = req.body;

    if (!paypalEmail) {
      return res.status(400).json({ error: 'PayPal email required' });
    }

    const minAmount = parseFloat(process.env.MIN_PAYOUT_AMOUNT || 5);
    if (amount < minAmount) {
      return res.status(400).json({ error: `Minimum payout is $${minAmount}` });
    }

    const balanceResult = await pool.query(
      'SELECT total_payouts, payout_pending FROM users WHERE id = $1',
      [user.id]
    );
    const balance = balanceResult.rows[0].total_payouts - balanceResult.rows[0].payout_pending;

    if (amount > balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const payoutId = uuidv4();
    const result = await pool.query(
      `INSERT INTO payouts (payout_id, user_id, amount, platform_fee, creator_amount, source, status, paypal_email)
       VALUES ($1, $2, $3, $4, $5, 'payout_request', 'pending', $6)
       RETURNING *`,
      [payoutId, user.id, amount, amount * PLATFORM_PERCENT, amount * CREATOR_PERCENT, paypalEmail]
    );

    await pool.query(
      'UPDATE users SET payout_pending = payout_pending + $1 WHERE id = $2',
      [amount, user.id]
    );

    res.json({
      success: true,
      payoutId,
      amount,
      creatorAmount: amount * CREATOR_PERCENT,
      platformFee: amount * PLATFORM_PERCENT,
      message: `💰 Payout of $${amount} requested. 70% ($${(amount * CREATOR_PERCENT).toFixed(2)}) to your PayPal.`
    });

  } catch (error) {
    console.error('Payout error:', error);
    res.status(500).json({ error: 'Failed to process payout' });
  }
});

// Get payout history
app.get('/api/payouts/history', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM payouts WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch payouts' });
  }
});

// ========================================
// 📹 Video Upload (Cloudinary/S3)
// ========================================

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: parseInt(process.env.MAX_VIDEO_SIZE) || 2147483648
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/mov', 'video/avi', 'video/mkv', 'video/webm', 'video/quicktime'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only video files are allowed.'));
    }
  }
});

// Upload video
app.post('/api/videos/upload', authenticateToken, upload.single('video'), async (req, res) => {
  try {
    const user = req.user;
    const { title, description, category, tags, isPublic } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No video file provided' });
    }

    if (!title) {
      return res.status(400).json({ error: 'Video title is required' });
    }

    const videoId = uuidv4();
    let videoUrl = '';
    let thumbnailUrl = '';

    try {
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            resource_type: 'video',
            public_id: `videos/${videoId}`,
            folder: 'nvme-videos',
            eager: [
              { width: 720, height: 480, crop: 'pad' },
              { width: 1080, height: 720, crop: 'pad' }
            ],
            eager_async: true
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.file.buffer);
      });

      videoUrl = result.secure_url;
      thumbnailUrl = result.eager?.[0]?.secure_url || result.secure_url.replace('.mp4', '.jpg');
    } catch (uploadError) {
      console.error('Cloudinary error:', uploadError);
      const s3Params = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: `videos/${videoId}/${req.file.originalname}`,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'public-read'
      };
      const s3Result = await s3.upload(s3Params).promise();
      videoUrl = s3Result.Location;
      thumbnailUrl = `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
    }

    const result = await pool.query(
      `INSERT INTO videos (video_id, user_id, username, title, description, category, tags, video_url, thumbnail_url, is_public, is_processing)
       VALUES ($1, $2, $3, $4, $5, $6, $7::text[], $8, $9, $10, false)
       RETURNING *`,
      [videoId, user.id, user.username, title, description || '', category || 'General', 
       tags ? tags.split(',').map(t => t.trim()) : [], videoUrl, thumbnailUrl, isPublic !== 'false']
    );

    res.json({
      success: true,
      videoId,
      videoUrl,
      thumbnailUrl,
      message: 'Video uploaded successfully!'
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video', details: error.message });
  }
});

// Get user's videos
app.get('/api/videos/my', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM videos WHERE user_id = $1 AND is_processing = false ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Get feed videos
app.get('/api/videos/feed', async (req, res) => {
  try {
    const { limit = 20, category } = req.query;
    let query = `SELECT v.*, u.display_name, u.avatar, u.is_verified 
                 FROM videos v
                 JOIN users u ON v.user_id = u.id
                 WHERE v.is_public = true AND v.is_processing = false`;
    const params = [];
    
    if (category && category !== 'all') {
      query += ` AND v.category = $1`;
      params.push(category);
    }
    query += ` ORDER BY v.created_at DESC LIMIT $${params.length + 1}`;
    params.push(parseInt(limit));

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

// Get single video
app.get('/api/videos/:videoId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.*, u.display_name, u.avatar, u.is_verified 
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.video_id = $1`,
      [req.params.videoId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }
    await pool.query(
      `UPDATE videos SET views = views + 1 WHERE video_id = $1`,
      [req.params.videoId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

// ========================================
// 🎬 Live Streaming
// ========================================

const activeStreams = new Map();

// Generate stream key
app.get('/api/streams/key', authenticateToken, async (req, res) => {
  try {
    let streamKey = req.user.stream_key;
    if (!streamKey) {
      streamKey = `sk_${uuidv4().replace(/-/g, '')}`;
      await pool.query(
        'UPDATE users SET stream_key = $1 WHERE id = $2',
        [streamKey, req.user.id]
      );
    }
    res.json({ streamKey });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate stream key' });
  }
});

// Start stream
app.post('/api/streams/start', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { title, category, tags } = req.body;

    const existing = await pool.query(
      'SELECT * FROM streams WHERE user_id = $1 AND is_live = true',
      [user.id]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'You already have an active stream' });
    }

    const streamId = `stream_${uuidv4().replace(/-/g, '')}`;
    const result = await pool.query(
      `INSERT INTO streams (stream_id, user_id, username, title, category, tags, is_live, started_at)
       VALUES ($1, $2, $3, $4, $5, $6::text[], true, NOW())
       RETURNING *`,
      [streamId, user.id, user.username, title || 'Live Stream', category || 'General', 
       tags ? tags.split(',').map(t => t.trim()) : []]
    );

    activeStreams.set(streamId, {
      stream: result.rows[0],
      viewers: new Set(),
      gifts: [],
      messages: []
    });

    io.emit('stream-started', {
      streamId,
      username: user.username,
      title: result.rows[0].title,
      userId: user.id
    });

    res.json({
      success: true,
      streamId,
      streamKey: user.stream_key,
      rtmpUrl: 'rtmp://your-streaming-server/live',
      message: 'Stream started!'
    });

  } catch (error) {
    console.error('Stream start error:', error);
    res.status(500).json({ error: 'Failed to start stream' });
  }
});

// End stream
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

    res.json({
      success: true,
      duration: result.rows[0].duration,
      message: 'Stream ended'
    });

  } catch (error) {
    console.error('Stream end error:', error);
    res.status(500).json({ error: 'Failed to end stream' });
  }
});

// Get live streams
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

    const callId = `call_${uuidv4().replace(/-/g, '')}`;

    const receiverResult = await pool.query('SELECT * FROM users WHERE id = $1', [receiverId]);
    if (receiverResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

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

    res.json({
      success: true,
      callId,
      message: 'Call initiated'
    });

  } catch (error) {
    console.error('Call error:', error);
    res.status(500).json({ error: 'Failed to initiate call' });
  }
});

// ========================================
// 🎁 Gifts & Tips
// ========================================

app.post('/api/gifts/send', authenticateToken, async (req, res) => {
  try {
    const { streamId, giftType, message } = req.body;
    const fromUser = req.user;

    const giftValues = {
      crown: 50,
      rocket: 100,
      heart: 10,
      star: 5,
      diamond: 200
    };

    const value = giftValues[giftType] || 10;
    const giftId = uuidv4();

    const streamResult = await pool.query('SELECT * FROM streams WHERE stream_id = $1', [streamId]);
    if (streamResult.rows.length === 0) {
      return res.status(404).json({ error: 'Stream not found' });
    }

    const stream = streamResult.rows[0];
    const toUserId = stream.user_id;

    const payout = await processPayout(toUserId, value, 'gift', giftId);

    await pool.query(
      `INSERT INTO gifts (gift_id, stream_id, from_user_id, to_user_id, gift_type, value, message)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [giftId, streamId, fromUser.id, toUserId, giftType, value, message || '']
    );

    await pool.query(
      `UPDATE streams 
       SET total_gifts = total_gifts + $1, 
           total_tips = total_tips + $1,
           gift_breakdown = COALESCE(gift_breakdown, '{}')::jsonb || jsonb_build_object($2, COALESCE((gift_breakdown->>$2)::int, 0) + 1)
       WHERE stream_id = $3`,
      [value, giftType, streamId]
    );

    io.to(`stream-${streamId}`).emit('new-gift', {
      giftId,
      giftType,
      fromUser: fromUser.username,
      toUser: stream.username,
      value,
      creatorAmount: value * CREATOR_PERCENT,
      platformFee: value * PLATFORM_PERCENT,
      message: message || '',
      time: new Date().toISOString()
    });

    res.json({
      success: true,
      giftId,
      value,
      creatorAmount: value * CREATOR_PERCENT,
      platformFee: value * PLATFORM_PERCENT,
      message: `🎁 ${giftType} sent! 70% ($${(value * CREATOR_PERCENT).toFixed(2)}) to creator.`
    });

  } catch (error) {
    console.error('Gift error:', error);
    res.status(500).json({ error: 'Failed to send gift' });
  }
});

// ========================================
// 🎁 Free Trial
// ========================================

app.post('/api/trial/start', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    if (user.trial_ends && new Date(user.trial_ends) > new Date()) {
      return res.status(400).json({ error: 'You already have an active trial' });
    }

    const trialDays = parseInt(process.env.TRIAL_DAYS) || 7;
    const trialEnds = new Date(Date.now() + trialDays * 24 * 60 * 60 * 1000);

    await pool.query(
      'UPDATE users SET trial_ends = $1, plan = $2 WHERE id = $3',
      [trialEnds, 'pro', user.id]
    );

    res.json({
      success: true,
      trialEnds,
      daysRemaining: trialDays,
      message: `🎁 ${trialDays}-day free trial started! Enjoy all Pro features.`
    });

  } catch (error) {
    console.error('Trial error:', error);
    res.status(500).json({ error: 'Failed to start trial' });
  }
});

// ========================================
// 📊 Dashboard
// ========================================

app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    // Get stream stats
    const streamStats = await pool.query(
      `SELECT COUNT(*) as total_streams, 
              SUM(viewer_count) as total_viewers,
              SUM(duration) as total_duration,
              SUM(total_gifts) as total_gifts
       FROM streams WHERE user_id = $1`,
      [user.id]
    );

    // Get video stats
    const videoStats = await pool.query(
      `SELECT COUNT(*) as total_videos, SUM(views) as total_views
       FROM videos WHERE user_id = $1 AND is_processing = false`,
      [user.id]
    );

    // Get payout stats
    const payoutStats = await pool.query(
      `SELECT SUM(creator_amount) as total_payouts, 
              SUM(platform_fee) as total_platform_fees,
              COUNT(*) as total_transactions
       FROM payouts WHERE user_id = $1 AND status = 'completed'`,
      [user.id]
    );

    res.json({
      user: {
        username: user.username,
        display_name: user.display_name,
        avatar: user.avatar,
        followers: user.followers || 0,
        plan: user.plan,
        is_verified: user.is_verified || false,
        trial_ends: user.trial_ends
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
        total_duration: parseInt(streamStats.rows[0]?.total_duration || 0),
        total_gifts: parseFloat(streamStats.rows[0]?.total_gifts || 0),
        total_videos: parseInt(videoStats.rows[0]?.total_videos || 0),
        total_video_views: parseInt(videoStats.rows[0]?.total_views || 0),
        total_payouts: parseFloat(payoutStats.rows[0]?.total_payouts || 0),
        total_platform_fees: parseFloat(payoutStats.rows[0]?.total_platform_fees || 0),
        total_transactions: parseInt(payoutStats.rows[0]?.total_transactions || 0)
      }
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// ========================================
// 📡 WebSocket (Socket.io)
// ========================================

io.on('connection', (socket) => {
  console.log('🟢 Client connected:', socket.id);

  // Join user room for calls
  socket.on('user-online', (data) => {
    const { userId } = data;
    socket.join(`user-${userId}`);
  });

  // Join stream
  socket.on('join-stream', (data) => {
    const { streamId } = data;
    socket.join(`stream-${streamId}`);
    
    const streamData = activeStreams.get(streamId);
    if (streamData) {
      streamData.viewers.add(socket.id);
      io.to(`stream-${streamId}`).emit('viewer-count', streamData.viewers.size);
    }
  });

  // Leave stream
  socket.on('leave-stream', (data) => {
    const { streamId } = data;
    socket.leave(`stream-${streamId}`);
    
    const streamData = activeStreams.get(streamId);
    if (streamData) {
      streamData.viewers.delete(socket.id);
      io.to(`stream-${streamId}`).emit('viewer-count', streamData.viewers.size);
    }
  });

  // Chat message
  socket.on('send-message', (data) => {
    const { streamId, message, username } = data;
    io.to(`stream-${streamId}`).emit('new-message', {
      username,
      message,
      time: new Date().toISOString()
    });
  });

  // WebRTC signaling for streaming
  socket.on('streamer-offer', (data) => {
    const { streamId, offer } = data;
    socket.to(`stream-${streamId}`).emit('streamer-offer', { offer });
  });

  socket.on('viewer-answer', (data) => {
    const { streamId, answer } = data;
    socket.to(`stream-${streamId}`).emit('viewer-answer', { answer });
  });

  socket.on('stream-ice-candidate', (data) => {
    const { streamId, candidate } = data;
    socket.to(`stream-${streamId}`).emit('stream-ice-candidate', { candidate });
  });

  // WebRTC signaling for video calls
  socket.on('call-offer', (data) => {
    const { targetUserId, offer } = data;
    socket.to(`user-${targetUserId}`).emit('call-offer', { offer });
  });

  socket.on('call-answer', (data) => {
    const { targetUserId, answer } = data;
    socket.to(`user-${targetUserId}`).emit('call-answer', { answer });
  });

  socket.on('call-ice-candidate', (data) => {
    const { targetUserId, candidate } = data;
    socket.to(`user-${targetUserId}`).emit('call-ice-candidate', { candidate });
  });

  socket.on('end-call', (data) => {
    const { targetUserId } = data;
    socket.to(`user-${targetUserId}`).emit('call-ended');
  });

  socket.on('disconnect', () => {
    console.log('🔴 Client disconnected:', socket.id);
    // Clean up from streams
    activeStreams.forEach((data, streamId) => {
      if (data.viewers.has(socket.id)) {
        data.viewers.delete(socket.id);
        io.to(`stream-${streamId}`).emit('viewer-count', data.viewers.size);
      }
    });
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
  console.log(`🚀 NVME.live upgraded server running on http://localhost:${PORT}`);
  console.log(`🎬 Live Streaming: WebRTC + Socket.io`);
  console.log(`📞 Video Calls: P2P WebRTC`);
  console.log(`📹 Video Uploads: Cloudinary/S3`);
  console.log(`💰 Creator Payouts: 70% / 30% split`);
  console.log(`🤖 AI Studio: NVIDIA + Kimi (auto-fallback)`);
  console.log(`🗄️ Database: PostgreSQL + Redis`);
});

// ========================================
// 🛑 Error Handling
// ========================================

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
