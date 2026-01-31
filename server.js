const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nvme-super-secret-key-2024';

// Hardcoded gift catalog for fallback when database is unavailable
const FALLBACK_GIFTS = [
  { id: 1, name: 'Rose', emoji: '🌹', coin_cost: 1, creator_earnings: 0.5, category: 'flowers', animation_type: 'float', is_active: true },
  { id: 2, name: 'Heart', emoji: '❤️', coin_cost: 5, creator_earnings: 2.5, category: 'love', animation_type: 'pulse', is_active: true },
  { id: 3, name: 'Fire', emoji: '🔥', coin_cost: 10, creator_earnings: 5, category: 'reactions', animation_type: 'shake', is_active: true },
  { id: 4, name: 'Star', emoji: '⭐', coin_cost: 20, creator_earnings: 10, category: 'premium', animation_type: 'spin', is_active: true },
  { id: 5, name: 'Diamond', emoji: '💎', coin_cost: 50, creator_earnings: 25, category: 'luxury', animation_type: 'sparkle', is_active: true },
  { id: 6, name: 'Crown', emoji: '👑', coin_cost: 100, creator_earnings: 50, category: 'royal', animation_type: 'bounce', is_active: true },
  { id: 7, name: 'Rocket', emoji: '🚀', coin_cost: 200, creator_earnings: 100, category: 'special', animation_type: 'fly', is_active: true },
  { id: 8, name: 'Rainbow', emoji: '🌈', coin_cost: 300, creator_earnings: 150, category: 'special', animation_type: 'wave', is_active: true },
  { id: 9, name: 'Unicorn', emoji: '🦄', coin_cost: 500, creator_earnings: 250, category: 'mythical', animation_type: 'magic', is_active: true },
  { id: 10, name: 'Dragon', emoji: '🐉', coin_cost: 1000, creator_earnings: 500, category: 'legendary', animation_type: 'fire', is_active: true },
  { id: 11, name: 'Kiss', emoji: '💋', coin_cost: 15, creator_earnings: 7.5, category: 'love', animation_type: 'float', is_active: true },
  { id: 12, name: 'Teddy Bear', emoji: '🧸', coin_cost: 25, creator_earnings: 12.5, category: 'cute', animation_type: 'bounce', is_active: true },
  { id: 13, name: 'Champagne', emoji: '🍾', coin_cost: 75, creator_earnings: 37.5, category: 'celebration', animation_type: 'pop', is_active: true },
  { id: 14, name: 'Trophy', emoji: '🏆', coin_cost: 150, creator_earnings: 75, category: 'achievement', animation_type: 'shine', is_active: true },
  { id: 15, name: 'Money Bag', emoji: '💰', coin_cost: 250, creator_earnings: 125, category: 'wealth', animation_type: 'rain', is_active: true },
  { id: 16, name: 'Sunflower', emoji: '🌻', coin_cost: 3, creator_earnings: 1.5, category: 'flowers', animation_type: 'sway', is_active: true },
  { id: 17, name: 'Butterfly', emoji: '🦋', coin_cost: 8, creator_earnings: 4, category: 'nature', animation_type: 'flutter', is_active: true },
  { id: 18, name: 'Lightning', emoji: '⚡', coin_cost: 30, creator_earnings: 15, category: 'power', animation_type: 'flash', is_active: true },
  { id: 19, name: 'Galaxy', emoji: '🌌', coin_cost: 400, creator_earnings: 200, category: 'cosmic', animation_type: 'swirl', is_active: true },
  { id: 20, name: 'Phoenix', emoji: '🔥', coin_cost: 750, creator_earnings: 375, category: 'mythical', animation_type: 'rise', is_active: true },
  { id: 21, name: 'Clover', emoji: '🍀', coin_cost: 7, creator_earnings: 3.5, category: 'luck', animation_type: 'spin', is_active: true },
  { id: 22, name: 'Pizza', emoji: '🍕', coin_cost: 12, creator_earnings: 6, category: 'food', animation_type: 'bounce', is_active: true },
  { id: 23, name: 'Ice Cream', emoji: '🍦', coin_cost: 18, creator_earnings: 9, category: 'food', animation_type: 'melt', is_active: true },
  { id: 24, name: 'Cake', emoji: '🎂', coin_cost: 35, creator_earnings: 17.5, category: 'celebration', animation_type: 'candle', is_active: true },
  { id: 25, name: 'Gift Box', emoji: '🎁', coin_cost: 45, creator_earnings: 22.5, category: 'surprise', animation_type: 'unwrap', is_active: true },
  { id: 26, name: 'Balloon', emoji: '🎈', coin_cost: 6, creator_earnings: 3, category: 'party', animation_type: 'float', is_active: true },
  { id: 27, name: 'Confetti', emoji: '🎊', coin_cost: 22, creator_earnings: 11, category: 'party', animation_type: 'burst', is_active: true },
  { id: 28, name: 'Fireworks', emoji: '🎆', coin_cost: 60, creator_earnings: 30, category: 'celebration', animation_type: 'explode', is_active: true },
  { id: 29, name: 'Sparkles', emoji: '✨', coin_cost: 4, creator_earnings: 2, category: 'magic', animation_type: 'twinkle', is_active: true },
  { id: 30, name: 'Moon', emoji: '🌙', coin_cost: 40, creator_earnings: 20, category: 'cosmic', animation_type: 'glow', is_active: true },
  { id: 31, name: 'Sun', emoji: '☀️', coin_cost: 55, creator_earnings: 27.5, category: 'cosmic', animation_type: 'radiate', is_active: true },
  { id: 32, name: 'Comet', emoji: '☄️', coin_cost: 180, creator_earnings: 90, category: 'cosmic', animation_type: 'streak', is_active: true },
  { id: 33, name: 'Alien', emoji: '👽', coin_cost: 120, creator_earnings: 60, category: 'fun', animation_type: 'beam', is_active: true },
  { id: 34, name: 'Robot', emoji: '🤖', coin_cost: 85, creator_earnings: 42.5, category: 'tech', animation_type: 'dance', is_active: true },
  { id: 35, name: 'Ghost', emoji: '👻', coin_cost: 28, creator_earnings: 14, category: 'fun', animation_type: 'fade', is_active: true },
  { id: 36, name: 'Skull', emoji: '💀', coin_cost: 33, creator_earnings: 16.5, category: 'edgy', animation_type: 'rattle', is_active: true },
  { id: 37, name: 'Devil', emoji: '😈', coin_cost: 66, creator_earnings: 33, category: 'edgy', animation_type: 'flame', is_active: true },
  { id: 38, name: 'Angel', emoji: '😇', coin_cost: 88, creator_earnings: 44, category: 'divine', animation_type: 'halo', is_active: true },
  { id: 39, name: 'Mermaid', emoji: '🧜‍♀️', coin_cost: 350, creator_earnings: 175, category: 'mythical', animation_type: 'swim', is_active: true },
  { id: 40, name: 'Fairy', emoji: '🧚', coin_cost: 280, creator_earnings: 140, category: 'mythical', animation_type: 'flutter', is_active: true },
  { id: 41, name: 'Gem', emoji: '💠', coin_cost: 95, creator_earnings: 47.5, category: 'luxury', animation_type: 'rotate', is_active: true },
  { id: 42, name: 'Ring', emoji: '💍', coin_cost: 450, creator_earnings: 225, category: 'luxury', animation_type: 'shine', is_active: true },
  { id: 43, name: 'Lipstick', emoji: '💄', coin_cost: 38, creator_earnings: 19, category: 'beauty', animation_type: 'swipe', is_active: true },
  { id: 44, name: 'Perfume', emoji: '🧴', coin_cost: 52, creator_earnings: 26, category: 'beauty', animation_type: 'spray', is_active: true },
  { id: 45, name: 'Microphone', emoji: '🎤', coin_cost: 70, creator_earnings: 35, category: 'music', animation_type: 'pulse', is_active: true },
  { id: 46, name: 'Guitar', emoji: '🎸', coin_cost: 110, creator_earnings: 55, category: 'music', animation_type: 'strum', is_active: true },
  { id: 47, name: 'Drum', emoji: '🥁', coin_cost: 90, creator_earnings: 45, category: 'music', animation_type: 'beat', is_active: true },
  { id: 48, name: 'Sports Car', emoji: '🏎️', coin_cost: 600, creator_earnings: 300, category: 'luxury', animation_type: 'zoom', is_active: true },
  { id: 49, name: 'Yacht', emoji: '🛥️', coin_cost: 800, creator_earnings: 400, category: 'luxury', animation_type: 'sail', is_active: true },
  { id: 50, name: 'Private Jet', emoji: '✈️', coin_cost: 2000, creator_earnings: 1000, category: 'ultimate', animation_type: 'takeoff', is_active: true }
];


// Database connection
const pool = new Pool({
  connectionString: 'postgresql://neondb_owner:npg_Ij3gvNYkr1wX@ep-soft-sunset-a5geqx3v.us-east-2.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'frontend')));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const type = file.fieldname === 'video' ? 'videos' : 'avatars';
    const dir = path.join(__dirname, 'uploads', type);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
      if (result.rows.length > 0) req.user = result.rows[0];
    }
  } catch (err) {}
  next();
};

// Initialize database tables
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(50),
        username VARCHAR(100) UNIQUE,
        password VARCHAR(255) NOT NULL,
        display_name VARCHAR(255),
        bio TEXT,
        avatar VARCHAR(500),
        cover_image VARCHAR(500),
        coins INTEGER DEFAULT 0,
        earnings DECIMAL(10,2) DEFAULT 0,
        is_verified BOOLEAN DEFAULT false,
        is_creator BOOLEAN DEFAULT false,
        is_live BOOLEAN DEFAULT false,
        followers_count INTEGER DEFAULT 0,
        following_count INTEGER DEFAULT 0,
        likes_count INTEGER DEFAULT 0,
        videos_count INTEGER DEFAULT 0,
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS videos (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(500),
        description TEXT,
        video_url VARCHAR(500) NOT NULL,
        thumbnail_url VARCHAR(500),
        duration INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        likes_count INTEGER DEFAULT 0,
        comments_count INTEGER DEFAULT 0,
        shares_count INTEGER DEFAULT 0,
        is_public BOOLEAN DEFAULT true,
        tags TEXT[],
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS video_likes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(video_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS comments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        parent_id UUID REFERENCES comments(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        likes_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS follows (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        follower_id UUID REFERENCES users(id) ON DELETE CASCADE,
        following_id UUID REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(follower_id, following_id)
      );

      CREATE TABLE IF NOT EXISTS gifts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        icon VARCHAR(100) NOT NULL,
        animation VARCHAR(100),
        coin_cost INTEGER NOT NULL,
        creator_earnings DECIMAL(10,2) NOT NULL,
        category VARCHAR(50) DEFAULT 'standard',
        is_active BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS gift_transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
        receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
        gift_id UUID REFERENCES gifts(id),
        video_id UUID REFERENCES videos(id) ON DELETE SET NULL,
        live_stream_id UUID,
        quantity INTEGER DEFAULT 1,
        total_coins INTEGER NOT NULL,
        creator_earnings DECIMAL(10,2) NOT NULL,
        message TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS coin_transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        amount INTEGER NOT NULL,
        description TEXT,
        stripe_payment_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        participant1_id UUID REFERENCES users(id) ON DELETE CASCADE,
        participant2_id UUID REFERENCES users(id) ON DELETE CASCADE,
        last_message_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(participant1_id, participant2_id)
      );

      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255),
        message TEXT,
        data JSONB,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS live_streams (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        description TEXT,
        thumbnail_url VARCHAR(500),
        stream_key VARCHAR(255) UNIQUE,
        viewer_count INTEGER DEFAULT 0,
        total_gifts INTEGER DEFAULT 0,
        total_earnings DECIMAL(10,2) DEFAULT 0,
        is_active BOOLEAN DEFAULT true,
        started_at TIMESTAMP DEFAULT NOW(),
        ended_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS live_chat (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        stream_id UUID REFERENCES live_streams(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_videos_user ON videos(user_id);
      CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id);
      CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
      CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);
      CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
    `);

    // Insert default gifts if not exist
    const giftsExist = await pool.query('SELECT COUNT(*) FROM gifts');
    if (parseInt(giftsExist.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO gifts (name, icon, animation, coin_cost, creator_earnings, category) VALUES
        ('Rose', '🌹', 'float-up', 1, 0.005, 'standard'),
        ('Heart', '❤️', 'pulse', 5, 0.025, 'standard'),
        ('Fire', '🔥', 'flame', 10, 0.05, 'standard'),
        ('Star', '⭐', 'spin', 20, 0.10, 'standard'),
        ('Diamond', '💎', 'sparkle', 50, 0.25, 'premium'),
        ('Crown', '👑', 'bounce', 100, 0.50, 'premium'),
        ('Rocket', '🚀', 'launch', 200, 1.00, 'premium'),
        ('Rainbow', '🌈', 'arc', 300, 1.50, 'premium'),
        ('Unicorn', '🦄', 'gallop', 500, 2.50, 'luxury'),
        ('Galaxy', '🌌', 'swirl', 1000, 5.00, 'luxury'),
        ('Lightning', '⚡', 'strike', 15, 0.075, 'standard'),
        ('Clover', '🍀', 'spin', 25, 0.125, 'standard'),
        ('Butterfly', '🦋', 'flutter', 30, 0.15, 'standard'),
        ('Sunflower', '🌻', 'bloom', 35, 0.175, 'standard'),
        ('Moon', '🌙', 'glow', 40, 0.20, 'standard'),
        ('Comet', '☄️', 'streak', 75, 0.375, 'premium'),
        ('Phoenix', '🔶', 'rise', 150, 0.75, 'premium'),
        ('Dragon', '🐉', 'fly', 250, 1.25, 'premium'),
        ('Castle', '🏰', 'build', 400, 2.00, 'luxury'),
        ('Treasure', '💰', 'rain', 750, 3.75, 'luxury'),
        ('Kiss', '💋', 'float', 8, 0.04, 'standard'),
        ('Sparkles', '✨', 'twinkle', 12, 0.06, 'standard'),
        ('Party', '🎉', 'explode', 45, 0.225, 'standard'),
        ('Music', '🎵', 'wave', 18, 0.09, 'standard'),
        ('Camera', '📸', 'flash', 22, 0.11, 'standard'),
        ('Trophy', '🏆', 'shine', 125, 0.625, 'premium'),
        ('Medal', '🥇', 'swing', 80, 0.40, 'premium'),
        ('Gem', '💠', 'rotate', 175, 0.875, 'premium'),
        ('Yacht', '🛥️', 'sail', 600, 3.00, 'luxury'),
        ('Jet', '✈️', 'fly', 800, 4.00, 'luxury'),
        ('Teddy', '🧸', 'hug', 55, 0.275, 'standard'),
        ('Cake', '🎂', 'celebrate', 65, 0.325, 'standard'),
        ('Balloon', '🎈', 'float', 28, 0.14, 'standard'),
        ('Gift Box', '🎁', 'unwrap', 90, 0.45, 'premium'),
        ('Fireworks', '🎆', 'burst', 110, 0.55, 'premium'),
        ('Angel', '👼', 'descend', 225, 1.125, 'premium'),
        ('Devil', '😈', 'bounce', 225, 1.125, 'premium'),
        ('Alien', '👽', 'beam', 275, 1.375, 'premium'),
        ('Robot', '🤖', 'dance', 325, 1.625, 'premium'),
        ('Mermaid', '🧜', 'swim', 450, 2.25, 'luxury'),
        ('Wizard', '🧙', 'cast', 550, 2.75, 'luxury'),
        ('Ninja', '🥷', 'slash', 350, 1.75, 'premium'),
        ('Superhero', '🦸', 'fly', 650, 3.25, 'luxury'),
        ('Dinosaur', '🦖', 'stomp', 375, 1.875, 'premium'),
        ('Panda', '🐼', 'roll', 95, 0.475, 'premium'),
        ('Lion', '🦁', 'roar', 135, 0.675, 'premium'),
        ('Elephant', '🐘', 'trumpet', 185, 0.925, 'premium'),
        ('Peacock', '🦚', 'display', 425, 2.125, 'luxury'),
        ('Lotus', '🪷', 'bloom', 475, 2.375, 'luxury'),
        ('Infinity', '♾️', 'loop', 999, 4.995, 'luxury')
      `);
    }

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
};

// ==================== AUTH ROUTES ====================

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, password, username } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR (username = $2 AND $2 IS NOT NULL)',
      [email, username]
    );
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const generatedUsername = username || 'user_' + Date.now();
    
    const result = await pool.query(
      `INSERT INTO users (email, phone, password, username, display_name, coins)
       VALUES ($1, $2, $3, $4, $5, 100) RETURNING *`,
      [email, phone, hashedPassword, generatedUsername, generatedUsername]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    delete user.password;
    res.json({ user, token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    delete user.password;
    res.json({ user, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/me', authenticate, (req, res) => {
  const user = { ...req.user };
  delete user.password;
  res.json({ user });
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    
    if (result.rows.length > 0) {
      const resetToken = uuidv4();
      const expires = new Date(Date.now() + 3600000); // 1 hour
      await pool.query(
        'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
        [resetToken, expires, email]
      );
      // In production, send email with reset link
    }
    
    res.json({ message: 'If email exists, reset link sent' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const result = await pool.query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hashedPassword, result.rows[0].id]
    );

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

// Update profile
app.put('/api/users/profile', authenticate, upload.single('avatar'), async (req, res) => {
  try {
    const { display_name, bio, username } = req.body;
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (display_name) {
      updates.push(`display_name = $${paramCount++}`);
      values.push(display_name);
    }
    if (bio !== undefined) {
      updates.push(`bio = $${paramCount++}`);
      values.push(bio);
    }
    if (username) {
      updates.push(`username = $${paramCount++}`);
      values.push(username);
    }
    if (req.file) {
      updates.push(`avatar = $${paramCount++}`);
      values.push('/uploads/avatars/' + req.file.filename);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No updates provided' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(req.user.id);

    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );

    const user = result.rows[0];
    delete user.password;
    res.json({ user });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/:id', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, bio, avatar, cover_image, is_verified, is_creator,
              followers_count, following_count, likes_count, videos_count, created_at
       FROM users WHERE id = $1 OR username = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    // Check if current user follows this user
    if (req.user) {
      const followCheck = await pool.query(
        'SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2',
        [req.user.id, user.id]
      );
      user.is_following = followCheck.rows.length > 0;
    }

    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== VIDEO ROUTES ====================

// Upload video
app.post('/api/videos/upload', authenticate, upload.single('video'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file provided' });
    }

    const { title, description, tags } = req.body;
    const videoUrl = '/uploads/videos/' + req.file.filename;
    const tagsArray = tags ? tags.split(',').map(t => t.trim()) : [];

    const result = await pool.query(
      `INSERT INTO videos (user_id, title, description, video_url, tags)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, title || '', description || '', videoUrl, tagsArray]
    );

    await pool.query(
      'UPDATE users SET videos_count = videos_count + 1 WHERE id = $1',
      [req.user.id]
    );

    res.json({ video: result.rows[0] });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get video feed
app.get('/api/videos/feed', optionalAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, type = 'foryou' } = req.query;
    const offset = (page - 1) * limit;

    let query;
    let params;

    if (type === 'following' && req.user) {
      query = `
        SELECT v.*, u.username, u.display_name, u.avatar, u.is_verified,
               EXISTS(SELECT 1 FROM video_likes WHERE video_id = v.id AND user_id = $1) as is_liked
        FROM videos v
        JOIN users u ON v.user_id = u.id
        WHERE v.is_public = true AND v.user_id IN (
          SELECT following_id FROM follows WHERE follower_id = $1
        )
        ORDER BY v.created_at DESC
        LIMIT $2 OFFSET $3
      `;
      params = [req.user.id, limit, offset];
    } else {
      query = `
        SELECT v.*, u.username, u.display_name, u.avatar, u.is_verified
        ${req.user ? `, EXISTS(SELECT 1 FROM video_likes WHERE video_id = v.id AND user_id = $3) as is_liked` : ''}
        FROM videos v
        JOIN users u ON v.user_id = u.id
        WHERE v.is_public = true
        ORDER BY (v.views * 0.3 + v.likes_count * 0.5 + v.comments_count * 0.2) DESC, v.created_at DESC
        LIMIT $1 OFFSET $2
      `;
      params = req.user ? [limit, offset, req.user.id] : [limit, offset];
    }

    const result = await pool.query(query, params);
    res.json({ videos: result.rows });
  } catch (err) {
    console.error('Feed error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single video
app.get('/api/videos/:id', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.*, u.username, u.display_name, u.avatar, u.is_verified
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Increment views
    await pool.query('UPDATE videos SET views = views + 1 WHERE id = $1', [req.params.id]);

    const video = result.rows[0];
    if (req.user) {
      const likeCheck = await pool.query(
        'SELECT id FROM video_likes WHERE video_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]
      );
      video.is_liked = likeCheck.rows.length > 0;
    }

    res.json({ video });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Like/unlike video
app.post('/api/videos/:id/like', authenticate, async (req, res) => {
  try {
    const videoId = req.params.id;
    const userId = req.user.id;

    const existing = await pool.query(
      'SELECT id FROM video_likes WHERE video_id = $1 AND user_id = $2',
      [videoId, userId]
    );

    let liked;
    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM video_likes WHERE video_id = $1 AND user_id = $2', [videoId, userId]);
      await pool.query('UPDATE videos SET likes_count = likes_count - 1 WHERE id = $1', [videoId]);
      liked = false;
    } else {
      await pool.query('INSERT INTO video_likes (video_id, user_id) VALUES ($1, $2)', [videoId, userId]);
      await pool.query('UPDATE videos SET likes_count = likes_count + 1 WHERE id = $1', [videoId]);
      liked = true;

      // Create notification
      const video = await pool.query('SELECT user_id FROM videos WHERE id = $1', [videoId]);
      if (video.rows[0] && video.rows[0].user_id !== userId) {
        await pool.query(
          `INSERT INTO notifications (user_id, type, title, message, data)
           VALUES ($1, 'like', 'New Like', $2, $3)`,
          [video.rows[0].user_id, `${req.user.username} liked your video`, JSON.stringify({ videoId, userId })]
        );
      }
    }

    const result = await pool.query('SELECT likes_count FROM videos WHERE id = $1', [videoId]);
    res.json({ liked, likes_count: result.rows[0].likes_count });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Add comment
app.post('/api/videos/:id/comment', authenticate, async (req, res) => {
  try {
    const { content, parent_id } = req.body;
    if (!content) {
      return res.status(400).json({ error: 'Comment content required' });
    }

    const result = await pool.query(
      `INSERT INTO comments (video_id, user_id, parent_id, content)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, req.user.id, parent_id || null, content]
    );

    await pool.query('UPDATE videos SET comments_count = comments_count + 1 WHERE id = $1', [req.params.id]);

    const comment = result.rows[0];
    comment.username = req.user.username;
    comment.display_name = req.user.display_name;
    comment.avatar = req.user.avatar;

    res.json({ comment });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get comments
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT c.*, u.username, u.display_name, u.avatar, u.is_verified
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.video_id = $1 AND c.parent_id IS NULL
       ORDER BY c.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );

    // Get replies for each comment
    for (let comment of result.rows) {
      const replies = await pool.query(
        `SELECT c.*, u.username, u.display_name, u.avatar
         FROM comments c
         JOIN users u ON c.user_id = u.id
         WHERE c.parent_id = $1
         ORDER BY c.created_at ASC
         LIMIT 3`,
        [comment.id]
      );
      comment.replies = replies.rows;
    }

    res.json({ comments: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== FOLLOW ROUTES ====================

// Follow user
app.post('/api/follow/:userId', authenticate, async (req, res) => {
  try {
    const followingId = req.params.userId;
    const followerId = req.user.id;

    if (followerId === followingId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }

    const existing = await pool.query(
      'SELECT id FROM follows WHERE follower_id = $1 AND following_id = $2',
      [followerId, followingId]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Already following' });
    }

    await pool.query(
      'INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)',
      [followerId, followingId]
    );

    await pool.query('UPDATE users SET following_count = following_count + 1 WHERE id = $1', [followerId]);
    await pool.query('UPDATE users SET followers_count = followers_count + 1 WHERE id = $1', [followingId]);

    // Create notification
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, data)
       VALUES ($1, 'follow', 'New Follower', $2, $3)`,
      [followingId, `${req.user.username} started following you`, JSON.stringify({ userId: followerId })]
    );

    res.json({ following: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Unfollow user
app.delete('/api/follow/:userId', authenticate, async (req, res) => {
  try {
    const followingId = req.params.userId;
    const followerId = req.user.id;

    const result = await pool.query(
      'DELETE FROM follows WHERE follower_id = $1 AND following_id = $2 RETURNING id',
      [followerId, followingId]
    );

    if (result.rows.length > 0) {
      await pool.query('UPDATE users SET following_count = following_count - 1 WHERE id = $1', [followerId]);
      await pool.query('UPDATE users SET followers_count = followers_count - 1 WHERE id = $1', [followingId]);
    }

    res.json({ following: false });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get followers
app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT u.id, u.username, u.display_name, u.avatar, u.is_verified
       FROM follows f
       JOIN users u ON f.follower_id = u.id
       WHERE f.following_id = $1
       ORDER BY f.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );

    res.json({ followers: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get following
app.get('/api/users/:id/following', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT u.id, u.username, u.display_name, u.avatar, u.is_verified
       FROM follows f
       JOIN users u ON f.following_id = u.id
       WHERE f.follower_id = $1
       ORDER BY f.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );

    res.json({ following: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== WALLET ROUTES ====================

// Get wallet balance
app.get('/api/wallet/balance', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT coins, earnings FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Buy coins
app.post('/api/wallet/buy-coins', authenticate, async (req, res) => {
  try {
    const { package_id, payment_method } = req.body;
    
    const packages = {
      'starter': { coins: 100, price: 0.99 },
      'popular': { coins: 500, price: 4.99 },
      'value': { coins: 1000, price: 9.99 },
      'premium': { coins: 2500, price: 19.99 },
      'mega': { coins: 5000, price: 39.99 },
      'ultimate': { coins: 10000, price: 74.99 }
    };

    const pkg = packages[package_id];
    if (!pkg) {
      return res.status(400).json({ error: 'Invalid package' });
    }

    // In production, process payment with Stripe here
    // For now, just add coins
    await pool.query(
      'UPDATE users SET coins = coins + $1 WHERE id = $2',
      [pkg.coins, req.user.id]
    );

    await pool.query(
      `INSERT INTO coin_transactions (user_id, type, amount, description)
       VALUES ($1, 'purchase', $2, $3)`,
      [req.user.id, pkg.coins, `Purchased ${pkg.coins} coins for $${pkg.price}`]
    );

    const result = await pool.query('SELECT coins FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true, coins: result.rows[0].coins });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== GIFT ROUTES ====================

// Get gift catalog
app.get('/api/gifts/catalog', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM gifts WHERE is_active = true ORDER BY coin_cost ASC'
    );
    if (result.rows.length > 0) {
      res.json({ gifts: result.rows });
    } else {
      // Return fallback gifts if database is empty
      res.json({ gifts: FALLBACK_GIFTS });
    }
  } catch (err) {
    // Return fallback gifts on database error
    console.log('Using fallback gifts catalog');
    res.json({ gifts: FALLBACK_GIFTS });
  }
});

// Send gift
app.post('/api/gifts/send', authenticate, async (req, res) => {
  try {
    const { gift_id, receiver_id, video_id, live_stream_id, quantity = 1, message } = req.body;

    const gift = await pool.query('SELECT * FROM gifts WHERE id = $1', [gift_id]);
    if (gift.rows.length === 0) {
      return res.status(404).json({ error: 'Gift not found' });
    }

    const totalCost = gift.rows[0].coin_cost * quantity;
    const creatorEarnings = gift.rows[0].creator_earnings * quantity;

    if (req.user.coins < totalCost) {
      return res.status(400).json({ error: 'Insufficient coins' });
    }

    // Deduct coins from sender
    await pool.query('UPDATE users SET coins = coins - $1 WHERE id = $2', [totalCost, req.user.id]);

    // Add earnings to receiver
    await pool.query('UPDATE users SET earnings = earnings + $1 WHERE id = $2', [creatorEarnings, receiver_id]);

    // Record transaction
    const result = await pool.query(
      `INSERT INTO gift_transactions (sender_id, receiver_id, gift_id, video_id, live_stream_id, quantity, total_coins, creator_earnings, message)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.id, receiver_id, gift_id, video_id, live_stream_id, quantity, totalCost, creatorEarnings, message]
    );

    // Create notification
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, data)
       VALUES ($1, 'gift', 'Gift Received!', $2, $3)`,
      [receiver_id, `${req.user.username} sent you ${quantity}x ${gift.rows[0].name}!`, 
       JSON.stringify({ giftId: gift_id, senderId: req.user.id, quantity })]
    );

    res.json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    console.error('Send gift error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get received gifts
app.get('/api/gifts/received', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT gt.*, g.name, g.icon, g.animation, u.username, u.display_name, u.avatar
       FROM gift_transactions gt
       JOIN gifts g ON gt.gift_id = g.id
       JOIN users u ON gt.sender_id = u.id
       WHERE gt.receiver_id = $1
       ORDER BY gt.created_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json({ gifts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== MESSAGE ROUTES ====================

// Send message
app.post('/api/messages/send', authenticate, async (req, res) => {
  try {
    const { receiver_id, content } = req.body;
    if (!receiver_id || !content) {
      return res.status(400).json({ error: 'Receiver and content required' });
    }

    // Get or create conversation
    let conversation = await pool.query(
      `SELECT id FROM conversations 
       WHERE (participant1_id = $1 AND participant2_id = $2)
          OR (participant1_id = $2 AND participant2_id = $1)`,
      [req.user.id, receiver_id]
    );

    let conversationId;
    if (conversation.rows.length === 0) {
      const newConv = await pool.query(
        'INSERT INTO conversations (participant1_id, participant2_id) VALUES ($1, $2) RETURNING id',
        [req.user.id, receiver_id]
      );
      conversationId = newConv.rows[0].id;
    } else {
      conversationId = conversation.rows[0].id;
    }

    // Insert message
    const result = await pool.query(
      'INSERT INTO messages (conversation_id, sender_id, content) VALUES ($1, $2, $3) RETURNING *',
      [conversationId, req.user.id, content]
    );

    // Update conversation timestamp
    await pool.query(
      'UPDATE conversations SET last_message_at = NOW() WHERE id = $1',
      [conversationId]
    );

    const message = result.rows[0];
    message.sender_username = req.user.username;
    message.sender_avatar = req.user.avatar;

    res.json({ message });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get conversations
app.get('/api/messages/conversations', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, 
              CASE WHEN c.participant1_id = $1 THEN u2.id ELSE u1.id END as other_user_id,
              CASE WHEN c.participant1_id = $1 THEN u2.username ELSE u1.username END as other_username,
              CASE WHEN c.participant1_id = $1 THEN u2.display_name ELSE u1.display_name END as other_display_name,
              CASE WHEN c.participant1_id = $1 THEN u2.avatar ELSE u1.avatar END as other_avatar,
              (SELECT content FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
              (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != $1 AND is_read = false) as unread_count
       FROM conversations c
       JOIN users u1 ON c.participant1_id = u1.id
       JOIN users u2 ON c.participant2_id = u2.id
       WHERE c.participant1_id = $1 OR c.participant2_id = $1
       ORDER BY c.last_message_at DESC`,
      [req.user.id]
    );
    res.json({ conversations: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get messages in conversation
app.get('/api/messages/:conversationId', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    // Verify user is part of conversation
    const conv = await pool.query(
      'SELECT * FROM conversations WHERE id = $1 AND (participant1_id = $2 OR participant2_id = $2)',
      [req.params.conversationId, req.user.id]
    );

    if (conv.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Mark messages as read
    await pool.query(
      'UPDATE messages SET is_read = true WHERE conversation_id = $1 AND sender_id != $2',
      [req.params.conversationId, req.user.id]
    );

    const result = await pool.query(
      `SELECT m.*, u.username, u.display_name, u.avatar
       FROM messages m
       JOIN users u ON m.sender_id = u.id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.conversationId, limit, offset]
    );

    res.json({ messages: result.rows.reverse() });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== NOTIFICATION ROUTES ====================

// Get notifications
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT * FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    // Get unread count
    const unreadCount = await pool.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false',
      [req.user.id]
    );

    res.json({ 
      notifications: result.rows,
      unread_count: parseInt(unreadCount.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark notifications as read
app.post('/api/notifications/read', authenticate, async (req, res) => {
  try {
    const { ids } = req.body;
    if (ids && ids.length > 0) {
      await pool.query(
        'UPDATE notifications SET is_read = true WHERE id = ANY($1) AND user_id = $2',
        [ids, req.user.id]
      );
    } else {
      await pool.query(
        'UPDATE notifications SET is_read = true WHERE user_id = $1',
        [req.user.id]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== LIVE STREAMING ROUTES ====================

// Start live stream
app.post('/api/live/start', authenticate, async (req, res) => {
  try {
    const { title, description } = req.body;
    const streamKey = uuidv4();

    const result = await pool.query(
      `INSERT INTO live_streams (user_id, title, description, stream_key)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.user.id, title || `${req.user.username}'s Live`, description, streamKey]
    );

    await pool.query('UPDATE users SET is_live = true WHERE id = $1', [req.user.id]);

    res.json({ stream: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// End live stream
app.post('/api/live/end', authenticate, async (req, res) => {
  try {
    const { stream_id } = req.body;

    await pool.query(
      'UPDATE live_streams SET is_active = false, ended_at = NOW() WHERE id = $1 AND user_id = $2',
      [stream_id, req.user.id]
    );

    await pool.query('UPDATE users SET is_live = false WHERE id = $1', [req.user.id]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get active live streams
app.get('/api/live/streams', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ls.*, u.username, u.display_name, u.avatar, u.is_verified, u.followers_count
       FROM live_streams ls
       JOIN users u ON ls.user_id = u.id
       WHERE ls.is_active = true
       ORDER BY ls.viewer_count DESC, ls.started_at DESC`
    );
    res.json({ streams: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single stream
app.get('/api/live/streams/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ls.*, u.username, u.display_name, u.avatar, u.is_verified
       FROM live_streams ls
       JOIN users u ON ls.user_id = u.id
       WHERE ls.id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Stream not found' });
    }

    res.json({ stream: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SEARCH & DISCOVERY ROUTES ====================

// Search
app.get('/api/search', async (req, res) => {
  try {
    const { q, type = 'all', page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const searchTerm = `%${q}%`;

    const results = { users: [], videos: [] };

    if (type === 'all' || type === 'users') {
      const users = await pool.query(
        `SELECT id, username, display_name, avatar, is_verified, followers_count
         FROM users
         WHERE username ILIKE $1 OR display_name ILIKE $1
         ORDER BY followers_count DESC
         LIMIT $2 OFFSET $3`,
        [searchTerm, limit, offset]
      );
      results.users = users.rows;
    }

    if (type === 'all' || type === 'videos') {
      const videos = await pool.query(
        `SELECT v.*, u.username, u.display_name, u.avatar
         FROM videos v
         JOIN users u ON v.user_id = u.id
         WHERE v.is_public = true AND (v.title ILIKE $1 OR v.description ILIKE $1 OR $2 = ANY(v.tags))
         ORDER BY v.views DESC
         LIMIT $3 OFFSET $4`,
        [searchTerm, q, limit, offset]
      );
      results.videos = videos.rows;
    }

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Trending
app.get('/api/trending', async (req, res) => {
  try {
    const { type = 'videos', period = 'day' } = req.query;

    let timeFilter;
    switch (period) {
      case 'hour': timeFilter = "created_at > NOW() - INTERVAL '1 hour'"; break;
      case 'day': timeFilter = "created_at > NOW() - INTERVAL '1 day'"; break;
      case 'week': timeFilter = "created_at > NOW() - INTERVAL '7 days'"; break;
      default: timeFilter = "created_at > NOW() - INTERVAL '1 day'";
    }

    if (type === 'videos') {
      const result = await pool.query(
        `SELECT v.*, u.username, u.display_name, u.avatar, u.is_verified
         FROM videos v
         JOIN users u ON v.user_id = u.id
         WHERE v.is_public = true AND v.${timeFilter}
         ORDER BY (v.views + v.likes_count * 2 + v.comments_count * 3) DESC
         LIMIT 50`
      );
      res.json({ videos: result.rows });
    } else if (type === 'creators') {
      const result = await pool.query(
        `SELECT id, username, display_name, avatar, is_verified, followers_count, likes_count
         FROM users
         WHERE is_creator = true
         ORDER BY followers_count DESC
         LIMIT 50`
      );
      res.json({ creators: result.rows });
    } else if (type === 'hashtags') {
      const result = await pool.query(
        `SELECT unnest(tags) as tag, COUNT(*) as count
         FROM videos
         WHERE ${timeFilter}
         GROUP BY tag
         ORDER BY count DESC
         LIMIT 30`
      );
      res.json({ hashtags: result.rows });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user videos
app.get('/api/users/:id/videos', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT v.*, u.username, u.display_name, u.avatar
       FROM videos v
       JOIN users u ON v.user_id = u.id
       WHERE v.user_id = $1 AND v.is_public = true
       ORDER BY v.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );

    res.json({ videos: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Start server
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NVME Platform running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api`);
  });
});
