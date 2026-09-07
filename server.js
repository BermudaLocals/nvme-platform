// ========================================
// 🚀 NVME.live — Full Server
// ========================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
const liveSFU = require('./modules/live-sfu');

// Optional — push routes no-op (with a log
// line) when the package or VAPID keys are
// missing, so the server still boots.

let webpush = null;

try {
  webpush = require('web-push');
} catch (e) {
  console.warn(
    '⚠️ web-push not installed — push notifications disabled (run npm install)'
  );
}

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

const FRONTEND_URL =
  process.env.NODE_ENV === 'production'
    ? 'https://nvme.live'
    : 'http://localhost:3000';

// ========================================
// 🗄️ Database
// ========================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ DB connection error:', err.stack);
    return;
  }

  console.log('✅ NeonDB connected');

  if (release) release();
});

pool.on('error', (err) => {
  console.error(
    '⚠️ Idle Postgres client error (pool will recover):',
    err.message
  );
});

// ========================================
// 🧠 NVME INTELLIGENCE DATABASE
// ========================================

async function initializeIntelligenceDatabase() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // ------------------------------------
    // Trending topics
    // ------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS trending_topics (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        topic TEXT NOT NULL,
        normalized_topic TEXT,
        source TEXT,
        source_url TEXT,
        source_external_id TEXT,
        category TEXT,
        region TEXT,
        language TEXT DEFAULT 'en',

        trend_score NUMERIC DEFAULT 0,
        velocity_score NUMERIC DEFAULT 0,
        engagement_score NUMERIC DEFAULT 0,
        freshness_score NUMERIC DEFAULT 0,

        status TEXT DEFAULT 'active',

        metadata JSONB DEFAULT '{}'::jsonb,

        first_seen_at TIMESTAMPTZ DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Existing deployments may already have this table.
    // Add missing columns safely.

    const trendColumns = [
      ['topic', 'TEXT'],
      ['normalized_topic', 'TEXT'],
      ['source', 'TEXT'],
      ['source_url', 'TEXT'],
      ['source_external_id', 'TEXT'],
      ['category', 'TEXT'],
      ['region', 'TEXT'],
      ['language', 'TEXT DEFAULT \'en\''],
      ['trend_score', 'NUMERIC DEFAULT 0'],
      ['velocity_score', 'NUMERIC DEFAULT 0'],
      ['engagement_score', 'NUMERIC DEFAULT 0'],
      ['freshness_score', 'NUMERIC DEFAULT 0'],
      ['status', 'TEXT DEFAULT \'active\''],
      ['metadata', 'JSONB DEFAULT \'{}\'::jsonb'],
      ['first_seen_at', 'TIMESTAMPTZ DEFAULT NOW()'],
      ['last_seen_at', 'TIMESTAMPTZ DEFAULT NOW()'],
      ['updated_at', 'TIMESTAMPTZ DEFAULT NOW()'],

      // Scraper-side columns (create-tables.js /
      // src/backend/lib/scraper.js) — both writers
      // share this one table.
      ['title', 'TEXT'],
      ['summary', 'TEXT'],
      ['keywords', 'TEXT[]'],
      ['score', 'INTEGER DEFAULT 50'],
      ['fetched_at', 'TIMESTAMP DEFAULT NOW()'],
      ['nvme_version_id', 'UUID']
    ];

    for (const [column, definition] of trendColumns) {
      await client.query(`
        ALTER TABLE trending_topics
        ADD COLUMN IF NOT EXISTS ${column} ${definition}
      `);
    }

    // Server INSERTs omit `title`, scraper INSERTs omit
    // `topic` — whichever path created the table first left
    // one of them NOT NULL, which would break the other
    // writer. DROP NOT NULL is a no-op when already nullable.
    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN topic DROP NOT NULL
    `);

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN title DROP NOT NULL
    `);

    // ------------------------------------
    // Atomic claims
    // ------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS atomic_claims (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

        trend_id UUID REFERENCES trending_topics(id) ON DELETE SET NULL,

        claim_text TEXT NOT NULL,
        normalized_claim TEXT NOT NULL,
        claim_hash TEXT NOT NULL,

        topic TEXT,
        category TEXT,

        entities JSONB DEFAULT '[]'::jsonb,
        source_urls JSONB DEFAULT '[]'::jsonb,

        confidence_score NUMERIC DEFAULT 0,

        status TEXT DEFAULT 'active',

        video_count INTEGER DEFAULT 0,

        first_seen_at TIMESTAMPTZ DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ------------------------------------
    // Video events
    // ------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS video_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

        video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,

        session_id TEXT,

        event_type TEXT NOT NULL,

        watch_ms INTEGER DEFAULT 0,
        video_duration_ms INTEGER DEFAULT 0,
        position_ms INTEGER DEFAULT 0,

        metadata JSONB DEFAULT '{}'::jsonb,

        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ------------------------------------
    // Video feedback
    // ------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS video_feedback (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,

        feedback_type TEXT NOT NULL,

        created_at TIMESTAMPTZ DEFAULT NOW(),

        UNIQUE(user_id, video_id, feedback_type)
      )
    `);

    // ------------------------------------
    // User topic affinity
    // ------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS user_topic_affinity (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

        topic TEXT NOT NULL,

        score NUMERIC DEFAULT 0,

        views INTEGER DEFAULT 0,
        completions INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        follows INTEGER DEFAULT 0,
        skips INTEGER DEFAULT 0,
        not_interested INTEGER DEFAULT 0,

        updated_at TIMESTAMPTZ DEFAULT NOW(),

        UNIQUE(user_id, topic)
      )
    `);

    // ------------------------------------
    // Video intelligence metadata
    // ------------------------------------

    const videoColumns = [
      ['trending_topic_id', 'UUID'],
      ['atomic_claim_id', 'UUID'],
      ['topic', 'TEXT'],
      ['category', 'TEXT'],
      ['content_score', 'NUMERIC DEFAULT 0'],
      ['completion_rate', 'NUMERIC DEFAULT 0'],
      ['avg_watch_ms', 'NUMERIC DEFAULT 0'],
      ['share_count', 'INTEGER DEFAULT 0'],
      ['save_count', 'INTEGER DEFAULT 0'],
      ['skip_count', 'INTEGER DEFAULT 0'],
      ['not_interested_count', 'INTEGER DEFAULT 0'],
      ['recommendation_score', 'NUMERIC DEFAULT 0'],
      ['impression_count', 'INTEGER DEFAULT 0'],
      ['last_ranked_at', 'TIMESTAMPTZ']
    ];

    for (const [column, definition] of videoColumns) {
      await client.query(`
        ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS ${column} ${definition}
      `);
    }

    // ------------------------------------
    // Foreign keys
    // ------------------------------------

    await client.query(`
      DO $$
      BEGIN

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'videos_trending_topic_id_fkey'
        ) THEN
          ALTER TABLE videos
          ADD CONSTRAINT videos_trending_topic_id_fkey
          FOREIGN KEY (trending_topic_id)
          REFERENCES trending_topics(id)
          ON DELETE SET NULL;
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'videos_atomic_claim_id_fkey'
        ) THEN
          ALTER TABLE videos
          ADD CONSTRAINT videos_atomic_claim_id_fkey
          FOREIGN KEY (atomic_claim_id)
          REFERENCES atomic_claims(id)
          ON DELETE SET NULL;
        END IF;

      EXCEPTION
        WHEN duplicate_object THEN
          NULL;
      END
      $$;
    `);

    // ------------------------------------
    // Indexes
    // ------------------------------------

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_trending_topics_score
      ON trending_topics(trend_score DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_trending_topics_status
      ON trending_topics(status)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_trending_topics_normalized
      ON trending_topics(normalized_topic)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_atomic_claims_hash
      ON atomic_claims(claim_hash)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_atomic_claims_trend
      ON atomic_claims(trend_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_video_events_video
      ON video_events(video_id, created_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_video_events_user
      ON video_events(user_id, created_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_video_feedback_user
      ON video_feedback(user_id, video_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_affinity_user
      ON user_topic_affinity(user_id, score DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_videos_recommendation
      ON videos(recommendation_score DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_videos_topic
      ON videos(topic)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_videos_atomic_claim
      ON videos(atomic_claim_id)
    `);

    await client.query('COMMIT');

    console.log('🧠 NVME Intelligence database ready');
  } catch (error) {
    await client.query('ROLLBACK');

    console.error(
      '❌ Intelligence database initialization failed:',
      error.message
    );
  } finally {
    client.release();
  }
}

// ========================================
// 👤 Public User
// ========================================

function publicUser(u) {
  if (!u) return null;

  return {
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    email: u.email,
    avatar_url: u.avatar_url,
    bio: u.bio,
    profile_link: u.profile_link,
    is_creator: u.is_creator,
    is_verified: u.is_verified,
    email_verified: u.email_verified,
    is_admin: u.is_admin,
    followers: u.follower_count,
    following: u.following_count,
    balance_credits: u.balance_credits,
    paypal_email: u.paypal_email
  };
}

// ========================================
// ✉️ Email (optional SMTP)
// ========================================

// No mail provider is configured by
// default: when SMTP_URL (or SMTP_HOST +
// SMTP_USER/SMTP_PASS) is set AND the
// optional `nodemailer` package is
// installed, mail is delivered for real.
// Otherwise the message is logged so auth
// flows stay testable in development.

function smtpTransportConfig() {
  if (process.env.SMTP_URL) {
    return process.env.SMTP_URL;
  }

  if (process.env.SMTP_HOST) {
    return {
      host: process.env.SMTP_HOST,

      port:
        Number(
          process.env.SMTP_PORT
        ) || 587,

      auth:
        process.env.SMTP_USER
          ? {
              user:
                process.env
                  .SMTP_USER,
              pass:
                process.env
                  .SMTP_PASS
            }
          : undefined
    };
  }

  return null;
}

async function sendEmail({
  to,
  subject,
  text
}) {
  const transportConfig =
    smtpTransportConfig();

  if (transportConfig) {
    try {
      const nodemailer =
        require('nodemailer');

      const transport =
        nodemailer.createTransport(
          transportConfig
        );

      await transport.sendMail({
        from:
          process.env.EMAIL_FROM ||
          'no-reply@nvme.live',
        to,
        subject,
        text
      });

      return true;
    } catch (error) {
      console.error(
        '✉️ SMTP send failed, logging instead:',
        error.message
      );
    }
  }

  console.log(
    `✉️ [email:not-sent] To: ${to} | Subject: ${subject}\n${text}`
  );

  return false;
}

// ========================================
// 🤖 AI Clients
// ========================================

const nvidiaClient = new OpenAI({
  apiKey: process.env.NVIDIA_API_KEY,
  baseURL:
    process.env.NVIDIA_BASE_URL ||
    'https://integrate.api.nvidia.com/v1'
});

const kimiClient = new OpenAI({
  apiKey: process.env.MOONSHOT_API_KEY,
  baseURL:
    process.env.KIMI_BASE_URL ||
    'https://api.moonshot.cn/v1'
});

async function generateWithFallback(
  systemPrompt,
  userPrompt,
  maxTokens
) {
  try {
    const completion =
      await nvidiaClient.chat.completions.create({
        model:
          process.env.NVIDIA_MODEL ||
          'nvidia/llama-3.1-nemotron-70b-instruct',

        messages: [
          {
            role: 'system',
            content: systemPrompt
          },
          {
            role: 'user',
            content: userPrompt
          }
        ],

        temperature: 0.8,
        max_tokens: maxTokens
      });

    return {
      content:
        completion.choices?.[0]?.message?.content || '',
      provider: 'nvidia'
    };
  } catch (e) {
    console.log(
      'NVIDIA failed, falling back to Kimi:',
      e.message
    );
  }

  const completion =
    await kimiClient.chat.completions.create({
      model:
        process.env.KIMI_DEFAULT_MODEL ||
        'kimi-k3',

      messages: [
        {
          role: 'system',
          content: systemPrompt
        },
        {
          role: 'user',
          content: userPrompt
        }
      ],

      temperature: 0.8,
      max_tokens: maxTokens
    });

  return {
    content:
      completion.choices?.[0]?.message?.content || '',
    provider: 'kimi'
  };
}

// ========================================
// 💳 PayPal
// ========================================

function paypalClient() {
  const env =
    process.env.PAYPAL_MODE === 'live'
      ? new paypal.core.LiveEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_CLIENT_SECRET
        )
      : new paypal.core.SandboxEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_CLIENT_SECRET
        );

  return new paypal.core.PayPalHttpClient(env);
}

// ----------------------------------------
// PayPal Payouts (creator withdrawals) —
// the checkout SDK has no Payouts support,
// so these call the REST API directly with
// the same env credentials and the same
// sandbox/live switch as paypalClient().
// ----------------------------------------

function paypalApiBase() {
  return process.env.PAYPAL_MODE ===
    'live'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';
}

function paypalConfigured() {
  return Boolean(
    process.env.PAYPAL_CLIENT_ID &&
      process.env.PAYPAL_CLIENT_SECRET
  );
}

async function paypalAccessToken() {
  const auth =
    Buffer.from(
      `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
    ).toString('base64');

  const response =
    await fetch(
      `${paypalApiBase()}/v1/oauth2/token`,
      {
        method: 'POST',

        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type':
            'application/x-www-form-urlencoded'
        },

        body:
          'grant_type=client_credentials'
      }
    );

  if (!response.ok) {
    throw new Error(
      `PayPal auth failed (${response.status})`
    );
  }

  const data =
    await response.json();

  return data.access_token;
}

// sender_item_id = transaction id, so a
// retried approve is idempotent on
// PayPal's side too.

async function paypalSendPayout({
  transactionId,
  email,
  amountUsd
}) {
  const token =
    await paypalAccessToken();

  const response =
    await fetch(
      `${paypalApiBase()}/v1/payments/payouts`,
      {
        method: 'POST',

        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type':
            'application/json'
        },

        body: JSON.stringify({
          sender_batch_header: {
            sender_batch_id: `withdrawal_${transactionId}`,
            email_subject:
              'Your NVME.live payout is here',
            email_message:
              'Your creator withdrawal from NVME.live has been paid.'
          },

          items: [
            {
              recipient_type:
                'EMAIL',

              amount: {
                value:
                  Number(
                    amountUsd
                  ).toFixed(2),
                currency: 'USD'
              },

              receiver: email,
              note:
                'NVME.live creator withdrawal',
              sender_item_id:
                String(transactionId)
            }
          ]
        })
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `PayPal payout failed (${response.status}): ${
        data.message ||
        data.name ||
        'unknown error'
      }`
    );
  }

  return (
    data.batch_header
      ?.payout_batch_id || null
  );
}

// ========================================
// 🔒 Middleware
// ========================================

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(compression());

app.use(
  cors({
    origin:
      process.env.NODE_ENV === 'production'
        ? [
            'https://nvme.live',
            'https://www.nvme.live'
          ]
        : [
            'http://localhost:3000',
            'http://127.0.0.1:3000'
          ],

    credentials: true
  })
);

app.use(morgan('dev'));

app.use(cookieParser());

app.use(
  express.json({
    limit: '100mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '100mb'
  })
);

app.use(
  session({
    store: new (require('connect-pg-simple')(session))({
      pool,
      createTableIfMissing: true
    }),

    secret:
      process.env.SESSION_SECRET ||
      `${process.env.JWT_SECRET}:session`,

    resave: false,

    saveUninitialized: false,

    cookie: {
      secure:
        process.env.NODE_ENV === 'production',

      maxAge: 5 * 60 * 1000
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,

  message: {
    error:
      'Too many requests, please try again later.'
  }
});

app.use('/api', limiter);

app.use(
  express.static('public', {
    extensions: ['html']
  })
);

// ========================================
// ❤️ Health
// ========================================

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/api/health', async (req, res) => {
  let database = 'unknown';

  try {
    await pool.query('SELECT 1');
    database = 'connected';
  } catch (_) {
    database = 'error';
  }

  res.json({
    status: database === 'connected'
      ? 'healthy'
      : 'degraded',

    database,

    intelligence: true,

    timestamp: new Date().toISOString(),

    uptime: process.uptime()
  });
});

// ========================================
// 🔐 Auth Middleware
// ========================================

const authenticateToken =
  async (req, res, next) => {
    const authHeader =
      req.headers['authorization'];

    const token =
      (authHeader &&
        authHeader.split(' ')[1]) ||
      req.cookies?.token;

    if (!token) {
      return res
        .status(401)
        .json({
          error: 'Access token required'
        });
    }

    try {
      const decoded =
        jwt.verify(
          token,
          process.env.JWT_SECRET
        );

      const result =
        await pool.query(
          'SELECT * FROM users WHERE id = $1',
          [decoded.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error: 'User not found'
          });
      }

      req.user = result.rows[0];

      next();
    } catch (err) {
      return res
        .status(403)
        .json({
          error: 'Invalid or expired token'
        });
    }
  };

const optionalAuth =
  async (req, res, next) => {
    const authHeader =
      req.headers['authorization'];

    const token =
      (authHeader &&
        authHeader.split(' ')[1]) ||
      req.cookies?.token;

    if (!token) return next();

    try {
      const decoded =
        jwt.verify(
          token,
          process.env.JWT_SECRET
        );

      const result =
        await pool.query(
          'SELECT * FROM users WHERE id = $1',
          [decoded.id]
        );

      if (result.rows.length > 0) {
        req.user = result.rows[0];
      }
    } catch (_) {}

    next();
  };

function issueToken(user) {
  return jwt.sign(
    {
      id: user.id,
      is_admin:
        !!user.is_admin
    },

    process.env.JWT_SECRET,

    {
      expiresIn:
        process.env.JWT_EXPIRE ||
        '7d'
    }
  );
}

// ----------------------------------------
// Refresh / one-time token helpers
// ----------------------------------------

function hashToken(token) {
  return crypto
    .createHash('sha256')
    .update(String(token))
    .digest('hex');
}

function generateSecureToken() {
  const raw =
    crypto
      .randomBytes(48)
      .toString('hex');

  return {
    raw,
    hash: hashToken(raw)
  };
}

// 30d refresh token — only the SHA-256
// hash is stored, never the raw token.

async function issueRefreshToken(
  userId
) {
  const { raw, hash } =
    generateSecureToken();

  await pool.query(
    `
    INSERT INTO refresh_tokens
    (
      user_id,
      token_hash,
      expires_at
    )
    VALUES
    (
      $1,
      $2,
      NOW() + INTERVAL '30 days'
    )
    `,
    [userId, hash]
  );

  return raw;
}

async function revokeUserRefreshTokens(
  userId
) {
  await pool.query(
    `
    UPDATE refresh_tokens
    SET revoked_at = NOW()
    WHERE
      user_id = $1
      AND revoked_at IS NULL
    `,
    [userId]
  );
}

// 24h single-use email verification
// token — returns the raw token so the
// caller can build the verify URL.

async function createEmailVerification(
  userId
) {
  const { raw, hash } =
    generateSecureToken();

  await pool.query(
    `
    INSERT INTO email_verifications
    (
      user_id,
      token_hash,
      expires_at
    )
    VALUES
    (
      $1,
      $2,
      NOW() + INTERVAL '24 hours'
    )
    `,
    [userId, hash]
  );

  return raw;
}

// ----------------------------------------
// Admin gate — is_admin is re-read from
// the DB on every request (the JWT claim
// alone is never trusted), so demotion
// takes effect immediately.
// ----------------------------------------

const requireAdmin =
  async (req, res, next) => {
    try {
      const result =
        await pool.query(
          'SELECT is_admin FROM users WHERE id = $1',
          [req.user?.id]
        );

      if (
        result.rows.length === 0 ||
        !result.rows[0].is_admin
      ) {
        return res
          .status(403)
          .json({
            error:
              'Admin access required'
          });
      }

      next();
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to verify admin access'
        });
    }
  };

// ========================================
// 🔑 Auth Routes
// ========================================

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const {
        username,
        email,
        password
      } = req.body;

      if (
        !username ||
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              'username, email, and password are required'
          });
      }

      if (password.length < 8) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters'
          });
      }

      const existing =
        await pool.query(
          'SELECT id FROM users WHERE email = $1 OR username = $2',
          [email, username]
        );

      if (existing.rows.length > 0) {
        return res
          .status(409)
          .json({
            error:
              'Username or email already in use'
          });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `
          INSERT INTO users
          (
            username,
            email,
            password_hash,
            display_name
          )
          VALUES ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            username,
            email,
            passwordHash,
            username
          ]
        );

      const user =
        result.rows[0];

      const refreshToken =
        await issueRefreshToken(
          user.id
        );

      const verificationToken =
        await createEmailVerification(
          user.id
        );

      const verificationUrl =
        `${FRONTEND_URL}/api/auth/verify-email?token=${verificationToken}`;

      await sendEmail({
        to: user.email,
        subject:
          'Verify your NVME.live email',
        text: `Welcome to NVME.live! Verify your email address:\n\n${verificationUrl}\n\nThis link expires in 24 hours.`
      });

      res.json({
        token: issueToken(user),
        refreshToken,
        user: publicUser(user),

        // No mail provider in dev —
        // the URL is logged by sendEmail
        // and echoed here outside prod.

        ...(process.env
            .NODE_ENV !==
          'production'
          ? {
              devVerificationUrl:
                verificationUrl
            }
          : {})
      });
    } catch (error) {
      console.error(
        'Register error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to register'
        });
    }
  }
);

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({
            error:
              'email and password are required'
          });
      }

      const result =
        await pool.query(
          'SELECT * FROM users WHERE email = $1',
          [email]
        );

      if (result.rows.length === 0) {
        return res
          .status(401)
          .json({
            error:
              'Invalid credentials'
          });
      }

      const user =
        result.rows[0];

      if (user.is_banned) {
        return res
          .status(403)
          .json({
            error:
              'Account suspended'
          });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res
          .status(401)
          .json({
            error:
              'Invalid credentials'
          });
      }

      // Unverified email does not block
      // login (product decision: warn
      // only — emailVerified is exposed
      // via /api/auth/me).

      const refreshToken =
        await issueRefreshToken(
          user.id
        );

      res.json({
        token: issueToken(user),
        refreshToken,
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        'Login error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to log in'
        });
    }
  }
);

app.get(
  '/api/auth/me',
  authenticateToken,
  (req, res) => {
    res.json({
      user: publicUser(req.user),
      emailVerified:
        !!req.user
          .email_verified
    });
  }
);

// ========================================
// 🔑 Google OAuth
// ========================================

if (
  process.env.GOOGLE_CLIENT_ID &&
  process.env.GOOGLE_CLIENT_SECRET
) {
  passport.use(
    new GoogleStrategy(
      {
        clientID:
          process.env.GOOGLE_CLIENT_ID,

        clientSecret:
          process.env.GOOGLE_CLIENT_SECRET,

        callbackURL:
          `${FRONTEND_URL}/auth/google/callback`
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {
        try {
          const email =
            profile.emails?.[0]?.value;

          let result =
            await pool.query(
              'SELECT * FROM users WHERE email = $1',
              [email]
            );

          let user =
            result.rows[0];

          if (!user) {
            const baseUsername =
              (
                profile.displayName ||
                email.split('@')[0]
              )
                .replace(
                  /[^a-zA-Z0-9_]/g,
                  ''
                )
                .slice(0, 40) ||
              'user';

            let username =
              baseUsername;

            let n = 0;

            while (
              (
                await pool.query(
                  'SELECT 1 FROM users WHERE username = $1',
                  [username]
                )
              ).rows.length > 0
            ) {
              n += 1;

              username =
                `${baseUsername}${n}`;
            }

            const randomPassword =
              await bcrypt.hash(
                uuidv4(),
                12
              );

            const insertResult =
              await pool.query(
                `
                INSERT INTO users
                (
                  username,
                  email,
                  password_hash,
                  display_name,
                  avatar_url,
                  is_verified,
                  email_verified
                )
                VALUES
                (
                  $1, $2, $3, $4, $5,
                  false,
                  true
                )
                RETURNING *
                `,
                [
                  username,
                  email,
                  randomPassword,
                  profile.displayName ||
                    username,
                  profile.photos?.[0]
                    ?.value || null
                ]
              );

            user =
              insertResult.rows[0];
          }

          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );

  passport.serializeUser(
    (user, done) =>
      done(null, user.id)
  );

  passport.deserializeUser(
    async (id, done) => {
      try {
        const result =
          await pool.query(
            'SELECT * FROM users WHERE id = $1',
            [id]
          );

        done(
          null,
          result.rows[0]
        );
      } catch (err) {
        done(err);
      }
    }
  );

  app.get(
    '/auth/google',
    passport.authenticate(
      'google',
      {
        scope: [
          'profile',
          'email'
        ]
      }
    )
  );

  app.get(
    '/auth/google/callback',

    passport.authenticate(
      'google',
      {
        session: false,

        failureRedirect:
          `${FRONTEND_URL}/?auth_error=1`
      }
    ),

    async (req, res) => {
      try {
        // Never put the JWT in the
        // redirect URL (leaks into logs
        // and browser history) — hand
        // out a 5-minute single-use
        // code instead; the client
        // swaps it via
        // POST /api/auth/oauth-exchange.

        const { raw, hash } =
          generateSecureToken();

        await pool.query(
          `
          INSERT INTO oauth_codes
          (
            user_id,
            code_hash,
            expires_at
          )
          VALUES
          (
            $1,
            $2,
            NOW() + INTERVAL '5 minutes'
          )
          `,
          [req.user.id, hash]
        );

        res.cookie(
          'oauth_code',
          raw,
          {
            httpOnly: true,
            secure:
              process.env
                .NODE_ENV ===
              'production',
            sameSite: 'lax',
            maxAge:
              5 * 60 * 1000
          }
        );

        res.redirect(
          `${FRONTEND_URL}/app?code=${raw}`
        );
      } catch (error) {
        console.error(
          'OAuth callback error:',
          error
        );

        res.redirect(
          `${FRONTEND_URL}/?auth_error=1`
        );
      }
    }
  );
} else {
  app.get(
    '/auth/google',
    (req, res) =>
      res
        .status(503)
        .json({
          error:
            'Google OAuth not configured'
        })
  );
}

// ========================================
// 🔄 Refresh / Logout
// ========================================

app.post(
  '/api/auth/refresh',
  async (req, res) => {
    try {
      const { refreshToken } =
        req.body;

      if (!refreshToken) {
        return res
          .status(400)
          .json({
            error:
              'refreshToken is required'
          });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            user_id
          FROM refresh_tokens
          WHERE
            token_hash = $1
            AND revoked_at IS NULL
            AND expires_at > NOW()
          `,
          [hashToken(refreshToken)]
        );

      if (result.rows.length === 0) {
        return res
          .status(401)
          .json({
            error:
              'Invalid or expired refresh token'
          });
      }

      const stored =
        result.rows[0];

      const userResult =
        await pool.query(
          'SELECT * FROM users WHERE id = $1',
          [stored.user_id]
        );

      if (
        userResult.rows.length === 0
      ) {
        return res
          .status(401)
          .json({
            error:
              'Invalid or expired refresh token'
          });
      }

      const user =
        userResult.rows[0];

      if (user.is_banned) {
        await revokeUserRefreshTokens(
          user.id
        );

        return res
          .status(403)
          .json({
            error:
              'Account suspended'
          });
      }

      // Rotate: the presented token is
      // revoked and a fresh pair issued.

      await pool.query(
        `
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE id = $1
        `,
        [stored.id]
      );

      res.json({
        token: issueToken(user),
        refreshToken:
          await issueRefreshToken(
            user.id
          ),
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        'Refresh error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to refresh token'
        });
    }
  }
);

app.post(
  '/api/auth/logout',
  async (req, res) => {
    try {
      const { refreshToken } =
        req.body;

      if (refreshToken) {
        await pool.query(
          `
          UPDATE refresh_tokens
          SET revoked_at = NOW()
          WHERE
            token_hash = $1
            AND revoked_at IS NULL
          `,
          [hashToken(refreshToken)]
        );
      }

      // Idempotent — unknown tokens get
      // the same success response.

      res.json({ success: true });
    } catch (error) {
      console.error(
        'Logout error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to log out'
        });
    }
  }
);

// ========================================
// ✉️ Email Verification
// ========================================

app.get(
  '/api/auth/verify-email',
  async (req, res) => {
    try {
      const { token } =
        req.query;

      if (token) {
        const result =
          await pool.query(
            `
            SELECT
              id,
              user_id
            FROM email_verifications
            WHERE
              token_hash = $1
              AND used_at IS NULL
              AND expires_at > NOW()
            `,
            [hashToken(token)]
          );

        if (
          result.rows.length > 0
        ) {
          const row =
            result.rows[0];

          await pool.query(
            `
            UPDATE email_verifications
            SET used_at = NOW()
            WHERE id = $1
            `,
            [row.id]
          );

          await pool.query(
            `
            UPDATE users
            SET
              email_verified =
                true
            WHERE id = $1
            `,
            [row.user_id]
          );

          return res.redirect(
            `${FRONTEND_URL}/app?verified=1`
          );
        }
      }

      return res.redirect(
        `${FRONTEND_URL}/app?verify_error=1`
      );
    } catch (error) {
      console.error(
        'Verify email error:',
        error
      );

      return res.redirect(
        `${FRONTEND_URL}/app?verify_error=1`
      );
    }
  }
);

app.post(
  '/api/auth/resend-verification',
  authenticateToken,
  async (req, res) => {
    try {
      if (
        req.user.email_verified
      ) {
        return res.json({
          success: true,
          alreadyVerified: true
        });
      }

      const verificationToken =
        await createEmailVerification(
          req.user.id
        );

      const verificationUrl =
        `${FRONTEND_URL}/api/auth/verify-email?token=${verificationToken}`;

      await sendEmail({
        to: req.user.email,
        subject:
          'Verify your NVME.live email',
        text: `Verify your email address:\n\n${verificationUrl}\n\nThis link expires in 24 hours.`
      });

      res.json({
        success: true,

        ...(process.env
            .NODE_ENV !==
          'production'
          ? {
              devVerificationUrl:
                verificationUrl
            }
          : {})
      });
    } catch (error) {
      console.error(
        'Resend verification error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to resend verification'
        });
    }
  }
);

// ========================================
// 🔑 Password Reset
// ========================================

app.post(
  '/api/auth/forgot-password',
  async (req, res) => {
    try {
      const { email } =
        req.body;

      // Always succeed — the response
      // must not reveal whether the
      // email is registered.

      if (email) {
        const result =
          await pool.query(
            'SELECT id, email FROM users WHERE email = $1',
            [email]
          );

        if (
          result.rows.length > 0
        ) {
          const user =
            result.rows[0];

          const {
            raw,
            hash
          } =
            generateSecureToken();

          await pool.query(
            `
            INSERT INTO password_resets
            (
              user_id,
              token_hash,
              expires_at
            )
            VALUES
            (
              $1,
              $2,
              NOW() + INTERVAL '1 hour'
            )
            `,
            [user.id, hash]
          );

          const resetUrl =
            `${FRONTEND_URL}/app?reset_token=${raw}`;

          await sendEmail({
            to: user.email,
            subject:
              'Reset your NVME.live password',
            text: `A password reset was requested for your account:\n\n${resetUrl}\n\nThis link expires in 1 hour. If you did not request it, ignore this email.`
          });

          if (
            process.env
              .NODE_ENV !==
            'production'
          ) {
            console.log(
              `🔑 Dev reset URL for ${user.email}: ${resetUrl}`
            );
          }
        }
      }

      res.json({ success: true });
    } catch (error) {
      console.error(
        'Forgot password error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to process request'
        });
    }
  }
);

app.post(
  '/api/auth/reset-password',
  async (req, res) => {
    try {
      const {
        token,
        password
      } = req.body;

      if (!token || !password) {
        return res
          .status(400)
          .json({
            error:
              'token and password are required'
          });
      }

      if (password.length < 8) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters'
          });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            user_id
          FROM password_resets
          WHERE
            token_hash = $1
            AND used_at IS NULL
            AND expires_at > NOW()
          `,
          [hashToken(token)]
        );

      if (result.rows.length === 0) {
        return res
          .status(400)
          .json({
            error:
              'Invalid or expired reset token'
          });
      }

      const reset =
        result.rows[0];

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      await pool.query(
        `
        UPDATE users
        SET
          password_hash = $1
        WHERE id = $2
        `,
        [
          passwordHash,
          reset.user_id
        ]
      );

      await pool.query(
        `
        UPDATE password_resets
        SET used_at = NOW()
        WHERE id = $1
        `,
        [reset.id]
      );

      // Force re-login on every other
      // device/session.

      await revokeUserRefreshTokens(
        reset.user_id
      );

      res.json({ success: true });
    } catch (error) {
      console.error(
        'Reset password error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to reset password'
        });
    }
  }
);

// ========================================
// 🔁 OAuth Code Exchange
// ========================================

app.post(
  '/api/auth/oauth-exchange',
  async (req, res) => {
    try {
      const { code } =
        req.body;

      if (!code) {
        return res
          .status(400)
          .json({
            error:
              'code is required'
          });
      }

      // When the browser carries the
      // HttpOnly cookie set by the OAuth
      // callback, it must match the code
      // being exchanged.

      if (
        req.cookies?.oauth_code &&
        req.cookies
          .oauth_code !== code
      ) {
        return res
          .status(401)
          .json({
            error:
              'Invalid or expired code'
          });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            user_id
          FROM oauth_codes
          WHERE
            code_hash = $1
            AND used_at IS NULL
            AND expires_at > NOW()
          `,
          [hashToken(code)]
        );

      if (result.rows.length === 0) {
        return res
          .status(401)
          .json({
            error:
              'Invalid or expired code'
          });
      }

      const oauthCode =
        result.rows[0];

      await pool.query(
        `
        UPDATE oauth_codes
        SET used_at = NOW()
        WHERE id = $1
        `,
        [oauthCode.id]
      );

      const userResult =
        await pool.query(
          'SELECT * FROM users WHERE id = $1',
          [oauthCode.user_id]
        );

      if (
        userResult.rows.length === 0
      ) {
        return res
          .status(401)
          .json({
            error:
              'Invalid or expired code'
          });
      }

      const user =
        userResult.rows[0];

      res.clearCookie(
        'oauth_code'
      );

      res.json({
        token: issueToken(user),
        refreshToken:
          await issueRefreshToken(
            user.id
          ),
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        'OAuth exchange error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to exchange code'
        });
    }
  }
);

// ========================================
// 🤖 AI Studio
// ========================================

const AI_PROMPTS = {
  script: (topic) =>
    `Write a viral short-video script for: ${topic}. Include hook, body, and CTA.`,

  caption: (topic) =>
    `Write 5 engaging captions for: ${topic}. Include hashtags.`,

  hashtags: (topic) =>
    `Generate 30+ trending hashtags for: ${topic}.`,

  idea: (topic) =>
    `Generate 10 viral content ideas for: ${topic}.`
};

const AI_SYSTEM_PROMPT =
  'You are a viral content expert for social media creators.';

function tokenBudget(user) {
  const isPro =
    user.is_creator ||
    (
      user.plan_ends &&
      new Date(user.plan_ends) >
        new Date()
    );

  return isPro
    ? 2000
    : 1000;
}

app.get(
  '/api/ai/status',
  authenticateToken,
  (req, res) => {
    res.json({
      ok: true,
      providers: [
        'nvidia',
        'kimi'
      ],
      studio:
        'nvme-ai-studio'
    });
  }
);

app.get(
  '/api/ai/usage',
  authenticateToken,
  (req, res) => {
    res.json({
      ok: true,
      providers: [
        'nvidia',
        'kimi'
      ],
      studio:
        'nvme-ai-studio'
    });
  }
);

app.post(
  '/api/ai/generate',
  authenticateToken,
  async (req, res) => {
    try {
      const { prompt } =
        req.body;

      if (!prompt) {
        return res
          .status(400)
          .json({
            error:
              'prompt is required'
          });
      }

      const {
        content,
        provider
      } =
        await generateWithFallback(
          AI_SYSTEM_PROMPT,
          prompt,
          tokenBudget(req.user)
        );

      res.json({
        success: true,
        content,
        provider
      });
    } catch (error) {
      console.error(
        'AI generate error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'All AI providers failed'
        });
    }
  }
);

for (
  const type of [
    'captions',
    'hashtags',
    'script'
  ]
) {
  app.post(
    `/api/ai/${type}`,
    authenticateToken,
    async (req, res) => {
      try {
        const { topic } =
          req.body;

        if (!topic) {
          return res
            .status(400)
            .json({
              error:
                'topic is required'
            });
        }

        const key =
          type === 'captions'
            ? 'caption'
            : type;

        const userPrompt =
          (
            AI_PROMPTS[key] ||
            AI_PROMPTS.idea
          )(topic);

        const {
          content,
          provider
        } =
          await generateWithFallback(
            AI_SYSTEM_PROMPT,
            userPrompt,
            tokenBudget(req.user)
          );

        res.json({
          success: true,
          content,
          provider
        });
      } catch (error) {
        console.error(
          `AI ${type} error:`,
          error
        );

        res
          .status(500)
          .json({
            error:
              'All AI providers failed'
          });
      }
    }
  );
}

// ========================================
// 🧠 INTELLIGENCE HELPERS
// ========================================

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hashText(value) {
  const crypto =
    require('crypto');

  return crypto
    .createHash('sha256')
    .update(normalizeText(value))
    .digest('hex');
}

function clamp(
  value,
  min,
  max
) {
  return Math.max(
    min,
    Math.min(max, value)
  );
}

function safeNumber(value) {
  const n =
    Number(value);

  return Number.isFinite(n)
    ? n
    : 0;
}

function parseJsonResponse(text) {
  try {
    return JSON.parse(text);
  } catch (_) {}

  const match =
    String(text || '')
      .match(/\{[\s\S]*\}/);

  if (!match) {
    return null;
  }

  try {
    return JSON.parse(
      match[0]
    );
  } catch (_) {
    return null;
  }
}

// ========================================
// 🔥 TREND ENGINE
// ========================================

async function calculateTrendScore(
  topicId
) {
  const result =
    await pool.query(
      `
      SELECT
        trend_score,
        velocity_score,
        engagement_score,
        freshness_score,
        first_seen_at,
        last_seen_at
      FROM trending_topics
      WHERE id = $1
      `,
      [topicId]
    );

  if (!result.rows.length) {
    return null;
  }

  const row =
    result.rows[0];

  const now =
    Date.now();

  const lastSeen =
    new Date(
      row.last_seen_at
    ).getTime();

  const ageHours =
    Math.max(
      0,
      (now - lastSeen) /
        3600000
    );

  const freshness =
    Math.exp(
      -ageHours / 24
    ) * 100;

  const score =
    safeNumber(
      row.velocity_score
    ) * 0.35 +

    safeNumber(
      row.engagement_score
    ) * 0.25 +

    freshness * 0.20 +

    safeNumber(
      row.trend_score
    ) * 0.20;

  const finalScore =
    clamp(
      score,
      0,
      100
    );

  await pool.query(
    `
    UPDATE trending_topics
    SET
      trend_score = $1,
      freshness_score = $2,
      updated_at = NOW()
    WHERE id = $3
    `,
    [
      finalScore,
      freshness,
      topicId
    ]
  );

  return finalScore;
}

// ----------------------------------------
// Create/update trend
// ----------------------------------------

async function upsertTrend({
  topic,
  source,
  sourceUrl,
  externalId,
  category,
  region,
  language,
  score,
  metadata
}) {
  const normalized =
    normalizeText(topic);

  if (!normalized) {
    return null;
  }

  const existing =
    await pool.query(
      `
      SELECT *
      FROM trending_topics
      WHERE normalized_topic = $1
        AND COALESCE(source, '') = COALESCE($2, '')
      ORDER BY last_seen_at DESC
      LIMIT 1
      `,
      [
        normalized,
        source || ''
      ]
    );

  if (existing.rows.length) {
    const current =
      existing.rows[0];

    const nextScore =
      Math.max(
        safeNumber(
          current.trend_score
        ),
        safeNumber(score)
      );

    const updated =
      await pool.query(
        `
        UPDATE trending_topics
        SET
          topic = $1,
          source_url = COALESCE($2, source_url),
          source_external_id = COALESCE($3, source_external_id),
          category = COALESCE($4, category),
          region = COALESCE($5, region),
          language = COALESCE($6, language),
          trend_score = $7,
          velocity_score = GREATEST(
            COALESCE(velocity_score, 0),
            $8
          ),
          metadata = COALESCE(metadata, '{}'::jsonb)
                     || COALESCE($9::jsonb, '{}'::jsonb),
          last_seen_at = NOW(),
          updated_at = NOW()
        WHERE id = $10
        RETURNING *
        `,
        [
          topic,
          sourceUrl || null,
          externalId || null,
          category || null,
          region || null,
          language || 'en',
          nextScore,
          safeNumber(score),
          JSON.stringify(
            metadata || {}
          ),
          current.id
        ]
      );

    return updated.rows[0];
  }

  const inserted =
    await pool.query(
      `
      INSERT INTO trending_topics
      (
        topic,
        normalized_topic,
        source,
        source_url,
        source_external_id,
        category,
        region,
        language,
        trend_score,
        velocity_score,
        metadata
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        $11
      )
      RETURNING *
      `,
      [
        topic,
        normalized,
        source || 'manual',
        sourceUrl || null,
        externalId || null,
        category || null,
        region || null,
        language || 'en',
        safeNumber(score),
        safeNumber(score),
        JSON.stringify(
          metadata || {}
        )
      ]
    );

  return inserted.rows[0];
}

// ----------------------------------------
// Extract atomic claims
// ----------------------------------------

async function extractAtomicClaims(
  trend
) {
  const prompt = `
Analyze this trending topic:

TOPIC:
${trend.topic}

SOURCE:
${trend.source || 'unknown'}

CATEGORY:
${trend.category || 'general'}

Return ONLY valid JSON using this exact structure:

{
  "claims": [
    {
      "claim": "one factual atomic claim",
      "normalized_claim": "normalized factual claim",
      "entities": ["entity1"],
      "confidence": 0.0
    }
  ]
}

Rules:

1. Produce 1-5 atomic claims.
2. Each claim must express one distinct factual idea.
3. Do not invent facts.
4. Do not combine multiple facts into one claim.
5. If the supplied information is insufficient, keep the claim conservative.
6. Confidence must be between 0 and 1.
`;

  try {
    const {
      content,
      provider
    } =
      await generateWithFallback(
        `
You are the NVME.live Atomic Claim Engine.

Your job is to break trending subjects into distinct factual claims that can be independently verified and used to generate short-form videos.

Never fabricate information.

Return JSON only.
        `,
        prompt,
        1800
      );

    const parsed =
      parseJsonResponse(
        content
      );

    if (
      !parsed ||
      !Array.isArray(
        parsed.claims
      )
    ) {
      return [];
    }

    return parsed.claims
      .filter(
        claim =>
          claim &&
          claim.claim
      )
      .map(
        claim => ({
          ...claim,
          provider
        })
      );
  } catch (error) {
    console.error(
      'Atomic claim extraction error:',
      error.message
    );

    return [];
  }
}

// ----------------------------------------
// Deduplicate atomic claim
// ----------------------------------------

async function createOrGetAtomicClaim(
  trend,
  claim
) {
  const normalized =
    normalizeText(
      claim.normalized_claim ||
      claim.claim
    );

  if (!normalized) {
    return null;
  }

  const claimHash =
    hashText(normalized);

  const existing =
    await pool.query(
      `
      SELECT *
      FROM atomic_claims
      WHERE claim_hash = $1
      LIMIT 1
      `,
      [claimHash]
    );

  if (existing.rows.length) {
    const row =
      existing.rows[0];

    await pool.query(
      `
      UPDATE atomic_claims
      SET
        last_seen_at = NOW(),
        confidence_score = GREATEST(
          COALESCE(confidence_score, 0),
          $1
        ),
        source_urls =
          COALESCE(source_urls, '[]'::jsonb)
          || COALESCE($2::jsonb, '[]'::jsonb),
        updated_at = NOW()
      WHERE id = $3
      `,
      [
        clamp(
          safeNumber(
            claim.confidence
          ),
          0,
          1
        ),
        JSON.stringify(
          trend.source_url
            ? [trend.source_url]
            : []
        ),
        row.id
      ]
    );

    return row;
  }

  const inserted =
    await pool.query(
      `
      INSERT INTO atomic_claims
      (
        trend_id,
        claim_text,
        normalized_claim,
        claim_hash,
        topic,
        category,
        entities,
        source_urls,
        confidence_score
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9
      )
      RETURNING *
      `,
      [
        trend.id,
        claim.claim,
        normalized,
        claimHash,
        trend.topic,
        trend.category || null,
        JSON.stringify(
          Array.isArray(
            claim.entities
          )
            ? claim.entities
            : []
        ),
        JSON.stringify(
          trend.source_url
            ? [trend.source_url]
            : []
        ),
        clamp(
          safeNumber(
            claim.confidence
          ),
          0,
          1
        )
      ]
    );

  return inserted.rows[0];
}

// ========================================
// 📈 TRENDING API
// ========================================

// Submit a trend from any source.

app.post(
  '/api/trending/ingest',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        topic,
        source,
        source_url,
        source_external_id,
        category,
        region,
        language,
        score,
        metadata
      } = req.body;

      if (!topic) {
        return res
          .status(400)
          .json({
            error:
              'topic is required'
          });
      }

      const trend =
        await upsertTrend({
          topic,
          source,
          sourceUrl:
            source_url,
          externalId:
            source_external_id,
          category,
          region,
          language,
          score,
          metadata
        });

      res.json({
        success: true,
        trend
      });
    } catch (error) {
      console.error(
        'Trend ingest error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to ingest trend'
        });
    }
  }
);

// Batch ingest.

app.post(
  '/api/trending/ingest/batch',
  authenticateToken,
  async (req, res) => {
    try {
      const trends =
        Array.isArray(
          req.body?.trends
        )
          ? req.body.trends
          : [];

      if (!trends.length) {
        return res
          .status(400)
          .json({
            error:
              'trends array is required'
          });
      }

      const results = [];

      for (
        const item of trends
      ) {
        if (!item?.topic) {
          continue;
        }

        const trend =
          await upsertTrend({
            topic:
              item.topic,

            source:
              item.source,

            sourceUrl:
              item.source_url,

            externalId:
              item.source_external_id,

            category:
              item.category,

            region:
              item.region,

            language:
              item.language,

            score:
              item.score,

            metadata:
              item.metadata
          });

        results.push(
          trend
        );
      }

      res.json({
        success: true,
        count:
          results.length,
        trends: results
      });
    } catch (error) {
      console.error(
        'Batch trend ingest error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to ingest trends'
        });
    }
  }
);

// Get trends.

app.get(
  '/api/trending',
  async (req, res) => {
    try {
      const limit =
        clamp(
          parseInt(
            req.query.limit
          ) || 30,
          1,
          100
        );

      const category =
        req.query.category;

      const params =
        [limit];

      let where =
        `
        WHERE status = 'active'
        AND (
          last_seen_at >
          NOW() - INTERVAL '7 days'
        )
        `;

      if (category) {
        params.push(
          category
        );

        where +=
          ` AND category = $${params.length}`;
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM trending_topics
          ${where}
          ORDER BY
            trend_score DESC,
            last_seen_at DESC
          LIMIT $1
          `,
          params
        );

      res.json({
        trends:
          result.rows
      });
    } catch (error) {
      console.error(
        'Trending list error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch trending topics'
        });
    }
  }
);

// Generate atomic claims from a trend.

app.post(
  '/api/trending/:id/claims',
  authenticateToken,
  async (req, res) => {
    try {
      const trendResult =
        await pool.query(
          `
          SELECT *
          FROM trending_topics
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!trendResult.rows.length) {
        return res
          .status(404)
          .json({
            error:
              'Trend not found'
          });
      }

      const trend =
        trendResult.rows[0];

      const extracted =
        await extractAtomicClaims(
          trend
        );

      const claims = [];

      for (
        const claim of extracted
      ) {
        const row =
          await createOrGetAtomicClaim(
            trend,
            claim
          );

        if (row) {
          claims.push(row);
        }
      }

      res.json({
        success: true,
        trend,
        claims
      });
    } catch (error) {
      console.error(
        'Atomic claims API error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to create atomic claims'
        });
    }
  }
);

// Get claims.

app.get(
  '/api/trending/:id/claims',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM atomic_claims
          WHERE trend_id = $1
          ORDER BY
            confidence_score DESC,
            created_at DESC
          `,
          [req.params.id]
        );

      res.json({
        claims:
          result.rows
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch claims'
        });
    }
  }
);

// ========================================
// 📹 Video Upload
// ========================================

cloudinary.config({
  cloud_name:
    process.env.CLOUDINARY_CLOUD_NAME,

  api_key:
    process.env.CLOUDINARY_API_KEY,

  api_secret:
    process.env.CLOUDINARY_API_SECRET
});

// Uploads land on disk first, not in
// memory — a 2GB upload held in a RAM
// buffer can OOM the process. The
// route streams the temp file to
// Cloudinary, then unlinks it.
// mkdirSync because git doesn't ship
// empty dirs, so storage/temp may not
// exist on a fresh deploy.

const uploadTempDir =
  path.join(
    __dirname,
    'storage',
    'temp'
  );

fs.mkdirSync(
  uploadTempDir,
  { recursive: true }
);

// Adaptive HLS: requested as an async
// eager transformation at upload time
// (Cloudinary transcodes — no local
// ffmpeg). The derived master playlist
// URL is deterministic, so the row
// stores it immediately; playback
// falls back to the MP4 until the
// transcode finishes.

const HLS_STREAMING_PROFILE =
  process.env
    .CLOUDINARY_STREAMING_PROFILE ||
  'full_hd';

const upload =
  multer({
    storage:
      multer.diskStorage({
        destination:
          uploadTempDir
      }),

    limits: {
      fileSize:
        parseInt(
          process.env.MAX_VIDEO_SIZE
        ) ||
        2147483648
    },

    fileFilter: (
      req,
      file,
      cb
    ) => {
      const allowedTypes = [
        'video/mp4',
        'video/mov',
        'video/avi',
        'video/mkv',
        'video/webm',
        'video/quicktime'
      ];

      allowedTypes.includes(
        file.mimetype
      )
        ? cb(null, true)
        : cb(
            new Error(
              'Invalid file type.'
            )
          );
    }
  });

app.post(
  '/api/upload',
  authenticateToken,
  upload.single('video'),
  async (req, res) => {
    try {
      const user =
        req.user;

      const {
        title,
        description,
        tags,
        topic,
        category,
        trending_topic_id,
        atomic_claim_id,
        sound_id
      } = req.body;

      if (
        !req.file ||
        !title
      ) {
        return res
          .status(400)
          .json({
            error:
              'Video file and title are required'
          });
      }

      // Optional attached sound — must
      // resolve to a real public library
      // entry (migration 015).
      let soundId = null;

      if (sound_id) {
        if (
          !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
            sound_id
          )
        ) {
          return res
            .status(400)
            .json({
              error:
                'Invalid sound_id'
            });
        }

        const sound =
          await pool.query(
            'SELECT id FROM sounds WHERE id = $1 AND is_public = true',
            [sound_id]
          );

        if (!sound.rows.length) {
          return res
            .status(400)
            .json({
              error:
                'Sound not found'
            });
        }

        soundId = sound_id;
      }

      const videoId =
        uuidv4();

      let videoUrl = '';
      let thumbnailUrl = '';
      let hlsUrl = '';

      try {
        const result =
          await new Promise(
            (
              resolve,
              reject
            ) => {
              const uploadStream =
                cloudinary
                  .uploader
                  .upload_stream(
                    {
                      resource_type:
                        'video',

                      public_id:
                        `videos/${videoId}`,

                      folder:
                        'nvme-videos',

                      eager: [
                        // eager[0] stays
                        // the 720x480 pad —
                        // the thumbnail
                        // below reads it.
                        {
                          width: 720,
                          height: 480,
                          crop: 'pad'
                        },
                        // Adaptive HLS
                        // ladder (.m3u8);
                        // eager_async is
                        // already true, so
                        // the response
                        // doesn't wait on
                        // transcoding.
                        {
                          streaming_profile:
                            HLS_STREAMING_PROFILE,

                          format:
                            'm3u8'
                        }
                      ],

                      eager_async:
                        true
                    },

                    (
                      error,
                      result
                    ) =>
                      error
                        ? reject(
                            error
                          )
                        : resolve(
                            result
                          )
                  );

              const fileStream =
                fs.createReadStream(
                  req.file.path
                );

              fileStream.on(
                'error',
                reject
              );

              fileStream.pipe(
                uploadStream
              );
            }
          );

        videoUrl =
          result.secure_url;

        thumbnailUrl =
          result.eager?.[0]
            ?.secure_url ||
          result.secure_url
            .replace(
              '.mp4',
              '.jpg'
            );

        // Deterministic eager URL —
        // same rewrite trick as the
        // thumbnail: sp_<profile> after
        // /upload/, trailing extension
        // swapped for .m3u8. Async
        // transcode means the playlist
        // 404s briefly; the player
        // falls back to the MP4
        // meanwhile.
        hlsUrl =
          result.secure_url
            .replace(
              '/upload/',
              `/upload/sp_${HLS_STREAMING_PROFILE}/`
            )
            .replace(
              /\.[a-z0-9]+$/i,
              '.m3u8'
            );
      } catch (
        uploadError
      ) {
        console.error(
          'Cloudinary error:',
          uploadError
        );

        return res
          .status(500)
          .json({
            error:
              'Failed to upload video to Cloudinary'
          });
      }

      const result =
        await pool.query(
          `
          INSERT INTO videos
          (
            id,
            user_id,
            title,
            description,
            video_url,
            thumbnail_url,
            hls_url,
            tags,
            topic,
            category,
            trending_topic_id,
            atomic_claim_id,
            sound_id,
            is_published
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8::text[],
            $9,
            $10,
            $11,
            $12,
            $13,
            true
          )
          RETURNING *
          `,
          [
            videoId,
            user.id,
            title,
            description || '',
            videoUrl,
            thumbnailUrl,
            hlsUrl || null,

            tags
              ? tags
                  .split(',')
                  .map(
                    t =>
                      t.trim()
                  )
              : [],

            topic || null,
            category || null,
            trending_topic_id ||
              null,
            atomic_claim_id ||
              null,
            soundId
          ]
        );

      if (soundId) {
        // Keep the library counters in
        // sync — use_count is the 013
        // column the library routes
        // order by; usage_count is the
        // 015 one.
        await pool.query(
          `
          UPDATE sounds
          SET
            usage_count =
              COALESCE(usage_count, 0) + 1,
            use_count =
              COALESCE(use_count, 0) + 1
          WHERE id = $1
          `,
          [soundId]
        );
      }

      if (atomic_claim_id) {
        await pool.query(
          `
          UPDATE atomic_claims
          SET
            video_count =
              COALESCE(video_count, 0) + 1,
            updated_at = NOW()
          WHERE id = $1
          `,
          [atomic_claim_id]
        );
      }

      res.json({
        success: true,
        url: videoUrl,
        thumbnail:
          thumbnailUrl,
        video:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Upload error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to upload video'
        });
    } finally {
      // Disk-backed upload: drop the
      // temp file on every exit path —
      // success, Cloudinary failure,
      // and the early 400 above all
      // land here. ENOENT is fine.
      if (
        req.file &&
        req.file.path
      ) {
        fs.unlink(
          req.file.path,
          () => {}
        );
      }
    }
  }
);

// ========================================
// 🎵 Sound Upload (artist songs)
// ========================================
// Audio counterpart of /api/upload:
// same disk-then-Cloudinary flow with
// an audio-only filter and a 25MB cap.
// Cloudinary serves audio under the
// 'video' resource type. Rows land in
// the sounds library table (see
// db/migration_015_sounds_upload.sql).

const SOUND_MAX_BYTES =
  25 * 1024 * 1024;

const SOUND_EXTS = [
  '.mp3',
  '.wav',
  '.m4a',
  '.ogg',
  '.aac'
];

const soundUpload =
  multer({
    storage:
      multer.diskStorage({
        destination:
          uploadTempDir
      }),

    limits: {
      fileSize:
        SOUND_MAX_BYTES
    },

    fileFilter: (
      req,
      file,
      cb
    ) => {
      const ext =
        path
          .extname(
            file.originalname ||
              ''
          )
          .toLowerCase();

      const okExt =
        SOUND_EXTS.includes(
          ext
        );

      const okMime =
        (
          file.mimetype || ''
        ).startsWith(
          'audio/'
        ) ||
        file.mimetype ===
          'application/octet-stream';

      okExt && okMime
        ? cb(null, true)
        : cb(
            new Error(
              'Invalid file type. Audio only (mp3/wav/m4a/ogg/aac).'
            )
          );
    }
  });

app.post(
  '/api/sounds/upload',
  authenticateToken,
  soundUpload.single('audio'),
  async (req, res) => {
    try {
      const user =
        req.user;

      const {
        title,
        artist,
        duration_seconds
      } = req.body;

      if (
        !req.file ||
        !title
      ) {
        return res
          .status(400)
          .json({
            error:
              'Audio file and title are required'
          });
      }

      const soundId =
        uuidv4();

      let audioUrl = '';

      try {
        const result =
          await new Promise(
            (
              resolve,
              reject
            ) => {
              const uploadStream =
                cloudinary
                  .uploader
                  .upload_stream(
                    {
                      resource_type:
                        'video',

                      public_id:
                        `sounds/${soundId}`,

                      folder:
                        'nvme-sounds'
                    },

                    (
                      error,
                      result
                    ) =>
                      error
                        ? reject(
                            error
                          )
                        : resolve(
                            result
                          )
                  );

              const fileStream =
                fs.createReadStream(
                  req.file.path
                );

              fileStream.on(
                'error',
                reject
              );

              fileStream.pipe(
                uploadStream
              );
            }
          );

        audioUrl =
          result.secure_url;
      } catch (
        uploadError
      ) {
        console.error(
          'Cloudinary sound error:',
          uploadError
        );

        return res
          .status(500)
          .json({
            error:
              'Failed to upload sound to Cloudinary'
          });
      }

      const durationSecs =
        parseInt(
          duration_seconds
        ) || null;

      const result =
        await pool.query(
          `
          INSERT INTO sounds
          (
            id,
            name,
            artist,
            url,
            audio_url,
            duration_sec,
            duration_seconds,
            user_id
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $4,
            $5,
            $6,
            $7
          )
          RETURNING *
          `,
          [
            soundId,
            title,
            artist ||
              user.display_name ||
              user.username ||
              'Unknown',
            audioUrl,
            durationSecs || 30,
            durationSecs,
            user.id
          ]
        );

      res.json({
        ok: true,
        sound:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Sound upload error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to upload sound'
        });
    } finally {
      // Same temp-file contract as
      // /api/upload above.
      if (
        req.file &&
        req.file.path
      ) {
        fs.unlink(
          req.file.path,
          () => {}
        );
      }
    }
  }
);

// ========================================
// 🧠 VIDEO CANDIDATE RANKING
// ========================================

async function calculateVideoScore(
  video,
  userId
) {
  const views =
    Math.max(
      1,
      safeNumber(
        video.views
      )
    );

  const likes =
    safeNumber(
      video.like_count
    );

  const comments =
    safeNumber(
      video.comment_count
    );

  const shares =
    safeNumber(
      video.share_count
    );

  const completions =
    safeNumber(
      video.completions
    );

  const impressions =
    Math.max(
      1,
      safeNumber(
        video.impression_count
      )
    );

  const notInterested =
    safeNumber(
      video.not_interested_count
    );

  const skips =
    safeNumber(
      video.skip_count
    );

  const completionRate =
    video.completion_rate !== null &&
    video.completion_rate !== undefined
      ? safeNumber(
          video.completion_rate
        )
      : completions /
        impressions;

  const likeRate =
    likes /
    views;

  const commentRate =
    comments /
    views;

  const shareRate =
    shares /
    views;

  const skipRate =
    skips /
    impressions;

  const negativeRate =
    notInterested /
    impressions;

  const ageHours =
    Math.max(
      0,
      (
        Date.now() -
        new Date(
          video.created_at
        ).getTime()
      ) /
        3600000
    );

  const freshness =
    Math.exp(
      -ageHours / 72
    );

  let affinity =
    0;

  if (
    userId &&
    video.topic
  ) {
    const result =
      await pool.query(
        `
        SELECT score
        FROM user_topic_affinity
        WHERE user_id = $1
          AND topic = $2
        LIMIT 1
        `,
        [
          userId,
          video.topic
        ]
      );

    if (result.rows.length) {
      affinity =
        clamp(
          safeNumber(
            result.rows[0]
              .score
          ),
          -100,
          100
        ) / 100;
    }
  }

  let followedCreator =
    0;

  if (userId) {
    const result =
      await pool.query(
        `
        SELECT 1
        FROM follows
        WHERE follower_id = $1
          AND following_id = $2
        LIMIT 1
        `,
        [
          userId,
          video.author_id
        ]
      );

    followedCreator =
      result.rows.length
        ? 1
        : 0;
  }

  const rawScore =

    completionRate * 0.28 +

    clamp(
      likeRate * 10,
      0,
      1
    ) * 0.12 +

    clamp(
      commentRate * 10,
      0,
      1
    ) * 0.08 +

    clamp(
      shareRate * 20,
      0,
      1
    ) * 0.10 +

    freshness * 0.12 +

    affinity * 0.12 +

    followedCreator * 0.08 -

    skipRate * 0.05 -

    negativeRate * 0.15;

  return rawScore * 100;
}

// ========================================
// 🎬 FEED / VIDEOS
// ========================================

async function getRankedFeed({
  userId,
  limit,
  cursor,
  followingOnly = false
}) {
  const params = [];

  let where =
    `
    WHERE v.is_published = true
    `;

  // $index of the viewer's id when
  // authenticated — reused by the
  // is_following / is_saved select
  // flags and the Following feed
  // filter below.

  let viewerParam =
    null;

  // Hide videos from users involved in a
  // block with the viewer (either
  // direction).

  if (userId) {
    params.push(userId);

    viewerParam =
      params.length;

    where +=
      ` AND NOT EXISTS (
        SELECT 1
        FROM blocks b
        WHERE (
            b.blocker_id =
              $${params.length}
            AND b.blocked_id =
              v.user_id
          )
          OR (
            b.blocker_id =
              v.user_id
            AND b.blocked_id =
              $${params.length}
          )
      )`;
  }

  // Following feed: only creators the
  // viewer follows.

  if (
    followingOnly &&
    viewerParam
  ) {
    where +=
      ` AND EXISTS (
        SELECT 1
        FROM follows ff
        WHERE ff.follower_id =
          $${viewerParam}
          AND ff.following_id =
            v.user_id
      )`;
  }

  // Per-viewer flags joined onto every
  // feed item (anonymous viewers get
  // false for all three).

  const viewerFlags =
    viewerParam
      ? `
        EXISTS (
          SELECT 1
          FROM follows vf
          WHERE vf.follower_id =
            $${viewerParam}
            AND vf.following_id =
              v.user_id
        ) AS is_following,

        EXISTS (
          SELECT 1
          FROM saves vs
          WHERE vs.user_id =
            $${viewerParam}
            AND vs.video_id =
              v.id
        ) AS is_saved,

        EXISTS (
          SELECT 1
          FROM likes vl
          WHERE vl.user_id =
            $${viewerParam}
            AND vl.video_id =
              v.id
        ) AS is_liked
        `
      : `
        false AS is_following,
        false AS is_saved,
        false AS is_liked
        `;

  if (cursor) {
    params.push(cursor);

    where +=
      ` AND v.created_at < $${params.length}`;
  }

  const candidateLimit =
    Math.max(
      limit * 5,
      100
    );

  params.push(
    candidateLimit
  );

  const candidateLimitParam =
    params.length;

  const result =
    await pool.query(
      `
      SELECT
        v.id,
        v.video_url AS url,
        v.thumbnail_url AS thumbnail,
        v.hls_url,
        v.title,
        v.description,

        v.view_count AS views,
        v.like_count,
        v.comment_count,

        COALESCE(
          v.share_count,
          0
        ) AS share_count,

        COALESCE(
          v.save_count,
          0
        ) AS save_count,

        COALESCE(
          v.skip_count,
          0
        ) AS skip_count,

        COALESCE(
          v.not_interested_count,
          0
        ) AS not_interested_count,

        COALESCE(
          v.impression_count,
          0
        ) AS impression_count,

        COALESCE(
          v.completion_rate,
          0
        ) AS completion_rate,

        COALESCE(
          v.avg_watch_ms,
          0
        ) AS avg_watch_ms,

        COALESCE(
          v.recommendation_score,
          0
        ) AS recommendation_score,

        v.topic,
        v.category,

        v.trending_topic_id,
        v.atomic_claim_id,

        v.sound_id,
        s.name AS sound_title,
        s.artist AS sound_artist,

        v.created_at,

        u.id AS author_id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.is_verified,

        ${viewerFlags}

      FROM videos v

      JOIN users u
        ON v.user_id = u.id

      LEFT JOIN sounds s
        ON s.id = v.sound_id

      ${where}

      ORDER BY
        v.created_at DESC

      LIMIT $${candidateLimitParam}
      `,
      params
    );

  const candidates =
    result.rows;

  const scored = [];

  for (
    const video of candidates
  ) {
    let score =
      await calculateVideoScore(
        video,
        userId
      );

    // Global recommendation score.

    score +=
      safeNumber(
        video.recommendation_score
      ) * 0.10;

    // Trend boost.

    if (
      video.trending_topic_id
    ) {
      const trend =
        await pool.query(
          `
          SELECT trend_score
          FROM trending_topics
          WHERE id = $1
          LIMIT 1
          `,
          [
            video.trending_topic_id
          ]
        );

      if (trend.rows.length) {
        score +=
          safeNumber(
            trend.rows[0]
              .trend_score
          ) * 0.10;
      }
    }

    scored.push({
      ...video,
      _ranking_score: score
    });
  }

  // Highest ranked first.

  scored.sort(
    (a, b) =>
      b._ranking_score -
      a._ranking_score
  );

  // ------------------------------------
  // Diversity filter
  // ------------------------------------

  const selected = [];

  const creatorCounts =
    new Map();

  const topicCounts =
    new Map();

  for (
    const video of scored
  ) {
    const creator =
      video.author_id;

    const topic =
      normalizeText(
        video.topic ||
        video.category ||
        ''
      );

    const creatorCount =
      creatorCounts.get(
        creator
      ) || 0;

    const topicCount =
      topicCounts.get(
        topic
      ) || 0;

    if (
      creatorCount >= 3
    ) {
      continue;
    }

    if (
      topic &&
      topicCount >= 5
    ) {
      continue;
    }

    selected.push(
      video
    );

    creatorCounts.set(
      creator,
      creatorCount + 1
    );

    if (topic) {
      topicCounts.set(
        topic,
        topicCount + 1
      );
    }

    if (
      selected.length >=
      limit
    ) {
      break;
    }
  }

  const feed = selected.map(
    video => {
      const {
        _ranking_score,
        ...clean
      } = video;

      return {
        ...clean,
        ranking_score:
          Number(
            _ranking_score.toFixed(
              4
            )
          )
      };
    }
  );

  // ------------------------------------
  // Sponsored (in-feed ads)
  // ------------------------------------
  // Blend active ads into the ranked
  // page. Ad items carry is_ad so the
  // client can badge + track them; they
  // have no created_at cursor and are
  // excluded from nextCursor math in the
  // route. Zero extra work when no ads
  // are active.

  const ads =
    await getFeedAds({
      userId,

      organicCount:
        feed.length
    });

  return injectFeedAds(feed, ads);
}

// ----------------------------------------
// Fetch active ads for feed injection.
// Priority-ordered with a random
// tiebreak; video_id ads join their
// video (+ author) so they render like
// normal feed items. Returns [] without
// querying when the page is too small
// for an ad slot.
// ----------------------------------------

async function getFeedAds({
  userId,
  organicCount
}) {
  // One ad max per 6 organic items.

  const maxAds =
    Math.min(
      Math.floor(
        organicCount / 6
      ),
      5
    );

  if (maxAds === 0) {
    return [];
  }

  const params = [];

  const likedFlag =
    userId
      ? `EXISTS (
          SELECT 1
          FROM likes al
          WHERE al.user_id = $1
            AND al.video_id = v.id
        ) AS is_liked`
      : 'false AS is_liked';

  if (userId) {
    params.push(userId);
  }

  params.push(maxAds);

  const result =
    await pool.query(
      `
      SELECT
        a.id AS ad_id,
        a.title AS ad_title,
        a.link_url,
        a.link_text,
        a.advertiser,
        a.image_url,
        a.video_url AS ad_video_url,

        v.id,
        v.video_url AS url,
        v.thumbnail_url AS thumbnail,
        v.title,
        v.description,

        v.view_count AS views,
        v.like_count,
        v.comment_count,

        COALESCE(
          v.share_count,
          0
        ) AS share_count,

        COALESCE(
          v.save_count,
          0
        ) AS save_count,

        u.id AS author_id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.is_verified,

        ${likedFlag}

      FROM ads a

      LEFT JOIN videos v
        ON v.id = a.video_id
        AND v.is_published = true

      LEFT JOIN users u
        ON u.id = v.user_id

      WHERE a.is_active = true
        AND (
          a.video_id IS NULL
          OR v.id IS NOT NULL
        )

      ORDER BY
        a.priority DESC,
        RANDOM()

      LIMIT $${params.length}
      `,
      params
    );

  return result.rows.map(
    ad => ({
      is_ad: true,
      ad_id: ad.ad_id,

      // Platform-video ads keep the
      // real video id so like/comment
      // wire up unchanged; external
      // creatives get id: null.

      id: ad.id,

      url:
        ad.url ||
        ad.ad_video_url ||
        null,

      thumbnail:
        ad.thumbnail ||
        ad.image_url ||
        null,

      image_url: ad.image_url,

      title:
        ad.ad_title ||
        ad.title ||
        null,

      description: ad.description,

      advertiser: ad.advertiser,
      link_url: ad.link_url,

      link_text:
        ad.link_text ||
        'Learn more',

      views: ad.views,
      like_count: ad.like_count,
      comment_count:
        ad.comment_count,
      share_count: ad.share_count,
      save_count: ad.save_count,

      author_id: ad.author_id,
      username: ad.username,
      display_name: ad.display_name,
      avatar_url: ad.avatar_url,
      is_verified: ad.is_verified,

      // Ads carry no sound — NULLs
      // keep the feed-item shape
      // uniform so the ticker
      // fallback logic applies.
      sound_id: null,
      sound_title: null,
      sound_artist: null,

      is_liked: !!ad.is_liked
    })
  );
}

// ----------------------------------------
// Blend ads into a ranked feed page:
// first ad at 0-indexed position 2-3,
// then at most one ad per 6 organic
// items. Ads never displace organic
// items and don't affect the cursor.
// ----------------------------------------

function injectFeedAds(feed, ads) {
  if (!ads.length) {
    return feed;
  }

  const out = [];

  let adIndex = 0;
  let organicSinceAd = 0;

  const firstAdAt =
    2 + Math.floor(Math.random() * 2);

  for (const video of feed) {
    const slotForAd =
      adIndex < ads.length &&
      (
        adIndex === 0
          ? out.length >= firstAdAt
          : organicSinceAd >= 6
      );

    if (slotForAd) {
      out.push(ads[adIndex]);
      adIndex += 1;
      organicSinceAd = 0;
    }

    out.push(video);
    organicSinceAd += 1;
  }

  return out;
}

app.get(
  '/api/feed',
  optionalAuth,
  async (req, res) => {
    try {
      const limit =
        clamp(
          parseInt(
            req.query.limit
          ) || 20,
          1,
          50
        );

      const cursor =
        req.query.cursor ||
        null;

      const type =
        req.query.type ||
        req.query.feed ||
        null;

      // The Following feed is
      // per-user — anonymous viewers
      // get a clear 401 instead of an
      // unfiltered feed.

      if (
        type === 'following' &&
        !req.user
      ) {
        return res
          .status(401)
          .json({
            error:
              'Sign in to see your Following feed'
          });
      }

      const feed =
        await getRankedFeed({
          userId:
            req.user?.id ||
            null,

          limit,
          cursor,

          followingOnly:
            type === 'following'
        });

      // Ads are blended into the page
      // but carry no created_at cursor —
      // compute nextCursor from organic
      // items only.

      const organic =
        feed.filter(
          item => !item.is_ad
        );

      const nextCursor =
        organic.length === limit
          ? organic[
              organic.length - 1
            ].created_at
          : undefined;

      res.json({
        feed,
        nextCursor,

        algorithm:
          req.user
            ? 'personalized-v1'
            : 'trending-v1'
      });
    } catch (error) {
      console.error(
        'Feed error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch feed'
        });
    }
  }
);

// Legacy chronological video list.

app.get(
  '/api/videos',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,
            v.view_count AS views,
            v.like_count,
            v.comment_count,
            v.created_at,

            u.id AS author_id,
            u.username,
            u.avatar_url

          FROM videos v

          JOIN users u
            ON v.user_id = u.id

          WHERE v.is_published = true

          ORDER BY
            v.created_at DESC

          LIMIT 40
          `
        );

      res.json({
        videos:
          result.rows
      });
    } catch (error) {
      console.error(
        'Videos list error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch videos'
        });
    }
  }
);

// ========================================
// 🎯 Video Details
// ========================================

app.get(
  '/api/videos/:id',
  optionalAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,

            v.view_count AS views,
            v.like_count,
            v.comment_count,

            COALESCE(v.share_count, 0)
              AS share_count,

            COALESCE(v.save_count, 0)
              AS save_count,

            COALESCE(v.topic, '') AS topic,
            v.category,

            v.trending_topic_id,
            v.atomic_claim_id,

            v.created_at,

            u.id AS author_id,
            u.username,
            u.avatar_url

          FROM videos v

          JOIN users u
            ON v.user_id = u.id

          WHERE v.id = $1
          `,
          [req.params.id]
        );

      if (
        result.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      res.json(
        result.rows[0]
      );
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch video'
        });
    }
  }
);

// ========================================
// 📊 VIDEO EVENTS
// ========================================

const ALLOWED_VIDEO_EVENTS = new Set([
  'impression',
  'play',
  'pause',
  '25_percent',
  '50_percent',
  '75_percent',
  'complete',
  'rewatch',
  'like',
  'unlike',
  'comment',
  'share',
  'save',
  'follow',
  'skip',
  'not_interested'
]);

async function updateTopicAffinity({
  userId,
  topic,
  eventType
}) {
  if (
    !userId ||
    !topic
  ) {
    return;
  }

  const normalizedTopic =
    normalizeText(topic);

  if (!normalizedTopic) {
    return;
  }

  const weights = {
    impression: 0.01,
    play: 0.05,
    '25_percent': 0.10,
    '50_percent': 0.15,
    '75_percent': 0.20,
    complete: 0.35,
    rewatch: 0.40,
    like: 0.50,
    comment: 0.70,
    share: 0.90,
    save: 0.75,
    follow: 1.00,
    skip: -0.35,
    not_interested: -1.00,
    unlike: -0.30
  };

  const weight =
    weights[eventType] ||
    0;

  const increment =
    weight * 10;

  const counterMap = {
    impression:
      'views',

    play:
      'views',

    complete:
      'completions',

    like:
      'likes',

    comment:
      'comments',

    share:
      'shares',

    follow:
      'follows',

    skip:
      'skips',

    not_interested:
      'not_interested'
  };

  const counter =
    counterMap[eventType];

  if (counter) {
    await pool.query(
      `
      INSERT INTO user_topic_affinity
      (
        user_id,
        topic,
        score,
        ${counter}
      )
      VALUES
      (
        $1,
        $2,
        $3,
        1
      )
      ON CONFLICT
      (
        user_id,
        topic
      )
      DO UPDATE SET
        score =
          user_topic_affinity.score
          + EXCLUDED.score,

        ${counter} =
          user_topic_affinity.${counter}
          + 1,

        updated_at =
          NOW()
      `,
      [
        userId,
        normalizedTopic,
        increment
      ]
    );
  } else {
    await pool.query(
      `
      INSERT INTO user_topic_affinity
      (
        user_id,
        topic,
        score
      )
      VALUES
      (
        $1,
        $2,
        $3
      )
      ON CONFLICT
      (
        user_id,
        topic
      )
      DO UPDATE SET
        score =
          user_topic_affinity.score
          + EXCLUDED.score,

        updated_at =
          NOW()
      `,
      [
        userId,
        normalizedTopic,
        increment
      ]
    );
  }
}

async function updateVideoSignal(
  videoId,
  eventType,
  eventData
) {
  const weights = {
    impression: 0.01,
    play: 0.05,
    '25_percent': 0.10,
    '50_percent': 0.15,
    '75_percent': 0.20,
    complete: 0.50,
    rewatch: 0.60,
    like: 0.75,
    comment: 0.90,
    share: 1.10,
    save: 0.95,
    follow: 1.20,
    skip: -0.45,
    not_interested: -1.50,
    unlike: -0.50
  };

  const signal =
    weights[eventType] ||
    0;

  await pool.query(
    `
    UPDATE videos
    SET
      recommendation_score =
        COALESCE(
          recommendation_score,
          0
        ) + $1,

      impression_count =
        COALESCE(
          impression_count,
          0
        ) +
        CASE
          WHEN $2 = 'impression'
          THEN 1
          ELSE 0
        END,

      share_count =
        COALESCE(
          share_count,
          0
        ) +
        CASE
          WHEN $2 = 'share'
          THEN 1
          ELSE 0
        END,

      save_count =
        COALESCE(
          save_count,
          0
        ) +
        CASE
          WHEN $2 = 'save'
          THEN 1
          ELSE 0
        END,

      skip_count =
        COALESCE(
          skip_count,
          0
        ) +
        CASE
          WHEN $2 = 'skip'
          THEN 1
          ELSE 0
        END,

      not_interested_count =
        COALESCE(
          not_interested_count,
          0
        ) +
        CASE
          WHEN $2 = 'not_interested'
          THEN 1
          ELSE 0
        END,

      last_ranked_at =
        NOW()

    WHERE id = $3
    `,
    [
      signal,
      eventType,
      videoId
    ]
  );

  if (
    eventData?.watch_ms &&
    eventData?.video_duration_ms
  ) {
    const watchMs =
      Math.max(
        0,
        Number(
          eventData.watch_ms
        )
      );

    const durationMs =
      Math.max(
        1,
        Number(
          eventData.video_duration_ms
        )
      );

    const completion =
      clamp(
        watchMs /
          durationMs,
        0,
        1
      );

    await pool.query(
      `
      UPDATE videos
      SET
        avg_watch_ms =
          CASE
            WHEN COALESCE(
              impression_count,
              0
            ) <= 1
            THEN $1
            ELSE
              (
                COALESCE(
                  avg_watch_ms,
                  0
                )
                *
                (
                  COALESCE(
                    impression_count,
                    1
                  ) - 1
                )
                + $1
              )
              /
              COALESCE(
                impression_count,
                1
              )
          END,

        completion_rate =
          CASE
            WHEN COALESCE(
              impression_count,
              0
            ) <= 1
            THEN $2
            ELSE
              (
                COALESCE(
                  completion_rate,
                  0
                )
                *
                (
                  COALESCE(
                    impression_count,
                    1
                  ) - 1
                )
                + $2
              )
              /
              COALESCE(
                impression_count,
                1
              )
          END

      WHERE id = $3
      `,
      [
        watchMs,
        completion,
        videoId
      ]
    );
  }
}

app.post(
  '/api/videos/:id/event',
  optionalAuth,
  async (req, res) => {
    try {
      const {
        event_type,
        session_id,
        watch_ms,
        video_duration_ms,
        position_ms,
        metadata
      } = req.body;

      if (
        !event_type ||
        !ALLOWED_VIDEO_EVENTS.has(
          event_type
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid event_type'
          });
      }

      const video =
        await pool.query(
          `
          SELECT
            id,
            topic,
            category,
            user_id
          FROM videos
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!video.rows.length) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      const v =
        video.rows[0];

      await pool.query(
        `
        INSERT INTO video_events
        (
          video_id,
          user_id,
          session_id,
          event_type,
          watch_ms,
          video_duration_ms,
          position_ms,
          metadata
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8
        )
        `,
        [
          v.id,
          req.user?.id ||
            null,

          session_id ||
            null,

          event_type,

          Number(
            watch_ms
          ) || 0,

          Number(
            video_duration_ms
          ) || 0,

          Number(
            position_ms
          ) || 0,

          JSON.stringify(
            metadata || {}
          )
        ]
      );

      await updateVideoSignal(
        v.id,
        event_type,
        {
          watch_ms,
          video_duration_ms
        }
      );

      if (
        req.user?.id &&
        v.topic
      ) {
        await updateTopicAffinity({
          userId:
            req.user.id,

          topic:
            v.topic,

          eventType:
            event_type
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Video event error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to record video event'
        });
    }
  }
);

// Batch events.

app.post(
  '/api/videos/events',
  optionalAuth,
  async (req, res) => {
    try {
      const events =
        Array.isArray(
          req.body?.events
        )
          ? req.body.events
          : [];

      if (!events.length) {
        return res
          .status(400)
          .json({
            error:
              'events array is required'
          });
      }

      let processed = 0;

      for (
        const event of events.slice(
          0,
          100
        )
      ) {
        if (
          !event?.video_id ||
          !event?.event_type
        ) {
          continue;
        }

        if (
          !ALLOWED_VIDEO_EVENTS.has(
            event.event_type
          )
        ) {
          continue;
        }

        const video =
          await pool.query(
            `
            SELECT
              id,
              topic
            FROM videos
            WHERE id = $1
            `,
            [event.video_id]
          );

        if (!video.rows.length) {
          continue;
        }

        await pool.query(
          `
          INSERT INTO video_events
          (
            video_id,
            user_id,
            session_id,
            event_type,
            watch_ms,
            video_duration_ms,
            position_ms,
            metadata
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
          )
          `,
          [
            event.video_id,

            req.user?.id ||
              null,

            event.session_id ||
              null,

            event.event_type,

            Number(
              event.watch_ms
            ) || 0,

            Number(
              event.video_duration_ms
            ) || 0,

            Number(
              event.position_ms
            ) || 0,

            JSON.stringify(
              event.metadata ||
                {}
            )
          ]
        );

        await updateVideoSignal(
          event.video_id,
          event.event_type,
          event
        );

        if (
          req.user?.id &&
          video.rows[0].topic
        ) {
          await updateTopicAffinity({
            userId:
              req.user.id,

            topic:
              video.rows[0]
                .topic,

            eventType:
              event.event_type
          });
        }

        processed += 1;
      }

      res.json({
        success: true,
        processed
      });
    } catch (error) {
      console.error(
        'Batch video event error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to process events'
        });
    }
  }
);

// ========================================
// 🚫 VIDEO FEEDBACK
// ========================================

app.post(
  '/api/videos/:id/feedback',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        feedback_type
      } = req.body;

      const allowed = [
        'not_interested',
        'hide',
        'report'
      ];

      if (
        !allowed.includes(
          feedback_type
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid feedback_type'
          });
      }

      const video =
        await pool.query(
          `
          SELECT
            id,
            topic,
            user_id
          FROM videos
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!video.rows.length) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      await pool.query(
        `
        INSERT INTO video_feedback
        (
          user_id,
          video_id,
          feedback_type
        )
        VALUES
        (
          $1,
          $2,
          $3
        )
        ON CONFLICT DO NOTHING
        `,
        [
          req.user.id,
          req.params.id,
          feedback_type
        ]
      );

      await updateVideoSignal(
        req.params.id,
        feedback_type,
        {}
      );

      if (
        video.rows[0].topic
      ) {
        await updateTopicAffinity({
          userId:
            req.user.id,

          topic:
            video.rows[0]
              .topic,

          eventType:
            feedback_type
        });
      }

      res.json({
        success: true,
        feedback_type
      });
    } catch (error) {
      console.error(
        'Video feedback error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to record feedback'
        });
    }
  }
);

// ========================================
// 👁️ VIEW
// ========================================

app.post(
  '/api/videos/:id/view',
  optionalAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE videos
          SET
            view_count =
              COALESCE(
                view_count,
                0
              ) + 1
          WHERE id = $1
          RETURNING
            view_count,
            topic
          `,
          [req.params.id]
        );

      if (
        result.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      await pool.query(
        `
        INSERT INTO video_events
        (
          video_id,
          user_id,
          session_id,
          event_type
        )
        VALUES
        (
          $1,
          $2,
          $3,
          'impression'
        )
        `,
        [
          req.params.id,
          req.user?.id ||
            null,
          req.body?.session_id ||
            null
        ]
      );

      await updateVideoSignal(
        req.params.id,
        'impression',
        {}
      );

      if (
        req.user?.id &&
        result.rows[0].topic
      ) {
        await updateTopicAffinity({
          userId:
            req.user.id,

          topic:
            result.rows[0]
              .topic,

          eventType:
            'impression'
        });
      }

      res.json({
        success: true,
        views:
          result.rows[0]
            .view_count
      });
    } catch (error) {
      console.error(
        'View count error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to record view'
        });
    }
  }
);

// ========================================
// 📣 AD TRACKING
// ========================================
// Fire-and-forget counters — no auth,
// no body, cheap single-row UPDATEs.
// The client fires an impression when
// an ad scrolls into view and a click
// when its CTA is tapped.

app.post(
  '/api/ads/:id/impression',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE ads
          SET
            impressions =
              COALESCE(
                impressions,
                0
              ) + 1
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error: 'Ad not found'
          });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Ad impression error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to track impression'
        });
    }
  }
);

app.post(
  '/api/ads/:id/click',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE ads
          SET
            clicks =
              COALESCE(
                clicks,
                0
              ) + 1
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error: 'Ad not found'
          });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Ad click error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to track click'
        });
    }
  }
);

// ========================================
// ❤️ Likes
// ========================================

app.post(
  '/api/videos/:id/like',
  authenticateToken,
  async (req, res) => {
    const videoId =
      req.params.id;

    const user =
      req.user;

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const videoResult =
        await client.query(
          `
          SELECT
            id,
            topic,
            user_id
          FROM videos
          WHERE id = $1
          FOR UPDATE
          `,
          [videoId]
        );

      if (
        videoResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      const existing =
        await client.query(
          `
          SELECT 1
          FROM likes
          WHERE video_id = $1
            AND user_id = $2
          `,
          [
            videoId,
            user.id
          ]
        );

      let liked;

      if (
        existing.rows.length >
        0
      ) {
        await client.query(
          `
          DELETE FROM likes
          WHERE video_id = $1
            AND user_id = $2
          `,
          [
            videoId,
            user.id
          ]
        );

        await client.query(
          `
          UPDATE videos
          SET
            like_count =
              GREATEST(
                COALESCE(
                  like_count,
                  0
                ) - 1,
                0
              )
          WHERE id = $1
          `,
          [videoId]
        );

        liked = false;
      } else {
        await client.query(
          `
          INSERT INTO likes
          (
            video_id,
            user_id
          )
          VALUES
          ($1, $2)
          `,
          [
            videoId,
            user.id
          ]
        );

        await client.query(
          `
          UPDATE videos
          SET
            like_count =
              COALESCE(
                like_count,
                0
              ) + 1
          WHERE id = $1
          `,
          [videoId]
        );

        liked = true;
      }

      const countResult =
        await client.query(
          `
          SELECT
            like_count,
            topic
          FROM videos
          WHERE id = $1
          `,
          [videoId]
        );

      await client.query(
        'COMMIT'
      );

      const likeCount =
        countResult.rows[0]
          .like_count;

      await updateVideoSignal(
        videoId,
        liked
          ? 'like'
          : 'unlike',
        {}
      );

      if (
        liked &&
        countResult.rows[0]
          .topic
      ) {
        await updateTopicAffinity({
          userId:
            user.id,

          topic:
            countResult.rows[0]
              .topic,

          eventType:
            'like'
        });
      }

      io.to(
        `video-${videoId}`
      ).emit(
        'like-update',
        {
          videoId,
          liked,
          likeCount
        }
      );

      // Notify the video owner — only
      // when a like is added, never on
      // unlike or self-like (the helper
      // skips self-notifications too).

      if (liked) {
        createNotification({
          userId:
            videoResult.rows[0]
              .user_id,

          actorId:
            user.id,

          actorUsername:
            user.username,

          type:
            'like',

          videoId
        }).catch(() => {});
      }

      res.json({
        success: true,
        liked,
        like_count:
          likeCount
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Like error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to update like'
        });
    } finally {
      client.release();
    }
  }
);

// ========================================
// 💬 Comments
// ========================================

app.get(
  '/api/videos/:id/comments',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            c.id,
            c.text,
            c.image_url,
            c.created_at,

            u.username,
            u.display_name,
            u.avatar_url

          FROM comments c

          JOIN users u
            ON c.user_id = u.id

          WHERE c.video_id = $1
            AND c.parent_id IS NULL

          ORDER BY
            c.created_at DESC

          LIMIT 100
          `,
          [req.params.id]
        );

      const comments =
        result.rows;

      // One extra query nests replies
      // (same DESC ordering convention)
      // under their parents.

      if (comments.length > 0) {
        const replies =
          await pool.query(
            `
            SELECT
              c.id,
              c.parent_id,
              c.text,
              c.image_url,
              c.created_at,

              u.username,
              u.display_name,
              u.avatar_url

            FROM comments c

            JOIN users u
              ON c.user_id = u.id

            WHERE c.parent_id =
              ANY($1::uuid[])

            ORDER BY
              c.created_at DESC
            `,
            [
              comments.map(
                c => c.id
              )
            ]
          );

        const byParent = {};

        for (const reply of
          replies.rows
        ) {
          (
            byParent[
              reply.parent_id
            ] =
              byParent[
                reply.parent_id
              ] || []
          ).push(reply);
        }

        for (const comment of comments) {
          comment.replies =
            byParent[comment.id] ||
            [];
        }
      }

      res.json({
        comments
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch comments'
        });
    }
  }
);

app.post(
  '/api/videos/:id/comments',
  authenticateToken,
  async (req, res) => {
    try {
      const videoId =
        req.params.id;

      const {
        text,
        image,
        parent_id
      } = req.body;

      if (
        !text ||
        !text.trim()
      ) {
        return res
          .status(400)
          .json({
            error:
              'Comment text is required'
          });
      }

      if (
        text.length > 500
      ) {
        return res
          .status(400)
          .json({
            error:
              'Comment too long (500 char max)'
          });
      }

      const videoResult =
        await pool.query(
          `
          SELECT
            id,
            topic,
            user_id
          FROM videos
          WHERE id = $1
          `,
          [videoId]
        );

      if (
        videoResult.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      // Reply? The parent must exist, belong
      // to the same video, and be top-level
      // (one level deep, TikTok-style).

      let parentComment = null;

      if (parent_id) {
        const parentResult =
          await pool.query(
            `
            SELECT
              id,
              user_id,
              video_id,
              parent_id
            FROM comments
            WHERE id = $1
            `,
            [parent_id]
          );

        if (
          parentResult.rows
            .length === 0 ||

          parentResult.rows[0]
            .video_id !== videoId
        ) {
          return res
            .status(400)
            .json({
              error:
                'Parent comment not found'
            });
        }

        if (
          parentResult.rows[0]
            .parent_id
        ) {
          return res
            .status(400)
            .json({
              error:
                'Replies can only go one level deep'
            });
        }

        parentComment =
          parentResult.rows[0];
      }

      const result =
        await pool.query(
          `
          INSERT INTO comments
          (
            video_id,
            user_id,
            text,
            image_url,
            parent_id
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5
          )
          RETURNING *
          `,
          [
            videoId,
            req.user.id,
            text.trim(),
            image || null,
            parentComment
              ? parentComment.id
              : null
          ]
        );

      await pool.query(
        `
        UPDATE videos
        SET
          comment_count =
            COALESCE(
              comment_count,
              0
            ) + 1
        WHERE id = $1
        `,
        [videoId]
      );

      await updateVideoSignal(
        videoId,
        'comment',
        {}
      );

      if (
        videoResult.rows[0]
          .topic
      ) {
        await updateTopicAffinity({
          userId:
            req.user.id,

          topic:
            videoResult.rows[0]
              .topic,

          eventType:
            'comment'
        });
      }

      const comment = {
        ...result.rows[0],

        username:
          req.user.username,

        display_name:
          req.user.display_name,

        avatar_url:
          req.user.avatar_url
      };

      io.to(
        `video-${videoId}`
      ).emit(
        'new-comment',
        comment
      );

      // A reply notifies the parent
      // comment's author; a top-level
      // comment notifies the video owner
      // (self-notifications are skipped by
      // the helper).

      createNotification({
        userId: parentComment
          ? parentComment.user_id
          : videoResult.rows[0]
              .user_id,

        actorId:
          req.user.id,

        actorUsername:
          req.user.username,

        type: parentComment
          ? 'reply'
          : 'comment',

        videoId,

        commentId:
          result.rows[0].id
      }).catch(() => {});

      res.json({
        success: true,
        comment
      });
    } catch (error) {
      console.error(
        'Comment error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to post comment'
        });
    }
  }
);

// Delete a comment — allowed for the
// comment author or the video owner.

app.delete(
  '/api/videos/:videoId/comments/:commentId',
  authenticateToken,
  async (req, res) => {
    const videoId =
      req.params.videoId;

    const commentId =
      req.params.commentId;

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
          SELECT
            c.id,
            c.user_id,
            v.user_id
              AS video_owner_id

          FROM comments c

          JOIN videos v
            ON c.video_id = v.id

          WHERE c.id = $1
            AND c.video_id = $2
          `,
          [
            commentId,
            videoId
          ]
        );

      if (
        result.rows.length === 0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'Comment not found'
          });
      }

      const commentRow =
        result.rows[0];

      if (
        commentRow.user_id !==
          req.user.id &&
        commentRow.video_owner_id !==
          req.user.id
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(403)
          .json({
            error:
              'Not allowed to delete this comment'
          });
      }

      await client.query(
        `
        DELETE FROM comments
        WHERE id = $1
        `,
        [commentId]
      );

      await client.query(
        `
        UPDATE videos
        SET
          comment_count =
            GREATEST(
              COALESCE(
                comment_count,
                0
              ) - 1,
              0
            )
        WHERE id = $1
        `,
        [videoId]
      );

      await client.query(
        'COMMIT'
      );

      io.to(
        `video-${videoId}`
      ).emit(
        'comment-deleted',
        {
          videoId,
          commentId
        }
      );

      res.json({
        success: true
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Comment delete error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to delete comment'
        });
    } finally {
      client.release();
    }
  }
);

// ========================================
// 👥 Users / Social
// ========================================

app.get(
  '/api/users/discover',
  optionalAuth,
  async (req, res) => {
    try {
      const excludeId =
        req.user?.id ||
        null;

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            display_name,
            avatar_url,
            bio,
            follower_count AS followers,
            is_verified

          FROM users

          WHERE
            is_banned = false
            AND (
              $1::uuid IS NULL
              OR id != $1
            )

          ORDER BY
            follower_count DESC NULLS LAST,
            created_at DESC

          LIMIT 30
          `,
          [excludeId]
        );

      res.json({
        users:
          result.rows
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch users'
        });
    }
  }
);

app.get(
  '/api/users/:username/stats',
  async (req, res) => {
    try {
      const userResult =
        await pool.query(
          `
          SELECT
            id,
            follower_count,
            following_count
          FROM users
          WHERE username = $1
          `,
          [req.params.username]
        );

      if (
        userResult.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      const user =
        userResult.rows[0];

      const videoStats =
        await pool.query(
          `
          SELECT
            COUNT(*) AS video_count,
            COALESCE(
              SUM(view_count),
              0
            ) AS total_views

          FROM videos

          WHERE user_id = $1
            AND is_published = true
          `,
          [user.id]
        );

      res.json({
        followers:
          user.follower_count,

        following:
          user.following_count,

        videos:
          parseInt(
            videoStats.rows[0]
              .video_count
          ),

        total_views:
          parseInt(
            videoStats.rows[0]
              .total_views
          )
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch stats'
        });
    }
  }
);

// Privacy.

app.put(
  '/api/profile/privacy',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        is_private
      } = req.body;

      await pool.query(
        `
        UPDATE users
        SET is_private = $1
        WHERE id = $2
        `,
        [
          !!is_private,
          req.user.id
        ]
      );

      res.json({
        ok: true,
        is_private:
          !!is_private
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error:
            e.message
        });
    }
  }
);

// Follow.

app.post(
  '/api/users/:userId/follow',
  authenticateToken,
  async (req, res) => {
    const targetId =
      req.params.userId;

    const user =
      req.user;

    if (
      targetId === user.id
    ) {
      return res
        .status(400)
        .json({
          error:
            "You can't follow yourself"
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const target =
        await client.query(
          `
          SELECT
            id,
            is_private
          FROM users
          WHERE id = $1
          `,
          [targetId]
        );

      if (
        target.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      const isPrivate =
        target.rows[0]
          .is_private;

      const existing =
        await client.query(
          `
          SELECT 1
          FROM follows
          WHERE follower_id = $1
            AND following_id = $2
          `,
          [
            user.id,
            targetId
          ]
        );

      if (
        existing.rows.length >
        0
      ) {
        await client.query(
          `
          DELETE FROM follows
          WHERE follower_id = $1
            AND following_id = $2
          `,
          [
            user.id,
            targetId
          ]
        );

        await client.query(
          `
          UPDATE users
          SET following_count =
            GREATEST(
              COALESCE(
                following_count,
                0
              ) - 1,
              0
            )
          WHERE id = $1
          `,
          [user.id]
        );

        await client.query(
          `
          UPDATE users
          SET follower_count =
            GREATEST(
              COALESCE(
                follower_count,
                0
              ) - 1,
              0
            )
          WHERE id = $1
          `,
          [targetId]
        );

        await client.query(
          'COMMIT'
        );

        return res.json({
          ok: true,
          following: false,
          status:
            'unfollowed'
        });
      }

      const pendingReq =
        await client.query(
          `
          SELECT 1
          FROM follow_requests
          WHERE requester_id = $1
            AND target_id = $2
            AND status = 'pending'
          `,
          [
            user.id,
            targetId
          ]
        );

      if (
        pendingReq.rows.length >
        0
      ) {
        await client.query(
          `
          DELETE FROM follow_requests
          WHERE requester_id = $1
            AND target_id = $2
            AND status = 'pending'
          `,
          [
            user.id,
            targetId
          ]
        );

        await client.query(
          'COMMIT'
        );

        return res.json({
          ok: true,
          following: false,
          status:
            'request_cancelled'
        });
      }

      if (isPrivate) {
        await client.query(
          `
          INSERT INTO follow_requests
          (
            requester_id,
            target_id
          )
          VALUES
          ($1, $2)
          ON CONFLICT DO NOTHING
          `,
          [
            user.id,
            targetId
          ]
        );

        await client.query(
          'COMMIT'
        );

        createNotification({
          userId:
            targetId,

          actorId:
            user.id,

          actorUsername:
            user.username,

          type:
            'follow_request'
        }).catch(() => {});

        return res.json({
          ok: true,
          following: false,
          status:
            'requested'
        });
      }

      await client.query(
        `
        INSERT INTO follows
        (
          follower_id,
          following_id
        )
        VALUES
        ($1, $2)
        `,
        [
          user.id,
          targetId
        ]
      );

      await client.query(
        `
        UPDATE users
        SET following_count =
          COALESCE(
            following_count,
            0
          ) + 1
        WHERE id = $1
        `,
        [user.id]
      );

      await client.query(
        `
        UPDATE users
        SET follower_count =
          COALESCE(
            follower_count,
            0
          ) + 1
        WHERE id = $1
        `,
        [targetId]
      );

      await client.query(
        'COMMIT'
      );

      await updateVideoSignal(
        null,
        'follow',
        {}
      ).catch(() => {});

      createNotification({
        userId:
          targetId,

        actorId:
          user.id,

        actorUsername:
          user.username,

        type:
          'follow'
      }).catch(() => {});

      res.json({
        ok: true,
        following: true,
        status:
          'following'
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Follow error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to update follow'
        });
    } finally {
      client.release();
    }
  }
);

// Follow requests.

app.get(
  '/api/follow-requests',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        rows
      } = await pool.query(
        `
        SELECT
          fr.id,
          fr.created_at,
          fr.requester_id,

          u.username,
          u.display_name,
          u.avatar_url

        FROM follow_requests fr

        JOIN users u
          ON u.id =
             fr.requester_id

        WHERE
          fr.target_id = $1
          AND fr.status =
            'pending'

        ORDER BY
          fr.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        requests:
          rows
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error:
            e.message
        });
    }
  }
);

app.post(
  '/api/follow-requests/:id/respond',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        action
      } = req.body;

      const {
        rows
      } = await pool.query(
        `
        SELECT *
        FROM follow_requests
        WHERE id = $1
          AND target_id = $2
          AND status = 'pending'
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (!rows.length) {
        return res
          .status(404)
          .json({
            error:
              'Request not found'
          });
      }

      const request =
        rows[0];

      if (
        action === 'accept'
      ) {
        await pool.query(
          `
          INSERT INTO follows
          (
            follower_id,
            following_id
          )
          VALUES
          ($1, $2)
          ON CONFLICT DO NOTHING
          `,
          [
            request.requester_id,
            req.user.id
          ]
        );

        await pool.query(
          `
          UPDATE users
          SET follower_count =
            COALESCE(
              follower_count,
              0
            ) + 1
          WHERE id = $1
          `,
          [req.user.id]
        );

        await pool.query(
          `
          UPDATE users
          SET following_count =
            COALESCE(
              following_count,
              0
            ) + 1
          WHERE id = $1
          `,
          [
            request.requester_id
          ]
        );

        // Tell the original requester
        // their follow request was
        // accepted.

        createNotification({
          userId:
            request.requester_id,

          actorId:
            req.user.id,

          actorUsername:
            req.user.username,

          type:
            'follow_accept'
        }).catch(() => {});
      }

      await pool.query(
        `
        DELETE FROM follow_requests
        WHERE id = $1
        `,
        [request.id]
      );

      res.json({
        ok: true,
        action
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error:
            e.message
        });
    }
  }
);

// ========================================
// 🔔 Notifications
// ========================================

// Human-readable line the Navbar bell
// renders (NvmeNotification.message).

function notificationMessage(
  type,
  actorUsername,
  extra = {}
) {
  const actor =
    '@' +
    (actorUsername || 'someone');

  switch (type) {
    case 'like':
      return `${actor} liked your video`;

    case 'comment':
      return `${actor} commented on your video`;

    case 'reply':
      return `${actor} replied to your comment`;

    case 'follow':
      return `${actor} started following you`;

    case 'follow_request':
      return `${actor} requested to follow you`;

    case 'follow_accept':
      return `${actor} accepted your follow request`;

    case 'gift':
      return `${actor} sent you ${
        extra.giftName || 'a gift'
      }${
        extra.quantity > 1
          ? ' x' + extra.quantity
          : ''
      }`;

    default:
      return `${actor} interacted with you`;
  }
}

// Insert a notifications row and push it
// to the recipient's `user-<id>` room on
// both event names the frontend listens
// for ('notification' and 'notify').
// Never throws — a notification failure
// must not break the action that
// triggered it. Self-notifications are
// skipped.

async function createNotification({
  userId,
  actorId,
  actorUsername,
  type,
  videoId = null,
  commentId = null,
  extra = {}
}) {
  try {
    if (
      !userId ||
      userId === actorId
    ) {
      return;
    }

    const result =
      await pool.query(
        `
        INSERT INTO notifications
        (
          user_id,
          actor_id,
          type,
          video_id,
          comment_id
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5
        )
        RETURNING *
        `,
        [
          userId,
          actorId,
          type,
          videoId,
          commentId
        ]
      );

    const payload = {
      id:
        result.rows[0].id,

      type,

      message:
        notificationMessage(
          type,
          actorUsername,
          extra
        ),

      from:
        actorUsername ||
        'someone',

      video_id:
        videoId,

      comment_id:
        commentId,

      created_at:
        result.rows[0]
          .created_at,

      ts:
        Date.now()
    };

    io.to(
      `user-${userId}`
    ).emit(
      'notification',
      payload
    );

    io.to(
      `user-${userId}`
    ).emit(
      'notify',
      payload
    );

    // Web push alongside the in-app emit —
    // fire-and-forget, never blocks the
    // request path.

    sendPushToUser(userId, {
      title: 'NVME',

      body:
        payload.message,

      url: videoId
        ? '/watch?v=' + videoId
        : '/app'
    }).catch(() => {});
  } catch (error) {
    console.error(
      'Notification error:',
      error
    );
  }
}

app.get(
  '/api/notifications',
  authenticateToken,
  async (req, res) => {
    try {
      const limit =
        clamp(
          parseInt(
            req.query.limit
          ) || 30,
          1,
          100
        );

      const result =
        await pool.query(
          `
          SELECT
            n.id,
            n.type,
            n.video_id,
            n.comment_id,
            n.read_at,
            n.created_at,

            a.id AS actor_id,
            a.username
              AS actor_username,
            a.display_name
              AS actor_display_name,
            a.avatar_url
              AS actor_avatar_url

          FROM notifications n

          LEFT JOIN users a
            ON n.actor_id = a.id

          WHERE n.user_id = $1

          ORDER BY
            n.created_at DESC

          LIMIT $2
          `,
          [
            req.user.id,
            limit
          ]
        );

      const unread =
        await pool.query(
          `
          SELECT COUNT(*) AS count
          FROM notifications
          WHERE user_id = $1
            AND read_at IS NULL
          `,
          [req.user.id]
        );

      res.json({
        notifications:
          result.rows.map(n => ({
            ...n,

            message:
              notificationMessage(
                n.type,
                n.actor_username
              ),

            from:
              n.actor_username ||
              'someone'
          })),

        unreadCount:
          parseInt(
            unread.rows[0]
              .count
          ) || 0
      });
    } catch (error) {
      console.error(
        'Notifications error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch notifications'
        });
    }
  }
);

// Mark notifications read — every one of
// the recipient's, or just the ids in
// `{ ids: [...] }`.

app.post(
  '/api/notifications/read',
  authenticateToken,
  async (req, res) => {
    try {
      const ids =
        Array.isArray(
          req.body?.ids
        )
          ? req.body.ids.filter(
              id =>
                typeof id ===
                  'string' &&
                /^[0-9a-f-]{36}$/i.test(
                  id
                )
            )
          : [];

      if (ids.length) {
        await pool.query(
          `
          UPDATE notifications
          SET read_at = NOW()
          WHERE user_id = $1
            AND id = ANY($2::uuid[])
            AND read_at IS NULL
          `,
          [
            req.user.id,
            ids
          ]
        );
      } else {
        await pool.query(
          `
          UPDATE notifications
          SET read_at = NOW()
          WHERE user_id = $1
            AND read_at IS NULL
          `,
          [req.user.id]
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Notifications read error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to mark notifications read'
        });
    }
  }
);

// ========================================
// 🔖 Saves
// ========================================

// Toggle a save — same shape as the
// like route. On save the save_count /
// score bump goes through
// updateVideoSignal('save'), exactly
// like a save feed event; on unsave the
// counter is decremented directly.

app.post(
  '/api/videos/:id/save',
  authenticateToken,
  async (req, res) => {
    const videoId =
      req.params.id;

    const user =
      req.user;

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const videoResult =
        await client.query(
          `
          SELECT id
          FROM videos
          WHERE id = $1
          FOR UPDATE
          `,
          [videoId]
        );

      if (
        videoResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      const existing =
        await client.query(
          `
          SELECT 1
          FROM saves
          WHERE user_id = $1
            AND video_id = $2
          `,
          [
            user.id,
            videoId
          ]
        );

      let saved;

      if (
        existing.rows.length >
        0
      ) {
        await client.query(
          `
          DELETE FROM saves
          WHERE user_id = $1
            AND video_id = $2
          `,
          [
            user.id,
            videoId
          ]
        );

        await client.query(
          `
          UPDATE videos
          SET
            save_count =
              GREATEST(
                COALESCE(
                  save_count,
                  0
                ) - 1,
                0
              )
          WHERE id = $1
          `,
          [videoId]
        );

        saved = false;
      } else {
        await client.query(
          `
          INSERT INTO saves
          (
            user_id,
            video_id
          )
          VALUES
          ($1, $2)
          `,
          [
            user.id,
            videoId
          ]
        );

        saved = true;
      }

      await client.query(
        'COMMIT'
      );

      if (saved) {
        // Increments save_count and the
        // recommendation score, same as
        // a 'save' event from
        // /api/videos/:id/event.

        await updateVideoSignal(
          videoId,
          'save',
          {}
        );
      }

      const countResult =
        await pool.query(
          `
          SELECT save_count
          FROM videos
          WHERE id = $1
          `,
          [videoId]
        );

      res.json({
        success: true,
        saved,

        save_count:
          countResult.rows[0]
            ?.save_count || 0
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Save error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to update save'
        });
    } finally {
      client.release();
    }
  }
);

// The viewer's saved videos, newest save
// first — same item shape as /api/feed.

app.get(
  '/api/users/me/saves',
  authenticateToken,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,

            v.view_count AS views,
            v.like_count,
            v.comment_count,

            COALESCE(
              v.share_count,
              0
            ) AS share_count,

            COALESCE(
              v.save_count,
              0
            ) AS save_count,

            v.created_at,
            s.created_at AS saved_at,

            u.id AS author_id,
            u.username,
            u.display_name,
            u.avatar_url,

            true AS is_saved,

            EXISTS (
              SELECT 1
              FROM follows f
              WHERE f.follower_id = $1
                AND f.following_id =
                  v.user_id
            ) AS is_following

          FROM saves s

          JOIN videos v
            ON s.video_id = v.id

          JOIN users u
            ON v.user_id = u.id

          WHERE s.user_id = $1
            AND v.is_published = true

          ORDER BY
            s.created_at DESC

          LIMIT 100
          `,
          [req.user.id]
        );

      res.json({
        videos:
          result.rows
      });
    } catch (error) {
      console.error(
        'Saves error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch saved videos'
        });
    }
  }
);

// ========================================
// 💬 Direct Messages
// ========================================

// Shape a dm_messages row the way
// public/messages.html consumes it.

function dmMessageJson(m) {
  return {
    id: m.id,
    conversationId:
      m.conversation_id,
    fromUserId: m.sender_id,
    content: m.body,
    mediaUrl: m.media_url,
    createdAt: m.created_at,
    isRead: !!m.read_at
  };
}

// True when either user has blocked
// the other.

async function isBlockedEitherWay(
  a,
  b
) {
  const { rows } =
    await pool.query(
      `
      SELECT 1
      FROM blocks
      WHERE (
          blocker_id = $1
          AND blocked_id = $2
        )
        OR (
          blocker_id = $2
          AND blocked_id = $1
        )
      LIMIT 1
      `,
      [a, b]
    );

  return rows.length > 0;
}

// Find the existing 1:1 conversation
// between two users, if any.

async function findDmConversation(
  a,
  b
) {
  const { rows } =
    await pool.query(
      `
      SELECT c.id
      FROM dm_conversations c

      JOIN dm_participants pa
        ON pa.conversation_id = c.id
       AND pa.user_id = $1

      JOIN dm_participants pb
        ON pb.conversation_id = c.id
       AND pb.user_id = $2

      LIMIT 1
      `,
      [a, b]
    );

  return rows.length
    ? rows[0].id
    : null;
}

app.get(
  '/api/dm/conversations',
  authenticateToken,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            c.id,

            o.id AS other_id,
            o.username AS other_username,
            o.display_name
              AS other_display_name,
            o.avatar_url
              AS other_avatar,

            lm.body AS last_body,
            lm.created_at AS last_at,

            (
              SELECT
                COUNT(*)::int
              FROM dm_messages um
              WHERE
                um.conversation_id =
                  c.id
                AND um.sender_id <> $1
                AND um.created_at >
                  COALESCE(
                    p.last_read_at,
                    '-infinity'
                  )
            ) AS unread_count

          FROM dm_participants p

          JOIN dm_conversations c
            ON c.id =
              p.conversation_id

          JOIN dm_participants op
            ON op.conversation_id =
              c.id
           AND op.user_id <> $1

          JOIN users o
            ON o.id = op.user_id

          LEFT JOIN LATERAL (
            SELECT
              m.body,
              m.created_at
            FROM dm_messages m
            WHERE
              m.conversation_id = c.id
            ORDER BY
              m.created_at DESC
            LIMIT 1
          ) lm ON true

          WHERE p.user_id = $1

          ORDER BY
            c.last_message_at
              DESC NULLS LAST,
            c.created_at DESC
          `,
          [req.user.id]
        );

      res.json(
        rows.map(r => ({
          id: r.id,
          userId: r.other_id,
          username:
            r.other_username,

          otherUser: {
            id: r.other_id,
            username:
              r.other_username,
            displayName:
              r.other_display_name,
            avatar:
              r.other_avatar
          },

          lastMessage:
            r.last_body,

          lastAt:
            r.last_at ||
            r.last_message_at,

          unreadCount:
            r.unread_count
        }))
      );
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

// Create (or reuse) the 1:1
// conversation with another user.

app.post(
  '/api/dm/conversations',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        userId,
        username
      } = req.body || {};

      let target = null;

      if (userId || username) {
        const found =
          await pool.query(
            `
            SELECT
              id,
              username,
              display_name,
              avatar_url
            FROM users
            WHERE id = $1
               OR username = $2
            LIMIT 1
            `,
            [
              userId || null,
              username || null
            ]
          );

        target =
          found.rows[0] || null;
      }

      if (!target) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      if (
        target.id === req.user.id
      ) {
        return res
          .status(400)
          .json({
            error:
              "You can't message yourself"
          });
      }

      if (
        await isBlockedEitherWay(
          req.user.id,
          target.id
        )
      ) {
        return res
          .status(403)
          .json({
            error:
              'User is blocked'
          });
      }

      let convId =
        await findDmConversation(
          req.user.id,
          target.id
        );

      if (!convId) {
        const client =
          await pool.connect();

        try {
          await client.query(
            'BEGIN'
          );

          const created =
            await client.query(
              `
              INSERT INTO
                dm_conversations
              DEFAULT VALUES
              RETURNING id
              `
            );

          convId =
            created.rows[0].id;

          await client.query(
            `
            INSERT INTO
              dm_participants
            (
              conversation_id,
              user_id
            )
            VALUES
              ($1, $2),
              ($1, $3)
            `,
            [
              convId,
              req.user.id,
              target.id
            ]
          );

          await client.query(
            'COMMIT'
          );
        } catch (e) {
          await client.query(
            'ROLLBACK'
          );

          throw e;
        } finally {
          client.release();
        }
      }

      res.json({
        id: convId,
        userId: target.id,
        username:
          target.username,

        otherUser: {
          id: target.id,
          username:
            target.username,
          displayName:
            target.display_name,
          avatar:
            target.avatar_url
        },

        lastMessage: null,
        lastAt: null,
        unreadCount: 0
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

app.get(
  '/api/dm/:id/messages',
  authenticateToken,
  async (req, res) => {
    try {
      const convId =
        req.params.id;

      const part =
        await pool.query(
          `
          SELECT 1
          FROM dm_participants
          WHERE
            conversation_id = $1
            AND user_id = $2
          `,
          [
            convId,
            req.user.id
          ]
        );

      if (
        part.rows.length === 0
      ) {
        return res
          .status(403)
          .json({
            error:
              'Not a participant'
          });
      }

      const limit = clamp(
        parseInt(
          req.query.limit
        ) || 50,
        1,
        100
      );

      const before =
        req.query.before || null;

      const params = [
        convId,
        limit
      ];

      let where =
        `
        WHERE
          conversation_id = $1
        `;

      if (before) {
        params.push(before);

        where +=
          ` AND created_at < $${params.length}`;
      }

      const { rows } =
        await pool.query(
          `
          SELECT
            id,
            conversation_id,
            sender_id,
            body,
            media_url,
            created_at,
            read_at
          FROM dm_messages
          ${where}
          ORDER BY
            created_at DESC
          LIMIT $2
          `,
          params
        );

      // The page renders oldest
      // first and scrolls down.

      const messages = rows
        .reverse()
        .map(dmMessageJson);

      // Opening the conversation
      // marks it read and tells the
      // other participant (the page
      // only listens for dm_read, it
      // never emits it).

      if (!before) {
        await pool.query(
          `
          UPDATE dm_participants
          SET
            last_read_at = NOW()
          WHERE
            conversation_id = $1
            AND user_id = $2
          `,
          [
            convId,
            req.user.id
          ]
        );

        await pool.query(
          `
          UPDATE dm_messages
          SET read_at = NOW()
          WHERE
            conversation_id = $1
            AND sender_id <> $2
            AND read_at IS NULL
          `,
          [
            convId,
            req.user.id
          ]
        );

        const others =
          await pool.query(
            `
            SELECT user_id
            FROM dm_participants
            WHERE
              conversation_id = $1
              AND user_id <> $2
            `,
            [
              convId,
              req.user.id
            ]
          );

        for (
          const o of others.rows
        ) {
          io.to(
            `user-${o.user_id}`
          ).emit(
            'dm_read',
            {
              conversationId:
                convId,
              readerId:
                req.user.id
            }
          );
        }
      }

      res.json(messages);
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

// ========================================
// 🚫 Blocks & Mutes
// ========================================

app.post(
  '/api/users/:userId/block',
  authenticateToken,
  async (req, res) => {
    try {
      const targetId =
        req.params.userId;

      if (
        targetId === req.user.id
      ) {
        return res
          .status(400)
          .json({
            error:
              "You can't block yourself"
          });
      }

      const target =
        await pool.query(
          `
          SELECT 1
          FROM users
          WHERE id = $1
          `,
          [targetId]
        );

      if (
        target.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      await pool.query(
        `
        INSERT INTO blocks
          (blocker_id, blocked_id)
        VALUES
          ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [
          req.user.id,
          targetId
        ]
      );

      res.json({
        ok: true,
        blocked: true
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

app.delete(
  '/api/users/:userId/block',
  authenticateToken,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM blocks
        WHERE blocker_id = $1
          AND blocked_id = $2
        `,
        [
          req.user.id,
          req.params.userId
        ]
      );

      res.json({
        ok: true,
        blocked: false
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

app.post(
  '/api/users/:userId/mute',
  authenticateToken,
  async (req, res) => {
    try {
      const targetId =
        req.params.userId;

      if (
        targetId === req.user.id
      ) {
        return res
          .status(400)
          .json({
            error:
              "You can't mute yourself"
          });
      }

      const target =
        await pool.query(
          `
          SELECT 1
          FROM users
          WHERE id = $1
          `,
          [targetId]
        );

      if (
        target.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      await pool.query(
        `
        INSERT INTO mutes
          (muter_id, muted_id)
        VALUES
          ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [
          req.user.id,
          targetId
        ]
      );

      res.json({
        ok: true,
        muted: true
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

app.delete(
  '/api/users/:userId/mute',
  authenticateToken,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM mutes
        WHERE muter_id = $1
          AND muted_id = $2
        `,
        [
          req.user.id,
          req.params.userId
        ]
      );

      res.json({
        ok: true,
        muted: false
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);

// Public profile.

app.get(
  '/api/users/:username',
  optionalAuth,
  async (req, res) => {
    try {
      const viewerId =
        req.user?.id ||
        null;

      const {
        rows: urows
      } = await pool.query(
        `
        SELECT
          id,
          username,
          display_name,
          bio,
          avatar_url,
          is_private,
          is_verified,
          follower_count,
          following_count,
          created_at

        FROM users

        WHERE username = $1
        `,
        [req.params.username]
      );

      if (!urows.length) {
        return res
          .status(404)
          .json({
            error:
              'user not found'
          });
      }

      const user =
        urows[0];

      let relationship =
        'none';

      if (
        viewerId === user.id
      ) {
        relationship =
          'self';
      } else if (
        viewerId
      ) {
        const {
          rows: frows
        } = await pool.query(
          `
          SELECT 1
          FROM follows
          WHERE follower_id = $1
            AND following_id = $2
          `,
          [
            viewerId,
            user.id
          ]
        );

        if (frows.length) {
          relationship =
            'following';
        } else {
          const {
            rows: rrows
          } = await pool.query(
            `
            SELECT 1
            FROM follow_requests
            WHERE requester_id = $1
              AND target_id = $2
              AND status = 'pending'
            `,
            [
              viewerId,
              user.id
            ]
          );

          if (rrows.length) {
            relationship =
              'requested';
          }
        }
      }

      const canSeeContent =
        !user.is_private ||
        relationship ===
          'following' ||
        relationship ===
          'self';

      let videos = [];

      if (
        canSeeContent
      ) {
        const {
          rows: vrows
        } = await pool.query(
          `
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,
            v.view_count AS views,
            v.like_count,
            v.comment_count,
            v.created_at

          FROM videos v

          WHERE
            v.user_id = $1
            AND v.is_published = true

          ORDER BY
            v.created_at DESC

          LIMIT 50
          `,
          [user.id]
        );

        videos =
          vrows;
      }

      res.json({
        ok: true,

        user: {
          id: user.id,
          username:
            user.username,
          display_name:
            user.display_name,
          bio:
            canSeeContent
              ? user.bio
              : null,
          avatar_url:
            user.avatar_url,
          is_private:
            user.is_private,
          is_verified:
            user.is_verified,
          created_at:
            user.created_at
        },

        stats: {
          followers:
            user.follower_count ||
            0,

          following:
            user.following_count ||
            0,

          videos:
            canSeeContent
              ? videos.length
              : null
        },

        relationship,

        can_see_content:
          canSeeContent,

        videos
      });
    } catch (e) {
      console.error(
        'Profile error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            e.message
        });
    }
  }
);

// Profile update.

app.put(
  '/api/profile',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        display_name,
        bio,
        avatar_url,
        username,
        profile_link,
        paypal_email
      } = req.body;

      const result =
        await pool.query(
          `
          UPDATE users
          SET
            display_name =
              COALESCE(
                $1,
                display_name
              ),

            bio =
              COALESCE(
                $2,
                bio
              ),

            avatar_url =
              COALESCE(
                $3,
                avatar_url
              ),

            username =
              COALESCE(
                $4,
                username
              ),

            profile_link =
              COALESCE(
                $5,
                profile_link
              ),

            paypal_email =
              COALESCE(
                $6,
                paypal_email
              ),

            updated_at =
              NOW()

          WHERE id = $7

          RETURNING *
          `,
          [
            display_name,
            bio,
            avatar_url,
            username,
            profile_link,
            paypal_email,
            req.user.id
          ]
        );

      res.json({
        ok: true,
        user:
          publicUser(
            result.rows[0]
          )
      });
    } catch (error) {
      console.error(
        'Profile update error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to update profile'
        });
    }
  }
);

// ========================================
// 🔎 Search
// ========================================

app.get(
  '/api/search',
  async (req, res) => {
    try {
      const q =
        `%${req.query.q || ''}%`;

      const [
        users,
        videos
      ] =
        await Promise.all([
          pool.query(
            `
            SELECT
              id,
              username,
              display_name,
              avatar_url,
              follower_count AS followers

            FROM users

            WHERE
              username ILIKE $1
              OR display_name ILIKE $1

            LIMIT 20
            `,
            [q]
          ),

          pool.query(
            `
            SELECT
              v.id,
              v.video_url AS url,
              v.thumbnail_url AS thumbnail,
              v.title,
              v.description,
              v.view_count AS views,

              u.username,
              u.avatar_url

            FROM videos v

            JOIN users u
              ON v.user_id = u.id

            WHERE
              v.is_published = true
              AND (
                v.title ILIKE $1
                OR v.description ILIKE $1
              )

            LIMIT 20
            `,
            [q]
          )
        ]);

      res.json({
        users:
          users.rows,

        videos:
          videos.rows
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Search failed'
        });
    }
  }
);

// ========================================
// 🎬 User Videos
// ========================================

app.get(
  '/api/users/:username/videos',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,
            v.view_count AS views,
            v.like_count,
            v.comment_count,
            v.created_at,

            u.id AS author_id,
            u.username,
            u.avatar_url

          FROM videos v

          JOIN users u
            ON v.user_id = u.id

          WHERE
            u.username = $1
            AND v.is_published = true

          ORDER BY
            v.created_at DESC
          `,
          [req.params.username]
        );

      res.json({
        videos:
          result.rows
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch videos'
        });
    }
  }
);

// ========================================
// 📊 User Interest Profile
// ========================================

app.get(
  '/api/recommendations/profile',
  authenticateToken,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            topic,
            score,
            views,
            completions,
            likes,
            comments,
            shares,
            follows,
            skips,
            not_interested,
            updated_at

          FROM user_topic_affinity

          WHERE user_id = $1

          ORDER BY
            score DESC

          LIMIT 100
          `,
          [req.user.id]
        );

      res.json({
        interests:
          result.rows
      });
    } catch (error) {
      console.error(
        'Recommendation profile error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch recommendation profile'
        });
    }
  }
);

// ========================================
// 🧠 Intelligence Admin/Debug
// ========================================

app.get(
  '/api/intelligence/stats',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [
        trends,
        claims,
        videos,
        events,
        feedback
      ] =
        await Promise.all([
          pool.query(
            `
            SELECT
              COUNT(*) AS count
            FROM trending_topics
            WHERE status = 'active'
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*) AS count
            FROM atomic_claims
            WHERE status = 'active'
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*) AS count
            FROM videos
            WHERE is_published = true
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*) AS count
            FROM video_events
            `
          ),

          pool.query(
            `
            SELECT
              COUNT(*) AS count
            FROM video_feedback
            `
          )
        ]);

      res.json({
        trends:
          Number(
            trends.rows[0].count
          ),

        atomic_claims:
          Number(
            claims.rows[0].count
          ),

        videos:
          Number(
            videos.rows[0].count
          ),

        events:
          Number(
            events.rows[0].count
          ),

        feedback:
          Number(
            feedback.rows[0].count
          )
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch intelligence stats'
        });
    }
  }
);

// ========================================
// 🎯 Trend → Claim Pipeline
// ========================================

app.post(
  '/api/intelligence/process-trend/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM trending_topics
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!result.rows.length) {
        return res
          .status(404)
          .json({
            error:
              'Trend not found'
          });
      }

      const trend =
        result.rows[0];

      const score =
        await calculateTrendScore(
          trend.id
        );

      const extracted =
        await extractAtomicClaims(
          trend
        );

      const claims = [];

      for (
        const claim of extracted
      ) {
        const row =
          await createOrGetAtomicClaim(
            trend,
            claim
          );

        if (row) {
          claims.push(row);
        }
      }

      res.json({
        success: true,

        trend: {
          ...trend,
          calculated_score:
            score
        },

        claims
      });
    } catch (error) {
      console.error(
        'Trend processing error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to process trend'
        });
    }
  }
);

// ========================================
// ⚔️ LIVE STREAMING
// ========================================

app.get(
  '/api/streams/live',
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE livestreams
        SET
          status = 'ended',
          ended_at = NOW()

        WHERE
          status = 'live'
          AND started_at IS NOT NULL
          AND started_at <
            NOW() -
            INTERVAL '6 hours'
        `
      );

      const result =
        await pool.query(
          `
          SELECT
            s.id,
            s.title,
            s.description,
            s.thumbnail_url,
            s.viewer_count,
            s.started_at,

            u.id AS host_id,
            u.username,
            u.display_name,
            u.avatar_url,
            u.is_verified

          FROM livestreams s

          JOIN users u
            ON s.user_id = u.id

          WHERE s.status = 'live'

          ORDER BY
            s.viewer_count DESC

          LIMIT 50
          `
        );

      res.json(
        result.rows
      );
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch live streams'
        });
    }
  }
);

app.get(
  '/api/streams/live/now',
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE livestreams
        SET
          status = 'ended',
          ended_at = NOW()

        WHERE
          status = 'live'
          AND started_at IS NOT NULL
          AND started_at <
            NOW() -
            INTERVAL '6 hours'
        `
      );

      const result =
        await pool.query(
          `
          SELECT
            s.id,
            s.title,
            s.description,
            s.thumbnail_url,
            s.viewer_count,
            s.started_at,

            u.id AS host_id,
            u.username,
            u.display_name,
            u.avatar_url,
            u.is_verified

          FROM livestreams s

          JOIN users u
            ON s.user_id = u.id

          WHERE s.status = 'live'

          ORDER BY
            s.viewer_count DESC

          LIMIT 50
          `
        );

      res.json(
        result.rows
      );
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch live streams'
        });
    }
  }
);

app.get(
  '/api/streams/:id',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            s.id,
            s.title,
            s.description,
            s.thumbnail_url,
            s.viewer_count,
            s.started_at,
            s.status,

            u.id AS host_id,
            u.username,
            u.display_name,
            u.avatar_url,
            u.is_verified

          FROM livestreams s

          JOIN users u
            ON s.user_id = u.id

          WHERE s.id = $1
          `,
          [req.params.id]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'Stream not found'
          });
      }

      const srow =
        result.rows[0];

      res.json({
        ...srow,

        is_live:
          srow.status ===
          'live',

        playback_url:
          '/live?id=' +
          encodeURIComponent(
            srow.id
          )
      });
    } catch (error) {
      console.error(
        'Stream by id error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch stream'
        });
    }
  }
);

app.get(
  '/api/creator/streams',
  authenticateToken,
  async (req, res) => {
    try {
      const limit =
        parseInt(
          req.query.limit
        ) || 20;

      const result =
        await pool.query(
          `
          SELECT
            id,
            title,
            description,
            thumbnail_url,
            status,
            viewer_count,
            peak_viewer_count,
            total_gifts_received,
            started_at,
            ended_at,
            created_at

          FROM livestreams

          WHERE user_id = $1

          ORDER BY
            created_at DESC

          LIMIT $2
          `,
          [
            req.user.id,
            limit
          ]
        );

      res.json({
        streams:
          result.rows
      });
    } catch (error) {
      console.error(
        'Creator streams error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch streams'
        });
    }
  }
);

app.post(
  '/api/streams',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        title,
        description,
        is_premium,
        price_credits
      } = req.body;

      const streamKey =
        uuidv4();

      const result =
        await pool.query(
          `
          INSERT INTO livestreams
          (
            user_id,
            title,
            description,
            stream_key,
            is_premium,
            price_credits,
            status
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'offline'
          )
          RETURNING *
          `,
          [
            req.user.id,
            title ||
              'Live Stream',
            description || '',
            streamKey,
            !!is_premium,
            price_credits || 0
          ]
        );

      res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        'Create stream error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to create stream'
        });
    }
  }
);

app.post(
  '/api/streams/:id/go-live',
  authenticateToken,
  async (req, res) => {
    try {
      const streamId = req.params.id;
      const roomName = `stream-${streamId}`;

      // Ensure livekit_room_id column exists (best-effort, won't break if fails)
      try {
        await pool.query(`ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS livekit_room_id TEXT`);
        await pool.query(`ALTER TABLE stream_battles ADD COLUMN IF NOT EXISTS livekit_room_id TEXT`);
      } catch {}

      try {
        await liveSFU.createRoom(roomName);
      } catch (e) {
        console.log('LiveKit createRoom skip', e.message);
      }

      const result = await pool.query(
        `
          UPDATE livestreams
          SET
            status = 'live',
            started_at = NOW(),
            livekit_room_id = $3

          WHERE
            id = $1
            AND user_id = $2

          RETURNING *
          

          WHERE
            id = $1
            AND user_id = $2

          RETURNING *
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Stream not found'
          });
      }

      io.emit(
        'stream-started',
        {
          streamId:
            result.rows[0]
              .id,

          username:
            req.user.username,

          title:
            result.rows[0]
              .title
        }
      );

      res.json({
        success: true,
        stream:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Go-live error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to go live'
        });
    }
  }
);

app.post(
  '/api/streams/:id/end-live',
  authenticateToken,
  async (req, res) => {
    try {
      const streamId = req.params.id;
      const roomName = `stream-${streamId}`;

      try {
        await liveSFU.deleteRoom(roomName);
      } catch (e) {
        console.log('LiveKit deleteRoom skip', e.message);
      }

      const result = await pool.query(
        `
          UPDATE livestreams
          SET
            status = 'ended',
            ended_at = NOW()


          WHERE
            id = $1
            AND user_id = $2

          RETURNING *
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Stream not found'
          });
      }

      io.emit(
        'stream-ended',
        {
          streamId:
            req.params.id
        }
      );

      io.to(
        `stream-${req.params.id}`
      ).emit(
        'stream_ended',
        {
          streamId:
            req.params.id
        }
      );

      res.json({
        success: true,
        stream:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'End-live error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to end stream'
        });
    }
  }
);


// ========================================
// 🔴 LiveKit — viewer join + token (NEW)
// ========================================

app.post(
  '/api/streams/:id/join',
  authenticateToken,
  async (req, res) => {
    try {
      const streamId = req.params.id;
      const roomName = `stream-${streamId}`;
      const role = req.body.role || 'viewer';

      try { await liveSFU.createRoom(roomName); } catch {}

      const token = await liveSFU.issueToken({
        identity: req.user.id,
        name: req.user.username,
        room: roomName,
        role
      });

      const participants = await liveSFU.listParticipants(roomName);

      res.json({
        success: true,
        livekit_room: roomName,
        livekit_url: process.env.LIVEKIT_URL,
        token,
        viewer_count: participants.length
      });
    } catch (error) {
      console.error('Join error:', error.message);
      res.status(500).json({ error: 'Failed to join stream' });
    }
  }
);

app.post(
  '/api/livekit/token',
  authenticateToken,
  async (req, res) => {
    try {
      const { room, role } = req.body;
      if (!room) return res.status(400).json({ error: 'room required' });

      const token = await liveSFU.issueToken({
        identity: req.user.id,
        name: req.user.username,
        room,
        role: role || 'viewer'
      });

      res.json({ token, url: process.env.LIVEKIT_URL, room });
    } catch (error) {
      console.error('LiveKit token error:', error.message);
      res.status(500).json({ error: 'Failed to issue token' });
    }
  }
);


app.post(
  '/api/streams/:id/goal',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        target,
        reward
      } = req.body;

      const result =
        await pool.query(
          `
          UPDATE livestreams

          SET
            goal_target = $1,
            goal_reward = $2,
            goal_current = 0

          WHERE
            id = $3
            AND user_id = $4

          RETURNING
            id,
            goal_target,
            goal_reward,
            goal_current
          `,
          [
            target,
            reward || null,
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Stream not found'
          });
      }

      res.json({
        success: true,
        goal:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Set goal error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to set goal'
        });
    }
  }
);

app.get(
  '/api/streams/:id/gift-leaderboard',
  authenticateToken,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            u.id,
            u.username,
            u.avatar_url,
            SUM(
              gt.credits_spent
            ) AS total

          FROM gift_transactions gt

          JOIN users u
            ON gt.from_user_id =
               u.id

          WHERE gt.stream_id =
            $1

          GROUP BY
            u.id,
            u.username,
            u.avatar_url

          ORDER BY
            total DESC

          LIMIT 20
          `,
          [req.params.id]
        );

      res.json({
        leaderboard:
          result.rows
      });
    } catch (error) {
      console.error(
        'Leaderboard error:',
        error.message
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch leaderboard'
        });
    }
  }
);

// ========================================
// ⚔️ LIVE Battles
// ========================================

app.post(
  '/api/streams/:id/battle',
  authenticateToken,
  async (req, res) => {
    try {
      const streamId =
        req.params.id;

      const {
        battle_type,
        team_a_name,
        team_b_name
      } =
        req.body || {};

      const owned =
        await pool.query(
          `
          SELECT id
          FROM livestreams
          WHERE id = $1
            AND user_id = $2
          `,
          [
            streamId,
            req.user.id
          ]
        );

      if (!owned.rows.length) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Stream not found'
          });
      }

      const battleResult =
        await pool.query(
          `
          INSERT INTO stream_battles
          (
            stream_id,
            host_id,
            status
          )
          VALUES
          ($1, $2, 'waiting')
          RETURNING *
          `,
          [
            streamId,
            req.user.id
          ]
        );

      const battle =
        battleResult.rows[0];

      await pool.query(
        `
        INSERT INTO battle_participants
        (
          battle_id,
          user_id,
          team
        )
        VALUES
        ($1, $2, 'a')
        ON CONFLICT DO NOTHING
        `,
        [
          battle.id,
          req.user.id
        ]
      );

      if (
        team_a_name ||
        team_b_name ||
        battle_type
      ) {
        await pool.query(
          `
          UPDATE stream_battles

          SET
            team_a_name =
              COALESCE(
                $1,
                team_a_name
              ),

            team_b_name =
              COALESCE(
                $2,
                team_b_name
              ),

            battle_type =
              COALESCE(
                $3,
                battle_type
              )

          WHERE id = $4
          `,
          [
            team_a_name ||
              null,

            team_b_name ||
              null,

            battle_type ||
              null,

            battle.id
          ]
        );
      }

      const participants =
        await pool.query(
          `
          SELECT
            bp.*,
            u.username,
            u.avatar_url

          FROM battle_participants bp

          JOIN users u
            ON bp.user_id =
               u.id

          WHERE
            bp.battle_id = $1
          `,
          [battle.id]
        );

      io.to(
        `stream-${streamId}`
      ).emit(
        'battle_created',
        {
          battle,
          participants:
            participants.rows
        }
      );

      res.json({
        ok: true,
        battle,
        participants:
          participants.rows
      });
    } catch (error) {
      console.error(
        'Create stream battle error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to create battle'
        });
    }
  }
);

// ========================================
// 🎁 Gifts
// ========================================

app.post(
  '/api/gifts/send',
  authenticateToken,
  async (req, res) => {
    const {
      streamId,
      giftName,
      quantity = 1,
      message
    } = req.body;

    const fromUser =
      req.user;

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const giftResult =
        await client.query(
          `
          SELECT *
          FROM gifts
          WHERE name = $1
            AND is_active = true
          `,
          [giftName]
        );

      if (
        giftResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'Unknown gift type'
          });
      }

      const gift =
        giftResult.rows[0];

      const totalCredits =
        parseFloat(
          gift.credit_cost
        ) * quantity;

      const senderResult =
        await client.query(
          `
          SELECT
            balance_credits
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [fromUser.id]
        );

      if (
        parseFloat(
          senderResult.rows[0]
            .balance_credits
        ) <
        totalCredits
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'Insufficient credits'
          });
      }

      const streamResult =
        await client.query(
          `
          SELECT user_id
          FROM livestreams
          WHERE id = $1
          `,
          [streamId]
        );

      if (
        streamResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'Stream not found'
          });
      }

      const toUserId =
        streamResult.rows[0]
          .user_id;

      const creatorCredits =
        totalCredits *
        (
          parseFloat(
            gift.creator_pct
          ) / 100
        );

      const platformCredits =
        totalCredits *
        (
          parseFloat(
            gift.platform_pct
          ) / 100
        );

      await client.query(
        `
        UPDATE users

        SET
          balance_credits =
            balance_credits - $1

        WHERE id = $2
        `,
        [
          totalCredits,
          fromUser.id
        ]
      );

      await client.query(
        `
        UPDATE users

        SET
          balance_credits =
            balance_credits + $1,

          total_earned =
            total_earned + $1

        WHERE id = $2
        `,
        [
          creatorCredits,
          toUserId
        ]
      );

      await client.query(
        `
        UPDATE livestreams

        SET
          total_gifts_received =
            total_gifts_received + $1

        WHERE id = $2
        `,
        [
          creatorCredits,
          streamId
        ]
      );

      const txResult =
        await client.query(
          `
          INSERT INTO gift_transactions
          (
            gift_id,
            stream_id,
            from_user_id,
            to_user_id,
            quantity,
            credits_spent,
            creator_credits,
            platform_credits,
            message
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          RETURNING *
          `,
          [
            gift.id,
            streamId,
            fromUser.id,
            toUserId,
            quantity,
            totalCredits,
            creatorCredits,
            platformCredits,
            message || ''
          ]
        );

      await client.query(
        `
        INSERT INTO transactions
        (
          user_id,
          type,
          amount_usd,
          credits_amount,
          description
        )
        VALUES
        (
          $1,
          'gift_received',
          $2,
          $2,
          $3
        )
        `,
        [
          toUserId,
          creatorCredits,
          `${gift.name} x${quantity} from ${fromUser.username}`
        ]
      );

      await client.query(
        'COMMIT'
      );

      io.to(
        `stream-${streamId}`
      ).emit(
        'new-gift',
        {
          giftName:
            gift.name,

          emoji:
            gift.emoji,

          fromUser:
            fromUser.username,

          quantity,

          creatorCredits,

          playSound:
            true,

          soundFile:
            `/sounds/gift-${gift.name.toLowerCase()}.mp3`
        }
      );

      // Notify the gift receiver
      // (self-gifts are skipped by the
      // helper).

      createNotification({
        userId:
          toUserId,

        actorId:
          fromUser.id,

        actorUsername:
          fromUser.username,

        type:
          'gift',

        extra: {
          giftName:
            gift.name,
          quantity
        }
      }).catch(() => {});

      res.json({
        success: true,
        gift:
          gift.name,
        quantity,
        creatorCredits,
        transaction:
          txResult.rows[0]
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Gift error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to send gift'
        });
    } finally {
      client.release();
    }
  }
);

// ========================================
// ⚔️ Battles
// ========================================

app.post(
  '/api/battles/invite',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        to_stream_id,
        to_user_id
      } = req.body;

      if (
        !to_stream_id ||
        !to_user_id
      ) {
        return res
          .status(400)
          .json({
            error:
              'to_stream_id and to_user_id are required'
          });
      }

      const myStream =
        await pool.query(
          `
          SELECT id
          FROM livestreams
          WHERE user_id = $1
            AND status = 'live'
          ORDER BY
            started_at DESC
          LIMIT 1
          `,
          [req.user.id]
        );

      if (
        myStream.rows.length ===
        0
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'You must be live to send a battle invite'
          });
      }

      const result =
        await pool.query(
          `
          INSERT INTO battle_invites
          (
            from_stream_id,
            from_user_id,
            to_stream_id,
            to_user_id
          )
          VALUES
          ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            myStream.rows[0]
              .id,

            req.user.id,

            to_stream_id,

            to_user_id
          ]
        );

      io.to(
        `user-${to_user_id}`
      ).emit(
        'battle-invite',
        {
          invite:
            result.rows[0],

          fromUsername:
            req.user.username
        }
      );

      io.to(
        `user-${to_user_id}`
      ).emit(
        'battle_invite_received',
        {
          invite:
            result.rows[0],

          fromUsername:
            req.user.username
        }
      );

      res.json({
        ok: true,
        invite:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Battle invite error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to send invite'
        });
    }
  }
);

app.post(
  '/api/battles/invite/:id/accept',
  authenticateToken,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const inviteResult =
        await client.query(
          `
          SELECT *
          FROM battle_invites
          WHERE id = $1
            AND to_user_id = $2
            AND status = 'pending'
          FOR UPDATE
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        inviteResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Invite not found or already handled'
          });
      }

      const invite =
        inviteResult.rows[0];

      const battleResult =
        await client.query(
          `
          INSERT INTO stream_battles
          (
            stream_id,
            host_id,
            status
          )
          VALUES
          ($1, $2, 'waiting')
          RETURNING *
          `,
          [
            invite.from_stream_id,
            invite.from_user_id
          ]
        );

      const battle =
        battleResult.rows[0];

      await client.query(
        `
        INSERT INTO battle_participants
        (
          battle_id,
          user_id,
          team
        )
        VALUES
        ($1, $2, 'a'),
        ($1, $3, 'b')
        `,
        [
          battle.id,
          invite.from_user_id,
          invite.to_user_id
        ]
      );

      await client.query(
        `
        UPDATE battle_invites

        SET
          status = 'accepted',
          responded_at = NOW(),
          battle_id = $1

        WHERE id = $2
        `,
        [
          battle.id,
          invite.id
        ]
      );

      await client.query(
        'COMMIT'
      );

      io.to(
        `user-${invite.from_user_id}`
      ).emit(
        'battle-invite-accepted',
        {
          battle
        }
      );

      io.to(
        `user-${invite.from_user_id}`
      ).emit(
        'battle_invite_accepted',
        {
          battle
        }
      );

      res.json({
        ok: true,
        battle
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Accept invite error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to accept invite'
        });
    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/battles/invite/:id/decline',
  authenticateToken,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE battle_invites

          SET
            status = 'declined',
            responded_at = NOW()

          WHERE
            id = $1
            AND to_user_id = $2

          RETURNING *
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Invite not found'
          });
      }

      io.to(
        `user-${result.rows[0]
          .from_user_id}`
      ).emit(
        'battle-invite-declined',
        {
          inviteId:
            req.params.id
        }
      );

      io.to(
        `user-${result.rows[0]
          .from_user_id}`
      ).emit(
        'battle_invite_declined',
        {
          inviteId:
            req.params.id
        }
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Decline invite error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to decline invite'
        });
    }
  }
);

app.get(
  '/api/battles/:id',
  authenticateToken,
  async (req, res) => {
    try {
      const battleResult =
        await pool.query(
          `
          SELECT *
          FROM stream_battles
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (
        battleResult.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            error:
              'Battle not found'
          });
      }

      const participants =
        await pool.query(
          `
          SELECT
            bp.*,
            u.username,
            u.avatar_url

          FROM battle_participants bp

          JOIN users u
            ON bp.user_id =
               u.id

          WHERE
            bp.battle_id = $1
          `,
          [req.params.id]
        );

      const battle =
        battleResult.rows[0];

      res.json({
        ok: true,
        battle,
        participants:
          participants.rows,
        ...battle
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to fetch battle'
        });
    }
  }
);

app.post(
  '/api/battles/:id/start',
  authenticateToken,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE stream_battles

          SET
            status = 'active',
            started_at = NOW()

          WHERE
            id = $1
            AND host_id = $2

          RETURNING *
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Battle not found'
          });
      }

      io.emit(
        'battle-started',
        {
          battleId:
            req.params.id
        }
      );

      io.emit(
        'battle_started',
        {
          battleId:
            req.params.id
        }
      );

      res.json({
        ok: true,
        battle:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Battle start error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to start battle'
        });
    }
  }
);

app.post(
  '/api/battles/:id/end',
  authenticateToken,
  async (req, res) => {
    try {
      const participants =
        await pool.query(
          `
          SELECT *
          FROM battle_participants
          WHERE battle_id = $1
          ORDER BY
            gifts_received DESC
          `,
          [req.params.id]
        );

      const winnerId =
        participants.rows[0]
          ?.user_id ||
        null;

      const result =
        await pool.query(
          `
          UPDATE stream_battles

          SET
            status = 'ended',
            ended_at = NOW(),
            winner_id = $1

          WHERE
            id = $2
            AND host_id = $3

          RETURNING *
          `,
          [
            winnerId,
            req.params.id,
            req.user.id
          ]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Battle not found'
          });
      }

      io.emit(
        'battle-ended',
        {
          battleId:
            req.params.id,
          winnerId
        }
      );

      io.emit(
        'battle_ended',
        {
          battleId:
            req.params.id,
          winnerId
        }
      );

      res.json({
        ok: true,
        battle:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Battle end error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to end battle'
        });
    }
  }
);

app.post(
  '/api/battles/:id/attack',
  authenticateToken,
  async (req, res) => {
    const {
      gift_type,
      cost,
      damage,
      stream_id
    } = req.body;

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const numericCost =
        Math.max(
          0,
          Number(cost) || 0
        );

      const senderResult =
        await client.query(
          `
          SELECT
            balance_credits
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        parseFloat(
          senderResult.rows[0]
            .balance_credits
        ) <
        numericCost
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.json({
          ok: false,
          error:
            'Insufficient credits'
        });
      }

      const targetResult =
        await client.query(
          `
          SELECT
            bp.id

          FROM battle_participants bp

          WHERE
            bp.battle_id = $1
            AND bp.user_id != $2
            AND bp.status = 'active'

          LIMIT 1
          `,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (
        targetResult.rows.length ===
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.json({
          ok: false,
          error:
            'No active opponent found'
        });
      }

      const targetParticipantId =
        targetResult.rows[0]
          .id;

      const updated =
        await client.query(
          `
          UPDATE users

          SET
            balance_credits =
              balance_credits - $1

          WHERE id = $2

          RETURNING
            balance_credits
          `,
          [
            numericCost,
            req.user.id
          ]
        );

      await client.query(
        `
        UPDATE battle_participants

        SET
          gifts_received =
            gifts_received + $1,

          votes =
            votes + 1

        WHERE id = $2
        `,
        [
          numericCost,
          targetParticipantId
        ]
      );

      await client.query(
        `
        INSERT INTO battle_attacks
        (
          battle_id,
          attacker_id,
          target_participant_id,
          gift_type,
          cost,
          damage
        )
        VALUES
        ($1, $2, $3, $4, $5, $6)
        `,
        [
          req.params.id,
          req.user.id,
          targetParticipantId,
          gift_type || null,
          numericCost,
          damage || 0
        ]
      );

      await client.query(
        'COMMIT'
      );

      io.emit(
        'battle-attack',
        {
          battleId:
            req.params.id,
          targetParticipantId,
          damage,
          gift_type
        }
      );

      res.json({
        ok: true,

        new_balance:
          parseFloat(
            updated.rows[0]
              .balance_credits
          )
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Battle attack error:',
        error.message
      );

      res.json({
        ok: false,
        error:
          'Attack failed'
      });
    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/battles/:id/background',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        participant_id,
        bg_data_url
      } = req.body;

      await pool.query(
        `
        UPDATE battle_participants

        SET
          background_url = $1

        WHERE
          id = $2
          AND user_id = $3
        `,
        [
          bg_data_url,
          participant_id,
          req.user.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Battle background error:',
        error.message
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Failed to save background'
        });
    }
  }
);

// ========================================
// 💰 Wallet
// ========================================

app.get(
  '/api/wallet/balance',
  authenticateToken,
  async (req, res) => {
    const result =
      await pool.query(
        `
        SELECT
          balance_credits,
          total_earned
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

    res.json({
      balance:
        parseFloat(
          result.rows[0]
            .balance_credits
        ),

      total_earned:
        parseFloat(
          result.rows[0]
            .total_earned
        )
    });
  }
);

app.get(
  '/api/wallet',
  authenticateToken,
  async (req, res) => {
    const result =
      await pool.query(
        `
        SELECT
          balance_credits,
          total_earned
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

    res.json({
      balance:
        parseFloat(
          result.rows[0]
            .balance_credits
        ),

      total_earned:
        parseFloat(
          result.rows[0]
            .total_earned
        )
    });
  }
);

app.get(
  '/api/wallet/transactions',
  authenticateToken,
  async (req, res) => {
    const result =
      await pool.query(
        `
        SELECT *
        FROM transactions
        WHERE user_id = $1
        ORDER BY
          created_at DESC
        LIMIT 100
        `,
        [req.user.id]
      );

    res.json({
      transactions:
        result.rows
    });
  }
);

app.post(
  '/api/wallet/connect',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        address
      } = req.body;

      if (!address) {
        return res
          .status(400)
          .json({
            error:
              'address is required'
          });
      }

      await pool.query(
        `
        UPDATE users

        SET
          wallet_address = $1

        WHERE id = $2
        `,
        [
          address,
          req.user.id
        ]
      );

      res.json({
        ok: true,
        address
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            'Failed to connect wallet'
        });
    }
  }
);

app.post(
  '/api/wallet/withdraw',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        amount
      } = req.body;

      const minAmount =
        parseFloat(
          process.env.MIN_PAYOUT_AMOUNT ||
          5
        );

      if (
        !amount ||
        amount < minAmount
      ) {
        return res
          .status(400)
          .json({
            error:
              `Minimum payout is $${minAmount}`
          });
      }

      if (
        !req.user.paypal_email
      ) {
        return res
          .status(400)
          .json({
            error:
              'Set a PayPal email on your profile first'
          });
      }

      const client =
        await pool.connect();

      try {
        await client.query(
          'BEGIN'
        );

        const balanceResult =
          await client.query(
            `
            SELECT
              balance_credits
            FROM users
            WHERE id = $1
            FOR UPDATE
            `,
            [req.user.id]
          );

        if (
          parseFloat(
            balanceResult.rows[0]
              .balance_credits
          ) < amount
        ) {
          await client.query(
            'ROLLBACK'
          );

          return res
            .status(400)
            .json({
              error:
                'Insufficient balance'
            });
        }

        await client.query(
          `
          UPDATE users

          SET
            balance_credits =
              balance_credits - $1

          WHERE id = $2
          `,
          [
            amount,
            req.user.id
          ]
        );

        const tx =
          await client.query(
            `
            INSERT INTO transactions
            (
              user_id,
              type,
              amount_usd,
              status,
              description
            )
            VALUES
            (
              $1,
              'withdrawal',
              $2,
              'pending',
              $3
            )
            RETURNING *
            `,
            [
              req.user.id,
              amount,
              `Payout to ${req.user.paypal_email}`
            ]
          );

        await client.query(
          'COMMIT'
        );

        res.json({
          success: true,
          transaction:
            tx.rows[0]
        });
      } catch (err) {
        await client.query(
          'ROLLBACK'
        );

        throw err;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(
        'Withdraw error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to request payout'
        });
    }
  }
);

// ========================================
// 💳 PayPal
// ========================================

app.post(
  '/api/payments/paypal/create-order',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        plan
      } = req.body;

      const amounts = {
        starter: '9.99',
        creator: '29.99',
        pro: '99.99'
      };

      const value =
        amounts[plan];

      if (!value) {
        return res
          .status(400)
          .json({
            error:
              'Unknown plan'
          });
      }

      const request =
        new paypal.orders
          .OrdersCreateRequest();

      request.requestBody({
        intent:
          'CAPTURE',

        purchase_units: [
          {
            amount: {
              currency_code:
                'USD',

              value
            }
          }
        ]
      });

      const order =
        await paypalClient()
          .execute(
            request
          );

      res.json({
        orderId:
          order.result.id
      });
    } catch (error) {
      console.error(
        'PayPal create-order error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to create order'
        });
    }
  }
);

app.post(
  '/api/payments/paypal/capture-order',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        orderId
      } = req.body;

      if (!orderId) {
        return res
          .status(400)
          .json({
            error:
              'orderId is required'
          });
      }

      // Idempotency: a replayed capture for an order we
      // already credited must not double-credit.
      const existing =
        await pool.query(
          `
          SELECT *
          FROM transactions
          WHERE user_id = $1
            AND type = 'credit_purchase'
            AND description = $2
          `,
          [
            req.user.id,
            `PayPal order ${orderId}`
          ]
        );

      if (existing.rows.length) {
        return res.json({
          success: true,
          transaction:
            existing.rows[0]
        });
      }

      const request =
        new paypal.orders
          .OrdersCaptureRequest(
            orderId
          );

      request.requestBody({});

      const capture =
        await paypalClient()
          .execute(
            request
          );

      const amountUsd =
        parseFloat(
          capture.result
            .purchase_units[0]
            .payments.captures[0]
            .amount.value
        );

      await pool.query(
        `
        UPDATE users

        SET
          balance_credits =
            balance_credits + $1

        WHERE id = $2
        `,
        [
          amountUsd,
          req.user.id
        ]
      );

      const tx =
        await pool.query(
          `
          INSERT INTO transactions
          (
            user_id,
            type,
            amount_usd,
            credits_amount,
            status,
            description
          )
          VALUES
          (
            $1,
            'credit_purchase',
            $2,
            $2,
            'completed',
            $3
          )
          RETURNING *
          `,
          [
            req.user.id,
            amountUsd,
            `PayPal order ${orderId}`
          ]
        );

      res.json({
        success: true,
        transaction:
          tx.rows[0]
      });
    } catch (error) {
      console.error(
        'PayPal capture-order error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to capture order'
        });
    }
  }
);

// ========================================
// 🪙 Credits (shop checkout)
// ========================================

// Mirrors the packs in public/shop.html — `value` is the
// PayPal charge in USD, `credits` is what the buyer gets.
const CREDIT_PACKAGES = {
  starter: { credits: 100, value: '0.99' },
  captain: { credits: 500, value: '3.99' },
  commander: { credits: 1200, value: '7.99' },
  elite: { credits: 3000, value: '17.99' },
  cxo: { credits: 7000, value: '34.99' },
  king: { credits: 20000, value: '89.99' }
};

app.get(
  '/api/credits/balance',
  authenticateToken,
  async (req, res) => {
    const result =
      await pool.query(
        `
        SELECT
          balance_credits,
          total_earned
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

    res.json({
      balance:
        parseFloat(
          result.rows[0]
            .balance_credits
        ),

      total_earned:
        parseFloat(
          result.rows[0]
            .total_earned
        )
    });
  }
);

app.post(
  '/api/credits/create-order',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        packageId
      } = req.body;

      const pack =
        CREDIT_PACKAGES[packageId];

      if (!pack) {
        return res
          .status(400)
          .json({
            error:
              'Unknown package'
          });
      }

      const request =
        new paypal.orders
          .OrdersCreateRequest();

      request.requestBody({
        intent:
          'CAPTURE',

        purchase_units: [
          {
            amount: {
              currency_code:
                'USD',

              value:
                pack.value
            }
          }
        ]
      });

      const order =
        await paypalClient()
          .execute(
            request
          );

      res.json({
        orderId:
          order.result.id
      });
    } catch (error) {
      console.error(
        'Credits create-order error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to create order'
        });
    }
  }
);

app.post(
  '/api/credits/capture-order',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        orderId
      } = req.body;

      if (!orderId) {
        return res
          .status(400)
          .json({
            error:
              'orderId is required'
          });
      }

      // Idempotency: a replayed capture for an order we
      // already credited must not double-credit.
      const existing =
        await pool.query(
          `
          SELECT *
          FROM transactions
          WHERE user_id = $1
            AND type = 'credit_purchase'
            AND description = $2
          `,
          [
            req.user.id,
            `PayPal order ${orderId}`
          ]
        );

      if (existing.rows.length) {
        const balanceRows =
          await pool.query(
            `
            SELECT balance_credits
            FROM users
            WHERE id = $1
            `,
            [req.user.id]
          );

        return res.json({
          success: true,

          newBalance:
            parseFloat(
              balanceRows.rows[0]
                .balance_credits
            ),

          transaction:
            existing.rows[0]
        });
      }

      const request =
        new paypal.orders
          .OrdersCaptureRequest(
            orderId
          );

      request.requestBody({});

      const capture =
        await paypalClient()
          .execute(
            request
          );

      const amountUsd =
        parseFloat(
          capture.result
            .purchase_units[0]
            .payments.captures[0]
            .amount.value
        );

      // Map the captured amount back to its shop pack and
      // credit the pack's credits (packs are not 1:1 USD).
      // Orders from other flows fall back to 1:1.
      const pack =
        Object.values(
          CREDIT_PACKAGES
        ).find(
          (p) =>
            parseFloat(p.value) ===
            amountUsd
        );

      const credits =
        pack
          ? pack.credits
          : amountUsd;

      const balanceResult =
        await pool.query(
          `
          UPDATE users

          SET
            balance_credits =
              balance_credits + $1

          WHERE id = $2

          RETURNING balance_credits
          `,
          [
            credits,
            req.user.id
          ]
        );

      const tx =
        await pool.query(
          `
          INSERT INTO transactions
          (
            user_id,
            type,
            amount_usd,
            credits_amount,
            status,
            description
          )
          VALUES
          (
            $1,
            'credit_purchase',
            $2,
            $3,
            'completed',
            $4
          )
          RETURNING *
          `,
          [
            req.user.id,
            amountUsd,
            credits,
            `PayPal order ${orderId}`
          ]
        );

      res.json({
        success: true,

        newBalance:
          parseFloat(
            balanceResult.rows[0]
              .balance_credits
          ),

        transaction:
          tx.rows[0]
      });
    } catch (error) {
      console.error(
        'Credits capture-order error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to capture order'
        });
    }
  }
);

// ========================================
// 📡 WebSocket
// ========================================

// userId -> open socket count, for DM
// presence (user_online / user_offline).

const onlineUserSockets =
  new Map();
const userSocketMap = new Map(); // userId -> Set<socketId> single session
const pendingSessionConflicts = new Map(); // socketId -> {userId, existingSet, timestamp}
const autoBattleQueue = []; // waiting for auto match
const activeBattles = new Map();

io.on(
  'connection',
  (socket) => {
    const handshakeToken =
      (
        socket.handshake
          .auth &&
        socket.handshake.auth
          .token
      ) ||

      (
        socket.handshake
          .query &&
        socket.handshake.query
          .token
      ) ||

      null;

    if (
      handshakeToken &&
      process.env.JWT_SECRET
    ) {
      try {
        const payload =
          jwt.verify(
            handshakeToken,
            process.env.JWT_SECRET
          );

        if (
          payload &&
          payload.id
        ) {
          socket.data.userId =
            payload.id;

          socket.join(
            'user-' +
              payload.id
          );
        }
      } catch (_) {}
    }

    // ------------------------------------
    // Presence + SINGLE SESSION ENFORCEMENT
    // ------------------------------------

    const authedUserId =
      socket.data.userId ||
      null;

    // helper to finalize login after confirm
    const finalizeLogin = () => {
      if (!authedUserId) return;
      // if already finalized, skip
      if (userSocketMap.has(authedUserId) && userSocketMap.get(authedUserId).has(socket.id)) return;

      if (!userSocketMap.has(authedUserId)) userSocketMap.set(authedUserId, new Set());
      userSocketMap.get(authedUserId).add(socket.id);

      for (const uid of onlineUserSockets.keys()) {
        socket.emit('user_online', { userId: uid });
      }

      const onlineCount = onlineUserSockets.get(authedUserId) || 0;
      onlineUserSockets.set(authedUserId, onlineCount + 1);

      if (onlineCount === 0) {
        io.emit('user_online', { userId: authedUserId });
      }

      socket.emit('session_confirmed', { userId: authedUserId });
    };

    if (authedUserId) {
      const existingSet = userSocketMap.get(authedUserId);

      if (existingSet && existingSet.size > 0) {
        // CONFLICT - ask user if they want to continue here and kill other device
        pendingSessionConflicts.set(socket.id, {
          userId: authedUserId,
          existingSet: new Set(existingSet),
          timestamp: Date.now()
        });

        socket.emit('session_conflict', {
          message: 'You are already logged in on another device. Do you want to continue here? The other device will be logged out.',
          otherDevices: existingSet.size,
          userId: authedUserId
        });

        console.log(`⚠️ Session conflict for ${authedUserId} - ${existingSet.size} other device(s), asking confirmation from ${socket.id}`);

        // auto-cancel after 60s if no response
        setTimeout(() => {
          if (pendingSessionConflicts.has(socket.id)) {
            pendingSessionConflicts.delete(socket.id);
            socket.emit('session_cancelled', { reason: 'Timeout - stayed on other device' });
            socket.disconnect(true);
          }
        }, 60000);

      } else {
        // No conflict, login directly
        finalizeLogin();
      }

      // Listen for user's choice
      socket.on('session_confirm', (p = {}) => {
        const action = p.action || p.choice || 'continue';
        const pending = pendingSessionConflicts.get(socket.id);
        if (!pending) return;

        if (action === 'continue' || action === 'yes' || action === 'confirm') {
          // Kick old devices
          for (const oldSid of pending.existingSet) {
            if (oldSid !== socket.id) {
              const oldSock = io.sockets.sockets.get(oldSid);
              if (oldSock) {
                oldSock.emit('session_kicked', { 
                  reason: 'You have been logged out because you logged in on another device',
                  by: socket.id
                });
                oldSock.disconnect(true);
              }
            }
          }
          pendingSessionConflicts.delete(socket.id);
          finalizeLogin();
          console.log(`✅ Session confirmed for ${authedUserId} - kicked ${pending.existingSet.size} old device(s)`);
        } else {
          // Cancel - stay on other device
          pendingSessionConflicts.delete(socket.id);
          socket.emit('session_cancelled', { reason: 'Cancelled - staying on other device' });
          socket.disconnect(true);
          console.log(`❌ Session cancelled for ${authedUserId} - staying on other device`);
        }
      });

      // Also support legacy event names
      socket.on('session:continue', () => socket.emit('session_confirm', { action: 'continue' }));
      socket.on('session:cancel', () => socket.emit('session_confirm', { action: 'cancel' }));
      socket.on('continue_here', () => socket.emit('session_confirm', { action: 'continue' }));
      socket.on('stay_there', () => socket.emit('session_confirm', { action: 'cancel' }));
    }

    socket.on(
      'disconnect',
      () => {
        // Clean pending conflict
        pendingSessionConflicts.delete(socket.id);

        // Remove from queue if disconnecting while searching
        const qIdx = autoBattleQueue.findIndex(q => q.socketId === socket.id);
        if (qIdx !== -1) {
          clearTimeout(autoBattleQueue[qIdx].timer);
          autoBattleQueue.splice(qIdx, 1);
        }

        if (!authedUserId) return;

        const set = userSocketMap.get(authedUserId);
        if (set) {
          set.delete(socket.id);
          if (set.size === 0) userSocketMap.delete(authedUserId);
        }

        const onlineCount =
          (
            onlineUserSockets.get(
              authedUserId
            ) || 1
          ) - 1;

        if (onlineCount <= 0) {
          onlineUserSockets.delete(
            authedUserId
          );

          io.emit(
            'user_offline',
            {
              userId:
                authedUserId
            }
          );
        } else {
          onlineUserSockets.set(
            authedUserId,
            onlineCount
          );
        }
      }
    );

    const onJoinUser =
      (p = {}) => {
        const userId =
          p.userId ||
          p.user_id;

        if (userId) {
          socket.join(
            'user-' +
              userId
          );
        }
      };

    socket.on(
      'user-online',
      onJoinUser
    );

    socket.on(
      'user_online',
      onJoinUser
    );

    const emitViewerCount =
      streamId => {
        const room =
          io.sockets
            .adapter.rooms.get(
              'stream-' +
                streamId
            );

        const n =
          room
            ? room.size
            : 0;

        io.to(
          'stream-' +
            streamId
        ).emit(
          'viewer_count',
          {
            viewer_count:
              n,

            streamId
          }
        );

        io.to(
          'stream-' +
            streamId
        ).emit(
          'viewer-count',
          {
            viewer_count:
              n,

            streamId
          }
        );
      };

    const onJoinStream =
      (p = {}) => {
        const streamId =
          p.streamId ||
          p.stream_id ||
          p.id;

        if (!streamId)
          return;

        socket.join(
          'stream-' +
            streamId
        );

        emitViewerCount(
          streamId
        );
      };

    const onLeaveStream =
      (p = {}) => {
        const streamId =
          p.streamId ||
          p.stream_id ||
          p.id;

        if (!streamId)
          return;

        socket.leave(
          'stream-' +
            streamId
        );

        emitViewerCount(
          streamId
        );
      };

    socket.on(
      'join-stream',
      onJoinStream
    );

    socket.on(
      'join_stream',
      onJoinStream
    );

    socket.on(
      'leave-stream',
      onLeaveStream
    );

    socket.on(
      'leave_stream',
      onLeaveStream
    );

    socket.on(
      'join-video',
      ({
        videoId
      } = {}) => {
        if (videoId) {
          socket.join(
            'video-' +
              videoId
          );
        }
      }
    );

    socket.on(
      'leave-video',
      ({
        videoId
      } = {}) => {
        if (videoId) {
          socket.leave(
            'video-' +
              videoId
          );
        }
      }
    );

    const onChat =
      (p = {}) => {
        const streamId =
          p.streamId ||
          p.stream_id;

        const message =
          p.message ||
          p.text ||
          p.content;

        const username =
          p.username ||
          p.user ||
          'Anonymous';

        if (
          !streamId ||
          !message
        ) {
          return;
        }

        const payload = {
          username,
          message,
          text:
            message,

          time:
            new Date()
              .toISOString()
        };

        io.to(
          'stream-' +
            streamId
        ).emit(
          'new-message',
          payload
        );

        io.to(
          'stream-' +
            streamId
        ).emit(
          'live_chat',
          payload
        );

        io.to(
          'stream-' +
            streamId
        ).emit(
          'live-chat',
          payload
        );
      };

    socket.on(
      'send-message',
      onChat
    );

    socket.on(
      'live_chat',
      onChat
    );

    socket.on(
      'live-chat',
      onChat
    );

    const onJoinBattle =
      (p = {}) => {
        const battleId =
          p.battleId ||
          p.battle_id;

        if (battleId) {
          socket.join(
            'battle-' +
              battleId
          );
        }
      };

    socket.on(
      'join_battle',
      onJoinBattle
    );

    socket.on(
      'join-battle',
      onJoinBattle
    );

    // ================= NVME LIVE FIX - START =================
    // TikTok-style same battleId room - this makes 2 phones see each other
    socket.on('battle:join', (p = {}) => {
      const battleId = p.battleId || p.battle_id || p.id;
      if (!battleId) return;
      socket.join(battleId);
      socket.join('battle-' + battleId);
      const room = io.sockets.adapter.rooms.get(battleId);
      const count = room ? room.size : 1;
      io.to(battleId).emit('battle:joined', { battleId, count, peerId: socket.id });
      socket.to(battleId).emit('battle:peer-joined', { id: socket.id, battleId });
      io.to('battle-' + battleId).emit('battle:joined', { battleId, count, peerId: socket.id });
    });

    socket.on('battle:leave', (p = {}) => {
      const battleId = p.battleId || p.battle_id || p.id;
      if (!battleId) return;
      socket.leave(battleId);
      socket.leave('battle-' + battleId);
      socket.to(battleId).emit('battle:peer-left', { id: socket.id, battleId });
      io.to(battleId).emit('battle:peer-left', { id: socket.id });
    });

    socket.on('gift:send', (p = {}) => {
      const battleId = p.battleId || p.battle_id;
      const giftId = p.giftId || p.gift_id || p.type;
      if (!battleId || !giftId) return;
      const isClub = giftId === 'daily-hug' || giftId === 'hug' || p.club;
      const payload = { type: giftId, id: giftId, sender: p.sender || 'Someone', legendary: !!p.legendary || isClub, club: isClub };
      if (p.legendary || isClub) {
        io.to(battleId).emit('gift:legendary', payload);
        io.to('battle-' + battleId).emit('gift:legendary', payload);
      } else {
        io.to(battleId).emit('gift', payload);
        io.to('battle-' + battleId).emit('gift', payload);
      }
    });
    
    // ================= AUTO BATTLE MATCHMAKING - 60s timeout =================
    const findOpponent = (myEntry) => {
      // find first different user
      const idx = autoBattleQueue.findIndex(q => q.userId !== myEntry.userId);
      if (idx === -1) return null;
      const opponent = autoBattleQueue[idx];
      autoBattleQueue.splice(idx, 1);
      return opponent;
    };

    const handleAutoBattleFind = async (p = {}) => {
      const userId = socket.data.userId;
      if (!userId) {
        socket.emit('battle:error', { error: 'Not authenticated' });
        return;
      }
      // prevent double queue
      const existing = autoBattleQueue.find(q => q.userId === userId);
      if (existing) {
        socket.emit('battle:searching', { message: 'Already searching...' });
        return;
      }

      const streamId = p.streamId || p.stream_id || null;

      const myEntry = {
        userId,
        socketId: socket.id,
        streamId,
        joinedAt: Date.now(),
        timer: null
      };

      // Try immediate match
      const opponent = findOpponent(myEntry);
      if (opponent) {
        // MATCHED!
        const battleId = uuidv4();
        activeBattles.set(battleId, {
          id: battleId,
          users: [userId, opponent.userId],
          sockets: [socket.id, opponent.socketId],
          createdAt: Date.now()
        });

        // Make both join battle room
        socket.join(battleId);
        socket.join('battle-' + battleId);
        const oppSock = io.sockets.sockets.get(opponent.socketId);
        if (oppSock) {
          oppSock.join(battleId);
          oppSock.join('battle-' + battleId);
        }

        // Create DB row if tables exist (best effort)
        try {
          const bRes = await pool.query(
            `INSERT INTO stream_battles (id, stream_id, host_id, status, started_at) VALUES ($1, $2, $3, 'active', NOW()) RETURNING *`,
            [battleId, streamId || opponent.streamId, userId]
          );
          await pool.query(
            `INSERT INTO battle_participants (battle_id, user_id, team) VALUES ($1, $2, 'a'), ($1, $3, 'b') ON CONFLICT DO NOTHING`,
            [battleId, userId, opponent.userId]
          );
        } catch(e){ console.log('battle db insert skip', e.message); }

        const payloadForMe = {
          battleId,
          opponentId: opponent.userId,
          opponentSocketId: opponent.socketId,
          role: 'a'
        };
        const payloadForOpp = {
          battleId,
          opponentId: userId,
          opponentSocketId: socket.id,
          role: 'b'
        };

        socket.emit('battle:matched', payloadForMe);
        io.to(opponent.socketId).emit('battle:matched', payloadForOpp);

        // Also emit to battle room for ring UI
        io.to(battleId).emit('battle:joined', { battleId, count: 2 });
        io.to(battleId).emit('battle:started', { battleId });

        console.log(`⚔️ Auto Battle matched ${userId} vs ${opponent.userId} => ${battleId}`);
        return;
      }

      // No opponent - add to queue and start 60s timer
      const timer = setTimeout(() => {
        const idx = autoBattleQueue.findIndex(q => q.socketId === socket.id);
        if (idx !== -1) {
          autoBattleQueue.splice(idx, 1);
          socket.emit('battle:timeout', { message: 'No opponent found in 60s' });
          socket.emit('battle:no_opponent', { message: 'No opponent found' });
          console.log(`⏰ Auto Battle timeout for ${userId}`);
        }
      }, 60000);

      myEntry.timer = timer;
      autoBattleQueue.push(myEntry);
      socket.emit('battle:searching', { message: 'Finding opponent...', position: autoBattleQueue.length });
      console.log(`🔍 Auto Battle queue: ${userId} waiting, queue size ${autoBattleQueue.length}`);
    };

    const handleAutoBattleCancel = () => {
      const idx = autoBattleQueue.findIndex(q => q.socketId === socket.id);
      if (idx !== -1) {
        clearTimeout(autoBattleQueue[idx].timer);
        autoBattleQueue.splice(idx, 1);
        socket.emit('battle:cancelled', { message: 'Search cancelled' });
      }
    };

    // Listen to all possible frontend event names
    socket.on('auto_battle:find', handleAutoBattleFind);
    socket.on('battle:find', handleAutoBattleFind);
    socket.on('find_battle', handleAutoBattleFind);
    socket.on('battle_find', handleAutoBattleFind);
    socket.on('auto_battle:cancel', handleAutoBattleCancel);
    socket.on('battle:cancel', handleAutoBattleCancel);
    socket.on('cancel_battle', handleAutoBattleCancel);
    // ================= END AUTO BATTLE =================

    // ================= NVME LIVE FIX - END =================


    const onGiftByName =
      async (p = {}) => {
        const streamId =
          p.streamId ||
          p.stream_id;

        const giftName =
          p.giftName ||
          p.gift_name ||
          p.name;

        if (
          !streamId ||
          !giftName
        ) {
          socket.emit(
            'gift_error',
            {
              error:
                'stream and gift name required'
            }
          );

          return;
        }

        const payload = {
          giftName,

          emoji:
            p.emoji ||
            '🎁',

          fromUser:
            p.username ||
            'fan',

          quantity:
            p.quantity ||
            1,

          streamId
        };

        io.to(
          'stream-' +
            streamId
        ).emit(
          'gift_received',
          payload
        );

        io.to(
          'stream-' +
            streamId
        ).emit(
          'new-gift',
          payload
        );
      };

    socket.on(
      'send_gift_by_name',
      onGiftByName
    );

    socket.on(
      'send-gift-by-name',
      onGiftByName
    );

    // ------------------------------------
    // WebRTC
    // ------------------------------------

    [
      'webrtc_offer',
      'webrtc_answer',
      'webrtc_ice',
      'webrtc_viewer_join'
    ].forEach(
      ev => {
        socket.on(
          ev,
          (p = {}) => {
            const target =
              p.targetSocketId;

            const streamId =
              p.stream_id ||
              p.streamId;

            const payload =
              Object.assign(
                {},
                p,
                {
                  from:
                    socket.id
                }
              );

            if (target) {
              return socket
                .to(target)
                .emit(
                  ev,
                  payload
                );
            }

            if (streamId) {
              return socket
                .to(
                  'stream-' +
                    streamId
                )
                .emit(
                  ev,
                  payload
                );
            }
          }
        );
      }
    );

    // ------------------------------------
    // Direct messages
    // ------------------------------------

    socket.on(
      'dm_send',
      async (p = {}) => {
        try {
          const fromUserId =
            socket.data.userId;

          if (!fromUserId)
            return;

          const toUserId =
            p.toUserId;

          const content =
            String(
              p.content || ''
            )
              .trim()
              .slice(0, 2000);

          if (
            !toUserId ||
            !content ||
            toUserId ===
              fromUserId
          ) {
            return;
          }

          if (
            await isBlockedEitherWay(
              fromUserId,
              toUserId
            )
          ) {
            return;
          }

          let convId =
            p.conversationId ||
            null;

          if (convId) {
            const part =
              await pool.query(
                `
                SELECT 1
                FROM
                  dm_participants
                WHERE
                  conversation_id =
                    $1
                  AND user_id = $2
                `,
                [
                  convId,
                  fromUserId
                ]
              );

            if (
              part.rows.length ===
              0
            ) {
              return;
            }
          } else {
            // No conversation yet —
            // reuse or create the 1:1
            // with the recipient.

            convId =
              await findDmConversation(
                fromUserId,
                toUserId
              );

            if (!convId) {
              const created =
                await pool.query(
                  `
                  INSERT INTO
                    dm_conversations
                  DEFAULT VALUES
                  RETURNING id
                  `
                );

              convId =
                created.rows[0].id;

              await pool.query(
                `
                INSERT INTO
                  dm_participants
                (
                  conversation_id,
                  user_id
                )
                VALUES
                  ($1, $2),
                  ($1, $3)
                `,
                [
                  convId,
                  fromUserId,
                  toUserId
                ]
              );
            }
          }

          const inserted =
            await pool.query(
              `
              INSERT INTO
                dm_messages
              (
                conversation_id,
                sender_id,
                body,
                media_url
              )
              VALUES
                ($1, $2, $3, $4)
              RETURNING
                id,
                conversation_id,
                sender_id,
                body,
                media_url,
                created_at,
                read_at
              `,
              [
                convId,
                fromUserId,
                content,
                p.mediaUrl ||
                  null
              ]
            );

          await pool.query(
            `
            UPDATE
              dm_conversations
            SET
              last_message_at =
                NOW()
            WHERE id = $1
            `,
            [convId]
          );

          // The sender renders its own
          // bubble optimistically, so
          // only deliver to the
          // recipient's room.

          io.to(
            'user-' + toUserId
          ).emit(
            'dm_message',
            dmMessageJson(
              inserted.rows[0]
            )
          );
        } catch (e) {
          console.error(
            'dm_send error:',
            e.message
          );
        }
      }
    );

    socket.on(
      'dm_typing',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'dm_typing',
          {
            fromUserId,
            isTyping:
              !!p.isTyping
          }
        );
      }
    );

    socket.on(
      'dm_read',
      async (p = {}) => {
        try {
          const readerId =
            socket.data.userId;

          const convId =
            p.conversationId;

          if (
            !readerId ||
            !convId
          ) {
            return;
          }

          const part =
            await pool.query(
              `
              SELECT 1
              FROM
                dm_participants
              WHERE
                conversation_id =
                  $1
                AND user_id = $2
              `,
              [
                convId,
                readerId
              ]
            );

          if (
            part.rows.length === 0
          ) {
            return;
          }

          await pool.query(
            `
            UPDATE
              dm_participants
            SET
              last_read_at =
                NOW()
            WHERE
              conversation_id = $1
              AND user_id = $2
            `,
            [
              convId,
              readerId
            ]
          );

          await pool.query(
            `
            UPDATE dm_messages
            SET
              read_at = NOW()
            WHERE
              conversation_id = $1
              AND sender_id <> $2
              AND read_at IS NULL
            `,
            [
              convId,
              readerId
            ]
          );

          const others =
            await pool.query(
              `
              SELECT user_id
              FROM
                dm_participants
              WHERE
                conversation_id =
                  $1
                AND user_id <> $2
              `,
              [
                convId,
                readerId
              ]
            );

          for (
            const o of others.rows
          ) {
            io.to(
              'user-' +
                o.user_id
            ).emit(
              'dm_read',
              {
                conversationId:
                  convId,
                readerId
              }
            );
          }
        } catch (e) {
          console.error(
            'dm_read error:',
            e.message
          );
        }
      }
    );

    // ------------------------------------
    // 1:1 call signaling (pure relays
    // to the target user's room)
    // ------------------------------------

    socket.on(
      'vc_offer',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        const targetRoom =
          io.sockets.adapter
            .rooms.get(
              'user-' +
                p.toUserId
            );

        if (
          !targetRoom ||
          targetRoom.size === 0
        ) {
          socket.emit(
            'vc_unreachable',
            {
              toUserId:
                p.toUserId
            }
          );

          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'vc_offer',
          {
            fromUserId,
            offer: p.offer,
            withVideo:
              p.withVideo
          }
        );
      }
    );

    socket.on(
      'vc_answer',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'vc_answer',
          {
            fromUserId,
            answer: p.answer
          }
        );
      }
    );

    socket.on(
      'vc_ice_candidate',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'vc_ice_candidate',
          {
            fromUserId,
            candidate:
              p.candidate
          }
        );
      }
    );

    socket.on(
      'vc_reject',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'vc_reject',
          { fromUserId }
        );
      }
    );

        socket.on(
      'vc_hangup',
      (p = {}) => {
        const fromUserId =
          socket.data.userId;

        if (
          !fromUserId ||
          !p.toUserId
        ) {
          return;
        }

        io.to(
          'user-' + p.toUserId
        ).emit(
          'vc_hangup',
          { fromUserId }
        );
      }
    );

    // LIVE HUB Ring Pass-Through - persists selector + filters to viewers
    socket.on('live_filter_change', (p = {}) => {
      const userId = socket.data.userId; if (!userId) return;
      if (p.streamId) io.to('stream-' + p.streamId).emit('live_filter_change', { userId, filter: p.filter, intensity: p.intensity, greenScreen: p.greenScreen });
      io.emit('live_filter_update', { userId, ...p });
    });
    socket.on('green_screen_change', (p = {}) => {
      const userId = socket.data.userId; if (!userId) return;
      if (p.streamId) io.to('stream-' + p.streamId).emit('green_screen_change', { userId, url: p.url, mode: p.mode });
    });
    socket.on('selector_ring_change', (p = {}) => {
      const userId = socket.data.userId; if (!userId) return;
      io.to('user-' + userId).emit('selector_ring_update', p);
      if (p.streamId) io.to('stream-' + p.streamId).emit('selector_ring_update', p);
    });
  }
);

// ========================================
// 🏠 Serve Frontend
// ========================================

app.get(
  '/u/:username',
  (req, res) => {
    res.sendFile(
      'profile-view.html',
      {
        root:
          path.join(
            __dirname,
            'frontend'
          )
      }
    );
  }
);

app.get(
  '/battles',
  (req, res) =>
    res.sendFile(
      'creator.html',
      {
        root: 'public'
      }
    )
);

app.get(
  '/profile',
  (req, res) =>
    res.sendFile(
      'app.html',
      {
        root: 'public'
      }
    )
);

app.get(
  '/discover',
  (req, res) =>
    res.sendFile(
      'app.html',
      {
        root: 'public'
      }
    )
);

app.get(
  '/inbox',
  (req, res) =>
    res.sendFile(
      'messages.html',
      {
        root: 'public'
      }
    )
);

// ========================================
// 🧠 Background Intelligence Worker
// ========================================

let intelligenceWorkerRunning =
  false;

async function runIntelligenceCycle() {
  if (
    intelligenceWorkerRunning
  ) {
    return;
  }

  intelligenceWorkerRunning =
    true;

  try {
    // ------------------------------------
    // 1. Recalculate active trends
    // ------------------------------------

    const trends =
      await pool.query(
        `
        SELECT id
        FROM trending_topics

        WHERE
          status = 'active'
          AND last_seen_at >
            NOW() -
            INTERVAL '7 days'

        ORDER BY
          trend_score DESC

        LIMIT 50
        `
      );

    for (
      const trend of trends.rows
    ) {
      await calculateTrendScore(
        trend.id
      );
    }

    // ------------------------------------
    // 2. Refresh video completion metrics
    // ------------------------------------

    await pool.query(
      `
      UPDATE videos v

      SET
        completion_rate =
          COALESCE(
            (
              SELECT
                AVG(
                  CASE
                    WHEN ve.video_duration_ms > 0
                    THEN
                      LEAST(
                        1,
                        GREATEST(
                          0,
                          ve.watch_ms::numeric /
                          ve.video_duration_ms::numeric
                        )
                      )
                    ELSE 0
                  END
                )

              FROM video_events ve

              WHERE
                ve.video_id = v.id

                AND ve.event_type IN
                (
                  'play',
                  'complete',
                  'rewatch',
                  '50_percent',
                  '75_percent'
                )

                AND ve.created_at >
                  NOW() -
                  INTERVAL '30 days'
            ),
            0
          ),

        avg_watch_ms =
          COALESCE(
            (
              SELECT
                AVG(
                  ve.watch_ms
                )

              FROM video_events ve

              WHERE
                ve.video_id = v.id

                AND ve.watch_ms > 0

                AND ve.created_at >
                  NOW() -
                  INTERVAL '30 days'
            ),
            0
          ),

        last_ranked_at =
          NOW()

      WHERE
        v.is_published = true
      `
    );

    // ------------------------------------
    // 3. Normalize recommendation scores
    // ------------------------------------

    await pool.query(
      `
      UPDATE videos

      SET
        recommendation_score =
          GREATEST(
            -100,
            LEAST(
              100,
              recommendation_score * 0.995
            )
          )

      WHERE
        recommendation_score IS NOT NULL
      `
    );

    // ------------------------------------
    // 4. Expire old trends
    // ------------------------------------

    await pool.query(
      `
      UPDATE trending_topics

      SET
        status = 'expired',
        updated_at = NOW()

      WHERE
        status = 'active'

        AND last_seen_at <
          NOW() -
          INTERVAL '7 days'
      `
    );
  } catch (error) {
    console.error(
      '🧠 Intelligence worker error:',
      error.message
    );
  } finally {
    intelligenceWorkerRunning =
      false;
  }
}

// ========================================
// 🛡️ Admin / Moderation
// ========================================
// All routes require a valid token AND a
// DB-verified is_admin row (requireAdmin
// re-checks per request). First admin is
// granted manually in the database:
//   UPDATE users SET is_admin = true
//   WHERE email = 'you@example.com';

app.get(
  '/api/admin/users',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const q =
        String(
          req.query.q || ''
        ).trim();

      const limit =
        Math.min(
          Number(
            req.query.limit
          ) || 50,
          100
        );

      const offset =
        Math.max(
          Number(
            req.query.offset
          ) || 0,
          0
        );

      const params = [];

      let where = '';

      if (q) {
        params.push(`%${q}%`);

        where =
          `WHERE
            username ILIKE $1
            OR email ILIKE $1`;
      }

      params.push(limit, offset);

      // Explicit column list — never
      // SELECT * (password_hash must not
      // leave the database).

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            email,
            is_admin,
            is_banned,
            email_verified,
            created_at
          FROM users
          ${where}
          ORDER BY created_at DESC
          LIMIT $${params.length - 1}
          OFFSET $${params.length}
          `,
          params
        );

      res.json({
        users: result.rows
      });
    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch users'
        });
    }
  }
);

app.post(
  '/api/admin/users/:id/ban',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE users
          SET is_banned = true
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      // Kill every active session —
      // access JWTs expire on their own,
      // refresh tokens do not get to.

      await revokeUserRefreshTokens(
        req.params.id
      );

      res.json({
        success: true,
        is_banned: true
      });
    } catch (error) {
      console.error(
        'Admin ban error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to ban user'
        });
    }
  }
);

app.post(
  '/api/admin/users/:id/unban',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE users
          SET is_banned = false
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      res.json({
        success: true,
        is_banned: false
      });
    } catch (error) {
      console.error(
        'Admin unban error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to unban user'
        });
    }
  }
);

// Moderation queue — video_feedback rows
// with feedback_type = 'report', joined
// with the video, its author, and the
// reporter. (video_feedback stores no
// free-text reason; feedback_type is
// surfaced as `reason`.)

app.get(
  '/api/admin/reports',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const limit =
        Math.min(
          Number(
            req.query.limit
          ) || 50,
          100
        );

      const offset =
        Math.max(
          Number(
            req.query.offset
          ) || 0,
          0
        );

      const result =
        await pool.query(
          `
          SELECT
            vf.id,
            vf.feedback_type
              AS reason,
            vf.created_at,

            v.id AS video_id,
            v.title
              AS video_title,
            v.video_url,
            v.thumbnail_url,
            v.is_published,

            author.id
              AS author_id,
            author.username
              AS author_username,

            reporter.id
              AS reporter_id,
            reporter.username
              AS reporter_username

          FROM video_feedback vf

          JOIN videos v
            ON v.id = vf.video_id

          LEFT JOIN users author
            ON author.id = v.user_id

          JOIN users reporter
            ON reporter.id =
              vf.user_id

          WHERE
            vf.feedback_type =
              'report'

          ORDER BY
            vf.created_at DESC

          LIMIT $1
          OFFSET $2
          `,
          [limit, offset]
        );

      res.json({
        reports: result.rows
      });
    } catch (error) {
      console.error(
        'Admin reports error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch reports'
        });
    }
  }
);

// Soft-remove — is_published = false
// drops the video from every feed query
// (they all filter is_published = true)
// without deleting data.

app.post(
  '/api/admin/videos/:id/remove',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE videos
          SET
            is_published = false
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error:
              'Video not found'
          });
      }

      res.json({
        success: true,
        is_published: false
      });
    } catch (error) {
      console.error(
        'Admin remove video error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to remove video'
        });
    }
  }
);

// ----------------------------------------
// Withdrawal queue — creators request
// payouts via POST /api/wallet/withdraw
// (balance debited up front, transaction
// row 'pending'). An admin then approves
// (real PayPal payout) or rejects
// (refund) here.
// ----------------------------------------

app.get(
  '/api/admin/withdrawals',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const status =
        String(
          req.query.status || ''
        ).trim();

      const allowed = [
        'pending',
        'processing',
        'failed',
        'completed',
        'rejected'
      ];

      if (
        status &&
        !allowed.includes(status)
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid status filter'
          });
      }

      const limit =
        Math.min(
          Number(
            req.query.limit
          ) || 50,
          100
        );

      const offset =
        Math.max(
          Number(
            req.query.offset
          ) || 0,
          0
        );

      const params = [];

      let where =
        `WHERE t.type = 'withdrawal'`;

      if (status) {
        params.push(status);

        where +=
          ` AND t.status = $${params.length}`;
      }

      params.push(limit, offset);

      // Explicit column list — user rows
      // are joined for context, but only
      // payout-relevant fields leave the
      // database.

      const result =
        await pool.query(
          `
          SELECT
            t.id,
            t.amount_usd,
            t.status,
            t.description,
            t.payout_batch_id,
            t.created_at,

            u.id AS user_id,
            u.username,
            u.email,
            u.paypal_email

          FROM transactions t

          JOIN users u
            ON u.id = t.user_id

          ${where}

          ORDER BY
            CASE
              WHEN t.status = 'pending'
                THEN 0
              ELSE 1
            END,
            t.created_at DESC

          LIMIT $${params.length - 1}
          OFFSET $${params.length}
          `,
          params
        );

      res.json({
        withdrawals:
          result.rows
      });
    } catch (error) {
      console.error(
        'Admin withdrawals error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch withdrawals'
        });
    }
  }
);

// Approve = send the real payout through
// the PayPal Payouts API. The pending row
// is first claimed atomically
// ('processing') so a double approve can
// never pay twice; sender_item_id is the
// transaction id, so PayPal-side retries
// are idempotent as well. On any PayPal
// failure the row goes 'failed' and the
// debited amount is refunded to the
// user's balance in one DB transaction.

app.post(
  '/api/admin/withdrawals/:id/approve',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (!paypalConfigured()) {
        return res
          .status(503)
          .json({
            error:
              'PayPal is not configured — set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET'
          });
      }

      const claim =
        await pool.query(
          `
          UPDATE transactions
          SET status = 'processing'
          WHERE id = $1
            AND type = 'withdrawal'
            AND status = 'pending'
          RETURNING
            user_id,
            amount_usd
          `,
          [req.params.id]
        );

      if (claim.rows.length === 0) {
        const existing =
          await pool.query(
            `
            SELECT status
            FROM transactions
            WHERE id = $1
              AND type = 'withdrawal'
            `,
            [req.params.id]
          );

        if (
          existing.rows.length === 0
        ) {
          return res
            .status(404)
            .json({
              error:
                'Withdrawal not found'
            });
        }

        return res
          .status(409)
          .json({
            error:
              `Withdrawal is already ${existing.rows[0].status}`
          });
      }

      const {
        user_id,
        amount_usd
      } = claim.rows[0];

      const userResult =
        await pool.query(
          `
          SELECT paypal_email
          FROM users
          WHERE id = $1
          `,
          [user_id]
        );

      const paypalEmail =
        userResult.rows[0]
          ?.paypal_email;

      let payoutBatchId =
        null;

      try {
        if (!paypalEmail) {
          throw new Error(
            'User has no PayPal email'
          );
        }

        payoutBatchId =
          await paypalSendPayout({
            transactionId:
              req.params.id,
            email: paypalEmail,
            amountUsd: amount_usd
          });
      } catch (payoutError) {
        // Payout failed — mark the
        // transaction failed and refund
        // the debited balance atomically.

        const client =
          await pool.connect();

        try {
          await client.query(
            'BEGIN'
          );

          await client.query(
            `
            UPDATE transactions
            SET status = 'failed'
            WHERE id = $1
            `,
            [req.params.id]
          );

          await client.query(
            `
            UPDATE users
            SET
              balance_credits =
                balance_credits + $1
            WHERE id = $2
            `,
            [amount_usd, user_id]
          );

          await client.query(
            'COMMIT'
          );
        } catch (err) {
          await client.query(
            'ROLLBACK'
          );

          throw err;
        } finally {
          client.release();
        }

        return res
          .status(502)
          .json({
            error:
              `PayPal payout failed: ${payoutError.message}`,
            refunded: true
          });
      }

      await pool.query(
        `
        UPDATE transactions
        SET
          status = 'completed',
          payout_batch_id = $2
        WHERE id = $1
        `,
        [
          req.params.id,
          payoutBatchId
        ]
      );

      res.json({
        success: true,
        status: 'completed',
        payout_batch_id:
          payoutBatchId
      });
    } catch (error) {
      console.error(
        'Admin approve withdrawal error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to approve withdrawal'
        });
    }
  }
);

// Reject = no payout; the debited amount
// is refunded and the row goes
// 'rejected', all in one transaction.

app.post(
  '/api/admin/withdrawals/:id/reject',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const claim =
        await client.query(
          `
          UPDATE transactions
          SET status = 'rejected'
          WHERE id = $1
            AND type = 'withdrawal'
            AND status = 'pending'
          RETURNING
            user_id,
            amount_usd
          `,
          [req.params.id]
        );

      if (claim.rows.length === 0) {
        await client.query(
          'ROLLBACK'
        );

        const existing =
          await pool.query(
            `
            SELECT status
            FROM transactions
            WHERE id = $1
              AND type = 'withdrawal'
            `,
            [req.params.id]
          );

        if (
          existing.rows.length === 0
        ) {
          return res
            .status(404)
            .json({
              error:
                'Withdrawal not found'
            });
        }

        return res
          .status(409)
          .json({
            error:
              `Withdrawal is already ${existing.rows[0].status}`
          });
      }

      await client.query(
        `
        UPDATE users
        SET
          balance_credits =
            balance_credits + $1
        WHERE id = $2
        `,
        [
          claim.rows[0].amount_usd,
          claim.rows[0].user_id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        success: true,
        status: 'rejected',
        refunded: true
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Admin reject withdrawal error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to reject withdrawal'
        });
    } finally {
      client.release();
    }
  }
);

// ----------------------------------------
// 📣 Admin: in-feed ads
// ----------------------------------------
// Sponsored placements blended into
// /api/feed by getRankedFeed. An ad
// either promotes an existing video
// (video_id) or carries an external
// creative (video_url / image_url).

app.get(
  '/api/admin/ads',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.*,
            v.title AS video_title
          FROM ads a
          LEFT JOIN videos v
            ON v.id = a.video_id
          ORDER BY a.created_at DESC
          `
        );

      res.json({
        ads: result.rows
      });
    } catch (error) {
      console.error(
        'Admin ads list error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to fetch ads'
        });
    }
  }
);

app.post(
  '/api/admin/ads',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        video_id,
        image_url,
        video_url,
        title,
        link_url,
        link_text,
        advertiser,
        priority,
        is_active
      } = req.body;

      if (
        !video_id &&
        !video_url &&
        !image_url
      ) {
        return res
          .status(400)
          .json({
            error:
              'Provide video_id, video_url, or image_url'
          });
      }

      if (video_id) {
        const video =
          await pool.query(
            `
            SELECT id
            FROM videos
            WHERE id = $1
            `,
            [video_id]
          );

        if (video.rows.length === 0) {
          return res
            .status(404)
            .json({
              error:
                'Video not found'
            });
        }
      }

      const result =
        await pool.query(
          `
          INSERT INTO ads
          (
            video_id,
            image_url,
            video_url,
            title,
            link_url,
            link_text,
            advertiser,
            priority,
            is_active
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          RETURNING *
          `,
          [
            video_id || null,
            image_url || null,
            video_url || null,
            title || null,
            link_url || null,
            link_text || 'Learn more',
            advertiser || null,
            Number(priority) || 1,
            is_active !== false
          ]
        );

      res.json({
        ad: result.rows[0]
      });
    } catch (error) {
      console.error(
        'Admin create ad error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to create ad'
        });
    }
  }
);

app.post(
  '/api/admin/ads/:id/toggle',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE ads
          SET
            is_active =
              NOT is_active
          WHERE id = $1
          RETURNING
            id,
            is_active
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error: 'Ad not found'
          });
      }

      res.json({
        success: true,
        is_active:
          result.rows[0].is_active
      });
    } catch (error) {
      console.error(
        'Admin toggle ad error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to toggle ad'
        });
    }
  }
);

app.delete(
  '/api/admin/ads/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          DELETE FROM ads
          WHERE id = $1
          RETURNING id
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({
            error: 'Ad not found'
          });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Admin delete ad error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to delete ad'
        });
    }
  }
);

// ========================================
// 🔔 Web Push — VAPID setup, subscription
// routes, and the sendPushToUser helper
// createNotification fires alongside its
// in-app socket emit. Schema lives in
// db/migration_014_push_replies.sql.
// Everything no-ops gracefully when the
// web-push package or VAPID keys are
// missing. MUST stay above the catch-all.
// ========================================

const VAPID_PUBLIC_KEY =
  process.env.VAPID_PUBLIC_KEY || '';

const VAPID_PRIVATE_KEY =
  process.env.VAPID_PRIVATE_KEY || '';

const VAPID_SUBJECT =
  process.env.VAPID_SUBJECT ||
  'mailto:admin@nvme.live';

let pushEnabled = false;

if (
  webpush &&
  VAPID_PUBLIC_KEY &&
  VAPID_PRIVATE_KEY
) {
  webpush.setVapidDetails(
    VAPID_SUBJECT,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );

  pushEnabled = true;

  console.log(
    '🔔 Web push enabled (VAPID configured)'
  );
} else {
  console.warn(
    '⚠️ Web push disabled — set VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY to enable'
  );
}

// Fire-and-forget: sends {title, body, url}
// to every subscription the user has, and
// prunes endpoints the push service reports
// as gone (404/410). Never throws — push
// must not break the action that triggered
// it.

async function sendPushToUser(
  userId,
  payload
) {
  if (!pushEnabled || !userId) return;

  try {
    const result = await pool.query(
      `
      SELECT endpoint, keys
      FROM push_subscriptions
      WHERE user_id = $1
      `,
      [userId]
    );

    const data =
      JSON.stringify(payload);

    await Promise.all(
      result.rows.map(async sub => {
        try {
          await webpush.sendNotification(
            {
              endpoint:
                sub.endpoint,

              keys:
                sub.keys
            },
            data
          );
        } catch (error) {
          if (
            error.statusCode ===
              404 ||
            error.statusCode ===
              410
          ) {
            await pool.query(
              `
              DELETE FROM push_subscriptions
              WHERE endpoint = $1
              `,
              [sub.endpoint]
            );
          } else {
            console.error(
              'Push send error:',
              error.statusCode ||
                error.message
            );
          }
        }
      })
    );
  } catch (error) {
    console.error(
      'Push send error:',
      error
    );
  }
}

app.get(
  '/api/push/vapid-public-key',
  (req, res) => {
    if (!pushEnabled) {
      return res
        .status(503)
        .json({
          error:
            'Push notifications not configured'
        });
    }

    res.json({
      publicKey: VAPID_PUBLIC_KEY
    });
  }
);

// Upsert by endpoint — the endpoint is the
// stable identity of a browser
// subscription; re-subscribing refreshes
// keys/ownership.

app.post(
  '/api/push/subscribe',
  authenticateToken,
  async (req, res) => {
    try {
      const subscription =
        req.body?.subscription ||
        {};

      const endpoint =
        subscription.endpoint;

      const keys =
        subscription.keys;

      if (
        !endpoint ||
        !keys ||
        !keys.p256dh ||
        !keys.auth
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid push subscription'
          });
      }

      await pool.query(
        `
        INSERT INTO push_subscriptions
        (
          user_id,
          endpoint,
          keys,
          user_agent
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4
        )
        ON CONFLICT (endpoint)
        DO UPDATE SET
          user_id =
            EXCLUDED.user_id,
          keys =
            EXCLUDED.keys,
          user_agent =
            EXCLUDED.user_agent
        `,
        [
          req.user.id,
          endpoint,
          JSON.stringify(keys),
          req.headers[
            'user-agent'
          ] || null
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Push subscribe error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to save subscription'
        });
    }
  }
);

// Delete by endpoint; creator.html's
// toggle sends no body, so fall back to
// clearing every subscription the caller
// owns.

app.post(
  '/api/push/unsubscribe',
  authenticateToken,
  async (req, res) => {
    try {
      const endpoint =
        req.body?.endpoint;

      if (endpoint) {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE endpoint = $1
            AND user_id = $2
          `,
          [
            endpoint,
            req.user.id
          ]
        );
      } else {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE user_id = $1
          `,
          [req.user.id]
        );
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Push unsubscribe error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to remove subscription'
        });
    }
  }
);

// Self/test notification — creator.html's
// "notify followers" button posts
// {title, body, url}. Scoped to the
// caller's own subscriptions.

app.post(
  '/api/push/notify',
  authenticateToken,
  async (req, res) => {
    try {
      const {
        title,
        body,
        url
      } = req.body || {};

      await sendPushToUser(
        req.user.id,
        {
          title:
            title || 'NVME',

          body:
            body || '',

          url:
            url || '/app'
        }
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Push notify error:',
        error
      );

      res
        .status(500)
        .json({
          error:
            'Failed to send notification'
        });
    }
  }
);

// ========================================
// 🏷️ Discovery — hashtags / sounds /
// duets / challenges. Salvaged from the
// old TikTok-parity module; schema lives
// in db/migration_013_discovery.sql,
// extended by 015_sounds_upload.sql.
// MUST stay above the catch-all.
// ========================================

require('./nvme-tiktok-features')(
  app,
  pool,
  authenticateToken,
  optionalAuth,
  requireAdmin
);

// ========================================
// Catch-all — MUST stay after every route
// registration; anything below this line
// is unreachable for GET requests.
// ========================================

app.get(
  '/live/:id',
  (req, res) =>
    res.sendFile(
      'live.html',
      {
        root: 'public'
      }
    )
);

app.get(
  '/live',
  (req, res) =>
    res.sendFile(
      'live.html',
      {
        root: 'public'
      }
    )
);

app.get(
  '*',
  (req, res) => {
    if (
      req.path.startsWith(
        '/api'
      ) ||

      req.path.startsWith(
        '/auth'
      ) ||

      req.path.startsWith(
        '/socket.io'
      )
    ) {
      return res
        .status(404)
        .json({
          error:
            'Not found'
        });
    }

    res.sendFile(
      'index.html',
      {
        root: 'public'
      }
    );
  }
);

// ========================================
// 🚀 Start Server
// ========================================

async function startServer() {
  try {
    await initializeIntelligenceDatabase();

    server.listen(
      PORT,
      () => {
        console.log('');
        console.log(
          '========================================'
        );

        console.log(
          `🚀 NVME.live running on port ${PORT}`
        );

        console.log(
          '========================================'
        );

        console.log(
          '🔐 Auth: register/login/me/google — enabled'
        );

        console.log(
          '❤️ Likes / 💬 Comments / 👥 Follows / 🔒 Privacy / 🔎 Search — enabled'
        );

        console.log(
          '💰 Gifts / Wallet / PayPal — enabled'
        );

        console.log(
          '⚔️ Battles — enabled'
        );

        console.log(
          '📹 Video upload / Cloudinary — enabled'
        );

        console.log(
          '🔥 Trending Engine — enabled'
        );

        console.log(
          '🧠 Atomic Claims — enabled'
        );

        console.log(
          '♻️ Claim Deduplication — enabled'
        );

        console.log(
          '📊 Behavioral Events — enabled'
        );

        console.log(
          '🚫 Not Interested — enabled'
        );

        console.log(
          '🎯 Personalized Ranking — enabled'
        );

        console.log(
          '🔁 Recommendation Feedback Loop — enabled'
        );

        console.log(
          '========================================'
        );
        console.log('');
      }
    );

    // Run shortly after startup.

    setTimeout(
      () => {
        runIntelligenceCycle()
          .catch(
            console.error
          );
      },
      10000
    );

    // Every 5 minutes.

    setInterval(
      () => {
        runIntelligenceCycle()
          .catch(
            console.error
          );
      },
      5 * 60 * 1000
    );
  } catch (error) {
    console.error(
      '❌ Failed to start NVME.live:',
      error
    );

    process.exit(1);
  }
}

startServer();

// ========================================
// 🛑 Process Error Handling
// ========================================

process.on(
  'unhandledRejection',
  err =>
    console.error(
      'Unhandled Rejection:',
      err
    )
);

process.on(
  'uncaughtException',
  err =>
    console.error(
      'Uncaught Exception:',
      err
    )
);
