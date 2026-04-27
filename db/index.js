// NVME Database - Neon Postgres
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

pool.on('error', (err) => {
  console.error('Postgres pool error:', err.message);
});

// Initialize schema - idempotent (safe to run multiple times)
async function initDB() {
  if (!process.env.DATABASE_URL) {
    console.warn('WARNING: DATABASE_URL not set - running in memory-only mode');
    return false;
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS creators (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        display_name VARCHAR(100),
        bio TEXT,
        country VARCHAR(10),
        categories TEXT[],
        avatar_url TEXT,
        followers INT DEFAULT 0,
        following INT DEFAULT 0,
        verified BOOLEAN DEFAULT FALSE,
        email_verified BOOLEAN DEFAULT FALSE,
        phone VARCHAR(20),
        phone_verified BOOLEAN DEFAULT FALSE,
        two_fa_enabled BOOLEAN DEFAULT FALSE,
        failed_login_count INT DEFAULT 0,
        locked_until TIMESTAMP,
        last_login_at TIMESTAMP,
        last_login_ip VARCHAR(45),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS videos (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID REFERENCES creators(id) ON DELETE CASCADE,
        caption TEXT,
        hashtags TEXT[],
        privacy VARCHAR(20) DEFAULT 'public',
        music VARCHAR(255),
        duration INT,
        file_url TEXT,
        thumbnail_url TEXT,
        views INT DEFAULT 0,
        likes INT DEFAULT 0,
        shares INT DEFAULT 0,
        comments INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID REFERENCES creators(id) ON DELETE CASCADE,
        refresh_token_hash VARCHAR(255) NOT NULL,
        device_fingerprint VARCHAR(64),
        ip_address VARCHAR(45),
        user_agent TEXT,
        expires_at TIMESTAMP NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        creator_id UUID,
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        metadata JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_creators_email ON creators(email);
      CREATE INDEX IF NOT EXISTS idx_creators_username ON creators(username);
      CREATE INDEX IF NOT EXISTS idx_videos_creator ON videos(creator_id);
      CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_creator ON sessions(creator_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_audit_creator ON audit_log(creator_id);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
    `);
    console.log('OK Database schema initialized');
    return true;
  } catch (err) {
    console.error('DB init error:', err.message);
    return false;
  }
}

// Write audit log entry
async function audit(creatorId, action, ip, userAgent, metadata = {}) {
  if (!process.env.DATABASE_URL) return;
  try {
    await pool.query(
      'INSERT INTO audit_log (creator_id, action, ip_address, user_agent, metadata) VALUES ($1, $2, $3, $4, $5)',
      [creatorId, action, ip, userAgent, JSON.stringify(metadata)]
    );
  } catch (err) {
    console.error('Audit error:', err.message);
  }
}

module.exports = { pool, initDB, audit };
