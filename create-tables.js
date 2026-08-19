require('dotenv').config({ path: './src/backend/.env' });
const pool = require('./src/backend/db');

(async () => {
  try {
    // Create the trending_topics table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS trending_topics (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        source TEXT,
        source_url TEXT,
        summary TEXT,
        category TEXT,
        keywords TEXT[],
        score INTEGER DEFAULT 50,
        fetched_at TIMESTAMP DEFAULT NOW(),
        nvme_version_id INTEGER
      );
    `);
    console.log('✅ Table "trending_topics" created (or already exists).');

    // Add missing columns to the videos table (for autoPostTrending)
    await pool.query(`
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS caption TEXT;
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS hashtags TEXT[];
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS source_type VARCHAR(50);
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0;
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_trending BOOLEAN DEFAULT false;
    `);
    console.log('✅ Videos table updated with trending-related columns (if missing).');

    await pool.end();
  } catch (err) {
    console.error('❌ Failed to set up tables:', err.message);
    process.exit(1);
  }
})();
