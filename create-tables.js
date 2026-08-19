require('dotenv').config({ path: './src/backend/.env' });
const pool = require('./src/backend/db');

(async () => {
  try {
    console.log('🔧 Setting up trending topics database...');

    // ============================================================
    // TRENDING TOPICS
    // ============================================================
    await pool.query(`
      CREATE TABLE IF NOT EXISTS trending_topics (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        source TEXT,
        source_url TEXT,
        summary TEXT,
        category TEXT,
        keywords TEXT[],
        score INTEGER DEFAULT 50,
        fetched_at TIMESTAMP DEFAULT NOW(),
        nvme_version_id UUID
      );
    `);

    console.log('✅ trending_topics table ready.');

    // ============================================================
    // VIDEOS - TRENDING COLUMNS
    // ============================================================
    await pool.query(`
      ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS caption TEXT;

      ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS hashtags TEXT[];

      ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS source_type VARCHAR(50);

      ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0;

      ALTER TABLE videos
        ADD COLUMN IF NOT EXISTS is_trending BOOLEAN DEFAULT false;
    `);

    console.log('✅ videos trending columns ready.');

    // ============================================================
    // ENSURE trending_topics.id IS UUID
    // ============================================================
    const idType = await pool.query(`
      SELECT data_type
      FROM information_schema.columns
      WHERE table_name = 'trending_topics'
        AND column_name = 'id'
    `);

    if (
      idType.rows.length > 0 &&
      idType.rows[0].data_type !== 'uuid'
    ) {
      console.log('🔧 Converting trending_topics.id to UUID...');

      await pool.query(`
        ALTER TABLE trending_topics
        ALTER COLUMN id DROP DEFAULT
      `);

      await pool.query(`
        ALTER TABLE trending_topics
        ALTER COLUMN id TYPE UUID
        USING gen_random_uuid()
      `);

      await pool.query(`
        ALTER TABLE trending_topics
        ALTER COLUMN id SET DEFAULT gen_random_uuid()
      `);

      console.log('✅ trending_topics.id converted to UUID.');
    } else {
      console.log('✅ trending_topics.id is already UUID.');
    }

    // ============================================================
    // ENSURE trending_topics.nvme_version_id IS UUID
    // ============================================================
    const versionIdType = await pool.query(`
      SELECT data_type
      FROM information_schema.columns
      WHERE table_name = 'trending_topics'
        AND column_name = 'nvme_version_id'
    `);

    if (
      versionIdType.rows.length > 0 &&
      versionIdType.rows[0].data_type !== 'uuid'
    ) {
      console.log('🔧 Converting trending_topics.nvme_version_id to UUID...');

      await pool.query(`
        ALTER TABLE trending_topics
        ALTER COLUMN nvme_version_id DROP DEFAULT
      `).catch(() => {});

      await pool.query(`
        ALTER TABLE trending_topics
        ALTER COLUMN nvme_version_id TYPE UUID
        USING NULL::UUID
      `);

      console.log('✅ trending_topics.nvme_version_id converted to UUID.');
    } else {
      console.log('✅ trending_topics.nvme_version_id is already UUID.');
    }

    // ============================================================
    // FINAL SCHEMA CHECK
    // ============================================================
    const result = await pool.query(`
      SELECT
        column_name,
        data_type,
        column_default
      FROM information_schema.columns
      WHERE table_name = 'trending_topics'
      ORDER BY ordinal_position
    `);

    console.log('');
    console.log('📊 Final trending_topics schema:');
    console.table(result.rows);

    console.log('');
    console.log('🎉 Database setup completed successfully.');

  } catch (err) {
    console.error('');
    console.error('❌ Database setup failed:', err.message);
    process.exitCode = 1;

  } finally {
    await pool.end();
  }
})();
