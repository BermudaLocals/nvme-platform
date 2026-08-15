// ========================================
// 🗄️ NVME.live — DB Migration
// Runs db/migration_002_social_features.sql against DATABASE_URL.
// Idempotent — safe to re-run. Run with: npm run migrate
// ========================================

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  const sqlPath = path.join(__dirname, '..', 'db', 'migration_002_social_features.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');
  const client = await pool.connect();

  console.log('🗄️  Running migration_002_social_features.sql...');
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('COMMIT');
    console.log('✅ Migration complete.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Migration failed, rolled back:', err.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
