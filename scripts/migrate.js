// ========================================
// 🗄️ NVME.live — DB Migration
// Runs db/schema.sql (base schema) first, then every db/migration_*.sql
// file, in filename order. Idempotent — safe
// to re-run; already-applied files just no-op on their IF NOT EXISTS checks.
// Run with: npm run migrate
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
  const dbDir = path.join(__dirname, '..', 'db');
  const files = fs.readdirSync(dbDir)
    .filter(f => /^migration_\d+.*\.sql$/.test(f))
    .sort();

  // Base schema first — the numbered migrations ALTER tables it creates,
  // so a fresh database fails without it. Idempotent (IF NOT EXISTS).
  if (fs.existsSync(path.join(dbDir, 'schema.sql'))) {
    files.unshift('schema.sql');
  }

  if (files.length === 0) {
    console.log('No migration_*.sql files found in db/.');
    return;
  }

  const client = await pool.connect();
  try {
    for (const file of files) {
      console.log(`🗄️  Running ${file}...`);
      const sql = fs.readFileSync(path.join(dbDir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('COMMIT');
        console.log(`✅ ${file} complete.`);
      } catch (err) {
        await client.query('ROLLBACK');
        console.error(`❌ ${file} failed, rolled back:`, err.message);
        process.exitCode = 1;
        break;
      }
    }
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
