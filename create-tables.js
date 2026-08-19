require('dotenv').config({ path: './src/backend/.env' });

const fs = require('fs');
const path = require('path');
const pool = require('./src/backend/db');

async function tableExists(client, tableName) {
  const result = await client.query(
    `
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = $1
      ) AS exists
    `,
    [tableName]
  );

  return result.rows[0].exists;
}

async function columnExists(client, tableName, columnName) {
  const result = await client.query(
    `
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = $1
          AND column_name = $2
      ) AS exists
    `,
    [tableName, columnName]
  );

  return result.rows[0].exists;
}

async function bootstrapBaseSchema(client) {
  const usersExists = await tableExists(client, 'users');
  const videosExists = await tableExists(client, 'videos');

  if (usersExists && videosExists) {
    console.log('Base schema already exists.');
    return;
  }

  const schemaPath = path.join(
    __dirname,
    'db',
    'schema.sql'
  );

  if (!fs.existsSync(schemaPath)) {
    throw new Error(
      `Base schema file not found: ${schemaPath}`
    );
  }

  if (!usersExists && !videosExists) {
    console.log('Base schema missing. Creating base schema...');

    const schemaSql = fs.readFileSync(
      schemaPath,
      'utf8'
    );

    await client.query(schemaSql);

    console.log('Base schema created.');
    return;
  }

  if (usersExists && !videosExists) {
    console.log(
      'Users table exists but videos table is missing. Repairing videos table...'
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS videos (
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
    `);

    console.log('Videos table repaired.');
    return;
  }

  if (!usersExists && videosExists) {
    throw new Error(
      'Database has videos but users is missing. Refusing automatic repair because videos.user_id depends on users.'
    );
  }
}

async function ensureTrendingSchema(client) {
  console.log('Setting up trending topics database...');

  await client.query(`
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

  console.log('trending_topics table ready.');

  const videosExists = await tableExists(
    client,
    'videos'
  );

  if (!videosExists) {
    throw new Error(
      'videos table does not exist after base-schema initialization.'
    );
  }

  await client.query(`
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

  console.log('videos trending columns ready.');

  const idType = await client.query(`
    SELECT data_type
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'trending_topics'
      AND column_name = 'id'
  `);

  if (
    idType.rows.length > 0 &&
    idType.rows[0].data_type !== 'uuid'
  ) {
    console.log(
      'Converting trending_topics.id to UUID...'
    );

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN id DROP DEFAULT
    `);

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN id TYPE UUID
      USING gen_random_uuid()
    `);

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN id SET DEFAULT gen_random_uuid()
    `);

    console.log(
      'trending_topics.id converted to UUID.'
    );
  } else {
    console.log(
      'trending_topics.id is already UUID.'
    );
  }

  const versionIdType = await client.query(`
    SELECT data_type
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'trending_topics'
      AND column_name = 'nvme_version_id'
  `);

  if (
    versionIdType.rows.length > 0 &&
    versionIdType.rows[0].data_type !== 'uuid'
  ) {
    console.log(
      'Converting trending_topics.nvme_version_id to UUID...'
    );

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN nvme_version_id DROP DEFAULT
    `).catch(() => {});

    await client.query(`
      ALTER TABLE trending_topics
      ALTER COLUMN nvme_version_id TYPE UUID
      USING NULL::UUID
    `);

    console.log(
      'trending_topics.nvme_version_id converted to UUID.'
    );
  } else {
    console.log(
      'trending_topics.nvme_version_id is already UUID.'
    );
  }
}

async function runMigrations(client) {
  const dbDir = path.join(__dirname, 'db');

  const files = fs
    .readdirSync(dbDir)
    .filter(function (file) {
      return /^migration_\d+.*\.sql$/.test(file);
    })
    .sort();

  if (files.length === 0) {
    console.log('No migrations found.');
    return;
  }

  for (const file of files) {
    const migrationPath = path.join(
      dbDir,
      file
    );

    console.log(`Running ${file}...`);

    const sql = fs.readFileSync(
      migrationPath,
      'utf8'
    );

    await client.query(sql);

    console.log(`${file} complete.`);
  }
}

async function verifySchema(client) {
  const requiredTables = [
    'users',
    'videos',
    'livestreams',
    'transactions',
    'gifts',
    'stream_battles',
    'battle_participants',
    'trending_topics',
    'feed_events'
  ];

  const missing = [];

  for (const table of requiredTables) {
    const exists = await tableExists(
      client,
      table
    );

    if (!exists) {
      missing.push(table);
    }
  }

  if (missing.length > 0) {
    throw new Error(
      `Required tables missing: ${missing.join(', ')}`
    );
  }

  const requiredVideoColumns = [
    'id',
    'user_id',
    'video_url',
    'caption',
    'hashtags',
    'source_type',
    'score',
    'is_trending'
  ];

  const missingVideoColumns = [];

  for (const column of requiredVideoColumns) {
    const exists = await columnExists(
      client,
      'videos',
      column
    );

    if (!exists) {
      missingVideoColumns.push(column);
    }
  }

  if (missingVideoColumns.length > 0) {
    throw new Error(
      `Required videos columns missing: ${missingVideoColumns.join(', ')}`
    );
  }

  console.log('Required database schema verified.');
}

async function printTrendingSchema(client) {
  const result = await client.query(`
    SELECT
      column_name,
      data_type,
      column_default
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'trending_topics'
    ORDER BY ordinal_position
  `);

  console.log('');
  console.log(
    'Final trending_topics schema:'
  );
  console.table(result.rows);
}

async function main() {
  const client = await pool.connect();

  try {
    console.log(
      'NVME database bootstrap starting...'
    );

    await client.query('BEGIN');

    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    `);

    await bootstrapBaseSchema(client);

    await ensureTrendingSchema(client);

    await runMigrations(client);

    await verifySchema(client);

    await printTrendingSchema(client);

    await client.query('COMMIT');

    console.log('');
    console.log(
      'Database setup completed successfully.'
    );
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});

    console.error('');
    console.error(
      'Database setup failed:',
      error.message
    );

    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main();
