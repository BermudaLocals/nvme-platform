-- ════════════════════════════════════════════════════════════════════════
-- Migration 013: discovery layer (hashtags / sounds / duets / challenges)
-- Schema for the salvaged routes in nvme-tiktok-features.js, so mounting
-- that module does zero DB work at require-time. Every statement is
-- idempotent (IF NOT EXISTS) — safe to re-run. Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── VIDEOS: hashtag / sound / duet columns ───────────────────────────────
-- caption + hashtags normally come from create-tables.js (scraper flow);
-- repeated here so this migration is self-sufficient on a fresh database.
ALTER TABLE videos ADD COLUMN IF NOT EXISTS caption TEXT;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS hashtags TEXT[];
ALTER TABLE videos ADD COLUMN IF NOT EXISTS sound_id UUID;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS duet_of UUID;

CREATE INDEX IF NOT EXISTS idx_videos_tags_gin ON videos USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_videos_hashtags_gin ON videos USING GIN (hashtags);
CREATE INDEX IF NOT EXISTS idx_videos_sound_id ON videos(sound_id);
CREATE INDEX IF NOT EXISTS idx_videos_duet_of ON videos(duet_of);

-- ── SOUNDS (audio library) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sounds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  artist TEXT DEFAULT 'Unknown',
  url TEXT NOT NULL,
  cover_url TEXT,
  duration_sec INTEGER DEFAULT 30,
  use_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed the default library only where missing (same pattern as the gifts
-- seed in migration_002).
INSERT INTO sounds (name, artist, url)
SELECT * FROM (VALUES
  ('Empire Rise',   'Kush Beats',       ''::text),
  ('Island Vibes',  'Bermuda Sound',    ''::text),
  ('Money Moves',   'Empire HQ',        ''::text),
  ('AI Dreams',     'Kush AI',          ''::text),
  ('Crown Anthem',  'Dollar Double',    ''::text),
  ('Night Hustle',  'Empire Collective',''::text),
  ('Viral Energy',  'NVME Sounds',      ''::text),
  ('Creator Flow',  'Studio Mix',       ''::text)
) AS s(name, artist, url)
WHERE NOT EXISTS (SELECT 1 FROM sounds x WHERE x.name = s.name);

-- ── HASHTAG CHALLENGES ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hashtag_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tag TEXT UNIQUE NOT NULL,
  description TEXT,
  prize_coins INTEGER DEFAULT 0,
  starts_at TIMESTAMPTZ DEFAULT NOW(),
  ends_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
