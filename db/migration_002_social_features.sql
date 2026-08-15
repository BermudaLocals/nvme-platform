-- ════════════════════════════════════════════════════════════════════════
-- Migration 002: social features + auth fields the frontend already expects
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS / WHERE NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── USERNAME (both frontends require it; base schema only has display_name) ──
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(255);

-- Backfill any existing rows that predate the column, so the UNIQUE constraint
-- doesn't choke on NULLs colliding (Postgres allows multiple NULLs under
-- UNIQUE, so this is only a courtesy backfill, not strictly required).
UPDATE users SET username = 'user_' || substr(id::text, 1, 8)
WHERE username IS NULL;

-- ── LIKES ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (video_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_video ON likes(video_id);
CREATE INDEX IF NOT EXISTS idx_likes_user ON likes(user_id);

-- ── COMMENTS (schema only ever had a comment_count counter, no rows) ───────
CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  image_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id, created_at DESC);

-- ── FOLLOWS (simple free follow; `subscriptions` table is paid-tier only) ──
CREATE TABLE IF NOT EXISTS follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (follower_id, following_id),
  CHECK (follower_id != following_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);

-- ── GIFT TRANSACTIONS (schema's `gifts` table is a catalog of gift TYPES —
-- there was never a table logging who-sent-what-to-whom) ───────────────────
-- DROP + recreate rather than IF NOT EXISTS: an earlier partial run left a
-- gift_transactions table missing the to_user_id column, which then made
-- CREATE TABLE IF NOT EXISTS silently skip it and broke the index below.
-- Nothing could have written real rows here yet (the only writer,
-- /api/gifts/send, would 500 without to_user_id), so dropping is safe.
DROP TABLE IF EXISTS gift_transactions CASCADE;
CREATE TABLE gift_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gift_id UUID NOT NULL REFERENCES gifts(id),
  stream_id UUID REFERENCES livestreams(id) ON DELETE SET NULL,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  quantity INTEGER DEFAULT 1,
  credits_spent NUMERIC(12,2) NOT NULL,
  creator_credits NUMERIC(12,2) NOT NULL,
  platform_credits NUMERIC(12,2) NOT NULL,
  message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gift_tx_stream ON gift_transactions(stream_id);
CREATE INDEX IF NOT EXISTS idx_gift_tx_to_user ON gift_transactions(to_user_id);

-- ── SEED DEFAULT GIFT CATALOG (matches the values server.js used to
-- hardcode: crown/rocket/heart/star/diamond) — only inserts if missing ─────
INSERT INTO gifts (name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
SELECT * FROM (VALUES
  ('Heart',   '❤️', 10::numeric,  10::numeric, 70::numeric, 30::numeric),
  ('Star',    '⭐', 5::numeric,   5::numeric,  70::numeric, 30::numeric),
  ('Crown',   '👑', 50::numeric,  50::numeric, 70::numeric, 30::numeric),
  ('Rocket',  '🚀', 100::numeric, 100::numeric,70::numeric, 30::numeric),
  ('Diamond', '💎', 200::numeric, 200::numeric,70::numeric, 30::numeric)
) AS v(name, emoji, credit_cost, usd_value, creator_pct, platform_pct)
WHERE NOT EXISTS (SELECT 1 FROM gifts g WHERE g.name = v.name);
