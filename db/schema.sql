CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name VARCHAR(100),
  avatar_url TEXT,
  bio TEXT,
  is_creator BOOLEAN DEFAULT FALSE,
  is_verified BOOLEAN DEFAULT FALSE,
  is_banned BOOLEAN DEFAULT FALSE,
  balance_credits NUMERIC(12,2) DEFAULT 0.00,
  total_earned NUMERIC(12,2) DEFAULT 0.00,
  paypal_email VARCHAR(255),
  follower_count INTEGER DEFAULT 0,
  following_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE videos (
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

CREATE TABLE livestreams (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  stream_key TEXT UNIQUE NOT NULL,
  playback_url TEXT,
  thumbnail_url TEXT,
  status VARCHAR(20) DEFAULT 'offline' CHECK (status IN ('offline','live','ended')),
  viewer_count INTEGER DEFAULT 0,
  peak_viewer_count INTEGER DEFAULT 0,
  total_gifts_received NUMERIC(12,2) DEFAULT 0.00,
  is_premium BOOLEAN DEFAULT FALSE,
  price_credits NUMERIC(10,2) DEFAULT 0.00,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Backward-compat view for any external tools referencing live_streams
CREATE OR REPLACE VIEW live_streams AS SELECT * FROM livestreams;

CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  subscriber_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tier VARCHAR(50) DEFAULT 'basic',
  price_usd NUMERIC(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active','cancelled','expired','paused')),
  paypal_subscription_id VARCHAR(255) UNIQUE,
  current_period_start TIMESTAMPTZ NOT NULL,
  current_period_end TIMESTAMPTZ NOT NULL,
  cancelled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(subscriber_id, creator_id)
);

CREATE TABLE transactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL CHECK (type IN ('credit_purchase','gift_sent','gift_received','subscription','withdrawal','refund','tip')),
  amount_usd NUMERIC(10,2) NOT NULL,
  credits_amount NUMERIC(10,2),
  status VARCHAR(20) DEFAULT 'completed',
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE gifts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  emoji VARCHAR(20),
  icon_url TEXT,
  credit_cost NUMERIC(10,2) NOT NULL,
  usd_value NUMERIC(10,2) NOT NULL,
  creator_pct NUMERIC(5,2) DEFAULT 70.00,
  platform_pct NUMERIC(5,2) DEFAULT 30.00,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE stream_guests (
  id SERIAL PRIMARY KEY,
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  guest_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guest_username VARCHAR(100),
  guest_avatar TEXT,
  status VARCHAR(20) DEFAULT 'invited',
  slot INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(stream_id, guest_user_id)
);

CREATE TABLE livestream_chat (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE jackpot_pool (
  id INTEGER PRIMARY KEY DEFAULT 1,
  pool NUMERIC(12,2) DEFAULT 25000,
  total_entries INTEGER DEFAULT 0,
  total_paid NUMERIC(12,2) DEFAULT 0,
  last_winner_username VARCHAR(100),
  last_won_at TIMESTAMPTZ
);


-- ── BATTLE SYSTEM ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS stream_battles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  host_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  battle_type VARCHAR(20) DEFAULT 'ffa' CHECK (battle_type IN ('ffa','team')),
  status VARCHAR(20) DEFAULT 'waiting' CHECK (status IN ('waiting','active','ended')),
  max_participants INTEGER DEFAULT 20,
  team_a_name VARCHAR(50) DEFAULT 'Team A',
  team_b_name VARCHAR(50) DEFAULT 'Team B',
  elimination_interval_seconds INTEGER DEFAULT 60,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  winner_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS battle_participants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  battle_id UUID NOT NULL REFERENCES stream_battles(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team VARCHAR(10) DEFAULT 'a' CHECK (team IN ('a','b')),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active','eliminated','winner')),
  gifts_received NUMERIC(12,2) DEFAULT 0,
  votes INTEGER DEFAULT 0,
  eliminated_at TIMESTAMPTZ,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(battle_id, user_id)
);

-- ── PRIVACY ─────────────────────────────────────────────────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT FALSE;

-- ── EPIC STUDIOS TRANSFER ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS epic_transfers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epic_username VARCHAR(100) NOT NULL,
  epic_diamonds INTEGER DEFAULT 0,
  epic_level INTEGER DEFAULT 1,
  diamonds_converted NUMERIC(12,2) DEFAULT 0,
  transfer_status VARCHAR(20) DEFAULT 'pending' CHECK (transfer_status IN ('pending','completed','failed')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── FOUNDER BADGES & LEVELS ─────────────────────────────────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS join_rank INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS founder_badge VARCHAR(20);
ALTER TABLE users ADD COLUMN IF NOT EXISTS level INTEGER DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS diamond_balance NUMERIC(12,2) DEFAULT 0;

-- Auto-assign founder badges to first 100/1000 users (silent, no error if already set)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE join_rank IS NULL LIMIT 1) THEN
    UPDATE users SET 
      join_rank = sub.rank,
      founder_badge = CASE 
        WHEN sub.rank <= 100 THEN 'founder-100'
        WHEN sub.rank <= 1000 THEN 'founder-1000'
        ELSE NULL
      END
    FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) as rank FROM users) sub
    WHERE users.id = sub.id AND users.join_rank IS NULL;
  END IF;
END $$;

-- ── BATTLE INVITES (live user → live user) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS battle_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_stream_id UUID NOT NULL REFERENCES livestreams(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending','accepted','declined','expired')),
  battle_id UUID REFERENCES stream_battles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  responded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_battle_invites_to_user ON battle_invites(to_user_id, status);
CREATE INDEX IF NOT EXISTS idx_battle_invites_from_user ON battle_invites(from_user_id, status);

