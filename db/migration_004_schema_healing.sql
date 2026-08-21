-- ════════════════════════════════════════════════════════════════════════
-- Migration 004: schema drift healing
-- Twice now the live database has been missing columns that db/schema.sql
-- claims exist (gift_transactions.to_user_id from an earlier partial run,
-- gifts.emoji from real drift). Rather than keep discovering these one at a
-- time, this ensures every optional/counter column server.js queries on
-- users, videos, livestreams, and transactions actually exists — using
-- ADD COLUMN IF NOT EXISTS, which is a no-op wherever the column is already
-- correct. Core required columns (username, email, video_url, etc.) are
-- deliberately left alone — if those are missing, the table is
-- fundamentally different and needs a human to look, not an auto-heal.
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════

-- users
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_creator BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_credits NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS total_earned NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_email VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS follower_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS following_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_link TEXT;

-- videos
ALTER TABLE videos ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS like_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS comment_count INTEGER DEFAULT 0;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_published BOOLEAN DEFAULT FALSE;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS price_credits NUMERIC(10,2) DEFAULT 0.00;
ALTER TABLE videos ADD COLUMN IF NOT EXISTS tags TEXT[];
ALTER TABLE videos ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- livestreams
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS playback_url TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'offline';
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS viewer_count INTEGER DEFAULT 0;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS peak_viewer_count INTEGER DEFAULT 0;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS total_gifts_received NUMERIC(12,2) DEFAULT 0.00;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS price_credits NUMERIC(10,2) DEFAULT 0.00;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS ended_at TIMESTAMPTZ;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- transactions
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS credits_amount NUMERIC(10,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT;
