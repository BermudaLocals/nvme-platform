-- ════════════════════════════════════════════════════════════════════════
-- Migration 011: ads — in-feed sponsored placements.
-- An ad either promotes an existing platform video (video_id) or carries an
-- external creative (video_url / image_url); at least one creative source is
-- required (CHECK). impressions/clicks are fire-and-forget counters bumped
-- by POST /api/ads/:id/impression|click; the feed query in getRankedFeed
-- reads (is_active, priority) via the index below.
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
  image_url TEXT,
  video_url TEXT,
  title TEXT,
  link_url TEXT,
  link_text TEXT DEFAULT 'Learn more',
  advertiser TEXT,
  priority INT DEFAULT 1,
  is_active BOOLEAN DEFAULT TRUE,
  impressions BIGINT DEFAULT 0,
  clicks BIGINT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT ads_creative_required CHECK (
    video_id IS NOT NULL
    OR video_url IS NOT NULL
    OR image_url IS NOT NULL
  )
);

-- Feed injection reads active ads ordered by priority.
CREATE INDEX IF NOT EXISTS idx_ads_active_priority ON ads(is_active, priority);
