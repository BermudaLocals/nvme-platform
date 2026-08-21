-- videos.is_trending is otherwise only added by create-tables.js — make this
-- migration self-sufficient on a fresh database.
ALTER TABLE videos ADD COLUMN IF NOT EXISTS is_trending BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS feed_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT,
  event_type TEXT NOT NULL,
  video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
  watch_ms BIGINT,
  duration_ms BIGINT,
  position_ms BIGINT,
  completion_rate NUMERIC(6,5),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feed_events_user_created
ON feed_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_feed_events_user_video
ON feed_events(user_id, video_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_feed_events_video_created
ON feed_events(video_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_feed_events_type_created
ON feed_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_videos_feed_published
ON videos(is_published, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_videos_feed_trending
ON videos(is_trending, created_at DESC)
WHERE is_trending = true;

CREATE INDEX IF NOT EXISTS idx_videos_feed_user
ON videos(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_videos_feed_tags
ON videos USING GIN(tags);
