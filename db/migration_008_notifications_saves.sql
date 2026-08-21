-- ════════════════════════════════════════════════════════════════════════
-- Migration 008: notifications + saves — tables queried by server.js
-- (GET/POST /api/notifications*, createNotification() fan-out from the
-- like/comment/follow/gift routes, POST /api/videos/:id/save,
-- GET /api/users/me/saves, is_saved in /api/feed) but never created
-- anywhere, so those routes 500.
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── NOTIFICATIONS (read_at NULL = unread; powers the bell badge) ─────────
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(30) NOT NULL,
  video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
  comment_id UUID REFERENCES comments(id) ON DELETE CASCADE,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── HEAL legacy/drifted notifications tables ─────────────────────────────
-- An older experiment created notifications with a different shape
-- (title/message/data/is_read) on some databases; add the columns the code
-- uses so both shapes converge.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS actor_id UUID;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS video_id UUID;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS comment_id UUID;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications(user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_notifications_actor ON notifications(actor_id);

-- ── SAVES (bookmarked videos; save_count on videos stays the denormalized
-- counter, maintained by the save toggle route / save feed events) ────────
CREATE TABLE IF NOT EXISTS saves (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, video_id)
);
CREATE INDEX IF NOT EXISTS idx_saves_video ON saves(video_id);
