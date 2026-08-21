-- ════════════════════════════════════════════════════════════════════════
-- Migration 007: 1:1 direct messaging + blocks/mutes — tables queried by
-- server.js (/api/dm/* routes, dm_send/dm_read socket handlers,
-- /api/users/:userId/block|mute, /api/feed block filter) but never created
-- anywhere, so those routes/handlers 500.
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── DM CONVERSATIONS (strictly 1:1; the pair is in dm_participants) ──────
CREATE TABLE IF NOT EXISTS dm_conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_message_at TIMESTAMPTZ
);

-- ── DM PARTICIPANTS (last_read_at drives the unread badge) ───────────────
CREATE TABLE IF NOT EXISTS dm_participants (
  conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  last_read_at TIMESTAMPTZ,
  UNIQUE (conversation_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_dm_participants_user ON dm_participants(user_id);

-- ── DM MESSAGES (read_at NULL = unread; powers the ✓✓ read ticks) ────────
CREATE TABLE IF NOT EXISTS dm_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
  sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  media_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  read_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dm_messages_conversation ON dm_messages(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_dm_messages_sender ON dm_messages(sender_id);

-- ── BLOCKS (either direction kills DM creation/sending and hides the
-- blocked user's videos from the blocker's /api/feed) ─────────────────────
CREATE TABLE IF NOT EXISTS blocks (
  blocker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id != blocked_id)
);
CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);

-- ── MUTES (storage only for now; feed filtering is a later pass) ─────────
CREATE TABLE IF NOT EXISTS mutes (
  muter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  muted_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (muter_id, muted_id),
  CHECK (muter_id != muted_id)
);
CREATE INDEX IF NOT EXISTS idx_mutes_muted ON mutes(muted_id);
