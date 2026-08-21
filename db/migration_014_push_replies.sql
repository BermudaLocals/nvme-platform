-- ════════════════════════════════════════════════════════════════════════
-- Migration 014: web push subscriptions + comment replies
-- push_subscriptions backs the /api/push/* routes; comments.parent_id
-- enables one-level-deep (TikTok-style) replies. Every statement is
-- idempotent (IF NOT EXISTS) — safe to re-run. Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── PUSH SUBSCRIPTIONS ───────────────────────────────────────────────────
-- One row per browser endpoint; a user can have several (phone + desktop).
-- Endpoint is globally unique, so re-subscribing upserts by endpoint.

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint TEXT UNIQUE NOT NULL,
  keys JSONB NOT NULL,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);

-- ── COMMENT REPLIES ──────────────────────────────────────────────────────
-- NULL = top-level comment. Replies point at their parent comment and
-- cascade away with it. One level deep is enforced by the API (a reply's
-- parent must itself be top-level).

ALTER TABLE comments ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES comments(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id) WHERE parent_id IS NOT NULL;
