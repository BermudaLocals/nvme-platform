-- ════════════════════════════════════════════════════════════════════════
-- Migration 015: artist song uploads (Sounds)
-- Heals/extends the sounds table from migration_013 so it can hold real
-- uploaded audio: a Cloudinary audio_url, uploader identity, visibility
-- flag and the newer usage_count/duration_seconds columns the upload
-- flow writes. 013 already created artist + cover_url, so only the
-- missing columns are added. Every statement is idempotent
-- (IF NOT EXISTS) — safe to re-run. Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

-- ── SOUNDS: upload columns ───────────────────────────────────────────────
ALTER TABLE sounds ADD COLUMN IF NOT EXISTS audio_url TEXT;
ALTER TABLE sounds ADD COLUMN IF NOT EXISTS duration_seconds INT;
ALTER TABLE sounds ADD COLUMN IF NOT EXISTS usage_count INT DEFAULT 0;
ALTER TABLE sounds ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT TRUE;
ALTER TABLE sounds ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);

-- ── Backfill from the 013 columns (one-time heal, safe to re-run) ───────
-- url was the original audio pointer; usage_count supersedes use_count.
UPDATE sounds SET audio_url = url
WHERE audio_url IS NULL AND url IS NOT NULL AND url <> '';

UPDATE sounds SET usage_count = use_count
WHERE use_count IS NOT NULL AND use_count > 0 AND COALESCE(usage_count, 0) = 0;

CREATE INDEX IF NOT EXISTS idx_sounds_user_id ON sounds(user_id);
