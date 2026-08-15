-- ════════════════════════════════════════════════════════════════════════
-- Migration 003: LIVE Battles + stream goals support
-- creator.html (Creator Studio) calls a battles/goals API that the base
-- schema's stream_battles/battle_participants/battle_invites tables don't
-- quite cover yet. Safe to re-run — idempotent.
-- Run with: npm run migrate:003  (see updated scripts/migrate.js)
-- ════════════════════════════════════════════════════════════════════════

-- ── STREAM GOALS (creator.html's "Set Goal" panel — target/reward/current
-- gift progress toward a stream milestone) ─────────────────────────────────
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_target NUMERIC(12,2);
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_reward TEXT;
ALTER TABLE livestreams ADD COLUMN IF NOT EXISTS goal_current NUMERIC(12,2) DEFAULT 0;

-- ── BATTLE PARTICIPANT BACKGROUNDS (creator.html lets a battler upload a
-- custom background image mid-battle, stored as a data URL) ────────────────
ALTER TABLE battle_participants ADD COLUMN IF NOT EXISTS background_url TEXT;

-- ── BATTLE ATTACK LOG (creator.html's gift-based "attack" mechanic — needs
-- its own log since it deducts credits and deals damage, distinct from a
-- normal gift_transactions row) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS battle_attacks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  battle_id UUID NOT NULL REFERENCES stream_battles(id) ON DELETE CASCADE,
  attacker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_participant_id UUID NOT NULL REFERENCES battle_participants(id) ON DELETE CASCADE,
  gift_type VARCHAR(50),
  cost NUMERIC(12,2) NOT NULL,
  damage INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_battle_attacks_battle ON battle_attacks(battle_id);
