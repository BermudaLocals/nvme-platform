-- ════════════════════════════════════════════════════════════════════════
-- Migration 010: payouts — PayPal Payouts support for creator withdrawals.
-- transactions gains payout_batch_id so an admin-approved withdrawal can be
-- correlated with its PayPal payout batch. The (type, status) index backs
-- the admin withdrawals queue (GET /api/admin/withdrawals).
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE transactions ADD COLUMN IF NOT EXISTS payout_batch_id TEXT;

-- ── HEAL legacy/drifted transactions tables ──────────────────────────────
-- Some databases carry an older payments table named `transactions` (from a
-- different product) that lacks the columns NVME's money code writes. Add
-- the NVME columns so gift/purchase/withdrawal inserts can't 500. Nullable
-- on purpose — healing, not redesigning, the legacy shape.
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS user_id UUID;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS type VARCHAR(50);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS amount_usd NUMERIC(10,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS credits_amount NUMERIC(10,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_transactions_withdrawals ON transactions(type, status);
