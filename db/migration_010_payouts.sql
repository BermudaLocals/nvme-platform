-- ════════════════════════════════════════════════════════════════════════
-- Migration 010: payouts — PayPal Payouts support for creator withdrawals.
-- transactions gains payout_batch_id so an admin-approved withdrawal can be
-- correlated with its PayPal payout batch. The (type, status) index backs
-- the admin withdrawals queue (GET /api/admin/withdrawals).
-- Safe to re-run — every statement is idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE transactions ADD COLUMN IF NOT EXISTS payout_batch_id TEXT;

CREATE INDEX IF NOT EXISTS idx_transactions_withdrawals ON transactions(type, status);
