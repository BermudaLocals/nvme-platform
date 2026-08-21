# Production Certification — NVME.live

Runbook for certifying a deployed instance against the owner's "DONE"
definition: a real person can register → verify email → login → OAuth →
profile → upload → publish → feed → like → comment → follow → DM →
notifications → trending → wallet → admin.

The automated half is `scripts/production-cert.js` (zero-dependency,
Node ≥ 18). The rest is a short manual checklist. Both are below.

---

## 1. Pre-deploy checklist

Run from the repo root:

- [ ] `npm install`
- [ ] `npm run migrate` — applies `db/schema.sql` plus every
      `db/migration_*.sql` in filename order (idempotent, safe to re-run).
      The upgrade adds migrations **006–010**
      (`006_follow_requests`, `007_messaging_blocks`,
      `008_notifications_saves`, `009_auth_hardening`, `010_payouts`).
- [ ] Required environment variables:
  - `DATABASE_URL` — Postgres connection string.
  - `JWT_SECRET` — signs/verifies access tokens. **No fallback**: if it is
    unset, every authenticated request fails.
  - `SESSION_SECRET` — session signing. Falls back to
    `${JWT_SECRET}:session` if unset; set it explicitly in production.
  - `PAYPAL_MODE` (`sandbox` or `live`), `PAYPAL_CLIENT_ID`,
    `PAYPAL_CLIENT_SECRET` — wallet top-ups / payouts.
  - `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`,
    `CLOUDINARY_API_SECRET` — video uploads fail without these.
  - Optional: `SMTP_URL` (or `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` /
    `SMTP_PASS`). Without a mail provider, verification/reset emails are
    only logged, and register/resend-verification echo a
    `devVerificationUrl` when `NODE_ENV !== 'production'`.
  - Optional: `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — without them,
    `/auth/google` responds 503 JSON by design.
  - `FRONTEND_URL` — used in email links and OAuth/verify redirects.
- [ ] **Rotate the previously-hardcoded Alchemy API key.**
      `modules/crypto-wallet.js` now refuses to load without the
      `ALCHEMY_API_KEY` env var (no hardcoded fallback). Generate a fresh
      key at alchemy.com, set `ALCHEMY_API_KEY`, and treat the old key as
      compromised.
- [ ] Grant the first admin by SQL (no UI/bootstrap route exists):
      ```sql
      UPDATE users SET is_admin = true WHERE email = 'you@example.com';
      ```
- [ ] PayPal **Payouts** must be approved on the PayPal app before live
      withdrawals work (sandbox works without approval). Until then, use
      `PAYPAL_MODE=sandbox` or expect withdrawal approval to fail at the
      payout call.

## 2. Running the certification

Against a local server (default `http://localhost:3000`):

```bash
npm run cert
```

Against a deployed instance — **read-only first** (creates nothing,
safe for production):

```bash
node scripts/production-cert.js --base-url https://nvme.live
```

Then the full end-to-end matrix (creates two throwaway users
`cert_<timestamp>_a/b@test.invalid` and drives the real flows):

```bash
node scripts/production-cert.js --base-url https://nvme.live --full
```

`BASE_URL` env works too: `BASE_URL=https://nvme.live npm run cert`.

What the full run covers: register ×2 → email verify (via the
`devVerificationUrl` returned outside production — against a
`NODE_ENV=production` deploy this one check skips itself) → login →
`/me` → refresh-token rotation (old token reuse must 401) → follow A→B →
search → following feed → like toggle → comment → comment delete →
save + saved list → DM conversation + history → notifications (B gets
the follow) → mark read → wallet balance/transactions → admin 403 →
logout + revoked-refresh-token reuse must 401.

Exit code: `0` when everything that ran passed, `1` on any FAIL.
⚠️ means skipped (e.g. empty feed → "no content to test against").

Notes:

- Likes/saves/comments the full run makes on existing videos are
  reverted (unlike / unsave / delete-comment), so existing counters end
  unchanged. The follow A→B and the DM conversation are between the two
  cert users only.
- Cert users are **not** deleted afterwards (there is no delete-account
  API). Remove them with:
  ```sql
  DELETE FROM users WHERE email LIKE 'cert_%@test.invalid';
  ```
- The API is rate-limited to 200 requests/IP per 15 min
  (`server.js` global `/api` limiter). A read-only run costs ~19
  requests, a full run ~50 — don't loop full runs back-to-back or you
  will start seeing 429s.

## 3. Manual-only checks

The script deliberately does not touch Socket.IO or real uploads. Verify
these by hand before calling the release done:

- [ ] **Google OAuth round-trip in a browser** — `/auth/google` →
      Google consent → callback → lands in `/app` logged in (the cert
      only proves the route is mounted).
- [ ] **Video upload via the UI** — pick a real file, watch the progress
      bar, confirm it publishes and appears in the feed (Cloudinary env
      required).
- [ ] **DM realtime** — two browsers, two accounts: `dm_send` delivery,
      typing indicator, read receipts, and the video call flow. (REST
      only creates conversations and reads history; sending is
      socket-only.)
- [ ] **Live stream + gifts** — go live, send a gift, confirm the
      leaderboard/balance movement.
- [ ] **Notification bell in the Next UI** — badge increments on
      follow/like, clears on open.
- [ ] **PayPal sandbox purchase** — create-order → capture-order →
      credits land in `/api/wallet/balance`.
- [ ] **Withdrawal approval in admin** — request a withdrawal, approve
      it in the admin panel, confirm the payout executes (sandbox).

## 4. Rollback note

Everything in the working tree is currently **uncommitted**
(`git status` shows modifications across `server.js`, `db/`, `public/`,
`frontend/`, `modules/`, `package.json`, …). There is no committed
checkpoint to roll back to.

**Commit before deploying.** Once committed, rollback is:

```bash
git revert <deployed-commit>   # or: git reset --hard <previous-commit>
```

plus re-running `npm run migrate` only if the rollback spans schema
changes (migrations are additive; roll forward with a corrective
migration rather than hand-editing the DB).
