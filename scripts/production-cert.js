#!/usr/bin/env node
// ========================================
// ✅ NVME.live — Production Certification
// ========================================
// Zero-dependency certification runner
// (Node >= 18, global fetch). Hits the real
// HTTP API of a deployed instance and
// prints a pass/fail/skip matrix.
//
// Usage:
//   node scripts/production-cert.js
//   node scripts/production-cert.js --base-url https://nvme.live
//   node scripts/production-cert.js --full
//
// Modes:
//   default   read-only — never creates or
//             mutates anything. Safe against
//             production.
//   --full    creates two throwaway cert
//             users (cert_<ts>_a/b@test.invalid)
//             and exercises the real flows:
//             register, verify, login, refresh,
//             follow, like, comment, save, DM,
//             notifications, wallet, admin-403,
//             logout/revocation. Likes/saves/
//             comments on existing videos are
//             reverted (unlike/unsave/delete);
//             the cert users themselves remain
//             in the DB (no delete-account API)
//             and can be removed by SQL.
//
// Out of scope (manual checks):
//   Socket.IO realtime (dm_send / typing /
//   calls / live gifts) and real multipart
//   video upload.
// ========================================

'use strict';

// ---------- args / config ----------

const argv = process.argv.slice(2);

function argValue(flag) {
  const i = argv.indexOf(flag);
  return i !== -1 ? argv[i + 1] : undefined;
}

const BASE_URL = (
  argValue('--base-url') ||
  process.env.BASE_URL ||
  'http://localhost:3000'
).replace(/\/+$/, '');

const FULL = argv.includes('--full');

const REQUEST_TIMEOUT_MS = 15000;

// ---------- output ----------

const useColor =
  process.stdout.isTTY && !process.env.NO_COLOR;

const paint = (code, s) =>
  useColor ? `\x1b[${code}m${s}\x1b[0m` : s;

const green = s => paint(32, s);
const red = s => paint(31, s);
const yellow = s => paint(33, s);
const bold = s => paint(1, s);

const ICON = {
  pass: green('✅'),
  fail: red('❌'),
  skip: yellow('⚠️')
};

// ---------- check framework ----------

const results = [];

class Skip extends Error {}

function skip(note) {
  throw new Skip(note);
}

async function check(group, name, fn) {
  try {
    const note = await fn();
    results.push({
      group,
      name,
      status: 'pass',
      note: note || ''
    });
  } catch (err) {
    if (err instanceof Skip) {
      results.push({
        group,
        name,
        status: 'skip',
        note: err.message
      });
    } else {
      results.push({
        group,
        name,
        status: 'fail',
        note: err.message
      });
    }
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function assertStatus(res, expected, what) {
  const ok = Array.isArray(expected)
    ? expected.includes(res.status)
    : res.status === expected;

  assert(
    ok,
    `${what}: expected HTTP ${
      Array.isArray(expected)
        ? expected.join('/')
        : expected
    }, got ${res.status}` +
      (res.text
        ? ` — ${res.text.slice(0, 140)}`
        : '')
  );
}

const sleep = ms =>
  new Promise(r => setTimeout(r, ms));

// ---------- HTTP helper ----------

async function api(method, path, opts = {}) {
  const { token, body } = opts;

  const ctrl = new AbortController();
  const timer = setTimeout(
    () => ctrl.abort(),
    REQUEST_TIMEOUT_MS
  );

  try {
    const res = await fetch(BASE_URL + path, {
      method,
      redirect: 'manual',
      signal: ctrl.signal,
      headers: {
        ...(body !== undefined
          ? { 'Content-Type': 'application/json' }
          : {}),
        ...(token
          ? { Authorization: `Bearer ${token}` }
          : {})
      },
      body:
        body !== undefined
          ? JSON.stringify(body)
          : undefined
    });

    const text = await res.text();

    let json = null;
    try {
      json = JSON.parse(text);
    } catch (_) {
      /* HTML / empty body */
    }

    return {
      status: res.status,
      json,
      text,
      headers: res.headers
    };
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(
        `${method} ${path}: timed out after ${REQUEST_TIMEOUT_MS}ms`
      );
    }
    throw new Error(
      `${method} ${path}: ${err.message} (is the server up at ${BASE_URL}?)`
    );
  } finally {
    clearTimeout(timer);
  }
}

// Expect an authenticated route to reject a
// request that carries no token. Server
// behavior (authenticateToken,
// server.js:920): missing token -> 401.
async function expectUnauthorized(
  group,
  name,
  method,
  path
) {
  await check(group, name, async () => {
    const r = await api(method, path);
    assert(
      r.status === 401,
      `expected 401 without token, got ${r.status}`
    );
  });
}

// ========================================
// READ-ONLY CHECKS (both modes)
// ========================================

async function readOnlyChecks() {
  // ---------- Health ----------

  await check(
    'Health',
    'GET /health responds healthy',
    async () => {
      const r = await api('GET', '/health');
      assertStatus(r, 200, 'health');
      assert(
        r.json && r.json.status === 'healthy',
        `status is "${r.json && r.json.status}", expected "healthy"`
      );
    }
  );

  await check(
    'Health',
    'GET /api/health reports database connected',
    async () => {
      const r = await api('GET', '/api/health');
      assertStatus(r, 200, 'api health');
      assert(
        r.json && r.json.database === 'connected',
        `database is "${r.json && r.json.database}", expected "connected" (DATABASE_URL / migrations OK?)`
      );
    }
  );

  // ---------- Trending ----------

  await check(
    'Trending',
    'GET /api/trending returns a trend list',
    async () => {
      const r = await api('GET', '/api/trending');
      assertStatus(r, 200, 'trending');
      assert(
        r.json && Array.isArray(r.json.trends),
        'response has no trends[] array'
      );
      return `${r.json.trends.length} active trends`;
    }
  );

  // ---------- Social (anonymous) ----------

  await check(
    'Social',
    'GET /api/feed works anonymously',
    async () => {
      const r = await api('GET', '/api/feed');
      assertStatus(r, 200, 'feed');
      assert(
        r.json && Array.isArray(r.json.feed),
        'response has no feed[] array'
      );
      return `${r.json.feed.length} items, algorithm=${r.json.algorithm}`;
    }
  );

  await check(
    'Social',
    'GET /api/search?q= returns users+videos',
    async () => {
      const r = await api(
        'GET',
        '/api/search?q=a'
      );
      assertStatus(r, 200, 'search');
      assert(
        r.json &&
          Array.isArray(r.json.users) &&
          Array.isArray(r.json.videos),
        'response lacks users[]/videos[] arrays'
      );
    }
  );

  // ---------- Sounds ----------

  await check(
    'Sounds',
    'GET /api/sounds returns a sound list',
    async () => {
      const r = await api('GET', '/api/sounds');
      assertStatus(r, 200, 'sounds');
      assert(
        r.json && Array.isArray(r.json.sounds),
        'response has no sounds[] array'
      );
      return `${r.json.sounds.length} sounds`;
    }
  );

  await expectUnauthorized(
    'Sounds',
    'POST /api/sounds/upload without token -> 401',
    'POST',
    '/api/sounds/upload'
  );

  // ---------- Security ----------

  await check(
    'Security',
    'Login with wrong password is rejected (401)',
    async () => {
      const r = await api(
        'POST',
        '/api/auth/login',
        {
          body: {
            email:
              'cert-nonexistent@test.invalid',
            password: 'WrongPass!123'
          }
        }
      );
      assert(
        r.status === 401,
        `expected 401, got ${r.status} — bad logins must not succeed or leak`
      );
    }
  );

  await check(
    'Security',
    'Login without fields is rejected (400)',
    async () => {
      const r = await api(
        'POST',
        '/api/auth/login',
        { body: {} }
      );
      assert(
        r.status === 400,
        `expected 400, got ${r.status}`
      );
    }
  );

  await expectUnauthorized(
    'Security',
    'POST /api/videos/:id/like without token -> 401',
    'POST',
    '/api/videos/00000000-0000-0000-0000-000000000000/like'
  );

  await expectUnauthorized(
    'Security',
    'POST /api/videos/:id/save without token -> 401',
    'POST',
    '/api/videos/00000000-0000-0000-0000-000000000000/save'
  );

  await expectUnauthorized(
    'Security',
    'GET /api/notifications without token -> 401',
    'GET',
    '/api/notifications'
  );

  await expectUnauthorized(
    'Security',
    'GET /api/wallet/balance without token -> 401',
    'GET',
    '/api/wallet/balance'
  );

  await expectUnauthorized(
    'Security',
    'GET /api/dm/conversations without token -> 401',
    'GET',
    '/api/dm/conversations'
  );

  await expectUnauthorized(
    'Security',
    'GET /api/admin/users without token -> 401',
    'GET',
    '/api/admin/users'
  );

  await expectUnauthorized(
    'Security',
    'POST /api/upload without token -> 401',
    'POST',
    '/api/upload'
  );

  await check(
    'Security',
    'GET /api/feed?type=following anonymous -> 401',
    async () => {
      const r = await api(
        'GET',
        '/api/feed?type=following'
      );
      assert(
        r.status === 401,
        `expected 401, got ${r.status} — Following feed must be per-user`
      );
    }
  );

  await check(
    'Security',
    'GET /auth/google route is mounted',
    async () => {
      const r = await api('GET', '/auth/google');
      assert(
        r.status !== 404,
        'got 404 — /auth/google is not mounted'
      );
      // 302: passport redirects to Google
      // (env configured). 503: JSON "not
      // configured". Both prove the route.
      assert(
        [200, 301, 302, 303, 503].includes(
          r.status
        ),
        `expected 302 (configured) or 503 (unconfigured), got ${r.status}`
      );
      return r.status === 503
        ? 'OAuth env not configured (503 JSON) — route mounted'
        : `redirects (${r.status}) — Google OAuth configured`;
    }
  );

  await check(
    'Security',
    'POST /api/auth/oauth-exchange rejects a bogus code (401)',
    async () => {
      const r = await api(
        'POST',
        '/api/auth/oauth-exchange',
        { body: { code: 'cert-bogus-code' } }
      );
      assert(
        r.status === 401,
        `expected 401, got ${r.status}`
      );
    }
  );

  await check(
    'Security',
    'GET /api/auth/verify-email with bogus token redirects to error (route mounted)',
    async () => {
      const r = await api(
        'GET',
        '/api/auth/verify-email?token=cert-bogus-token'
      );
      assert(
        r.status !== 404,
        'got 404 — verify-email not mounted'
      );
      // Route always redirects; a bogus
      // token must land on verify_error.
      assert(
        r.status >= 300 && r.status < 400,
        `expected a redirect, got ${r.status}`
      );
      const loc =
        r.headers.get('location') || '';
      assert(
        loc.includes('verify_error=1'),
        `expected redirect to verify_error=1, got Location: ${loc}`
      );
    }
  );

  await check(
    'Security',
    'POST /api/auth/forgot-password always succeeds (no account enumeration)',
    async () => {
      const r = await api(
        'POST',
        '/api/auth/forgot-password',
        {
          body: {
            email:
              'cert-nonexistent@test.invalid'
          }
        }
      );
      assertStatus(r, 200, 'forgot-password');
      assert(
        r.json && r.json.success === true,
        'expected { success: true }'
      );
    }
  );
}

// ========================================
// FULL-MODE CHECKS (--full)
// ========================================

async function fullChecks() {
  const ts = Date.now();

  const creds = {
    a: {
      username: `cert_${ts}_a`,
      email: `cert_${ts}_a@test.invalid`,
      password: `CertPass!${ts}`
    },
    b: {
      username: `cert_${ts}_b`,
      email: `cert_${ts}_b@test.invalid`,
      password: `CertPass!${ts}`
    }
  };

  // Live session state for both cert users.
  const A = { ...creds.a };
  const B = { ...creds.b };

  console.log(
    `\nCert users: ${A.email} / ${B.email}`
  );

  // ---------- Account ----------

  let devVerifyUrlA = null;

  for (const [key, u] of [
    ['A', A],
    ['B', B]
  ]) {
    await check(
      'Account',
      `Register cert user ${key} (${u.email})`,
      async () => {
        const r = await api(
          'POST',
          '/api/auth/register',
          {
            body: {
              username: u.username,
              email: u.email,
              password: u.password
            }
          }
        );
        assertStatus(r, 200, 'register');
        assert(
          r.json &&
            r.json.token &&
            r.json.refreshToken &&
            r.json.user &&
            r.json.user.id,
          'register response missing token/refreshToken/user.id'
        );
        u.token = r.json.token;
        u.refreshToken = r.json.refreshToken;
        u.id = r.json.user.id;
        if (r.json.devVerificationUrl) {
          devVerifyUrlA =
            key === 'A'
              ? r.json.devVerificationUrl
              : devVerifyUrlA;
        }
      }
    );
  }

  // Everything below needs both users;
  // bail out of dependent checks cleanly.
  const needUsers = () => {
    if (!A.id || !B.id || !A.token || !B.token) {
      skip(
        'cert users were not created — earlier register checks failed'
      );
    }
  };

  await check(
    'Account',
    'Login as A returns a fresh token pair',
    async () => {
      needUsers();
      const r = await api(
        'POST',
        '/api/auth/login',
        {
          body: {
            email: A.email,
            password: A.password
          }
        }
      );
      assertStatus(r, 200, 'login');
      assert(
        r.json && r.json.token && r.json.refreshToken,
        'login response missing token/refreshToken'
      );
      A.token = r.json.token;
      A.refreshToken = r.json.refreshToken;
    }
  );

  await check(
    'Account',
    'GET /api/auth/me returns A profile',
    async () => {
      needUsers();
      const r = await api('GET', '/api/auth/me', {
        token: A.token
      });
      assertStatus(r, 200, 'me');
      assert(
        r.json &&
          r.json.user &&
          r.json.user.username === A.username,
        `me returned wrong user: ${r.json && r.json.user && r.json.user.username}`
      );
      assert(
        r.json.emailVerified === false,
        'emailVerified should start false'
      );
    }
  );

  await check(
    'Account',
    'Email verification via dev link marks A verified',
    async () => {
      needUsers();
      if (!devVerifyUrlA) {
        skip(
          'no devVerificationUrl in register response (NODE_ENV=production) — verify via the real mailbox instead'
        );
      }
      const tokenMatch =
        devVerifyUrlA.match(/[?&]token=([^&]+)/);
      assert(
        tokenMatch,
        `could not parse token from ${devVerifyUrlA}`
      );
      const r = await api(
        'GET',
        `/api/auth/verify-email?token=${encodeURIComponent(tokenMatch[1])}`
      );
      assert(
        r.status >= 300 && r.status < 400,
        `expected redirect, got ${r.status}`
      );
      const loc =
        r.headers.get('location') || '';
      assert(
        loc.includes('verified=1'),
        `expected verified=1 redirect, got Location: ${loc}`
      );
      const me = await api(
        'GET',
        '/api/auth/me',
        { token: A.token }
      );
      assert(
        me.json && me.json.emailVerified === true,
        'emailVerified still false after verify'
      );
    }
  );

  await check(
    'Account',
    'Refresh token rotates and the old token dies (401)',
    async () => {
      needUsers();
      const oldRefresh = A.refreshToken;
      const r = await api(
        'POST',
        '/api/auth/refresh',
        { body: { refreshToken: oldRefresh } }
      );
      assertStatus(r, 200, 'refresh');
      assert(
        r.json && r.json.token && r.json.refreshToken,
        'refresh response missing token pair'
      );
      A.token = r.json.token;
      A.refreshToken = r.json.refreshToken;

      // Reuse of the rotated token must fail.
      const reuse = await api(
        'POST',
        '/api/auth/refresh',
        { body: { refreshToken: oldRefresh } }
      );
      assert(
        reuse.status === 401,
        `rotated refresh token reuse gave ${reuse.status}, expected 401`
      );
    }
  );

  await check(
    'Account',
    'Forgot-password for a real cert user still succeeds',
    async () => {
      needUsers();
      const r = await api(
        'POST',
        '/api/auth/forgot-password',
        { body: { email: A.email } }
      );
      assertStatus(r, 200, 'forgot-password');
      assert(
        r.json && r.json.success === true,
        'expected { success: true }'
      );
    }
  );

  // ---------- Social ----------

  await check(
    'Social',
    'A follows B',
    async () => {
      needUsers();
      const r = await api(
        'POST',
        `/api/users/${B.id}/follow`,
        { token: A.token }
      );
      assertStatus(r, 200, 'follow');
      assert(
        r.json &&
          r.json.ok === true &&
          r.json.following === true &&
          r.json.status === 'following',
        `unexpected follow response: ${r.text.slice(0, 120)}`
      );
    }
  );

  await check(
    'Social',
    'Search finds the cert user',
    async () => {
      needUsers();
      const r = await api(
        'GET',
        `/api/search?q=${encodeURIComponent(A.username)}`
      );
      assertStatus(r, 200, 'search');
      assert(
        r.json.users.some(
          u => u.username === A.username
        ),
        `search for "${A.username}" did not return the cert user`
      );
    }
  );

  await check(
    'Social',
    'Following feed (?type=following) works for B',
    async () => {
      needUsers();
      const r = await api(
        'GET',
        '/api/feed?type=following',
        { token: B.token }
      );
      assertStatus(r, 200, 'following feed');
      assert(
        r.json && Array.isArray(r.json.feed),
        'response has no feed[] array'
      );
      return `${r.json.feed.length} items (B follows nobody — empty is fine)`;
    }
  );

  await check(
    'Social',
    'B receives a follow notification (unreadCount >= 1)',
    async () => {
      needUsers();
      // createNotification is fire-and-forget
      // in the follow route — allow a brief
      // settle window.
      let last = null;
      for (let i = 0; i < 4; i++) {
        const r = await api(
          'GET',
          '/api/notifications',
          { token: B.token }
        );
        assertStatus(r, 200, 'notifications');
        last = r.json;
        if (
          last.unreadCount >= 1 &&
          last.notifications.some(
            n => n.type === 'follow'
          )
        ) {
          return `unreadCount=${last.unreadCount}, follow notification present`;
        }
        await sleep(500);
      }
      assert(
        false,
        `no follow notification for B after retries: ${JSON.stringify(last).slice(0, 160)}`
      );
    }
  );

  await check(
    'Social',
    'POST /api/notifications/read clears B unread count',
    async () => {
      needUsers();
      const r = await api(
        'POST',
        '/api/notifications/read',
        { token: B.token, body: {} }
      );
      assertStatus(r, 200, 'mark read');
      assert(
        r.json && r.json.ok === true,
        'expected { ok: true }'
      );
      const after = await api(
        'GET',
        '/api/notifications',
        { token: B.token }
      );
      assert(
        after.json.unreadCount === 0,
        `unreadCount is ${after.json.unreadCount}, expected 0`
      );
    }
  );

  // ---------- Video ----------
  // Like/comment/save need an existing
  // video; use the first feed item. The
  // checks revert their own writes (unlike,
  // delete comment, unsave) so existing
  // users' counters end unchanged.

  let videoId = null;

  await check(
    'Video',
    'Feed yields a video to exercise',
    async () => {
      needUsers();
      const r = await api('GET', '/api/feed', {
        token: A.token
      });
      assertStatus(r, 200, 'feed');
      const first =
        r.json.feed && r.json.feed[0];
      if (!first || !first.id) {
        skip(
          'no content to test against — feed is empty on this deployment'
        );
      }
      videoId = first.id;
      return `using video ${videoId} ("${(first.title || '').slice(0, 40)}")`;
    }
  );

  const needVideo = () => {
    needUsers();
    if (!videoId) {
      skip(
        'no content to test against — feed is empty on this deployment'
      );
    }
  };

  await check(
    'Video',
    'GET /api/videos/:id returns the video',
    async () => {
      needVideo();
      const r = await api(
        'GET',
        `/api/videos/${videoId}`
      );
      assertStatus(r, 200, 'video detail');
      assert(
        r.json && r.json.id === videoId,
        'video detail id mismatch'
      );
    }
  );

  await check(
    'Video',
    'Like toggles on and back off (counters restored)',
    async () => {
      needVideo();
      const on = await api(
        'POST',
        `/api/videos/${videoId}/like`,
        { token: A.token }
      );
      assertStatus(on, 200, 'like');
      assert(
        on.json &&
          on.json.success === true &&
          on.json.liked === true,
        `expected liked:true, got ${on.text.slice(0, 120)}`
      );
      const off = await api(
        'POST',
        `/api/videos/${videoId}/like`,
        { token: A.token }
      );
      assert(
        off.json && off.json.liked === false,
        `second toggle expected liked:false, got ${off.text.slice(0, 120)}`
      );
    }
  );

  let commentId = null;

  await check(
    'Video',
    'A comments on the video',
    async () => {
      needVideo();
      const r = await api(
        'POST',
        `/api/videos/${videoId}/comments`,
        {
          token: A.token,
          body: {
            text: `cert smoke comment ${ts}`
          }
        }
      );
      assertStatus(r, 200, 'comment');
      assert(
        r.json &&
          r.json.success === true &&
          r.json.comment &&
          r.json.comment.id,
        `comment not created: ${r.text.slice(0, 120)}`
      );
      commentId = r.json.comment.id;

      const list = await api(
        'GET',
        `/api/videos/${videoId}/comments`
      );
      assert(
        list.json.comments.some(
          c => c.id === commentId
        ),
        'comment not visible in GET comments'
      );
    }
  );

  await check(
    'Video',
    'A deletes their comment (counters restored)',
    async () => {
      needVideo();
      if (!commentId) {
        skip('comment creation failed earlier');
      }
      const r = await api(
        'DELETE',
        `/api/videos/${videoId}/comments/${commentId}`,
        { token: A.token }
      );
      assertStatus(r, 200, 'delete comment');
      assert(
        r.json && r.json.success === true,
        'expected { success: true }'
      );
      const list = await api(
        'GET',
        `/api/videos/${videoId}/comments`
      );
      assert(
        !list.json.comments.some(
          c => c.id === commentId
        ),
        'comment still listed after delete'
      );
    }
  );

  await check(
    'Video',
    'Save toggles on, appears in /api/users/me/saves, then unsaves',
    async () => {
      needVideo();
      const on = await api(
        'POST',
        `/api/videos/${videoId}/save`,
        { token: A.token }
      );
      assertStatus(on, 200, 'save');
      assert(
        on.json && on.json.saved === true,
        `expected saved:true, got ${on.text.slice(0, 120)}`
      );
      const saves = await api(
        'GET',
        '/api/users/me/saves',
        { token: A.token }
      );
      assert(
        saves.json.videos.some(
          v => v.id === videoId
        ),
        'saved video not in /api/users/me/saves'
      );
      const off = await api(
        'POST',
        `/api/videos/${videoId}/save`,
        { token: A.token }
      );
      assert(
        off.json && off.json.saved === false,
        `unsave expected saved:false, got ${off.text.slice(0, 120)}`
      );
    }
  );

  // ---------- Messaging ----------
  // NOTE: sending a DM message is
  // socket-only (socket.io "dm_send",
  // server.js:11861) — there is no REST
  // POST /api/dm/:id/messages. The cert
  // covers conversation create + history.

  let convId = null;

  await check(
    'Messaging',
    'A creates a DM conversation with B',
    async () => {
      needUsers();
      const r = await api(
        'POST',
        '/api/dm/conversations',
        {
          token: A.token,
          body: { userId: B.id }
        }
      );
      assertStatus(r, 200, 'dm create');
      assert(
        r.json && r.json.id,
        `no conversation id: ${r.text.slice(0, 120)}`
      );
      convId = r.json.id;
    }
  );

  await check(
    'Messaging',
    'Conversation listed for both A and B',
    async () => {
      needUsers();
      if (!convId) {
        skip('conversation creation failed earlier');
      }
      for (const [key, u] of [
        ['A', A],
        ['B', B]
      ]) {
        const r = await api(
          'GET',
          '/api/dm/conversations',
          { token: u.token }
        );
        assertStatus(r, 200, 'dm list');
        assert(
          Array.isArray(r.json) &&
            r.json.some(c => c.id === convId),
          `conversation not in ${key}'s list`
        );
      }
    }
  );

  await check(
    'Messaging',
    'DM message history retrievable by both participants',
    async () => {
      needUsers();
      if (!convId) {
        skip('conversation creation failed earlier');
      }
      for (const [key, u] of [
        ['A', A],
        ['B', B]
      ]) {
        const r = await api(
          'GET',
          `/api/dm/${convId}/messages`,
          { token: u.token }
        );
        assertStatus(r, 200, 'dm messages');
        assert(
          Array.isArray(r.json),
          `${key}: messages response is not an array`
        );
      }
      return 'empty history — message SEND is socket-only (dm_send), not covered here';
    }
  );

  // ---------- Wallet ----------

  await check(
    'Wallet',
    'GET /api/wallet/balance for cert user',
    async () => {
      needUsers();
      const r = await api(
        'GET',
        '/api/wallet/balance',
        { token: A.token }
      );
      assertStatus(r, 200, 'wallet balance');
      assert(
        r.json &&
          typeof r.json.balance === 'number' &&
          typeof r.json.total_earned === 'number',
        `unexpected balance shape: ${r.text.slice(0, 120)}`
      );
      return `balance=${r.json.balance}`;
    }
  );

  await check(
    'Wallet',
    'GET /api/wallet/transactions for cert user',
    async () => {
      needUsers();
      const r = await api(
        'GET',
        '/api/wallet/transactions',
        { token: A.token }
      );
      assertStatus(r, 200, 'wallet txns');
      assert(
        r.json &&
          Array.isArray(r.json.transactions),
        'response has no transactions[] array'
      );
    }
  );

  // ---------- Admin ----------

  await check(
    'Admin',
    'Non-admin cert user is forbidden from /api/admin/users (403)',
    async () => {
      needUsers();
      const r = await api('GET', '/api/admin/users', {
        token: A.token
      });
      assert(
        r.status === 403,
        `expected 403, got ${r.status} — requireAdmin must reject non-admins`
      );
    }
  );

  // ---------- Security (session end) ----------

  await check(
    'Security',
    'Logout revokes the refresh token (reuse -> 401)',
    async () => {
      needUsers();
      const doomed = A.refreshToken;
      const out = await api(
        'POST',
        '/api/auth/logout',
        { body: { refreshToken: doomed } }
      );
      assertStatus(out, 200, 'logout');
      assert(
        out.json && out.json.success === true,
        'expected { success: true }'
      );
      const reuse = await api(
        'POST',
        '/api/auth/refresh',
        { body: { refreshToken: doomed } }
      );
      assert(
        reuse.status === 401,
        `revoked refresh token reuse gave ${reuse.status}, expected 401`
      );
    }
  );

  console.log(
    yellow(
      `\nNote: cert users ${A.email} and ${B.email} remain in the DB`
    )
  );
  console.log(
    yellow(
      '(no delete-account API). Remove with SQL if unwanted:'
    )
  );
  console.log(
    yellow(
      `  DELETE FROM users WHERE email LIKE 'cert_%@test.invalid';`
    )
  );
}

// ========================================
// Report
// ========================================

function report() {
  const groups = [];
  for (const r of results) {
    if (!groups.includes(r.group)) {
      groups.push(r.group);
    }
  }

  console.log('');

  let pass = 0;
  let fail = 0;
  let skipped = 0;

  for (const g of groups) {
    console.log(bold(g));
    for (const r of results.filter(
      x => x.group === g
    )) {
      if (r.status === 'pass') pass++;
      if (r.status === 'fail') fail++;
      if (r.status === 'skip') skipped++;

      const note = r.note
        ? ` — ${r.note}`
        : '';
      console.log(
        `  ${ICON[r.status]} ${r.name}${r.status === 'pass' ? (note ? paint(90, note) : '') : note}`
      );
    }
    console.log('');
  }

  const total = results.length;
  const effective = total - skipped;

  console.log(
    'Out of scope (manual checks): Socket.IO realtime (dm_send / typing / video call / live gifts), real multipart video upload, Google OAuth browser round-trip.'
  );
  console.log('');

  if (fail === 0) {
    console.log(
      green(
        bold(
          `PASS ${pass}/${effective}` +
            (skipped
              ? ` (${skipped} skipped)`
              : '')
        )
      )
    );
  } else {
    console.log(
      red(
        bold(
          `FAIL ${pass}/${effective} passed, ${fail} FAILED` +
            (skipped
              ? `, ${skipped} skipped`
              : '')
        )
      )
    );
  }

  return fail === 0 ? 0 : 1;
}

// ========================================
// Main
// ========================================

(async () => {
  console.log(
    bold('NVME.live Production Certification')
  );
  console.log(`Target: ${BASE_URL}`);
  console.log(
    `Mode:   ${
      FULL
        ? 'FULL (creates cert_<ts>_a/b@test.invalid)'
        : 'READ-ONLY (no writes; use --full for the end-to-end matrix)'
    }`
  );

  await readOnlyChecks();

  if (FULL) {
    await fullChecks();
  } else {
    console.log(
      '\nRead-only mode: register/login/follow/DM/wallet/admin-403 checks are skipped (they need throwaway users). Re-run with --full.'
    );
  }

  process.exitCode = report();
})().catch(err => {
  console.error(
    red(`\nCert runner crashed: ${err.stack || err}`)
  );
  process.exitCode = 2;
});
