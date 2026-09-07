'use strict';

// ========================================
// 🎥 Live SFU (LiveKit) integration
// ========================================
//
// This module is the ONLY thing responsible for real video/audio
// transport for the LIVE feature. Everything else (chat, gifts,
// leaderboards, battle score) keeps working exactly as it does today
// over Socket.IO — this just makes sure there's an actual video
// stream underneath it.
//
// Requires three env vars (see .env.example additions):
//   LIVEKIT_URL          e.g. wss://your-project.livekit.cloud
//   LIVEKIT_API_KEY
//   LIVEKIT_API_SECRET
//
// If they're unset, every function here throws a clear error instead
// of failing silently — callers should catch that and return a 503
// (see the server.js patch) rather than letting a stream "go live"
// with no video path.

const { AccessToken, RoomServiceClient } = require('livekit-server-sdk');

const LIVEKIT_URL = process.env.LIVEKIT_URL || '';
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY || '';
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET || '';

const isConfigured = Boolean(
  LIVEKIT_URL && LIVEKIT_API_KEY && LIVEKIT_API_SECRET
);

if (!isConfigured) {
  console.warn(
    '⚠️ LiveKit env vars missing (LIVEKIT_URL / LIVEKIT_API_KEY / ' +
      'LIVEKIT_API_SECRET) — going live will fail until these are set. ' +
      'Chat, gifts, and the rest of the app are unaffected.'
  );
}

// RoomServiceClient wants an http(s) URL, not the wss:// URL the
// browser client uses — derive it instead of asking for a second env var.
const roomServiceUrl = LIVEKIT_URL.replace(/^wss:\/\//, 'https://').replace(
  /^ws:\/\//,
  'http://'
);

const roomService = isConfigured
  ? new RoomServiceClient(roomServiceUrl, LIVEKIT_API_KEY, LIVEKIT_API_SECRET)
  : null;

function assertConfigured() {
  if (!isConfigured) {
    const err = new Error('LiveKit is not configured on this server');
    err.code = 'LIVEKIT_NOT_CONFIGURED';
    throw err;
  }
}

function roomNameForStream(streamId) {
  return `live-${streamId}`;
}

/**
 * Idempotently ensures a LiveKit room exists for this stream.
 * Safe to call every time a broadcaster goes live.
 */
async function ensureRoom(streamId) {
  assertConfigured();
  const name = roomNameForStream(streamId);

  try {
    await roomService.createRoom({
      name,
      emptyTimeout: 10 * 60, // seconds — auto-cleans if everyone leaves
      maxParticipants: 5000
    });
  } catch (err) {
    // Some SDK/server versions throw when the room already exists.
    // That's fine — the room existing is exactly what we want.
    const msg = String(err && err.message);
    if (!/already exists/i.test(msg)) {
      throw err;
    }
  }

  return name;
}

/**
 * Tears down the LiveKit room when a stream ends. Disconnects any
 * lingering participants (viewers get a room-disconnected event on
 * the client, which the frontend patch treats as "stream ended").
 */
async function closeRoom(streamId) {
  if (!isConfigured) return; // nothing to close if it was never opened
  const name = roomNameForStream(streamId);

  try {
    await roomService.deleteRoom(name);
  } catch (err) {
    console.warn('[live-sfu] deleteRoom warning:', err.message);
  }
}

/**
 * Issues a signed LiveKit access token.
 *
 * @param {Object} opts
 * @param {string} opts.streamId
 * @param {string} opts.identity   Must be unique per participant in the
 *                                 room — use the user id.
 * @param {string} [opts.name]     Display name shown to other participants.
 * @param {boolean} [opts.canPublish] true for the broadcaster (and any
 *                                    co-host/battle participant), false
 *                                    for plain viewers.
 */
async function issueToken({ streamId, identity, name, canPublish }) {
  assertConfigured();

  const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity,
    name: name || identity,
    ttl: '6h'
  });

  at.addGrant({
    room: roomNameForStream(streamId),
    roomJoin: true,
    canPublish: Boolean(canPublish),
    canSubscribe: true,
    canPublishData: true
  });

  return at.toJwt();
}

module.exports = {
  isConfigured,
  LIVEKIT_URL,
  roomNameForStream,
  ensureRoom,
  closeRoom,
  issueToken
};
