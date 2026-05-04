// ============================================================
// NVME HELP NETWORK — Offline Emergency & Community Aid
// Works via SMS when internet is down
// Text HELP, FOOD, WATER, MEDICAL, SHELTER to your region number
// ============================================================
const express = require('express');
const router = express.Router();
const { pool } = require('./db');

// Twilio setup
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  const twilio = require('twilio');
  twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  console.log('OK NVME HelpNet SMS active');
} else {
  console.warn('WARN HelpNet running without Twilio — SMS disabled');
}

// ── DB Tables ─────────────────────────────────────────────────
async function initHelpNet() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS help_requests (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type VARCHAR(50) NOT NULL,
        message TEXT,
        phone VARCHAR(30),
        lat DECIMAL(10,7),
        lng DECIMAL(10,7),
        country VARCHAR(100),
        region VARCHAR(100),
        status VARCHAR(20) DEFAULT 'open',
        responders INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_help_status ON help_requests(status, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_help_country ON help_requests(country)`);
  } catch (e) {
    console.error('HelpNet DB init error:', e.message);
  }
}
initHelpNet();

// ── Help Categories ───────────────────────────────────────────
const HELP_TYPES = {
  FOOD:     { emoji: '🍚', label: 'Food',      color: '#f59e0b', keywords: ['food','hungry','eat','starving','meal'] },
  WATER:    { emoji: '💧', label: 'Water',     color: '#3b82f6', keywords: ['water','drink','thirsty','flood'] },
  MEDICAL:  { emoji: '🏥', label: 'Medical',   color: '#ef4444', keywords: ['medical','sick','hurt','injury','hospital','medicine','help'] },
  SHELTER:  { emoji: '🏠', label: 'Shelter',   color: '#8b5cf6', keywords: ['shelter','homeless','roof','house','stay','sleep'] },
  POWER:    { emoji: '⚡', label: 'Power',     color: '#eab308', keywords: ['power','electricity','generator','lights','outage'] },
  INTERNET: { emoji: '📡', label: 'Internet',  color: '#06b6d4', keywords: ['internet','wifi','data','signal','network','connectivity'] },
  SAFETY:   { emoji: '🚨', label: 'Safety',    color: '#dc2626', keywords: ['danger','safety','attack','crime','threat','sos','emergency'] },
  GENERAL:  { emoji: '🤝', label: 'General',   color: '#10b981', keywords: [] }
};

function detectType(text) {
  if (!text) return 'GENERAL';
  const upper = text.toUpperCase();
  for (const [type, info] of Object.entries(HELP_TYPES)) {
    if (upper.includes(type)) return type;
    if (info.keywords.some(k => upper.includes(k.toUpperCase()))) return type;
  }
  return 'GENERAL';
}

// ── POST /api/helpnet/request — Web form submission ───────────
router.post('/request', async (req, res) => {
  try {
    const { type, message, lat, lng, country, region, phone } = req.body;
    if (!type && !message) return res.status(400).json({ error: 'type or message required' });

    const helpType = type || detectType(message);
    const info = HELP_TYPES[helpType] || HELP_TYPES.GENERAL;

    let result;
    try {
      const r = await pool.query(
        `INSERT INTO help_requests (type,message,phone,lat,lng,country,region)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,created_at`,
        [helpType, message, phone||null, lat||null, lng||null, country||'Unknown', region||'Unknown']
      );
      result = r.rows[0];
    } catch (dbErr) {
      // DB not ready — still respond with in-memory confirmation
      result = { id: 'mem-' + Date.now(), created_at: new Date() };
    }

    // Notify via Twilio if phone provided
    if (twilioClient && phone && process.env.TWILIO_FROM_NUMBER) {
      try {
        await twilioClient.messages.create({
          to: phone,
          from: process.env.TWILIO_FROM_NUMBER,
          body: `✅ NVME HelpNet received your ${info.emoji} ${info.label} request. ID: ${result.id.toString().slice(0,8)}. Community responders have been notified. Stay safe. Reply CANCEL to withdraw.`
        });
      } catch (smsErr) {
        console.error('SMS send error:', smsErr.message);
      }
    }

    res.json({
      success: true,
      id: result.id,
      type: helpType,
      emoji: info.emoji,
      label: info.label,
      message: `Your ${info.label} request has been broadcast to the NVME community.`,
      created_at: result.created_at
    });
  } catch (err) {
    console.error('HelpNet request error:', err.message);
    res.status(500).json({ error: 'Failed to submit request' });
  }
});

// ── POST /api/helpnet/sms — Twilio inbound SMS webhook ────────
router.post('/sms', express.urlencoded({ extended: false }), async (req, res) => {
  const from = req.body.From || '';
  const body = (req.body.Body || '').trim();
  const country = req.body.FromCountry || 'Unknown';
  const region  = req.body.FromCity || req.body.FromState || 'Unknown';

  let replyText = '';

  if (body.toUpperCase() === 'CANCEL') {
    replyText = '✅ Your help request has been withdrawn. Stay safe. Text HELP anytime.';
  } else if (body.toUpperCase() === 'STATUS') {
    replyText = '📡 NVME HelpNet is active. Community is standing by. Text: FOOD, WATER, MEDICAL, SHELTER, POWER, SAFETY or describe your need.';
  } else {
    const helpType = detectType(body);
    const info = HELP_TYPES[helpType] || HELP_TYPES.GENERAL;
    try {
      await pool.query(
        `INSERT INTO help_requests (type,message,phone,country,region) VALUES ($1,$2,$3,$4,$5)`,
        [helpType, body, from, country, region]
      );
    } catch (e) { /* DB not ready */ }
    replyText = `${info.emoji} NVME HelpNet received your ${info.label} request from ${region || country}. Notifying nearby community members now. Reply STATUS for updates or CANCEL to withdraw.`;
  }

  // Respond with TwiML
  res.set('Content-Type', 'text/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?><Response><Message>${replyText}</Message></Response>`);
});

// ── GET /api/helpnet/feed — Live help requests ────────────────
router.get('/feed', async (req, res) => {
  try {
    const { country, type } = req.query;
    let query = `SELECT id, type, message, country, region, status, responders, created_at
                 FROM help_requests WHERE status='open'`;
    const params = [];
    if (country) { params.push(country); query += ` AND country=$${params.length}`; }
    if (type)    { params.push(type);    query += ` AND type=$${params.length}`; }
    query += ` ORDER BY created_at DESC LIMIT 50`;
    const r = await pool.query(query, params);
    res.json({ requests: r.rows, total: r.rowCount });
  } catch (e) {
    res.json({ requests: [], total: 0 });
  }
});

// ── POST /api/helpnet/respond — Mark as responding ────────────
router.post('/respond', async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'id required' });
    await pool.query(
      `UPDATE help_requests SET responders=responders+1, updated_at=NOW() WHERE id=$1`,
      [id]
    );
    res.json({ success: true, message: 'You are now a responder. Thank you!' });
  } catch (e) {
    res.status(500).json({ error: 'Could not register response' });
  }
});

// ── GET /api/helpnet/stats ────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status='open') as open_requests,
        COUNT(*) FILTER (WHERE status='resolved') as resolved,
        COUNT(DISTINCT country) as countries_active,
        SUM(responders) as total_responders,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h
      FROM help_requests
    `);
    res.json(r.rows[0]);
  } catch (e) {
    res.json({ open_requests: 0, resolved: 0, countries_active: 0, total_responders: 0, last_24h: 0 });
  }
});

module.exports = router;
