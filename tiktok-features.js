// ============================================================
// NVME TikTok-Style Features Module v1.0
// All TikTok features reimagined with creator-first economics
// ============================================================

const { v4: uuidv4 } = require('uuid');

// ============================================================
// 1. REVENUE SPLIT CONFIG (TikTok-style with launch discount)
// ============================================================
// NVME launch date - change this to your actual launch date
const LAUNCH_DATE = new Date(process.env.LAUNCH_DATE || '2026-04-21');
const LAUNCH_PERIOD_MONTHS = 6;

function getRevenueSplit() {
  const now = new Date();
  const monthsSinceLaunch = (now - LAUNCH_DATE) / (1000 * 60 * 60 * 24 * 30.44);
  const isLaunchPeriod = monthsSinceLaunch < LAUNCH_PERIOD_MONTHS;
  
  return {
    period: isLaunchPeriod ? 'launch' : 'standard',
    platformCut: isLaunchPeriod ? 0.45 : 0.40,
    creatorShare: isLaunchPeriod ? 0.55 : 0.60,
    tiktokCut: 0.50,
    advantageVsTikTok: isLaunchPeriod ? '5% better than TikTok' : '10% better than TikTok',
    daysRemainingInLaunch: isLaunchPeriod 
      ? Math.ceil((LAUNCH_PERIOD_MONTHS * 30.44) - (monthsSinceLaunch * 30.44))
      : 0,
    launchDate: LAUNCH_DATE.toISOString(),
    standardStartDate: new Date(LAUNCH_DATE.getTime() + LAUNCH_PERIOD_MONTHS * 30.44 * 24 * 60 * 60 * 1000).toISOString()
  };
}

// ============================================================
// 2. COIN ECONOMY (TikTok-style pricing)
// ============================================================
const COIN_PACKAGES = [
  { id: 'coins_20',    coins: 20,    priceUSD: 0.29,  name: 'Starter Pack',  bonus: 0,    popular: false },
  { id: 'coins_70',    coins: 70,    priceUSD: 1.00,  name: 'Basic Pack',    bonus: 0,    popular: false },
  { id: 'coins_350',   coins: 350,   priceUSD: 5.00,  name: 'Popular Pack',  bonus: 0,    popular: true  },
  { id: 'coins_700',   coins: 700,   priceUSD: 10.00, name: 'Power Pack',    bonus: 0,    popular: false },
  { id: 'coins_1750',  coins: 1750,  priceUSD: 25.00, name: 'Super Pack',    bonus: 0,    popular: false },
  { id: 'coins_3500',  coins: 3500,  priceUSD: 50.00, name: 'Mega Pack',     bonus: 150,  popular: false },
  { id: 'coins_7000',  coins: 7000,  priceUSD: 100.00, name: 'Ultra Pack',   bonus: 350,  popular: false },
  { id: 'coins_17500', coins: 17500, priceUSD: 250.00, name: 'Ultimate Pack', bonus: 1000, popular: false }
];

// Diamond conversion: 1 coin received = 1 diamond (simpler than TikTok's complex rate)
// Diamonds cash out at creator's share rate
// NVME coin value: ~$0.0143 each (vs TikTok's ~$0.0134)
const COIN_TO_USD = 0.0143;

function calculatePayout(diamonds) {
  const split = getRevenueSplit();
  const grossUSD = diamonds * COIN_TO_USD;
  const platformFee = grossUSD * split.platformCut;
  const creatorEarnings = grossUSD * split.creatorShare;
  const tiktokEquivalent = grossUSD * (1 - split.tiktokCut);
  
  return {
    diamonds,
    grossUSD: Number(grossUSD.toFixed(2)),
    platformFee: Number(platformFee.toFixed(2)),
    creatorEarnings: Number(creatorEarnings.toFixed(2)),
    tiktokEquivalent: Number(tiktokEquivalent.toFixed(2)),
    youEarnMoreBy: Number((creatorEarnings - tiktokEquivalent).toFixed(2)),
    split
  };
}

// ============================================================
// 3. VS BATTLE SYSTEM (1v1 up to 10v10)
// ============================================================
const BATTLE_FORMATS = {
  '1v1':  { teams: 2, perTeam: 1,  maxTotal: 2,  name: 'Classic Duel' },
  '2v2':  { teams: 2, perTeam: 2,  maxTotal: 4,  name: 'Tag Team' },
  '3v3':  { teams: 2, perTeam: 3,  maxTotal: 6,  name: 'Squad Clash' },
  '4v4':  { teams: 2, perTeam: 4,  maxTotal: 8,  name: 'Team Wars' },
  '5v5':  { teams: 2, perTeam: 5,  maxTotal: 10, name: 'Full Squad' },
  '10v10': { teams: 2, perTeam: 10, maxTotal: 20, name: 'NVME MAX Battle' },
  '3way': { teams: 3, perTeam: 6,  maxTotal: 18, name: 'Triangle' },
  '4way': { teams: 4, perTeam: 5,  maxTotal: 20, name: 'Four Corners' },
  'ffa':  { teams: 20, perTeam: 1, maxTotal: 20, name: 'Free For All' }
};

const activeBattles = new Map();

function createBattle({ format, durationSec, hostId, prizePool }) {
  const config = BATTLE_FORMATS[format];
  if (!config) throw new Error(`Unknown battle format: ${format}`);
  
  const battleId = uuidv4();
  const battle = {
    battleId,
    format,
    config,
    hostId,
    prizePool: prizePool || 0,
    startedAt: Date.now(),
    duration: (durationSec || 180) * 1000,
    teams: Array.from({ length: config.teams }, (_, i) => ({
      teamId: `team_${i + 1}`,
      members: [],
      diamonds: 0,
      supporters: new Set()
    })),
    status: 'waiting',
    winner: null
  };
  
  activeBattles.set(battleId, battle);
  return battle;
}

function joinBattle(battleId, { userId, teamId }) {
  const battle = activeBattles.get(battleId);
  if (!battle) throw new Error('Battle not found');
  if (battle.status !== 'waiting') throw new Error('Battle already started');
  
  const team = battle.teams.find(t => t.teamId === teamId);
  if (!team) throw new Error('Team not found');
  if (team.members.length >= battle.config.perTeam) throw new Error('Team full');
  
  team.members.push(userId);
  return battle;
}

function sendGiftToBattle(battleId, { teamId, supporterId, diamonds }) {
  const battle = activeBattles.get(battleId);
  if (!battle) throw new Error('Battle not found');
  
  const team = battle.teams.find(t => t.teamId === teamId);
  if (!team) throw new Error('Team not found');
  
  team.diamonds += diamonds;
  team.supporters.add(supporterId);
  return { teamId, newTotal: team.diamonds, totalSupporters: team.supporters.size };
}

function finishBattle(battleId) {
  const battle = activeBattles.get(battleId);
  if (!battle) throw new Error('Battle not found');
  
  const sorted = [...battle.teams].sort((a, b) => b.diamonds - a.diamonds);
  battle.winner = sorted[0].teamId;
  battle.status = 'ended';
  battle.endedAt = Date.now();
  
  // Calculate payouts per winning team member
  const split = getRevenueSplit();
  const totalDiamonds = battle.teams.reduce((s, t) => s + t.diamonds, 0);
  const grossUSD = totalDiamonds * COIN_TO_USD;
  const creatorPool = grossUSD * split.creatorShare + (battle.prizePool || 0);
  const winningTeamMembers = sorted[0].members.length || 1;
  const perWinner = creatorPool / winningTeamMembers;
  
  return {
    battleId,
    winner: battle.winner,
    teams: battle.teams.map(t => ({
      teamId: t.teamId,
      diamonds: t.diamonds,
      members: t.members,
      supporters: t.supporters.size,
      isWinner: t.teamId === battle.winner
    })),
    totalDiamonds,
    creatorPool: Number(creatorPool.toFixed(2)),
    perWinnerPayout: Number(perWinner.toFixed(2)),
    platformFee: Number((grossUSD * split.platformCut).toFixed(2))
  };
}

// ============================================================
// 4. FYP ALGORITHM (For You Page)
// ============================================================
const watchEvents = [];
const userInterests = new Map();

function trackWatch({ userId, videoId, watchSec, totalSec, action }) {
  const event = {
    userId,
    videoId,
    watchSec,
    totalSec,
    action, // 'watched' | 'liked' | 'shared' | 'commented' | 'skipped'
    completion: totalSec > 0 ? watchSec / totalSec : 0,
    timestamp: Date.now()
  };
  watchEvents.push(event);
  
  // Keep only last 10000 events in memory
  if (watchEvents.length > 10000) watchEvents.shift();
  
  return event;
}

function scoreVideo(video, userId) {
  // TikTok-style scoring:
  // - Watch time / completion rate (50%)
  // - Engagement (likes, shares, comments) (30%)
  // - Freshness (recency) (15%)
  // - Creator quality (5%)
  
  const completionScore = (video.avgCompletion || 0.5) * 50;
  const engagementRate = (video.likes + video.shares * 3 + video.comments * 2) / Math.max(1, video.views);
  const engagementScore = Math.min(engagementRate * 100, 30);
  const ageHours = (Date.now() - new Date(video.createdAt || Date.now()).getTime()) / (1000 * 60 * 60);
  const freshnessScore = Math.max(0, 15 - ageHours / 24); // Decay over days
  const qualityScore = (video.creatorScore || 0.5) * 5;
  
  return completionScore + engagementScore + freshnessScore + qualityScore;
}

function getFYP(userId, count = 20) {
  // In production, this would query the database
  // For now, return mock scored videos
  const mockVideos = Array.from({ length: count }, (_, i) => ({
    videoId: `vid_${i}`,
    creatorId: `creator_${i % 10}`,
    title: `Trending video #${i + 1}`,
    views: Math.floor(Math.random() * 1000000),
    likes: Math.floor(Math.random() * 100000),
    shares: Math.floor(Math.random() * 10000),
    comments: Math.floor(Math.random() * 5000),
    avgCompletion: 0.4 + Math.random() * 0.5,
    creatorScore: Math.random(),
    createdAt: new Date(Date.now() - Math.random() * 86400000 * 7).toISOString(),
    videoUrl: `https://cdn.nvme.live/video/${i}.mp4`,
    thumbnail: `https://cdn.nvme.live/thumb/${i}.jpg`
  }));
  
  const scored = mockVideos.map(v => ({ ...v, fypScore: scoreVideo(v, userId) }));
  return scored.sort((a, b) => b.fypScore - a.fypScore);
}

// ============================================================
// 5. DUET & STITCH
// ============================================================
function createDuet({ originalVideoId, reactorId, reactorVideoUrl, layout }) {
  return {
    duetId: uuidv4(),
    originalVideoId,
    reactorId,
    reactorVideoUrl,
    layout: layout || 'side-by-side', // 'side-by-side' | 'top-bottom' | 'pip'
    createdAt: new Date().toISOString(),
    revenueShare: { original: 0.30, reactor: 0.70 } // Original creator gets 30% of revenue
  };
}

function createStitch({ originalVideoId, clipStart, clipEnd, reactorId, reactorVideoUrl }) {
  return {
    stitchId: uuidv4(),
    originalVideoId,
    clipStart,
    clipEnd,
    clipDuration: clipEnd - clipStart,
    reactorId,
    reactorVideoUrl,
    createdAt: new Date().toISOString(),
    revenueShare: { original: 0.20, reactor: 0.80 }
  };
}

// ============================================================
// 6. HASHTAG CHALLENGES
// ============================================================
const challenges = new Map();

function createChallenge({ hashtag, title, description, prizePoolUSD, endsAt, sponsor }) {
  const challenge = {
    challengeId: uuidv4(),
    hashtag: hashtag.startsWith('#') ? hashtag : '#' + hashtag,
    title,
    description,
    prizePoolUSD: prizePoolUSD || 0,
    sponsor: sponsor || null,
    startsAt: new Date().toISOString(),
    endsAt: endsAt || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    status: 'active',
    participants: [],
    topVideos: []
  };
  challenges.set(challenge.challengeId, challenge);
  return challenge;
}

function joinChallenge(challengeId, { userId, videoId }) {
  const challenge = challenges.get(challengeId);
  if (!challenge) throw new Error('Challenge not found');
  if (challenge.status !== 'active') throw new Error('Challenge ended');
  
  if (!challenge.participants.find(p => p.userId === userId)) {
    challenge.participants.push({ userId, videoId, joinedAt: Date.now() });
  }
  return challenge;
}

// ============================================================
// 7. CREATOR ANALYTICS
// ============================================================
function getCreatorAnalytics(creatorId) {
  // In production: query database
  // Mock data for now
  return {
    creatorId,
    period: 'last_30_days',
    overview: {
      totalViews: Math.floor(Math.random() * 5000000),
      uniqueViewers: Math.floor(Math.random() * 500000),
      followerGrowth: Math.floor(Math.random() * 10000),
      totalEarnings: Number((Math.random() * 5000).toFixed(2)),
      avgWatchTime: Math.floor(Math.random() * 45) + 15 // seconds
    },
    demographics: {
      ageGroups: {
        '13-17': 0.05, '18-24': 0.35, '25-34': 0.30, '35-44': 0.18, '45+': 0.12
      },
      genderSplit: { male: 0.48, female: 0.49, other: 0.03 },
      topCountries: ['US', 'BM', 'UK', 'CA', 'AU']
    },
    bestPostingTimes: [
      { day: 'Monday', hour: 19, engagementScore: 8.4 },
      { day: 'Thursday', hour: 20, engagementScore: 9.1 },
      { day: 'Saturday', hour: 14, engagementScore: 8.8 },
      { day: 'Sunday', hour: 21, engagementScore: 9.3 }
    ],
    topPerformingVideos: Array.from({ length: 5 }, (_, i) => ({
      videoId: `top_${i}`,
      title: `Top video ${i + 1}`,
      views: Math.floor(Math.random() * 1000000),
      earnings: Number((Math.random() * 500).toFixed(2))
    })),
    revenueBreakdown: {
      gifts: 0.45,
      tips: 0.20,
      subscriptions: 0.15,
      adRevenue: 0.10,
      battles: 0.05,
      shop: 0.05
    }
  };
}

// ============================================================
// 8. LIVE CO-HOST ROOMS
// ============================================================
const liveRooms = new Map();

function createLiveRoom({ hostId, maxGuests, isPaid, entryFeeCoins }) {
  const roomId = uuidv4();
  const room = {
    roomId,
    hostId,
    maxGuests: Math.min(maxGuests || 19, 19), // NVME max = 19 guests + 1 host = 20
    guests: [],
    viewers: 0,
    isPaid: isPaid || false,
    entryFeeCoins: entryFeeCoins || 0,
    startedAt: Date.now(),
    giftsReceived: 0,
    status: 'live',
    layout: 'auto' // Auto-adjusts based on guest count
  };
  liveRooms.set(roomId, room);
  return room;
}

function joinLiveAsGuest(roomId, { userId }) {
  const room = liveRooms.get(roomId);
  if (!room) throw new Error('Room not found');
  if (room.guests.length >= room.maxGuests) throw new Error('Room full');
  if (!room.guests.includes(userId)) room.guests.push(userId);
  
  // Calculate grid layout (1x1 to 4x5)
  const total = room.guests.length + 1; // +1 for host
  let layout;
  if (total <= 1) layout = '1x1';
  else if (total <= 2) layout = '1x2';
  else if (total <= 4) layout = '2x2';
  else if (total <= 6) layout = '2x3';
  else if (total <= 9) layout = '3x3';
  else if (total <= 12) layout = '3x4';
  else if (total <= 16) layout = '4x4';
  else layout = '4x5';
  
  room.layout = layout;
  return room;
}

// ============================================================
// 9. IN-VIDEO SHOPPING
// ============================================================
const shopPins = new Map();

function pinProductToVideo({ videoId, creatorId, productId, name, priceUSD, imageUrl, affiliateUrl, timestampSec }) {
  const pinId = uuidv4();
  const pin = {
    pinId,
    videoId,
    creatorId,
    productId,
    name,
    priceUSD,
    imageUrl,
    affiliateUrl,
    timestampSec: timestampSec || 0,
    // Creator commission: 10-30% depending on product category
    creatorCommission: 0.15,
    nvmeFee: 0.05, // NVME takes 5% of sale (much less than TikTok Shop's 30%)
    clicks: 0,
    conversions: 0
  };
  shopPins.set(pinId, pin);
  return pin;
}

// ============================================================
// 10. TRENDING SOUNDS (integrate with Sound Empire)
// ============================================================
const trendingSounds = [
  { soundId: 'se_001', title: 'Phoenix Rise', artist: 'ITAL PHOENIX', label: 'Sound Empire', uses: 0, bpm: 76, duration: 30, licensed: true },
  { soundId: 'se_002', title: 'Rebirth Anthem', artist: 'ITAL PHOENIX', label: 'Sound Empire', uses: 0, bpm: 85, duration: 15, licensed: true }
];

function getTrendingSounds(limit = 20) {
  return trendingSounds
    .sort((a, b) => b.uses - a.uses)
    .slice(0, limit);
}

function useSound(soundId) {
  const sound = trendingSounds.find(s => s.soundId === soundId);
  if (sound) sound.uses++;
  return sound;
}

// ============================================================
// EXPORT ROUTER SETUP
// ============================================================
function setupRoutes(app) {
  // Revenue split endpoint
  app.get('/api/revenue/split', (req, res) => {
    res.json(getRevenueSplit());
  });
  
  // Coin packages
  app.get('/api/coins/packages', (req, res) => {
    res.json({ packages: COIN_PACKAGES, coinToUSD: COIN_TO_USD });
  });
  
  // Calculate payout from diamonds
  app.get('/api/payouts/calculate', (req, res) => {
    const diamonds = parseInt(req.query.diamonds || 0);
    res.json(calculatePayout(diamonds));
  });
  
  // Battle endpoints
  app.get('/api/battles/formats', (req, res) => {
    res.json({ formats: BATTLE_FORMATS, maxParticipants: 20 });
  });
  app.post('/api/battles/create', (req, res) => {
    try { res.json(createBattle(req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.post('/api/battles/:id/join', (req, res) => {
    try { res.json(joinBattle(req.params.id, req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.post('/api/battles/:id/gift', (req, res) => {
    try { res.json(sendGiftToBattle(req.params.id, req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.post('/api/battles/:id/finish', (req, res) => {
    try { res.json(finishBattle(req.params.id)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.get('/api/battles/active', (req, res) => {
    const active = Array.from(activeBattles.values())
      .filter(b => b.status !== 'ended')
      .map(b => ({ ...b, teams: b.teams.map(t => ({ ...t, supporters: t.supporters.size })) }));
    res.json({ count: active.length, battles: active });
  });
  
  // FYP endpoints
  app.get('/api/fyp/:userId', (req, res) => {
    res.json({ userId: req.params.userId, videos: getFYP(req.params.userId, parseInt(req.query.count) || 20) });
  });
  app.post('/api/fyp/track', (req, res) => {
    res.json(trackWatch(req.body));
  });
  
  // Duet & Stitch
  app.post('/api/duet', (req, res) => {
    res.json(createDuet(req.body));
  });
  app.post('/api/stitch', (req, res) => {
    res.json(createStitch(req.body));
  });
  
  // Challenges
  app.post('/api/challenges/create', (req, res) => {
    res.json(createChallenge(req.body));
  });
  app.post('/api/challenges/:id/join', (req, res) => {
    try { res.json(joinChallenge(req.params.id, req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.get('/api/challenges/active', (req, res) => {
    res.json({ challenges: Array.from(challenges.values()).filter(c => c.status === 'active') });
  });
  
  // Analytics
  app.get('/api/analytics/creator/:id', (req, res) => {
    res.json(getCreatorAnalytics(req.params.id));
  });
  
  // Live rooms
  app.post('/api/live/create', (req, res) => {
    res.json(createLiveRoom(req.body));
  });
  app.post('/api/live/:id/join', (req, res) => {
    try { res.json(joinLiveAsGuest(req.params.id, req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.get('/api/live/active', (req, res) => {
    res.json({ rooms: Array.from(liveRooms.values()).filter(r => r.status === 'live') });
  });
  
  // Shopping
  app.post('/api/shop/pin', (req, res) => {
    res.json(pinProductToVideo(req.body));
  });
  app.get('/api/shop/video/:videoId', (req, res) => {
    const pins = Array.from(shopPins.values()).filter(p => p.videoId === req.params.videoId);
    res.json({ videoId: req.params.videoId, pins });
  });
  
  // Sounds
  app.get('/api/sounds/trending', (req, res) => {
    res.json({ sounds: getTrendingSounds(parseInt(req.query.limit) || 20) });
  });
  app.post('/api/sounds/:id/use', (req, res) => {
    const sound = useSound(req.params.id);
    if (!sound) return res.status(404).json({ error: 'Sound not found' });
    res.json(sound);
  });
  
  // Feature overview
  app.get('/api/features', (req, res) => {
    res.json({
      platform: 'NVME',
      version: '2.1.0',
      revenue: getRevenueSplit(),
      features: {
        coins: { endpoint: '/api/coins/packages', packages: COIN_PACKAGES.length },
        battles: { endpoint: '/api/battles/formats', formats: Object.keys(BATTLE_FORMATS), maxParticipants: 20 },
        fyp: { endpoint: '/api/fyp/:userId', algorithm: 'TikTok-style with transparency' },
        duet: { endpoint: '/api/duet', layouts: ['side-by-side', 'top-bottom', 'pip'] },
        stitch: { endpoint: '/api/stitch', revenueShare: { original: 0.20, reactor: 0.80 } },
        challenges: { endpoint: '/api/challenges/active', prizePoolSupported: true },
        analytics: { endpoint: '/api/analytics/creator/:id' },
        liveRooms: { endpoint: '/api/live/active', maxGuests: 19 },
        shop: { endpoint: '/api/shop/video/:videoId', platformFee: 0.05, creatorCommission: 0.15 },
        sounds: { endpoint: '/api/sounds/trending', soundEmpireIntegrated: true }
      }
    });
  });
}

module.exports = {
  setupRoutes,
  getRevenueSplit,
  calculatePayout,
  COIN_PACKAGES,
  BATTLE_FORMATS,
  createBattle,
  getCreatorAnalytics
};
