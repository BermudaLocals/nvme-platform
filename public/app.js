// NVME PWA - Mobile Creator Platform
// Connects to all /api endpoints on nvme.live

const API = '/api';
const state = {
  currentPage: 'home',
  user: null,
  coins: 0,
  gifts: [],
  feed: [],
  lives: [],
  battles: [],
  installPrompt: null,
};

// ========== UTILITY ==========
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function toast(msg, duration = 2500) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), duration);
}

async function api(path, opts = {}) {
  try {
    const res = await fetch(API + path, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    return await res.json();
  } catch (e) {
    console.error('API error:', path, e);
    return null;
  }
}

function avatarColor(seed = '') {
  const colors = [
    'linear-gradient(135deg, #ff0050, #00f2ea)',
    'linear-gradient(135deg, #a855f7, #ff0050)',
    'linear-gradient(135deg, #ffd700, #ff8800)',
    'linear-gradient(135deg, #00f2ea, #0066ff)',
    'linear-gradient(135deg, #10b981, #0ea5e9)',
    'linear-gradient(135deg, #f97316, #ef4444)',
  ];
  const idx = seed.charCodeAt(0) % colors.length || 0;
  return colors[idx];
}

// ========== PAGES ==========

// HOME - For You Feed
async function renderHome() {
  const container = $('#page-container');
  container.innerHTML = `
    <div class="page">
      <div class="feed-tabs">
        <button class="feed-tab" data-tab="following">Following</button>
        <button class="feed-tab active" data-tab="foryou">For You</button>
      </div>
      <div class="feed" id="feed">
        <div class="loader"><div class="loader-spinner"></div></div>
      </div>
    </div>
  `;
  loadFeed();
}

async function loadFeed() {
  // Fetch sample content + trending sounds to populate feed
  const feed = $('#feed');
  const [activity, sounds, battles] = await Promise.all([
    api('/activity'),
    api('/sounds/trending'),
    api('/battles/active'),
  ]);

  const items = [];
  
  // Add battle promo cards
  if (battles && battles.battles && battles.battles.length) {
    battles.battles.slice(0, 2).forEach(b => items.push({ type: 'battle', data: b }));
  }
  
  // Fill with sample video cards
  const samples = [
    { username: '@sovereign5', caption: 'Launching NVME today 🚀 #creator #platform', sound: 'Original Sound - NVME', likes: '24.5K', comments: '1.2K', shares: '3.4K' },
    { username: '@ital_phoenix', caption: 'Phoenix Rise drops tomorrow 🔥 #reggae #conscious', sound: 'Phoenix Rise - ITAL PHOENIX', likes: '18.2K', comments: '892', shares: '2.1K' },
    { username: '@creator_king', caption: '10v10 battle tonight at 8pm EST! Who you got? 🏆', sound: 'Epic Battle Beat', likes: '45.1K', comments: '3.4K', shares: '8.9K' },
    { username: '@money_maker', caption: 'NVME pays 55% vs TikTok 50% 💰 Switch today', sound: 'Original Sound - Money', likes: '67.8K', comments: '5.6K', shares: '12.3K' },
    { username: '@gift_goddess', caption: '606 gifts on NVME! Send me your favorites 🎁', sound: 'Gift Unboxing', likes: '34.7K', comments: '2.1K', shares: '5.4K' },
  ];
  samples.forEach(s => items.push({ type: 'video', data: s }));

  feed.innerHTML = items.map((item, i) => {
    if (item.type === 'battle') {
      const b = item.data;
      return `
        <div class="feed-item">
          <div style="position:absolute;inset:0;background:linear-gradient(135deg,#1a0033,#330066);"></div>
          <div class="feed-gradient"></div>
          <div style="position:absolute;top:40%;left:50%;transform:translate(-50%,-50%);text-align:center;z-index:2;">
            <div style="font-size:48px;margin-bottom:12px;">⚔️</div>
            <div style="font-size:24px;font-weight:900;margin-bottom:8px;">${b.format || '1v1'} BATTLE</div>
            <div style="font-size:14px;opacity:0.8;margin-bottom:20px;">LIVE NOW</div>
            <button onclick="joinBattle('${b.id || 'demo'}')" style="background:linear-gradient(135deg,#ff0050,#00f2ea);border:none;color:#fff;padding:14px 32px;border-radius:24px;font-weight:700;font-size:16px;cursor:pointer;">Join Battle</button>
          </div>
        </div>
      `;
    }
    const v = item.data;
    const bg = avatarColor(v.username);
    return `
      <div class="feed-item">
        <div style="position:absolute;inset:0;background:${bg};opacity:0.3;"></div>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:72px;opacity:0.2;">🎬</div>
        <div class="feed-gradient"></div>
        <div class="feed-info">
          <div class="feed-username">${v.username}</div>
          <div class="feed-caption">${v.caption}</div>
          <div class="feed-sound">♪ ${v.sound}</div>
        </div>
        <div class="feed-avatar" style="background:${bg};"></div>
        <div class="feed-actions">
          <div class="feed-action">
            <button class="feed-action-btn" onclick="likeVideo(${i})">
              <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg>
            </button>
            <div class="feed-action-label">${v.likes}</div>
          </div>
          <div class="feed-action">
            <button class="feed-action-btn" onclick="openComments(${i})">
              <svg viewBox="0 0 24 24" fill="currentColor"><path d="M21 6h-2v9H6v2c0 .55.45 1 1 1h11l4 4V7c0-.55-.45-1-1-1zm-4 6V3c0-.55-.45-1-1-1H3c-.55 0-1 .45-1 1v14l4-4h10c.55 0 1-.45 1-1z"/></svg>
            </button>
            <div class="feed-action-label">${v.comments}</div>
          </div>
          <div class="feed-action">
            <button class="feed-action-btn" onclick="openGifts(${i})" style="background:linear-gradient(135deg,#ff0050,#00f2ea);">
              <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-2.18c.11-.31.18-.65.18-1 0-1.66-1.34-3-3-3-1.05 0-1.96.54-2.5 1.35l-.5.67-.5-.68C10.96 2.54 10.05 2 9 2 7.34 2 6 3.34 6 5c0 .35.07.69.18 1H4c-1.11 0-1.99.89-1.99 2L2 19c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2zm-5-2c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zM9 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm11 15H4v-2h16v2zm0-5H4V8h5.08L7 10.83 8.62 12 11 8.76l1-1.36 1 1.36L15.38 12 17 10.83 14.92 8H20v6z"/></svg>
            </button>
            <div class="feed-action-label">Gift</div>
          </div>
          <div class="feed-action">
            <button class="feed-action-btn" onclick="shareVideo(${i})">
              <svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z"/></svg>
            </button>
            <div class="feed-action-label">${v.shares}</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Tab switches
  $$('.feed-tab').forEach(btn => {
    btn.onclick = () => {
      $$('.feed-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    };
  });
}

// DISCOVER
async function renderDiscover() {
  const container = $('#page-container');
  container.innerHTML = `
    <div class="page">
      <div class="page-header">
        <div class="page-title">Discover</div>
        <button class="page-header-btn" onclick="openChallenges()">Challenges</button>
      </div>
      <div class="discover-search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
        <input placeholder="Search creators, sounds, hashtags" />
      </div>
      <div class="trending-strip">
        <div class="trending-title">🔥 Trending Now</div>
        <div class="trending-scroll" id="trending-tags">
          <div class="loader"><div class="loader-spinner"></div></div>
        </div>
      </div>
      <div class="trending-strip">
        <div class="trending-title">🎵 Trending Sounds</div>
        <div class="trending-scroll" id="trending-sounds"></div>
      </div>
      <div style="padding:0 16px;">
        <div class="trending-title">🎬 Popular Videos</div>
        <div class="discover-grid" id="discover-grid"></div>
      </div>
    </div>
  `;
  loadDiscover();
}

async function loadDiscover() {
  const [challenges, sounds] = await Promise.all([
    api('/challenges/active'),
    api('/sounds/trending'),
  ]);
  
  const tags = ['#NVMELaunch', '#10v10Battle', '#CreatorFreedom', '#55PercentPayout', '#NoShadowban', '#NVMECoin'];
  $('#trending-tags').innerHTML = tags.map((t, i) => 
    `<button class="trending-pill ${i < 2 ? 'hot' : ''}" onclick="searchTag('${t}')">${t}</button>`
  ).join('');

  const soundList = (sounds && sounds.sounds) || [
    { title: 'Phoenix Rise', artist: 'ITAL PHOENIX' },
    { title: 'Battle Anthem', artist: 'NVME Labs' },
    { title: 'Gift Unboxing', artist: 'NVME Labs' },
    { title: 'Creator Vibe', artist: 'Sound Empire' },
  ];
  $('#trending-sounds').innerHTML = soundList.map(s => 
    `<button class="trending-pill">♪ ${s.title} - ${s.artist}</button>`
  ).join('');

  const grid = $('#discover-grid');
  const thumbs = ['🎬','🔥','⚔️','🎁','💰','🎵','🎭','🏆'];
  grid.innerHTML = thumbs.map((emoji, i) => `
    <div class="discover-item" onclick="openVideo(${i})" style="background:${avatarColor(String(i))};">
      <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:48px;opacity:0.5;">${emoji}</div>
      <div class="discover-item-gradient"></div>
      <div class="discover-item-info">
        <div class="discover-item-title">Video #${i + 1}</div>
        <div class="discover-item-views">👁 ${Math.floor(Math.random() * 999)}K views</div>
      </div>
    </div>
  `).join('');
}

// LIVE
async function renderLive() {
  const container = $('#page-container');
  container.innerHTML = `
    <div class="page">
      <div class="page-header">
        <div class="page-title">LIVE 🔴</div>
        <button class="page-header-btn" onclick="startLive()">Go Live</button>
      </div>
      <div class="trending-strip">
        <div class="trending-title">⚔️ Active Battles</div>
        <div id="active-battles"><div class="loader"><div class="loader-spinner"></div></div></div>
      </div>
      <div style="padding:0 8px;">
        <div class="trending-title" style="margin-left:8px;">🔴 Live Now</div>
        <div class="live-grid" id="live-grid"></div>
      </div>
    </div>
  `;
  loadLive();
}

async function loadLive() {
  const [battles, lives] = await Promise.all([
    api('/battles/active'),
    api('/live/active'),
  ]);

  // Active battles
  const battleList = (battles && battles.battles) || [];
  const demoBattles = battleList.length ? battleList : [
    { id: 'b1', format: '10v10', teamA: 'Team Phoenix', teamB: 'Team Kings', scoreA: 34210, scoreB: 28450, timer: '04:32' },
    { id: 'b2', format: '1v1', teamA: '@sovereign5', teamB: '@creator_king', scoreA: 12340, scoreB: 11890, timer: '02:15' },
  ];
  $('#active-battles').innerHTML = demoBattles.map(b => `
    <div class="battle-card" onclick="joinBattle('${b.id}')">
      <div class="battle-header">
        <div class="battle-format">${b.format} BATTLE</div>
        <div class="battle-timer">⏱ ${b.timer}</div>
      </div>
      <div class="battle-teams">
        <div class="battle-team">
          <div class="battle-team-name">${b.teamA}</div>
          <div class="battle-team-score">${b.scoreA.toLocaleString()}</div>
        </div>
        <div class="battle-vs">VS</div>
        <div class="battle-team">
          <div class="battle-team-name">${b.teamB}</div>
          <div class="battle-team-score">${b.scoreB.toLocaleString()}</div>
        </div>
      </div>
    </div>
  `).join('');

  // Live grid
  const liveList = (lives && lives.lives) || [];
  const demoLives = liveList.length ? liveList : [
    { id: 'l1', user: '@ital_phoenix', title: 'Phoenix Rise listening party', viewers: '12.4K' },
    { id: 'l2', user: '@sovereign5', title: 'Building NVME live', viewers: '8.2K' },
    { id: 'l3', user: '@money_maker', title: '10v10 battle training', viewers: '15.7K' },
    { id: 'l4', user: '@gift_goddess', title: 'Gift unboxing spree', viewers: '23.1K' },
    { id: 'l5', user: '@creator_king', title: 'Late night stream', viewers: '9.8K' },
    { id: 'l6', user: '@music_maven', title: 'Sound Empire session', viewers: '6.5K' },
  ];
  $('#live-grid').innerHTML = demoLives.map((l, i) => `
    <div class="live-card" onclick="joinLive('${l.id}')" style="background:${avatarColor(l.user)};">
      <div class="live-badge">LIVE</div>
      <div class="live-viewers">👁 ${l.viewers}</div>
      <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:64px;opacity:0.4;">🎥</div>
      <div class="live-card-info">
        <div class="live-card-user">
          <div class="live-card-avatar"></div>
          <div>
            <div class="live-card-username">${l.user}</div>
            <div class="live-card-title">${l.title}</div>
          </div>
        </div>
      </div>
    </div>
  `).join('');
}

// PROFILE
async function renderProfile() {
  const container = $('#page-container');
  const user = state.user || { name: 'Guest', handle: '@guest', bio: 'Welcome to NVME!', followers: 0, following: 0, likes: 0 };
  
  container.innerHTML = `
    <div class="page">
      <div class="page-header">
        <div class="page-title">${user.handle}</div>
        <button class="page-header-btn" onclick="openSettings()">⚙</button>
      </div>
      <div class="profile-header">
        <div class="profile-avatar"></div>
        <div class="profile-username">${user.name}</div>
        <div class="profile-handle">${user.handle}</div>
        <div class="profile-stats">
          <div class="profile-stat">
            <div class="profile-stat-num">${user.following}</div>
            <div class="profile-stat-label">Following</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-num">${user.followers}</div>
            <div class="profile-stat-label">Followers</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-num">${user.likes}</div>
            <div class="profile-stat-label">Likes</div>
          </div>
        </div>
        <div class="profile-bio">${user.bio}</div>
      </div>
      <div class="profile-actions">
        <button class="btn-primary" onclick="openSignup()">Sign Up / Login</button>
        <button class="btn-secondary" onclick="openTikTokImport()">Import TikTok</button>
      </div>
      <div class="profile-actions">
        <button class="btn-secondary" onclick="openCoinShop()">💰 Get Coins (${state.coins})</button>
        <button class="btn-secondary" onclick="openAnalytics()">📊 Analytics</button>
      </div>
      <div class="profile-tabs">
        <button class="profile-tab active" data-tab="videos">Videos</button>
        <button class="profile-tab" data-tab="liked">Liked</button>
        <button class="profile-tab" data-tab="earnings">Earnings</button>
      </div>
      <div class="profile-grid" id="profile-grid">
        ${Array.from({length: 9}).map((_, i) => `
          <div class="profile-grid-item" style="background:${avatarColor(String(i))};">
            <div style="height:100%;display:flex;align-items:center;justify-content:center;font-size:36px;opacity:0.4;">🎬</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  $$('.profile-tab').forEach(btn => {
    btn.onclick = () => {
      $$('.profile-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (btn.dataset.tab === 'earnings') showEarnings();
    };
  });
}

async function showEarnings() {
  const split = await api('/revenue/split');
  const grid = $('#profile-grid');
  if (split) {
    grid.innerHTML = `
      <div style="grid-column:1/-1;padding:24px;">
        <div style="background:rgba(255,255,255,0.05);border-radius:16px;padding:20px;text-align:center;">
          <div style="font-size:12px;opacity:0.6;margin-bottom:8px;">REVENUE SPLIT</div>
          <div style="font-size:32px;font-weight:900;background:linear-gradient(135deg,#ff0050,#00f2ea);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px;">${(split.creatorShare*100).toFixed(0)}% YOURS</div>
          <div style="font-size:13px;opacity:0.8;margin-bottom:16px;">${split.advantageVsTikTok}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px;">
            <div style="background:rgba(255,0,80,0.1);padding:12px;border-radius:8px;">
              <div style="font-size:11px;opacity:0.7;">TikTok Cut</div>
              <div style="font-size:20px;font-weight:700;color:#ff0050;">${(split.tiktokCut*100).toFixed(0)}%</div>
            </div>
            <div style="background:rgba(0,242,234,0.1);padding:12px;border-radius:8px;">
              <div style="font-size:11px;opacity:0.7;">NVME Cut</div>
              <div style="font-size:20px;font-weight:700;color:#00f2ea;">${(split.platformCut*100).toFixed(0)}%</div>
            </div>
          </div>
          <div style="margin-top:16px;font-size:12px;opacity:0.6;">${split.daysRemainingInLaunch} days left at launch rate</div>
        </div>
      </div>
    `;
  }
}

// ========== MODALS & INTERACTIONS ==========

function openCreateModal() {
  const modal = document.createElement('div');
  modal.className = 'create-modal';
  modal.id = 'create-modal';
  modal.innerHTML = `
    <div class="create-header">
      <div class="create-title">Create</div>
      <button class="create-close" onclick="closeCreateModal()">✕</button>
    </div>
    <div class="create-options">
      <button class="create-option" onclick="startVideoCreate()">
        <div class="create-option-icon video">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 10.5V7a1 1 0 00-1-1H4a1 1 0 00-1 1v10a1 1 0 001 1h12a1 1 0 001-1v-3.5l4 4v-11l-4 4z"/></svg>
        </div>
        <div class="create-option-text">
          <div class="create-option-title">Post Video</div>
          <div class="create-option-desc">Record or upload - any length, no limits</div>
        </div>
      </button>
      <button class="create-option" onclick="startLive()">
        <div class="create-option-icon live">
          <svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="8"/></svg>
        </div>
        <div class="create-option-text">
          <div class="create-option-title">Go LIVE</div>
          <div class="create-option-desc">Invite up to 19 co-hosts</div>
        </div>
      </button>
      <button class="create-option" onclick="startBattle()">
        <div class="create-option-icon battle">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6.92 5L5 6.92l4.34 4.34 1.92-1.92L6.92 5zM19 12.66V4h-8.66l2 2h4.24l-8.37 8.37 1.41 1.41L17.99 7.41v4.24l1.01 1.01zM20.29 18.71l-4.95-4.95-1.41 1.41 4.95 4.95c.2.2.51.2.71 0l.71-.71c.19-.19.19-.51-.01-.7z"/></svg>
        </div>
        <div class="create-option-text">
          <div class="create-option-title">Start Battle</div>
          <div class="create-option-desc">1v1 to 10v10 - pick your format</div>
        </div>
      </button>
      <button class="create-option" onclick="startChallenge()">
        <div class="create-option-icon challenge">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/></svg>
        </div>
        <div class="create-option-text">
          <div class="create-option-title">Launch Challenge</div>
          <div class="create-option-desc">Add prize pool, get viral</div>
        </div>
      </button>
    </div>
  `;
  document.body.appendChild(modal);
}

function closeCreateModal() {
  const m = $('#create-modal');
  if (m) m.remove();
}

async function openGifts(videoIdx) {
  const drawer = document.createElement('div');
  drawer.className = 'gift-drawer';
  drawer.id = 'gift-drawer';
  drawer.innerHTML = `
    <div class="gift-drawer-header">
      <div style="font-size:17px;font-weight:700;">Send a Gift</div>
      <div class="gift-balance">💰 ${state.coins} coins</div>
    </div>
    <div class="gift-grid" id="gift-grid">
      <div class="loader"><div class="loader-spinner"></div></div>
    </div>
  `;
  document.body.appendChild(drawer);
  setTimeout(() => drawer.classList.add('open'), 10);

  const giftData = await api('/gifts');
  const gifts = (giftData && giftData.gifts) || [];
  
  $('#gift-grid').innerHTML = gifts.slice(0, 40).map(g => `
    <div class="gift-item" onclick="sendGift('${g.id || g.name}', ${g.cost || 10})">
      <div class="gift-emoji">${g.emoji || '🎁'}</div>
      <div class="gift-name">${g.name}</div>
      <div class="gift-cost">${g.cost || 10} 💰</div>
    </div>
  `).join('');

  drawer.addEventListener('click', e => {
    if (e.target === drawer) {
      drawer.classList.remove('open');
      setTimeout(() => drawer.remove(), 300);
    }
  });
}

async function sendGift(giftId, cost) {
  if (state.coins < cost) {
    toast('Not enough coins. Tap profile to buy more 💰');
    return;
  }
  state.coins -= cost;
  toast(`🎁 Sent! -${cost} coins`);
  const drawer = $('#gift-drawer');
  if (drawer) {
    drawer.classList.remove('open');
    setTimeout(() => drawer.remove(), 300);
  }
}

async function openCoinShop() {
  const data = await api('/coins/packages');
  const packs = (data && data.packages) || [];
  const modal = document.createElement('div');
  modal.className = 'create-modal';
  modal.id = 'coin-modal';
  modal.innerHTML = `
    <div class="create-header">
      <div class="create-title">Get Coins</div>
      <button class="create-close" onclick="closeCoinModal()">✕</button>
    </div>
    <div class="coin-packages">
      ${packs.map(p => `
        <button class="coin-pack ${p.popular ? 'popular' : ''}" onclick="buyCoins('${p.id}', ${p.coins + (p.bonus||0)}, ${p.priceUSD})">
          <div class="coin-pack-left">
            <div class="coin-pack-icon">💰</div>
            <div class="coin-pack-info">
              <h4>${p.name}</h4>
              <div class="coin-pack-coins">${p.coins.toLocaleString()} coins${p.bonus ? ` +${p.bonus} bonus` : ''}</div>
            </div>
          </div>
          <div class="coin-pack-price">$${p.priceUSD}</div>
        </button>
      `).join('')}
    </div>
  `;
  document.body.appendChild(modal);
}

function closeCoinModal() {
  const m = $('#coin-modal');
  if (m) m.remove();
}

function buyCoins(id, coins, price) {
  toast(`Processing $${price} payment...`);
  // In production: call /api/payments/checkout with stripe/paypal
  setTimeout(() => {
    state.coins += coins;
    toast(`✅ ${coins} coins added!`);
    closeCoinModal();
  }, 1500);
}

async function openTikTokImport() {
  const config = await api('/tiktok/config');
  const modal = document.createElement('div');
  modal.className = 'create-modal';
  modal.id = 'tiktok-modal';
  const ready = config && config.configured;
  modal.innerHTML = `
    <div class="create-header">
      <div class="create-title">Import TikTok</div>
      <button class="create-close" onclick="closeTikTokModal()">✕</button>
    </div>
    <div style="padding:24px;text-align:center;">
      <div style="font-size:64px;margin-bottom:16px;">📥</div>
      <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Connect Your TikTok</div>
      <div style="font-size:14px;opacity:0.7;margin-bottom:24px;line-height:1.5;">Import your profile, video count, follower count, and earn a verified badge on NVME.</div>
      ${ready ? `
        <button class="btn-primary" onclick="connectTikTok()" style="padding:14px 32px;font-size:16px;">Connect TikTok Account</button>
      ` : `
        <div style="background:rgba(255,215,0,0.1);border:1px solid rgba(255,215,0,0.3);padding:16px;border-radius:12px;margin-top:16px;text-align:left;">
          <div style="font-size:13px;font-weight:600;color:#ffd700;margin-bottom:4px;">⚠ TikTok OAuth Not Configured</div>
          <div style="font-size:12px;opacity:0.8;line-height:1.5;">Admin needs to add TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET to .env file.</div>
        </div>
      `}
      <div style="margin-top:32px;font-size:12px;opacity:0.6;line-height:1.6;">
        <div>✓ Your follower count</div>
        <div>✓ Your video stats</div>
        <div>✓ Verified badge transfer</div>
        <div>✓ Auto-detect mega creator tier</div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
}

function closeTikTokModal() {
  const m = $('#tiktok-modal');
  if (m) m.remove();
}

async function connectTikTok() {
  const res = await api('/tiktok/connect');
  if (res && res.authUrl) {
    window.location.href = res.authUrl;
  } else {
    toast('TikTok connection unavailable');
  }
}

// ========== ACTIONS (called from onclick) ==========
window.likeVideo = (i) => toast('❤️ Liked!');
window.openComments = (i) => toast('💬 Comments coming soon');
window.shareVideo = (i) => {
  if (navigator.share) navigator.share({ title: 'NVME', url: window.location.href });
  else toast('🔗 Link copied');
};
window.joinBattle = (id) => toast(`⚔️ Joining battle ${id}...`);
window.joinLive = (id) => toast(`🔴 Joining live ${id}...`);
window.openVideo = (i) => toast(`▶️ Playing video ${i + 1}`);
window.searchTag = (tag) => toast(`🔍 Searching ${tag}`);
window.openChallenges = () => toast('🏆 Challenges page coming soon');
window.startLive = () => { closeCreateModal(); toast('🔴 Go LIVE coming soon'); };
window.startBattle = () => { closeCreateModal(); toast('⚔️ Battle creator coming soon'); };
window.startVideoCreate = () => { closeCreateModal(); toast('🎬 Video creator coming soon'); };
window.startChallenge = () => { closeCreateModal(); toast('🏆 Challenge creator coming soon'); };
window.openSignup = () => toast('🔐 Signup coming soon');
window.openSettings = () => toast('⚙️ Settings coming soon');
window.openAnalytics = async () => {
  const a = await api('/analytics/creator/demo');
  toast(`📊 Views: ${a?.analytics?.views || 0}`);
};
window.openGifts = openGifts;
window.sendGift = sendGift;
window.openCoinShop = openCoinShop;
window.closeCoinModal = closeCoinModal;
window.buyCoins = buyCoins;
window.openTikTokImport = openTikTokImport;
window.closeTikTokModal = closeTikTokModal;
window.connectTikTok = connectTikTok;
window.closeCreateModal = closeCreateModal;

// ========== ROUTER ==========
const pages = { home: renderHome, discover: renderDiscover, live: renderLive, profile: renderProfile };

function navigate(page) {
  if (page === 'create') {
    openCreateModal();
    return;
  }
  state.currentPage = page;
  $$('.nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.page === page);
  });
  if (pages[page]) pages[page]();
}

// ========== INIT ==========
async function init() {
  // Set up navigation
  $$('.nav-btn').forEach(btn => {
    btn.onclick = () => navigate(btn.dataset.page);
  });

  // Verify API is live
  const health = await api('/health');
  if (health) {
    console.log('NVME API online:', health.version);
  }

  // Hide splash, show main
  setTimeout(() => {
    $('#splash').classList.add('hidden');
    $('#main').classList.remove('hidden');
    navigate('home');
  }, 1200);
}

// PWA Install
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  state.installPrompt = e;
  // Show install banner if not dismissed
  if (!localStorage.getItem('nvme_install_dismissed')) {
    const banner = document.createElement('div');
    banner.className = 'install-banner';
    banner.innerHTML = `
      <span>📱 Install NVME for the best experience</span>
      <div>
        <button onclick="installApp()">Install</button>
        <button onclick="dismissInstall()" style="background:transparent;margin-left:4px;">✕</button>
      </div>
    `;
    document.body.appendChild(banner);
  }
});

window.installApp = async () => {
  if (state.installPrompt) {
    state.installPrompt.prompt();
    const { outcome } = await state.installPrompt.userChoice;
    if (outcome === 'accepted') toast('✅ Installing...');
    state.installPrompt = null;
    document.querySelector('.install-banner')?.remove();
  }
};

window.dismissInstall = () => {
  localStorage.setItem('nvme_install_dismissed', '1');
  document.querySelector('.install-banner')?.remove();
};

// iOS install hint (Safari doesn't support beforeinstallprompt)
function showIOSInstallHint() {
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
  const isStandalone = window.navigator.standalone;
  if (isIOS && !isStandalone && !localStorage.getItem('nvme_ios_hint_dismissed')) {
    setTimeout(() => {
      const banner = document.createElement('div');
      banner.className = 'install-banner';
      banner.innerHTML = `
        <span>📱 Tap Share → Add to Home Screen</span>
        <button onclick="dismissIOSHint()">✕</button>
      `;
      document.body.appendChild(banner);
    }, 3000);
  }
}

window.dismissIOSHint = () => {
  localStorage.setItem('nvme_ios_hint_dismissed', '1');
  document.querySelector('.install-banner')?.remove();
};

document.addEventListener('DOMContentLoaded', () => {
  init();
  showIOSInstallHint();
});
