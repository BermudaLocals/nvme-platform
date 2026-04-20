// NVME Platform - 500+ Gift System with Holiday Themes
// Auto-switches gifts based on current holiday

const HOLIDAY_CONFIG = {
  default: { name: 'Standard', theme: 'neon-tokyo', css: 'theme-neon.css' },
  valentines: { name: "Valentine's Day", theme: 'romance-pink', css: 'theme-valentine.css', months: [1], days: [1, 28] },
  stpatricks: { name: "St. Patrick's Day", theme: 'irish-green', css: 'theme-stpatricks.css', months: [2], days: [1, 20] },
  easter: { name: 'Easter', theme: 'pastel-rainbow', css: 'theme-easter.css', months: [2, 3], days: [21, 25] },
  mothersday: { name: "Mother's Day", theme: 'spring-floral', css: 'theme-mothers.css', months: [4], days: [1, 14] },
  fathersday: { name: "Father's Day", theme: 'nautical-blue', css: 'theme-fathers.css', months: [5], days: [1, 21] },
  halloween: { name: 'Halloween', theme: 'horror-purple', css: 'theme-halloween.css', months: [9], days: [1, 31] },
  thanksgiving: { name: 'Thanksgiving', theme: 'autumn-gold', css: 'theme-thanksgiving.css', months: [10], days: [1, 30] },
  christmas: { name: 'Christmas', theme: 'xmas-red', css: 'theme-christmas.css', months: [11], days: [1, 26] },
  newyear: { name: 'New Year', theme: 'fireworks-gold', css: 'theme-newyear.css', months: [11, 0], days: [27, 15] }
};

function getCurrentHoliday() {
  const now = new Date();
  const month = now.getMonth();
  const day = now.getDate();
  
  for (const [key, config] of Object.entries(HOLIDAY_CONFIG)) {
    if (key === 'default') continue;
    if (config.months.includes(month)) {
      if (key === 'newyear') {
        if ((month === 11 && day >= 27) || (month === 0 && day <= 15)) return key;
      } else if (day >= config.days[0] && day <= config.days[1]) {
        return key;
      }
    }
  }
  return 'default';
}

// Generate 500+ gifts from templates
function generateGifts() {
  const gifts = [];
  const categories = {
    sparks: { baseCredits: 5, multiplier: 2, count: 50 },
    love: { baseCredits: 10, multiplier: 1.5, count: 40 },
    luxury: { baseCredits: 25, multiplier: 3, count: 45 },
    nature: { baseCredits: 8, multiplier: 1.8, count: 35 },
    party: { baseCredits: 6, multiplier: 1.6, count: 38 },
    gaming: { baseCredits: 12, multiplier: 2.5, count: 42 },
    music: { baseCredits: 7, multiplier: 1.4, count: 35 },
    arts: { baseCredits: 9, multiplier: 1.6, count: 30 },
    social: { baseCredits: 4, multiplier: 1.2, count: 45 },
    tiktok: { baseCredits: 3, multiplier: 1.1, count: 40 },
    food: { baseCredits: 5, multiplier: 1.3, count: 35 },
    travel: { baseCredits: 15, multiplier: 2.2, count: 30 },
    fitness: { baseCredits: 6, multiplier: 1.5, count: 25 },
    tech: { baseCredits: 20, multiplier: 2.8, count: 28 },
    fantasy: { baseCredits: 18, multiplier: 2.4, count: 32 }
  };

  const rarityMultipliers = {
    common: 1,
    rare: 2.5,
    epic: 6,
    legendary: 15,
    mythic: 50
  };

  let idCounter = 1;

  Object.entries(categories).forEach(([category, config]) => {
    for (let i = 0; i < config.count; i++) {
      const rarityRoll = Math.random();
      let rarity = 'common';
      if (rarityRoll > 0.98) rarity = 'mythic';
      else if (rarityRoll > 0.90) rarity = 'legendary';
      else if (rarityRoll > 0.70) rarity = 'epic';
      else if (rarityRoll > 0.40) rarity = 'rare';

      const basePrice = Math.floor(config.baseCredits * config.multiplier * (i + 1) * 0.5);
      const credits = Math.max(1, Math.floor(basePrice * rarityMultipliers[rarity] / 10));

      gifts.push({
        id: `${category}-${idCounter++}`,
        name: `${category.charAt(0).toUpperCase() + category.slice(1)} ${i + 1}`,
        credits: credits,
        rarity: rarity,
        category: category,
        icon: getCategoryIcon(category),
        animated: rarity === 'legendary' || rarity === 'mythic',
        particle: rarity === 'mythic' ? 'rainbow-explosion' : 
                  rarity === 'legendary' ? 'gold-shower' :
                  rarity === 'epic' ? 'sparkle-burst' :
                  rarity === 'rare' ? 'glow-pulse' : 'simple'
      });
    }
  });

  // Add holiday-specific gifts
  const holidays = {
    valentines: ['Rose Bouquet', 'Valentine Heart', 'Love Letter', 'Cupid Arrow', 'Romance Dinner', 'Chocolate Box', 'Teddy Bear', 'Diamond Ring', 'Kiss Mark'],
    stpatricks: ['Leprechaun', 'Pot of Gold', 'Lucky Rainbow', 'Four Leaf Clover', 'Green Beer', 'Irish Dance', 'Celtic Knot', 'Horseshoe'],
    easter: ['Painted Egg', 'Easter Basket', 'Chocolate Bunny', 'Easter Bunny', 'Marshmallow Peeps', 'Spring Daffodil', 'Baby Chick', 'Easter Bonnet'],
    halloween: ['Jack OLantern', 'Ghost', 'Witch', 'Vampire', 'Skeleton', 'Candy Corn', 'Spider', 'Bat', 'Haunted House'],
    thanksgiving: ['Turkey', 'Pumpkin Pie', 'Cornucopia', 'Autumn Leaves', 'Harvest Moon', 'Family Feast', 'Gratitude Heart'],
    christmas: ['Santa Claus', 'Reindeer', 'Christmas Tree', 'Stocking', 'Snowman', 'Ornament', 'Gift Box', 'Mistletoe'],
    newyear: ['Fireworks', 'Ball Drop', 'Champagne', 'Confetti Rain', 'Countdown', 'Party Hat', 'Resolution']
  };

  Object.entries(holidays).forEach(([holiday, items]) => {
    items.forEach((item, idx) => {
      gifts.push({
        id: `${holiday}-${idx}`,
        name: item,
        credits: Math.floor(10 + (idx * 15)),
        rarity: idx > items.length - 3 ? 'epic' : 'rare',
        category: 'holiday',
        icon: '🎁',
        holiday: holiday,
        animated: false,
        particle: 'holiday-sparkle'
      });
    });
  });

  return gifts;
}

function getCategoryIcon(category) {
  const icons = {
    sparks: '✨', love: '❤️', luxury: '💎', nature: '🌿', party: '🎉',
    gaming: '🎮', music: '🎵', arts: '🎨', social: '👥', tiktok: '📱',
    food: '🍕', travel: '✈️', fitness: '💪', tech: '⚡', fantasy: '🔮'
  };
  return icons[category] || '🎁';
}

const ALL_GIFTS = generateGifts();

function getAvailableGifts() {
  const currentHoliday = getCurrentHoliday();
  return {
    gifts: ALL_GIFTS,
    currentHoliday: currentHoliday,
    holidayConfig: HOLIDAY_CONFIG[currentHoliday],
    activeTheme: HOLIDAY_CONFIG[currentHoliday].css,
    evergreenCount: ALL_GIFTS.filter(g => !g.holiday).length,
    holidayCount: ALL_GIFTS.filter(g => g.holiday === currentHoliday).length,
    totalCount: ALL_GIFTS.length
  };
}

module.exports = {
  getAvailableGifts,
  getCurrentHoliday,
  HOLIDAY_CONFIG,
  ALL_GIFTS
};
