// ============================================================
// NVME.live — gifts.js  |  500 Animated Gifts System
// ============================================================

'use strict';

const NVME_GIFTS = [
  // STANDARD (50)
  {id:'rose',name:'Rose',emoji:'🌹',category:'standard',coins:1,usd:0.01,rarity:'common',animation:'float-up',color:'#ff4757',particles:true,sound:'whoosh'},
  {id:'heart',name:'Heart',emoji:'❤️',category:'standard',coins:2,usd:0.02,rarity:'common',animation:'float-up',color:'#ff4757',particles:true,sound:'pop'},
  {id:'star',name:'Star',emoji:'⭐',category:'standard',coins:5,usd:0.05,rarity:'common',animation:'spiral',color:'#ffd700',particles:true,sound:'sparkle'},
  {id:'diamond',name:'Diamond',emoji:'💎',category:'standard',coins:50,usd:0.50,rarity:'rare',animation:'bounce',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'crown',name:'Crown',emoji:'👑',category:'standard',coins:100,usd:1.00,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'rocket',name:'Rocket',emoji:'🚀',category:'standard',coins:200,usd:2.00,rarity:'epic',animation:'explode',color:'#7c3aed',particles:true,sound:'blast'},
  {id:'galaxy',name:'Galaxy',emoji:'🌌',category:'standard',coins:500,usd:5.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'empire',name:'Empire',emoji:'🏛️',category:'standard',coins:1000,usd:10.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'fire',name:'Fire',emoji:'🔥',category:'standard',coins:10,usd:0.10,rarity:'common',animation:'float-up',color:'#ff6b35',particles:true,sound:'crackle'},
  {id:'thunder',name:'Thunder',emoji:'⚡',category:'standard',coins:25,usd:0.25,rarity:'rare',animation:'lightning-strike',color:'#ffe600',particles:true,sound:'zap'},
  {id:'rainbow',name:'Rainbow',emoji:'🌈',category:'standard',coins:75,usd:0.75,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'unicorn',name:'Unicorn',emoji:'🦄',category:'standard',coins:150,usd:1.50,rarity:'epic',animation:'spiral',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'dragon',name:'Dragon',emoji:'🐉',category:'standard',coins:300,usd:3.00,rarity:'epic',animation:'explode',color:'#ff4757',particles:true,sound:'roar'},
  {id:'phoenix',name:'Phoenix',emoji:'🦅',category:'standard',coins:750,usd:7.50,rarity:'legendary',animation:'rainbow-burst',color:'#ff6b35',particles:true,sound:'epic'},
  {id:'kiss',name:'Kiss',emoji:'💋',category:'standard',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'pop'},
  {id:'clap',name:'Clap',emoji:'👏',category:'standard',coins:1,usd:0.01,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'clap'},
  {id:'100',name:'100',emoji:'💯',category:'standard',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'pop'},
  {id:'gem',name:'Gem',emoji:'💠',category:'standard',coins:20,usd:0.20,rarity:'common',animation:'spiral',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'trophy',name:'Trophy',emoji:'🏆',category:'standard',coins:80,usd:0.80,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'medal',name:'Medal',emoji:'🥇',category:'standard',coins:40,usd:0.40,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'bling'},
  {id:'lightning_bolt',name:'Lightning Bolt',emoji:'🌩️',category:'standard',coins:15,usd:0.15,rarity:'common',animation:'lightning-strike',color:'#ffe600',particles:true,sound:'zap'},
  {id:'sparkles',name:'Sparkles',emoji:'✨',category:'standard',coins:8,usd:0.08,rarity:'common',animation:'float-up',color:'#ffd700',particles:true,sound:'sparkle'},
  {id:'comet_trail',name:'Comet Trail',emoji:'☄️',category:'standard',coins:120,usd:1.20,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'planet',name:'Planet',emoji:'🪐',category:'standard',coins:180,usd:1.80,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'black_hole',name:'Black Hole',emoji:'🕳️',category:'standard',coins:400,usd:4.00,rarity:'legendary',animation:'galaxy-swirl',color:'#0a0a0f',particles:true,sound:'cosmic'},
  {id:'supernova',name:'Supernova',emoji:'💥',category:'standard',coins:600,usd:6.00,rarity:'legendary',animation:'explode',color:'#ffd700',particles:true,sound:'epic'},
  {id:'angel',name:'Angel',emoji:'👼',category:'standard',coins:30,usd:0.30,rarity:'common',animation:'float-up',color:'#ffffff',particles:true,sound:'harp'},
  {id:'devil',name:'Devil',emoji:'😈',category:'standard',coins:35,usd:0.35,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'evil'},
  {id:'magic_wand',name:'Magic Wand',emoji:'🪄',category:'standard',coins:45,usd:0.45,rarity:'common',animation:'spiral',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'infinity',name:'Infinity',emoji:'♾️',category:'standard',coins:250,usd:2.50,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'tornado_red',name:'Red Tornado',emoji:'🌪️',category:'standard',coins:60,usd:0.60,rarity:'rare',animation:'spiral',color:'#ff4757',particles:true,sound:'whoosh'},
  {id:'skull',name:'Skull',emoji:'💀',category:'standard',coins:90,usd:0.90,rarity:'rare',animation:'bounce',color:'#ffffff',particles:false,sound:'evil'},
  {id:'alien',name:'Alien',emoji:'👽',category:'standard',coins:70,usd:0.70,rarity:'rare',animation:'float-up',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'robot_heart',name:'Robot Heart',emoji:'🤖',category:'standard',coins:55,usd:0.55,rarity:'rare',animation:'bounce',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'wizard',name:'Wizard',emoji:'🧙',category:'standard',coins:130,usd:1.30,rarity:'epic',animation:'spiral',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'samurai',name:'Samurai',emoji:'⚔️',category:'standard',coins:160,usd:1.60,rarity:'epic',animation:'explode',color:'#ff4757',particles:true,sound:'slash'},
  {id:'ninja_star',name:'Ninja Star',emoji:'🌟',category:'standard',coins:20,usd:0.20,rarity:'common',animation:'spiral',color:'#ffd700',particles:true,sound:'whoosh'},
  {id:'bomb',name:'Bomb',emoji:'💣',category:'standard',coins:110,usd:1.10,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'crystal_ball',name:'Crystal Ball',emoji:'🔮',category:'standard',coins:190,usd:1.90,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'microphone',name:'Microphone',emoji:'🎤',category:'standard',coins:12,usd:0.12,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'mic_drop'},
  {id:'confetti',name:'Confetti',emoji:'🎉',category:'standard',coins:6,usd:0.06,rarity:'common',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'pop'},
  {id:'balloon',name:'Balloon',emoji:'🎈',category:'standard',coins:4,usd:0.04,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'pop'},
  {id:'gift_box',name:'Gift Box',emoji:'🎁',category:'standard',coins:18,usd:0.18,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:true,sound:'pop'},
  {id:'bow',name:'Bow',emoji:'🎀',category:'standard',coins:7,usd:0.07,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'handshake',name:'Handshake',emoji:'🤝',category:'standard',coins:9,usd:0.09,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'clap'},
  {id:'fist_bump',name:'Fist Bump',emoji:'👊',category:'standard',coins:11,usd:0.11,rarity:'common',animation:'explode',color:'#ff6b35',particles:true,sound:'punch'},
  {id:'peace',name:'Peace',emoji:'✌️',category:'standard',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'pop'},
  {id:'sunflower',name:'Sunflower',emoji:'🌻',category:'standard',coins:5,usd:0.05,rarity:'common',animation:'float-up',color:'#ffd700',particles:true,sound:'whoosh'},
  {id:'four_leaf',name:'Four Leaf Clover',emoji:'🍀',category:'standard',coins:14,usd:0.14,rarity:'common',animation:'spiral',color:'#00d4ff',particles:true,sound:'magic'},
  {id:'cherry_blossom',name:'Cherry Blossom',emoji:'🌸',category:'standard',coins:8,usd:0.08,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:true,sound:'whoosh'},

  // BERMUDA-THEMED (50)
  {id:'pink_sand',name:'Pink Sand',emoji:'🏖️',category:'bermuda',coins:25,usd:0.25,rarity:'bermuda',animation:'wave-pulse',color:'#ff6b9d',particles:true,sound:'waves'},
  {id:'longtail_bird',name:'Longtail Bird',emoji:'🦢',category:'bermuda',coins:40,usd:0.40,rarity:'bermuda',animation:'float-up',color:'#ffffff',particles:true,sound:'birds'},
  {id:'hogfish',name:'Hogfish',emoji:'🐠',category:'bermuda',coins:20,usd:0.20,rarity:'bermuda',animation:'wave-pulse',color:'#ff6b35',particles:true,sound:'splash'},
  {id:'bermuda_triangle',name:'Bermuda Triangle',emoji:'🔺',category:'bermuda',coins:500,usd:5.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'coral_reef',name:'Coral Reef',emoji:'🪸',category:'bermuda',coins:30,usd:0.30,rarity:'bermuda',animation:'coral-grow',color:'#ff6b9d',particles:true,sound:'bubbles'},
  {id:'bermuda_shorts',name:'Bermuda Shorts',emoji:'🩳',category:'bermuda',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'royal_palms',name:'Royal Palms',emoji:'🌴',category:'bermuda',coins:15,usd:0.15,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'breeze'},
  {id:'blue_hole',name:'Blue Hole',emoji:'🌀',category:'bermuda',coins:200,usd:2.00,rarity:'epic',animation:'galaxy-swirl',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'bermuda_onion',name:'Bermuda Onion',emoji:'🧅',category:'bermuda',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'devil_isle',name:'Devils Isle',emoji:'🏝️',category:'bermuda',coins:100,usd:1.00,rarity:'epic',animation:'wave-pulse',color:'#ff4757',particles:true,sound:'thunder'},
  {id:'cedar_tree',name:'Cedar Tree',emoji:'🌲',category:'bermuda',coins:18,usd:0.18,rarity:'bermuda',animation:'float-up',color:'#00d4ff',particles:true,sound:'breeze'},
  {id:'gombey_dancer',name:'Gombey Dancer',emoji:'💃',category:'bermuda',coins:80,usd:0.80,rarity:'bermuda',animation:'gombey-dance',color:'#ff6b9d',particles:true,sound:'drums'},
  {id:'bermuda_flag',name:'Bermuda Flag',emoji:'🚩',category:'bermuda',coins:50,usd:0.50,rarity:'bermuda',animation:'wave-pulse',color:'#ff4757',particles:false,sound:'fanfare'},
  {id:'glass_beach',name:'Glass Beach',emoji:'💎',category:'bermuda',coins:60,usd:0.60,rarity:'bermuda',animation:'bounce',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'sea_glass',name:'Sea Glass',emoji:'🔵',category:'bermuda',coins:12,usd:0.12,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'waves'},
  {id:'moongate',name:'Moongate',emoji:'🌕',category:'bermuda',coins:150,usd:1.50,rarity:'epic',animation:'moongate-spin',color:'#ffd700',particles:true,sound:'magic'},
  {id:'bermuda_fitted_cap',name:'Bermuda Fitted Cap',emoji:'🧢',category:'bermuda',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'portuguese_man',name:'Portuguese Man o War',emoji:'🪼',category:'bermuda',coins:45,usd:0.45,rarity:'bermuda',animation:'wave-pulse',color:'#7c3aed',particles:true,sound:'bubbles'},
  {id:'wahoo_fish',name:'Wahoo Fish',emoji:'🐟',category:'bermuda',coins:22,usd:0.22,rarity:'bermuda',animation:'float-up',color:'#00d4ff',particles:true,sound:'splash'},
  {id:'spiny_lobster',name:'Spiny Lobster',emoji:'🦞',category:'bermuda',coins:35,usd:0.35,rarity:'bermuda',animation:'bounce',color:'#ff6b35',particles:true,sound:'splash'},
  {id:'mangrove',name:'Mangrove',emoji:'🌿',category:'bermuda',coins:16,usd:0.16,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'breeze'},
  {id:'humpback_whale',name:'Humpback Whale',emoji:'🐋',category:'bermuda',coins:300,usd:3.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'whale'},
  {id:'turtle',name:'Sea Turtle',emoji:'🐢',category:'bermuda',coins:55,usd:0.55,rarity:'bermuda',animation:'float-up',color:'#00d4ff',particles:true,sound:'bubbles'},
  {id:'bermuda_petrel',name:'Bermuda Petrel',emoji:'🐦',category:'bermuda',coins:70,usd:0.70,rarity:'bermuda',animation:'float-up',color:'#ffffff',particles:true,sound:'birds'},
  {id:'anchor',name:'Anchor',emoji:'⚓',category:'bermuda',coins:28,usd:0.28,rarity:'bermuda',animation:'bounce',color:'#00d4ff',particles:false,sound:'clank'},
  {id:'lighthouse',name:'Lighthouse',emoji:'🗼',category:'bermuda',coins:90,usd:0.90,rarity:'epic',animation:'moongate-spin',color:'#ffd700',particles:true,sound:'foghorn'},
  {id:'sailboat',name:'Sailboat',emoji:'⛵',category:'bermuda',coins:40,usd:0.40,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:false,sound:'waves'},
  {id:'dolphin',name:'Dolphin',emoji:'🐬',category:'bermuda',coins:65,usd:0.65,rarity:'bermuda',animation:'spiral',color:'#00d4ff',particles:true,sound:'dolphin'},
  {id:'bermuda_sunset',name:'Bermuda Sunset',emoji:'🌅',category:'bermuda',coins:120,usd:1.20,rarity:'epic',animation:'rainbow-burst',color:'#ff6b35',particles:true,sound:'birds'},
  {id:'conch_shell',name:'Conch Shell',emoji:'🐚',category:'bermuda',coins:20,usd:0.20,rarity:'bermuda',animation:'spiral',color:'#ff6b9d',particles:true,sound:'ocean'},
  {id:'sand_dollar',name:'Sand Dollar',emoji:'🪙',category:'bermuda',coins:30,usd:0.30,rarity:'bermuda',animation:'float-up',color:'#ffd700',particles:true,sound:'bling'},
  {id:'bermuda_bus',name:'Pink Bus',emoji:'🚌',category:'bermuda',coins:7,usd:0.07,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'honk'},
  {id:'bermuda_moped',name:'Bermuda Moped',emoji:'🛵',category:'bermuda',coins:10,usd:0.10,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'vroom'},
  {id:'cricket',name:'Cricket',emoji:'🏏',category:'bermuda',coins:15,usd:0.15,rarity:'bermuda',animation:'bounce',color:'#ffffff',particles:false,sound:'clap'},
  {id:'cup_match',name:'Cup Match',emoji:'🏆',category:'bermuda',coins:85,usd:0.85,rarity:'bermuda',animation:'rainbow-burst',color:'#ff4757',particles:true,sound:'fanfare'},
  {id:'bermuda_canoe',name:'Bermuda Cedar Canoe',emoji:'🚣',category:'bermuda',coins:50,usd:0.50,rarity:'bermuda',animation:'wave-pulse',color:'#ff6b35',particles:true,sound:'paddle'},
  {id:'snorkeler',name:'Snorkeler',emoji:'🤿',category:'bermuda',coins:25,usd:0.25,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'bubbles'},
  {id:'night_heron',name:'Night Heron',emoji:'🦤',category:'bermuda',coins:60,usd:0.60,rarity:'bermuda',animation:'float-up',color:'#ffd700',particles:true,sound:'birds'},
  {id:'spadefish',name:'Spadefish',emoji:'🐡',category:'bermuda',coins:18,usd:0.18,rarity:'bermuda',animation:'wave-pulse',color:'#ffffff',particles:true,sound:'bubbles'},
  {id:'devil_ray',name:'Devil Ray',emoji:'🦈',category:'bermuda',coins:160,usd:1.60,rarity:'epic',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'whale'},
  {id:'bermuda_arch',name:'Natural Arch',emoji:'🌉',category:'bermuda',coins:200,usd:2.00,rarity:'epic',animation:'moongate-spin',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'warwick_bay',name:'Warwick Long Bay',emoji:'🌊',category:'bermuda',coins:35,usd:0.35,rarity:'bermuda',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'waves'},
  {id:'horseshoe_bay',name:'Horseshoe Bay',emoji:'🏝️',category:'bermuda',coins:90,usd:0.90,rarity:'epic',animation:'wave-pulse',color:'#ff6b9d',particles:true,sound:'waves'},
  {id:'cedar_wood',name:'Cedar Wood',emoji:'🪵',category:'bermuda',coins:12,usd:0.12,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'bermuda_kite',name:'Good Friday Kite',emoji:'🪁',category:'bermuda',coins:22,usd:0.22,rarity:'bermuda',animation:'float-up',color:'#ff4757',particles:true,sound:'breeze'},
  {id:'saltfish',name:'Saltfish & Codfish',emoji:'🍽️',category:'bermuda',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'dark_n_stormy',name:'Dark n Stormy',emoji:'🍹',category:'bermuda',coins:15,usd:0.15,rarity:'bermuda',animation:'bounce',color:'#ff6b35',particles:true,sound:'clink'},
  {id:'rum_swizzle',name:'Rum Swizzle',emoji:'🍸',category:'bermuda',coins:18,usd:0.18,rarity:'bermuda',animation:'spiral',color:'#ff4757',particles:true,sound:'clink'},
  {id:'fish_chowder',name:'Fish Chowder',emoji:'🍲',category:'bermuda',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'triangle_vortex',name:'Triangle Vortex',emoji:'🌀',category:'bermuda',coins:750,usd:7.50,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},

  // LUXURY (50)
  {id:'lambo',name:'Lamborghini',emoji:'🏎️',category:'luxury',coins:1000,usd:10.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'vroom'},
  {id:'yacht',name:'Yacht',emoji:'🛥️',category:'luxury',coins:2000,usd:20.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'horn'},
  {id:'mansion',name:'Mansion',emoji:'🏰',category:'luxury',coins:5000,usd:50.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'private_jet',name:'Private Jet',emoji:'✈️',category:'luxury',coins:3000,usd:30.00,rarity:'legendary',animation:'explode',color:'#ffffff',particles:true,sound:'jet'},
  {id:'rolex',name:'Rolex',emoji:'⌚',category:'luxury',coins:500,usd:5.00,rarity:'legendary',animation:'bounce',color:'#ffd700',particles:true,sound:'bling'},
  {id:'champagne',name:'Champagne',emoji:'🍾',category:'luxury',coins:200,usd:2.00,rarity:'epic',animation:'explode',color:'#ffd700',particles:true,sound:'pop'},
  {id:'caviar',name:'Caviar',emoji:'🫧',category:'luxury',coins:300,usd:3.00,rarity:'epic',animation:'float-up',color:'#0a0a0f',particles:true,sound:'pop'},
  {id:'penthouse',name:'Penthouse',emoji:'🏙️',category:'luxury',coins:4000,usd:40.00,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'epic'},
  {id:'ferrari',name:'Ferrari',emoji:'🚗',category:'luxury',coins:1500,usd:15.00,rarity:'legendary',animation:'screen-shake',color:'#ff4757',particles:true,sound:'vroom'},
  {id:'bentley',name:'Bentley',emoji:'🚙',category:'luxury',coins:1200,usd:12.00,rarity:'legendary',animation:'bounce',color:'#ffd700',particles:true,sound:'vroom'},
  {id:'gold_bar',name:'Gold Bar',emoji:'🥇',category:'luxury',coins:400,usd:4.00,rarity:'epic',animation:'bounce',color:'#ffd700',particles:true,sound:'bling'},
  {id:'pink_diamond',name:'Pink Diamond',emoji:'💍',category:'luxury',coins:800,usd:8.00,rarity:'legendary',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'bling'},
  {id:'helicopter',name:'Helicopter',emoji:'🚁',category:'luxury',coins:2500,usd:25.00,rarity:'legendary',animation:'spiral',color:'#00d4ff',particles:true,sound:'chopper'},
  {id:'space_rocket',name:'Space Rocket',emoji:'🛸',category:'luxury',coins:10000,usd:100.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'blast'},
  {id:'sushi_platter',name:'Sushi Platter',emoji:'🍣',category:'luxury',coins:150,usd:1.50,rarity:'epic',animation:'float-up',color:'#ff4757',particles:false,sound:'pop'},
  {id:'truffle',name:'Black Truffle',emoji:'🍄',category:'luxury',coins:250,usd:2.50,rarity:'epic',animation:'bounce',color:'#0a0a0f',particles:true,sound:'pop'},
  {id:'tiara',name:'Tiara',emoji:'👸',category:'luxury',coins:600,usd:6.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'sparkle'},
  {id:'fur_coat',name:'Fur Coat',emoji:'🧥',category:'luxury',coins:350,usd:3.50,rarity:'epic',animation:'float-up',color:'#ffffff',particles:false,sound:'pop'},
  {id:'island',name:'Private Island',emoji:'🏝️',category:'luxury',coins:9999,usd:99.99,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'epic'},
  {id:'submarine',name:'Submarine',emoji:'🤿',category:'luxury',coins:3500,usd:35.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'sonar'},
  {id:'castle',name:'Castle',emoji:'🏯',category:'luxury',coins:6000,usd:60.00,rarity:'legendary',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'epic'},
  {id:'wine_cellar',name:'Wine Cellar',emoji:'🍷',category:'luxury',coins:700,usd:7.00,rarity:'legendary',animation:'bounce',color:'#ff4757',particles:true,sound:'clink'},
  {id:'pool',name:'Infinity Pool',emoji:'🏊',category:'luxury',coins:800,usd:8.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'splash'},
  {id:'butler',name:'Personal Butler',emoji:'🤵',category:'luxury',coins:450,usd:4.50,rarity:'epic',animation:'bounce',color:'#ffffff',particles:false,sound:'fanfare'},
  {id:'chef',name:'Private Chef',emoji:'👨‍🍳',category:'luxury',coins:550,usd:5.50,rarity:'legendary',animation:'float-up',color:'#ff6b35',particles:true,sound:'pop'},
  {id:'stadium',name:'Stadium',emoji:'🏟️',category:'luxury',coins:7500,usd:75.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'crowd'},
  {id:'oscar',name:'Oscar Award',emoji:'🏅',category:'luxury',coins:900,usd:9.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'grand_piano',name:'Grand Piano',emoji:'🎹',category:'luxury',coins:1300,usd:13.00,rarity:'legendary',animation:'bounce',color:'#0a0a0f',particles:true,sound:'piano'},
  {id:'art_collection',name:'Art Collection',emoji:'🖼️',category:'luxury',coins:2200,usd:22.00,rarity:'legendary',animation:'galaxy-swirl',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'emerald',name:'Emerald',emoji:'💚',category:'luxury',coins:650,usd:6.50,rarity:'legendary',animation:'bounce',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'ruby',name:'Ruby',emoji:'❤️',category:'luxury',coins:680,usd:6.80,rarity:'legendary',animation:'rainbow-burst',color:'#ff4757',particles:true,sound:'bling'},
  {id:'sapphire',name:'Sapphire',emoji:'💙',category:'luxury',coins:660,usd:6.60,rarity:'legendary',animation:'galaxy-swirl',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'vault',name:'Vault of Gold',emoji:'🏦',category:'luxury',coins:5500,usd:55.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'globe',name:'Globe Trotter',emoji:'🌍',category:'luxury',coins:1600,usd:16.00,rarity:'legendary',animation:'spiral',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'infinity_stone',name:'Infinity Stone',emoji:'💠',category:'luxury',coins:3200,usd:32.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'jetpack',name:'Jetpack',emoji:'🚀',category:'luxury',coins:2100,usd:21.00,rarity:'legendary',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'golden_ticket',name:'Golden Ticket',emoji:'🎫',category:'luxury',coins:1400,usd:14.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'moon_rock',name:'Moon Rock',emoji:'🌙',category:'luxury',coins:1900,usd:19.00,rarity:'legendary',animation:'galaxy-swirl',color:'#ffd700',particles:true,sound:'cosmic'},
  {id:'velvet_throne',name:'Velvet Throne',emoji:'🪑',category:'luxury',coins:2400,usd:24.00,rarity:'legendary',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'epic'},
  {id:'emperor_crown',name:'Emperor Crown',emoji:'👑',category:'luxury',coins:7000,usd:70.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'batmobile',name:'Batmobile',emoji:'🦇',category:'luxury',coins:2700,usd:27.00,rarity:'legendary',animation:'explode',color:'#0a0a0f',particles:true,sound:'vroom'},
  {id:'diamond_throne',name:'Diamond Throne',emoji:'💎',category:'luxury',coins:8000,usd:80.00,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'epic'},
  {id:'sun_yacht',name:'Sun Yacht',emoji:'☀️',category:'luxury',coins:4200,usd:42.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'horn'},
  {id:'watch_collection',name:'Watch Collection',emoji:'⌚',category:'luxury',coins:4500,usd:45.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'bling'},
  {id:'holographic_vault',name:'Holographic Vault',emoji:'🔐',category:'luxury',coins:3800,usd:38.00,rarity:'legendary',animation:'galaxy-swirl',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'crystal_chandelier',name:'Crystal Chandelier',emoji:'💡',category:'luxury',coins:1100,usd:11.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'sparkle'},
  {id:'gold_controller',name:'Gold Controller',emoji:'🕹️',category:'luxury',coins:1700,usd:17.00,rarity:'legendary',animation:'bounce',color:'#ffd700',particles:true,sound:'bling'},
  {id:'snow_globe_tower',name:'Snow Globe City',emoji:'🏙️',category:'luxury',coins:1350,usd:13.50,rarity:'legendary',animation:'galaxy-swirl',color:'#ffffff',particles:true,sound:'magic'},
  {id:'penthouse_view',name:'Penthouse View',emoji:'🌃',category:'luxury',coins:1800,usd:18.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'epic'},
  {id:'luxury_yacht_xl',name:'Mega Yacht',emoji:'🚢',category:'luxury',coins:9500,usd:95.00,rarity:'legendary',animation:'wave-pulse',color:'#ffd700',particles:true,sound:'horn'},

  // GAMING (50)
  {id:'sword',name:'Sword',emoji:'⚔️',category:'gaming',coins:30,usd:0.30,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'slash'},
  {id:'shield',name:'Shield',emoji:'🛡️',category:'gaming',coins:25,usd:0.25,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'clank'},
  {id:'level_up',name:'Level Up!',emoji:'⬆️',category:'gaming',coins:50,usd:0.50,rarity:'rare',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'levelup'},
  {id:'boss_kill',name:'Boss Kill',emoji:'💀',category:'gaming',coins:200,usd:2.00,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'epic'},
  {id:'legendary_drop',name:'Legendary Drop',emoji:'🌟',category:'gaming',coins:500,usd:5.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'epic_loot',name:'Epic Loot',emoji:'📦',category:'gaming',coins:300,usd:3.00,rarity:'epic',animation:'explode',color:'#7c3aed',particles:true,sound:'loot'},
  {id:'game_over',name:'Game Over',emoji:'👾',category:'gaming',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'gameover'},
  {id:'respawn',name:'Respawn',emoji:'♻️',category:'gaming',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#00d4ff',particles:true,sound:'respawn'},
  {id:'headshot',name:'Headshot',emoji:'🎯',category:'gaming',coins:100,usd:1.00,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'headshot'},
  {id:'noscope',name:'No Scope',emoji:'🎳',category:'gaming',coins:75,usd:0.75,rarity:'rare',animation:'explode',color:'#ff6b35',particles:true,sound:'bang'},
  {id:'combo',name:'Combo x100',emoji:'💥',category:'gaming',coins:150,usd:1.50,rarity:'epic',animation:'screen-shake',color:'#ffd700',particles:true,sound:'combo'},
  {id:'first_blood',name:'First Blood',emoji:'🩸',category:'gaming',coins:80,usd:0.80,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'slash'},
  {id:'ace',name:'Ace',emoji:'🃏',category:'gaming',coins:250,usd:2.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'ultra_kill',name:'Ultra Kill',emoji:'💀',category:'gaming',coins:400,usd:4.00,rarity:'legendary',animation:'screen-shake',color:'#ff4757',particles:true,sound:'epic'},
  {id:'ragequit',name:'Rage Quit',emoji:'🕹️',category:'gaming',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'smash'},
  {id:'gg',name:'GG EZ',emoji:'🏆',category:'gaming',coins:35,usd:0.35,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'pop'},
  {id:'chicken_dinner',name:'Chicken Dinner',emoji:'🍗',category:'gaming',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'speedrun',name:'World Record',emoji:'⏱️',category:'gaming',coins:600,usd:6.00,rarity:'legendary',animation:'explode',color:'#00d4ff',particles:true,sound:'levelup'},
  {id:'dragon_slayer',name:'Dragon Slayer',emoji:'🐉',category:'gaming',coins:450,usd:4.50,rarity:'legendary',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'roar'},
  {id:'dungeon_master',name:'Dungeon Master',emoji:'🧙',category:'gaming',coins:320,usd:3.20,rarity:'epic',animation:'spiral',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'power_up',name:'Power Up',emoji:'⚡',category:'gaming',coins:40,usd:0.40,rarity:'common',animation:'float-up',color:'#ffe600',particles:true,sound:'zap'},
  {id:'extra_life',name:'Extra Life',emoji:'❤️',category:'gaming',coins:55,usd:0.55,rarity:'rare',animation:'float-up',color:'#ff4757',particles:true,sound:'pop'},
  {id:'treasure_chest',name:'Treasure Chest',emoji:'📦',category:'gaming',coins:180,usd:1.80,rarity:'epic',animation:'explode',color:'#ffd700',particles:true,sound:'loot'},
  {id:'crystal_key',name:'Crystal Key',emoji:'🗝️',category:'gaming',coins:90,usd:0.90,rarity:'rare',animation:'spiral',color:'#00d4ff',particles:true,sound:'click'},
  {id:'portal_gun',name:'Portal Gun',emoji:'🔫',category:'gaming',coins:210,usd:2.10,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'portal'},
  {id:'death_star',name:'Death Star',emoji:'💫',category:'gaming',coins:800,usd:8.00,rarity:'legendary',animation:'screen-shake',color:'#ff4757',particles:true,sound:'epic'},
  {id:'healing_potion',name:'Healing Potion',emoji:'🧪',category:'gaming',coins:20,usd:0.20,rarity:'common',animation:'bounce',color:'#ff4757',particles:true,sound:'gulp'},
  {id:'fire_spell',name:'Fire Spell',emoji:'🔥',category:'gaming',coins:60,usd:0.60,rarity:'rare',animation:'explode',color:'#ff6b35',particles:true,sound:'crackle'},
  {id:'ice_spell',name:'Ice Spell',emoji:'❄️',category:'gaming',coins:60,usd:0.60,rarity:'rare',animation:'spiral',color:'#00d4ff',particles:true,sound:'freeze'},
  {id:'lightning_spell',name:'Lightning Spell',emoji:'⚡',category:'gaming',coins:70,usd:0.70,rarity:'rare',animation:'lightning-strike',color:'#ffe600',particles:true,sound:'zap'},
  {id:'berserker',name:'Berserker',emoji:'😡',category:'gaming',coins:170,usd:1.70,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'roar'},
  {id:'katana',name:'Katana',emoji:'🗡️',category:'gaming',coins:160,usd:1.60,rarity:'epic',animation:'explode',color:'#ffffff',particles:true,sound:'slash'},
  {id:'holy_grail',name:'Holy Grail',emoji:'🏆',category:'gaming',coins:700,usd:7.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'time_machine',name:'Time Machine',emoji:'⏰',category:'gaming',coins:550,usd:5.50,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'exosuit',name:'Exosuit',emoji:'🦾',category:'gaming',coins:480,usd:4.80,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'mech'},
  {id:'infinity_gauntlet',name:'Infinity Gauntlet',emoji:'🧤',category:'gaming',coins:2000,usd:20.00,rarity:'legendary',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'epic'},
  {id:'master_sword',name:'Master Sword',emoji:'🗡️',category:'gaming',coins:900,usd:9.00,rarity:'legendary',animation:'lightning-strike',color:'#ffd700',particles:true,sound:'slash'},
  {id:'pac_dot',name:'Pac Dot',emoji:'🟡',category:'gaming',coins:1,usd:0.01,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'chomp'},
  {id:'mushroom',name:'Super Mushroom',emoji:'🍄',category:'gaming',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ff4757',particles:true,sound:'pop'},
  {id:'coin_block',name:'Coin Block',emoji:'🟨',category:'gaming',coins:16,usd:0.16,rarity:'common',animation:'bounce',color:'#ffd700',particles:true,sound:'coin'},
  {id:'star_power',name:'Star Power',emoji:'⭐',category:'gaming',coins:120,usd:1.20,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'starpower'},
  {id:'rage_mode',name:'Rage Mode',emoji:'💢',category:'gaming',coins:280,usd:2.80,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'roar'},
  {id:'nuke',name:'Nuke',emoji:'☢️',category:'gaming',coins:1000,usd:10.00,rarity:'legendary',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'explosion'},
  {id:'mana_potion',name:'Mana Potion',emoji:'💧',category:'gaming',coins:20,usd:0.20,rarity:'common',animation:'bounce',color:'#00d4ff',particles:true,sound:'gulp'},
  {id:'invisibility',name:'Invisibility',emoji:'👻',category:'gaming',coins:110,usd:1.10,rarity:'epic',animation:'float-up',color:'#7c3aed',particles:true,sound:'whoosh'},
  {id:'sniper_rifle',name:'Sniper Rifle',emoji:'🎯',category:'gaming',coins:140,usd:1.40,rarity:'epic',animation:'explode',color:'#ffffff',particles:true,sound:'bang'},
  {id:'rpg',name:'Rocket Launcher',emoji:'💥',category:'gaming',coins:220,usd:2.20,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'hack_device',name:'Hack Device',emoji:'💻',category:'gaming',coins:130,usd:1.30,rarity:'epic',animation:'matrix-rain',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'ancient_scroll',name:'Ancient Scroll',emoji:'📜',category:'gaming',coins:65,usd:0.65,rarity:'rare',animation:'float-up',color:'#ff6b35',particles:false,sound:'magic'},

  // NATURE (50)
  {id:'tsunami',name:'Tsunami',emoji:'🌊',category:'nature',coins:500,usd:5.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'wave'},
  {id:'volcano',name:'Volcano',emoji:'🌋',category:'nature',coins:300,usd:3.00,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'rumble'},
  {id:'tornado',name:'Tornado',emoji:'🌪️',category:'nature',coins:200,usd:2.00,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'aurora',name:'Aurora Borealis',emoji:'🌌',category:'nature',coins:400,usd:4.00,rarity:'legendary',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'meteor',name:'Meteor',emoji:'☄️',category:'nature',coins:250,usd:2.50,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'crash'},
  {id:'comet',name:'Comet',emoji:'🌠',category:'nature',coins:180,usd:1.80,rarity:'epic',animation:'spiral',color:'#ffd700',particles:true,sound:'whoosh'},
  {id:'earthquake',name:'Earthquake',emoji:'🏔️',category:'nature',coins:350,usd:3.50,rarity:'epic',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'rumble'},
  {id:'hurricane',name:'Hurricane',emoji:'🌀',category:'nature',coins:450,usd:4.50,rarity:'legendary',animation:'spiral',color:'#00d4ff',particles:true,sound:'wind'},
  {id:'blizzard',name:'Blizzard',emoji:'❄️',category:'nature',coins:220,usd:2.20,rarity:'epic',animation:'spiral',color:'#ffffff',particles:true,sound:'wind'},
  {id:'lightning_storm',name:'Lightning Storm',emoji:'⛈️',category:'nature',coins:160,usd:1.60,rarity:'epic',animation:'lightning-strike',color:'#ffe600',particles:true,sound:'thunder'},
  {id:'solar_flare',name:'Solar Flare',emoji:'☀️',category:'nature',coins:600,usd:6.00,rarity:'legendary',animation:'rainbow-burst',color:'#ff6b35',particles:true,sound:'cosmic'},
  {id:'avalanche',name:'Avalanche',emoji:'🏔️',category:'nature',coins:280,usd:2.80,rarity:'epic',animation:'explode',color:'#ffffff',particles:true,sound:'rumble'},
  {id:'sandstorm',name:'Sandstorm',emoji:'🌵',category:'nature',coins:100,usd:1.00,rarity:'rare',animation:'spiral',color:'#ff6b35',particles:true,sound:'wind'},
  {id:'wildfire',name:'Wildfire',emoji:'🔥',category:'nature',coins:140,usd:1.40,rarity:'epic',animation:'explode',color:'#ff4757',particles:true,sound:'crackle'},
  {id:'blood_moon',name:'Blood Moon',emoji:'🌕',category:'nature',coins:700,usd:7.00,rarity:'legendary',animation:'galaxy-swirl',color:'#ff4757',particles:true,sound:'cosmic'},
  {id:'super_moon',name:'Super Moon',emoji:'🌝',category:'nature',coins:400,usd:4.00,rarity:'legendary',animation:'galaxy-swirl',color:'#ffd700',particles:true,sound:'cosmic'},
  {id:'solar_eclipse',name:'Solar Eclipse',emoji:'🌑',category:'nature',coins:800,usd:8.00,rarity:'legendary',animation:'screen-shake',color:'#0a0a0f',particles:true,sound:'cosmic'},
  {id:'northern_lights',name:'Northern Lights',emoji:'🌌',category:'nature',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'magic'},
  {id:'volcanic_eruption',name:'Eruption',emoji:'💥',category:'nature',coins:550,usd:5.50,rarity:'legendary',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'monsoon',name:'Monsoon',emoji:'🌧️',category:'nature',coins:120,usd:1.20,rarity:'rare',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'rain'},
  {id:'crystal_cave',name:'Crystal Cave',emoji:'💎',category:'nature',coins:240,usd:2.40,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'underwater_world',name:'Underwater World',emoji:'🌊',category:'nature',coins:320,usd:3.20,rarity:'epic',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'bubbles'},
  {id:'lava_river',name:'Lava River',emoji:'🌋',category:'nature',coins:270,usd:2.70,rarity:'epic',animation:'wave-pulse',color:'#ff6b35',particles:true,sound:'crackle'},
  {id:'deep_sea',name:'Deep Sea',emoji:'🐙',category:'nature',coins:190,usd:1.90,rarity:'epic',animation:'wave-pulse',color:'#0a0a0f',particles:true,sound:'bubbles'},
  {id:'whale_song',name:'Whale Song',emoji:'🐋',category:'nature',coins:500,usd:5.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'whale'},
  {id:'tiger',name:'Tiger Roar',emoji:'🐯',category:'nature',coins:200,usd:2.00,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'roar'},
  {id:'lion',name:'Lion',emoji:'🦁',category:'nature',coins:250,usd:2.50,rarity:'epic',animation:'explode',color:'#ffd700',particles:true,sound:'roar'},
  {id:'eagle',name:'Eagle',emoji:'🦅',category:'nature',coins:150,usd:1.50,rarity:'epic',animation:'float-up',color:'#ffd700',particles:true,sound:'screech'},
  {id:'shark',name:'Shark',emoji:'🦈',category:'nature',coins:180,usd:1.80,rarity:'epic',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'jaws'},
  {id:'megalodon',name:'Megalodon',emoji:'🦷',category:'nature',coins:700,usd:7.00,rarity:'legendary',animation:'screen-shake',color:'#0a0a0f',particles:true,sound:'roar'},
  {id:'ice_age',name:'Ice Age',emoji:'🧊',category:'nature',coins:450,usd:4.50,rarity:'legendary',animation:'spiral',color:'#00d4ff',particles:true,sound:'freeze'},
  {id:'dinosaur',name:'T-Rex',emoji:'🦕',category:'nature',coins:600,usd:6.00,rarity:'legendary',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'roar'},
  {id:'mammoth',name:'Mammoth',emoji:'🦣',category:'nature',coins:550,usd:5.50,rarity:'legendary',animation:'screen-shake',color:'#ffffff',particles:true,sound:'roar'},
  {id:'firefly',name:'Firefly Night',emoji:'✨',category:'nature',coins:35,usd:0.35,rarity:'rare',animation:'float-up',color:'#ffd700',particles:true,sound:'magic'},
  {id:'milky_way',name:'Milky Way',emoji:'🌌',category:'nature',coins:750,usd:7.50,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'great_barrier',name:'Great Barrier Reef',emoji:'🪸',category:'nature',coins:480,usd:4.80,rarity:'legendary',animation:'wave-pulse',color:'#ff6b9d',particles:true,sound:'bubbles'},
  {id:'amazon',name:'Amazon Jungle',emoji:'🌿',category:'nature',coins:260,usd:2.60,rarity:'epic',animation:'coral-grow',color:'#00d4ff',particles:true,sound:'jungle'},
  {id:'supercell',name:'Supercell Storm',emoji:'🌩️',category:'nature',coins:380,usd:3.80,rarity:'epic',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'thunder'},
  {id:'tidal_wave',name:'Tidal Wave',emoji:'🌊',category:'nature',coins:430,usd:4.30,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'wave'},
  {id:'geiser',name:'Geyser Blast',emoji:'💦',category:'nature',coins:170,usd:1.70,rarity:'epic',animation:'explode',color:'#00d4ff',particles:true,sound:'splash'},
  {id:'blue_fire',name:'Blue Fire',emoji:'🔵',category:'nature',coins:310,usd:3.10,rarity:'epic',animation:'explode',color:'#00d4ff',particles:true,sound:'crackle'},
  {id:'storm_surge',name:'Storm Surge',emoji:'⛈️',category:'nature',coins:360,usd:3.60,rarity:'epic',animation:'wave-pulse',color:'#7c3aed',particles:true,sound:'thunder'},
  {id:'rainbow_aurora',name:'Rainbow Aurora',emoji:'🌈',category:'nature',coins:650,usd:6.50,rarity:'legendary',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'earthquake_major',name:'Major Quake',emoji:'📳',category:'nature',coins:420,usd:4.20,rarity:'legendary',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'rumble'},
  {id:'hailstorm',name:'Hailstorm',emoji:'🌨️',category:'nature',coins:90,usd:0.90,rarity:'rare',animation:'spiral',color:'#ffffff',particles:true,sound:'hail'},
  {id:'drought',name:'Desert Sun',emoji:'☀️',category:'nature',coins:60,usd:0.60,rarity:'rare',animation:'float-up',color:'#ff6b35',particles:true,sound:'wind'},
  {id:'thunder_cloud',name:'Thunder Cloud',emoji:'⛈️',category:'nature',coins:80,usd:0.80,rarity:'rare',animation:'float-up',color:'#7c3aed',particles:true,sound:'thunder'},
  {id:'fogbank',name:'Fogbank',emoji:'🌫️',category:'nature',coins:45,usd:0.45,rarity:'rare',animation:'float-up',color:'#ffffff',particles:false,sound:'wind'},

  // TECH (50)
  {id:'ai_brain',name:'AI Brain',emoji:'🧠',category:'tech',coins:500,usd:5.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'beep'},
  {id:'quantum_chip',name:'Quantum Chip',emoji:'⚛️',category:'tech',coins:800,usd:8.00,rarity:'legendary',animation:'explode',color:'#00d4ff',particles:true,sound:'cosmic'},
  {id:'hologram',name:'Hologram',emoji:'🔵',category:'tech',coins:300,usd:3.00,rarity:'epic',animation:'float-up',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'cyborg',name:'Cyborg',emoji:'🦿',category:'tech',coins:400,usd:4.00,rarity:'legendary',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'mech'},
  {id:'nanobot',name:'Nanobot Swarm',emoji:'🔬',category:'tech',coins:250,usd:2.50,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'buzz'},
  {id:'neural_link',name:'Neural Link',emoji:'🔗',category:'tech',coins:600,usd:6.00,rarity:'legendary',animation:'lightning-strike',color:'#7c3aed',particles:true,sound:'zap'},
  {id:'crypto_mining',name:'Crypto Mining',emoji:'⛏️',category:'tech',coins:100,usd:1.00,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'ding'},
  {id:'bitcoin',name:'Bitcoin',emoji:'₿',category:'tech',coins:200,usd:2.00,rarity:'epic',animation:'bounce',color:'#ffd700',particles:true,sound:'bling'},
  {id:'eth',name:'Ethereum',emoji:'Ξ',category:'tech',coins:150,usd:1.50,rarity:'epic',animation:'float-up',color:'#7c3aed',particles:true,sound:'bling'},
  {id:'server_rack',name:'Server Rack',emoji:'🖥️',category:'tech',coins:80,usd:0.80,rarity:'rare',animation:'bounce',color:'#00d4ff',particles:false,sound:'buzz'},
  {id:'robot_arm',name:'Robot Arm',emoji:'🤖',category:'tech',coins:120,usd:1.20,rarity:'rare',animation:'bounce',color:'#00d4ff',particles:true,sound:'mech'},
  {id:'drone',name:'Drone',emoji:'🚁',category:'tech',coins:90,usd:0.90,rarity:'rare',animation:'float-up',color:'#ffffff',particles:true,sound:'buzz'},
  {id:'vr_headset',name:'VR Headset',emoji:'🥽',category:'tech',coins:70,usd:0.70,rarity:'rare',animation:'bounce',color:'#7c3aed',particles:false,sound:'beep'},
  {id:'augmented_reality',name:'AR Vision',emoji:'👁️',category:'tech',coins:180,usd:1.80,rarity:'epic',animation:'galaxy-swirl',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'3d_printer',name:'3D Printer',emoji:'🖨️',category:'tech',coins:60,usd:0.60,rarity:'rare',animation:'bounce',color:'#00d4ff',particles:false,sound:'buzz'},
  {id:'laser',name:'Laser Beam',emoji:'🔴',category:'tech',coins:50,usd:0.50,rarity:'rare',animation:'lightning-strike',color:'#ff4757',particles:true,sound:'zap'},
  {id:'satellite',name:'Satellite',emoji:'📡',category:'tech',coins:200,usd:2.00,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'smart_home',name:'Smart Home',emoji:'🏠',category:'tech',coins:140,usd:1.40,rarity:'epic',animation:'bounce',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'electric_car',name:'Electric Car',emoji:'🚗',category:'tech',coins:350,usd:3.50,rarity:'epic',animation:'explode',color:'#00d4ff',particles:true,sound:'vroom'},
  {id:'starlink',name:'Starlink',emoji:'🌐',category:'tech',coins:450,usd:4.50,rarity:'legendary',animation:'galaxy-swirl',color:'#ffd700',particles:true,sound:'cosmic'},
  {id:'super_computer',name:'Super Computer',emoji:'💻',category:'tech',coins:700,usd:7.00,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'data_stream',name:'Data Stream',emoji:'📊',category:'tech',coins:30,usd:0.30,rarity:'common',animation:'matrix-rain',color:'#00d4ff',particles:false,sound:'beep'},
  {id:'firewall',name:'Firewall',emoji:'🧱',category:'tech',coins:45,usd:0.45,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'ding'},
  {id:'encryption',name:'Encryption',emoji:'🔐',category:'tech',coins:110,usd:1.10,rarity:'rare',animation:'matrix-rain',color:'#7c3aed',particles:true,sound:'beep'},
  {id:'bug_bounty',name:'Bug Bounty',emoji:'🐛',category:'tech',coins:160,usd:1.60,rarity:'epic',animation:'bounce',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'cluster',name:'Server Cluster',emoji:'⚙️',category:'tech',coins:900,usd:9.00,rarity:'legendary',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'mech'},
  {id:'microchip',name:'Microchip',emoji:'🔲',category:'tech',coins:25,usd:0.25,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'battery',name:'Mega Battery',emoji:'🔋',category:'tech',coins:35,usd:0.35,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'zap'},
  {id:'wifi',name:'WiFi Boost',emoji:'📶',category:'tech',coins:10,usd:0.10,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'bluetooth',name:'Bluetooth Connect',emoji:'🎧',category:'tech',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'rocket_engine',name:'Rocket Engine',emoji:'🛰️',category:'tech',coins:1000,usd:10.00,rarity:'legendary',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'ai_assistant',name:'AI Assistant',emoji:'🤖',category:'tech',coins:220,usd:2.20,rarity:'epic',animation:'spiral',color:'#7c3aed',particles:true,sound:'beep'},
  {id:'blockchain',name:'Blockchain',emoji:'⛓️',category:'tech',coins:190,usd:1.90,rarity:'epic',animation:'chain-react',color:'#ffd700',particles:true,sound:'ding'},
  {id:'quantum_sim',name:'Quantum Sim',emoji:'🧬',category:'tech',coins:380,usd:3.80,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'exoskeleton',name:'Exoskeleton',emoji:'🦾',category:'tech',coins:270,usd:2.70,rarity:'epic',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'mech'},
  {id:'cyberdeck',name:'Cyberdeck',emoji:'⌨️',category:'tech',coins:340,usd:3.40,rarity:'epic',animation:'matrix-rain',color:'#00d4ff',particles:true,sound:'beep'},
  {id:'neon_sign',name:'Neon Sign',emoji:'💡',category:'tech',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'buzz'},
  {id:'deep_learning',name:'Deep Learning',emoji:'📓',category:'tech',coins:550,usd:5.50,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'smart_watch',name:'Smart Watch',emoji:'⌚',category:'tech',coins:40,usd:0.40,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'laser_tag',name:'Laser Tag',emoji:'🔫',category:'tech',coins:55,usd:0.55,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'zap'},
  {id:'thermal_vision',name:'Thermal Vision',emoji:'👀',category:'tech',coins:170,usd:1.70,rarity:'epic',animation:'galaxy-swirl',color:'#ff4757',particles:true,sound:'beep'},
  {id:'plasma_cannon',name:'Plasma Cannon',emoji:'🔫',category:'tech',coins:480,usd:4.80,rarity:'legendary',animation:'explode',color:'#7c3aed',particles:true,sound:'blast'},
  {id:'time_complexity',name:'O(1) Time',emoji:'⏱️',category:'tech',coins:65,usd:0.65,rarity:'rare',animation:'spiral',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'memory_leak',name:'Memory Leak Fix',emoji:'🔧',category:'tech',coins:30,usd:0.30,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'ding'},
  {id:'super_ai',name:'Super AI',emoji:'🤯',category:'tech',coins:2000,usd:20.00,rarity:'legendary',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'epic'},
  {id:'singularity',name:'Singularity',emoji:'🌀',category:'tech',coins:1500,usd:15.00,rarity:'legendary',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'cosmic'},
  {id:'matrix_pill',name:'Matrix Pill',emoji:'💊',category:'tech',coins:95,usd:0.95,rarity:'rare',animation:'matrix-rain',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'rpi',name:'Raspberry Pi',emoji:'🍓',category:'tech',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'ding'},
  {id:'darkweb',name:'Dark Web Scan',emoji:'🕸️',category:'tech',coins:420,usd:4.20,rarity:'epic',animation:'matrix-rain',color:'#0a0a0f',particles:true,sound:'buzz'},

  // FOOD & FUN (50)
  {id:'pizza',name:'Pizza',emoji:'🍕',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'tacos',name:'Tacos',emoji:'🌮',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'lobster',name:'Lobster',emoji:'🦞',category:'food_fun',coins:100,usd:1.00,rarity:'rare',animation:'bounce',color:'#ff6b35',particles:true,sound:'splash'},
  {id:'birthday_cake',name:'Birthday Cake',emoji:'🎂',category:'food_fun',coins:50,usd:0.50,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'pop'},
  {id:'sushi',name:'Sushi Roll',emoji:'🍣',category:'food_fun',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'pop'},
  {id:'ramen',name:'Ramen',emoji:'🍜',category:'food_fun',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'slurp'},
  {id:'ice_cream',name:'Ice Cream',emoji:'🍦',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'coffee',name:'Coffee',emoji:'☕',category:'food_fun',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#ff6b35',particles:false,sound:'gulp'},
  {id:'bubble_tea',name:'Bubble Tea',emoji:'🧋',category:'food_fun',coins:6,usd:0.06,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'sushi_tray',name:'Sushi Tray',emoji:'🍱',category:'food_fun',coins:150,usd:1.50,rarity:'epic',animation:'rainbow-burst',color:'#ff4757',particles:true,sound:'pop'},
  {id:'donut',name:'Donut',emoji:'🍩',category:'food_fun',coins:4,usd:0.04,rarity:'common',animation:'spiral',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'croissant',name:'Croissant',emoji:'🥐',category:'food_fun',coins:4,usd:0.04,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'pop'},
  {id:'wine',name:'Wine Glass',emoji:'🍷',category:'food_fun',coins:30,usd:0.30,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'clink'},
  {id:'beer',name:'Beer',emoji:'🍺',category:'food_fun',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'clink'},
  {id:'cocktail',name:'Cocktail',emoji:'🍹',category:'food_fun',coins:15,usd:0.15,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'clink'},
  {id:'steak',name:'Steak Dinner',emoji:'🥩',category:'food_fun',coins:80,usd:0.80,rarity:'rare',animation:'bounce',color:'#ff4757',particles:true,sound:'sizzle'},
  {id:'burger',name:'Burger',emoji:'🍔',category:'food_fun',coins:6,usd:0.06,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'wings',name:'Chicken Wings',emoji:'🍗',category:'food_fun',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'macaron',name:'Macaron Tower',emoji:'🧁',category:'food_fun',coins:45,usd:0.45,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'pop'},
  {id:'food_truck',name:'Food Truck',emoji:'🚚',category:'food_fun',coins:60,usd:0.60,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'honk'},
  {id:'sushi_boat',name:'Sushi Boat',emoji:'🍣',category:'food_fun',coins:200,usd:2.00,rarity:'epic',animation:'wave-pulse',color:'#ff4757',particles:true,sound:'water'},
  {id:'waffle',name:'Waffle',emoji:'🧇',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'pasta',name:'Pasta',emoji:'🍝',category:'food_fun',coins:7,usd:0.07,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'smoothie',name:'Smoothie',emoji:'🥤',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'slurp'},
  {id:'cheese_board',name:'Cheese Board',emoji:'🧀',category:'food_fun',coins:35,usd:0.35,rarity:'rare',animation:'bounce',color:'#ffd700',particles:false,sound:'pop'},
  {id:'candy',name:'Candy Rain',emoji:'🍬',category:'food_fun',coins:25,usd:0.25,rarity:'common',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'pop'},
  {id:'ice_cream_cake',name:'Ice Cream Cake',emoji:'🎂',category:'food_fun',coins:75,usd:0.75,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'seafood_tower',name:'Seafood Tower',emoji:'🦐',category:'food_fun',coins:180,usd:1.80,rarity:'epic',animation:'bounce',color:'#00d4ff',particles:true,sound:'splash'},
  {id:'truffle_pasta',name:'Truffle Pasta',emoji:'🍝',category:'food_fun',coins:120,usd:1.20,rarity:'epic',animation:'float-up',color:'#ffd700',particles:true,sound:'pop'},
  {id:'wagyu',name:'Wagyu Beef',emoji:'🥩',category:'food_fun',coins:300,usd:3.00,rarity:'epic',animation:'rainbow-burst',color:'#ff4757',particles:true,sound:'sizzle'},
  {id:'dom_perignon',name:'Dom Perignon',emoji:'🍾',category:'food_fun',coins:400,usd:4.00,rarity:'legendary',animation:'explode',color:'#ffd700',particles:true,sound:'pop'},
  {id:'dinner_table',name:'Dinner Party',emoji:'🍽️',category:'food_fun',coins:500,usd:5.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'cooking_fire',name:'Cooking Show',emoji:'🔥',category:'food_fun',coins:65,usd:0.65,rarity:'rare',animation:'explode',color:'#ff6b35',particles:true,sound:'crackle'},
  {id:'bakery',name:'Bakery Shop',emoji:'🥖',category:'food_fun',coins:40,usd:0.40,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'pop'},
  {id:'matcha',name:'Matcha Latte',emoji:'🍵',category:'food_fun',coins:8,usd:0.08,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'slurp'},
  {id:'tasting_menu',name:'Tasting Menu',emoji:'👨‍🍳',category:'food_fun',coins:250,usd:2.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'mystery_box',name:'Mystery Box',emoji:'📦',category:'food_fun',coins:150,usd:1.50,rarity:'epic',animation:'explode',color:'#7c3aed',particles:true,sound:'loot'},
  {id:'drunk_dance',name:'Drunk Dance',emoji:'🕺',category:'food_fun',coins:10,usd:0.10,rarity:'common',animation:'spiral',color:'#ff4757',particles:false,sound:'pop'},
  {id:'karaoke',name:'Karaoke Night',emoji:'🎤',category:'food_fun',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'mic_drop'},
  {id:'game_night',name:'Game Night',emoji:'🎲',category:'food_fun',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'pop'},
  {id:'pizza_party',name:'Pizza Party',emoji:'🍕',category:'food_fun',coins:100,usd:1.00,rarity:'rare',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'pop'},
  {id:'food_fight',name:'Food Fight',emoji:'🥄',category:'food_fun',coins:30,usd:0.30,rarity:'rare',animation:'explode',color:'#ff6b35',particles:true,sound:'splash'},
  {id:'snack_mountain',name:'Snack Mountain',emoji:'🗻',category:'food_fun',coins:80,usd:0.80,rarity:'rare',animation:'screen-shake',color:'#ffd700',particles:true,sound:'pop'},
  {id:'cooking_mess',name:'Cooking Disaster',emoji:'💥',category:'food_fun',coins:5,usd:0.05,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'pop'},
  {id:'taste_test',name:'Taste Test',emoji:'👅',category:'food_fun',coins:12,usd:0.12,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'pop'},
  {id:'chocolate',name:'Chocolate Box',emoji:'🍫',category:'food_fun',coins:25,usd:0.25,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'pop'},
  {id:'potion',name:'Love Potion',emoji:'🧪',category:'food_fun',coins:50,usd:0.50,rarity:'rare',animation:'spiral',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'feast',name:'Grand Feast',emoji:'🥘',category:'food_fun',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},

  // MUSIC (50)
  {id:'gold_record',name:'Gold Record',emoji:'💿',category:'music',coins:500,usd:5.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'concert_stage',name:'Concert Stage',emoji:'🎪',category:'music',coins:300,usd:3.00,rarity:'epic',animation:'screen-shake',color:'#ff6b9d',particles:true,sound:'crowd'},
  {id:'dj_booth',name:'DJ Booth',emoji:'🎧',category:'music',coins:200,usd:2.00,rarity:'epic',animation:'spiral',color:'#7c3aed',particles:true,sound:'beat'},
  {id:'vinyl',name:'Vinyl Record',emoji:'📀',category:'music',coins:40,usd:0.40,rarity:'common',animation:'spiral',color:'#0a0a0f',particles:true,sound:'vinyl'},
  {id:'guitar',name:'Guitar',emoji:'🎸',category:'music',coins:80,usd:0.80,rarity:'rare',animation:'bounce',color:'#ff6b35',particles:true,sound:'chord'},
  {id:'drum_kit',name:'Drum Kit',emoji:'🥁',category:'music',coins:60,usd:0.60,rarity:'rare',animation:'screen-shake',color:'#ff4757',particles:true,sound:'drums'},
  {id:'piano',name:'Piano',emoji:'🎹',category:'music',coins:100,usd:1.00,rarity:'rare',animation:'bounce',color:'#0a0a0f',particles:true,sound:'piano'},
  {id:'violin',name:'Violin',emoji:'🎻',category:'music',coins:90,usd:0.90,rarity:'rare',animation:'float-up',color:'#ff6b35',particles:true,sound:'violin'},
  {id:'trumpet',name:'Trumpet',emoji:'🎺',category:'music',coins:70,usd:0.70,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'saxophone',name:'Saxophone',emoji:'🎷',category:'music',coins:85,usd:0.85,rarity:'rare',animation:'float-up',color:'#ffd700',particles:true,sound:'sax'},
  {id:'platinum_record',name:'Platinum Record',emoji:'💿',category:'music',coins:800,usd:8.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffffff',particles:true,sound:'fanfare'},
  {id:'studio_mic',name:'Studio Mic',emoji:'🎙️',category:'music',coins:50,usd:0.50,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'mic_drop'},
  {id:'headphones',name:'Headphones',emoji:'🎧',category:'music',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#7c3aed',particles:false,sound:'pop'},
  {id:'bass_drop',name:'Bass Drop',emoji:'🔊',category:'music',coins:35,usd:0.35,rarity:'rare',animation:'screen-shake',color:'#7c3aed',particles:true,sound:'bass'},
  {id:'singer',name:'Singer',emoji:'🎤',category:'music',coins:25,usd:0.25,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'mic_drop'},
  {id:'music_note',name:'Music Note',emoji:'🎵',category:'music',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#7c3aed',particles:false,sound:'ding'},
  {id:'synth',name:'Synthesizer',emoji:'🎹',category:'music',coins:130,usd:1.30,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'synth'},
  {id:'amplifier',name:'Amplifier',emoji:'🔊',category:'music',coins:45,usd:0.45,rarity:'common',animation:'explode',color:'#ff6b35',particles:true,sound:'amp'},
  {id:'flute',name:'Flute',emoji:'🎵',category:'music',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'flute'},
  {id:'harp',name:'Harp',emoji:'🪕',category:'music',coins:65,usd:0.65,rarity:'rare',animation:'float-up',color:'#ffffff',particles:true,sound:'harp'},
  {id:'gramophone',name:'Gramophone',emoji:'📻',category:'music',coins:110,usd:1.10,rarity:'epic',animation:'spiral',color:'#ffd700',particles:true,sound:'vinyl'},
  {id:'choir',name:'Choir',emoji:'👥',category:'music',coins:160,usd:1.60,rarity:'epic',animation:'float-up',color:'#ffffff',particles:true,sound:'choir'},
  {id:'rock_band',name:'Rock Band',emoji:'🎸',category:'music',coins:250,usd:2.50,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'chord'},
  {id:'symphony',name:'Symphony',emoji:'🎻',category:'music',coins:450,usd:4.50,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'symphony'},
  {id:'festival',name:'Festival',emoji:'🎪',category:'music',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'crowd'},
  {id:'encore',name:'Encore!',emoji:'👏',category:'music',coins:75,usd:0.75,rarity:'rare',animation:'explode',color:'#ffd700',particles:true,sound:'clap'},
  {id:'ticket_stub',name:'VIP Ticket',emoji:'🎟️',category:'music',coins:180,usd:1.80,rarity:'epic',animation:'rainbow-burst',color:'#7c3aed',particles:true,sound:'fanfare'},
  {id:'backstage',name:'Backstage Pass',emoji:'🔑',category:'music',coins:220,usd:2.20,rarity:'epic',animation:'float-up',color:'#ff6b9d',particles:true,sound:'ding'},
  {id:'record_deal',name:'Record Deal',emoji:'📝',category:'music',coins:600,usd:6.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'world_tour',name:'World Tour',emoji:'🌍',category:'music',coins:1000,usd:10.00,rarity:'legendary',animation:'screen-shake',color:'#ff6b9d',particles:true,sound:'crowd'},
  {id:'beats',name:'Sick Beats',emoji:'💓',category:'music',coins:12,usd:0.12,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'beat'},
  {id:'rhythm',name:'Rhythm',emoji:'💃',category:'music',coins:18,usd:0.18,rarity:'common',animation:'spiral',color:'#7c3aed',particles:false,sound:'beat'},
  {id:'karaoke_mic',name:'Karaoke Mic',emoji:'🎤',category:'music',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'mic_drop'},
  {id:'guitar_solo',name:'Guitar Solo',emoji:'🎸',category:'music',coins:140,usd:1.40,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'chord'},
  {id:'drum_solo',name:'Drum Solo',emoji:'🥁',category:'music',coins:95,usd:0.95,rarity:'rare',animation:'screen-shake',color:'#ffd700',particles:true,sound:'drums'},
  {id:'mixing_board',name:'Mixing Board',emoji:'🎚️',category:'music',coins:170,usd:1.70,rarity:'epic',animation:'bounce',color:'#00d4ff',particles:true,sound:'beat'},
  {id:'grammy',name:'Grammy Award',emoji:'🏆',category:'music',coins:900,usd:9.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'falsetto',name:'Falsetto Hit',emoji:'✨',category:'music',coins:30,usd:0.30,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'bass_guitar',name:'Bass Guitar',emoji:'🎸',category:'music',coins:55,usd:0.55,rarity:'rare',animation:'bounce',color:'#0a0a0f',particles:true,sound:'bass'},
  {id:'cello',name:'Cello',emoji:'🎻',category:'music',coins:105,usd:1.05,rarity:'rare',animation:'float-up',color:'#ff6b35',particles:true,sound:'violin'},
  {id:'harmonica',name:'Harmonica',emoji:'🎵',category:'music',coins:15,usd:0.15,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'harmonica'},
  {id:'ukulele',name:'Ukulele',emoji:'🎸',category:'music',coins:22,usd:0.22,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'uke'},
  {id:'xylophone',name:'Xylophone',emoji:'🎵',category:'music',coins:28,usd:0.28,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'bongo',name:'Bongos',emoji:'🥁',category:'music',coins:32,usd:0.32,rarity:'common',animation:'bounce',color:'#ff6b35',particles:true,sound:'drums'},
  {id:'xylophone_solo',name:'Xylophone Solo',emoji:'🎼',category:'music',coins:48,usd:0.48,rarity:'rare',animation:'spiral',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'orchestra',name:'Orchestra',emoji:'🎻',category:'music',coins:700,usd:7.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'symphony'},

  // SPORTS (50)
  {id:'championship_belt',name:'Championship Belt',emoji:'🥇',category:'sports',coins:500,usd:5.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'olympic_gold',name:'Olympic Gold',emoji:'🏅',category:'sports',coins:400,usd:4.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'slam_dunk',name:'Slam Dunk',emoji:'🏀',category:'sports',coins:100,usd:1.00,rarity:'rare',animation:'explode',color:'#ff6b35',particles:true,sound:'dunk'},
  {id:'hat_trick',name:'Hat Trick',emoji:'⚽',category:'sports',coins:150,usd:1.50,rarity:'epic',animation:'rainbow-burst',color:'#ffffff',particles:true,sound:'crowd'},
  {id:'touchdown',name:'Touchdown!',emoji:'🏈',category:'sports',coins:120,usd:1.20,rarity:'epic',animation:'screen-shake',color:'#ff6b35',particles:true,sound:'crowd'},
  {id:'home_run',name:'Home Run',emoji:'⚾',category:'sports',coins:100,usd:1.00,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'crack'},
  {id:'hole_in_one',name:'Hole in One',emoji:'⛳',category:'sports',coins:300,usd:3.00,rarity:'epic',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'magic'},
  {id:'tennis_ace',name:'Tennis Ace',emoji:'🎾',category:'sports',coins:80,usd:0.80,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'whack'},
  {id:'boxing_ko',name:'Boxing KO',emoji:'🥊',category:'sports',coins:200,usd:2.00,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'punch'},
  {id:'trophy_world',name:'World Trophy',emoji:'🏆',category:'sports',coins:600,usd:6.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'medal_silver',name:'Silver Medal',emoji:'🥈',category:'sports',coins:150,usd:1.50,rarity:'rare',animation:'bounce',color:'#c0c0c0',particles:true,sound:'bling'},
  {id:'medal_bronze',name:'Bronze Medal',emoji:'🥉',category:'sports',coins:100,usd:1.00,rarity:'rare',animation:'bounce',color:'#cd7f32',particles:true,sound:'bling'},
  {id:'goal',name:'Goal!',emoji:'🥅',category:'sports',coins:60,usd:0.60,rarity:'rare',animation:'explode',color:'#00d4ff',particles:true,sound:'crowd'},
  {id:'basketball',name:'Basketball',emoji:'🏀',category:'sports',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'bounce'},
  {id:'football',name:'Football',emoji:'🏈',category:'sports',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#ff6b35',particles:false,sound:'bounce'},
  {id:'soccer_ball',name:'Soccer Ball',emoji:'⚽',category:'sports',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ffffff',particles:false,sound:'kick'},
  {id:'tennis_ball',name:'Tennis Ball',emoji:'🎾',category:'sports',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'whack'},
  {id:'golf_ball',name:'Golf Ball',emoji:'🏐',category:'sports',coins:12,usd:0.12,rarity:'common',animation:'float-up',color:'#ffffff',particles:false,sound:'whack'},
  {id:'boxing_glove',name:'Boxing Glove',emoji:'🥊',category:'sports',coins:25,usd:0.25,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'punch'},
  {id:'surfboard',name:'Surfboard',emoji:'🏄',category:'sports',coins:40,usd:0.40,rarity:'common',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'wave'},
  {id:'skateboard',name:'Skateboard',emoji:'🛹',category:'sports',coins:20,usd:0.20,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'whoosh'},
  {id:'skiing',name:'Skiing',emoji:'⛷️',category:'sports',coins:35,usd:0.35,rarity:'common',animation:'float-up',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'swimmer',name:'Swimmer',emoji:'🏊',category:'sports',coins:30,usd:0.30,rarity:'common',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'splash'},
  {id:'runner',name:'Runner',emoji:'🏃',category:'sports',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ff6b35',particles:false,sound:'whistle'},
  {id:'cyclist',name:'Cyclist',emoji:'🚴',category:'sports',coins:25,usd:0.25,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'gym',name:'Gym Beast',emoji:'🏋️',category:'sports',coins:45,usd:0.45,rarity:'rare',animation:'screen-shake',color:'#ff4757',particles:true,sound:'groan'},
  {id:'yoga',name:'Yoga Flow',emoji:'🧘',category:'sports',coins:30,usd:0.30,rarity:'common',animation:'float-up',color:'#7c3aed',particles:true,sound:'bells'},
  {id:'wrestling',name:'Wrestling',emoji:'🤼',category:'sports',coins:90,usd:0.90,rarity:'rare',animation:'screen-shake',color:'#ff4757',particles:true,sound:'slam'},
  {id:'fencing',name:'Fencing',emoji:'🤺',category:'sports',coins:70,usd:0.70,rarity:'rare',animation:'explode',color:'#ffffff',particles:true,sound:'clash'},
  {id:'archery',name:'Archery',emoji:'🏹',category:'sports',coins:55,usd:0.55,rarity:'rare',animation:'explode',color:'#ffd700',particles:true,sound:'arrow'},
  {id:'karate',name:'Karate Kick',emoji:'🥋',category:'sports',coins:50,usd:0.50,rarity:'rare',animation:'screen-shake',color:'#ffffff',particles:true,sound:'punch'},
  {id:'champion',name:'Champion',emoji:'🏆',category:'sports',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'ballon_dor',name:'Ballon d'Or',emoji:'⚽',category:'sports',coins:450,usd:4.50,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'mvp',name:'MVP Award',emoji:'🌟',category:'sports',coins:250,usd:2.50,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'grand_slam',name:'Grand Slam',emoji:'🎾',category:'sports',coins:350,usd:3.50,rarity:'epic',animation:'screen-shake',color:'#ffd700',particles:true,sound:'crowd'},
  {id:'track_record',name:'Track Record',emoji:'⏱️',category:'sports',coins:180,usd:1.80,rarity:'epic',animation:'explode',color:'#00d4ff',particles:true,sound:'whistle'},
  {id:'world_cup',name:'World Cup',emoji:'🏆',category:'sports',coins:800,usd:8.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'crowd'},
  {id:'super_bowl',name:'Super Bowl Ring',emoji:'💍',category:'sports',coins:900,usd:9.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'mma_finish',name:'MMA Finish',emoji:'💥',category:'sports',coins:170,usd:1.70,rarity:'epic',animation:'screen-shake',color:'#ff4757',particles:true,sound:'punch'},
  {id:'bowling_strike',name:'Bowling Strike',emoji:'🎳',category:'sports',coins:40,usd:0.40,rarity:'common',animation:'explode',color:'#00d4ff',particles:true,sound:'crash'},
  {id:'cricket_six',name:'Cricket Six',emoji:'🏏',category:'sports',coins:60,usd:0.60,rarity:'rare',animation:'explode',color:'#00d4ff',particles:true,sound:'whack'},
  {id:'rugby_try',name:'Rugby Try',emoji:'🏉',category:'sports',coins:75,usd:0.75,rarity:'rare',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'crowd'},
  {id:'pole_vault',name:'Pole Vault',emoji:'🏋️',category:'sports',coins:50,usd:0.50,rarity:'rare',animation:'float-up',color:'#ffd700',particles:true,sound:'whoosh'},
  {id:'hockey_goal',name:'Hockey Goal',emoji:'🏒',category:'sports',coins:65,usd:0.65,rarity:'rare',animation:'explode',color:'#00d4ff',particles:true,sound:'crack'},
  {id:'volleyball_spike',name:'Volleyball Spike',emoji:'🏐',category:'sports',coins:45,usd:0.45,rarity:'common',animation:'explode',color:'#ffffff',particles:true,sound:'whack'},
  {id:'ping_pong',name:'Ping Pong Ace',emoji:'🏓',category:'sports',coins:20,usd:0.20,rarity:'common',animation:'bounce',color:'#ffffff',particles:false,sound:'ding'},

  // EMOTIONS (50)
  {id:'mega_love',name:'Mega Love',emoji:'💖',category:'emotions',coins:200,usd:2.00,rarity:'epic',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'heartbeat'},
  {id:'tears_of_joy',name:'Tears of Joy',emoji:'😂',category:'emotions',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'laugh'},
  {id:'mind_blown',name:'Mind Blown',emoji:'🤯',category:'emotions',coins:80,usd:0.80,rarity:'rare',animation:'screen-shake',color:'#ff4757',particles:true,sound:'boom'},
  {id:'pure_joy',name:'Pure Joy',emoji:'🥰',category:'emotions',coins:50,usd:0.50,rarity:'rare',animation:'float-up',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'crying',name:'Crying',emoji:'😢',category:'emotions',coins:5,usd:0.05,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'cry'},
  {id:'furious',name:'Furious',emoji:'🤬',category:'emotions',coins:30,usd:0.30,rarity:'rare',animation:'screen-shake',color:'#ff4757',particles:true,sound:'growl'},
  {id:'surprised',name:'Surprised',emoji:'😲',category:'emotions',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'gasp'},
  {id:'cool',name:'Cool',emoji:'😎',category:'emotions',coins:10,usd:0.10,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'confused',name:'Confused',emoji:'😕',category:'emotions',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'hmm'},
  {id:'proud',name:'Proud',emoji:'😤',category:'emotions',coins:25,usd:0.25,rarity:'common',animation:'float-up',color:'#ff4757',particles:true,sound:'hmm'},
  {id:'sobbing',name:'Sobbing',emoji:'😭',category:'emotions',coins:8,usd:0.08,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'cry'},
  {id:'love_letter',name:'Love Letter',emoji:'💌',category:'emotions',coins:40,usd:0.40,rarity:'rare',animation:'float-up',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'broken_heart',name:'Broken Heart',emoji:'💔',category:'emotions',coins:20,usd:0.20,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'crack'},
  {id:'heart_eyes',name:'Heart Eyes',emoji:'😍',category:'emotions',coins:35,usd:0.35,rarity:'rare',animation:'float-up',color:'#ff6b9d',particles:true,sound:'heartbeat'},
  {id:'skull_laugh',name:'Dead Laughing',emoji:'💀',category:'emotions',coins:12,usd:0.12,rarity:'common',animation:'bounce',color:'#ffffff',particles:false,sound:'laugh'},
  {id:'eyeroll',name:'Eyeroll',emoji:'🙄',category:'emotions',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'hmm'},
  {id:'salute',name:'Salute',emoji:'🫡',category:'emotions',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'ding'},
  {id:'nervous',name:'Nervous',emoji:'😰',category:'emotions',coins:8,usd:0.08,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'gasp'},
  {id:'angry_flame',name:'Angry Flame',emoji:'🤬',category:'emotions',coins:45,usd:0.45,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'growl'},
  {id:'sparkle_heart',name:'Sparkle Heart',emoji:'💖',category:'emotions',coins:60,usd:0.60,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'sparkle'},
  {id:'warm_hug',name:'Warm Hug',emoji:'🤗',category:'emotions',coins:25,usd:0.25,rarity:'common',animation:'float-up',color:'#ffd700',particles:true,sound:'pop'},
  {id:'kiss_heart',name:'Kiss Heart',emoji:'😘',category:'emotions',coins:15,usd:0.15,rarity:'common',animation:'float-up',color:'#ff4757',particles:false,sound:'pop'},
  {id:'nervous_sweat',name:'Nervous Sweat',emoji:'😅',category:'emotions',coins:5,usd:0.05,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'pop'},
  {id:'peeking',name:'Peeking',emoji:'🫣',category:'emotions',coins:6,usd:0.06,rarity:'common',animation:'bounce',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'fire_heart',name:'Fire Heart',emoji:'❤️‍🔥',category:'emotions',coins:100,usd:1.00,rarity:'rare',animation:'explode',color:'#ff4757',particles:true,sound:'crackle'},
  {id:'mending_heart',name:'Mending Heart',emoji:'❤️‍🩹',category:'emotions',coins:45,usd:0.45,rarity:'rare',animation:'float-up',color:'#ff4757',particles:true,sound:'heartbeat'},
  {id:'crown_heart',name:'Crown Heart',emoji:'❣️',category:'emotions',coins:70,usd:0.70,rarity:'rare',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'sparkle'},
  {id:'infinity_love',name:'Infinity Love',emoji:'💞',category:'emotions',coins:150,usd:1.50,rarity:'epic',animation:'spiral',color:'#ff6b9d',particles:true,sound:'heartbeat'},
  {id:'revolving_hearts',name:'Revolving Hearts',emoji:'💕',category:'emotions',coins:80,usd:0.80,rarity:'rare',animation:'spiral',color:'#ff6b9d',particles:true,sound:'heartbeat'},
  {id:'blushing',name:'Blushing',emoji:'😊',category:'emotions',coins:8,usd:0.08,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'star_struck',name:'Star Struck',emoji:'🤩',category:'emotions',coins:20,usd:0.20,rarity:'common',animation:'bounce',color:'#ffd700',particles:true,sound:'sparkle'},
  {id:'vomiting',name:'Vomiting',emoji:'🤮',category:'emotions',coins:3,usd:0.03,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'splat'},
  {id:'deadpan',name:'Deadpan',emoji:'😐',category:'emotions',coins:2,usd:0.02,rarity:'common',animation:'float-up',color:'#ffffff',particles:false,sound:'crickets'},
  {id:'drooling',name:'Drooling',emoji:'🤤',category:'emotions',coins:4,usd:0.04,rarity:'common',animation:'float-up',color:'#ffd700',particles:false,sound:'pop'},
  {id:'smirk',name:'Smirk',emoji:'😏',category:'emotions',coins:5,usd:0.05,rarity:'common',animation:'float-up',color:'#7c3aed',particles:false,sound:'pop'},
  {id:'crying_laughing',name:'Crying Laughing',emoji:'😹',category:'emotions',coins:6,usd:0.06,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'laugh'},
  {id:'anguished',name:'Anguished',emoji:'😧',category:'emotions',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'gasp'},
  {id:'sleepy',name:'Sleepy',emoji:'😴',category:'emotions',coins:3,usd:0.03,rarity:'common',animation:'float-up',color:'#7c3aed',particles:false,sound:'snore'},
  {id:'partying',name:'Partying',emoji:'🥳',category:'emotions',coins:30,usd:0.30,rarity:'common',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'fanfare'},
  {id:'smiling_devil',name:'Smiling Devil',emoji:'😈',category:'emotions',coins:15,usd:0.15,rarity:'common',animation:'explode',color:'#ff4757',particles:true,sound:'evil'},
  {id:'ghost',name:'Ghost',emoji:'👻',category:'emotions',coins:20,usd:0.20,rarity:'common',animation:'float-up',color:'#ffffff',particles:false,sound:'spooky'},
  {id:'crying_snowman',name:'Melting',emoji:'🫠',category:'emotions',coins:7,usd:0.07,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'pop'},
  {id:'anxiety',name:'Anxiety',emoji:'🫠',category:'emotions',coins:10,usd:0.10,rarity:'common',animation:'bounce',color:'#ff4757',particles:false,sound:'heartbeat'},
  {id:'ecstatic',name:'Ecstatic',emoji:'🥳',category:'emotions',coins:50,usd:0.50,rarity:'rare',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'grateful',name:'Grateful',emoji:'🥲',category:'emotions',coins:15,usd:0.15,rarity:'common',animation:'float-up',color:'#ff6b9d',particles:false,sound:'pop'},
  {id:'love_storm',name:'Love Storm',emoji:'💘',category:'emotions',coins:180,usd:1.80,rarity:'epic',animation:'rainbow-burst',color:'#ff6b9d',particles:true,sound:'heartbeat'},
  {id:'overwhelmed',name:'Overwhelmed',emoji:'😵‍💫',category:'emotions',coins:5,usd:0.05,rarity:'common',animation:'spiral',color:'#7c3aed',particles:false,sound:'gasp'},
  {id:'zen',name:'Zen Mode',emoji:'🧘',category:'emotions',coins:40,usd:0.40,rarity:'rare',animation:'float-up',color:'#7c3aed',particles:true,sound:'bells'},
  {id:'astonished',name:'Astonished',emoji:'😱',category:'emotions',coins:18,usd:0.18,rarity:'common',animation:'screen-shake',color:'#ff4757',particles:true,sound:'gasp'},
  {id:'love_explosion',name:'Love Explosion',emoji:'💗',category:'emotions',coins:300,usd:3.00,rarity:'epic',animation:'explode',color:'#ff6b9d',particles:true,sound:'heartbeat'},

  // BERMUDA DOLLAR DOUBLE (50)
  {id:'dollar_rain',name:'Dollar Rain',emoji:'💵',category:'bermuda_dollar',coins:100,usd:1.00,rarity:'bermuda',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'cash'},
  {id:'money_tornado',name:'Money Tornado',emoji:'💰',category:'bermuda_dollar',coins:250,usd:2.50,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'wealth_wave',name:'Wealth Wave',emoji:'🌊',category:'bermuda_dollar',coins:500,usd:5.00,rarity:'legendary',animation:'wave-pulse',color:'#ffd700',particles:true,sound:'wave'},
  {id:'bermuda_dollar',name:'Bermuda Dollar',emoji:'💎',category:'bermuda_dollar',coins:50,usd:0.50,rarity:'bermuda',animation:'bounce',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'gold_shower',name:'Gold Shower',emoji:'🌟',category:'bermuda_dollar',coins:300,usd:3.00,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'magic'},
  {id:'treasure_map',name:'Treasure Map',emoji:'🗺️',category:'bermuda_dollar',coins:150,usd:1.50,rarity:'rare',animation:'float-up',color:'#ff6b35',particles:true,sound:'magic'},
  {id:'pirate_gold',name:'Pirate Gold',emoji:'🏴‍☠️',category:'bermuda_dollar',coins:200,usd:2.00,rarity:'epic',animation:'explode',color:'#ffd700',particles:true,sound:'coin'},
  {id:'crypto_moon',name:'To The Moon',emoji:'🚀',category:'bermuda_dollar',coins:400,usd:4.00,rarity:'legendary',animation:'explode',color:'#ffd700',particles:true,sound:'blast'},
  {id:'dollar_sign',name:'Dollar Sign',emoji:'💲',category:'bermuda_dollar',coins:25,usd:0.25,rarity:'common',animation:'bounce',color:'#ffd700',particles:false,sound:'ding'},
  {id:'money_bag',name:'Money Bag',emoji:'💰',category:'bermuda_dollar',coins:75,usd:0.75,rarity:'rare',animation:'bounce',color:'#ffd700',particles:true,sound:'cash'},
  {id:'cash_stack',name:'Cash Stack',emoji:'💵',category:'bermuda_dollar',coins:40,usd:0.40,rarity:'common',animation:'float-up',color:'#00d4ff',particles:false,sound:'cash'},
  {id:'gold_coins',name:'Gold Coins',emoji:'🪙',category:'bermuda_dollar',coins:30,usd:0.30,rarity:'common',animation:'bounce',color:'#ffd700',particles:true,sound:'coin'},
  {id:'money_wings',name:'Money With Wings',emoji:'💸',category:'bermuda_dollar',coins:60,usd:0.60,rarity:'rare',animation:'float-up',color:'#00d4ff',particles:true,sound:'whoosh'},
  {id:'credit_card',name:'Credit Card',emoji:'💳',category:'bermuda_dollar',coins:15,usd:0.15,rarity:'common',animation:'bounce',color:'#00d4ff',particles:false,sound:'ding'},
  {id:'bank',name:'Bank Vault',emoji:'🏦',category:'bermuda_dollar',coins:350,usd:3.50,rarity:'epic',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'bitcoin_profit',name:'Bitcoin Profit',emoji:'₿',category:'bermuda_dollar',coins:180,usd:1.80,rarity:'epic',animation:'float-up',color:'#ffd700',particles:true,sound:'bling'},
  {id:'stock_gain',name:'Stock Gain',emoji:'📈',category:'bermuda_dollar',coins:120,usd:1.20,rarity:'rare',animation:'float-up',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'portfolio',name:'Portfolio',emoji:'💼',category:'bermuda_dollar',coins:90,usd:0.90,rarity:'rare',animation:'bounce',color:'#ffffff',particles:false,sound:'ding'},
  {id:'diamond_hands',name:'Diamond Hands',emoji:'💎',category:'bermuda_dollar',coins:200,usd:2.00,rarity:'epic',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'rocket_profit',name:'Rocket Profit',emoji:'🚀',category:'bermuda_dollar',coins:350,usd:3.50,rarity:'epic',animation:'explode',color:'#ff6b35',particles:true,sound:'blast'},
  {id:'money_tree',name:'Money Tree',emoji:'🌳',category:'bermuda_dollar',coins:220,usd:2.20,rarity:'epic',animation:'float-up',color:'#00d4ff',particles:true,sound:'breeze'},
  {id:'golden_egg',name:'Golden Egg',emoji:'🥚',category:'bermuda_dollar',coins:280,usd:2.80,rarity:'epic',animation:'bounce',color:'#ffd700',particles:true,sound:'magic'},
  {id:'cash_explosion',name:'Cash Explosion',emoji:'💥',category:'bermuda_dollar',coins:500,usd:5.00,rarity:'legendary',animation:'explode',color:'#ffd700',particles:true,sound:'blast'},
  {id:'bermuda_jackpot',name:'Bermuda Jackpot',emoji:'🎰',category:'bermuda_dollar',coins:750,usd:7.50,rarity:'legendary',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'jackpot'},
  {id:'dollar_storm',name:'Dollar Storm',emoji:'⛈️',category:'bermuda_dollar',coins:160,usd:1.60,rarity:'epic',animation:'spiral',color:'#00d4ff',particles:true,sound:'cash'},
  {id:'coin_rain',name:'Coin Rain',emoji:'🪙',category:'bermuda_dollar',coins:110,usd:1.10,rarity:'rare',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'coin'},
  {id:'profit_margin',name:'Profit Margin',emoji:'📊',category:'bermuda_dollar',coins:70,usd:0.70,rarity:'rare',animation:'float-up',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'staking',name:'Staking Rewards',emoji:'⛓️',category:'bermuda_dollar',coins:140,usd:1.40,rarity:'rare',animation:'bounce',color:'#7c3aed',particles:true,sound:'ding'},
  {id:'dividend',name:'Dividend',emoji:'💰',category:'bermuda_dollar',coins:80,usd:0.80,rarity:'rare',animation:'float-up',color:'#ffd700',particles:true,sound:'ding'},
  {id:'compound',name:'Compound Interest',emoji:'📈',category:'bermuda_dollar',coins:95,usd:0.95,rarity:'rare',animation:'float-up',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'treasure_chest_x',name:'Treasure Chest',emoji:'📦',category:'bermuda_dollar',coins:450,usd:4.50,rarity:'legendary',animation:'explode',color:'#ffd700',particles:true,sound:'loot'},
  {id:'nft_mint',name:'NFT Mint',emoji:'🖼️',category:'bermuda_dollar',coins:250,usd:2.50,rarity:'epic',animation:'galaxy-swirl',color:'#7c3aed',particles:true,sound:'magic'},
  {id:'airdrop',name:'Airdrop',emoji:'🪂',category:'bermuda_dollar',coins:175,usd:1.75,rarity:'epic',animation:'float-up',color:'#7c3aed',particles:true,sound:'whoosh'},
  {id:'yield_farm',name:'Yield Farm',emoji:'🌾',category:'bermuda_dollar',coins:200,usd:2.00,rarity:'epic',animation:'float-up',color:'#00d4ff',particles:true,sound:'breeze'},
  {id:'golden_crown',name:'Golden Crown',emoji:'👑',category:'bermuda_dollar',coins:600,usd:6.00,rarity:'legendary',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'fanfare'},
  {id:'emerald_ring',name:'Emerald Ring',emoji:'💚',category:'bermuda_dollar',coins:400,usd:4.00,rarity:'legendary',animation:'bounce',color:'#00d4ff',particles:true,sound:'bling'},
  {id:'silver_bullet',name:'Silver Bullet',emoji:'🔫',category:'bermuda_dollar',coins:50,usd:0.50,rarity:'rare',animation:'explode',color:'#c0c0c0',particles:true,sound:'bang'},
  {id:'bermuda_bank',name:'Bermuda Bank',emoji:'🏛️',category:'bermuda_dollar',coins:300,usd:3.00,rarity:'epic',animation:'screen-shake',color:'#00d4ff',particles:true,sound:'ding'},
  {id:'money_rain_duo',name:'Money Rain Duo',emoji:'💰',category:'bermuda_dollar',coins:125,usd:1.25,rarity:'rare',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'cash'},
  {id:'digital_gold',name:'Digital Gold',emoji:'💎',category:'bermuda_dollar',coins:500,usd:5.00,rarity:'legendary',animation:'galaxy-swirl',color:'#ffd700',particles:true,sound:'bling'},
  {id:'bermuda_pink',name:'Pink Profits',emoji:'💖',category:'bermuda_dollar',coins:80,usd:0.80,rarity:'bermuda',animation:'float-up',color:'#ff6b9d',particles:true,sound:'magic'},
  {id:'ocean_gold',name:'Ocean Gold',emoji:'🌊',category:'bermuda_dollar',coins:180,usd:1.80,rarity:'bermuda',animation:'wave-pulse',color:'#ffd700',particles:true,sound:'wave'},
  {id:'sand_gold',name:'Sand Gold',emoji:'🏖️',category:'bermuda_dollar',coins:95,usd:0.95,rarity:'bermuda',animation:'float-up',color:'#ffd700',particles:true,sound:'waves'},
  {id:'island_profit',name:'Island Profit',emoji:'🏝️',category:'bermuda_dollar',coins:350,usd:3.50,rarity:'epic',animation:'rainbow-burst',color:'#00d4ff',particles:true,sound:'fanfare'},
  {id:'crown_jewels',name:'Crown Jewels',emoji:'👑',category:'bermuda_dollar',coins:900,usd:9.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'epic'},
  {id:'profit_tsunami',name:'Profit Tsunami',emoji:'🌊',category:'bermuda_dollar',coins:700,usd:7.00,rarity:'legendary',animation:'wave-pulse',color:'#00d4ff',particles:true,sound:'wave'},
  {id:'golden_hour',name:'Golden Hour',emoji:'🌅',category:'bermuda_dollar',coins:275,usd:2.75,rarity:'epic',animation:'rainbow-burst',color:'#ffd700',particles:true,sound:'magic'},
  {id:'moon_lambo',name:'Moon Lambo',emoji:'🌙',category:'bermuda_dollar',coins:1000,usd:10.00,rarity:'legendary',animation:'screen-shake',color:'#ffd700',particles:true,sound:'vroom'},
];

// ============================================================
// Gift Categories
// ============================================================
const GIFT_CATEGORIES = [
  { id: 'standard', name: 'Standard', icon: '🎁' },
  { id: 'bermuda', name: 'Bermuda 🇧🇲', icon: '🏝️' },
  { id: 'luxury', name: 'Luxury', icon: '💎' },
  { id: 'gaming', name: 'Gaming', icon: '🎮' },
  { id: 'nature', name: 'Nature', icon: '🌿' },
  { id: 'tech', name: 'Tech', icon: '💻' },
  { id: 'food_fun', name: 'Food & Fun', icon: '🍕' },
  { id: 'music', name: 'Music', icon: '🎵' },
  { id: 'sports', name: 'Sports', icon: '⚽' },
  { id: 'emotions', name: 'Emotions', icon: '❤️' },
  { id: 'bermuda_dollar', name: 'Bermuda Dollar 💵', icon: '💰' }
];

const GIFT_SOUNDS = {
  whoosh: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  pop: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  sparkle: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  bling: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  fanfare: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  blast: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  epic: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  cosmic: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  zap: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=',
  magic: 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA='
};

// ============================================================
// Utility Functions
// ============================================================

function getGiftsByCategory(category) {
  if (!category || category === 'all') return NVME_GIFTS;
  return NVME_GIFTS.filter(g => g.category === category);
}

function searchGifts(query) {
  if (!query || query.trim() === '') return NVME_GIFTS;
  const q = query.toLowerCase().trim();
  return NVME_GIFTS.filter(g =>
    g.id.toLowerCase().includes(q) ||
    g.name.toLowerCase().includes(q) ||
    g.category.toLowerCase().includes(q) ||
    g.rarity.toLowerCase().includes(q)
  );
}

function getGiftById(id) {
  return NVME_GIFTS.find(g => g.id === id);
}

function getRarityColor(rarity) {
  switch (rarity) {
    case 'common': return '#8b8b8b';
    case 'rare': return '#00d4ff';
    case 'epic': return '#7c3aed';
    case 'legendary': return '#ffd700';
    case 'bermuda': return '#ff6b9d';
    default: return '#ffffff';
  }
}

// ============================================================
// Particle Explosion Engine
// ============================================================

function createParticleExplosion(x, y, color, count) {
  count = count || 30;
  const container = document.createElement('div');
  container.className = 'nvme-particle-container';
  container.style.cssText = position:fixed;top:{y}px;left:{x}px;pointer-events:none;z-index:99999;width:0;height:0;;
  document.body.appendChild(container);

  for (let i = 0; i < count; i++) {
    const particle = document.createElement('div');
    const angle = (Math.PI * 2 * i) / count;
    const velocity = 80 + Math.random() * 120;
    const size = 4 + Math.random() * 8;
    const duration = 600 + Math.random() * 800;
    const dx = Math.cos(angle) * velocity;
    const dy = Math.sin(angle) * velocity;

    particle.className = 'nvme-particle';
    particle.style.cssText = \
      position:absolute;width:{size}px;height:{size}px;background:{color};\
       border-radius:50%;box-shadow:0 0 {size*2}px {color};\
       animation:nvmeParticleExplode {duration}ms ease-out forwards;\
       --dx:{dx}px;--dy:{dy}px;;
    container.appendChild(particle);
  }

  setTimeout(() => container.remove(), 2000);
}

// ============================================================
// Gift Animation Trigger
// ============================================================

function triggerGiftAnimation(gift, container) {
  if (!gift) return;

  // Create the animated gift element
  const el = document.createElement('div');
  el.className = nvme-gift-anim nvme-gift-{gift.animation};
  el.style.cssText = \
    position:fixed;bottom:20%;left:50%;transform:translateX(-50%);\
     font-size:80px;z-index:99998;pointer-events:none;;
  el.textContent = gift.emoji;
  document.body.appendChild(el);

  // Text label
  const label = document.createElement('div');
  label.className = 'nvme-gift-label';
  label.style.cssText = \
    position:fixed;bottom:12%;left:50%;transform:translateX(-50%);\
     color:{gift.color};font-size:18px;font-weight:700;\
     text-shadow:0 0 20px {gift.color};z-index:99998;pointer-events:none;\
     font-family:Inter,system-ui,sans-serif;;
  label.textContent = \{gift.name} (+\${gift.coins} coins)\;
  document.body.appendChild(label);

  // Particles
  if (gift.particles) {
    const rect = el.getBoundingClientRect();
    createParticleExplosion(
      rect.left + rect.width / 2,
      rect.top + rect.height / 2,
      gift.color,
      gift.rarity === 'legendary' ? 60 : gift.rarity === 'epic' ? 40 : 25
    );
  }

  // Screen effects based on rarity
  if (gift.rarity === 'legendary') {
    const overlay = document.createElement('div');
    overlay.style.cssText = \
      position:fixed;top:0;left:0;width:100%;height:100%;\
       background:radial-gradient(circle,transparent 30%,rgba(0,0,0,0.8) 100%);\
       z-index:99997;pointer-events:none;animation:nvmeScreenFlash 3s ease-out forwards;;
    document.body.appendChild(overlay);
    setTimeout(() => overlay.remove(), 3000);
  }

  if (gift.category === 'bermuda' || gift.category === 'bermuda_dollar') {
    document.body.classList.add('nvme-bermuda-effect');
    setTimeout(() => document.body.classList.remove('nvme-bermuda-effect'), 2500);
  }

  // Play sound
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.5);
    osc.frequency.setValueAtTime(800, audioCtx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(1200, audioCtx.currentTime + 0.3);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.5);
  } catch (e) { /* silent fail */ }

  // Cleanup
  setTimeout(() => { el.remove(); label.remove(); }, 2500);
}

// ============================================================
// Gift Panel Renderer
// ============================================================

function renderGiftPanel(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  let activeCategory = 'all';

  function render() {
    const gifts = activeCategory === 'all' ? NVME_GIFTS : getGiftsByCategory(activeCategory);

    container.innerHTML = \
    \\
      <div class="nvme-gift-panel" style="background:rgba(10,10,15,0.97);border-radius:16px;padding:16px;\
           max-height:420px;overflow:hidden;display:flex;flex-direction:column;\
           border:1px solid rgba(124,58,237,0.3);backdrop-filter:blur(20px);">

        <!-- Search -->
        <input type="text" class="nvme-gift-search" placeholder="🔍 Search gifts..."\
               style="background:rgba(255,255,255,0.06);border:1px solid rgba(124,58,237,0.3);\
                      border-radius:10px;padding:10px 14px;color:#fff;font-size:14px;\
                      outline:none;margin-bottom:12px;font-family:Inter,system-ui,sans-serif;"
               oninput="handleGiftSearch(this.value)">

        <!-- Category tabs -->
        <div class="nvme-category-tabs" style="display:flex;gap:6px;overflow-x:auto;padding-bottom:8px;\
             margin-bottom:12px;-webkit-overflow-scrolling:touch;scrollbar-width:none;">
          <button onclick="switchGiftCat('all')"\
                  class="nvme-cat-btn \{activeCategory==='all'?'active':''}"\
                  style="padding:6px 14px;border-radius:20px;border:none;cursor:pointer;\
                         font-size:12px;font-weight:600;white-space:nowrap;\
                         background:\{activeCategory==='all'?'#7c3aed':'rgba(255,255,255,0.08)'};\
                         color:\{activeCategory==='all'?'#fff':'#999'};">
            🎁 All
          </button>\
          \{GIFT_CATEGORIES.map(c => \
            \<button onclick="switchGiftCat('\{c.id}')"\
                      class="nvme-cat-btn \{activeCategory===c.id?'active':''}"\
                      style="padding:6px 14px;border-radius:20px;border:none;cursor:pointer;\
                             font-size:12px;font-weight:600;white-space:nowrap;\
                             background:\{activeCategory===c.id?'#7c3aed':'rgba(255,255,255,0.08)'};\
                             color:\{activeCategory===c.id?'#fff':'#999'};">
                       \{c.icon} \{c.name}\
             </button>\\
          ).join('')}
        </div>

        <!-- Gift grid -->
        <div class="nvme-gift-grid" style="display:grid;grid-template-columns:repeat(5,1fr);\
             gap:8px;overflow-y:auto;flex:1;padding-right:4px;\
             scrollbar-width:thin;scrollbar-color:rgba(124,58,237,0.5) transparent;">
          \{gifts.slice(0, 500).map(g => \
            \<div class="nvme-gift-item" onclick="sendGift('\{g.id}')"\
                   title="\{g.name} - \{g.coins} coins (\{g.rarity})"\
                   style="background:rgba(255,255,255,0.04);border-radius:12px;padding:10px 6px;\
                          text-align:center;cursor:pointer;transition:all 0.2s;\
                          border:2px solid transparent;position:relative;"\
                   onmouseover="this.style.border='2px solid \{g.color}';\
                                this.style.background='rgba(124,58,237,0.15)'"\
                   onmouseout="this.style.border='2px solid transparent';\
                               this.style.background='rgba(255,255,255,0.04)'">
              <div style="font-size:28px;line-height:1.2;">\{g.emoji}</div>
              <div style="font-size:10px;color:#999;margin-top:4px;\
                          overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                \{g.name}
              </div>
              <div style="font-size:10px;color:\{getRarityColor(g.rarity)};font-weight:600;">
                \{g.coins}c
              </div>\
              \{g.rarity==='legendary'?\<div style="position:absolute;top:2px;right:2px;\
                  font-size:8px;background:linear-gradient(135deg,#ffd700,#ff6b35);\
                  padding:1px 4px;border-radius:4px;color:#000;font-weight:700;">★</div>\:''}\
              \{g.rarity==='bermuda'?\<div style="position:absolute;top:2px;right:2px;\
                  font-size:8px;background:linear-gradient(135deg,#ff6b9d,#7c3aed);\
                  padding:1px 4px;border-radius:4px;color:#fff;font-weight:700;">🇧🇲</div>\:''}\
            </div>\\
          ).join('')}
        </div>

        <!-- Gift count -->
        <div style="text-align:center;padding:8px 0 0;font-size:11px;color:#666;">
          \{gifts.length} gifts available
        </div>
      </div>\
    \;
  }

  // Global handlers
  window.switchGiftCat = function(cat) {
    activeCategory = cat;
    render();
  };

  window.handleGiftSearch = function(query) {
    const results = searchGifts(query);
    const grid = container.querySelector('.nvme-gift-grid');
    if (!grid) return;
    grid.innerHTML = results.map(g => \
      \<div class="nvme-gift-item" onclick="sendGift('\{g.id}')"\
             title="\{g.name} - \{g.coins} coins"\
             style="background:rgba(255,255,255,0.04);border-radius:12px;padding:10px 6px;\
                    text-align:center;cursor:pointer;transition:all 0.2s;\
                    border:2px solid transparent;">\
        <div style="font-size:28px;line-height:1.2;">\{g.emoji}</div>
        <div style="font-size:10px;color:#999;margin-top:4px;">\{g.name}</div>
        <div style="font-size:10px;color:\{getRarityColor(g.rarity)};font-weight:600;">
          \{g.coins}c
        </div>
      </div>\\
    ).join('');
  };

  window.sendGift = function(giftId) {
    const gift = getGiftById(giftId);
    if (!gift) return;
    triggerGiftAnimation(gift, document.body);
    // Dispatch custom event for WebSocket integration
    document.dispatchEvent(new CustomEvent('nvme:gift-sent', { detail: gift }));
  };

  render();
}

// ============================================================
// Auto-inject styles if not present
// ============================================================
(function() {
  if (!document.getElementById('nvme-gift-styles')) {
    const style = document.createElement('style');
    style.id = 'nvme-gift-styles';
    style.textContent = \
      .nvme-gift-panel::-webkit-scrollbar { width: 6px; }
      .nvme-gift-panel::-webkit-scrollbar-thumb { background: rgba(124,58,237,0.5); border-radius: 3px; }
      .nvme-gift-grid::-webkit-scrollbar { width: 4px; }
      .nvme-gift-grid::-webkit-scrollbar-thumb { background: rgba(124,58,237,0.4); border-radius: 3px; }
      .nvme-cat-btn { transition: all 0.2s ease; }
      .nvme-cat-btn:hover { filter: brightness(1.2); }
      .nvme-bermuda-effect { animation: bermudaGlow 2.5s ease-out; }
      @keyframes bermudaGlow {
        0% { filter: hue-rotate(0deg) brightness(1); }
        50% { filter: hue-rotate(30deg) brightness(1.2); }
        100% { filter: hue-rotate(0deg) brightness(1); }
      }
    \;
    document.head.appendChild(style);
  }
})();

// ============================================================
// Module exports for Node.js / bundler use
// ============================================================
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    NVME_GIFTS,
    GIFT_CATEGORIES,
    getGiftsByCategory,
    searchGifts,
    getGiftById,
    getRarityColor,
    triggerGiftAnimation,
    createParticleExplosion,
    renderGiftPanel
  };
}
