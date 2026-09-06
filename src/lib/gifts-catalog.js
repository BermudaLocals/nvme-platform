export const gifts = [
  // BERMUDA - NVME
  { id: 'bermuda-triangle', name: 'Bermuda Triangle', price_cents: 5000, category: 'bermuda', file_url: '/gifts/bermuda-triangle.png', legendary: true },
  { id: 'daily-hug', name: 'Hug', price_cents: 100, category: 'bermuda', file_url: '/gifts/daily-hug.png', legendary: false, club: true },
  { id: 'bermuda-hurricane', name: 'Hurricane', price_cents: 2500, category: 'bermuda', file_url: '/gifts/hurricane-spin.png', legendary: true },
  { id: 'bermuda-dolphin', name: 'Dolphin', price_cents: 2000, category: 'bermuda', file_url: '/gifts/bermuda-dolphin.png', legendary: false },

  // WONDERS
  { id: 'taj-mahal', name: 'Taj Mahal', price_cents: 3000, category: 'wonders', file_url: '/gifts/wonders-taj.png', legendary: true },
  { id: 'eiffel-tower', name: 'Eiffel Tower', price_cents: 2000, category: 'wonders', file_url: '/gifts/wonders-eiffel.png', legendary: false },
  { id: 'pyramid', name: 'Pyramid', price_cents: 2000, category: 'wonders', file_url: '/gifts/pyramid.png', legendary: false },

  // HOLIDAYS - auto rotate by season
  { id: 'halloween-pumpkin', name: 'Halloween', price_cents: 1500, category: 'holidays', season_start: '10-01', season_end: '10-31', file_url: '/gifts/halloween-pumpkin.png', legendary: true },
  { id: 'xmas-tree', name: 'Christmas Tree', price_cents: 2000, category: 'holidays', season_start: '12-01', season_end: '12-31', file_url: '/gifts/xmas-tree.png', legendary: true },
  { id: 'thanksgiving-turkey', name: 'Thanksgiving', price_cents: 1000, category: 'holidays', season_start: '11-20', season_end: '11-30', file_url: '/gifts/thanksgiving-turkey.png', legendary: false },
  { id: 'carnival-mask', name: 'Carnival', price_cents: 1800, category: 'holidays', season_start: '02-01', season_end: '03-15', file_url: '/gifts/carnival-mask.png', legendary: true },

  // SPORTS - battle
  { id: 'dolphins-helmet', name: 'Dolphins', price_cents: 1200, category: 'sports', file_url: '/gifts/dolphins-helmet.png', legendary: false },
  { id: 'cowboys-star', name: 'Cowboys', price_cents: 1200, category: 'sports', file_url: '/gifts/cowboys-star.png', legendary: false },
  { id: 'vs-battle-beam', name: 'VS BATTLE BEAM', price_cents: 10000, category: 'sports', file_url: '/gifts/vs-beam.png', legendary: true },
]

export const getActiveGifts = () => {
  const month = new Date().toISOString().slice(5,10) // MM-DD
  return gifts.filter(g => {
    if (!g.season_start) return true
    return month >= g.season_start && month <= g.season_end
  })
}
