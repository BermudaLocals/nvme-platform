export const gifts = [
  // BERMUDA - money maker
  { id: 'bermuda-triangle', name: 'Bermuda Triangle', price_cents: 5000, category: 'bermuda', file_url: '/gifts/bermuda-triangle.webm', epic: true },
  { id: 'pink-sand', name: 'Pink Sand', price_cents: 1000, category: 'bermuda', file_url: '/gifts/pink-sand.webm' },
  { id: 'bermuda-hurricane', name: 'Hurricane', price_cents: 2500, category: 'bermuda', file_url: '/gifts/hurricane.webm', epic: true },

  // WONDERS
  { id: 'taj-mahal', name: 'Taj Mahal', price_cents: 3000, category: 'wonders', file_url: '/gifts/taj-mahal.webm', epic: true },
  { id: 'eiffel-tower', name: 'Eiffel Tower', price_cents: 2000, category: 'wonders', file_url: '/gifts/eiffel.webm' },
  { id: 'pyramid', name: 'Pyramid', price_cents: 2000, category: 'wonders', file_url: '/gifts/pyramid.webm' },

  // HOLIDAYS - auto rotate
  { id: 'halloween-pumpkin', name: 'Halloween', price_cents: 1500, category: 'holidays', season_start: '10-01', season_end: '10-31', file_url: '/gifts/halloween.webm', epic: true },
  { id: 'xmas-tree', name: 'Christmas Tree', price_cents: 2000, category: 'holidays', season_start: '12-01', season_end: '12-31', file_url: '/gifts/xmas.webm', epic: true },
  { id: 'thanksgiving-turkey', name: 'Thanksgiving', price_cents: 1000, category: 'holidays', season_start: '11-20', season_end: '11-30', file_url: '/gifts/turkey.webm' },
  { id: 'carnival-mask', name: 'Carnival', price_cents: 1800, category: 'holidays', season_start: '02-01', season_end: '03-15', file_url: '/gifts/carnival.webm', epic: true },

  // SPORTS - battle
  { id: 'dolphins-helmet', name: 'Dolphins', price_cents: 1200, category: 'sports', file_url: '/gifts/dolphins.webm' },
  { id: 'cowboys-star', name: 'Cowboys', price_cents: 1200, category: 'sports', file_url: '/gifts/cowboys.webm' },
  { id: 'vs-battle-beam', name: 'VS BATTLE BEAM', price_cents: 10000, category: 'sports', file_url: '/gifts/vs-beam.webm', epic: true },
]

export const getActiveGifts = () => {
  const month = new Date().toISOString().slice(5,10) // MM-DD
  return gifts.filter(g => {
    if (!g.season_start) return true
    return month >= g.season_start && month <= g.season_end
  })
}
