export const gifts = [
  { id: 'bermuda-triangle', name: 'Bermuda Triangle', category: 'bermuda', price_cents: 10000, file_url: '/gifts/bermuda-triangle.png', legendary: true },
  { id: 'vs-beam', name: 'VS Clash', category: 'battle', price_cents: 7500, file_url: '/gifts/vs-beam.png', legendary: true },
  { id: 'hurricane-spin', name: 'Hurricane', category: 'bermuda', price_cents: 5000, file_url: '/gifts/hurricane-spin.png', legendary: false },
  { id: 'pink-sand-heart', name: 'Pink Sand Heart', category: 'bermuda', price_cents: 1000, file_url: '/gifts/pink-sand-heart.png', legendary: false },
  { id: 'bermuda-dolphin', name: 'Dolphin Jump', category: 'bermuda', price_cents: 2000, file_url: '/gifts/bermuda-dolphin.png', legendary: false },
  { id: 'wonders-eiffel', name: 'Eiffel Spark', category: 'wonders', price_cents: 3000, file_url: '/gifts/wonders-eiffel.png', legendary: false },
  { id: 'wonders-taj', name: 'Taj Glow', category: 'wonders', price_cents: 3000, file_url: '/gifts/wonders-taj.png', legendary: false },
  { id: 'halloween-pumpkin', name: 'Pumpkin Blast', category: 'holidays', price_cents: 1500, file_url: '/gifts/halloween-pumpkin.png', legendary: false },
  { id: 'xmas-tree', name: 'Xmas Nova', category: 'holidays', price_cents: 1500, file_url: '/gifts/xmas-tree.png', legendary: false },
  { id: 'carnival-mask', name: 'Carnival', category: 'holidays', price_cents: 2000, file_url: '/gifts/carnival-mask.png', legendary: false },
  { id: 'dolphins-helmet', name: 'Dolphins Wave', category: 'sports', price_cents: 2500, file_url: '/gifts/dolphins-helmet.png', legendary: false },
  { id: 'cowboys-star', name: 'Cowboys Star', category: 'sports', price_cents: 2500, file_url: '/gifts/cowboys-star.png', legendary: false },
]

export const getActiveGifts = () => {
  const month = new Date().getMonth() + 1
  return gifts.filter(g => {
    if (g.category === 'holidays' && g.id.includes('halloween') && month!== 10) return false
    if (g.id.includes('xmas') && month!== 12) return false
    return true
  })
}
