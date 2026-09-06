export const gifts = {
  // WONDERS - $0.99 - $99 (Bermuda = 8th wonder)
  wonders: [
    { id: 'bermuda-triangle', name: 'Bermuda Triangle Portal', price: 999, file: 'bermuda-triangle.webm', rarity: 'legendary' },
    { id: 'eiffel', name: 'Eiffel Tower', price: 499 },
    { id: 'pyramids', name: 'Pyramids', price: 499 },
    { id: 'christ-redeemer', name: 'Christ the Redeemer', price: 799 },
    { id: 'colosseum', name: 'Colosseum', price: 399 },
    { id: 'taj-mahal', name: 'Taj Mahal', price: 399 },
    { id: 'great-wall', name: 'Great Wall', price: 599 },
    { id: 'pink-sand', name: 'Pink Sand Beach', price: 199, bermuda: true },
  ],
  // BERMUDA - your exclusive
  bermuda: [
    { id: 'hamilton-harbour', name: 'Hamilton Harbour Lights', price: 299 },
    { id: 'gombey', name: 'Gombey Dancer', price: 199 },
    { id: 'rum-swizzle', name: 'Rum Swizzle', price: 99 },
  ],
  // HOLIDAYS - ROTATE SEASONALLY = $$$$
  holidays: {
    halloween: [{ id: 'haunted-triangle', name: 'Haunted Triangle', price: 699, season: 'Oct 1-31' }],
    christmas: [{ id: 'xmas-lights', name: 'Xmas Lights Over Hamilton', price: 599, season: 'Dec 1-26' }],
    thanksgiving: [{ id: 'turkey-battle', name: 'Turkey Battle', price: 299, season: 'Nov 20-28' }],
    carnival: [{ id: 'carnival-float', name: 'Bermuda Carnival', price: 499, season: 'Jun' }],
  },
  // SPORTS - GAME NIGHT BATTLES (your killer feature)
  sports: [
    { id: 'nfl-dolphins', name: 'Dolphins Wave', price: 199, team: 'NFL' },
    { id: 'nfl-cowboys', name: 'Cowboys Star', price: 199, team: 'NFL' },
    // Add all 32 NFL + NBA + Premier League
    { id: 'game-night-vs', name: 'VS Battle Beam', price: 999, effect: 'splits screen team vs team' },
  ]
}
