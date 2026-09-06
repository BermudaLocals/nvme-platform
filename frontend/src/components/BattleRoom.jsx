import { useState, useEffect } from 'react'
import EpicGift from './EpicGift'
import { gifts, getActiveGifts } from '../lib/gifts-catalog'

export default function BattleRoom({ socket, battleId }) {
  const [currentGift, setCurrentGift] = useState(null)
  const activeGifts = getActiveGifts()

  useEffect(() => {
    if (!socket) return
    socket.on('gift:epic', (data) => {
      setCurrentGift(data)
      setTimeout(() => setCurrentGift(null), 2300)
    })
    socket.on('gift', (data) => {
      if (data.epic) {
        setCurrentGift(data)
        setTimeout(() => setCurrentGift(null), 2300)
      }
    })
    return () => {
      socket.off('gift:epic')
      socket.off('gift')
    }
  }, [socket])

  const sendGift = (gift) => {
    socket.emit('gift:send', { battleId, giftId: gift.id, epic: gift.epic })
    if (gift.epic) {
      setCurrentGift({ type: gift.id, sender: 'You' })
      setTimeout(() => setCurrentGift(null), 2300)
    }
  }

  return (
    <div className="battle-room">
      {currentGift && <EpicGift {...currentGift} />}

      <div className="gift-bar">
        {activeGifts.map(g => (
          <button key={g.id} onClick={() => sendGift(g)} className={g.epic? 'epic-btn' : ''}>
            <img src={g.file_url.replace('.webm','.png')} alt={g.name} />
            <span>{g.name}</span>
            <small>${(g.price_cents/100).toFixed(2)}</small>
          </button>
        ))}
      </div>

      <style>{`
       .gift-bar{display:flex;gap:8px;overflow-x:auto;padding:10px;background:rgba(0,0,0,.8)}
       .gift-bar button{min-width:80px;background:#222;border:1px solid #444;color:white;border-radius:8px;padding:6px}
       .epic-btn{border-color:gold!important;box-shadow:0 0 10px gold}
       .gift-bar img{width:48px;height:48px;object-fit:contain}
      `}</style>
    </div>
  )
}
