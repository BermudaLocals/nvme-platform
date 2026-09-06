import { useState, useEffect } from 'react'
import EpicGift from './EpicGift'
import { gifts, getActiveGifts } from '../lib/gifts-catalog'

export default function BattleRoom({ socket, battleId }) {
  const [currentGift, setCurrentGift] = useState(null)
  const list = getActiveGifts? getActiveGifts() : gifts

  useEffect(() => {
    if (!socket) return
    const onEpic = (data) => {
      setCurrentGift(data)
      setTimeout(() => setCurrentGift(null), 2300)
    }
    const onGift = (data) => {
      if (data.epic) {
        setCurrentGift(data)
        setTimeout(() => setCurrentGift(null), 2300)
      }
    }
    socket.on('gift:epic', onEpic)
    socket.on('gift', onGift)
    return () => {
      socket.off('gift:epic', onEpic)
      socket.off('gift', onGift)
    }
  }, [socket])

  const sendGift = (gift) => {
    if (socket) socket.emit('gift:send', { battleId, giftId: gift.id, epic: gift.epic })
    if (gift.epic) {
      setCurrentGift({ type: gift.id, sender: 'You' })
      setTimeout(() => setCurrentGift(null), 2300)
    }
  }

  return (
    <div className="battle-room">
      {currentGift && <EpicGift {...currentGift} />}

      <div className="gift-bar">
        {list.map(g => (
          <button key={g.id} onClick={() => sendGift(g)} className={g.epic? 'epic-btn' : ''}>
            <img src={(g.file_url || '').replace('.webm','.png')} alt={g.name} />
            <span>{g.name}</span>
            <small>${(g.price_cents/100).toFixed(2)}</small>
          </button>
        ))}
      </div>

      <style jsx>{`
       .battle-room{position:relative}
       .gift-bar{display:flex;gap:8px;overflow-x:auto;padding:10px;background:rgba(0,0,0,.8);position:relative;z-index:2}
       .gift-bar button{min-width:84px;background:#222;border:1px solid #444;color:white;border-radius:10px;padding:6px;cursor:pointer}
       .epic-btn{border-color:gold!important;box-shadow:0 0 12px gold}
       .gift-bar img{width:48px;height:48px;object-fit:contain;margin:0 auto;display:block}
       .gift-bar span{display:block;font-size:11px;margin-top:4px;text-align:center}
       .gift-bar small{display:block;color:#aaa;text-align:center;font-size:10px}
      `}</style>
    </div>
  )
}
