import { useState, useEffect } from 'react'
import EpicGift from './EpicGift'
import { gifts, getActiveGifts } from '../lib/gifts-catalog'
import { backgrounds } from '../lib/backgrounds-catalog'

export default function BattleRoom({ socket, battleId }) {
  const [currentGift, setCurrentGift] = useState(null)
  const [filter, setFilter] = useState('all')
  const [bg, setBg] = useState(backgrounds[0])

  const allGifts = getActiveGifts? getActiveGifts() : gifts
  const filtered = filter === 'all'? allGifts : allGifts.filter(g => g.category === filter || (filter==='epic' && g.epic))

  useEffect(() => {
    if (!socket) return
    const onEpic = (d) => { setCurrentGift(d); setTimeout(()=>setCurrentGift(null),2300) }
    socket.on('gift:epic', onEpic)
    socket.on('gift', (d)=>{ if(d.epic) onEpic(d) })
    return () => { socket.off('gift:epic', onEpic); socket.off('gift') }
  }, [socket])

  const sendGift = (gift) => {
    socket?.emit('gift:send', { battleId, giftId: gift.id, epic: gift.epic })
    if (gift.epic) { setCurrentGift({ type: gift.id, sender: 'You' }); setTimeout(()=>setCurrentGift(null),2300) }
  }

  return (
    <div className="room" style={{ backgroundImage: `url(${bg.file})` }}>
      <div className="overlay"></div>
      {currentGift && <EpicGift {...currentGift} />}

      <div className="topbar">
        <div className="filters">
          {['all','bermuda','wonders','holidays','sports','epic'].map(c => (
            <button key={c} onClick={()=>setFilter(c)} className={filter===c?'active':''}>{c.toUpperCase()}</button>
          ))}
        </div>
        <div className="bglist">
          {backgrounds.map(b => (
            <button key={b.id} onClick={()=>setBg(b)} className={bg.id===b.id?'active-bg':''} title={b.name}>
              <img src={b.file} alt={b.name} />
            </button>
          ))}
        </div>
      </div>

      <div className="gift-bar">
        {filtered.map(g => (
          <button key={g.id} onClick={()=>sendGift(g)} className={g.epic?'epic-btn':''}>
            <img src={(g.file_url||'').replace('.webm','.png')} alt={g.name} />
            <span>{g.name}</span>
            <small>${(g.price_cents/100).toFixed(2)}</small>
          </button>
        ))}
      </div>

      <style jsx>{`
      .room{position:relative;min-height:100vh;background-size:cover;background-position:center;overflow:hidden}
      .overlay{position:absolute;inset:0;background:linear-gradient(0deg,rgba(0,0,0,.85) 0%,rgba(0,0,0,.2) 60%,rgba(0,0,0,.4) 100%);z-index:1}
      .topbar{position:relative;z-index:3;padding:8px;background:rgba(0,0,0,.6);backdrop-filter:blur(8px)}
      .filters{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px}
      .filters button{background:#222;border:1px solid #333;color:#aaa;padding:6px 12px;border-radius:20px;font-size:11px;cursor:pointer;white-space:nowrap}
      .filters.active{background:gold;color:black;border-color:gold;font-weight:900}
      .bglist{display:flex;gap:6px;overflow-x:auto;margin-top:8px}
      .bglist button{width:56px;height:36px;border-radius:6px;overflow:hidden;border:2px solid transparent;padding:0;cursor:pointer;opacity:.7}
      .bglist.active-bg{border-color:gold;opacity:1;box-shadow:0 0 8px gold}
      .bglist img{width:100%;height:100%;object-fit:cover}
      .gift-bar{position:relative;z-index:3;display:flex;gap:8px;overflow-x:auto;padding:10px;background:rgba(0,0,0,.75)}
      .gift-bar button{min-width:84px;background:#222;border:1px solid #444;color:white;border-radius:10px;padding:6px;cursor:pointer}
      .epic-btn{border-color:gold!important;box-shadow:0 0 12px gold}
      .gift-bar img{width:48px;height:48px;object-fit:contain;margin:0 auto;display:block}
      .gift-bar span{display:block;font-size:11px;margin-top:4px;text-align:center}
      .gift-bar small{display:block;color:#aaa;text-align:center;font-size:10px}
      `}</style>
    </div>
  )
}
