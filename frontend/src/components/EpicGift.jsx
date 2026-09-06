export default function EpicGift({ id, type, sender, price_cents }) {
  const giftId = type || id || 'bermuda-triangle'
  return (
    <div className="epic-stage">
      <div className="gift-3d">
        <img src={`/gifts/${giftId}.png`} alt={giftId} onError={(e)=>e.target.src=`/gifts/${giftId}.webm`} />
        <div className="gift-glow"></div>
      </div>
      <div className="sender-tag">{sender || 'Someone'} sent {giftId}!</div>
      <style>{`
        .epic-stage{position:fixed;inset:0;z-index:9999;perspective:1200px;pointer-events:none;display:flex;align-items:center;justify-content:center}
        .gift-3d{width:92vw;max-width:720px;transform-style:preserve-3d;animation:outOfScreen 2.2s cubic-bezier(.17,.89,.32,1.49) forwards}
        .gift-3d img{width:100%;filter:drop-shadow(0 20px 60px rgba(255,215,0,.85)) drop-shadow(0 0 120px gold)}
        .gift-glow{position:absolute;inset:-40%;background:radial-gradient(circle,rgba(255,215,0,.45) 0%,transparent 70%);animation:pulse .7s ease-out forwards}
        @keyframes outOfScreen{0%{transform:translateZ(-1000px) scale(.08) rotateY(-30deg) rotateX(10deg);opacity:0}22%{transform:translateZ(300px) scale(1.5) rotateY(18deg);opacity:1}65%{transform:translateZ(90px) scale(1.15)}100%{transform:translateZ(0) scale(1);opacity:0}}
        @keyframes pulse{0%{transform:scale(0);opacity:1}100%{transform:scale(2.2);opacity:0}}
        .sender-tag{position:absolute;bottom:18%;font-size:22px;font-weight:900;color:white;text-shadow:0 2px 12px black,0 0 20px gold}
        .epic-stage{animation:shake .28s .18s}
        @keyframes shake{0%,100%{transform:translate(0)}20%{transform:translate(-10px,4px)}60%{transform:translate(10px,-4px)}}
      `}</style>
    </div>
  )
}
