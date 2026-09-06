export default function EpicGift({ id, type, sender }) {
  const giftId = type || id || 'bermuda-triangle'
  return (
    <div className="epic-stage">
      <div className="gift-3d">
        <img src={`/gifts/${giftId}.png`} alt={giftId} />
        <div className="glow"></div>
      </div>
      <div className="tag">{sender || 'Someone'} sent {giftId}!</div>
      <style jsx>{`
       .epic-stage{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;pointer-events:none;perspective:1200px}
       .gift-3d{width:92vw;max-width:720px;animation:out 2.2s cubic-bezier(.17,.89,.32,1.49) forwards;transform-style:preserve-3d;position:relative}
       .gift-3d img{width:100%;filter:drop-shadow(0 20px 60px rgba(255,215,0,.85)) drop-shadow(0 0 120px gold)}
       .glow{position:absolute;inset:-40%;background:radial-gradient(circle,rgba(255,215,0,.45) 0%,transparent 70%);animation:pulse.7s ease-out forwards}
       .tag{position:absolute;bottom:18%;font-size:22px;font-weight:900;color:white;text-shadow:0 2px 12px black,0 0 20px gold}
        @keyframes out{0%{transform:translateZ(-1000px) scale(.08) rotateY(-30deg);opacity:0}22%{transform:translateZ(300px) scale(1.5) rotateY(18deg);opacity:1}65%{transform:translateZ(90px) scale(1.15)}100%{transform:translateZ(0) scale(1);opacity:0}}
        @keyframes pulse{0%{transform:scale(0);opacity:1}100%{transform:scale(2.2);opacity:0}}
      `}</style>
    </div>
  )
}
