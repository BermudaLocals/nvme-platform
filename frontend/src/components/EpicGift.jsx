export default function EpicGift({ type, sender }) {
  return (
    <div className="epic-stage">
      <div className="gift-3d">
        <img src={`/gifts/${type}.png`} alt={type} />
        <div className="gift-glow"></div>
      </div>
      <div className="sender-tag">{sender} sent {type}!</div>
      <style>{`
        .epic-stage{position:fixed;inset:0;z-index:9999;perspective:1000px;pointer-events:none;display:flex;align-items:center;justify-content:center}
        .gift-3d{width:90vw;max-width:700px;transform-style:preserve-3d;animation:outOfScreen 2.2s cubic-bezier(.17,.89,.32,1.49) forwards}
        .gift-3d img{width:100%;filter:drop-shadow(0 20px 60px rgba(255,215,0,.8)) drop-shadow(0 0 100px gold)}
        .gift-glow{position:absolute;inset:-50%;background:radial-gradient(circle,rgba(255,215,0,.4) 0%,transparent 70%);animation:pulse .8s ease-out}
        @keyframes outOfScreen{0%{transform:translateZ(-800px) scale(.1) rotateY(-30deg);opacity:0}25%{transform:translateZ(200px) scale(1.4) rotateY(15deg);opacity:1}60%{transform:translateZ(80px) scale(1.1)}100%{transform:translateZ(0) scale(1);opacity:0}}
        @keyframes pulse{0%{transform:scale(0);opacity:1}100%{transform:scale(2);opacity:0}}
        .epic-stage{animation:shake .3s .2s}.sender-tag{position:absolute;bottom:20%;color:white;font-weight:800;text-shadow:0 2px 10px black}
        @keyframes shake{0%,100%{transform:translate(0)}25%{transform:translate(-8px,5px)}75%{transform:translate(8px,-5px)}}
      `}</style>
    </div>
  )
}
