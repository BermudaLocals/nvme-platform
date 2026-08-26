'use client';
import { useEffect, useRef, useState } from 'react';

const FILTERS = [
  { id: 'none', label: 'Original', css: '' },
  { id: 'beauty', label: 'Beauty', css: 'brightness(1.12) contrast(1.05) saturate(1.1)' },
  { id: 'glow', label: 'Glow', css: 'brightness(1.25) saturate(1.3) contrast(1.1)' },
  { id: 'vintage', label: 'Vintage', css: 'sepia(0.6) contrast(1.15) brightness(0.95)' },
  { id: 'warm', label: 'Warm', css: 'sepia(0.35) saturate(1.6) hue-rotate(-8deg)' },
  { id: 'cool', label: 'Cool', css: 'hue-rotate(18deg) saturate(1.15) brightness(1.08)' },
];

const VOICE_EFFECTS = ['Normal','Chipmunk','Robot','Deep','Echo','Underwater','Telephone','Alien'];

export default function CreatorStudioLive() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [activeFilter, setActiveFilter] = useState('none');
  const [facing, setFacing] = useState<'user' | 'environment'>('user');
  const [isLive, setIsLive] = useState(false);
  const [viewers, setViewers] = useState(0);
  const [voiceEffect, setVoiceEffect] = useState('Normal');
  const [showVoice, setShowVoice] = useState(false);

  const startCamera = async (mode = facing) => {
    try {
      if (streamRef.current) streamRef.current.getTracks().forEach(t => t.stop());
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: mode, width: { ideal: 1080 }, height: { ideal: 1920 } },
        audio: true
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play().catch(()=>{});
      }
    } catch (e) { console.error('Camera failed', e); }
  };

  useEffect(() => {
    startCamera();
    try {
      const saved = JSON.parse(localStorage.getItem('livehub_ring_state') || '{}');
      if (saved.activeFilter) setActiveFilter(saved.activeFilter);
      if (saved.facing) setFacing(saved.facing);
    } catch {}
    return () => { streamRef.current?.getTracks().forEach(t => t.stop()); };
  }, []);

  const saveRing = async (updates: any) => {
    const state = { activeFilter, facing, ...updates };
    localStorage.setItem('livehub_ring_state', JSON.stringify(state));
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await fetch('/api/live/effects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ active_filter: state.activeFilter, filter_state: state, live_mode: 'tiktok' })
        });
      }
    } catch {}
  };

  const handleFlip = async () => {
    const newFacing = facing === 'user' ? 'environment' : 'user';
    setFacing(newFacing);
    await startCamera(newFacing);
    saveRing({ facing: newFacing });
  };

  const handleFilter = (id: string) => {
    setActiveFilter(id);
    saveRing({ activeFilter: id });
  };

  const currentCss = FILTERS.find(f => f.id === activeFilter)?.css || '';

  return (
    <div className="relative h-[100dvh] w-full bg-black overflow-hidden flex flex-col">
      <div className="relative flex-1 overflow-hidden bg-black">
        <video ref={videoRef} autoPlay muted playsInline className="absolute inset-0 h-full w-full object-cover" style={{ filter: currentCss, transform: facing === 'user' ? 'scaleX(-1)' : 'none' }} />
        <div className="absolute inset-0 -z-10 bg-gradient-to-br from-pink-600 via-purple-600 to-cyan-500" />
        <div className="absolute top-0 left-0 right-0 z-20 flex items-center justify-between p-3 pt-12 sm:pt-3">
          <div className="flex items-center gap-2 rounded-full bg-black/50 px-3 py-1.5 text-xs font-bold text-white backdrop-blur">ðŸŽµ Add sound</div>
          <div className="flex items-center gap-2 rounded-full bg-black/50 px-2 py-1 text-[10px] text-white backdrop-blur"><span className="text-yellow-400">Est. $0.02</span><span className="max-w-[140px] truncate hidden sm:inline">Scaled LIVE Rewards</span></div>
        </div>
        {isLive && <div className="absolute top-16 left-3 z-20 rounded-full bg-black/60 px-3 py-1 text-xs font-bold text-white backdrop-blur">ðŸ‘ï¸ {viewers} viewers â€¢ ðŸ”´ LIVE</div>}
      </div>

      <div className="fixed bottom-0 left-0 w-full bg-black/90 backdrop-blur-md text-white flex flex-col z-50 select-none border-t border-white/10">
        <div className="flex gap-3 overflow-x-auto px-3 py-2 scrollbar-hide border-b border-white/10">
          {FILTERS.map(f => (
            <button key={f.id} onClick={() => handleFilter(f.id)} className={`flex flex-col items-center gap-1.5 shrink-0 transition-all ${activeFilter === f.id ? 'scale-105' : 'opacity-70'}`}>
              <div className={`h-14 w-14 rounded-full bg-gradient-to-br from-pink-400 to-cyan-400 p-[2px] ${activeFilter === f.id ? 'ring-2 ring-cyan-400' : ''}`}><div className="h-full w-full rounded-full bg-zinc-800 flex items-center justify-center text-[10px] font-bold" style={{ filter: f.css }}>{f.label[0]}</div></div>
              <span className={`text-[10px] font-bold ${activeFilter === f.id ? 'text-cyan-400' : 'text-white'}`}>{f.label}</span>
            </button>
          ))}
        </div>

        <div className="grid grid-cols-5 gap-2 p-3 text-center text-[11px] border-b border-white/10">
          <button onClick={handleFlip} className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸ”„</span><span>Flip</span></button>
          <button onClick={() => handleFilter(activeFilter === 'beauty' ? 'none' : 'beauty')} className={`flex flex-col items-center gap-1 transition ${activeFilter === 'beauty' ? 'text-pink-500' : 'hover:text-pink-500'}`}><span className="text-xl">âœ¨</span><span>Beautify</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸŽ¨</span><span>Effects</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">âš™ï¸</span><span>Settings</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸ‘¥</span><span>Hangout</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸ“‹</span><span>Boards</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸ›Žï¸</span><span>Service+</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">ðŸ‘‘</span><span>Fan Club</span></button>
          <button onClick={() => setShowVoice(!showVoice)} className={`flex flex-col items-center gap-1 transition ${showVoice ? 'text-pink-500' : 'hover:text-pink-500'}`}><span className="text-xl">ðŸŽ™ï¸</span><span>Interact</span></button>
          <button className="flex flex-col items-center gap-1 hover:text-pink-500 transition"><span className="text-xl">â†—ï¸</span><span>Share</span></button>
        </div>

        {showVoice && <div className="grid grid-cols-4 gap-2 p-3 text-[10px] bg-zinc-900/50 border-b border-white/10">{VOICE_EFFECTS.map(v => (<button key={v} onClick={() => setVoiceEffect(v)} className={`rounded-full px-2 py-2 font-bold border ${voiceEffect === v ? 'bg-pink-500 border-pink-500 text-white' : 'bg-white/10 border-white/10 hover:bg-white/20'}`}>{v}</button>))}</div>}

        <div className="flex justify-between items-center px-4 py-2 bg-black/40 text-sm"><span className="truncate font-medium text-xs">ðŸ›¡ Build Your Digital System</span><span className="text-[10px] bg-white/10 px-2 py-1 rounded-full cursor-pointer">ðŸŽ¯ LIVE goal</span></div>

        <div className="px-4 py-3"><button onClick={() => { setIsLive(!isLive); if (!isLive) setViewers(Math.floor(Math.random()*10)); else setViewers(0); }} className={`w-full ${isLive ? 'bg-zinc-700 hover:bg-zinc-600' : 'bg-[#FE2C55] hover:bg-[#e6264d]'} text-white font-black py-3.5 rounded-full text-center shadow-lg transition tracking-wider`}>{isLive ? 'â–  End LIVE' : 'Go LIVE'}</button></div>

        <div className="flex justify-around text-[11px] text-white/70 py-2 border-t border-white/10"><span className="cursor-pointer hover:text-white">Voice chat</span><span className="cursor-pointer text-white font-semibold border-b-2 border-white pb-0.5">Device camera</span><span className="cursor-pointer hover:text-white">Mobile gaming</span><span className="cursor-pointer hover:text-white">LIVE Studio</span></div>

        <div className="flex justify-center gap-8 py-3 text-[13px] font-black tracking-wider bg-black"><span className="text-white cursor-pointer border-b-2 border-white pb-1">LIVE</span><span className="text-white/40 cursor-pointer hover:text-white">POST</span><span className="text-white/40 cursor-pointer hover:text-white">CREATE</span></div>
      </div>
      <style>{`.scrollbar-hide::-webkit-scrollbar{display:none}.scrollbar-hide{-ms-overflow-style:none;scrollbar-width:none}`}</style>
    </div>
  );
}
