(function(){
const RING_STYLES=['solid','gradient','neon','pulse','gold','rainbow'];
const RING_COLORS=['#e91e8c','#00d4ff','#00e676','#ffd600','#ff1744','#7c5cfc','#ffffff'];
function injectUI(){
  const ringEl=document.getElementById('live-ring');
  if(!ringEl||document.getElementById('ring-controls'))return;
  ringEl.insertAdjacentHTML('afterend',`
  <div id="ring-controls" style="width:100%;margin-top:14px;background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:12px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span style="font-size:0.75rem;font-weight:700;letter-spacing:.08em;color:var(--muted);">SELECTOR RING</span>
      <span id="ring-preview-dot" style="width:18px;height:18px;border-radius:50%;background:${localStorage.getItem('nvme_ring_color')||'#00d4ff'};border:2px solid #fff;display:inline-block;"></span>
    </div>
    <div id="ring-style-row" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;"></div>
    <div id="ring-color-row" style="display:flex;gap:6px;flex-wrap:wrap;"></div>
  </div>`);
  const styleRow=document.getElementById('ring-style-row');
  const colorRow=document.getElementById('ring-color-row');
  const savedStyle=localStorage.getItem('nvme_ring_style')||'neon';
  const savedColor=localStorage.getItem('nvme_ring_color')||'#00d4ff';
  RING_STYLES.forEach(st=>{const b=document.createElement('button');b.className='btn btn-ghost btn-sm';b.textContent=st;b.style.fontSize='0.70rem';if(st===savedStyle){b.style.borderColor='var(--cyan)';b.style.color='var(--cyan)';}b.onclick=()=>{localStorage.setItem('nvme_ring_style',st);applyRingStyle(st,localStorage.getItem('nvme_ring_color')||savedColor);emitRing();highlightStyles(st);};styleRow.appendChild(b);});
  RING_COLORS.forEach(c=>{const b=document.createElement('button');b.style.width='28px';b.style.height='28px';b.style.borderRadius='50%';b.style.background=c;b.style.border=c===savedColor?'2px solid #fff':'1px solid var(--border)';b.style.cursor='pointer';b.onclick=()=>{localStorage.setItem('nvme_ring_color',c);applyRingStyle(localStorage.getItem('nvme_ring_style')||savedStyle,c);emitRing();highlightColors(c);document.getElementById('ring-preview-dot').style.background=c;};colorRow.appendChild(b);});
  applyRingStyle(savedStyle,savedColor);
}
function highlightStyles(a){document.querySelectorAll('#ring-style-row .btn').forEach(btn=>{if(btn.textContent===a){btn.style.borderColor='var(--cyan)';btn.style.color='var(--cyan)';}else{btn.style.borderColor='';btn.style.color='';}});}
function highlightColors(a){document.querySelectorAll('#ring-color-row button').forEach(btn=>{btn.style.border=(btn.style.background===a?'2px solid #fff':'1px solid var(--border)');});}
window.applyRingStyle=function(style,color){
  const ring=document.getElementById('live-ring');if(!ring)return;
  ring.style.boxShadow='none';ring.style.border='none';ring.style.background='transparent';ring.style.borderRadius='50%';
  switch(style){
    case 'solid':ring.style.border=`4px solid ${color}`;break;
    case 'gradient':ring.style.background=`linear-gradient(135deg, ${color}, #e91e8c)`;ring.style.padding='4px';break;
    case 'neon':ring.style.border=`3px solid ${color}`;ring.style.boxShadow=`0 0 12px ${color}, 0 0 24px ${color}`;break;
    case 'pulse':ring.style.border=`3px solid ${color}`;ring.classList.add('pulsing');break;
    case 'gold':ring.style.border=`4px solid transparent`;ring.style.background=`linear-gradient(var(--card),var(--card)) padding-box, linear-gradient(135deg,#ffd600,#ff8f00) border-box`;break;
    case 'rainbow':ring.style.border=`4px solid transparent`;ring.style.background=`linear-gradient(var(--card),var(--card)) padding-box, conic-gradient(from 0deg, #ff0050,#ffd600,#00e676,#00d4ff,#7c5cfc,#ff0050) border-box`;break;
  }
};
function emitRing(){
  const style=localStorage.getItem('nvme_ring_style')||'neon';
  const color=localStorage.getItem('nvme_ring_color')||'#00d4ff';
  try{if(window.socket&&window.currentStreamId){socket.emit('selector_ring_change',{streamId:currentStreamId,style,color,ring:{style,color}});}}catch{}
}
const orig=window.setCameraFilter;
window.setCameraFilter=function(f,el){
  if(orig)orig(f,el);
  localStorage.setItem('nvme_cam_filter',f);
  try{if(window.socket&&window.currentStreamId){socket.emit('live_filter_change',{streamId:currentStreamId,filter:f,intensity:1});socket.emit('selector_ring_change',{streamId:currentStreamId,style:localStorage.getItem('nvme_ring_style')||'neon',color:localStorage.getItem('nvme_ring_color')||'#00d4ff',filter:f});}}catch{}
};
window.addEventListener('load',()=>{setTimeout(()=>{injectUI();const sf=localStorage.getItem('nvme_cam_filter');if(sf&&sf!=='none'){try{setCameraFilter(sf);}catch{}}const s=localStorage.getItem('nvme_ring_style')||'neon';const c=localStorage.getItem('nvme_ring_color')||'#00d4ff';applyRingStyle(s,c);},800);});
})();
