
// ════════════════════════════════════════════
// DATA
// ════════════════════════════════════════════
const N = Date.now()/1000;

let AGENTS = [];
let ALL_ALERTS = [];
let TIER_INFO = null;
// ════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════
function genH(b,n){const r=[];for(let i=30;i>=0;i--){const v=Math.max(0,Math.min(1,b+(Math.random()-.5)*n*2));r.push({t:N-i*86400,v:+v.toFixed(3)})}return r}
function sc(s){return{SAFE:'#00e676',WATCH:'#ffb300',ALERT:'#ff6200',CRITICAL:'#f5003c',STABLE:'#00e676',UNSTABLE:'#ff6200',NONE:'#3a5570',LOW:'#ffb300',MEDIUM:'#ff6200',HIGH:'#ff6200',OK:'#00e676',stable:'#00e676',watch:'#ffb300',alert:'#ff6200',cluster:'#ff6200',fork:'#f5003c',rotation:'#ffb300',critical:'#f5003c'}[s]||'#3a5570'}
function scls(s){return{SAFE:'bs',WATCH:'bw',ALERT:'ba',CRITICAL:'bc',STABLE:'bs',UNSTABLE:'ba'}[s]||'bs'}
function fv(v){return typeof v==='number'?v.toFixed(3):'—'}
function rt(ts){const s=Math.floor(N-ts);if(s<60)return`${s}s ago`;if(s<3600)return`${Math.floor(s/60)}m ago`;if(s<86400)return`${Math.floor(s/3600)}h ago`;return`${Math.floor(s/86400)}d ago`}
function sbar(v,col,mw){mw=mw||100;return`<div class="sbar"><div class="sbt" style="max-width:${mw}px"><div class="sbf" style="width:${v*100}%;background:${col}"></div></div><span class="sbn" style="color:${col}">${fv(v)}</span></div>`}
function sparkPts(vals,W,H){if(vals.length<2)return{l:'',a:''};const xs=vals.map((_,i)=>i/(vals.length-1)*W);const ys=vals.map(v=>H-v*H);const l=`M ${xs.map((x,i)=>`${x},${ys[i]}`).join(' L ')}`;const a=`M ${xs[0]},${H} L ${xs.map((x,i)=>`${x},${ys[i]}`).join(' L ')} L ${xs[xs.length-1]},${H} Z`;return{l,a}}
function aRow(a){const c=sc(a.sev);return`<div class="arow"><span class="ar-sev" style="color:${c}">${a.sev}</span><span class="ar-ag">${a.ag||''}</span><span class="ar-msg">${a.msg||''}</span><span class="ar-t">${rt(a.t)}</span></div>`}

const sel={};AGENTS.forEach(a=>sel[a.name]=true);
setInterval(()=>{document.getElementById('top-clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'},1000);

// ════════════════════════════════════════════
// OVERVIEW
// ════════════════════════════════════════════
function renderOverview(){
  // Global VRS = max agent VRS (worst case), pas la moyenne
  const gv=AGENTS.length?Math.max(...AGENTS.map(a=>a.vrs)):0;
  const vrs=+gv.toFixed(3),state=vrs>=0.75?'CRITICAL':vrs>=0.50?'ALERT':vrs>=0.25?'WATCH':'SAFE',col=sc(state);
  const arc=document.getElementById('vrs-arc');
  const AL=163;arc.style.strokeDashoffset=AL;
  setTimeout(()=>{arc.style.strokeDashoffset=AL-(vrs*AL);arc.style.stroke=col},100);
  document.getElementById('vrs-txt').textContent=fv(vrs);
  document.getElementById('vrs-txt').setAttribute('fill',col);
  document.getElementById('vrs-badge').className=`sbadge ${scls(state)}`;
  document.getElementById('vrs-badge').textContent=`● ${state}`;
  ['tv-vrs','tv-st'].forEach((id,i)=>{const el=document.getElementById(id);el.textContent=i?state:fv(vrs);el.style.color=col});
  document.getElementById('tv-ag').textContent=AGENTS.length;
  document.getElementById('tv-al').textContent=ALL_ALERTS.length;
  document.getElementById('sb-aln').textContent=ALL_ALERTS.length;

  // ── KPIs : events/mois + tier + uptime ─────────────────────────────
  const totalEv = AGENTS.reduce((s,a)=>s+(a.event_count||a.events||0),0);
  const evEl = document.getElementById('tv-ev');
  if(evEl){ evEl.textContent = totalEv>1e6?(totalEv/1e6).toFixed(1)+'M':totalEv>1e3?(totalEv/1e3).toFixed(0)+'k':String(totalEv||'—'); }
  const tierEl = document.getElementById('tv-tier');
  if(tierEl && TIER_INFO){
    const tierLabels={free:'FREE',pro:'PRO ⭐',team:'TEAM',business:'BIZ',enterprise:'ENT ◆'};
    const tierColors={free:'var(--txd)',pro:'var(--ac)',team:'#a78bfa',business:'#f59e0b',enterprise:'#e879f9'};
    tierEl.textContent = tierLabels[TIER_INFO.tier]||TIER_INFO.tier.toUpperCase();
    tierEl.style.color = tierColors[TIER_INFO.tier]||'var(--txm)';
  }
  // Uptime in live-pill tooltip
  const pillEl = document.getElementById('live-pill');
  if(pillEl && _serverStart){ const up=Math.floor((Date.now()-_serverStart)/1000); const h=Math.floor(up/3600),m=Math.floor((up%3600)/60); pillEl.title=`Uptime: ${h}h ${m}m`; }

  // Dernière alerte dans topbar si CRITICAL/HIGH
  const lastCrit = ALL_ALERTS.filter(a=>['CRITICAL','HIGH'].includes((a.sev||a.severity||'').toUpperCase())).sort((a,b)=>(b.ts||b.timestamp||0)-(a.ts||a.timestamp||0))[0];
  const alertPill = document.getElementById('top-last-alert');
  if(alertPill){ alertPill.style.display=lastCrit?'flex':'none'; if(lastCrit) alertPill.textContent='⚡ '+((lastCrit.agent_name||lastCrit.agent||'?').split('_')[0])+' '+((lastCrit.type||lastCrit.event_type||'alert').replace(/_/g,' ')); }
  document.getElementById('sc').textContent=AGENTS.filter(a=>a.state==='CRITICAL').length;document.getElementById('sa').textContent=AGENTS.filter(a=>a.state==='ALERT').length;
  document.getElementById('sw').textContent=AGENTS.filter(a=>a.state==='WATCH').length;document.getElementById('ss').textContent=AGENTS.filter(a=>a.state==='SAFE').length;

  document.getElementById('mini-agents').innerHTML=AGENTS.length===0?'<div style="padding:28px 16px;text-align:center;color:var(--txd);font-size:11px"><div style="font-size:24px;margin-bottom:8px">◎</div><div style="color:var(--txm);font-weight:500;margin-bottom:6px">Aucun agent enregistré</div><div style="line-height:1.8">Créez votre premier agent :<br><code style=\"color:var(--ac)\">piqrypt identity create mon_agent</code></div></div>':AGENTS.map(a=>{const c=sc(a.state);return`<div style="background:var(--s2);border:1px solid ${c}22;border-left:2px solid ${c};border-radius:var(--r);padding:8px 10px;cursor:pointer" onclick="openAgent('${a.name}')"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px"><span style="font-size:11px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:110px">${a.name}</span><span class="sbadge ${scls(a.state)}" style="font-size:8px">${a.state}</span></div><div style="display:flex;gap:10px;font-family:var(--mono);font-size:12px;font-weight:700"><div><div style="color:${c}">${fv(a.vrs)}</div><div style="font-size:9px;color:var(--txd);font-weight:400">VRS</div></div><div><div>${fv(a.ts)}</div><div style="font-size:9px;color:var(--txd);font-weight:400">TS</div></div><div style="margin-left:auto;text-align:right;font-size:9px;color:var(--txd);font-weight:400"><div>${a.tier}</div><div>${rt(a.last_seen)}</div></div></div></div>`}).join('');

  document.getElementById('chain-badges').innerHTML=AGENTS.map(a=>{const cls=a.chain_label==='CANONICAL CHAIN'?'cok':a.chain_label==='FORKED IDENTITY'?'cfrk':'crot';const ico=a.chain_label==='CANONICAL CHAIN'?'✔':a.chain_label==='FORKED IDENTITY'?'✖':'⚠';return`<div><div style="font-size:10px;color:var(--txd);margin-bottom:3px">${a.name}</div><span class="chain-badge ${cls}">${ico} ${a.chain_label}</span></div>`}).join('');

  const top2=[...AGENTS].sort((a,b)=>b.vrs-a.vrs).slice(0,2);
  const sc_={HIGH:'var(--alert)',MEDIUM:'var(--watch)',LOW:'var(--watch)',OK:'var(--safe)',CRITICAL:'var(--crit)'};
  const sb_={HIGH:'var(--alertb)',MEDIUM:'var(--watchb)',LOW:'var(--watchb)',OK:'var(--safeb)',CRITICAL:'var(--critb)'};
  document.getElementById('risk-narr').innerHTML=top2.map(a=>`<div class="narr ${a.narr_cls}" style="margin-bottom:8px"><div class="narr-why">WHY IS VRS ${fv(a.vrs)}? — ${a.name}</div><div class="narr-title" style="color:${sc(a.state)}"><span class="sbadge ${scls(a.state)}">● ${a.state}</span>${a.narr_title}</div><div class="narr-items">${a.narr_items.map(ni=>`<div class="narr-item"><span class="narr-bul" style="background:${sb_[ni.s]||'var(--b1)'};color:${sc_[ni.s]||'var(--txd)'}">${ni.s}</span><span class="narr-txt">${ni.t}</span></div>`).join('')}</div></div>`).join('');

  document.getElementById('a2c-ov').innerHTML=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px">${AGENTS.map(a=>{const worst=Object.entries(a.a2c_ind).reduce((w,[k,v])=>v.score>w.score?{k,...v}:w,{score:0});const c=sc(worst.sev||'NONE');const cls={NONE:'n',LOW:'l',MEDIUM:'m',HIGH:'h',CRITICAL:'c'}[worst.sev||'NONE']||'n';return`<div class="a2c-card ${cls}" style="cursor:pointer" onclick="openAgent('${a.name}')"><div class="a2c-hdr"><span class="a2c-ico">${worst.icon||'·'}</span><span class="a2c-nm">${a.name}</span><span class="a2c-sc" style="color:${c}">${fv(a.a2c)}</span><span class="a2c-sv" style="color:${c}">${worst.sev||'NONE'}</span></div><div class="sbar"><div class="sbt"><div class="sbf" style="width:${a.a2c*100}%;background:${c}"></div></div></div><div class="a2c-dt">${worst.detail||'No anomaly'}</div></div>`}).join('')}</div>`;

  document.getElementById('sparks').innerHTML=AGENTS.map(a=>{const c=sc(a.state);const {l,a:ar}=sparkPts(a.hist.map(h=>h.v),210,34);const mn=Math.min(...a.hist.map(h=>h.v)).toFixed(2),mx=Math.max(...a.hist.map(h=>h.v)).toFixed(2);return`<div class="card" style="padding:11px;cursor:pointer" onclick="openAgent('${a.name}')"><div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:7px"><div><div style="font-size:11px;font-weight:500">${a.name}</div><div style="font-size:9px;color:var(--txd);margin-top:1px">${a.tier} · TSI ${a.tsi}</div></div><div style="text-align:right"><div style="font-family:var(--mono);font-size:15px;font-weight:700;color:${c}">${fv(a.vrs)}</div><span class="sbadge ${scls(a.state)}" style="font-size:8px">${a.state}</span></div></div><svg width="100%" height="34" viewBox="0 0 210 34" preserveAspectRatio="none"><defs><linearGradient id="sg${a.name.replace(/\W/g,'')}"><stop offset="0%" stop-color="${c}" stop-opacity=".22"/><stop offset="100%" stop-color="${c}" stop-opacity="0"/></linearGradient></defs><path d="${ar}" fill="url(#sg${a.name.replace(/\W/g,'')})"/><path d="${l}" fill="none" stroke="${c}" stroke-width="1.5" stroke-linejoin="round"/></svg><div style="display:flex;justify-content:space-between;margin-top:3px;font-family:var(--mono);font-size:9px;color:var(--txd)"><span>↓${mn}</span><span>30d</span><span>↑${mx}</span></div></div>`}).join('');

  const srt=[...ALL_ALERTS].sort((a,b)=>{const o={CRITICAL:4,HIGH:3,ALERT:3,MEDIUM:2,WATCH:1};return(o[b.sev]||0)-(o[a.sev]||0)});
  document.getElementById('ov-alerts').innerHTML=srt.length?srt.map(aRow).join(''):`<div style="padding:18px 14px;font-family:var(--mono);font-size:10px;color:var(--txd)">All systems nominal</div>`;
}

// ════════════════════════════════════════════
// STAR GRAPH — Agent Network (Dynamic Live)
// ════════════════════════════════════════════
let hoveredNode = null;

// ── Stamp flash system ─────────────────────────────────────────────────────
// Tracks per-agent stamp activity to drive blink + flash effects
const _stampFlash   = {};   // agentName → {t, intensity}  (t=0..1, decays)
const _stampHistory = [];   // [{src, dst, t, col, id}]  cross-agent stamps
let   _lastEventCounts = {};
let   _serverStart = null;
let _starRaf = null;

function _injectStampFlash(agentName, intensity=1.0){
  _stampFlash[agentName] = { t: 1.0, intensity };
}
function _decayFlashes(dt){
  for(const k of Object.keys(_stampFlash)){
    _stampFlash[k].t -= dt * 1.8;
    if(_stampFlash[k].t <= 0) delete _stampFlash[k];
  }
}
function _detectNewStamps(){
  // Compare current event counts to previous — trigger flash on delta
  AGENTS.forEach(a=>{
    const cur = a.event_count||a.events||0;
    const prev = _lastEventCounts[a.name]||0;
    if(cur > prev && prev > 0){
      const delta = cur - prev;
      _injectStampFlash(a.name, Math.min(1.0, 0.5 + delta*0.1));
    }
    _lastEventCounts[a.name] = cur;
  });
}

// ── Particle burst on stamp ────────────────────────────────────────────────
const _burstParticles = [];  // [{x,y,vx,vy,life,col,r}]
function _spawnBurst(x, y, col, count=6){
  for(let i=0;i<count;i++){
    const angle = Math.random()*Math.PI*2;
    const speed = 1.5 + Math.random()*3;
    _burstParticles.push({
      x, y,
      vx: Math.cos(angle)*speed,
      vy: Math.sin(angle)*speed,
      life: 1.0,
      col,
      r: 1.5 + Math.random()*2,
    });
  }
}

// ── drawStar : alias vers _drawOrbital sur star-canvas ────────────────────
// Toutes les logiques de rendu sont dans _drawOrbital / setCanvasMode.
// Cette fonction est conservée pour compatibilité avec les appels existants.
function drawStar(){
  _drawOrbital('star-canvas', 560);
}
function populateStarSelect(){
  const s=document.getElementById('star-center');
  const cur=s.value;
  while(s.options.length>1) s.remove(1);
  AGENTS.forEach(a=>{const o=document.createElement('option');o.value=a.name;o.textContent=a.name;s.appendChild(o)});
  if(cur && AGENTS.find(a=>a.name===cur)) s.value=cur;
}

// ════════════════════════════════════════════
// AGENTS TABLE + DETAIL
// ════════════════════════════════════════════
function renderAgentsTable(){
  document.getElementById('tbl-body').innerHTML=AGENTS.map(a=>{
    const c=sc(a.state);
    const cc=a.chain_label==='CANONICAL CHAIN'?'var(--safe)':a.chain_label==='FORKED IDENTITY'?'var(--crit)':'var(--watch)';
    const ci=a.chain_label==='CANONICAL CHAIN'?'✔':a.chain_label==='FORKED IDENTITY'?'✖':'⚠';
    return`<tr onclick="showDetail('${a.name}')" class="${sel[a.name]?'sel':''}">
      <td onclick="event.stopPropagation()"><input type="checkbox" ${sel[a.name]?'checked':''} style="accent-color:var(--ac)" onchange="sel['${a.name}']=this.checked;updSelInfo()"></td>
      <td><div style="font-size:12px;font-weight:500">${a.name}</div><div style="font-family:var(--mono);font-size:9px;color:var(--txd)">${a.id.slice(0,14)}… · ${a.tier}</div></td>
      <td><span class="sbadge ${scls(a.state)}" style="color:${c}">● ${a.state}</span></td>
      <td>${sbar(a.vrs,c,80)}</td>
      <td>${sbar(a.ts,sc(a.ts>.8?'SAFE':a.ts>.6?'WATCH':'ALERT'),80)}</td>
      <td><span style="font-family:var(--mono);font-size:10px;color:${sc(a.tsi)}">${a.tsi}</span></td>
      <td>${sbar(a.a2c,sc(a.a2c<.25?'SAFE':a.a2c<.5?'WATCH':'ALERT'),80)}</td>
      <td><span style="font-family:var(--mono);font-size:9px;color:${cc};font-weight:700">${ci} ${a.chain_label.split(' ').pop()}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${a.alerts>0?'var(--alert)':'var(--txd)'}">${a.alerts}</span></td>
      <td><span style="font-family:var(--mono);font-size:9px;color:var(--txd)">${rt(a.last_seen)}</span></td>
    </tr>`;
  }).join('');
  updSelInfo();
}
function selAll(cb){AGENTS.forEach(a=>sel[a.name]=cb.checked);renderAgentsTable();renderSbAgents()}
function updSelInfo(){
  const n=Object.values(sel).filter(Boolean).length;
  document.getElementById('sel-info').textContent=`${n}/${AGENTS.length} selected`;
  const btn=document.getElementById('btn-delete-agents');
  if(btn) btn.style.display=n>0?'inline-block':'none';
}
async function deleteSelectedAgents(){
  const names=Object.entries(sel).filter(([,v])=>v).map(([k])=>k);
  if(!names.length)return;

  // Étape 1 — vérifier si export mémoire disponible
  const previews=await Promise.all(names.map(name=>
    _vigilFetch('/api/agent/'+encodeURIComponent(name)+'/delete',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({confirmed:false})
    }).then(r=>r.json()).catch(()=>({agent:name,memory_exported:false}))
  ));

  const withMemory=previews.filter(p=>p.memory_exported);
  let msg='Delete '+names.length+' agent(s)?';
  if(withMemory.length>0){
    msg+='\n\n'+withMemory.length+' agent(s) have memory archives available:\n';
    msg+=withMemory.map(p=>'  • '+p.agent+' → '+(p.memory_path||'archive')).join('\n');
    msg+='\n\nMemory archives are saved in ~/.piqrypt/agents/<name>/archive/\nDownload them before confirming deletion.';
  }
  if(!confirm(msg))return;

  // Étape 2 — suppression confirmée
  const results=await Promise.all(names.map(name=>
    _vigilFetch('/api/agent/'+encodeURIComponent(name)+'/delete',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({confirmed:true})
    }).then(r=>r.json()).catch(()=>({error:'network'}))
  ));

  const ok=results.filter(r=>r.status==='deleted').length;
  const fail=results.filter(r=>r.error).length;
  if(ok)   showToast('✓ '+ok+' agent(s) deleted');
  if(fail) showToast('⚠ '+fail+' agent(s) could not be deleted');
  names.forEach(n=>{delete sel[n];});
  setTimeout(loadFromBackend,800);
}

function showDetail(name){
  const a=AGENTS.find(x=>x.name===name);if(!a)return;
  const c=sc(a.state);
  const sc_={HIGH:'var(--alert)',MEDIUM:'var(--watch)',LOW:'var(--watch)',OK:'var(--safe)',CRITICAL:'var(--crit)'};
  const sb_={HIGH:'var(--alertb)',MEDIUM:'var(--watchb)',LOW:'var(--watchb)',OK:'var(--safeb)',CRITICAL:'var(--critb)'};

  const tsRows=Object.entries(a.ts_d).map(([k,v])=>{const lb={I:'Integrity',V_t:'Verified peers',D_t:'Diversity',F:'Finalization',R:'Rotation'};const cc=sc(v>.85?'SAFE':v>.65?'WATCH':'ALERT');return`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span style="font-family:var(--mono);font-size:10px;color:var(--txd);width:22px">${k}</span><span style="font-size:10px;color:var(--txm);width:110px">${lb[k]||k}</span><div class="sbt" style="flex:1"><div class="sbf" style="width:${v*100}%;background:${cc}"></div></div><span class="sbn" style="color:${cc}">${fv(v)}</span></div>`}).join('');

  const a2cRows=Object.entries(a.a2c_ind).map(([k,v])=>{const cc=sc(v.sev);const cls={NONE:'n',LOW:'l',MEDIUM:'m',HIGH:'h',CRITICAL:'c'}[v.sev]||'n';return`<div class="a2c-card ${cls}"><div class="a2c-hdr"><span class="a2c-ico">${v.icon}</span><span class="a2c-nm">${k.replace(/_/g,' ')}</span><span class="a2c-sc" style="color:${cc}">${fv(v.score)}</span><span class="a2c-sv" style="color:${cc}">${v.sev}</span></div><div class="sbar"><div class="sbt"><div class="sbf" style="width:${v.score*100}%;background:${cc}"></div></div></div><div class="a2c-dt">${v.detail}</div></div>`}).join('');

  const tl=agentTimeline(a,440,50);
  const narr=a.narr_items.map(ni=>`<div class="narr-item"><span class="narr-bul" style="background:${sb_[ni.s]||'var(--b1)'};color:${sc_[ni.s]||'var(--txd)'}">${ni.s}</span><span class="narr-txt">${ni.t}</span></div>`).join('');

  document.getElementById('agent-detail').innerHTML=`
  <div class="card card-p0">
    <div style="padding:14px 16px;border-bottom:1px solid var(--b1);display:flex;align-items:center;gap:12px">
      <div style="flex:1"><div style="font-size:14px;font-weight:600;margin-bottom:2px">${a.name}</div><div style="font-family:var(--mono);font-size:9px;color:var(--txd)">${a.id} · ${a.tier} · ${rt(a.last_seen)}</div></div>
      <span class="chain-badge ${a.chain_label==='CANONICAL CHAIN'?'cok':a.chain_label==='FORKED IDENTITY'?'cfrk':'crot'}">${a.chain_label==='CANONICAL CHAIN'?'✔':a.chain_label==='FORKED IDENTITY'?'✖':'⚠'} ${a.chain_label}</span>
      <div style="text-align:right"><div style="font-family:var(--mono);font-size:22px;font-weight:700;color:${c}">${fv(a.vrs)}</div><span class="sbadge ${scls(a.state)}">● ${a.state}</span></div>
    </div>
    <div class="tabs" style="padding:0 16px">
      <div class="tab active" onclick="stab(this,'dt1${a.name}')">Why VRS ${fv(a.vrs)}?</div>
      <div class="tab" onclick="stab(this,'dt2${a.name}')">Trust Score</div>
      <div class="tab" onclick="stab(this,'dt3${a.name}')">A2C Detail</div>
      <div class="tab" onclick="stab(this,'dt4${a.name}')">Timeline</div>
      <div class="tab" onclick="stab(this,'dt5${a.name}')">Export</div>
    </div>
    <div style="padding:14px 16px">
      <div id="dt1${a.name}" class="tp active"><div class="narr ${a.narr_cls}"><div class="narr-why">ROOT CAUSE ANALYSIS</div><div class="narr-title" style="color:${c}"><span class="sbadge ${scls(a.state)}">● ${a.state}</span>${a.narr_title}</div><div class="narr-items">${narr}</div></div></div>
      <div id="dt2${a.name}" class="tp"><div style="font-family:var(--mono);font-size:9px;color:var(--txd);margin-bottom:10px">TS ${fv(a.ts)} · TSI ${a.tsi} · z=${a.tsi_d.z} · Δ24h=${a.tsi_d.d24}</div>${tsRows}</div>
      <div id="dt3${a.name}" class="tp"><div class="a2c-grid">${a2cRows}</div></div>
      <div id="dt4${a.name}" class="tp"><div class="tl-wrap">${tl}</div><div class="tl-legend"><div class="tl-li"><div class="tl-dot" style="background:var(--crit)"></div> Fork</div><div class="tl-li"><div class="tl-dot" style="background:var(--watch)"></div> Rotation anomaly</div><div class="tl-li"><div class="tl-dot" style="background:var(--alert)"></div> Peer cluster spike</div><div class="tl-li"><div class="tl-dot" style="background:var(--safe)"></div>● Stable</div></div></div>
      <div id="dt5${a.name}" class="tp">
        <div style="font-size:11px;color:var(--txm);margin-bottom:12px">Export options for <strong style="color:var(--tx)">${a.name}</strong></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">
          <div class="exp-card" onclick="doExport('${a.name}','pqz-cert')"><div class="exp-icon" style="font-size:16px"></div><div class="exp-name" style="font-size:11px">.pqz Certified</div><div class="exp-desc" style="font-size:10px">Signed events · TSA · hash chain</div><button class="exp-btn primary" style="font-size:9px">↓ EXPORT</button></div>
          <div class="exp-card" onclick="doExport('${a.name}','pqz-memory')"><div class="exp-icon" style="font-size:16px"></div><div class="exp-name" style="font-size:11px">.pqz Memory</div><div class="exp-desc" style="font-size:10px">Full history · self-consultable · portable</div><button class="exp-btn" style="font-size:9px">↓ EXPORT</button></div>
          <div class="exp-card" onclick="doExport('${a.name}','pdf')"><div class="exp-icon" style="font-size:16px"></div><div class="exp-name" style="font-size:11px">PDF Report</div><div class="exp-desc" style="font-size:10px">Rapport lisible local</div><div class="exp-warn" style="font-size:9px">⚠ Non certifié PiQrypt</div><button class="exp-btn" style="font-size:9px">↓ EXPORT</button></div>
        </div>
      </div>
    </div>
  </div>`;
}
function stab(btn,id){const p=btn.closest('.card');p.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));p.querySelectorAll('.tp').forEach(t=>t.classList.remove('active'));btn.classList.add('active');document.getElementById(id).classList.add('active')}

// ════════════════════════════════════════════
// SOC TIMELINE
// ════════════════════════════════════════════
function agentTimeline(agent,W,H){
  const ev=agent.tl;if(!ev||ev.length<2)return'<div style="color:var(--txd);font-size:11px">No events</div>';
  const tMin=ev[0].t,tMax=ev[ev.length-1].t,tR=tMax-tMin||1;
  const pad=24;
  const typeIcon={fork:'',rotation:'',cluster:'',alert:'',watch:'',stable:'●',critical:''};
  let svg=`<svg width="100%" height="${H+32}" viewBox="0 0 ${W} ${H+36}" preserveAspectRatio="xMidYMid meet">`;
  for(let i=0;i<ev.length-1;i++){const e=ev[i],en=ev[i+1];const x1=pad+(e.t-tMin)/tR*(W-pad*2);const x2=pad+(en.t-tMin)/tR*(W-pad*2);svg+=`<rect x="${x1}" y="${H/2-4}" width="${x2-x1}" height="8" fill="${sc(e.type)}" opacity="${e.type==='stable'?.1:.28}" rx="4"/>`}
  svg+=`<line x1="${pad}" y1="${H/2}" x2="${W-pad}" y2="${H/2}" stroke="var(--b2)" stroke-width="1"/>`;
  ev.forEach((e,i)=>{
    const x=pad+(e.t-tMin)/tR*(W-pad*2);const c=sc(e.type);
    const isAnom=['fork','alert','critical','rotation','cluster'].includes(e.type);
    if(isAnom){
      svg+=`<line x1="${x}" y1="${H/2-16}" x2="${x}" y2="${H/2+16}" stroke="${c}" stroke-width="2" ${e.type==='rotation'?'stroke-dasharray="4,3"':''} opacity=".9"/>`;
      svg+=`<polygon points="${x},${H/2-21} ${x+5},${H/2-14} ${x},${H/2-7} ${x-5},${H/2-14}" fill="${c}"/>`;
    } else {
      svg+=`<circle cx="${x}" cy="${H/2}" r="5" fill="${c}" opacity=".9"/>`;
      svg+=`<circle cx="${x}" cy="${H/2}" r="9" fill="${c}" opacity=".1"/>`;
    }
    const above=i%2===0;const ly=above?H/2-27:H/2+30;
    const anchor=i===0?'start':i===ev.length-1?'end':'middle';
    svg+=`<text x="${x}" y="${ly}" text-anchor="${anchor}" font-family="'JetBrains Mono'" font-size="8.5" fill="${c}" opacity=".9">${typeIcon[e.type]||''} ${e.label}</text>`;
  });
  svg+='</svg>';return svg;
}
function renderSOC(){
  document.getElementById('soc-wrap').innerHTML=AGENTS.map(a=>{const c=sc(a.state);const tl=agentTimeline(a,540,44);return`<div class="card" style="margin-bottom:10px;padding:12px 14px"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><span style="font-size:12px;font-weight:500;min-width:130px">${a.name}</span><span class="sbadge ${scls(a.state)}" style="font-size:8px">● ${a.state}</span><span class="chain-badge ${a.chain_label==='CANONICAL CHAIN'?'cok':a.chain_label==='FORKED IDENTITY'?'cfrk':'crot'}" style="font-size:8px;padding:2px 7px">${a.chain_label==='CANONICAL CHAIN'?'✔':a.chain_label==='FORKED IDENTITY'?'✖':'⚠'} ${a.chain_label.split(' ').pop()}</span><span style="margin-left:auto;font-family:var(--mono);font-size:11px;font-weight:700;color:${c}">VRS ${fv(a.vrs)}</span></div><div class="tl-wrap">${tl}</div></div>`}).join('')+`<div class="tl-legend" style="margin-top:6px"><div class="tl-li"><div class="tl-dot" style="background:var(--crit)"></div> Fork detected</div><div class="tl-li"><div class="tl-dot" style="background:var(--watch)"></div> Rotation anomaly</div><div class="tl-li"><div class="tl-dot" style="background:var(--alert)"></div> Peer cluster spike</div><div class="tl-li"><div class="tl-dot" style="background:var(--safe)"></div>● Stable</div></div>`;
}

// ════════════════════════════════════════════
// EXPORT
// ════════════════════════════════════════════
function renderExportAgents(agents){
  document.getElementById('exp-agent-list').innerHTML=agents.map(a=>{const c=sc(a.state);return`<div class="card" style="border-left:2px solid ${c};padding:11px 14px"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><div style="flex:1"><div style="font-size:12px;font-weight:500">${a.name}</div><div style="font-family:var(--mono);font-size:9px;color:var(--txd)">${a.tier} · ${a.id.slice(0,16)}… · VRS ${fv(a.vrs)}</div></div><span class="sbadge ${scls(a.state)}">● ${a.state}</span></div><div style="display:flex;gap:7px"><button class="exp-btn primary" style="flex:1;font-size:9px" onclick="doExport('${a.name}','pqz-cert')"> .pqz CERT</button><button class="exp-btn" style="flex:1;font-size:9px" onclick="doExport('${a.name}','pqz-memory')"> MEMORY</button><button class="exp-btn" style="flex:1;font-size:9px;border-color:rgba(255,179,0,.3);color:var(--watch)" onclick="doExport('${a.name}','pdf')"> PDF <span style="font-size:8px;opacity:.7">⚠ local</span></button></div></div>`}).join('');
}

function filterExports(){
  const q=(document.getElementById('exp-search').value||'').toLowerCase();
  const type=document.getElementById('exp-type').value;
  const tier=document.getElementById('exp-tier').value;
  const filtered=AGENTS.filter(a=>{
    const matchQ=!q||a.name.toLowerCase().includes(q)||a.tier.toLowerCase().includes(q)||a.state.toLowerCase().includes(q);
    const matchTier=!tier||a.tier===tier;
    return matchQ&&matchTier;
  });
  renderExportAgents(filtered);
}
function doExport(agent, type){
  if(agent === 'all'){
    if(type === 'pdf'){
      AGENTS.forEach((a,i)=>setTimeout(()=>_dlExport(a.name,'pdf'), i*600));
    } else if(type === 'pqz-cert'){
      showCertModal(AGENTS.length ? AGENTS[0].name : 'all');
    } else {
      showToast('Export global .pqz : piqrypt archive --all');
    }
    return;
  }
  if(type === 'pqz-cert'){
    showCertModal(agent);
    return;
  }
  _dlExport(agent, type);
}
function _dlExport(agent, type){
  const url = '/api/agent/'+encodeURIComponent(agent)+'/export/'+type;
  showToast('↓ Export '+agent+' ('+type+')…');
  _vigilFetch(url)
    .then(function(r){
      if(!r.ok) return r.json().then(function(d){throw new Error(d.error||r.status);});
      return r.blob();
    })
    .then(function(blob){
      const ext = type==='pdf'?'.pdf':'.pqz';
      const fname = agent+'_'+type+ext;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fname;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
      showToast('✓ Téléchargé : '+fname);
    })
    .catch(function(e){ showToast('⚠ Export échoué : '+e.message); });
}

// ── Certification modal ───────────────────────────────────────────────────
var _certModalAgent = '';
var _STRIPE_LINKS = {
  simple:    'https://buy.stripe.com/00w7sKag8cDDgTKdC98bS04',
  timestamp: 'https://buy.stripe.com/aFa4gy1JC7jjeLC2Xv8bS05',
  pq_bundle: 'https://buy.stripe.com/5kQdR84VO1YZbzq9lT8bS06'
};
var _CERT_LABELS = {
  simple:    'Simple  · €9',
  timestamp: 'Timestamp · €29',
  pq_bundle: 'Post-Quantum · €99'
};

function showCertModal(agent){
  _certModalAgent = agent;
  var m = document.getElementById('cert-modal');
  document.getElementById('cert-modal-agent').textContent = 'Agent: ' + agent;
  document.getElementById('cert-modal-buttons').innerHTML =
    '<div style="font-size:10px;color:#4a7a99">Loading credits…</div>';
  m.style.display = 'flex';
  _loadCreditsForModal();
}

function closeCertModal(){
  document.getElementById('cert-modal').style.display = 'none';
}

function _loadCreditsForModal(){
  _vigilFetch('/api/credits')
    .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function(credits){
      var types = ['simple','timestamp','pq_bundle'];
      var html = types.map(function(t){
        var avail = (credits[t] && credits[t].available != null)
                    ? credits[t].available : 0;
        if(avail > 0){
          return '<button onclick="closeCertModal();_doCertify(\''
            + _certModalAgent + '\',\'' + t + '\')" '
            + 'style="width:100%;padding:9px 12px;background:#0f2236;'
            + 'border:1px solid #1a4060;border-radius:7px;color:#c5d8ec;'
            + 'font-size:11px;cursor:pointer;text-align:left;display:flex;'
            + 'justify-content:space-between;align-items:center">'
            + '<span>' + _CERT_LABELS[t] + '</span>'
            + '<span style="color:#00c8a0;font-size:10px">'
            + avail + ' credit' + (avail>1?'s':'') + ' remaining</span>'
            + '</button>';
        } else {
          return '<button onclick="window.open(\''
            + _STRIPE_LINKS[t] + '?ref=vigil&agent='
            + encodeURIComponent(_certModalAgent) + '\',\'_blank\')" '
            + 'style="width:100%;padding:9px 12px;background:transparent;'
            + 'border:1px solid #1a2740;border-radius:7px;color:#4a7a99;'
            + 'font-size:11px;cursor:pointer;text-align:left;display:flex;'
            + 'justify-content:space-between;align-items:center">'
            + '<span>' + _CERT_LABELS[t] + '</span>'
            + '<span style="color:#f59e0b;font-size:10px">0 credits · Buy ↗</span>'
            + '</button>';
        }
      }).join('');
      document.getElementById('cert-modal-buttons').innerHTML = html;
    })
    .catch(function(){
      document.getElementById('cert-modal-buttons').innerHTML =
        '<div style="font-size:10px;color:#f59e0b">'
        + '⚠ Cannot reach trust-server — direct download only</div>';
    });
}

function _doCertify(agent, certType){
  showToast('⏳ Certifying ' + agent + ' (' + certType + ')…');
  _vigilFetch('/api/certify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({agent: agent, cert_type: certType})
  })
  .then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); })
  .then(function(res){
    if(!res.ok){
      showToast('⚠ Certification failed: ' + (res.d.message || res.d.error));
      return;
    }
    var certId = res.d.cert_id || '';
    var url    = res.d.registry_url || '';
    showToast('✓ Certified: ' + certId);
    if(url) setTimeout(function(){ window.open(url, '_blank'); }, 400);
    _dlRawPqz(agent);
  })
  .catch(function(e){ showToast('⚠ ' + e.message); });
}

function _dlRawPqz(agent){
  _dlExport(agent, 'pqz-cert');
}

// ════════════════════════════════════════════
// ALERTS VIEW
// ════════════════════════════════════════════
function renderAV(){
  const fs=document.getElementById('f-sev').value;
  const fa=document.getElementById('f-ag').value;
  const o={CRITICAL:4,HIGH:3,ALERT:3,MEDIUM:2,WATCH:1};
  const list=[...ALL_ALERTS].filter(a=>(!fs||a.sev===fs)&&(!fa||a.ag===fa)).sort((a,b)=>(o[b.sev]||0)-(o[a.sev]||0)||(b.t||0)-(a.t||0));
  document.getElementById('alerts-list').innerHTML=list.length?list.map(aRow).join(''):`<div style="padding:20px 14px;font-family:var(--mono);font-size:10px;color:var(--txd)">No alerts match filter</div>`;
}
function popAlertFilters(){const s=document.getElementById('f-ag');while(s.options.length>1)s.remove(1);AGENTS.forEach(a=>{const o=document.createElement('option');o.value=a.name;o.textContent=a.name;s.appendChild(o)})}

// ════════════════════════════════════════════
// SIDEBAR
// ════════════════════════════════════════════
function renderSbAgents(){
  document.getElementById('sb-agents').innerHTML=AGENTS.map(a=>`<div class="sb-agent"><input type="checkbox" ${sel[a.name]?'checked':''} style="accent-color:var(--ac)" onchange="sel['${a.name}']=this.checked"><div class="ag-dot" style="background:${sc(a.state)}"></div><span class="ag-nm" onclick="openAgent('${a.name}')" style="cursor:pointer">${a.name}</span><span class="ag-vr" style="color:${sc(a.state)}">${fv(a.vrs)}</span></div>`).join('');
}

// ════════════════════════════════════════════
// VIEW ROUTING
// ════════════════════════════════════════════

function sv(name,el){
  // Stop star animation when leaving that view
  if(name !== 'star'){ _stopAllRenderers && _stopAllRenderers(); }
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(n=>n.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  if(el)el.classList.add('active');
  if(name==='agents'){renderAgentsTable()}
  if(name==='star'){setTimeout(()=>setCanvasMode(_currentMode),50)}
  if(name==='alerts'){renderAV()}
  if(name==='timeline'){renderSOC()}
  if(name==='export'){filterExports()}
}
function openAgent(name){
  sv('agents',document.querySelectorAll('.sb-item')[1]);
  renderAgentsTable();showDetail(name);
  setTimeout(()=>document.getElementById('agent-detail').scrollIntoView({behavior:'smooth',block:'start'}),100);
}

// ════════════════════════════════════════════
// WIZARD
// ════════════════════════════════════════════
let wizStep=1,wizTier='free',wizBridge='crewai';
function openWizard(){document.getElementById('wizard').classList.add('open');setWizStep(1)}
function closeWizard(){document.getElementById('wizard').classList.remove('open')}
function setWizStep(s){
  wizStep=s;
  document.querySelectorAll('.wiz-pane').forEach((p,i)=>p.classList.toggle('active',i===s-1));
  document.querySelectorAll('.wiz-step').forEach((st,i)=>{st.classList.toggle('active',i===s-1);st.classList.toggle('done',i<s-1)});
  document.getElementById('wiz-ind').textContent=`Step ${s} of 3`;
  document.getElementById('wiz-back').style.visibility=s>1?'visible':'hidden';
  document.getElementById('wiz-next').textContent=s===3?'✓ Create Agent':'Next →';
  if(s===3)updateSnippet();
}
function wizNext(){
  if(wizStep<3){setWizStep(wizStep+1);}
  else{
    var name=(document.getElementById('w-name').value||'').trim()||'my_agent';
    var tier=typeof wizTier!=='undefined'?wizTier:'free';
    var bridge=typeof wizBridge!=='undefined'?wizBridge:'';
    var passphrase=(document.getElementById('new-agent-passphrase')?.value||'').trim();
    var confirm_pp=(document.getElementById('new-agent-passphrase-confirm')?.value||'').trim();
    if(passphrase && passphrase!==confirm_pp){showToast('⚠ Passphrases do not match');return;}
    if(passphrase && passphrase.length<8){showToast('⚠ Passphrase must be at least 8 characters');return;}
    var warn=document.getElementById('passphrase-warning');
    if(warn) warn.style.display=passphrase?'none':'block';
    showToast('Création de l\'agent "'+name+'"...');
    _vigilFetch('/api/agent/create',{
      method:'POST',
      body:JSON.stringify({name:name,tier:tier,bridge:bridge,passphrase:passphrase||null})
    })
    .then(function(r){return r.json();})
    .then(function(d){
      closeWizard();
      if(d.status==='ok'){
        var createdName=d.agent_name;
        var encrypted=d.encrypted;
        var toastMsg='✅ Agent "'+createdName+'" créé';
        if(encrypted) toastMsg+=' — clé chiffrée 🔒';
        showToast(toastMsg);
        _showAgentCreatedPanel(createdName,encrypted);
        setTimeout(loadFromBackend,800);
      } else {
        showToast('❌ '+(d.error||'Erreur inconnue'));
      }
    })
    .catch(function(e){
      closeWizard();
      showToast('❌ Réseau: '+e.message);
    });
  }
}
function wizBack(){if(wizStep>1)setWizStep(wizStep-1)}

function _showAgentCreatedPanel(agentName,encrypted){
  var existing=document.getElementById('agent-created-panel');
  if(existing) existing.remove();
  var panel=document.createElement('div');
  panel.id='agent-created-panel';
  panel.style.cssText='position:fixed;bottom:80px;right:24px;z-index:600;'+
    'background:var(--s1);border:1px solid var(--safe);border-radius:var(--r2);'+
    'padding:16px 20px;min-width:280px;box-shadow:0 8px 32px rgba(0,0,0,.4)';
  panel.innerHTML=
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">'+
      '<span style="font-size:12px;font-weight:600;color:var(--safe)">✓ Agent created</span>'+
      '<button onclick="this.parentElement.parentElement.remove()" '+
        'style="background:none;border:none;color:var(--txd);cursor:pointer;font-size:16px">×</button>'+
    '</div>'+
    '<div style="font-family:var(--mono);font-size:11px;color:var(--txm);margin-bottom:12px">'+
      agentName+(encrypted?' <span style="color:var(--safe)">🔒</span>':' <span style="color:var(--watch)">⚠ plaintext</span>')+
    '</div>'+
    '<button onclick="_downloadIdentity(\''+agentName+'\')" '+
      'style="width:100%;padding:8px;background:var(--ac2);border:1px solid var(--ac);'+
      'border-radius:var(--r);color:var(--ac);font-family:var(--mono);font-size:10px;'+
      'cursor:pointer;letter-spacing:.05em">↓ Download identity.json</button>'+
    '<div style="font-size:10px;color:var(--txd);margin-top:8px">'+
      'Required by your bridge (identity_file parameter)'+
    '</div>';
  document.body.appendChild(panel);
  setTimeout(function(){if(panel.parentElement)panel.remove();},30000);
}

function _downloadIdentity(agentName){
  _vigilFetch('/api/agent/'+encodeURIComponent(agentName)+'/identity')
    .then(function(r){
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.blob();
    })
    .then(function(blob){
      var a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download=agentName+'_identity.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
      showToast('↓ identity.json téléchargé');
    })
    .catch(function(e){showToast('⚠ Download failed: '+e.message);});
}
function setTier(t){wizTier=t;document.getElementById('tier-free').classList.toggle('sel',t==='free');document.getElementById('tier-pro').classList.toggle('sel',t==='pro');}
function updPassphraseHint(){
  const v=(document.getElementById('new-agent-passphrase')?.value||'').trim();
  document.getElementById('passphrase-warning').style.display=v?'none':'block';
  document.getElementById('passphrase-ok').style.display=v?'block':'none';
}
function selBridge(b,el){wizBridge=b;document.querySelectorAll('.bridge-card').forEach(c=>c.classList.remove('sel'));el.classList.add('sel');if(wizStep===3)updateSnippet()}
function updateSnippet(){
  const name=(document.getElementById('w-name').value||'my_agent').replace(/[^a-z0-9_]/gi,'_');
  const bm={
    crewai:{
      pkg:'piqrypt-crewai',
      imp:'from piqrypt_crewai import AuditedAgent, AuditedCrew',
      body:`agent = AuditedAgent(\n    role=<span class="snippet-str">"${name}"</span>,\n    goal=<span class="snippet-str">"..."</span>,\n    backstory=<span class="snippet-str">"..."</span>,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\ncrew = AuditedCrew(agents=[agent], tasks=[...])\nresult = crew.kickoff()`
    },
    autogen:{
      pkg:'piqrypt-autogen',
      imp:'from piqrypt_autogen import AuditedAssistant, AuditedUserProxy',
      body:`assistant = AuditedAssistant(\n    name=<span class="snippet-str">"${name}"</span>,\n    llm_config={<span class="snippet-str">"model"</span>: <span class="snippet-str">"gpt-4o"</span>},\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nuser_proxy = AuditedUserProxy(\n    name=<span class="snippet-str">"user_proxy"</span>,\n    human_input_mode=<span class="snippet-str">"NEVER"</span>\n)\nuser_proxy.initiate_chat(assistant, message=<span class="snippet-str">"..."</span>)`
    },
    langchain:{
      pkg:'piqrypt-langchain',
      imp:'from piqrypt_langchain import PiQryptCallbackHandler',
      body:`handler = PiQryptCallbackHandler(\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\n<span class="snippet-cm"># Attach to any LangChain component</span>\nllm = ChatOpenAI(callbacks=[handler])\nagent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])`
    },
    ollama:{
      pkg:'piqrypt-ollama',
      imp:'from piqrypt_ollama import AuditedOllama',
      body:`agent = AuditedOllama(\n    model=<span class="snippet-str">"llama3"</span>,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nresponse = agent.chat(messages=[{<span class="snippet-str">"role"</span>: <span class="snippet-str">"user"</span>, <span class="snippet-str">"content"</span>: <span class="snippet-str">"..."</span>}])`
    },
    mcp:{
      pkg:'piqrypt-mcp',
      imp:'from piqrypt_mcp import PiQryptMCPServer',
      body:`server = PiQryptMCPServer(\n    name=<span class="snippet-str">"${name}"</span>,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nserver.run()`
    },
    openclaw:{
      pkg:'piqrypt-openclaw',
      imp:'from piqrypt_openclaw import AuditableOpenClaw',
      body:`from openclaw import Agent\nbase_agent = Agent(config)\nagent = AuditableOpenClaw(\n    base_agent,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nresult = agent.execute_task(task)`
    },
    session:{
      pkg:'piqrypt-session',
      imp:'from piqrypt_session import AgentSession',
      body:`session = AgentSession([\n    {<span class="snippet-str">"name"</span>: <span class="snippet-str">"${name}"</span>,     <span class="snippet-str">"identity_file"</span>: <span class="snippet-str">"${name}.json"</span>},\n    {<span class="snippet-str">"name"</span>: <span class="snippet-str">"agent_2"</span>, <span class="snippet-str">"identity_file"</span>: <span class="snippet-str">"agent_2.json"</span>},\n])\nsession.start()\nsession.stamp(<span class="snippet-str">"${name}"</span>, <span class="snippet-str">"action"</span>, {<span class="snippet-str">"key"</span>: <span class="snippet-str">"value"</span>}, peer=<span class="snippet-str">"agent_2"</span>)\nsession.end()`
    },
    ros:{
      pkg:'piqrypt-ros',
      imp:'from piqrypt_ros import AuditedNode',
      body:`node = AuditedNode(\n    node_name=<span class="snippet-str">"${name}"</span>,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nnode.spin()`
    },
    rpi:{
      pkg:'piqrypt-rpi',
      imp:'from piqrypt_rpi import AuditedPiAgent',
      body:`agent = AuditedPiAgent(\n    name=<span class="snippet-str">"${name}"</span>,\n    identity_file=<span class="snippet-str">"${name}.json"</span>\n)\nagent.run()`
    }
  };
  const b=bm[wizBridge]||bm.crewai;
  // Mise à jour commande pip — utilise les extras piqrypt[bridge] si disponible
  const pipExtra = wizBridge==='session'?'session':wizBridge==='mcp'?'mcp':wizBridge;
  document.getElementById('install-cmd').textContent=`pip install piqrypt[${pipExtra}]`;
  document.getElementById('identity-path').textContent=`~/.piqrypt/agents/${name}/`;
  document.getElementById('code-snippet').innerHTML=
    `<span class="snippet-cm"># Auto-generated by Vigil · PiQrypt v1.7.0</span>\n`+
    `<span class="snippet-kw">import</span> piqrypt <span class="snippet-kw">as</span> aiss\n`+
    `${b.imp}\n\n`+
    `<span class="snippet-cm"># Identity (créée par le wizard)</span>\n`+
    b.body;
}
function copyInstall(){navigator.clipboard.writeText(document.getElementById('install-cmd').textContent).then(()=>showToast('✓ Copied'))}
function copySnippet(){navigator.clipboard.writeText(document.getElementById('code-snippet').textContent).then(()=>showToast('✓ Snippet copied'))}

// ════════════════════════════════════════════
// TOAST
// ════════════════════════════════════════════
let toastT;
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('show'),2800)}

// ════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════
renderOverview();
renderSbAgents();
popAlertFilters();
renderAV();
populateStarSelect();
updateSnippet();
// resize star on window resize
window.addEventListener('resize',()=>{if(document.getElementById('view-star').classList.contains('active'))_redrawCurrentMode()});

// ════════════════════════════════════════════
// BACKEND CONNECTION (merged — single script block)
// ════════════════════════════════════════════

// ── Auth helper ──────────────────────────────────────────────────────────────
// Le token est injecté par vigil_server.py au moment de servir le HTML.
// window.VIGIL_TOKEN est donc disponible dès le chargement de la page.
// Fallback : localStorage pour les sessions longues (rechargement de page).
(function(){
  if(window.VIGIL_TOKEN && window.VIGIL_TOKEN !== '__NO_TOKEN__'){
    try{ localStorage.setItem('_vt', window.VIGIL_TOKEN); }catch(e){}
  } else {
    try{
      var stored = localStorage.getItem('_vt');
      if(stored) window.VIGIL_TOKEN = stored;
    }catch(e){}
  }
})();

function _authHeaders(extra){
  var h = Object.assign({'Content-Type':'application/json'}, extra||{});
  if(window.VIGIL_TOKEN && window.VIGIL_TOKEN !== '__NO_TOKEN__'){
    h['Authorization'] = 'Bearer ' + window.VIGIL_TOKEN;
  }
  return h;
}

// Wrapper fetch authentifié — utiliser partout à la place de fetch()
function _vigilFetch(url, opts){
  opts = opts || {};
  opts.headers = _authHeaders(opts.headers||{});
  return fetch(url, opts).then(function(r){
    if(r.status === 401){
      showToast('❌ Auth: VIGIL_TOKEN invalide ou absent — vérifiez la config serveur');
      throw new Error('Unauthorized');
    }
    if(r.status === 403){
      return r.json().then(function(d){
        showToast('🔒 ' + (d.message || 'Feature non disponible sur ce tier'));
        throw new Error('Forbidden');
      });
    }
    return r;
  });
}

// ── Peer ID → name resolution cache ─────────────────────────────────────────
// Populated from /api/summary — maps agent_id → agent_name
var _peerNameCache = {};

function _mapAgent(a){
  var vrs=+(a.vrs||0).toFixed(3);
  var state=(a.state||'SAFE').toUpperCase();
  var ts=+(a.ts_score||1).toFixed(3);
  var tsi=(a.tsi_state||'STABLE').toUpperCase();
  var a2c=+(a.a2c_risk||0).toFixed(3);
  var td=a.tsi_detail||{},ad=a.a2c_detail||{};

  // Résolution des peers : si le peer_id est un UUID, on tente de le résoudre
  // vers un nom lisible via _peerNameCache (peuplé depuis le summary)
  var rawPeers=(a.a2c_peers||a.peers||[]).map(function(p){
    if(Array.isArray(p)){
      var pid=p[0], score=p[1]||0;
      // Si l'ID ressemble à un UUID ou hash (pas un nom lisible), résoudre
      var name = _peerNameCache[pid] || pid;
      return [name, score];
    }
    return [p.name||p.agent_name||p.peer_id||p, p.score||p.correlation||0];
  });

  return{
    name:a.agent_name||a.name, id:a.agent_id||a.name, tier:a.tier||'Pro',
    vrs:vrs, state:state, ts:ts, tsi:tsi, a2c:a2c,
    is_external:!!a.is_external,
    avg_latency_ms:a.avg_latency_ms||0,
    external_type:a.external_type||'',
    chain_label:a.chain_label||'CANONICAL CHAIN',
    last_seen:a.last_seen||(Date.now()/1000-60),
    alerts:a.alert_count||0,
    event_count:a.event_count||a.events||0,
    bridge:a.bridge||'',
    ts_d:{I:ts,V_t:ts,D_t:ts,F:ts,R:1},
    tsi_d:{z:td.z_score||0,d24:td.delta_24h||0,base:td.baseline_mean||ts},
    a2c_ind:{
      concentration:   {score:ad.concentration||0,   sev:ad.concentration_sev||'NONE',   icon:'⊙',detail:ad.concentration_detail||'No anomaly'},
      entropy_drop:    {score:ad.entropy_drop||0,     sev:ad.entropy_drop_sev||'NONE',     icon:'↘',detail:ad.entropy_drop_detail||'No anomaly'},
      synchronization: {score:ad.synchronization||0,  sev:ad.synchronization_sev||'NONE',  icon:'⇄',detail:ad.synchronization_detail||'No anomaly'},
      silence_break:   {score:ad.silence_break||0,    sev:ad.silence_break_sev||'NONE',    icon:'◌',detail:ad.silence_break_detail||'No anomaly'}
    },
    narr_cls:state==='ALERT'?'a':state==='WATCH'?'w':state==='CRITICAL'?'c':'n',
    narr_title:a.narrative_title||('VRS '+vrs.toFixed(2)+' — '+state),
    narr_items:(a.narrative_items||[]).map(function(ni){return{s:ni.severity||ni.s||'LOW',t:ni.text||ni.t||''}}),
    tl:(a.timeline||[]).map(function(e){return{t:e.timestamp||e.t,type:e.type,label:e.label}}),
    hist:(a.history||a.vrs_history||[]).length>0
      ?(a.history||a.vrs_history).map(function(h){return{t:h.timestamp||h.t,v:+(h.vrs||h.v||0)}})
      :genH(vrs,0.04),
    peers:rawPeers,
    a2c_peers:rawPeers
  };
}

// ════════════════════════════════════════════
// WELCOME OVERLAY
// ════════════════════════════════════════════
function _showWelcome(){
  var el = document.getElementById('pq-welcome');
  if(el){ el.style.display=''; return; }

  // Inject scoped styles once
  if(!document.getElementById('pq-welcome-style')){
    var st=document.createElement('style');
    st.id='pq-welcome-style';
    st.textContent=[
      '#pq-welcome{position:fixed;inset:0;z-index:400;background:var(--bg);overflow-y:auto;display:flex;flex-direction:column;align-items:center;padding:48px 20px 60px}',
      '#pq-welcome .wc-inner{width:100%;max-width:900px}',
      '#pq-welcome .wc-header{text-align:center;margin-bottom:40px}',
      '#pq-welcome .wc-logo{font-family:var(--mono);font-size:24px;font-weight:700;color:var(--ac);letter-spacing:.06em}',
      '#pq-welcome .wc-ver{font-family:var(--mono);font-size:11px;color:var(--txd);margin-left:8px}',
      '#pq-welcome .wc-tagline{font-family:var(--sans);font-size:13px;color:var(--txd);margin-top:8px;letter-spacing:.02em}',
      '#pq-welcome .wc-cols{display:grid;grid-template-columns:1fr 1fr;gap:40px}',
      '#pq-welcome .wc-sec-title{font-family:var(--sans);font-size:15px;font-weight:600;color:var(--tx);margin-bottom:4px}',
      '#pq-welcome .wc-sec-sub{font-family:var(--mono);font-size:9px;color:var(--txd);letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px}',
      '#pq-welcome .wc-bridge-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}',
      '#pq-welcome .wc-btn{width:100%;padding:9px;border-radius:var(--r);font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.06em;border:1px solid var(--ac);color:var(--ac);background:var(--ac2);cursor:pointer;transition:background .15s}',
      '#pq-welcome .wc-btn:hover{background:rgba(0,200,224,.18)}',
      '#pq-welcome .wc-demo-cards{display:flex;flex-direction:column;gap:10px}',
      '#pq-welcome .wc-demo-card{background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px;transition:border-color .15s}',
      '#pq-welcome .wc-demo-card:hover{border-color:var(--b2)}',
      '#pq-welcome .wc-launch-btn{padding:6px 14px;border-radius:var(--r);font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.06em;border:1px solid var(--b2);color:var(--txm);background:transparent;cursor:pointer;transition:all .15s;white-space:nowrap;flex-shrink:0}',
      '#pq-welcome .wc-launch-btn:hover{border-color:var(--ac);color:var(--ac);background:var(--ac2)}',
      '#pq-welcome .wc-launch-btn:disabled{opacity:.45;cursor:not-allowed}',
      '@media(max-width:640px){#pq-welcome .wc-cols{grid-template-columns:1fr}#pq-welcome .wc-bridge-grid{grid-template-columns:repeat(2,1fr)}}',
    ].join('');
    document.head.appendChild(st);
  }

  var ver=(TIER_INFO&&TIER_INFO.version)?'v'+TIER_INFO.version:'';

  var bridges=[
    {id:'langchain', name:'LangChain', icon:'🔗'},
    {id:'crewai',    name:'CrewAI',    icon:'🤖'},
    {id:'autogen',   name:'AutoGen',   icon:'🤝'},
    {id:'ollama',    name:'Ollama',    icon:'🦙'},
    {id:'mcp',       name:'MCP',       icon:'⚡'},
    {id:'openclaw',  name:'OpenClaw',  icon:'🦞'},
    {id:'session',   name:'Session',   icon:'💬'},
    {id:'ros',       name:'ROS2',      icon:'⚙️'},
  ];

  var demos=[
    {id:'nexus',     name:'Nexus Labs', desc:'DevOps / Infra',  tags:'Ollama · LangGraph'},
    {id:'pixelflow', name:'PixelFlow',  desc:'Digital Agency',  tags:'CrewAI'},
    {id:'alphacore', name:'AlphaCore', desc:'Quant Trading',    tags:'AutoGen'},
  ];

  var bridgeCards=bridges.map(function(b){
    return '<div class="bridge-card" onclick="_wc_selBridge(\''+b.id+'\',this)">'
      +'<div class="bridge-logo" style="font-size:15px">'+b.icon+'</div>'
      +'<div class="bridge-name" style="font-size:11px">'+b.name+'</div>'
      +'</div>';
  }).join('');

  var demoCards=demos.map(function(d){
    return '<div class="wc-demo-card">'
      +'<div>'
      +'<div style="font-family:var(--sans);font-size:13px;font-weight:500;color:var(--tx);margin-bottom:3px">'+d.name+'</div>'
      +'<div style="font-family:var(--mono);font-size:9px;color:var(--txd)">'+d.desc
        +' &nbsp;·&nbsp; <span style="color:var(--txm)">'+d.tags+'</span></div>'
      +'</div>'
      +'<button class="wc-launch-btn" onclick="_wc_launchDemo(\''+d.id+'\',this)">▶ Launch</button>'
      +'</div>';
  }).join('');

  el=document.createElement('div');
  el.id='pq-welcome';
  el.innerHTML=
    '<div class="wc-inner">'
      +'<div class="wc-header">'
        +'<div><span class="wc-logo">PiQrypt</span><span class="wc-ver">'+ver+'</span></div>'
        +'<div class="wc-tagline">Trust &amp; Continuity for Autonomous AI Agents</div>'
      +'</div>'
      +'<div class="wc-cols">'
        +'<div>'
          +'<div class="wc-sec-title">Your first agent</div>'
          +'<div class="wc-sec-sub">Identity · cryptographic chain · live in Vigil</div>'
          +'<div class="wc-bridge-grid">'+bridgeCards+'</div>'
          +'<button class="wc-btn" onclick="openWizard()">→ Create agent</button>'
        +'</div>'
        +'<div>'
          +'<div class="wc-sec-title">See it live</div>'
          +'<div class="wc-sec-sub">Real agents · real events · no setup</div>'
          +'<div class="wc-demo-cards">'+demoCards+'</div>'
        +'</div>'
      +'</div>'
    +'</div>';
  document.body.appendChild(el);
}

function _hideWelcome(){
  var el=document.getElementById('pq-welcome');
  if(el) el.style.display='none';
}

function _wc_selBridge(id, cardEl){
  var grid=cardEl.closest('.wc-bridge-grid');
  if(grid) grid.querySelectorAll('.bridge-card').forEach(function(c){c.classList.remove('sel');});
  cardEl.classList.add('sel');
  wizBridge=id;
  openWizard();
}

function _wc_launchDemo(family, btn){
  btn.disabled=true;
  btn.textContent='…';
  _vigilFetch('/api/demo/start',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({family:family})
  }).then(function(r){return r.json();})
    .then(function(){
      _hideWelcome();
      setTimeout(loadFromBackend, 2000);
    })
    .catch(function(){
      btn.disabled=false;
      btn.textContent='▶ Launch';
    });
}

function loadFromBackend(){
  _vigilFetch('/api/summary')
    .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
    .then(function(d){
      var raw=d.agents||[];
      console.log('[Vigil] /api/summary -> '+raw.length+' agents', raw);

      // ── Peupler le cache ID→name depuis tous les agents du summary ────
      raw.forEach(function(a){
        var aid  = a.agent_id||a.name;
        var name = a.agent_name||a.name;
        if(aid && name) _peerNameCache[aid] = name;
        // Aussi depuis a2c_peers si présent (paires [id, score])
        (a.a2c_peers||a.peers||[]).forEach(function(p){
          if(Array.isArray(p) && p[0] && typeof p[0]==='string'){
            // Si la clé ressemble à un nom (pas un hex long), ignorer
            // Sinon on l'enregistre en attente de résolution au prochain cycle
          } else if(p && p.agent_id && p.agent_name){
            _peerNameCache[p.agent_id] = p.agent_name;
          }
        });
      });

      // ── Detect stamp activity before updating AGENTS ──────────────
      var prevCounts={};
      AGENTS.forEach(function(a){ prevCounts[a.name]=a.event_count||a.events||0; });

      // ── Merge doux : mettre à jour les agents existants sans reset ──
      // Évite le re-calcul des positions et des particules dans le graphe
      var newAgents=raw.map(_mapAgent);
      var starVisible=document.getElementById('view-star').classList.contains('active');
      var agentCountChanged=(newAgents.length !== AGENTS.length);

      if(!agentCountChanged && AGENTS.length>0){
        // Mise à jour in-place des propriétés dynamiques uniquement
        newAgents.forEach(function(na){
          var existing=AGENTS.find(function(a){return a.name===na.name;});
          if(existing){
            existing.vrs=na.vrs; existing.state=na.state; existing.ts=na.ts;
            existing.tsi=na.tsi; existing.a2c=na.a2c; existing.alerts=na.alerts;
            existing.event_count=na.event_count; existing.last_seen=na.last_seen;
            existing.chain_label=na.chain_label; existing.narr_cls=na.narr_cls;
            existing.narr_title=na.narr_title; existing.narr_items=na.narr_items;
            existing.tsi_d=na.tsi_d; existing.a2c_ind=na.a2c_ind; existing.hist=na.hist;
            existing.tl=na.tl;
            // Peers : mettre à jour seulement si non vide (évite d'effacer les arêtes)
            if(na.peers && na.peers.length>0){ existing.peers=na.peers; existing.a2c_peers=na.peers; }
          }
        });
        // Ajouter les nouveaux agents non présents
        newAgents.forEach(function(na){
          if(!AGENTS.find(function(a){return a.name===na.name;})) AGENTS.push(na);
        });
        // Retirer les agents supprimés
        AGENTS=AGENTS.filter(function(a){return newAgents.find(function(na){return na.name===a.name;});});
      } else {
        AGENTS=newAgents;
      }

      // ── Welcome overlay — show when no agents are registered ───────────────
      if (AGENTS.length === 0) { _showWelcome(); } else { _hideWelcome(); }

      // ── Trigger flash on agents with new events ────────────────────
      AGENTS.forEach(function(a){
        var cur=a.event_count||a.events||0;
        var prev=prevCounts[a.name]||0;
        if(cur>prev && prev>0){ _injectStampFlash(a.name, Math.min(1.0, 0.5+(cur-prev)*0.05)); }
      });

      // ── Ingest tier info + server start ───────────────────────────
      if(d.tier_info){
        TIER_INFO = d.tier_info;
        if(!_serverStart && d.tier_info.server_start) _serverStart = d.tier_info.server_start*1000;
      }
      if(!_serverStart) _serverStart = Date.now();

      // Refresh star graph — uniquement si le nombre d'agents a changé
      // (sinon le renderer en cours continue sans interruption)
      if(starVisible && agentCountChanged){
        _stopAllRenderers();
        _redrawCurrentMode();
      }

      ALL_ALERTS=(d.active_alerts||[]).map(function(a){
        return{ag:a.agent_name||a.agent||'',sev:(a.severity||a.sev||'LOW').toUpperCase(),
               msg:a.message||a.msg||'',t:a.timestamp||a.t||Date.now()/1000};
      });
      renderOverview();
      renderSbAgents();
      popAlertFilters();
      renderAV();
      populateStarSelect();
      updateSnippet();
      showToast(AGENTS.length===0
        ?'Backend LIVE — aucun agent (utilisez le wizard +)'
        :'Backend LIVE — '+AGENTS.length+' agent(s)');
    })
    .catch(function(e){
      console.error('[Vigil] Backend error:',e.message);
    });
}

// ── Demo mode: simulate stamp activity when no backend ─────────────────────
function _demoStampLoop(){
  if(!AGENTS.length) return;
  // Random agent stamps every 1.5–4s
  const a=AGENTS[Math.floor(Math.random()*AGENTS.length)];
  _injectStampFlash(a.name, 0.6+Math.random()*0.4);
  setTimeout(_demoStampLoop, 1500+Math.random()*2500);
}

// ════════════════════════════════════════════
// STAMP PANEL
// ════════════════════════════════════════════
let _stampPanelAgent = null;
let _stampPanelData  = [];

function _openStampPanel(agentName){
  _stampPanelAgent = agentName;
  const agent = AGENTS.find(a=>a.name===agentName);
  const col = agent ? sc(agent.state) : 'var(--txd)';

  // Header
  document.getElementById('sp-dot').style.background = col;
  document.getElementById('sp-title').textContent = agentName.replace(/_/g,' ');

  // Meta row
  if(agent){
    document.getElementById('sp-meta').innerHTML = `
      <div class="sp-meta-item">
        <span class="sp-meta-label">State</span>
        <span class="sp-meta-value" style="color:${col}">${agent.state}</span>
      </div>
      <div class="sp-meta-item">
        <span class="sp-meta-label">VRS</span>
        <span class="sp-meta-value" style="color:${col}">${fv(agent.vrs)}</span>
      </div>
      <div class="sp-meta-item">
        <span class="sp-meta-label">Events</span>
        <span class="sp-meta-value" style="color:var(--ac)">${(agent.event_count||0).toLocaleString()}</span>
      </div>
      <div class="sp-meta-item">
        <span class="sp-meta-label">Chain</span>
        <span class="sp-meta-value" style="color:var(--safe)">✓ ${agent.chain_label||'CANONICAL'}</span>
      </div>
    `;
  }

  document.getElementById('sp-search').value = '';
  document.getElementById('stamp-panel').classList.add('open');

  // Initialiser le live feed
  openCockpit(agentName);

  // Fetch stamps from backend
  _fetchStamps(agentName);
}

function _closeStampPanel(){
  document.getElementById('stamp-panel').classList.remove('open');
  _stampPanelAgent = null;
  _closeCockpit();
}

function _fetchStamps(agentName){
  document.getElementById('sp-list').innerHTML = '<div class="sp-empty">Loading stamps…</div>';
  _vigilFetch('/api/agent/'+encodeURIComponent(agentName))
    .then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
    .then(d=>{
      // /api/agent/<n> retourne {vrs, history, alerts} — on construit les stamps
      _stampPanelData = _agentDataToStamps(d, agentName);
      _renderStamps(_stampPanelData);
    })
    .catch(()=>{
      // Fallback: use timeline data already in AGENTS
      const agent = AGENTS.find(a=>a.name===agentName);
      _stampPanelData = agent && agent.tl && agent.tl.length
        ? agent.tl.map((e,i)=>({
            seq: i+1,
            timestamp: e.t,
            event_type: e.type||e.label||'event',
            payload: e.label ? {action: e.label} : {},
            hash: '—',
            prev_hash: '—',
            sig_status: 'valid',
            algorithm: 'Ed25519',
          }))
        : _generateDemoStamps(agentName, agent);
      _renderStamps(_stampPanelData);
    });
}

function _generateDemoStamps(agentName, agent){
  // Generate plausible demo stamps when no backend
  const now = Date.now()/1000;
  const types = ['action','decision','observation','alert','a2a_handshake','trust_update','chain_verify'];
  const count = agent ? Math.min(agent.event_count||12, 20) : 12;
  const stamps = [];
  for(let i=count;i>=1;i--){
    const t = types[Math.floor(Math.random()*types.length)];
    const h = Array.from({length:16},()=>Math.floor(Math.random()*16).toString(16)).join('');
    stamps.push({
      seq: i,
      timestamp: now - i*180 - Math.random()*60,
      event_type: t,
      payload: _demoPayload(t, agentName),
      hash: h+'...'+h.slice(0,8),
      prev_hash: i>1 ? (h.slice(2)+'...'+h.slice(0,6)) : 'GENESIS',
      sig_status: Math.random()>0.04 ? 'valid' : 'invalid',
      algorithm: agent && agent.tier==='Pro' ? 'Ed25519+Dilithium3' : 'Ed25519',
    });
  }
  return stamps.reverse();
}

function _demoPayload(type, agent){
  const p = {
    action:         {action:'execute', target:'market_eval', confidence:+(Math.random()).toFixed(3)},
    decision:       {decision:'buy', symbol:['AAPL','MSFT','ETH'][Math.floor(Math.random()*3)], amount:Math.floor(Math.random()*1000)},
    observation:    {observation:'market_shift', delta:+(Math.random()-.5).toFixed(4), source:'feed'},
    alert:          {alert:'threshold_exceeded', vrs:+(Math.random()*.3+.5).toFixed(3), escalated:true},
    a2a_handshake:  {handshake:'init', peer:agent+'_peer', session_id:'ses_'+Math.random().toString(36).slice(2,8)},
    trust_update:   {trust_score:+(Math.random()).toFixed(3), delta:+(Math.random()*.1-.05).toFixed(4)},
    chain_verify:   {chain:'ok', depth:Math.floor(Math.random()*50+5), fork_detected:false},
  };
  return p[type] || {type};
}

function _renderStamps(stamps){
  const q = (document.getElementById('sp-search').value||'').toLowerCase();
  const filtered = q
    ? stamps.filter(s=>
        (s.event_type||'').toLowerCase().includes(q) ||
        JSON.stringify(s.payload||{}).toLowerCase().includes(q))
    : stamps;

  document.getElementById('sp-count').textContent = filtered.length+' / '+stamps.length+' stamps';

  if(!filtered.length){
    document.getElementById('sp-list').innerHTML =
      '<div class="sp-empty">No stamps match the filter.</div>';
    return;
  }

  // Show most recent first
  const sorted = [...filtered].reverse();

  document.getElementById('sp-list').innerHTML = sorted.map((s,idx)=>{
    const isValid = (s.sig_status||'valid') === 'valid';
    const col = sc(s.event_type==='alert'?'ALERT':s.event_type==='a2a_handshake'?'WATCH':'SAFE');
    const typeCol = s.event_type==='alert'?'var(--alert)':s.event_type==='decision'?'var(--watch)':'var(--ac)';
    const typeBg  = s.event_type==='alert'?'var(--alertb)':s.event_type==='decision'?'var(--watchb)':'var(--ac2)';
    const ts = s.timestamp ? new Date(s.timestamp*1000).toISOString().replace('T',' ').slice(0,19)+' UTC' : '—';
    const payload = s.payload ? JSON.stringify(s.payload, null, 2) : '{}';
    const hash = s.hash||'—';
    const prev = s.prev_hash||'—';
    const algo = s.algorithm||'Ed25519';
    const seq  = s.seq || (sorted.length - idx);
    return `<div class="stamp-row">
      <div class="stamp-row-header">
        <span class="stamp-seq">#${seq}</span>
        <span class="stamp-type" style="color:${typeCol};background:${typeBg}">${(s.event_type||'event').toUpperCase()}</span>
        <span class="stamp-sig ${isValid?'sig-ok':'sig-bad'}">${isValid?'✓ '+algo:'✗ INVALID'}</span>
        <span class="stamp-time">${ts}</span>
      </div>
      <div class="stamp-payload">${payload}</div>
      <div class="stamp-hashes">
        <div class="stamp-hash-row">
          <span class="stamp-hash-label">HASH</span>
          <span class="stamp-hash-val" title="${hash}">${hash}</span>
        </div>
        <div class="stamp-hash-row">
          <span class="stamp-hash-label">PREV</span>
          <span class="stamp-hash-val" title="${prev}" style="color:${prev==='GENESIS'?'var(--ac)':'var(--txd)'}">${prev}</span>
        </div>
      </div>
    </div>`;
  }).join('');
}

function _filterStamps(){
  _renderStamps(_stampPanelData);
}

// Auto-refresh stamp panel if open
setInterval(()=>{
  if(_stampPanelAgent && document.getElementById('stamp-panel').classList.contains('open')){
    _fetchStamps(_stampPanelAgent);
  }
}, 8000);

// ════════════════════════════════════════════
// CANVAS MODE SYSTEM
// ════════════════════════════════════════════
let _currentMode = 'split';
let _laneRaf = null, _circuitRaf = null, _radarRaf = null;

function _stopAllRenderers(){
  if(_starRaf){ cancelAnimationFrame(_starRaf); _starRaf=null; }
  if(_laneRaf){ cancelAnimationFrame(_laneRaf); _laneRaf=null; }
  if(_circuitRaf){ cancelAnimationFrame(_circuitRaf); _circuitRaf=null; }
  if(_radarRaf){ cancelAnimationFrame(_radarRaf); _radarRaf=null; }
}

function setCanvasMode(mode){
  _stopAllRenderers();
  _currentMode = mode;

  // Toggle panel visibility
  const panes = ['split','orbital','circuit','radar','lanes'];
  panes.forEach(p=>{
    const el = document.getElementById('cv-'+p);
    if(el) el.style.display = p===mode ? (p==='split'?'grid':'block') : 'none';
  });

  // Toggle button states
  document.querySelectorAll('.cmode-btn').forEach(b=>b.classList.remove('active'));
  const btn = document.getElementById('cmb-'+mode);
  if(btn) btn.classList.add('active');

  // Launch renderer(s)
  setTimeout(()=>{
    if(mode==='split'){
      _drawOrbital('star-canvas', 560);
      _drawLanes('lanes-canvas', 560);
    } else if(mode==='orbital'){
      _drawOrbital('orbital-canvas', 640);
    } else if(mode==='circuit'){
      _drawCircuit('circuit-canvas', 640);
    } else if(mode==='radar'){
      _drawRadar('radar-canvas', 640);
    } else if(mode==='lanes'){
      _drawLanes('lanes-full-canvas', 640);
    }
  }, 40);
}

function _redrawCurrentMode(){
  setCanvasMode(_currentMode);
}

// ── Shared drawing helpers ───────────────────────────────────────────────
function _gridDots(ctx, W, H, col='rgba(0,200,224,0.04)', step=28){
  ctx.fillStyle=col;
  for(let gx=0;gx<W;gx+=step)for(let gy=0;gy<H;gy+=step){
    ctx.beginPath();ctx.arc(gx,gy,.8,0,Math.PI*2);ctx.fill();
  }
}
function _hexPath(ctx, cx, cy, r){
  ctx.beginPath();
  for(let k=0;k<6;k++){
    const a=(Math.PI/3)*k+Math.PI/6;
    k===0?ctx.moveTo(cx+r*Math.cos(a),cy+r*Math.sin(a))
         :ctx.lineTo(cx+r*Math.cos(a),cy+r*Math.sin(a));
  }
  ctx.closePath();
}

// ════════════════════════════════════════════
// RENDERER A — Orbital (enhanced drawStar wrapper)
// ════════════════════════════════════════════
function _drawOrbital(canvasId, H){
  if(_starRaf){ cancelAnimationFrame(_starRaf); _starRaf=null; }

  const canvas = document.getElementById(canvasId);
  if(!canvas) return;

  // Full orbital renderer for standalone orbital-canvas
  const ctx = canvas.getContext('2d');
  const W = canvas.parentElement.clientWidth||600;
  canvas.width=W; canvas.height=H;
  const agents=AGENTS, n=agents.length;
  const centerFilter=document.getElementById('star-center').value;
  const cx=W/2, cy=H/2;
  const orbitR=Math.min(W,H)*0.29;
  const angles=agents.map((_,i)=>i/Math.max(n,1)*Math.PI*2-Math.PI/2);

  const positions={};
  agents.forEach((a,i)=>{
    if(centerFilter===a.name){ positions[a.name]={x:cx,y:cy,r:26}; return; }
    const others=agents.filter(ag=>ag.name!==centerFilter);
    const idx=others.indexOf(a);
    const angle=idx/Math.max(others.length,1)*Math.PI*2-Math.PI/2;
    const R=centerFilter?orbitR:orbitR;
    positions[a.name]={x:cx+Math.cos(angle)*R, y:cy+Math.sin(angle)*R, r:18};
  });

  // Flows same as drawStar
  const sessionStreams=[];
  agents.forEach(agent=>{
    (agent.peers||[]).filter(([,c])=>c>0.3).forEach(([peer,corr])=>{
      if(positions[agent.name]&&positions[peer]){
        sessionStreams.push({src:agent.name,dst:peer,corr,col:'#00c8e0',t:Math.random(),speed:.004+corr*.005});
        sessionStreams.push({src:peer,dst:agent.name,corr,col:'#a78bfa',t:Math.random(),speed:.003+corr*.004});
      }
    });
  });

  let tick=0, lastTime=performance.now();
  function frame(now){
    const dt=Math.min((now-lastTime)/1000,.1); lastTime=now; tick++;
    ctx.clearRect(0,0,W,H);
    _gridDots(ctx,W,H);

    // Orbit ring
    ctx.beginPath();ctx.arc(cx,cy,orbitR,0,Math.PI*2);
    ctx.strokeStyle='rgba(0,200,224,0.07)';ctx.lineWidth=1;
    ctx.setLineDash([4,10]);ctx.stroke();ctx.setLineDash([]);

    // Vigil nucleus
    const ng=ctx.createRadialGradient(cx,cy,0,cx,cy,22);
    ng.addColorStop(0,'rgba(0,200,224,0.25)');ng.addColorStop(1,'rgba(0,200,224,0)');
    ctx.beginPath();ctx.arc(cx,cy,22,0,Math.PI*2);ctx.fillStyle=ng;ctx.fill();
    ctx.beginPath();ctx.arc(cx,cy,8,0,Math.PI*2);
    ctx.fillStyle='#0d1420';ctx.fill();
    ctx.strokeStyle='#00c8e0';ctx.lineWidth=1.5;ctx.stroke();
    ctx.textAlign='center';ctx.font='bold 7px monospace';ctx.fillStyle='#00c8e0';
    ctx.fillText('VIGIL',cx,cy+2.5);

    // Edges
    const drawn=new Set();
    agents.forEach(agent=>{
      (agent.peers||[]).forEach(([peer,corr])=>{
        const key=[agent.name,peer].sort().join('|');
        if(drawn.has(key))return; drawn.add(key);
        const p1=positions[agent.name],p2=positions[peer];
        if(!p1||!p2)return;
        const maxV=Math.max(agent.vrs,(agents.find(a=>a.name===peer)||{vrs:0}).vrs);
        const rgb=maxV>.5?'255,98,0':maxV>.25?'255,179,0':'0,230,118';
        // Bezier curve
        const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2;
        const dx=p2.x-p1.x,dy=p2.y-p1.y,len=Math.sqrt(dx*dx+dy*dy)||1;
        const bend=len*.15;
        const cpx=mx-(dy/len)*bend,cpy=my+(dx/len)*bend;
        ctx.beginPath();
        ctx.strokeStyle=`rgba(${rgb},${.07+corr*.2})`;
        ctx.lineWidth=.5+corr*2;
        corr>.5?ctx.setLineDash([5,4]):ctx.setLineDash([]);
        ctx.moveTo(p1.x,p1.y);ctx.quadraticCurveTo(cpx,cpy,p2.x,p2.y);
        ctx.stroke();ctx.setLineDash([]);
      });
    });

    // Session streams on bezier paths
    sessionStreams.forEach(s=>{
      const p1=positions[s.src],p2=positions[s.dst];
      if(!p1||!p2){s.t=0;return;}
      s.t+=s.speed; if(s.t>1)s.t=0;
      const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2;
      const dx=p2.x-p1.x,dy=p2.y-p1.y,len=Math.sqrt(dx*dx+dy*dy)||1;
      const bend=len*.15;
      const cpx=mx-(dy/len)*bend,cpy=my+(dx/len)*bend;
      const t=s.t;
      const x=(1-t)*(1-t)*p1.x+2*(1-t)*t*cpx+t*t*p2.x;
      const y=(1-t)*(1-t)*p1.y+2*(1-t)*t*cpy+t*t*p2.y;
      const g=ctx.createRadialGradient(x,y,0,x,y,6);
      g.addColorStop(0,s.col+'cc');g.addColorStop(1,s.col+'00');
      ctx.beginPath();ctx.arc(x,y,6,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();
      ctx.beginPath();ctx.arc(x,y,2,0,Math.PI*2);
      ctx.fillStyle=s.col;ctx.globalAlpha=.9;ctx.fill();ctx.globalAlpha=1;
    });

    // Burst particles
    for(let i=_burstParticles.length-1;i>=0;i--){
      const bp=_burstParticles[i];
      bp.x+=bp.vx;bp.y+=bp.vy;bp.vx*=.92;bp.vy*=.92;bp.life-=.04;
      if(bp.life<=0){_burstParticles.splice(i,1);continue;}
      ctx.beginPath();ctx.arc(bp.x,bp.y,bp.r*bp.life,0,Math.PI*2);
      ctx.fillStyle=bp.col;ctx.globalAlpha=bp.life*.8;ctx.fill();ctx.globalAlpha=1;
    }

    // Nodes — hexagonal
    agents.forEach(agent=>{
      const pos=positions[agent.name];
      if(!pos)return;
      const col=sc(agent.state);
      const r=pos.r;
      const flash=_stampFlash[agent.name];
      const fb=flash?flash.t*flash.intensity:0;

      // Alert pulse
      if(agent.state==='ALERT'||agent.state==='CRITICAL'){
        const phase=(tick*.025)%1;
        ctx.beginPath();ctx.arc(pos.x,pos.y,r+phase*20,0,Math.PI*2);
        ctx.strokeStyle=col;ctx.globalAlpha=(1-phase)*.45;ctx.lineWidth=1.5;ctx.stroke();ctx.globalAlpha=1;
      }

      // Stamp flash ring
      if(fb>0){
        ctx.beginPath();ctx.arc(pos.x,pos.y,r+(1-fb)*28,0,Math.PI*2);
        ctx.strokeStyle='#00c8e0';ctx.globalAlpha=fb*.8;ctx.lineWidth=2;ctx.stroke();ctx.globalAlpha=1;
        if(fb>.92){_spawnBurst(pos.x,pos.y,'#00c8e0',6);}
      }

      // Outer glow
      const grd=ctx.createRadialGradient(pos.x,pos.y,r*.3,pos.x,pos.y,r*2.8);
      grd.addColorStop(0,col+(fb>.5?'55':'28'));grd.addColorStop(1,col+'00');
      ctx.beginPath();ctx.arc(pos.x,pos.y,r*2.8,0,Math.PI*2);ctx.fillStyle=grd;ctx.fill();

      // Hex body
      _hexPath(ctx,pos.x,pos.y,r);
      ctx.fillStyle='#0d1420';ctx.fill();
      ctx.strokeStyle=fb>.3?`rgba(0,200,224,${.5+fb*.5})`:col;
      ctx.lineWidth=centerFilter===agent.name?3:1.5;ctx.stroke();

      // Outer hex ring
      _hexPath(ctx,pos.x,pos.y,r+5);
      ctx.strokeStyle=col+'20';ctx.lineWidth=1;ctx.stroke();

      // VRS arc inside hex
      const innerR=r*.65;
      _hexPath(ctx,pos.x,pos.y,innerR);
      ctx.save();ctx.clip();
      ctx.beginPath();ctx.moveTo(pos.x,pos.y);
      ctx.arc(pos.x,pos.y,innerR*1.5,-Math.PI/2,-Math.PI/2+agent.vrs*Math.PI*2);
      ctx.closePath();ctx.fillStyle=col+'30';ctx.fill();ctx.restore();

      // Vertex dots (VRS gauge)
      for(let k=0;k<6;k++){
        const a=(Math.PI/3)*k+Math.PI/6;
        const px=pos.x+r*Math.cos(a),py=pos.y+r*Math.sin(a);
        ctx.beginPath();ctx.arc(px,py,2,0,Math.PI*2);
        ctx.fillStyle=col+(k<Math.round(agent.vrs*6)?'cc':'25');ctx.fill();
      }

      // Stamp indicator dot
      if(fb>.1){
        ctx.beginPath();ctx.arc(pos.x+r*.65,pos.y-r*.65,3,0,Math.PI*2);
        ctx.fillStyle='#00c8e0';ctx.globalAlpha=fb;ctx.fill();ctx.globalAlpha=1;
      }

      // Labels
      ctx.textAlign='center';
      ctx.font='bold 8px monospace';ctx.fillStyle=col;
      ctx.fillText(fv(agent.vrs),pos.x,pos.y+2);
      ctx.font='6px monospace';ctx.fillStyle=col+'88';
      ctx.fillText(agent.state,pos.x,pos.y+10);
      ctx.font='500 9px sans-serif';ctx.fillStyle='#c5d8ec';
      ctx.fillText(agent.name.replace(/_/g,' '),pos.x,pos.y+r+13);
    });

    _decayFlashes(dt);
    if(tick%30===0)_detectNewStamps();
    _starRaf=requestAnimationFrame(frame);
  }
  frame(performance.now());

  // Click handler
  canvas.onclick=e=>{
    const rect=canvas.getBoundingClientRect();
    const mx=(e.clientX-rect.left)*(W/rect.width);
    const my=(e.clientY-rect.top)*(H/rect.height);
    for(const[name,pos]of Object.entries(positions)){
      if((mx-pos.x)**2+(my-pos.y)**2<pos.r**2*3){
        const sel=document.getElementById('star-center');
        if(sel.value===name){sel.value='';_redrawCurrentMode();_closeStampPanel();return;}
        sel.value=name;_redrawCurrentMode();_openStampPanel(name);return;
      }
    }
    document.getElementById('star-center').value='';
    _redrawCurrentMode();_closeStampPanel();
  };
}

// ════════════════════════════════════════════
// RENDERER B — Circuit board
// ════════════════════════════════════════════
function _drawCircuit(canvasId, H){
  if(_circuitRaf){cancelAnimationFrame(_circuitRaf);_circuitRaf=null;}
  const canvas=document.getElementById(canvasId);
  if(!canvas)return;
  const W=canvas.parentElement.clientWidth||600;
  canvas.width=W;canvas.height=H;
  const ctx=canvas.getContext('2d');
  const agents=AGENTS, n=agents.length;

  // Position agents in a grid-snapped layout
  const cols=Math.ceil(Math.sqrt(n)), rows=Math.ceil(n/cols);
  const gx=W/(cols+1), gy=H/(rows+1);
  const gridPos=agents.map((_,i)=>({x:gx*(i%cols+1), y:gy*(Math.floor(i/cols)+1)}));

  function tracePts(p1,p2){
    const mx=(p1.x+p2.x)/2;
    return[p1.x,p1.y, mx,p1.y, mx,p2.y, p2.x,p2.y];
  }
  function ptOnTrace(pts,t){
    const segs=[[pts[0],pts[1],pts[2],pts[3]],[pts[2],pts[3],pts[4],pts[5]],[pts[4],pts[5],pts[6],pts[7]]];
    const lens=segs.map(s=>Math.hypot(s[2]-s[0],s[3]-s[1]));
    const total=lens.reduce((a,b)=>a+b,0);
    let d=t*total;
    for(let i=0;i<segs.length;i++){
      if(d<=lens[i]||i===segs.length-1){
        const f=Math.min(d/Math.max(lens[i],.001),1);
        return{x:segs[i][0]+(segs[i][2]-segs[i][0])*f, y:segs[i][1]+(segs[i][3]-segs[i][1])*f};
      }
      d-=lens[i];
    }
  }

  // Build particles from peers
  const particles=[];
  agents.forEach((agent,i)=>{
    (agent.peers||[]).forEach(([peer,corr])=>{
      const j=agents.findIndex(a=>a.name===peer);
      if(j<0)return;
      const maxV=Math.max(agent.vrs,(agents.find(a=>a.name===peer)||{vrs:0}).vrs);
      const col=maxV>.5?'#ff6200':maxV>.25?'#ffb300':'#00e676';
      particles.push({pts:tracePts(gridPos[i],gridPos[j]),t:Math.random(),speed:.003+corr*.005,corr,col,i,j});
    });
  });

  let tick=0;
  function frame(){
    tick++;
    ctx.clearRect(0,0,W,H);

    // PCB grid
    ctx.strokeStyle='rgba(0,160,60,0.05)';ctx.lineWidth=.5;
    for(let x=0;x<W;x+=20){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(let y=0;y<H;y+=20){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}

    // Traces
    particles.forEach(p=>{
      const pts=p.pts;
      ctx.beginPath();ctx.moveTo(pts[0],pts[1]);
      for(let k=2;k<pts.length;k+=2)ctx.lineTo(pts[k],pts[k+1]);
      const rgb=p.col==='#ff6200'?'255,98,0':p.col==='#ffb300'?'255,179,0':'0,230,118';
      ctx.strokeStyle=`rgba(${rgb},${.1+p.corr*.15})`;
      ctx.lineWidth=.8+p.corr*1.2;ctx.stroke();
      // Pad dots
      [[pts[0],pts[1]],[pts[6],pts[7]]].forEach(([px,py])=>{
        ctx.beginPath();ctx.arc(px,py,2.5,0,Math.PI*2);
        ctx.fillStyle=`rgba(${rgb},.3)`;ctx.fill();
      });
    });

    // Signal particles
    particles.forEach(p=>{
      p.t=(p.t+p.speed)%1;
      const pt=ptOnTrace(p.pts,p.t);
      if(!pt)return;
      const rgb=p.col==='#ff6200'?'255,98,0':p.col==='#ffb300'?'255,179,0':'0,230,118';
      const g=ctx.createRadialGradient(pt.x,pt.y,0,pt.x,pt.y,8);
      g.addColorStop(0,`rgba(${rgb},.9)`);g.addColorStop(1,`rgba(${rgb},0)`);
      ctx.beginPath();ctx.arc(pt.x,pt.y,8,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();
      ctx.beginPath();ctx.arc(pt.x,pt.y,2.5,0,Math.PI*2);ctx.fillStyle=p.col;ctx.fill();
    });

    // IC chip nodes
    agents.forEach((ag,i)=>{
      const {x,y}=gridPos[i];
      const col=sc(ag.state);
      const s=28;
      const flash=_stampFlash[ag.name];
      const fb=flash?flash.t*flash.intensity:0;

      // Stamp flash
      if(fb>.1){
        ctx.strokeStyle=`rgba(0,200,224,${fb*.8})`;ctx.lineWidth=2;
        ctx.strokeRect(x-s-fb*8,y-s-fb*8,s*2+fb*16,s*2+fb*16);
      }

      ctx.fillStyle='#0a1018';ctx.fillRect(x-s,y-s,s*2,s*2);
      ctx.strokeStyle=fb>.3?`rgba(0,200,224,${.5+fb*.5})`:col;
      ctx.lineWidth=1.5;ctx.strokeRect(x-s,y-s,s*2,s*2);
      ctx.strokeStyle=col+'30';ctx.lineWidth=.7;
      ctx.strokeRect(x-s+5,y-s+5,s*2-10,s*2-10);

      // Pin marks
      [0,1,2,3].forEach(side=>{
        for(let p=0;p<3;p++){
          const t=(p+1)/4;
          let px,py,ex,ey;
          if(side===0){px=x-s+t*s*2;py=y-s;ex=px;ey=py-5;}
          else if(side===1){px=x+s;py=y-s+t*s*2;ex=px+5;ey=py;}
          else if(side===2){px=x-s+t*s*2;py=y+s;ex=px;ey=py+5;}
          else{px=x-s;py=y-s+t*s*2;ex=px-5;ey=py;}
          ctx.beginPath();ctx.moveTo(px,py);ctx.lineTo(ex,ey);
          ctx.strokeStyle=col+'50';ctx.lineWidth=1;ctx.stroke();
        }
      });

      // VRS fill bar
      const fh=ag.vrs*s*2*.72;
      ctx.fillStyle=col+'1a';ctx.fillRect(x-s+6,y+s-6-fh,s*2-12,fh);

      // Crosshair
      ctx.strokeStyle=col+'18';ctx.lineWidth=.5;
      ctx.beginPath();ctx.moveTo(x,y-s+5);ctx.lineTo(x,y+s-5);ctx.stroke();
      ctx.beginPath();ctx.moveTo(x-s+5,y);ctx.lineTo(x+s-5,y);ctx.stroke();

      ctx.textAlign='center';
      ctx.font='bold 8px monospace';ctx.fillStyle=col;ctx.fillText(fv(ag.vrs),x,y-2);
      ctx.font='7px monospace';ctx.fillStyle=col+'88';ctx.fillText(ag.state,x,y+9);
      ctx.font='500 9px sans-serif';ctx.fillStyle='#8aa8c0';
      ctx.fillText(ag.name.replace(/_/g,' '),x,y+s+14);
    });

    _decayFlashes(1/60);
    if(tick%30===0)_detectNewStamps();
    _circuitRaf=requestAnimationFrame(frame);
  }
  frame();
}

// ════════════════════════════════════════════
// RENDERER C — Radar / polar matrix
// ════════════════════════════════════════════
function _drawRadar(canvasId, H){
  if(_radarRaf){cancelAnimationFrame(_radarRaf);_radarRaf=null;}
  const canvas=document.getElementById(canvasId);
  if(!canvas)return;
  const W=canvas.parentElement.clientWidth||600;
  canvas.width=W;canvas.height=H;
  const ctx=canvas.getContext('2d');
  const agents=AGENTS;
  const axes=['VRS','Trust','A2C','Chain','Events'];
  const N=axes.length;
  const cx=W/2, cy=H/2+10;
  const maxR=Math.min(W,H)*0.32;

  function axisXY(k,r){
    const a=k/N*Math.PI*2-Math.PI/2;
    return{x:cx+Math.cos(a)*r, y:cy+Math.sin(a)*r};
  }
  function agentVals(a){
    const evNorm=Math.min((a.event_count||0)/1000,1);
    return[a.vrs, a.ts, a.a2c, a.chain_label==='CANONICAL CHAIN'?0:.7, evNorm];
  }

  let tick=0;
  function frame(){
    tick++;
    ctx.clearRect(0,0,W,H);
    _gridDots(ctx,W,H,'rgba(0,200,224,0.03)',32);

    // Rings
    [.2,.4,.6,.8,1].forEach(t=>{
      ctx.beginPath();
      for(let k=0;k<N;k++){
        const {x,y}=axisXY(k,t*maxR);
        k===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
      }
      ctx.closePath();
      ctx.strokeStyle=`rgba(0,200,224,${.04+t*.015})`;ctx.lineWidth=.5;ctx.stroke();
    });

    // Axis lines + labels
    for(let k=0;k<N;k++){
      const {x,y}=axisXY(k,maxR);
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(x,y);
      ctx.strokeStyle='rgba(0,200,224,0.1)';ctx.lineWidth=.5;ctx.stroke();
      const lp=axisXY(k,maxR+18);
      ctx.font='8px monospace';ctx.fillStyle='#4a7a99';
      ctx.textAlign='center';ctx.fillText(axes[k],lp.x,lp.y+3);
    }

    // Agent polygons
    agents.forEach((ag,i)=>{
      const vals=agentVals(ag);
      const col=sc(ag.state);
      const pulse=1+.025*Math.sin(tick*.04+i*1.5);
      const flash=_stampFlash[ag.name];
      const fb=flash?flash.t*flash.intensity:0;

      ctx.beginPath();
      vals.forEach((v,k)=>{
        const {x,y}=axisXY(k,v*maxR*pulse*(1+fb*.05));
        k===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
      });
      ctx.closePath();
      const rgb=col==='#00e676'?'0,230,118':col==='#ffb300'?'255,179,0':col==='#ff6200'?'255,98,0':'245,0,60';
      ctx.fillStyle=`rgba(${rgb},${.05+fb*.05})`;ctx.fill();
      ctx.strokeStyle=`rgba(${rgb},${.45+fb*.3})`;ctx.lineWidth=1+fb*.5;ctx.stroke();

      vals.forEach((v,k)=>{
        const {x,y}=axisXY(k,v*maxR*pulse);
        ctx.beginPath();ctx.arc(x,y,2.5,0,Math.PI*2);
        ctx.fillStyle=`rgba(${rgb},.8)`;ctx.fill();
      });
    });

    // Center
    ctx.beginPath();ctx.arc(cx,cy,5,0,Math.PI*2);
    ctx.fillStyle='#0d1420';ctx.fill();
    ctx.strokeStyle='#00c8e0';ctx.lineWidth=1.5;ctx.stroke();

    // Legend
    agents.forEach((ag,i)=>{
      const lx=20+i*Math.floor(W/agents.length),ly=H-14;
      const col=sc(ag.state);
      ctx.beginPath();ctx.arc(lx+4,ly,4,0,Math.PI*2);
      ctx.fillStyle=col+'66';ctx.fill();
      ctx.strokeStyle=col;ctx.lineWidth=1;ctx.stroke();
      ctx.font='8px monospace';ctx.fillStyle='#6a90a8';
      ctx.textAlign='left';ctx.fillText(ag.name,lx+12,ly+3);
    });

    _decayFlashes(1/60);
    if(tick%30===0)_detectNewStamps();
    _radarRaf=requestAnimationFrame(frame);
  }
  frame();
}

// ════════════════════════════════════════════
// RENDERER D — Flow lanes / swimlanes
// ════════════════════════════════════════════
const _laneEvents=[];
const _laneBeams=[];
let _laneSpawnT=0;

function _laneSpawn(){
  const agents=AGENTS, n=agents.length;
  if(!n)return;
  const i=Math.floor(Math.random()*n);
  const types=['action','stamp','a2a','alert','decision'];
  const type=types[Math.floor(Math.random()*types.length)];
  _laneEvents.push({lane:i,y:1,speed:.35+Math.random()*.5,col:sc(agents[i].state),
    type,life:1,size:type==='alert'?6:type==='stamp'?4:3});
  // Occasionally spawn a beam
  if(Math.random()<.15&&agents.length>1){
    const peers=agents[i].peers||[];
    if(peers.length){
      const [peer,corr]=peers[Math.floor(Math.random()*peers.length)];
      const j=agents.findIndex(a=>a.name===peer);
      if(j>=0){
        const col=corr>.5?'#ff6200':corr>.25?'#ffb300':'#00e676';
        _laneBeams.push({i,j,t:0,speed:.018+corr*.015,corr,col,life:1});
      }
    }
  }
}

function _drawLanes(canvasId, H){
  if(_laneRaf){cancelAnimationFrame(_laneRaf);_laneRaf=null;}
  const canvas=document.getElementById(canvasId);
  if(!canvas)return;
  const W=canvas.parentElement.clientWidth||600;
  canvas.width=W;canvas.height=H;
  const ctx=canvas.getContext('2d');
  const agents=AGENTS, n=agents.length;
  if(!n){ ctx.clearRect(0,0,W,H); return; }
  const laneW=W/n;
  const HEADER=48;

  function laneCX(i){return laneW*i+laneW/2;}

  let tick=0, lastSpawn=0;
  function frame(){
    tick++;
    ctx.clearRect(0,0,W,H);

    // Spawn
    if(tick-lastSpawn>40+Math.random()*30){_laneSpawn();lastSpawn=tick;}

    // Lane BG
    agents.forEach((_,i)=>{
      ctx.fillStyle=i%2===0?'rgba(0,200,224,0.012)':'rgba(0,0,0,0)';
      ctx.fillRect(i*laneW,HEADER,laneW,H-HEADER);
    });

    // Dividers
    for(let i=1;i<n;i++){
      ctx.beginPath();ctx.moveTo(i*laneW,0);ctx.lineTo(i*laneW,H);
      ctx.strokeStyle='rgba(25,37,53,0.9)';ctx.lineWidth=1;ctx.stroke();
    }

    // Headers
    agents.forEach((ag,i)=>{
      const x=laneCX(i);
      const col=sc(ag.state);
      const flash=_stampFlash[ag.name];
      const fb=flash?flash.t*flash.intensity:0;

      ctx.fillStyle=fb>.3?'#0a1220':'#080d14';
      ctx.fillRect(i*laneW+1,1,laneW-2,HEADER-1);
      ctx.strokeStyle=fb>.3?`rgba(0,200,224,${.3+fb*.4})`:col+'44';
      ctx.lineWidth=1;ctx.strokeRect(i*laneW+1,1,laneW-2,HEADER-1);

      // State color bar at top of header
      ctx.fillStyle=col;
      ctx.fillRect(i*laneW+1,1,laneW-2,2);

      ctx.textAlign='center';
      ctx.font='bold 9px monospace';ctx.fillStyle=col;
      ctx.fillText(ag.name.replace(/_/g,' '),x,18);
      ctx.font='7px monospace';ctx.fillStyle=col+'88';
      ctx.fillText('VRS '+fv(ag.vrs),x,30);
      ctx.font='7px monospace';ctx.fillStyle=col+'60';
      ctx.fillText(ag.state,x,41);

      // Pulse dot
      if(ag.state==='ALERT'||ag.state==='CRITICAL'){
        const pulse=.5+.5*Math.sin(tick*.08+i);
        ctx.beginPath();ctx.arc(i*laneW+laneW-10,10,3,0,Math.PI*2);
        ctx.fillStyle=col;ctx.globalAlpha=pulse;ctx.fill();ctx.globalAlpha=1;
      }
    });

    // Horizontal A2A beams
    for(let b=_laneBeams.length-1;b>=0;b--){
      const bm=_laneBeams[b];
      bm.t+=bm.speed; bm.life=Math.max(0,1-bm.t);
      if(bm.life===0){_laneBeams.splice(b,1);continue;}
      const x1=laneCX(bm.i),x2=laneCX(bm.j);
      const xCur=x1+(x2-x1)*Math.min(bm.t,1);
      const y=HEADER+20+Math.random()*.3*(H-HEADER-40);
      const rgb=bm.col==='#ff6200'?'255,98,0':bm.col==='#ffb300'?'255,179,0':'0,230,118';
      ctx.beginPath();ctx.moveTo(x1,y);ctx.lineTo(xCur,y);
      ctx.strokeStyle=`rgba(${rgb},${.12*bm.life})`;ctx.lineWidth=1;ctx.stroke();
      const g=ctx.createRadialGradient(xCur,y,0,xCur,y,9);
      g.addColorStop(0,`rgba(${rgb},.75)`);g.addColorStop(1,`rgba(${rgb},0)`);
      ctx.beginPath();ctx.arc(xCur,y,9,0,Math.PI*2);
      ctx.fillStyle=g;ctx.globalAlpha=bm.life;ctx.fill();ctx.globalAlpha=1;
    }

    // Floating events
    for(let e=_laneEvents.length-1;e>=0;e--){
      const ev=_laneEvents[e];
      const yAbs=H-HEADER-ev.y*(H-HEADER-10);
      ev.y+=ev.speed/100;
      if(yAbs<HEADER+4||ev.y>1.05){_laneEvents.splice(e,1);continue;}
      const x=laneCX(ev.lane);
      const alpha=Math.min(1,ev.y*8)*Math.min(1,(1-ev.y)*8);
      const rgb=ev.col==='#00e676'?'0,230,118':ev.col==='#ffb300'?'255,179,0':ev.col==='#ff6200'?'255,98,0':'245,0,60';
      ctx.globalAlpha=alpha;
      if(ev.type==='stamp'){
        ctx.save();ctx.translate(x,yAbs);ctx.rotate(Math.PI/4);
        ctx.fillStyle=`rgba(${rgb},.85)`;
        ctx.fillRect(-ev.size,-ev.size,ev.size*2,ev.size*2);
        ctx.restore();
      } else if(ev.type==='alert'){
        ctx.beginPath();
        ctx.moveTo(x,yAbs-ev.size);
        ctx.lineTo(x+ev.size,yAbs+ev.size);
        ctx.lineTo(x-ev.size,yAbs+ev.size);
        ctx.closePath();ctx.fillStyle=`rgba(${rgb},.9)`;ctx.fill();
      } else if(ev.type==='decision'){
        ctx.beginPath();ctx.arc(x,yAbs,ev.size,0,Math.PI*2);
        ctx.strokeStyle=`rgba(${rgb},.8)`;ctx.lineWidth=1.5;ctx.stroke();
      } else {
        ctx.beginPath();ctx.arc(x,yAbs,ev.size,0,Math.PI*2);
        ctx.fillStyle=`rgba(${rgb},.7)`;ctx.fill();
      }
      ctx.globalAlpha=1;
    }

    _decayFlashes(1/60);
    if(tick%30===0)_detectNewStamps();
    _laneRaf=requestAnimationFrame(frame);
  }
  frame();
}

// ════════════════════════════════════════════
// LIVE COCKPIT
// ════════════════════════════════════════════
let _ckAgent       = null;   // nom de l'agent surveillé
let _ckLive        = true;   // mode live activé
let _ckAutoScroll  = true;   // défilement automatique
let _ckFilter      = '';     // filtre type
let _ckSeenHashes  = new Set(); // hashes déjà affichés (déduplication)
let _ckRaf         = null;   // RAF pour le ticker de rate
let _ckEventTimes  = [];     // timestamps des events récents (pour rate/min)
let _ckRefreshT    = null;   // setInterval live fetch
let _ckHeight      = 340;    // hauteur cockpit en px
let _ckResizing    = false;

// Couleurs par type
const _ckTypeColors = {
  action:        {col:'var(--ac)',    bg:'var(--ac2)'},
  decision:      {col:'var(--watch)', bg:'var(--watchb)'},
  observation:   {col:'#a78bfa',      bg:'rgba(167,139,250,.1)'},
  alert:         {col:'var(--alert)', bg:'var(--alertb)'},
  a2a_handshake: {col:'var(--safe)',  bg:'var(--safeb)'},
  trust_update:  {col:'#64b5f6',      bg:'rgba(100,181,246,.1)'},
  chain_verify:  {col:'var(--ac)',    bg:'var(--ac2)'},
};

// Traduction payload → langage naturel
function _ckNaturalLanguage(type, payload, peerName){
  const p = payload || {};
  const peer = peerName ? `<strong>${peerName}</strong>` : 'a peer';
  switch(type){
    case 'action':
      return `Executing <strong>${p.action||'task'}</strong>${p.target?' on '+p.target:''}`
           + (p.confidence!=null?` — confidence <strong>${(p.confidence*100).toFixed(0)}%</strong>`:'');
    case 'decision':
      return `Decision: <strong>${p.decision||'?'}</strong>`
           + (p.symbol?` ${p.symbol}`:'')
           + (p.amount!=null?` — amount <strong>${p.amount}</strong>`:'');
    case 'observation':
      return `Observed <strong>${p.observation||'event'}</strong>`
           + (p.delta!=null?` Δ<strong>${p.delta>0?'+':''}${p.delta}</strong>`:'')
           + (p.source?` from ${p.source}`:'');
    case 'alert':
      return `⚡ <strong>${p.alert||'threshold exceeded'}</strong>`
           + (p.vrs!=null?` VRS=<strong>${p.vrs}</strong>`:'')
           + (p.escalated?' — escalated':'');
    case 'a2a_handshake':
      return `Handshake <strong>${p.handshake||'init'}</strong> with ${peer}`
           + (p.session_id?` · session <code>${p.session_id}</code>`:'');
    case 'trust_update': {
      const d=+(p.delta||0);
      const dSign = d>=0 ? '+' : '';
      const dCol = d>=0 ? 'var(--safe)' : 'var(--alert)';
      return 'Trust score → <strong>'+(p.trust_score!=null?(p.trust_score*100).toFixed(1)+'%':'?')+'</strong>'
           + ' (<strong style="color:'+dCol+'">'+dSign+d.toFixed(4)+'</strong>)';
    }
    case 'chain_verify': {
      return 'Chain <strong style="color:'+(p.fork_detected?'var(--crit)':'var(--safe)')+'">'+
             (p.chain||'ok')+'</strong>'+
             (p.depth!=null?' — depth '+p.depth:'')+
             (p.fork_detected?' ⚠ FORK DETECTED':'');
    }
    default: {
      // Essayer de décrire le payload générique
      const keys = Object.keys(p).slice(0,3);
      if(!keys.length) return '<strong>'+type+'</strong> event';
      return '<strong>'+type+'</strong> — '+keys.map(function(k){return k+': <strong>'+JSON.stringify(p[k])+'</strong>';}).join(' · ');
    }
  }
}

function _ckRowHTML(stamp, isNew){
  const type = stamp.event_type || 'event';
  const tc   = _ckTypeColors[type] || {col:'var(--txm)', bg:'rgba(255,255,255,.04)'};
  const ts   = stamp.timestamp
    ? new Date(stamp.timestamp*1000).toISOString().slice(11,19)
    : '—';

  // Résoudre le nom du peer
  const rawPeer = stamp.peer_id || stamp.payload?.peer_id || '';
  const peerName = _peerNameCache[rawPeer] || rawPeer || '';

  const isValid = (stamp.sig_status||'valid') === 'valid';
  const natural = _ckNaturalLanguage(type, stamp.payload, peerName);
  const hash = (stamp.hash||'').slice(0,24);
  const seq  = stamp.seq ? `#${stamp.seq}` : '';

  return `<div class="ck-row${isNew?' ck-new':''}">
    <div class="ck-time">${ts}</div>
    <div class="ck-type-col" style="background:${tc.col};opacity:.7"></div>
    <div class="ck-body">
      <div class="ck-head">
        <span class="ck-type" style="color:${tc.col};background:${tc.bg}">${type.toUpperCase()}</span>
        ${peerName?`<span class="ck-peer">→ <span>${peerName}</span></span>`:''}
        ${seq?`<span style="font-family:var(--mono);font-size:8px;color:var(--txd)">${seq}</span>`:''}
        <span class="ck-sig ${isValid?'sig-ok':'sig-bad'}">${isValid?'✓':'✗'}</span>
      </div>
      <div class="ck-natural">${natural}</div>
      ${hash?`<div class="ck-hash">${hash}…</div>`:''}
    </div>
  </div>`;
}

function _ckPushStamps(stamps, isNew=false){
  const stream = document.getElementById('ck-stream');
  const filter = _ckFilter;

  const toAdd = stamps.filter(s=>{
    const h = s.hash||s.nonce||JSON.stringify(s).slice(0,32);
    if(_ckSeenHashes.has(h)) return false;
    _ckSeenHashes.add(h);
    if(filter && (s.event_type||'')!==filter) return false;
    return true;
  });

  if(!toAdd.length) return;

  // Enregistrer timestamps pour rate
  const now = Date.now()/1000;
  toAdd.forEach(()=>_ckEventTimes.push(now));
  _ckEventTimes = _ckEventTimes.filter(t=>now-t<60);

  // Injecter les nouvelles lignes en bas
  const frag = document.createDocumentFragment();
  const tmp  = document.createElement('div');
  tmp.innerHTML = toAdd.map(s=>_ckRowHTML(s, isNew)).join('');
  while(tmp.firstChild) frag.appendChild(tmp.firstChild);

  // Supprimer les vieilles lignes si trop nombreuses (>200)
  const existing = stream.querySelectorAll('.ck-row');
  if(existing.length > 200){
    for(let i=0;i<existing.length-180;i++) existing[i].remove();
  }

  // Retirer le placeholder vide si présent
  const empty = stream.querySelector('div:not(.ck-row)');
  if(empty) empty.remove();

  stream.appendChild(frag);

  if(_ckAutoScroll){
    stream.scrollTop = stream.scrollHeight;
  }
}

// ════════════════════════════════════════════
// STAMP PANEL — onglets STAMPS / LIVE
// ════════════════════════════════════════════
function _spSetTab(tab){
  ['stamps','live'].forEach(function(t){
    var pane = document.getElementById('sp-pane-'+t);
    var btn  = document.getElementById('sp-tab-'+t);
    if(!pane||!btn) return;
    var active = (t===tab);
    pane.style.display    = active ? 'flex' : 'none';
    btn.style.color       = active ? 'var(--ac)' : 'var(--txd)';
    btn.style.borderBottom= active ? '2px solid var(--ac)' : '2px solid transparent';
  });
  // Démarrer le polling live si on bascule sur cet onglet
  if(tab==='live' && _ckAgent && !_ckRefreshT){
    _ckRefreshT = setInterval(_ckFetchAndPush, 2500);
  }
}

// ════════════════════════════════════════════
// LIVE FEED — dans le panneau stamp
// ════════════════════════════════════════════
function openCockpit(agentName){
  _ckAgent = agentName;
  _ckSeenHashes.clear();
  _ckEventTimes = [];
  _ckFilter = '';
  var fe = document.getElementById('ck-filter');
  if(fe) fe.value = '';
  // Réinitialiser le stream
  var stream = document.getElementById('ck-stream');
  if(stream) stream.innerHTML = '<div style="padding:10px 14px;font-family:var(--mono);font-size:9px;color:var(--txd);border-bottom:1px solid var(--b1)">── '+agentName.replace(/_/g,' ')+' — '+new Date().toISOString().slice(11,19)+' UTC ──</div>';
  // Charger l'historique initial depuis /api/agent/<name>
  _vigilFetch('/api/agent/'+encodeURIComponent(agentName))
    .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function(d){ _ckPushStamps(_agentDataToStamps(d, agentName), false); })
    .catch(function(){
      var agent = AGENTS.find(function(a){ return a.name===agentName; });
      _ckPushStamps(_generateDemoStamps(agentName, agent), false);
    });
  // Démarrer polling seulement si onglet live visible
  if(_ckRefreshT) clearInterval(_ckRefreshT);
  var livePane = document.getElementById('sp-pane-live');
  if(livePane && livePane.style.display !== 'none'){
    _ckRefreshT = setInterval(_ckFetchAndPush, 2500);
  }
}

// Convertit la réponse /api/agent/<n> en stamps affichables
function _agentDataToStamps(d, agentName){
  var stamps = [];
  var now = Date.now()/1000;
  // Alertes → stamps
  var alerts = (d.alerts||[]).slice().reverse();
  alerts.forEach(function(al, i){
    stamps.push({
      seq: i+1, timestamp: al.timestamp||now,
      event_type: 'alert',
      payload: {severity: al.severity||'?', message: al.message||'', agent: al.agent_name||agentName},
      hash: '—', prev_hash: '—', sig_status: 'valid', algorithm: 'Ed25519'
    });
  });
  // Historique VRS → stamps trust_update
  var history = (d.history||[]).slice(-20).reverse();
  history.forEach(function(h, i){
    stamps.push({
      seq: alerts.length+i+1, timestamp: h.timestamp||h.t||now,
      event_type: 'trust_update',
      payload: {trust_score: h.vrs||h.v||0, state: h.state||'?'},
      hash: '—', prev_hash: '—', sig_status: 'valid', algorithm: 'Ed25519'
    });
  });
  if(!stamps.length){
    var agent = AGENTS.find(function(a){ return a.name===agentName; });
    return _generateDemoStamps(agentName, agent);
  }
  return stamps;
}

function _ckFetchAndPush(){
  if(!_ckAgent || !_ckLive) return;
  _vigilFetch('/api/agent/'+encodeURIComponent(_ckAgent))
    .then(function(r){ return r.ok ? r.json() : Promise.reject(); })
    .then(function(d){ _ckPushStamps(_agentDataToStamps(d, _ckAgent), true); })
    .catch(function(){
      if(!_ckAgent) return;
      var agent = AGENTS.find(function(a){ return a.name===_ckAgent; });
      if(!agent) return;
      var types = ['action','decision','observation','a2a_handshake','trust_update','chain_verify'];
      var type  = types[Math.floor(Math.random()*types.length)];
      var now   = Date.now()/1000;
      var h     = Array.from({length:12},function(){ return Math.floor(Math.random()*16).toString(16); }).join('');
      _ckPushStamps([{seq:Math.floor(now),timestamp:now,event_type:type,
        payload:_demoPayload(type,_ckAgent),hash:h,prev_hash:h.slice(2),
        sig_status:Math.random()>.05?'valid':'invalid',algorithm:'Ed25519'}], true);
    });
}

function _closeCockpit(){
  if(_ckRefreshT){ clearInterval(_ckRefreshT); _ckRefreshT=null; }
  _ckAgent = null;
}

function _ckToggleLive(){
  _ckLive = !_ckLive;
  var btn = document.getElementById('ck-btn-live');
  if(btn) btn.textContent = _ckLive ? '⟳ LIVE' : '⏸ PAUSED';
  var banner = document.getElementById('ck-paused-banner');
  if(banner) banner.style.display = _ckLive ? 'none' : 'block';
  var dot = document.getElementById('ck-live-d');
  if(dot) dot.style.background = _ckLive ? 'var(--safe)' : 'var(--watch)';
}

function _ckToggleScroll(){
  _ckAutoScroll = !_ckAutoScroll;
  var btn = document.getElementById('ck-btn-scroll');
  if(btn) btn.textContent = _ckAutoScroll ? '↓ AUTO' : '↕ MANUAL';
}

function _ckClear(){
  _ckSeenHashes.clear(); _ckEventTimes = [];
  var stream = document.getElementById('ck-stream');
  if(stream) stream.innerHTML = '<div style="padding:10px 14px;font-family:var(--mono);font-size:9px;color:var(--txd);border-bottom:1px solid var(--b1)">── Cleared '+new Date().toISOString().slice(11,19)+' UTC ──</div>';
}

function _ckApplyFilter(){
  var el = document.getElementById('ck-filter');
  _ckFilter = el ? el.value : '';
}

loadFromBackend();
setInterval(loadFromBackend,5000);
// Start demo stamp simulation — will be overridden by real data when backend is live
setTimeout(_demoStampLoop, 2000);
