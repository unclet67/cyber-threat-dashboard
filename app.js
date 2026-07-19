import { buildRelationshipClassifier, relationshipLabel, scoreArticle } from './intel-model.mjs';

/* Big 4 Cyber & IW Threat Dashboard — application logic.
   Config: data/sources.json · Data: produced hourly by scripts/fetch-news.mjs */
let COUNTRIES={  // inline fallback; canonical config in data/sources.json (loaded by loadSources)
  CN:{name:'China',flag:'🇨🇳',short:'PRC',color:'CN',genericTerms:['China','PRC','Chinese','Beijing'],terms:['China','PRC','Chinese','Beijing','PLA','MSS','Salt Typhoon','Volt Typhoon','Flax Typhoon','APT41','APT40','Mustang Panda','Storm-0558'],focus:'Telecom, critical infrastructure, strategic espionage, IP theft, Taiwan/US targeting, influence activity.'},
  RU:{name:'Russia',flag:'🇷🇺',short:'Russia',color:'RU',genericTerms:['Russia','Russian','Moscow'],terms:['Russia','Russian','Moscow','GRU','SVR','FSB','Sandworm','APT28','APT29','Fancy Bear','Cozy Bear','Gamaredon','Turla','Star Blizzard'],focus:'Wartime cyber operations, disruptive attacks, NATO/defense espionage, hack-and-leak, election influence.'},
  IR:{name:'Iran',flag:'🇮🇷',short:'Iran',color:'IR',genericTerms:['Iran','Iranian','Tehran'],terms:['Iran','Iranian','Tehran','IRGC','MOIS','APT33','APT34','APT35','APT42','MuddyWater','OilRig','Charming Kitten','CyberAv3ngers'],focus:'Regional espionage, hack-and-leak, wipers, ransomware enablement, Israel/Gulf/US targeting.'},
  KP:{name:'North Korea',flag:'🇰🇵',short:'DPRK',color:'KP',genericTerms:['North Korea','DPRK','North Korean','Pyongyang'],terms:['North Korea','DPRK','North Korean','Pyongyang','Lazarus','Kimsuky','APT38','APT37','APT43','Andariel','Bluenoroff','Emerald Sleet','Diamond Sleet'],focus:'Crypto theft, defense/aerospace espionage, IT worker schemes, sanctions evasion, nuclear/missile support.'}
};
function escapeRegex(s){return String(s).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
// Ambiguous short acronyms (e.g. MSS = managed security services) only count in titles; overridden from sources.json.
let WEAK_TERMS=new Set(['PLA','MSS','GRU','SVR','FSB']);
let classifyRelationships=buildRelationshipClassifier(COUNTRIES,[...WEAK_TERMS]);
// Feeds load from data/sources.json (single source of truth, shared with the collector).
let CYBER_FEEDS=[];
async function loadSources(){
  try{
    const r=await fetch('data/sources.json?_='+Date.now(),{cache:'no-store'});
    if(!r.ok) throw new Error(r.status);
    const d=await r.json();
    if(d&&d.countries&&Array.isArray(d.feeds)){ COUNTRIES=d.countries; CYBER_FEEDS=d.feeds; if(Array.isArray(d.weakTerms)) WEAK_TERMS=new Set(d.weakTerms); classifyRelationships=buildRelationshipClassifier(COUNTRIES,[...WEAK_TERMS]); }
  }catch(e){ /* offline: keep the inline fallback COUNTRIES; live feeds unavailable */ }
}
// Public CORS proxies, tried in order, so the browser can read feeds that lack CORS headers.
const CORS_PROXIES=[
  u=>`https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u=>`https://corsproxy.io/?url=${encodeURIComponent(u)}`
];
const FALLBACK_ACTORS=[
  {c:'CN',n:'APT1',a:['Comment Crew','PLA Unit 61398','Byzantine Candor','TG-8223','G0006'],d:'PLA-linked espionage actor widely associated with Unit 61398.'},
  {c:'CN',n:'APT2',a:['Putter Panda','PLA Unit 61486','MSUpdater','TG-6952','G0024'],d:'Aerospace/satellite-focused PRC-linked cluster.'},
  {c:'CN',n:'APT3',a:['Buckeye','Gothic Panda','UPS Team','Brocade Typhoon','TG-0110'],d:'China-nexus cyber espionage group.'},
  {c:'CN',n:'APT4',a:['Sykipot','Wisp Team'],d:'Historic China-linked intrusion set focused on DIB and aerospace.'},
  {c:'CN',n:'APT5',a:['Manganese','Keyhole Panda','Mulberry Typhoon'],d:'Long-running telecom and technology espionage actor.'},
  {c:'CN',n:'APT6',a:['1.php Group','Circle Typhoon overlap'],d:'China-nexus actor, often tracked through legacy APT naming.'},
  {c:'CN',n:'APT7',a:['PittyTiger overlap','Group 7'],d:'Legacy China-linked actor in IP theft reporting.'},
  {c:'CN',n:'APT8',a:['Group 8'],d:'China-linked group reported in industrial and media targeting.'},
  {c:'CN',n:'APT10',a:['MenuPass','Stone Panda','Red Apollo','Cicada','Potassium'],d:'MSS-linked espionage actor; managed service provider compromises.'},
  {c:'CN',n:'APT12',a:['Numbered Panda','Calc Team','BeeBus','DynCalc','Hexagon Typhoon'],d:'China-linked actor targeting journalists, government, and DIB.'},
  {c:'CN',n:'APT14',a:['QAZTeam'],d:'China-linked data theft actor, maritime/military themes.'},
  {c:'CN',n:'APT15',a:['Ke3chang','Vixen Panda','Mirage','NICKEL','Flea'],d:'China-nexus actor targeting government, finance, energy, military.'},
  {c:'CN',n:'APT16',a:['SVCMONDR'],d:'China-linked actor in Japan/Taiwan themed campaigns.'},
  {c:'CN',n:'APT17',a:['DeputyDog','Tailgator Team','Aurora Panda'],d:'China-linked intrusions against government and technology targets.'},
  {c:'CN',n:'APT18',a:['Wekby','Dynamite Panda'],d:'China-linked actor targeting aerospace, health, telecom, high tech.'},
  {c:'CN',n:'APT19',a:['Deep Panda','Codoso','Checkered Typhoon','TG-3551'],d:'China-linked legal, investment, and high-value sector espionage.'},
  {c:'CN',n:'APT20',a:['Violin Panda','Wocao'],d:'China-linked actor with strategic web compromise history.'},
  {c:'CN',n:'APT21',a:['Zhenbao'],d:'China-linked government-focused espionage cluster.'},
  {c:'CN',n:'APT22',a:['Barista','Suckfly'],d:'China-nexus actor targeting political, military, and economic entities.'},
  {c:'CN',n:'APT23',a:['Pirate Panda'],d:'China-linked actor targeting media and government.'},
  {c:'CN',n:'APT24',a:['PittyTiger','Palmerworm','Canary Typhoon','BlackTech overlap'],d:'China-linked actor targeting government, healthcare, telecom, and Taiwan-related issues.'},
  {c:'CN',n:'APT25',a:['Uncool','Ke3chang','Vixen Panda'],d:'China-linked data theft actor targeting DIB, media, finance, transportation.'},
  {c:'CN',n:'APT26',a:['Hippo Team'],d:'China-linked aerospace, defense, and energy espionage actor.'},
  {c:'CN',n:'APT27',a:['Emissary Panda','Lucky Mouse','Iron Tiger','Circle Typhoon','TG-3390'],d:'China-linked actor targeting government, defense, technology, and embassies.'},
  {c:'CN',n:'APT30',a:['Naikon'],d:'Long-running China-linked ASEAN/government espionage actor.'},
  {c:'CN',n:'APT31',a:['Zirconium','Judgment Panda','Violet Typhoon','TA412'],d:'China-nexus actor targeting government, aerospace, telecom, finance, and policy.'},
  {c:'CN',n:'APT40',a:['Leviathan','TEMP.Periscope','Kryptonite Panda','Gingham Typhoon','BRONZE MOHAWK'],d:'MSS/Hainan-linked maritime, defense, and Belt-and-Road espionage actor.'},
  {c:'CN',n:'APT41',a:['Barium','Winnti','Wicked Panda','Brass Typhoon','Double Dragon'],d:'PRC state-sponsored espionage plus financially motivated activity.'},
  {c:'CN',n:'BackdoorDiplomacy',a:['Playful Taurus','CloudComputating'],d:'China-linked diplomatic and government targeting cluster.'},
  {c:'CN',n:'BlackTech',a:['Palmerworm','Circuit Panda','Earth Hundun'],d:'Taiwan/Japan/US-focused China-linked espionage actor.'},
  {c:'CN',n:'Flax Typhoon',a:['Ethyl APT'],d:'PRC-linked actor associated with botnet/proxy infrastructure reporting.'},
  {c:'CN',n:'Gallium',a:['Soft Cell','PingPull','Alloy Taurus'],d:'China-linked telecom-focused espionage actor.'},
  {c:'CN',n:'Hafnium',a:['Silk Typhoon'],d:'China-linked Exchange exploitation and espionage cluster.'},
  {c:'CN',n:'Mustang Panda',a:['TA416','RedDelta','Bronze President','Stately Taurus'],d:'China-linked group targeting NGOs, governments, and regions of strategic interest.'},
  {c:'CN',n:'Salt Typhoon',a:['GhostEmperor','FamousSparrow','Earth Estries','UNC2286'],d:'PRC-linked telecom/counterintelligence espionage reporting.'},
  {c:'CN',n:'Storm-0558',a:['Antique Typhoon'],d:'China-linked cloud/email espionage actor.'},
  {c:'CN',n:'Tropic Trooper',a:['Pirate Panda','KeyBoy'],d:'China-linked actor targeting Taiwan, Philippines, Hong Kong, and energy/government sectors.'},
  {c:'CN',n:'Volt Typhoon',a:['VANGUARD PANDA','BRONZE SILHOUETTE','Insidious Taurus','VOLTZITE','UNC3236'],d:'PRC-linked critical infrastructure pre-positioning actor.'},

  {c:'RU',n:'APT28',a:['Fancy Bear','Sofacy','Sednit','Pawn Storm','STRONTIUM','Forest Blizzard'],d:'GRU-linked espionage and influence/hack-and-leak actor.'},
  {c:'RU',n:'APT29',a:['Cozy Bear','The Dukes','NOBELIUM','Midnight Blizzard','CozyDuke'],d:'SVR-linked strategic espionage actor.'},
  {c:'RU',n:'Sandworm',a:['APT44','Voodoo Bear','Telebots','Seashell Blizzard','IRON VIKING','Unit 74455'],d:'GRU-linked destructive and disruptive operations actor.'},
  {c:'RU',n:'Turla',a:['Snake','Venomous Bear','Secret Blizzard','KRYPTON'],d:'Russia-linked long-running espionage platform and actor.'},
  {c:'RU',n:'Gamaredon',a:['Primitive Bear','Aqua Blizzard','Armageddon','Shuckworm','UAC-0010'],d:'FSB-linked Ukraine-focused espionage actor.'},
  {c:'RU',n:'Energetic Bear',a:['Dragonfly','Crouching Yeti','Berserk Bear','DYMALLOY'],d:'Russia-linked energy and industrial-control targeting actor.'},
  {c:'RU',n:'COLDRIVER',a:['Callisto Group','Star Blizzard','SEABORGIUM','TA446'],d:'Russia-linked credential phishing and influence-adjacent targeting.'},
  {c:'RU',n:'Cadet Blizzard',a:['Ember Bear','DEV-0586','UAC-0056','Lorec53'],d:'Russia-linked destructive/disruptive actor observed in Ukraine-related activity.'},
  {c:'RU',n:'BlueDelta',a:['APT28 infrastructure clusters','TAG-53'],d:'Russia-linked infrastructure/activity cluster in defense and policy targeting.'},
  {c:'RU',n:'BlueBravo',a:['Cloaked Ursa','Nobelium overlap'],d:'Russia-linked espionage cluster often associated with SVR-style objectives.'},
  {c:'RU',n:'BlueCharlie',a:['Calisto-related infrastructure'],d:'Russia-linked credential harvesting and infrastructure cluster.'},
  {c:'RU',n:'Winter Vivern',a:['TA473','UAC-0114'],d:'Russia/Belarus-aligned espionage cluster targeting governments and NGOs.'},
  {c:'RU',n:'XDSpy',a:['XDSpy Team'],d:'Eastern Europe/Russia-linked espionage actor.'},
  {c:'RU',n:'UNC2589',a:['UAC-0056 overlap'],d:'Russia-linked Ukraine-focused phishing/espionage cluster.'},
  {c:'RU',n:'NoName057(16)',a:['NoName05716'],d:'Russia-aligned hacktivist/DDoS persona; not a classic APT but relevant to IW/cyber effects.'},
  {c:'RU',n:'Killnet',a:['KillNet'],d:'Russia-aligned hacktivist/DDoS ecosystem; relevant to cyber-enabled influence.'},

  {c:'IR',n:'APT33',a:['Elfin','Refined Kitten','Magnallium','Peach Sandstorm','Holmium'],d:'Iran-linked aerospace, energy, and regional espionage/destructive-adjacent actor.'},
  {c:'IR',n:'APT34',a:['OilRig','Helix Kitten','Hazel Sandstorm','Cobalt Gypsy','Crambus'],d:'Iran-linked regional espionage actor targeting government, energy, telecom.'},
  {c:'IR',n:'APT35',a:['Charming Kitten','Phosphorus','Mint Sandstorm','TA453','Newscaster'],d:'Iran-linked phishing/espionage actor targeting policy, academia, dissidents.'},
  {c:'IR',n:'APT39',a:['Chafer','Remix Kitten','Burgundy Sandstorm','ITG07'],d:'Iran-linked travel, telecom, government, and personal-data targeting actor.'},
  {c:'IR',n:'APT42',a:['Charming Kitten overlap','Mint Sandstorm overlap'],d:'Iran-linked credential harvesting and surveillance-focused actor.'},
  {c:'IR',n:'MuddyWater',a:['Static Kitten','Seedworm','Mango Sandstorm','TEMP.Zagros','Mercury'],d:'Iran MOIS-linked espionage actor active across Middle East and beyond.'},
  {c:'IR',n:'Pioneer Kitten',a:['Fox Kitten','Parisite','UNC757','Rubidium'],d:'Iran-linked initial access/ransomware-enablement reporting.'},
  {c:'IR',n:'Imperial Kitten',a:['Tortoiseshell','Crimson Sandstorm','TA456','Houseblend'],d:'Iran-linked actor targeting defense, IT, and regional interests.'},
  {c:'IR',n:'CopyKittens',a:['Slayer Kitten'],d:'Iran-linked espionage actor historically targeting Israel and regional entities.'},
  {c:'IR',n:'Ajax Security Team',a:['Operation Saffron Rose'],d:'Iran-linked group associated with early social engineering and malware campaigns.'},
  {c:'IR',n:'Rocket Kitten',a:['Operation Woolen-Goldfish'],d:'Iran-linked spear-phishing actor targeting policy, defense, and dissidents.'},
  {c:'IR',n:'Agrius',a:['Pink Sandstorm','Americium','BlackShadow','Deadwood'],d:'Iran-linked destructive/wiper and ransomware-masked operations.'},
  {c:'IR',n:'Cobalt Mirage',a:['TunnelVision','UNC2448 overlap'],d:'Iran-linked intrusion/ransomware and espionage activity cluster.'},
  {c:'IR',n:'UNC1860',a:['Mandiant UNC1860'],d:'Iran-linked initial access and persistence actor reported against Middle East sectors.'},
  {c:'IR',n:'UNC1549',a:['Smoke Sandstorm','Tortoiseshell overlap'],d:'Iran-linked espionage actor targeting aerospace, defense, and technology.'},
  {c:'IR',n:'Void Manticore',a:['Storm-0842'],d:'Iran-linked destructive activity cluster reported with Israel-focused operations.'},
  {c:'IR',n:'Moses Staff',a:['Marigold Sandstorm'],d:'Iran-linked hack-and-leak/destructive persona.'},
  {c:'IR',n:'CyberAv3ngers',a:['Cyber Avengers'],d:'IRGC-affiliated hacktivist persona targeting OT/ICS and Israeli-linked entities.'},
  {c:'IR',n:'Shamoon Group',a:['Cutting Sword of Justice'],d:'Iran-linked destructive Shamoon/Disttrack wiper operations.'},

  {c:'KP',n:'Lazarus Group',a:['Hidden Cobra','Diamond Sleet','ZINC','Labyrinth Chollima','Guardians of Peace'],d:'DPRK umbrella actor spanning espionage, destructive operations, and theft.'},
  {c:'KP',n:'APT38',a:['Bluenoroff','Stardust Chollima','Sapphire Sleet','BeagleBoyz'],d:'DPRK financially motivated/crypto and bank-heist operations.'},
  {c:'KP',n:'APT37',a:['ScarCruft','Reaper','InkySquid','Ricochet Chollima','Group123'],d:'DPRK espionage group targeting South Korea, Japan, and regional interests.'},
  {c:'KP',n:'Kimsuky',a:['APT43','Emerald Sleet','Thallium','Velvet Chollima','Black Banshee'],d:'DPRK strategic intelligence collection actor.'},
  {c:'KP',n:'Andariel',a:['Onyx Sleet','Silent Chollima','Stonefly'],d:'DPRK actor targeting defense, industry, and financial objectives.'},
  {c:'KP',n:'Citrine Sleet',a:['AppleJeus','Labyrinth Chollima overlap'],d:'DPRK actor associated with crypto targeting and related activity.'},
  {c:'KP',n:'Moonstone Sleet',a:['Storm-1789'],d:'DPRK cluster using custom ransomware, fake companies, and software supply-chain lures.'},
  {c:'KP',n:'Jade Sleet',a:['TraderTraitor','UNC4899'],d:'DPRK crypto and blockchain targeting cluster.'},
  {c:'KP',n:'Ruby Sleet',a:['Cerium','Velvet Chollima overlap'],d:'DPRK actor focused on aerospace/defense and strategic intelligence.'},
  {c:'KP',n:'Coral Sleet',a:['Storm-1877'],d:'DPRK actor tracked in Microsoft activity-group naming.'},
  {c:'KP',n:'Opal Sleet',a:['Konni','TA406 overlap'],d:'DPRK-linked espionage cluster in some vendor reporting.'},
  {c:'KP',n:'TEMP.Hermit',a:['Lazarus overlap'],d:'Historic DPRK activity label used by FireEye/Mandiant reporting.'}
];
let actors=[...FALLBACK_ACTORS.map(x=>({...x,source:'Curated fallback'}))];
let news=[];
let liveActorLoaded=false;
let prebuiltMeta=null;
let dataLoading=true;
const byId=id=>document.getElementById(id);
function relTime(iso){
  const t=Date.parse(iso); if(isNaN(t)) return '';
  const s=Math.max(0,(Date.now()-t)/1000);
  if(s<90) return 'just now';
  const m=s/60; if(m<60) return Math.round(m)+' min ago';
  const h=m/60; if(h<48) return Math.round(h)+' hr ago';
  return Math.round(h/24)+' days ago';
}
function renderFeedHealth(){
  const el=byId('feedHealth'); if(!el) return;
  const show=byId('newsSource').value==='prebuilt'&&prebuiltMeta;
  if(!show){ el.innerHTML=''; return; }
  const st=prebuiltMeta.status||[]; const failed=st.filter(f=>!f.ok); const okN=st.length-failed.length;
  let html=prebuiltMeta.generated?`Prebuilt feed updated ${escapeHtml(relTime(prebuiltMeta.generated))}`:'Prebuilt feed not generated yet';
  if(st.length) html+=` · ${okN}/${st.length} feeds ok`;
  if(failed.length) html+=` · <span style="color:var(--warn)" title="${escapeHtml(failed.map(f=>f.name+(f.error?' ('+f.error+')':'')).join('\n'))}">⚠ ${failed.length} failed: ${escapeHtml(failed.map(f=>f.name).join(', '))}</span>`;
  el.innerHTML=html;
}
function setStatus(s){byId('status').textContent=s;}
function cleanText(s){return (s||'').replace(/<[^>]*>/g,'').replace(/\s+/g,' ').trim();}
function norm(s){return (s||'').toLowerCase().replace(/[^a-z0-9]+/g,'');}
function inferCountry(meta={}){
  const candidates=[];
  const add=v=>{ if(!v)return; Array.isArray(v)?v.forEach(add):candidates.push(String(v)); };
  add(meta.country); add(meta['cfr-suspected-state-sponsor']); add(meta['microsoft-origin-threat']); add(meta.sector);
  const t=candidates.join(' ').toLowerCase();
  if(/\bcn\b|china|chinese|prc/.test(t)) return 'CN';
  if(/\bru\b|russia|russian/.test(t)) return 'RU';
  if(/\bir\b|iran|iranian/.test(t)) return 'IR';
  if(/\bkp\b|north korea|dprk|korea \(democratic/.test(t)) return 'KP';
  return null;
}
function addActorFromCluster(cluster, source){
  const meta=cluster.meta||{}; const c=inferCountry(meta); if(!c) return null;
  const synonyms=[...(meta.synonyms||[]), ...(meta['associated-groups']||[])].filter(Boolean);
  return {c,n:cluster.value||cluster.name||'Unknown',a:[...new Set(synonyms)],d:cleanText(cluster.description||''),source,refs:meta.refs||[]};
}
async function refreshActors(){
  setStatus('Loading actor catalogs…');
  const urls=[
    ['MISP Threat Actor','https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json'],
    ['Microsoft Activity Group','https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/microsoft-activity-group.json']
  ];
  const loaded=[];
  for(const [label,url] of urls){
    try{ const r=await fetchT(url,45000); if(!r.ok) throw new Error(r.status+' '+r.statusText); const j=await r.json(); (j.values||[]).forEach(v=>{ const a=addActorFromCluster(v,label); if(a) loaded.push(a); }); }
    catch(e){ console.warn('Actor source failed',label,e); }
  }
  if(loaded.length){
    const merged=[...FALLBACK_ACTORS.map(x=>({...x,source:'Curated fallback'})),...loaded];
    const seen=new Map();
    for(const a of merged){ const key=a.c+'|'+norm(a.n); if(!seen.has(key)){seen.set(key,a)} else { const cur=seen.get(key); cur.a=[...new Set([...(cur.a||[]),...(a.a||[])])]; cur.d=cur.d||a.d; cur.source=cur.source.includes(a.source)?cur.source:cur.source+' + '+a.source; cur.refs=[...new Set([...(cur.refs||[]),...(a.refs||[])])]; }}
    actors=[...seen.values()].sort((x,y)=>x.c.localeCompare(y.c)||x.n.localeCompare(y.n)); actorIndex=null;
    liveActorLoaded=true; setStatus(`Loaded ${actors.length} actors (${loaded.length} live records merged)`);
  } else { liveActorLoaded=false; setStatus('Live actor sources unavailable; using curated fallback list'); }
  renderAll();
}
function actorMatches(a){
  const cf=byId('countryFilter').value, q=byId('search').value.toLowerCase();
  if(cf!=='ALL'&&a.c!==cf)return false;
  const blob=[a.n,(a.a||[]).join(' '),a.d,a.source,COUNTRIES[a.c]?.name].join(' ').toLowerCase();
  return !q||blob.includes(q);
}
function renderActors(){
  const tbody=byId('actorTable').querySelector('tbody'); tbody.innerHTML='';
  const list=actors.filter(actorMatches);
  for(const a of list){
    const tr=document.createElement('tr');
    const refs=(a.refs||[]).map(safeUrl).filter(Boolean).slice(0,2).map((r,i)=>`<a href="${r}" target="_blank" rel="noreferrer">ref ${i+1}</a>`).join(' ');
    const cveN=cvesForActor(a).length; const cveChip=cveN?` <span class="tag high" title="Known exploited CVEs">${cveN} CVE${cveN>1?'s':''}</span>`:'';
    tr.innerHTML=`<td><span class="pill ${a.c}">${COUNTRIES[a.c].flag} ${COUNTRIES[a.c].name}</span></td><td><div class="actor-name">${escapeHtml(a.n)}${cveChip}</div></td><td class="aliases">${(a.a||[]).slice(0,18).map(escapeHtml).join(', ')||'<span class="muted">—</span>'}</td><td>${escapeHtml((a.d||'').slice(0,360))}${a.d&&a.d.length>360?'…':''}</td><td>${escapeHtml(a.source||'')}${refs?'<br>'+refs:''}</td>`;
    tr.className='clickable'; tr.title='Open name crosswalk'; tr.tabIndex=0; tr.setAttribute('role','button'); tr.addEventListener('click',()=>openCrosswalk(a)); tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openCrosswalk(a);}});
    tbody.appendChild(tr);
  }
}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
// External URLs (feed items, MISP refs) go into href attributes: allow only http(s) and escape quotes.
function safeUrl(u){const s=String(u||'').trim();return /^https?:\/\//i.test(s)?escapeHtml(s):'';}
function renderCards(){
  const wrap=byId('countryCards'); wrap.innerHTML='';
  for(const code of Object.keys(COUNTRIES)){
    const c=COUNTRIES[code]; const ac=actors.filter(a=>a.c===code).length; const nc=new Set(news.filter(n=>n.c===code).map(n=>n.url||n.title)).size;
    const div=document.createElement('div'); div.className='card country-card'; div.dataset.country=code;
    const reportValue=dataLoading?'…':nc;
    const actorValue=dataLoading?'…':ac;
    const catalogValue=dataLoading?'Loading':(liveActorLoaded?'Live':'Fallback');
    div.innerHTML=`<div class="country-head"><span class="flag">${c.flag}</span><span class="country-name">${c.name}</span><span class="pill ${code}">${c.short}</span></div><div class="stat-row"><div class="stat"><b>${actorValue}</b><span>actors</span></div><div class="stat"><b>${reportValue}</b><span>matching reports</span></div><div class="stat"><b>${catalogValue}</b><span>actor catalog</span></div></div><div class="focus">${c.focus}</div>`;
    wrap.appendChild(div);
  }
}
function renderSnapshot(){
  const wrap=byId('snapshotList'); wrap.innerHTML='';
  for(const code of Object.keys(COUNTRIES)){
    const c=COUNTRIES[code];
    const candidates=news.filter(n=>n.c===code&&n.relationship==='sponsor').map(n=>({n,priority:priorityFor(n)})).sort((a,b)=>b.priority.score-a.priority.score||String(b.n.seendate||'').localeCompare(String(a.n.seendate||'')));
    const top=candidates[0];
    const div=document.createElement('div'); div.className='small-card';
    if(dataLoading) div.innerHTML=`<h3>${c.flag} ${c.name}</h3><p class="section-note">Loading current reporting…</p>`;
    else if(top) div.innerHTML=`<h3>${c.flag} ${c.name}</h3><a class="news-title compact-title" href="${safeUrl(top.n.url)||'#'}" target="_blank" rel="noreferrer">${escapeHtml(top.n.title)}</a><p class="section-note">Priority ${top.priority.score}/100 · ${escapeHtml(top.priority.reasons.join(' · '))}</p>`;
    else div.innerHTML=`<h3>${c.flag} ${c.name}</h3><p><strong>No explicitly attributed reporting matched the selected window.</strong></p><p class="section-note">This is a collection result, not an assessment that no activity occurred. Standing priority: ${escapeHtml(c.focus)}</p>`;
    wrap.appendChild(div);
  }
}
function renderChanges(){
  const wrap=byId('changeList'); if(!wrap) return;
  if(dataLoading){ wrap.innerHTML='<div class="small-card"><p class="section-note">Loading and scoring current collection…</p></div>'; return; }
  const seen=new Set();
  const changes=news.map(n=>({n,priority:priorityFor(n)}))
    .sort((a,b)=>b.priority.score-a.priority.score||String(b.n.seendate||'').localeCompare(String(a.n.seendate||'')))
    .filter(({n})=>{ const key=n.url||n.title; if(seen.has(key)) return false; seen.add(key); return true; }).slice(0,4);
  if(!changes.length){ wrap.innerHTML='<div class="small-card"><p><strong>No reportable changes matched this window.</strong></p><p class="section-note">Try a longer lookback or another source. This describes collection, not adversary inactivity.</p></div>'; return; }
  wrap.innerHTML=changes.map(({n,priority})=>`<div class="small-card"><div class="news-meta"><span class="tag ${priority.cssClass}">${priority.level} · ${priority.score}/100</span><span>${COUNTRIES[n.c]?.flag||''} ${escapeHtml(relationshipLabel(n.relationship))}</span></div><a class="news-title compact-title" href="${safeUrl(n.url)||'#'}" target="_blank" rel="noreferrer">${escapeHtml(n.title)}</a><p class="score-reasons"><strong>Why:</strong> ${escapeHtml(priority.reasons.join(' · '))}</p></div>`).join('');
}
function priorityFor(article){
  return scoreArticle(article,{kevSet:new Set(kev.map(v=>v.cve))});
}
function classifiedCopies(base,title=base.title||'',summary=base.summary||''){
  const result=classifyRelationships(title,summary);
  return result.relationships.map(rel=>({...base,c:rel.country,relationship:rel.relationship,confidence:rel.confidence,evidence:rel.evidence,activityType:result.activityType,summary}));
}
function normalizeNewsItem(item){
  if(item.relationship&&item.confidence) return item;
  const inferred=classifiedCopies(item,item.title,item.summary||'').find(candidate=>candidate.c===item.c);
  return inferred||{...item,relationship:'context',confidence:'low',activityType:'cyber-activity',evidence:'Legacy feed item; relationship not yet classified.'};
}
function queryFor(code){
  const cyber='(cyber OR hack OR hacker OR malware OR ransomware OR espionage OR "zero day" OR vulnerability OR "critical infrastructure" OR telecom OR wiper OR "information warfare" OR disinformation OR propaganda OR "influence operation" OR botnet OR "hack and leak")';
  const country='('+COUNTRIES[code].terms.map(t=>t.includes(' ')?`"${t}"`:t).join(' OR ')+')';
  return `${cyber} ${country}`;
}
async function refreshNewsGdelt(){
  dataLoading=true; renderCards(); renderSnapshot(); renderNews();
  setStatus('Loading live news…');
  const days=byId('timespan').value; const all=[];
  for(const code of Object.keys(COUNTRIES)){
    const q=queryFor(code);
    const url=`https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=ArtList&format=json&maxrecords=25&sort=HybridRel&timespan=${days}d`;
    try{
      const r=await fetchT(url); if(!r.ok) throw new Error(r.status+' '+r.statusText); const j=await r.json();
      for(const x of (j.articles||[])) all.push(...classifiedCopies({...x,sourceCountry:x.sourcecountry||x.domain||'GDELT'},x.title||'',x.summary||''));
    }catch(e){ console.warn('News source failed',code,e); }
  }
  const seen=new Set(); news=[];
  for(const n of all){ const key=norm(n.title||'')||n.url; if(!seen.has(key)){seen.add(key); news.push(n);} }
  news.sort((a,b)=>String(b.seendate||'').localeCompare(String(a.seendate||'')));
  dataLoading=false;
  if(news.length) setStatus(`Loaded ${news.length} live news items`); else setStatus('No live news returned; check browser internet/CORS settings');
  renderAll();
}
// Dispatch to the selected news source.
function refreshNews(){
  const src=byId('newsSource').value;
  if(src==='prebuilt') return fetchPrebuilt();
  if(src==='feeds') return fetchCyberFeeds();
  if(src==='gnews') return fetchGoogleNews();
  return refreshNewsGdelt();
}
// Load the hourly, server-collected feed (news.json) — same-origin, no CORS proxy.
async function fetchPrebuilt(){
  dataLoading=true; renderCards(); renderSnapshot(); renderNews();
  setStatus('Loading prebuilt feed…');
  try{
    const r=await fetch('data/news.json?_='+Date.now(),{cache:'no-store'});
    if(!r.ok) throw new Error(r.status+' '+r.statusText);
    const data=await r.json();
    prebuiltMeta={generated:data.generated||null,feeds:data.feeds||0,status:Array.isArray(data.feedsStatus)?data.feedsStatus:[]};
    const days=parseInt(byId('timespan').value,10)||14; const cutoff=Date.now()-days*86400000;
    news=(data.items||[]).map(normalizeNewsItem).filter(n=>{
      if(!COUNTRIES[n.c]) return false;
      const s=String(n.seendate||''); if(s.length<8) return true;
      const dt=new Date(`${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)||'00'}:${s.slice(10,12)||'00'}:${s.slice(12,14)||'00'}Z`);
      return isNaN(dt)||dt.getTime()>=cutoff;
    });
    news.sort((a,b)=>String(b.seendate||'').localeCompare(String(a.seendate||'')));
    const when=data.generated?new Date(data.generated).toLocaleString():null;
    if(!when) setStatus('Prebuilt feed not generated yet — run the “Sync news feed” workflow (Actions → Run workflow), then refresh.');
    else if(!news.length) setStatus(`Prebuilt feed has no Big 4 items in the last ${days} days (updated ${when}) — try a longer lookback.`);
    else setStatus(`Loaded ${news.length} items from the prebuilt hourly feed (updated ${when})`);
  }catch(e){
    news=[]; prebuiltMeta=null; setStatus('No prebuilt feed found (news.json) — it is generated hourly by the Sync news feed workflow, or pick a live source.');
  }
  dataLoading=false;
  renderAll();
}
// Cross-origin fetch with a hard timeout so a hung proxy/API can't stall the UI forever.
function fetchT(url,ms=20000){
  const c=new AbortController(); const t=setTimeout(()=>c.abort(),ms);
  return fetch(url,{cache:'no-store',signal:c.signal}).finally(()=>clearTimeout(t));
}
async function fetchViaProxy(url){
  let lastErr;
  for(const proxy of CORS_PROXIES){
    try{ const r=await fetchT(proxy(url)); if(!r.ok) throw new Error(r.status+' '+r.statusText); return await r.text(); }
    catch(e){ lastErr=e; }
  }
  throw lastErr||new Error('All CORS proxies failed');
}
// Run an async worker over items with limited concurrency (kind to the public CORS proxy).
async function runPool(items,limit,worker){
  const queue=items.slice();
  const next=async()=>{ while(queue.length) await worker(queue.shift()); };
  await Promise.all(Array.from({length:Math.min(limit,items.length)||1},next));
}
function parseFeed(xmlText){
  const doc=new DOMParser().parseFromString(xmlText,'text/xml');
  if(doc.querySelector('parsererror')) return [];
  const nodes=[...doc.querySelectorAll('item'),...doc.querySelectorAll('entry')];
  const out=[];
  for(const node of nodes){
    const txt=tag=>node.querySelector(tag)?.textContent?.trim()||'';
    const title=txt('title');
    // RSS puts the URL in <link> text; Atom uses <link rel="alternate" href="…"> among several link rels.
    const links=[...node.querySelectorAll('link')];
    const link=links.find(l=>l.textContent.trim())?.textContent.trim()
      || links.find(l=>l.getAttribute('rel')==='alternate')?.getAttribute('href')
      || links.find(l=>l.getAttribute('href'))?.getAttribute('href')||'';
    const desc=txt('description')||txt('summary')||txt('content');
    const dateStr=txt('pubDate')||txt('updated')||txt('published')||txt('date');
    if(title&&link) out.push({title,link,desc,dateStr});
  }
  return out;
}
async function fetchCyberFeeds(){
  dataLoading=true; renderCards(); renderSnapshot(); renderNews();
  setStatus('Reaching out to cyber news sources…');
  const days=parseInt(byId('timespan').value,10)||14; const cutoff=Date.now()-days*86400000;
  const collected=[]; let okFeeds=0;
  await runPool(CYBER_FEEDS,5,async f=>{
    try{
      const items=parseFeed(await fetchViaProxy(f.url)); okFeeds++;
      for(const it of items){
        const dt=it.dateStr?new Date(it.dateStr):null; const valid=dt&&!isNaN(dt);
        if(valid&&dt.getTime()<cutoff) continue;
        let domain=''; try{ domain=new URL(it.link).hostname.replace(/^www\./,''); }catch(e){}
        const seendate=valid?dt.toISOString().replace(/[-:T.Z]/g,'').slice(0,14):'';
        collected.push(...classifiedCopies({title:it.title,url:it.link,domain,seendate,sourceCountry:f.name},it.title,it.desc));
      }
    }catch(e){ console.warn('Feed failed',f.name,e); }
  });
  const seen=new Set(); news=[];
  for(const n of collected){ const key=n.c+'|'+norm(n.title); if(!seen.has(key)){seen.add(key); news.push(n);} }
  news.sort((a,b)=>String(b.seendate||'').localeCompare(String(a.seendate||'')));
  dataLoading=false;
  if(news.length) setStatus(`Loaded ${news.length} Big 4-relevant items from ${okFeeds}/${CYBER_FEEDS.length} cyber news feeds`);
  else if(okFeeds) setStatus(`Reached ${okFeeds} feed(s) but found no Big 4-relevant items in the last ${days} days`);
  else setStatus('Could not reach cyber news feeds — the CORS proxy may be unavailable. Try the GDELT source instead.');
  renderAll();
}
async function fetchGoogleNews(){
  dataLoading=true; renderCards(); renderSnapshot(); renderNews();
  setStatus('Searching Google News…');
  const days=parseInt(byId('timespan').value,10)||14;
  const collected=[]; let okQ=0;
  await Promise.all(Object.keys(COUNTRIES).map(async code=>{
    const q=`${queryFor(code)} when:${days}d`;
    const url=`https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en-US&gl=US&ceid=US:en`;
    try{
      const items=parseFeed(await fetchViaProxy(url)); okQ++;
      for(const it of items){
        let outlet='', title=it.title; const i=title.lastIndexOf(' - ');
        if(i>0){ outlet=title.slice(i+3).trim(); title=title.slice(0,i).trim(); }
        const dt=it.dateStr?new Date(it.dateStr):null; const valid=dt&&!isNaN(dt);
        const seendate=valid?dt.toISOString().replace(/[-:T.Z]/g,'').slice(0,14):'';
        collected.push(...classifiedCopies({title,url:it.link,domain:outlet||'news.google.com',seendate,sourceCountry:'Google News'},title,it.desc));
      }
    }catch(e){ console.warn('Google News query failed',code,e); }
  }));
  const seen=new Set(); news=[];
  for(const n of collected){ const key=n.c+'|'+norm(n.title); if(!seen.has(key)){seen.add(key); news.push(n);} }
  news.sort((a,b)=>String(b.seendate||'').localeCompare(String(a.seendate||'')));
  dataLoading=false;
  if(news.length) setStatus(`Loaded ${news.length} Google News items across ${okQ}/4 country searches`);
  else if(okQ) setStatus('Google News returned no items — try a longer lookback or another source');
  else setStatus('Could not reach Google News — the CORS proxy may be unavailable. Try another source.');
  renderAll();
}
function newsMatches(n){
  const cf=byId('countryFilter').value, q=byId('search').value.toLowerCase();
  if(cf!=='ALL'&&n.c!==cf)return false;
  const blob=[n.title,n.summary,n.domain,n.sourceCountry,COUNTRIES[n.c]?.name,n.url].join(' ').toLowerCase();
  return !q||blob.includes(q);
}
// Detect APT/actor names mentioned in an article title (against the loaded catalog + aliases).
let actorIndex=null;
const ACTOR_STOP=new Set(['apt','axiom','platinum','silence','machete','confucius','windigo','thrip','sowbug','moafee','group5','mercury','patchwork','elderwood']);
function buildActorIndex(){
  const map=new Map(); const toks=[];
  for(const a of actors){
    for(const nm of [a.n,...(a.a||[])]){
      const t=String(nm||'').trim(); if(t.length<4) continue;
      const key=t.toLowerCase(); if(ACTOR_STOP.has(key)) continue;
      if(!map.has(key)){ map.set(key,a); toks.push(t); }
    }
  }
  actorIndex={map,rx:toks.length?new RegExp('\\b('+toks.map(escapeRegex).join('|')+')\\b','gi'):null};
}
function actorsInText(text){
  if(!actorIndex) buildActorIndex();
  const rx=actorIndex.rx; if(!rx||!text) return [];
  rx.lastIndex=0; const seen=new Map(); let m;
  while((m=rx.exec(text))){ const a=actorIndex.map.get(m[1].toLowerCase()); if(a&&!seen.has(a.n)) seen.set(a.n,a); }
  return [...seen.values()];
}
function renderNews(){
  const wrap=byId('newsGrid'); wrap.innerHTML='';
  const matched=news.filter(newsMatches).map(n=>({n,priority:priorityFor(n)}));
  const sort=byId('newsSort')?.value||'newest';
  matched.sort((a,b)=>sort==='priority'
    ? b.priority.score-a.priority.score||String(b.n.seendate||'').localeCompare(String(a.n.seendate||''))
    : String(b.n.seendate||'').localeCompare(String(a.n.seendate||''))||b.priority.score-a.priority.score);
  if(!matched.length){
    const title=dataLoading?'Loading current reporting…':'No matching reports in the selected period.';
    const note=dataLoading?'The dashboard is loading and classifying the latest feed.':'This is a collection result, not evidence that no activity occurred. Try a longer lookback, another source, or broader filters.';
    wrap.innerHTML=`<div class="news-card empty-state" role="status"><div class="news-title">${title}</div><p class="section-note">${note}</p></div>`; return;
  }
  // Group by article URL so a story tagged to multiple countries shows one card with multiple flags.
  const groups=[]; const byKey=new Map();
  for(const scored of matched){ const n=scored.n;
    const key=n.url||n.title; let g=byKey.get(key);
    if(!g){ g={item:n,priority:scored.priority,relationships:[]}; groups.push(g); byKey.set(key,g); }
    if(COUNTRIES[n.c]&&!g.relationships.some(rel=>rel.c===n.c)) g.relationships.push({c:n.c,relationship:n.relationship||'context',confidence:n.confidence||'low'});
  }
  for(const g of groups.slice(0,60)){
    const n=g.item; const priority=g.priority; const date=n.seendate?String(n.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/, '$1-$2-$3'):'Recent';
    const pills=g.relationships.map(rel=>`<span class="pill ${rel.c}" title="${escapeHtml(rel.confidence)} confidence">${COUNTRIES[rel.c].flag} ${COUNTRIES[rel.c].name} · ${escapeHtml(relationshipLabel(rel.relationship))}</span>`).join('');
    const div=document.createElement('div'); div.className='news-card';
    div.innerHTML=`<div class="news-meta">${pills}<span>${escapeHtml(date)}</span><span>${escapeHtml(n.domain||'')}</span></div><a class="news-title" href="${safeUrl(n.url)||'#'}" target="_blank" rel="noreferrer">${escapeHtml(n.title||'Untitled')}</a><div class="tagbar"><span class="tag ${priority.cssClass}" title="${escapeHtml(priority.reasons.join('; '))}">${priority.level} · ${priority.score}/100</span><span class="tag">${escapeHtml(n.activityType||'cyber-activity')}</span><span class="tag">${escapeHtml(n.sourceCountry||'source')}</span></div><p class="score-reasons"><strong>Why:</strong> ${escapeHtml(priority.reasons.join(' · '))}</p>`;
    const acts=actorsInText([n.title,n.summary].filter(Boolean).join(' '));
    if(acts.length){
      const bar=document.createElement('div'); bar.className='actor-tags';
      const lbl=document.createElement('span'); lbl.className='at-label'; lbl.textContent='Actors:'; bar.appendChild(lbl);
      for(const a of acts){ const s=document.createElement('span'); s.className='at-chip'; s.textContent=a.n; s.title='Open name crosswalk'; s.addEventListener('click',ev=>{ ev.stopPropagation(); openCrosswalk(a); }); bar.appendChild(s); }
      div.appendChild(bar);
    }
    const hit=watchHit(n);
    if(hit){ div.classList.add('watch-hit'); const wb=document.createElement('span'); wb.className='tag high'; wb.textContent='WATCH: '+hit; div.querySelector('.tagbar').appendChild(wb); }
    const row=document.createElement('div'); row.style.cssText='display:flex;gap:6px;flex-wrap:wrap';
    const dm=document.createElement('button'); dm.className='dm-btn'; dm.textContent='◆ Diamond'; dm.title='Map this story to the Diamond Model';
    dm.addEventListener('click',ev=>{ ev.stopPropagation(); mapToDiamond(n); });
    const pk=n.url||n.title; const pin=document.createElement('button'); pin.className='pin-btn'+(pins[pk]?' pinned':''); pin.textContent=pins[pk]?'📌 Pinned':'📌 Pin'; pin.title='Pin to the Analyst Workbench';
    pin.addEventListener('click',ev=>{ ev.stopPropagation(); togglePin(n); });
    row.appendChild(dm); row.appendChild(pin); div.appendChild(row);
    wrap.appendChild(div);
  }
}
// CISA KEV (Known Exploited Vulnerabilities) — general, not country-attributed.
// ---- MITRE ATT&CK enrichment (data/attack.json, produced daily by fetch-enrichment.mjs) ----
let ATTACK={groups:[]}; let attackIndex=null;
async function loadAttack(){
  try{ const r=await fetch('data/attack.json?_='+Date.now(),{cache:'no-store'}); if(r.ok){ const d=await r.json(); if(d&&Array.isArray(d.groups)) ATTACK=d; } }catch(e){}
  attackIndex=null;
}
function attackForActor(actor){
  if(!attackIndex){
    attackIndex=new Map();
    for(const g of (ATTACK.groups||[])) for(const nm of [g.gid,g.name,...(g.aliases||[])]) if(nm&&!attackIndex.has(norm(nm))) attackIndex.set(norm(nm),g);
  }
  for(const nm of [actor.n,...(actor.a||[])]){ const g=attackIndex.get(norm(nm)); if(g) return g; }
  return null;
}
// Build an ATT&CK Navigator layer for a group's techniques and download it.
function downloadNavigatorLayer(group,actorName){
  const layer={
    name:`${actorName||group.name} — known techniques`,
    versions:{attack:String(ATTACK.version||''),navigator:'5.1.0',layer:'4.5'},
    domain:'enterprise-attack',
    description:`Techniques attributed to ${group.gid} (${group.name}) in MITRE ATT&CK. Generated by the Big 4 Threat Dashboard.`,
    techniques:(group.techniques||[]).map(t=>({techniqueID:t.id,score:1,comment:''})),
    gradient:{colors:['#ffffff','#e05151'],minValue:0,maxValue:1},
  };
  const blob=new Blob([JSON.stringify(layer,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`${group.gid}-navigator-layer.json`; document.body.appendChild(a); a.click();
  setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);
  setStatus(`Navigator layer for ${group.gid} downloaded — load it at mitre-attack.github.io/attack-navigator`);
}
// ---- EPSS scores for KEV CVEs (data/epss.json, daily) ----
let EPSS={scores:{}};
async function loadEpss(){
  try{ const r=await fetch('data/epss.json?_='+Date.now(),{cache:'no-store'}); if(r.ok){ const d=await r.json(); if(d&&d.scores) EPSS=d; } }catch(e){}
  renderKev();
}
// ---- IOC extraction (kept in sync with scripts/lib.mjs extractIocs/defang) ----
function extractIocs(text){
  const t=String(text||''); const uniq=a=>[...new Set(a)];
  const sha256=uniq(t.match(/\b[a-f0-9]{64}\b/gi)||[]);
  const sha1=uniq((t.match(/\b[a-f0-9]{40}\b/gi)||[]).filter(h=>!sha256.some(s=>s.includes(h))));
  const md5=uniq((t.match(/\b[a-f0-9]{32}\b/gi)||[]).filter(h=>!sha256.concat(sha1).some(s=>s.includes(h))));
  const ips=uniq((t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]).filter(ip=>ip.split('.').every(o=>+o<=255)));
  const cves=uniq((t.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()));
  const defanged=uniq([...(t.match(/\bhxxps?:\/\/[^\s"'<>]+/gi)||[]),...(t.match(/\b(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,}\b/gi)||[]).filter(d=>d.includes('[.]'))]);
  return {sha256,sha1,md5,ips,cves,defanged};
}
function defang(ioc){ let s=String(ioc).replace(/^http(s?):\/\//i,'hxxp$1://'); if(!s.includes('[.]')) s=s.replace(/\./g,'[.]'); return s; }
function iocReport(ioc,context){
  const sec=(label,arr,df)=>arr.length?`## ${label}\n${arr.map(x=>df?defang(x):x).join('\n')}\n`:'';
  return `# IOCs — ${context}\n\n`+sec('SHA256',ioc.sha256)+sec('SHA1',ioc.sha1)+sec('MD5',ioc.md5)
    +sec('IPs (defanged)',ioc.ips,true)+sec('Domains/URLs (defanged, as published)',ioc.defanged)+sec('CVEs',ioc.cves)
    +'\n_Extracted automatically; validate before operational use._\n';
}
function iocCount(ioc){ return ioc.sha256.length+ioc.sha1.length+ioc.md5.length+ioc.ips.length+ioc.cves.length+ioc.defanged.length; }
let kev=[]; let kevMeta=null;
async function loadKev(){
  try{
    const r=await fetch('data/kev.json?_='+Date.now(),{cache:'no-store'});
    if(!r.ok) throw new Error(r.status);
    const d=await r.json();
    kev=Array.isArray(d.items)?d.items:[];
    kevMeta={generated:d.generated||null,total:d.total||0,catalogVersion:d.catalogVersion||null};
  }catch(e){ kev=[]; kevMeta=null; }
  renderKev();
}
function renderKev(){
  const table=byId('kevTable'); if(!table) return;
  const tbody=table.querySelector('tbody'); tbody.innerHTML='';
  const q=byId('search').value.toLowerCase();
  const list=kev.filter(v=>{ if(!q) return true; return [v.cve,v.vendor,v.product,v.name,v.description].join(' ').toLowerCase().includes(q); });
  const hl=byId('kevHealth');
  if(hl) hl.textContent=kevMeta&&kevMeta.generated?`Showing ${list.length} of ${kev.length} recent KEV entries · catalog updated ${relTime(kevMeta.generated)}`:'KEV catalog not generated yet — run the Sync news feed workflow.';
  for(const v of list){
    const tr=document.createElement('tr');
    const rw=v.ransomware?'<span class="tag high">🔒 Known</span>':'<span class="tag">—</span>';
    const es=EPSS.scores&&EPSS.scores[v.cve];
    const epssCell=es?`<span class="mono" title="percentile ${(es.percentile*100).toFixed(0)}%">${(es.epss*100).toFixed(1)}%</span>`:'—';
    tr.innerHTML=`<td class="mono"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve||'')}" target="_blank" rel="noreferrer">${escapeHtml(v.cve||'')}</a></td><td>${escapeHtml(v.vendor||'')}${v.product?' / '+escapeHtml(v.product):''}</td><td>${escapeHtml(v.name||'')}</td><td class="mono">${escapeHtml(v.added||'')}</td><td class="mono">${escapeHtml(v.due||'')}</td><td>${epssCell}</td><td>${rw}</td><td class="kev-actors"></td>`;
    const cell=tr.querySelector('.kev-actors');
    const linked=actorsForCve(v.cve);
    if(!linked.length) cell.textContent='—';
    else for(const l of linked){
      if(l.actor){ const s=document.createElement('span'); s.className='at-chip'; s.textContent=l.label; s.title='Open name crosswalk'; s.addEventListener('click',()=>openCrosswalk(l.actor)); cell.appendChild(s); cell.appendChild(document.createTextNode(' ')); }
      else { const s=document.createElement('span'); s.className='tag'; s.textContent=l.label; cell.appendChild(s); cell.appendChild(document.createTextNode(' ')); }
    }
    tbody.appendChild(tr);
  }
}
// ---- Threat Actor Name Crosswalk: derived live from the loaded catalog + provider conventions ----
let CROSSWALK={providers:[
  {name:'Microsoft',lexicon:'Weather + nation: Typhoon=China, Blizzard=Russia, Sandstorm=Iran, Sleet=North Korea; Storm-#### emerging.',suffixes:['Typhoon','Blizzard','Sandstorm','Sleet','Tempest'],prefixes:['Storm-','DEV-'],names:['Barium','Strontium','Phosphorus','Nobelium','Zinc','Thallium','Hafnium','Mercury']},
  {name:'CrowdStrike',lexicon:'Animal = sponsor: Panda=China, Bear=Russia, Kitten=Iran, Chollima=North Korea, Spider=eCrime.',suffixes:['Panda','Bear','Kitten','Chollima','Spider','Jackal']},
  {name:'Mandiant',lexicon:'APT##, FIN##, UNC####, TEMP.*',regex:['^APT[ -]?\\d+$','^FIN\\d+$','^UNC\\d+','^TEMP\\.']},
  {name:'MITRE ATT&CK',lexicon:'G#### group IDs.',regex:['^G\\d{3,4}$']},
  {name:'Secureworks',lexicon:'BRONZE/IRON/GOLD/COBALT + word; TG-####.',prefixes:['BRONZE ','IRON ','GOLD ','COBALT ','TG-']},
  {name:'Palo Alto Unit 42',lexicon:'Constellations: *Taurus, *Ursa.',suffixes:['Taurus','Ursa']},
  {name:'Recorded Future',lexicon:'TAG-## and color clusters.',prefixes:['TAG-']}
]};
// Known exploited CVEs per actor (curated from public CISA/vendor advisories).
let ACTOR_CVES={actors:[]};
async function loadActorCves(){
  try{ const r=await fetch('data/actor-cves.json?_='+Date.now(),{cache:'no-store'}); if(r.ok){ const d=await r.json(); if(d&&Array.isArray(d.actors)) ACTOR_CVES=d; } }catch(e){}
  renderActors(); renderCrosswalk();
}
// Reverse lookup: which curated actors are known to exploit a given CVE.
function actorsForCve(cveId){
  const out=[];
  for(const e of (ACTOR_CVES.actors||[])){
    if(!(e.cves||[]).some(v=>v.id===cveId)) continue;
    const names=(e.names||[]).map(norm);
    const cat=actors.find(a=>[a.n,...(a.a||[])].some(n=>names.includes(norm(n))));
    out.push({label:(e.names||[])[0]||'?',actor:cat||null});
  }
  return out;
}
function cvesForActor(actor){
  const names=[actor.n,...(actor.a||[])].map(norm); const out=[]; const seen=new Set();
  for(const e of (ACTOR_CVES.actors||[])){
    if((e.names||[]).some(n=>names.includes(norm(n)))){
      for(const v of (e.cves||[])){ if(!seen.has(v.id)){ seen.add(v.id); out.push(v); } }
    }
  }
  return out;
}
async function loadCrosswalk(){
  try{ const r=await fetch('data/crosswalk.json?_='+Date.now(),{cache:'no-store'}); if(r.ok){ const d=await r.json(); if(d&&Array.isArray(d.providers)&&d.providers.length) CROSSWALK=d; } }catch(e){}
  renderCrosswalkLegend(); renderCrosswalk();
}
function classifyProvider(tok){
  const t=String(tok||'').trim(); const tl=t.toLowerCase();
  for(const p of CROSSWALK.providers){
    if(p.regex&&p.regex.some(r=>new RegExp(r,'i').test(t))) return p.name;
    if(p.prefixes&&p.prefixes.some(pre=>tl.startsWith(pre.toLowerCase()))) return p.name;
    if(p.suffixes&&p.suffixes.some(s=>tl===s.toLowerCase()||tl.endsWith(' '+s.toLowerCase()))) return p.name;
    if(p.names&&p.names.some(n=>n.toLowerCase()===tl)) return p.name;
  }
  return 'Common / other';
}
function crosswalkGroups(actor){
  const names=[actor.n,...(actor.a||[])].filter(Boolean);
  const order=[...CROSSWALK.providers.map(p=>p.name),'Common / other'];
  const map=new Map(order.map(o=>[o,[]])); const seen=new Set();
  for(const nm of names){ const key=nm.toLowerCase(); if(seen.has(key))continue; seen.add(key); const prov=classifyProvider(nm); (map.get(prov)||map.get('Common / other')).push(nm); }
  return order.filter(o=>map.get(o).length).map(o=>({provider:o,names:map.get(o),lexicon:(CROSSWALK.providers.find(p=>p.name===o)||{}).lexicon||''}));
}
function openCrosswalk(actor){
  const c=COUNTRIES[actor.c]||{flag:'',name:actor.c}; const groups=crosswalkGroups(actor);
  const rows=groups.map(g=>`<div class="p">${escapeHtml(g.provider)}</div><div>${g.names.map(escapeHtml).join(', ')}${g.lexicon?`<div class="cw-lex">${escapeHtml(g.lexicon)}</div>`:''}</div>`).join('');
  const cves=cvesForActor(actor);
  const cveHtml=cves.length?`<h3 style="margin:16px 0 6px">Known exploited CVEs</h3><div class="cw-prov">`+cves.map(v=>{
      const k=(kev||[]).find(x=>x.cve===v.id); const badge=k?` <span class="tag high">🔒 KEV${k.ransomware?' · ransomware':''}</span>`:'';
      return `<div class="p mono"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}" target="_blank" rel="noreferrer">${escapeHtml(v.id)}</a></div><div>${escapeHtml(v.product||'')}${v.note?' — '+escapeHtml(v.note):''}${badge}</div>`;
    }).join('')+`</div><p class="cw-lex">Curated from public CISA / vendor advisories; not exhaustive. 🔒 KEV = listed in CISA Known Exploited Vulnerabilities.</p>`:'';
  const ag=attackForActor(actor);
  const attackHtml=ag?`<h3 style="margin:16px 0 6px">ATT&CK profile — ${escapeHtml(ag.gid)} (${ag.techniques.length} techniques)</h3>
    <div class="cw-ttp">${ag.techniques.slice(0,14).map(t=>`<span class="tag" title="${escapeHtml(t.name)}"><span class="mono">${escapeHtml(t.id)}</span> ${escapeHtml(t.name)}</span>`).join(' ')}${ag.techniques.length>14?` <span class="cw-lex">+${ag.techniques.length-14} more in the Navigator layer</span>`:''}</div>
    ${ag.software.length?`<p class="cw-lex" style="margin-top:8px"><strong>Known software:</strong> ${ag.software.slice(0,12).map(s=>escapeHtml(s.name)).join(', ')}${ag.software.length>12?` +${ag.software.length-12} more`:''}</p>`:''}`
    :'';
  byId('cwBody').innerHTML=`<div class="cw-head"><span class="flag">${c.flag}</span><span class="cw-name" id="cwTitle">${escapeHtml(actor.n)}</span><span class="pill ${actor.c}">${escapeHtml(c.name)}</span></div>`
    +(actor.d?`<p class="section-note">${escapeHtml(actor.d)}</p>`:'')
    +`<div class="cw-prov">${rows}</div>`
    +cveHtml
    +attackHtml
    +`<div class="cw-actions"><button id="cwNews">📰 News mentioning ${escapeHtml(actor.n)}</button>${ag?`<button id="cwLayer">⬇ Navigator layer (${ag.techniques.length} techniques)</button>`:''}${safeUrl((actor.refs||[])[0])?`<a class="tab" href="${safeUrl(actor.refs[0])}" target="_blank" rel="noreferrer">Source ↗</a>`:''}<a class="tab" href="${ag?`https://attack.mitre.org/groups/${encodeURIComponent(ag.gid)}/`:'https://attack.mitre.org/groups/'}" target="_blank" rel="noreferrer">MITRE ATT&amp;CK ↗</a></div>`;
  byId('cwNews').addEventListener('click',()=>{ byId('search').value=actor.n; byId('countryFilter').value='ALL'; closeCrosswalk(); activate('news'); renderAll(); });
  if(ag) byId('cwLayer').addEventListener('click',()=>downloadNavigatorLayer(ag,actor.n));
  cwPrevFocus=document.activeElement;
  byId('crosswalkModal').classList.remove('hidden');
  byId('cwClose').focus();
}
let cwPrevFocus=null;
function closeCrosswalk(){
  byId('crosswalkModal').classList.add('hidden');
  if(cwPrevFocus&&document.contains(cwPrevFocus)){ try{cwPrevFocus.focus();}catch(e){} }
  cwPrevFocus=null;
}
function renderCrosswalkLegend(){
  const el=byId('crosswalkLegend'); if(!el) return; el.innerHTML='';
  for(const p of CROSSWALK.providers){ const d=document.createElement('div'); d.className='small-card'; d.innerHTML=`<h3>${escapeHtml(p.name)}</h3><p>${escapeHtml(p.lexicon||'')}</p>`; el.appendChild(d); }
}
function renderCrosswalk(){
  const table=byId('crosswalkTable'); if(!table) return; const tbody=table.querySelector('tbody'); tbody.innerHTML='';
  const q=byId('search').value.toLowerCase();
  const list=actors.filter(a=>{ if(!q) return true; return [a.n,(a.a||[]).join(' '),a.d,COUNTRIES[a.c]?.name].join(' ').toLowerCase().includes(q); });
  for(const a of list){
    const provs=crosswalkGroups(a).filter(g=>g.provider!=='Common / other').map(g=>g.provider);
    const c=COUNTRIES[a.c]||{flag:'',name:a.c};
    const tr=document.createElement('tr'); tr.className='clickable'; tr.title='Open name crosswalk';
    tr.innerHTML=`<td><div class="actor-name">${escapeHtml(a.n)}</div></td><td>${provs.map(escapeHtml).join(', ')||'<span class="muted">—</span>'}</td><td><span class="pill ${a.c}">${c.flag} ${escapeHtml(c.name)}</span></td><td class="aliases">${(a.a||[]).slice(0,14).map(escapeHtml).join(', ')||'—'}</td>`;
    tr.tabIndex=0; tr.setAttribute('role','button'); tr.addEventListener('click',()=>openCrosswalk(a)); tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openCrosswalk(a);}});
    tbody.appendChild(tr);
  }
}
// ---- Diamond Model mapper: extract Adversary / Capability / Infrastructure / Victim from a headline ----
let diamondList=[]; let diamondCurrent=null;
const DM_TTP=[['ransomware','Ransomware'],['ransom','Ransomware'],['wiper','Wiper / destructive'],['spear-phishing','Spear-phishing'],['spear phishing','Spear-phishing'],['phishing','Phishing'],['botnet','Botnet'],['backdoor','Backdoor'],['infostealer','Infostealer'],['stealer','Infostealer'],['zero-day','Zero-day'],['0-day','Zero-day'],['supply chain','Supply-chain'],['ddos','DDoS'],['credential','Credential theft'],['espionage','Espionage'],['exploit','Exploitation'],['vulnerability','Vulnerability exploitation'],['malware','Malware'],['trojan','Trojan'],['loader','Loader'],['dropper','Dropper'],['disinformation','Disinformation / IO'],['influence operation','Influence operation'],['hack-and-leak','Hack-and-leak'],['scam','Scam / fraud'],['fraud','Scam / fraud'],['rootkit','Rootkit']];
const DM_INFRA=[['command-and-control','C2 infrastructure'],['command and control','C2 infrastructure'],['bulletproof','Bulletproof hosting'],['botnet','Botnet / proxy network'],['proxy','Proxy / relay'],['vpn','VPN appliance'],['router','Router / edge device'],['edge device','Edge device'],['server','Server(s)'],['domain','Domain(s)'],['hosting','Hosting']];
const DM_VICTIM=[['government','Government'],['defense','Defense'],['military','Military'],['telecom','Telecommunications'],['energy','Energy'],['grid','Power grid'],['healthcare','Healthcare'],['hospital','Healthcare'],['finance','Finance'],['bank','Banking / finance'],['university','Education'],['education','Education'],['critical infrastructure','Critical infrastructure'],['manufacturing','Manufacturing'],['aerospace','Aerospace'],['water','Water utility'],['election','Elections'],['journalist','Journalists / media'],['media','Media'],['cryptocurrency','Cryptocurrency'],['crypto','Cryptocurrency'],['developer','Software developers'],['ics','ICS / OT']];
const DM_GEO=['Ukraine','Ukrainian','Israel','Israeli','Taiwan','United States','NATO','Europe','European','Gulf','South Korea','Japan','Latin America','Czech','Netherlands','Dutch','United Kingdom','Saudi','India'];
function dmScan(text,dict){const t=text.toLowerCase();const out=[];for(const [kw,label] of dict){if(t.includes(kw)&&!out.includes(label))out.push(label);}return out;}
function diamondForArticle(it, extra){
  const text=`${it.title||''} ${it.summary||''} ${extra||''}`.trim();
  const hitActors=actorsInText(text);
  const country=COUNTRIES[it.c]?COUNTRIES[it.c].name:null;
  const adversary=[...new Set([...hitActors.map(a=>a.n), ...(country?[country+' (attributed)']:[])])];
  const cves=[...new Set((text.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(s=>s.toUpperCase()))];
  let actorCves=[]; for(const a of hitActors) actorCves.push(...cvesForActor(a).map(v=>v.id));
  actorCves=[...new Set(actorCves)].filter(id=>!cves.includes(id));
  const capability=[...cves.map(c=>'CVE '+c), ...dmScan(text,DM_TTP)];
  const infrastructure=dmScan(text,DM_INFRA);
  const victim=[...dmScan(text,DM_VICTIM), ...DM_GEO.filter(g=>new RegExp('\\b'+escapeRegex(g)+'\\b','i').test(text))];
  return {adversary,capability,infrastructure,victim,actorCves,firstActor:hitActors[0]||null};
}
function renderDiamondOptions(){
  const sel=byId('diamondSelect'); if(!sel) return; const prev=sel.value;
  diamondList=[]; const seen=new Set();
  for(const n of news){ const k=n.url||n.title; if(seen.has(k))continue; seen.add(k); diamondList.push(n); }
  sel.innerHTML='<option value="">— Select a news story —</option>'+diamondList.map((n,i)=>{const d=n.seendate?String(n.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/,'$1-$2-$3'):'';return `<option value="${i}">${escapeHtml((d?d+' — ':'')+(n.title||'').slice(0,90))}</option>`;}).join('');
  if(prev!==''&&diamondList[+prev]) sel.value=prev;
}
let dmFullText=new Map();
async function fetchFullArticle(it){
  const btn=byId('dmFetch'); if(btn){ btn.disabled=true; btn.textContent='Fetching…'; }
  try{
    const html=await fetchViaProxy(it.url);
    const doc=new DOMParser().parseFromString(html,'text/html');
    doc.querySelectorAll('script,style,nav,header,footer,aside,form').forEach(e=>e.remove());
    let txt=[...doc.querySelectorAll('article p, main p, p')].map(p=>p.textContent).join(' ').replace(/\s+/g,' ').trim();
    if(!txt&&doc.body) txt=doc.body.textContent.replace(/\s+/g,' ').trim();
    dmFullText.set(it.url, txt.slice(0,8000));
    setStatus(txt?'Full article analyzed':'Fetched the page but found no readable body text');
  }catch(e){ dmFullText.set(it.url,''); setStatus('Could not fetch full article (CORS proxy blocked or site unavailable)'); }
  renderDiamond();
}
function renderDiamond(){
  const view=byId('diamondView'); if(!view) return;
  if(!diamondCurrent){ view.innerHTML='<p class="section-note">Select a news story above — or click <strong>◆ Diamond</strong> on any card in Recent News — to map it onto the Diamond Model.</p>'; return; }
  const it=diamondCurrent; const extra=dmFullText.get(it.url); const D=diamondForArticle(it,extra||'');
  const date=it.seendate?String(it.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/,'$1-$2-$3'):'';
  const depth=extra?'headline + summary + full article':(it.summary?'headline + article summary':'headline only');
  const vtx=(t,items,cls,hint)=>`<div class="dm-vertex ${cls}"><div class="dm-vtitle">${t}</div>${items.length?'<ul>'+items.map(x=>'<li>'+escapeHtml(x)+'</li>').join('')+'</ul>':'<p class="dm-empty">'+escapeHtml(hint)+'</p>'}</div>`;
  const capExtra=D.actorCves.length?`<p class="dm-empty">Actor's other known CVEs: ${escapeHtml(D.actorCves.join(', '))}</p>`:'';
  const artUrl=safeUrl(it.url)||'#';
  const iocs=extractIocs([it.title,it.summary,extra].filter(Boolean).join(' ')); const iocN=iocCount(iocs);
  view.innerHTML=`<div class="dm-meta"><a class="dm-t news-title" href="${artUrl}" target="_blank" rel="noreferrer">${escapeHtml(it.title||'Untitled')}</a><div class="section-note">${escapeHtml(date)}${it.sourceCountry?' · '+escapeHtml(it.sourceCountry):''}${it.domain?' · '+escapeHtml(it.domain):''}</div>${it.summary?`<p class="section-note" style="margin-top:6px">${escapeHtml(it.summary.slice(0,280))}${it.summary.length>280?'…':''}</p>`:''}</div>`
   +`<div class="diamond-grid">`
   + vtx('Adversary',D.adversary,'adv','Unattributed in text')
   + `<div class="dm-vertex cap"><div class="dm-vtitle">Capability</div>${D.capability.length?'<ul>'+D.capability.map(x=>'<li>'+escapeHtml(x)+'</li>').join('')+'</ul>':'<p class="dm-empty">No TTP/CVE found</p>'}${capExtra}</div>`
   + `<div class="dm-mid"><div class="dia">◆</div>Diamond<br>Model</div>`
   + vtx('Infrastructure',D.infrastructure,'inf','Not indicated')
   + vtx('Victim',D.victim,'vic','Target not indicated')
   + `</div>`
   + `<p class="cw-lex">Analyzed from: <strong>${depth}</strong>. Auto-extracted as a starting point — confirm against the full article.</p>`
   + `<div class="cw-actions"><a class="tab" href="${artUrl}" target="_blank" rel="noreferrer">Open article ↗</a>${extra===undefined?'<button id="dmFetch">🔍 Fetch full article</button>':''}${D.firstActor?'<button id="dmActor">Actor crosswalk</button>':''}${iocN?`<button id="dmIocs" title="Hashes, IPs, CVEs and published defanged indicators — copied defanged">🧬 Copy IOCs (${iocN})</button>`:''}<button id="dmCopy">📋 Copy Diamond</button></div>`;
  if(extra===undefined) byId('dmFetch').addEventListener('click',()=>fetchFullArticle(it));
  if(iocN) byId('dmIocs').addEventListener('click',async()=>{
    const md=iocReport(iocs,it.title||'article');
    try{ await navigator.clipboard.writeText(md); setStatus(`${iocN} IOC(s) copied (defanged)`); }
    catch(e){ const ta=document.createElement('textarea'); ta.value=md; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');setStatus('IOCs copied');}catch(_){console.log(md);} ta.remove(); }
  });
  if(D.firstActor) byId('dmActor').addEventListener('click',()=>openCrosswalk(D.firstActor));
  byId('dmCopy').addEventListener('click',()=>{
    const md=`# Diamond Model — ${it.title}\n\n- **Adversary:** ${D.adversary.join(', ')||'—'}\n- **Capability:** ${D.capability.join(', ')||'—'}${D.actorCves.length?` (actor known CVEs: ${D.actorCves.join(', ')})`:''}\n- **Infrastructure:** ${D.infrastructure.join(', ')||'—'}\n- **Victim:** ${D.victim.join(', ')||'—'}\n\n_Source: ${it.sourceCountry||it.domain||''} ${date} — ${it.url}_\n`;
    (navigator.clipboard?navigator.clipboard.writeText(md):Promise.reject()).then(()=>setStatus('Diamond copied as Markdown')).catch(()=>{const ta=document.createElement('textarea');ta.value=md;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');setStatus('Diamond copied');}catch(_){}ta.remove();});
  });
}
function mapToDiamond(item){
  activate('diamond'); renderDiamondOptions();
  const k=item.url||item.title; const idx=diamondList.findIndex(n=>(n.url||n.title)===k);
  byId('diamondSelect').value=idx>=0?String(idx):''; diamondCurrent=item; renderDiamond();
}
function renderAll(){renderCards(); renderSnapshot(); renderChanges(); renderActors(); renderNews(); renderFeedHealth(); renderKev(); renderCrosswalk(); renderDiamondOptions(); renderWorkbench(); const pm=byId('newsSource').value==='prebuilt'&&prebuiltMeta&&prebuiltMeta.generated; byId('updatedStamp').textContent=pm?('Feed updated '+relTime(prebuiltMeta.generated)):('Last rendered: '+new Date().toLocaleString());}
// ---- Analyst workbench: pins + notes + keyword watchlist (localStorage only) ----
function lsGet(k,fb){ try{ const v=JSON.parse(localStorage.getItem('ctd:'+k)); return v==null?fb:v; }catch(e){ return fb; } }
function lsSet(k,v){ try{ localStorage.setItem('ctd:'+k,JSON.stringify(v)); }catch(e){} }
let pins=lsGet('pins',{});
let watchTerms=lsGet('watch',[]);
function togglePin(n){
  const k=n.url||n.title;
  if(pins[k]) delete pins[k];
  else pins[k]={title:n.title,url:n.url,c:n.c,seendate:n.seendate||'',sourceCountry:n.sourceCountry||n.domain||'',note:'',added:new Date().toISOString()};
  lsSet('pins',pins); renderWorkbench(); renderNews();
}
function watchHit(n){
  if(!watchTerms.length) return null;
  const blob=`${n.title} ${n.summary||''}`.toLowerCase();
  return watchTerms.find(t=>blob.includes(t.toLowerCase()))||null;
}
function renderWorkbench(){
  const pl=byId('pinList'); if(!pl) return;
  const entries=Object.entries(pins).sort((a,b)=>String(b[1].added).localeCompare(String(a[1].added)));
  pl.innerHTML=entries.length?'':'<p class="section-note">Nothing pinned yet — use the 📌 button on any Recent News card.</p>';
  for(const [k,p] of entries){
    const d=document.createElement('div'); d.className='small-card pin-item';
    const date=p.seendate?String(p.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/,'$1-$2-$3'):'';
    d.innerHTML=`<a class="news-title" href="${safeUrl(p.url)||'#'}" target="_blank" rel="noreferrer">${escapeHtml(p.title||'Untitled')}</a>
      <p class="section-note" style="margin:4px 0">${escapeHtml(date)}${p.sourceCountry?' · '+escapeHtml(p.sourceCountry):''}${COUNTRIES[p.c]?' · '+COUNTRIES[p.c].flag:''}</p>`;
    const ta=document.createElement('textarea'); ta.placeholder='Analyst note…'; ta.value=p.note||'';
    ta.addEventListener('change',()=>{ pins[k].note=ta.value; lsSet('pins',pins); });
    const un=document.createElement('button'); un.className='pin-btn pinned'; un.textContent='📌 Unpin';
    un.addEventListener('click',()=>togglePin({url:p.url,title:p.title}));
    d.appendChild(ta); d.appendChild(un); pl.appendChild(d);
  }
  const wl=byId('watchList'); if(!wl) return;
  wl.innerHTML=watchTerms.length?'':'<span class="section-note">No terms yet.</span>';
  for(const t of watchTerms){
    const s=document.createElement('span'); s.className='tag watch-term'; s.textContent=t+' ✕'; s.title='Remove';
    s.addEventListener('click',()=>{ watchTerms=watchTerms.filter(x=>x!==t); lsSet('watch',watchTerms); renderWorkbench(); renderNews(); });
    wl.appendChild(s);
  }
}
function downloadJson(filename,value){
  const blob=new Blob([JSON.stringify(value,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; document.body.appendChild(a); a.click();
  setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);
}
function exportWorkbench(){
  downloadJson(`cyber-dashboard-workbench-${new Date().toISOString().slice(0,10)}.json`,{schemaVersion:1,exportedAt:new Date().toISOString(),pins,watchTerms});
  setStatus(`Workbench backup downloaded — ${Object.keys(pins).length} pin(s), ${watchTerms.length} watch term(s)`);
}
async function importWorkbenchFile(file){
  try{
    const data=JSON.parse(await file.text());
    if(data.schemaVersion!==1||!data.pins||typeof data.pins!=='object'||Array.isArray(data.pins)||!Array.isArray(data.watchTerms)) throw new Error('unsupported backup format');
    const cleanPins={};
    for(const [key,pin] of Object.entries(data.pins)) if(pin&&typeof pin==='object'&&typeof pin.title==='string') cleanPins[String(key)]={...pin,title:String(pin.title),note:String(pin.note||'')};
    pins=cleanPins; watchTerms=[...new Set(data.watchTerms.filter(t=>typeof t==='string').map(t=>t.trim()).filter(Boolean))].slice(0,100);
    lsSet('pins',pins); lsSet('watch',watchTerms); renderWorkbench(); renderNews(); setStatus(`Workbench restored — ${Object.keys(pins).length} pin(s), ${watchTerms.length} watch term(s)`);
  }catch(e){ setStatus(`Backup not restored: ${e.message}`); }
}
// ---- STIX 2.1 export of the current (filtered) news ----
function stixId(type){ return `${type}--${(crypto.randomUUID?crypto.randomUUID():'00000000-0000-4000-8000-'+String(Date.now()).padStart(12,'0'))}`; }
function exportStix(){
  const now=new Date().toISOString();
  const seen=new Set(); const stories=[];
  for(const n of news.filter(newsMatches)){ const k=n.url||n.title; if(!seen.has(k)){ seen.add(k); stories.push(n); } }
  if(!stories.length){ setStatus('Nothing to export — no stories match the current filters'); return; }
  const identity={type:'identity',spec_version:'2.1',id:stixId('identity'),created:now,modified:now,name:'Big 4 Cyber & IW Threat Dashboard',identity_class:'system'};
  const objs=[identity]; const actorIds=new Map(); const vulnIds=new Map();
  for(const n of stories){
    const refs=[identity.id];
    for(const a of actorsInText([n.title,n.summary].filter(Boolean).join(' '))){
      if(!actorIds.has(a.n)){ const id=stixId('threat-actor'); actorIds.set(a.n,id);
        objs.push({type:'threat-actor',spec_version:'2.1',id,created:now,modified:now,name:a.n,aliases:(a.a||[]).slice(0,20),threat_actor_types:['nation-state']}); }
      refs.push(actorIds.get(a.n));
    }
    for(const c of (`${n.title} ${n.summary||''}`.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(x=>x.toUpperCase())){
      if(!vulnIds.has(c)){ const id=stixId('vulnerability'); vulnIds.set(c,id);
        objs.push({type:'vulnerability',spec_version:'2.1',id,created:now,modified:now,name:c,external_references:[{source_name:'cve',external_id:c}]}); }
      refs.push(vulnIds.get(c));
    }
    const s=String(n.seendate||'');
    const published=s.length>=8?`${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)||'00'}:${s.slice(10,12)||'00'}:${s.slice(12,14)||'00'}Z`:now;
    objs.push({type:'report',spec_version:'2.1',id:stixId('report'),created:now,modified:now,created_by_ref:identity.id,
      name:n.title,published,report_types:['threat-report'],object_refs:[...new Set(refs)],
      external_references:[{source_name:n.sourceCountry||n.domain||'source',url:n.url}]});
  }
  const bundle={type:'bundle',id:stixId('bundle'),objects:objs};
  const blob=new Blob([JSON.stringify(bundle,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`big4-news-stix-${now.slice(0,10)}.json`; document.body.appendChild(a); a.click();
  setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);
  setStatus(`STIX bundle exported — ${stories.length} report(s), ${actorIds.size} actor(s), ${vulnIds.size} CVE(s)`);
}
// ---- Activity trends from data/archive.json (chart palette validated for CVD + contrast, light & dark) ----
let ARCHIVE={entries:[]};
const TREND_SERIES=[['CN','China','var(--chart-cn)'],['RU','Russia','var(--chart-ru)'],['IR','Iran','var(--chart-ir)'],['KP','North Korea','var(--chart-kp)']];
async function loadArchive(){
  try{ const r=await fetch('data/archive.json?_='+Date.now(),{cache:'no-store'}); if(r.ok){ const d=await r.json(); if(d&&Array.isArray(d.entries)) ARCHIVE=d; } }catch(e){}
  renderTrends();
}
function renderTrends(){
  const el=byId('trendChart'); if(!el) return;
  const es=ARCHIVE.entries||[];
  const note=byId('trendNote');
  const leg=byId('trendLegend');
  leg.innerHTML=TREND_SERIES.map(([c,name,color])=>`<span class="legend-chip"><span class="sw" style="background:${color}"></span>${name}</span>`).join(' ');
  const tb=byId('trendTable').querySelector('tbody'); tb.innerHTML='';
  for(const e of es.slice().reverse()){
    const tr=document.createElement('tr');
    tr.innerHTML=`<td class="mono">${escapeHtml(e.date)}</td><td>${e.counts.CN}</td><td>${e.counts.RU}</td><td>${e.counts.IR}</td><td>${e.counts.KP}</td><td>${e.total}</td><td>${e.okFeeds??'—'}</td>`;
    tb.appendChild(tr);
  }
  if(es.length<2){
    note.textContent=`The archive is accumulating — ${es.length} day(s) recorded so far. The chart appears at 2+ days; the table below shows what exists.`;
    el.innerHTML=''; return;
  }
  note.textContent=`${es.length} day(s) of history · one point per UTC day (last sync of the day)`;
  const W=860,H=280,L=34,R=86,T=12,B=26,iw=W-L-R,ih=H-T-B;
  const max=Math.max(1,...es.map(e=>Math.max(e.counts.CN,e.counts.RU,e.counts.IR,e.counts.KP)));
  const x=i=>L+iw*(i/(es.length-1)), y=v=>T+ih*(1-v/max);
  const gridY=[0,0.5,1].map(f=>Math.round(max*f));
  let svg=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Stories per country per day">`;
  for(const g of gridY) svg+=`<line x1="${L}" y1="${y(g)}" x2="${W-R}" y2="${y(g)}" stroke="var(--line)" stroke-width="1"/><text x="${L-6}" y="${y(g)+4}" text-anchor="end" font-size="11" fill="var(--muted)">${g}</text>`;
  svg+=`<text x="${L}" y="${H-6}" font-size="11" fill="var(--muted)">${es[0].date}</text><text x="${W-R}" y="${H-6}" text-anchor="end" font-size="11" fill="var(--muted)">${es[es.length-1].date}</text>`;
  for(const [c,name,color] of TREND_SERIES){
    const pts=es.map((e,i)=>`${x(i)},${y(e.counts[c])}`).join(' ');
    svg+=`<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    const last=es[es.length-1];
    svg+=`<circle cx="${x(es.length-1)}" cy="${y(last.counts[c])}" r="3" fill="${color}"/><text x="${W-R+8}" y="${y(last.counts[c])+4}" font-size="11.5" fill="var(--ink)"><tspan fill="${color}">●</tspan> ${escapeHtml(COUNTRIES[c]?COUNTRIES[c].short:name)}</text>`;
  }
  svg+=`<line id="trendCross" x1="0" y1="${T}" x2="0" y2="${T+ih}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="3 3" visibility="hidden"/>`;
  svg+='</svg>';
  el.innerHTML=svg+'<div class="trend-tip" id="trendTip" style="display:none"></div>';
  const svgEl=el.querySelector('svg'), cross=el.querySelector('#trendCross'), tip=byId('trendTip');
  svgEl.setAttribute('tabindex','0'); svgEl.setAttribute('aria-describedby','trendNote');
  svgEl.addEventListener('mousemove',ev=>{
    const rect=svgEl.getBoundingClientRect(); const sx=(ev.clientX-rect.left)*(W/rect.width);
    const i=Math.max(0,Math.min(es.length-1,Math.round((sx-L)/iw*(es.length-1))));
    const e=es[i];
    cross.setAttribute('x1',x(i)); cross.setAttribute('x2',x(i)); cross.setAttribute('visibility','visible');
    tip.style.display='block';
    tip.innerHTML=`<div class="d mono">${escapeHtml(e.date)}</div>`+TREND_SERIES.map(([c,name,color])=>`<div class="row"><span><span class="sw" style="background:${color}"></span>${escapeHtml(name)}</span><span class="mono">${e.counts[c]}</span></div>`).join('')+`<div class="row" style="margin-top:3px;border-top:1px solid var(--line);padding-top:3px"><span>Total</span><span class="mono">${e.total}</span></div>`;
    const px=(x(i)/W)*rect.width;
    tip.style.left=Math.min(rect.width-150,Math.max(0,px+12))+'px';
    tip.style.top='14px';
  });
  svgEl.addEventListener('mouseleave',()=>{ cross.setAttribute('visibility','hidden'); tip.style.display='none'; });
}
// ---- Shareable deep links: tab/filter/search state lives in the URL hash ----
let applyingHash=false;
function updateHash(){
  if(applyingHash) return;
  const cur=document.querySelector('#tabs .tab.active'); const p=new URLSearchParams();
  if(cur&&cur.dataset.tab!=='overview') p.set('tab',cur.dataset.tab);
  const q=byId('search').value.trim(); if(q) p.set('q',q);
  const c=byId('countryFilter').value; if(c!=='ALL') p.set('c',c);
  const s=p.toString();
  history.replaceState(null,'',s?('#'+s):location.pathname+location.search);
}
function applyHash(){
  const h=location.hash.slice(1); if(!h) return;
  applyingHash=true;
  try{
    const p=new URLSearchParams(h);
    if(p.get('q')!==null) byId('search').value=p.get('q')||'';
    const c=p.get('c'); if(c&&COUNTRIES[c]) byId('countryFilter').value=c;
    const t=p.get('tab'); if(t&&document.querySelector(`#tabs .tab[data-tab="${t}"]`)) activate(t);
    renderAll();
  } finally { applyingHash=false; }
}
window.addEventListener('hashchange',applyHash);
function activate(tab){
  document.querySelectorAll('#tabs .tab').forEach(t=>{const on=t.dataset.tab===tab;t.classList.toggle('active',on);t.setAttribute('aria-selected',on?'true':'false');t.tabIndex=on?0:-1;});
  for(const name of ['overview','news','actors','crosswalk','kev','diamond','trends','workbench','sources']){ const panel=byId(name+'Panel'), off=name!==tab; panel.classList.toggle('hidden',off); panel.hidden=off; }
  updateHash();
}
document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>activate(t.dataset.tab)));
byId('tabs').addEventListener('keydown',e=>{
  if(!['ArrowRight','ArrowLeft','Home','End'].includes(e.key)) return;
  const tabs=[...document.querySelectorAll('#tabs .tab')], current=tabs.indexOf(document.activeElement); if(current<0) return;
  e.preventDefault(); const next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(current+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
  tabs[next].focus(); activate(tabs[next].dataset.tab);
});
// Build a dated, country-grouped Markdown brief from the current (filtered) news.
function buildBrief(){
  const matched=news.filter(newsMatches);
  const byKey=new Map();
  for(const n of matched){ const k=n.url||n.title; if(!byKey.has(k)) byKey.set(k,{item:n,countries:new Set()}); if(COUNTRIES[n.c]) byKey.get(k).countries.add(n.c); }
  const groups=[...byKey.values()];
  const days=byId('timespan').value, cf=byId('countryFilter').value, q=byId('search').value.trim();
  const today=new Date().toISOString().slice(0,10);
  let pinMd='';
  const pinned=Object.values(pins).sort((a,b)=>String(b.added).localeCompare(String(a.added)));
  if(pinned.length){
    pinMd='## 📌 Pinned by analyst\n\n'+pinned.map(p=>{
      const d=p.seendate?String(p.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/,'$1-$2-$3'):'';
      return `- [${(p.title||'Untitled').replace(/[\[\]]/g,'')}](${p.url})${d?' ('+d+')':''}${p.note?`\n  - _${p.note.replace(/\n/g,' ')}_`:''}`;
    }).join('\n')+'\n\n';
  }
  let md=`# Big 4 Cyber & IW Threat Brief — ${today}\n\n_Lookback: ${days} days`;
  if(cf!=='ALL') md+=` · ${COUNTRIES[cf]?COUNTRIES[cf].name:cf}`;
  if(q) md+=` · filter: "${q}"`;
  md+=`_\n\n`+pinMd;
  let any=false;
  for(const code of Object.keys(COUNTRIES)){
    if(cf!=='ALL'&&cf!==code) continue;
    const inC=groups.filter(g=>g.countries.has(code));
    if(!inC.length) continue;
    any=true;
    inC.sort((a,b)=>String(b.item.seendate||'').localeCompare(String(a.item.seendate||'')));
    md+=`## ${COUNTRIES[code].flag} ${COUNTRIES[code].name} (${inC.length})\n\n`;
    for(const g of inC){
      const n=g.item; const date=n.seendate?String(n.seendate).replace(/(\d{4})(\d{2})(\d{2}).*/,'$1-$2-$3'):'';
      const also=[...g.countries].filter(c=>c!==code).map(c=>COUNTRIES[c]?COUNTRIES[c].short:c);
      const title=(n.title||'Untitled').replace(/[\[\]]/g,'');
      md+=`- [${title}](${n.url}) — ${n.sourceCountry||n.domain||'source'}${date?' ('+date+')':''}${also.length?' _[also: '+also.join(', ')+']_':''}\n`;
    }
    md+=`\n`;
  }
  if(!any) md+=`_No items match the current filters._\n`;
  md+=`\n---\n_Generated from the Big 4 Cyber & IW Threat Dashboard. Attribution is probabilistic; treat as a naming/triage index, not a legal determination._\n`;
  return md;
}
async function copyBrief(){
  const md=buildBrief();
  try{
    await navigator.clipboard.writeText(md);
    setStatus('Brief copied to clipboard as Markdown');
  }catch(e){
    const ta=document.createElement('textarea'); ta.value=md; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.focus(); ta.select();
    let okCopy=false; try{ okCopy=document.execCommand('copy'); }catch(_){}
    document.body.removeChild(ta);
    setStatus(okCopy?'Brief copied to clipboard':'Copy blocked — brief logged to console'); if(!okCopy) console.log(md);
  }
}
byId('refreshNews').addEventListener('click',refreshNews); byId('refreshActors').addEventListener('click',refreshActors);
byId('copyBrief').addEventListener('click',copyBrief);
// Light/dark theme toggle (initial theme is applied by the early <head> script).
function syncThemeIcon(){ byId('themeToggle').textContent=document.documentElement.dataset.theme==='light'?'☀️':'🌙'; }
syncThemeIcon();
byId('themeToggle').addEventListener('click',()=>{
  const next=document.documentElement.dataset.theme==='light'?'dark':'light';
  document.documentElement.dataset.theme=next;
  try{ localStorage.setItem('theme',next); }catch(e){}
  syncThemeIcon();
});
byId('countryFilter').addEventListener('change',()=>{updateHash();renderAll();}); byId('timespan').addEventListener('change',refreshNews);
let searchDebounce=null;
byId('search').addEventListener('input',()=>{ clearTimeout(searchDebounce); searchDebounce=setTimeout(()=>{updateHash();renderAll();},150); });
byId('newsSource').addEventListener('change',refreshNews);
byId('newsSort').addEventListener('change',renderNews);
renderAll();
// Load canonical feeds/country config from data/sources.json, then populate.
loadSources().then(()=>{
  renderAll();
  // Try a live actor refresh on load, but do not block offline use.
  refreshActors();
  // Auto-load the prebuilt hourly feed (default source) so the dashboard is populated on open.
  refreshNews();
});
// Load the CISA KEV catalog (independent of country config).
loadKev();
loadEpss();
loadAttack();
loadCrosswalk();
byId('diamondSelect').addEventListener('change',e=>{ const v=e.target.value; diamondCurrent=v===''?null:diamondList[+v]; renderDiamond(); });
renderDiamondOptions(); renderDiamond();
loadActorCves();
loadArchive();
byId('watchAdd').addEventListener('click',()=>{ const v=byId('watchInput').value.trim(); if(v&&!watchTerms.includes(v)){ watchTerms.push(v); lsSet('watch',watchTerms); byId('watchInput').value=''; renderWorkbench(); renderNews(); } });
byId('watchInput').addEventListener('keydown',e=>{ if(e.key==='Enter') byId('watchAdd').click(); });
byId('stixExport').addEventListener('click',exportStix);
byId('workbenchExport').addEventListener('click',exportWorkbench);
byId('workbenchImport').addEventListener('click',()=>byId('workbenchFile').click());
byId('workbenchFile').addEventListener('change',e=>{ const file=e.target.files?.[0]; if(file) importWorkbenchFile(file); e.target.value=''; });
renderWorkbench();
// Apply any shared deep link (#tab=…&q=…&c=…) once the static UI exists.
applyHash();
// Crosswalk modal close: button, backdrop click, Escape.
byId('cwClose').addEventListener('click',closeCrosswalk);
byId('crosswalkModal').addEventListener('click',e=>{ if(e.target===byId('crosswalkModal')) closeCrosswalk(); });
document.addEventListener('keydown',e=>{
  const modal=byId('crosswalkModal'); if(modal.classList.contains('hidden')) return;
  if(e.key==='Escape'){ closeCrosswalk(); return; }
  if(e.key==='Tab'){
    const focusable=[...modal.querySelectorAll('button,a[href],[tabindex]:not([tabindex="-1"])')].filter(el=>!el.disabled);
    if(!focusable.length) return; const first=focusable[0],last=focusable[focusable.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  }
});
