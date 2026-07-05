// scripts/fetch-enrichment.mjs
// Daily enrichment collector (runs in GitHub Actions; see sync-enrichment.yml).
// 1. MITRE ATT&CK: fetches the enterprise-attack STIX bundle (~40 MB, changes a few
//    times a year) and reduces it to a compact groups -> techniques/software map
//    (data/attack.json) that powers actor TTP profiles and Navigator layer export.
// 2. EPSS: fetches FIRST's daily exploit-probability scores and keeps only the CVEs
//    present in our KEV slice (data/epss.json). Full EPSS is ~300k rows; we need ~150.
// Each part is isolated: a failure leaves the previous file in place and never
// breaks the other part.

import { readFile, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { reduceAttack, parseEpssCsv } from './lib.mjs';

const ATTACK_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';

async function fetchRaw(url, ms = 120000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': 'threat-dashboard-enrichment/1.0' } });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return Buffer.from(await r.arrayBuffer());
  } finally {
    clearTimeout(t);
  }
}

// --- ATT&CK ---
try {
  const stix = JSON.parse((await fetchRaw(ATTACK_URL)).toString('utf8'));
  const groups = reduceAttack(stix);
  const version = ((stix.objects || []).find(o => o.type === 'x-mitre-collection') || {}).x_mitre_version || null;
  const out = { generated: new Date().toISOString(), source: 'MITRE ATT&CK (enterprise)', version, count: groups.length, groups };
  await writeFile('data/attack.json', JSON.stringify(out) + '\n');
  const tech = groups.reduce((n, g) => n + g.techniques.length, 0);
  const sw = groups.reduce((n, g) => n + g.software.length, 0);
  console.log(`Wrote attack.json — ${groups.length} groups, ${tech} technique links, ${sw} software links (ATT&CK v${version})`);
} catch (e) {
  console.warn(`ATT&CK fetch failed (attack.json left unchanged): ${e.message}`);
}

// --- EPSS (scoped to the CVEs in our KEV slice) ---
try {
  const kev = JSON.parse(await readFile('data/kev.json', 'utf8'));
  const wanted = new Set((kev.items || []).map(v => v.cve).filter(Boolean));
  if (!wanted.size) throw new Error('kev.json has no CVEs yet — run the news sync first');
  const csv = gunzipSync(await fetchRaw(EPSS_URL)).toString('utf8');
  const scores = parseEpssCsv(csv, wanted);
  const out = { generated: new Date().toISOString(), source: 'FIRST EPSS', count: Object.keys(scores).length, scores };
  await writeFile('data/epss.json', JSON.stringify(out) + '\n');
  console.log(`Wrote epss.json — scores for ${out.count}/${wanted.size} KEV CVEs`);
} catch (e) {
  console.warn(`EPSS fetch failed (epss.json left unchanged): ${e.message}`);
}
