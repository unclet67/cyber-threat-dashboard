// scripts/validate.mjs
// Deterministic, offline validation run by CI on every PR (and locally via `node scripts/validate.mjs`).
// Checks: index.html inline JS parses, news.json matches the expected schema.
// Collector syntax is checked separately in CI via `node --check scripts/fetch-news.mjs`.

import { readFileSync } from 'node:fs';
import vm from 'node:vm';

let failures = 0;
const fail = m => { console.error('✗ ' + m); failures++; };
const ok = m => console.log('✓ ' + m);

// 1. App JS must parse (compile-only; browser globals are never executed):
//    app.js plus any inline <script> blocks left in index.html (the pre-paint theme snippet).
try {
  const appSource = readFileSync('app.js', 'utf8');
  // The browser app is an ES module; its imported model is syntax-checked
  // separately. Remove only the import declaration for compile-only VM parsing.
  new vm.Script(appSource.replace(/^import[^;]+;\s*/m, ''), { filename: 'app.js' });
  const html = readFileSync('index.html', 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  scripts.forEach((code, i) => new vm.Script(code, { filename: `index.html#script${i}` }));
  for (const ref of ['src="app.js"', 'href="styles.css"']) {
    if (!html.includes(ref)) throw new Error(`index.html missing ${ref}`);
  }
  ok(`app.js parses; index.html inline JS parses (${scripts.length} block(s)); asset refs present`);
} catch (e) {
  fail('app JS: ' + e.message);
}

// 2. news.json schema.
try {
  const data = JSON.parse(readFileSync('data/news.json', 'utf8'));
  const COUNTRIES = new Set(['CN', 'RU', 'IR', 'KP']);
  if (typeof data !== 'object' || data === null) throw new Error('not an object');
  if (!('generated' in data)) throw new Error('missing "generated"');
  if (!Array.isArray(data.items)) throw new Error('"items" is not an array');
  data.items.forEach((it, i) => {
    for (const k of ['title', 'url', 'c']) if (!it[k]) throw new Error(`item ${i} missing "${k}"`);
    if (!COUNTRIES.has(it.c)) throw new Error(`item ${i} invalid country "${it.c}"`);
    if (!/^https?:\/\//.test(it.url)) throw new Error(`item ${i} url not http(s): ${it.url}`);
    if ('relationship' in it && !['sponsor','victim','criminal','context'].includes(it.relationship)) throw new Error(`item ${i} invalid relationship "${it.relationship}"`);
    if ('confidence' in it && !['high','medium','low'].includes(it.confidence)) throw new Error(`item ${i} invalid confidence "${it.confidence}"`);
  });
  if ('feedsStatus' in data) {
    if (!Array.isArray(data.feedsStatus)) throw new Error('"feedsStatus" is not an array');
    data.feedsStatus.forEach((f, i) => {
      if (!f.name) throw new Error(`feedsStatus ${i} missing "name"`);
      if (typeof f.ok !== 'boolean') throw new Error(`feedsStatus ${i} "ok" not boolean`);
    });
  }
  ok(`news.json valid (${data.items.length} items${data.feedsStatus ? `, ${data.feedsStatus.length} feed statuses` : ''})`);
} catch (e) {
  fail('news.json schema: ' + e.message);
}

// 3. data/sources.json schema (single source of truth for countries + feeds).
try {
  const s = JSON.parse(readFileSync('data/sources.json', 'utf8'));
  if (!s.countries || typeof s.countries !== 'object') throw new Error('missing "countries"');
  for (const [code, c] of Object.entries(s.countries)) {
    for (const k of ['name', 'focus']) if (!c[k]) throw new Error(`country ${code} missing "${k}"`);
    if (!Array.isArray(c.terms) || !c.terms.length) throw new Error(`country ${code} has no terms`);
  }
  if (!Array.isArray(s.feeds) || !s.feeds.length) throw new Error('"feeds" empty or not an array');
  s.feeds.forEach((f, i) => {
    if (!f.name || !f.url) throw new Error(`feed ${i} missing name/url`);
    if (!/^https?:\/\//.test(f.url)) throw new Error(`feed ${i} url not http(s): ${f.url}`);
  });
  ok(`data/sources.json valid (${Object.keys(s.countries).length} countries, ${s.feeds.length} feeds)`);
} catch (e) {
  fail('data/sources.json schema: ' + e.message);
}

// 4. kev.json schema (CISA KEV catalog slice).
try {
  const kev = JSON.parse(readFileSync('data/kev.json', 'utf8'));
  if (!('generated' in kev)) throw new Error('missing "generated"');
  if (!Array.isArray(kev.items)) throw new Error('"items" is not an array');
  kev.items.forEach((v, i) => {
    if (!v.cve) throw new Error(`item ${i} missing "cve"`);
    if (typeof v.ransomware !== 'boolean') throw new Error(`item ${i} "ransomware" not boolean`);
  });
  ok(`kev.json valid (${kev.items.length} entries)`);
} catch (e) {
  fail('kev.json schema: ' + e.message);
}

// 5. data/crosswalk.json schema (provider naming-convention reference).
try {
  const cw = JSON.parse(readFileSync('data/crosswalk.json', 'utf8'));
  if (!Array.isArray(cw.providers) || !cw.providers.length) throw new Error('"providers" empty or not an array');
  cw.providers.forEach((p, i) => {
    if (!p.name) throw new Error(`provider ${i} missing "name"`);
    if (!p.lexicon) throw new Error(`provider ${i} missing "lexicon"`);
    (p.regex || []).forEach(r => new RegExp(r)); // throws if invalid
  });
  ok(`data/crosswalk.json valid (${cw.providers.length} providers)`);
} catch (e) {
  fail('data/crosswalk.json schema: ' + e.message);
}

// 6. data/actor-cves.json schema (curated actor -> known exploited CVEs).
try {
  const ac = JSON.parse(readFileSync('data/actor-cves.json', 'utf8'));
  if (!Array.isArray(ac.actors) || !ac.actors.length) throw new Error('"actors" empty or not an array');
  let cveCount = 0;
  ac.actors.forEach((a, i) => {
    if (!Array.isArray(a.names) || !a.names.length) throw new Error(`actor ${i} has no "names"`);
    if (!Array.isArray(a.cves) || !a.cves.length) throw new Error(`actor ${i} has no "cves"`);
    a.cves.forEach((v, j) => {
      if (!/^CVE-\d{4}-\d{4,}$/.test(v.id || '')) throw new Error(`actor ${i} cve ${j} bad id "${v.id}"`);
      cveCount++;
    });
  });
  ok(`data/actor-cves.json valid (${ac.actors.length} actors, ${cveCount} CVE mappings)`);
} catch (e) {
  fail('data/actor-cves.json schema: ' + e.message);
}

// 7. data/archive.json schema (rolling daily counts for trend views).
try {
  const ar = JSON.parse(readFileSync('data/archive.json', 'utf8'));
  if (!Array.isArray(ar.entries)) throw new Error('"entries" is not an array');
  ar.entries.forEach((e, i) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date || '')) throw new Error(`entry ${i} bad date "${e.date}"`);
    if (typeof e.total !== 'number') throw new Error(`entry ${i} "total" not a number`);
  });
  ok(`data/archive.json valid (${ar.entries.length} day(s))`);
} catch (e) {
  fail('data/archive.json schema: ' + e.message);
}

// 8. data/attack.json schema (reduced MITRE ATT&CK groups map).
try {
  const at = JSON.parse(readFileSync('data/attack.json', 'utf8'));
  if (!Array.isArray(at.groups)) throw new Error('"groups" is not an array');
  at.groups.forEach((g, i) => {
    if (!/^G\d{3,4}$/.test(g.gid || '')) throw new Error(`group ${i} bad gid "${g.gid}"`);
    if (!g.name) throw new Error(`group ${i} missing "name"`);
    (g.techniques || []).forEach(t => { if (!/^T\d{4}$/.test(t.id || '')) throw new Error(`group ${g.gid} bad technique id "${t.id}"`); });
  });
  ok(`data/attack.json valid (${at.groups.length} groups)`);
} catch (e) {
  fail('data/attack.json schema: ' + e.message);
}

// 9. data/epss.json schema (EPSS scores for KEV CVEs).
try {
  const ep = JSON.parse(readFileSync('data/epss.json', 'utf8'));
  if (typeof ep.scores !== 'object' || ep.scores === null) throw new Error('"scores" is not an object');
  for (const [cve, s] of Object.entries(ep.scores)) {
    if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) throw new Error(`bad CVE key "${cve}"`);
    if (typeof s.epss !== 'number' || s.epss < 0 || s.epss > 1) throw new Error(`${cve} epss out of range`);
  }
  ok(`data/epss.json valid (${Object.keys(ep.scores).length} scores)`);
} catch (e) {
  fail('data/epss.json schema: ' + e.message);
}

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll checks passed.');
