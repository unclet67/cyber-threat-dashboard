// scripts/validate.mjs
// Deterministic, offline validation run by CI on every PR (and locally via `node scripts/validate.mjs`).
// Checks: index.html inline JS parses, news.json matches the expected schema.
// Collector syntax is checked separately in CI via `node --check scripts/fetch-news.mjs`.

import { readFileSync } from 'node:fs';
import vm from 'node:vm';

let failures = 0;
const fail = m => { console.error('✗ ' + m); failures++; };
const ok = m => console.log('✓ ' + m);

// 1. index.html inline <script> blocks must parse (compile-only; browser globals are never executed).
try {
  const html = readFileSync('index.html', 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  if (!scripts.length) throw new Error('no <script> block found');
  scripts.forEach((code, i) => new vm.Script(code, { filename: `index.html#script${i}` }));
  ok(`index.html inline JS parses (${scripts.length} block(s))`);
} catch (e) {
  fail('index.html inline JS: ' + e.message);
}

// 2. news.json schema.
try {
  const data = JSON.parse(readFileSync('news.json', 'utf8'));
  const COUNTRIES = new Set(['CN', 'RU', 'IR', 'KP']);
  if (typeof data !== 'object' || data === null) throw new Error('not an object');
  if (!('generated' in data)) throw new Error('missing "generated"');
  if (!Array.isArray(data.items)) throw new Error('"items" is not an array');
  data.items.forEach((it, i) => {
    for (const k of ['title', 'url', 'c']) if (!it[k]) throw new Error(`item ${i} missing "${k}"`);
    if (!COUNTRIES.has(it.c)) throw new Error(`item ${i} invalid country "${it.c}"`);
    if (!/^https?:\/\//.test(it.url)) throw new Error(`item ${i} url not http(s): ${it.url}`);
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

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll checks passed.');
