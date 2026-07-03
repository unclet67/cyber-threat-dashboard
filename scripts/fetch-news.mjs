// scripts/fetch-news.mjs
// Server-side news collector for the Big 4 Cyber & Information Warfare dashboard.
// Runs in GitHub Actions (Node 20+), where there is no CORS/proxy constraint:
// it fetches the cyber-security RSS/Atom feeds directly, keeps items mentioning
// China, Russia, Iran, or North Korea, and writes data/news.json for the dashboard
// to read same-origin. Countries and feeds come from data/sources.json (single
// source of truth shared with the browser UI). Pure logic lives in lib.mjs (tested).

import { readFile, writeFile } from 'node:fs/promises';
import { buildClassifier, parseItems, sigWords, jaccard, norm, fmtSeen, hostOf, runPool } from './lib.mjs';

const SOURCES = JSON.parse(await readFile(new URL('../data/sources.json', import.meta.url), 'utf8'));
const COUNTRIES = SOURCES.countries;
const FEEDS = SOURCES.feeds.map(f => [f.name, f.url]);

const LOOKBACK_DAYS = 90;   // matches the UI's largest lookback option
const MAX_ITEMS = 500;      // cap output size
const CONCURRENCY = 6;

const classify = buildClassifier(COUNTRIES, SOURCES.weakTerms);

async function fetchText(url, ms = 20000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, {
      signal: ctl.signal,
      redirect: 'follow',
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; threat-dashboard-collector/1.0)',
        'accept': 'application/rss+xml,application/atom+xml,application/xml,text/xml,*/*',
      },
    });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}



const cutoff = Date.now() - LOOKBACK_DAYS * 86400000;
const collected = [];
const report = [];
const feedsStatus = [];

await runPool(FEEDS, CONCURRENCY, async ([name, url]) => {
  try {
    const items = parseItems(await fetchText(url));
    let kept = 0;
    for (const it of items) {
      if (!it.title || !it.link) continue;
      const dt = it.date ? new Date(it.date) : null;
      const valid = dt && !isNaN(dt);
      if (valid && dt.getTime() < cutoff) continue;
      const codes = classify(it.title, it.desc);
      if (!codes.length) continue;
      const seendate = valid ? fmtSeen(dt) : '';
      for (const c of codes) {
        collected.push({ title: it.title, url: it.link, domain: hostOf(it.link), seendate, sourceCountry: name, c, summary: (it.desc || '').slice(0, 500) });
        kept++;
      }
    }
    feedsStatus.push({ name, ok: true, items: items.length, kept });
    report.push(`ok    ${name} — ${items.length} items, ${kept} kept`);
  } catch (e) {
    feedsStatus.push({ name, ok: false, error: e.message });
    report.push(`FAIL  ${name} — ${e.message}`);
  }
});
// Newest first; within each country drop exact and near-duplicate titles; keep cross-country tags.
collected.sort((a, b) => String(b.seendate).localeCompare(String(a.seendate)));
const keptByCountry = {};
const items = [];
for (const n of collected) {
  const kept = (keptByCountry[n.c] ||= []);
  const words = sigWords(n.title);
  const dup = kept.some(k => norm(k.title) === norm(n.title) || jaccard(words, k.words) >= 0.7);
  if (dup) continue;
  kept.push({ title: n.title, words });
  items.push(n);
  if (items.length >= MAX_ITEMS) break;
}

const out = {
  generated: new Date().toISOString(),
  lookbackDays: LOOKBACK_DAYS,
  feeds: FEEDS.length,
  okFeeds: feedsStatus.filter(f => f.ok).length,
  count: items.length,
  feedsStatus: feedsStatus.sort((a, b) => a.name.localeCompare(b.name)),
  items,
};
await writeFile('data/news.json', JSON.stringify(out) + '\n');

console.log(report.sort().join('\n'));
console.log(`\nWrote news.json — ${items.length} items from ${FEEDS.length} feeds at ${out.generated}`);

// Append today's per-country counts to a small rolling archive (enables trend views later).
// One entry per UTC day (the last sync of the day wins), capped at 400 days.
try {
  let archive = { entries: [] };
  try { archive = JSON.parse(await readFile('data/archive.json', 'utf8')); } catch { /* start fresh */ }
  if (!Array.isArray(archive.entries)) archive.entries = [];
  const date = out.generated.slice(0, 10);
  const counts = { CN: 0, RU: 0, IR: 0, KP: 0 };
  for (const n of items) if (n.c in counts) counts[n.c]++;
  archive.entries = archive.entries.filter(e => e.date !== date);
  archive.entries.push({ date, total: items.length, okFeeds: out.okFeeds, counts });
  archive.entries.sort((a, b) => a.date.localeCompare(b.date));
  archive.entries = archive.entries.slice(-400);
  await writeFile('data/archive.json', JSON.stringify(archive) + '\n');
  console.log(`Archived ${date}: ${JSON.stringify(counts)} (${archive.entries.length} days retained)`);
} catch (e) {
  console.warn(`Archive update failed (non-fatal): ${e.message}`);
}

// CISA Known Exploited Vulnerabilities — a separate, general (not country-attributed) catalog.
// Isolated so a KEV fetch failure never affects news collection or the exit status.
try {
  const kevUrl = SOURCES.kevUrl || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const recent = SOURCES.kevRecent || 150;
  const kev = JSON.parse(await fetchText(kevUrl, 30000));
  const vulns = (kev.vulnerabilities || [])
    .slice()
    .sort((a, b) => String(b.dateAdded || '').localeCompare(String(a.dateAdded || '')))
    .slice(0, recent)
    .map(v => ({
      cve: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      added: v.dateAdded,
      due: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      description: (v.shortDescription || '').replace(/\s+/g, ' ').trim().slice(0, 400),
    }));
  const kevOut = {
    generated: new Date().toISOString(),
    source: 'CISA Known Exploited Vulnerabilities',
    catalogVersion: kev.catalogVersion || null,
    total: (kev.vulnerabilities || []).length,
    count: vulns.length,
    items: vulns,
  };
  await writeFile('data/kev.json', JSON.stringify(kevOut) + '\n');
  console.log(`Wrote kev.json — ${vulns.length} of ${kevOut.total} KEV entries (catalog ${kevOut.catalogVersion})`);
} catch (e) {
  console.warn(`KEV fetch failed (kev.json left unchanged): ${e.message}`);
}
