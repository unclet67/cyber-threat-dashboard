// scripts/fetch-news.mjs
// Server-side news collector for the Big 4 Cyber & Information Warfare dashboard.
// Runs in GitHub Actions (Node 20+), where there is no CORS/proxy constraint:
// it fetches the cyber-security RSS/Atom feeds directly, keeps items mentioning
// China, Russia, Iran, or North Korea, and writes news.json for the dashboard to
// read same-origin. Countries and feeds come from data/sources.json (single source
// of truth shared with the browser UI).

import { readFile, writeFile } from 'node:fs/promises';

const SOURCES = JSON.parse(await readFile(new URL('../data/sources.json', import.meta.url), 'utf8'));
const COUNTRIES = SOURCES.countries;
const FEEDS = SOURCES.feeds.map(f => [f.name, f.url]);

const LOOKBACK_DAYS = 30;   // keep items published within this window
const MAX_ITEMS = 500;      // cap output size
const CONCURRENCY = 6;

const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const WEAK = new Set(SOURCES.weakTerms || []);
const rxFor = terms => terms.length ? new RegExp('\\b(' + terms.map(escapeRegex).join('|') + ')\\b', 'i') : null;
const COUNTRY_RX = Object.fromEntries(Object.entries(COUNTRIES).map(([c, v]) => {
  const all = [v.name, ...v.terms];
  return [c, { strong: rxFor(all.filter(t => !WEAK.has(t))), weak: rxFor(all.filter(t => WEAK.has(t))) }];
}));
// A country matches on a strong term anywhere, or an ambiguous (weak) term only in the title —
// this avoids false positives like "MSS" (managed security services) tagging China from body text.
const classify = (title, desc) => Object.keys(COUNTRY_RX).filter(c => {
  const { strong, weak } = COUNTRY_RX[c];
  return (strong && strong.test(`${title} ${desc}`)) || (weak && weak.test(title));
});

function decode(s) {
  return (s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ').trim();
}

const tag = (block, name) => {
  const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1] : '';
};

function extractLink(block) {
  // RSS: <link>URL</link>. Atom: self-closing <link rel="alternate" href="URL"/> among several rels.
  const rss = decode(tag(block, 'link'));
  if (rss && /^https?:/i.test(rss)) return rss;
  const alt = block.match(/<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i)
    || block.match(/<link[^>]*href=["']([^"']+)["'][^>]*rel=["']alternate["']/i);
  if (alt) return alt[1];
  const any = block.match(/<link[^>]*href=["']([^"']+)["']/i);
  return any ? any[1] : rss;
}

function parseItems(xml) {
  const blocks = [...xml.matchAll(/<(item|entry)[\s\S]*?<\/\1>/gi)].map(m => m[0]);
  return blocks.map(b => ({
    title: decode(tag(b, 'title')),
    link: extractLink(b),
    date: decode(tag(b, 'pubDate') || tag(b, 'updated') || tag(b, 'published') || tag(b, 'dc:date') || tag(b, 'date')),
    desc: decode(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content')),
  }));
}

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

async function runPool(items, limit, worker) {
  const q = items.slice();
  const run = async () => { while (q.length) await worker(q.shift()); };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 1 }, run));
}

const fmtSeen = d => d.toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return ''; } };
const norm = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '');

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

// Significant-word sets for fuzzy, cross-outlet dedup (same story, different headline/outlet).
const STOP = new Set(['the','and','for','with','from','over','into','that','this','their','have','has','says','new','amid','after','using','used']);
const sigWords = t => new Set(t.toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter(w => w.length > 3 && !STOP.has(w)));
const jaccard = (a, b) => { let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i || 1); };

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
await writeFile('news.json', JSON.stringify(out) + '\n');

console.log(report.sort().join('\n'));
console.log(`\nWrote news.json — ${items.length} items from ${FEEDS.length} feeds at ${out.generated}`);

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
  await writeFile('kev.json', JSON.stringify(kevOut) + '\n');
  console.log(`Wrote kev.json — ${vulns.length} of ${kevOut.total} KEV entries (catalog ${kevOut.catalogVersion})`);
} catch (e) {
  console.warn(`KEV fetch failed (kev.json left unchanged): ${e.message}`);
}
