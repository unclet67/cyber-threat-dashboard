// scripts/fetch-news.mjs
// Server-side news collector for the Big 4 Cyber & Information Warfare dashboard.
// Runs in GitHub Actions (Node 20+), where there is no CORS/proxy constraint:
// it fetches the cyber-security RSS/Atom feeds directly, keeps items mentioning
// China, Russia, Iran, or North Korea, and writes news.json for the dashboard to
// read same-origin. The feed list and country terms mirror index.html — keep in sync.

import { writeFile } from 'node:fs/promises';

const COUNTRIES = {
  CN: { name: 'China', terms: ['China','PRC','Chinese','Beijing','PLA','MSS','Salt Typhoon','Volt Typhoon','Flax Typhoon','APT41','APT40','Mustang Panda','Storm-0558'] },
  RU: { name: 'Russia', terms: ['Russia','Russian','Moscow','GRU','SVR','FSB','Sandworm','APT28','APT29','Fancy Bear','Cozy Bear','Gamaredon','Turla','Star Blizzard'] },
  IR: { name: 'Iran', terms: ['Iran','Iranian','Tehran','IRGC','MOIS','APT33','APT34','APT35','APT42','MuddyWater','OilRig','Charming Kitten','CyberAv3ngers'] },
  KP: { name: 'North Korea', terms: ['North Korea','DPRK','Lazarus','Kimsuky','APT38','APT37','APT43','Andariel','Bluenoroff','Emerald Sleet','Diamond Sleet'] },
};

const FEEDS = [
  // Cyber-security press
  ['The Hacker News', 'https://thehackernews.com/feeds/posts/default'],
  ['BleepingComputer', 'https://www.bleepingcomputer.com/feed/'],
  ['Krebs on Security', 'https://krebsonsecurity.com/feed/'],
  ['CyberScoop', 'https://cyberscoop.com/feed/'],
  ['SecurityWeek', 'https://www.securityweek.com/feed/atom/'],
  ['Dark Reading', 'https://www.darkreading.com/rss.xml'],
  ['The Record (Recorded Future)', 'https://therecord.media/feed/'],
  ['Help Net Security', 'https://www.helpnetsecurity.com/feed/'],
  ['The Register — Security', 'https://www.theregister.com/security/headlines.atom'],
  ['WIRED — Security', 'https://www.wired.com/feed/category/security/latest/rss'],
  ['SANS Internet Storm Center', 'https://isc.sans.edu/rssfeed_full.xml'],
  ['CISA Advisories', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'],
  // Vendor threat-research blogs
  ['Microsoft Security Blog', 'https://www.microsoft.com/en-us/security/blog/feed/'],
  ['Cisco Talos', 'https://blog.talosintelligence.com/feeds/posts/default?alt=rss'],
  ['Palo Alto Unit 42', 'https://unit42.paloaltonetworks.com/feed/'],
  ['Unit 42 — Threat Research', 'https://unit42.paloaltonetworks.com/category/threat-research/feed/'],
  ['CrowdStrike Blog', 'https://www.crowdstrike.com/blog/feed/'],
  ['SentinelOne Blog', 'https://www.sentinelone.com/blog/feed/'],
  ['ESET WeLiveSecurity', 'https://feeds.feedburner.com/eset/blog'],
  ['Kaspersky Securelist', 'https://securelist.com/feed/'],
  ['Check Point Research', 'https://research.checkpoint.com/feed/'],
  ['Fortinet Threat Research', 'https://www.fortinet.com/blog/threat-research/rss.xml'],
  ['Trend Micro Research', 'http://feeds.trendmicro.com/Anti-MalwareBlog/'],
  ['Proofpoint Threat Insight', 'https://www.proofpoint.com/us/threat-insight-blog.xml'],
];

const LOOKBACK_DAYS = 30;   // keep items published within this window
const MAX_ITEMS = 500;      // cap output size
const CONCURRENCY = 6;

const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const COUNTRY_RX = Object.fromEntries(Object.entries(COUNTRIES).map(([c, v]) =>
  [c, new RegExp('\\b(' + [v.name, ...v.terms].map(escapeRegex).join('|') + ')\\b', 'i')]));
const classify = text => Object.keys(COUNTRY_RX).filter(c => COUNTRY_RX[c].test(text));

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

await runPool(FEEDS, CONCURRENCY, async ([name, url]) => {
  try {
    const items = parseItems(await fetchText(url));
    let kept = 0;
    for (const it of items) {
      if (!it.title || !it.link) continue;
      const dt = it.date ? new Date(it.date) : null;
      const valid = dt && !isNaN(dt);
      if (valid && dt.getTime() < cutoff) continue;
      const codes = classify(`${it.title} ${it.desc}`);
      if (!codes.length) continue;
      const seendate = valid ? fmtSeen(dt) : '';
      for (const c of codes) {
        collected.push({ title: it.title, url: it.link, domain: hostOf(it.link), seendate, sourceCountry: name, c });
        kept++;
      }
    }
    report.push(`ok    ${name} — ${items.length} items, ${kept} kept`);
  } catch (e) {
    report.push(`FAIL  ${name} — ${e.message}`);
  }
});

// Newest first, dedup by country + normalized title, cap size.
collected.sort((a, b) => String(b.seendate).localeCompare(String(a.seendate)));
const seen = new Set();
const items = [];
for (const n of collected) {
  const key = n.c + '|' + norm(n.title);
  if (seen.has(key)) continue;
  seen.add(key);
  items.push(n);
  if (items.length >= MAX_ITEMS) break;
}

const out = {
  generated: new Date().toISOString(),
  lookbackDays: LOOKBACK_DAYS,
  feeds: FEEDS.length,
  count: items.length,
  items,
};
await writeFile('news.json', JSON.stringify(out) + '\n');

console.log(report.sort().join('\n'));
console.log(`\nWrote news.json — ${items.length} items from ${FEEDS.length} feeds at ${out.generated}`);
