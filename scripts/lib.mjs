// scripts/lib.mjs
// Pure logic shared by the collector (fetch-news.mjs) and the unit tests.
// No I/O here — everything is deterministic and testable.

export const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function decode(s) {
  return (s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&nbsp;/gi, ' ')
    .replace(/&(?:rsquo|lsquo);/gi, "'").replace(/&(?:rdquo|ldquo);/gi, '"')
    .replace(/&mdash;/gi, '—').replace(/&ndash;/gi, '–').replace(/&hellip;/gi, '…')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, '&')
    .replace(/<[^>]+>/g, ' ')   // strip tags that arrived entity-encoded (&lt;p&gt; …)
    .replace(/\s+/g, ' ').trim();
}

export const tag = (block, name) => {
  const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1] : '';
};

export function extractLink(block) {
  // RSS: <link>URL</link>. Atom: self-closing <link rel="alternate" href="URL"/> among several rels.
  const rss = decode(tag(block, 'link'));
  if (rss && /^https?:/i.test(rss)) return rss;
  const alt = block.match(/<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i)
    || block.match(/<link[^>]*href=["']([^"']+)["'][^>]*rel=["']alternate["']/i);
  if (alt) return alt[1];
  const any = block.match(/<link[^>]*href=["']([^"']+)["']/i);
  return any ? any[1] : rss;
}

export function parseItems(xml) {
  const blocks = [...xml.matchAll(/<(item|entry)[\s\S]*?<\/\1>/gi)].map(m => m[0]);
  return blocks.map(b => ({
    title: decode(tag(b, 'title')),
    link: extractLink(b),
    date: decode(tag(b, 'pubDate') || tag(b, 'updated') || tag(b, 'published') || tag(b, 'dc:date') || tag(b, 'date')),
    desc: decode(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content')),
  }));
}

// Build the country classifier: strong terms match anywhere; ambiguous (weak) terms only in
// the title — avoids false positives like "MSS" (managed security services) tagging China.
export function buildClassifier(countries, weakTerms = []) {
  const WEAK = new Set(weakTerms);
  const rxFor = terms => terms.length ? new RegExp('\\b(' + terms.map(escapeRegex).join('|') + ')\\b', 'i') : null;
  const RX = Object.fromEntries(Object.entries(countries).map(([c, v]) => {
    const all = [v.name, ...v.terms];
    return [c, { strong: rxFor(all.filter(t => !WEAK.has(t))), weak: rxFor(all.filter(t => WEAK.has(t))) }];
  }));
  return (title, desc) => Object.keys(RX).filter(c => {
    const { strong, weak } = RX[c];
    return (strong && strong.test(`${title} ${desc}`)) || (weak && weak.test(title));
  });
}

// Fuzzy cross-outlet dedup helpers (same story, different headline/outlet).
const STOP = new Set(['the','and','for','with','from','over','into','that','this','their','have','has','says','new','amid','after','using','used']);
export const sigWords = t => new Set(t.toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter(w => w.length > 3 && !STOP.has(w)));
export const jaccard = (a, b) => { let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i || 1); };

export const norm = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '');
export const fmtSeen = d => d.toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
export const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return ''; } };

export async function runPool(items, limit, worker) {
  const q = items.slice();
  const run = async () => { while (q.length) await worker(q.shift()); };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 1 }, run));
}
