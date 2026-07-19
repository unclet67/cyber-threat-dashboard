// scripts/lib.mjs
// Pure logic shared by the collector (fetch-news.mjs) and the unit tests.
// No I/O here — everything is deterministic and testable.

export { buildClassifier, buildRelationshipClassifier, scoreArticle } from '../intel-model.mjs';

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

// ---- MITRE ATT&CK enterprise STIX reduction ----
// Input: the enterprise-attack STIX bundle. Output: compact groups -> techniques/software map.
export function reduceAttack(stix) {
  const objs = stix.objects || [];
  const alive = o => !o.revoked && !o.x_mitre_deprecated;
  const extId = o => ((o.external_references || []).find(r => r.source_name === 'mitre-attack') || {}).external_id || null;

  const groups = new Map();     // stix id -> {gid,name,aliases,techniques:[],software:[]}
  const techniques = new Map(); // stix id -> {id,name}
  const software = new Map();   // stix id -> {id,name,type}
  for (const o of objs) {
    if (!alive(o)) continue;
    if (o.type === 'intrusion-set') {
      const gid = extId(o); if (!gid) continue;
      groups.set(o.id, { gid, name: o.name, aliases: (o.aliases || []).filter(a => a !== o.name), techniques: [], software: [] });
    } else if (o.type === 'attack-pattern') {
      const id = extId(o); if (!id || o.x_mitre_is_subtechnique) continue; // parent techniques only, keeps output small
      techniques.set(o.id, { id, name: o.name });
    } else if (o.type === 'malware' || o.type === 'tool') {
      const id = extId(o); if (!id) continue;
      software.set(o.id, { id, name: o.name, type: o.type });
    }
  }
  for (const o of objs) {
    if (o.type !== 'relationship' || o.relationship_type !== 'uses' || (o.revoked || o.x_mitre_deprecated)) continue;
    const g = groups.get(o.source_ref); if (!g) continue;
    const t = techniques.get(o.target_ref);
    if (t) { if (!g.techniques.some(x => x.id === t.id)) g.techniques.push(t); continue; }
    const s = software.get(o.target_ref);
    if (s && !g.software.some(x => x.id === s.id)) g.software.push(s);
  }
  const out = [...groups.values()].filter(g => g.techniques.length || g.software.length);
  for (const g of out) { g.techniques.sort((a, b) => a.id.localeCompare(b.id)); g.software.sort((a, b) => a.name.localeCompare(b.name)); }
  return out.sort((a, b) => a.gid.localeCompare(b.gid));
}

// ---- EPSS CSV -> scores for a wanted set of CVEs ----
// CSV format: optional "#comment" lines, header "cve,epss,percentile", then rows.
export function parseEpssCsv(csv, wanted) {
  const want = wanted instanceof Set ? wanted : new Set(wanted);
  const out = {};
  for (const line of csv.split('\n')) {
    if (!line || line.startsWith('#') || line.startsWith('cve,')) continue;
    const [cve, epss, pct] = line.split(',');
    if (want.has(cve)) out[cve] = { epss: +epss, percentile: +pct };
  }
  return out;
}

// ---- IOC extraction (defanged output for hunting) ----
// Extracts hashes, IPv4s, CVEs always; domains/URLs only when the source defanged them
// (hxxp / [.] style) — a defanged token is an intentional indicator, a live link is not.
// NOTE: mirrored in app.js (classic script, cannot import) — keep the two in sync.
export function extractIocs(text) {
  const t = String(text || '');
  const uniq = a => [...new Set(a)];
  const sha256 = uniq(t.match(/\b[a-f0-9]{64}\b/gi) || []);
  const sha1 = uniq((t.match(/\b[a-f0-9]{40}\b/gi) || []).filter(h => !sha256.some(s => s.includes(h))));
  const md5 = uniq((t.match(/\b[a-f0-9]{32}\b/gi) || []).filter(h => !sha256.concat(sha1).some(s => s.includes(h))));
  const ips = uniq((t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(ip => ip.split('.').every(o => +o <= 255)));
  const cves = uniq((t.match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase()));
  const defanged = uniq([
    ...(t.match(/\bhxxps?:\/\/[^\s"'<>]+/gi) || []),
    ...(t.match(/\b(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,}\b/gi) || []).filter(d => d.includes('[.]')),
  ]);
  return { sha256, sha1, md5, ips, cves, defanged };
}

export function defang(ioc) {
  let s = String(ioc).replace(/^http(s?):\/\//i, 'hxxp$1://');
  if (!s.includes('[.]')) s = s.replace(/\./g, '[.]');
  return s;
}

// ---- RSS 2.0 emitter for the curated Big 4 stream ----
export const xmlEscape = s => String(s || '').replace(/[<>&'"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));
export function buildRss(items, { title, link, description }) {
  const toRfc822 = seen => {
    const s = String(seen || '');
    if (s.length < 8) return '';
    const d = new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10) || '00'}:${s.slice(10, 12) || '00'}:${s.slice(12, 14) || '00'}Z`);
    return isNaN(d) ? '' : d.toUTCString();
  };
  const entries = items.map(n => `  <item>
    <title>${xmlEscape(n.title)}</title>
    <link>${xmlEscape(n.url)}</link>
    <guid isPermaLink="true">${xmlEscape(n.url)}</guid>
    ${toRfc822(n.seendate) ? `<pubDate>${toRfc822(n.seendate)}</pubDate>` : ''}
    <category>${xmlEscape(n.c)}</category>
    <source url="${xmlEscape(n.url)}">${xmlEscape(n.sourceCountry || n.domain || '')}</source>
    ${n.summary ? `<description>${xmlEscape(n.summary)}</description>` : ''}
  </item>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>${xmlEscape(title)}</title>
  <link>${xmlEscape(link)}</link>
  <description>${xmlEscape(description)}</description>
${entries}
</channel></rss>
`;
}
