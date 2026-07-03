// tests/lib.test.mjs — run with `node --test tests/`
// Locks in behavior of the riskiest logic: feed parsing, country classification,
// fuzzy dedup, and the browser's URL sanitizer.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { decode, extractLink, parseItems, buildClassifier, sigWords, jaccard, norm, hostOf } from '../scripts/lib.mjs';

// ---------- feed parsing ----------

const RSS = `<?xml version="1.0"?><rss version="2.0"><channel>
  <item>
    <title><![CDATA[Salt Typhoon &amp; friends hit telecoms]]></title>
    <link>https://example.com/story-1</link>
    <pubDate>Wed, 02 Jul 2026 10:00:00 GMT</pubDate>
    <description>&lt;p&gt;A &quot;big&quot; espionage story &#8212; details inside.&lt;/p&gt;</description>
  </item>
  <item><title>No link item</title><description>orphan</description></item>
</channel></rss>`;

const ATOM = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom entry title</title>
    <link rel="self" href="https://example.com/self.xml"/>
    <link rel="alternate" href="https://example.com/article-42"/>
    <updated>2026-07-01T08:30:00Z</updated>
    <summary>Backdoor deployed via spear-phishing.</summary>
  </entry>
</feed>`;

test('parseItems handles RSS with CDATA, entities, and HTML stripping', () => {
  const items = parseItems(RSS);
  assert.equal(items.length, 2);
  assert.equal(items[0].title, 'Salt Typhoon & friends hit telecoms');
  assert.equal(items[0].link, 'https://example.com/story-1');
  assert.match(items[0].desc, /^A "big" espionage story/);
  assert.ok(!items[0].desc.includes('<p>'), 'HTML tags stripped');
});

test('parseItems picks the Atom rel=alternate link, not rel=self', () => {
  const items = parseItems(ATOM);
  assert.equal(items.length, 1);
  assert.equal(items[0].link, 'https://example.com/article-42');
  assert.equal(items[0].desc, 'Backdoor deployed via spear-phishing.');
  assert.equal(items[0].date, '2026-07-01T08:30:00Z');
});

test('extractLink falls back to any href when no alternate exists', () => {
  assert.equal(extractLink('<entry><link href="https://x.example/only"/></entry>'), 'https://x.example/only');
});

test('decode converts numeric and named entities, and strips entity-encoded tags', () => {
  assert.equal(decode('A&#8217;s &amp; B&#x27;s text'), 'A’s & B\'s text');
  assert.equal(decode('China&rsquo;s plan&nbsp;&mdash;&nbsp;detail &lt;p&gt;inside&lt;/p&gt;'), "China's plan — detail inside");
});

// ---------- country classification ----------

const COUNTRIES = {
  CN: { name: 'China', terms: ['Chinese', 'PLA', 'MSS', 'Salt Typhoon'] },
  RU: { name: 'Russia', terms: ['Russian', 'GRU', 'Sandworm'] },
};
const classify = buildClassifier(COUNTRIES, ['PLA', 'MSS', 'GRU']);

test('strong terms match in title or body', () => {
  assert.deepEqual(classify('New campaign', 'linked to Salt Typhoon activity'), ['CN']);
  assert.deepEqual(classify('Sandworm wipes systems', ''), ['RU']);
});

test('weak terms match only in the title (MSS false-positive guard)', () => {
  assert.deepEqual(classify('Vendor expands offerings', 'our MSS and SOC services grew'), []);
  assert.deepEqual(classify('MSS-linked intrusion set exposed', ''), ['CN']);
});

test('multi-country stories tag every matching country', () => {
  assert.deepEqual(classify('Chinese and Russian actors target grid', ''), ['CN', 'RU']);
});

test('whole-word matching: no substring hits', () => {
  assert.deepEqual(classify('Graduate students research plasma', ''), []);
});

// ---------- fuzzy dedup ----------

test('jaccard on significant words flags same-story headlines', () => {
  const a = sigWords('Russian Attackers Weaponize WinRAR Flaw Against Ukrainian Orgs');
  const b = sigWords('Russian attackers weaponize WinRAR flaw against Ukrainian organizations today');
  assert.ok(jaccard(a, b) >= 0.7, `expected >=0.7, got ${jaccard(a, b)}`);
  const c = sigWords('Iranian group claims water utility hack');
  assert.ok(jaccard(a, c) < 0.3);
});

test('norm collapses punctuation and case for exact-dup detection', () => {
  assert.equal(norm("APT41's 'Double-Dragon' Campaign!"), norm('apt41s double dragon campaign'));
});

test('hostOf strips www and tolerates garbage', () => {
  assert.equal(hostOf('https://www.example.com/a/b'), 'example.com');
  assert.equal(hostOf('not a url'), '');
});

// ---------- browser URL sanitizer (extracted from app.js) ----------

test('app.js safeUrl blocks non-http(s) schemes and escapes quotes', () => {
  const appSrc = readFileSync(new URL('../app.js', import.meta.url), 'utf8');
  const ctx = {};
  vm.createContext(ctx);
  const lines = appSrc.split('\n');
  const esc = lines.find(l => l.startsWith('function escapeHtml('));
  const su = lines.find(l => l.startsWith('function safeUrl('));
  assert.ok(esc && su, 'escapeHtml/safeUrl found in app.js');
  vm.runInContext(esc + '\n' + su, ctx);
  const safeUrl = vm.runInContext('safeUrl', ctx);
  assert.equal(safeUrl('https://ok.example/a'), 'https://ok.example/a');
  assert.equal(safeUrl('javascript:alert(1)'), '');
  assert.equal(safeUrl('data:text/html,x'), '');
  assert.ok(!safeUrl('https://evil.example/" onmouseover="x').includes('"'), 'quotes escaped');
});
