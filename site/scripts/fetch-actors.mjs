#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

const URLS = {
  misp: "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
  microsoft: "https://raw.githubusercontent.com/microsoft/mstic/master/PublicFeeds/ThreatActorNaming/MicrosoftMapping.json",
  google: "https://cloud.google.com/security/resources/insights/apt-groups",
  mitre: "https://attack.mitre.org/groups/",
};

const ORIGIN_CODES = new Map(Object.entries({
  Australia: "AU", Canada: "CA", China: "CN", Germany: "DE", India: "IN", Iran: "IR",
  Israel: "IL", Lebanon: "LB", "New Zealand": "NZ", "North Korea": "KP", Pakistan: "PK",
  Russia: "RU", Singapore: "SG", "South Korea": "KR", Spain: "ES", Syria: "SY", Turkey: "TR",
  Türkiye: "TR", Ukraine: "UA", "United Arab Emirates": "AE", "United Kingdom": "GB",
  "United States": "US", Vietnam: "VN", Belarus: "BY", Palestine: "PS", "Palestinian Authority": "PS",
}));

const displayNames = new Intl.DisplayNames(["en"], { type: "region" });
const clean = (value) => String(value || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
const norm = (value) => clean(value).toLowerCase().replace(/[^a-z0-9]+/g, "");
const unique = (values) => [...new Set(values.map(clean).filter(Boolean))];
const splitNames = (value) => unique(String(value || "").split(/[,;]\s*/));

function codeFromOrigin(origin = "") {
  for (const [name, code] of ORIGIN_CODES) if (origin.toLowerCase().includes(name.toLowerCase())) return code;
  return "UN";
}

function originFromCode(code, fallback = "") {
  if (fallback) return clean(fallback);
  try { return code && code !== "UN" ? displayNames.of(code) || code : "Unknown / unattributed"; }
  catch { return code || "Unknown / unattributed"; }
}

async function fetchText(url) {
  const response = await fetch(url, { headers: { "user-agent": "Cyber-Threat-Dashboard/1.0" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}: ${url}`);
  return response.text();
}

async function sourceText(cacheName, url) {
  if (process.env.ACTOR_SOURCE_DIR) return readFile(`${process.env.ACTOR_SOURCE_DIR}/${cacheName}`, "utf8");
  return fetchText(url);
}

const attack = JSON.parse(await readFile(new URL("../public/data/attack.json", import.meta.url), "utf8"));
const [misp, microsoft, googleHtml] = await Promise.all([
  sourceText("misp-threat-actor.json", URLS.misp).then(JSON.parse),
  sourceText("microsoft-mapping.json", URLS.microsoft).then(JSON.parse),
  sourceText("google-apt-groups.html", URLS.google),
]);

const records = [];

for (const item of misp.values || []) {
  const meta = item.meta || {};
  const rawCode = Array.isArray(meta.country) ? meta.country[0] : meta.country;
  const sponsor = Array.isArray(meta["cfr-suspected-state-sponsor"]) ? meta["cfr-suspected-state-sponsor"][0] : meta["cfr-suspected-state-sponsor"];
  const code = clean(rawCode).toUpperCase() || codeFromOrigin(clean(sponsor));
  records.push({
    name: item.value,
    aliases: meta.synonyms || [],
    countryCode: code || "UN",
    origin: originFromCode(code, clean(sponsor)),
    description: clean(item.description),
    refs: meta.refs || [],
    sources: ["MISP Galaxy"],
    techniques: [], software: [], gid: "",
  });
}

for (const item of microsoft || []) {
  const origin = clean(item["Origin/Threat"]);
  records.push({
    name: item["Threat actor name"],
    aliases: splitNames(item["Other names"]),
    countryCode: codeFromOrigin(origin),
    origin: origin || "Unknown / unattributed",
    description: `Microsoft threat actor profile. Origin or category: ${origin || "not publicly attributed"}.`,
    refs: ["https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming"],
    sources: ["Microsoft Threat Intelligence"],
    techniques: [], software: [], gid: "",
  });
}

for (const group of attack.groups || []) {
  records.push({
    name: group.name,
    aliases: group.aliases || [],
    countryCode: "UN",
    origin: "Unknown / unattributed",
    description: "",
    refs: [`https://attack.mitre.org/groups/${group.gid}/`],
    sources: ["MITRE ATT&CK"],
    techniques: group.techniques || [],
    software: group.software || [],
    gid: group.gid,
  });
}

const googleApts = [...googleHtml.matchAll(/\bAPT\s?(\d{1,3})\b/gi)].map((match) => `APT${Number(match[1])}`);
for (const name of unique(googleApts)) records.push({
  name, aliases: [], countryCode: "UN", origin: "Unknown / unattributed", description: "",
  refs: [URLS.google], sources: ["Google Threat Intelligence / Mandiant"], techniques: [], software: [], gid: "",
});

const parent = records.map((_, index) => index);
const find = (index) => parent[index] === index ? index : (parent[index] = find(parent[index]));
const union = (a, b) => { const ra = find(a); const rb = find(b); if (ra !== rb) parent[rb] = ra; };
const nameIndex = new Map();
const ignored = new Set(["unknown", "threatactor", "apt", "group"]);

records.forEach((record, index) => {
  for (const value of [record.name, ...record.aliases]) {
    const key = norm(value);
    if (key.length < 4 || ignored.has(key)) continue;
    if (nameIndex.has(key)) union(index, nameIndex.get(key)); else nameIndex.set(key, index);
  }
});

const clusters = new Map();
records.forEach((record, index) => {
  const root = find(index);
  if (!clusters.has(root)) clusters.set(root, []);
  clusters.get(root).push(record);
});

const sourceRank = (record) => record.sources.includes("MITRE ATT&CK") ? 0 : record.sources.includes("MISP Galaxy") ? 1 : record.sources.includes("Microsoft Threat Intelligence") ? 2 : 3;
const items = [...clusters.values()].map((cluster) => {
  const ordered = [...cluster].sort((a, b) => sourceRank(a) - sourceRank(b));
  const canonical = ordered[0];
  const attributed = ordered.find((record) => record.countryCode && record.countryCode !== "UN");
  const described = [...ordered].sort((a, b) => b.description.length - a.description.length)[0];
  const enriched = ordered.find((record) => record.gid) || canonical;
  const allNames = unique(ordered.flatMap((record) => [record.name, ...record.aliases]));
  return {
    gid: enriched.gid || "",
    name: clean(canonical.name),
    aliases: allNames.filter((name) => norm(name) !== norm(canonical.name)).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true })),
    countryCode: attributed?.countryCode || "UN",
    origin: attributed?.origin || "Unknown / unattributed",
    description: described.description,
    sources: unique(ordered.flatMap((record) => record.sources)),
    refs: unique(ordered.flatMap((record) => record.refs)).filter((ref) => /^https?:\/\//i.test(ref)).slice(0, 20),
    techniques: enriched.techniques || [],
    software: enriched.software || [],
  };
}).filter((item) => item.name && norm(item.name) !== "unnamedgroup").sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base", numeric: true }));

const output = {
  generated: new Date().toISOString(),
  count: items.length,
  methodology: "Exact normalized-name and alias reconciliation across public source records. Similarity-only relationships are not automatically merged.",
  caveat: "No public catalog is exhaustive. Vendor clusters can overlap, split, or reflect different confidence thresholds; attribution remains probabilistic.",
  sources: [
    { name: "MISP Galaxy", url: URLS.misp, records: (misp.values || []).length },
    { name: "MITRE ATT&CK", url: URLS.mitre, records: (attack.groups || []).length },
    { name: "Microsoft Threat Intelligence", url: URLS.microsoft, records: (microsoft || []).length },
    { name: "Google Threat Intelligence / Mandiant", url: URLS.google, records: unique(googleApts).length },
  ],
  items,
};

await writeFile(new URL("../public/data/actors.json", import.meta.url), `${JSON.stringify(output)}\n`);
console.log(`Wrote actors.json — ${items.length} deduplicated actors from ${records.length} source records`);
console.log(output.sources.map((source) => `${source.name}: ${source.records}`).join(" · "));
