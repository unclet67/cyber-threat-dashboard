"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type CountryCode = "CN" | "RU" | "IR" | "KP";
type Tab = "overview" | "intel" | "actors" | "kev" | "workbench";
type ActorSortKey = "country" | "name";
type KevSortKey = "cve" | "vendor" | "added" | "due" | "epss";
type DataMode = "live" | "partial" | "snapshot";
type NewsItem = { title: string; url: string; domain: string; seendate: string; sourceCountry: string; c: CountryCode; summary: string };
type Actor = { gid: string; name: string; aliases: string[]; countryCode: string; origin: string; description: string; sources: string[]; refs: string[]; techniques: { id: string; name: string }[]; software: { id: string; name: string; type: string }[] };
type Kev = { cve: string; vendor: string; product: string; name: string; added: string; due: string; ransomware: boolean; description: string };
type Trend = { date: string; total: number; okFeeds: number; counts: Record<CountryCode, number> };
type FeedStatus = { name: string; ok: boolean; items: number; kept: number };
type EpssScore = { epss: number; percentile: number };
type ActorCveGroup = { names: string[]; cves: { id: string; product: string; note: string }[] };
type Country = { name: string; flag: string; short: string; terms: string[]; focus: string };
type DiamondModel = { id: string; storyUrl: string; title: string; adversary: string; capability: string; infrastructure: string; victim: string; phase: string; direction: string; result: string; confidence: string; evidence: string; assumptions: string; gaps: string; notes: string; createdAt: string };

const ORDER: CountryCode[] = ["CN", "RU", "IR", "KP"];
const UPSTREAM_DATA = "https://raw.githubusercontent.com/unclet67/cyber-threat-dashboard/main/data";
const COLORS: Record<CountryCode, string> = { CN: "#ef5b61", RU: "#7694ff", IR: "#38c899", KP: "#d69b42" };
const fallbackCountries: Record<CountryCode, Country> = {
  CN: { name: "China", flag: "🇨🇳", short: "PRC", terms: ["China", "APT41", "Volt Typhoon", "Salt Typhoon", "Mustang Panda"], focus: "Telecom, critical infrastructure, strategic espionage, IP theft, and influence activity." },
  RU: { name: "Russia", flag: "🇷🇺", short: "Russia", terms: ["Russia", "APT28", "APT29", "Sandworm", "Turla", "Gamaredon"], focus: "Disruptive operations, NATO targeting, wartime cyber effects, and hack-and-leak activity." },
  IR: { name: "Iran", flag: "🇮🇷", short: "Iran", terms: ["Iran", "APT33", "APT34", "APT35", "MuddyWater", "OilRig"], focus: "Regional espionage, wipers, hack-and-leak operations, and ransomware enablement." },
  KP: { name: "North Korea", flag: "🇰🇵", short: "DPRK", terms: ["North Korea", "Lazarus", "APT38", "APT37", "Kimsuky", "Andariel"], focus: "Cryptocurrency theft, defense espionage, IT-worker schemes, and sanctions evasion." },
};

function parseDate(value: string) {
  if (/^\d{14}$/.test(value)) return new Date(`${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`);
  return new Date(value);
}

function relativeDate(value: string) {
  const days = Math.max(0, Math.round((Date.now() - parseDate(value).getTime()) / 86_400_000));
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return `${days} days ago`;
}

function actorCountry(actor: Actor, countries: Record<CountryCode, Country>): string {
  if (actor.countryCode && actor.countryCode !== "UN") return actor.countryCode;
  const haystack = `${actor.name} ${actor.aliases.join(" ")}`.toLowerCase();
  for (const code of ORDER) {
    if (countries[code].terms.some((term) => term.length > 3 && haystack.includes(term.toLowerCase()))) return code;
  }
  return "UN";
}

function actorBadgeClass(code: string) {
  return ORDER.includes(code as CountryCode) ? `badge-${code.toLowerCase()}` : "badge-other";
}

function hostname(value: string) {
  try { return new URL(value).hostname.replace("www.", ""); }
  catch { return "Source"; }
}

const blankDiamond = (): DiamondModel => ({ id: "", storyUrl: "", title: "", adversary: "", capability: "", infrastructure: "", victim: "", phase: "Unknown", direction: "Unknown", result: "Unknown", confidence: "Moderate", evidence: "", assumptions: "", gaps: "", notes: "", createdAt: "" });

function scoreNews(item: NewsItem, kev: Kev[], now: number) {
  const ageDays = Math.max(0, Math.floor((now - parseDate(item.seendate).getTime()) / 86_400_000));
  const text = `${item.title} ${item.summary}`.toLowerCase();
  const reasons: string[] = [];
  let score = ageDays === 0 ? 30 : ageDays <= 2 ? 24 : ageDays <= 7 ? 16 : 8;
  if (ageDays <= 2) reasons.push("recent reporting");
  const highImpact = [["zero-day", 22, "zero-day activity"], ["ransomware", 18, "ransomware activity"], ["wiper", 20, "destructive effects"], ["critical infrastructure", 18, "critical-infrastructure targeting"], ["actively exploited", 18, "active exploitation"], ["supply chain", 15, "supply-chain exposure"]] as const;
  for (const [needle, points, label] of highImpact) if (text.includes(needle)) { score += points; reasons.push(label); }
  const cves = text.match(/CVE-\d{4}-\d{4,7}/gi)?.map((x) => x.toUpperCase()) || [];
  if (cves.some((cve) => kev.some((entry) => entry.cve === cve))) { score += 22; reasons.push("CISA KEV match"); }
  if (/cisa|ncsc|microsoft|unit 42|talos|mandiant|google threat/i.test(item.sourceCountry)) { score += 10; reasons.push("high-confidence source"); }
  return { score: Math.min(100, score), riskReasons: [...new Set(reasons)].slice(0, 3) };
}

function downloadJson(filename: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function inferredCapability(text: string) {
  const values = [...new Set([...(text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((x) => x.toUpperCase()), ...[
    ["phish", "Phishing / social engineering"], ["ransomware", "Ransomware"], ["wiper", "Destructive malware / wiper"],
    ["credential", "Credential access"], ["exploit", "Vulnerability exploitation"], ["malware", "Malware deployment"],
    ["ddos", "Distributed denial of service"], ["supply chain", "Supply-chain compromise"],
  ].filter(([needle]) => text.toLowerCase().includes(needle)).map(([, label]) => label)])];
  return values.join("; ");
}

function inferredVictim(text: string) {
  const sectors = [["telecom", "Telecommunications"], ["government", "Government"], ["defense", "Defense industrial base"], ["energy", "Energy"], ["health", "Healthcare"], ["university", "Higher education"], ["financial", "Financial services"], ["crypto", "Cryptocurrency / blockchain"], ["critical infrastructure", "Critical infrastructure"]];
  return [...new Set(sectors.filter(([needle]) => text.toLowerCase().includes(needle)).map(([, label]) => label))].join("; ");
}

export default function Home() {
  const [tab, setTab] = useState<Tab>("overview");
  const [country, setCountry] = useState<CountryCode | "ALL">("ALL");
  const [query, setQuery] = useState("");
  const [countries, setCountries] = useState<Record<CountryCode, Country>>(fallbackCountries);
  const [news, setNews] = useState<NewsItem[]>([]);
  const [actors, setActors] = useState<Actor[]>([]);
  const [kev, setKev] = useState<Kev[]>([]);
  const [trends, setTrends] = useState<Trend[]>([]);
  const [feedStatus, setFeedStatus] = useState<FeedStatus[]>([]);
  const [epssScores, setEpssScores] = useState<Record<string, EpssScore>>({});
  const [actorCveGroups, setActorCveGroups] = useState<ActorCveGroup[]>([]);
  const [generated, setGenerated] = useState("");
  const [loading, setLoading] = useState(true);
  const [dataMode, setDataMode] = useState<DataMode>("snapshot");
  const [pins, setPins] = useState<string[]>([]);
  const [selectedActor, setSelectedActor] = useState<Actor | null>(null);
  const [actorSort, setActorSort] = useState<{ key: ActorSortKey; direction: "asc" | "desc" }>({ key: "name", direction: "asc" });
  const [kevSort, setKevSort] = useState<{ key: KevSortKey; direction: "asc" | "desc" }>({ key: "epss", direction: "desc" });
  const [kevRansomwareOnly, setKevRansomwareOnly] = useState(false);
  const [kevDueFilter, setKevDueFilter] = useState<"all" | "overdue" | "soon">("all");
  const [minRisk, setMinRisk] = useState(0);
  const [intelSort, setIntelSort] = useState<"newest" | "risk">("newest");
  const [diamond, setDiamond] = useState<DiamondModel>(blankDiamond);
  const [savedDiamonds, setSavedDiamonds] = useState<DiamondModel[]>([]);
  const [watchlists, setWatchlists] = useState<string[]>([]);
  const [newWatch, setNewWatch] = useState("");
  const [storageMode, setStorageMode] = useState<"syncing" | "durable" | "local">("syncing");
  const [notice, setNotice] = useState("");
  const [now, setNow] = useState(() => Date.now());

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const stamp = Date.now();
      const fetchDataset = async (name: string, live = true) => {
        if (live) {
          try {
            const response = await fetch(`${UPSTREAM_DATA}/${name}?t=${stamp}`, { cache: "no-store" });
            if (response.ok) return { data: await response.json(), live: true };
          } catch { /* Fall back to the version bundled with the Site. */ }
        }
        const response = await fetch(`/data/${name}?t=${stamp}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`Unable to load ${name}`);
        return { data: await response.json(), live: false };
      };
      const [newsResult, actorResult, kevResult, trendResult, sourceResult, epssResult, actorCveResult] = await Promise.all([
        fetchDataset("news.json"),
        fetchDataset("actors.json", false),
        fetchDataset("kev.json"),
        fetchDataset("archive.json"),
        fetchDataset("sources.json"),
        fetchDataset("epss.json"),
        fetchDataset("actor-cves.json", false),
      ]);
      const n = newsResult.data;
      const a = actorResult.data;
      const k = kevResult.data;
      const t = trendResult.data;
      const s = sourceResult.data;
      setNews(n.items || []);
      setActors(a.items || []);
      setKev(k.items || []);
      setTrends(t.entries || []);
      setCountries(s.countries || fallbackCountries);
      setFeedStatus(n.feedsStatus || []);
      setEpssScores(epssResult.data.scores || {});
      setActorCveGroups(actorCveResult.data.actors || []);
      setGenerated(n.generated || "");
      setNow(Date.now());
      const liveResults = [newsResult, kevResult, trendResult, sourceResult, epssResult].filter((result) => result.live).length;
      setDataMode(liveResults === 5 ? "live" : liveResults === 0 ? "snapshot" : "partial");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const startup = window.setTimeout(() => {
      loadData();
      try { setPins(JSON.parse(localStorage.getItem("ctd-pins") || "[]")); } catch { /* local-only preference */ }
      try { setSavedDiamonds(JSON.parse(localStorage.getItem("ctd-diamonds") || "[]")); } catch { /* local-only preference */ }
      try { setWatchlists(JSON.parse(localStorage.getItem("ctd-watchlists") || "[]")); } catch { /* local-only preference */ }
    }, 0);
    const refreshInterval = window.setInterval(loadData, 15 * 60 * 1000);
    const refreshOnFocus = () => { if (document.visibilityState === "visible") loadData(); };
    document.addEventListener("visibilitychange", refreshOnFocus);
    return () => {
      window.clearTimeout(startup);
      window.clearInterval(refreshInterval);
      document.removeEventListener("visibilitychange", refreshOnFocus);
    };
  }, [loadData]);

  useEffect(() => {
    const loadWorkspace = async () => {
      try {
        const response = await fetch("/api/workbench", { cache: "no-store" });
        if (!response.ok) throw new Error("durable storage unavailable");
        const payload = await response.json();
        if (Array.isArray(payload.state?.pins)) setPins(payload.state.pins);
        if (Array.isArray(payload.state?.watchlists)) setWatchlists(payload.state.watchlists);
        if (Array.isArray(payload.state?.diamonds)) setSavedDiamonds(payload.state.diamonds.map((item: Partial<DiamondModel>) => ({ ...blankDiamond(), ...item })));
        setStorageMode("durable");
      } catch { setStorageMode("local"); }
    };
    loadWorkspace();
  }, []);

  useEffect(() => {
    if (!selectedActor) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setSelectedActor(null); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [selectedActor]);

  const persistWorkspace = useCallback(async (key: "pins" | "watchlists" | "diamonds", value: unknown) => {
    localStorage.setItem(`ctd-${key}`, JSON.stringify(value));
    try {
      const response = await fetch("/api/workbench", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ key, value }) });
      if (!response.ok) throw new Error("save failed");
      setStorageMode("durable");
    } catch { setStorageMode("local"); }
  }, []);

  const flash = useCallback((message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 2400);
  }, []);

  const classifiedActors = useMemo(() => actors.map((actor) => ({ actor, c: actorCountry(actor, countries) })), [actors, countries]);
  const q = query.trim().toLowerCase();
  const scoredNews = useMemo(() => news.map((item) => ({ ...item, ...scoreNews(item, kev, now) })), [news, kev, now]);
  const priorityNews = useMemo(() => [...scoredNews].sort((a, b) => b.score - a.score || parseDate(b.seendate).getTime() - parseDate(a.seendate).getTime()), [scoredNews]);
  const filteredNews = useMemo(() => scoredNews.filter((item) => item.score >= minRisk && (country === "ALL" || item.c === country) && (!q || `${item.title} ${item.summary} ${item.sourceCountry}`.toLowerCase().includes(q))).sort((a, b) => intelSort === "risk" ? b.score - a.score || parseDate(b.seendate).getTime() - parseDate(a.seendate).getTime() : parseDate(b.seendate).getTime() - parseDate(a.seendate).getTime() || b.score - a.score), [scoredNews, country, q, minRisk, intelSort]);
  const filteredActors = useMemo(() => classifiedActors.filter(({ actor, c }) => (country === "ALL" || c === country) && (!q || `${actor.name} ${actor.aliases.join(" ")} ${actor.origin} ${actor.description} ${actor.sources.join(" ")} ${actor.techniques.map((x) => x.name).join(" ")}`.toLowerCase().includes(q))), [classifiedActors, country, q]);
  const filteredKev = useMemo(() => kev.filter((item) => !q || `${item.cve} ${item.vendor} ${item.product} ${item.name}`.toLowerCase().includes(q)), [kev, q]);
  const displayedKev = useMemo(() => filteredKev.filter((item) => {
    if (kevRansomwareOnly && !item.ransomware) return false;
    const daysUntilDue = Math.ceil((new Date(`${item.due}T23:59:59Z`).getTime() - now) / 86_400_000);
    if (kevDueFilter === "overdue" && daysUntilDue >= 0) return false;
    if (kevDueFilter === "soon" && (daysUntilDue < 0 || daysUntilDue > 14)) return false;
    return true;
  }).sort((a, b) => {
    const values = {
      cve: [a.cve, b.cve], vendor: [a.vendor, b.vendor], added: [a.added, b.added], due: [a.due, b.due],
      epss: [epssScores[a.cve]?.epss || 0, epssScores[b.cve]?.epss || 0],
    }[kevSort.key];
    const result = typeof values[0] === "number" ? Number(values[0]) - Number(values[1]) : String(values[0]).localeCompare(String(values[1]), undefined, { numeric: true });
    return kevSort.direction === "asc" ? result : -result;
  }), [filteredKev, kevRansomwareOnly, kevDueFilter, kevSort, epssScores, now]);
  const sortedActors = useMemo(() => [...filteredActors].sort((a, b) => {
    const left = actorSort.key === "country" ? a.actor.origin : a.actor.name;
    const right = actorSort.key === "country" ? b.actor.origin : b.actor.name;
    const result = left.localeCompare(right, undefined, { sensitivity: "base", numeric: true });
    return actorSort.direction === "asc" ? result : -result;
  }), [filteredActors, actorSort]);
  const selectedActorCves = useMemo(() => {
    if (!selectedActor) return [];
    const names = [selectedActor.name, ...selectedActor.aliases].map((name) => name.toLowerCase());
    return actorCveGroups.filter((group) => group.names.some((name) => names.includes(name.toLowerCase()))).flatMap((group) => group.cves);
  }, [selectedActor, actorCveGroups]);

  function toggleActorSort(key: ActorSortKey) {
    setActorSort((current) => current.key === key
      ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
      : { key, direction: "asc" });
  }

  function togglePin(url: string) {
    const next = pins.includes(url) ? pins.filter((x) => x !== url) : [...pins, url];
    setPins(next);
    void persistWorkspace("pins", next);
    flash(next.includes(url) ? "Reporting pinned" : "Pin removed");
  }

  function addWatchlist() {
    const value = newWatch.trim();
    if (!value || watchlists.some((item) => item.toLowerCase() === value.toLowerCase())) return;
    const next = [...watchlists, value];
    setWatchlists(next);
    setNewWatch("");
    void persistWorkspace("watchlists", next);
    flash("Watch term saved");
  }

  function removeWatchlist(value: string) {
    const next = watchlists.filter((item) => item !== value);
    setWatchlists(next);
    void persistWorkspace("watchlists", next);
  }

  function updateDiamond(field: keyof DiamondModel, value: string) {
    setDiamond((current) => ({ ...current, [field]: value }));
  }

  function seedDiamond(storyUrl: string) {
    if (!storyUrl) { setDiamond(blankDiamond()); return; }
    const story = news.find((item) => item.url === storyUrl);
    if (!story) return;
    const text = `${story.title} ${story.summary}`;
    const lower = text.toLowerCase();
    const matchedActor = actors
      .flatMap((actor) => [actor.name, ...actor.aliases].map((name) => ({ actor, name })))
      .filter(({ name }) => name.length > 4 && lower.includes(name.toLowerCase()))
      .sort((a, b) => b.name.length - a.name.length)[0]?.actor;
    setDiamond({
      ...blankDiamond(), storyUrl, title: story.title,
      adversary: matchedActor ? `${matchedActor.name}${matchedActor.aliases.length ? ` (${matchedActor.aliases.slice(0, 2).join(", ")})` : ""}` : `${countries[story.c].name}-linked activity (reporting classification; confirm attribution)`,
      capability: inferredCapability(text),
      victim: inferredVictim(text),
      evidence: `${story.sourceCountry} — ${story.title}\n${story.url}`,
      assumptions: "Country classification and any actor match are derived from open-source reporting and require corroboration.",
      gaps: "Confirm attribution, affected organizations, infrastructure ownership, timing, and observed technical indicators.",
      notes: `Seeded from ${story.sourceCountry} reporting. Confirm each vertex against the full article or primary technical reporting. The publisher domain is not adversary infrastructure.`,
    });
  }

  function persistDiamonds(next: DiamondModel[]) {
    setSavedDiamonds(next);
    void persistWorkspace("diamonds", next);
  }

  function saveDiamond() {
    const now = new Date().toISOString();
    const saved = { ...diamond, id: diamond.id || crypto.randomUUID(), title: diamond.title.trim() || "Untitled Diamond analysis", createdAt: diamond.createdAt || now };
    const next = savedDiamonds.some((item) => item.id === saved.id) ? savedDiamonds.map((item) => item.id === saved.id ? saved : item) : [saved, ...savedDiamonds];
    persistDiamonds(next);
    setDiamond(saved);
    flash("Diamond analysis saved");
  }

  function deleteDiamond(id: string) {
    persistDiamonds(savedDiamonds.filter((item) => item.id !== id));
    if (diamond.id === id) setDiamond(blankDiamond());
    flash("Analysis deleted");
  }

  async function copyDiamond() {
    const source = diamond.storyUrl ? `\nSource reporting: ${diamond.storyUrl}` : "";
    const text = `# Diamond Model Analysis: ${diamond.title || "Untitled"}${source}\n\n**Confidence:** ${diamond.confidence}\n**Campaign phase:** ${diamond.phase}\n**Direction:** ${diamond.direction}\n**Result:** ${diamond.result}\n\n## Adversary\n${diamond.adversary || "Unknown / collection gap"}\n\n## Capability\n${diamond.capability || "Unknown / collection gap"}\n\n## Infrastructure\n${diamond.infrastructure || "Unknown / collection gap"}\n\n## Victim\n${diamond.victim || "Unknown / collection gap"}\n\n## Evidence\n${diamond.evidence || "No evidence recorded."}\n\n## Assumptions\n${diamond.assumptions || "No assumptions recorded."}\n\n## Collection gaps\n${diamond.gaps || "No collection gaps recorded."}\n\n## Relationships, pivots, and analytic notes\n${diamond.notes || "Not assessed."}\n\n> Analytic caveat: distinguish observed facts from assessment; validate auto-seeded fields against primary reporting.`;
    await navigator.clipboard.writeText(text);
    flash("Diamond Markdown copied");
  }

  async function copyBrief() {
    const selected = pins.length ? filteredNews.filter((item) => pins.includes(item.url)) : filteredNews.slice(0, 20);
    const judgments = selected.slice(0, 5).map((item) => `- **${countries[item.c].name}:** ${item.title} *(Risk ${item.score}/100; ${item.riskReasons.join(", ") || "baseline reporting"})*`).join("\n");
    const sources = selected.map((item) => `- [${item.title}](${item.url}) — ${item.sourceCountry}, ${parseDate(item.seendate).toISOString().slice(0, 10)}`).join("\n");
    const gaps = ORDER.filter((code) => !selected.some((item) => item.c === code)).map((code) => `- No selected reporting for ${countries[code].name}; maintain standing collection.`).join("\n") || "- Validate attribution and assess mission-specific exposure against primary reporting.";
    await navigator.clipboard.writeText(`# Big 4 Cyber Threat Brief\n\n**Generated:** ${new Date().toISOString()}\n**Scope:** ${country === "ALL" ? "China, Russia, Iran, and North Korea" : countries[country].name}\n\n## Key judgments\n${judgments || "- No reporting meets the current filters."}\n\n## Indicators and warning\n${selected.filter((item) => item.score >= 65).map((item) => `- ${item.title} — ${item.riskReasons.join(", ")}`).join("\n") || "- No high-priority indicators under the current scoring model."}\n\n## Collection gaps\n${gaps}\n\n## Sources\n${sources || "- None selected."}\n\n> Open-source assessment. Attribution remains probabilistic; validate against primary technical reporting.`);
    flash("Structured brief copied");
  }

  function toggleKevSort(key: KevSortKey) {
    setKevSort((current) => current.key === key ? { key, direction: current.direction === "asc" ? "desc" : "asc" } : { key, direction: key === "epss" || key === "added" ? "desc" : "asc" });
  }

  function exportNavigator(actor: Actor) {
    downloadJson(`${actor.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-navigator.json`, {
      name: `${actor.name} — Enterprise techniques`, version: "4.5", domain: "enterprise-attack",
      description: `Generated from the dashboard's MITRE ATT&CK enrichment for ${actor.name}.`,
      techniques: actor.techniques.map((technique) => ({ techniqueID: technique.id, color: "#54d7db", comment: technique.name, enabled: true })),
      gradient: { colors: ["#e8f5f5", "#54d7db"], minValue: 0, maxValue: 1 }, legendItems: [], metadata: [], links: [],
    });
    flash("ATT&CK Navigator layer downloaded");
  }

  function exportStix() {
    const selected = pins.length ? filteredNews.filter((item) => pins.includes(item.url)) : filteredNews;
    const objects = selected.map((item) => ({
      type: "report", spec_version: "2.1", id: `report--${crypto.randomUUID()}`, created: new Date().toISOString(), modified: new Date().toISOString(),
      name: item.title, description: item.summary, published: parseDate(item.seendate).toISOString(), report_types: ["threat-report"], object_refs: [], external_references: [{ source_name: item.sourceCountry, url: item.url }],
    }));
    downloadJson(`big-4-threat-intelligence-${new Date().toISOString().slice(0, 10)}.json`, { type: "bundle", id: `bundle--${crypto.randomUUID()}`, objects });
    flash("STIX 2.1 bundle downloaded");
  }

  const latest = trends.at(-1);
  const maxTrend = Math.max(1, ...trends.flatMap((d) => ORDER.map((c) => d.counts[c] || 0)));
  const diamondStories = useMemo(() => [...priorityNews].sort((a, b) => Number(pins.includes(b.url)) - Number(pins.includes(a.url)) || b.score - a.score), [priorityNews, pins]);
  const onlineFeeds = feedStatus.filter((feed) => feed.ok).length;
  const watchHits = filteredNews.filter((item) => watchlists.some((term) => `${item.title} ${item.summary}`.toLowerCase().includes(term.toLowerCase())));
  const newestStory = useMemo(() => [...scoredNews].sort((a, b) => parseDate(b.seendate).getTime() - parseDate(a.seendate).getTime())[0], [scoredNews]);

  return (
    <main className="shell">
      {notice && <div className="toast" role="status">{notice}</div>}
      <header className="masthead">
        <div className="brand-mark" aria-hidden="true"><span /><span /><span /></div>
        <div className="brand-copy">
          <p className="eyebrow">Operational intelligence / Big 4 watch</p>
          <h1>Cyber Threat Dashboard</h1>
        </div>
        <div className="header-status">
          <span className={`pulse ${loading ? "working" : ""}`} />
          <div>
            <strong>{loading ? "Syncing intelligence" : dataMode === "live" ? "Live intelligence" : dataMode === "partial" ? "Partial live feed" : "Snapshot fallback"}</strong>
            <small>{generated ? `Feed synced ${relativeDate(generated)}${newestStory ? ` · newest report ${relativeDate(newestStory.seendate)}` : ""}` : "Local source pack"}</small>
          </div>
        </div>
      </header>

      <section className="commandbar" aria-label="Dashboard controls">
        <nav className="tabs" aria-label="Sections">
          {(["overview", "intel", "actors", "kev", "workbench"] as Tab[]).map((name) => (
            <button key={name} className={tab === name ? "active" : ""} onClick={() => setTab(name)}>{name === "intel" ? "Intelligence" : name === "kev" ? "Exploited CVEs" : name[0].toUpperCase() + name.slice(1)}</button>
          ))}
        </nav>
        <div className="actions">
          <label className="search"><span>⌕</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search actors, reporting, or CVEs" /></label>
          <button className="icon-button" onClick={loadData} aria-label="Refresh intelligence" title="Refresh intelligence">↻</button>
          <button className="brief-button" onClick={copyBrief}>Copy brief</button>
        </div>
      </section>

      <section className="country-strip" aria-label="Country filters">
        <button className={`country-card all-card ${country === "ALL" ? "selected" : ""}`} onClick={() => setCountry("ALL")}>
          <span className="country-label">All activity</span><strong>{news.length}</strong><small>reported items</small>
        </button>
        {ORDER.map((code) => {
          const item = countries[code];
          const count = news.filter((n) => n.c === code).length;
          const actorCount = classifiedActors.filter((a) => a.c === code).length;
          return <button key={code} className={`country-card country-${code.toLowerCase()} ${country === code ? "selected" : ""}`} onClick={() => setCountry(country === code ? "ALL" : code)}>
            <span className="country-label"><span>{item.flag}</span>{item.name}</span><strong>{count}</strong><small>{actorCount} profiled actors</small><i style={{ width: `${news.length ? Math.max(10, count / news.length * 100) : 10}%` }} />
          </button>;
        })}
      </section>

      {q && <section className="panel page-panel search-results">
        <div className="panel-heading search-heading">
          <div><p className="eyebrow">Unified search</p><h2>Results for “{query.trim()}”</h2><p>Searching reporting, threat actors, ATT&amp;CK techniques, vendors, products, and CVE identifiers.</p></div>
          <button className="clear-search" onClick={() => setQuery("")}>Clear search</button>
        </div>
        <div className="result-summary">
          <span><strong>{filteredNews.length}</strong> intelligence items</span>
          <span><strong>{filteredActors.length}</strong> actor profiles</span>
          <span><strong>{filteredKev.length}</strong> exploited CVEs</span>
        </div>
        <div className="search-columns">
          <section className="result-group">
            <div className="result-group-title"><h3>Intelligence</h3><button onClick={() => { setQuery(""); setTab("intel"); }}>View all</button></div>
            {filteredNews.slice(0, 6).map((item) => <a className="search-result" href={item.url} target="_blank" rel="noreferrer" key={`${item.url}-${item.c}`}>
              <span className={`badge badge-${item.c.toLowerCase()}`}>{item.c}</span><div><strong>{item.title}</strong><small>{item.sourceCountry} · {relativeDate(item.seendate)}</small></div><i>↗</i>
            </a>)}
            {!filteredNews.length && <p className="no-results">No matching reporting.</p>}
          </section>
          <section className="result-group">
            <div className="result-group-title"><h3>Threat actors</h3><button onClick={() => { setQuery(""); setTab("actors"); }}>View all</button></div>
            {filteredActors.slice(0, 6).map(({ actor, c }) => <button className="search-result" onClick={() => { setQuery(""); setTab("actors"); setSelectedActor(actor); }} key={`${actor.name}-${actor.gid}`}>
              <span className={`badge ${actorBadgeClass(c)}`}>{c}</span><div><strong>{actor.name}</strong><small>{actor.aliases.slice(0, 3).join(" · ") || actor.origin}</small></div><i>›</i>
            </button>)}
            {!filteredActors.length && <p className="no-results">No matching actor profiles.</p>}
          </section>
          <section className="result-group">
            <div className="result-group-title"><h3>Exploited CVEs</h3><button onClick={() => { setQuery(""); setTab("kev"); }}>View all</button></div>
            {filteredKev.slice(0, 6).map((item) => <a className="search-result" href={`https://nvd.nist.gov/vuln/detail/${item.cve}`} target="_blank" rel="noreferrer" key={item.cve}>
              <span className="cve-mark">CVE</span><div><strong>{item.cve}</strong><small>{item.vendor} · {item.product}</small></div><i>↗</i>
            </a>)}
            {!filteredKev.length && <p className="no-results">No matching exploited CVEs.</p>}
          </section>
        </div>
        {!filteredNews.length && !filteredActors.length && !filteredKev.length && <div className="empty-search"><strong>No results across the dashboard</strong><span>Try an actor name, vendor, product, technique, or CVE identifier.</span></div>}
      </section>}

      {!q && tab === "overview" && <section className="page-grid overview-grid">
        <article className="panel priority-panel">
          <div className="panel-heading"><div><p className="eyebrow">Executive view</p><h2>Priority watch</h2></div><span className="count-chip">{latest?.total || news.length} signals today</span></div>
          <div className="watch-list">
            {ORDER.filter((code) => country === "ALL" || country === code).map((code) => {
              const countryPriority = priorityNews.filter((item) => item.c === code);
              const top = countryPriority.find((item) => now - parseDate(item.seendate).getTime() <= 3 * 86_400_000) || countryPriority[0];
              return <div className="watch-row" key={code}>
                <div className="watch-rank" style={{ color: COLORS[code] }}>{code}</div>
                <div><h3>{top?.title || countries[code].focus}</h3><p>{top?.summary?.slice(0, 180) || countries[code].focus}</p><span>{top?.sourceCountry || "Analytic baseline"} · {top ? relativeDate(top.seendate) : "standing watch"}{top ? ` · Risk ${top.score}/100 · ${top.riskReasons.join(", ") || "baseline"}` : ""}</span></div>
                {top && <a href={top.url} target="_blank" rel="noreferrer" aria-label={`Open ${top.title}`}>↗</a>}
              </div>;
            })}
          </div>
        </article>

        <article className="panel trend-panel">
          <div className="panel-heading"><div><p className="eyebrow">Collection volume</p><h2>12-day activity</h2></div><span className="count-chip">{latest?.okFeeds || 0} feeds online</span></div>
          <div className="legend">{ORDER.map((code) => <span key={code}><i style={{ background: COLORS[code] }} />{countries[code].short}</span>)}</div>
          <div className="trend-chart">
            {trends.map((day) => <div className="trend-day" key={day.date} title={`${day.date}: ${day.total} items`}>
              <div className="bars">{ORDER.map((code) => <i key={code} style={{ height: `${Math.max(3, (day.counts[code] || 0) / maxTrend * 100)}%`, background: COLORS[code] }} />)}</div>
              <small>{day.date.slice(5).replace("-", "/")}</small>
            </div>)}
          </div>
        </article>

        <article className="panel focus-panel">
          <div className="panel-heading"><div><p className="eyebrow">Standing requirements</p><h2>Operational focus</h2></div></div>
          {ORDER.map((code) => <div className="focus-item" key={code}><span style={{ color: COLORS[code] }}>{code}</span><p>{countries[code].focus}</p></div>)}
        </article>

        <article className="panel health-panel">
          <div className="panel-heading"><div><p className="eyebrow">Collection assurance</p><h2>Feed health</h2></div><span className={`count-chip health-${dataMode}`}>{dataMode === "live" ? "Live" : dataMode}</span></div>
          <div className="health-metrics"><div><strong>{onlineFeeds}/{feedStatus.length || "—"}</strong><span>feeds online</span></div><div><strong>{feedStatus.reduce((sum, feed) => sum + feed.kept, 0)}</strong><span>items retained</span></div><div><strong>{generated ? relativeDate(generated) : "—"}</strong><span>last successful sync</span></div></div>
          <div className="feed-list">{feedStatus.map((feed) => <span className={feed.ok ? "feed-ok" : "feed-failed"} key={feed.name}><i />{feed.name}<b>{feed.kept}</b></span>)}</div>
          {!feedStatus.length && <p className="no-results">Feed-level telemetry is unavailable in the bundled fallback.</p>}
        </article>
      </section>}

      {!q && tab === "intel" && <section className="panel page-panel">
        <div className="panel-heading"><div><p className="eyebrow">Risk-ranked open-source reporting</p><h2>Intelligence stream</h2><p>Priority scores combine recency, operational impact, trusted-source reporting, and CISA KEV matches.</p></div><span className="count-chip">{filteredNews.length} items</span></div>
        <div className="filterbar"><label>Order<select value={intelSort} onChange={(event) => setIntelSort(event.target.value as "newest" | "risk")}><option value="newest">Newest first</option><option value="risk">Highest risk first</option></select></label><label>Minimum risk<select value={minRisk} onChange={(event) => setMinRisk(Number(event.target.value))}><option value="0">All reporting</option><option value="40">40+ watch</option><option value="60">60+ elevated</option><option value="75">75+ priority</option></select></label><span>Default view is chronological; switch to risk order for operational triage.</span></div>
        <div className="intel-grid">{filteredNews.map((item) => <article className="intel-card" key={`${item.url}-${item.c}`}>
          <div className="intel-meta"><span className={`badge badge-${item.c.toLowerCase()}`}>{countries[item.c].short}</span><span>{item.sourceCountry}</span><span>{relativeDate(item.seendate)}</span><span className={`risk-pill risk-${item.score >= 75 ? "high" : item.score >= 55 ? "medium" : "low"}`}>{item.score}</span></div>
          <h3><a href={item.url} target="_blank" rel="noreferrer">{item.title}</a></h3>
          <p>{item.summary}</p>
          <div className="risk-reasons">{item.riskReasons.map((reason) => <span key={reason}>{reason}</span>)}</div>
          <div className="intel-footer"><span>{item.domain}{watchlists.some((term) => `${item.title} ${item.summary}`.toLowerCase().includes(term.toLowerCase())) ? " · WATCHLIST MATCH" : ""}</span><button className={pins.includes(item.url) ? "pinned" : ""} onClick={() => togglePin(item.url)}>{pins.includes(item.url) ? "Pinned" : "Pin to brief"}</button></div>
        </article>)}</div>
      </section>}

      {!q && tab === "actors" && <section className="panel page-panel">
        <div className="panel-heading actor-heading"><div><p className="eyebrow">Multi-source actor intelligence</p><h2>Threat actor catalog</h2><p>Deduplicated across MITRE ATT&amp;CK, Microsoft Threat Intelligence, Google Threat Intelligence / Mandiant, and MISP Galaxy. Exact aliases are merged; similarity-only relationships remain separate.</p></div><span className="count-chip">{filteredActors.length} cataloged actors</span></div>
        <div className="table-wrap"><table><thead><tr>
          <th aria-sort={actorSort.key === "country" ? (actorSort.direction === "asc" ? "ascending" : "descending") : "none"}><button className={actorSort.key === "country" ? "sort-active" : ""} onClick={() => toggleActorSort("country")}>Origin <span>{actorSort.key === "country" ? (actorSort.direction === "asc" ? "↑" : "↓") : "↕"}</span></button></th>
          <th aria-sort={actorSort.key === "name" ? (actorSort.direction === "asc" ? "ascending" : "descending") : "none"}><button className={actorSort.key === "name" ? "sort-active" : ""} onClick={() => toggleActorSort("name")}>Actor / group <span>{actorSort.key === "name" ? (actorSort.direction === "asc" ? "↑" : "↓") : "↕"}</span></button></th>
          <th>Aliases</th><th>Sources</th><th>Techniques</th><th>Software</th></tr></thead><tbody>
          {sortedActors.map(({ actor, c }) => <tr key={`${actor.name}-${actor.gid}`} tabIndex={0} onClick={() => setSelectedActor(actor)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") setSelectedActor(actor); }}><td><span className={`badge ${actorBadgeClass(c)}`} title={actor.origin}>{c}</span></td><td><strong>{actor.name}</strong><small>{actor.gid || actor.origin}</small></td><td>{actor.aliases.slice(0, 4).join(" · ") || "—"}</td><td>{actor.sources.length}</td><td>{actor.techniques.length}</td><td>{actor.software.length}</td></tr>)}
        </tbody></table></div>
        {selectedActor && <div className="actor-drawer" role="dialog" aria-modal="true" aria-label={`${selectedActor.name} intelligence profile`}><button onClick={() => setSelectedActor(null)} aria-label="Close actor detail">×</button><p className="eyebrow">{selectedActor.gid || selectedActor.countryCode} / multi-source profile</p><h3>{selectedActor.name}</h3><p className="actor-origin">{selectedActor.origin}</p><p className="alias-line">{selectedActor.aliases.join(" · ") || "No public aliases recorded."}</p>{selectedActor.description && <p className="actor-description">{selectedActor.description}</p>}<div className="drawer-actions"><button className="secondary-action" onClick={() => exportNavigator(selectedActor)}>Download Navigator layer</button></div><h4>Catalog sources</h4><div className="tag-cloud source-tags">{selectedActor.sources.map((source) => <span key={source}>{source}</span>)}</div><h4>Observed techniques</h4><div className="tag-cloud">{selectedActor.techniques.map((x) => <span key={x.id}>{x.id} · {x.name}</span>)}{!selectedActor.techniques.length && <span>No ATT&amp;CK techniques mapped publicly</span>}</div><h4>Associated software</h4><div className="tag-cloud">{selectedActor.software.map((x) => <span key={x.id}>{x.name}</span>)}{!selectedActor.software.length && <span>No ATT&amp;CK software mapped publicly</span>}</div><h4>Associated vulnerabilities</h4><div className="actor-cve-list">{selectedActorCves.map((entry) => <a key={`${entry.id}-${entry.product}`} href={`https://nvd.nist.gov/vuln/detail/${entry.id}`} target="_blank" rel="noreferrer"><strong>{entry.id}</strong><span>{entry.product} · {entry.note}</span></a>)}{!selectedActorCves.length && <span className="no-results">No curated actor-to-CVE associations recorded.</span>}</div><h4>References</h4><div className="actor-refs">{selectedActor.refs.slice(0, 8).map((ref) => <a key={ref} href={ref} target="_blank" rel="noreferrer">{hostname(ref)} ↗</a>)}</div></div>}
      </section>}

      {!q && tab === "kev" && <section className="panel page-panel">
        <div className="panel-heading"><div><p className="eyebrow">CISA KEV + FIRST EPSS</p><h2>Exploited CVE queue</h2><p>Prioritize vulnerabilities by exploitation probability, remediation deadline, ransomware use, and actor association.</p></div><span className="count-chip">{displayedKev.length} entries</span></div>
        <div className="filterbar kev-filters"><label>Remediation status<select value={kevDueFilter} onChange={(event) => setKevDueFilter(event.target.value as "all" | "overdue" | "soon")}><option value="all">All deadlines</option><option value="overdue">Overdue</option><option value="soon">Due in 14 days</option></select></label><label className="check-filter"><input type="checkbox" checked={kevRansomwareOnly} onChange={(event) => setKevRansomwareOnly(event.target.checked)} /> Known ransomware use</label></div>
        <div className="table-wrap"><table><thead><tr><th><button onClick={() => toggleKevSort("cve")}>CVE {kevSort.key === "cve" ? (kevSort.direction === "asc" ? "↑" : "↓") : "↕"}</button></th><th><button onClick={() => toggleKevSort("vendor")}>Vendor / product {kevSort.key === "vendor" ? (kevSort.direction === "asc" ? "↑" : "↓") : "↕"}</button></th><th>Vulnerability</th><th><button onClick={() => toggleKevSort("epss")}>EPSS {kevSort.key === "epss" ? (kevSort.direction === "asc" ? "↑" : "↓") : "↕"}</button></th><th><button onClick={() => toggleKevSort("added")}>Added {kevSort.key === "added" ? (kevSort.direction === "asc" ? "↑" : "↓") : "↕"}</button></th><th><button onClick={() => toggleKevSort("due")}>Remediation due {kevSort.key === "due" ? (kevSort.direction === "asc" ? "↑" : "↓") : "↕"}</button></th><th>Ransomware</th></tr></thead><tbody>
          {displayedKev.map((item) => { const epss = epssScores[item.cve]; const overdue = new Date(`${item.due}T23:59:59Z`).getTime() < now; return <tr key={item.cve}><td><a href={`https://nvd.nist.gov/vuln/detail/${item.cve}`} target="_blank" rel="noreferrer"><strong>{item.cve}</strong></a></td><td>{item.vendor}<small>{item.product}</small></td><td>{item.name}</td><td><strong className={(epss?.epss || 0) >= .5 ? "epss-high" : ""}>{epss ? `${(epss.epss * 100).toFixed(1)}%` : "—"}</strong><small>{epss ? `${(epss.percentile * 100).toFixed(1)} percentile` : "No score"}</small></td><td>{item.added}</td><td><span className={overdue ? "due-overdue" : ""}>{item.due}{overdue ? " · OVERDUE" : ""}</span></td><td>{item.ransomware ? <span className="ransomware">Known use</span> : "—"}</td></tr>; })}
        </tbody></table></div>
      </section>}

      {!q && tab === "workbench" && <section className="page-grid workbench-grid">
        <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Analyst workbench</p><h2>Pinned reporting</h2></div><span className="count-chip">{pins.length} pinned · {storageMode === "durable" ? "synced" : storageMode === "local" ? "local fallback" : "syncing"}</span></div>
          <div className="watch-list">{news.filter((n) => pins.includes(n.url)).map((item) => <div className="watch-row" key={item.url}><div className="watch-rank" style={{ color: COLORS[item.c] }}>{item.c}</div><div><h3>{item.title}</h3><p>{item.summary}</p><span>{item.sourceCountry}</span></div><button onClick={() => togglePin(item.url)}>×</button></div>)}{!pins.length && <div className="empty-state"><span>⌖</span><h3>No reporting pinned</h3><p>Pin high-value items from the Intelligence stream to assemble a working brief.</p></div>}</div>
        </article>
        <article className="panel brief-panel"><p className="eyebrow">Rapid production</p><h2>Build an intelligence product</h2><p>Produce a structured Markdown brief with key judgments, indicators and warning, collection gaps, and traceable sources—or export the reporting as STIX 2.1.</p><button className="primary-action" onClick={copyBrief}>Copy structured brief</button><button className="secondary-action full-action" onClick={exportStix}>Export STIX 2.1 bundle</button><div className="brief-stat"><strong>{pins.length || filteredNews.length}</strong><span>{pins.length ? "pinned sources" : "filtered sources"}</span></div></article>

        <article className="panel watchlist-panel">
          <div className="panel-heading"><div><p className="eyebrow">Indicators and warning</p><h2>Saved watchlists</h2><p>Track actors, malware, sectors, vendors, products, and CVEs across incoming reporting.</p></div><span className="count-chip">{watchHits.length} current matches</span></div>
          <div className="watchlist-entry"><input value={newWatch} onChange={(event) => setNewWatch(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") addWatchlist(); }} placeholder="Add actor, CVE, malware, sector, or keyword" /><button className="secondary-action" onClick={addWatchlist}>Add watch</button></div>
          <div className="watch-tags">{watchlists.map((term) => <span key={term}>{term}<button onClick={() => removeWatchlist(term)} aria-label={`Remove ${term}`}>×</button></span>)}{!watchlists.length && <p className="no-results">No saved watch terms.</p>}</div>
          {watchHits.length > 0 && <div className="watch-hit-list">{watchHits.slice(0, 6).map((item) => <a href={item.url} target="_blank" rel="noreferrer" key={item.url}><strong>{item.title}</strong><span>{countries[item.c].short} · Risk {item.score}/100</span></a>)}</div>}
        </article>

        <article className="panel diamond-panel">
          <div className="panel-heading diamond-heading"><div><p className="eyebrow">Relational intrusion analysis</p><h2>Diamond Model workspace</h2><p>Model the relationships among adversary, capability, infrastructure, and victim. Auto-seeded fields are analytic starting points—confirm them against primary reporting.</p></div><span className="count-chip">{savedDiamonds.length} saved analyses</span></div>
          <div className="diamond-sourcebar">
            <label><span>Seed from reporting</span><select value={diamond.storyUrl} onChange={(event) => seedDiamond(event.target.value)}><option value="">Start a manual analysis</option>{diamondStories.map((story) => <option key={`${story.url}-${story.c}`} value={story.url}>{pins.includes(story.url) ? "★ " : ""}{story.title}</option>)}</select></label>
            <label><span>Analysis title</span><input value={diamond.title} onChange={(event) => updateDiamond("title", event.target.value)} placeholder="Campaign, intrusion, or incident name" /></label>
            <button className="secondary-action" onClick={() => setDiamond(blankDiamond())}>New model</button>
          </div>
          <div className="diamond-workspace">
            <div className="diamond-map" aria-label="Editable Diamond Model vertices">
              <label className="diamond-vertex adversary"><span>Adversary</span><small>Identity, sponsorship, intent, resources, uncertainty</small><textarea value={diamond.adversary} onChange={(event) => updateDiamond("adversary", event.target.value)} placeholder="Who is assessed to be behind the activity?" /></label>
              <label className="diamond-vertex capability"><span>Capability</span><small>Tools, exploits, credentials, tradecraft, access methods</small><textarea value={diamond.capability} onChange={(event) => updateDiamond("capability", event.target.value)} placeholder="What capability enabled the event?" /></label>
              <label className="diamond-vertex infrastructure"><span>Infrastructure</span><small>Controlled, compromised, leased, proxy, cloud, relay</small><textarea value={diamond.infrastructure} onChange={(event) => updateDiamond("infrastructure", event.target.value)} placeholder="What infrastructure supported the activity?" /></label>
              <label className="diamond-vertex victim"><span>Victim</span><small>Organization, sector, technology, geography, mission</small><textarea value={diamond.victim} onChange={(event) => updateDiamond("victim", event.target.value)} placeholder="Who or what was targeted?" /></label>
            </div>
            <aside className="diamond-context">
              <h3>Event context</h3>
              <div className="context-grid">
                <label><span>Campaign phase</span><select value={diamond.phase} onChange={(event) => updateDiamond("phase", event.target.value)}>{["Unknown", "Preparation", "Initial access", "Persistence", "Collection", "Command and control", "Exfiltration", "Impact"].map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Direction</span><select value={diamond.direction} onChange={(event) => updateDiamond("direction", event.target.value)}>{["Unknown", "Adversary → Victim", "Adversary → Infrastructure", "Infrastructure → Victim", "Capability → Victim"].map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Result</span><select value={diamond.result} onChange={(event) => updateDiamond("result", event.target.value)}>{["Unknown", "Attempted", "Successful", "Disrupted", "Failed"].map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Confidence</span><select value={diamond.confidence} onChange={(event) => updateDiamond("confidence", event.target.value)}>{["Low", "Moderate", "High"].map((value) => <option key={value}>{value}</option>)}</select></label>
              </div>
              <label className="relationship-notes"><span>Evidence and source traceability</span><textarea value={diamond.evidence} onChange={(event) => updateDiamond("evidence", event.target.value)} placeholder="Record the source, observation, date, and which vertex or relationship it supports." /></label>
              <div className="evidence-grid"><label><span>Assumptions</span><textarea value={diamond.assumptions} onChange={(event) => updateDiamond("assumptions", event.target.value)} placeholder="What must be true for this assessment to hold?" /></label><label><span>Collection gaps</span><textarea value={diamond.gaps} onChange={(event) => updateDiamond("gaps", event.target.value)} placeholder="What information would confirm or refute the assessment?" /></label></div>
              <label className="relationship-notes"><span>Relationships, pivots, and gaps</span><textarea value={diamond.notes} onChange={(event) => updateDiamond("notes", event.target.value)} placeholder="Explain how the vertices relate, useful pivots, durable indicators, uncertainties, and collection gaps." /></label>
              <div className="diamond-actions"><button className="primary-action" onClick={saveDiamond}>Save analysis</button><button className="secondary-action" onClick={copyDiamond}>Copy Markdown</button></div>
            </aside>
          </div>
          <div className="saved-diamonds"><div className="result-group-title"><h3>Saved analyses</h3><span>Stored only in this browser</span></div>{savedDiamonds.length ? <div className="saved-diamond-grid">{savedDiamonds.map((model) => <div className="saved-diamond" key={model.id}><button className="saved-diamond-main" onClick={() => setDiamond(model)}><strong>{model.title}</strong><span>{model.confidence} confidence · {model.phase}</span></button><button onClick={() => deleteDiamond(model.id)} aria-label={`Delete ${model.title}`}>×</button></div>)}</div> : <p className="no-results">No Diamond Model analyses saved yet.</p>}</div>
        </article>
      </section>}

      <footer><span>Big 4 Cyber & Information Warfare Threat Dashboard</span><span>Open-source reporting · Attribution remains probabilistic</span></footer>
    </main>
  );
}
